// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Platform-agnostic colour conversions for the encoder layer.
//!
//! Today the only public entry point is [`bgra_to_nv12`], used by the
//! Media Foundation backend which wants NV12 input. The BGRA→I420 path
//! used by openh264 lives inside `openh264_backend` for now — once a
//! second SW encoder backend needs it, lift that helper up here too.
//!
//! All converters are scalar Rust. libyuv with SSE/AVX would be ~4–8×
//! faster at 1080p and is a known optimisation — not on the phase-1
//! critical path because the hardware encoder backend eliminates most
//! of the encode cost and makes this conversion the remaining CPU hog
//! only at 4K, where a phase-2 GPU path replaces it entirely.
//!
//! Coefficients: BT.601 limited-range (TV range, luma [16,235], chroma
//! [16,240]). This is what the vast majority of H.264 decoders and
//! WebRTC browsers assume when no colour-range metadata is attached.

use anyhow::{Result, anyhow};

/// Convert a BGRA image buffer to NV12 (one Y plane followed by an
/// interleaved UV plane at half resolution in each axis).
///
/// Output layout:
///
/// ```text
/// +---------------+
/// |   Y (w×h)     |
/// +---------------+
/// |  UV (w×h/2)   |   UVUVUV... interleaved, half width, half height
/// +---------------+
/// ```
///
/// Width and height must both be even. `src_stride` is the BGRA row
/// stride in bytes — lets us accept capture buffers that include row
/// padding without a prior copy.
///
/// Returns a single `Vec<u8>` of length `w*h + w*h/2` ready to be
/// wrapped in an `IMFMediaBuffer` (MF) / `CVPixelBuffer` (VT) / whatever
/// the target backend wants.
pub fn bgra_to_nv12(src: &[u8], width: u32, height: u32, src_stride: u32) -> Result<Vec<u8>> {
    if width == 0 || height == 0 {
        return Err(anyhow!("bgra_to_nv12: zero-sized frame {width}x{height}"));
    }
    if !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err(anyhow!(
            "bgra_to_nv12: NV12 requires even dimensions, got {width}x{height}"
        ));
    }
    let w = width as usize;
    let h = height as usize;
    let stride = src_stride as usize;
    let expected = stride * h;
    if src.len() < expected {
        return Err(anyhow!(
            "bgra_to_nv12: src too short: got {}, need at least {}",
            src.len(),
            expected
        ));
    }

    let y_size = w * h;
    let uv_size = w * h / 2;
    let mut dst = vec![0u8; y_size + uv_size];
    let (y_plane, uv_plane) = dst.split_at_mut(y_size);

    // Two rows at a time so we can average 2×2 chroma blocks in the
    // same pass. Saves re-reading the BGRA buffer for the chroma plane.
    for y in (0..h).step_by(2) {
        let row0 = y * stride;
        let row1 = (y + 1) * stride;
        for x in (0..w).step_by(2) {
            let p00 = row0 + x * 4;
            let p10 = row0 + (x + 1) * 4;
            let p01 = row1 + x * 4;
            let p11 = row1 + (x + 1) * 4;

            // BGRA order from scrap: [B, G, R, A].
            let (b00, g00, r00) = (src[p00] as i32, src[p00 + 1] as i32, src[p00 + 2] as i32);
            let (b10, g10, r10) = (src[p10] as i32, src[p10 + 1] as i32, src[p10 + 2] as i32);
            let (b01, g01, r01) = (src[p01] as i32, src[p01 + 1] as i32, src[p01 + 2] as i32);
            let (b11, g11, r11) = (src[p11] as i32, src[p11 + 1] as i32, src[p11 + 2] as i32);

            y_plane[y * w + x] = bt601_y(r00, g00, b00);
            y_plane[y * w + x + 1] = bt601_y(r10, g10, b10);
            y_plane[(y + 1) * w + x] = bt601_y(r01, g01, b01);
            y_plane[(y + 1) * w + x + 1] = bt601_y(r11, g11, b11);

            // Average the 2×2 block to one chroma sample.
            let r = (r00 + r10 + r01 + r11) / 4;
            let g = (g00 + g10 + g01 + g11) / 4;
            let b = (b00 + b10 + b01 + b11) / 4;
            let uv_off = (y / 2) * w + (x / 2) * 2;
            uv_plane[uv_off] = bt601_u(r, g, b);
            uv_plane[uv_off + 1] = bt601_v(r, g, b);
        }
    }

    Ok(dst)
}

/// Rec.601 luma formula, TV-range (Y in [16, 235]).
#[inline]
fn bt601_y(r: i32, g: i32, b: i32) -> u8 {
    // Y = 0.257 R + 0.504 G + 0.098 B + 16
    // Using integer math with 16-bit scale to avoid f32 round-trip
    // per pixel. 0.257*65536 = 16843, 0.504*65536 = 33030, 0.098*65536 = 6423.
    let y = (16843 * r + 33030 * g + 6423 * b + 32_768) >> 16;
    (y + 16).clamp(0, 255) as u8
}

/// Rec.601 chroma-blue difference, TV-range (U/Cb in [16, 240]).
#[inline]
fn bt601_u(r: i32, g: i32, b: i32) -> u8 {
    // U = -0.148 R - 0.291 G + 0.439 B + 128
    let u = (-9699 * r - 19071 * g + 28770 * b + 32_768) >> 16;
    (u + 128).clamp(0, 255) as u8
}

/// Rec.601 chroma-red difference, TV-range (V/Cr in [16, 240]).
#[inline]
fn bt601_v(r: i32, g: i32, b: i32) -> u8 {
    // V = 0.439 R - 0.368 G - 0.071 B + 128
    let v = (28770 * r - 24117 * g - 4653 * b + 32_768) >> 16;
    (v + 128).clamp(0, 255) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_bgra(w: u32, h: u32, b: u8, g: u8, r: u8) -> Vec<u8> {
        let mut v = vec![0u8; (w * h * 4) as usize];
        for px in v.chunks_exact_mut(4) {
            px[0] = b;
            px[1] = g;
            px[2] = r;
            px[3] = 255;
        }
        v
    }

    #[test]
    fn rejects_odd_dimensions() {
        let buf = solid_bgra(3, 2, 0, 0, 0);
        assert!(bgra_to_nv12(&buf, 3, 2, 12).is_err());
        let buf = solid_bgra(4, 3, 0, 0, 0);
        assert!(bgra_to_nv12(&buf, 4, 3, 16).is_err());
    }

    #[test]
    fn rejects_zero_dims() {
        let buf = vec![0u8; 16];
        assert!(bgra_to_nv12(&buf, 0, 4, 16).is_err());
        assert!(bgra_to_nv12(&buf, 4, 0, 16).is_err());
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = vec![0u8; 15];
        assert!(bgra_to_nv12(&buf, 4, 4, 16).is_err());
    }

    #[test]
    fn solid_black_yields_black_luma_neutral_chroma() {
        // BGRA black = (0,0,0). Y should be 16 (TV range floor), U/V = 128.
        let src = solid_bgra(8, 8, 0, 0, 0);
        let nv12 = bgra_to_nv12(&src, 8, 8, 32).unwrap();
        assert_eq!(nv12.len(), 8 * 8 + 8 * 8 / 2);
        for y in &nv12[..64] {
            assert_eq!(*y, 16, "black Y should be 16 in TV range");
        }
        for uv in &nv12[64..] {
            assert_eq!(*uv, 128, "grayscale chroma should be 128");
        }
    }

    #[test]
    fn solid_white_yields_peak_luma_neutral_chroma() {
        // BGRA white = (255,255,255). Y should be 235 (TV range ceiling).
        let src = solid_bgra(8, 8, 255, 255, 255);
        let nv12 = bgra_to_nv12(&src, 8, 8, 32).unwrap();
        for y in &nv12[..64] {
            // Small rounding slack around the 235 peak — integer math
            // lands within ±1 of the exact BT.601 value.
            assert!(
                (234..=236).contains(y),
                "white Y expected near 235, got {}",
                y
            );
        }
        for uv in &nv12[64..] {
            assert!((127..=129).contains(uv), "grayscale chroma near 128");
        }
    }

    #[test]
    fn solid_mid_gray_is_grayscale() {
        let src = solid_bgra(8, 8, 128, 128, 128);
        let nv12 = bgra_to_nv12(&src, 8, 8, 32).unwrap();
        for uv in &nv12[64..] {
            assert!((127..=129).contains(uv), "mid-gray chroma near 128");
        }
    }

    #[test]
    fn pure_red_has_expected_cr_sign() {
        // Pure red pushes V (Cr) well above 128 and pulls U (Cb) below.
        let src = solid_bgra(8, 8, 0, 0, 255);
        let nv12 = bgra_to_nv12(&src, 8, 8, 32).unwrap();
        let uv_start = 64;
        let u = nv12[uv_start];
        let v = nv12[uv_start + 1];
        assert!(u < 128, "red should produce U < 128, got {u}");
        assert!(v > 200, "red should produce V well above 128, got {v}");
    }

    #[test]
    fn honours_source_stride() {
        // Build a 4×4 BGRA with a stride of 24 bytes (extra 8 bytes of
        // padding per row). NV12 output should ignore the pad and match
        // the no-pad version.
        let mut padded = vec![0u8; 24 * 4];
        for y in 0..4 {
            for x in 0..4 {
                let off = y * 24 + x * 4;
                padded[off] = 100;
                padded[off + 1] = 150;
                padded[off + 2] = 200;
                padded[off + 3] = 255;
            }
        }
        let out_padded = bgra_to_nv12(&padded, 4, 4, 24).unwrap();
        let tight = solid_bgra(4, 4, 100, 150, 200);
        let out_tight = bgra_to_nv12(&tight, 4, 4, 16).unwrap();
        assert_eq!(out_padded, out_tight);
    }
}
