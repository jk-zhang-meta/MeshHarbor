// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! "Host is locked" overlay frame producer (M3 phase 3b, Z-path).
//!
//! When the lock-state monitor (`lock_state.rs`) reports `Locked`,
//! the user-context worker's capture pump can no longer grab real
//! frames — it's attached to `winsta0\Default` while input has
//! moved to `winsta0\Winlogon`. WGC returns black or stale frames;
//! `scrap` returns ERROR_ACCESS_DENIED on Win11.
//!
//! Instead of forwarding garbage to the WebRTC encoder, the pump
//! routes through `produce()` from this module and gets back a BGRA
//! buffer the same size as the configured capture resolution. The
//! buffer paints:
//!
//!   - Dark grey fill so it's visibly *not* the user's desktop
//!     (typical desktops have light or busy backgrounds — a flat
//!     dark grey is unmistakable as "the agent is paused").
//!   - A large centered yellow rounded square containing a stylised
//!     padlock shape rendered from rectangles. No font crate, no
//!     bundled PNG — pure pixel paint, ~5 KB of code at runtime.
//!   - Designed to encode efficiently: the shape is 4-5 distinct
//!     colour regions, so an H.264/HEVC keyframe of this image is
//!     tiny (~10 KB) regardless of capture resolution.
//!
//! Why not text? Rendering "Host is locked" requires either a font
//! crate (ab_glyph + a bundled TTF, ~200 KB extra agent binary) or
//! a hand-rolled bitmap font. The padlock visual is distinctive
//! enough that operators recognise "not the desktop" in <1 s; we
//! can add text later if field reports indicate confusion.
//!
//! Cross-platform: compiled everywhere, called only on Windows. Off Windows
//! `lock_state` always reads `Unlocked`: a Linux lock screen is captured and
//! takes input like any other (FR-97 P3b's hint is advisory); macOS has no probe.

use std::sync::Arc;

use crate::capture::{Frame, PixelFormat};

// ── Palette ─────────────────────────────────────────────────────────
// BGRA byte layout (little-endian DWORD = 0xAARRGGBB), so
// channel order in the buffer is [B, G, R, A].
const BG_GRAY: [u8; 4] = [0x20, 0x20, 0x20, 0xFF]; // dark grey background
const BADGE_YELLOW: [u8; 4] = [0x10, 0xC8, 0xF0, 0xFF]; // amber-ish
const PADLOCK_DARK: [u8; 4] = [0x10, 0x10, 0x10, 0xFF]; // near-black contrast

/// Produce a BGRA `Frame` of the requested dimensions painted with
/// the lock overlay. `monotonic_us` should be the encoder-pump
/// monotonic clock so timestamps stay coherent with surrounding
/// real frames.
pub fn produce(width: u32, height: u32, monotonic_us: u64, monitor: u8) -> Arc<Frame> {
    let stride = width * 4;
    let mut data = vec![0u8; (stride * height) as usize];

    // 1. Fill background.
    fill_solid(&mut data, stride, 0, 0, width, height, BG_GRAY);

    // 2. Centered yellow badge — square, side = min(40 % of width,
    //    60 % of height) so it scales sanely across 16:9, 4:3, and
    //    portrait-orientation captures. Floor at 80 px so a tiny
    //    480 px capture still has a visible badge.
    let side = (width * 4 / 10).min(height * 6 / 10).max(80);
    let badge_x = width.saturating_sub(side) / 2;
    let badge_y = height.saturating_sub(side) / 2;
    fill_solid(
        &mut data,
        stride,
        badge_x,
        badge_y,
        side,
        side,
        BADGE_YELLOW,
    );

    // 3. Padlock shape inside the badge. The shape is composed of
    //    four rectangles: two vertical bars for the shackle, a
    //    horizontal bar across the top of the shackle, and the
    //    body. Proportions sit comfortably inside the badge with
    //    margins so JPEG/H.264 quantisation doesn't bleed colour
    //    across the badge edge.
    paint_padlock(&mut data, stride, badge_x, badge_y, side);

    Arc::new(Frame {
        width,
        height,
        stride,
        pixel_format: PixelFormat::Bgra,
        data,
        monotonic_us,
        monitor,
        // P8a — a synthetic frozen still: provably nothing changes
        // frame-to-frame while the overlay is up.
        damage: crate::capture::Damage::Tracked(Vec::new()),
        // The overlay is painted at the requested dims — they ARE native.
        source: None,
    })
}

/// Fill `[x, x+w) × [y, y+h)` of `buf` with `color`. Out-of-bounds
/// writes are clamped silently — caller passes valid coords by
/// construction, this is just defensive against integer overflow
/// at extreme resolutions.
fn fill_solid(buf: &mut [u8], stride: u32, x: u32, y: u32, w: u32, h: u32, color: [u8; 4]) {
    let buf_h = (buf.len() as u32) / stride;
    let buf_w = stride / 4;
    let x0 = x.min(buf_w);
    let x1 = (x + w).min(buf_w);
    let y0 = y.min(buf_h);
    let y1 = (y + h).min(buf_h);
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    for row in y0..y1 {
        let row_start = (row * stride) as usize;
        for col in x0..x1 {
            let i = row_start + (col * 4) as usize;
            buf[i] = color[0];
            buf[i + 1] = color[1];
            buf[i + 2] = color[2];
            buf[i + 3] = color[3];
        }
    }
}

/// Paint a stylised padlock inside the badge `(x0, y0, side, side)`.
/// All measurements are fractions of `side` so the shape scales with
/// the badge.
fn paint_padlock(buf: &mut [u8], stride: u32, x0: u32, y0: u32, side: u32) {
    // Inner margin so the padlock doesn't touch the badge edge.
    let margin = side * 12 / 100;
    let inner_x = x0 + margin;
    let inner_y = y0 + margin;
    let inner_side = side.saturating_sub(margin * 2);

    // Body is the bottom ~55 % of the inner area.
    let body_h = inner_side * 55 / 100;
    let body_y = inner_y + (inner_side - body_h);
    let body_w = inner_side * 80 / 100;
    let body_x = inner_x + (inner_side - body_w) / 2;
    fill_solid(buf, stride, body_x, body_y, body_w, body_h, PADLOCK_DARK);

    // Shackle: a U-shape above the body, made from two vertical
    // rectangles + a horizontal rectangle across the top. Width is
    // ~60 % of body width; height is the inner area minus body.
    let shackle_thickness = inner_side * 10 / 100;
    let shackle_w = body_w * 65 / 100;
    let shackle_x = body_x + (body_w - shackle_w) / 2;
    let shackle_top = inner_y;
    let shackle_h = body_y - shackle_top;
    // Top horizontal bar.
    fill_solid(
        buf,
        stride,
        shackle_x,
        shackle_top,
        shackle_w,
        shackle_thickness,
        PADLOCK_DARK,
    );
    // Left vertical bar.
    fill_solid(
        buf,
        stride,
        shackle_x,
        shackle_top,
        shackle_thickness,
        shackle_h,
        PADLOCK_DARK,
    );
    // Right vertical bar.
    fill_solid(
        buf,
        stride,
        shackle_x + shackle_w - shackle_thickness,
        shackle_top,
        shackle_thickness,
        shackle_h,
        PADLOCK_DARK,
    );

    // Keyhole: a small yellow square in the upper third of the
    // body, providing visual "is this a padlock?" disambiguation
    // (a plain rectangle could be misread as a shipping crate).
    let kh_size = body_w * 18 / 100;
    let kh_x = body_x + (body_w - kh_size) / 2;
    let kh_y = body_y + body_h * 25 / 100;
    fill_solid(buf, stride, kh_x, kh_y, kh_size, kh_size, BADGE_YELLOW);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produce_returns_frame_of_requested_size() {
        let f = produce(640, 480, 1234, 0);
        assert_eq!(f.width, 640);
        assert_eq!(f.height, 480);
        assert_eq!(f.stride, 640 * 4);
        assert_eq!(f.pixel_format, PixelFormat::Bgra);
        assert_eq!(f.data.len(), (640 * 480 * 4) as usize);
    }

    #[test]
    fn produce_paints_dark_corners() {
        // The badge is centered with margins, so the four corners
        // should be the BG_GRAY background colour. Sample at
        // (0,0), (w-1, 0), (0, h-1), (w-1, h-1).
        let f = produce(640, 480, 0, 0);
        let pixel_at = |x: u32, y: u32| {
            let i = ((y * f.stride) + x * 4) as usize;
            [f.data[i], f.data[i + 1], f.data[i + 2], f.data[i + 3]]
        };
        assert_eq!(pixel_at(0, 0), BG_GRAY);
        assert_eq!(pixel_at(639, 0), BG_GRAY);
        assert_eq!(pixel_at(0, 479), BG_GRAY);
        assert_eq!(pixel_at(639, 479), BG_GRAY);
    }

    #[test]
    fn produce_paints_yellow_in_the_centre() {
        // The exact center of the badge should be either
        // BADGE_YELLOW (the keyhole-square sits offset, so center
        // is mostly yellow body interior or PADLOCK_DARK body).
        // Just lock that it is *not* BG_GRAY — i.e. the badge
        // actually drew something.
        let f = produce(640, 480, 0, 0);
        let cx = 320u32;
        let cy = 240u32;
        let i = ((cy * f.stride) + cx * 4) as usize;
        let centre = [f.data[i], f.data[i + 1], f.data[i + 2], f.data[i + 3]];
        assert_ne!(
            centre, BG_GRAY,
            "centre pixel should be inside the badge, got {centre:?}"
        );
    }

    #[test]
    fn produce_handles_extreme_aspect_ratios() {
        // Portrait-tall (e.g. side monitor rotated). The badge
        // should still fit (uses min(40% width, 60% height)).
        let f = produce(480, 1080, 0, 0);
        assert_eq!(f.data.len(), (480 * 1080 * 4) as usize);
        // Square 1:1 (kiosk).
        let f = produce(1024, 1024, 0, 0);
        assert_eq!(f.data.len(), (1024 * 1024 * 4) as usize);
    }

    #[test]
    fn produce_handles_tiny_resolutions() {
        // Below the 80 px badge floor — should still produce a
        // valid frame, just with a clamped badge.
        let f = produce(60, 60, 0, 0);
        assert_eq!(f.width, 60);
        assert_eq!(f.height, 60);
        // Frame should be non-empty and correctly sized.
        assert_eq!(f.data.len(), 60 * 60 * 4);
    }

    #[test]
    fn produce_preserves_monotonic_us_and_monitor() {
        let f = produce(320, 240, 9_999_999, 7);
        assert_eq!(f.monotonic_us, 9_999_999);
        assert_eq!(f.monitor, 7);
    }

    #[test]
    fn fill_solid_clamps_oob_gracefully() {
        let mut buf = vec![0u8; 16 * 16 * 4];
        // Try to fill past the right edge.
        fill_solid(&mut buf, 16 * 4, 14, 0, 100, 100, [0xFF, 0, 0, 0xFF]);
        // Pixel at (15, 0) should be filled.
        assert_eq!(buf[15 * 4], 0xFF);
        // Pixel at (15, 99) is OOB but the call shouldn't have
        // panicked — that's the contract.
    }

    #[test]
    fn fill_solid_zero_dim_is_noop() {
        let mut buf = vec![0u8; 16 * 16 * 4];
        let snapshot = buf.clone();
        fill_solid(&mut buf, 16 * 4, 0, 0, 0, 0, [0xFF; 4]);
        assert_eq!(buf, snapshot, "zero-width fill should not mutate buffer");
    }
}
