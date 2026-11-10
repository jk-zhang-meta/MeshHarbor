// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-93 P3c — the hardware cursor, read from the DRM cursor plane.
//!
//! A compositor keeps the pointer on the CRTC's **cursor plane** wherever the
//! hardware has one (mutter and KWin both do, in a virtio-gpu VM and on real
//! GPUs), so it is absent from every frame the DRM arm reads off the primary
//! plane. The DRM worker (`drm_backend.rs`) therefore also reads the cursor
//! plane on every frame it grabs:
//!
//! - its position, `CRTC_X/Y`: the buffer's top-left on the CRTC;
//! - its hotspot, `HOTSPOT_X/Y`, where the driver has one (virtio-gpu, qxl,
//!   vmwgfx: a hypervisor needs it to move the host's pointer);
//! - its ARGB buffer, re-read when the framebuffer changes, and every
//!   [`SHAPE_REREAD`] in case a compositor redraws a buffer in place.
//!
//! It publishes the result in [`publish`], and the cursor data channel's
//! tracker (`capture::cursor::CursorTracker`) reads it with [`latest`]. The
//! wire is the Windows cursor's: `cursor:shape`, `cursor:pos`, `cursor:hide`.
//!
//! ⚠️ **Only an arm whose frames carry no pointer writes here**: the DRM arm, and
//! the X11 arm from FR-97 P3a (`x11_cursor.rs`). mutter's and the portal's streams
//! embed it, so they publish nothing, and the tracker keeps answering `None` there.
//!
//! Everything below the slot is pure, so the conversions are pinned by tests
//! with no DRM device.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::CursorInfo;

/// How long a published cursor stays good. The worker refreshes it on every
/// frame a session pulls, so an older one means nobody is pulling (the session
/// ended, or the worker died): the pointer then reads as hidden rather than
/// frozen in place.
pub const STALE_AFTER: Duration = Duration::from_secs(2);

/// How often an unchanged cursor framebuffer is read again. A compositor may
/// redraw its cursor buffer in place for a new shape, with no new framebuffer
/// to say so.
pub const SHAPE_REREAD: Duration = Duration::from_millis(250);

/// The cursor as the data channel needs it, in the captured CRTC's native
/// pixels.
#[derive(Debug, Clone)]
pub struct CursorSnapshot {
    /// The hotspot's position on the CRTC.
    pub x: i32,
    pub y: i32,
    /// Changes whenever the image or its hotspot does: the viewer caches a
    /// shape by id for the whole session and never replaces one.
    pub shape_id: u64,
    pub shape: Arc<CursorInfo>,
    /// When the worker read it.
    pub at: Instant,
}

static CURSOR: Mutex<Option<CursorSnapshot>> = Mutex::new(None);

/// The worker's write: the cursor at this frame, or `None` when no cursor
/// plane shows one. That is a hidden pointer, or a compositor drawing the
/// pointer into the primary plane itself, where it is already in the frame.
pub fn publish(snapshot: Option<CursorSnapshot>) {
    if let Ok(mut slot) = CURSOR.lock() {
        *slot = snapshot;
    }
}

/// The tracker's read: the last published cursor, while it is fresh.
pub fn latest() -> Option<CursorSnapshot> {
    let slot = CURSOR.lock().ok()?;
    let snapshot = slot.as_ref()?;
    fresh(snapshot.at, Instant::now()).then(|| snapshot.clone())
}

/// Is a cursor read at `at` still good at `now`?
pub fn fresh(at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(at) <= STALE_AFTER
}

/// A cursor buffer's pixels, straightened and cropped to what is visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPixels {
    pub width: u32,
    pub height: u32,
    /// Where the crop starts in the plane's buffer.
    pub origin_x: i32,
    pub origin_y: i32,
    /// Tightly packed BGRA with STRAIGHT alpha (the wire's), top-down.
    pub bgra: Vec<u8>,
}

/// Straighten and crop one ARGB8888 cursor buffer.
///
/// ARGB8888 is the bytes B, G, R, A in memory (the format is little-endian),
/// which is the wire's own order. KMS cursor buffers are **premultiplied** by
/// convention (the plane's default blend mode), and the viewer expects straight
/// alpha, so each colour is divided back out.
///
/// The crop keeps the bounding box of every pixel with any alpha. Cursor
/// buffers are sized by the hardware (64×64, or 256×256 on some GPUs) rather
/// than by the image, and the transparent rest would be most of every
/// `cursor:shape` sent.
///
/// `None` for a fully transparent buffer (nothing to show), or one shorter
/// than `pitch × height`.
pub fn straighten_and_crop(
    src: &[u8],
    width: u32,
    height: u32,
    pitch: u32,
) -> Option<CursorPixels> {
    let (w, h, pitch) = (width as usize, height as usize, pitch as usize);
    if w == 0 || h == 0 || pitch < w * 4 || src.len() < pitch * (h - 1) + w * 4 {
        return None;
    }
    let row = |y: usize| &src[y * pitch..y * pitch + w * 4];
    let (mut x0, mut y0, mut x1, mut y1) = (usize::MAX, usize::MAX, 0usize, 0usize);
    for y in 0..h {
        for (x, px) in row(y).chunks_exact(4).enumerate() {
            if px[3] != 0 {
                x0 = x0.min(x);
                x1 = x1.max(x);
                y0 = y0.min(y);
                y1 = y1.max(y);
            }
        }
    }
    if x0 == usize::MAX {
        return None;
    }
    let (cw, ch) = (x1 - x0 + 1, y1 - y0 + 1);
    let mut bgra = Vec::with_capacity(cw * ch * 4);
    for y in y0..=y1 {
        for px in row(y)[x0 * 4..(x1 + 1) * 4].chunks_exact(4) {
            let a = px[3];
            if a == 0 {
                bgra.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            let straight = |c: u8| -> u8 {
                ((u32::from(c) * 255 + u32::from(a) / 2) / u32::from(a)).min(255) as u8
            };
            bgra.extend_from_slice(&[straight(px[0]), straight(px[1]), straight(px[2]), a]);
        }
    }
    Some(CursorPixels {
        width: cw as u32,
        height: ch as u32,
        origin_x: x0 as i32,
        origin_y: y0 as i32,
        bgra,
    })
}

/// Where the cursor goes, from the plane's state.
///
/// `crtc` is the plane's `CRTC_X/Y`, the buffer's top-left on the CRTC.
/// `hotspot` is the plane's `HOTSPOT_X/Y` where the driver has them. Real GPUs
/// have none: their compositor already placed the buffer so that the hotspot
/// lands on the pointer, and the visible image's own top-left stands in for it.
///
/// Returns the position the wire carries (the hotspot on the CRTC) and the
/// hotspot within the CROPPED image. The viewer draws at `pos - hotspot`,
/// which is the crop's top-left on the CRTC either way.
pub fn place(
    crtc: (i32, i32),
    hotspot: Option<(i32, i32)>,
    pixels: &CursorPixels,
) -> ((i32, i32), (i32, i32)) {
    let full = hotspot.unwrap_or((pixels.origin_x, pixels.origin_y));
    let pos = (crtc.0 + full.0, crtc.1 + full.1);
    let in_crop = (full.0 - pixels.origin_x, full.1 - pixels.origin_y);
    (pos, in_crop)
}

/// The id the viewer caches a shape under: its pixels and its hotspot, since a
/// change to either is a new shape to the viewer, which never replaces a
/// cached id.
pub fn shape_id(pixels: &CursorPixels, hotspot: (i32, i32)) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (pixels.width, pixels.height, hotspot, &pixels.bgra).hash(&mut h);
    h.finish()
}

/// The wire's shape for a cursor: straight-alpha BGRA, its hotspot within the
/// image. `css` stays `None`: a Linux plane carries no system-cursor name.
pub fn shape_info(pixels: &CursorPixels, hotspot: (i32, i32)) -> CursorInfo {
    CursorInfo {
        width: pixels.width,
        height: pixels.height,
        hotspot_x: hotspot.0,
        hotspot_y: hotspot.1,
        bgra: pixels.bgra.clone(),
        css: None,
    }
}

/// Which plane is the scanout to capture, by each plane's `type` property.
///
/// The first PRIMARY plane bound to a CRTC with a framebuffer. A cursor or an
/// overlay is never it, however it is enumerated, and once the cursor plane is
/// visible and bound it would otherwise win on enumeration order alone. A plane
/// with no `type` (a driver that never said) is the fallback, which is what this
/// backend took before it read types at all.
pub fn pick_primary<T: Copy>(planes: &[(Option<PlaneKind>, Option<T>)]) -> Option<T> {
    let mut untyped = None;
    for (kind, bound) in planes {
        let Some(bound) = bound else { continue };
        match kind {
            Some(PlaneKind::Primary) => return Some(*bound),
            Some(_) => {}
            None => {
                if untyped.is_none() {
                    untyped = Some(*bound);
                }
            }
        }
    }
    untyped
}

/// A plane's `type` property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneKind {
    Overlay,
    Primary,
    Cursor,
}

impl PlaneKind {
    /// The `type` property's raw value (`DRM_PLANE_TYPE_*`).
    pub fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Overlay),
            1 => Some(Self::Primary),
            2 => Some(Self::Cursor),
            _ => None,
        }
    }
}

/// The cursor plane's signed position or hotspot property. The kernel stores a
/// signed range's value two's-complement in the raw `u64`.
pub fn signed(raw: u64) -> i32 {
    (raw as i64).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One premultiplied ARGB8888 pixel, as the bytes B, G, R, A.
    fn premul(b: u8, g: u8, r: u8, a: u8) -> [u8; 4] {
        [b, g, r, a]
    }

    /// A `w×h` buffer with a `pitch`, every pixel transparent but the listed
    /// `(x, y, pixel)`s.
    fn buffer(w: usize, h: usize, pitch: usize, set: &[(usize, usize, [u8; 4])]) -> Vec<u8> {
        assert!(pitch >= w * 4, "a pitch shorter than its row");
        let mut b = vec![0u8; pitch * h];
        for (x, y, px) in set {
            b[y * pitch + x * 4..y * pitch + x * 4 + 4].copy_from_slice(px);
        }
        b
    }

    /// The viewer wants straight alpha; KMS hands us premultiplied. A half-
    /// transparent mid-grey (premultiplied 64 at alpha 128) is a full 128 grey.
    #[test]
    fn premultiplied_colour_is_straightened() {
        let src = buffer(1, 1, 4, &[(0, 0, premul(64, 32, 0, 128))]);
        let px = straighten_and_crop(&src, 1, 1, 4).unwrap();
        assert_eq!(px.bgra, vec![128, 64, 0, 128]);
        // Opaque passes through unchanged.
        let src = buffer(1, 1, 4, &[(0, 0, premul(10, 20, 30, 255))]);
        assert_eq!(
            straighten_and_crop(&src, 1, 1, 4).unwrap().bgra,
            vec![10, 20, 30, 255]
        );
    }

    /// A 64×64 hardware buffer with an arrow in one corner sends only the
    /// arrow, and says where it starts. The padding past each row is skipped.
    #[test]
    fn the_buffer_is_cropped_to_what_is_visible() {
        let set = [
            (2, 3, premul(0, 0, 0, 255)),
            (5, 3, premul(0, 0, 0, 255)),
            (2, 9, premul(255, 255, 255, 255)),
        ];
        let src = buffer(64, 64, 64 * 4 + 32, &set);
        let px = straighten_and_crop(&src, 64, 64, 64 * 4 + 32).unwrap();
        assert_eq!((px.width, px.height), (4, 7));
        assert_eq!((px.origin_x, px.origin_y), (2, 3));
        assert_eq!(px.bgra.len(), 4 * 7 * 4);
        // The crop's top-left is the arrow's first pixel.
        assert_eq!(&px.bgra[..4], &[0, 0, 0, 255]);
    }

    /// Nothing visible is nothing to send, and a short buffer is refused
    /// rather than read past its end.
    #[test]
    fn a_transparent_or_short_buffer_is_none() {
        assert_eq!(straighten_and_crop(&buffer(8, 8, 32, &[]), 8, 8, 32), None);
        assert_eq!(straighten_and_crop(&[0u8; 10], 8, 8, 32), None);
    }

    /// With the driver's hotspot (a paravirtual GPU) the wire's position is the
    /// hotspot on the CRTC; without one the visible image's top-left stands in.
    /// Either way the viewer, drawing at `pos - hotspot`, puts the crop's
    /// top-left at `CRTC_X/Y` plus its origin in the buffer.
    #[test]
    fn the_viewer_draws_the_crop_where_the_plane_shows_it() {
        let px = CursorPixels {
            width: 10,
            height: 16,
            origin_x: 2,
            origin_y: 3,
            bgra: vec![255; 10 * 16 * 4],
        };
        let ((x, y), (hx, hy)) = place((100, 200), Some((5, 7)), &px);
        assert_eq!(((x, y), (hx, hy)), ((105, 207), (3, 4)));
        assert_eq!((x - hx, y - hy), (102, 203));

        let ((x, y), (hx, hy)) = place((100, 200), None, &px);
        assert_eq!(((x, y), (hx, hy)), ((102, 203), (0, 0)));
        assert_eq!((x - hx, y - hy), (102, 203));

        // A pointer partly off the left edge: the plane sits at a negative X.
        let ((x, _), (hx, _)) = place((-4, 0), Some((5, 7)), &px);
        assert_eq!(x - hx, -2);
    }

    /// The viewer never replaces a cached shape, so the id must follow the
    /// pixels AND the hotspot, and stay put while neither moves.
    #[test]
    fn the_shape_id_follows_the_pixels_and_the_hotspot() {
        let px = CursorPixels {
            width: 2,
            height: 1,
            origin_x: 0,
            origin_y: 0,
            bgra: vec![1, 2, 3, 255, 4, 5, 6, 255],
        };
        let id = shape_id(&px, (0, 0));
        assert_eq!(id, shape_id(&px.clone(), (0, 0)), "stable");
        assert_ne!(id, shape_id(&px, (1, 0)), "a new hotspot is a new shape");
        let mut other = px.clone();
        other.bgra[0] = 9;
        assert_ne!(id, shape_id(&other, (0, 0)), "new pixels are a new shape");
    }

    /// Once the cursor plane is visible and bound (it is, wherever the pointer
    /// shows), enumeration order must not make it the scanout we capture.
    #[test]
    fn the_primary_plane_is_picked_by_type() {
        use PlaneKind::*;
        let planes = [
            (Some(Cursor), Some('c')),
            (Some(Overlay), Some('o')),
            (Some(Primary), Some('p')),
        ];
        assert_eq!(pick_primary(&planes), Some('p'));
        // An unbound primary is no scanout.
        assert_eq!(
            pick_primary(&[(Some(Primary), None), (Some(Cursor), Some('c'))]),
            None
        );
        // A driver that never said what its planes are: the first bound one, as
        // before P3c.
        assert_eq!(
            pick_primary(&[(None, None), (None, Some('x')), (None, Some('y'))]),
            Some('x')
        );
        // A typed primary wins over an earlier untyped plane.
        assert_eq!(
            pick_primary(&[(None, Some('x')), (Some(Primary), Some('p'))]),
            Some('p')
        );
    }

    #[test]
    fn plane_types_and_signed_values_decode() {
        assert_eq!(PlaneKind::from_raw(1), Some(PlaneKind::Primary));
        assert_eq!(PlaneKind::from_raw(2), Some(PlaneKind::Cursor));
        assert_eq!(PlaneKind::from_raw(7), None);
        assert_eq!(signed((-12i64) as u64), -12);
        assert_eq!(signed(640), 640);
    }

    /// A cursor read longer ago than [`STALE_AFTER`] is no cursor: the session
    /// that refreshed it is gone.
    #[test]
    fn a_stale_cursor_is_none() {
        let at = Instant::now();
        assert!(fresh(at, at + STALE_AFTER));
        assert!(!fresh(at, at + STALE_AFTER + Duration::from_millis(1)));
        // A clock read before the snapshot (a racing reader) is fresh, not a panic.
        assert!(fresh(at + Duration::from_secs(1), at));
    }
}
