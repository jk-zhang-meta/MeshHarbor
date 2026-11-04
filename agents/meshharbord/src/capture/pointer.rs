// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P1d — the mouse pointer in a RECORDING.
//!
//! The live path keeps the pointer OUT of its frames on purpose. It streams
//! the pointer on a channel of its own (`cursor.rs`) and the browser draws
//! it, because a pointer baked into video lags by the video's latency. A
//! recording has no second channel: the file is the only picture. So each
//! backend answers one question here: does the pointer reach a recording,
//! and how.
//!
//! | Backend | The pointer in a recording |
//! |---|---|
//! | WGC (Windows) | drawn by WGC: the recorder opens its session with cursor capture on ([`PointerRequest::InFrame`]); the live path's stays off |
//! | CoreGraphics (macOS) | drawn by WindowServer (`kCGDisplayStreamShowCursor`, a vendored scrap patch) |
//! | the portal and mutter (Wayland) | drawn by the compositor, where it offers an embedded cursor |
//! | DXGI (Windows' fallback) | drawn by the recorder ([`WindowsPointer`]): `GetCursorInfo`, and the shape the live tracker decodes |
//! | X11 | drawn by the recorder ([`X11Pointer`]): XFixes `GetCursorImage` |
//! | DRM, SystemContext, synthetic | none; the sidecar says `none` |
//!
//! The drawing itself is `recording::pointer`. This module only says where
//! the pointer is, in the frame's own pixels.

use std::sync::Arc;

/// Whether a capturer's frames should carry the mouse pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerRequest {
    /// The live path: the pointer travels on its own channel, so a backend
    /// that can leave it out of the frame does.
    Separate,
    /// A recording: the file is the only picture, so a backend that can draw
    /// the pointer into the frame does.
    InFrame,
}

/// The largest pointer image taken from the OS, per side. Accessibility
/// sizes reach 256 px; anything past this is a malformed reply, not a
/// pointer.
pub const MAX_SHAPE_SIDE: u32 = 1024;

/// A pointer image: **premultiplied** BGRA, top-down rows,
/// `width * height * 4` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerShape {
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
}

impl PointerShape {
    /// From straight-alpha BGRA: Windows' cursor bitmaps, as the live
    /// tracker decodes them (and as the browser draws them).
    pub fn from_straight_bgra(width: u32, height: u32, bgra: &[u8]) -> Option<Self> {
        let len = shape_len(width, height)?;
        let src = bgra.get(..len)?;
        let mut out = Vec::with_capacity(len);
        for px in src.chunks_exact(4) {
            let a = u32::from(px[3]);
            for &c in &px[..3] {
                out.push(((u32::from(c) * a + 127) / 255) as u8);
            }
            out.push(px[3]);
        }
        Some(Self {
            width,
            height,
            bgra: out,
        })
    }

    /// From XFixes `GetCursorImage`: one ARGB32 word per pixel, alpha in the
    /// top byte, and the colour already premultiplied (the protocol says so).
    pub fn from_argb_words(width: u32, height: u32, words: &[u32]) -> Option<Self> {
        let len = shape_len(width, height)?;
        let src = words.get(..len / 4)?;
        let mut out = Vec::with_capacity(len);
        for w in src {
            // 0xAARRGGBB, little-endian in memory: B, G, R, A.
            out.extend_from_slice(&w.to_le_bytes());
        }
        Some(Self {
            width,
            height,
            bgra: out,
        })
    }
}

fn shape_len(width: u32, height: u32) -> Option<usize> {
    if width == 0 || height == 0 || width > MAX_SHAPE_SIDE || height > MAX_SHAPE_SIDE {
        return None;
    }
    Some(width as usize * height as usize * 4)
}

/// Where the pointer is now, in the FRAME's pixels: the top-left of `shape`,
/// with the hotspot and the display's origin already taken off.
#[derive(Debug, Clone)]
pub struct PointerSample {
    pub x: i32,
    pub y: i32,
    /// Equal ids mean an equal shape.
    pub shape_id: u64,
    pub shape: Arc<PointerShape>,
}

/// Something that says where the pointer is. Polled once per recorded frame,
/// on the recorder's loop, so it must be quick.
pub trait PointerSource: Send {
    /// `None` = hidden, or unreadable this instant: that frame goes without.
    fn poll(&mut self) -> Option<PointerSample>;
}

/// How the pointer gets into a recording from one capturer.
pub enum RecordedPointer {
    /// The backend draws it into every frame itself.
    InFrame,
    /// It does not, and the recorder draws what this source reports.
    Drawn(Box<dyn PointerSource>),
    /// Neither: the recording has no pointer.
    Absent,
}

/// A point in screen coordinates (the pointer's), placed in a frame whose
/// top-left sits at `origin`, with the shape's `hotspot` on the point.
pub fn place(point: (i32, i32), hotspot: (i32, i32), origin: (i32, i32)) -> (i32, i32) {
    (
        point.0.saturating_sub(hotspot.0).saturating_sub(origin.0),
        point.1.saturating_sub(hotspot.1).saturating_sub(origin.1),
    )
}

/// DXGI's frames carry no pointer, so this reads it the way the live tracker
/// does: `GetCursorInfo` for where, the tracker's decoded bitmap for what.
/// The recorder runs per-monitor DPI aware (`main` sets it before any
/// subcommand), so both are in physical pixels, like the frame.
#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
pub struct WindowsPointer {
    tracker: super::cursor::CursorTracker,
    origin: (i32, i32),
    /// Converted shapes and their hotspots, by `HCURSOR`. Bounded: an app
    /// that mints cursors endlessly empties it rather than growing it.
    shapes: std::collections::HashMap<u64, (Arc<PointerShape>, (i32, i32))>,
}

#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
impl WindowsPointer {
    /// `origin`: the captured output's top-left on the virtual desktop.
    pub fn new(origin: (i32, i32)) -> Self {
        Self {
            tracker: super::cursor::CursorTracker::new(),
            origin,
            shapes: std::collections::HashMap::new(),
        }
    }
}

#[cfg(all(target_os = "windows", feature = "mf-encoder"))]
impl PointerSource for WindowsPointer {
    fn poll(&mut self) -> Option<PointerSample> {
        let tick = self.tracker.poll_with_shape()?;
        if !self.shapes.contains_key(&tick.shape_id) {
            let info = tick.shape.as_ref()?;
            let shape = PointerShape::from_straight_bgra(info.width, info.height, &info.bgra)?;
            if self.shapes.len() >= 64 {
                self.shapes.clear();
            }
            self.shapes.insert(
                tick.shape_id,
                (Arc::new(shape), (info.hotspot_x, info.hotspot_y)),
            );
        }
        let (shape, hotspot) = self.shapes.get(&tick.shape_id)?;
        let (x, y) = place((tick.x, tick.y), *hotspot, self.origin);
        Some(PointerSample {
            x,
            y,
            shape_id: tick.shape_id,
            shape: shape.clone(),
        })
    }
}

/// X11's `GetImage` carries no pointer (it is a sprite the server draws on
/// top), so this asks XFixes for it, on a connection of its own.
#[cfg(all(target_os = "linux", feature = "scrap-capture"))]
pub struct X11Pointer {
    conn: x11rb::rust_connection::RustConnection,
    origin: (i32, i32),
    /// The last shape, by the server's cursor serial.
    last: Option<(u32, Arc<PointerShape>)>,
}

#[cfg(all(target_os = "linux", feature = "scrap-capture"))]
impl X11Pointer {
    /// `origin`: the captured monitor's top-left on the root window. `None`
    /// when there is no X server or it has no XFixes; the recording then
    /// goes without a pointer, and its sidecar says so.
    pub fn open(origin: (i32, i32)) -> Option<Self> {
        use x11rb::protocol::xfixes::ConnectionExt as _;
        let (conn, _screen) = x11rb::connect(None)
            .map_err(|e| tracing::info!(%e, "recording: no X connection for the pointer"))
            .ok()?;
        // The extension must be negotiated before any XFixes request is legal.
        // GetCursorImage is XFixes 1.0.
        let version = conn
            .xfixes_query_version(5, 0)
            .ok()?
            .reply()
            .map_err(|e| tracing::info!(%e, "recording: the X server has no usable XFixes"))
            .ok()?;
        if version.major_version < 1 {
            return None;
        }
        Some(Self {
            conn,
            origin,
            last: None,
        })
    }
}

#[cfg(all(target_os = "linux", feature = "scrap-capture"))]
impl PointerSource for X11Pointer {
    fn poll(&mut self) -> Option<PointerSample> {
        use x11rb::protocol::xfixes::ConnectionExt as _;
        let r = self.conn.xfixes_get_cursor_image().ok()?.reply().ok()?;
        let shape = match &self.last {
            Some((serial, s)) if *serial == r.cursor_serial => s.clone(),
            _ => {
                let s = Arc::new(PointerShape::from_argb_words(
                    u32::from(r.width),
                    u32::from(r.height),
                    &r.cursor_image,
                )?);
                self.last = Some((r.cursor_serial, s.clone()));
                s
            }
        };
        let (x, y) = place(
            (i32::from(r.x), i32::from(r.y)),
            (i32::from(r.xhot), i32::from(r.yhot)),
            self.origin,
        );
        Some(PointerSample {
            x,
            y,
            shape_id: u64::from(r.cursor_serial),
            shape,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_straight_pixel_is_premultiplied_and_an_opaque_one_is_left_alone() {
        let s = PointerShape::from_straight_bgra(
            2,
            1,
            &[
                200, 100, 50, 128, // half-transparent
                10, 20, 30, 255, // opaque
            ],
        )
        .unwrap();
        assert_eq!(s.bgra, vec![100, 50, 25, 128, 10, 20, 30, 255]);
    }

    #[test]
    fn an_xfixes_word_becomes_b_g_r_a() {
        let s = PointerShape::from_argb_words(2, 1, &[0x80_40_20_10, 0xFF_FF_FF_FF]).unwrap();
        assert_eq!(s.bgra, vec![0x10, 0x20, 0x40, 0x80, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn a_short_or_absurd_image_is_refused_not_read_past() {
        assert!(PointerShape::from_argb_words(2, 2, &[0; 3]).is_none());
        assert!(PointerShape::from_straight_bgra(2, 2, &[0; 15]).is_none());
        assert!(PointerShape::from_argb_words(0, 4, &[]).is_none());
        let too_wide = MAX_SHAPE_SIDE + 1;
        assert!(PointerShape::from_argb_words(too_wide, 1, &vec![0; too_wide as usize]).is_none());
    }

    #[test]
    fn the_hotspot_and_the_displays_origin_are_both_taken_off() {
        // A pointer at (1930, 60) on a monitor whose top-left is (1920, 0),
        // with its hotspot 4 px into the shape: the shape starts at (6, 56).
        assert_eq!(place((1930, 60), (4, 4), (1920, 0)), (6, 56));
        // A monitor LEFT of the primary has a negative origin.
        assert_eq!(place((-100, 10), (0, 0), (-1280, 0)), (1180, 10));
        assert_eq!(place((i32::MIN, 0), (5, 0), (5, 0)), (i32::MIN, 0));
    }
}

/// The X11 source against a REAL X server. `ROOMLERD_TEST_X11=1` makes a
/// missing server a failure rather than a skip, so the CI lane that runs this
/// under Xvfb cannot pass by running nothing.
#[cfg(all(test, target_os = "linux", feature = "scrap-capture"))]
mod x11_tests {
    use super::*;
    use x11rb::connection::Connection;
    use x11rb::protocol::xfixes::ConnectionExt as _;
    use x11rb::protocol::xproto::ConnectionExt as _;
    use x11rb::wrapper::ConnectionExt as _;

    fn required() -> bool {
        std::env::var("ROOMLERD_TEST_X11").as_deref() == Ok("1")
    }

    /// Put the server's pointer at (`x`, `y`) on the root window and wait
    /// until the server has done it.
    fn warp(conn: &impl Connection, root: u32, x: i16, y: i16) {
        conn.warp_pointer(x11rb::NONE, root, 0, 0, 0, 0, x, y)
            .unwrap();
        conn.sync().unwrap();
    }

    #[test]
    fn xfixes_says_where_the_pointer_is_in_the_frames_own_pixels() {
        let Ok((conn, screen)) = x11rb::connect(None) else {
            assert!(!required(), "ROOMLERD_TEST_X11=1 but there is no X server");
            eprintln!("no X server — skipping (ROOMLERD_TEST_X11=1 makes this a failure)");
            return;
        };
        let root = conn.setup().roots[screen].root;
        conn.xfixes_query_version(5, 0).unwrap().reply().unwrap();
        let hot = |c: &x11rb::rust_connection::RustConnection| {
            let r = c.xfixes_get_cursor_image().unwrap().reply().unwrap();
            (i32::from(r.xhot), i32::from(r.yhot))
        };

        warp(&conn, root, 300, 200);
        let (hx, hy) = hot(&conn);
        let mut at_zero = X11Pointer::open((0, 0)).expect("XFixes on this server");
        let s = at_zero.poll().expect("the pointer");
        assert_eq!((s.x, s.y), (300 - hx, 200 - hy), "hotspot {hx},{hy}");
        assert!(s.shape.width > 0 && s.shape.height > 0);
        assert_eq!(
            s.shape.bgra.len(),
            (s.shape.width * s.shape.height * 4) as usize
        );
        assert!(
            s.shape.bgra.chunks_exact(4).any(|p| p[3] != 0),
            "the pointer image has something visible in it"
        );

        // A monitor that starts at (100, 50) on the root sees the same
        // pointer 100 px further left and 50 px higher in its own frame.
        let mut offset = X11Pointer::open((100, 50)).unwrap();
        let o = offset.poll().unwrap();
        assert_eq!((o.x, o.y), (300 - hx - 100, 200 - hy - 50));

        // It follows the pointer, and the shape cache keeps the same image.
        warp(&conn, root, 10, 20);
        let m = at_zero.poll().unwrap();
        assert_eq!((m.x, m.y), (10 - hx, 20 - hy));
        assert_eq!(m.shape_id, s.shape_id);
        assert!(
            Arc::ptr_eq(&m.shape, &s.shape),
            "an unchanged shape is not rebuilt"
        );
    }
}
