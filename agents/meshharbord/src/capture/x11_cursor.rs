// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P3a — the X11 pointer on the cursor channel.
//!
//! X11 draws the pointer as a sprite over the framebuffer, so the XShm frames
//! the X11 arm reads never carry it, and until P3a the viewer drew a stand-in
//! at the controller's own mouse. The capture worker now reads it from XFixes
//! on every frame request, a skipped frame's included, and publishes it in the
//! slot the DRM arm fills from its cursor plane ([`drm_cursor::publish`]). The
//! cursor channel's tracker sends it from there unchanged: `cursor:shape`,
//! `cursor:pos`, `cursor:hide`.
//!
//! - **One small round trip per frame.** The shape is read only when XFixes
//!   says the cursor changed (`CursorNotify`, selected on the root window), and
//!   at least every [`SHAPE_REREAD`]. The position comes from `QueryPointer`.
//! - **XFixes images are premultiplied ARGB**, as a cursor plane's are, so the
//!   DRM arm's [`drm_cursor::straighten_and_crop`] serves both.
//! - **An invisible cursor is a hidden one.** An app hides the pointer by
//!   setting a fully transparent cursor, which reads as `cursor:hide`: what
//!   FR-109's relative mouse waits for.
//! - **A named cursor carries its CSS keyword.** Xcursor themes name theirs
//!   (`left_ptr`, `xterm`, `hand2`), and for one of those the viewer shows its
//!   own native cursor, as it does for the Windows tracker's stock cursors.
//!
//! Kill switch `ROOMLERD_X11_CURSOR=0`: nothing is read or published, and the
//! viewer draws its stand-in, as before P3a.

use std::sync::Arc;
use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{self, ConnectionExt as _};
use x11rb::rust_connection::RustConnection;

use super::CursorInfo;
use super::drm_cursor::{self, CursorSnapshot};

/// The longest an unchanged shape goes unread. A live connection reports
/// every change as a `CursorNotify`; this bounds what one it did not costs.
pub const SHAPE_REREAD: Duration = Duration::from_secs(1);

/// FR-97 P3a — kill switch `ROOMLERD_X11_CURSOR=0`.
pub fn enabled() -> bool {
    tunnel_core::env::flag("X11_CURSOR", true)
}

/// A visible cursor shape, as the wire carries it.
#[derive(Debug, Clone)]
pub struct Shape {
    /// What the viewer caches the shape under: the cropped pixels and the
    /// hotspot ([`drm_cursor::shape_id`]).
    pub id: u64,
    pub info: Arc<CursorInfo>,
}

/// What XFixes last said the cursor looks like.
struct LastRead {
    /// `None`: a fully transparent cursor, which is a hidden pointer.
    shape: Option<Shape>,
    at: Instant,
}

/// The X11 pointer, read for the cursor channel on the capture worker's
/// thread, beside the damage tracker and on a connection of its own.
pub struct X11Cursor {
    conn: RustConnection,
    root: xproto::Window,
    /// The captured monitor's top-left on the root window.
    origin: (i32, i32),
    /// XFixes 2 and later name the cursor (`GetCursorImageAndName`).
    named: bool,
    last: Option<LastRead>,
    /// A `CursorNotify` arrived since the last read.
    changed: bool,
}

impl X11Cursor {
    /// `origin`: the captured monitor's top-left on the root window. `None`
    /// with the kill switch set, or without an X server that has XFixes; the
    /// viewer then draws its stand-in.
    pub fn open(origin: (i32, i32)) -> Option<Self> {
        if !enabled() {
            tracing::info!(
                "capture: the X11 pointer stays off the cursor channel (ROOMLERD_X11_CURSOR=0)"
            );
            return None;
        }
        let (conn, screen) = x11rb::connect(None)
            .map_err(|e| tracing::info!(%e, "capture: no X connection for the cursor channel"))
            .ok()?;
        let root = conn.setup().roots.get(screen)?.root;
        // The extension must be negotiated before any XFixes request is legal.
        // GetCursorImage and cursor notification are XFixes 1.0; the name is 2.0.
        let version = conn
            .xfixes_query_version(5, 0)
            .ok()?
            .reply()
            .map_err(|e| tracing::info!(%e, "capture: the X server has no usable XFixes"))
            .ok()?;
        if version.major_version < 1 {
            return None;
        }
        conn.xfixes_select_cursor_input(root, xfixes::CursorNotifyMask::DISPLAY_CURSOR)
            .ok()?
            .check()
            .map_err(|e| tracing::info!(%e, "capture: XFixes refused cursor notification"))
            .ok()?;
        tracing::info!(
            xfixes = version.major_version,
            "capture: the X11 pointer is on the cursor channel (FR-97 P3a)"
        );
        Some(Self {
            conn,
            root,
            origin,
            named: version.major_version >= 2,
            last: None,
            changed: true,
        })
    }

    /// Read the pointer and publish it for the cursor channel. An X error
    /// publishes nothing, and the last cursor goes stale on its own
    /// ([`drm_cursor::STALE_AFTER`]), as a stopped DRM worker's does.
    pub fn publish(&mut self) {
        if let Some(cursor) = self.read() {
            drm_cursor::publish(cursor);
        }
    }

    /// `None` on an X error; `Some(None)` for a hidden pointer.
    fn read(&mut self) -> Option<Option<CursorSnapshot>> {
        loop {
            match self.conn.poll_for_event() {
                Ok(Some(Event::XfixesCursorNotify(_))) => self.changed = true,
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return None,
            }
        }
        let now = Instant::now();
        let due = self.changed
            || self
                .last
                .as_ref()
                .is_none_or(|l| now.saturating_duration_since(l.at) >= SHAPE_REREAD);
        let pointer = if due {
            let (pointer, shape) = self.read_shape()?;
            self.last = Some(LastRead { shape, at: now });
            self.changed = false;
            pointer
        } else {
            let p = self.conn.query_pointer(self.root).ok()?.reply().ok()?;
            (i32::from(p.root_x), i32::from(p.root_y))
        };
        let shape = self.last.as_ref()?.shape.clone();
        Some(shape.map(|s| {
            let (x, y) = on_monitor(pointer, self.origin);
            CursorSnapshot {
                x,
                y,
                shape_id: s.id,
                shape: s.info,
                at: now,
            }
        }))
    }

    /// The pointer's place on the root window and the shape now showing.
    fn read_shape(&self) -> Option<((i32, i32), Option<Shape>)> {
        if self.named {
            let r = self
                .conn
                .xfixes_get_cursor_image_and_name()
                .ok()?
                .reply()
                .ok()?;
            let shape = shape_of(
                (u32::from(r.width), u32::from(r.height)),
                (i32::from(r.xhot), i32::from(r.yhot)),
                &r.cursor_image,
                Some(&r.name),
            );
            Some(((i32::from(r.x), i32::from(r.y)), shape))
        } else {
            let r = self.conn.xfixes_get_cursor_image().ok()?.reply().ok()?;
            let shape = shape_of(
                (u32::from(r.width), u32::from(r.height)),
                (i32::from(r.xhot), i32::from(r.yhot)),
                &r.cursor_image,
                None,
            );
            Some(((i32::from(r.x), i32::from(r.y)), shape))
        }
    }
}

/// The wire's position: the pointer's hotspot in the captured monitor's own
/// pixels. The viewer draws the image at this point less the hotspot.
pub fn on_monitor(pointer: (i32, i32), origin: (i32, i32)) -> (i32, i32) {
    (
        pointer.0.saturating_sub(origin.0),
        pointer.1.saturating_sub(origin.1),
    )
}

/// One XFixes cursor image as the wire's shape: straight alpha, cropped to
/// what is visible, its hotspot moved into the crop, and its CSS keyword when
/// the cursor's name has one. `None` for a fully transparent image (a hidden
/// pointer) or one shorter than `width × height`.
pub fn shape_of(
    (width, height): (u32, u32),
    hotspot: (i32, i32),
    argb: &[u32],
    name: Option<&[u8]>,
) -> Option<Shape> {
    let n = (width as usize).checked_mul(height as usize)?;
    // A word is 0xAARRGGBB, so its little-endian bytes are B, G, R, A: the
    // cursor plane's own order, which `straighten_and_crop` reads.
    let bytes: Vec<u8> = argb
        .get(..n)?
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let pixels = drm_cursor::straighten_and_crop(&bytes, width, height, width.checked_mul(4)?)?;
    let hot = (hotspot.0 - pixels.origin_x, hotspot.1 - pixels.origin_y);
    let mut info = drm_cursor::shape_info(&pixels, hot);
    info.css = name.and_then(css_for);
    Some(Shape {
        id: drm_cursor::shape_id(&pixels, hot),
        info: Arc::new(info),
    })
}

/// The CSS `cursor` keyword for a cursor by the names Xcursor themes give
/// them: the X core cursor font's, freedesktop's, and Qt's for the same
/// shape. The keywords are the Windows tracker's set for its stock cursors
/// (`cursor.rs`). Any other name keeps the bitmap.
pub fn css_for(name: &[u8]) -> Option<&'static str> {
    Some(match name {
        b"left_ptr" | b"default" | b"arrow" | b"top_left_arrow" | b"left_arrow" => "default",
        b"xterm" | b"text" | b"ibeam" => "text",
        b"hand1" | b"hand2" | b"hand" | b"pointer" | b"pointing_hand" => "pointer",
        b"watch" | b"wait" => "wait",
        b"left_ptr_watch" | b"progress" | b"half-busy" => "progress",
        b"crosshair" | b"cross" | b"tcross" => "crosshair",
        b"sb_h_double_arrow" | b"h_double_arrow" | b"ew-resize" | b"size_hor" | b"left_side"
        | b"right_side" => "ew-resize",
        b"sb_v_double_arrow" | b"v_double_arrow" | b"ns-resize" | b"size_ver" | b"top_side"
        | b"bottom_side" => "ns-resize",
        b"fd_double_arrow"
        | b"nesw-resize"
        | b"size_bdiag"
        | b"top_right_corner"
        | b"bottom_left_corner" => "nesw-resize",
        b"bd_double_arrow"
        | b"nwse-resize"
        | b"size_fdiag"
        | b"top_left_corner"
        | b"bottom_right_corner" => "nwse-resize",
        b"fleur" | b"move" | b"all-scroll" | b"size_all" => "move",
        b"not-allowed" | b"crossed_circle" | b"forbidden" => "not-allowed",
        b"question_arrow" | b"help" | b"whats_this" | b"left_ptr_help" => "help",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An XFixes word is premultiplied 0xAARRGGBB. The viewer wants straight
    /// B, G, R, A, so a half-transparent mid-grey comes back a full 128 grey.
    #[test]
    fn an_xfixes_word_reaches_the_wire_straight_and_in_bgra_order() {
        let s = shape_of((1, 1), (0, 0), &[0x80_40_40_40], None).unwrap();
        assert_eq!(s.info.bgra, vec![128, 128, 128, 128]);
        let s = shape_of((1, 1), (0, 0), &[0xFF_30_20_10], None).unwrap();
        assert_eq!(s.info.bgra, vec![0x10, 0x20, 0x30, 0xFF], "B, G, R, A");
    }

    /// A 24×24 image with an arrow in its middle sends only the arrow, and the
    /// hotspot moves with the crop, so the viewer draws it where X11 does.
    #[test]
    fn the_image_is_cropped_and_the_hotspot_follows() {
        let mut img = vec![0u32; 24 * 24];
        img[5 * 24 + 4] = 0xFF_00_00_00; // (4, 5)
        img[9 * 24 + 7] = 0xFF_FF_FF_FF; // (7, 9)
        let s = shape_of((24, 24), (4, 5), &img, None).unwrap();
        assert_eq!((s.info.width, s.info.height), (4, 5));
        assert_eq!((s.info.hotspot_x, s.info.hotspot_y), (0, 0));
        // A hotspot inside the crop keeps its offset from the crop's corner.
        let s = shape_of((24, 24), (6, 7), &img, None).unwrap();
        assert_eq!((s.info.hotspot_x, s.info.hotspot_y), (2, 2));
    }

    /// An app hides the pointer with a cursor that has nothing visible in it,
    /// and a short image is refused rather than read past its end.
    #[test]
    fn a_transparent_or_short_image_is_no_shape() {
        assert!(shape_of((8, 8), (0, 0), &[0; 64], None).is_none());
        assert!(shape_of((8, 8), (0, 0), &[0xFF_00_00_00; 63], None).is_none());
        assert!(shape_of((0, 8), (0, 0), &[], None).is_none());
    }

    /// The viewer never replaces a cached id, so a new hotspot over the same
    /// pixels is a new shape, and the same cursor read twice is the same one.
    #[test]
    fn the_id_follows_the_pixels_and_the_hotspot() {
        let img = [0xFF_00_00_00u32; 4];
        let a = shape_of((2, 2), (0, 0), &img, None).unwrap();
        assert_eq!(a.id, shape_of((2, 2), (0, 0), &img, None).unwrap().id);
        assert_ne!(a.id, shape_of((2, 2), (1, 1), &img, None).unwrap().id);
    }

    /// The names a theme gives its standard cursors map to the Windows
    /// tracker's keywords; an app's own cursor keeps its bitmap.
    #[test]
    fn a_standard_name_carries_its_css_keyword() {
        for (name, css) in [
            (&b"left_ptr"[..], "default"),
            (b"xterm", "text"),
            (b"ibeam", "text"),
            (b"hand2", "pointer"),
            (b"pointing_hand", "pointer"),
            (b"watch", "wait"),
            (b"left_ptr_watch", "progress"),
            (b"crosshair", "crosshair"),
            (b"sb_h_double_arrow", "ew-resize"),
            (b"sb_v_double_arrow", "ns-resize"),
            (b"top_right_corner", "nesw-resize"),
            (b"bottom_right_corner", "nwse-resize"),
            (b"fleur", "move"),
            (b"crossed_circle", "not-allowed"),
            (b"question_arrow", "help"),
        ] {
            assert_eq!(
                css_for(name),
                Some(css),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        assert_eq!(css_for(b"an_apps_own_cursor"), None);
        assert_eq!(css_for(b"left_ptr "), None, "names match exactly");
        assert_eq!(css_for(b""), None);
        let img = [0xFF_00_00_00u32; 4];
        let named = shape_of((2, 2), (0, 0), &img, Some(b"xterm")).unwrap();
        assert_eq!(named.info.css, Some("text"));
        assert_eq!(shape_of((2, 2), (0, 0), &img, None).unwrap().info.css, None);
    }

    /// The wire's position is in the captured monitor's own pixels: a monitor
    /// right of the primary starts at its own x, and one left of it at a
    /// negative one.
    #[test]
    fn the_position_is_on_the_captured_monitor() {
        assert_eq!(on_monitor((300, 200), (0, 0)), (300, 200));
        assert_eq!(on_monitor((1930, 60), (1920, 0)), (10, 60));
        assert_eq!(on_monitor((-100, 10), (-1280, 0)), (1180, 10));
        assert_eq!(on_monitor((i32::MIN, 0), (1, 0)), (i32::MIN, 0));
    }
}

/// Against a REAL X server. `ROOMLERD_TEST_X11=1` makes a missing server a
/// failure rather than a skip, so the CI lane that runs this under Xvfb
/// cannot pass by running nothing.
#[cfg(test)]
mod x11_tests {
    use super::*;
    use x11rb::wrapper::ConnectionExt as _;

    fn required() -> bool {
        std::env::var("ROOMLERD_TEST_X11").as_deref() == Ok("1")
    }

    fn warp(conn: &impl x11rb::connection::Connection, root: u32, x: i16, y: i16) {
        conn.warp_pointer(x11rb::NONE, root, 0, 0, 0, 0, x, y)
            .unwrap();
        conn.sync().unwrap();
    }

    /// A glyph cursor from the core cursor font, named as a theme names its
    /// I-beam, made the root window's cursor.
    fn set_root_cursor(
        conn: &impl x11rb::connection::Connection,
        root: u32,
        glyph: u16,
        name: &[u8],
    ) {
        let font = conn.generate_id().unwrap();
        conn.open_font(font, b"cursor").unwrap();
        let cursor = conn.generate_id().unwrap();
        conn.create_glyph_cursor(
            cursor,
            font,
            font,
            glyph,
            glyph + 1,
            0,
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFF,
        )
        .unwrap();
        conn.xfixes_set_cursor_name(cursor, name).unwrap();
        conn.change_window_attributes(
            root,
            &xproto::ChangeWindowAttributesAux::new().cursor(cursor),
        )
        .unwrap();
        conn.sync().unwrap();
    }

    #[test]
    fn the_pointer_reaches_the_slot_with_its_shape_place_and_name() {
        let Ok((conn, screen)) = x11rb::connect(None) else {
            assert!(!required(), "ROOMLERD_TEST_X11=1 but there is no X server");
            eprintln!("no X server — skipping (ROOMLERD_TEST_X11=1 makes this a failure)");
            return;
        };
        let root = conn.setup().roots[screen].root;
        conn.xfixes_query_version(5, 0).unwrap().reply().unwrap();
        // XC_xterm is glyph 152 of the cursor font.
        set_root_cursor(&conn, root, 152, b"xterm");
        warp(&conn, root, 300, 200);

        let mut reader = X11Cursor::open((100, 50)).expect("XFixes on this server");
        let first = reader
            .read()
            .expect("no X error")
            .expect("a visible pointer");
        assert_eq!(
            (first.x, first.y),
            (200, 150),
            "the hotspot, less the monitor's origin"
        );
        assert!(first.shape.width > 0 && first.shape.height > 0);
        assert_eq!(first.shape.css, Some("text"), "the name's keyword");

        // Between notifications only the position is read, and the shape stays.
        warp(&conn, root, 110, 60);
        let moved = reader.read().unwrap().unwrap();
        assert_eq!((moved.x, moved.y), (10, 10));
        assert_eq!(moved.shape_id, first.shape_id);

        // A new cursor is a notification, and the next read takes its shape.
        set_root_cursor(&conn, root, 68, b"left_ptr"); // XC_left_ptr
        let mut seen = None;
        for _ in 0..50 {
            let c = reader.read().unwrap().unwrap();
            if c.shape_id != first.shape_id {
                seen = Some(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let arrow = seen.expect("the new cursor within a second");
        assert_eq!(arrow.shape.css, Some("default"));
        eprintln!(
            "x11-real: the X11 pointer reached the cursor channel (shape {}x{}, css {:?} then {:?})",
            first.shape.width, first.shape.height, first.shape.css, arrow.shape.css
        );
    }
}
