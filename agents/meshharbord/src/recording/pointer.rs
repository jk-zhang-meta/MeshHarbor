// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P1d — drawing the pointer into a recording, for the backends that
//! cannot (DXGI, X11; see `capture::pointer` for who draws it where).
//!
//! The pointer is drawn on the recorder's tick, NOT on the capture: a
//! pointer that moves over a still screen produces no new capture at all
//! (DXGI and X11's damage tracking both report "unchanged"), and a recording
//! that drew it only on new captures would show it frozen until something
//! else on screen changed.
//!
//! So the layer keeps a canvas: the latest capture with the pointer drawn on
//! it, and the pixels the pointer covers. Each tick asks the source where the
//! pointer is; if it moved, the covered pixels go back and the pointer is
//! drawn at its new place. A still pointer on a still screen costs nothing.
//!
//! ⚠️ The encoder may still hold the frame it was handed on the previous
//! tick. The canvas is changed through `Arc::make_mut`, so a frame someone
//! else holds is copied first and never written under them.

use std::sync::Arc;

use crate::capture::pointer::{PointerSample, PointerSource};
use crate::capture::{Frame, PixelFormat};

/// The pixels the drawn pointer covers, to put back before it moves.
struct Covered {
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    /// `w * 4` bytes per row, `h` rows.
    pixels: Vec<u8>,
}

/// What is drawn: position and shape. While it has not changed, a tick does
/// nothing.
type Drawn = Option<(i32, i32, u64)>;

pub struct PointerLayer {
    source: Box<dyn PointerSource>,
    /// The latest capture, with the pointer drawn on it.
    canvas: Arc<Frame>,
    covered: Option<Covered>,
    drawn: Drawn,
    /// Logged once: a frame that is not BGRA is recorded as it comes.
    warned_format: bool,
}

impl PointerLayer {
    pub fn new(source: Box<dyn PointerSource>, first: Arc<Frame>) -> Self {
        Self {
            source,
            canvas: first,
            covered: None,
            drawn: None,
            warned_format: false,
        }
    }

    /// A new capture. It replaces the canvas; the pointer is drawn on it at
    /// the next [`Self::frame`].
    ///
    /// ⚠️ The covered pixels belong to the OLD capture and are dropped with
    /// it. Putting them back into the new one would paint a patch of the
    /// past over the present.
    pub fn replace(&mut self, frame: Arc<Frame>) {
        self.canvas = frame;
        self.covered = None;
        self.drawn = None;
    }

    /// The frame to encode now: the latest capture, with the pointer where
    /// it is now.
    pub fn frame(&mut self) -> Arc<Frame> {
        let sample = self.source.poll();
        self.frame_with(sample)
    }

    fn frame_with(&mut self, sample: Option<PointerSample>) -> Arc<Frame> {
        if self.canvas.pixel_format != PixelFormat::Bgra {
            if !self.warned_format {
                self.warned_format = true;
                tracing::warn!(
                    format = ?self.canvas.pixel_format,
                    "recording: the capture is not BGRA — recording it without the pointer"
                );
            }
            return self.canvas.clone();
        }
        let sample = sample.map(|s| scaled(s, &self.canvas));
        let want: Drawn = sample.as_ref().map(|s| (s.x, s.y, s.shape_id));
        if want == self.drawn {
            return self.canvas.clone();
        }
        // Copies the frame only if the encoder still holds it.
        let canvas = Arc::make_mut(&mut self.canvas);
        if let Some(c) = self.covered.take() {
            put_back(canvas, &c);
        }
        if let Some(s) = &sample {
            self.covered = draw(canvas, s);
        }
        self.drawn = want;
        self.canvas.clone()
    }
}

/// A frame scaled on the way out (`Frame::source` set) takes the pointer's
/// position through the same ratio. The shape itself is drawn at its own
/// size. The recorder asks for native frames, so this is a guard, not a path.
fn scaled(mut s: PointerSample, f: &Frame) -> PointerSample {
    let (nw, nh) = f.native_dims();
    if (nw, nh) != (f.width, f.height) && nw > 0 && nh > 0 {
        s.x = (i64::from(s.x) * i64::from(f.width) / i64::from(nw)) as i32;
        s.y = (i64::from(s.y) * i64::from(f.height) / i64::from(nh)) as i32;
    }
    s
}

/// The part of a `w × h` shape at (`x`, `y`) that lies inside the frame:
/// (first frame column, first frame row, first shape column, first shape
/// row, width, height). `None` when none of it does.
fn clip(
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    fw: u32,
    fh: u32,
) -> Option<(usize, usize, usize, usize, usize, usize)> {
    let (x, y, w, h, fw, fh) = (
        i64::from(x),
        i64::from(y),
        i64::from(w),
        i64::from(h),
        i64::from(fw),
        i64::from(fh),
    );
    let x0 = x.max(0);
    let y0 = y.max(0);
    let x1 = (x + w).min(fw);
    let y1 = (y + h).min(fh);
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    Some((
        x0 as usize,
        y0 as usize,
        (x0 - x) as usize,
        (y0 - y) as usize,
        (x1 - x0) as usize,
        (y1 - y0) as usize,
    ))
}

/// Draw `s` over the frame (premultiplied "over"), returning the pixels it
/// covered.
fn draw(f: &mut Frame, s: &PointerSample) -> Option<Covered> {
    let shape = &s.shape;
    let (fx, fy, sx, sy, w, h) = clip(s.x, s.y, shape.width, shape.height, f.width, f.height)?;
    let stride = f.stride as usize;
    let sw = shape.width as usize;
    // Both buffers are checked whole BEFORE a pixel changes: a draw that
    // stopped halfway would leave part of a pointer that nothing puts back.
    let frame_end = (fy + h - 1) * stride + (fx + w) * 4;
    let shape_end = ((sy + h - 1) * sw + sx + w) * 4;
    if f.data.len() < frame_end || shape.bgra.len() < shape_end {
        return None;
    }
    let mut pixels = Vec::with_capacity(w * h * 4);
    for row in 0..h {
        let start = (fy + row) * stride + fx * 4;
        let dst = &mut f.data[start..start + w * 4];
        pixels.extend_from_slice(dst);
        let src_start = ((sy + row) * sw + sx) * 4;
        let src = &shape.bgra[src_start..src_start + w * 4];
        for (d, p) in dst.chunks_exact_mut(4).zip(src.chunks_exact(4)) {
            let a = u32::from(p[3]);
            if a == 0 {
                continue;
            }
            let keep = 255 - a;
            for (dc, &pc) in d[..3].iter_mut().zip(&p[..3]) {
                // Saturating: a malformed "premultiplied" pixel whose colour
                // exceeds its alpha must not wrap to a dark speck.
                let v = u32::from(pc) + (u32::from(*dc) * keep + 127) / 255;
                *dc = v.min(255) as u8;
            }
        }
    }
    Some(Covered {
        x: fx,
        y: fy,
        w,
        h,
        pixels,
    })
}

fn put_back(f: &mut Frame, c: &Covered) {
    let stride = f.stride as usize;
    for row in 0..c.h {
        let start = (c.y + row) * stride + c.x * 4;
        let src = &c.pixels[row * c.w * 4..(row + 1) * c.w * 4];
        if let Some(dst) = f.data.get_mut(start..start + c.w * 4) {
            dst.copy_from_slice(src);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Damage;
    use crate::capture::pointer::PointerShape;
    use std::sync::Mutex;

    const W: u32 = 16;
    const H: u32 = 12;

    fn frame(fill: u8, stride_pad: u32) -> Frame {
        let stride = W * 4 + stride_pad;
        Frame {
            width: W,
            height: H,
            stride,
            pixel_format: PixelFormat::Bgra,
            data: vec![fill; (stride * H) as usize],
            monotonic_us: 0,
            monitor: 0,
            damage: Damage::Unknown,
            source: None,
        }
    }

    /// An opaque white `n × n` square.
    fn square(n: u32) -> Arc<PointerShape> {
        Arc::new(PointerShape {
            width: n,
            height: n,
            bgra: vec![0xFF; (n * n * 4) as usize],
        })
    }

    fn at(x: i32, y: i32, id: u64, shape: &Arc<PointerShape>) -> Option<PointerSample> {
        Some(PointerSample {
            x,
            y,
            shape_id: id,
            shape: shape.clone(),
        })
    }

    fn px(f: &Frame, x: u32, y: u32) -> [u8; 4] {
        let i = (y * f.stride + x * 4) as usize;
        [f.data[i], f.data[i + 1], f.data[i + 2], f.data[i + 3]]
    }

    /// A source that answers from a script and counts its polls.
    struct Script(Arc<Mutex<Vec<Option<PointerSample>>>>, Arc<Mutex<usize>>);

    impl PointerSource for Script {
        fn poll(&mut self) -> Option<PointerSample> {
            *self.1.lock().unwrap() += 1;
            let mut q = self.0.lock().unwrap();
            if q.len() > 1 {
                q.remove(0)
            } else {
                q[0].clone()
            }
        }
    }

    fn layer_on(f: Frame) -> PointerLayer {
        PointerLayer::new(
            Box::new(Script(
                Arc::new(Mutex::new(vec![None])),
                Arc::new(Mutex::new(0)),
            )),
            Arc::new(f),
        )
    }

    #[test]
    fn the_pointer_is_drawn_where_the_source_says_and_nowhere_else() {
        let mut l = layer_on(frame(0x40, 0));
        let s = square(3);
        let out = l.frame_with(at(5, 4, 1, &s));
        for y in 0..H {
            for x in 0..W {
                let inside = (5..8).contains(&x) && (4..7).contains(&y);
                let want = if inside { 0xFF } else { 0x40 };
                assert_eq!(px(&out, x, y)[..3], [want; 3], "at ({x}, {y})");
            }
        }
    }

    #[test]
    fn a_translucent_pointer_blends_over_the_frame() {
        let mut l = layer_on(frame(0x00, 0));
        // 50 % white, premultiplied: (128, 128, 128, 128).
        let half = Arc::new(PointerShape {
            width: 1,
            height: 1,
            bgra: vec![128, 128, 128, 128],
        });
        let out = l.frame_with(at(0, 0, 1, &half));
        assert_eq!(px(&out, 0, 0)[..3], [128; 3]);
        let mut l = layer_on(frame(0xFF, 0));
        let out = l.frame_with(at(0, 0, 1, &half));
        assert_eq!(px(&out, 0, 0)[..3], [255; 3]);
        // A transparent pixel leaves the frame exactly as it was.
        let clear = Arc::new(PointerShape {
            width: 1,
            height: 1,
            bgra: vec![0, 0, 0, 0],
        });
        let mut l = layer_on(frame(0x33, 0));
        let out = l.frame_with(at(0, 0, 1, &clear));
        assert_eq!(px(&out, 0, 0)[..3], [0x33; 3]);
    }

    #[test]
    fn a_malformed_pixel_saturates_instead_of_wrapping() {
        // Colour above its alpha: not valid premultiplied, and it must not
        // wrap around to a dark speck.
        let bad = Arc::new(PointerShape {
            width: 1,
            height: 1,
            bgra: vec![250, 250, 250, 10],
        });
        let mut l = layer_on(frame(0xF0, 0));
        let out = l.frame_with(at(0, 0, 1, &bad));
        assert_eq!(px(&out, 0, 0)[..3], [255; 3]);
    }

    #[test]
    fn moving_the_pointer_leaves_no_trail() {
        let base = frame(0x40, 0);
        let mut l = layer_on(base.clone());
        let s = square(3);
        let _ = l.frame_with(at(1, 1, 1, &s));
        let moved = l.frame_with(at(10, 6, 1, &s));
        // The same pointer drawn once, at the new place, on a clean frame.
        let mut reference = layer_on(base);
        let expect = reference.frame_with(at(10, 6, 1, &s));
        assert_eq!(moved.data, expect.data);
    }

    #[test]
    fn hiding_the_pointer_gives_back_the_frame_exactly() {
        let mut f = frame(0, 0);
        for (i, b) in f.data.iter_mut().enumerate() {
            *b = (i * 7 % 251) as u8;
        }
        let original = f.data.clone();
        let mut l = layer_on(f);
        let _ = l.frame_with(at(2, 2, 1, &square(4)));
        let hidden = l.frame_with(None);
        assert_eq!(hidden.data, original);
    }

    #[test]
    fn a_pointer_over_an_edge_is_clipped_never_wrapped() {
        let s = square(4);
        for (x, y) in [(-2, -2), (14, 10), (-3, 5), (5, -3), (14, 0), (0, 10)] {
            let mut l = layer_on(frame(0x40, 0));
            let out = l.frame_with(at(x, y, 1, &s));
            for fy in 0..H {
                for fx in 0..W {
                    let (fx_i, fy_i) = (fx as i32, fy as i32);
                    let inside = fx_i >= x && fx_i < x + 4 && fy_i >= y && fy_i < y + 4;
                    let want = if inside { 0xFF } else { 0x40 };
                    assert_eq!(
                        px(&out, fx, fy)[..3],
                        [want; 3],
                        "pointer at ({x}, {y}), pixel ({fx}, {fy})"
                    );
                }
            }
        }
        // Wholly outside: nothing drawn, nothing covered, no panic.
        let mut l = layer_on(frame(0x40, 0));
        for (x, y) in [(-4, 0), (16, 0), (0, -4), (0, 12), (i32::MIN, i32::MAX)] {
            let out = l.frame_with(at(x, y, 1, &s));
            assert!(out.data.iter().all(|&b| b == 0x40), "at ({x}, {y})");
        }
    }

    #[test]
    fn row_padding_is_respected() {
        // A stride wider than the row: the pointer's second row must land on
        // the frame's second row, not in the padding.
        let mut l = layer_on(frame(0x40, 12));
        let out = l.frame_with(at(0, 0, 1, &square(2)));
        assert_eq!(px(&out, 0, 1)[..3], [0xFF; 3]);
        assert_eq!(px(&out, 1, 1)[..3], [0xFF; 3]);
        assert_eq!(px(&out, 2, 1)[..3], [0x40; 3]);
        let pad = (W * 4) as usize;
        assert!(out.data[pad..pad + 12].iter().all(|&b| b == 0x40));
    }

    #[test]
    fn a_still_pointer_on_a_still_screen_costs_nothing() {
        let mut l = layer_on(frame(0x40, 0));
        let s = square(3);
        let a = l.frame_with(at(4, 4, 1, &s));
        let b = l.frame_with(at(4, 4, 1, &s));
        assert!(
            Arc::ptr_eq(&a, &b),
            "an unchanged pointer re-used the frame"
        );
        // A new shape at the same place IS a change.
        let c = l.frame_with(at(4, 4, 2, &square(2)));
        assert!(!Arc::ptr_eq(&b, &c));
    }

    #[test]
    fn the_frame_the_encoder_still_holds_is_never_written() {
        let mut l = layer_on(frame(0x40, 0));
        let s = square(3);
        let held = l.frame_with(at(1, 1, 1, &s));
        let before = held.data.clone();
        let next = l.frame_with(at(9, 5, 1, &s));
        assert_eq!(
            held.data, before,
            "a frame the encoder holds was changed under it"
        );
        assert_eq!(px(&next, 9, 5)[..3], [0xFF; 3]);
        assert_eq!(px(&next, 1, 1)[..3], [0x40; 3]);
    }

    #[test]
    fn a_new_capture_is_not_patched_with_the_old_ones_pixels() {
        let mut l = layer_on(frame(0x40, 0));
        let s = square(3);
        let _ = l.frame_with(at(2, 2, 1, &s));
        // The screen changed under the pointer; the pointer moved too.
        l.replace(Arc::new(frame(0x90, 0)));
        let out = l.frame_with(at(10, 6, 1, &s));
        assert_eq!(
            px(&out, 2, 2)[..3],
            [0x90; 3],
            "the old capture's pixels were put back into the new one"
        );
        assert_eq!(px(&out, 10, 6)[..3], [0xFF; 3]);
    }

    #[test]
    fn a_new_capture_gets_the_pointer_even_when_it_did_not_move() {
        let mut l = layer_on(frame(0x40, 0));
        let s = square(3);
        let _ = l.frame_with(at(2, 2, 1, &s));
        l.replace(Arc::new(frame(0x90, 0)));
        let out = l.frame_with(at(2, 2, 1, &s));
        assert_eq!(px(&out, 2, 2)[..3], [0xFF; 3]);
        assert_eq!(px(&out, 6, 6)[..3], [0x90; 3]);
    }

    #[test]
    fn a_frame_that_is_not_bgra_is_recorded_as_it_comes() {
        let mut f = frame(0x40, 0);
        f.pixel_format = PixelFormat::Nv12;
        let mut l = layer_on(f);
        let out = l.frame_with(at(0, 0, 1, &square(3)));
        assert!(out.data.iter().all(|&b| b == 0x40));
    }

    #[test]
    fn a_scaled_frame_takes_the_pointer_through_the_same_ratio() {
        let mut f = frame(0x40, 0);
        f.source = Some((W * 2, H * 2));
        let mut l = layer_on(f);
        let out = l.frame_with(at(10, 8, 1, &square(1)));
        assert_eq!(px(&out, 5, 4)[..3], [0xFF; 3]);
    }

    #[test]
    fn each_frame_asks_the_source_once() {
        let polls = Arc::new(Mutex::new(0));
        let s = square(2);
        let mut l = PointerLayer::new(
            Box::new(Script(
                Arc::new(Mutex::new(vec![at(0, 0, 1, &s), at(3, 3, 1, &s)])),
                polls.clone(),
            )),
            Arc::new(frame(0x40, 0)),
        );
        let a = l.frame();
        let b = l.frame();
        assert_eq!(*polls.lock().unwrap(), 2);
        assert_eq!(px(&a, 0, 0)[..3], [0xFF; 3]);
        assert_eq!(px(&b, 3, 3)[..3], [0xFF; 3]);
        assert_eq!(px(&b, 0, 0)[..3], [0x40; 3]);
    }
}
