// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-16 L4 — the frame marker: a 12-bit number and a CRC-4, painted as a
//! 2×8 grid of 16×16 blocks inside an 8 px quiet margin.
//!
//! Why this shape: the old 1-px counter strip does not survive a lossy
//! encode. A 16×16 block of pure black or white (luma 16 / 235 after the
//! BT.601 conversion) does, through 4:2:0, a high QP and a 4× downscale,
//! and its centre still averages far from the 125 threshold. The CRC turns
//! a misread into a miss instead of a wrong number. The browser's decoder
//! (`ui/src/workers/rc-bench-marker.ts`) reads the same layout; this module
//! is the reference.
//!
//! Always compiled: the synthetic source paints it (re-exported as
//! `synthetic_backend::marker`), and so does `roomlerd probe-target`, the
//! L4 window a release build runs.

pub const BLOCK: u32 = 16;
pub const COLS: u32 = 8;
pub const ROWS: u32 = 2;
pub const MARGIN: u32 = 8;
/// The grid, without its margin.
pub const W: u32 = BLOCK * COLS;
pub const H: u32 = BLOCK * ROWS;
/// Luma threshold between a 0 block and a 1 block.
const THRESHOLD: u32 = 125;
/// A block whose centre averages inside this band around the threshold
/// is unreadable, not a guess.
const DEAD_BAND: u32 = 40;
/// The downscale factors a decoder tries, smallest first.
const SCALES: [u32; 3] = [1, 2, 4];

/// The sequence number a frame counter carries (12 bits, wrapping).
pub fn seq_of(counter: u64) -> u16 {
    (counter & 0x0FFF) as u16
}

/// CRC-4/ITU (x⁴ + x + 1, init 0) over the 12 bits, MSB first.
pub fn crc4(seq: u16) -> u8 {
    let mut crc: u8 = 0;
    for i in (0..12).rev() {
        let bit = ((seq >> i) & 1) as u8;
        let top = (crc >> 3) & 1;
        crc = (crc << 1) & 0x0F;
        if top ^ bit == 1 {
            crc ^= 0x03;
        }
    }
    crc
}

/// The 16-bit word painted: sequence (12 bits) then CRC (4 bits).
pub fn word(seq: u16) -> u16 {
    let s = seq & 0x0FFF;
    (s << 4) | crc4(s) as u16
}

/// Which corner a marker sits in. The frame's own sequence number is
/// bottom-left; the last bench probe the source saw is bottom-right
/// (FR-16 L4, `synthetic_backend::probe`; `roomlerd probe-target` paints
/// the same corner from real OS input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corner {
    BottomLeft,
    BottomRight,
}

/// The bottom-left grid's top-left corner in a `w × h` frame, or `None`
/// when the frame is too small to hold it with its margin.
pub fn origin(w: u32, h: u32) -> Option<(u32, u32)> {
    origin_at(Corner::BottomLeft, w, h)
}

/// [`origin`] for either corner. The bottom-right grid needs room for
/// both, so the two can never overlap.
pub fn origin_at(corner: Corner, w: u32, h: u32) -> Option<(u32, u32)> {
    let need_w = match corner {
        Corner::BottomLeft => W + 2 * MARGIN,
        Corner::BottomRight => 2 * (W + 2 * MARGIN),
    };
    if w < need_w || h < H + 2 * MARGIN {
        return None;
    }
    let x = match corner {
        Corner::BottomLeft => MARGIN,
        Corner::BottomRight => w - MARGIN - W,
    };
    Some((x, h - MARGIN - H))
}

/// Paint `seq` into a BGRA buffer's bottom-left corner, the quiet margin
/// as mid-grey.
pub fn paint_bgra(data: &mut [u8], w: u32, h: u32, stride: u32, seq: u16) {
    paint_bgra_at(Corner::BottomLeft, data, w, h, stride, seq);
}

/// [`paint_bgra`] into either corner.
pub fn paint_bgra_at(corner: Corner, data: &mut [u8], w: u32, h: u32, stride: u32, seq: u16) {
    let Some((ox, oy)) = origin_at(corner, w, h) else {
        return;
    };
    let word = word(seq);
    for y in (oy - MARGIN)..(oy + H + MARGIN) {
        for x in (ox - MARGIN)..(ox + W + MARGIN) {
            let inside = x >= ox && x < ox + W && y >= oy && y < oy + H;
            let v = if inside {
                let bit = ((y - oy) / BLOCK) * COLS + (x - ox) / BLOCK;
                if (word >> (15 - bit)) & 1 == 1 {
                    0xFF
                } else {
                    0x00
                }
            } else {
                0x80
            };
            let i = (y * stride + x * 4) as usize;
            data[i] = v;
            data[i + 1] = v;
            data[i + 2] = v;
            data[i + 3] = 0xFF;
        }
    }
}

/// Read the sequence number back from a decoded luma plane, trying each
/// downscale factor in [`SCALES`]. `None` when no factor yields a grid
/// whose every block is readable and whose CRC matches.
pub fn decode_luma(y: &[u8], w: u32, h: u32, stride: usize) -> Option<u16> {
    decode_luma_at(Corner::BottomLeft, y, w, h, stride)
}

/// [`decode_luma`] for either corner.
pub fn decode_luma_at(corner: Corner, y: &[u8], w: u32, h: u32, stride: usize) -> Option<u16> {
    SCALES
        .iter()
        .find_map(|&k| decode_at_scale(corner, y, w, h, stride, k))
}

fn decode_at_scale(corner: Corner, y: &[u8], w: u32, h: u32, stride: usize, k: u32) -> Option<u16> {
    // The marker sits MARGIN in from its side and the bottom of the
    // SOURCE frame; a k× downscale divides every coordinate by k.
    let block = BLOCK / k;
    let ox = match corner {
        Corner::BottomLeft => MARGIN / k,
        Corner::BottomRight => w.checked_sub((MARGIN + W) / k)?,
    };
    let oy = h.checked_sub((MARGIN + H) / k)?;
    if block < 4 || ox + W / k > w || oy + H / k > h {
        return None;
    }
    // The quiet margin anchors the scale: all four strips around the
    // grid must read mid-grey. At a wrong scale at least one lands on the
    // gradient or on the grid itself, and the dead band and the CRC are
    // then not the only guard against a lucky misread.
    if !margin_is_grey(y, w, h, stride, ox, oy, k) {
        return None;
    }
    // Sample each block's centre half, away from the edges where the
    // encoder's blocking and chroma bleed live.
    let inset = block / 4;
    let mut word: u16 = 0;
    for bit in 0..(ROWS * COLS) {
        let bx = ox + (bit % COLS) * block;
        let by = oy + (bit / COLS) * block;
        let (mut sum, mut n) = (0u32, 0u32);
        for yy in (by + inset)..(by + block - inset) {
            let row = yy as usize * stride;
            for xx in (bx + inset)..(bx + block - inset) {
                sum += *y.get(row + xx as usize)? as u32;
                n += 1;
            }
        }
        let mean = sum / n.max(1);
        if mean.abs_diff(THRESHOLD) < DEAD_BAND {
            return None;
        }
        word = (word << 1) | u16::from(mean > THRESHOLD);
    }
    let seq = word >> 4;
    (crc4(seq) == (word & 0x0F) as u8).then_some(seq)
}

/// Mid-grey (0x80 → luma ≈ 126 after BT.601), within this band.
const GREY: std::ops::RangeInclusive<u32> = 100..=152;

/// Are the centre lines of the four margin strips around the grid grey?
fn margin_is_grey(y: &[u8], w: u32, h: u32, stride: usize, ox: u32, oy: u32, k: u32) -> bool {
    let (gw, gh) = (W / k, H / k);
    let d = (MARGIN / k / 2).max(1);
    let (Some(left), right, Some(top), bottom) = (
        ox.checked_sub(d),
        ox + gw + d - 1,
        oy.checked_sub(d),
        oy + gh + d - 1,
    ) else {
        return false;
    };
    if right >= w || bottom >= h {
        return false;
    }
    let mean = |pts: &mut dyn Iterator<Item = (u32, u32)>| -> Option<u32> {
        let (mut sum, mut n) = (0u32, 0u32);
        for (xx, yy) in pts {
            sum += *y.get(yy as usize * stride + xx as usize)? as u32;
            n += 1;
        }
        (n > 0).then(|| sum / n)
    };
    [
        mean(&mut (oy..oy + gh).map(|yy| (left, yy))),
        mean(&mut (oy..oy + gh).map(|yy| (right, yy))),
        mean(&mut (ox..ox + gw).map(|xx| (xx, top))),
        mean(&mut (ox..ox + gw).map(|xx| (xx, bottom))),
    ]
    .into_iter()
    .all(|m| m.is_some_and(|m| GREY.contains(&m)))
}
