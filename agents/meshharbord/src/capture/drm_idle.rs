// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-93 P3d — an idle desktop's DRM frames, skipped.
//!
//! DRM reports nothing about which pixels changed, so the DRM arm read,
//! converted and encoded the whole scanout buffer at the target frame rate on
//! a desktop nobody touched: **57.9 % of a core** for the FR-93 lab's idle
//! GNOME 50 desktop (1280×800, 0.4.133), where FR-29's X11 damage tracking
//! idles at 3.4 %.
//!
//! A Wayland compositor gives the signal damage would have. It never draws into
//! the buffer on screen: it draws the next frame into another buffer and flips
//! to it, so the primary plane's buffer changes when the picture does. The DRM
//! worker (`drm_backend.rs`) skips a frame, which the pump takes as an idle
//! screen, when all three hold:
//!
//! - the plane shows the same framebuffer over the same buffer as the last
//!   frame delivered. The buffer is named by its dma-buf's inode, because the
//!   kernel reuses a framebuffer id for a new buffer once the old one is gone;
//! - [`SAMPLE_ROWS`] rows spread down the picture hash the same as they did. A
//!   compositor that flips twice between two reads (A → B → A) shows the same
//!   buffer again with new pixels, and the rows see any change that crosses
//!   one of them;
//! - the last frame delivered is younger than [`MAX_SKIP`]. A change that
//!   crosses no sampled row waits at most that long: FR-29's bound for X11.
//!
//! A skip is not reported to the pump at once. `next_frame` goes on asking at
//! the frame rate and says "nothing this tick" after [`IDLE_WAIT`] of
//! unchanged frames, as the portal arm does on a still stream. The pump answers
//! each "nothing" with a keepalive re-encode of its last frame, so one every
//! frame period would spend on keepalives most of what the skip saves.
//!
//! ⚠️ **An X server draws in place** (FR-113 P1, [`IdleSkip::InPlace`]). It and
//! the kernel console draw into the buffer on screen, so its identity never
//! changes and only the sampled rows can see a change. 32 rows would leave a
//! typed character waiting up to [`MAX_SKIP`], so an X11 seat's gate samples a
//! row every [`IN_PLACE_ROW_GAP`] rows instead: a change that tall is seen on
//! the next tick wherever it lands, and the text caret (which moves on every
//! keystroke) is that tall. The console gets no gate at all
//! ([`IdleSkip::Off`]).
//!
//! Everything here is pure, so it is pinned by tests with no DRM device.

use std::time::{Duration, Instant};

/// The longest a frame is skipped for: a change no sampled row crosses is
/// delivered this late at worst. FR-29's bound for the X11 damage skip.
pub const MAX_SKIP: Duration = Duration::from_millis(1000);

/// How long `next_frame` waits out a still screen before it tells the pump
/// "nothing this tick": the portal arm's `FRAME_WAIT`, so every Wayland arm
/// meets the pump the same way. The pump answers each "nothing" with a
/// keepalive re-encode of its last frame (every 60 ms at most on the data
/// channel pumps), so answering every frame period would trade the frames this
/// skips for as many keepalives. A change inside the wait is still delivered
/// within a frame period.
pub const IDLE_WAIT: Duration = Duration::from_millis(250);

/// How many rows the change check hashes on a Wayland seat, spread evenly down
/// the picture. 32 rows of a 1280-pixel scanout is 160 KiB a tick, against the
/// 4 MiB a delivered frame copies.
pub const SAMPLE_ROWS: u32 = 32;

/// FR-113 P1 — on an X11 seat, at most this many rows apart, so a change at
/// least this tall crosses a sampled row wherever it lands and is delivered on
/// the next tick. The text caret (16 px or more at 1×) moves on every
/// keystroke, so typing is seen at once; a smaller change waits [`MAX_SKIP`]
/// at worst. The cost is an eighth of the rows a tick (512 KiB of a 1280×800
/// scanout), against the whole picture a delivered frame reads, converts and
/// encodes.
pub const IN_PLACE_ROW_GAP: u32 = 8;

/// How the DRM worker may skip a frame nothing changed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleSkip {
    /// Every frame is read: the kill switch (`ROOMLERD_DRM_IDLE_SKIP=0`), the
    /// console, or an X11 seat with `x11_auto_system = false` (0.4.143 read
    /// every frame there, and that switch gives 0.4.143 back).
    Off,
    /// A Wayland seat (FR-93 P3d): the compositor flips, so the buffer and
    /// [`SAMPLE_ROWS`] rows tell.
    Flips,
    /// An X11 seat (FR-113 P1): drawn in place, so rows alone, one every
    /// [`IN_PLACE_ROW_GAP`].
    InPlace,
}

impl IdleSkip {
    /// The gate this mode runs, `None` for [`IdleSkip::Off`].
    pub fn gate(self) -> Option<IdleGate> {
        match self {
            IdleSkip::Off => None,
            IdleSkip::Flips => Some(IdleGate::default()),
            IdleSkip::InPlace => Some(IdleGate {
                last: None,
                in_place: true,
            }),
        }
    }
}

/// What the primary plane showed on one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shown {
    /// The framebuffer id on the plane.
    pub fb: u32,
    /// The buffer under it: its dma-buf's inode, `0` when unknown (an old
    /// kernel, or a failed `fstat`), which leaves the framebuffer id and the
    /// rows to tell buffers apart.
    pub buffer: u64,
    /// [`sample_rows`] of its pixels.
    pub rows: u64,
}

/// Whether a tick may be skipped: the last delivered frame, and when.
#[derive(Debug, Default)]
pub struct IdleGate {
    last: Option<(Shown, Instant)>,
    /// FR-113 P1 — an X11 seat's gate ([`IdleSkip::InPlace`]): dense rows.
    in_place: bool,
}

impl IdleGate {
    /// How many rows this gate's check hashes for a `height`-row picture:
    /// [`SAMPLE_ROWS`], or on an X11 seat one every [`IN_PLACE_ROW_GAP`].
    pub fn rows(&self, height: u32) -> u32 {
        if self.in_place {
            height.div_ceil(IN_PLACE_ROW_GAP).min(height)
        } else {
            SAMPLE_ROWS.min(height)
        }
    }

    /// Whether a tick that shows `shown` at `now` may be skipped: the same
    /// framebuffer, buffer and rows as the last frame delivered, and that frame
    /// younger than [`MAX_SKIP`].
    pub fn unchanged(&self, shown: Shown, now: Instant) -> bool {
        match self.last {
            Some((last, at)) => last == shown && now.saturating_duration_since(at) < MAX_SKIP,
            None => false,
        }
    }

    /// A frame showing `shown` went out at `now`.
    pub fn delivered(&mut self, shown: Shown, now: Instant) {
        self.last = Some((shown, now));
    }

    /// Nothing is scanned out (a blanked panel, a mode change): whatever shows
    /// next is delivered.
    pub fn forget(&mut self) {
        self.last = None;
    }
}

/// A hash of [`SAMPLE_ROWS`] rows of a `height`-row picture whose rows start
/// `pitch` bytes apart, hashing the first `row_bytes` of each: the visible
/// pixels, never the pitch's padding, which may hold anything.
///
/// The rows are the centres of [`SAMPLE_ROWS`] equal bands, so the picture's
/// top and bottom are both covered. Each 8-byte word goes through
/// `h = (h ^ word) * FNV_PRIME`, a bijection of `h` for a given word: two
/// inputs that differ in a single word always hash apart.
pub fn sample_rows(src: &[u8], row_bytes: usize, height: u32, pitch: u32) -> u64 {
    sample_rows_n(src, row_bytes, height, pitch, SAMPLE_ROWS)
}

/// [`sample_rows`] over `n` rows (at most `height`), the centres of `n` equal
/// bands: [`IdleGate::rows`] says how many.
pub fn sample_rows_n(src: &[u8], row_bytes: usize, height: u32, pitch: u32, n: u32) -> u64 {
    let mut h = FNV_OFFSET;
    let n = n.min(height);
    for i in 0..n {
        let start = sampled_row(i, n, height) * pitch as usize;
        let Some(row) = src.get(start..start + row_bytes) else {
            break;
        };
        h = mix(h, row);
    }
    h
}

/// The `i`-th of `n` sampled rows of a `height`-row picture: the centre of the
/// `i`-th of `n` equal bands.
fn sampled_row(i: u32, n: u32, height: u32) -> usize {
    (u64::from(2 * i + 1) * u64::from(height) / u64::from(2 * n)) as usize
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn mix(mut h: u64, bytes: &[u8]) -> u64 {
    let mut words = bytes.chunks_exact(8);
    for word in &mut words {
        let mut w = [0u8; 8];
        w.copy_from_slice(word);
        h = (h ^ u64::from_le_bytes(w)).wrapping_mul(FNV_PRIME);
    }
    for &b in words.remainder() {
        h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(fb: u32, buffer: u64, rows: u64) -> Shown {
        Shown { fb, buffer, rows }
    }

    #[test]
    fn a_tick_is_skipped_only_when_framebuffer_buffer_and_rows_all_match() {
        let t0 = Instant::now();
        let mut gate = IdleGate::default();
        let a = shown(31, 1001, 0xabc);
        assert!(!gate.unchanged(a, t0), "nothing delivered yet: deliver");
        gate.delivered(a, t0);
        let soon = t0 + Duration::from_millis(33);
        assert!(gate.unchanged(a, soon));
        // A flip to another framebuffer.
        assert!(!gate.unchanged(shown(32, 1002, 0xabc), soon));
        // The framebuffer id reused for a new buffer (FR-93 §2.3 #6).
        assert!(!gate.unchanged(shown(31, 1003, 0xabc), soon));
        // A → B → A between two reads: the same buffer, new pixels.
        assert!(!gate.unchanged(shown(31, 1001, 0xdef), soon));
    }

    #[test]
    fn no_frame_is_skipped_past_max_skip() {
        let t0 = Instant::now();
        let mut gate = IdleGate::default();
        let a = shown(31, 1001, 0xabc);
        gate.delivered(a, t0);
        assert!(gate.unchanged(a, t0 + MAX_SKIP - Duration::from_millis(1)));
        assert!(!gate.unchanged(a, t0 + MAX_SKIP), "the bound delivers");
        gate.delivered(a, t0 + MAX_SKIP);
        assert!(
            gate.unchanged(a, t0 + MAX_SKIP + Duration::from_millis(33)),
            "and the bound restarts from that delivery"
        );
    }

    #[test]
    fn after_nothing_was_scanned_out_the_next_frame_is_delivered() {
        let t0 = Instant::now();
        let mut gate = IdleGate::default();
        let a = shown(31, 1001, 0xabc);
        gate.delivered(a, t0);
        gate.forget();
        assert!(!gate.unchanged(a, t0 + Duration::from_millis(33)));
    }

    /// A `height`-row XRGB picture `width` pixels wide, rows `pitch` bytes
    /// apart, every byte set from its position.
    fn picture(width: usize, height: usize, pitch: usize) -> Vec<u8> {
        let mut v = vec![0u8; pitch * height];
        for y in 0..height {
            for x in 0..width * 4 {
                v[y * pitch + x] = (y * 7 + x * 13) as u8;
            }
        }
        v
    }

    /// The rows [`sample_rows`] reads for a `height`-row picture.
    fn sampled(height: u32) -> Vec<usize> {
        let n = SAMPLE_ROWS.min(height);
        (0..n).map(|i| sampled_row(i, n, height)).collect()
    }

    #[test]
    fn a_change_on_a_sampled_row_changes_the_hash_wherever_it_lands_in_the_row() {
        // 63 pixels: 252 bytes a row, 31 whole words and a 4-byte remainder.
        let (w, h, pitch) = (63usize, 96u32, 63 * 4 + 36);
        let base = picture(w, h as usize, pitch);
        let before = sample_rows(&base, w * 4, h, pitch as u32);
        for &y in &sampled(h) {
            // The first byte, one in the last whole word, and both ends of the
            // trailing partial word all count.
            for x in [0, w * 4 - 5, w * 4 - 4, w * 4 - 1] {
                let mut p = base.clone();
                p[y * pitch + x] ^= 0x40;
                assert_ne!(
                    sample_rows(&p, w * 4, h, pitch as u32),
                    before,
                    "row {y}, byte {x}"
                );
            }
        }
    }

    #[test]
    fn the_pitch_padding_and_unsampled_rows_are_not_read() {
        let (w, h, pitch) = (64usize, 96u32, 64 * 4 + 32);
        let base = picture(w, h as usize, pitch);
        let before = sample_rows(&base, w * 4, h, pitch as u32);
        let rows = sampled(h);
        let mut p = base.clone();
        for y in 0..h as usize {
            // The padding past the visible pixels, on every row.
            for x in w * 4..pitch {
                p[y * pitch + x] = !p[y * pitch + x];
            }
            // A row no sample lands on, in full.
            if !rows.contains(&y) {
                for x in 0..w * 4 {
                    p[y * pitch + x] = !p[y * pitch + x];
                }
            }
        }
        assert_eq!(sample_rows(&p, w * 4, h, pitch as u32), before);
    }

    #[test]
    fn the_samples_span_the_picture_and_never_repeat_a_row() {
        for h in [1u32, 2, 31, 32, 33, 768, 800, 1080, 2160] {
            let rows = sampled(h);
            assert_eq!(rows.len(), SAMPLE_ROWS.min(h) as usize, "height {h}");
            assert!(rows.windows(2).all(|r| r[0] < r[1]), "height {h}: {rows:?}");
            assert!(*rows.last().unwrap() < h as usize, "height {h}");
            // The first and last bands' centres: within one band of each edge.
            let band = (h as usize).div_ceil(SAMPLE_ROWS.min(h) as usize);
            assert!(rows[0] <= band, "height {h}: first row {}", rows[0]);
            assert!(
                h as usize - 1 - rows.last().unwrap() <= band,
                "height {h}: last row {}",
                rows.last().unwrap()
            );
        }
    }

    /// FR-113 P1 — on an X11 seat the X server draws in place, so a change
    /// must be SEEN by the rows: any band at least [`IN_PLACE_ROW_GAP`] rows
    /// tall, wherever it lands (the caret moving on a keystroke is one), must
    /// cross a sampled row. Every height a scanout plausibly has, every start.
    #[test]
    fn on_an_x11_seat_any_change_a_gap_tall_crosses_a_sampled_row() {
        let gate = IdleSkip::InPlace.gate().expect("an X11 seat runs a gate");
        for h in [
            1u32, 7, 8, 9, 63, 600, 768, 800, 1012, 1080, 1440, 1600, 2160,
        ] {
            let n = gate.rows(h);
            let rows: Vec<usize> = (0..n).map(|i| sampled_row(i, n, h)).collect();
            assert!(rows.windows(2).all(|r| r[0] < r[1]), "height {h}");
            for start in 0..h.saturating_sub(IN_PLACE_ROW_GAP - 1) as usize {
                let band = start..start + IN_PLACE_ROW_GAP as usize;
                assert!(
                    rows.iter().any(|r| band.contains(r)),
                    "height {h}: rows {band:?} cross no sampled row"
                );
            }
        }
    }

    /// The same, end to end through the hash: a caret-sized change (2 px
    /// wide, a gap tall) anywhere in an X11 seat's picture changes it.
    #[test]
    fn on_an_x11_seat_a_caret_sized_change_changes_the_hash() {
        let gate = IdleSkip::InPlace.gate().unwrap();
        let (w, h, pitch) = (320usize, 200u32, 320 * 4 + 64);
        let base = picture(w, h as usize, pitch);
        let n = gate.rows(h);
        let before = sample_rows_n(&base, w * 4, h, pitch as u32, n);
        for top in 0..(h - IN_PLACE_ROW_GAP) as usize {
            let mut p = base.clone();
            for y in top..top + IN_PLACE_ROW_GAP as usize {
                for x in 100 * 4..102 * 4 {
                    p[y * pitch + x] = !p[y * pitch + x];
                }
            }
            assert_ne!(
                sample_rows_n(&p, w * 4, h, pitch as u32, n),
                before,
                "a caret at rows {top}.. was missed"
            );
        }
    }

    /// The modes: no gate at all with the switch off, the Wayland gate as
    /// FR-93 P3d left it, and the X11 gate's row count.
    #[test]
    fn each_mode_runs_its_own_gate() {
        assert!(IdleSkip::Off.gate().is_none());
        let flips = IdleSkip::Flips.gate().unwrap();
        assert_eq!(flips.rows(800), SAMPLE_ROWS);
        assert_eq!(flips.rows(20), 20, "never more rows than the picture has");
        let in_place = IdleSkip::InPlace.gate().unwrap();
        assert_eq!(in_place.rows(800), 100);
        assert_eq!(in_place.rows(2160), 270);
        assert_eq!(in_place.rows(5), 1);
        // The Wayland hash is the one P3d shipped, row for row.
        let (w, h, pitch) = (64usize, 96u32, 64 * 4);
        let p = picture(w, h as usize, pitch);
        assert_eq!(
            sample_rows_n(&p, w * 4, h, pitch as u32, flips.rows(h)),
            sample_rows(&p, w * 4, h, pitch as u32)
        );
    }

    #[test]
    fn a_short_buffer_hashes_what_it_has_instead_of_panicking() {
        // A pitch × height larger than the mapping: the rows past its end are
        // left out rather than read.
        let (w, h, pitch) = (16usize, 64u32, 16 * 4);
        let full = picture(w, h as usize, pitch);
        let short = &full[..pitch * 10];
        let _ = sample_rows(short, w * 4, h, pitch as u32);
        assert_eq!(sample_rows(&[], w * 4, h, pitch as u32), FNV_OFFSET);
    }
}
