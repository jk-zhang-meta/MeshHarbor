// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P3c-ii — the frame wire format between the helper and the daemon.
//!
//! [P3c-i](super::pipewire) proved frames arrive in the helper. They still have
//! to reach the daemon, which is where `ScreenCapture` lives.
//!
//! ## Why a pipe and a copy, not `SCM_RIGHTS` and none
//!
//! The FR-45 plan said "buffer fds over `SCM_RIGHTS` once at negotiation, then
//! a ready-message per frame". That is the right *optimisation*, and it is not
//! the right first version:
//!
//! 1. [`crate::capture::Frame`] owns a `Vec<u8>`. The daemon copies into one no
//!    matter how the bytes get there, so passing fds saves the helper→daemon
//!    copy only — not "zero copy" end to end.
//! 2. Passing the compositor's own buffers means the helper **must not** queue
//!    them back until the daemon has finished reading, or the compositor
//!    overwrites pixels mid-read. That is a per-frame round trip and a stall
//!    the compositor can see. Getting it wrong produces *torn frames*, which
//!    look like a codec bug and are miserable to trace.
//!
//! So: one copy out of the PipeWire buffer, framed on the helper's **stdout**,
//! one copy into a `Frame`. Simple, correct, and measurable. If the copy ever
//! shows up in a measurement, shared memory is the fix — and by then there will
//! be a number saying so, rather than an assumption.
//!
//! ⚠️ **stdout is binary after the handshake line; diagnostics go to stderr.**
//! Exactly the rule the SSH subsystem already documents for `sftp-server` —
//! injected text corrupts a binary transfer, and here it would corrupt a frame.

/// Marks the start of a frame header, so a desynchronised reader fails loudly
/// at the next boundary instead of interpreting pixels as a length.
pub const MAGIC: [u8; 4] = *b"RPWF";

/// A frame header. Fixed size, native endian — both ends are the same process
/// tree on the same machine, and byte-swapping would only add a way to be
/// wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    /// `enum spa_video_format` — carried through so the daemon maps it to a
    /// [`crate::capture::PixelFormat`] rather than assuming BGRx.
    pub video_format: u32,
    /// Payload length that follows this header.
    pub len: u32,
}

/// Header bytes on the wire: magic + five `u32`s.
pub const HEADER_LEN: usize = 4 + 5 * 4;

/// A frame larger than this is treated as a desynchronised stream rather than
/// a very big screen. 8K BGRA is ~132 MB; this leaves headroom and still
/// refuses a length that could only come from misreading pixels as a header.
pub const MAX_PAYLOAD: u32 = 256 * 1024 * 1024;

impl FrameHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&MAGIC);
        b[4..8].copy_from_slice(&self.width.to_ne_bytes());
        b[8..12].copy_from_slice(&self.height.to_ne_bytes());
        b[12..16].copy_from_slice(&self.stride.to_ne_bytes());
        b[16..20].copy_from_slice(&self.video_format.to_ne_bytes());
        b[20..24].copy_from_slice(&self.len.to_ne_bytes());
        b
    }

    /// Decode, refusing anything that cannot be a frame.
    ///
    /// ⚠️ Validates rather than trusts. A reader that got out of step would
    /// otherwise take four pixels as a length and try to allocate them.
    pub fn decode(b: &[u8; HEADER_LEN]) -> Result<Self, String> {
        if b[0..4] != MAGIC {
            return Err(format!(
                "frame header magic is {:02x?}, expected {:02x?} — the stream is out of step",
                &b[0..4],
                MAGIC
            ));
        }
        let g = |at: usize| u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let h = FrameHeader {
            width: g(4),
            height: g(8),
            stride: g(12),
            video_format: g(16),
            len: g(20),
        };
        if h.len > MAX_PAYLOAD {
            return Err(format!(
                "frame claims {} bytes, over the {MAX_PAYLOAD}-byte ceiling",
                h.len
            ));
        }
        if h.width == 0 || h.height == 0 {
            return Err(format!("frame is {}x{}", h.width, h.height));
        }
        // A stride below one packed row cannot describe the pixels claimed.
        // Larger IS legal — padding to an alignment is normal.
        if (h.stride as u64) < h.width as u64 * 4 {
            return Err(format!(
                "stride {} is below {}x4 — not a 32-bit packed frame",
                h.stride, h.width
            ));
        }
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr() -> FrameHeader {
        FrameHeader {
            width: 1920,
            height: 1080,
            stride: 7680,
            video_format: 8,
            len: 1920 * 1080 * 4,
        }
    }

    #[test]
    fn a_header_round_trips() {
        assert_eq!(FrameHeader::decode(&hdr().encode()).unwrap(), hdr());
        assert_eq!(hdr().encode().len(), HEADER_LEN);
    }

    /// The magic exists so a desynchronised reader fails at the next boundary
    /// rather than reading pixels as a length. Prove it actually does.
    #[test]
    fn pixels_misread_as_a_header_are_refused() {
        let mut b = hdr().encode();
        b[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let e = FrameHeader::decode(&b).unwrap_err();
        assert!(e.contains("out of step"), "{e}");
    }

    /// A length that could only come from misreading must be refused before
    /// anything tries to allocate it.
    #[test]
    fn an_absurd_length_is_refused() {
        let mut h = hdr();
        h.len = MAX_PAYLOAD + 1;
        let e = FrameHeader::decode(&h.encode()).unwrap_err();
        assert!(e.contains("ceiling"), "{e}");
    }

    /// A stride below one packed row cannot describe the pixels claimed —
    /// but a LARGER one is legal, because padding to an alignment is normal
    /// and rejecting it would break real captures.
    #[test]
    fn stride_is_checked_as_a_floor_not_an_equality() {
        let mut h = hdr();
        h.stride = 1920 * 4 - 4;
        assert!(FrameHeader::decode(&h.encode()).is_err());

        h.stride = 1920 * 4 + 256; // padded — must be accepted
        assert_eq!(FrameHeader::decode(&h.encode()).unwrap().stride, h.stride);
    }

    #[test]
    fn a_zero_dimension_is_refused() {
        let mut h = hdr();
        h.width = 0;
        assert!(FrameHeader::decode(&h.encode()).is_err());
    }
}
