// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P0d-2 — how a viewer peer's messages cross a DataChannel.
//!
//! One SCTP message may not exceed the negotiated `max_message_size` — 65,536
//! bytes by default — and a larger one is not refused, it is silently LOST
//! (field 2026-05-13: RC's `rc:logs-fetch` dropped every 1,000-line answer
//! until it chunked). A transcript event can carry a 64 KiB tool output before
//! its JSON, so every logical message — one JSON object — travels as one or
//! more binary frames:
//!
//! ```text
//! byte 0      version (1)
//! bytes 1..5  message id, u32 big-endian — per sender, wraps
//! bytes 5..7  part index, u16 big-endian
//! bytes 7..9  part count, u16 big-endian (≥ 1)
//! bytes 9..   payload: a slice of the message's UTF-8 bytes
//! ```
//!
//! Payload slices are cut at byte boundaries and joined before decoding, so a
//! frame never has to hold whole characters. The reassembler is bounded on
//! every axis a misbehaving peer could push — parts per message, bytes per
//! message, messages in flight — and drops a message it cannot hold rather
//! than buffering without end.

use std::collections::HashMap;

/// The only version this build speaks.
pub const VERSION: u8 = 1;
/// Header bytes before the payload.
pub const HEADER: usize = 9;
/// Payload bytes per frame. With the header, well under 65,536.
pub const MAX_PAYLOAD: usize = 60_000;

/// Split one message into frames.
pub fn encode(id: u32, message: &[u8]) -> Vec<Vec<u8>> {
    let chunks: Vec<&[u8]> = if message.is_empty() {
        vec![&[][..]]
    } else {
        message.chunks(MAX_PAYLOAD).collect()
    };
    // A message longer than u16::MAX parts (3.9 GB) is not one this protocol
    // carries; callers bound what they send far below that.
    let parts = u16::try_from(chunks.len()).unwrap_or(u16::MAX);
    chunks
        .into_iter()
        .take(usize::from(parts))
        .enumerate()
        .map(|(i, chunk)| {
            let mut frame = Vec::with_capacity(HEADER + chunk.len());
            frame.push(VERSION);
            frame.extend_from_slice(&id.to_be_bytes());
            frame.extend_from_slice(&(i as u16).to_be_bytes());
            frame.extend_from_slice(&parts.to_be_bytes());
            frame.extend_from_slice(chunk);
            frame
        })
        .collect()
}

/// Why a frame was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Shorter than the header, or not this version.
    Malformed,
    /// More parts, or more bytes, than one message may have.
    TooLarge,
    /// More messages half-received at once than allowed; the oldest is
    /// dropped to make room.
    TooManyInFlight,
    /// A part index outside the count, or a count that changed mid-message.
    Inconsistent,
}

/// Bounds for what one side accepts.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    pub max_message_bytes: usize,
    pub max_in_flight: usize,
}

struct Partial {
    parts: u16,
    got: Vec<Option<Vec<u8>>>,
    bytes: usize,
    received: usize,
    /// Arrival order, to drop the oldest when too many are in flight.
    order: u64,
}

/// Joins frames back into messages.
pub struct Reassembler {
    bounds: Bounds,
    partial: HashMap<u32, Partial>,
    next_order: u64,
}

impl Reassembler {
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            partial: HashMap::new(),
            next_order: 0,
        }
    }

    /// Feed one frame. `Ok(Some(message))` when it completed one; `Ok(None)`
    /// while a message is still arriving. `Err` says a message was LOST:
    /// the one this frame belonged to (`Malformed`, `TooLarge`,
    /// `Inconsistent`), or — `TooManyInFlight` — the oldest half-received
    /// one, dropped to make room for this frame, which was kept.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        if frame.len() < HEADER || frame[0] != VERSION {
            return Err(FrameError::Malformed);
        }
        let id = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let index = u16::from_be_bytes([frame[5], frame[6]]);
        let parts = u16::from_be_bytes([frame[7], frame[8]]);
        let payload = &frame[HEADER..];
        if parts == 0 || index >= parts {
            self.partial.remove(&id);
            return Err(FrameError::Inconsistent);
        }
        let max_parts = self.bounds.max_message_bytes.div_ceil(MAX_PAYLOAD).max(1);
        if usize::from(parts) > max_parts || payload.len() > MAX_PAYLOAD {
            self.partial.remove(&id);
            return Err(FrameError::TooLarge);
        }
        if parts == 1 {
            if payload.len() > self.bounds.max_message_bytes {
                return Err(FrameError::TooLarge);
            }
            return Ok(Some(payload.to_vec()));
        }

        let mut evicted = false;
        if !self.partial.contains_key(&id)
            && self.partial.len() >= self.bounds.max_in_flight
            && let Some(oldest) = self
                .partial
                .iter()
                .min_by_key(|(_, p)| p.order)
                .map(|(id, _)| *id)
        {
            self.partial.remove(&oldest);
            evicted = true;
        }
        let order = self.next_order;
        let entry = self.partial.entry(id).or_insert_with(|| Partial {
            parts,
            got: vec![None; usize::from(parts)],
            bytes: 0,
            received: 0,
            order,
        });
        self.next_order += 1;
        if entry.parts != parts {
            self.partial.remove(&id);
            return Err(FrameError::Inconsistent);
        }
        let slot = &mut entry.got[usize::from(index)];
        if slot.is_none() {
            entry.bytes += payload.len();
            entry.received += 1;
            *slot = Some(payload.to_vec());
        }
        if entry.bytes > self.bounds.max_message_bytes {
            self.partial.remove(&id);
            return Err(FrameError::TooLarge);
        }
        if entry.received < usize::from(entry.parts) {
            return if evicted {
                Err(FrameError::TooManyInFlight)
            } else {
                Ok(None)
            };
        }
        let done = self.partial.remove(&id).expect("present");
        let mut message = Vec::with_capacity(done.bytes);
        for part in done.got.into_iter().flatten() {
            message.extend_from_slice(&part);
        }
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDS: Bounds = Bounds {
        max_message_bytes: 1024 * 1024,
        max_in_flight: 2,
    };

    fn round_trip(message: &[u8]) -> Vec<u8> {
        let mut r = Reassembler::new(BOUNDS);
        let mut out = None;
        for frame in encode(7, message) {
            assert!(frame.len() <= HEADER + MAX_PAYLOAD);
            assert!(frame.len() < 65_536, "a frame must fit one SCTP message");
            if let Some(m) = r.push(&frame).unwrap() {
                out = Some(m);
            }
        }
        out.expect("the message completes")
    }

    #[test]
    fn messages_of_every_size_survive_the_trip() {
        for len in [0, 1, MAX_PAYLOAD - 1, MAX_PAYLOAD, MAX_PAYLOAD + 1, 300_000] {
            let message: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(round_trip(&message), message, "length {len}");
        }
    }

    /// Cut anywhere — inside a multi-byte character too — and joined
    /// before decoding, text comes back whole.
    #[test]
    fn a_cut_through_a_character_is_joined_before_decoding() {
        let text = "ž".repeat(MAX_PAYLOAD); // two bytes each: cuts land mid-character
        let back = round_trip(text.as_bytes());
        assert_eq!(String::from_utf8(back).unwrap(), text);
    }

    #[test]
    fn parts_out_of_order_still_complete() {
        let message: Vec<u8> = (0..150_000).map(|i| (i % 7) as u8).collect();
        let mut frames = encode(1, &message);
        frames.reverse();
        let mut r = Reassembler::new(BOUNDS);
        let mut out = None;
        for f in frames {
            if let Some(m) = r.push(&f).unwrap() {
                out = Some(m);
            }
        }
        assert_eq!(out.unwrap(), message);
    }

    /// A peer that announces more than a message may hold is refused at
    /// the first frame, before anything is buffered.
    #[test]
    fn an_oversized_message_is_refused_up_front() {
        let small = Bounds {
            max_message_bytes: 100_000,
            max_in_flight: 2,
        };
        let mut r = Reassembler::new(small);
        let frames = encode(3, &vec![0u8; 200_000]);
        assert_eq!(r.push(&frames[0]), Err(FrameError::TooLarge));
        assert!(r.partial.is_empty());
    }

    #[test]
    fn junk_is_malformed_and_a_bad_index_is_inconsistent() {
        let mut r = Reassembler::new(BOUNDS);
        assert_eq!(r.push(&[1, 2, 3]), Err(FrameError::Malformed));
        let mut f = encode(9, b"hi").remove(0);
        f[0] = 2;
        assert_eq!(r.push(&f), Err(FrameError::Malformed));
        let mut f = encode(9, b"hi").remove(0);
        f[5..7].copy_from_slice(&3u16.to_be_bytes()); // index 3 of 1
        assert_eq!(r.push(&f), Err(FrameError::Inconsistent));
    }

    /// Half-sent messages cannot pile up: past the bound, the oldest goes.
    #[test]
    fn half_sent_messages_are_bounded() {
        let mut r = Reassembler::new(BOUNDS);
        let big = vec![1u8; 2 * MAX_PAYLOAD];
        for id in 0..2 {
            assert_eq!(r.push(&encode(id, &big)[0]), Ok(None));
        }
        assert_eq!(
            r.push(&encode(2, &big)[0]),
            Err(FrameError::TooManyInFlight)
        );
        assert_eq!(r.partial.len(), 2, "never more than the bound");
        assert!(!r.partial.contains_key(&0), "the oldest was dropped");
    }
}
