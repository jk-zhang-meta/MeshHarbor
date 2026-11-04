// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Opus encoder for the WebRTC audio track.
//!
//! Wraps [`audiopus::coder::Encoder`] configured for the WebRTC Opus
//! profile: 48 kHz, stereo, 20 ms frames (960 samples/channel). Incoming
//! PCM (whatever rate/channels the capture device produced) is minimally
//! resampled + upmixed to 48 kHz stereo, then buffered in a ring so we
//! emit EXACTLY 960-sample-per-channel Opus packets — carrying any
//! remainder across `push` calls.
//!
//! **v1 resampling is nearest-neighbour** (no interpolation / anti-alias
//! filter). Desktop capture is almost always already 48 kHz (WASAPI
//! shared-mode mix + PulseAudio default sink both run at 48 k), so the
//! resampler is a rarely-hit safety net; nearest-neighbour keeps it
//! dependency-free and cheap. If a real 44.1 kHz source shows up in the
//! field and aliasing is audible, swap in a proper resampler here — the
//! interface (`push` → `Vec<Vec<u8>>`) doesn't change.

use anyhow::{Context, Result};
use audiopus::coder::Encoder as OpusCoder;
use audiopus::{Application, Bitrate, Channels, SampleRate};
use tunnel_core::env::node_env;

/// Opus output sample rate — the only rate WebRTC negotiates.
const OUT_RATE: u32 = 48_000;
/// Opus output channel count.
const OUT_CHANNELS: usize = 2;
/// 20 ms @ 48 kHz = 960 samples PER CHANNEL. This is the frame size
/// every packet must carry; Opus supports 2.5/5/10/20/40/60 ms and we
/// pick 20 ms as the WebRTC default (good latency/overhead balance).
const SAMPLES_PER_CH: usize = 960;
/// Interleaved frame length (L,R,L,R,…) for one 20 ms packet.
const FRAME_INTERLEAVED: usize = SAMPLES_PER_CH * OUT_CHANNELS;
/// Max Opus packet size we'll ever emit at 96 kbps / 20 ms. 4000 bytes
/// is the conventional safe ceiling (well above the ~240 B a 96 kbps
/// 20 ms frame actually produces).
const MAX_PACKET: usize = 4000;

/// Default target bitrate (bits/s). Overridable via
/// `ROOMLERD_AUDIO_BITRATE_BPS`.
const DEFAULT_BITRATE_BPS: i32 = 96_000;

pub struct OpusEncoder {
    enc: OpusCoder,
    /// Ring of interleaved 48 kHz stereo i16 awaiting a full 20 ms
    /// frame. Drained `FRAME_INTERLEAVED` samples at a time.
    pending: Vec<i16>,
    /// Scratch output buffer reused across encodes.
    out: Vec<u8>,
}

impl OpusEncoder {
    /// Build a 48 kHz stereo Opus encoder tuned for general audio.
    /// Bitrate from `ROOMLERD_AUDIO_BITRATE_BPS` (default 96000).
    pub fn new() -> Result<Self> {
        let mut enc = OpusCoder::new(SampleRate::Hz48000, Channels::Stereo, Application::Audio)
            .context("create opus encoder")?;
        let bitrate = bitrate_from_env();
        enc.set_bitrate(Bitrate::BitsPerSecond(bitrate))
            .context("set opus bitrate")?;
        tracing::info!(
            bitrate_bps = bitrate,
            "audio: opus encoder ready (48kHz stereo, 20ms frames)"
        );
        Ok(Self {
            enc,
            pending: Vec::with_capacity(FRAME_INTERLEAVED * 2),
            out: vec![0u8; MAX_PACKET],
        })
    }

    /// Feed one captured buffer; returns zero or more complete 20 ms
    /// Opus packets (each already length-correct for a `Sample`). The
    /// remainder that doesn't fill a full frame is retained for the next
    /// call.
    pub fn push(
        &mut self,
        samples: &[i16],
        in_channels: u16,
        in_rate: u32,
    ) -> Result<Vec<Vec<u8>>> {
        // 1. Normalise to 48 kHz stereo interleaved, appending into the
        //    ring.
        append_normalized(&mut self.pending, samples, in_channels, in_rate);

        // 2. Drain complete 20 ms frames.
        let mut packets = Vec::new();
        while self.pending.len() >= FRAME_INTERLEAVED {
            // Encode the leading frame. audiopus takes an interleaved
            // &[i16] of exactly frame_size*channels and the sample-per-
            // channel count is inferred from the slice length / channels.
            let frame = &self.pending[..FRAME_INTERLEAVED];
            let n = self
                .enc
                .encode(frame, &mut self.out)
                .context("opus encode")?;
            packets.push(self.out[..n].to_vec());
            // Shift the ring left past the consumed frame. `drain` keeps
            // the tail; for typical single-frame buffers this is cheap.
            self.pending.drain(..FRAME_INTERLEAVED);
        }
        Ok(packets)
    }
}

/// Read the Opus bitrate override, clamped to a sane Opus range
/// (6–510 kbps). Falls back to [`DEFAULT_BITRATE_BPS`] on unset /
/// unparseable / out-of-range.
fn bitrate_from_env() -> i32 {
    match node_env("AUDIO_BITRATE_BPS") {
        Some(v) => match v.trim().parse::<i32>() {
            Ok(n) if (6_000..=510_000).contains(&n) => n,
            Ok(n) => {
                tracing::warn!(
                    value = n,
                    "audio: ROOMLERD_AUDIO_BITRATE_BPS out of range (6000..=510000) — using default"
                );
                DEFAULT_BITRATE_BPS
            }
            Err(_) => {
                tracing::warn!(
                    value = %v,
                    "audio: ROOMLERD_AUDIO_BITRATE_BPS not an integer — using default"
                );
                DEFAULT_BITRATE_BPS
            }
        },
        None => DEFAULT_BITRATE_BPS,
    }
}

/// Normalise an incoming interleaved buffer to 48 kHz stereo and append
/// the result to `dst`. Handles:
///   * channel up/down-mix to stereo (mono → duplicate; >2 → take first
///     two channels),
///   * nearest-neighbour resample to 48 kHz (see module docs for the v1
///     caveat).
fn append_normalized(dst: &mut Vec<i16>, samples: &[i16], in_channels: u16, in_rate: u32) {
    let in_ch = in_channels.max(1) as usize;
    if samples.is_empty() {
        return;
    }
    let in_frames = samples.len() / in_ch;
    if in_frames == 0 {
        return;
    }

    // Fast path: already 48 kHz stereo → copy through untouched.
    if in_rate == OUT_RATE && in_ch == OUT_CHANNELS {
        dst.extend_from_slice(&samples[..in_frames * OUT_CHANNELS]);
        return;
    }

    // General path: per output frame, map to a source frame index
    // (nearest neighbour) and emit an L/R pair.
    let out_frames = if in_rate == OUT_RATE {
        in_frames
    } else {
        // Round to nearest to avoid systematically dropping the tail.
        ((in_frames as u64 * OUT_RATE as u64 + (in_rate as u64 / 2)) / in_rate as u64) as usize
    };
    dst.reserve(out_frames * OUT_CHANNELS);
    for o in 0..out_frames {
        let src_frame = if in_rate == OUT_RATE {
            o
        } else {
            // Nearest source frame.
            let f = (o as u64 * in_rate as u64) / OUT_RATE as u64;
            (f as usize).min(in_frames - 1)
        };
        let base = src_frame * in_ch;
        let (l, r) = match in_ch {
            1 => {
                let m = samples[base];
                (m, m)
            }
            _ => (samples[base], samples[base + 1]),
        };
        dst.push(l);
        dst.push(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 48 kHz-stereo passthrough buffer of exactly one 20 ms frame
    /// yields exactly one packet, and leaves the ring empty.
    #[test]
    fn exact_frame_produces_one_packet_no_remainder() {
        let mut enc = OpusEncoder::new().expect("encoder");
        // One full 20 ms stereo frame of silence.
        let pcm = vec![0i16; FRAME_INTERLEAVED];
        let packets = enc.push(&pcm, 2, 48_000).expect("push");
        assert_eq!(packets.len(), 1, "one 20ms frame → one packet");
        assert!(!packets[0].is_empty(), "opus packet non-empty");
        assert_eq!(enc.pending.len(), 0, "no remainder after an exact frame");
    }

    /// A sub-frame buffer produces no packet and is fully retained;
    /// the next push that tops it up over the frame boundary emits one
    /// packet and carries the leftover.
    #[test]
    fn remainder_is_carried_across_calls() {
        let mut enc = OpusEncoder::new().expect("encoder");
        // Half a frame → nothing emitted yet.
        let half = vec![0i16; FRAME_INTERLEAVED / 2];
        let p0 = enc.push(&half, 2, 48_000).expect("push half");
        assert!(p0.is_empty(), "half a frame → no packet");
        assert_eq!(enc.pending.len(), FRAME_INTERLEAVED / 2);

        // Another 0.75 frame → total 1.25 frames → one packet + 0.25
        // frame carried.
        let three_q = vec![0i16; (FRAME_INTERLEAVED * 3) / 4];
        let p1 = enc.push(&three_q, 2, 48_000).expect("push 0.75");
        assert_eq!(p1.len(), 1, "crossing the boundary emits one packet");
        assert_eq!(
            enc.pending.len(),
            FRAME_INTERLEAVED / 4,
            "0.25 frame remainder carried"
        );
    }

    /// Two-and-a-bit frames in one push emit two packets and carry the
    /// fractional tail — the exact-960-sample chunking the plan asks us
    /// to lock.
    #[test]
    fn multiple_frames_chunk_at_960_samples_per_channel() {
        let mut enc = OpusEncoder::new().expect("encoder");
        let pcm = vec![0i16; FRAME_INTERLEAVED * 2 + FRAME_INTERLEAVED / 3];
        let packets = enc.push(&pcm, 2, 48_000).expect("push");
        assert_eq!(packets.len(), 2, "2.33 frames → exactly 2 packets");
        assert_eq!(
            enc.pending.len(),
            FRAME_INTERLEAVED / 3,
            "0.33 frame remainder carried"
        );
    }

    /// Mono capture is upmixed to stereo: N mono samples → N stereo
    /// frames (2N interleaved), so a mono 20 ms frame (960 samples)
    /// yields one packet.
    #[test]
    fn mono_is_upmixed_to_stereo() {
        let mut enc = OpusEncoder::new().expect("encoder");
        // 960 mono samples = one 20 ms frame after upmix.
        let mono = vec![0i16; SAMPLES_PER_CH];
        let packets = enc.push(&mono, 1, 48_000).expect("push mono");
        assert_eq!(packets.len(), 1, "one 20ms mono frame → one packet");
        assert_eq!(enc.pending.len(), 0);
    }

    /// 24 kHz stereo resamples up to 48 kHz: 480 input frames → ~960
    /// output frames → one packet.
    #[test]
    fn resamples_24k_to_48k() {
        let mut enc = OpusEncoder::new().expect("encoder");
        // 480 frames @ 24 kHz stereo = 20 ms → ~960 frames @ 48 kHz.
        let pcm = vec![0i16; 480 * 2];
        let packets = enc.push(&pcm, 2, 24_000).expect("push 24k");
        assert_eq!(packets.len(), 1, "20ms @ 24k upsamples to one 48k frame");
    }

    #[test]
    fn append_normalized_passthrough_48k_stereo() {
        let mut dst = Vec::new();
        let src = vec![1i16, 2, 3, 4]; // 2 stereo frames
        append_normalized(&mut dst, &src, 2, 48_000);
        assert_eq!(dst, vec![1, 2, 3, 4]);
    }

    #[test]
    fn append_normalized_mono_upmix() {
        let mut dst = Vec::new();
        let src = vec![5i16, 6]; // 2 mono frames
        append_normalized(&mut dst, &src, 1, 48_000);
        // Each mono sample duplicated to L=R.
        assert_eq!(dst, vec![5, 5, 6, 6]);
    }
}
