// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-70 M1 — the FFmpeg encoder behind the generic handle.
//!
//! The pump holds an [`EncoderHandle`] and calls the same nine methods it
//! always did; whether the encoder lives inline (today's `block_in_place` on
//! a runtime worker) or on its own thread ([`crate::encode::thread`]) is a
//! constructor choice made once per open from the `media_thread` switch.

use anyhow::Result;

use super::encoder::{FfmpegEncoder, RateStats, RebuildSpec, RebuiltEncoder};
use crate::capture::Frame;
use crate::encode::EncodedPacket;
use crate::encode::thread::{EncoderCaps, EncoderOps};

/// The FFmpeg encoder as the pump sees it.
pub type EncoderHandle = crate::encode::thread::EncoderHandle<FfmpegEncoder>;

impl EncoderOps for FfmpegEncoder {
    type Rebuilt = RebuiltEncoder;
    type RebuildSpec = RebuildSpec;
    type Stats = RateStats;

    // The FFmpeg pump has run its encode under `block_in_place` since FR-1
    // P5; the inline path keeps that verbatim.
    const INLINE_BLOCK_IN_PLACE: bool = true;

    fn encode_sync(&mut self, frame: &Frame) -> Result<Vec<EncodedPacket>> {
        FfmpegEncoder::encode_sync(self, frame)
    }
    fn set_bitrate(&mut self, bps: u32) {
        crate::encode::VideoEncoder::set_bitrate(self, bps)
    }
    fn request_keyframe(&mut self) {
        crate::encode::VideoEncoder::request_keyframe(self)
    }
    fn adopt_rebuilt(&mut self, rebuilt: RebuiltEncoder) -> bool {
        FfmpegEncoder::adopt_rebuilt(self, rebuilt)
    }
    fn rebuild_spec(&self, bps: u32) -> Option<RebuildSpec> {
        FfmpegEncoder::rebuild_spec(self, bps)
    }
    fn rebuild_spec_at(&self, width: u32, height: u32, fps: u32, bps: u32) -> Option<RebuildSpec> {
        Some(FfmpegEncoder::rebuild_spec_at(
            self, width, height, fps, bps,
        ))
    }
    fn caps(&self) -> EncoderCaps {
        EncoderCaps {
            name: crate::encode::VideoEncoder::name(self),
            supports_dynamic_bitrate: self.supports_dynamic_bitrate(),
            reconfig_forces_idr: self.reconfig_forces_idr(),
            chroma444: self.chroma444(),
        }
    }
    fn current_maxrate_bps(&self) -> u32 {
        FfmpegEncoder::current_maxrate_bps(self)
    }
    fn rate_stats(&self) -> RateStats {
        FfmpegEncoder::rate_stats(self)
    }
}
