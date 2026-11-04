// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Single-frame probe for MF H.264 pipelines.
//!
//! Activated MFTs report OK on `ActivateObject` but can fail on first
//! real frame — NVENC returns 0x8000FFFF without an adapter-matched
//! D3D device, Intel QSV silently drops sync input, the MS SW MFT may
//! loop on STREAM_CHANGE. This module feeds one synthetic NV12 frame
//! through an already-assembled [`MfPipeline`] and requires at least
//! one byte of encoded output within the drain cap; the cascade in
//! [`super::activate`] only declares a candidate healthy after it
//! probes clean.

#![cfg(all(target_os = "windows", feature = "mf-encoder"))]

use anyhow::{Result, bail};

use super::sync_pipeline::MfPipeline;

/// Feed a single probe frame through an assembled pipeline. Returns
/// `Ok(())` iff at least one encoded packet carried non-zero bytes.
///
/// Probe frame is a flat black image: Y plane zeros, chroma plane 0x80
/// (neutral gray). Using 0x00 for chroma would be pure green NV12 and
/// some encoders treat zero-energy input as noise-free (which they
/// may handle on a fast path that bypasses the bug we're trying to
/// catch). Zero + neutral is benign across every backend we've seen.
pub(super) fn probe_pipeline(pipeline: &mut MfPipeline) -> Result<()> {
    let (width, height) = pipeline.dims();
    let y_size = (width as usize) * (height as usize);
    let uv_size = y_size / 2;
    let mut nv12 = vec![0u8; y_size + uv_size];
    nv12[y_size..].fill(0x80);

    let packets = pipeline.encode_nv12(&nv12, 0)?;
    let total_bytes: usize = packets.iter().map(|p| p.data.len()).sum();
    if total_bytes == 0 {
        bail!(
            "probe: MFT produced zero bytes across {} packets",
            packets.len()
        );
    }
    tracing::debug!(
        packets = packets.len(),
        total_bytes,
        "mf-encoder: probe produced output"
    );
    Ok(())
}
