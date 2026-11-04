// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! HW H.264 MFT cascade with probe-and-rollback.
//!
//! Phase 3 commit 3. This is the entry point replacing the monolithic
//! `activate_h264_encoder` that used to live in `mf/mod.rs`.
//!
//! Shape of the cascade:
//!
//! ```text
//! for adapter in enumerate_adapters():
//!     (device, manager) = create_d3d11_device_on(adapter)
//!     for mft_candidate in enumerate_hw_h264_mfts():
//!         try_activate_and_probe(candidate, device, manager, w, h)
//!           ─ Ok(pipeline) ─▶ return
//!           ─ Err(AsyncRequired) ─▶ route to commit 1A.2's async pipeline
//!                                   (not yet wired — log + skip)
//!           ─ Err(ProbeFailed)    ─▶ log, next candidate
//! else:
//!     fall back to default-adapter SW MFT (matches pre-cascade behaviour)
//! ```
//!
//! Why this shape: activation reporting OK is not sufficient. NVENC
//! `ActivateObject` returns 0x8000FFFF if the D3D11 device is bound to
//! the wrong adapter (the Intel iGPU on a hybrid laptop). Intel QSV is
//! async-only and silently buffers input on the sync ProcessOutput
//! loop. The MS SW MFT can loop on STREAM_CHANGE under specific
//! media-type negotiations. Running a probe frame through a fully-
//! assembled pipeline catches all three classes before the live media
//! pump starts.

#![cfg(all(target_os = "windows", feature = "mf-encoder"))]

use anyhow::{Result, anyhow};
use thiserror::Error;

use windows::Win32::Foundation::E_NOTIMPL;
use windows::Win32::Graphics::Direct3D11::ID3D11Device;
use windows::Win32::Media::MediaFoundation::{
    CLSID_MSH264EncoderMFT, IMFActivate, IMFDXGIDeviceManager, IMFTransform, MF_TRANSFORM_ASYNC,
    MF_TRANSFORM_ASYNC_UNLOCK, MFMediaType_Video, MFT_CATEGORY_VIDEO_ENCODER,
    MFT_ENUM_ADAPTER_LUID, MFT_ENUM_FLAG, MFT_ENUM_FLAG_ASYNCMFT, MFT_ENUM_FLAG_HARDWARE,
    MFT_ENUM_FLAG_SORTANDFILTER, MFT_ENUM_FLAG_SYNCMFT, MFT_FRIENDLY_NAME_Attribute,
    MFT_MESSAGE_SET_D3D_MANAGER, MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_AV1,
    MFVideoFormat_H264, MFVideoFormat_HEVC, MFVideoFormat_NV12,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree};
use windows::core::Interface;

use super::adapter::{create_d3d11_device_on, enumerate_adapters};
use super::create_d3d11_device_and_manager;
use super::probe::probe_pipeline;
use super::sync_pipeline::{MfPipeline, OutputCodec};

/// Cascade error classifier. Each variant maps to a specific caller
/// action: `AsyncRequired` routes to the async pipeline (1A.2),
/// `ProbeFailed` skips to the next candidate.
#[derive(Debug, Error)]
pub(super) enum MfInitError {
    /// MFT reports `MF_TRANSFORM_ASYNC=1` and the async-unlock
    /// attribute did not flip it back. The only valid handler is an
    /// `IMFAsyncCallback`-driven pipeline (Phase 3 commit 4 / 1A.2).
    #[error("MFT is async-only (MF_TRANSFORM_ASYNC=1, unlock ignored)")]
    AsyncRequired,

    /// Any other failure during activation, D3D bind, media-type
    /// setup, or the probe frame itself. Cascade treats this as
    /// "skip this candidate, try the next."
    #[error("MFT probe failed: {0}")]
    ProbeFailed(anyhow::Error),
}

/// One candidate returned by [`MFTEnumEx`] over hardware H.264 encoder
/// MFTs. The `activate` handle is consumed by `ActivateObject` on the
/// first successful use — re-activating a consumed handle is
/// undefined, so each cascade iteration gets its own.
pub(super) struct HwMftCandidate {
    pub(super) friendly_name: String,
    pub(super) activate: IMFActivate,
}

/// Enumerate hardware H.265/HEVC encoder MFTs on this host. Same
/// semantics as [`enumerate_hw_h264_mfts`] but for HEVC. Used by
/// capability detection (2A.1) to advertise `mf-h265-hw` in
/// AgentCaps.hw_encoders. Doesn't activate or probe — that's a
/// separate concern (the HEVC pipeline itself lands in 2C.1).
pub(super) fn enumerate_hw_hevc_mfts() -> Result<Vec<HwMftCandidate>> {
    enumerate_hw_video_mfts(MFVideoFormat_HEVC)
}

/// Enumerate hardware AV1 encoder MFTs on this host. Lights up the
/// `mf-av1-hw` chip in AgentCaps when the host has an AV1-capable
/// encoder. Ships on Windows 11 24H2+ with recent IHV drivers —
/// NVIDIA RTX 40+, Intel Arc, AMD RDNA3+. Returns empty on older
/// Windows / non-AV1 GPUs; caller then does not advertise AV1.
pub(super) fn enumerate_hw_av1_mfts() -> Result<Vec<HwMftCandidate>> {
    enumerate_hw_video_mfts(MFVideoFormat_AV1)
}

/// Enumerate hardware H.264 encoder MFTs on this host.
///
/// Returns the empty vec on boxes with no HW encoder — caller then
/// falls through to the default-adapter SW MFT path. We include both
/// sync (`NVENC`, `AMF`) and async (`Intel QSV`) HW MFTs; the async
/// ones route to [`MfInitError::AsyncRequired`] during probe.
pub(super) fn enumerate_hw_h264_mfts() -> Result<Vec<HwMftCandidate>> {
    enumerate_hw_video_mfts(MFVideoFormat_H264)
}

/// Inner helper: enumerate hardware encoder MFTs for a given output
/// codec subtype GUID. Factored out so H.264 / H.265 / AV1 share a
/// single MFTEnumEx invocation; only the output media subtype differs.
fn enumerate_hw_video_mfts(output_subtype: windows::core::GUID) -> Result<Vec<HwMftCandidate>> {
    let input_info = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output_info = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: output_subtype,
    };
    // Union of HW + sync + async + sort-and-filter. Without `SYNCMFT`
    // the default excludes all sync MFTs; without `ASYNCMFT` QSV is
    // invisible. Both must be OR'd in to see the full IHV set.
    let flags = MFT_ENUM_FLAG(
        MFT_ENUM_FLAG_HARDWARE.0
            | MFT_ENUM_FLAG_SYNCMFT.0
            | MFT_ENUM_FLAG_ASYNCMFT.0
            | MFT_ENUM_FLAG_SORTANDFILTER.0,
    );
    unsafe {
        let mut activates: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut count: u32 = 0;
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            Some(&input_info),
            Some(&output_info),
            &mut activates,
            &mut count,
        )
        .map_err(|e| anyhow!("MFTEnumEx: {e:?}"))?;

        let mut out = Vec::new();
        if count > 0 && !activates.is_null() {
            let slice = std::slice::from_raw_parts(activates, count as usize);
            for maybe in slice {
                let Some(act) = maybe else { continue };
                let friendly_name = read_friendly_name(act);
                out.push(HwMftCandidate {
                    friendly_name,
                    activate: act.clone(),
                });
            }
            CoTaskMemFree(Some(activates as *const _));
        }
        tracing::info!(
            subtype = format!("{:?}", output_subtype),
            count = out.len(),
            names = ?out.iter().map(|c| c.friendly_name.clone()).collect::<Vec<_>>(),
            "mf-encoder: enumerated HW video encoder MFTs"
        );
        Ok(out)
    }
}

/// Read the `MFT_FRIENDLY_NAME_Attribute` off an `IMFActivate`, UTF-16
/// decoded. Returns the empty string if the attribute is missing or
/// empty — the caller uses it only for logging, never for logic.
fn read_friendly_name(act: &IMFActivate) -> String {
    unsafe {
        let mut name_buf = [0u16; 256];
        let mut name_len = 0u32;
        let _ = act.GetString(
            &MFT_FRIENDLY_NAME_Attribute,
            &mut name_buf,
            Some(&mut name_len),
        );
        String::from_utf16_lossy(&name_buf[..name_len as usize])
    }
}

/// Codec-parametric adapter × MFT cascade. Returns a fully-assembled
/// [`MfPipeline`] bound to whichever HW (or, for H.264, SW fallback)
/// combination probes cleanly.
///
/// H.264: never returns `Err` unless every HW candidate AND the
/// `CLSID_MSH264EncoderMFT` default-adapter SW MFT failed — a box with
/// no HW encoder still produces a working pipeline so long as COM /
/// MF are functional.
///
/// HEVC: Windows does NOT ship a software HEVC encoder CLSID. When the
/// HW cascade fails for HEVC the function returns Err — the caller
/// (currently `encode::open_for_codec`) demotes to H.264 rather than
/// expecting a SW MFT fallback.
pub(super) fn activate_and_probe_pipeline_for_codec(
    codec: OutputCodec,
    width: u32,
    height: u32,
) -> Result<MfPipeline> {
    let adapters = enumerate_adapters().unwrap_or_else(|e| {
        tracing::warn!(%e, codec = codec.backend_name(), "mf-encoder: enumerate_adapters failed — cascade skips HW path");
        Vec::new()
    });
    let candidates = match codec {
        OutputCodec::H264 => enumerate_hw_h264_mfts(),
        OutputCodec::Hevc => enumerate_hw_hevc_mfts(),
        OutputCodec::Av1 => enumerate_hw_av1_mfts(),
    }
    .unwrap_or_else(|e| {
        tracing::warn!(%e, codec = codec.backend_name(), "mf-encoder: enumerate_hw_*_mfts failed — cascade skips HW path");
        Vec::new()
    });
    tracing::info!(
        codec = codec.backend_name(),
        adapter_count = adapters.len(),
        mft_count = candidates.len(),
        "mf-encoder: starting probe-and-rollback cascade"
    );

    for adapter_info in &adapters {
        let (device, manager) = match create_d3d11_device_on(&adapter_info.adapter) {
            Ok(t) => t,
            Err(e) => {
                // Optimus laptops put the dGPU to sleep until a render
                // target is created on it; `D3D11CreateDevice` then
                // returns `DXGI_ERROR_UNSUPPORTED`. Skip, not fatal.
                tracing::warn!(
                    adapter = %adapter_info.description,
                    %e,
                    "mf-encoder: D3D11CreateDevice on adapter failed — skipping"
                );
                continue;
            }
        };
        for candidate in &candidates {
            match try_activate_and_probe(
                candidate,
                &device,
                &manager,
                width,
                height,
                codec,
                adapter_info.luid,
            ) {
                Ok(pipeline) => {
                    tracing::info!(
                        codec = codec.backend_name(),
                        adapter = %adapter_info.description,
                        mft = %candidate.friendly_name,
                        "mf-encoder: cascade winner — HW pipeline active"
                    );
                    return Ok(pipeline);
                }
                Err(MfInitError::AsyncRequired) => {
                    tracing::info!(
                        adapter = %adapter_info.description,
                        mft = %candidate.friendly_name,
                        "mf-encoder: async MFT — deferring to async pipeline (commit 1A.2)"
                    );
                    continue;
                }
                Err(MfInitError::ProbeFailed(e)) => {
                    tracing::warn!(
                        adapter = %adapter_info.description,
                        mft = %candidate.friendly_name,
                        error = %e,
                        "mf-encoder: probe failed — trying next candidate"
                    );
                    continue;
                }
            }
        }
    }

    match codec {
        OutputCodec::H264 => {
            tracing::info!(
                "mf-encoder: no HW candidate succeeded — falling back to SW MFT on default adapter"
            );
            build_sw_fallback(width, height)
        }
        OutputCodec::Hevc => {
            // No CLSID_MSH265EncoderMFT on stock Windows — fail here so
            // the caller can demote to H.264 cleanly rather than
            // pretending a non-existent SW path succeeded.
            Err(anyhow!(
                "mf-encoder: HEVC cascade exhausted all HW candidates and no SW HEVC encoder is available"
            ))
        }
        OutputCodec::Av1 => {
            // Same shape as HEVC: no software AV1 encoder CLSID ships
            // on stock Windows (libaom's Store-distributed MFT is an
            // exception but not widely deployed). Err here so the
            // caller demotes to the next-best codec.
            Err(anyhow!(
                "mf-encoder: AV1 cascade exhausted all HW candidates and no SW AV1 encoder is available"
            ))
        }
    }
}

/// Activate one HW candidate against a specific D3D11 device, build
/// the full pipeline, and probe it. Any failure short-circuits to
/// [`MfInitError`]; the caller's cascade handles the rollback.
fn try_activate_and_probe(
    candidate: &HwMftCandidate,
    device: &ID3D11Device,
    manager: &IMFDXGIDeviceManager,
    width: u32,
    height: u32,
    codec: OutputCodec,
    adapter_luid: u64,
) -> std::result::Result<MfPipeline, MfInitError> {
    unsafe {
        // Hint the target DXGI adapter via MFT_ENUM_ADAPTER_LUID on the
        // IMFActivate BEFORE ActivateObject. Some IHV MFTs (notably
        // NVIDIA NVENC on Blackwell / RTX 5090 Laptop GPUs with current
        // drivers) inspect this attribute during activation and fall
        // back to "catastrophic failure" (E_UNEXPECTED / 0x8000FFFF)
        // when it's absent, even with SET_D3D_MANAGER pointed at a D3D11
        // device on the right adapter. Setting it is a best-effort hint
        // — MFTs that don't care will ignore it (SetUINT64 returning
        // E_FAIL / E_NOTIMPL is swallowed).
        // IMFActivate derives from IMFAttributes (auto-deref in
        // windows-rs 0.58), so SetUINT64 is a direct call.
        let _ = candidate
            .activate
            .SetUINT64(&MFT_ENUM_ADAPTER_LUID, adapter_luid);

        let transform: IMFTransform = candidate
            .activate
            .ActivateObject()
            .map_err(|e| MfInitError::ProbeFailed(anyhow!("ActivateObject: {e:?}")))?;

        // Async detection + unlock MUST come before SET_D3D_MANAGER.
        // Async-only MFTs reject SET_D3D_MANAGER with
        // MF_E_TRANSFORM_ASYNC_LOCKED (0xC00D6D77) until the caller
        // asserts async-aware capability via MF_TRANSFORM_ASYNC_UNLOCK.
        // Observed on RTX 5090 Laptop + AMD Radeon 610M: every MFT
        // except the bare MS SW MFT returned 0xC00D6D77 here until we
        // unlocked first. We always attempt the unlock regardless of
        // the MF_TRANSFORM_ASYNC flag — some MFTs (notably the MS SW
        // MFT when HW drivers are installed) report async=false but
        // still silently buffer input until unlocked. The unlock is
        // a no-op on true sync-only MFTs.
        if let Ok(attrs) = transform.GetAttributes() {
            let _ = attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1);
            // Re-read the async flag after unlock. If the MFT still
            // insists on async, route to the async pipeline (Intel
            // QSV is the main case — it ignores unlock silently).
            let still_async = attrs
                .GetUINT32(&MF_TRANSFORM_ASYNC)
                .map(|v| v != 0)
                .unwrap_or(false);
            if still_async {
                return Err(MfInitError::AsyncRequired);
            }
        }

        // Bind D3D manager so HW MFTs know which GPU memory pool to
        // pull input from. NVENC returns 0x8000FFFF on first
        // ProcessOutput without this. E_NOTIMPL is normal on the MS
        // SW MFT that shows up in the HW enum — we treat that
        // candidate as a sync MFT that doesn't need D3D and continue
        // with None for device/manager.
        let manager_ptr: usize = manager.as_raw() as usize;
        let d3d_device: Option<ID3D11Device>;
        let d3d_manager: Option<IMFDXGIDeviceManager>;
        match transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager_ptr) {
            Ok(()) => {
                d3d_device = Some(device.clone());
                d3d_manager = Some(manager.clone());
            }
            Err(e) if e.code() == E_NOTIMPL => {
                tracing::debug!(
                    mft = %candidate.friendly_name,
                    "mf-encoder: SET_D3D_MANAGER E_NOTIMPL — treating as sync CPU MFT"
                );
                d3d_device = None;
                d3d_manager = None;
            }
            Err(e) => {
                return Err(MfInitError::ProbeFailed(anyhow!("SET_D3D_MANAGER: {e:?}")));
            }
        }

        let backend_kind = if d3d_device.is_some() { "hw" } else { "sw" };
        let mut pipeline = MfPipeline::new(
            transform,
            d3d_device,
            d3d_manager,
            backend_kind,
            width,
            height,
            codec,
        )
        .map_err(MfInitError::ProbeFailed)?;
        probe_pipeline(&mut pipeline).map_err(MfInitError::ProbeFailed)?;
        Ok(pipeline)
    }
}

/// Default-adapter SW MFT path. Identical to what [`MfPipeline::new`]
/// used to do in 0.1.25; re-cast here as the final fallback when the
/// HW cascade produces no winner. Lets the agent keep working on boxes
/// with no HW encoder or where every HW candidate failed.
fn build_sw_fallback(width: u32, height: u32) -> Result<MfPipeline> {
    unsafe {
        let d3d_aux = create_d3d11_device_and_manager()
            .map_err(|e| {
                tracing::warn!(%e, "mf-encoder: D3D11 default-adapter setup skipped");
            })
            .ok();

        let transform: IMFTransform =
            CoCreateInstance(&CLSID_MSH264EncoderMFT, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| anyhow!("CoCreateInstance MSH264Encoder: {e:?}"))?;
        tracing::info!("mf-encoder: SW fallback MFT activated");

        // Async detection + unlock. Must precede SET_D3D_MANAGER and
        // SetOutputType. The MS-shipped CLSID_MSH264EncoderMFT can
        // silently delegate to async HW on boxes with installed HW
        // encoder drivers and then the sync ProcessOutput loop
        // starves (observed on RTX 5090 Laptop: pipeline builds fine,
        // ProcessInput=OK, ProcessOutput=NEED_MORE_INPUT forever
        // despite `MF_TRANSFORM_ASYNC` reading 0). We unconditionally
        // attempt the unlock rather than gating on the flag; it's a
        // no-op on true sync-only SW MFTs (WARP / pure-SW VMs).
        if let Ok(attrs) = transform.GetAttributes() {
            let _ = attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1);
            let is_async = attrs
                .GetUINT32(&MF_TRANSFORM_ASYNC)
                .map(|v| v != 0)
                .unwrap_or(false);
            tracing::info!(
                is_async,
                "mf-encoder: SW fallback async-mode probe (post-unlock)"
            );
        }

        // #2283 — whether a GPU can be behind this MFT at all. Without the
        // manager it is Microsoft's encoder on the CPU alone.
        let mut manager_bound = false;
        if let Some((_, ref d3d_manager)) = d3d_aux {
            let manager_ptr: usize = d3d_manager.as_raw() as usize;
            match transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager_ptr) {
                Ok(()) => {
                    manager_bound = true;
                    tracing::info!("mf-encoder: D3D manager bound to SW MFT")
                }
                Err(e) => tracing::info!(
                    code = %e.code().0,
                    "mf-encoder: SW MFT ignored D3D manager — continuing pure-SW"
                ),
            }
        }

        let (d3d_device, d3d_manager) = match d3d_aux {
            Some((dev, mgr)) => (Some(dev), Some(mgr)),
            None => (None, None),
        };

        MfPipeline::new(
            transform,
            d3d_device,
            d3d_manager,
            if manager_bound {
                "sw"
            } else {
                super::BACKEND_PURE_SW
            },
            width,
            height,
            OutputCodec::H264,
        )
    }
}
