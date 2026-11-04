// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows Media Foundation hardware H.264 encoder backend.
//!
//! The MFT-backed alternative to [`openh264_backend`]. Wraps
//! `CLSID_MSH264EncoderMFT` (the Microsoft-shipped H264 Encoder MFT,
//! which ships the hardware fast path on every IHV driver since
//! Windows 8.1) in a pinned-worker-thread wrapper that matches the
//! VideoEncoder trait.
//!
//! Layering:
//!
//! ```text
//! peer.rs media_pump
//!       │  Arc<Frame>  (BGRA, variable dims)
//!       ▼
//! MfEncoder::encode
//!       │  mpsc::Cmd → worker thread
//!       ▼
//! worker:
//!       │  color::bgra_to_nv12()  (software — phase 1)
//!       │  IMFSample + IMFMediaBuffer (NV12, timestamped)
//!       │  ProcessInput
//!       │  ProcessOutput (drain until NEED_MORE_INPUT)
//!       │  NALU extraction from output sample
//!       ▼  Vec<EncodedPacket>
//! ```
//!
//! Module layout (Phase 3 commit 3 — probe-and-rollback cascade):
//!
//! - `mod.rs` — thread-pinned `MfEncoder` handle + Cmd loop; COM/MF
//!   lifecycle (CoInitializeEx / MFStartup / MFShutdown /
//!   CoUninitialize); shared `create_d3d11_device_and_manager`
//!   helper (default-adapter path).
//! - `adapter.rs` — DXGI adapter enumeration + adapter-scoped D3D11
//!   device creation (Phase 3 commit 2).
//! - `activate.rs` — adapter × MFT cascade with probe-and-rollback.
//!   Replaces the monolithic `activate_h264_encoder` helper.
//! - `probe.rs` — single-frame probe harness used by the cascade to
//!   verify an activated MFT actually emits bytes.
//! - `sync_pipeline.rs` — `MfPipeline`: synchronous MFT pipeline
//!   (media-type setup, ProcessInput + drain loop, codec-api tuning
//!   knobs, Annex-B NALU extraction). Assumes pre-activated MFT.
//!
//! Latency knobs applied via `ICodecAPI` (all off by default,
//! every one a must-set for sub-100 ms interactive streaming):
//!
//! * `AVLowLatencyMode = true`
//! * `AVEncCommonRateControlMode = CBR`
//! * `AVEncCommonMeanBitRate = <resolution-scaled>`
//! * `AVEncMPVGOPSize = 60` (IDR every ~2 s at 30 fps)
//! * `AVEncH264CABACEnable = true` (better quality at our bitrate)

#![cfg(all(target_os = "windows", feature = "mf-encoder"))]

use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::thread;

use anyhow::{Result, anyhow, bail};
use tokio::sync::oneshot;

use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_10_1,
    D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_SDK_VERSION,
    D3D11CreateDevice, ID3D11Device, ID3D11Multithread,
};
use windows::Win32::Media::MediaFoundation::{
    IMFDXGIDeviceManager, MFCreateDXGIDeviceManager, MFSTARTUP_FULL, MFShutdown, MFStartup,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};
use windows::core::Interface;

use super::{EncodedPacket, VideoEncoder};
use crate::capture::{Frame, PixelFormat};

mod activate;
mod adapter;
mod probe;
mod sync_pipeline;

/// Cheap availability check used by capability detection (2A.1).
/// Returns the number of HW H.264 MFTs installed on this host as
/// reported by MFTEnumEx. Doesn't activate them or run the cascade
/// — that's the heavy operation kept inside MfEncoder::new. 0 means
/// no HW encoder; capability reporting falls back to SW only.
pub(crate) fn probe_adapter_count() -> Result<usize> {
    activate::enumerate_hw_h264_mfts().map(|v| v.len())
}

/// Same as [`probe_adapter_count`] but for HEVC encoders. Lights up
/// the H.265 chip in AgentsSection when HW HEVC is available.
pub(crate) fn probe_hevc_adapter_count() -> Result<usize> {
    activate::enumerate_hw_hevc_mfts().map(|v| v.len())
}

/// Same as [`probe_adapter_count`] but for AV1 encoders. Lights up
/// the AV1 chip in AgentsSection when HW AV1 is available. Expected
/// 0 on most boxes today; AV1 HW encode ships on Windows 11 24H2+ with
/// RTX 40+ / Intel Arc / RDNA3+ drivers.
pub(crate) fn probe_av1_adapter_count() -> Result<usize> {
    activate::enumerate_hw_av1_mfts().map(|v| v.len())
}

use sync_pipeline::{MfPipeline, OutputCodec};

/// Public-facing handle. Owns only the command channel; the IMFTransform
/// and every other COM interface live on the pinned worker thread.
pub struct MfEncoder {
    cmd_tx: std_mpsc::Sender<Cmd>,
    width: u32,
    height: u32,
    codec: OutputCodec,
    /// "hw" when the cascade winner was a dedicated HW MFT with a
    /// live D3D11 manager, "sw" when it fell through to
    /// `CLSID_MSH264EncoderMFT` / `HEVCVideoExtensionEncoder`, and
    /// [`BACKEND_PURE_SW`] when that fallback also ignored the D3D
    /// manager. Sent up from the worker through the ready channel at
    /// startup. Consulted by `VideoEncoder::is_hardware`; the peer media
    /// pump reads that to trigger auto-downscale on SW HEVC at 4K.
    backend_kind: &'static str,
}

/// #2283 — the backend kind of the default-adapter software MFT when it
/// also ignored the D3D manager: Microsoft's encoder with no GPU behind it,
/// as on a VM whose only adapter is the Basic Render Driver. On the RTP
/// track it held frames for ~850 ms of input to photon where OpenH264 took
/// 37 ms on the same host, so Auto does not keep it
/// ([`MfEncoder::is_pure_software`]). Rate control reads it as `"sw"`.
pub(crate) const BACKEND_PURE_SW: &str = "sw-pure";

enum Cmd {
    Encode {
        frame: Arc<Frame>,
        reply: oneshot::Sender<Result<Vec<EncodedPacket>>>,
    },
    RequestKeyframe,
    SetBitrate(u32),
    Shutdown,
}

impl MfEncoder {
    /// Build an MF H.264 encoder for a given output resolution.
    /// Convenience wrapper around [`MfEncoder::new_h264`]; pre-existing
    /// call sites in the agent use this.
    pub fn new(width: u32, height: u32) -> Result<Self> {
        Self::new_h264(width, height)
    }

    /// H.264 entry point. Preserves the original probe-and-rollback
    /// cascade behaviour; falls back to the SW `CLSID_MSH264EncoderMFT`
    /// when every HW candidate fails.
    pub fn new_h264(width: u32, height: u32) -> Result<Self> {
        Self::new_internal(width, height, OutputCodec::H264)
    }

    /// HEVC entry point. Walks the same DXGI adapter × HW MFT cascade
    /// but filters for `CLSID_MSH265EncoderMFT` / IHV HEVC encoders.
    /// Returns Err when no HW HEVC path succeeds — Windows ships no
    /// software HEVC encoder so the caller must demote to H.264.
    pub fn new_hevc(width: u32, height: u32) -> Result<Self> {
        Self::new_internal(width, height, OutputCodec::Hevc)
    }

    /// AV1 entry point. HW-only like HEVC; returns Err on cascade
    /// exhaustion so the caller demotes. Expected to fail on most
    /// boxes today — AV1 HW encoders ship on Windows 11 24H2+ with
    /// RTX 40+ / Intel Arc / RDNA3+. On the RTX 5090 Laptop dev box
    /// the NVIDIA AV1 MFT is likely to hit the same Blackwell
    /// `ActivateObject 0x8000FFFF` regression as H.264/HEVC and skip
    /// through to the next candidate.
    pub fn new_av1(width: u32, height: u32) -> Result<Self> {
        Self::new_internal(width, height, OutputCodec::Av1)
    }

    fn new_internal(width: u32, height: u32, codec: OutputCodec) -> Result<Self> {
        if width == 0 || height == 0 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
            bail!("mf-encoder: require non-zero, even dimensions, got {width}x{height}");
        }

        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<&'static str>>();
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();

        thread::Builder::new()
            .name(format!("roomlerd-mf-encoder-{}", codec.backend_name()))
            .spawn(move || {
                // 1. Initialise COM for this thread. MTA because MF is
                //    happy with it and we never touch UI.
                let coinit = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
                if coinit.is_err() {
                    let _ = ready_tx.send(Err(anyhow!("CoInitializeEx failed: {:?}", coinit)));
                    return;
                }

                // 2. Start Media Foundation.
                if let Err(e) = unsafe { MFStartup(windows_mf_version(), MFSTARTUP_FULL) } {
                    unsafe { CoUninitialize() };
                    let _ = ready_tx.send(Err(anyhow!("MFStartup failed: {e:?}")));
                    return;
                }

                // 3. Run the codec-parametric cascade.
                let pipeline =
                    match activate::activate_and_probe_pipeline_for_codec(codec, width, height) {
                        Ok(p) => p,
                        Err(e) => {
                            unsafe { MFShutdown().ok() };
                            unsafe { CoUninitialize() };
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };

                let backend_kind = pipeline.backend_kind();
                let _ = ready_tx.send(Ok(backend_kind));
                run_worker(pipeline, cmd_rx);

                unsafe { MFShutdown().ok() };
                unsafe { CoUninitialize() };
            })
            .map_err(|e| anyhow!("spawning mf worker: {e}"))?;

        let backend_kind = ready_rx
            .recv()
            .map_err(|e| anyhow!("mf worker ack: {e}"))??;

        Ok(Self {
            cmd_tx,
            width,
            height,
            codec,
            backend_kind,
        })
    }

    /// #2283 — did the cascade end on Microsoft's software MFT with no GPU
    /// behind it ([`BACKEND_PURE_SW`])? The same CLSID inside the hardware
    /// loop, or a fallback that took the D3D manager, may hand frames to a
    /// GPU and is not this.
    pub fn is_pure_software(&self) -> bool {
        self.backend_kind == BACKEND_PURE_SW
    }
}

impl Drop for MfEncoder {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown);
    }
}

#[async_trait::async_trait]
impl VideoEncoder for MfEncoder {
    async fn encode(&mut self, frame: Arc<Frame>) -> Result<Vec<EncodedPacket>> {
        if frame.pixel_format != PixelFormat::Bgra {
            bail!(
                "mf-encoder: expected BGRA input, got {:?}",
                frame.pixel_format
            );
        }
        if frame.width != self.width || frame.height != self.height {
            bail!(
                "mf-encoder: frame dim mismatch: configured {}x{}, got {}x{}",
                self.width,
                self.height,
                frame.width,
                frame.height
            );
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Encode {
                frame,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("mf worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("mf worker dropped reply"))?
    }

    fn request_keyframe(&mut self) {
        let _ = self.cmd_tx.send(Cmd::RequestKeyframe);
    }

    fn set_bitrate(&mut self, bps: u32) {
        let _ = self.cmd_tx.send(Cmd::SetBitrate(bps));
    }

    fn name(&self) -> &'static str {
        self.codec.backend_name()
    }

    fn is_hardware(&self) -> bool {
        self.backend_kind == "hw"
    }
}

// ---------------------------------------------------------------------
// Worker loop. Runs on the pinned encoder thread; all COM calls happen
// through `pipeline`.
// ---------------------------------------------------------------------

fn run_worker(mut pipeline: MfPipeline, cmd_rx: std_mpsc::Receiver<Cmd>) {
    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            Cmd::Encode { frame, reply } => {
                let result = pipeline.encode(&frame);
                let _ = reply.send(result);
            }
            Cmd::RequestKeyframe => {
                if let Err(e) = pipeline.force_keyframe() {
                    tracing::debug!(%e, "mf-encoder: force-keyframe failed");
                }
            }
            Cmd::SetBitrate(bps) => {
                if let Err(e) = pipeline.set_bitrate(bps) {
                    tracing::debug!(%e, "mf-encoder: set-bitrate failed");
                }
            }
            Cmd::Shutdown => break,
        }
    }
    // Best-effort flush on the way out.
    let _ = pipeline.end_stream();
}

// ---------------------------------------------------------------------
// Shared D3D11 helpers. Kept in mod.rs until Phase 3 commit 2 replaces
// the default-adapter path with DXGI adapter enumeration.
// ---------------------------------------------------------------------

/// Create a D3D11 device suitable for MF hardware-accelerated video
/// encoding, wrap it in an IMFDXGIDeviceManager, return both. The
/// device needs BGRA_SUPPORT (our input) + VIDEO_SUPPORT (HW video
/// codec access) + multithread protection (MF worker threads call
/// into the device outside our control).
///
/// Feature-level list starts at 11_1 and falls back through 11_0,
/// 10_1, 10_0. Anything below 10_0 can't run MF video encoders.
pub(super) fn create_d3d11_device_and_manager() -> Result<(ID3D11Device, IMFDXGIDeviceManager)> {
    unsafe {
        let feature_levels = [
            D3D_FEATURE_LEVEL_11_1,
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_1,
            D3D_FEATURE_LEVEL_10_0,
        ];
        let mut device: Option<ID3D11Device> = None;
        let mut actual_level = D3D_FEATURE_LEVEL_11_0;
        D3D11CreateDevice(
            None, // default adapter
            D3D_DRIVER_TYPE_HARDWARE,
            windows::Win32::Foundation::HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&feature_levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            Some(&mut actual_level),
            None, // no immediate context needed here
        )
        .map_err(|e| anyhow!("D3D11CreateDevice: {e:?}"))?;
        let device = device.ok_or_else(|| anyhow!("D3D11CreateDevice: null device"))?;

        // Make the device multithread-protected: MF spins its own
        // worker threads that call methods on the D3D device
        // concurrently with ours; without this MF will hit undefined
        // behaviour under contention.
        let mt: ID3D11Multithread = device
            .cast()
            .map_err(|e| anyhow!("ID3D11Multithread cast: {e:?}"))?;
        // Returns the previous protection state as BOOL; we don't care.
        let _ = mt.SetMultithreadProtected(true);

        let mut reset_token: u32 = 0;
        let mut mgr: Option<IMFDXGIDeviceManager> = None;
        MFCreateDXGIDeviceManager(&mut reset_token, &mut mgr)
            .map_err(|e| anyhow!("MFCreateDXGIDeviceManager: {e:?}"))?;
        let mgr = mgr.ok_or_else(|| anyhow!("MFCreateDXGIDeviceManager: null"))?;
        mgr.ResetDevice(&device, reset_token)
            .map_err(|e| anyhow!("IMFDXGIDeviceManager::ResetDevice: {e:?}"))?;

        tracing::info!(
            level = actual_level.0,
            reset_token,
            "mf-encoder: D3D11 device + DXGI manager created"
        );
        Ok((device, mgr))
    }
}

/// MF version number passed to MFStartup. `MF_VERSION` is
/// `(MF_API_VERSION << 16) | MF_SDK_VERSION`; the `windows` crate
/// exposes the constants but not the composed value, so we compose it
/// here — this matches what the Microsoft headers produce.
const fn windows_mf_version() -> u32 {
    // From `mfapi.h`: MF_SDK_VERSION = 0x2, MF_API_VERSION = 0x70.
    0x0002_0070
}
