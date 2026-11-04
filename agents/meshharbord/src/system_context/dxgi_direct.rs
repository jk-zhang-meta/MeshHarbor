// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Direct (adapter-bound) DXGI Desktop Duplication backend for the
//! SYSTEM-context capture path.
//!
//! ## Why this exists (rc.108, Phase 1 of the hybrid-GPU fix)
//!
//! The existing [`super::dxgi_dup::DxgiDupBackend`] wraps `scrap-0.5.0`,
//! which creates its D3D11 device on the *default* adapter and gives the
//! caller no say in adapter / output selection. On a single-GPU box that
//! is fine. On a hybrid "Optimus" laptop — Intel iGPU drives the display,
//! NVIDIA dGPU is render-only with **zero attached outputs** — `scrap`
//! can bind Desktop Duplication to the render-only dGPU; `DuplicateOutput`
//! then fails (the dGPU owns no output to duplicate) and the capture pump
//! falls through to the slow GDI BitBlt path (~85 ms/frame ⇒ ~12 fps).
//! Field host WINHOST-B (rc.105 telemetry: `backend=gdi`, Intel owns the
//! primary output, NVIDIA reports 0 outputs, `scrap::Capturer::new:
//! permission denied`) is the motivating case.
//!
//! This backend talks the `windows` crate's DXGI/D3D11 API directly so we
//! can:
//!   1. enumerate adapters + their outputs (reusing the same logic the
//!      rc.105 [`super::dxgi_util`] diagnostic already proved correct),
//!   2. pick the adapter that **owns the primary output** (its top-left is
//!      the virtual-desktop origin 0,0), and
//!   3. create the D3D11 device on *that* adapter and `DuplicateOutput`
//!      the primary output — so on Optimus we bind to the iGPU, exactly
//!      where the display lives, and DXGI stays on the fast path.
//!
//! On an Intel-only host (WINHOST-E, already 62 fps via the scrap path) the
//! primary-output adapter IS the only adapter, so this backend binds to
//! the same GPU `scrap` would have — no behaviour change, just an explicit
//! adapter handle.
//!
//! ## Same `BackendBail` contract as the scrap backend
//!
//! Implements [`super::dxgi_dup::DxgiCapture`] so the capture pump consumes
//! either backend through one trait object. HRESULT → `BackendBail`:
//!
//! | HRESULT | `BackendBail` | Pump action |
//! |---|---|---|
//! | `DXGI_ERROR_WAIT_TIMEOUT` | `Transient` | retry next tick (static desktop) |
//! | `DXGI_ERROR_ACCESS_LOST` | `AccessLost` | `reset()` (desktop transition / device-lost) |
//! | `E_ACCESSDENIED` | `DesktopMismatch` | `try_change_desktop` then retry |
//! | (other) | `HardError` | fall to scrap → GDI |
//!
//! ## Threading
//!
//! D3D11 device/context + the duplication object have thread affinity at
//! runtime. The capture pump owns one of these on its dedicated
//! `roomlerd-system-capture` thread and drives it synchronously;
//! nobody else touches it. We never send it across threads.
//!
//! ## Feature gating
//!
//! Compiled only when BOTH `mf-encoder` (pulls in the `windows` crate) and
//! `scrap-capture` (the [`DxgiFrame`] / [`DxgiCapture`] surface lives under
//! that flag, and we keep the scrap backend as the fallback) are enabled —
//! i.e. the production `full-hw,system-context` MSI. Builds without
//! `mf-encoder` keep the scrap-only path unchanged.

#![cfg(all(
    target_os = "windows",
    feature = "mf-encoder",
    feature = "scrap-capture"
))]

use std::io;

use windows::Win32::Foundation::{E_ACCESSDENIED, E_FAIL, HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_10_1,
    D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION,
    D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    D3D11_USAGE_STAGING, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_COLOR_SPACE,
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_STREAM,
    D3D11_VIDEO_USAGE_PLAYBACK_NORMAL, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext,
    ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoDevice, ID3D11VideoProcessor,
    ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_R16G16B16A16_FLOAT,
    DXGI_MODE_ROTATION_IDENTITY, DXGI_MODE_ROTATION_UNSPECIFIED, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ADAPTER_FLAG, DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_ERROR_ACCESS_LOST,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_MOVE_RECT, IDXGIAdapter,
    IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
};
use windows::core::Interface;

use super::dxgi_dup::{BackendBail, DxgiCapture, DxgiFrame};
use crate::capture::{Damage, DirtyRect};
use crate::fp16;

/// Phase B — kill switch for the GPU scale-before-readback path.
/// `ROOMLERD_GPU_SCALE=0` (config key `gpu_scale`) reverts to the
/// Phase-A CPU resample per session — a field A/B is one env flip.
fn gpu_scale_enabled() -> bool {
    !matches!(
        tunnel_core::env::node_env("GPU_SCALE").as_deref(),
        Some("0") | Some("false")
    )
}

/// Map a `windows::core::Error` HRESULT to the capture pump's typed bail.
/// Mirrors the scrap backend's `io::ErrorKind`-based table so both DXGI
/// backends route identically through the pump.
fn map_dxgi_err(e: windows::core::Error) -> BackendBail {
    let code = e.code();
    if code == DXGI_ERROR_WAIT_TIMEOUT {
        // No new frame since the last AcquireNextFrame — the desktop is
        // static. Fires constantly on an idle screen; never log it.
        BackendBail::Transient
    } else if code == DXGI_ERROR_ACCESS_LOST {
        // Desktop transition (lock/unlock) or GPU device-lost. Caller
        // rebuilds via reset().
        BackendBail::AccessLost
    } else if code == E_ACCESSDENIED {
        // Thread's desktop binding doesn't match the input desktop.
        BackendBail::DesktopMismatch
    } else {
        BackendBail::HardError(io::Error::other(format!("DXGI-direct: {e}")))
    }
}

/// Adapter-bound DXGI Desktop Duplication. Owns the D3D11 device/context,
/// the duplication object, and a lazily-(re)created CPU-readable staging
/// texture. Not driven from more than one thread.
pub struct DxgiDirectBackend {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    width: u32,
    height: u32,
    /// CPU-readable copy target. `CopyResource` the acquired (GPU-only)
    /// desktop texture into this, then `Map` it for readback. Recreated
    /// when the source dimensions / format change (resolution swap).
    staging: Option<ID3D11Texture2D>,
    staging_w: u32,
    staging_h: u32,
    staging_fmt: DXGI_FORMAT,
    /// rc.207 — half-bits → sRGB-u8 table for FP16 (scRGB) desktops (ACM /
    /// HDR). Built lazily on the first FP16 frame; None on plain BGRA8
    /// desktops. See [`crate::fp16`] for the field incident that motivated
    /// accepting FP16 here instead of bailing to the scrap path (which reads
    /// FP16 surfaces as BGRA8 → purple 2×-zoomed garbage).
    lut: Option<Box<[u8; 65536]>>,
    /// P8a — whether duplication metadata rects can be trusted for this
    /// output. False on rotated panels: this backend copies the surface
    /// RAW (never re-orients), and the metadata's coordinate space vs a
    /// rotated raw surface is ambiguous enough that damage degrades to
    /// `Unknown` there instead of risking wrong-region truth.
    rects_trustworthy: bool,
    /// P8a — at least one image-carrying frame was delivered since the
    /// duplication was (re)created. Guards the pointer-only fast-path:
    /// the FIRST acquire after (re)creation can report
    /// `LastPresentTime == 0` while carrying the current desktop image —
    /// skipping it on a static desktop would black-screen the session
    /// until the first real change.
    delivered_any: bool,
    /// P8a — reused metadata buffers (byte-sized per the API contract:
    /// move rects are 24 B, dirty RECTs 16 B).
    meta_moves: Vec<DXGI_OUTDUPL_MOVE_RECT>,
    meta_dirty: Vec<RECT>,
    /// Phase B — the pump's effective encode box, refreshed on every
    /// `frame()` call from the capture request. `None` = deliver native.
    output_cap: Option<(u32, u32)>,
    /// Phase B — cached VideoProcessor state for the CURRENT
    /// (native → cap) pair. Deliberately KEPT while the cap is `None`
    /// (a refine Up passes native through without touching it), so the
    /// Down↔Up flip cadence never churns creates; rebuilt only when the
    /// dims pair actually changes. Dropped wholesale by `reset()`'s
    /// `*self = Self::primary()?`.
    vp: Option<VpState>,
    /// Phase B — VP failure latch. VP-layer errors are CONTAINED here,
    /// never routed into [`BackendBail`] (three HardErrors would demote
    /// this healthy DXGI backend to the 12 fps GDI path): log once, drop
    /// the state, deliver native, retry no sooner than [`VP_RETRY_AFTER`].
    vp_failed_at: Option<std::time::Instant>,
    /// Phase B — some drivers reject a VP input view created directly on
    /// the duplication surface (E_INVALIDARG). Latched per session: route
    /// through an intermediate GPU copy instead (one native GPU-GPU copy,
    /// still eliminates the big CPU readback).
    vp_input_needs_copy: bool,
    /// The intermediate native-size RENDER_TARGET texture for the
    /// `vp_input_needs_copy` route (lazy).
    vp_mid_tex: Option<ID3D11Texture2D>,
}

/// Retry cadence for a failed VideoProcessor path — long enough that a
/// persistently broken driver costs one attempt a minute, short enough
/// that a transient (device reset mid-session) recovers.
const VP_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// Phase B — cached D3D11 VideoProcessor objects for one
/// (input dims → output dims) pair. See the plan's D3D11 recipe; every
/// interface here is compiled under the already-enabled
/// `Win32_Graphics_Direct3D11` feature.
struct VpState {
    vdev: ID3D11VideoDevice,
    vctx: ID3D11VideoContext,
    venum: ID3D11VideoProcessorEnumerator,
    vp: ID3D11VideoProcessor,
    key: ((u32, u32), (u32, u32)),
    /// BGRA8 DEFAULT + BIND_RENDER_TARGET output target of the Blt.
    out_tex: ID3D11Texture2D,
    out_view: ID3D11VideoProcessorOutputView,
    /// CPU-readable staging at OUTPUT dims — the readback shrinks with
    /// the scale (~3.5× fewer bytes at the 1024 rung on a 1920×1200
    /// panel), which is half the win.
    small_staging: ID3D11Texture2D,
}

impl VpState {
    /// Build the whole processor chain for `(in_dims → out_dims)`.
    /// String errors — the caller latches + logs; nothing here may
    /// escape into the BackendBail taxonomy.
    fn create(
        device: &ID3D11Device,
        in_dims: (u32, u32),
        out_dims: (u32, u32),
    ) -> Result<Self, String> {
        let vdev: ID3D11VideoDevice = device
            .cast()
            .map_err(|e| format!("ID3D11VideoDevice cast: {e}"))?;
        let context = unsafe { device.GetImmediateContext() }
            .map_err(|e| format!("GetImmediateContext: {e}"))?;
        let vctx: ID3D11VideoContext = context
            .cast()
            .map_err(|e| format!("ID3D11VideoContext cast: {e}"))?;
        let cd = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: DXGI_RATIONAL {
                Numerator: 30,
                Denominator: 1,
            },
            InputWidth: in_dims.0,
            InputHeight: in_dims.1,
            OutputFrameRate: DXGI_RATIONAL {
                Numerator: 30,
                Denominator: 1,
            },
            OutputWidth: out_dims.0,
            OutputHeight: out_dims.1,
            Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
        };
        let venum = unsafe { vdev.CreateVideoProcessorEnumerator(&cd) }
            .map_err(|e| format!("CreateVideoProcessorEnumerator: {e}"))?;
        // BGRA8 must be legal on BOTH sides (input 0x1 | output 0x2) —
        // required plumbing on every fleet driver, but not spec-
        // guaranteed, so gate rather than assume.
        let fmt = unsafe { venum.CheckVideoProcessorFormat(DXGI_FORMAT_B8G8R8A8_UNORM) }
            .map_err(|e| format!("CheckVideoProcessorFormat: {e}"))?;
        if fmt & 0x3 != 0x3 {
            return Err(format!("B8G8R8A8 not supported both ways (flags {fmt:#x})"));
        }
        let vp = unsafe { vdev.CreateVideoProcessor(&venum, 0) }
            .map_err(|e| format!("CreateVideoProcessor: {e}"))?;
        // One-time processor state: no driver "enhancement" (Intel's
        // adaptive contrast/denoise mangles screen content), progressive
        // frames, IDENTICAL zeroed colour space on stream + output so no
        // conversion runs (same-space RGB→RGB), source = full input,
        // dest/target = full output (the scale).
        let cs = D3D11_VIDEO_PROCESSOR_COLOR_SPACE::default();
        let src_rect = RECT {
            left: 0,
            top: 0,
            right: in_dims.0 as i32,
            bottom: in_dims.1 as i32,
        };
        let dst_rect = RECT {
            left: 0,
            top: 0,
            right: out_dims.0 as i32,
            bottom: out_dims.1 as i32,
        };
        unsafe {
            vctx.VideoProcessorSetStreamAutoProcessingMode(&vp, 0, false);
            vctx.VideoProcessorSetStreamFrameFormat(&vp, 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
            vctx.VideoProcessorSetStreamColorSpace(&vp, 0, &cs);
            vctx.VideoProcessorSetOutputColorSpace(&vp, &cs);
            vctx.VideoProcessorSetStreamSourceRect(&vp, 0, true, Some(&src_rect));
            vctx.VideoProcessorSetStreamDestRect(&vp, 0, true, Some(&dst_rect));
            vctx.VideoProcessorSetOutputTargetRect(&vp, true, Some(&dst_rect));
        }
        // Blt output: BGRA8, DEFAULT usage, RENDER_TARGET bind (documented
        // requirement for VP output view resources).
        let out_desc = D3D11_TEXTURE2D_DESC {
            Width: out_dims.0,
            Height: out_dims.1,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut out_tex: Option<ID3D11Texture2D> = None;
        unsafe { device.CreateTexture2D(&out_desc, None, Some(&mut out_tex)) }
            .map_err(|e| format!("CreateTexture2D(out): {e}"))?;
        let out_tex = out_tex.ok_or("CreateTexture2D(out) returned None")?;
        let ov_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
            },
        };
        let mut out_view: Option<ID3D11VideoProcessorOutputView> = None;
        unsafe {
            vdev.CreateVideoProcessorOutputView(&out_tex, &venum, &ov_desc, Some(&mut out_view))
        }
        .map_err(|e| format!("CreateVideoProcessorOutputView: {e}"))?;
        let out_view = out_view.ok_or("CreateVideoProcessorOutputView returned None")?;
        // Small CPU staging at output dims.
        let staging_desc = D3D11_TEXTURE2D_DESC {
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
            ..out_desc
        };
        let mut small_staging: Option<ID3D11Texture2D> = None;
        unsafe { device.CreateTexture2D(&staging_desc, None, Some(&mut small_staging)) }
            .map_err(|e| format!("CreateTexture2D(small staging): {e}"))?;
        let small_staging = small_staging.ok_or("CreateTexture2D(small staging) returned None")?;
        Ok(Self {
            vdev,
            vctx,
            venum,
            vp,
            key: (in_dims, out_dims),
            out_tex,
            out_view,
            small_staging,
        })
    }
}

impl DxgiDirectBackend {
    /// Enumerate adapters, find the one owning the primary output, create
    /// a D3D11 device on it, and start Desktop Duplication on that output.
    ///
    /// Returns `BackendBail::HardError` when no adapter owns a primary
    /// output, the desktop format is neither BGRA8 nor FP16 (10-bit etc. —
    /// out of scope; let the caller fall to scrap/GDI), or any DXGI call
    /// fails for a non-typed reason. The capture pump treats a `HardError`
    /// here as "try the next backend" (scrap, then GDI). FP16 (scRGB — the
    /// ACM/HDR desktop composition format) is ACCEPTED since rc.207 and
    /// converted to sRGB BGRA8 per frame via [`crate::fp16`] — critically,
    /// this backend must own that case because the scrap fallback misreads
    /// FP16 surfaces as BGRA8 (field WINHOST-F: purple 2×-zoomed
    /// flicker on every recomposited frame).
    pub fn primary() -> Result<Self, BackendBail> {
        unsafe {
            let factory: IDXGIFactory1 = CreateDXGIFactory1().map_err(map_dxgi_err)?;

            let (adapter, output, adapter_name) =
                find_primary_output(&factory).ok_or_else(|| {
                    BackendBail::HardError(io::Error::other(
                        "DXGI-direct: no adapter owns a primary output at origin (0,0)",
                    ))
                })?;

            // Each step maps to a distinct HRESULT on failure (create:
            // DXGI_ERROR_UNSUPPORTED on an idle Optimus adapter; DuplicateOutput:
            // E_INVALIDARG cross-adapter / E_ACCESSDENIED on the secure desktop),
            // and try_build_dxgi logs the whole error before falling back to
            // scrap — so the message is self-disambiguating without per-step logs.
            let (device, context) = create_device_on(&adapter).map_err(map_dxgi_err)?;

            // Desktop Duplication lives on IDXGIOutput1.
            let output1: IDXGIOutput1 = output.cast().map_err(map_dxgi_err)?;
            let duplication = output1.DuplicateOutput(&device).map_err(map_dxgi_err)?;

            // IDXGIOutputDuplication::GetDesc returns the desc by value
            // (no out-param) in windows-rs 0.58.
            let desc = duplication.GetDesc();
            let width = desc.ModeDesc.Width;
            let height = desc.ModeDesc.Height;

            let desktop_fmt = desc.ModeDesc.Format;
            let fp16 = desktop_fmt == DXGI_FORMAT_R16G16B16A16_FLOAT;
            if desktop_fmt != DXGI_FORMAT_B8G8R8A8_UNORM && !fp16 {
                // 10-bit scanout (R10G10B10A2) and other exotic formats stay
                // out of scope — bail so the pump falls to scrap/GDI. FP16 is
                // handled below (rc.207): it's what ACM/HDR desktops hand out,
                // and the scrap fallback misreads it as BGRA8 (purple garbage),
                // so the direct backend must own that case.
                return Err(BackendBail::HardError(io::Error::other(format!(
                    "DXGI-direct: desktop format {:?} is not BGRA8/FP16 — falling back",
                    desktop_fmt.0
                ))));
            }
            if fp16 {
                // Loud on purpose: this is the observable marker that a host
                // composites in scRGB (Settings → Display → Advanced display →
                // "Automatically manage color for apps", or true HDR). Costs a
                // few ms/frame of CPU convert; turning ACM/HDR off on the host
                // removes it. Field: WINHOST-F purple-flicker incident.
                tracing::warn!(
                    width,
                    height,
                    "DXGI-direct: FP16 (scRGB) desktop detected — ACM/HDR is ON; converting to sRGB on CPU (disable 'Automatically manage color for apps' on this host to avoid the convert cost)"
                );
            }

            tracing::info!(
                adapter = %adapter_name,
                width,
                height,
                fp16,
                "DXGI-direct: bound Desktop Duplication to the primary-output adapter (hybrid-GPU fix)"
            );

            // P8a — metadata rects are only trusted on un-rotated outputs
            // (this backend never re-orients the raw surface copy).
            let rotation = desc.Rotation;
            let rects_trustworthy = rotation == DXGI_MODE_ROTATION_IDENTITY
                || rotation == DXGI_MODE_ROTATION_UNSPECIFIED;
            if !rects_trustworthy {
                tracing::info!(
                    rotation = rotation.0,
                    "DXGI-direct: rotated output — damage metadata degraded to Unknown"
                );
            }

            Ok(Self {
                device,
                context,
                duplication,
                width,
                height,
                staging: None,
                staging_w: 0,
                staging_h: 0,
                staging_fmt: desktop_fmt,
                lut: None,
                rects_trustworthy,
                delivered_any: false,
                meta_moves: Vec::new(),
                meta_dirty: Vec::new(),
                output_cap: None,
                vp: None,
                vp_failed_at: None,
                vp_input_needs_copy: false,
                vp_mid_tex: None,
            })
        }
    }

    /// P8a — read the duplication metadata for the CURRENTLY HELD frame
    /// (valid only between `AcquireNextFrame` and `ReleaseFrame`).
    /// Damage = dirty rects ∪ move DESTINATION rects (the changed-pixel
    /// superset under the API's cumulative-metadata contract), clipped
    /// to the staging dims. Any anomaly (metadata call failure, zero
    /// metadata on an image-carrying frame, buffer weirdness) degrades
    /// to a FULL-FRAME rect — motion-true, never an under-report.
    fn read_damage(&mut self, frame_info: &DXGI_OUTDUPL_FRAME_INFO) -> Damage {
        if !self.rects_trustworthy {
            return Damage::Unknown;
        }
        let full = || {
            Damage::Tracked(vec![DirtyRect {
                x: 0,
                y: 0,
                w: self.width,
                h: self.height,
            }])
        };
        let total = frame_info.TotalMetadataBufferSize as usize;
        if total == 0 {
            // An image-carrying frame with no move/dirty metadata —
            // shouldn't happen for real damage, so claim everything.
            return full();
        }
        const MOVE_SZ: usize = std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>();
        const DIRTY_SZ: usize = std::mem::size_of::<RECT>();
        // The metadata API speaks BYTES, not element counts — lock the
        // struct sizes at compile time (the classic DXGI footgun).
        const _: () = assert!(MOVE_SZ == 24 && DIRTY_SZ == 16);
        // Size each typed buffer to hold the WHOLE metadata block (the
        // API reports one combined byte budget; over-allocating per
        // array is the documented safe pattern).
        self.meta_moves
            .resize(total.div_ceil(MOVE_SZ), DXGI_OUTDUPL_MOVE_RECT::default());
        self.meta_dirty
            .resize(total.div_ceil(DIRTY_SZ), RECT::default());

        let mut moves_bytes: u32 = 0;
        // SAFETY: buffer sized ≥ total bytes; valid only while the frame
        // is held (caller guarantees), out-params valid for the call.
        if unsafe {
            self.duplication.GetFrameMoveRects(
                (self.meta_moves.len() * MOVE_SZ) as u32,
                self.meta_moves.as_mut_ptr(),
                &mut moves_bytes,
            )
        }
        .is_err()
        {
            return full();
        }
        let mut dirty_bytes: u32 = 0;
        // SAFETY: same contract as above.
        if unsafe {
            self.duplication.GetFrameDirtyRects(
                (self.meta_dirty.len() * DIRTY_SZ) as u32,
                self.meta_dirty.as_mut_ptr(),
                &mut dirty_bytes,
            )
        }
        .is_err()
        {
            return full();
        }
        // Byte counts → element counts (the classic DXGI footgun — the
        // API speaks BYTES; a unit test locks the conversion sizes).
        let n_moves = (moves_bytes as usize) / MOVE_SZ;
        let n_dirty = (dirty_bytes as usize) / DIRTY_SZ;
        let mut out = Vec::with_capacity(n_moves + n_dirty);
        let clip = |r: &RECT| -> Option<DirtyRect> {
            let x = r.left.max(0) as u32;
            let y = r.top.max(0) as u32;
            let x1 = (r.right.max(0) as u32).min(self.width);
            let y1 = (r.bottom.max(0) as u32).min(self.height);
            let x = x.min(self.width);
            let y = y.min(self.height);
            (x1 > x && y1 > y).then(|| DirtyRect {
                x,
                y,
                w: x1 - x,
                h: y1 - y,
            })
        };
        for m in &self.meta_moves[..n_moves] {
            if let Some(r) = clip(&m.DestinationRect) {
                out.push(r);
            }
        }
        for d in &self.meta_dirty[..n_dirty] {
            if let Some(r) = clip(d) {
                out.push(r);
            }
        }
        if out.is_empty() {
            // Metadata present but everything clipped away — claim the
            // frame rather than under-report.
            return full();
        }
        Damage::Tracked(out)
    }

    /// Ensure `self.staging` is a STAGING texture matching the acquired
    /// frame's dimensions + format. Recreates on a resolution change and
    /// updates `self.width`/`height` to the authoritative texture size.
    fn ensure_staging(&mut self, src: &ID3D11Texture2D) -> Result<(), BackendBail> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: src is a valid ID3D11Texture2D from AcquireNextFrame.
        unsafe { src.GetDesc(&mut desc) };

        let stale = match self.staging {
            Some(_) => {
                self.staging_w != desc.Width
                    || self.staging_h != desc.Height
                    || self.staging_fmt != desc.Format
            }
            None => true,
        };
        if !stale {
            return Ok(());
        }

        // Start from the source texture's desc and override usage/access so
        // the staging copy is CPU-readable. The flag fields are raw u32 in
        // windows-rs 0.58 (not the typed newtypes used at the call sites).
        let mut sdesc = desc;
        sdesc.Usage = D3D11_USAGE_STAGING;
        sdesc.BindFlags = 0;
        sdesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
        sdesc.MiscFlags = 0;

        let mut staging: Option<ID3D11Texture2D> = None;
        // SAFETY: sdesc is fully initialised; no initial data; out-param.
        unsafe {
            self.device
                .CreateTexture2D(&sdesc, None, Some(&mut staging))
        }
        .map_err(map_dxgi_err)?;
        let staging = staging.ok_or_else(|| {
            BackendBail::HardError(io::Error::other(
                "DXGI-direct: CreateTexture2D null staging",
            ))
        })?;

        self.staging = Some(staging);
        self.staging_w = desc.Width;
        self.staging_h = desc.Height;
        self.staging_fmt = desc.Format;
        // Authoritative dimensions come from the actual desktop texture,
        // not the duplication ModeDesc (handles a mid-session resolution
        // change without a full reset()).
        self.width = desc.Width;
        self.height = desc.Height;
        Ok(())
    }

    /// Phase B — attempt the GPU scale-before-readback path. `Some` =
    /// a scaled frame was produced (source = native dims; damage is
    /// stamped by `frame()`); `None` = take the native CPU path (cap
    /// absent/not-a-shrink, rotated output, FP16/HDR desktop, VP
    /// unavailable, or a contained VP failure). NOTHING here may
    /// surface as a [`BackendBail`] — a VP quirk must not cost this
    /// healthy backend its DXGI seat.
    fn try_gpu_scaled(&mut self, src: &ID3D11Texture2D) -> Option<DxgiFrame> {
        if !gpu_scale_enabled() {
            return None;
        }
        let (tw, th) = self.output_cap?;
        if tw == 0 || th == 0 || (tw >= self.width && th >= self.height) {
            return None; // shrink-only; cap-at-native is a passthrough
        }
        if !self.rects_trustworthy {
            return None; // rotated output — v1 exclusion (raw-copy path)
        }
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: valid texture + out-param.
        unsafe { src.GetDesc(&mut desc) };
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return None; // FP16/scRGB (ACM/HDR) — v1 exclusion, LUT path
        }
        if let Some(when) = self.vp_failed_at {
            if when.elapsed() < VP_RETRY_AFTER {
                return None;
            }
            self.vp_failed_at = None;
        }
        let need = ((self.width, self.height), (tw, th));
        if self.vp.as_ref().map(|v| v.key) != Some(need) {
            tracing::info!(
                in_w = self.width,
                in_h = self.height,
                out_w = tw,
                out_h = th,
                src_bind_flags = desc.BindFlags,
                "DXGI-direct: building GPU scale-before-readback (D3D11 VideoProcessor)"
            );
            match VpState::create(&self.device, need.0, need.1) {
                Ok(v) => self.vp = Some(v),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        retry_s = VP_RETRY_AFTER.as_secs(),
                        "DXGI-direct: VideoProcessor unavailable — staying on the CPU resample path"
                    );
                    self.vp = None;
                    self.vp_failed_at = Some(std::time::Instant::now());
                    return None;
                }
            }
        }
        match self.vp_blt_and_read(src, tw, th) {
            Ok(bytes) => Some(DxgiFrame {
                bytes,
                width: tw,
                height: th,
                stride: tw * 4,
                // Stamped (and scaled) by frame() while the dup frame is
                // still held — same flow as the native path.
                damage: Damage::Unknown,
                source: Some((self.width, self.height)),
            }),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    retry_s = VP_RETRY_AFTER.as_secs(),
                    "DXGI-direct: GPU scale failed — delivering native (CPU resample fallback)"
                );
                self.vp = None;
                self.vp_failed_at = Some(std::time::Instant::now());
                None
            }
        }
    }

    /// The per-frame VP work: input view (direct on the dup surface, or
    /// through the intermediate copy once a driver rejects the direct
    /// view) → Blt → copy to the SMALL staging → packed readback. String
    /// errors only — the caller owns containment.
    fn vp_blt_and_read(
        &mut self,
        src: &ID3D11Texture2D,
        tw: u32,
        th: u32,
    ) -> Result<Vec<u8>, String> {
        let (vdev, vctx, venum, vp, out_view, out_tex, small_staging) = {
            let s = self.vp.as_ref().ok_or("vp state missing")?;
            (
                s.vdev.clone(),
                s.vctx.clone(),
                s.venum.clone(),
                s.vp.clone(),
                s.out_view.clone(),
                s.out_tex.clone(),
                s.small_staging.clone(),
            )
        };
        let iv_desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPIV {
                    MipSlice: 0,
                    ArraySlice: 0,
                },
            },
        };
        let view_src: ID3D11Texture2D = if self.vp_input_needs_copy {
            let mid = self.ensure_vp_mid_tex()?;
            // SAFETY: dim/format-matched textures on the owning context.
            unsafe { self.context.CopyResource(&mid, src) };
            mid
        } else {
            src.clone()
        };
        let mut in_view: Option<ID3D11VideoProcessorInputView> = None;
        // SAFETY: valid resource/enumerator/desc + out-param.
        let created = unsafe {
            vdev.CreateVideoProcessorInputView(&view_src, &venum, &iv_desc, Some(&mut in_view))
        };
        let in_view = match (created, in_view) {
            (Ok(()), Some(v)) => v,
            (Err(e), _) if !self.vp_input_needs_copy => {
                // Some drivers reject a view directly on the duplication
                // surface — route through one native GPU-GPU copy from
                // now on (still eliminates the big CPU readback).
                tracing::info!(
                    error = %e,
                    "DXGI-direct: direct VP input view rejected — switching to the intermediate-copy route"
                );
                self.vp_input_needs_copy = true;
                let mid = self.ensure_vp_mid_tex()?;
                // SAFETY: as above.
                unsafe { self.context.CopyResource(&mid, src) };
                let mut retry: Option<ID3D11VideoProcessorInputView> = None;
                // SAFETY: as above.
                unsafe {
                    vdev.CreateVideoProcessorInputView(&mid, &venum, &iv_desc, Some(&mut retry))
                }
                .map_err(|e| format!("CreateVideoProcessorInputView(mid): {e}"))?;
                retry.ok_or("CreateVideoProcessorInputView(mid) returned None")?
            }
            (Err(e), _) => return Err(format!("CreateVideoProcessorInputView: {e}")),
            (Ok(()), None) => return Err("CreateVideoProcessorInputView returned None".into()),
        };
        // ⚠ windows-rs 0.58 footgun: `pInputSurface` is
        // `ManuallyDrop<Option<…>>` — reclaim the COM ref after the call
        // (win or lose) or leak one reference per frame.
        let mut streams = [D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            OutputIndex: 0,
            InputFrameOrField: 0,
            PastFrames: 0,
            FutureFrames: 0,
            ppPastSurfaces: std::ptr::null_mut(),
            pInputSurface: std::mem::ManuallyDrop::new(Some(in_view)),
            ppFutureSurfaces: std::ptr::null_mut(),
            ppPastSurfacesRight: std::ptr::null_mut(),
            pInputSurfaceRight: std::mem::ManuallyDrop::new(None),
            ppFutureSurfacesRight: std::ptr::null_mut(),
        }];
        // SAFETY: processor/view/streams all valid for the call.
        let blt = unsafe { vctx.VideoProcessorBlt(&vp, &out_view, 0, &streams) };
        // SAFETY: reclaiming the ref we placed above, exactly once.
        unsafe { std::mem::ManuallyDrop::drop(&mut streams[0].pInputSurface) };
        blt.map_err(|e| format!("VideoProcessorBlt: {e}"))?;
        // SAFETY: dim/format-matched DEFAULT → STAGING copy.
        unsafe { self.context.CopyResource(&small_staging, &out_tex) };
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: staging texture with CPU read; out-param valid. The Map
        // is what forces GPU completion before ReleaseFrame — same
        // discipline as the native readback, now over ~3.5× fewer bytes.
        unsafe {
            self.context
                .Map(&small_staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }
        .map_err(|e| format!("Map(small staging): {e}"))?;
        let w = tw as usize;
        let h = th as usize;
        let stride = w * 4;
        let mut bytes = vec![0u8; stride * h];
        // SAFETY: mapped region holds RowPitch*h bytes; per-row copy is
        // bounded by min(stride, RowPitch) on both sides.
        unsafe {
            let src_ptr = mapped.pData as *const u8;
            let row_pitch = mapped.RowPitch as usize;
            let copy_w = stride.min(row_pitch);
            for y in 0..h {
                std::ptr::copy_nonoverlapping(
                    src_ptr.add(y * row_pitch),
                    bytes.as_mut_ptr().add(y * stride),
                    copy_w,
                );
            }
            self.context.Unmap(&small_staging, 0);
        }
        Ok(bytes)
    }

    /// Lazy native-size RENDER_TARGET texture for the intermediate-copy
    /// input route. Rebuilt when the native dims change; dropped with
    /// the backend on `reset()`.
    fn ensure_vp_mid_tex(&mut self) -> Result<ID3D11Texture2D, String> {
        if let Some(t) = &self.vp_mid_tex {
            let mut d = D3D11_TEXTURE2D_DESC::default();
            // SAFETY: valid texture + out-param.
            unsafe { t.GetDesc(&mut d) };
            if d.Width == self.width && d.Height == self.height {
                return Ok(t.clone());
            }
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: self.width,
            Height: self.height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut t: Option<ID3D11Texture2D> = None;
        // SAFETY: valid desc + out-param.
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut t)) }
            .map_err(|e| format!("CreateTexture2D(mid): {e}"))?;
        let t = t.ok_or("CreateTexture2D(mid) returned None")?;
        self.vp_mid_tex = Some(t.clone());
        Ok(t)
    }

    /// Copy the acquired GPU texture into the staging texture, map it, and
    /// read out a tightly-packed BGRA8 buffer. Called between
    /// AcquireNextFrame and ReleaseFrame.
    fn read_acquired(&mut self, resource: Option<IDXGIResource>) -> Result<DxgiFrame, BackendBail> {
        let resource = resource.ok_or_else(|| {
            BackendBail::HardError(io::Error::other(
                "DXGI-direct: AcquireNextFrame returned a null resource",
            ))
        })?;
        let src: ID3D11Texture2D = resource.cast().map_err(map_dxgi_err)?;

        // Phase B — GPU scale-before-readback when the pump asked for a
        // smaller box and the path is available. Any refusal or failure
        // falls through to the native readback below unchanged.
        if let Some(f) = self.try_gpu_scaled(&src) {
            return Ok(f);
        }

        self.ensure_staging(&src)?;
        let staging = self
            .staging
            .as_ref()
            .expect("ensure_staging guarantees Some on Ok");

        // GPU copy desktop → CPU-readable staging.
        // SAFETY: staging + src are valid, format/dim-matched textures.
        unsafe { self.context.CopyResource(staging, &src) };

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: staging is a STAGING texture with CPU read access; the
        // mapped out-param is valid for the duration of the call.
        unsafe {
            self.context
                .Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }
        .map_err(map_dxgi_err)?;

        let w = self.width as usize;
        let h = self.height as usize;
        let stride = w * 4;
        let mut bytes = vec![0u8; stride * h];
        if self.staging_fmt == DXGI_FORMAT_R16G16B16A16_FLOAT {
            // rc.207 — FP16 (scRGB) desktop: convert each RGBA16F row (8 B/px)
            // to BGRA8 through the half→sRGB LUT. `ensure_staging` keeps
            // `staging_fmt` in sync with the ACTUAL acquired texture, so an
            // ACM toggle mid-session flips this branch on the next frame.
            let lut = self.lut.get_or_insert_with(fp16::build_half_to_srgb_lut);
            // SAFETY: mapped.pData points to at least RowPitch*height bytes;
            // each row slice is bounded by min(w, RowPitch/8) pixels so we
            // never over-read a row (RowPitch >= w*8 in practice — driver
            // pads rows up), and the dst row is exactly `stride` bytes.
            unsafe {
                let src_ptr = mapped.pData as *const u8;
                let row_pitch = mapped.RowPitch as usize;
                let px = w.min(row_pitch / 8);
                for y in 0..h {
                    let src_row = std::slice::from_raw_parts(src_ptr.add(y * row_pitch), px * 8);
                    fp16::convert_row_rgba16f_to_bgra8(
                        src_row,
                        &mut bytes[y * stride..(y + 1) * stride],
                        px,
                        lut,
                    );
                }
                self.context.Unmap(staging, 0);
            }
        } else {
            // SAFETY: mapped.pData points to at least RowPitch*height bytes;
            // we copy min(stride, RowPitch) per row into a stride*height buf,
            // so neither side is over-read / over-written. RowPitch >= stride
            // always (driver pads rows up), so copy_w == stride in practice.
            unsafe {
                let src_ptr = mapped.pData as *const u8;
                let row_pitch = mapped.RowPitch as usize;
                let copy_w = stride.min(row_pitch);
                for y in 0..h {
                    std::ptr::copy_nonoverlapping(
                        src_ptr.add(y * row_pitch),
                        bytes.as_mut_ptr().add(y * stride),
                        copy_w,
                    );
                }
                self.context.Unmap(staging, 0);
            }
        }

        Ok(DxgiFrame {
            bytes,
            width: self.width,
            height: self.height,
            stride: stride as u32,
            damage: Damage::Unknown,
            source: None,
        })
    }
}

impl DxgiCapture for DxgiDirectBackend {
    fn frame(&mut self, output_cap: Option<(u32, u32)>) -> Result<DxgiFrame, BackendBail> {
        // Phase B field fix (2026-08-21, winhost-a/corplap): a refine Up flips the
        // cap Some→None while the desktop is AT REST — but every real frame
        // delivered under the rung was GPU-scaled, so the pump's keepalive
        // holds no native pixels and the "crisp native IDR" can never ship
        // ("text doesn't crystallize", heartbeats pinned at width=1024
        // after every Up). Desktop Duplication cannot re-deliver a static
        // desktop on demand — but the FIRST acquire after a duplication
        // (re)creation carries the CURRENT image (the delivered_any guard
        // exists for exactly that). Surface AccessLost here: the pump's
        // standard recovery rebuilds this backend, and the next acquire
        // hands the pump a native frame to refine from. Cost: one backend
        // rebuild per cap-LIFT, bounded by the refine Up cooldown; the
        // Down direction needs nothing (motion is flowing by definition).
        if output_cap.is_none() && self.output_cap.is_some() {
            self.output_cap = None;
            tracing::debug!(
                "DXGI-direct: output cap lifted at rest — recycling duplication so the native redeliver can ship"
            );
            return Err(BackendBail::AccessLost);
        }
        self.output_cap = output_cap;
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        // timeout=0 → non-blocking: returns DXGI_ERROR_WAIT_TIMEOUT
        // immediately on a static desktop (mapped to Transient). The
        // capture pump owns cadence; we never block the worker thread.
        // SAFETY: out-params are valid; duplication is live.
        unsafe {
            self.duplication
                .AcquireNextFrame(0, &mut frame_info, &mut resource)
        }
        .map_err(map_dxgi_err)?;

        // P8a — pointer-only update (mouse moved, no image change):
        // release + Transient instead of paying an 8-33 MB readback and
        // surfacing a fake "real frame" that blocks the idle-refine
        // keepalive path during mouse wiggle (and feeds the settle gate
        // a phantom burst). Guarded by `delivered_any`: the FIRST
        // acquire after (re)creation can carry the current desktop
        // image with LastPresentTime==0 — skipping it on a static
        // desktop would black-screen the session until the next change.
        if self.delivered_any
            && frame_info.LastPresentTime == 0
            && frame_info.AccumulatedFrames == 0
        {
            // SAFETY: pairs with the successful AcquireNextFrame above.
            unsafe {
                if let Err(e) = self.duplication.ReleaseFrame() {
                    tracing::trace!(?e, "DXGI-direct: ReleaseFrame (non-fatal)");
                }
            }
            return Err(BackendBail::Transient);
        }

        // From here we hold the frame and MUST ReleaseFrame before the
        // next AcquireNextFrame, on every path. read_acquired never
        // touches self.duplication, so the borrows don't overlap; the
        // metadata read MUST happen while the frame is still held.
        let mut result = self.read_acquired(resource);
        if let Ok(f) = result.as_mut() {
            f.damage = self.read_damage(&frame_info);
            // Phase B — a GPU-scaled frame's damage must share ITS
            // coordinate space (the codebase invariant behind
            // area_permille + ROI hints); the duplication metadata is in
            // native coords, so re-project it through the same per-edge
            // floor/ceil the CPU resample uses.
            if let Some((nw, nh)) = f.source {
                f.damage = crate::capture::scale_damage(&f.damage, nw, nh, f.width, f.height);
            }
            self.delivered_any = true;
        }
        // SAFETY: pairs with the AcquireNextFrame that just succeeded.
        unsafe {
            if let Err(e) = self.duplication.ReleaseFrame() {
                tracing::trace!(?e, "DXGI-direct: ReleaseFrame (non-fatal)");
            }
        }
        result
    }

    fn reset(&mut self) -> Result<(), BackendBail> {
        // Rebuild everything (adapter re-enum + device + duplication). The
        // display config may have changed across the AccessLost (resolution
        // swap during a lock screen), so re-deriving from scratch is the
        // safe move — same as the scrap backend's reset().
        *self = Self::primary()?;
        Ok(())
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn kind(&self) -> &'static str {
        // Distinct name so the capture-timing heartbeat (`backend=` field in
        // agent_logs) shows fleet-wide which hosts are paying the FP16
        // convert — the observable half of the rc.207 ACM/HDR fix.
        if self.staging_fmt == DXGI_FORMAT_R16G16B16A16_FLOAT {
            "dxgi-direct-fp16"
        } else {
            "dxgi-direct"
        }
    }
}

/// Walk every DXGI adapter + output; return the (adapter, output, adapter
/// name) that owns the primary output — the one whose desktop rect top-left
/// is the virtual-desktop origin (0,0). Software adapters are skipped. This
/// is the adapter Desktop Duplication must bind to; on Optimus it's the
/// iGPU (the dGPU owns no output).
///
/// # Safety
/// Calls DXGI enumeration vtable methods; `factory` must be a live
/// `IDXGIFactory1`.
unsafe fn find_primary_output(
    factory: &IDXGIFactory1,
) -> Option<(IDXGIAdapter1, IDXGIOutput, String)> {
    let mut adapter_index = 0u32;
    loop {
        let adapter: IDXGIAdapter1 = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(a) => a,
            Err(_) => break,
        };
        adapter_index += 1;

        let desc1 = unsafe { adapter.GetDesc1() }.ok();
        // Skip software / WARP adapters — they own no real display output.
        if let Some(d) = &desc1
            && (DXGI_ADAPTER_FLAG(d.Flags as i32).0 & DXGI_ADAPTER_FLAG_SOFTWARE.0) != 0
        {
            continue;
        }
        let name = desc1
            .as_ref()
            .map(|d| utf16_trim(&d.Description))
            .unwrap_or_default();

        let mut output_index = 0u32;
        loop {
            let output: IDXGIOutput = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(o) => o,
                Err(_) => break,
            };
            output_index += 1;
            if let Ok(od) = unsafe { output.GetDesc() } {
                let r = od.DesktopCoordinates;
                if od.AttachedToDesktop.as_bool() && r.left == 0 && r.top == 0 {
                    return Some((adapter, output, name));
                }
            }
        }
    }
    None
}

/// Build a D3D11 device + immediate context bound to a specific adapter.
/// Driver type MUST be `UNKNOWN` when an explicit adapter is supplied
/// (passing HARDWARE is the canonical DXGI foot-gun → `E_INVALIDARG`).
/// BGRA support is required so the BGRA8 desktop texture maps cleanly.
///
/// # Safety
/// Calls `D3D11CreateDevice`; `adapter` must be a live `IDXGIAdapter1`.
unsafe fn create_device_on(
    adapter: &IDXGIAdapter1,
) -> windows::core::Result<(ID3D11Device, ID3D11DeviceContext)> {
    let adapter_base: IDXGIAdapter = adapter.cast()?;
    let feature_levels = [
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    ];
    // Phase B — VIDEO_SUPPORT so the ID3D11VideoDevice/-Context casts for
    // the GPU scale-before-readback path succeed reliably; retry WITHOUT
    // the flag on failure (Basic Display Adapter / IddCx indirect displays
    // / stripped VMs can reject it, and capture must survive there — the
    // VP path then simply reports unavailable and the CPU resample runs).
    let attempt = |flags| {
        let mut dev: Option<ID3D11Device> = None;
        let mut ctx: Option<ID3D11DeviceContext> = None;
        let mut lvl = D3D_FEATURE_LEVEL_11_0;
        // SAFETY: out-params valid; adapter is live.
        unsafe {
            D3D11CreateDevice(
                &adapter_base,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                flags,
                Some(&feature_levels),
                D3D11_SDK_VERSION,
                Some(&mut dev),
                Some(&mut lvl),
                Some(&mut ctx),
            )
        }
        .map(|_| (dev, ctx))
    };
    let (device, context) = match attempt(
        D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::info!(
                error = %e,
                "DXGI-direct: device creation with VIDEO_SUPPORT failed — retrying without (GPU scale will be unavailable)"
            );
            attempt(D3D11_CREATE_DEVICE_BGRA_SUPPORT)?
        }
    };
    let device = device.ok_or_else(|| windows::core::Error::from(E_FAIL))?;
    let context = context.ok_or_else(|| windows::core::Error::from(E_FAIL))?;
    Ok((device, context))
}

/// Trim a fixed-size NUL-terminated UTF-16 buffer (adapter description) to
/// a `String`.
fn utf16_trim(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_dxgi_err_classifies_typed_hresults() {
        assert!(matches!(
            map_dxgi_err(windows::core::Error::from(DXGI_ERROR_WAIT_TIMEOUT)),
            BackendBail::Transient
        ));
        assert!(matches!(
            map_dxgi_err(windows::core::Error::from(DXGI_ERROR_ACCESS_LOST)),
            BackendBail::AccessLost
        ));
        assert!(matches!(
            map_dxgi_err(windows::core::Error::from(E_ACCESSDENIED)),
            BackendBail::DesktopMismatch
        ));
        assert!(matches!(
            map_dxgi_err(windows::core::Error::from(E_FAIL)),
            BackendBail::HardError(_)
        ));
    }

    #[test]
    fn utf16_trim_stops_at_nul() {
        let mut buf = [0u16; 8];
        for (i, c) in "GPU".encode_utf16().enumerate() {
            buf[i] = c;
        }
        assert_eq!(utf16_trim(&buf), "GPU");
    }

    #[test]
    fn primary_does_not_panic_under_test_runner() {
        // On a real Win11 desktop this binds to the primary-output
        // adapter; on headless CI it returns HardError at factory /
        // enumeration. Lock against panic, not a specific outcome.
        let _ = DxgiDirectBackend::primary();
    }
}
