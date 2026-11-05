// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! D3D11 BGRA video-processor scaling followed by output-size CPU readback.
//! Owns pixel-processing resources only; capture lifetime and fallback policy
//! remain with the caller. The supplied device/context and source share a device.

use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_CPU_ACCESS_READ, D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE,
    D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    D3D11_USAGE_STAGING, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_COLOR_SPACE,
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_STREAM,
    D3D11_VIDEO_USAGE_PLAYBACK_NORMAL, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    ID3D11VideoContext, ID3D11VideoDevice, ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator,
    ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::core::Interface;

/// Cached processor, output and staging textures for one dimensions pair.
pub(crate) struct BgraScaler {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    vdev: ID3D11VideoDevice,
    vctx: ID3D11VideoContext,
    venum: ID3D11VideoProcessorEnumerator,
    vp: ID3D11VideoProcessor,
    key: ((u32, u32), (u32, u32)),
    /// BGRA8 DEFAULT + BIND_RENDER_TARGET output target of the Blt.
    out_tex: ID3D11Texture2D,
    out_view: ID3D11VideoProcessorOutputView,
    /// CPU-readable staging at output dimensions.
    small_staging: ID3D11Texture2D,
    input_needs_copy: bool,
    mid_tex: Option<ID3D11Texture2D>,
}

impl BgraScaler {
    /// Build the whole processor chain for `(in_dims → out_dims)`.
    pub(crate) fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        in_dims: (u32, u32),
        out_dims: (u32, u32),
    ) -> Result<Self, String> {
        if [in_dims.0, in_dims.1, out_dims.0, out_dims.1]
            .iter()
            .any(|&dim| dim == 0 || dim > i32::MAX as u32)
        {
            return Err("scaler dimensions must be nonzero and fit D3D11 rects".into());
        }
        let byte_len = (out_dims.0 as usize)
            .checked_mul(4)
            .and_then(|stride| stride.checked_mul(out_dims.1 as usize));
        if byte_len.is_none_or(|len| len > isize::MAX as usize) {
            return Err("scaled BGRA buffer is too large".into());
        }
        let vdev: ID3D11VideoDevice = device
            .cast()
            .map_err(|e| format!("ID3D11VideoDevice cast: {e}"))?;
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
            device: device.clone(),
            context: context.clone(),
            vdev,
            vctx,
            venum,
            vp,
            key: (in_dims, out_dims),
            out_tex,
            out_view,
            small_staging,
            input_needs_copy: false,
            mid_tex: None,
        })
    }

    pub(crate) fn matches(&self, input_dims: (u32, u32), output_dims: (u32, u32)) -> bool {
        self.key == (input_dims, output_dims)
    }

    /// Scale a BGRA8 texture and return tightly packed BGRA8 pixels.
    /// The texture must match the input dimensions and belong to the
    /// supplied device; the caller serializes use of its immediate context.
    pub(crate) fn read(&mut self, src: &ID3D11Texture2D) -> Result<Vec<u8>, String> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: valid texture and out-param.
        unsafe { src.GetDesc(&mut desc) };
        if (desc.Width, desc.Height) != self.key.0
            || desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM
            || desc.SampleDesc.Count != 1
        {
            return Err("scaler input must match its dimensions and be single-sample BGRA8".into());
        }
        let (tw, th) = self.key.1;
        let (vdev, vctx, venum, vp, out_view, out_tex, small_staging) = {
            let s = &*self;
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
        let view_src: ID3D11Texture2D = if self.input_needs_copy {
            let mid = self.ensure_mid_tex()?;
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
            (Err(_), _) if !self.input_needs_copy => {
                // Some drivers reject a view directly on the input
                // surface — route through one native GPU-GPU copy from
                // now on (still eliminates the big CPU readback).
                self.input_needs_copy = true;
                let mid = self.ensure_mid_tex()?;
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
        // forces GPU completion before the caller can release its source.
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
    /// input route. The scaler owns one fixed input/output dimensions pair.
    fn ensure_mid_tex(&mut self) -> Result<ID3D11Texture2D, String> {
        if let Some(t) = &self.mid_tex {
            return Ok(t.clone());
        }
        let (width, height) = self.key.0;
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
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
        self.mid_tex = Some(t.clone());
        Ok(t)
    }
}
