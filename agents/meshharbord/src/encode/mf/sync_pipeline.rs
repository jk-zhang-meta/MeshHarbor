// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Synchronous Media Foundation H.264 encoder pipeline.
//!
//! Owns the MFT, the D3D11 device + DXGI manager, and all input/output
//! media-type state. Every method runs on the pinned worker thread
//! created by [`super::MfEncoder`]; nothing here is thread-safe on its
//! own. The sync in the name distinguishes it from the async-MFT
//! pipeline that Phase 3 commit 4 introduces for Intel QSV.

#![cfg(all(target_os = "windows", feature = "mf-encoder"))]

use anyhow::{Result, anyhow, bail};

use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, E_NOTIMPL};
use windows::Win32::Graphics::Direct3D11::ID3D11Device;
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonBufferSize, CODECAPI_AVEncCommonMaxBitRate,
    CODECAPI_AVEncCommonMeanBitRate, CODECAPI_AVEncCommonRateControlMode,
    CODECAPI_AVEncH264CABACEnable, CODECAPI_AVEncMPVGOPSize, CODECAPI_AVEncVideoForceKeyFrame,
    CODECAPI_AVEncVideoGradualIntraRefresh, CODECAPI_AVLowLatencyMode, ICodecAPI,
    IMFDXGIDeviceManager, IMFMediaBuffer, IMFMediaType, IMFSample, IMFTransform, MF_E_NOTACCEPTING,
    MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_MT_AVG_BITRATE,
    MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE, MFCreateMediaType, MFCreateMemoryBuffer,
    MFCreateSample, MFMediaType_Video, MFT_MESSAGE_COMMAND_FLUSH,
    MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
    MFT_MESSAGE_NOTIFY_END_STREAMING, MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_INFO, MFVideoFormat_AV1, MFVideoFormat_H264, MFVideoFormat_HEVC,
    MFVideoFormat_NV12, MFVideoInterlace_Progressive, eAVEncCommonRateControlMode_CBR,
    eAVEncCommonRateControlMode_LowDelayVBR,
};
use windows::core::{GUID, Interface};

/// Output codec selector for the shared sync pipeline. H.264, HEVC, and
/// AV1 share ~90% of the MF wiring (input = NV12, same latency knobs,
/// same rate control, same GOP size, same force-keyframe behaviour);
/// what differs per codec:
///
/// - Output subtype GUID (`MFVideoFormat_{H264,HEVC,AV1}`)
/// - H.264 CABAC enable knob: only meaningful for H.264; HEVC always
///   uses CABAC (spec-mandatory), AV1 doesn't use it (different entropy
///   coding entirely).
/// - Keyframe detection heuristic: H.264 and HEVC emit Annex-B-framed
///   NALUs, AV1 emits raw OBU sequences with length-prefixed elements.
///
/// Exposed pub(crate) so `encode::mod` can pick the codec without
/// reaching into this module's privates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputCodec {
    H264,
    Hevc,
    Av1,
}

impl OutputCodec {
    /// Stable name for logging + `VideoEncoder::name()`.
    pub(crate) fn backend_name(&self) -> &'static str {
        match self {
            Self::H264 => "mf-h264",
            Self::Hevc => "mf-h265",
            Self::Av1 => "mf-av1",
        }
    }

    fn subtype_guid(&self) -> GUID {
        match self {
            Self::H264 => MFVideoFormat_H264,
            Self::Hevc => MFVideoFormat_HEVC,
            Self::Av1 => MFVideoFormat_AV1,
        }
    }
}

use super::super::EncodedPacket;
use crate::capture::Frame;
use crate::encode::color;

/// Frame-rate the MFT is told about. Has to match the
/// `MF_MT_FRAME_RATE` we set on input/output media types so the VBV
/// buffer math (one frame's worth of bits) stays consistent with the
/// MFT's internal pacer. Currently a constant; once 1F.1 lands the
/// agent's media pump can pick this dynamically and re-init the
/// pipeline on a resolution/fps change.
const TARGET_FPS_NUM: u32 = 30;
const TARGET_FPS_DEN: u32 = 1;
const TARGET_FPS: u32 = TARGET_FPS_NUM / TARGET_FPS_DEN;

/// MF pipeline owner. Everything COM-touching lives in here, on the worker.
pub(super) struct MfPipeline {
    transform: IMFTransform,
    codec_api: ICodecAPI,
    /// D3D11 device + DXGI manager kept alive for the MFT's lifetime.
    /// Hardware MFTs (NVIDIA NVENC, Intel QSV, AMD AMF) and
    /// CLSID_MSH264EncoderMFT on a box with HW acceleration drivers
    /// installed require this handoff before they'll produce output.
    /// Without it NVENC ActivateObject returns 0x8000FFFF and the MS
    /// MFT silently returns NEED_MORE_INPUT forever. The device must
    /// outlive the transform — dropping it early would leave the MFT
    /// holding a dangling manager reference.
    _d3d_device: Option<ID3D11Device>,
    _d3d_manager: Option<IMFDXGIDeviceManager>,
    width: u32,
    height: u32,
    frame_count: u64,
    codec: OutputCodec,
    /// Reported upward to `MfEncoder::is_hardware()`. Set by
    /// `build_sync_pipeline` based on whether a D3D manager handoff
    /// actually stuck (i.e. whether `_d3d_device` is `Some`). The
    /// `peer` media pump consults this to auto-downscale the capture
    /// resolution when SW HEVC wins at 4K — the cascade-winner log
    /// line is "HW pipeline active" regardless of actual backend, so
    /// log-parsing wouldn't work.
    backend_kind: &'static str,
}

impl MfPipeline {
    pub(super) fn backend_kind(&self) -> &'static str {
        self.backend_kind
    }
}

impl MfPipeline {
    /// Build a pipeline from an already-activated [`IMFTransform`].
    ///
    /// Caller contract (satisfied by the cascade in [`super::activate`]):
    /// - transform has been activated via `IMFActivate::ActivateObject`
    ///   (HW path) or `CoCreateInstance(CLSID_MSH264EncoderMFT)` (SW).
    /// - D3D manager, if any, has already been bound via
    ///   `MFT_MESSAGE_SET_D3D_MANAGER`.
    /// - `MF_TRANSFORM_ASYNC_UNLOCK` has already been applied if the MFT
    ///   reports async. Async-only MFTs should never reach this path;
    ///   they get routed to the async pipeline instead.
    ///
    /// `backend_kind` selects rate-control mode: `"hw"` → CBR (NVENC,
    /// QSV, AMF all honour it), `"sw"` or `"sw-pure"` → LowDelayVBR (MS SW MFT rejects
    /// CBR + LowLatency combo and silently falls back to quality-VBR,
    /// overshooting target bitrate ~5×). Either value is shared with
    /// the cascade logger via the returned pipeline's name.
    ///
    /// `_d3d_device` and `_d3d_manager` are kept as fields so the MFT's
    /// weak references remain valid for the pipeline's lifetime.
    pub(super) fn new(
        transform: IMFTransform,
        d3d_device: Option<ID3D11Device>,
        d3d_manager: Option<IMFDXGIDeviceManager>,
        backend_kind: &'static str,
        width: u32,
        height: u32,
        codec: OutputCodec,
    ) -> Result<Self> {
        unsafe {
            // Set output type first (required by the MFT contract).
            let out_type = build_output_media_type(width, height, codec)?;
            transform
                .SetOutputType(0, &out_type, 0)
                .map_err(|e| anyhow!("SetOutputType: {e:?}"))?;

            let in_type = build_input_media_type(width, height)?;
            transform
                .SetInputType(0, &in_type, 0)
                .map_err(|e| anyhow!("SetInputType: {e:?}"))?;

            // Latency + rate-control knobs.
            let codec_api: ICodecAPI = transform
                .cast()
                .map_err(|e| anyhow!("MFT does not expose ICodecAPI: {e:?}"))?;
            set_codec_bool(&codec_api, &CODECAPI_AVLowLatencyMode, true)?;
            // H.264: CABAC is an off-by-default knob the encoder picks
            // up at init; enable for better compression at our bitrate.
            // HEVC: CABAC is mandatory in the spec (no CAVLC alternative),
            // so the knob is irrelevant — skip to avoid logging every
            // session about an "unsupported codec key" that's not
            // actually a problem.
            if matches!(codec, OutputCodec::H264) {
                set_codec_bool(&codec_api, &CODECAPI_AVEncH264CABACEnable, true)?;
            }
            let rc_mode = if backend_kind == "hw" {
                eAVEncCommonRateControlMode_CBR.0 as u32
            } else {
                eAVEncCommonRateControlMode_LowDelayVBR.0 as u32
            };
            set_codec_u32(&codec_api, &CODECAPI_AVEncCommonRateControlMode, rc_mode)?;
            set_codec_u32(&codec_api, &CODECAPI_AVEncMPVGOPSize, 60)?;
            let initial_bps = crate::encode::initial_bitrate_for(width, height);
            set_codec_u32(&codec_api, &CODECAPI_AVEncCommonMeanBitRate, initial_bps)?;
            // Max bitrate cap for VBR modes — prevents the encoder
            // from bursting way over target on complex frames. 1.5×
            // the mean as a reasonable ceiling.
            set_codec_u32(
                &codec_api,
                &CODECAPI_AVEncCommonMaxBitRate,
                initial_bps.saturating_mul(3) / 2,
            )?;

            // VBV buffer = one frame's worth of bits (≈ initial_bps /
            // fps). Tight buffers cap per-frame burst at ~1× the
            // average frame size, so a 6 Mbps stream emits roughly
            // 25 KB max per frame at 30 fps instead of letting the
            // encoder spend a 200 KB budget at the start of a GOP.
            // This is the single biggest knob for cutting glass-to-
            // glass latency under WAN — without it WebRTC's pacer
            // queues bursty frames and adds 30-80 ms RTT.
            set_codec_u32(
                &codec_api,
                &CODECAPI_AVEncCommonBufferSize,
                initial_bps / TARGET_FPS.max(1),
            )?;

            // Gradual intra refresh: spread the I-coding across N
            // frames instead of emitting a full IDR keyframe every
            // GOP. An IDR at 1080p is typically 60-100 KB which
            // overshoots the VBV buffer for a single frame and
            // pushes 200-500 ms of pacer queue. With gradual
            // refresh, the cost is ~3 KB extra per frame for the
            // refresh window. Boolean enable here; the MFT picks
            // its own refresh period (typically equal to the GOP).
            // Some MFTs ignore this knob — set_codec_bool's blanket
            // E_FAIL/E_INVALIDARG swallow keeps that benign.
            set_codec_bool(&codec_api, &CODECAPI_AVEncVideoGradualIntraRefresh, true)?;

            // Start streaming.
            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(|e| anyhow!("BEGIN_STREAMING: {e:?}"))?;
            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(|e| anyhow!("START_OF_STREAM: {e:?}"))?;

            tracing::info!(
                backend = backend_kind,
                codec = codec.backend_name(),
                width,
                height,
                initial_bps,
                "mf-encoder: pipeline ready"
            );

            Ok(Self {
                transform,
                codec_api,
                _d3d_device: d3d_device,
                _d3d_manager: d3d_manager,
                width,
                height,
                frame_count: 0,
                codec,
                backend_kind,
            })
        }
    }

    /// Pipeline dimensions. Used by the probe harness to shape its
    /// synthetic NV12 payload.
    pub(super) fn dims(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Encode a pre-converted NV12 payload. Shared path used by both
    /// the regular [`Self::encode`] (which does BGRA→NV12 upstream)
    /// and the cascade probe in [`super::probe`].
    pub(super) fn encode_nv12(
        &mut self,
        nv12: &[u8],
        frame_index: u64,
    ) -> Result<Vec<EncodedPacket>> {
        let sample = unsafe { build_input_sample(nv12, frame_index)? };
        let mut drained_first = false;
        loop {
            let rc = unsafe { self.transform.ProcessInput(0, &sample, 0) };
            match rc {
                Ok(()) => {
                    tracing::debug!(frame = frame_index, "mf ProcessInput: OK");
                    break;
                }
                Err(e) if e.code() == MF_E_NOTACCEPTING => {
                    tracing::debug!(
                        frame = frame_index,
                        "mf ProcessInput: NOTACCEPTING — draining first"
                    );
                    if drained_first {
                        return Err(anyhow!(
                            "mf-encoder: MFT would not accept input after drain"
                        ));
                    }
                    let _ = self.drain_output(Vec::new())?;
                    drained_first = true;
                }
                Err(e) => bail!("ProcessInput: {e:?}"),
            }
        }
        self.frame_count = self.frame_count.wrapping_add(1);
        let packets = self.drain_output(Vec::new())?;
        Ok(packets)
    }

    pub(super) fn encode(&mut self, frame: &Frame) -> Result<Vec<EncodedPacket>> {
        // Defensive check — the MfEncoder handle also validates, but
        // a direct caller to MfPipeline (probe harness) can skip that
        // layer.
        if frame.width != self.width || frame.height != self.height {
            bail!(
                "mf-pipeline: frame dim mismatch: configured {}x{}, got {}x{}",
                self.width,
                self.height,
                frame.width,
                frame.height
            );
        }

        // BGRA → NV12 on the CPU. Phase 2 replaces this with
        // VideoProcessorMFT chained upstream (per-plan 1C.3).
        let nv12 = color::bgra_to_nv12(&frame.data, frame.width, frame.height, frame.stride)
            .map_err(|e| anyhow!("bgra_to_nv12: {e}"))?;

        let frame_index = self.frame_count;
        self.encode_nv12(&nv12, frame_index)
    }

    /// Drain `ProcessOutput` until it signals `NEED_MORE_INPUT`.
    /// Collects NALU bytes from each output sample into `EncodedPacket`s.
    fn drain_output(&mut self, mut acc: Vec<EncodedPacket>) -> Result<Vec<EncodedPacket>> {
        // Safety valve: the MS H.264 Encoder MFT can, in rare cases, keep
        // emitting STREAM_CHANGE notifications if we negotiate the output
        // type wrong. Cap the drain loop so a pathological MFT can't spin
        // forever.
        const MAX_ITERATIONS: u32 = 64;
        for iter in 0..MAX_ITERATIONS {
            let output_info: MFT_OUTPUT_STREAM_INFO =
                unsafe { self.transform.GetOutputStreamInfo(0)? };

            let needs_sample = (output_info.dwFlags & 0x100) == 0; // MFT_OUTPUT_STREAM_PROVIDES_SAMPLES
            let sample_slot = if needs_sample {
                let sample = unsafe { MFCreateSample()? };
                let buffer = unsafe { MFCreateMemoryBuffer(output_info.cbSize.max(1_048_576))? };
                unsafe { sample.AddBuffer(&buffer)? };
                Some(sample)
            } else {
                None
            };

            let mut output_buffer = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(sample_slot.clone()),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            };
            let mut status = 0u32;

            let rc = unsafe {
                self.transform.ProcessOutput(
                    0,
                    std::slice::from_mut(&mut output_buffer),
                    &mut status,
                )
            };
            let produced: Option<IMFSample> =
                unsafe { std::mem::ManuallyDrop::take(&mut output_buffer.pSample) };
            let _events = unsafe { std::mem::ManuallyDrop::take(&mut output_buffer.pEvents) };

            match rc {
                Ok(()) => {
                    if let Some(s) = produced {
                        match read_packet_from_sample(&s, self.codec)? {
                            Some(pkt) => {
                                tracing::debug!(
                                    bytes = pkt.data.len(),
                                    is_keyframe = pkt.is_keyframe,
                                    dw_status = status,
                                    "mf ProcessOutput produced"
                                );
                                acc.push(pkt);
                            }
                            None => {
                                tracing::debug!(
                                    dw_status = status,
                                    "mf ProcessOutput returned zero-byte sample"
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            dw_status = status,
                            "mf ProcessOutput Ok but no sample produced"
                        );
                    }
                }
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => {
                    tracing::debug!(
                        iter,
                        produced = acc.len(),
                        "mf ProcessOutput: NEED_MORE_INPUT (drain done)"
                    );
                    return Ok(acc);
                }
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    // The MFT changed its output media type (common on
                    // the first ProcessOutput — MS H.264 Encoder MFT
                    // renegotiates the exact profile/level once it sees
                    // the first input). Re-query + re-apply and retry
                    // the drain loop. Without this, every subsequent
                    // ProcessOutput buffers input but produces zero
                    // output — the symptom observed in 0.1.15 smoke.
                    tracing::info!(
                        iter,
                        "mf ProcessOutput: STREAM_CHANGE — renegotiating output type"
                    );
                    unsafe {
                        let new_type = self.transform.GetOutputAvailableType(0, 0)?;
                        self.transform.SetOutputType(0, &new_type, 0)?;
                    }
                    // Loop continues, retry ProcessOutput with the new
                    // type. The MFT will now accept / produce output.
                }
                Err(e) => bail!("ProcessOutput: {e:?}"),
            }
            let _ = iter; // unused in non-trace builds
        }
        tracing::warn!(
            iterations = MAX_ITERATIONS,
            "mf drain_output hit iteration cap — suspect stream-change loop"
        );
        Ok(acc)
    }

    pub(super) fn force_keyframe(&self) -> Result<()> {
        set_codec_u32(&self.codec_api, &CODECAPI_AVEncVideoForceKeyFrame, 1)
    }

    pub(super) fn set_bitrate(&self, bps: u32) -> Result<()> {
        set_codec_u32(&self.codec_api, &CODECAPI_AVEncCommonMeanBitRate, bps)
    }

    pub(super) fn end_stream(&self) -> Result<()> {
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0)
                .ok();
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)
                .ok();
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0)
                .ok();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Helpers (all unsafe-COM, kept in one place for easier auditing).
// ---------------------------------------------------------------------

unsafe fn build_output_media_type(
    width: u32,
    height: u32,
    codec: OutputCodec,
) -> Result<IMFMediaType> {
    unsafe {
        let t: IMFMediaType = MFCreateMediaType()?;
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        let subtype = codec.subtype_guid();
        t.SetGUID(&MF_MT_SUBTYPE, &subtype)?;
        t.SetUINT32(
            &MF_MT_AVG_BITRATE,
            crate::encode::initial_bitrate_for(width, height),
        )?;
        set_ratio(&t, &MF_MT_FRAME_SIZE, width, height)?;
        set_ratio(&t, &MF_MT_FRAME_RATE, TARGET_FPS_NUM, TARGET_FPS_DEN)?;
        set_ratio(&t, &MF_MT_PIXEL_ASPECT_RATIO, 1, 1)?;
        t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        Ok(t)
    }
}

unsafe fn build_input_media_type(width: u32, height: u32) -> Result<IMFMediaType> {
    unsafe {
        let t: IMFMediaType = MFCreateMediaType()?;
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        t.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
        set_ratio(&t, &MF_MT_FRAME_SIZE, width, height)?;
        set_ratio(&t, &MF_MT_FRAME_RATE, TARGET_FPS_NUM, TARGET_FPS_DEN)?;
        set_ratio(&t, &MF_MT_PIXEL_ASPECT_RATIO, 1, 1)?;
        t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        Ok(t)
    }
}

/// MF encodes a pair of u32 values into a single u64 for ratio-type
/// attributes like frame size and frame rate.
unsafe fn set_ratio(t: &IMFMediaType, key: &GUID, hi: u32, lo: u32) -> Result<()> {
    let packed: u64 = ((hi as u64) << 32) | (lo as u64);
    unsafe { t.SetUINT64(key, packed)? };
    Ok(())
}

unsafe fn build_input_sample(nv12: &[u8], frame_index: u64) -> Result<IMFSample> {
    unsafe {
        let sample: IMFSample = MFCreateSample()?;
        let buffer: IMFMediaBuffer = MFCreateMemoryBuffer(nv12.len() as u32)?;

        // Lock, copy, SetCurrentLength, unlock.
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut max_len: u32 = 0;
        let mut cur_len: u32 = 0;
        buffer.Lock(&mut ptr, Some(&mut max_len), Some(&mut cur_len))?;
        if (max_len as usize) < nv12.len() {
            let _ = buffer.Unlock();
            bail!("mf: buffer too small: {} < {}", max_len, nv12.len());
        }
        std::ptr::copy_nonoverlapping(nv12.as_ptr(), ptr, nv12.len());
        buffer.SetCurrentLength(nv12.len() as u32)?;
        buffer.Unlock()?;

        sample.AddBuffer(&buffer)?;
        // MF timestamps are 100-ns units. At fps=N each frame is
        // 10_000_000 / N units long. Computed from TARGET_FPS so a
        // future fps bump (1F.1 / Phase 2 Option B 60 fps) keeps the
        // PTS axis correct without a second source of truth.
        let ts_per_frame_100ns: i64 = 10_000_000 / TARGET_FPS.max(1) as i64;
        let ts_100ns: i64 = frame_index as i64 * ts_per_frame_100ns;
        sample.SetSampleTime(ts_100ns)?;
        sample.SetSampleDuration(ts_per_frame_100ns)?;
        Ok(sample)
    }
}

/// Read the NALU run out of an output IMFSample and wrap it in an
/// `EncodedPacket`. Returns `None` if the sample is empty (e.g. the
/// MFT handed us a format-change notification).
fn read_packet_from_sample(
    sample: &IMFSample,
    codec: OutputCodec,
) -> Result<Option<EncodedPacket>> {
    unsafe {
        let total_len: u32 = sample.GetTotalLength()?;
        if total_len == 0 {
            return Ok(None);
        }
        let buffer = sample.ConvertToContiguousBuffer()?;
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut max_len: u32 = 0;
        let mut cur_len: u32 = 0;
        buffer.Lock(&mut ptr, Some(&mut max_len), Some(&mut cur_len))?;
        let data = std::slice::from_raw_parts(ptr, cur_len as usize).to_vec();
        buffer.Unlock()?;

        // H.264/HEVC emit Annex-B NALUs; webrtc-rs's H264Payloader +
        // HevcPayloader split on start codes. AV1 emits a raw OBU
        // sequence (length-prefixed elements, no start codes); the
        // Av1Payloader consumes exactly that shape. Bytes pass through
        // unchanged for all three. `is_keyframe` uses the per-codec
        // detector below — observability-only.
        let is_keyframe = is_keyframe_bitstream(&data, codec);
        Ok(Some(EncodedPacket {
            data,
            is_keyframe,
            duration_us: 1_000_000 / TARGET_FPS.max(1) as u64,
            // Follow-up if the MF lane ever needs QP telemetry: read
            // MFSampleExtension_VideoEncodeQP off the output sample.
            qp: None,
        }))
    }
}

/// Scan the encoded bitstream for a keyframe marker. Good-enough
/// heuristic for the `is_keyframe` observability flag — the RTP layer
/// doesn't use this for packetization.
///
/// H.264 (RFC 6184): Annex-B framed; nal_unit_type = first byte after
/// start code & 0x1F; IDR = 5.
/// HEVC (RFC 7798): Annex-B framed; nal_unit_type = (first byte >> 1)
/// & 0x3F; keyframes are IDR_W_RADL (19), IDR_N_LP (20), CRA_NUT (21).
/// AV1: OBU sequence, no Annex-B; the presence of an
/// OBU_SEQUENCE_HEADER (obu_type=1) implies the frame is a keyframe
/// — IHV AV1 encoders emit a fresh sequence header at every forced
/// IDR + at the start of each GOP but never mid-GOP. Missing that
/// header on the first frame is an encoder bug (the decoder can't
/// initialise), so false-negatives here mean something is already
/// broken upstream.
fn is_keyframe_bitstream(buf: &[u8], codec: OutputCodec) -> bool {
    match codec {
        OutputCodec::H264 | OutputCodec::Hevc => annex_b_contains_idr(buf, codec),
        OutputCodec::Av1 => av1_contains_sequence_header(buf),
    }
}

fn annex_b_contains_idr(buf: &[u8], codec: OutputCodec) -> bool {
    let mut i = 0;
    while i + 4 < buf.len() {
        // Annex-B start code: 00 00 00 01 or 00 00 01.
        let (nal_off, next) =
            if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 1 {
                (i + 4, i + 4)
            } else if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1 {
                (i + 3, i + 3)
            } else {
                i += 1;
                continue;
            };
        if nal_off < buf.len() {
            let head = buf[nal_off];
            let is_idr = match codec {
                OutputCodec::H264 => (head & 0x1f) == 5,
                OutputCodec::Hevc => {
                    let nt = (head >> 1) & 0x3f;
                    matches!(nt, 19..=21)
                }
                OutputCodec::Av1 => unreachable!("AV1 does not use Annex-B"),
            };
            if is_idr {
                return true;
            }
        }
        i = next + 1;
    }
    false
}

/// Walk an AV1 OBU sequence looking for OBU_SEQUENCE_HEADER
/// (obu_type=1). Stops at the first OBU that can't be length-decoded
/// — a cheap safety valve so a malformed buffer doesn't cause an
/// infinite loop.
///
/// OBU header byte layout (AV1 spec §5.3.2):
///   bit 7: obu_forbidden_bit (must be 0)
///   bits 6-3: obu_type (4 bits)
///   bit 2: obu_extension_flag
///   bit 1: obu_has_size_field
///   bit 0: obu_reserved_1bit
fn av1_contains_sequence_header(buf: &[u8]) -> bool {
    const OBU_SEQUENCE_HEADER: u8 = 1;
    const MAX_OBUS: usize = 32;
    let mut i = 0;
    for _ in 0..MAX_OBUS {
        if i >= buf.len() {
            return false;
        }
        let head = buf[i];
        let obu_type = (head >> 3) & 0x0f;
        let has_extension = (head & 0x04) != 0;
        let has_size_field = (head & 0x02) != 0;
        if obu_type == OBU_SEQUENCE_HEADER {
            return true;
        }
        i += 1;
        if has_extension {
            i += 1;
        }
        if has_size_field {
            let (payload_size, leb_bytes) = match decode_leb128(&buf[i..]) {
                Some(v) => v,
                None => return false,
            };
            i += leb_bytes;
            i = i.saturating_add(payload_size as usize);
        } else {
            // No size field means the OBU runs to the end of the
            // buffer. MF AV1 MFT emits OBUs with size fields — this
            // branch is a safety valve for spec-compliant-but-unusual
            // streams. Stop walking here.
            return false;
        }
    }
    false
}

/// Decode an unsigned LEB128 integer, returning `(value, bytes_read)`
/// or `None` if the buffer is exhausted / value overflows u32. AV1
/// uses at most 8 LEB128 bytes per integer per spec §4.10.5.
fn decode_leb128(buf: &[u8]) -> Option<(u32, usize)> {
    const MAX_BYTES: usize = 8;
    let mut value: u64 = 0;
    for i in 0..MAX_BYTES {
        if i >= buf.len() {
            return None;
        }
        let b = buf[i];
        value |= ((b & 0x7f) as u64) << (i * 7);
        if (b & 0x80) == 0 {
            // Cap at u32 to match the OBU length field's range.
            if value > u32::MAX as u64 {
                return None;
            }
            return Some((value as u32, i + 1));
        }
    }
    None
}

// Helper functions after the tests module are flagged by
// `clippy::items_after_test_module` in clippy 1.95+. They existed
// here pre-lint; reordering would be a ~40-line diff for zero
// behavior change. Scoped allow keeps the module history stable.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h264_idr_detected() {
        // [0 0 0 1] start + NAL header 0x65 → type 5 (IDR slice)
        let buf = [0, 0, 0, 1, 0x65, 0x88];
        assert!(is_keyframe_bitstream(&buf, OutputCodec::H264));
        // Non-IDR slice (type 1)
        let buf = [0, 0, 0, 1, 0x41, 0x88];
        assert!(!is_keyframe_bitstream(&buf, OutputCodec::H264));
    }

    #[test]
    fn hevc_idr_detected() {
        // HEVC NAL header: first byte is (nt << 1) with the high bit
        // as forbidden_zero. IDR_W_RADL (19) => 0x26. IDR_N_LP (20)
        // => 0x28. CRA_NUT (21) => 0x2A. TRAIL_R (1) => 0x02 (not IDR).
        let idr_w_radl = [0, 0, 0, 1, 0x26, 0x01];
        let idr_n_lp = [0, 0, 0, 1, 0x28, 0x01];
        let cra = [0, 0, 0, 1, 0x2A, 0x01];
        let non_idr = [0, 0, 0, 1, 0x02, 0x01];
        assert!(is_keyframe_bitstream(&idr_w_radl, OutputCodec::Hevc));
        assert!(is_keyframe_bitstream(&idr_n_lp, OutputCodec::Hevc));
        assert!(is_keyframe_bitstream(&cra, OutputCodec::Hevc));
        assert!(!is_keyframe_bitstream(&non_idr, OutputCodec::Hevc));
    }

    #[test]
    fn hevc_codec_names() {
        assert_eq!(OutputCodec::H264.backend_name(), "mf-h264");
        assert_eq!(OutputCodec::Hevc.backend_name(), "mf-h265");
        assert_eq!(OutputCodec::Av1.backend_name(), "mf-av1");
    }

    #[test]
    fn av1_sequence_header_detected() {
        // OBU header: obu_type=1 (SEQUENCE_HEADER) → (1 << 3) = 0x08.
        // With has_size_field bit (bit 1) set: 0x0A. Size leb128=0x03,
        // payload = [0xAA, 0xBB, 0xCC].
        let buf = [0x0A, 0x03, 0xAA, 0xBB, 0xCC];
        assert!(is_keyframe_bitstream(&buf, OutputCodec::Av1));
    }

    #[test]
    fn av1_no_sequence_header() {
        // obu_type=6 (OBU_FRAME) with size=3.
        let buf = [0x32, 0x03, 0x11, 0x22, 0x33];
        assert!(!is_keyframe_bitstream(&buf, OutputCodec::Av1));
    }

    #[test]
    fn av1_sequence_header_after_temporal_delimiter() {
        // Realistic: OBU_TEMPORAL_DELIMITER (type=2, size=0), then
        // OBU_SEQUENCE_HEADER (type=1, size=3). Both have size bits set.
        let buf = [
            0x12, 0x00, // TD, size=0
            0x0A, 0x03, 0xAA, 0xBB, 0xCC, // SEQ_HEADER, size=3
        ];
        assert!(is_keyframe_bitstream(&buf, OutputCodec::Av1));
    }

    #[test]
    fn decode_leb128_handles_multibyte() {
        // 129 = 0b1000_0001 → LEB128 [0x81, 0x01]
        assert_eq!(decode_leb128(&[0x81, 0x01]), Some((129, 2)));
        // Short buffer returns None
        assert_eq!(decode_leb128(&[0x81]), None);
        // Single-byte value
        assert_eq!(decode_leb128(&[0x05]), Some((5, 1)));
    }

    #[test]
    fn hevc_idr_bytes_not_mistaken_for_h264_idr() {
        // An HEVC IDR_W_RADL byte (0x26 → nt=19) is NOT an H.264 IDR
        // under the H.264 mask (0x26 & 0x1F = 6, a type-6 SEI).
        // Cross-check the guard: the right mask is applied per codec.
        let hevc_idr = [0, 0, 0, 1, 0x26, 0x01];
        assert!(is_keyframe_bitstream(&hevc_idr, OutputCodec::Hevc));
        assert!(!is_keyframe_bitstream(&hevc_idr, OutputCodec::H264));
    }
}

/// Set a boolean codec-api property. `windows` 0.58 exposes a
/// high-level `VARIANT` from `windows::core` with `From<bool>`, so we
/// skip the union-field dance of the raw Win32 VARIANT. An `E_FAIL`
/// from the MFT is interpreted as "key not supported" — non-fatal,
/// since we try to set a superset of knobs that any given driver may
/// or may not recognise.
/// MFT quirk: different vendors reject "unsupported codec knob"
/// differently. MS SW MFT returns E_FAIL. Intel QSV / NVIDIA / some
/// older Windows builds return E_INVALIDARG. HEVCVideoExtensionEncoder
/// (shipped via the Microsoft HEVC Video Extension in Store) returns
/// E_NOTIMPL for knobs it doesn't expose. None of these should fail
/// init — unsupported knobs are observability noise, the MFT still
/// works for actual encode. Downgrade all three to a debug log.
fn is_unsupported_codec_key_error(e: &windows::core::Error) -> bool {
    let code = e.code();
    code == E_FAIL || code == E_INVALIDARG || code == E_NOTIMPL
}

fn set_codec_bool(codec: &ICodecAPI, key: &GUID, value: bool) -> Result<()> {
    let var: windows::core::VARIANT = value.into();
    let hr = unsafe { codec.SetValue(key, &var) };
    match hr {
        Ok(()) => Ok(()),
        Err(e) if is_unsupported_codec_key_error(&e) => {
            tracing::debug!(?key, code = %e.code().0, "codec-api key not supported by MFT");
            Ok(())
        }
        Err(e) => Err(anyhow!("codec SetValue bool: {e:?}")),
    }
}

fn set_codec_u32(codec: &ICodecAPI, key: &GUID, value: u32) -> Result<()> {
    let var: windows::core::VARIANT = value.into();
    let hr = unsafe { codec.SetValue(key, &var) };
    match hr {
        Ok(()) => Ok(()),
        Err(e) if is_unsupported_codec_key_error(&e) => {
            tracing::debug!(?key, value, code = %e.code().0, "codec-api key not supported by MFT");
            Ok(())
        }
        Err(e) => Err(anyhow!("codec SetValue u32: {e:?}")),
    }
}
