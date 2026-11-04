// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Software H.264 encoder built on [OpenH264].
//!
//! Pinned to a dedicated OS thread the same way the capture backend is —
//! the openh264 encoder isn't `Send`-safe to bounce between tokio workers,
//! and the encode call is CPU-bound so it belongs off the async runtime
//! anyway. The async front end hands frames in via a bounded mpsc and
//! reads encoded packets back via a second mpsc.
//!
//! BGRA → I420 conversion is done inline with a simple BT.601 matrix.
//! That's good enough for a v1 software path; a follow-up can plug in
//! libyuv / an NV12-producing capture path to skip the conversion cost.
//!
//! 1B.1 note: the MF backend gained tight-VBV + gradual-intra-refresh
//! tunings in 0.1.27. The openh264 crate at v0.9.3 doesn't expose
//! either knob — `EncoderConfig::max_slice_len` only sets
//! `SM_SIZELIMITED_SLICE` (size-bounded slices, not a fixed count),
//! and there is no public hook for `iIntraRefresh` /
//! `bUseRefFrame`-style controls. The SW path therefore still emits
//! a full IDR every 60 frames with single-slice frames. That's an
//! ~80 KB spike on 1080p that WebRTC's pacer absorbs in ~10 ms; not
//! a big deal for the SW fallback case (1080p SW already maxes a
//! desktop CPU at 30 fps), but worth revisiting if openh264 0.10+
//! exposes the SVC parameters directly.
//!
//! [OpenH264]: https://www.openh264.org/

use anyhow::{Context, Result, anyhow};
use openh264::encoder::{
    BitRate, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, QpRange,
    RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::YUVBuffer;
use std::sync::mpsc as std_mpsc;
use std::thread;
use tokio::sync::oneshot;

// Raw FFI handles needed for runtime bitrate control. The openh264
// crate exposes a builder-style `bitrate()` only at construction;
// changing it on a live Encoder requires the C-API SetOption with
// ENCODER_OPTION_BITRATE + an SBitrateInfo struct.
use openh264_sys2::{
    ENCODER_OPTION_BITRATE, ENCODER_OPTION_FRAME_RATE, ENCODER_OPTION_IDR_INTERVAL,
    ENCODER_OPTION_MAX_BITRATE, SBitrateInfo, SPATIAL_LAYER_0,
};

use super::{EncodedPacket, VideoEncoder};
use crate::capture::{Frame, PixelFormat};

use super::initial_bitrate_for;

const TARGET_FPS: u32 = 30;

/// The live profile's keyframe floor: an IDR about every two seconds,
/// whatever the frame rate (60 frames at 30 fps, 120 at 60). FR-112 P2b keeps
/// it in seconds when the pump's rate changes: a period left at 60 frames
/// would double the keyframes at 60 fps, each a big frame on the link.
const IDR_EVERY_S: u32 = 2;

/// FR-85 — the recording profile's rate target: ~0.2 bits per pixel per
/// frame, floored at 4 Mbps and capped at 40 Mbps. Quality mode treats it as
/// a budget to aim at, not a wall; the QP window is what guards quality.
/// 1080p30 → ~12.4 Mbps; screen content (mostly static) averages far less.
pub fn recording_bitrate_for(width: u32, height: u32, fps: u32) -> u32 {
    let bps = u64::from(width) * u64::from(height) * u64::from(fps.max(1)) / 5;
    bps.clamp(4_000_000, 40_000_000) as u32
}

pub struct Openh264Encoder {
    /// Worker thread; commands go in, packets come out.
    cmd_tx: std_mpsc::Sender<Cmd>,
}

enum Cmd {
    Encode {
        frame: std::sync::Arc<Frame>,
        reply: oneshot::Sender<Result<Vec<EncodedPacket>>>,
    },
    RequestKeyframe,
    SetBitrate(u32),
    /// FR-112 P2b — the rate the pump feeds frames at.
    SetFrameRate(u32),
    Shutdown,
}

impl Openh264Encoder {
    /// Build an encoder sized for the given frame dimensions. OpenH264 needs
    /// the width/height at construction time; if the capture source resizes
    /// (dock/undock) the caller must rebuild this encoder.
    pub fn new(width: u32, height: u32) -> Result<Self> {
        let bitrate_bps = initial_bitrate_for(width, height);
        Self::spawn(
            width,
            height,
            "roomlerd-encoder",
            Some(IDR_EVERY_S),
            move || {
                tracing::info!(bitrate_bps, width, height, "openh264 encoder init");
                EncoderConfig::new()
                    .bitrate(BitRate::from_bps(bitrate_bps))
                    .max_frame_rate(FrameRate::from_hz(TARGET_FPS as f32))
                    // Force an IDR every 60 frames (≈2 s @ 30 fps).
                    // Without a bounded IDR interval, openh264 can go
                    // 300+ frames between keyframes on a static
                    // desktop; a single lost packet then freezes the
                    // decoder for ~10 s. 60 gives <2 s recovery floor
                    // even if the RTCP-PLI round-trip drops.
                    .intra_frame_period(IntraFramePeriod::from_num_frames(TARGET_FPS * IDR_EVERY_S))
                    // rcfix 2026-11-04 — never let rate control drop a frame.
                    // OpenH264's frame skip (the crate's default) answers an
                    // over-budget frame by encoding NOTHING for the next ones:
                    // measured with this config, eight empty encodes in a row
                    // after the keyframe, then every other one, the idle
                    // keepalive's repeat included. A skipped frame is invisible
                    // to the pump (it counts it encoded) and to the viewer (no
                    // loss, no NACK, no PLI): the session just goes byte-silent
                    // and the stall watchdog hangs it up. Without skip, rate
                    // control holds the budget with QP instead, and the pump's
                    // own pacing (FR-112) owns the frame rate.
                    .skip_frames(false)
            },
        )
    }

    /// FR-85 — the RECORDING profile. What differs from the live one, and why:
    ///
    /// - quality-mode rate control with a QP window, not a bitrate the network
    ///   sets — a file has no link to fit, so the target is generous and the
    ///   QP ceiling (30) is what bounds the worst frame;
    /// - `skip_frames(false)`: a skipped frame is a hole in a constant-rate file;
    /// - a fixed GOP (`gop_frames`), so every fragment starts on a keyframe and
    ///   a cut in the editor needs at most one GOP of decoding;
    /// - screen-content tuning;
    /// - BT.601 limited range signalled in the SPS VUI — what
    ///   [`bgra_to_yuv_buffer`] actually produces, and what the MP4's `colr`
    ///   says, so an HD player does not assume BT.709 and shift every colour.
    pub fn new_recording(width: u32, height: u32, fps: u32, gop_frames: u32) -> Result<Self> {
        let fps = fps.clamp(1, 60);
        let bitrate_bps = recording_bitrate_for(width, height, fps);
        let gop = gop_frames.max(1);
        // `None`: the recording's GOP is its own (fragment boundaries), and no
        // frame-rate change moves it.
        Self::spawn(width, height, "roomlerd-rec-encoder", None, move || {
            tracing::info!(
                bitrate_bps,
                width,
                height,
                fps,
                gop,
                "openh264 recording encoder init"
            );
            EncoderConfig::new()
                .rate_control_mode(RateControlMode::Quality)
                .bitrate(BitRate::from_bps(bitrate_bps))
                .qp(QpRange::new(10, 30))
                .max_frame_rate(FrameRate::from_hz(fps as f32))
                .intra_frame_period(IntraFramePeriod::from_num_frames(gop))
                .skip_frames(false)
                .usage_type(UsageType::ScreenContentRealTime)
                .num_threads(0)
                .vui(VuiConfig::bt601())
        })
    }

    /// `idr_every_s`: the keyframe floor in seconds, which a frame-rate change
    /// keeps (FR-112 P2b); `None` leaves the configured period alone.
    fn spawn(
        width: u32,
        height: u32,
        thread_name: &str,
        idr_every_s: Option<u32>,
        make_config: impl FnOnce() -> EncoderConfig + Send + 'static,
    ) -> Result<Self> {
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();

        thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {
                // FR-112 P1 — this thread encodes every frame; ask for its clock
                // first (a 30 fps encoder is otherwise clocked down to fill its
                // period: 16 ms a frame live against 5 with the clock).
                crate::encode::clock::ask_for_this_thread("openh264");
                let init = || -> Result<Encoder> {
                    let api = openh264::OpenH264API::from_source();
                    let cfg = make_config();
                    Encoder::with_api_config(api, cfg).map_err(|e| anyhow!("encoder init: {e}"))
                };

                let mut enc = match init() {
                    Ok(e) => {
                        let _ = ready_tx.send(Ok(()));
                        e
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                run_worker(&mut enc, width, height, idr_every_s, cmd_rx);
            })
            .context("spawning encoder thread")?;

        ready_rx
            .recv()
            .context("encoder thread never signalled")??;
        Ok(Self { cmd_tx })
    }
}

impl Drop for Openh264Encoder {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown);
    }
}

/// Apply a runtime bitrate change to a live OpenH264 encoder via raw
/// FFI, on layer 0 (we only use a single spatial layer).
///
/// FR-112 P2b — the layer's MAX bitrate moves with the target. The crate
/// initialises the max to the construction bitrate, and OpenH264 refuses a
/// target above the max (`cmInitParaError`, "MaxSpatialBitrate should be
/// larger than SpatialBitrate"): until this, no runtime raise above the
/// construction figure ever took — not Quality=High, not REMB recovering past
/// it, not the 60 fps base. So a rising target raises the max first, and a
/// falling one lowers it after, which keeps the two equal as the crate set them.
fn apply_runtime_bitrate(enc: &mut Encoder, bps: u32) -> Result<()> {
    let raising = runtime_bitrate(enc).is_none_or(|current| bps > current);
    if raising {
        set_bitrate_option(enc, ENCODER_OPTION_MAX_BITRATE, "MAX_BITRATE", bps)?;
        set_bitrate_option(enc, ENCODER_OPTION_BITRATE, "BITRATE", bps)
    } else {
        set_bitrate_option(enc, ENCODER_OPTION_BITRATE, "BITRATE", bps)?;
        set_bitrate_option(enc, ENCODER_OPTION_MAX_BITRATE, "MAX_BITRATE", bps)
    }
}

/// One `SBitrateInfo` option on layer 0. C-API returns 0 on success.
fn set_bitrate_option(
    enc: &mut Encoder,
    option: openh264_sys2::ENCODER_OPTION,
    name: &str,
    bps: u32,
) -> Result<()> {
    let mut info = SBitrateInfo {
        iLayer: SPATIAL_LAYER_0,
        // OpenH264's iBitrate is signed 32-bit; clamp at 2 Gbps to
        // avoid wraparound on absurd inputs (TWCC values shouldn't
        // exceed 50 Mbps but defensive).
        iBitrate: bps.min(i32::MAX as u32) as i32,
    };
    // SAFETY: raw_api gives us &mut EncoderRawAPI; set_option is a C
    // function pointer accepting (encoder*, option_id, *mut c_void).
    // SBitrateInfo is repr(C) and `info` lives for the duration of
    // this call. The encoder is initialised (a frame went through; see
    // `Settings`) so the option is valid at this point.
    let rc = unsafe {
        let raw = enc.raw_api();
        raw.set_option(
            option,
            (&raw mut info) as *mut openh264_sys2::SBitrateInfo as *mut std::ffi::c_void,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "openh264 SetOption(ENCODER_OPTION_{name}, {bps}) returned {rc}"
        ))
    }
}

/// The live encoder's layer-0 target bitrate, or `None` if it will not say.
fn runtime_bitrate(enc: &mut Encoder) -> Option<u32> {
    let mut info = SBitrateInfo {
        iLayer: SPATIAL_LAYER_0,
        iBitrate: 0,
    };
    // SAFETY: as `set_bitrate_option`; GetOption fills `info`, which lives
    // for the call.
    let rc = unsafe {
        enc.raw_api().get_option(
            ENCODER_OPTION_BITRATE,
            (&raw mut info) as *mut openh264_sys2::SBitrateInfo as *mut std::ffi::c_void,
        )
    };
    (rc == 0).then(|| info.iBitrate.max(0) as u32)
}

/// FR-112 P2b — set the live encoder's frame rate (`ENCODER_OPTION_FRAME_RATE`,
/// a float that OpenH264 clips to 1–60). Its rate control budgets each frame's
/// bits from it.
fn apply_runtime_frame_rate(enc: &mut Encoder, fps: u32) -> Result<()> {
    let mut rate = fps as f32;
    // SAFETY: as `apply_runtime_bitrate` — the option takes a `float*` that
    // lives for the call, and the encoder is initialised (see `Settings`).
    let rc = unsafe {
        let raw = enc.raw_api();
        raw.set_option(
            ENCODER_OPTION_FRAME_RATE,
            (&raw mut rate) as *mut std::ffi::c_void,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "openh264 SetOption(ENCODER_OPTION_FRAME_RATE, {fps}) returned {rc}"
        ))
    }
}

/// FR-112 P2b — what a live encoder's runtime settings wait for. The openh264
/// crate creates the C encoder's state at the FIRST encode (it needs the
/// frame's dimensions), and `SetOption` before then answers `cmInitExpected`
/// (4). The RTP pump applies its bitrate before its first frame, so on every
/// session that first `set_bitrate` failed, was never retried (the pump had
/// recorded it as applied), and the encoder ran at its construction bitrate
/// until REMB moved 15 %. Settings that arrive early are held here and applied
/// once the first frame is through; the newest of each wins.
#[derive(Debug, Default)]
struct Settings {
    live: bool,
    bitrate: Option<u32>,
    frame_rate: Option<u32>,
}

impl Settings {
    /// The bitrate to apply now, or `None` when it is held for the first frame.
    fn bitrate(&mut self, bps: u32) -> Option<u32> {
        if self.live {
            return Some(bps);
        }
        self.bitrate = Some(bps);
        None
    }

    /// The frame rate to apply now, or `None` when it is held.
    fn frame_rate(&mut self, fps: u32) -> Option<u32> {
        if self.live {
            return Some(fps);
        }
        self.frame_rate = Some(fps);
        None
    }

    /// A frame went through: what was held, to apply now (once).
    fn went_live(&mut self) -> (Option<u32>, Option<u32>) {
        if self.live {
            return (None, None);
        }
        self.live = true;
        (self.bitrate.take(), self.frame_rate.take())
    }
}

fn set_bitrate_now(enc: &mut Encoder, bps: u32) {
    if let Err(e) = apply_runtime_bitrate(enc, bps) {
        tracing::warn!(bps, %e, "openh264 set_bitrate failed");
    } else {
        tracing::debug!(bps, "openh264 set_bitrate applied");
    }
}

/// FR-112 P2b — the keyframe period in frames (`ENCODER_OPTION_IDR_INTERVAL`,
/// an int; OpenH264 takes it at runtime).
fn apply_runtime_idr_interval(enc: &mut Encoder, frames: u32) -> Result<()> {
    let mut period = frames.min(i32::MAX as u32) as i32;
    // SAFETY: as `apply_runtime_frame_rate` — an `int*` that lives for the
    // call, on an initialised encoder.
    let rc = unsafe {
        enc.raw_api().set_option(
            ENCODER_OPTION_IDR_INTERVAL,
            (&raw mut period) as *mut std::ffi::c_void,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "openh264 SetOption(ENCODER_OPTION_IDR_INTERVAL, {frames}) returned {rc}"
        ))
    }
}

/// The frame rate, and with it the keyframe period that keeps `idr_every_s`
/// (when the profile has one).
fn set_frame_rate_now(enc: &mut Encoder, fps: u32, idr_every_s: Option<u32>) {
    if let Err(e) = apply_runtime_frame_rate(enc, fps) {
        tracing::warn!(fps, %e, "openh264 set_frame_rate failed");
        return;
    }
    let idr_frames = idr_every_s.map(|s| fps.max(1) * s);
    if let Some(frames) = idr_frames
        && let Err(e) = apply_runtime_idr_interval(enc, frames)
    {
        tracing::warn!(fps, frames, %e, "openh264 keyframe period not moved");
    }
    tracing::info!(fps, idr_frames, "openh264 frame rate applied (FR-112)");
}

fn run_worker(
    enc: &mut Encoder,
    width: u32,
    height: u32,
    idr_every_s: Option<u32>,
    cmd_rx: std_mpsc::Receiver<Cmd>,
) {
    let mut settings = Settings::default();
    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            Cmd::Encode { frame, reply } => {
                let result = encode_one(enc, width, height, frame);
                if result.is_ok() {
                    let (bps, fps) = settings.went_live();
                    if let Some(bps) = bps {
                        set_bitrate_now(enc, bps);
                    }
                    if let Some(fps) = fps {
                        set_frame_rate_now(enc, fps, idr_every_s);
                    }
                }
                let _ = reply.send(result);
            }
            Cmd::RequestKeyframe => {
                enc.force_intra_frame();
            }
            Cmd::SetBitrate(bps) => {
                if let Some(bps) = settings.bitrate(bps) {
                    set_bitrate_now(enc, bps);
                }
            }
            Cmd::SetFrameRate(fps) => {
                if let Some(fps) = settings.frame_rate(fps) {
                    set_frame_rate_now(enc, fps, idr_every_s);
                }
            }
            Cmd::Shutdown => break,
        }
    }
}

fn encode_one(
    enc: &mut Encoder,
    width: u32,
    height: u32,
    frame: std::sync::Arc<Frame>,
) -> Result<Vec<EncodedPacket>> {
    if frame.pixel_format != PixelFormat::Bgra {
        return Err(anyhow!(
            "openh264 backend needs BGRA input; got {:?}",
            frame.pixel_format
        ));
    }
    if frame.width != width || frame.height != height {
        return Err(anyhow!(
            "frame size mismatch: encoder configured for {}x{}, got {}x{}",
            width,
            height,
            frame.width,
            frame.height
        ));
    }

    let yuv = bgra_to_yuv_buffer(
        &frame.data,
        frame.width as usize,
        frame.height as usize,
        frame.stride as usize,
    );
    let bitstream = enc.encode(&yuv).map_err(|e| anyhow!("encode: {e}"))?;

    // Walk the layered bitstream and return one packet per NAL-unit
    // grouped by layer. For our SW path with a single layer there's
    // effectively one packet, but keeping the structure faithful means
    // the SFU / track feeder can treat multi-layer output the same way.
    let mut packets = Vec::new();
    let is_keyframe = matches!(bitstream.frame_type(), FrameType::IDR | FrameType::I);
    for layer_idx in 0..bitstream.num_layers() {
        if let Some(layer) = bitstream.layer(layer_idx) {
            let mut data = Vec::new();
            for nal_idx in 0..layer.nal_count() {
                if let Some(nal) = layer.nal_unit(nal_idx) {
                    data.extend_from_slice(nal);
                }
            }
            if !data.is_empty() {
                packets.push(EncodedPacket {
                    data,
                    is_keyframe,
                    duration_us: 0,
                    // openh264's C API exposes no per-frame QP readout.
                    qp: None,
                });
            }
        }
    }
    Ok(packets)
}

#[async_trait::async_trait]
impl VideoEncoder for Openh264Encoder {
    async fn encode(&mut self, frame: std::sync::Arc<Frame>) -> Result<Vec<EncodedPacket>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Encode {
                frame,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("encoder worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("encoder reply dropped"))?
    }

    fn request_keyframe(&mut self) {
        let _ = self.cmd_tx.send(Cmd::RequestKeyframe);
    }

    fn set_bitrate(&mut self, bps: u32) {
        let _ = self.cmd_tx.send(Cmd::SetBitrate(bps));
    }

    fn set_frame_rate(&mut self, fps: u32) {
        let _ = self.cmd_tx.send(Cmd::SetFrameRate(fps));
    }

    fn name(&self) -> &'static str {
        "openh264"
    }
}

/// Convert a BGRA buffer (what scrap produces on Linux/Windows/macOS) into
/// an I420 [`YUVBuffer`] suitable for OpenH264. Uses BT.601 studio swing
/// because that's the WebRTC convention for sub-HD content; BT.709 would
/// be a valid choice for ≥720p and can be swapped in later.
///
/// Output layout: a single packed vector `[Y... U... V...]` passed to
/// `YUVBuffer::from_vec`, with plane sizes `w*h`, `(w/2)*(h/2)`,
/// `(w/2)*(h/2)` respectively. Width and height must be even.
fn bgra_to_yuv_buffer(bgra: &[u8], width: usize, height: usize, stride: usize) -> YUVBuffer {
    // OpenH264 needs even dimensions; callers should size the encoder
    // accordingly. We round down here defensively.
    let w = width & !1;
    let h = height & !1;

    let y_size = w * h;
    let uv_size = (w / 2) * (h / 2);
    let mut packed = vec![0u8; y_size + 2 * uv_size];

    // Y plane.
    for row in 0..h {
        let src_row = &bgra[row * stride..row * stride + w * 4];
        let dst_row = &mut packed[row * w..(row + 1) * w];
        for (col, px) in src_row.chunks_exact(4).enumerate() {
            let b = px[0] as i32;
            let g = px[1] as i32;
            let r = px[2] as i32;
            let y_val = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            dst_row[col] = y_val.clamp(0, 255) as u8;
        }
    }

    // U / V planes: 2x2 chroma subsample. Average the 2x2 block first then
    // apply the coefficient matrix — cheap and keeps visual quality OK.
    let u_base = y_size;
    let v_base = y_size + uv_size;
    let cw = w / 2;
    for row in (0..h).step_by(2) {
        for col in (0..w).step_by(2) {
            let i0 = row * stride + col * 4;
            let i1 = row * stride + (col + 1) * 4;
            let i2 = (row + 1) * stride + col * 4;
            let i3 = (row + 1) * stride + (col + 1) * 4;

            let b_avg =
                ((bgra[i0] as i32 + bgra[i1] as i32 + bgra[i2] as i32 + bgra[i3] as i32) + 2) >> 2;
            let g_avg = ((bgra[i0 + 1] as i32
                + bgra[i1 + 1] as i32
                + bgra[i2 + 1] as i32
                + bgra[i3 + 1] as i32)
                + 2)
                >> 2;
            let r_avg = ((bgra[i0 + 2] as i32
                + bgra[i1 + 2] as i32
                + bgra[i2 + 2] as i32
                + bgra[i3 + 2] as i32)
                + 2)
                >> 2;

            let u_val = ((-38 * r_avg - 74 * g_avg + 112 * b_avg + 128) >> 8) + 128;
            let v_val = ((112 * r_avg - 94 * g_avg - 18 * b_avg + 128) >> 8) + 128;

            let chroma_idx = (row / 2) * cw + (col / 2);
            packed[u_base + chroma_idx] = u_val.clamp(0, 255) as u8;
            packed[v_base + chroma_idx] = v_val.clamp(0, 255) as u8;
        }
    }

    YUVBuffer::from_vec(packed, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bgra_frame(width: u32, height: u32, r: u8, g: u8, b: u8) -> Frame {
        let stride = width * 4;
        let mut data = vec![0u8; (stride * height) as usize];
        for px in data.chunks_exact_mut(4) {
            px[0] = b;
            px[1] = g;
            px[2] = r;
            px[3] = 255;
        }
        Frame {
            width,
            height,
            stride,
            pixel_format: PixelFormat::Bgra,
            data,
            monotonic_us: 0,
            monitor: 0,
            damage: crate::capture::Damage::Unknown,
            source: None,
        }
    }

    #[tokio::test]
    async fn encodes_first_frame_as_keyframe() {
        let mut enc = Openh264Encoder::new(320, 240).expect("encoder");
        let frame = std::sync::Arc::new(make_bgra_frame(320, 240, 100, 150, 200));
        let packets = enc.encode(frame).await.expect("encode");
        assert!(!packets.is_empty(), "no packets produced");
        assert!(packets.iter().any(|p| p.is_keyframe));
        let total: usize = packets.iter().map(|p| p.data.len()).sum();
        assert!(total > 10, "unexpectedly small bitstream: {total} bytes");
    }

    #[tokio::test]
    async fn rejects_wrong_pixel_format() {
        let mut enc = Openh264Encoder::new(64, 64).expect("encoder");
        let mut frame = make_bgra_frame(64, 64, 0, 0, 0);
        frame.pixel_format = PixelFormat::Nv12;
        assert!(enc.encode(std::sync::Arc::new(frame)).await.is_err());
    }

    #[tokio::test]
    async fn rejects_size_mismatch() {
        let mut enc = Openh264Encoder::new(320, 240).expect("encoder");
        let frame = std::sync::Arc::new(make_bgra_frame(640, 480, 0, 0, 0));
        assert!(enc.encode(frame).await.is_err());
    }

    #[tokio::test]
    async fn request_keyframe_is_noisy_next_frame() {
        let mut enc = Openh264Encoder::new(64, 64).expect("encoder");
        let _ = enc
            .encode(std::sync::Arc::new(make_bgra_frame(64, 64, 0, 0, 0)))
            .await
            .unwrap();
        enc.request_keyframe();
        let out = enc
            .encode(std::sync::Arc::new(make_bgra_frame(64, 64, 255, 255, 255)))
            .await
            .unwrap();
        assert!(!out.is_empty());
    }

    /// Layer 0's bitrate option (`ENCODER_OPTION_BITRATE` or `_MAX_BITRATE`)
    /// as the live encoder reports it.
    fn read_bitrate_option(enc: &mut Encoder, option: openh264_sys2::ENCODER_OPTION) -> u32 {
        let mut info = SBitrateInfo {
            iLayer: SPATIAL_LAYER_0,
            iBitrate: 0,
        };
        // SAFETY: GetOption fills `info`, which lives for the call; the
        // encoder is initialised.
        let rc = unsafe {
            enc.raw_api().get_option(
                option,
                (&raw mut info) as *mut openh264_sys2::SBitrateInfo as *mut std::ffi::c_void,
            )
        };
        assert_eq!(rc, 0);
        info.iBitrate as u32
    }

    /// FR-112 P2b — the premises of `Settings` and of `apply_runtime_bitrate`:
    /// before its first frame the C encoder refuses every runtime option
    /// (`cmInitExpected`); after it the frame rate takes, a bitrate far above
    /// the construction figure takes (the max rises with it), and a lower one
    /// takes too, the max following it down.
    #[test]
    fn options_take_only_after_the_first_frame() {
        // The crate's default construction bitrate (120 kbps) is also the max.
        let cfg = EncoderConfig::new().max_frame_rate(FrameRate::from_hz(30.0));
        let mut enc =
            Encoder::with_api_config(openh264::OpenH264API::from_source(), cfg).expect("encoder");
        assert!(
            apply_runtime_bitrate(&mut enc, 2_000_000).is_err(),
            "refused before"
        );
        assert!(
            apply_runtime_frame_rate(&mut enc, 60).is_err(),
            "refused before"
        );
        // 720p, not a thumbnail: OpenH264 picks the level from the first frame's
        // size and refuses a bitrate above that level's ceiling (a 64×64 frame
        // is level 1, whose ceiling is ~77 kbps), which is a different refusal.
        let frame = std::sync::Arc::new(make_bgra_frame(1280, 720, 10, 20, 30));
        encode_one(&mut enc, 1280, 720, frame).expect("the first frame");
        apply_runtime_frame_rate(&mut enc, 60).expect("taken after");
        let mut rate = 0f32;
        // SAFETY: `ENCODER_OPTION_FRAME_RATE` reads into a `float*` that lives
        // for the call; the encoder is initialised (a frame went through).
        let rc = unsafe {
            enc.raw_api().get_option(
                ENCODER_OPTION_FRAME_RATE,
                (&raw mut rate) as *mut std::ffi::c_void,
            )
        };
        assert_eq!((rc, rate), (0, 60.0));
        apply_runtime_idr_interval(&mut enc, 120).expect("the keyframe period taken");
        let mut period = 0i32;
        // SAFETY: an `int*` that lives for the call; the encoder is initialised.
        let rc = unsafe {
            enc.raw_api().get_option(
                ENCODER_OPTION_IDR_INTERVAL,
                (&raw mut period) as *mut std::ffi::c_void,
            )
        };
        assert_eq!((rc, period), (0, 120));
        apply_runtime_bitrate(&mut enc, 2_000_000).expect("raised past the construction max");
        assert_eq!(
            read_bitrate_option(&mut enc, ENCODER_OPTION_BITRATE),
            2_000_000
        );
        assert_eq!(
            read_bitrate_option(&mut enc, ENCODER_OPTION_MAX_BITRATE),
            2_000_000
        );
        apply_runtime_bitrate(&mut enc, 1_000_000).expect("lowered");
        assert_eq!(
            read_bitrate_option(&mut enc, ENCODER_OPTION_BITRATE),
            1_000_000
        );
        assert_eq!(
            read_bitrate_option(&mut enc, ENCODER_OPTION_MAX_BITRATE),
            1_000_000
        );
    }

    /// FR-112 P2b — settings sent before the first frame are held, the newest
    /// of each wins, they are released once, and later ones apply at once.
    #[test]
    fn early_settings_wait_for_the_first_frame() {
        let mut s = Settings::default();
        assert_eq!(s.bitrate(1_000_000), None);
        assert_eq!(s.bitrate(3_000_000), None);
        assert_eq!(s.frame_rate(60), None);
        assert_eq!(s.went_live(), (Some(3_000_000), Some(60)));
        assert_eq!(s.went_live(), (None, None), "released once");
        assert_eq!(s.bitrate(2_000_000), Some(2_000_000));
        assert_eq!(s.frame_rate(45), Some(45));
        let mut s = Settings::default();
        assert_eq!(s.went_live(), (None, None), "nothing held, nothing applied");
    }

    /// FR-112 P2b — at 60 fps the live encoder still cuts a keyframe about every
    /// two seconds: 120 frames apart, not the 60 that were two seconds at 30.
    #[tokio::test]
    async fn the_keyframe_period_keeps_its_seconds_at_60_fps() {
        let mut enc = Openh264Encoder::new(64, 64).expect("encoder");
        enc.set_frame_rate(60);
        let mut keyframes = Vec::new();
        for i in 0..130u32 {
            // A small step a frame: no scene change for the encoder to answer.
            let shade = i as u8;
            let out = enc
                .encode(std::sync::Arc::new(make_bgra_frame(
                    64,
                    64,
                    shade,
                    255 - shade,
                    shade / 2,
                )))
                .await
                .expect("encode");
            if out.iter().any(|p| p.is_keyframe) {
                keyframes.push(i);
            }
        }
        assert_eq!(
            keyframes,
            vec![0, 120],
            "one at the start, the next two seconds of 60 fps later"
        );
    }

    /// FR-112 P2b — through the worker: a frame rate and a bitrate sent before
    /// the first frame cost nothing and break nothing.
    #[tokio::test]
    async fn the_worker_holds_settings_until_its_first_frame() {
        let mut enc = Openh264Encoder::new(64, 64).expect("encoder");
        enc.set_frame_rate(60);
        enc.set_bitrate(2_000_000);
        for shade in [0u8, 128, 255] {
            let out = enc
                .encode(std::sync::Arc::new(make_bgra_frame(
                    64, 64, shade, shade, shade,
                )))
                .await
                .expect("encode");
            assert!(!out.is_empty());
        }
    }
}

#[cfg(test)]
mod rcfix_tests {
    use super::*;
    use crate::capture::{Frame, PixelFormat};

    /// rcfix 2026-11-04 — every encode of the live encoder reaches the wire,
    /// a repeated (keepalive) frame after a large keyframe included. With the
    /// crate's default frame skip, OpenH264 returned NOTHING for the next eight
    /// encodes of this exact input (and for ~1.6 s of 400 ms-spaced repeats).
    #[tokio::test]
    async fn the_live_encoder_never_skips_a_frame() {
        let (w, h) = (640u32, 400u32);
        let mut data = vec![0u8; (w * h * 4) as usize];
        let mut x: u32 = 12345;
        for p in data.chunks_mut(4) {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            p[0] = (x >> 16) as u8;
            p[1] = (x >> 8) as u8;
            p[2] = x as u8;
            p[3] = 255;
        }
        let f = std::sync::Arc::new(Frame {
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: PixelFormat::Bgra,
            data,
            monotonic_us: 0,
            monitor: 0,
            damage: crate::capture::Damage::Unknown,
            source: None,
        });
        let mut enc = Openh264Encoder::new(w, h).expect("encoder");
        let idr = enc.encode(f.clone()).await.expect("encode");
        assert!(!idr.is_empty(), "the keyframe");
        let mut empty = 0;
        for _ in 0..8 {
            let out = enc.encode(f.clone()).await.expect("encode");
            if out.iter().map(|p| p.data.len()).sum::<usize>() == 0 {
                empty += 1;
            }
        }
        assert_eq!(empty, 0, "a keepalive repeat was skipped by rate control");
    }
}
