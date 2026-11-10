// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P1 — the recorder, end to end: frames in, a playable MP4 out, and
//! the frames that come back out of a decoder are the ones that went in.
//!
//! ⚠️ This binary runs only when CI NAMES it (`--test recorder`) — every
//! `cargo test -p meshharbord` lane is `--lib`, so an integration test nobody
//! names is decoration.
//!
//! The oracle: a test capturer paints its frame counter as 16 blocks of
//! 16×16 px, black or white, into the luma a decoder hands back. A block that
//! size survives H.264 at any sane QP; a 1-px counter strip (the synthetic
//! backend's) does not. The oracle is proven to discriminate before it is
//! trusted (`the_oracle_reads_what_was_painted_and_nothing_else`).

#![cfg(all(feature = "recording", feature = "openh264-encoder"))]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use meshharbord::capture::pointer::{PointerSample, PointerShape, PointerSource, RecordedPointer};
use meshharbord::capture::{Damage, Frame, PixelFormat, ScreenCapture};
use meshharbord::encode::VideoEncoder;
use meshharbord::encode::openh264_backend::Openh264Encoder;
use meshharbord::recording::annexb::length_prefixed_to_annexb;
use meshharbord::recording::folder::{PARTIAL_DIR, PARTIAL_SUFFIX};
use meshharbord::recording::mp4::{ProgressiveFile, VIDEO_TRACK_ID};
use meshharbord::recording::recorder::{
    self, EncoderFactory, RecordOptions, RecorderEvent, StartError, StartRefusal,
};
use meshharbord::recording::sidecar::{Initiator, Pointer, Sidecar, StopReason};
use tokio::sync::{mpsc, watch};

const W: u32 = 320;
const H: u32 = 240;
const BLOCK: u32 = 16;
const BITS: u32 = 16;

/// Paint `counter` as 16 luma blocks along the top of a mid-grey frame.
fn render(counter: u16, w: u32, h: u32) -> Vec<u8> {
    let mut data = vec![0x80u8; (w * h * 4) as usize];
    for bit in 0..BITS {
        let on = (counter >> (BITS - 1 - bit)) & 1 == 1;
        let v = if on { 0xFF } else { 0x00 };
        for y in 0..BLOCK {
            for x in bit * BLOCK..(bit + 1) * BLOCK {
                let i = ((y * w + x) * 4) as usize;
                data[i] = v;
                data[i + 1] = v;
                data[i + 2] = v;
                data[i + 3] = 0xFF;
            }
        }
    }
    data
}

/// Read the counter back from a luma plane: the centre 8×8 of each block,
/// thresholded at mid-grey.
fn read_counter(y_plane: &[u8], stride: usize) -> u16 {
    let mut v = 0u16;
    for bit in 0..BITS as usize {
        let mut sum = 0u32;
        for dy in 4..12usize {
            for dx in 4..12usize {
                sum += u32::from(y_plane[dy * stride + bit * BLOCK as usize + dx]);
            }
        }
        let on = sum / 64 > 128;
        v = (v << 1) | u16::from(on);
    }
    v
}

/// BT.601 limited-range luma of a BGRA frame, for the oracle's self-test.
fn luma_of(bgra: &[u8], w: u32, h: u32) -> Vec<u8> {
    let mut y = vec![0u8; (w * h) as usize];
    for (i, px) in bgra.chunks_exact(4).enumerate() {
        let (b, g, r) = (i32::from(px[0]), i32::from(px[1]), i32::from(px[2]));
        y[i] = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16).clamp(0, 255) as u8;
    }
    y
}

/// A capturer that paints its frame counter and paces itself at `fps`.
/// After `resize_after` frames (if set) it changes size.
///
/// ⚠️ The counter is the frame index of ELAPSED TIME, like a real screen that
/// shows the present — not a count of calls. A call-counting capturer bursts
/// through its backlog after a slow encoder open, and the first frame the
/// recorder encodes is then a late one; measured on a loaded run, where the
/// first test version read `counters[0] == 15` and failed for a reason no
/// real backend has.
struct CounterCapture {
    start: Instant,
    interval: Duration,
    n: u64,
    resize_after: Option<u64>,
    fail: bool,
    /// FR-85 P1d — a pointer this "backend" cannot draw itself, handed to
    /// the recorder to draw (as DXGI and X11 do).
    pointer: Option<Box<dyn PointerSource>>,
    /// FR-85 P1d — after this many frames the screen goes still: no new
    /// frame, the way DXGI, or X11's damage tracking, reports "unchanged".
    still_after: Option<u64>,
}

impl CounterCapture {
    fn new(fps: u32) -> Self {
        Self {
            start: Instant::now(),
            interval: Duration::from_micros(1_000_000 / u64::from(fps)),
            n: 0,
            resize_after: None,
            fail: false,
            pointer: None,
            still_after: None,
        }
    }
}

#[async_trait::async_trait]
impl ScreenCapture for CounterCapture {
    async fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.fail {
            anyhow::bail!("no display");
        }
        // Sleep to the next frame boundary, then show the frame of NOW.
        let due = self.start + self.interval * (self.n as u32);
        let now = Instant::now();
        if due > now {
            tokio::time::sleep(due - now).await;
        }
        self.n = (self.start.elapsed().as_nanos() / self.interval.as_nanos()) as u64;
        if self.still_after.is_some_and(|k| self.n >= k) {
            self.n += 1;
            return Ok(None);
        }
        let (w, h) = match self.resize_after {
            Some(k) if self.n >= k => (W + 64, H),
            _ => (W, H),
        };
        let f = Frame {
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: PixelFormat::Bgra,
            data: render(self.n as u16, w, h),
            monotonic_us: self.start.elapsed().as_micros() as u64,
            monitor: 0,
            damage: Damage::Unknown,
            source: None,
        };
        self.n += 1;
        Ok(Some(f))
    }

    fn monitor_count(&self) -> u8 {
        1
    }

    fn recorded_pointer(&mut self) -> RecordedPointer {
        match self.pointer.take() {
            Some(p) => RecordedPointer::Drawn(p),
            None => RecordedPointer::Absent,
        }
    }
}

fn openh264_factory(fps: u32) -> EncoderFactory {
    Box::new(move |w, h| {
        let e = Openh264Encoder::new_recording(w, h, fps, fps * 2)?;
        Ok(Box::new(e) as Box<dyn VideoEncoder>)
    })
}

fn options(dir: &Path) -> RecordOptions {
    let mut o = RecordOptions::new(
        dir.to_path_buf(),
        "test.mp4".into(),
        Initiator::Local {
            user: Some("tester".into()),
        },
    );
    o.encoder_keeps_gop = true;
    // CI runners have far less than the production 2 GiB floor free, and this
    // test is not about disk space.
    o.min_free_to_start = 0;
    o.min_free_to_continue = 0;
    o
}

/// Record for `for_how_long`, then stop with `Requested`.
async fn record_for(
    opts: RecordOptions,
    cap: CounterCapture,
    for_how_long: Duration,
) -> (Result<recorder::RecordingSummary>, Vec<RecorderEvent>) {
    let (stop_tx, stop_rx) = watch::channel(None);
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let fps = opts.fps;
    let handle = tokio::spawn(recorder::run(
        opts,
        Box::new(cap),
        openh264_factory(fps),
        stop_rx,
        ev_tx,
    ));
    tokio::time::sleep(for_how_long).await;
    let _ = stop_tx.send(Some(StopReason::Requested));
    let result = handle.await.expect("the recorder task panicked");
    let mut events = Vec::new();
    while let Ok(e) = ev_rx.try_recv() {
        events.push(e);
    }
    (result, events)
}

struct Decoded {
    counters: Vec<u16>,
    samples: usize,
    dts: Vec<u64>,
}

/// Decode every video sample of a progressive recording with openh264 and
/// read the counter back out of each picture.
fn decode_counters(path: &Path) -> Decoded {
    let (counters, samples, dts) = decode_pictures(path, read_counter);
    Decoded {
        counters,
        samples,
        dts,
    }
}

/// Decode every video sample and hand each picture's luma plane (and its
/// stride) to `read`. Returns what `read` said per picture, the sample count
/// and the samples' decode times.
fn decode_pictures<T>(
    path: &Path,
    mut read: impl FnMut(&[u8], usize) -> T,
) -> (Vec<T>, usize, Vec<u64>) {
    use openh264::formats::YUVSource;
    let pf = ProgressiveFile::open(path).expect("open the recording");
    assert!(pf.moov_offset < pf.mdat_offset, "moov must precede mdat");
    let samples = pf.samples(VIDEO_TRACK_ID).expect("sample table");
    let ps = pf.avc_parameter_sets_annexb().expect("avcC");
    let mut dec = openh264::decoder::Decoder::new().expect("openh264 decoder");
    let mut f = std::fs::File::open(path).unwrap();
    let mut out = Vec::new();
    for (i, s) in samples.iter().enumerate() {
        let bytes = pf.read_sample(&mut f, s).unwrap();
        let mut annexb = length_prefixed_to_annexb(&bytes).expect("a well-formed sample");
        if i == 0 {
            assert!(s.sync, "the first sample must be a keyframe");
            annexb = [ps.clone(), annexb].concat();
        }
        if let Some(yuv) = dec.decode(&annexb).expect("decode") {
            let (ys, _, _) = yuv.strides();
            out.push(read(yuv.y(), ys));
        }
    }
    (out, samples.len(), samples.iter().map(|s| s.dts).collect())
}

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ── the oracle, proven before it is trusted ────────────────────────────────

#[test]
fn the_oracle_reads_what_was_painted_and_nothing_else() {
    for c in [0u16, 1, 0x8001, 0x5A5A, 0xFFFF, 1234] {
        let y = luma_of(&render(c, W, H), W, H);
        assert_eq!(read_counter(&y, W as usize), c);
    }
    // Negative control: a flipped block reads as a DIFFERENT counter, so a
    // pipeline that returned the wrong frame could not pass by accident.
    let mut bgra = render(0x00F0, W, H);
    for y in 0..BLOCK {
        for x in 0..BLOCK {
            let i = ((y * W + x) * 4) as usize;
            bgra[i..i + 3].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
        }
    }
    assert_eq!(read_counter(&luma_of(&bgra, W, H), W as usize), 0x80F0);
}

// ── in-process: the pipeline ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recording_plays_back_the_frames_that_went_in() {
    let dir = scratch();
    let opts = options(dir.path());
    // ⚠️ The screen runs at TWICE the recording's rate, as a 60 Hz display
    // under a 30 fps recording does. At exactly matched rates the screen's
    // clock and the recorder's alias: how many of the recorder's ticks find a
    // new frame depends on the phase between them. Where a tick falls on a
    // frame boundary, jitter decides which side each frame lands, and a third
    // of the ticks repeat the last frame with nothing wrong in the recorder.
    // CI met that phase now and then (61 and 62 of 91 distinct); scanning it
    // here failed 3 runs of 30 at matched rates and none at twice the rate.
    let (result, events) = record_for(opts, CounterCapture::new(60), Duration::from_secs(3)).await;
    let summary = result.expect("the recording finalizes");
    assert_eq!(summary.reason, StopReason::Requested);
    let path = summary.path.expect("a finished file");
    assert_eq!(path, dir.path().join("test.mp4"));
    assert!(
        !dir.path()
            .join(PARTIAL_DIR)
            .join(format!("test.mp4{PARTIAL_SUFFIX}"))
            .exists(),
        "the partial is removed once the file is final"
    );

    let d = decode_counters(&path);
    // ~3 s at 30 fps. Generous bounds: CI runners are noisy, and the
    // assertion that matters is the next one.
    assert!(
        (75..=100).contains(&d.samples),
        "expected ~90 frames in 3 s, got {}",
        d.samples
    );
    assert_eq!(
        d.counters.len(),
        d.samples,
        "every sample decoded to a picture"
    );
    // Frames come out in the order they went in; a still screen may repeat a
    // frame, nothing may go backwards.
    assert!(
        d.counters.windows(2).all(|p| p[0] <= p[1]),
        "counters went backwards: {:?}",
        d.counters
    );
    // Within the first ~130 ms (the encoder opens in between): frame 7 of a
    // 60 fps screen, as frame 3 was of a 30 fps one.
    assert!(
        d.counters[0] <= 7,
        "the recording starts at the start: {:?}",
        &d.counters[..5]
    );
    let unique = {
        let mut u = d.counters.clone();
        u.dedup();
        u.len()
    };
    assert!(
        unique * 10 >= d.samples * 8,
        "at least 80% distinct frames ({unique} of {})",
        d.samples
    );
    // Constant frame rate on the recorder's own clock: 3000 ticks of 90 kHz
    // per frame, except where the encoder fell behind (a longer gap, never a
    // shorter one).
    assert!(
        d.dts
            .windows(2)
            .all(|p| p[1] - p[0] >= 3000 && (p[1] - p[0]) % 3000 == 0)
    );

    // The sidecar says what happened.
    let sc: Sidecar =
        serde_json::from_str(&std::fs::read_to_string(Sidecar::path_for(&path)).unwrap()).unwrap();
    assert_eq!(sc.stop_reason, Some(StopReason::Requested));
    assert_eq!((sc.width, sc.height, sc.fps), (W, H, 30));
    assert_eq!(sc.encoder, "openh264");
    assert_eq!(sc.frames as usize, d.samples);
    assert!(matches!(sc.initiator, Initiator::Local { .. }));
    // A backend that neither draws the pointer nor says where it is: the
    // sidecar says there is none, rather than leaving it to be guessed.
    assert_eq!(sc.pointer, Some(Pointer::Absent));

    // And the event stream said it too.
    assert!(matches!(
        events.first(),
        Some(RecorderEvent::Started {
            width: 320,
            height: 240,
            ..
        })
    ));
    assert!(matches!(
        events.last(),
        Some(RecorderEvent::Stopped {
            reason: StopReason::Requested,
            fragmented: false,
            ..
        })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_display_that_changes_size_ends_the_file_cleanly() {
    let dir = scratch();
    let mut cap = CounterCapture::new(30);
    cap.resize_after = Some(30);
    let (result, _) = record_for(options(dir.path()), cap, Duration::from_secs(4)).await;
    let s = result.unwrap();
    assert_eq!(s.reason, StopReason::DisplayChanged);
    let d = decode_counters(&s.path.unwrap());
    assert!(
        d.samples >= 20 && d.samples <= 40,
        "{} frames before the resize",
        d.samples
    );
}

// ── the pointer (FR-85 P1d) ──────────────────────────────────────────────────

/// Where the test pointer is: at `a` for the first `switch_after` polls, at
/// `b` from then on. The recorder polls once per recorded frame.
struct Walk {
    polls: usize,
    switch_after: usize,
    a: (i32, i32),
    b: (i32, i32),
    shape: Arc<PointerShape>,
}

impl PointerSource for Walk {
    fn poll(&mut self) -> Option<PointerSample> {
        self.polls += 1;
        let (x, y) = if self.polls <= self.switch_after {
            self.a
        } else {
            self.b
        };
        Some(PointerSample {
            x,
            y,
            shape_id: 1,
            shape: self.shape.clone(),
        })
    }
}

/// Mean luma of the 8×8 patch centred on (`cx`, `cy`).
fn patch_luma(y_plane: &[u8], stride: usize, cx: usize, cy: usize) -> u32 {
    let mut sum = 0u32;
    for dy in 0..8 {
        for dx in 0..8 {
            sum += u32::from(y_plane[(cy - 4 + dy) * stride + cx - 4 + dx]);
        }
    }
    sum / 64
}

/// FR-85 P1d. A backend that cannot draw the pointer (DXGI, X11) says where
/// it is, and the recorder draws it: here a 32×32 white square on the
/// mid-grey test screen, at A for the first half of the recording and at B
/// for the rest. Decoded back, the square is where the source said, and
/// moving it leaves nothing behind.
///
/// ⚠️ The screen goes STILL (no new capture) well before the pointer moves.
/// That is the case that matters: over a changing screen every tick brings a
/// fresh capture, which hides a pointer drawn only on captures, and a trail
/// left by pixels never put back. Measured: with the put-back removed, this
/// cell stayed green while the screen kept changing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pointer_a_backend_cannot_draw_is_drawn_into_the_recording() {
    const SIDE: u32 = 32;
    let (a, b) = ((96, 112), (224, 112));
    let dir = scratch();
    let mut cap = CounterCapture::new(30);
    cap.still_after = Some(20);
    cap.pointer = Some(Box::new(Walk {
        polls: 0,
        switch_after: 45,
        a,
        b,
        shape: Arc::new(PointerShape {
            width: SIDE,
            height: SIDE,
            bgra: vec![0xFF; (SIDE * SIDE * 4) as usize],
        }),
    }));
    let (result, _) = record_for(options(dir.path()), cap, Duration::from_secs(3)).await;
    let summary = result.expect("the recording finalizes");
    assert_eq!(
        summary.sidecar.as_ref().and_then(|s| s.pointer),
        Some(Pointer::Drawn),
        "the sidecar says the recorder drew the pointer"
    );
    let path = summary.path.expect("a finished file");

    // Is the square at A, at B? (Its centre; the grey around it reads ~126,
    // white ~235 after BT.601 limited range and H.264.)
    let centre = |p: (i32, i32)| {
        (
            (p.0 as u32 + SIDE / 2) as usize,
            (p.1 as u32 + SIDE / 2) as usize,
        )
    };
    let (ca, cb) = (centre(a), centre(b));
    let (seen, samples, _) = decode_pictures(&path, |y, s| {
        (
            patch_luma(y, s, ca.0, ca.1) > 180,
            patch_luma(y, s, cb.0, cb.1) > 180,
        )
    });
    assert_eq!(seen.len(), samples, "every sample decoded to a picture");
    assert!(
        seen[0].0 && !seen[0].1,
        "the first frame has the pointer at A and nowhere else: {:?}",
        &seen[..3]
    );
    assert!(
        seen.iter().any(|&(at_a, at_b)| at_b && !at_a),
        "the pointer reached B: {seen:?}"
    );
    assert!(
        !seen.iter().any(|&(at_a, at_b)| at_a && at_b),
        "the pointer left a copy behind when it moved: {seen:?}"
    );
    let first_b = seen.iter().position(|&(_, at_b)| at_b).unwrap();
    assert!(
        seen[..first_b].iter().all(|&(at_a, _)| at_a),
        "the pointer was at A on every frame before it moved: {seen:?}"
    );
    assert!(
        seen[first_b..].iter().all(|&(at_a, at_b)| at_b && !at_a),
        "once at B it stayed at B: {seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_enough_disk_refuses_the_start_and_writes_nothing() {
    let dir = scratch();
    let mut opts = options(dir.path());
    opts.min_free_to_start = u64::MAX;
    let (result, events) =
        record_for(opts, CounterCapture::new(30), Duration::from_millis(50)).await;
    let err = result.unwrap_err();
    let se = err.downcast_ref::<StartError>().expect("a StartError");
    assert_eq!(se.refusal, StartRefusal::DiskLow);
    assert!(events.is_empty(), "a refused start emits no events");
    assert!(!dir.path().join("test.mp4").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_frame_refuses_the_start() {
    let dir = scratch();
    let mut opts = options(dir.path());
    opts.first_frame_timeout = Duration::from_millis(300);
    let mut cap = CounterCapture::new(30);
    cap.fail = true;
    let (result, _) = record_for(opts, cap, Duration::from_millis(50)).await;
    let err = result.unwrap_err();
    assert_eq!(
        err.downcast_ref::<StartError>().unwrap().refusal,
        StartRefusal::NoFrame
    );
}

// ── audio (FR-85 P1c) ────────────────────────────────────────────────────────

/// Decode a recording's audio track back to 48 kHz stereo PCM, in the codec
/// its sample entry names — FR-85 P4: AAC where the build's FFmpeg carries
/// the encoder, Opus otherwise — through the test's OWN decoders, never the
/// export engine's reader. Opus's `pre_skip` is dropped; AAC's priming was
/// paid by the recorder, so decoded sample 0 is time zero either way.
#[cfg(feature = "audio")]
fn decode_audio(path: &Path) -> Vec<i16> {
    use meshharbord::recording::mp4::{AUDIO_TRACK_ID, AudioCodec};
    let pf = ProgressiveFile::open(path).expect("open the recording");
    let format = pf.audio_format().unwrap().expect("an audio track");
    let samples = pf.samples(AUDIO_TRACK_ID).expect("an audio track");
    let mut f = std::fs::File::open(path).unwrap();
    let mut pcm = Vec::new();
    match format.codec {
        AudioCodec::Opus { pre_skip } => {
            use audiopus::coder::Decoder;
            use audiopus::packet::Packet;
            use audiopus::{Channels, MutSignals, SampleRate};
            let mut dec = Decoder::new(SampleRate::Hz48000, Channels::Stereo).unwrap();
            let mut out = vec![0i16; 5760 * 2];
            for s in &samples {
                let pkt = pf.read_sample(&mut f, s).unwrap();
                let n = dec
                    .decode(
                        Some(Packet::try_from(&pkt[..]).unwrap()),
                        MutSignals::try_from(&mut out[..]).unwrap(),
                        false,
                    )
                    .unwrap();
                pcm.extend_from_slice(&out[..n * 2]);
            }
            pcm.split_off(usize::from(pre_skip) * 2)
        }
        AudioCodec::Aac { asc, .. } => {
            use symphonia::core::audio::SampleBuffer;
            use symphonia::core::codecs::{CODEC_TYPE_AAC, CodecParameters, DecoderOptions};
            use symphonia::core::formats::Packet;
            let mut params = CodecParameters::new();
            params
                .for_codec(CODEC_TYPE_AAC)
                .with_sample_rate(48_000)
                .with_extra_data(asc.into_boxed_slice());
            let mut dec = symphonia::default::get_codecs()
                .make(&params, &DecoderOptions::default())
                .unwrap();
            for s in &samples {
                let pkt = pf.read_sample(&mut f, s).unwrap();
                let decoded = dec.decode(&Packet::new_from_slice(0, 0, 0, &pkt)).unwrap();
                let spec = *decoded.spec();
                assert_eq!(spec.channels.count(), 2, "a stereo track");
                let mut buf = SampleBuffer::<i16>::new(decoded.capacity() as u64, spec);
                buf.copy_interleaved_ref(decoded);
                pcm.extend_from_slice(buf.samples());
            }
            pcm
        }
    }
}

/// FR-85 P4 — the audio codec this build records: AAC when its FFmpeg has
/// the encoder, Opus otherwise. A lane that declares AAC
/// (`MESHHARBOR_EXPECT_FFMPEG_AAC=1`) fails here if it fell back.
#[cfg(feature = "audio")]
fn expected_audio_codec() -> &'static str {
    #[cfg(feature = "ffmpeg-encoder")]
    {
        use meshharbord::recording::audio_codec::{AudioEncoder, aac_expected};
        match AudioEncoder::aac() {
            Ok(_) => return "aac",
            Err(e) => assert!(
                !aac_expected(),
                "MESHHARBOR_EXPECT_FFMPEG_AAC=1 but AAC did not open: {e:#}"
            ),
        }
    }
    "opus"
}

/// Zero crossings per second of the left channel over `pcm[from..to)`
/// (48 kHz frames).
#[cfg(feature = "audio")]
fn crossings_per_second(pcm: &[i16], from: usize, to: usize) -> f64 {
    let left: Vec<i16> = pcm[from * 2..to * 2].iter().step_by(2).copied().collect();
    let n = left.windows(2).filter(|w| (w[0] < 0) != (w[1] < 0)).count();
    n as f64 * 48_000.0 / (to - from) as f64
}

/// FR-85 P1c — audio on the RECORDER's clock. A 440 Hz tone arriving at
/// 44.1 kHz mono (a real device's shape) comes out as an Opus track as long
/// as the video, still at 440 Hz; and a source that delivers NOTHING (the
/// microphone here, a quiet WASAPI loopback in the field) leaves no hole.
#[cfg(feature = "audio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_with_audio_is_in_step_with_its_video() {
    use meshharbord::recording::audio::SineCapture;
    use meshharbord::recording::mp4::AUDIO_TRACK_ID;
    use meshharbord::recording::recorder::AudioSources;

    let dir = scratch();
    let opts = options(dir.path());
    let (stop_tx, stop_rx) = watch::channel(None);
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    let audio = AudioSources {
        system: Some(Box::new(SineCapture::new(440.0, 44_100, 1, 8_000.0))),
        microphone: Some(Box::new(meshharbord::audio::NoopAudioCapture)),
    };
    let fps = opts.fps;
    let handle = tokio::spawn(recorder::run_with_audio(
        opts,
        Box::new(CounterCapture::new(fps)),
        openh264_factory(fps),
        audio,
        stop_rx,
        ev_tx,
    ));
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let _ = stop_tx.send(Some(StopReason::Requested));
    let summary = handle.await.unwrap().expect("the recording");
    let path = summary.path.expect("a file");

    let pf = ProgressiveFile::open(&path).unwrap();
    let video = pf.samples(VIDEO_TRACK_ID).unwrap().len() as u64;
    let packets = pf.samples(AUDIO_TRACK_ID).unwrap();
    let audio = packets.len() as u64;
    let video_ms = video * 1000 / u64::from(fps);
    // Summed from the packets' own durations: 20 ms Opus, 1024-sample AAC.
    let audio_ms = packets.iter().map(|s| u64::from(s.duration)).sum::<u64>() * 1000 / 48_000;
    assert!(audio > 100, "{audio} audio frames");
    assert!(
        audio_ms.abs_diff(video_ms) <= 80,
        "audio {audio_ms} ms vs video {video_ms} ms"
    );

    let pcm = decode_audio(&path);
    // Past the start-up (the pre-skip, the mix lag, the first deliveries).
    let (from, to) = (48_000 / 2, 48_000 * 2);
    let rate = crossings_per_second(&pcm, from, to);
    assert!(
        (836.0..=924.0).contains(&rate),
        "440 Hz = 880 crossings/s, got {rate:.0}"
    );
    let rms = (pcm[from * 2..to * 2]
        .iter()
        .map(|&s| f64::from(s).powi(2))
        .sum::<f64>()
        / ((to - from) * 2) as f64)
        .sqrt();
    // An 8000-peak sine is ~5657 RMS; Opus keeps it within a few percent.
    assert!((4_500.0..=6_800.0).contains(&rms), "rms {rms:.0}");

    let sc = summary.sidecar.expect("sidecar");
    assert!(sc.audio.system && sc.audio.microphone, "{:?}", sc.audio);
    // FR-85 P4 — the sidecar names the codec the track actually carries.
    let codec = expected_audio_codec();
    assert_eq!(sc.audio.codec.as_deref(), Some(codec));
    let track = pf.audio_format().unwrap().expect("an audio track").codec;
    assert_eq!(
        matches!(track, meshharbord::recording::mp4::AudioCodec::Aac { .. }),
        codec == "aac",
        "the track is {track:?}, the sidecar says {codec}"
    );
}

/// The negative control for the test above: the same recording WITHOUT audio
/// has no audio track at all — so the assertions there are about audio that
/// was recorded, not about a track that is always present.
#[cfg(feature = "audio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_without_audio_has_no_audio_track() {
    use meshharbord::recording::mp4::AUDIO_TRACK_ID;
    let dir = scratch();
    let (res, _) = record_for(
        options(dir.path()),
        CounterCapture::new(30),
        Duration::from_millis(1500),
    )
    .await;
    let path = res.unwrap().path.unwrap();
    let pf = ProgressiveFile::open(&path).unwrap();
    assert!(pf.samples(AUDIO_TRACK_ID).is_err() || pf.samples(AUDIO_TRACK_ID).unwrap().is_empty());
}

// ── the real `meshharbord record` process ──────────────────────────────────────

#[cfg(feature = "synthetic-frame-source")]
mod process {
    use super::*;
    use meshharbord::recording::recorder::PartialLock;
    use std::io::{BufRead, BufReader, Write};
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, Command, Stdio};

    struct Rec {
        child: Child,
        stdin: Option<ChildStdin>,
        lines: std::sync::mpsc::Receiver<String>,
        out: PathBuf,
    }

    fn spawn(out: &Path) -> Rec {
        spawn_with(out, &[], &[])
    }

    fn spawn_with(out: &Path, extra_args: &[&str], extra_env: &[(&str, &str)]) -> Rec {
        let mut child = Command::new(env!("CARGO_BIN_EXE_meshharbord"))
            .args(["record", "--encoder", "software", "--fps", "30", "--out"])
            .arg(out)
            .args(extra_args)
            .envs(extra_env.iter().copied())
            .env("MESHHARBORD_SYNTHETIC_FRAMES", "1")
            // No config on the runner; point it at a path that does not exist
            // so the test never reads a developer's real config.
            .arg("--config")
            .arg(out.join("no-such-config.toml"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn meshharbord record");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let stdin = child.stdin.take();
        Rec {
            child,
            stdin,
            lines: rx,
            out: out.to_path_buf(),
        }
    }

    impl Rec {
        /// Wait for the first stdout event of kind `ev`.
        fn wait_for(&self, ev: &str, within: Duration) -> serde_json::Value {
            let deadline = Instant::now() + within;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let line = self
                    .lines
                    .recv_timeout(left)
                    .unwrap_or_else(|_| panic!("no `{ev}` event within {within:?}"));
                // Log lines share stdout; only prefixed lines are protocol.
                let Some(v) = meshharbord::recording::child::parse_event_line(&line) else {
                    continue;
                };
                assert_ne!(v["ev"], "refused", "the recorder refused to start: {v}");
                if v["ev"] == ev {
                    return v;
                }
            }
        }

        /// The first `started` or `refused` — for the tests about which.
        #[cfg_attr(feature = "audio", allow(dead_code))]
        fn outcome(&self, within: Duration) -> serde_json::Value {
            let deadline = Instant::now() + within;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let line = self
                    .lines
                    .recv_timeout(left)
                    .unwrap_or_else(|_| panic!("no outcome within {within:?}"));
                let Some(v) = meshharbord::recording::child::parse_event_line(&line) else {
                    continue;
                };
                if v["ev"] == "started" || v["ev"] == "refused" {
                    return v;
                }
            }
        }

        fn wait_exit(&mut self, within: Duration) -> std::process::ExitStatus {
            let deadline = Instant::now() + within;
            loop {
                if let Some(st) = self.child.try_wait().unwrap() {
                    return st;
                }
                assert!(
                    Instant::now() < deadline,
                    "the recorder did not exit within {within:?}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        fn only_recording(&self) -> PathBuf {
            let mut mp4s: Vec<PathBuf> = std::fs::read_dir(&self.out)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "mp4"))
                .collect();
            assert_eq!(mp4s.len(), 1, "exactly one recording: {mp4s:?}");
            mp4s.pop().unwrap()
        }
    }

    fn sidecar_of(p: &Path) -> Sidecar {
        serde_json::from_str(&std::fs::read_to_string(Sidecar::path_for(p)).unwrap()).unwrap()
    }

    #[test]
    fn the_stop_command_finalizes_and_reports_the_file() {
        let dir = scratch();
        let mut r = spawn(dir.path());
        r.wait_for("started", Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(2500));
        writeln!(r.stdin.as_mut().unwrap(), r#"{{"cmd":"stop"}}"#).unwrap();
        let stopped = r.wait_for("stopped", Duration::from_secs(30));
        assert_eq!(stopped["reason"], "requested");
        assert_eq!(stopped["fragmented"], false);
        assert!(r.wait_exit(Duration::from_secs(30)).success());
        let p = r.only_recording();
        assert_eq!(stopped["path"].as_str().map(PathBuf::from), Some(p.clone()));
        assert_eq!(sidecar_of(&p).stop_reason, Some(StopReason::Requested));
        assert!(
            ProgressiveFile::open(&p)
                .unwrap()
                .samples(VIDEO_TRACK_ID)
                .unwrap()
                .len()
                >= 45
        );
    }

    #[test]
    fn closing_stdin_finalizes_as_parent_gone() {
        let dir = scratch();
        let mut r = spawn(dir.path());
        r.wait_for("started", Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(1500));
        drop(r.stdin.take());
        let stopped = r.wait_for("stopped", Duration::from_secs(30));
        assert_eq!(stopped["reason"], "parent_gone");
        assert!(r.wait_exit(Duration::from_secs(30)).success());
        assert_eq!(
            sidecar_of(&r.only_recording()).stop_reason,
            Some(StopReason::ParentGone)
        );
    }

    #[test]
    fn a_killed_recorder_leaves_a_partial_the_reconciler_finalizes() {
        let dir = scratch();
        let mut r = spawn(dir.path());
        r.wait_for("started", Duration::from_secs(30));
        // Past the first 2 s fragment, so at least one GOP is on disk.
        std::thread::sleep(Duration::from_millis(3500));
        r.child.kill().unwrap(); // SIGKILL / TerminateProcess: no finalize ran
        let _ = r.child.wait();
        let staging = dir.path().join(PARTIAL_DIR);
        let partials = partials_in(&staging);
        assert_eq!(partials.len(), 1, "the dead recorder left its partial");
        assert!(
            PartialLock::path_for(&partials[0]).exists(),
            "…and its lock file, which the kernel unlocked when it died"
        );

        let done = recorder::reconcile_partials(&staging, dir.path());
        assert_eq!(done.len(), 1);
        let p = &done[0];
        assert_eq!(sidecar_of(p).stop_reason, Some(StopReason::Interrupted));
        let n = ProgressiveFile::open(p)
            .unwrap()
            .samples(VIDEO_TRACK_ID)
            .unwrap()
            .len();
        assert!(
            n >= 60,
            "at least the first complete 2 s fragment survives ({n} frames)"
        );
        assert_eq!(
            std::fs::read_dir(&staging).unwrap().count(),
            0,
            "the partial and its lock are gone"
        );
    }

    fn partials_in(staging: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(staging)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(PARTIAL_SUFFIX))
            .collect()
    }

    /// The reconciler runs at every recorder start, beside whatever else is
    /// recording into the same folder. A partial that is still being
    /// written is not interrupted: finalizing it would remux a file under its
    /// writer — or, before its first fragment, delete it as unrecoverable.
    #[test]
    fn a_live_partial_is_left_alone_by_the_reconciler() {
        let dir = scratch();
        let mut r = spawn(dir.path());
        r.wait_for("started", Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(2500)); // a fragment on disk
        let staging = dir.path().join(PARTIAL_DIR);
        assert_eq!(partials_in(&staging).len(), 1);

        let done = recorder::reconcile_partials(&staging, dir.path());
        assert!(done.is_empty(), "a live partial was finalized: {done:?}");
        assert_eq!(partials_in(&staging).len(), 1, "…and it is still there");

        // The live recording is unharmed: it stops and finalizes normally.
        writeln!(r.stdin.as_mut().unwrap(), r#"{{"cmd":"stop"}}"#).unwrap();
        let stopped = r.wait_for("stopped", Duration::from_secs(30));
        assert_eq!(stopped["reason"], "requested");
        assert_eq!(stopped["fragmented"], false);
        assert!(r.wait_exit(Duration::from_secs(30)).success());
        let p = r.only_recording();
        assert_eq!(sidecar_of(&p).stop_reason, Some(StopReason::Requested));
        assert_eq!(
            std::fs::read_dir(&staging).unwrap().count(),
            0,
            "the finished recording took its partial and lock with it"
        );
    }

    /// P2a — the daemon's side, end to end: the manager launches the real
    /// `meshharbord record` into the configured `record_dir`, answers `start`
    /// once encoding began, refuses a second one, answers `stop` once the
    /// file is final, lists it from its sidecar, and deletes it by name only.
    /// The manager tests share the process-wide "a recording is running" mark
    /// the updater reads; run them one at a time so each reads only its own.
    static MANAGER_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_manager_drives_a_recording_end_to_end() {
        use meshharbord::recording::manager::{RecordingManager, is_recording};
        use tunnel_core::localapi::{RecordStartOpts, Response};

        let _serial = MANAGER_TESTS.lock().await;
        let dir = scratch();
        let out = dir.path().join("Recordings");
        let cfg_path = dir.path().join("config.toml");
        let mut cfg = meshharbor_node_core::config::test_fixture();
        cfg.record_dir = Some(out.to_string_lossy().into_owned());
        meshharbor_node_core::config::save(&cfg_path, &cfg).unwrap();

        let m = RecordingManager::new(PathBuf::from(env!("CARGO_BIN_EXE_meshharbord")), cfg_path)
            .with_service_identity(false)
            .with_child_env([("MESHHARBORD_SYNTHETIC_FRAMES", "1")]);
        let software = || RecordStartOpts {
            encoder: Some("software".into()),
            ..Default::default()
        };

        let st = match m.start(software()).await {
            Response::Recording(s) => s,
            other => panic!("start: {other:?}"),
        };
        assert!(st.active, "{st:?}");
        assert!(st.available && st.unavailable_reason.is_none(), "{st:?}");
        assert_eq!(st.encoder.as_deref(), Some("openh264"));
        assert!(
            st.path
                .as_deref()
                .is_some_and(|p| Path::new(p).starts_with(&out))
        );
        assert!(is_recording(), "the updater's defer gate sees it");
        assert!(
            matches!(m.start(software()).await, Response::Error { .. }),
            "one recording at a time"
        );

        tokio::time::sleep(Duration::from_millis(2000)).await;
        let st = match m.stop().await {
            Response::Recording(s) => s,
            other => panic!("stop: {other:?}"),
        };
        assert!(!st.active && !is_recording());
        let last = st.last.expect("how it ended");
        assert_eq!(last.reason, "requested");
        assert!(last.duration_ms >= 1000, "{last:?}");
        let file = PathBuf::from(last.path.expect("the finished file"));
        assert!(file.starts_with(&out) && file.is_file());

        let listing = match m.list().await {
            Response::Recordings(l) => l,
            other => panic!("list: {other:?}"),
        };
        assert_eq!(Path::new(&listing.dir), out.as_path());
        assert_eq!(listing.items.len(), 1, "{listing:?}");
        let item = &listing.items[0];
        assert_eq!(item.origin, "local");
        assert_eq!(item.stop_reason.as_deref(), Some("requested"));
        assert!(item.width >= 16 && item.duration_ms >= 1000, "{item:?}");

        for bad in ["../escape.mp4", "a/b.mp4", "notes.txt"] {
            assert!(
                matches!(
                    m.delete(bad).await,
                    Response::RecordingDeleted { ok: false, .. }
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            m.delete(&item.name).await,
            Response::RecordingDeleted { ok: true, .. }
        ));
        assert!(!file.exists() && !Sidecar::path_for(&file).exists());
    }

    /// A recorder that misses the start deadline is STOPPED, not left behind:
    /// its caller was told "did not start", and one that began a second later
    /// would be recording unseen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_recorder_that_misses_the_start_deadline_is_stopped_not_left_recording() {
        use meshharbord::recording::manager::RecordingManager;
        use tunnel_core::localapi::{RecordStartOpts, Response};

        let _serial = MANAGER_TESTS.lock().await;
        let dir = scratch();
        let out = dir.path().join("Recordings");
        let cfg_path = dir.path().join("config.toml");
        let mut cfg = meshharbor_node_core::config::test_fixture();
        cfg.record_dir = Some(out.to_string_lossy().into_owned());
        meshharbor_node_core::config::save(&cfg_path, &cfg).unwrap();
        let m = RecordingManager::new(PathBuf::from(env!("CARGO_BIN_EXE_meshharbord")), cfg_path)
            .with_service_identity(false)
            .with_child_env([("MESHHARBORD_SYNTHETIC_FRAMES", "1")])
            // Far shorter than a process spawn: the deadline always wins.
            .with_start_timeout(Duration::from_millis(1));
        let opts = RecordStartOpts {
            encoder: Some("software".into()),
            ..Default::default()
        };
        match m.start(opts).await {
            Response::Error { message } => {
                assert!(message.contains("did not start"), "{message}")
            }
            other => panic!("a missed deadline must be an error: {other:?}"),
        }
        // Long enough for a surviving child to have opened its encoder and
        // reported `started` (the healthy path takes well under a second).
        tokio::time::sleep(Duration::from_secs(4)).await;
        let st = match m.status() {
            Response::Recording(s) => s,
            other => panic!("{other:?}"),
        };
        assert!(!st.active, "a killed recorder started anyway: {st:?}");
        assert!(st.path.is_none(), "it reported `started` after all: {st:?}");
        assert_eq!(st.last.map(|l| l.reason).as_deref(), Some("start_timeout"));
        // (A killed child may not even have created the folder.)
        let written = std::fs::read_dir(&out)
            .map(|d| {
                d.flatten()
                    .filter(|e| e.path().extension().is_some_and(|x| x == "mp4"))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(written, 0, "no recording was written");
    }

    /// FR-85 P1c — `--system-audio` through the real process, the synthetic
    /// tone standing in for the device: `started` says so, and the finished
    /// file carries an audio track.
    #[cfg(feature = "audio")]
    #[test]
    fn the_process_records_computer_audio_when_asked() {
        let dir = scratch();
        let mut r = spawn_with(
            dir.path(),
            &["--system-audio"],
            &[("MESHHARBORD_SYNTHETIC_AUDIO", "1")],
        );
        let started = r.wait_for("started", Duration::from_secs(30));
        assert_eq!(started["system_audio"], true);
        assert_eq!(
            started["microphone"], false,
            "the microphone was not asked for"
        );
        std::thread::sleep(Duration::from_millis(2000));
        writeln!(r.stdin.as_mut().unwrap(), r#"{{"cmd":"stop"}}"#).unwrap();
        r.wait_for("stopped", Duration::from_secs(30));
        assert!(r.wait_exit(Duration::from_secs(30)).success());
        let p = r.only_recording();
        let n = ProgressiveFile::open(&p)
            .unwrap()
            .samples(meshharbord::recording::mp4::AUDIO_TRACK_ID)
            .unwrap()
            .len();
        assert!(n > 50, "{n} audio frames");
        let sc = sidecar_of(&p);
        assert!(sc.audio.system && !sc.audio.microphone, "{:?}", sc.audio);
    }

    /// A build WITHOUT audio refuses an audio request by name — never a
    /// recording that silently lacks the audio the person asked for.
    #[cfg(not(feature = "audio"))]
    #[test]
    fn a_build_without_audio_refuses_an_audio_request_by_name() {
        let dir = scratch();
        let mut r = spawn_with(dir.path(), &["--microphone"], &[]);
        let ev = r.outcome(Duration::from_secs(30));
        assert_eq!(ev["ev"], "refused", "{ev}");
        assert_eq!(ev["code"], "audio_unavailable", "{ev}");
        let _ = r.wait_exit(Duration::from_secs(30));
        let wrote_one = std::fs::read_dir(dir.path())
            .map(|d| {
                d.flatten()
                    .any(|e| e.path().extension().is_some_and(|x| x == "mp4"))
            })
            .unwrap_or(false);
        assert!(!wrote_one, "nothing was recorded");
    }

    /// A service with nobody to record as (SYSTEM with nobody signed in;
    /// root, until the unix drop exists) refuses a local recording — and
    /// says why, before spawning anything.
    #[tokio::test]
    async fn a_service_identity_daemon_refuses_a_local_recording() {
        use meshharbord::recording::manager::RecordingManager;
        use tunnel_core::localapi::{RecordStartOpts, Response};
        let dir = scratch();
        let m = RecordingManager::new(
            PathBuf::from("does-not-exist-so-a-spawn-would-fail"),
            dir.path().join("config.toml"),
        )
        .with_service_identity(true);
        // What the refusal names: a Windows service with nobody signed in is
        // at its sign-in screen (decision 6); root elsewhere, the account.
        let names_why = |m: &str| {
            if cfg!(windows) {
                m.contains("sign-in screen")
            } else {
                m.contains("this device service runs as")
            }
        };
        // Said AHEAD of time, so a client greys its Start out (P2b)…
        match m.status() {
            Response::Recording(st) => {
                assert!(!st.available, "{st:?}");
                assert!(
                    st.unavailable_reason.as_deref().is_some_and(names_why),
                    "{st:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        // …and again if a start is attempted anyway.
        match m.start(RecordStartOpts::default()).await {
            Response::Error { message } => assert!(names_why(&message), "{message}"),
            other => panic!("{other:?}"),
        }
    }

    /// FR-85 P1f — a REMOTE start decided under one identity is refused when
    /// another holds as the recorder launches. An unattended start skipped
    /// the banner because nobody was signed in, and must not then record a
    /// person who signed in meanwhile, with nothing on their screen.
    #[tokio::test]
    async fn a_remote_start_refuses_if_who_is_signed_in_changed() {
        use meshharbord::recording::launch::Identity;
        use meshharbord::recording::manager::{RecordingManager, RemoteInitiator, StartError};
        let dir = scratch();
        let m = RecordingManager::new(
            PathBuf::from("does-not-exist-so-a-spawn-would-fail"),
            dir.path().join("config.toml"),
        )
        .with_identity(Ok(Identity::Inherit));
        let initiator = RemoteInitiator {
            session_id: bson::oid::ObjectId::new(),
            controller_user_id: bson::oid::ObjectId::new(),
            controller_name: "Tester".into(),
        };
        match m.start_remote(initiator, false, Identity::Unattended).await {
            Err(StartError::Failed(message)) => {
                assert!(message.contains("changed"), "{message}")
            }
            other => panic!("the start went ahead: {other:?}"),
        }
    }

    /// FR-85 decision 6 — a login screen that comes up between the decision
    /// (unattended) and the launch refuses by ITS name: the refusal travels
    /// whole, so the controller is told `login_screen`, never a bare
    /// "unavailable" (found in review: it was flattened to a sentence).
    #[tokio::test]
    async fn a_login_screen_at_the_launch_refuses_by_its_own_name() {
        use meshharbord::recording::launch::{Identity, Refusal};
        use meshharbord::recording::manager::{RecordingManager, RemoteInitiator, StartError};
        let dir = scratch();
        let m = RecordingManager::new(
            PathBuf::from("does-not-exist-so-a-spawn-would-fail"),
            dir.path().join("config.toml"),
        )
        .with_identity(Err(Refusal::LoginScreen));
        let initiator = RemoteInitiator {
            session_id: bson::oid::ObjectId::new(),
            controller_user_id: bson::oid::ObjectId::new(),
            controller_name: "Tester".into(),
        };
        match m.start_remote(initiator, false, Identity::Unattended).await {
            Err(StartError::Unavailable(Refusal::LoginScreen)) => {}
            other => panic!("not refused as a login screen: {other:?}"),
        }
    }

    /// `MESHHARBORD_RECORDING=0` closes every path at once, and says so: the
    /// state a client greys Start out with, a start, what the device
    /// advertises (`available`), the listing and the folder a download is
    /// served from.
    #[tokio::test]
    async fn the_kill_switch_closes_every_path_and_says_so() {
        use meshharbord::recording::manager::RecordingManager;
        use tunnel_core::localapi::{RecordStartOpts, Response};
        let dir = scratch();
        let manager = |off: bool| {
            RecordingManager::new(
                PathBuf::from("does-not-exist-so-a-spawn-would-fail"),
                dir.path().join("config.toml"),
            )
            .with_service_identity(false)
            .with_switched_off(off)
        };
        // The control: the same manager with the switch left alone can record.
        assert!(manager(false).available());

        let m = manager(true);
        assert!(
            !m.available(),
            "a switched-off device must not advertise recording"
        );
        match m.status() {
            Response::Recording(st) => {
                assert!(!st.available, "{st:?}");
                assert!(
                    st.unavailable_reason
                        .as_deref()
                        .is_some_and(|r| r.contains("MESHHARBORD_RECORDING=0")),
                    "{st:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        match m.start(RecordStartOpts::default()).await {
            Response::Error { message } => {
                assert!(message.contains("MESHHARBORD_RECORDING=0"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        match m.list().await {
            Response::Recordings(l) => {
                assert!(l.items.is_empty() && l.dir.is_empty(), "{l:?}");
                assert!(
                    l.folder_reason
                        .as_deref()
                        .is_some_and(|r| r.contains("switched off")),
                    "{l:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(
            m.folder().await.is_none(),
            "nothing is served while switched off"
        );
    }

    /// FR-85 P1e — the recorder a daemon launches runs at normal integrity
    /// whatever the daemon runs at: an elevated worker (a UAC-split
    /// administrator's, the service default) hands it a restricted copy of
    /// its token — the same user, the admin group deny-only, medium
    /// integrity. `record --whoami` reports what the child actually got.
    ///
    /// On an elevated test run the parent is High and the child must not be;
    /// on a medium one both are medium and the case still holds.
    #[cfg(windows)]
    #[tokio::test]
    async fn an_elevated_daemon_launches_the_recorder_at_medium_integrity() {
        use meshharbord::recording::launch::{self, Identity};
        use tokio::io::AsyncBufReadExt;
        let parent = launch::describe_self();
        let expected = launch::decide().expect("a test run is never refused");
        let whoami = |identity: Identity| async move {
            let l = launch::spawn(
                identity,
                Path::new(env!("CARGO_BIN_EXE_meshharbord")),
                &["record".into(), "--whoami".into()],
                &[],
            )
            .expect("launch");
            drop(l.stdin);
            let mut lines = tokio::io::BufReader::new(l.stdout).lines();
            tokio::time::timeout(Duration::from_secs(20), async {
                while let Some(line) = lines.next_line().await.expect("read") {
                    if let Some(ev) = meshharbord::recording::child::parse_event_line(&line) {
                        return ev;
                    }
                }
                panic!("the recorder said nothing")
            })
            .await
            .expect("the recorder answers")
        };
        let child = whoami(expected).await;
        println!("the daemon: {parent}\nits recorder, as {expected:?}: {child}");
        // The CI lane runs elevated ON PURPOSE and says so: there, a medium
        // run would prove nothing and must not pass as if it had.
        if std::env::var_os("MESHHARBORD_TEST_REQUIRE_ELEVATED").is_some() {
            assert!(
                parent["integrity_rid"]
                    .as_u64()
                    .is_some_and(|rid| rid > 0x2000),
                "this lane must run elevated for the drop to be proven: {parent}"
            );
        }
        assert_eq!(child["ev"], "whoami", "{child}");
        assert_eq!(
            child["user"], parent["user"],
            "the same person: {child} vs {parent}"
        );
        assert_eq!(child["system"], false, "{child}");
        assert!(
            child["integrity_rid"]
                .as_u64()
                .is_some_and(|rid| rid <= 0x2000),
            "the recorder ran above medium integrity: {child} (the daemon: {parent})"
        );
        assert_eq!(
            child["admin_enabled"], false,
            "{child} (the daemon: {parent})"
        );
        if parent["integrity_rid"]
            .as_u64()
            .is_some_and(|rid| rid > 0x2000)
        {
            assert_eq!(expected, Identity::RestrictedCopy);
            // The positive control: launched as the daemon itself, the child
            // IS elevated — so the assertions above can fail.
            let same = whoami(Identity::Inherit).await;
            assert_eq!(same["integrity_rid"], parent["integrity_rid"], "{same}");
        }
    }

    /// FR-85 P1e — a whole recording through the identity rule. On an
    /// elevated run the recorder is the restricted, medium copy: the folder
    /// is asked of it (`record --where`), it captures, encodes and writes the
    /// file as the person, and the daemon's list and delete run impersonating
    /// it. On a medium run the same flow is the plain launch.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_manager_records_as_the_person_at_normal_integrity() {
        use meshharbord::recording::launch;
        use meshharbord::recording::manager::RecordingManager;
        use tunnel_core::localapi::{RecordStartOpts, Response};

        let _serial = MANAGER_TESTS.lock().await;
        let identity = launch::decide().expect("a test run is never refused");
        let dir = scratch();
        let out = dir.path().join("Recordings");
        let cfg_path = dir.path().join("config.toml");
        let mut cfg = meshharbor_node_core::config::test_fixture();
        cfg.record_dir = Some(out.to_string_lossy().into_owned());
        meshharbor_node_core::config::save(&cfg_path, &cfg).unwrap();
        let exe = PathBuf::from(env!("CARGO_BIN_EXE_meshharbord"));
        let manager = || {
            RecordingManager::new(exe.clone(), cfg_path.clone())
                .with_identity(Ok(identity))
                .with_child_env([("MESHHARBORD_SYNTHETIC_FRAMES", "1")])
        };

        // A fresh manager has no answer cached: this one comes from the
        // recorder, launched as `identity`.
        assert_eq!(
            manager().folder().await.as_deref(),
            Some(out.as_path()),
            "as {identity:?}"
        );

        let m = manager();
        let started = m
            .start(RecordStartOpts {
                encoder: Some("software".into()),
                ..Default::default()
            })
            .await;
        let st = match started {
            Response::Recording(s) => s,
            other => panic!("start as {identity:?}: {other:?}"),
        };
        assert!(st.active, "{st:?}");
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let st = match m.stop().await {
            Response::Recording(s) => s,
            other => panic!("stop: {other:?}"),
        };
        let file = PathBuf::from(st.last.and_then(|l| l.path).expect("the finished file"));
        assert!(
            file.starts_with(&out) && file.is_file(),
            "{}",
            file.display()
        );

        let listing = match m.list().await {
            Response::Recordings(l) => l,
            other => panic!("list: {other:?}"),
        };
        assert_eq!(listing.items.len(), 1, "{listing:?}");
        assert!(matches!(
            m.delete(&listing.items[0].name).await,
            Response::RecordingDeleted { ok: true, .. }
        ));
        assert!(!file.exists(), "deleted as {identity:?}");
    }
}
