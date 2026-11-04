// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — the recording pipeline: capture → CFR pacer → encoder → MP4.
//!
//! A recording is a pipeline of its OWN. It never taps the live remote-control
//! pump — whose capture is capped by the viewer's rung and whose encoder is
//! rate-governed to the network — because a recording made from that would be
//! transport quality, and a new consumer on the most-tuned path in the product
//! is a new way to break it. The price is a second capturer when a session is
//! live (a second WGC session; one of DXGI's duplication seats), paid only
//! while recording.
//!
//! Tasks:
//! - **capture** — pulls frames and keeps only the latest (a slot the loop
//!   takes from), so a slow encoder never backs capture up; a size change ends
//!   the recording (`display_changed`) rather than scaling mid-file.
//! - **the pointer** (FR-85 P1d) — drawn by the backend where it can
//!   ([`crate::capture::open_for_recording`]), otherwise drawn here each tick
//!   from where the backend says it is ([`super::pointer`]).
//! - **the loop here** — one tick per `1/fps` on its own clock, encodes the
//!   latest frame (or repeats the last one on a still screen — constant frame
//!   rate), forces a keyframe every GOP when the encoder does not keep one
//!   itself, and hands access units to the [`FragmentedWriter`].
//!
//! Stop is a `watch` of [`StopReason`]; every guard (disk, duration, encoder,
//! capture) stops through the same path, so the finalize is the same code no
//! matter why it ended.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use tokio::sync::{mpsc, watch};

use crate::capture::pointer::{PointerSource, RecordedPointer};
use crate::capture::{Frame, ScreenCapture};
use crate::encode::VideoEncoder;

use super::folder::{self, PARTIAL_DIR, PARTIAL_SUFFIX};
use super::mp4::{self, ColorInfo, FragmentedWriter, VideoTrack};
use super::pacer::{Cadence, TickFifo};
use super::pointer::PointerLayer;
use super::sidecar::{AudioInfo, Event, Initiator, Pointer, SIDECAR_VERSION, Sidecar, StopReason};

/// Everything a recording needs to know before its first frame.
#[derive(Debug, Clone)]
pub struct RecordOptions {
    /// Where the finished file goes.
    pub dest_dir: PathBuf,
    /// Its file name (see [`folder::unique_recording_name`]).
    pub file_name: String,
    /// Where the partial is written while recording. `None` = the in-folder
    /// staging dir `<dest_dir>/.roomler-partial/`.
    pub staging_dir: Option<PathBuf>,
    pub fps: u32,
    /// Seconds between keyframes (and so between fragments).
    pub gop_seconds: u32,
    pub max_duration: Duration,
    /// Refuse to start with less free space than this.
    pub min_free_to_start: u64,
    /// Stop cleanly once free space falls below this.
    pub min_free_to_continue: u64,
    pub initiator: Initiator,
    /// The encoder keeps its own GOP (openh264's recording profile); `false`
    /// = the recorder forces a keyframe every `gop_seconds`.
    pub encoder_keeps_gop: bool,
    /// How long to wait for the first captured frame.
    pub first_frame_timeout: Duration,
}

impl RecordOptions {
    pub fn new(dest_dir: PathBuf, file_name: String, initiator: Initiator) -> Self {
        Self {
            dest_dir,
            file_name,
            staging_dir: None,
            fps: 30,
            gop_seconds: 2,
            max_duration: Duration::from_secs(240 * 60),
            min_free_to_start: 2 << 30,
            min_free_to_continue: 1 << 30,
            initiator,
            encoder_keeps_gop: false,
            first_frame_timeout: Duration::from_secs(10),
        }
    }

    pub fn staging(&self) -> PathBuf {
        self.staging_dir
            .clone()
            .unwrap_or_else(|| self.dest_dir.join(PARTIAL_DIR))
    }
}

/// What the recorder reports while it runs.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum RecorderEvent {
    Started {
        partial: PathBuf,
        path: PathBuf,
        width: u32,
        height: u32,
        fps: u32,
        encoder: String,
        /// FR-85 P1c — which audio is going in.
        system_audio: bool,
        microphone: bool,
    },
    Progress {
        duration_ms: u64,
        bytes: u64,
        frames: u64,
        late_ticks: u64,
    },
    Stopped {
        reason: StopReason,
        /// The finished file, when there is one.
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<PathBuf>,
        bytes: u64,
        duration_ms: u64,
        frames: u64,
        /// The progressive remux failed and the fragmented file was kept.
        fragmented: bool,
    },
}

/// Why a recording could not even start. A closed set, like [`StopReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartRefusal {
    NoFrame,
    DiskLow,
    EncoderUnavailable,
    FolderUnwritable,
    /// Audio was asked for and this build or platform cannot record it.
    AudioUnavailable,
    /// Computer audio was asked for and no loopback / monitor source opened.
    SystemAudioUnavailable,
    /// The microphone was asked for and did not open (none, or blocked by a
    /// privacy setting).
    MicUnavailable,
}

impl StartRefusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoFrame => "no_frame",
            Self::DiskLow => "disk_low",
            Self::EncoderUnavailable => "encoder_unavailable",
            Self::FolderUnwritable => "folder_unwritable",
            Self::AudioUnavailable => "audio_unavailable",
            Self::SystemAudioUnavailable => "system_audio_unavailable",
            Self::MicUnavailable => "mic_unavailable",
        }
    }
}

/// The audio a recording is made with (FR-85 P1c). Without the `audio`
/// feature there is nothing to put in it: a recording is video-only.
#[cfg(feature = "audio")]
pub use super::audio::AudioSources;

/// The audio a recording is made with — nothing, in a build without the
/// `audio` feature.
#[cfg(not(feature = "audio"))]
#[derive(Default)]
pub struct AudioSources;

#[cfg(not(feature = "audio"))]
impl AudioSources {
    pub fn is_empty(&self) -> bool {
        true
    }
}

/// A refused start, with the reason and the detail for the log.
#[derive(Debug)]
pub struct StartError {
    pub refusal: StartRefusal,
    pub detail: String,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.refusal.as_str(), self.detail)
    }
}

impl std::error::Error for StartError {}

fn refuse(refusal: StartRefusal, detail: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(StartError {
        refusal,
        detail: detail.into(),
    })
}

/// The result of a finished recording.
#[derive(Debug, Clone)]
pub struct RecordingSummary {
    pub reason: StopReason,
    pub path: Option<PathBuf>,
    pub sidecar: Option<Sidecar>,
}

/// Builds the encoder once the first frame's size is known.
pub type EncoderFactory = Box<dyn FnOnce(u32, u32) -> Result<Box<dyn VideoEncoder>> + Send>;

/// Openh264 returns a keyframe as one packet per layer; every other backend
/// returns one packet per frame. Group accordingly.
pub(crate) fn group_access_units(
    encoder: &str,
    packets: Vec<crate::encode::EncodedPacket>,
) -> Vec<(Vec<u8>, bool)> {
    if packets.is_empty() {
        return Vec::new();
    }
    if encoder == "openh264" {
        let key = packets.iter().any(|p| p.is_keyframe);
        let data = packets.into_iter().flat_map(|p| p.data).collect();
        vec![(data, key)]
    } else {
        packets
            .into_iter()
            .map(|p| (p.data, p.is_keyframe))
            .collect()
    }
}

/// The newest captured frame, waiting for the loop. Latest wins: a frame the
/// loop has not taken yet is replaced, never queued, so a slow encoder never
/// backs capture up. The loop TAKES it, and so owns it outright.
#[derive(Default)]
struct Latest(std::sync::Mutex<Option<Frame>>);

impl Latest {
    fn put(&self, f: Frame) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(f);
    }

    fn take(&self) -> Option<Frame> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// What the loop encodes each tick: the latest frame, with the pointer drawn
/// on it when the backend does not draw it itself (FR-85 P1d).
enum Picture {
    Plain(Arc<Frame>),
    WithPointer(PointerLayer),
}

impl Picture {
    fn new(first: Arc<Frame>, pointer: Option<Box<dyn PointerSource>>) -> Self {
        match pointer {
            Some(source) => Self::WithPointer(PointerLayer::new(source, first)),
            None => Self::Plain(first),
        }
    }

    fn replace(&mut self, f: Arc<Frame>) {
        match self {
            Self::Plain(p) => *p = f,
            Self::WithPointer(l) => l.replace(f),
        }
    }

    /// The frame for this tick. On a still screen, the same one again.
    fn frame(&mut self) -> Arc<Frame> {
        match self {
            Self::Plain(p) => p.clone(),
            Self::WithPointer(l) => l.frame(),
        }
    }
}

/// Crop a frame to even dimensions in place (H.264 4:2:0 needs them). No
/// copy: `stride` already describes the rows.
fn even(mut f: Frame) -> Frame {
    f.width &= !1;
    f.height &= !1;
    f
}

/// Record until `stop` carries a reason (or a guard trips). Events stream to
/// `events`; the summary is returned once the file is final. Video only —
/// [`run_with_audio`] adds audio.
// `AudioSources` is a unit struct without `audio` and a struct with fields
// with it; `default()` is the one spelling that builds both.
#[allow(clippy::default_constructed_unit_structs)]
pub async fn run(
    opts: RecordOptions,
    capturer: Box<dyn ScreenCapture>,
    make_encoder: EncoderFactory,
    stop: watch::Receiver<Option<StopReason>>,
    events: mpsc::UnboundedSender<RecorderEvent>,
) -> Result<RecordingSummary> {
    run_with_audio(
        opts,
        capturer,
        make_encoder,
        AudioSources::default(),
        stop,
        events,
    )
    .await
}

/// [`run`], with the audio sources the recording was asked for (FR-85 P1c).
pub async fn run_with_audio(
    opts: RecordOptions,
    mut capturer: Box<dyn ScreenCapture>,
    make_encoder: EncoderFactory,
    audio: AudioSources,
    mut stop: watch::Receiver<Option<StopReason>>,
    events: mpsc::UnboundedSender<RecorderEvent>,
) -> Result<RecordingSummary> {
    let staging = opts.staging();
    std::fs::create_dir_all(&staging).map_err(|e| {
        refuse(
            StartRefusal::FolderUnwritable,
            format!("{}: {e}", staging.display()),
        )
    })?;
    std::fs::create_dir_all(&opts.dest_dir).map_err(|e| {
        refuse(
            StartRefusal::FolderUnwritable,
            format!("{}: {e}", opts.dest_dir.display()),
        )
    })?;
    if let Some(free) = folder::available_space(&staging)
        && free < opts.min_free_to_start
    {
        return Err(refuse(
            StartRefusal::DiskLow,
            format!(
                "{} MiB free in {}, {} MiB needed to start",
                free >> 20,
                staging.display(),
                opts.min_free_to_start >> 20
            ),
        ));
    }

    // ── the first frame decides the size ────────────────────────────────────
    let first = tokio::time::timeout(opts.first_frame_timeout, async {
        loop {
            match capturer.next_frame().await {
                Ok(Some(f)) => return Ok(f),
                Ok(None) => continue,
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .map_err(|_| refuse(StartRefusal::NoFrame, "no frame from the capture backend"))?
    .map_err(|e| refuse(StartRefusal::NoFrame, format!("{e:#}")))?;
    let first = even(first);
    let (width, height) = (first.width, first.height);
    if width < 16 || height < 16 {
        return Err(refuse(
            StartRefusal::NoFrame,
            format!("frame too small: {width}x{height}"),
        ));
    }

    let mut encoder = make_encoder(width, height)
        .map_err(|e| refuse(StartRefusal::EncoderUnavailable, format!("{e:#}")))?;
    let encoder_name = encoder.name().to_string();
    if encoder_name == "noop" {
        return Err(refuse(
            StartRefusal::EncoderUnavailable,
            "every encoder backend failed to open",
        ));
    }

    let partial = staging.join(format!("{}{PARTIAL_SUFFIX}", opts.file_name));
    let dest = opts.dest_dir.join(&opts.file_name);
    // Held until the file is final: the reconciler leaves a partial alone
    // for exactly as long as this lock is held.
    let partial_lock = match PartialLock::try_take(&partial) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            return Err(refuse(
                StartRefusal::FolderUnwritable,
                format!("another recorder holds {}", partial.display()),
            ));
        }
        Err(e) => {
            return Err(refuse(
                StartRefusal::FolderUnwritable,
                format!("{}: {e}", PartialLock::path_for(&partial).display()),
            ));
        }
    };
    let cadence = Cadence::new(opts.fps);
    let video = VideoTrack {
        width,
        height,
        fps: cadence.fps(),
        color: ColorInfo::BT601_LIMITED,
    };
    // FR-85 P1c — the audio sources start pulling now; what they buffered
    // before the clock starts is cut as a backlog.
    #[cfg(feature = "audio")]
    let mut audio_rt = if audio.is_empty() {
        None
    } else {
        Some(
            super::audio::RecordingAudio::start(audio)
                .map_err(|e| refuse(StartRefusal::AudioUnavailable, format!("{e:#}")))?,
        )
    };
    #[cfg(not(feature = "audio"))]
    let _ = audio;
    #[cfg(feature = "audio")]
    let (audio_system, audio_microphone) = audio_rt
        .as_ref()
        .map(|a| (a.system, a.microphone))
        .unwrap_or((false, false));
    #[cfg(not(feature = "audio"))]
    let (audio_system, audio_microphone) = (false, false);
    // FR-85 P4 — the track's codec: AAC where this build's FFmpeg has it,
    // Opus otherwise (`audio_codec::AudioEncoder::best`).
    #[cfg(feature = "audio")]
    let mut audio_enc = match audio_rt {
        Some(_) => Some(
            super::audio_codec::AudioEncoder::best()
                .map_err(|e| refuse(StartRefusal::AudioUnavailable, format!("{e:#}")))?,
        ),
        None => None,
    };
    #[cfg(feature = "audio")]
    let audio_codec_name = audio_enc.as_ref().map(|e| e.name());
    #[cfg(not(feature = "audio"))]
    let audio_codec_name: Option<&'static str> = None;
    #[cfg(feature = "audio")]
    let audio_track = audio_enc.as_ref().map(|e| e.track());
    #[cfg(not(feature = "audio"))]
    let audio_track: Option<mp4::AudioTrack> = None;

    let mut writer = FragmentedWriter::create(&partial, video, audio_track)
        .map_err(|e| refuse(StartRefusal::FolderUnwritable, format!("{e:#}")))?;
    let started_at = chrono::Utc::now();
    let _ = events.send(RecorderEvent::Started {
        partial: partial.clone(),
        path: dest.clone(),
        width,
        height,
        fps: cadence.fps(),
        encoder: encoder_name.clone(),
        system_audio: audio_system,
        microphone: audio_microphone,
    });
    tracing::info!(
        width, height, fps = cadence.fps(), encoder = %encoder_name,
        partial = %partial.display(), "recording: started"
    );

    // ── the pointer (FR-85 P1d) ─────────────────────────────────────────────
    // Asked once, now that the first frame proved the backend works: does it
    // draw the pointer into its frames, must the recorder draw it, or is
    // there none? The sidecar keeps the answer.
    let (pointer, pointer_source) = match capturer.recorded_pointer() {
        RecordedPointer::InFrame => (Pointer::InFrame, None),
        RecordedPointer::Drawn(source) => (Pointer::Drawn, Some(source)),
        RecordedPointer::Absent => (Pointer::Absent, None),
    };
    tracing::info!(pointer = pointer.as_str(), "recording: the pointer");

    // ── capture task: latest frame wins ─────────────────────────────────────
    // A slot the loop TAKES from, so the loop owns each new frame outright
    // and the pointer layer draws on it in place rather than copying it.
    let latest = Arc::new(Latest::default());
    let latest_tx = latest.clone();
    let (cap_stop_tx, mut cap_stop_rx) = watch::channel(false);
    let (cap_fail_tx, mut cap_fail_rx) = watch::channel::<Option<StopReason>>(None);
    let capture = tokio::spawn(async move {
        let mut consecutive_errors = 0u32;
        loop {
            tokio::select! {
                _ = cap_stop_rx.changed() => break,
                r = capturer.next_frame() => match r {
                    Ok(Some(f)) => {
                        consecutive_errors = 0;
                        let f = even(f);
                        if (f.width, f.height) != (width, height) {
                            tracing::info!(
                                from = %format!("{width}x{height}"),
                                to = %format!("{}x{}", f.width, f.height),
                                "recording: the display changed size — ending the file cleanly"
                            );
                            let _ = cap_fail_tx.send(Some(StopReason::DisplayChanged));
                            break;
                        }
                        latest_tx.put(f);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        consecutive_errors += 1;
                        // A lock screen or a desktop switch fails a few pulls
                        // and comes back; the pacer keeps repeating the last
                        // frame meanwhile. Only a persistent failure ends it.
                        if consecutive_errors == 1 || consecutive_errors.is_multiple_of(50) {
                            tracing::warn!(%e, consecutive_errors, "recording: capture error");
                        }
                        if consecutive_errors >= 300 {
                            let _ = cap_fail_tx.send(Some(StopReason::CaptureFailed));
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
    });

    // ── the paced encode loop ───────────────────────────────────────────────
    let start = Instant::now();
    let mut interval = tokio::time::interval(cadence.interval());
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let gop_ticks = cadence.gop_ticks(opts.gop_seconds);
    let mut picture = Picture::new(Arc::new(first), pointer_source);
    let mut fifo = TickFifo::default();
    let mut next_tick = 0u64;
    let mut last_keyframe_tick: Option<u64> = None;
    let mut late_ticks = 0u64;
    let mut frames = 0u64;
    let mut encode_errors = 0u32;
    let mut last_progress = Instant::now();
    let mut last_disk_check = Instant::now();
    let mut events_log: Vec<Event> = Vec::new();
    // FR-85 P1c — mixed audio waits here until the first video frame is
    // written: that frame's time is audio time zero (`audio_origin`, in
    // 48 kHz samples), and audio before it is dropped rather than shifted.
    // P4 — it waits as PCM, not packets, so the cut is sample-exact and a
    // codec with its own frame size (AAC's 1024) starts where it should.
    #[cfg(feature = "audio")]
    let mut audio_queue: std::collections::VecDeque<(u64, Vec<i16>)> =
        std::collections::VecDeque::new();
    #[cfg(feature = "audio")]
    let mut audio_origin: Option<u64> = None;

    let reason = loop {
        tokio::select! {
            _ = interval.tick() => {}
            r = stop.changed() => {
                if r.is_err() {
                    break StopReason::ParentGone;
                }
                if let Some(reason) = *stop.borrow() {
                    break reason;
                }
                continue;
            }
            r = cap_fail_rx.changed() => {
                // A capture task that ended without saying why (a panic drops
                // its sender) must not leave this select spinning on a closed
                // channel.
                if r.is_err() {
                    break StopReason::CaptureFailed;
                }
                if let Some(reason) = *cap_fail_rx.borrow() {
                    break reason;
                }
                continue;
            }
        }
        let elapsed = start.elapsed();
        if elapsed >= opts.max_duration {
            break StopReason::MaxDuration;
        }
        let tick = cadence.tick_at(elapsed).max(next_tick);
        if tick > next_tick {
            late_ticks += tick - next_tick;
        }
        next_tick = tick + 1;

        if let Some(f) = latest.take() {
            picture.replace(Arc::new(f));
        }
        if !opts.encoder_keeps_gop
            && last_keyframe_tick.is_none_or(|k| tick.saturating_sub(k) >= gop_ticks)
        {
            encoder.request_keyframe();
            last_keyframe_tick = Some(tick);
        }

        fifo.submitted(tick);
        // A backend that silently returns nothing for some frames (rather
        // than delaying them) would otherwise grow the FIFO and push every
        // later frame's PTS further into the past. No encoder we dispatch
        // holds more than a couple of frames.
        while fifo.in_flight() > 8 {
            let _ = fifo.finished();
        }
        let packets = match encoder.encode(picture.frame()).await {
            Ok(p) => {
                encode_errors = 0;
                p
            }
            Err(e) => {
                encode_errors += 1;
                tracing::warn!(%e, encode_errors, "recording: encode error");
                // The tick produced nothing; drop its FIFO slot.
                let _ = fifo.finished();
                if encode_errors >= 30 {
                    break StopReason::EncoderFailed;
                }
                continue;
            }
        };
        let mut failed = None;
        for (au, key) in group_access_units(&encoder_name, packets) {
            let t = fifo.finished();
            let pts = cadence.pts(t);
            let r = tokio::task::block_in_place(|| writer.push_video(pts, &au, key));
            match r {
                Ok(mp4::PushOutcome::Written) => {
                    frames += 1;
                    #[cfg(feature = "audio")]
                    if audio_origin.is_none() {
                        audio_origin = Some(
                            pts * u64::from(super::audio::RATE) / u64::from(mp4::VIDEO_TIMESCALE),
                        );
                    }
                }
                Ok(mp4::PushOutcome::DroppedBeforeKeyframe) => {}
                Err(e) => {
                    tracing::warn!(%e, "recording: writer refused an access unit");
                    failed = Some(StopReason::EncoderFailed);
                    break;
                }
            }
        }
        if let Some(r) = failed {
            break r;
        }

        // FR-85 P1c — audio on the same clock, a mix lag behind it.
        #[cfg(feature = "audio")]
        {
            let until = super::audio::samples_for(start.elapsed())
                .saturating_sub(super::audio::samples_for(super::audio::MIX_LAG));
            let failed = match (audio_rt.as_mut(), audio_enc.as_mut()) {
                (Some(a), Some(enc)) => {
                    pump_audio(a, enc, until, &mut audio_queue, audio_origin, &mut writer).err()
                }
                _ => None,
            };
            if let Some(e) = failed {
                // The video goes on: a recording without its audio is still
                // the recording, and the sidecar says what happened.
                tracing::warn!(%e, "recording: audio failed — continuing without it");
                events_log.push(Event {
                    t_ms: start.elapsed().as_millis() as u64,
                    kind: "audio_failed".into(),
                    detail: Some(format!("{e:#}")),
                });
                if let Some(a) = audio_rt.take() {
                    let _ = a.stop();
                }
                audio_enc = None;
                audio_queue.clear();
            }
        }

        if last_progress.elapsed() >= Duration::from_secs(1) {
            last_progress = Instant::now();
            let st = writer.stats();
            let _ = events.send(RecorderEvent::Progress {
                duration_ms: start.elapsed().as_millis() as u64,
                bytes: st.bytes,
                frames,
                late_ticks,
            });
        }
        if last_disk_check.elapsed() >= Duration::from_secs(5) {
            last_disk_check = Instant::now();
            if folder::available_space(&staging)
                .is_some_and(|free| free < opts.min_free_to_continue)
            {
                break StopReason::DiskLow;
            }
        }
    };

    // ── finalize ────────────────────────────────────────────────────────────
    let _ = cap_stop_tx.send(true);
    let _ = capture.await;
    // The audio catches up to the video's end (no lag now: what is buffered
    // is all there will be), then its sources stop.
    #[cfg(feature = "audio")]
    if let Some(mut a) = audio_rt.take() {
        let until = super::audio::samples_for(start.elapsed());
        if let Some(enc) = audio_enc.as_mut() {
            // Then the encoder's last partial frame and whatever it still
            // holds — AAC keeps a frame back until it is flushed.
            let written = pump_audio(
                &mut a,
                enc,
                until,
                &mut audio_queue,
                audio_origin,
                &mut writer,
            )
            .and_then(|()| match audio_origin {
                Some(_) => tokio::task::block_in_place(|| {
                    enc.finish(&mut |packet, duration| writer.push_audio(&packet, duration))
                }),
                None => Ok(()),
            });
            if let Err(e) = written {
                tracing::warn!(%e, "recording: the last audio could not be written");
            }
        }
        for s in a.stop() {
            tracing::info!(
                source = s.name,
                padded_frames = s.padded_frames,
                trimmed_frames = s.trimmed_frames,
                lost = s.lost,
                "recording: audio source summary"
            );
            if s.lost {
                events_log.push(Event {
                    t_ms: start.elapsed().as_millis() as u64,
                    kind: "audio_source_lost".into(),
                    detail: Some(s.name.to_string()),
                });
            }
        }
    }
    if late_ticks > 0 {
        events_log.push(Event {
            t_ms: start.elapsed().as_millis() as u64,
            kind: "late_ticks".into(),
            detail: Some(late_ticks.to_string()),
        });
    }
    let stats = tokio::task::block_in_place(|| writer.finish())
        .context("recording: closing the fragmented file")?;
    tracing::info!(
        reason = reason.as_str(),
        frames,
        bytes = stats.bytes,
        fragments = stats.fragments,
        "recording: stopped — finalizing"
    );
    let finalized = tokio::task::block_in_place(|| finalize_into_place(&partial, &dest));
    let (path, fragmented, bytes, duration_ms) = match finalized {
        Ok(s) => (Some(dest.clone()), false, s.bytes, s.duration_ms),
        Err(e) => {
            // Keep what exists: a fragmented MP4 still plays nearly everywhere.
            tracing::warn!(%e, "recording: the remux failed — keeping the fragmented file");
            match std::fs::rename(&partial, &dest) {
                Ok(()) => (
                    Some(dest.clone()),
                    true,
                    stats.bytes,
                    stats.video_ticks * 1000 / u64::from(mp4::VIDEO_TIMESCALE),
                ),
                Err(e2) => {
                    tracing::error!(%e2, "recording: could not even keep the fragmented file");
                    (None, true, stats.bytes, 0)
                }
            }
        }
    };
    // The partial is gone, or left for the reconciler to retry.
    drop(partial_lock);

    let sidecar = path.as_ref().map(|p| Sidecar {
        version: SIDECAR_VERSION,
        file: p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        initiator: opts.initiator.clone(),
        started_at: started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ended_at: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        duration_ms,
        width,
        height,
        fps: cadence.fps(),
        codec: "h264".into(),
        encoder: encoder_name.clone(),
        color: ColorInfo::BT601_LIMITED,
        audio: AudioInfo {
            system: audio_system,
            microphone: audio_microphone,
            codec: audio_codec_name.map(str::to_string),
        },
        frames,
        late_ticks,
        events: events_log,
        stop_reason: Some(reason),
        bytes,
        pointer: Some(pointer),
    });
    if let (Some(p), Some(s)) = (&path, &sidecar)
        && let Err(e) = std::fs::write(Sidecar::path_for(p), s.to_json())
    {
        tracing::warn!(%e, "recording: could not write the sidecar");
    }
    let _ = events.send(RecorderEvent::Stopped {
        reason,
        path: path.clone(),
        bytes,
        duration_ms,
        frames,
        fragmented,
    });
    Ok(RecordingSummary {
        reason,
        path,
        sidecar,
    })
}

/// FR-85 P1c — mix the audio up to `until` (48 kHz samples since the clock
/// started) and encode whatever is at or after `origin`, the first written
/// video frame's time. Before the first frame nothing is encoded: the mixed
/// frames wait in `queue`, so audio time zero is video time zero, to the
/// sample (P4).
#[cfg(feature = "audio")]
fn pump_audio(
    a: &mut super::audio::RecordingAudio,
    enc: &mut super::audio_codec::AudioEncoder,
    until: u64,
    queue: &mut std::collections::VecDeque<(u64, Vec<i16>)>,
    origin: Option<u64>,
    writer: &mut FragmentedWriter,
) -> Result<()> {
    a.produce_until(until, &mut |start, pcm| {
        queue.push_back((start, pcm.to_vec()))
    })?;
    let Some(origin) = origin else {
        // No video frame yet. Everything before the first one is dropped
        // anyway; the bound only keeps a recorder whose encoder never answers
        // from holding its whole audio in memory.
        while queue.len() > MAX_AUDIO_BEFORE_VIDEO {
            queue.pop_front();
        }
        return Ok(());
    };
    tokio::task::block_in_place(|| {
        encode_from_origin(queue, origin, enc, &mut |packet, duration| {
            writer.push_audio(&packet, duration)
        })
    })
}

/// FR-85 P4 — hand the encoder every queued frame from the first video
/// frame's time (`origin`, 48 kHz samples on the recorder's clock) on, cut
/// to the sample.
///
/// The encoder's input sample 0 is recording time `origin + delay`: a codec
/// whose decoder puts out a priming delay ahead of its input (AAC) starts
/// that far past the first frame, so what a player decodes at time k is what
/// was heard at time k (`audio_codec` module docs).
#[cfg(feature = "audio")]
fn encode_from_origin(
    queue: &mut std::collections::VecDeque<(u64, Vec<i16>)>,
    origin: u64,
    enc: &mut super::audio_codec::AudioEncoder,
    sink: &mut super::audio_codec::PacketSink<'_>,
) -> Result<()> {
    let first = origin + enc.unsignalled_delay();
    let ch = super::audio::CHANNELS;
    while let Some((start, pcm)) = queue.pop_front() {
        let len = (pcm.len() / ch) as u64;
        if start + len <= first {
            continue;
        }
        let skip = first.saturating_sub(start) as usize * ch;
        enc.push(&pcm[skip..], sink)?;
    }
    Ok(())
}

/// Mixed 20 ms frames kept while no video frame has been written (a minute).
#[cfg(feature = "audio")]
const MAX_AUDIO_BEFORE_VIDEO: usize = 3000;

/// The liveness lock beside a partial, `<name>.partial.lock`: an OS file lock
/// held for as long as a recorder owns the partial, and released by the
/// kernel however that recorder dies.
///
/// ⚠️ Without it the reconciler cannot tell a dead recorder's partial from a
/// live one's — a second recorder in the same folder (a manual `roomlerd
/// record` beside the daemon's) would remux a file under its writer, or,
/// finding no complete fragment yet, DELETE it as unrecoverable.
pub struct PartialLock {
    file: std::fs::File,
    path: PathBuf,
}

impl PartialLock {
    pub fn path_for(partial: &Path) -> PathBuf {
        let mut name = partial
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(".lock");
        partial.with_file_name(name)
    }

    /// Take the lock without waiting: `Ok(None)` = a live recorder holds it.
    pub fn try_take(partial: &Path) -> std::io::Result<Option<PartialLock>> {
        let path = Self::path_for(partial);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(PartialLock { file, path })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }
}

impl Drop for PartialLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Remux `partial` to `dest` and remove the partial on success.
fn finalize_into_place(partial: &Path, dest: &Path) -> Result<mp4::FinalizeSummary> {
    if dest.exists() {
        return Err(anyhow!("{} already exists", dest.display()));
    }
    let s = mp4::finalize(partial, dest)?;
    let _ = std::fs::remove_file(partial);
    Ok(s)
}

/// Finalize every partial a dead recorder left in `staging` (the boot
/// reconciler): remux what is complete, mark it `interrupted`. Returns the
/// finished paths. A partial with nothing recoverable is removed; one whose
/// [`PartialLock`] is held belongs to a live recorder and is left alone.
pub fn reconcile_partials(staging: &Path, dest_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(staging) else {
        return Vec::new();
    };
    let mut done = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        let Some(name) = p
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(PARTIAL_SUFFIX))
            .map(str::to_string)
        else {
            continue;
        };
        // A partial whose lock is held is being written right now — not
        // interrupted. The guard lives to the end of this iteration.
        let _lock = match PartialLock::try_take(&p) {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                tracing::debug!(partial = %p.display(), "recording: a partial another recorder is writing — left alone");
                continue;
            }
            Err(e) => {
                tracing::warn!(%e, partial = %p.display(), "recording: cannot take a partial's lock — left alone");
                continue;
            }
        };
        let dest = dest_dir.join(&name);
        if dest.exists() {
            continue;
        }
        match finalize_into_place(&p, &dest) {
            Ok(s) => {
                let sc = Sidecar {
                    version: SIDECAR_VERSION,
                    file: name.clone(),
                    initiator: Initiator::Local { user: None },
                    started_at: String::new(),
                    ended_at: None,
                    duration_ms: s.duration_ms,
                    width: 0,
                    height: 0,
                    fps: 0,
                    codec: "h264".into(),
                    encoder: String::new(),
                    color: ColorInfo::BT601_LIMITED,
                    audio: AudioInfo::default(),
                    frames: s.video_samples,
                    late_ticks: 0,
                    events: Vec::new(),
                    stop_reason: Some(StopReason::Interrupted),
                    bytes: s.bytes,
                    // Unknown: the recorder that knew is gone.
                    pointer: None,
                };
                // A sidecar the dead recorder never wrote: keep an existing
                // one's facts if there is one, only mark it interrupted.
                let sc_path = Sidecar::path_for(&dest);
                let sc = std::fs::read_to_string(&sc_path)
                    .ok()
                    .and_then(|j| serde_json::from_str::<Sidecar>(&j).ok())
                    .map(|mut old| {
                        old.stop_reason = Some(StopReason::Interrupted);
                        old.duration_ms = s.duration_ms;
                        old.bytes = s.bytes;
                        old
                    })
                    .unwrap_or(sc);
                let _ = std::fs::write(&sc_path, sc.to_json());
                tracing::info!(file = %dest.display(), truncated = s.truncated, "recording: an interrupted recording was finalized");
                done.push(dest);
            }
            Err(e) => {
                tracing::warn!(%e, partial = %p.display(), "recording: an interrupted partial holds nothing recoverable — removing it");
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::EncodedPacket;

    fn pkt(data: &[u8], key: bool) -> EncodedPacket {
        EncodedPacket {
            data: data.to_vec(),
            is_keyframe: key,
            duration_us: 0,
            qp: None,
        }
    }

    #[test]
    fn openh264_layers_merge_into_one_access_unit() {
        let aus = group_access_units(
            "openh264",
            vec![
                pkt(&[0, 0, 0, 1, 0x67], true),
                pkt(&[0, 0, 0, 1, 0x65], true),
            ],
        );
        assert_eq!(aus.len(), 1);
        assert_eq!(aus[0], (vec![0, 0, 0, 1, 0x67, 0, 0, 0, 1, 0x65], true));
    }

    #[test]
    fn other_backends_emit_one_access_unit_per_packet() {
        let aus = group_access_units(
            "h264_nvenc",
            vec![
                pkt(&[0, 0, 0, 1, 0x65], true),
                pkt(&[0, 0, 0, 1, 0x41], false),
            ],
        );
        assert_eq!(aus.len(), 2);
        assert!(aus[0].1 && !aus[1].1);
        assert!(group_access_units("h264_qsv", Vec::new()).is_empty());
    }

    #[test]
    fn odd_frames_are_cropped_to_even_without_a_copy() {
        let f = Frame {
            width: 1367,
            height: 769,
            stride: 1368 * 4,
            pixel_format: crate::capture::PixelFormat::Bgra,
            data: vec![0; 1368 * 4 * 769],
            monotonic_us: 0,
            monitor: 0,
            damage: crate::capture::Damage::Unknown,
            source: None,
        };
        let ptr = f.data.as_ptr();
        let e = even(f);
        assert_eq!((e.width, e.height), (1366, 768));
        assert_eq!(
            e.stride,
            1368 * 4,
            "the stride still describes the source rows"
        );
        assert_eq!(e.data.as_ptr(), ptr);
    }

    #[test]
    fn start_refusals_have_stable_names() {
        assert_eq!(StartRefusal::DiskLow.as_str(), "disk_low");
        assert_eq!(
            serde_json::to_string(&StartRefusal::EncoderUnavailable).unwrap(),
            "\"encoder_unavailable\""
        );
    }

    /// FR-85 P4 — audio time zero is the first video frame, TO THE SAMPLE,
    /// in either codec: a click the mixer made `offset` samples after the
    /// first frame is decoded `offset` samples into the track. AAC's priming
    /// (1024 samples) is exactly what this would miss if the recorder
    /// signalled it instead of paying it.
    #[cfg(feature = "audio")]
    mod alignment {
        use super::*;
        use crate::recording::audio_codec::AudioEncoder;
        use crate::recording::mp4::AudioCodec;
        use std::collections::VecDeque;

        const ORIGIN: u64 = 30_000;
        const CLICK: u64 = 60_000;

        /// Mixed 20 ms frames on the recorder's clock, silent but for a 1 ms
        /// click at clock sample `CLICK`.
        fn mixed() -> VecDeque<(u64, Vec<i16>)> {
            (0..100u64)
                .map(|k| {
                    let start = k * 960;
                    let pcm = (start..start + 960)
                        .flat_map(|s| {
                            let v = if (CLICK..CLICK + 48).contains(&s) {
                                20_000
                            } else {
                                0
                            };
                            [v, v]
                        })
                        .collect();
                    (start, pcm)
                })
                .collect()
        }

        fn decode(codec: &AudioCodec, packets: &[Vec<u8>]) -> Vec<i16> {
            let mut pcm = Vec::new();
            match codec {
                AudioCodec::Opus { pre_skip } => {
                    let mut dec = audiopus::coder::Decoder::new(
                        audiopus::SampleRate::Hz48000,
                        audiopus::Channels::Stereo,
                    )
                    .unwrap();
                    let mut out = vec![0i16; 5760 * 2];
                    for p in packets {
                        let packet: audiopus::packet::Packet<'_> = (&p[..]).try_into().unwrap();
                        let signals: audiopus::MutSignals<'_, i16> =
                            (&mut out[..]).try_into().unwrap();
                        let n = dec.decode(Some(packet), signals, false).unwrap();
                        pcm.extend_from_slice(&out[..n * 2]);
                    }
                    pcm.split_off(usize::from(*pre_skip) * 2)
                }
                AudioCodec::Aac { asc, .. } => {
                    use symphonia::core::audio::SampleBuffer;
                    use symphonia::core::codecs::{
                        CODEC_TYPE_AAC, CodecParameters, DecoderOptions,
                    };
                    let mut params = CodecParameters::new();
                    params
                        .for_codec(CODEC_TYPE_AAC)
                        .with_sample_rate(48_000)
                        .with_extra_data(asc.clone().into_boxed_slice());
                    let mut dec = symphonia::default::get_codecs()
                        .make(&params, &DecoderOptions::default())
                        .unwrap();
                    for p in packets {
                        let packet = symphonia::core::formats::Packet::new_from_slice(0, 0, 0, p);
                        let decoded = dec.decode(&packet).unwrap();
                        let spec = *decoded.spec();
                        let mut buf = SampleBuffer::<i16>::new(decoded.capacity() as u64, spec);
                        buf.copy_interleaved_ref(decoded);
                        pcm.extend_from_slice(buf.samples());
                    }
                    pcm
                }
            }
        }

        /// Where the click is in the decoded track (the first loud sample).
        fn click_in_track(mut enc: AudioEncoder) -> usize {
            let codec = enc.track_codec();
            let mut packets = Vec::new();
            let mut queue = mixed();
            encode_from_origin(&mut queue, ORIGIN, &mut enc, &mut |p, _| {
                packets.push(p);
                Ok(())
            })
            .unwrap();
            enc.finish(&mut |p, _| {
                packets.push(p);
                Ok(())
            })
            .unwrap();
            let pcm = decode(&codec, &packets);
            pcm.iter()
                .step_by(2)
                .position(|s| s.unsigned_abs() > 5_000)
                .expect("the click survives the codec")
        }

        fn assert_on_time(at: usize, codec: &str) {
            let want = (CLICK - ORIGIN) as usize;
            assert!(
                at.abs_diff(want) <= 64,
                "{codec}: the click is at track sample {at}, it was {want} samples after the first frame"
            );
        }

        #[test]
        fn opus_audio_starts_at_the_first_video_frame_to_the_sample() {
            assert_on_time(click_in_track(AudioEncoder::opus().unwrap()), "opus");
        }

        #[cfg(feature = "ffmpeg-encoder")]
        #[test]
        fn aac_audio_starts_at_the_first_video_frame_despite_its_priming() {
            let enc = match AudioEncoder::aac() {
                Ok(e) => e,
                Err(e) => {
                    assert!(
                        !crate::recording::audio_codec::aac_expected(),
                        "ROOMLER_EXPECT_FFMPEG_AAC=1 but AAC did not open: {e:#}"
                    );
                    eprintln!("skipped: this FFmpeg has no AAC encoder ({e:#})");
                    return;
                }
            };
            assert_on_time(click_in_track(enc), "aac");
        }
    }
}
