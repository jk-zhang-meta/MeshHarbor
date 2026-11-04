// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P1c — a recording's audio: computer audio and/or the microphone,
//! mixed on the RECORDER's clock. The encoder (Opus, or AAC from P4) is
//! [`super::audio_codec`]'s, fed by the recorder once its video has begun.
//!
//! **The clock is the recorder's, not the devices'.** WASAPI loopback
//! delivers nothing while nothing plays, and every device clock drifts from
//! the system clock. An audio track timed by what the devices delivered
//! would collapse during silence and walk away from the video. So the mixer
//! PULLS: every 20 ms of recording time it takes one frame from each source's
//! buffer (silence for whatever is missing), and audio time is video time by
//! construction.
//!
//! **A fixed lag absorbs delivery jitter.** Devices hand audio over in ~10 ms
//! bursts; a mixer level with the clock would pad silence into every frame.
//! It runs [`MIX_LAG`] behind and each source keeps about that much buffered,
//! so frame k still holds what was captured around k × 20 ms.
//!
//! **Drift is corrected by rate, not by cutting.** Each source goes through a
//! streaming linear resampler whose ratio is nudged (±0.5 % at most) by how
//! far its buffer is from [`MIX_LAG`]. Padding and trimming alone would click:
//! a device clock 0.1 % slow empties the buffer, and from then on every frame
//! pads a sample of silence. The hard trim remains only for a backlog (the
//! capture's pre-roll at start).
//!
//! ⚠️ Never a microphone the person did not ask for: computer audio opens the
//! loopback / monitor source ONLY (`cpal_backend::Source::SystemOnly`).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use audiopus::coder::Encoder as OpusCoder;
use audiopus::{Application, Bitrate, Channels, SampleRate};

use crate::audio::{AudioCapture, AudioFrame};

/// The recording's audio rate — the only rate its tracks carry.
pub const RATE: u32 = 48_000;
/// Stereo.
pub const CHANNELS: usize = 2;
/// One mixer frame (and one Opus packet): 20 ms at 48 kHz, per channel.
pub const FRAME: usize = 960;
/// How far behind the recording clock the mixer runs (see the module doc).
pub const MIX_LAG: Duration = Duration::from_millis(60);
/// A buffer deeper than this is cut back to [`MIX_LAG`] — a backlog, not
/// drift (drift never builds this far under the rate correction).
const MAX_DEPTH: Duration = Duration::from_millis(250);
/// The most the rate correction bends a source (0.5 %): far beyond any real
/// device clock error, far below anything audible.
const MAX_RATE_ADJUST: f64 = 0.005;
/// Proportional gain of the rate correction, per unit of relative depth error.
const RATE_GAIN: f64 = 0.01;
/// Recording bitrate — transparent for screen audio and speech.
const BITRATE_BPS: i32 = 128_000;

/// Samples (per channel) of `d` at [`RATE`].
pub fn samples_for(d: Duration) -> u64 {
    (d.as_micros() * u128::from(RATE) / 1_000_000) as u64
}

/// The sources a recording was asked for.
#[derive(Default)]
pub struct AudioSources {
    pub system: Option<Box<dyn AudioCapture>>,
    pub microphone: Option<Box<dyn AudioCapture>>,
}

impl AudioSources {
    pub fn is_empty(&self) -> bool {
        self.system.is_none() && self.microphone.is_none()
    }
}

/// Streaming linear-interpolation resampler + channel mapping, any rate and
/// channel count in, 48 kHz stereo out, with a rate trim for drift.
///
/// Linear, not the live path's nearest-neighbour: a 44.1 kHz laptop
/// microphone is common, and nearest-neighbour aliases audibly on speech.
pub(crate) struct Resampler {
    in_rate: u32,
    /// The last input frame of the previous buffer (`s[-1]`).
    prev: [f32; 2],
    /// Position of the next output frame, in input frames, measured from
    /// `prev` (0.0 = exactly `prev`).
    t: f64,
    primed: bool,
}

impl Resampler {
    pub(crate) fn new(in_rate: u32) -> Self {
        Self {
            in_rate: in_rate.max(1),
            prev: [0.0; 2],
            t: 0.0,
            primed: false,
        }
    }

    /// Resample `f` into `out` (interleaved stereo). `adjust` bends the rate:
    /// positive consumes input faster (fewer output frames per input frame).
    pub(crate) fn push(&mut self, f: &AudioFrame, adjust: f64, out: &mut VecDeque<i16>) {
        let ch = usize::from(f.channels.max(1));
        let n = f.samples.len() / ch;
        if n == 0 {
            return;
        }
        let frame = |i: usize| -> [f32; 2] {
            let l = f32::from(f.samples[i * ch]);
            let r = if ch >= 2 {
                f32::from(f.samples[i * ch + 1])
            } else {
                l
            };
            [l, r]
        };
        if !self.primed {
            self.prev = frame(0);
            // The first output frame is exactly the first input frame.
            self.t = 1.0;
            self.primed = true;
        }
        let step = f64::from(self.in_rate) / f64::from(RATE) * (1.0 + adjust);
        // s[-1] = prev, s[0..n) = this buffer; an output frame at position t
        // (from s[-1]) interpolates s[floor(t) - 1] and s[floor(t)].
        while (self.t.floor() as usize) < n {
            let whole = self.t.floor() as usize;
            let frac = (self.t - self.t.floor()) as f32;
            let a = if whole == 0 {
                self.prev
            } else {
                frame(whole - 1)
            };
            let b = frame(whole);
            for c in 0..CHANNELS {
                let v = a[c] + (b[c] - a[c]) * frac;
                out.push_back(v.round().clamp(-32768.0, 32767.0) as i16);
            }
            self.t += step;
        }
        self.prev = frame(n - 1);
        self.t -= n as f64;
    }
}

/// One source's audio, normalized, waiting to be mixed.
struct SourceBuffer {
    name: &'static str,
    /// Interleaved 48 kHz stereo.
    q: VecDeque<i16>,
    resampler: Option<Resampler>,
    /// Frames cut by the backlog trim.
    trimmed: u64,
    /// Frames padded with silence because the source had nothing.
    padded: u64,
    /// The source ended or failed; silence from here.
    lost: bool,
}

impl SourceBuffer {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            q: VecDeque::new(),
            resampler: None,
            trimmed: 0,
            padded: 0,
            lost: false,
        }
    }

    fn depth_frames(&self) -> u64 {
        (self.q.len() / CHANNELS) as u64
    }

    fn push(&mut self, f: &AudioFrame) {
        let target = samples_for(MIX_LAG) as f64;
        let error = (self.depth_frames() as f64 - target) / target;
        let adjust = (error * RATE_GAIN).clamp(-MAX_RATE_ADJUST, MAX_RATE_ADJUST);
        let rs = match &mut self.resampler {
            Some(r) if r.in_rate == f.sample_rate.max(1) => r,
            slot => slot.insert(Resampler::new(f.sample_rate)),
        };
        rs.push(f, adjust, &mut self.q);
        let max = samples_for(MAX_DEPTH) as usize * CHANNELS;
        if self.q.len() > max {
            let keep = samples_for(MIX_LAG) as usize * CHANNELS;
            let cut = self.q.len() - keep;
            self.q.drain(..cut);
            self.trimmed += (cut / CHANNELS) as u64;
        }
    }

    /// Add one frame's worth into `acc`; silence for whatever is missing.
    fn take_into(&mut self, acc: &mut [i32]) {
        let n = acc.len().min(self.q.len());
        for (a, s) in acc.iter_mut().zip(self.q.drain(..n)) {
            *a += i32::from(s);
        }
        if n < acc.len() {
            self.padded += ((acc.len() - n) / CHANNELS) as u64;
        }
    }
}

/// Sum without wrapping: linear up to 3/4 of full scale, then a tanh knee
/// that approaches full scale (reaching it only far past it, where `tanh`
/// saturates). Two loud sources together clip softly instead of wrapping
/// into a crack.
pub fn soft_clip(x: i32) -> i16 {
    const KNEE: f32 = 24_576.0;
    const TOP: f32 = 32_767.0;
    let v = x as f32;
    let a = v.abs();
    if a <= KNEE {
        return v as i16;
    }
    let range = TOP - KNEE;
    let y = KNEE + range * ((a - KNEE) / range).tanh();
    y.copysign(v).round().clamp(-TOP, TOP) as i16
}

/// Pulls 20 ms frames from every source on the recording clock and mixes
/// them.
pub struct Mixer {
    sources: Vec<Arc<Mutex<SourceBuffer>>>,
    /// Frames (per channel) produced so far — the audio clock.
    produced: u64,
    acc: Vec<i32>,
    frame: Vec<i16>,
}

impl Mixer {
    fn new(sources: Vec<Arc<Mutex<SourceBuffer>>>) -> Self {
        Self {
            sources,
            produced: 0,
            acc: vec![0; FRAME * CHANNELS],
            frame: vec![0; FRAME * CHANNELS],
        }
    }

    /// Mix every whole frame that ends at or before `until` (frames per
    /// channel since the recording's clock started), handing each to `emit`
    /// with its start.
    fn mix_until(
        &mut self,
        until: u64,
        mut emit: impl FnMut(u64, &[i16]) -> Result<()>,
    ) -> Result<()> {
        while self.produced + FRAME as u64 <= until {
            self.acc.fill(0);
            for s in &self.sources {
                if let Ok(mut b) = s.lock() {
                    b.take_into(&mut self.acc);
                }
            }
            for (o, a) in self.frame.iter_mut().zip(&self.acc) {
                *o = soft_clip(*a);
            }
            emit(self.produced, &self.frame)?;
            self.produced += FRAME as u64;
        }
        Ok(())
    }
}

/// Opus for a recording: 48 kHz stereo, 20 ms frames, 128 kb/s, full
/// complexity. Its own encoder — the live path's stays untouched.
pub(crate) struct RecordingOpus {
    enc: OpusCoder,
    out: Vec<u8>,
    pub(crate) pre_skip: u16,
}

impl RecordingOpus {
    pub(crate) fn new() -> Result<Self> {
        let mut enc = OpusCoder::new(SampleRate::Hz48000, Channels::Stereo, Application::Audio)
            .context("recording: create the Opus encoder")?;
        enc.set_bitrate(Bitrate::BitsPerSecond(BITRATE_BPS))
            .context("recording: set the Opus bitrate")?;
        enc.set_complexity(10)
            .context("recording: set the Opus complexity")?;
        // What a decoder must discard at the start, written into `dOps`.
        let pre_skip = enc.lookahead().unwrap_or(312).min(u32::from(u16::MAX)) as u16;
        Ok(Self {
            enc,
            out: vec![0; 4000],
            pre_skip,
        })
    }

    pub(crate) fn encode(&mut self, frame: &[i16]) -> Result<Vec<u8>> {
        let n = self
            .enc
            .encode(frame, &mut self.out)
            .context("recording: Opus encode")?;
        Ok(self.out[..n].to_vec())
    }
}

/// What the audio did over a recording, for the sidecar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceStats {
    pub name: &'static str,
    /// Frames of silence padded because the source had nothing (a quiet
    /// WASAPI loopback, a stall).
    pub padded_frames: u64,
    /// Frames cut by the backlog trim.
    pub trimmed_frames: u64,
    /// The source ended or failed during the recording.
    pub lost: bool,
}

/// A recording's audio, running: a task per source feeding its buffer, and
/// the mixer driven by the recorder's loop.
pub struct RecordingAudio {
    mixer: Mixer,
    buffers: Vec<Arc<Mutex<SourceBuffer>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    pub system: bool,
    pub microphone: bool,
}

impl RecordingAudio {
    /// Start pulling every source. Their pre-roll (whatever the devices
    /// buffered before the clock started) is cut by the backlog trim.
    pub fn start(sources: AudioSources) -> Result<Self> {
        let system = sources.system.is_some();
        let microphone = sources.microphone.is_some();
        let mut buffers = Vec::new();
        let mut tasks = Vec::new();
        for (name, cap) in [
            ("system", sources.system),
            ("microphone", sources.microphone),
        ] {
            let Some(mut cap) = cap else { continue };
            let buf = Arc::new(Mutex::new(SourceBuffer::new(name)));
            let b = buf.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match cap.next_frame().await {
                        Ok(Some(f)) => {
                            if let Ok(mut g) = b.lock() {
                                g.push(&f);
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::warn!(source = name, %e, "recording: an audio source failed — silence from here");
                            break;
                        }
                    }
                }
                if let Ok(mut g) = b.lock() {
                    g.lost = true;
                }
            }));
            buffers.push(buf);
        }
        Ok(Self {
            mixer: Mixer::new(buffers.clone()),
            buffers,
            tasks,
            system,
            microphone,
        })
    }

    /// Mix every frame that ends at or before `until` (frames per channel
    /// since the clock started), handing `(frame start, interleaved stereo)`
    /// to `sink`.
    pub fn produce_until(&mut self, until: u64, sink: &mut dyn FnMut(u64, &[i16])) -> Result<()> {
        self.mixer.mix_until(until, |start, frame| {
            sink(start, frame);
            Ok(())
        })
    }

    /// Stop every source and say how each behaved.
    pub fn stop(mut self) -> Vec<SourceStats> {
        for t in self.tasks.drain(..) {
            t.abort();
        }
        self.buffers
            .iter()
            .filter_map(|b| b.lock().ok())
            .map(|b| SourceStats {
                name: b.name,
                padded_frames: b.padded,
                trimmed_frames: b.trimmed,
                lost: b.lost,
            })
            .collect()
    }
}

impl Drop for RecordingAudio {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

// ── a synthetic source, for tests and `ROOMLERD_SYNTHETIC_AUDIO` ─────────────

/// A sine wave at `hz`, delivered in real time in 10 ms buffers of
/// `sample_rate` / `channels` — the shape a real device has, including a rate
/// that is not 48 kHz. `ROOMLERD_SYNTHETIC_AUDIO=1` makes `roomlerd record`
/// use it for computer audio (builds with `synthetic-frame-source` only).
pub struct SineCapture {
    hz: f32,
    sample_rate: u32,
    channels: u16,
    amplitude: f32,
    phase: f64,
    started: Option<tokio::time::Instant>,
    delivered: u64,
}

impl SineCapture {
    pub fn new(hz: f32, sample_rate: u32, channels: u16, amplitude: f32) -> Self {
        Self {
            hz,
            sample_rate,
            channels: channels.max(1),
            amplitude,
            phase: 0.0,
            started: None,
            delivered: 0,
        }
    }
}

#[async_trait::async_trait]
impl AudioCapture for SineCapture {
    async fn next_frame(&mut self) -> Result<Option<AudioFrame>> {
        let started = *self.started.get_or_insert_with(tokio::time::Instant::now);
        let n = (self.sample_rate / 100) as u64; // 10 ms
        // Deliver on the wall clock, like a device.
        let due = started
            + Duration::from_micros(self.delivered * 1_000_000 / u64::from(self.sample_rate));
        tokio::time::sleep_until(due).await;
        let mut samples = Vec::with_capacity(n as usize * usize::from(self.channels));
        let inc = f64::from(self.hz) * std::f64::consts::TAU / f64::from(self.sample_rate);
        for _ in 0..n {
            let v = (self.phase.sin() as f32 * self.amplitude) as i16;
            for _ in 0..self.channels {
                samples.push(v);
            }
            self.phase = (self.phase + inc) % std::f64::consts::TAU;
        }
        self.delivered += n;
        Ok(Some(AudioFrame {
            samples,
            channels: self.channels,
            sample_rate: self.sample_rate,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(samples: Vec<i16>, channels: u16, sample_rate: u32) -> AudioFrame {
        AudioFrame {
            samples,
            channels,
            sample_rate,
        }
    }

    /// An interpolator holds its last input frame until the next buffer
    /// arrives (it needs both neighbours), so the pass-through is exact with
    /// one frame of latency.
    #[test]
    fn a_48k_stereo_buffer_passes_through_unchanged() {
        let mut r = Resampler::new(48_000);
        let input: Vec<i16> = (0..960 * 2).map(|i| (i % 1000) as i16).collect();
        let mut out = VecDeque::new();
        r.push(&frame(input.clone(), 2, 48_000), 0.0, &mut out);
        assert_eq!(out.len(), input.len() - 2, "one frame held back");
        r.push(&frame(vec![0; 2], 2, 48_000), 0.0, &mut out);
        assert_eq!(out.iter().copied().collect::<Vec<_>>(), input);
    }

    #[test]
    fn mono_is_duplicated_to_both_channels() {
        let mut r = Resampler::new(48_000);
        let mut out = VecDeque::new();
        r.push(&frame(vec![100, -200, 300], 1, 48_000), 0.0, &mut out);
        r.push(&frame(vec![0], 1, 48_000), 0.0, &mut out);
        assert_eq!(
            out.iter().copied().collect::<Vec<_>>(),
            vec![100, 100, -200, -200, 300, 300]
        );
    }

    /// 44.1 kHz in, 48 kHz out: the count follows the ratio across buffer
    /// boundaries, and a sine keeps its frequency (zero crossings).
    #[test]
    fn a_44k1_sine_resamples_to_48k_at_the_same_pitch() {
        let mut sine = 0.0f64;
        let inc = 440.0 * std::f64::consts::TAU / 44_100.0;
        let mut r = Resampler::new(44_100);
        let mut out = VecDeque::new();
        for _ in 0..100 {
            // 100 × 10 ms = 1 s
            let buf: Vec<i16> = (0..441)
                .map(|_| {
                    let v = (sine.sin() * 16_000.0) as i16;
                    sine += inc;
                    v
                })
                .collect();
            r.push(&frame(buf, 1, 44_100), 0.0, &mut out);
        }
        let frames = out.len() / 2;
        assert!(
            (47_990..=48_010).contains(&frames),
            "{frames} frames for 1 s"
        );
        let left: Vec<i16> = out.iter().step_by(2).copied().collect();
        let crossings = left.windows(2).filter(|w| (w[0] < 0) != (w[1] < 0)).count();
        // 440 Hz = 880 crossings per second.
        assert!((870..=890).contains(&crossings), "{crossings} crossings");
    }

    #[test]
    fn a_positive_adjust_consumes_faster() {
        let input: Vec<i16> = vec![0; 48_000 * 2];
        let mut plain = VecDeque::new();
        Resampler::new(48_000).push(&frame(input.clone(), 2, 48_000), 0.0, &mut plain);
        let mut fast = VecDeque::new();
        Resampler::new(48_000).push(&frame(input, 2, 48_000), MAX_RATE_ADJUST, &mut fast);
        let (p, f) = (plain.len() / 2, fast.len() / 2);
        assert!(f < p && p - f > 200, "{p} vs {f}");
    }

    #[test]
    fn soft_clip_is_linear_below_the_knee_and_never_wraps() {
        for x in [0, 1, -1, 1000, -24_000, 24_576] {
            assert_eq!(i32::from(soft_clip(x)), x);
        }
        let mut last = soft_clip(24_576);
        for x in (24_577..=70_000).step_by(97) {
            let y = soft_clip(x);
            assert!(y >= last, "monotonic at {x}");
            assert!(y >= 24_576, "never wraps at {x}");
            last = y;
        }
        // A moderate overload is compressed, not flattened to full scale…
        assert!(soft_clip(40_000) < 32_700, "{}", soft_clip(40_000));
        // …and far past it the output settles AT full scale, never beyond.
        assert_eq!(soft_clip(1_000_000), i16::MAX);
        assert_eq!(soft_clip(-70_000), -soft_clip(70_000));
    }

    #[test]
    fn a_silent_source_still_yields_a_continuous_track() {
        // The WASAPI-loopback-while-nothing-plays case: the mixer produces
        // exactly one frame per 20 ms of clock, all silence.
        let buf = Arc::new(Mutex::new(SourceBuffer::new("system")));
        let mut m = Mixer::new(vec![buf.clone()]);
        let mut starts = Vec::new();
        m.mix_until(samples_for(Duration::from_secs(1)), |s, f| {
            assert!(f.iter().all(|&v| v == 0));
            starts.push(s);
            Ok(())
        })
        .unwrap();
        assert_eq!(starts.len(), 50);
        assert_eq!(starts[1] - starts[0], FRAME as u64);
        assert_eq!(buf.lock().unwrap().padded, 50 * FRAME as u64);
    }

    #[test]
    fn two_sources_are_summed() {
        let a = Arc::new(Mutex::new(SourceBuffer::new("system")));
        let b = Arc::new(Mutex::new(SourceBuffer::new("microphone")));
        // More than one frame in: the resampler holds its last input frame
        // back, and the rate trim may bend the count either way.
        a.lock()
            .unwrap()
            .push(&frame(vec![1000; 1000 * 2], 2, 48_000));
        b.lock()
            .unwrap()
            .push(&frame(vec![500; 1000 * 2], 2, 48_000));
        let mut m = Mixer::new(vec![a, b]);
        let mut got = Vec::new();
        m.mix_until(FRAME as u64, |_, f| {
            got.extend_from_slice(f);
            Ok(())
        })
        .unwrap();
        assert!(got.iter().all(|&v| v == 1500), "{:?}", &got[..4]);
    }

    #[test]
    fn a_backlog_is_cut_back_to_the_lag_keeping_the_newest() {
        let mut b = SourceBuffer::new("system");
        // 400 ms arrives at once (a device's pre-roll): the newest 60 ms stay
        // (the last 100 ms of input are 7s, a margin for the interpolator's
        // held-back frame and the rate trim).
        let mut samples = vec![0i16; 48 * 300 * 2];
        samples.extend(std::iter::repeat_n(7i16, 48 * 100 * 2));
        b.push(&frame(samples, 2, 48_000));
        assert_eq!(b.depth_frames(), samples_for(MIX_LAG));
        assert!(b.q.iter().all(|&v| v == 7), "the newest samples are kept");
        assert!(b.trimmed > 0);
    }

    /// A device 0.3 % fast, delivering 10 ms buffers against a mixer that
    /// pulls on the clock. WITHOUT the correction its buffer grows ~1.4 ms a
    /// second and is cut (an audible skip) within ~2 minutes; with it, the
    /// depth settles near the lag and nothing is ever cut. Five simulated
    /// minutes, so the uncorrected case cannot pass (red with
    /// `RATE_GAIN = 0`).
    #[test]
    fn the_rate_correction_holds_a_fast_source_near_the_lag() {
        let buf = Arc::new(Mutex::new(SourceBuffer::new("microphone")));
        let mut m = Mixer::new(vec![buf.clone()]);
        let mut clock = samples_for(MIX_LAG) + FRAME as u64; // start with the lag filled
        buf.lock()
            .unwrap()
            .push(&frame(vec![1; clock as usize * 2], 2, 48_000));
        // 48 000 × 1.003 / 100 = 481.44 frames per 10 ms, delivered exactly.
        let mut delivered = 0u64;
        for i in 0..30_000u64 {
            // 30 000 × 10 ms = 5 min
            let due = (i + 1) * 48_144 / 100;
            let n = (due - delivered) as usize;
            delivered = due;
            buf.lock().unwrap().push(&frame(vec![1; n * 2], 2, 48_000));
            clock += 480;
            m.mix_until(clock - samples_for(MIX_LAG), |_, _| Ok(()))
                .unwrap();
        }
        let b = buf.lock().unwrap();
        assert_eq!(b.trimmed, 0, "no backlog cut: the rate held it");
        let depth = b.depth_frames();
        assert!(
            depth < samples_for(MIX_LAG) * 2,
            "depth {depth} settles near the lag"
        );
    }
}
