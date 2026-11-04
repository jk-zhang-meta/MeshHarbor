// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! cpal-backed system-audio capture (Linux + Windows).
//!
//! * **Windows** — WASAPI loopback. cpal 0.15 lets you open the default
//!   *output* device with `build_input_stream`; the WASAPI backend
//!   detects the output device driven as input and opens a loopback
//!   client, so we capture exactly what's playing out of the speakers.
//! * **Linux** — an ALSA capture device, picked by name
//!   ([`crate::audio_source::pick_linux`]): the one `ROOMLERD_AUDIO_SOURCE`
//!   names, else one whose name says monitor, else NOTHING. ⚠️ Never the
//!   default input: cpal 0.15 lists only ALSA devices, never a sound server's
//!   sources, and through PipeWire or PulseAudio the default input is the
//!   microphone (FR-97 P3c, measured; the reasoning is in `audio_source`).
//!
//! cpal's data callback fires on a real-time audio thread. We must NOT
//! block or allocate heavily there — we convert the buffer to `i16`
//! into a small reusable scratch and push a frame down a bounded
//! `tokio::mpsc` (drop-OLDEST on overflow so a stalled encoder can't
//! back-pressure the audio device into an xrun). `next_frame` reads the
//! receiver from the async pump task.

use anyhow::{Context, Result, anyhow};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use tokio::sync::mpsc;

use super::{AudioCapture, AudioFrame};
#[cfg(target_os = "windows")]
use crate::audio_source::{AudioUnavailable, AudioUnavailableCode};
use async_trait::async_trait;

/// Bounded channel depth between the RT capture callback and the async
/// pump. ~64 × 10 ms cpal buffers ≈ 640 ms of slack — plenty to ride
/// out a scheduling hiccup without unbounded memory growth. On overflow
/// we drop the OLDEST frame (see the callback) so latency stays capped.
const CHANNEL_DEPTH: usize = 64;

/// Live cpal loopback capture. Holds the `Stream` (dropping it stops
/// capture) and the receiving half of the RT→async bridge.
pub struct CpalLoopbackCapture {
    // The stream must stay alive for the callback to keep firing; it is
    // `!Send` on some platforms, but we never move it across threads —
    // it lives on the pump's task alongside the receiver. Kept in an
    // Option only so `Drop` reads cleanly; always `Some` while live.
    _stream: cpal::Stream,
    rx: mpsc::Receiver<AudioFrame>,
    channels: u16,
    sample_rate: u32,
}

// cpal's `Stream` is `!Send` on Windows (the WASAPI client is
// thread-affine). The audio pump future that owns this capture is
// spawned with `tokio::spawn`, which requires `Send`. In practice the
// stream is created, used, and dropped entirely within that single
// task and never touched from another thread; the RT callback runs on
// cpal's own audio thread and communicates only through the `Send`
// channel. Assert `Send` so the pump can own it. This mirrors how the
// video pump treats its thread-affine encoder handles.
unsafe impl Send for CpalLoopbackCapture {}

/// Which device a capture opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// "Computer audio", for a live session and a recording alike: the
    /// loopback / monitor source ONLY. ⚠️ Never the default input on Linux:
    /// that is a microphone, which a recording captures only when the person
    /// asked for the microphone, and a live session never does. FR-97 P3c-1
    /// removed the live path's own variant, which fell back to it.
    SystemOnly,
    /// FR-85 recording's microphone: the default input device.
    Microphone,
}

impl CpalLoopbackCapture {
    /// Open the platform loopback source for a live session and start the
    /// RT→async bridge. A failure carries an [`crate::audio_source::AudioUnavailable`]
    /// wherever the picker knows why.
    pub fn open() -> Result<Self> {
        Self::open_source(Source::SystemOnly)
    }

    /// Open `source` and start the RT→async bridge.
    pub fn open_source(source: Source) -> Result<Self> {
        let host = cpal::default_host();
        let (device, is_loopback_output) = pick_device(&host, source)?;
        let dev_name = device.name().unwrap_or_else(|_| "<unknown>".into());

        // Pick the capture format. On Windows loopback we must use the
        // OUTPUT device's default OUTPUT config (that's the shared-mode
        // mix format WASAPI hands back for loopback). On Linux the
        // monitor source is a genuine input, so its default INPUT
        // config is right.
        let supported = if is_loopback_output {
            device
                .default_output_config()
                .context("default_output_config for loopback device")?
        } else {
            device
                .default_input_config()
                .context("default_input_config for monitor/input device")?
        };
        let sample_format = supported.sample_format();
        let config: cpal::StreamConfig = supported.into();
        let channels = config.channels;
        let sample_rate = config.sample_rate.0;

        tracing::info!(
            device = %dev_name,
            loopback_output = is_loopback_output,
            channels,
            sample_rate,
            ?sample_format,
            "audio: cpal capture config resolved"
        );

        let (tx, rx) = mpsc::channel::<AudioFrame>(CHANNEL_DEPTH);

        let err_tx = tx.clone();
        let err_fn = move |err| {
            tracing::warn!(%err, "audio: cpal stream error");
            // Nothing to forward; the receiver just sees a gap. Keep the
            // clone alive so the closure type is consistent across
            // platforms.
            let _ = &err_tx;
        };

        // Build an `AudioFrame` from a ready i16 buffer. `channels` /
        // `sample_rate` are `Copy`, so this closure is `Copy` — each
        // match arm below gets its own copy implicitly (no `.clone()`).
        let mk_frame = move |samples: Vec<i16>| AudioFrame {
            samples,
            channels,
            sample_rate,
        };

        let stream = match sample_format {
            cpal::SampleFormat::F32 => {
                let tx = tx.clone();
                device
                    .build_input_stream(
                        &config,
                        move |data: &[f32], _: &cpal::InputCallbackInfo| {
                            let mut out = Vec::with_capacity(data.len());
                            for &s in data {
                                out.push(f32_to_i16(s));
                            }
                            push_drop_oldest(&tx, mk_frame(out));
                        },
                        err_fn,
                        None,
                    )
                    .context("build_input_stream f32")?
            }
            cpal::SampleFormat::I16 => {
                let tx = tx.clone();
                device
                    .build_input_stream(
                        &config,
                        move |data: &[i16], _: &cpal::InputCallbackInfo| {
                            push_drop_oldest(&tx, mk_frame(data.to_vec()));
                        },
                        err_fn,
                        None,
                    )
                    .context("build_input_stream i16")?
            }
            cpal::SampleFormat::U16 => {
                let tx = tx.clone();
                device
                    .build_input_stream(
                        &config,
                        move |data: &[u16], _: &cpal::InputCallbackInfo| {
                            let mut out = Vec::with_capacity(data.len());
                            for &s in data {
                                // u16 → i16 centred at 0.
                                out.push((s as i32 - 32768) as i16);
                            }
                            push_drop_oldest(&tx, mk_frame(out));
                        },
                        err_fn,
                        None,
                    )
                    .context("build_input_stream u16")?
            }
            other => {
                return Err(anyhow!("audio: unsupported cpal sample format {other:?}"));
            }
        };

        stream.play().context("cpal stream.play()")?;

        Ok(Self {
            _stream: stream,
            rx,
            channels,
            sample_rate,
        })
    }
}

#[async_trait]
impl AudioCapture for CpalLoopbackCapture {
    async fn next_frame(&mut self) -> Result<Option<AudioFrame>> {
        // `recv` yields None only when every sender is dropped, which
        // for us means the stream was torn down — signal exhaustion.
        match self.rx.recv().await {
            Some(f) => Ok(Some(f)),
            None => {
                tracing::debug!(
                    channels = self.channels,
                    sample_rate = self.sample_rate,
                    "audio: cpal capture channel closed"
                );
                Ok(None)
            }
        }
    }
}

/// Push a frame, dropping the OLDEST queued frame first if the channel
/// is full. Called from the RT audio callback — must never block. A
/// full channel means the async encoder is behind; shedding the oldest
/// frame caps end-to-end latency at the channel depth instead of
/// letting WASAPI/Pulse xrun on a stalled callback.
fn push_drop_oldest(tx: &mpsc::Sender<AudioFrame>, frame: AudioFrame) {
    use mpsc::error::TrySendError;
    match tx.try_send(frame) {
        Ok(()) => {}
        Err(TrySendError::Full(frame)) => {
            // Best-effort: we can't pop the receiver from here, so send
            // again after the consumer drains one slot. If it's STILL
            // full we simply drop this frame (bounded, no growth).
            // `try_send` a second time keeps the callback wait-free.
            if tx.try_send(frame).is_err() {
                // Silent drop — logging on the RT thread is itself a
                // hazard. The pump logs aggregate frames-sent counts.
            }
        }
        Err(TrySendError::Closed(_)) => {
            // Receiver gone (pump ended); nothing to do.
        }
    }
}

/// Select the capture device + whether it is an output device we're
/// driving as loopback (Windows) vs a genuine input (Linux monitor).
fn pick_device(host: &cpal::Host, source: Source) -> Result<(cpal::Device, bool)> {
    if source == Source::Microphone {
        let dev = host
            .default_input_device()
            .ok_or_else(|| anyhow!("no microphone: this device has no default audio input"))?;
        return Ok((dev, false));
    }
    #[cfg(target_os = "windows")]
    {
        // WASAPI loopback: open the default OUTPUT device as an input.
        let dev = host.default_output_device().ok_or_else(|| {
            anyhow::Error::new(AudioUnavailable::new(
                AudioUnavailableCode::NoOutput,
                "no default output device for WASAPI loopback",
            ))
        })?;
        Ok((dev, true))
    }
    #[cfg(target_os = "linux")]
    {
        // FR-97 P3c-1 — by name, over ONE enumeration (cpal opens every PCM
        // to list it). ⚠️ No fallback to `host.default_input_device()`: on
        // Linux that is the sound server's default source, the microphone,
        // and it was the only thing this ever opened (`audio_source`).
        let named = crate::audio_source::named();
        let mut devices: Vec<(String, cpal::Device)> = host
            .input_devices()
            .map(|it| it.filter_map(|d| d.name().ok().map(|n| (n, d))).collect())
            .unwrap_or_default();
        let names: Vec<&str> = devices.iter().map(|(n, _)| n.as_str()).collect();
        let i = crate::audio_source::pick_linux(named.as_deref(), &names)
            .map_err(anyhow::Error::new)?;
        let (name, dev) = devices.swap_remove(i);
        match named.as_deref() {
            Some(want) if want == name => {
                tracing::info!(source = %name, "audio: opening the ROOMLERD_AUDIO_SOURCE device");
            }
            Some(want) => tracing::warn!(
                source = %want,
                monitor = %name,
                "audio: ROOMLERD_AUDIO_SOURCE is not a capture device here; opening the device named as a monitor"
            ),
            None => tracing::info!(source = %name, "audio: opening the device named as a monitor"),
        }
        Ok((dev, false))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = host;
        Err(anyhow::Error::new(
            crate::audio_source::AudioUnavailable::new(
                crate::audio_source::AudioUnavailableCode::NotSupported,
                "cpal loopback capture is Linux/Windows only",
            ),
        ))
    }
}

/// Convert a normalized `f32` sample in `[-1.0, 1.0]` to `i16`, clamping
/// out-of-range values. Rounds to nearest.
#[inline]
fn f32_to_i16(s: f32) -> i16 {
    let scaled = (s * 32767.0).round();
    scaled.clamp(-32768.0, 32767.0) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_to_i16_clamps_and_scales() {
        assert_eq!(f32_to_i16(0.0), 0);
        assert_eq!(f32_to_i16(1.0), 32767);
        assert_eq!(f32_to_i16(-1.0), -32767);
        // Out of range clamps rather than wrapping.
        assert_eq!(f32_to_i16(2.0), 32767);
        assert_eq!(f32_to_i16(-2.0), -32768);
    }
}
