// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Desktop / system audio capture → Opus for the WebRTC audio track.
//!
//! Opt-in per session (`ServerMsg::Request.audio_enabled`, threaded from
//! the controller's `rc:session.request`). When enabled AND the agent was
//! built with the `audio` Cargo feature, `peer.rs` adds a second
//! sendonly WebRTC track (audio/opus, PT 111) and spawns `audio_pump`,
//! which drives [`AudioCapture`] → [`opus_encode::OpusEncoder`] → 20 ms
//! Opus packets → `TrackLocalStaticSample::write_sample`.
//!
//! Capture backend ([`open_default`]):
//!   * **Linux** — the default output's monitor through Pulse's client
//!     library ([`pulse`], FR-97 P3c-2): in this process for a per-user
//!     daemon, through the seat user's helper for a root one. A device the
//!     host's owner names in `ROOMLERD_AUDIO_SOURCE` wins, through cpal.
//!     ⚠️ Never the default input, which is the microphone
//!     ([`crate::audio_source::linux_route`]).
//!   * **Windows** — WASAPI loopback: cpal opens the default OUTPUT
//!     device with `build_input_stream` (cpal 0.15 special-cases an
//!     output device driven as an input into a loopback capture).
//!   * **macOS / everything else** — none (ScreenCaptureKit system audio
//!     is FR-97 P2a). The hello offers no track there, so no session asks.
//!
//! A capture that cannot open says why: the pump sends the reason to the
//! controller as `rc:audio-unavailable` (`peer.rs`) instead of a silent
//! track nobody can explain.
//!
//! The whole module is gated behind `#[cfg(feature = "audio")]` at the
//! `lib.rs` `pub mod audio;` site, so default / signalling-only builds
//! never pull in cpal or audiopus.

use async_trait::async_trait;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod cpal_backend;
pub mod opus_encode;
#[cfg(target_os = "linux")]
pub mod pulse;

/// One buffer of interleaved PCM samples straight off the capture
/// backend, BEFORE resample / upmix. `channels` and `sample_rate`
/// describe THIS frame's format (the capture device's native format);
/// the [`opus_encode::OpusEncoder`] resamples/upmixes to 48 kHz stereo
/// as needed.
#[derive(Debug, Clone)]
pub struct AudioFrame {
    /// Interleaved samples: `[L0, R0, L1, R1, …]` for stereo,
    /// `[S0, S1, …]` for mono. Length is a multiple of `channels`.
    pub samples: Vec<i16>,
    pub channels: u16,
    pub sample_rate: u32,
}

/// Pull-based capture source. `next_frame` yields the next available
/// buffer, `Ok(None)` when the source is permanently exhausted (or a
/// Noop that never produces), and `Err` on a hard backend failure.
///
/// `Send` (not `Sync`) — the pump owns it exclusively on one task.
#[async_trait]
pub trait AudioCapture: Send {
    async fn next_frame(&mut self) -> anyhow::Result<Option<AudioFrame>>;
}

/// Capture backend that never produces audio: the recorder's stand-in for a
/// source it has nothing to open for (its synthetic-test microphone).
/// `next_frame` parks so a pump idles cheaply instead of busy-looping on
/// `Ok(None)`. The live path no longer falls back to it: a capture that does
/// not open is a reason sent to the controller (FR-97 P3c-1).
pub struct NoopAudioCapture;

#[async_trait]
impl AudioCapture for NoopAudioCapture {
    async fn next_frame(&mut self) -> anyhow::Result<Option<AudioFrame>> {
        // Park indefinitely rather than return Ok(None) immediately —
        // a hot Ok(None) loop in the pump would spin a core. The pump's
        // JoinHandle is aborted on `AgentPeer::close()`, which cancels
        // this future.
        std::future::pending::<()>().await;
        Ok(None)
    }
}

/// Open this platform's system-audio capture for a live session: the
/// loopback / monitor source only, never a microphone (FR-97 P3c).
///
/// On failure, the reason, which the audio pump sends to the controller.
/// Before P3c-1 this returned a [`NoopAudioCapture`] and kept the reason in
/// the log, so the session carried a silent track nobody could explain.
pub fn open_default() -> Result<Box<dyn AudioCapture>, crate::audio_source::AudioUnavailable> {
    #[cfg(target_os = "linux")]
    {
        open_linux_system_audio()
    }
    #[cfg(target_os = "windows")]
    {
        open_cpal()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(crate::audio_source::AudioUnavailable::new(
            crate::audio_source::AudioUnavailableCode::NotSupported,
            "no system-audio capture backend on this OS (macOS ScreenCaptureKit audio is FR-97 P2a)",
        ))
    }
}

/// The loopback (Windows) or the named device (Linux), through cpal.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn open_cpal() -> Result<Box<dyn AudioCapture>, crate::audio_source::AudioUnavailable> {
    match cpal_backend::CpalLoopbackCapture::open() {
        Ok(cap) => {
            tracing::info!("audio: opened cpal loopback capture");
            Ok(Box::new(cap))
        }
        Err(e) => Err(crate::audio_source::AudioUnavailable::from_error(&e)),
    }
}

/// FR-97 P3c-2 — Linux "computer audio", for a live session and the recorder
/// alike: the route [`crate::audio_source::linux_route`] picks, which is the
/// owner's named device or the default output's monitor, never a microphone.
/// The library question is asked of the loader here, at the open.
#[cfg(target_os = "linux")]
pub fn open_linux_system_audio()
-> Result<Box<dyn AudioCapture>, crate::audio_source::AudioUnavailable> {
    use crate::audio_source::{LinuxRoute, linux_facts, linux_route};
    let mut facts = linux_facts(pulse::present());
    // A per-user daemon loads the library itself, so the loader decides where
    // the disk check found nothing; a root daemon's helper loads it there.
    if !facts.root && !facts.pulse_lib {
        facts.pulse_lib = pulse::loadable();
    }
    match linux_route(facts)? {
        LinuxRoute::Named => open_cpal(),
        LinuxRoute::Pulse => pulse::PulseCapture::open(pulse::DEFAULT_MONITOR)
            .map(|c| Box::new(c) as Box<dyn AudioCapture>),
        #[cfg(feature = "portal-capture")]
        LinuxRoute::Helper => {
            pulse::HelperCapture::spawn().map(|c| Box::new(c) as Box<dyn AudioCapture>)
        }
        // `linux_route` never answers Helper without the helper built.
        #[cfg(not(feature = "portal-capture"))]
        LinuxRoute::Helper => Err(crate::audio_source::AudioUnavailable::new(
            crate::audio_source::AudioUnavailableCode::NoSession,
            "this build has no session helper",
        )),
    }
}
