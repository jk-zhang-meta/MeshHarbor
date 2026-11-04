// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — HQ screen recording (P1: the recorder core).
//!
//! A recording is encoded **at the source**, in a pipeline of its own, and
//! written to a local file: `roomlerd record` ([`child`]) opens its own
//! capturer at native resolution ([`recorder`]), paces it to a constant frame
//! rate on its own clock ([`pacer`]), encodes with a recording profile, and
//! writes a fragmented MP4 that survives a crash, remuxed on stop to a
//! progressive, moov-first file ([`mp4`], [`annexb`]). Where the capture
//! backend leaves the mouse pointer out, the recorder draws it ([`pointer`]).
//! The folder rules live in [`folder`], the facts about a finished recording
//! in [`sidecar`].
//!
//! Not here yet (later FR-85 phases): the microphone and computer audio on
//! macOS (P1c-mac), and re-attaching after a dropped session (P3b-3). AAC
//! ([`audio_codec`]) and FFmpeg's H.264 decoder for hardware-encoded
//! recordings ([`decode`]) are built (P4) and wait only for the vendored
//! FFmpeg that carries them.
//!
//! Design and gates: `docs/fr/FR-85-hq-screen-recording.md`.

/// Can THIS build record what the computer plays? (#1760)
///
/// The ONE answer every entry point reads. The recorder child opens a
/// loopback only where this says yes ([`child`] asserts at compile time that
/// its platform `cfg` agrees); the device advertises `remote-audio` and lets
/// an audio start through only where it says yes ([`remote::advertise`],
/// [`remote::precheck`]); and the LocalAPI state tells the companion the
/// same ahead of any start (`RecordingState::system_audio_unavailable_reason`,
/// [`manager`]).
///
/// ⚠️ Before this fn the remote gates read the `audio` FEATURE alone, which
/// the macOS build has (it is in `full`, for the microphone path). So a Mac
/// whose owner had allowed computer audio advertised a capability it did not
/// have, the start passed every gate, and it failed inside the recorder as a
/// bare `start_failed`. A gate that is not the capability is a courtesy:
/// keep this the only place the platform rule is spelled out.
pub const fn system_audio_supported() -> bool {
    cfg!(all(
        feature = "audio",
        any(target_os = "linux", target_os = "windows")
    ))
}

/// The words for [`system_audio_supported`] being false, chosen at compile
/// time like the capability: for the person at the device (the companion's
/// greyed-out box), the controller (a refusal's `detail`) and the recorder
/// child's own refusal, so every surface says the same thing.
pub const SYSTEM_AUDIO_UNSUPPORTED: &str = if !cfg!(feature = "audio") {
    "this device service was built without audio capture"
} else if cfg!(target_os = "macos") {
    "macOS can't capture what the computer plays yet"
} else {
    "this device can't capture what the computer plays"
};

/// Why computer audio cannot be recorded here, or `None` where it can.
pub fn system_audio_unsupported_reason() -> Option<&'static str> {
    (!system_audio_supported()).then_some(SYSTEM_AUDIO_UNSUPPORTED)
}

pub mod annexb;
/// FR-85 P1c — computer audio and the microphone, mixed on the recorder's
/// clock (the `audio` feature: cpal + audiopus).
#[cfg(feature = "audio")]
pub mod audio;
/// FR-85 P4 — the audio encoder: AAC where this build's FFmpeg has it, Opus
/// everywhere else.
#[cfg(feature = "audio")]
pub mod audio_codec;
pub mod child;
/// FR-85 P4 — the decoder an export reads a recording's video with:
/// openh264 for Baseline, FFmpeg's `h264` for the rest where it is linked.
#[cfg(feature = "openh264-encoder")]
pub mod decode;
/// FR-85 P5 — the edit list and its exact time map.
pub mod edit;
/// FR-85 P5a — the export engine (it decodes with openh264, so it comes with
/// the software encoder's feature).
#[cfg(feature = "openh264-encoder")]
pub mod export;
/// FR-85 P5b — an export's sound: the recording's audio through the edit
/// list, and background music (Opus, like a recording's).
#[cfg(feature = "audio")]
pub mod export_audio;
pub mod folder;
/// FR-85 P1e — who the recorder runs as (the person signed in at the
/// device, at normal integrity), and launching it as that.
pub mod launch;
pub mod manager;
/// FR-85 P5a — `roomlerd media probe|export`, the engine as its own process.
#[cfg(feature = "openh264-encoder")]
pub mod media;
pub mod mp4;
pub mod pacer;
/// FR-85 P1d — drawing the pointer into a recording, where the backend does
/// not.
pub mod pointer;
pub mod recorder;
/// FR-85 P3b — the device's half of remote recording: the owner's gates,
/// what the device advertises, and the `record` DataChannel.
pub mod remote;
pub mod sidecar;
