// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P3c — what a session's or a recording's "computer audio" may open,
//! and why it opened nothing.
//!
//! Always compiled, though only the `audio` feature captures. The hello's
//! promise (`encode::caps::HostFacts`) and the capture backend
//! (`audio::cpal_backend`) read the same rule from here, and its tests run in
//! the lanes that build no audio.
//!
//! **Linux.** cpal 0.15 has one host there, ALSA, so it lists ALSA capture
//! devices (`pipewire`, `pulse`, `default`, the cards) and never a sound
//! server's sources. Opened through the PipeWire or PulseAudio ALSA plugin,
//! `default` and `pulse` capture the server's default SOURCE, which is the
//! microphone wherever there is one. Measured 2026-10-17 (WSL, PulseAudio 17):
//!
//! - the devices were exactly `pipewire`, `pulse`, `default`;
//! - no name ended in `.monitor`, so the auto-pick before this module never
//!   matched, and neither did the documented `ROOMLERD_AUDIO_SOURCE=<sink>.monitor`;
//! - the fallback to the default input recorded the microphone (`RDPSource`
//!   running) while the speakers' monitor stayed suspended.
//!
//! So the pick is never the default input. It is the device the host's owner
//! named ([`named`]) or one whose name says monitor; otherwise it refuses,
//! with the reason.
//!
//! ⚠️ `ROOMLERD_AUDIO_SOURCE` names an ALSA device (`arecord -L`), not a
//! PulseAudio source. `pulse` with `PULSE_SOURCE=@DEFAULT_MONITOR@` in the
//! daemon's environment captures the speakers through either server (measured
//! on the same host).

/// Why a session or a recording has no computer audio.
///
/// - The live path sends it to the controller as `rc:audio-unavailable`
///   (`peer.rs`), the audio twin of FR-80's `rc:media-unavailable`.
/// - The recorder refuses its start with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioUnavailable {
    pub code: AudioUnavailableCode,
    /// The backend's own words, capped. A quote, never a paraphrase.
    pub detail: String,
}

impl AudioUnavailable {
    /// FR-80's cap (`capture::CaptureUnavailable::DETAIL_MAX`), for the same
    /// reason: one verbose backend error must not dominate a message the viewer
    /// renders inline. Truncates on a char boundary.
    pub const DETAIL_MAX: usize = 200;

    pub fn new(code: AudioUnavailableCode, detail: impl Into<String>) -> Self {
        let detail: String = detail.into();
        let detail = if detail.chars().count() > Self::DETAIL_MAX {
            detail.chars().take(Self::DETAIL_MAX).collect()
        } else {
            detail
        };
        Self { code, detail }
    }

    /// The reason the backend put inside `e`, else the backend's own words as
    /// a `backend_error`.
    pub fn from_error(e: &anyhow::Error) -> Self {
        match e.downcast_ref::<Self>() {
            Some(reason) => reason.clone(),
            None => Self::new(AudioUnavailableCode::BackendError, format!("{e:#}")),
        }
    }
}

impl std::fmt::Display for AudioUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for AudioUnavailable {}

/// A closed set, and a compatibility surface like every `rc:*` string. The
/// viewer keeps a code it does not know and shows its hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioUnavailableCode {
    /// Linux: no capture device is the computer's own sound, and the default
    /// input is a microphone.
    NoMonitor,
    /// `ROOMLERD_AUDIO_SOURCE` names a device this host does not have.
    SourceNotFound,
    /// Windows: no output device to loop back.
    NoOutput,
    /// The device was found and failed to open, or stopped mid-session.
    /// `detail` carries the backend's words.
    BackendError,
    /// This OS has no system-audio capture (macOS until FR-97 P2a).
    NotSupported,
    /// FR-97 P3c-2 — Linux: no sound server could be reached, or no Pulse
    /// client library to reach one with.
    NoSoundServer,
    /// FR-97 P3c-2 — a root daemon with nobody signed in at the screen: there
    /// is no session, so no session sound.
    NoSession,
}

impl AudioUnavailableCode {
    /// The wire spelling. ⚠️ Renaming one does not fail loudly: it changes
    /// what an operator reads on the screen that explains the silence.
    pub fn wire(self) -> &'static str {
        match self {
            Self::NoMonitor => "no_monitor",
            Self::SourceNotFound => "source_not_found",
            Self::NoOutput => "no_output",
            Self::BackendError => "backend_error",
            Self::NotSupported => "not_supported",
            Self::NoSoundServer => "no_sound_server",
            Self::NoSession => "no_session",
        }
    }

    /// The sentence the viewer shows. Composed here, as FR-80's are, because
    /// only the agent knows which OS it is on.
    pub fn hint(self) -> &'static str {
        match self {
            Self::NoMonitor => {
                "This host sends no sound. A session carries what the computer plays, never its \
                 microphone, and this agent finds nothing here that captures the computer's sound. \
                 The host's owner can name a capture device for it in ROOMLERD_AUDIO_SOURCE."
            }
            Self::SourceNotFound => {
                "This host sends no sound: the capture device named in its ROOMLERD_AUDIO_SOURCE is \
                 not there, and the agent does not open a microphone in its place."
            }
            Self::NoOutput => {
                "This host sends no sound: it has no audio output device to capture, which is usual \
                 on a server or a virtual machine without a sound device."
            }
            Self::BackendError => {
                "This host's audio capture failed, so the session carries no sound. The agent's own \
                 words follow."
            }
            Self::NotSupported => {
                "This host's OS cannot capture the computer's sound yet, so the session carries none."
            }
            Self::NoSoundServer => {
                "This host sends no sound: the agent could not reach the session's sound server \
                 (PulseAudio, or PipeWire's Pulse server), or this host has no Pulse client library."
            }
            Self::NoSession => {
                "This host sends no sound: nobody is signed in at its screen, so there is no session \
                 sound to capture."
            }
        }
    }
}

/// FR-97 P3c-2's kill switch: `ROOMLERD_AUDIO_SESSION=0` puts Linux back on
/// P3c-1's rule (a named device, or nothing). On by default.
pub fn session_audio_enabled() -> bool {
    tunnel_core::env::node_env("AUDIO_SESSION").is_none_or(|v| v.trim() != "0")
}

/// How Linux reaches the computer's sound, decided once for the hello and
/// again for each session, by the same function ([`linux_route`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxRoute {
    /// The ALSA device the host's owner named (`ROOMLERD_AUDIO_SOURCE`),
    /// through cpal. An explicit choice, so it wins.
    Named,
    /// The default output's monitor, recorded in this process through Pulse's
    /// client library: a per-user daemon is already the session's owner.
    Pulse,
    /// The same, recorded by the seat user's helper (`portal-helper --audio`):
    /// a root daemon reaches no session's sound server itself, because
    /// PulseAudio admits a client by uid or cookie.
    Helper,
}

/// The facts [`linux_route`] decides on, as plain values so it is tested on
/// every OS.
#[derive(Debug, Clone, Copy)]
pub struct LinuxAudioFacts {
    pub named: bool,
    pub session_audio: bool,
    /// `libpulse-simple.so.0` loads.
    pub pulse_lib: bool,
    pub root: bool,
    /// This build carries the seat-user helper (`portal-capture`).
    pub helper_built: bool,
}

/// This process's facts for [`linux_route`]. `pulse_lib` is the caller's: the
/// hello asks the disk (`audio::pulse::present`), and a capture asks the
/// loader when it opens.
pub fn linux_facts(pulse_lib: bool) -> LinuxAudioFacts {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let root = false;
    LinuxAudioFacts {
        named: named().is_some(),
        session_audio: session_audio_enabled(),
        pulse_lib,
        root,
        helper_built: cfg!(all(target_os = "linux", feature = "portal-capture")),
    }
}

/// The Linux route to the computer's sound, or why there is none. ⚠️ Every
/// route captures a monitor or the owner's named device: none of them is the
/// default input.
pub fn linux_route(f: LinuxAudioFacts) -> Result<LinuxRoute, AudioUnavailable> {
    if f.named {
        return Ok(LinuxRoute::Named);
    }
    if !f.session_audio {
        return Err(AudioUnavailable::new(
            AudioUnavailableCode::NoMonitor,
            "session audio is switched off on this host (ROOMLERD_AUDIO_SESSION=0), and no capture \
             device is named",
        ));
    }
    if !f.pulse_lib {
        return Err(AudioUnavailable::new(
            AudioUnavailableCode::NoSoundServer,
            "no Pulse client library (libpulse-simple.so.0) on this host",
        ));
    }
    if !f.root {
        return Ok(LinuxRoute::Pulse);
    }
    if f.helper_built {
        return Ok(LinuxRoute::Helper);
    }
    Err(AudioUnavailable::new(
        AudioUnavailableCode::NoSession,
        "this daemon runs as root and was built without the session helper that records a \
         session's sound",
    ))
}

/// The capture device the host's owner named for computer audio
/// (`ROOMLERD_AUDIO_SOURCE`), trimmed, if any.
///
/// - The picker opens it first ([`pick_linux`]).
/// - On Linux the hello's `audio` promise rests on it (`encode::caps::HostFacts`).
pub fn named() -> Option<String> {
    tunnel_core::env::node_env("AUDIO_SOURCE")
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
}

/// The Linux pick over cpal's capture devices, by name: the named device,
/// else one whose name says monitor, else a refusal. ⚠️ Never the default
/// input (see the module doc). Pure, so it is tested on every OS.
pub fn pick_linux(named: Option<&str>, devices: &[&str]) -> Result<usize, AudioUnavailable> {
    if let Some(want) = named
        && let Some(i) = devices.iter().position(|d| *d == want)
    {
        return Ok(i);
    }
    if let Some(i) = devices.iter().position(|d| d.ends_with(".monitor")) {
        return Ok(i);
    }
    let here = if devices.is_empty() {
        "none".to_owned()
    } else {
        devices.join(", ")
    };
    Err(match named {
        Some(want) => AudioUnavailable::new(
            AudioUnavailableCode::SourceNotFound,
            format!("ROOMLERD_AUDIO_SOURCE={want} is not a capture device here (devices: {here})"),
        ),
        None => AudioUnavailable::new(
            AudioUnavailableCode::NoMonitor,
            format!(
                "no capture device here is named as the computer's sound (devices: {here}); the \
                 default input is a microphone wherever there is one, so it is not opened"
            ),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The devices cpal 0.15 listed on a PulseAudio host (WSL, 2026-10-17).
    const MEASURED: [&str; 3] = ["pipewire", "pulse", "default"];

    #[test]
    fn the_default_input_is_never_the_pick() {
        // Before P3c-1 this host opened `default`: the microphone.
        let refused = pick_linux(None, &MEASURED).unwrap_err();
        assert_eq!(refused.code, AudioUnavailableCode::NoMonitor);
        assert!(
            refused.detail.contains("pipewire, pulse, default"),
            "the refusal names what was there: {}",
            refused.detail
        );
        assert_eq!(
            pick_linux(None, &[]).unwrap_err().code,
            AudioUnavailableCode::NoMonitor
        );
    }

    #[test]
    fn a_named_device_is_opened_as_given() {
        assert_eq!(pick_linux(Some("pulse"), &MEASURED), Ok(1));
        // Even `default`: an owner who names it chose it.
        assert_eq!(pick_linux(Some("default"), &MEASURED), Ok(2));
    }

    #[test]
    fn a_monitor_is_picked_by_its_name() {
        let devices = ["default", "speakers.monitor"];
        assert_eq!(pick_linux(None, &devices), Ok(1));
        // A name that is not there still finds the monitor rather than refusing.
        assert_eq!(pick_linux(Some("gone"), &devices), Ok(1));
    }

    #[test]
    fn a_named_device_that_is_not_there_is_refused_by_name() {
        // The form the code documented before P3c-1: a PulseAudio source, which
        // cpal's ALSA host never lists.
        let refused =
            pick_linux(Some("alsa_output.pci.analog-stereo.monitor"), &MEASURED).unwrap_err();
        assert_eq!(refused.code, AudioUnavailableCode::SourceNotFound);
        assert!(
            refused
                .detail
                .contains("alsa_output.pci.analog-stereo.monitor")
        );
    }

    #[test]
    fn a_reason_survives_the_trip_through_anyhow() {
        let reason = AudioUnavailable::new(AudioUnavailableCode::NoOutput, "no default output");
        let e = anyhow::Error::new(reason.clone()).context("opening the loopback");
        assert_eq!(AudioUnavailable::from_error(&e), reason);
        let other = AudioUnavailable::from_error(&anyhow::anyhow!("WASAPI said no"));
        assert_eq!(other.code, AudioUnavailableCode::BackendError);
        assert_eq!(other.detail, "WASAPI said no");
    }

    fn facts() -> LinuxAudioFacts {
        LinuxAudioFacts {
            named: false,
            session_audio: true,
            pulse_lib: true,
            root: false,
            helper_built: true,
        }
    }

    #[test]
    fn a_per_user_daemon_records_the_monitor_itself_and_root_through_the_seat_user() {
        assert_eq!(linux_route(facts()), Ok(LinuxRoute::Pulse));
        assert_eq!(
            linux_route(LinuxAudioFacts {
                root: true,
                ..facts()
            }),
            Ok(LinuxRoute::Helper)
        );
        let no_helper = linux_route(LinuxAudioFacts {
            root: true,
            helper_built: false,
            ..facts()
        })
        .unwrap_err();
        assert_eq!(no_helper.code, AudioUnavailableCode::NoSession);
    }

    #[test]
    fn a_named_device_wins_even_with_session_audio_off_or_no_library() {
        for (session_audio, pulse_lib, root) in [(false, false, false), (true, false, true)] {
            assert_eq!(
                linux_route(LinuxAudioFacts {
                    named: true,
                    session_audio,
                    pulse_lib,
                    root,
                    helper_built: false,
                }),
                Ok(LinuxRoute::Named)
            );
        }
    }

    #[test]
    fn the_kill_switch_is_p3c_1s_rule_and_a_missing_library_says_so() {
        let off = linux_route(LinuxAudioFacts {
            session_audio: false,
            ..facts()
        })
        .unwrap_err();
        assert_eq!(off.code, AudioUnavailableCode::NoMonitor);
        assert!(
            off.detail.contains("ROOMLERD_AUDIO_SESSION=0"),
            "{}",
            off.detail
        );
        let no_lib = linux_route(LinuxAudioFacts {
            pulse_lib: false,
            ..facts()
        })
        .unwrap_err();
        assert_eq!(no_lib.code, AudioUnavailableCode::NoSoundServer);
        assert!(
            no_lib.detail.contains("libpulse-simple"),
            "{}",
            no_lib.detail
        );
    }

    #[test]
    fn the_detail_is_capped_on_a_char_boundary() {
        let long = "é".repeat(AudioUnavailable::DETAIL_MAX + 50);
        let r = AudioUnavailable::new(AudioUnavailableCode::BackendError, long);
        assert_eq!(r.detail.chars().count(), AudioUnavailable::DETAIL_MAX);
    }

    #[test]
    fn every_code_has_a_wire_name_and_words() {
        use AudioUnavailableCode::*;
        let all = [
            NoMonitor,
            SourceNotFound,
            NoOutput,
            BackendError,
            NotSupported,
            NoSoundServer,
            NoSession,
        ];
        let mut wires: Vec<&str> = all.iter().map(|c| c.wire()).collect();
        wires.sort_unstable();
        wires.dedup();
        assert_eq!(wires.len(), all.len(), "wire names are distinct");
        for c in all {
            assert!(
                c.wire()
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "{c:?}"
            );
            assert!(c.hint().len() > 40, "{c:?}");
        }
    }
}
