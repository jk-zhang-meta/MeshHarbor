// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — `<recording>.roomler.json`, the facts about a recording that the
//! file itself cannot carry.
//!
//! Three readers: meshharbor-desktop's Recordings list (origin, duration, why it
//! stopped), the remote download path (only the controller named as the
//! initiator may list or fetch a remote recording — ownership is by user, not
//! by session id, because the reconnect ladder mints new session ids), and a
//! person asking afterwards why a recording has a black stretch or ended early.
//!
//! ⚠️ Never content: no window titles, no key counts, nothing typed. The
//! recording is the content; this file only describes it.

use serde::{Deserialize, Serialize};

use super::mp4::ColorInfo;

/// Why a recording ended. A closed set on purpose: the UI maps each to a
/// sentence, and an open string would reach it as a code nobody wrote words for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The person (local) or the controller (remote) pressed Stop.
    Requested,
    /// The host pressed Stop on the recording banner.
    HostStopped,
    /// The remote session ended and no re-attach came within the grace.
    SessionEnded,
    /// The console user changed (fast user switch, sign-out): a recording
    /// never follows a user switch.
    SessionChanged,
    /// The captured display changed size; P1 ends the file cleanly instead of
    /// scaling mid-recording.
    DisplayChanged,
    /// Free space fell below the stop threshold.
    DiskLow,
    /// The configured maximum length was reached.
    MaxDuration,
    /// The encoder failed, or changed its parameter sets mid-file.
    EncoderFailed,
    /// Capture failed and could not be re-acquired.
    CaptureFailed,
    /// The device owner switched remote recording off.
    GateRevoked,
    /// The launching process went away (stdin closed).
    ParentGone,
    /// The recorder died; the boot reconciler finalized what it left.
    Interrupted,
}

impl StopReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::HostStopped => "host_stopped",
            Self::SessionEnded => "session_ended",
            Self::SessionChanged => "session_changed",
            Self::DisplayChanged => "display_changed",
            Self::DiskLow => "disk_low",
            Self::MaxDuration => "max_duration",
            Self::EncoderFailed => "encoder_failed",
            Self::CaptureFailed => "capture_failed",
            Self::GateRevoked => "gate_revoked",
            Self::ParentGone => "parent_gone",
            Self::Interrupted => "interrupted",
        }
    }
}

/// Who started the recording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Initiator {
    /// The person at the device.
    Local {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// A controller over a remote-control session.
    Remote {
        controller_user_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_name: Option<String>,
    },
}

/// Something that happened during the recording, in media time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Milliseconds from the start of the recording.
    pub t_ms: u64,
    /// `lock`, `unlock`, `capture_gap`, `encoder_fallback`, …
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// FR-85 P1d — how the mouse pointer got into the recording. A closed set,
/// like [`StopReason`]: "why is there no pointer?" deserves an answer that is
/// already written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pointer {
    /// The capture backend drew it (WGC, CoreGraphics, a compositor's
    /// embedded cursor).
    InFrame,
    /// The recorder drew it, from where the backend said it was (DXGI, X11).
    Drawn,
    /// The recording has no pointer: the backend neither draws it nor says
    /// where it is (DRM, the SystemContext capture, a portal that offers only
    /// a hidden cursor).
    #[serde(rename = "none")]
    Absent,
}

impl Pointer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InFrame => "in_frame",
            Self::Drawn => "drawn",
            Self::Absent => "none",
        }
    }
}

/// Which audio went into the file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioInfo {
    pub system: bool,
    pub microphone: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
}

/// The sidecar itself. `version` bumps on an incompatible change; readers
/// ignore fields they do not know.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sidecar {
    pub version: u32,
    /// The recording's file name (not a path — the sidecar sits beside it).
    pub file: String,
    pub initiator: Initiator,
    /// RFC 3339, UTC.
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    pub duration_ms: u64,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub codec: String,
    /// The backend that encoded it, as it names itself (`openh264`,
    /// `h264_nvenc`, …).
    pub encoder: String,
    pub color: ColorInfo,
    #[serde(default)]
    pub audio: AudioInfo,
    /// Frames written.
    pub frames: u64,
    /// Ticks the encoder fell behind on (the previous frame was shown longer).
    #[serde(default)]
    pub late_ticks: u64,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<StopReason>,
    pub bytes: u64,
    /// FR-85 P1d — how the pointer got in. Missing from a sidecar written
    /// before P1d, and from one the reconciler rebuilt after a crash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<Pointer>,
}

pub const SIDECAR_VERSION: u32 = 1;
pub const SIDECAR_SUFFIX: &str = ".roomler.json";

impl Sidecar {
    /// The sidecar path for a recording path: `x.mp4` → `x.mp4.roomler.json`.
    pub fn path_for(recording: &std::path::Path) -> std::path::PathBuf {
        let mut name = recording
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(SIDECAR_SUFFIX);
        recording.with_file_name(name)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Sidecar {
        Sidecar {
            version: SIDECAR_VERSION,
            file: "Roomler Recording 2026-09-25 14-30-12.mp4".into(),
            initiator: Initiator::Remote {
                controller_user_id: "66f0c0ffee0000000000abcd".into(),
                controller_name: Some("GJ".into()),
            },
            started_at: "2026-09-25T12:30:12Z".into(),
            ended_at: Some("2026-09-25T12:31:12Z".into()),
            duration_ms: 60_000,
            width: 1920,
            height: 1080,
            fps: 30,
            codec: "h264".into(),
            encoder: "openh264".into(),
            color: ColorInfo::BT601_LIMITED,
            audio: AudioInfo::default(),
            frames: 1800,
            late_ticks: 0,
            events: vec![Event {
                t_ms: 4200,
                kind: "lock".into(),
                detail: None,
            }],
            stop_reason: Some(StopReason::Requested),
            bytes: 12_345,
            pointer: Some(Pointer::Drawn),
        }
    }

    #[test]
    fn round_trips_through_json() {
        let s = sample();
        let back: Sidecar = serde_json::from_str(&s.to_json()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn stop_reasons_serialise_as_their_wire_names() {
        for r in [
            StopReason::Requested,
            StopReason::HostStopped,
            StopReason::SessionEnded,
            StopReason::SessionChanged,
            StopReason::DisplayChanged,
            StopReason::DiskLow,
            StopReason::MaxDuration,
            StopReason::EncoderFailed,
            StopReason::CaptureFailed,
            StopReason::GateRevoked,
            StopReason::ParentGone,
            StopReason::Interrupted,
        ] {
            assert_eq!(
                serde_json::to_string(&r).unwrap(),
                format!("\"{}\"", r.as_str())
            );
        }
    }

    #[test]
    fn the_initiator_is_tagged_and_a_remote_one_names_its_user() {
        let j = serde_json::to_value(sample().initiator).unwrap();
        assert_eq!(j["kind"], "remote");
        assert_eq!(j["controller_user_id"], "66f0c0ffee0000000000abcd");
        let local = serde_json::to_value(Initiator::Local { user: None }).unwrap();
        assert_eq!(local, serde_json::json!({"kind": "local"}));
    }

    #[test]
    fn an_older_reader_ignores_fields_it_does_not_know() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["a_field_from_the_future"] = serde_json::json!(42);
        let back: Sidecar = serde_json::from_value(v).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn the_pointer_is_named_on_the_wire_and_absent_when_unknown() {
        for p in [Pointer::InFrame, Pointer::Drawn, Pointer::Absent] {
            assert_eq!(
                serde_json::to_string(&p).unwrap(),
                format!("\"{}\"", p.as_str())
            );
        }
        // A sidecar from before P1d (no `pointer`) still reads, as unknown.
        let mut v = serde_json::to_value(sample()).unwrap();
        v.as_object_mut().unwrap().remove("pointer");
        let back: Sidecar = serde_json::from_value(v).unwrap();
        assert_eq!(back.pointer, None);
        // And an unknown one is not written as `null`.
        let mut s = sample();
        s.pointer = None;
        assert!(!s.to_json().contains("pointer"));
    }

    #[test]
    fn the_sidecar_sits_beside_its_recording() {
        let p = std::path::Path::new("/tmp/x/r.mp4");
        assert_eq!(
            Sidecar::path_for(p),
            std::path::PathBuf::from("/tmp/x/r.mp4.roomler.json")
        );
    }
}
