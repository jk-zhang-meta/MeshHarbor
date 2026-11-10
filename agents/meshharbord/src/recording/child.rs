// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — `meshharbord record`, the recorder as a process of its own.
//!
//! Spawned by the worker (P2/P3) and runnable by hand. A driver fault inside a
//! recording's encoder costs this process, never the daemon or a live session
//! — the same reason the capability probe is a child.
//!
//! **Protocol.** stdout carries one JSON object per line: the
//! [`RecorderEvent`]s (`started`, `progress`, `stopped`) plus `refused` (it
//! never started, with a closed `code`) and `error`. stdin takes JSON lines:
//! `{"cmd":"stop"}` (optionally `"reason":"host_stopped"`); **end of stdin
//! stops the recording** (`parent_gone`), so a recorder never outlives the
//! process that launched it. Ctrl+C stops it too. Every stop finalizes.
//!
//! ⚠️ The encoder cells denylist is read by the FFmpeg constructors through
//! `node_env("ENCODER_CELLS_DENY")`. A child spawned by the daemon receives it
//! as env (`config_fallbacks_for_child`); run by hand, [`register_encoder_fallbacks`]
//! reads it from the config file — a gate the probe and the live session honour
//! must be honoured here too, or it is a courtesy.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use serde::Deserialize;
use tokio::sync::{mpsc, watch};

use super::folder;
use super::recorder::{
    self, AudioSources, EncoderFactory, RecordOptions, RecorderEvent, StartError, StartRefusal,
};
use super::sidecar::{Initiator, StopReason};

/// Command-line options of `meshharbord record`.
#[derive(Debug, Clone)]
pub struct RecordArgs {
    /// Destination folder; `None` = the configured or default folder.
    pub out: Option<PathBuf>,
    pub fps: u32,
    /// `auto` | `hardware` | `software`.
    pub encoder: String,
    pub max_minutes: u32,
    /// A remote recording's controller (P3 passes it); `None` = local.
    pub remote_user_id: Option<String>,
    pub remote_user_name: Option<String>,
    /// FR-85 P1c — record what the computer plays.
    pub system_audio: bool,
    /// FR-85 P1c — record the microphone. Local only: no remote path ever
    /// sets it.
    pub microphone: bool,
    /// FR-85 P1e — only say which folder a recording would go to, and why
    /// (`{"ev":"where"}`), then exit. The daemon asks the recorder rather
    /// than deciding itself, because the answer depends on who asks: a
    /// SYSTEM daemon's Videos folder is not the person's, and its write probe
    /// passes where theirs would not.
    pub where_only: bool,
    /// FR-85 P1e — only report the identity this process runs as
    /// (`{"ev":"whoami"}`), then exit.
    pub whoami: bool,
}

/// Open the audio sources the recording was asked for. Each failure is
/// named — a recording that silently lacks the audio the person asked for is
/// worse than a refusal that says which source did not open.
fn open_audio(
    system: bool,
    microphone: bool,
) -> std::result::Result<AudioSources, (StartRefusal, String)> {
    #[cfg(feature = "audio")]
    {
        let mut sources = AudioSources::default();
        if system {
            sources.system = Some(
                open_system_audio()
                    .map_err(|e| (StartRefusal::SystemAudioUnavailable, format!("{e:#}")))?,
            );
        }
        if microphone {
            sources.microphone = Some(
                open_microphone().map_err(|e| (StartRefusal::MicUnavailable, mic_detail(&e)))?,
            );
        }
        Ok(sources)
    }
    #[cfg(not(feature = "audio"))]
    {
        if system || microphone {
            return Err((
                StartRefusal::AudioUnavailable,
                "this build of meshharbord has no audio capture".into(),
            ));
        }
        Ok(AudioSources)
    }
}

/// Computer audio: the loopback / monitor source only — never a microphone.
///
/// ⚠️ The platform rule is [`super::system_audio_supported`]'s, not this
/// function's (#1760): the daemon's gates read that fn, and each arm below
/// asserts at compile time that it agrees, so the two cannot drift again.
/// The synthetic tone (a test's `MESHHARBORD_SYNTHETIC_AUDIO`) is answered
/// first, on any platform: it is what the audio tests record with.
#[cfg(feature = "audio")]
fn open_system_audio() -> Result<Box<dyn crate::audio::AudioCapture>> {
    #[cfg(feature = "synthetic-frame-source")]
    if std::env::var_os("MESHHARBORD_SYNTHETIC_AUDIO").is_some() {
        // A 440 Hz tone at 44.1 kHz mono: the shape of a real device,
        // including a rate that is not 48 kHz.
        return Ok(Box::new(super::audio::SineCapture::new(
            440.0, 44_100, 1, 8_000.0,
        )));
    }
    // FR-97 P3c-2 — the live path's own route: the owner's named device, or
    // the default output's monitor through Pulse's client library. The
    // recorder already runs as the person at the screen, so it records in
    // this process; never a microphone.
    #[cfg(target_os = "linux")]
    {
        const _: () = assert!(
            super::system_audio_supported(),
            "a monitor opens here, so `system_audio_supported` must say so"
        );
        crate::audio::open_linux_system_audio().map_err(anyhow::Error::new)
    }
    #[cfg(target_os = "windows")]
    {
        const _: () = assert!(
            super::system_audio_supported(),
            "a loopback opens here, so `system_audio_supported` must say so"
        );
        let cap = crate::audio::cpal_backend::CpalLoopbackCapture::open_source(
            crate::audio::cpal_backend::Source::SystemOnly,
        )?;
        Ok(Box::new(cap))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        const _: () = assert!(
            !super::system_audio_supported(),
            "nothing opens here, so `system_audio_supported` must say no"
        );
        bail!("{}", super::SYSTEM_AUDIO_UNSUPPORTED)
    }
}

/// The microphone: the default input device.
#[cfg(feature = "audio")]
fn open_microphone() -> Result<Box<dyn crate::audio::AudioCapture>> {
    #[cfg(feature = "synthetic-frame-source")]
    if std::env::var_os("MESHHARBORD_SYNTHETIC_AUDIO").is_some() {
        return Ok(Box::new(crate::audio::NoopAudioCapture));
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let cap = crate::audio::cpal_backend::CpalLoopbackCapture::open_source(
            crate::audio::cpal_backend::Source::Microphone,
        )?;
        Ok(Box::new(cap))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        bail!("recording the microphone on this platform arrives with FR-85 P1c (macOS)")
    }
}

/// What to say when the microphone did not open: on Windows, the one
/// setting that most often blocks it without any other sign.
#[cfg(feature = "audio")]
fn mic_detail(e: &anyhow::Error) -> String {
    #[cfg(target_os = "windows")]
    {
        format!(
            "{e:#} — if a microphone is connected, check Settings › Privacy & security › \
             Microphone › “Let desktop apps access your microphone”"
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        format!("{e:#}")
    }
}

#[derive(Debug, Deserialize)]
struct StdinCommand {
    cmd: String,
    #[serde(default)]
    reason: Option<String>,
}

/// Ask the recorder to stop. The FIRST reason wins: a parent that sends
/// `stop` and then closes stdin must get `requested`, not `parent_gone`.
pub fn request_stop(tx: &watch::Sender<Option<StopReason>>, reason: StopReason) {
    tx.send_if_modified(|v| {
        if v.is_none() {
            *v = Some(reason);
            true
        } else {
            false
        }
    });
}

/// Map a stdin stop reason to the closed set. Unknown words are a plain
/// `requested` stop — a newer parent must not be able to wedge an older child.
fn stop_reason_from(word: Option<&str>) -> StopReason {
    match word.unwrap_or("requested") {
        "host_stopped" => StopReason::HostStopped,
        "session_ended" => StopReason::SessionEnded,
        "session_changed" => StopReason::SessionChanged,
        "gate_revoked" => StopReason::GateRevoked,
        _ => StopReason::Requested,
    }
}

/// Register the encoder knobs the record child reads from config, exactly the
/// keys `main.rs` registers for the daemon's own encoders (`ENCODER_CELLS_DENY`
/// and the pinned hardware devices). An env var set by a parent still wins —
/// that is `node_env`'s precedence.
pub fn register_encoder_fallbacks(cfg: &meshharbor_node_core::config::AgentConfig) {
    let mut m: HashMap<String, String> = HashMap::new();
    if let Some(v) = &cfg.encoder_cells_deny {
        m.insert("ENCODER_CELLS_DENY".into(), v.clone());
    }
    if let Some(v) = &cfg.vaapi_device {
        m.insert("VAAPI_DEVICE".into(), v.clone());
    }
    if let Some(v) = &cfg.d3d12_adapter {
        m.insert("D3D12_ADAPTER".into(), v.clone());
    }
    if let Some(v) = &cfg.vulkan_device {
        m.insert("VULKAN_DEVICE".into(), v.clone());
    }
    if !m.is_empty() {
        tunnel_core::env::register_config_fallbacks(m);
    }
}

/// Every protocol line starts with this, like the probe children's
/// `MESHHARBOR_CAPS_JSON:` — the daemon's tracing writes to stdout too, so a
/// parent that parsed every line would choke on the first log line.
pub const EVENT_PREFIX: &str = "MESHHARBOR_REC_JSON:";

pub(crate) fn emit(value: &serde_json::Value) {
    let mut out = std::io::stdout().lock();
    // EPIPE (the parent went away) must not abort the finalize that follows.
    let _ = writeln!(out, "{EVENT_PREFIX}{value}");
    let _ = out.flush();
}

/// Parse one stdout line of a record child: `Some(event)` for a protocol
/// line, `None` for anything else (log lines).
pub fn parse_event_line(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str(line.trim_end().strip_prefix(EVENT_PREFIX)?).ok()
}

/// openh264's recording profile — the software rung, and the whole ladder on a
/// build without FFmpeg (Linux arm64).
fn software_encoder(
    w: u32,
    h: u32,
    fps: u32,
    gop_frames: u32,
) -> Result<Box<dyn crate::encode::VideoEncoder>> {
    #[cfg(feature = "openh264-encoder")]
    {
        let e =
            crate::encode::openh264_backend::Openh264Encoder::new_recording(w, h, fps, gop_frames)?;
        Ok(Box::new(e))
    }
    #[cfg(not(feature = "openh264-encoder"))]
    {
        let _ = (w, h, fps, gop_frames);
        bail!("this build has no software H.264 encoder (openh264-encoder)");
    }
}

/// The recording encoder for this run. Every rung keeps its own GOP (the
/// recorder never has to force keyframes):
///
/// - `software`: openh264's recording profile;
/// - `hardware`: the FFmpeg H.264 cascade in its RECORDING profile
///   (`FfmpegEncoder::new_recording` — the device denylist honoured exactly as
///   a session's), and nothing else: asked for hardware, a host without it
///   refuses rather than quietly recording in software;
/// - `auto`: hardware, then software.
pub(crate) fn encoder_factory(
    pref: &str,
    fps: u32,
    gop_seconds: u32,
) -> Result<(EncoderFactory, bool)> {
    let gop = fps * gop_seconds.max(1);
    let prefer_hw = match pref {
        "software" => {
            let f: EncoderFactory = Box::new(move |w, h| software_encoder(w, h, fps, gop));
            return Ok((f, true));
        }
        "hardware" => true,
        "auto" => false,
        other => bail!("unknown --encoder {other:?} (auto | hardware | software)"),
    };
    let f: EncoderFactory = Box::new(move |w, h| {
        #[cfg(feature = "ffmpeg-encoder")]
        match crate::encode::ffmpeg::FfmpegEncoder::new_recording(
            meshharbor_remote_control::models::VideoCodec::H264,
            w,
            h,
            fps,
            gop,
        ) {
            Ok(e) => return Ok(Box::new(e) as Box<dyn crate::encode::VideoEncoder>),
            Err(e) if prefer_hw => bail!("no hardware H.264 encoder opened for recording: {e:#}"),
            Err(e) => {
                tracing::info!(%e, "recording: no hardware H.264 encoder — the software recording profile");
            }
        }
        #[cfg(not(feature = "ffmpeg-encoder"))]
        if prefer_hw {
            bail!("this build has no hardware encoder backend (ffmpeg-encoder)");
        }
        software_encoder(w, h, fps, gop)
    });
    Ok((f, true))
}

/// Body of `meshharbord record`. Returns once the file is final.
pub async fn run(args: RecordArgs, config_path: &std::path::Path) -> Result<()> {
    if args.whoami {
        let mut ev = super::launch::describe_self();
        ev["ev"] = "whoami".into();
        emit(&ev);
        return Ok(());
    }
    if let Ok(cfg) = meshharbor_node_core::config::load(&config_path.to_path_buf()) {
        register_encoder_fallbacks(&cfg);
    }

    let choice = match &args.out {
        Some(dir) => {
            if let Err(e) = folder::validate_record_dir(&dir.to_string_lossy()) {
                emit(
                    &serde_json::json!({"ev": "refused", "code": "folder_unwritable", "detail": e}),
                );
                bail!("{e}");
            }
            folder::resolve(Some(dir))
        }
        None => folder::resolve(None),
    };
    if args.where_only {
        emit(&serde_json::json!({"ev": "where", "dir": choice.dir, "reason": choice.reason}));
        return Ok(());
    }
    if let Some(reason) = &choice.reason {
        tracing::info!(folder = %choice.dir.display(), %reason, "recording: folder fallback");
        emit(&serde_json::json!({"ev": "folder", "path": choice.dir, "reason": reason}));
    }

    let initiator = match &args.remote_user_id {
        Some(id) => Initiator::Remote {
            controller_user_id: id.clone(),
            controller_name: args.remote_user_name.clone(),
        },
        None => Initiator::Local {
            user: std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .ok(),
        },
    };
    let name = folder::unique_recording_name(&choice.dir, chrono::Local::now());
    let mut opts = RecordOptions::new(choice.dir.clone(), name, initiator);
    opts.fps = args.fps;
    opts.max_duration = Duration::from_secs(u64::from(args.max_minutes.max(1)) * 60);

    // A recorder that died (a crash, a killed parent, an update's Restart
    // Manager) left its partial behind: finalize it now, as the identity that
    // owns this folder. Beside this recording, not before it — a multi-GB
    // remux must not hold up `started` (the daemon waits 20 s for it) — and
    // safe beside it: this recording's partial is locked from its creation.
    let reconcile = {
        let staging = opts.staging();
        let dest = opts.dest_dir.clone();
        tokio::task::spawn_blocking(move || {
            for p in recorder::reconcile_partials(&staging, &dest) {
                emit(&serde_json::json!({"ev": "recovered", "path": p}));
            }
        })
    };

    let (factory, keeps_gop) = match encoder_factory(&args.encoder, opts.fps, opts.gop_seconds) {
        Ok(v) => v,
        Err(e) => {
            emit(
                &serde_json::json!({"ev": "refused", "code": "encoder_unavailable", "detail": format!("{e:#}")}),
            );
            return Err(e);
        }
    };
    opts.encoder_keeps_gop = keeps_gop;

    // FR-85 P1c — audio, both sources default OFF; a source asked for and not
    // opened refuses the whole start, by name.
    let audio = match open_audio(args.system_audio, args.microphone) {
        Ok(a) => a,
        Err((refusal, detail)) => {
            emit(&serde_json::json!({"ev": "refused", "code": refusal.as_str(), "detail": detail}));
            bail!("{detail}");
        }
    };

    // The recorder's own capturer, at native resolution — never the live
    // pump's capped rung — and with the pointer in its frames wherever the
    // backend can draw it (FR-85 P1d).
    let capturer = crate::capture::open_for_recording(opts.fps);

    let (stop_tx, stop_rx) = watch::channel::<Option<StopReason>>(None);
    let stop_tx = Arc::new(stop_tx);
    // stdin: commands, and EOF = the parent is gone.
    //
    // ⚠️ A detached std thread, NOT `tokio::io::stdin()`: tokio reads stdin on
    // a blocking-pool thread, and the runtime waits for its blocking threads
    // at shutdown — so a recorder told to stop while its parent kept stdin
    // open finalized, reported `stopped`, and then never exited (the
    // `the_stop_command_finalizes_and_reports_the_file` test caught it). A
    // detached thread dies with the process.
    {
        let stop_tx = stop_tx.clone();
        std::thread::Builder::new()
            .name("meshharbord-rec-stdin".into())
            .spawn(move || {
                use std::io::BufRead as _;
                for line in std::io::stdin().lock().lines() {
                    let Ok(line) = line else { break };
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<StdinCommand>(line) {
                        Ok(c) if c.cmd == "stop" => {
                            request_stop(&stop_tx, stop_reason_from(c.reason.as_deref()));
                        }
                        Ok(c) => tracing::warn!(cmd = %c.cmd, "recording: unknown command ignored"),
                        Err(e) => tracing::warn!(%e, "recording: unparseable command ignored"),
                    }
                }
                // EOF or a read error: whoever launched us is gone.
                request_stop(&stop_tx, StopReason::ParentGone);
            })
            .map_err(|e| anyhow::anyhow!("recording: cannot start the stdin reader: {e}"))?;
    }
    {
        let stop_tx = stop_tx.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                request_stop(&stop_tx, StopReason::Requested);
            }
        });
    }

    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<RecorderEvent>();
    let printer = tokio::spawn(async move {
        while let Some(ev) = ev_rx.recv().await {
            if let Ok(v) = serde_json::to_value(&ev) {
                emit(&v);
            }
        }
    });

    let result = recorder::run_with_audio(opts, capturer, factory, audio, stop_rx, ev_tx).await;
    let _ = printer.await;
    // Never exit mid-remux: a killed remux is safe (it writes a temp and
    // renames), but it is work the next recorder would only have to redo.
    let _ = reconcile.await;
    match result {
        Ok(summary) => {
            tracing::info!(reason = summary.reason.as_str(), path = ?summary.path, "recording: finished");
            Ok(())
        }
        Err(e) => {
            let (code, detail) = match e.downcast_ref::<StartError>() {
                Some(se) => (se.refusal.as_str().to_string(), se.detail.clone()),
                None => ("error".to_string(), format!("{e:#}")),
            };
            emit(
                &serde_json::json!({"ev": if code == "error" { "error" } else { "refused" }, "code": code, "detail": detail}),
            );
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_stop_reasons_map_to_the_closed_set() {
        assert_eq!(stop_reason_from(None), StopReason::Requested);
        assert_eq!(
            stop_reason_from(Some("host_stopped")),
            StopReason::HostStopped
        );
        assert_eq!(
            stop_reason_from(Some("gate_revoked")),
            StopReason::GateRevoked
        );
        assert_eq!(
            stop_reason_from(Some("something_from_a_newer_parent")),
            StopReason::Requested
        );
    }

    #[test]
    fn stdin_commands_parse() {
        let c: StdinCommand =
            serde_json::from_str(r#"{"cmd":"stop","reason":"host_stopped"}"#).unwrap();
        assert_eq!(c.cmd, "stop");
        assert_eq!(c.reason.as_deref(), Some("host_stopped"));
        let bare: StdinCommand = serde_json::from_str(r#"{"cmd":"stop"}"#).unwrap();
        assert!(bare.reason.is_none());
    }

    #[test]
    fn an_unknown_encoder_preference_is_refused() {
        assert!(encoder_factory("quantum", 30, 2).is_err());
    }

    #[test]
    fn the_first_stop_reason_wins() {
        let (tx, rx) = watch::channel(None);
        request_stop(&tx, StopReason::Requested);
        request_stop(&tx, StopReason::ParentGone);
        assert_eq!(*rx.borrow(), Some(StopReason::Requested));
    }

    #[test]
    fn only_prefixed_lines_are_protocol() {
        let v = parse_event_line(r#"MESHHARBOR_REC_JSON:{"ev":"started"}"#).unwrap();
        assert_eq!(v["ev"], "started");
        // A log line on the same stdout is ignored, not an error.
        assert!(
            parse_event_line("2026-09-25T15:00:00Z INFO meshharbord: recording: started").is_none()
        );
        assert!(
            parse_event_line(r#"{"ev":"started"}"#).is_none(),
            "unprefixed JSON is not protocol"
        );
        // CRLF from a Windows child.
        assert!(parse_event_line("MESHHARBOR_REC_JSON:{\"ev\":\"stopped\"}\r").is_some());
    }
}
