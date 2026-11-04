// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P5a — `roomlerd media`: the editor's engine as a process of its own.
//!
//! meshharbor-desktop launches it AS THE PERSON (never the daemon): the files are
//! theirs, in their folder, and a codec fault in an export costs this process,
//! nothing else. It speaks the recorder's protocol — one JSON event per stdout
//! line, prefixed like `roomlerd record`'s ([`super::child::parse_event_line`]
//! reads both).
//!
//! - `probe <file>` → one `probe` event: length, size, rate, and whether this
//!   build can edit it (`editable`, and why not).
//! - `export --edl <file>` → `progress` events, then `done` (the new file,
//!   frames, length, bytes, and what its sound carries: `audio`), or
//!   `refused` with a closed `code`.
//!
//! An export stops on `{"cmd":"cancel"}` on stdin, and leaves nothing
//! behind. End of stdin does NOT cancel: a finished file is harmless, and an
//! export started with stdin closed (a script) must still run.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use serde_json::json;

use super::child::emit;
use super::edit::EditList;
use super::export::{self, ExportError};
use super::mp4::{self, ProgressiveFile};

/// `roomlerd media probe <file>`.
pub fn probe(file: &Path) -> Result<()> {
    let read = || -> Result<serde_json::Value> {
        let pf = ProgressiveFile::open(file)?;
        let format = pf.video_format()?;
        let samples = pf.samples(mp4::VIDEO_TRACK_ID)?;
        let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
            bail!("the recording has no video");
        };
        let ts = u64::from(format.timescale);
        let duration_ms = (last.dts - first.dts + u64::from(last.duration)) * 1000 / ts;
        let audio = pf
            .samples(mp4::AUDIO_TRACK_ID)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        // P4 — High profile is editable where FFmpeg's decoder is linked in.
        let editable = super::decode::can_decode(format.profile);
        Ok(json!({
            "ev": "probe",
            "duration_ms": duration_ms,
            "width": format.width,
            "height": format.height,
            "frames": samples.len(),
            "profile": format.profile,
            "audio": audio,
            "editable": editable,
            "reason": (!editable).then(|| ExportError::DecoderUnavailable { profile: format.profile }.detail()),
        }))
    };
    match read() {
        Ok(ev) => {
            emit(&ev);
            Ok(())
        }
        Err(e) => {
            emit(
                &json!({"ev": "refused", "code": "source_unreadable", "detail": format!("{e:#}")}),
            );
            Err(e)
        }
    }
}

/// `roomlerd media export --edl <file> [--encoder …]`.
pub async fn export(edl_path: &Path, encoder: &str) -> Result<()> {
    let refuse = |code: &str, detail: String| -> Result<()> {
        emit(&json!({"ev": "refused", "code": code, "detail": detail}));
        bail!("{code}: {detail}")
    };
    let text = match std::fs::read_to_string(edl_path) {
        Ok(t) => t,
        Err(e) => return refuse("bad_edit_list", format!("{}: {e}", edl_path.display())),
    };
    let edits: EditList = match serde_json::from_str(&text) {
        Ok(l) => l,
        Err(e) => return refuse("bad_edit_list", format!("{}: {e}", edl_path.display())),
    };
    // The list names its recording, bare, in its own folder: nothing it says
    // can reach a file anywhere else.
    if let Err(e) = super::manager::check_recording_name(&edits.source) {
        return refuse("bad_edit_list", e);
    }
    let dir = edl_path.parent().map(Path::to_path_buf).unwrap_or_default();
    let source: PathBuf = dir.join(&edits.source);
    let Some(dest) = export::edited_name(&source) else {
        return refuse(
            "write_failed",
            format!("no free name beside {}", source.display()),
        );
    };

    // The encoder runs at the rate the engine will feed it: the source's,
    // decided the same way (the commonest sample, not a stall).
    let fps = ProgressiveFile::open(&source)
        .and_then(|pf| {
            let f = pf.video_format()?;
            Ok(export::source_fps(
                &pf.samples(mp4::VIDEO_TRACK_ID)?,
                f.timescale,
            ))
        })
        .unwrap_or(30);
    let (factory, _) = match super::child::encoder_factory(encoder, fps, 2) {
        Ok(f) => f,
        Err(e) => return refuse("encoder_unavailable", format!("{e:#}")),
    };

    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel = cancel.clone();
        // A detached std thread, as the recorder's: a blocking read the
        // runtime would otherwise wait on at shutdown.
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if serde_json::from_str::<serde_json::Value>(&line)
                    .is_ok_and(|v| v["cmd"] == "cancel")
                {
                    cancel.store(true, Ordering::Release);
                    break;
                }
            }
        });
    }

    emit(&json!({"ev": "started", "source": source, "path": dest}));
    let result = export::export(&source, &edits, &dest, factory, &cancel, |done, total| {
        emit(&json!({"ev": "progress", "frames": done, "total": total}));
    })
    .await;
    match result {
        Ok(s) => {
            emit(&json!({
                "ev": "done",
                "path": s.path,
                "frames": s.frames,
                "duration_ms": s.duration_ms,
                "bytes": s.bytes,
                "encoder": s.encoder,
                // What the file's sound is: `none`, `original`, `music`,
                // `original_and_music`, or `not_carried` (the recording had
                // audio this build cannot encode) — never a silent file
                // presented as the whole export.
                "audio": s.audio,
            }));
            Ok(())
        }
        Err(e) => refuse(e.code(), e.detail()),
    }
}
