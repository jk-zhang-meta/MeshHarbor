// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P5c — the Edit view's commands: an edit list saved beside its
//! recording, the export engine (`meshharbord media`) run as the person, and a
//! preview the webview may play.
//!
//! - **The page never names a path.** Every file here is the daemon's
//!   recordings folder (its own listing) joined with a checked bare name, the
//!   rule `cmd_recording_open` follows. The music file is the one exception:
//!   it comes from the native file dialog, and the engine reads it as the
//!   person, so it reaches nothing they could not open themselves.
//! - **The engine runs as the person**, because this app does: the files are
//!   theirs, and a codec fault in an export costs that process, never this
//!   app or the daemon (P5a).
//! - **One export at a time**, polled like the rest of the app
//!   (`cmd_export_status`). `{"cmd":"cancel"}` on the engine's stdin stops
//!   it; closing this app does not (a finished file is harmless).
//! - **The preview** is the asset protocol, allowed one file at a time (the
//!   recording being edited), never the folder.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};

use meshharbor_localapi as localapi;
use serde::Serialize;

use crate::commands::{
    agent_exe_path, check_recording_name, daemon_unreachable, explain_recording_error,
    no_window_command,
};

/// The recorder's line protocol, which `meshharbord media` speaks too
/// (`recording::child::EVENT_PREFIX` in meshharbord).
const EVENT_PREFIX: &str = "MESHHARBOR_REC_JSON:";

/// An edit list this app writes is a few KiB; a bigger file is not one.
const MAX_EDIT_LIST_BYTES: usize = 256 * 1024;

/// What the engine reads as music (symphonia's formats in meshharbord).
pub const MUSIC_EXTENSIONS: &[&str] = &["mp3", "m4a", "aac", "flac", "ogg", "oga", "wav"];

/// How much of the engine's stderr a failed export keeps.
const STDERR_TAIL: usize = 2048;

fn parse_event_line(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str(line.trim_end().strip_prefix(EVENT_PREFIX)?).ok()
}

/// `<name>.edit.json`, where meshharbord looks for it (`EditList::path_for`).
fn edit_list_name(name: &str) -> String {
    format!("{name}.edit.json")
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

async fn recordings_dir() -> Result<PathBuf, String> {
    let mut client = localapi::connect().await.map_err(daemon_unreachable)?;
    let listing = client
        .recordings_list()
        .await
        .map_err(|e| explain_recording_error(&e.to_string()))?;
    Ok(PathBuf::from(listing.dir))
}

/// A recording in the folder: a checked bare name, a regular file (a link
/// at a recording's name is refused, as the daemon's download refuses it).
fn recording_path(dir: &Path, name: &str) -> Result<PathBuf, String> {
    check_recording_name(name)?;
    let path = dir.join(name);
    let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a recording file", path.display()));
    }
    Ok(path)
}

/// Keep the last `max` bytes of a stream, reading ALL of it: a child whose
/// stderr pipe fills blocks on its next write, so a reader that stops early
/// hangs the export.
fn drain_tail(mut r: impl Read, max: usize) -> String {
    let mut keep: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                keep.extend_from_slice(&buf[..n]);
                if keep.len() > max {
                    keep.drain(..keep.len() - max);
                }
            }
        }
    }
    String::from_utf8_lossy(&keep).trim().to_string()
}

fn join_err(e: tokio::task::JoinError) -> String {
    format!("task join: {e}")
}

/// Whether this device's `meshharbord` has the export engine. The Edit button
/// shows only when it does: an older service refuses the subcommand.
#[tauri::command]
pub async fn cmd_media_available() -> bool {
    tokio::task::spawn_blocking(|| {
        let Ok(exe) = agent_exe_path() else {
            return false;
        };
        no_window_command(&exe)
            .args(["media", "--help"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
    .await
    .unwrap_or(false)
}

/// The engine's `probe` of a recording (length, size, whether it can be
/// edited and why not), or its `refused` answer, returned as it is: the page
/// says either.
#[tauri::command]
pub async fn cmd_media_probe(name: String) -> Result<serde_json::Value, String> {
    let dir = recordings_dir().await?;
    tokio::task::spawn_blocking(move || {
        let path = recording_path(&dir, &name)?;
        let exe = agent_exe_path()?;
        let out = no_window_command(&exe)
            .args(["media", "probe"])
            .arg(&path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("the export engine ({}): {e}", exe.display()))?;
        probe_answer(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
            format!(
                "the export engine gave no answer ({}): {}",
                out.status,
                drain_tail(&out.stderr[..], STDERR_TAIL)
            )
        })
    })
    .await
    .map_err(join_err)?
}

fn probe_answer(stdout: &str) -> Option<serde_json::Value> {
    stdout
        .lines()
        .filter_map(parse_event_line)
        .find(|e| matches!(e["ev"].as_str(), Some("probe" | "refused")))
}

/// The recording's saved edit list, `None` when it has none yet.
#[tauri::command]
pub async fn cmd_edit_load(name: String) -> Result<Option<serde_json::Value>, String> {
    let dir = recordings_dir().await?;
    tokio::task::spawn_blocking(move || load_edit_list(&dir, &name))
        .await
        .map_err(join_err)?
}

fn load_edit_list(dir: &Path, name: &str) -> Result<Option<serde_json::Value>, String> {
    check_recording_name(name)?;
    let path = dir.join(edit_list_name(name));
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() > MAX_EDIT_LIST_BYTES => Err(format!(
            "{} is too large to be an edit list",
            path.display()
        )),
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Save the page's edit list beside its recording.
#[tauri::command]
pub async fn cmd_edit_save(name: String, list: serde_json::Value) -> Result<(), String> {
    let dir = recordings_dir().await?;
    tokio::task::spawn_blocking(move || save_edit_list(&dir, &name, &list))
        .await
        .map_err(join_err)?
}

/// Check the one thing this app owns (the list names THIS recording; the
/// engine validates the rest and refuses by name), then replace the file
/// whole: a crash mid-write leaves the previous list, never half of one.
fn save_edit_list(dir: &Path, name: &str, list: &serde_json::Value) -> Result<(), String> {
    recording_path(dir, name)?;
    if list.get("source").and_then(|s| s.as_str()) != Some(name) {
        return Err(format!("the edit list must name {name:?}"));
    }
    let bytes = serde_json::to_vec_pretty(list).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_EDIT_LIST_BYTES {
        return Err("the edit list is too large".to_string());
    }
    let path = dir.join(edit_list_name(name));
    let tmp = dir.join(format!(".{}.tmp", edit_list_name(name)));
    std::fs::write(&tmp, &bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

/// Where an export stands, for the page's poll.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ExportStatus {
    /// The recording being (or last) exported.
    pub name: Option<String>,
    pub running: bool,
    pub frames: u64,
    pub total: u64,
    /// The engine's `done` event, as it said it (`path`, `duration_ms`,
    /// `bytes`, `audio`, …).
    pub done: Option<serde_json::Value>,
    /// Why it did not finish: the engine's own code, `cancelled`, or
    /// `engine_failed` for a run that ended without an answer.
    pub refused: Option<ExportRefusal>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportRefusal {
    pub code: String,
    pub detail: String,
}

impl ExportStatus {
    /// Fold one event of the engine's protocol in.
    fn apply(&mut self, ev: &serde_json::Value) {
        match ev["ev"].as_str() {
            Some("progress") => {
                self.frames = ev["frames"].as_u64().unwrap_or(self.frames);
                self.total = ev["total"].as_u64().unwrap_or(self.total);
            }
            Some("done") => {
                self.frames = ev["frames"].as_u64().unwrap_or(self.frames);
                self.done = Some(ev.clone());
            }
            Some("refused") => {
                self.refused = Some(ExportRefusal {
                    code: ev["code"].as_str().unwrap_or("refused").to_string(),
                    detail: ev["detail"].as_str().unwrap_or_default().to_string(),
                });
            }
            _ => {}
        }
    }

    /// The engine exited. A run that said neither `done` nor `refused` died
    /// (a crash, a kill), and the page is told so, never left at a bar that
    /// stopped moving.
    fn exited(&mut self, how: String) {
        self.running = false;
        if self.done.is_none() && self.refused.is_none() {
            self.refused = Some(ExportRefusal {
                code: "engine_failed".to_string(),
                detail: how,
            });
        }
    }
}

struct Job {
    status: Arc<Mutex<ExportStatus>>,
    stdin: Option<ChildStdin>,
}

static JOB: Mutex<Option<Job>> = Mutex::new(None);

/// Export `name` through its saved edit list, beside it. Resolves once the
/// engine is running; the page polls `cmd_export_status`.
#[tauri::command]
pub async fn cmd_export_start(
    name: String,
    encoder: Option<String>,
) -> Result<ExportStatus, String> {
    let encoder = encoder.unwrap_or_else(|| "auto".to_string());
    if !matches!(encoder.as_str(), "auto" | "hardware" | "software") {
        return Err(format!("{encoder:?} is not an encoder choice"));
    }
    let dir = recordings_dir().await?;
    tokio::task::spawn_blocking(move || start_export(&dir, &name, &encoder))
        .await
        .map_err(join_err)?
}

/// ⚠️ std's `Command` on Windows passes every inheritable handle this process
/// holds to the child (the #1035 class, where a DAEMON-lifetime child kept a
/// companion's ports). This child is the person's own, lives for one export,
/// and needs its three pipes, the one thing a bounded handle list would keep;
/// `cmd_check_update` spawns `meshharbord` the same way.
fn start_export(dir: &Path, name: &str, encoder: &str) -> Result<ExportStatus, String> {
    recording_path(dir, name)?;
    let mut job = lock(&JOB);
    if job.as_ref().is_some_and(|j| lock(&j.status).running) {
        return Err("An export is already running.".to_string());
    }
    let edl = dir.join(edit_list_name(name));
    if !edl.is_file() {
        return Err("There is no saved edit list beside the recording.".to_string());
    }
    let exe = agent_exe_path()?;
    let mut child = no_window_command(&exe)
        .args(["media", "export", "--edl"])
        .arg(&edl)
        .args(["--encoder", encoder])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("the export engine ({}): {e}", exe.display()))?;
    let status = Arc::new(Mutex::new(ExportStatus {
        name: Some(name.to_string()),
        running: true,
        ..Default::default()
    }));
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        return Err("the export engine's output could not be read".to_string());
    };
    let stdin = child.stdin.take();
    let shared = status.clone();
    let watch = std::thread::Builder::new()
        .name("export-engine".to_string())
        .spawn(move || {
            let stderr_tail = std::thread::spawn(move || drain_tail(stderr, STDERR_TAIL));
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some(ev) = parse_event_line(&line) {
                    lock(&shared).apply(&ev);
                }
            }
            let exit = child
                .wait()
                .map(|s| s.to_string())
                .unwrap_or_else(|e| e.to_string());
            let err = stderr_tail.join().unwrap_or_default();
            let how = if err.is_empty() {
                format!("the export engine ended without an answer ({exit})")
            } else {
                format!("the export engine ended without an answer ({exit}): {err}")
            };
            lock(&shared).exited(how);
        });
    if let Err(e) = watch {
        return Err(format!("a thread for the export: {e}"));
    }
    let snapshot = lock(&status).clone();
    *job = Some(Job { status, stdin });
    Ok(snapshot)
}

/// The current (or last) export's status; all-default when there has been
/// none.
#[tauri::command]
pub fn cmd_export_status() -> ExportStatus {
    lock(&JOB)
        .as_ref()
        .map(|j| lock(&j.status).clone())
        .unwrap_or_default()
}

/// Ask the running export to stop. It leaves nothing behind (P5a) and ends
/// `cancelled`.
#[tauri::command]
pub fn cmd_export_cancel() -> Result<(), String> {
    let mut job = lock(&JOB);
    let Some(j) = job.as_mut() else {
        return Ok(());
    };
    if !lock(&j.status).running {
        return Ok(());
    }
    if let Some(stdin) = j.stdin.as_mut() {
        stdin
            .write_all(b"{\"cmd\":\"cancel\"}\n")
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("cancelling the export: {e}"))?;
    }
    Ok(())
}

/// The native file picker for background music. `None` when the person
/// cancelled.
#[tauri::command]
pub async fn cmd_pick_music(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri::Manager as _;
    use tauri_plugin_dialog::DialogExt as _;
    tokio::task::spawn_blocking(move || {
        let mut dialog = app
            .dialog()
            .file()
            .set_title("Background music")
            .add_filter("Music", MUSIC_EXTENSIONS);
        if let Some(window) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&window);
        }
        Ok(dialog
            .blocking_pick_file()
            .and_then(|p| p.into_path().ok())
            .map(|p| p.to_string_lossy().into_owned()))
    })
    .await
    .map_err(join_err)?
}

/// The recording's path for the preview, once exactly that file is allowed
/// on the asset protocol. The page makes the URL (`convertFileSrc`).
#[tauri::command]
pub async fn cmd_preview_src(app: tauri::AppHandle, name: String) -> Result<String, String> {
    use tauri::Manager as _;
    let dir = recordings_dir().await?;
    let path = tokio::task::spawn_blocking(move || recording_path(&dir, &name))
        .await
        .map_err(join_err)??;
    app.asset_protocol_scope()
        .allow_file(&path)
        .map_err(|e| format!("the preview: {e}"))?;
    Ok(path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_prefix_is_the_recorders() {
        // meshharbord's `recording::child::EVENT_PREFIX`. A change there that is
        // not made here leaves every export looking like it never answered.
        let ev =
            parse_event_line("MESHHARBOR_REC_JSON:{\"ev\":\"done\",\"frames\":3}\r\n").unwrap();
        assert_eq!(ev["frames"], 3);
        assert!(parse_event_line("INFO a log line").is_none());
        assert!(parse_event_line("MESHHARBOR_REC_JSON:not json").is_none());
    }

    #[test]
    fn the_probe_answer_skips_log_lines_and_keeps_a_refusal() {
        let out = "starting\nMESHHARBOR_REC_JSON:{\"ev\":\"probe\",\"editable\":true}\n";
        assert_eq!(probe_answer(out).unwrap()["editable"], true);
        let out = "MESHHARBOR_REC_JSON:{\"ev\":\"refused\",\"code\":\"source_unreadable\"}\n";
        assert_eq!(probe_answer(out).unwrap()["code"], "source_unreadable");
        assert!(probe_answer("nothing\n").is_none());
    }

    #[test]
    fn an_export_is_folded_from_the_engines_events() {
        let mut s = ExportStatus {
            running: true,
            ..Default::default()
        };
        s.apply(&json!({"ev": "started", "path": "x (edited).mp4"}));
        s.apply(&json!({"ev": "progress", "frames": 30, "total": 150}));
        assert_eq!((s.frames, s.total), (30, 150));
        s.apply(&json!({"ev": "done", "frames": 150, "audio": "music"}));
        s.exited("exit code: 0".into());
        assert!(!s.running);
        assert_eq!(s.done.as_ref().unwrap()["audio"], "music");
        assert_eq!(s.refused, None, "a finished export is not a failure");
    }

    #[test]
    fn a_run_that_ends_without_an_answer_says_so() {
        let mut s = ExportStatus {
            running: true,
            ..Default::default()
        };
        s.apply(&json!({"ev": "progress", "frames": 30, "total": 150}));
        s.exited("the export engine ended without an answer (exit code: 101)".into());
        let r = s.refused.unwrap();
        assert_eq!(r.code, "engine_failed");
        assert!(r.detail.contains("101"), "{}", r.detail);

        // A refusal the engine SAID is kept as it said it.
        let mut s = ExportStatus {
            running: true,
            ..Default::default()
        };
        s.apply(&json!({"ev": "refused", "code": "cancelled", "detail": "stopped"}));
        s.exited("exit code: 1".into());
        assert_eq!(s.refused.unwrap().code, "cancelled");
    }

    #[test]
    fn the_stderr_tail_reads_everything_and_keeps_the_end() {
        let long = "x".repeat(100_000) + "the end";
        let tail = drain_tail(long.as_bytes(), 16);
        assert_eq!(tail.len(), 16);
        assert!(tail.ends_with("the end"));
    }

    fn folder() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.mp4"), b"not really").unwrap();
        d
    }

    #[test]
    fn an_edit_list_round_trips_beside_its_recording() {
        let d = folder();
        assert_eq!(load_edit_list(d.path(), "a.mp4").unwrap(), None);
        let list = json!({"version": 1, "source": "a.mp4", "segments": []});
        save_edit_list(d.path(), "a.mp4", &list).unwrap();
        assert!(
            d.path().join("a.mp4.edit.json").is_file(),
            "meshharbord's name"
        );
        assert_eq!(load_edit_list(d.path(), "a.mp4").unwrap(), Some(list));
        let left: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "no temporary file left: {left:?}");
    }

    #[test]
    fn an_edit_list_names_its_own_recording_and_nothing_else() {
        let d = folder();
        let other = json!({"version": 1, "source": "b.mp4", "segments": []});
        assert!(save_edit_list(d.path(), "a.mp4", &other).is_err());
        let list = json!({"version": 1, "source": "../a.mp4", "segments": []});
        assert!(save_edit_list(d.path(), "../a.mp4", &list).is_err());
        let list = json!({"version": 1, "source": "missing.mp4", "segments": []});
        assert!(
            save_edit_list(d.path(), "missing.mp4", &list).is_err(),
            "no recording, no edit list"
        );
        let huge = json!({"version": 1, "source": "a.mp4", "x": "y".repeat(MAX_EDIT_LIST_BYTES)});
        assert!(save_edit_list(d.path(), "a.mp4", &huge).is_err());
        assert!(!d.path().join("a.mp4.edit.json").exists());
    }

    #[test]
    fn a_directory_at_a_recordings_name_is_not_a_recording() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("dir.mp4")).unwrap();
        assert!(recording_path(d.path(), "dir.mp4").is_err());
        assert!(recording_path(d.path(), "absent.mp4").is_err());
    }
}
