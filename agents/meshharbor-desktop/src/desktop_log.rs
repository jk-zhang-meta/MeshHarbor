// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D1 — the companion's own file log.
//!
//! The daemon has a persistent rolling log; the companion had stderr only —
//! and a tray app has no stderr anyone reads, so every error a poller
//! swallowed was gone the moment it happened. The Routes page blanked every
//! few seconds for weeks with nothing anywhere saying why. This writes the
//! same `tracing` events to a small size-capped file under the per-user data
//! dir (`…/roomler/roomler/data/desktop/desktop.log`, one rotated generation
//! kept as `desktop.log.1`), so "what did the companion see" has an answer.
//!
//! Size-capped rather than daily-rolling on purpose: a companion on a
//! never-rebooted workstation runs for months, and a 2 s poller that logs
//! only failures (rate-limited — see `commands::RefreshLedger`) produces
//! kilobytes, not megabytes. Two generations of [`MAX_BYTES`] bound the disk
//! cost regardless of uptime.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Cap per generation. The previous generation is kept, so the worst case on
/// disk is twice this.
pub const MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Where the log lives: `<per-user data dir>/desktop/desktop.log`. `None`
/// when the platform exposes no data dir at all (then stderr is all there
/// is, as before).
pub fn default_path() -> Option<PathBuf> {
    meshharbor_node_core::appdirs::project_dirs()
        .map(|d| d.data_local_dir().join("desktop").join("desktop.log"))
}

/// The rotated generation next to `path`: `desktop.log` → `desktop.log.1`.
pub fn rotated_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".1");
    PathBuf::from(p)
}

/// An append-only file that rotates to `<path>.1` when the NEXT write would
/// carry it past `cap` — so a generation is never split mid-line (the fmt
/// layer hands a whole event per `write`).
pub struct CappedFile {
    path: PathBuf,
    cap: u64,
    file: Option<File>,
    written: u64,
}

impl CappedFile {
    /// Open (creating the parent dir) for append; `written` starts at the
    /// file's current size so a restart continues the same generation.
    pub fn open(path: PathBuf, cap: u64) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            cap,
            file: Some(file),
            written,
        })
    }

    /// Bytes written to the current generation (including what it held
    /// when opened). Only the tests read it back; the writer itself keeps
    /// the count in `self.written`.
    #[cfg(test)]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Move the current generation aside and start a fresh one. Closes the
    /// handle first: Windows refuses to rename an open file. If the rename
    /// itself fails (a reader holding the file), truncate in place instead
    /// — losing history beats growing without bound.
    fn rotate(&mut self) -> std::io::Result<()> {
        self.file = None;
        let previous = rotated_path(&self.path);
        let _ = std::fs::remove_file(&previous);
        let renamed = std::fs::rename(&self.path, &previous);
        let mut opts = OpenOptions::new();
        opts.create(true);
        if renamed.is_ok() {
            opts.append(true);
        } else {
            opts.write(true).truncate(true);
        }
        self.file = Some(opts.open(&self.path)?);
        self.written = 0;
        Ok(())
    }
}

impl Write for CappedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written > 0 && self.written + buf.len() as u64 > self.cap {
            self.rotate()?;
        }
        let file = match self.file.as_mut() {
            Some(f) => f,
            None => {
                // A failed rotation left no handle; reopen for append.
                self.file = Some(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&self.path)?,
                );
                self.file.as_mut().expect("just set")
            }
        };
        let n = file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

/// Install the tracing subscriber: stderr (as before) plus the capped file
/// when the per-user data dir resolves and the file opens. Returns the log
/// path when file logging is on, so `main` can say where it is. Infallible
/// — a companion that cannot log must still surface consent prompts.
pub fn init() -> Option<PathBuf> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr = fmt::layer().with_target(false).with_writer(std::io::stderr);
    let path = default_path();
    let file = path
        .as_ref()
        .and_then(|p| CappedFile::open(p.clone(), MAX_BYTES).ok());
    match file {
        Some(f) => {
            let file_layer = fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(Mutex::new(f));
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stderr)
                .with(file_layer)
                .try_init();
            path
        }
        None => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stderr)
                .try_init();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "meshharbor-desktop-log-{}-{nanos}",
                std::process::id()
            ))
            .join(name)
            .join("desktop.log")
    }

    /// The cap is a cap: past it the file rotates to `.1` at a line
    /// boundary, the newest line lands in the fresh generation, and the
    /// disk footprint stays within two generations.
    #[test]
    fn capped_file_rotates_at_the_cap_and_keeps_one_generation() {
        let path = scratch("rotate");
        let cap = 100;
        let mut f = CappedFile::open(path.clone(), cap).unwrap();
        // Ten 30-byte lines against a 100-byte cap: rotations before lines
        // 03, 06 and 09. One `write_all` per line, as the fmt layer does
        // (it formats the whole event first, then writes it in one call).
        for i in 0..10 {
            let line = format!("line {i:02} {}\n", "x".repeat(21));
            f.write_all(line.as_bytes()).unwrap();
        }
        f.flush().unwrap();
        let current = std::fs::read_to_string(&path).unwrap();
        let previous = std::fs::read_to_string(rotated_path(&path)).unwrap();
        assert!(
            current.len() as u64 <= cap,
            "current generation within the cap: {current:?}"
        );
        assert!(
            previous.len() as u64 <= cap,
            "kept generation within the cap: {previous:?}"
        );
        assert!(
            current.ends_with("line 09 xxxxxxxxxxxxxxxxxxxxx\n"),
            "newest line in the current file: {current:?}"
        );
        assert!(
            previous.contains("line 08"),
            "the generation before it is kept: {previous:?}"
        );
        assert!(
            !previous.contains("line 05"),
            "only ONE previous generation is kept: {previous:?}"
        );
        assert!(
            current.lines().all(|l| l.starts_with("line ")),
            "a rotation never splits a line: {current:?}"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// Reopening continues the same generation (a restart every day must
    /// not defeat the cap by starting the count at zero).
    #[test]
    fn capped_file_reopen_continues_the_generation() {
        let path = scratch("reopen");
        {
            let mut f = CappedFile::open(path.clone(), 1000).unwrap();
            writeln!(f, "first run").unwrap();
        }
        let f = CappedFile::open(path.clone(), 1000).unwrap();
        assert_eq!(f.written(), "first run\n".len() as u64);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn rotated_path_appends_a_generation_suffix() {
        assert_eq!(
            rotated_path(Path::new("C:/x/desktop.log")),
            PathBuf::from("C:/x/desktop.log.1")
        );
    }
}
