// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D6 — the desktop companion's own per-user state: has this person
//! been through the Welcome tour, and did they turn "Start Roomler at login"
//! off for their account.
//!
//! It lives here rather than in the companion because TWO processes read it:
//! the companion, which owns it, and `meshharbord service install` on a per-user
//! Windows install, which registers the login start and must not put it back
//! for someone who turned it off.
//!
//! The file is `<per-user data dir>/desktop/desktop-state.json`, next to the
//! companion's own log (`desktop_log.rs`). A missing, unreadable or corrupt
//! file is a FIRST RUN — the Welcome shows — and never an error: the worst a
//! bad file can cost is one more look at the tour.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// File name inside the companion's data dir.
pub const FILE_NAME: &str = "desktop-state.json";

/// The per-user state. Unknown keys a newer companion wrote are carried
/// through a load/save by an older one (`extra`), so a downgrade cannot
/// quietly erase a choice.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DesktopState {
    /// The person finished (or explicitly skipped) the Welcome tour.
    #[serde(default)]
    pub first_run_done: bool,
    /// The person turned "Start Roomler at login" off for their account.
    #[serde(default)]
    pub autostart_opt_out: bool,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `<per-user data dir>/desktop/desktop-state.json`; `None` when the
/// platform exposes no data dir at all.
pub fn default_path() -> Option<PathBuf> {
    crate::appdirs::project_dirs().map(|d| d.data_local_dir().join("desktop").join(FILE_NAME))
}

/// Read the state. Missing, unreadable or corrupt ⇒ the default, which is a
/// first run.
pub fn load_from(path: &Path) -> DesktopState {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return DesktopState::default();
    };
    match serde_json::from_str::<DesktopState>(&raw) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "desktop state unreadable — treating this as a first run"
            );
            DesktopState::default()
        }
    }
}

/// Write the state atomically (temp file + rename), creating the directory.
/// A crash mid-write leaves either the old file or the new one, never half
/// of either — and a half file would read as a first run anyway.
pub fn save_to(path: &Path, state: &DesktopState) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, body)?;
    // `rename` replaces an existing target on every platform we ship to
    // (`MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows).
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// [`load_from`] at [`default_path`]; the default when there is no path.
pub fn load() -> DesktopState {
    default_path().map(|p| load_from(&p)).unwrap_or_default()
}

/// [`save_to`] at [`default_path`].
pub fn save(state: &DesktopState) -> std::io::Result<()> {
    let path = default_path().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no per-user data directory")
    })?;
    save_to(&path, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_a_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let s = load_from(&dir.path().join("desktop").join(FILE_NAME));
        assert!(!s.first_run_done, "no file ⇒ show the Welcome");
        assert!(!s.autostart_opt_out, "no file ⇒ nobody opted out");
    }

    /// A half-written or hand-mangled file must neither crash the companion
    /// nor be read as "done": both would take the Welcome away from someone
    /// who never saw it.
    #[test]
    fn a_corrupt_file_is_a_first_run_not_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        for junk in [
            "",
            "{",
            "not json at all",
            "[1,2,3]",
            "{\"first_run_done\": \"yes\"}",
        ] {
            std::fs::write(&path, junk).unwrap();
            let s = load_from(&path);
            assert_eq!(
                s,
                DesktopState::default(),
                "{junk:?} must read as a first run"
            );
        }
    }

    #[test]
    fn state_round_trips_and_creates_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desktop").join(FILE_NAME);
        let s = DesktopState {
            first_run_done: true,
            autostart_opt_out: true,
            ..DesktopState::default()
        };
        save_to(&path, &s).unwrap();
        assert_eq!(load_from(&path), s);
        // No temp file is left behind by the atomic write.
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [FILE_NAME]);
    }

    /// A newer companion's keys survive an older one's save.
    #[test]
    fn unknown_keys_survive_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(
            &path,
            r#"{"first_run_done":false,"welcome_step":3,"autostart_opt_out":false}"#,
        )
        .unwrap();
        let mut s = load_from(&path);
        s.first_run_done = true;
        save_to(&path, &s).unwrap();
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["welcome_step"], 3);
        assert_eq!(raw["first_run_done"], true);
    }
}
