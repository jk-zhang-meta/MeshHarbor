// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — the rules for a recording folder (`record_dir`).
//!
//! Here, and not in `meshharbord`, because three parties must apply the SAME
//! rules: the config surface's validator (a `ConfigSet` of `record_dir`), the
//! recorder at start time, and meshharbor-desktop before it offers a folder the
//! daemon would then refuse. A validator each would drift.
//!
//! The rules: an absolute, local path; no `~` (never expanded); no UNC share
//! (a dropped link would cut a recording mid-write) and no `\\?\` / `\\.\`
//! device path; no `..`; and no symlink or junction among the components that
//! already exist. On Windows `FileType::is_symlink` is true for name-surrogate
//! reparse points — symlinks AND junctions — and false for cloud placeholders,
//! which is exactly the distinction wanted: a placeholder does not redirect a
//! path, a junction does.

use std::path::{Component, Path, PathBuf};

/// Validate a `record_dir` value. `Err` carries the config surface's error
/// text, which names the fix.
pub fn validate_record_dir(raw: &str) -> Result<PathBuf, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("record_dir: empty — unset the key to use the default folder".into());
    }
    if raw.starts_with('~') {
        return Err("record_dir: `~` is not expanded — give the full path".into());
    }
    if raw.starts_with(r"\\?\") || raw.starts_with(r"\\.\") || raw.starts_with("//?/") {
        return Err(
            "record_dir: device and verbatim paths (\\\\?\\, \\\\.\\) are not accepted".into(),
        );
    }
    if raw.starts_with(r"\\") || raw.starts_with("//") {
        return Err(
            "record_dir: network shares are not accepted — a dropped link would cut a recording mid-write"
                .into(),
        );
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err("record_dir: must be an absolute path".into());
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("record_dir: `..` is not accepted".into());
    }
    if let Some(link) = link_component(&path) {
        return Err(format!(
            "record_dir: {} is a symbolic link or junction — choose the folder it points to",
            link.display()
        ));
    }
    Ok(path)
}

/// The first existing component of `path`, below the filesystem root, that is
/// a symlink or a junction. `None` when there is none (or the path does not
/// exist yet past some point — a missing tail cannot be a link).
pub fn link_component(path: &Path) -> Option<PathBuf> {
    let mut cur = PathBuf::new();
    for (i, c) in path.components().enumerate() {
        cur.push(c.as_os_str());
        // Skip the prefix and root (`C:`, `\`, `/`).
        if i == 0 || matches!(c, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return Some(cur),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "meshharbor-fr85-recdir-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn refuses_what_it_should() {
        assert!(validate_record_dir("").is_err());
        assert!(validate_record_dir("   ").is_err());
        assert!(validate_record_dir("~/Videos").is_err());
        assert!(validate_record_dir("relative/dir").is_err());
        assert!(validate_record_dir(r"\\server\share\rec").is_err());
        assert!(validate_record_dir("//server/share/rec").is_err());
        assert!(validate_record_dir(r"\\?\C:\rec").is_err());
        assert!(validate_record_dir(r"\\.\PhysicalDrive0").is_err());
        let d = scratch("dots");
        assert!(validate_record_dir(&d.join("..").join("x").to_string_lossy()).is_err());
    }

    #[test]
    fn accepts_an_absolute_local_path_even_if_missing() {
        let d = scratch("ok").join("not-yet");
        assert_eq!(validate_record_dir(&d.to_string_lossy()).unwrap(), d);
        // Surrounding whitespace is trimmed, not part of the path.
        assert_eq!(
            validate_record_dir(&format!("  {}  ", d.to_string_lossy())).unwrap(),
            d
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_component() {
        let d = scratch("link");
        let target = d.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = validate_record_dir(&link.join("rec").to_string_lossy()).unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        // Positive control: the real folder is fine.
        assert!(validate_record_dir(&target.join("rec").to_string_lossy()).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_junction_component() {
        let d = scratch("junction");
        let target = d.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let junction = d.join("junction");
        // `mklink /J` needs no privilege (unlike a symlink).
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
        let err = validate_record_dir(&junction.join("rec").to_string_lossy()).unwrap_err();
        assert!(err.contains("junction"), "{err}");
        assert!(validate_record_dir(&target.join("rec").to_string_lossy()).is_ok());
    }
}
