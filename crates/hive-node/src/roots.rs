// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Confining a session's folder to the device's `hive_roots`.
//!
//! A device lists the directory trees sessions may run in. The list is the
//! device's own (gate 4 of FR-90 — never pushable by the server), and the
//! check runs on the *resolved* path, so neither `..` nor a symlink inside a
//! root can lead a session outside it.

use std::path::{Path, PathBuf};

/// Why a folder is not allowed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootsError {
    /// ⚠️ An empty `hive_roots` means **nowhere**, never "anywhere" — the
    /// overlay ACL's `Some([])`-means-deny lesson, applied before anyone ships
    /// the other reading.
    #[error("no hive_roots are configured on this device, so sessions may run nowhere")]
    NoRoots,
    #[error("{path} cannot be resolved: {reason}")]
    Unresolvable { path: PathBuf, reason: String },
    #[error("{path} is outside every hive_roots entry")]
    OutsideRoots { path: PathBuf },
}

/// Resolve `folder` and confirm it lies within one of `roots`. Returns the
/// resolved path — the one the session must actually use, so the check and the
/// use cannot disagree.
///
/// A root that does not resolve (deleted, mistyped) is skipped: it can contain
/// nothing. The folder itself must exist.
pub fn confine(folder: &Path, roots: &[PathBuf]) -> Result<PathBuf, RootsError> {
    if roots.is_empty() {
        return Err(RootsError::NoRoots);
    }
    let resolved = folder
        .canonicalize()
        .map_err(|e| RootsError::Unresolvable {
            path: folder.to_path_buf(),
            reason: e.to_string(),
        })?;
    let inside = roots
        .iter()
        .filter_map(|r| r.canonicalize().ok())
        // `Path::starts_with` compares whole components: `/srv/a` does not
        // start with `/srv/ab`, unlike a string prefix check.
        .any(|root| resolved.starts_with(&root));
    if inside {
        Ok(resolved)
    } else {
        Err(RootsError::OutsideRoots { path: resolved })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roots_mean_nowhere() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(confine(dir.path(), &[]), Err(RootsError::NoRoots));
    }

    #[test]
    fn a_folder_inside_a_root_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        let repo = root.join("meshharbor");
        std::fs::create_dir_all(&repo).unwrap();
        let got = confine(&repo, std::slice::from_ref(&root)).unwrap();
        assert_eq!(got, repo.canonicalize().unwrap());
        // The root itself is allowed too.
        assert!(confine(&root, std::slice::from_ref(&root)).is_ok());
    }

    #[test]
    fn dot_dot_cannot_climb_out() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        let outside = dir.path().join("secrets");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let sneaky = root.join("..").join("secrets");
        assert!(matches!(
            confine(&sneaky, &[root]),
            Err(RootsError::OutsideRoots { .. })
        ));
    }

    #[test]
    fn a_sibling_with_a_shared_prefix_is_outside() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        let sibling = dir.path().join("src-other");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        assert!(matches!(
            confine(&sibling, &[root]),
            Err(RootsError::OutsideRoots { .. })
        ));
    }

    #[test]
    fn a_missing_folder_is_unresolvable_and_a_missing_root_contains_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        std::fs::create_dir_all(&root).unwrap();
        assert!(matches!(
            confine(&root.join("nope"), std::slice::from_ref(&root)),
            Err(RootsError::Unresolvable { .. })
        ));
        let gone = dir.path().join("gone");
        assert!(matches!(
            confine(&root, &[gone]),
            Err(RootsError::OutsideRoots { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_a_root_cannot_lead_outside() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        let outside = dir.path().join("etc");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let link = root.join("escape");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(matches!(
            confine(&link, &[root]),
            Err(RootsError::OutsideRoots { .. })
        ));
    }
}
