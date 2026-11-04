// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Cross-platform archive extraction for the tunnel CLI download.
//!
//! Two callers, one entry point: [`extract_archive`] sniffs the
//! filename + does the right thing per platform.
//!
//! - **Windows**: tunnel CLI ships as `.zip` (see
//!   `.github/workflows/release-tunnel.yml`). Use the pure-Rust `zip`
//!   crate to extract into the per-user install dir.
//! - **Linux/macOS**: tunnel CLI ships as `.tar.gz`. Use `flate2` to
//!   stream-decompress, then `tar` to walk entries.
//!
//! Both paths protect against the **zip-slip** vulnerability: an
//! archive entry named `../../etc/passwd` would otherwise write
//! outside the destination dir. We reject any entry whose normalised
//! path escapes the dest root, with a clear error so the wizard can
//! surface "tampered archive — please retry".
//!
// RETIRED-NAME-ANCHOR-BEGIN
// This module exists to extract archives the project ALREADY PUBLISHED, so
// every retired name below is an input it must keep accepting, not a name it
// chooses. The probe tries the current name first and the retired one second;
// the tests pin both. Removing the retired arm breaks upgrades from any
// tunnel release older than FR-21. docs/fr/FR-21 D6
//! The archives produced by `release-tunnel.yml` carry a single
//! top-level directory (`roomler-tunnel-<version>-<target>/`); the
//! caller (orchestrator) walks one level deep to find the `roomler-
//! tunnel` binary after extraction.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

/// Extract `archive` into `dest_dir`. The dest dir is created if
/// missing. Existing files inside dest_dir are overwritten.
///
/// Sniffs the format from the filename: `.zip` → ZIP, `.tar.gz` /
/// `.tgz` → gzipped tar. Anything else returns an error so the
/// orchestrator can surface "unexpected archive type {ext}".
pub fn extract_archive(archive: &Path, dest_dir: &Path) -> Result<()> {
    fs::create_dir_all(dest_dir)
        .with_context(|| format!("creating dest dir {}", dest_dir.display()))?;

    let lower = archive
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if lower.ends_with(".zip") {
        extract_zip(archive, dest_dir)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        extract_tar_gz(archive, dest_dir)
    } else {
        Err(anyhow!(
            "unexpected archive extension on {} (want .zip / .tar.gz / .tgz)",
            archive.display()
        ))
    }
}

/// Extract a ZIP archive into `dest_dir`. Refuses any entry whose
/// joined path escapes `dest_dir` (zip-slip protection).
pub fn extract_zip(archive: &Path, dest_dir: &Path) -> Result<()> {
    let file =
        fs::File::open(archive).with_context(|| format!("opening zip {}", archive.display()))?;
    let mut zip =
        zip::ZipArchive::new(file).with_context(|| format!("parsing zip {}", archive.display()))?;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).with_context(|| format!("zip entry {i}"))?;
        let raw_name = entry
            .enclosed_name()
            .ok_or_else(|| anyhow!("zip entry {i} has unsafe path {:?}", entry.name()))?;

        let safe_path = sanitize_path(dest_dir, &raw_name)?;

        if entry.is_dir() {
            fs::create_dir_all(&safe_path)
                .with_context(|| format!("mkdir {}", safe_path.display()))?;
            continue;
        }
        if let Some(parent) = safe_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("mkdir parent {}", parent.display()))?;
        }
        let mut out = fs::File::create(&safe_path)
            .with_context(|| format!("create {}", safe_path.display()))?;
        io::copy(&mut entry, &mut out)
            .with_context(|| format!("extract → {}", safe_path.display()))?;

        // Restore unix permissions when they're present on the entry
        // (Linux/macOS archives carry these; ZIP-from-Windows doesn't).
        // The tunnel CLI binary needs the executable bit set so the
        // operator can run it post-install without a manual chmod.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                let _ = fs::set_permissions(&safe_path, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

/// Extract a `.tar.gz` archive into `dest_dir`. Refuses any entry
/// whose joined path escapes `dest_dir` (zip-slip protection — same
/// vuln class applies to tar).
pub fn extract_tar_gz(archive: &Path, dest_dir: &Path) -> Result<()> {
    let file =
        fs::File::open(archive).with_context(|| format!("opening tar.gz {}", archive.display()))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(gz);
    // Default `unpack` behaviour preserves permissions on unix — we
    // want that for the executable bit. We don't use `unpack` directly
    // because we need our own sanitisation; instead we walk entries
    // and write each one through the same helper as the ZIP path.
    for entry_result in tar.entries().context("reading tar entries")? {
        let mut entry = entry_result.context("reading tar entry")?;
        let raw_path = entry.path().context("reading tar entry path")?;
        let safe_path = sanitize_path(dest_dir, &raw_path)?;

        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(&safe_path)
                .with_context(|| format!("mkdir {}", safe_path.display()))?;
            continue;
        }
        if kind.is_symlink() {
            // Symlinks in the CLI archive are limited to the universal
            // macOS layout (lipo'd binary) where they don't carry
            // privileges. We follow the upstream `tar::Archive`
            // behaviour here: extract the link target verbatim. Same
            // zip-slip rule applies though — refuse if the *target*
            // escapes dest_dir.
            let link_target = entry
                .link_name()
                .context("reading symlink target")?
                .ok_or_else(|| anyhow!("symlink entry missing link_name"))?;
            // Refuse absolute targets outright; relative targets get
            // normalised against the symlink's parent dir.
            let resolved = safe_path
                .parent()
                .map(|p| p.join(&link_target))
                .unwrap_or_else(|| dest_dir.join(&link_target));
            check_within(dest_dir, &resolved)?;
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(&safe_path);
                std::os::unix::fs::symlink(&link_target, &safe_path)
                    .with_context(|| format!("symlink → {}", safe_path.display()))?;
            }
            #[cfg(not(unix))]
            {
                // Windows: emit a regular file with the target's
                // contents if possible, else skip with a warning.
                // CLI archives shouldn't have symlinks targeting the
                // wizard's Win install layout, so this branch is
                // defensive.
                tracing::warn!(
                    "skipping symlink {} → {} on non-unix host",
                    safe_path.display(),
                    link_target.display()
                );
            }
            continue;
        }
        if let Some(parent) = safe_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("mkdir parent {}", parent.display()))?;
        }
        let mut out = fs::File::create(&safe_path)
            .with_context(|| format!("create {}", safe_path.display()))?;
        io::copy(&mut entry, &mut out)
            .with_context(|| format!("extract → {}", safe_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mode) = entry.header().mode() {
                let _ = fs::set_permissions(&safe_path, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

/// Resolve `entry` against `dest_dir` while rejecting any path that
/// climbs above the dest root (`..`) or starts with a root component
/// (`/foo`, `C:\foo`).
///
/// This is the zip-slip guard. Tested directly so a regression here
/// can't ship silently.
fn sanitize_path(dest_dir: &Path, entry: &Path) -> Result<PathBuf> {
    // Reject absolute paths AND any `..` component up front — the
    // safe answer is "extract under dest_dir or refuse entirely",
    // never "let canonicalize sort it out" (canonicalize requires the
    // file to already exist on disk).
    let mut clean = PathBuf::new();
    for comp in entry.components() {
        match comp {
            Component::Normal(seg) => clean.push(seg),
            Component::CurDir => {}
            Component::ParentDir => {
                bail!("archive entry contains '..' component: {}", entry.display());
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("archive entry is absolute: {}", entry.display());
            }
        }
    }
    let joined = dest_dir.join(&clean);
    check_within(dest_dir, &joined)?;
    Ok(joined)
}

/// Defence-in-depth: even after [`sanitize_path`] has stripped `..`
/// + absolute prefixes, a corner case (UNC, weird Unicode normalisation)
/// could still produce a path that escapes the dest root. Verify by
/// component-prefix comparison, which doesn't require the path to
/// exist on disk yet.
fn check_within(dest_dir: &Path, candidate: &Path) -> Result<()> {
    let dest_components: Vec<_> = dest_dir.components().collect();
    let cand_components: Vec<_> = candidate.components().collect();
    if cand_components.len() < dest_components.len() {
        bail!(
            "archive entry escapes dest dir: {} not under {}",
            candidate.display(),
            dest_dir.display()
        );
    }
    for (i, dest_comp) in dest_components.iter().enumerate() {
        if cand_components[i] != *dest_comp {
            bail!(
                "archive entry escapes dest dir: {} not under {}",
                candidate.display(),
                dest_dir.display()
            );
        }
    }
    Ok(())
}

/// Walk one level into `extracted_root` looking for the tunnel CLI
/// binary. The CLI archive layout is
/// `<extracted_root>/roomler-tunnel-<version>-<target>/<binary>`,
/// where `<binary>` has shipped under BOTH names since the P3d
/// rename: `roomler{.exe}` (current) and `roomler-tunnel{.exe}`
/// (compat alias). P4b flips the preference to the NEW name so
/// installs land the end-state binary; the legacy name stays as a
/// fallback so pre-P3d archives still resolve. Returns the full path
/// to the binary.
///
/// Tolerates the archive being unpacked flat (binary directly under
/// `extracted_root`) for forward-compat with future layouts.
pub fn find_tunnel_binary(extracted_root: &Path) -> Result<PathBuf> {
    let candidate_names: [&str; 2] = if cfg!(target_os = "windows") {
        ["roomler.exe", "roomler-tunnel.exe"]
    } else {
        // RETIRED-NAME-ANCHOR: member names inside ALREADY-PUBLISHED tarballs.
        // The extractor must keep accepting them. docs/fr/FR-21
        ["roomler", "roomler-tunnel"]
    };

    // Flat layout? New name wins when both are present.
    for name in candidate_names {
        let flat = extracted_root.join(name);
        if flat.is_file() {
            return Ok(flat);
        }
    }

    // Single-subdir layout (the canonical one). Within each subdir
    // the new name wins; across subdirs, directory-iteration order
    // decides (the canonical archive has exactly one subdir).
    for entry in fs::read_dir(extracted_root)
        .with_context(|| format!("readdir {}", extracted_root.display()))?
    {
        let entry = entry.context("reading dir entry")?;
        for name in candidate_names {
            let candidate = entry.path().join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(anyhow!(
        "could not locate {} (or legacy {}) under {}",
        candidate_names[0],
        candidate_names[1],
        extracted_root.display()
    ))
}

// Helper for tests so we don't depend on the `zip-from-buffer` API in
// every assertion. Builds an in-memory ZIP with the given entries.
#[cfg(test)]
fn build_zip_to_path(path: &Path, entries: &[(&str, &[u8])]) -> Result<()> {
    use std::io::Write;
    let file = fs::File::create(path).context("creating test zip")?;
    let mut writer = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, opts).context("zip start_file")?;
        writer.write_all(bytes).context("zip write_all")?;
    }
    writer.finish().context("zip finish")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn extract_zip_writes_expected_files() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("test.zip");
        let dest = tmp.path().join("out");
        build_zip_to_path(
            &archive,
            &[
                ("roomler-tunnel-1.2.3-target/roomler-tunnel.exe", b"binary"),
                ("roomler-tunnel-1.2.3-target/README.txt", b"readme"),
            ],
        )
        .unwrap();
        extract_zip(&archive, &dest).unwrap();
        let bin = dest
            .join("roomler-tunnel-1.2.3-target")
            .join("roomler-tunnel.exe");
        assert!(bin.is_file());
        let bytes = std::fs::read(&bin).unwrap();
        assert_eq!(bytes, b"binary");
    }

    #[test]
    fn extract_archive_dispatches_by_extension() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("test.zip");
        let dest = tmp.path().join("out");
        build_zip_to_path(&archive, &[("file.txt", b"hi")]).unwrap();
        extract_archive(&archive, &dest).unwrap();
        assert!(dest.join("file.txt").is_file());
    }

    #[test]
    fn extract_archive_rejects_unknown_extension() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("test.rar");
        std::fs::write(&archive, b"not a real rar").unwrap();
        let err = extract_archive(&archive, &tmp.path().join("out")).unwrap_err();
        assert!(format!("{err}").contains("unexpected archive extension"));
    }

    #[test]
    fn sanitize_path_accepts_normal_relative() {
        let dest = PathBuf::from(if cfg!(windows) {
            r"C:\tmp\out"
        } else {
            "/tmp/out"
        });
        let entry = PathBuf::from("foo/bar.txt");
        let resolved = sanitize_path(&dest, &entry).unwrap();
        assert!(resolved.ends_with(PathBuf::from("foo/bar.txt")));
    }

    #[test]
    fn sanitize_path_rejects_parent_dir_climb() {
        let dest = PathBuf::from(if cfg!(windows) {
            r"C:\tmp\out"
        } else {
            "/tmp/out"
        });
        let entry = PathBuf::from("../etc/passwd");
        let err = sanitize_path(&dest, &entry).unwrap_err();
        assert!(format!("{err}").contains(".."));
    }

    #[test]
    fn sanitize_path_rejects_absolute_unix() {
        let dest = PathBuf::from(if cfg!(windows) {
            r"C:\tmp\out"
        } else {
            "/tmp/out"
        });
        let entry = PathBuf::from(if cfg!(windows) {
            r"C:\Windows\system32"
        } else {
            "/etc/passwd"
        });
        let err = sanitize_path(&dest, &entry).unwrap_err();
        assert!(format!("{err}").contains("absolute"));
    }

    #[test]
    fn extract_zip_blocks_zip_slip() {
        let tmp = TempDir::new().unwrap();
        let archive = tmp.path().join("test.zip");
        let dest = tmp.path().join("out");
        // `../escape.txt` would write to the parent of `dest`.
        build_zip_to_path(&archive, &[("../escape.txt", b"bad")]).unwrap();
        // `enclosed_name` in the zip crate already rejects ".." paths,
        // so we may either fail at enclosed_name OR at sanitize_path.
        // Either error message is acceptable — both mean the entry was
        // refused.
        let err = extract_zip(&archive, &dest).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("..") || msg.contains("unsafe path"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn find_tunnel_binary_locates_under_single_subdir() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp
            .path()
            .join("roomler-tunnel-0.3.0-rc.46-x86_64-pc-windows-msvc");
        std::fs::create_dir_all(&sub).unwrap();
        let bin_name = if cfg!(target_os = "windows") {
            "roomler-tunnel.exe"
        } else {
            "roomler-tunnel"
        };
        std::fs::write(sub.join(bin_name), b"binary").unwrap();
        let found = find_tunnel_binary(tmp.path()).unwrap();
        assert_eq!(found.file_name().unwrap(), bin_name);
    }

    #[test]
    fn find_tunnel_binary_locates_flat_layout() {
        let tmp = TempDir::new().unwrap();
        let bin_name = if cfg!(target_os = "windows") {
            "roomler-tunnel.exe"
        } else {
            "roomler-tunnel"
        };
        std::fs::write(tmp.path().join(bin_name), b"binary").unwrap();
        let found = find_tunnel_binary(tmp.path()).unwrap();
        assert_eq!(found.file_name().unwrap(), bin_name);
    }

    #[test]
    fn find_tunnel_binary_errors_when_missing() {
        let tmp = TempDir::new().unwrap();
        let err = find_tunnel_binary(tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("could not locate"));
    }

    // P4b: the archives ship BOTH names since P3d; the NEW name must
    // win at every layout level so installs land the end-state binary.
    #[test]
    fn find_tunnel_binary_prefers_new_name_when_both_present() {
        let (new_name, old_name) = if cfg!(target_os = "windows") {
            ("roomler.exe", "roomler-tunnel.exe")
        } else {
            ("roomler", "roomler-tunnel")
        };
        // Flat layout.
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(new_name), b"new").unwrap();
        std::fs::write(tmp.path().join(old_name), b"old").unwrap();
        let found = find_tunnel_binary(tmp.path()).unwrap();
        assert_eq!(found.file_name().unwrap(), new_name);
        // Single-subdir layout.
        let tmp = TempDir::new().unwrap();
        let sub = tmp
            .path()
            .join("roomler-tunnel-0.3.0-rc.195-x86_64-pc-windows-msvc");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(new_name), b"new").unwrap();
        std::fs::write(sub.join(old_name), b"old").unwrap();
        let found = find_tunnel_binary(tmp.path()).unwrap();
        assert_eq!(found.file_name().unwrap(), new_name);
    }

    #[test]
    fn find_tunnel_binary_finds_new_name_alone() {
        let new_name = if cfg!(target_os = "windows") {
            "roomler.exe"
        } else {
            "roomler"
        };
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("some-archive-dir");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(new_name), b"binary").unwrap();
        let found = find_tunnel_binary(tmp.path()).unwrap();
        assert_eq!(found.file_name().unwrap(), new_name);
    }
}
// RETIRED-NAME-ANCHOR-END
