// SPDX-License-Identifier: AGPL-3.0-only
//! The server's own release directory — releases served from OUR domain with
//! no GitHub in the path (`releases.local_dir`, `docs/self-hosted-releases.md`).
//!
//! Layout: `<dir>/<tag>/<file>`, where `<tag>` is an `agent-v*` / `tunnel-v*`
//! / `setup-v*` release tag and every artifact sits next to its detached
//! `<file>.asc`. A scan turns that tree into the same [`AgentRelease`] list
//! the GitHub cache produces, so every route, filter and picker downstream is
//! unchanged; only [`crate::release_delivery`] learns to stream from disk.
//!
//! ⚠️ This directory is a DELIVERY channel, never a trust anchor. The digest a
//! scan computes is a transport check computed by the same server that serves
//! the bytes — exactly the same-origin "proof" the agents already refuse to
//! trust on its own. What makes an artifact installable is its `.asc`
//! verifying against the key compiled into the agent (`pgp_verify`), and
//! `release_delivery` refuses to serve an artifact whose `.asc` is absent.
//!
//! What a scan admits, and why each rule exists:
//! - Tag directories and file names must pass `release_delivery::validate_path`
//!   — the same token rules as the GitHub path, so neither can carry a
//!   separator, a dot segment or an unknown family.
//! - Symlinks are skipped, never followed: whoever can drop a symlink into the
//!   directory must not get the server to stream an arbitrary file.
//! - Hidden entries (`.staging-*`, editor droppings) are skipped, so a publish
//!   that stages into a dot-directory and renames it into place is atomic from
//!   the reader's point of view.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use meshharbor_core::ApiError;
use sha2::{Digest, Sha256};

use crate::agent_release::{AgentRelease, AgentReleaseAsset};

/// How long one scan is reused. Short on purpose: there is no GitHub quota to
/// protect, and a release dropped into the directory should reach the fleet
/// within one agent check, without a refresh call.
pub(crate) const SCAN_TTL: Duration = Duration::from_secs(30);

/// Bounds on one scan, so a mis-pointed directory cannot make every release
/// request walk an unbounded tree.
const MAX_RELEASES: usize = 512;
const MAX_ASSETS_PER_RELEASE: usize = 64;

struct Scan {
    at: Instant,
    releases: Vec<AgentRelease>,
}

fn scans() -> &'static tokio::sync::Mutex<HashMap<PathBuf, Scan>> {
    static S: OnceLock<tokio::sync::Mutex<HashMap<PathBuf, Scan>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// Per file: the `(size, mtime)` it was hashed at and its `"sha256:<hex>"`.
type DigestMemo = HashMap<PathBuf, (u64, SystemTime, String)>;

/// So a rescan hashes only what changed: a replaced file changes size or
/// mtime and is hashed again.
fn digests() -> &'static Mutex<DigestMemo> {
    static D: OnceLock<Mutex<DigestMemo>> = OnceLock::new();
    D.get_or_init(Default::default)
}

/// The releases in `dir`, rescanned at most every [`SCAN_TTL`]. A failed
/// rescan serves the previous scan rather than break every client at once —
/// the same stale-on-error rule as the GitHub cache.
pub(crate) async fn cached(dir: &str) -> Result<Vec<AgentRelease>, ApiError> {
    let dir = PathBuf::from(dir);
    let mut guard = scans().lock().await;
    if let Some(s) = guard.get(&dir)
        && s.at.elapsed() < SCAN_TTL
    {
        return Ok(s.releases.clone());
    }
    let scan_dir = dir.clone();
    let result = tokio::task::spawn_blocking(move || scan(&scan_dir))
        .await
        .map_err(|_| ApiError::Internal("local release scan task failed".into()))?;
    match result {
        Ok(releases) => {
            guard.insert(
                dir,
                Scan {
                    at: Instant::now(),
                    releases: releases.clone(),
                },
            );
            Ok(releases)
        }
        Err(e) => {
            tracing::warn!(error = %e, "local release directory scan failed; serving the previous scan if any");
            guard
                .get(&dir)
                .map(|s| s.releases.clone())
                .ok_or_else(|| ApiError::Internal("local release directory unreadable".into()))
        }
    }
}

fn plain_name(entry: &std::fs::DirEntry) -> Option<String> {
    let name = entry.file_name().into_string().ok()?;
    (!name.starts_with('.')).then_some(name)
}

/// One synchronous pass over `dir`. Blocking I/O (it may hash new files):
/// call it from `spawn_blocking`.
pub(crate) fn scan(dir: &Path) -> std::io::Result<Vec<AgentRelease>> {
    let mut releases = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // `DirEntry::file_type` does not follow symlinks: a symlinked tag
        // directory is skipped, not resolved.
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(tag) = plain_name(&entry) else {
            continue;
        };
        if crate::release_delivery::validate_path(&tag, "probe").is_err() {
            continue;
        }
        let mut assets = Vec::new();
        for file in std::fs::read_dir(entry.path())? {
            let file = file?;
            if !file.file_type()?.is_file() {
                continue;
            }
            let Some(name) = plain_name(&file) else {
                continue;
            };
            if crate::release_delivery::validate_path(&tag, &name).is_err() {
                continue;
            }
            let path = file.path();
            let meta = file.metadata()?;
            let digest = digest_of(&path, meta.len(), meta.modified()?)?;
            assets.push(AgentReleaseAsset {
                // Never served: `release_delivery::own_urls` rewrites every
                // URL to the center's own `/api/agent/artifacts/...` before a
                // client sees it. A marker, not a filesystem path.
                browser_download_url: format!("local-release:{tag}/{name}"),
                name,
                size: meta.len(),
                digest: Some(digest),
                local_path: Some(path),
            });
            if assets.len() >= MAX_ASSETS_PER_RELEASE {
                break;
            }
        }
        assets.sort_by(|a, b| a.name.cmp(&b.name));
        releases.push(AgentRelease {
            tag_name: tag,
            draft: false,
            prerelease: false,
            published_at: None,
            assets,
        });
        if releases.len() >= MAX_RELEASES {
            break;
        }
    }
    Ok(releases)
}

fn digest_of(path: &Path, size: u64, mtime: SystemTime) -> std::io::Result<String> {
    if let Some((s, m, d)) = digests().lock().expect("digest memo").get(path)
        && *s == size
        && *m == mtime
    {
        return Ok(d.clone());
    }
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    digests()
        .lock()
        .expect("digest memo")
        .insert(path.to_path_buf(), (size, mtime, digest.clone()));
    Ok(digest)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};

    /// Self-removing scratch directory (the crate carries no `tempfile`).
    pub(crate) struct TempDir(PathBuf);
    impl TempDir {
        pub(crate) fn new() -> Self {
            let p =
                std::env::temp_dir().join(format!("mh-local-releases-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TempDir;
    use super::*;

    fn write(p: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    #[test]
    fn a_scan_lists_tag_dirs_with_their_files_digests_and_local_paths() {
        let d = TempDir::new();
        let deb = d
            .path()
            .join("agent-v0.4.152/meshharbord-0.4.152-x86_64-unknown-linux-gnu.deb");
        write(&deb, b"deb bytes");
        write(
            &d.path()
                .join("agent-v0.4.152/meshharbord-0.4.152-x86_64-unknown-linux-gnu.deb.asc"),
            b"sig",
        );
        let releases = scan(d.path()).unwrap();
        assert_eq!(releases.len(), 1);
        let r = &releases[0];
        assert_eq!(r.tag_name, "agent-v0.4.152");
        assert!(!r.draft && !r.prerelease);
        assert_eq!(r.assets.len(), 2);
        let a = &r.assets[0];
        assert_eq!(a.name, "meshharbord-0.4.152-x86_64-unknown-linux-gnu.deb");
        assert_eq!(a.size, 9);
        assert_eq!(
            a.digest.as_deref(),
            Some(format!("sha256:{}", hex::encode(Sha256::digest(b"deb bytes"))).as_str())
        );
        assert_eq!(a.local_path.as_deref(), Some(deb.as_path()));
        assert_eq!(
            r.assets[1].name,
            "meshharbord-0.4.152-x86_64-unknown-linux-gnu.deb.asc"
        );
    }

    #[test]
    fn hidden_unknown_family_and_unsafe_entries_are_skipped() {
        let d = TempDir::new();
        // A staging dir being published is invisible until it is renamed.
        write(&d.path().join(".staging-agent-v0.4.153/x.deb"), b"x");
        // Not a release family the routes serve.
        write(&d.path().join("vendored-ffmpeg-9/x.tar.gz"), b"x");
        // A loose file at the top level is not a release.
        write(&d.path().join("agent-v0.4.150.deb"), b"x");
        // Hidden file inside a real release.
        write(&d.path().join("agent-v0.4.152/.x.deb.swp"), b"x");
        write(&d.path().join("agent-v0.4.152/ok.deb"), b"ok");
        let releases = scan(d.path()).unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].tag_name, "agent-v0.4.152");
        let names: Vec<_> = releases[0].assets.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["ok.deb"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed() {
        let d = TempDir::new();
        let outside = TempDir::new();
        write(&outside.path().join("secret"), b"not a release");
        std::fs::create_dir_all(d.path().join("agent-v0.4.152")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            d.path().join("agent-v0.4.152/meshharbord.deb"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("agent-v0.4.153")).unwrap();
        let releases = scan(d.path()).unwrap();
        assert_eq!(releases.len(), 1, "the symlinked tag dir is skipped");
        assert!(
            releases[0].assets.is_empty(),
            "the symlinked file is skipped"
        );
    }

    #[test]
    fn a_replaced_file_is_hashed_again() {
        let d = TempDir::new();
        let p = d.path().join("agent-v0.4.152/a.deb");
        write(&p, b"one");
        let first = scan(d.path()).unwrap()[0].assets[0].digest.clone();
        write(&p, b"second version");
        let second = scan(d.path()).unwrap()[0].assets[0].digest.clone();
        assert_ne!(first, second);
        assert_eq!(
            second.as_deref(),
            Some(format!("sha256:{}", hex::encode(Sha256::digest(b"second version"))).as_str())
        );
    }

    /// The security property of `local_path`: it can be SET only by a scan.
    /// Deserialising a GitHub-shaped asset never yields one, and serialising a
    /// scanned asset never reveals one.
    #[test]
    fn local_path_never_crosses_serde_in_either_direction() {
        let parsed: AgentReleaseAsset = serde_json::from_str(
            r#"{"name":"a.deb","browser_download_url":"https://x/a.deb","size":1,"local_path":"/etc/shadow"}"#,
        )
        .unwrap();
        assert!(parsed.local_path.is_none());
        let d = TempDir::new();
        write(&d.path().join("agent-v0.4.152/a.deb"), b"a");
        let scanned = scan(d.path()).unwrap();
        let json = serde_json::to_string(&scanned).unwrap();
        assert!(!json.contains("local_path"), "{json}");
        assert!(!json.contains(d.path().to_str().unwrap()), "{json}");
    }

    #[tokio::test]
    async fn cached_serves_a_fresh_scan_and_reuses_it_within_the_ttl() {
        let d = TempDir::new();
        write(&d.path().join("agent-v0.4.152/a.deb"), b"a");
        let dir = d.path().to_str().unwrap().to_string();
        let first = cached(&dir).await.unwrap();
        assert_eq!(first.len(), 1);
        // Added inside the TTL: not visible yet, by design (bounded rescans).
        write(&d.path().join("agent-v0.4.153/a.deb"), b"a");
        assert_eq!(cached(&dir).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_unreadable_directory_with_no_previous_scan_is_an_error() {
        let d = TempDir::new();
        let missing = d.path().join("does-not-exist");
        assert!(cached(missing.to_str().unwrap()).await.is_err());
    }
}
