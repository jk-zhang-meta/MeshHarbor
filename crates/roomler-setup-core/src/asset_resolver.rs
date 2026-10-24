// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Artifact resolution + download — the shared streaming machinery
//! behind both wizards' `asset_resolver` wrappers (and the unified
//! `roomler-setup` app).
//!
//! The wizards hit roomler.ai's installer proxies (`/api/agent/
//! installer/{flavour}`, `/api/tunnel/installer/{platform}`) instead
//! of downloading directly from `github.com`: corporate ESET /
//! Defender allow-lists are typically per-domain; `roomler.ai`'s TLS
//! cert is already trusted by IT, `github.com` is often blocked
//! outright (field-reproduced 2026-05-11).
//!
//! Layering (P4a): this module owns the wire mechanics — health GET,
//! chunked streaming download, SHA256 verification. The CALLERS own
//! everything identity-shaped: proxy-base env-var resolution, temp
//! staging namespaces, User-Agent strings, and origin/suffix
//! stripping. That split is what lets the two legacy wizards keep
//! byte-identical wire behaviour through their wrappers while the
//! unified app uses the same code with its own identity.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// This crate cannot depend on either updater. Keep the boundary at the shared
// setup transport so every installer and companion uses the caller-selected proxy.
fn trusted_url(raw: &str) -> Result<reqwest::Url> {
    let path = raw.split('?').next().unwrap_or(raw);
    let lower = path.to_ascii_lowercase();
    if path.contains('\\')
        || raw.chars().any(|c| c.is_control())
        || ["%2e", "%2f", "%5c", "%25", "%00", "%0a", "%0d"]
            .iter()
            .any(|s| lower.contains(s))
        || path
            .split_once("://")
            .and_then(|(_, p)| p.split_once('/'))
            .is_some_and(|(_, p)| p.split('/').any(|c| c == "." || c == ".."))
    {
        bail!("ambiguous setup artifact URL");
    }
    let url = reqwest::Url::parse(raw).context("invalid setup artifact URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.host_str().is_some_and(|h| h.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("setup artifacts require HTTPS without userinfo or fragment");
    }
    Ok(url)
}

fn center_boundary(raw: &str) -> Result<reqwest::Url> {
    let mut url = trusted_url(raw)?;
    if url.query().is_some() {
        bail!("setup center base must not contain a query");
    }
    url.set_path(&format!("{}/", url.path().trim_end_matches('/')));
    Ok(url)
}

fn endpoint_boundary(raw: &str) -> Result<reqwest::Url> {
    let mut url = trusted_url(raw)?;
    let path = url.path().trim_end_matches('/');
    let prefix = [
        "/api/agent/installer",
        "/api/tunnel/installer",
        "/api/tunnel-wizard",
        "/api/agent/latest-release",
        "/api/tunnel/latest-release",
        "/api/setup/latest-release",
    ]
    .iter()
    .find_map(|s| path.strip_suffix(s))
    .unwrap_or(path)
    .to_string();
    url.set_path(&prefix);
    url.set_query(None);
    center_boundary(url.as_str())
}

fn scoped_url(boundary: &reqwest::Url, raw: &str) -> Result<reqwest::Url> {
    let url = trusted_url(raw)?;
    if url.origin() != boundary.origin() || !url.path().starts_with(boundary.path()) {
        bail!("setup artifact URL escaped the configured center origin/prefix");
    }
    Ok(url)
}

fn http_client(
    boundary: reqwest::Url,
    user_agent: &str,
    timeout: Duration,
) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() < 3 && scoped_url(&boundary, attempt.url().as_str()).is_ok()
            {
                attempt.follow()
            } else {
                attempt.error("setup redirect escaped its configured center or redirect budget")
            }
        }))
        .build()
        .context("building reqwest client")
}

/// Unified mirror of the backend's installer-health JSON. The agent
/// endpoint (`agent_release.rs`) returns the discriminator as
/// `flavour`, the tunnel endpoint (`tunnel_release.rs`) as
/// `platform` — the serde aliases fold either into [`Self::target`].
/// Deser-only unification is safe: nothing re-serializes health onto
/// a wire (the `Serialize` derive is kept for parity with the legacy
/// structs' derives).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactHealth {
    /// Resolved tag, e.g. `agent-v0.3.0-rc.28` / `tunnel-v0.3.0-rc.46`.
    pub tag: String,
    /// Normalised flavour/platform discriminator — whatever the
    /// caller asked the endpoint for (`"peruser"`, `"permachine"`,
    /// `"windows-x86_64"`, …).
    #[serde(alias = "flavour", alias = "platform")]
    pub target: String,
    // RETIRED-NAME-ANCHOR(8): names a PUBLISHED release asset. Filenames are fixed by
    // what is already on GitHub Releases (FR-21 D6).
    /// Canonical asset filename, e.g.
    /// `roomler-agent-0.3.0-rc.28-perMachine-x86_64-pc-windows-msvc.msi`.
    pub filename: String,
    /// Asset size in bytes.
    pub size: u64,
    /// `"sha256:<hex>"` from GitHub's `digest` field. None on
    /// releases that pre-date the field.
    pub digest: Option<String>,
    /// Relative URI to stream the artifact bytes from. The caller
    /// composes it against its proxy origin for the download GET.
    pub uri: String,
}

/// Fetch the JSON metadata for the matching artifact. Used before
/// kicking the download so the progress bar has a denominator and the
/// wizard can pre-validate the SHA256 digest format.
///
/// `base` is the caller's already-normalised proxy base (no trailing
/// slash); `user_agent` is caller-supplied so each wizard keeps its
/// historical wire-visible UA.
pub async fn resolve(
    base: &str,
    target: &str,
    version: &str,
    user_agent: &str,
) -> Result<ArtifactHealth> {
    let boundary = endpoint_boundary(base)?;
    let url = format!("{base}/{target}/health?version={version}");
    scoped_url(&boundary, &url)?;
    let client = http_client(boundary.clone(), user_agent, Duration::from_secs(30))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "installer-health GET {url} returned {}",
            resp.status()
        ));
    }
    let health: ArtifactHealth = resp.json().await.context("parsing installer-health JSON")?;
    if !health.uri.starts_with('/') || health.uri.starts_with("//") {
        bail!("installer-health uri must be a center-relative absolute path");
    }
    scoped_url(
        &boundary,
        &format!("{}{}", boundary.as_str().trim_end_matches('/'), health.uri),
    )?;
    Ok(health)
}

/// Identity-shaped inputs to [`download`] the caller owns: the fully
/// composed URL, the full staging destination path, the User-Agent,
/// and the artifact label used in error messages (`"installer"` for
/// the agent wizard, `"CLI archive"` for the tunnel wizard — kept
/// caller-supplied so the legacy error strings stay byte-identical).
pub struct DownloadSpec<'a> {
    /// Actual caller-selected center/proxy base, including its deployment prefix.
    /// Never derive this authority from the manifest's untrusted download URL.
    pub center_base: &'a str,
    /// Absolute URL (proxy origin + `health.uri`), caller-composed.
    pub url: &'a str,
    /// Full staging path (the caller owns the temp-namespace
    /// convention, e.g. `%TEMP%\roomler-setup\{tag}\{filename}`).
    pub dest: &'a Path,
    pub user_agent: &'a str,
    /// Label interpolated into error messages.
    pub artifact_label: &'a str,
}

/// Stream the artifact bytes to `spec.dest`, firing
/// `on_progress(received_bytes)` after each chunk; the SPA throttles
/// UI updates client-side.
///
/// `cancel` is checked before each chunk write — callers that don't
/// want mid-stream abort (the legacy wizards, preserving their
/// step-boundary-only cancel granularity) pass a never-true static.
///
/// Does NOT call [`verify_sha256`] itself — the caller chains them so
/// the orchestrator can emit a `DownloadVerified` ProgressEvent only
/// after both succeed.
pub async fn download<F: FnMut(u64)>(
    spec: &DownloadSpec<'_>,
    cancel: &AtomicBool,
    mut on_progress: F,
) -> Result<()> {
    let boundary = center_boundary(spec.center_base)?;
    let url = scoped_url(&boundary, spec.url)?;
    let client = http_client(boundary, spec.user_agent, Duration::from_secs(15 * 60))?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {}", spec.url))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "{} GET {} returned {}",
            spec.artifact_label,
            spec.url,
            resp.status()
        ));
    }

    if let Some(parent) = spec.dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating staging dir {}", parent.display()))?;
    }
    use futures::StreamExt;
    let mut file = tokio::fs::File::create(spec.dest)
        .await
        .with_context(|| format!("creating staging file {}", spec.dest.display()))?;
    let mut received: u64 = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        if cancel.load(Ordering::Relaxed) {
            return Err(anyhow!("download cancelled"));
        }
        let bytes = chunk.with_context(|| format!("reading {} chunk", spec.artifact_label))?;
        use tokio::io::AsyncWriteExt;
        file.write_all(&bytes)
            .await
            .with_context(|| format!("writing staging file {}", spec.dest.display()))?;
        received += bytes.len() as u64;
        on_progress(received);
    }
    use tokio::io::AsyncWriteExt;
    file.flush().await.context("flushing staging file")?;
    drop(file);

    Ok(())
}

/// Exact immutable center-side signature route for a health-resolved package.
pub fn release_signature_url(center_base: &str, tag: &str, filename: &str) -> Result<String> {
    let boundary = center_boundary(center_base)?;
    let token = |value: &str| {
        !value.is_empty()
            && value.len() <= 236
            && !matches!(value, "." | "..")
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-+".contains(&c))
    };
    if !token(tag)
        || !token(filename)
        || !["agent-v", "tunnel-v", "setup-v"]
            .iter()
            .any(|p| tag.starts_with(p) && tag.len() > p.len())
    {
        bail!("invalid resolved release tag or filename for signature");
    }
    let mut url = boundary.clone();
    url.path_segments_mut()
        .map_err(|_| anyhow!("center cannot contain artifact path"))?
        .pop_if_empty()
        .extend(["api", "agent", "artifacts", tag, &format!("{filename}.asc")]);
    scoped_url(&boundary, url.as_str())?;
    Ok(url.into())
}

/// Manifest asset sidecar: suffix is part of PATH, never the version query.
pub fn detached_signature_url(center_base: &str, artifact_url: &str) -> Result<String> {
    let boundary = center_boundary(center_base)?;
    let mut url = scoped_url(&boundary, artifact_url)?;
    url.set_path(&format!("{}.asc", url.path()));
    scoped_url(&boundary, url.as_str())?;
    Ok(url.into())
}

/// Remote auto-install is fail closed on missing/invalid detached signatures.
/// The app supplies the existing pinned verifier; core adds no crypto/dependency.
/// No caller may unpack/execute before this helper succeeds. Local-artifact
/// installation does not call this remote-only path and keeps its explicit SHA.
pub async fn download_signed<F: FnMut(u64)>(
    spec: &DownloadSpec<'_>,
    signature_url: &str,
    cancel: &AtomicBool,
    verifier: fn(&[u8], &str) -> Result<()>,
    on_progress: F,
) -> Result<()> {
    const MAX_SIGNATURE: usize = 1024 * 1024;
    const MAX_ARTIFACT: u64 = 512 * 1024 * 1024;
    let boundary = center_boundary(spec.center_base)?;
    scoped_url(&boundary, spec.url)?;
    let signature_url = scoped_url(&boundary, signature_url)?;
    let client = http_client(boundary, spec.user_agent, Duration::from_secs(30))?;
    let response = client
        .get(signature_url)
        .send()
        .await
        .context("fetching required release signature")?
        .error_for_status()
        .context("missing release signature: refusing unsigned artifact")?;
    if response
        .content_length()
        .is_some_and(|n| n > MAX_SIGNATURE as u64)
    {
        bail!("release signature exceeds size limit");
    }
    use futures::StreamExt;
    let mut signature = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        if cancel.load(Ordering::Relaxed) {
            bail!("signature download cancelled");
        }
        let chunk = chunk.context("reading release signature")?;
        if signature.len().saturating_add(chunk.len()) > MAX_SIGNATURE {
            bail!("release signature exceeds size limit");
        }
        signature.extend_from_slice(&chunk);
    }
    let signature =
        std::str::from_utf8(&signature).context("release signature is not UTF-8 armor")?;
    let result = async {
        download(spec, cancel, on_progress).await?;
        let file = tokio::fs::File::open(spec.dest)
            .await
            .context("opening staged artifact for signature")?;
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        file.take(MAX_ARTIFACT + 1)
            .read_to_end(&mut bytes)
            .await
            .context("reading bounded staged artifact")?;
        if bytes.len() as u64 > MAX_ARTIFACT {
            bail!("signed artifact exceeds size limit");
        }
        if cancel.load(Ordering::Relaxed) {
            bail!("signature verification cancelled");
        }
        verifier(&bytes, signature).context("release PGP signature verification failed")
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(spec.dest).await;
    }
    result
}

/// A companion asset located by [`find_release_asset`] — a binary
/// served straight off a GitHub Release (e.g. the `roomler-desktop`
/// GUI EXE) rather than through a health-manifest installer proxy.
#[derive(Clone, Debug)]
pub struct ReleaseAsset {
    /// Download URL (GitHub `browser_download_url` from the
    /// latest-release list).
    pub url: String,
    pub filename: String,
    /// `"sha256:<hex>"` when the release carries the digest field.
    pub digest: Option<String>,
}

// Deser-only mirrors of the `/api/*/latest-release` JSON. Local to
// core (NO roomlerd dep — D8 dep hygiene; core never links the
// agent/tunnel crates).
#[derive(Deserialize)]
struct RelListEntry {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<RelListAsset>,
}
#[derive(Deserialize)]
struct RelListAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

/// GET a `.../latest-release` list and locate a companion asset: the
/// first non-draft release whose tag starts with `tag_prefix`, and
/// within it the first asset whose lower-cased name CONTAINS
/// `name_contains` and ends with `suffix` (skipping `.sha256`
/// sidecars). Returns `None` when nothing matches (older server /
/// missing asset) so the caller degrades gracefully. Used by the
/// daemon orchestrator to place `roomler-desktop` (GAP-A / P6) — the
/// GUI companion isn't in the MSI, it's a standalone release EXE.
pub async fn find_release_asset(
    latest_release_url: &str,
    tag_prefix: &str,
    name_contains: &str,
    suffix: &str,
    user_agent: &str,
) -> Result<Option<ReleaseAsset>> {
    let boundary = endpoint_boundary(latest_release_url)?;
    scoped_url(&boundary, latest_release_url)?;
    let client = http_client(boundary.clone(), user_agent, Duration::from_secs(30))?;
    let resp = client
        .get(latest_release_url)
        .send()
        .await
        .with_context(|| format!("GET {latest_release_url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "GET {latest_release_url} returned {}",
            resp.status()
        ));
    }
    let releases: Vec<RelListEntry> = resp.json().await.context("parse latest-release list")?;
    let nc = name_contains.to_ascii_lowercase();
    let sfx = suffix.to_ascii_lowercase();
    for rel in releases {
        if rel.draft || !rel.tag_name.starts_with(tag_prefix) {
            continue;
        }
        for a in rel.assets {
            let lower = a.name.to_ascii_lowercase();
            if lower.ends_with(".sha256") || !lower.contains(&nc) || !lower.ends_with(&sfx) {
                continue;
            }
            scoped_url(&boundary, &a.browser_download_url)?;
            return Ok(Some(ReleaseAsset {
                url: a.browser_download_url,
                filename: a.name,
                digest: a.digest,
            }));
        }
    }
    Ok(None)
}

/// Detect the current platform string the backend understands. The
/// wizard EXE runs on the same OS+arch as the CLI it's about to
/// install, so the platform discriminator is whatever the wizard
/// itself was compiled for.
pub fn current_platform() -> &'static str {
    // Matches the backend's `normalise_platform` enum-shape used in
    // both tunnel_release.rs and setup_release.rs.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "windows-x86_64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Wizard defaults to the plain tarball; the `.deb` variant is
        // a packaging detail for fleet installs, not what a
        // double-clicked wizard EXE consumes.
        "linux-x86_64"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        // FR-97 P7b — the aarch64 wizard installs the aarch64 CLI. Before
        // it this said "unsupported", and the wizard refused on an arm64
        // host with UnsupportedPlatform.
        "linux-aarch64"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "macos"
    )))]
    {
        // FreeBSD, Windows on ARM, etc. — the wizard doesn't ship for
        // these, but the const has to exist so the crate compiles.
        // Backend will 404 for an unknown platform.
        "unsupported"
    }
}

/// Verify a staged artifact's SHA256 against the digest from
/// [`ArtifactHealth`]. Returns `Ok(true)` on match, `Ok(false)` on
/// mismatch, `Err` on malformed digest or read error.
///
/// Accepts `digest` either as `"sha256:<hex>"` (the canonical GitHub
/// shape forwarded by the backend) or as bare hex. Hex is
/// case-insensitive.
pub fn verify_sha256(staged: &Path, expected_digest: &str) -> Result<bool> {
    let hex = expected_digest
        .strip_prefix("sha256:")
        .unwrap_or(expected_digest);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "expected sha256 digest as 64 hex chars (optional sha256: prefix); got {expected_digest:?}"
        ));
    }
    let bytes = std::fs::read(staged).with_context(|| format!("reading {}", staged.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = hasher.finalize();
    let actual_hex = hex_encode(&actual);
    Ok(actual_hex.eq_ignore_ascii_case(hex))
}

/// Lowercase hex encoder. The `hex` crate would suffice but the
/// 6-line helper predates this crate and the legacy wizards' test
/// suites pin its behaviour; public so the wrapper crates' tests can
/// keep exercising it through `use`.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn verify_sha256_matches_correct_hash() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello.bin");
        std::fs::write(&path, b"hello").unwrap();
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(&path, digest).unwrap());
    }

    #[test]
    fn verify_sha256_rejects_wrong_hash() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello.bin");
        std::fs::write(&path, b"hello").unwrap();
        let bogus = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_sha256(&path, bogus).unwrap());
    }

    #[test]
    fn verify_sha256_accepts_bare_hex_without_prefix() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello.bin");
        std::fs::write(&path, b"hello").unwrap();
        let bare = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(&path, bare).unwrap());
    }

    #[test]
    fn verify_sha256_case_insensitive() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello.bin");
        std::fs::write(&path, b"hello").unwrap();
        let upper = "sha256:2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824";
        assert!(verify_sha256(&path, upper).unwrap());
    }

    #[test]
    fn verify_sha256_rejects_short_digest() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello.bin");
        std::fs::write(&path, b"hello").unwrap();
        let err = verify_sha256(&path, "sha256:abc").unwrap_err();
        assert!(format!("{err}").contains("64 hex"));
    }

    #[test]
    fn verify_sha256_rejects_non_hex() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hello.bin");
        std::fs::write(&path, b"hello").unwrap();
        let err = verify_sha256(
            &path,
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("hex"));
    }

    #[test]
    fn hex_encode_lowercase() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn current_platform_returns_a_supported_value_on_this_host() {
        let plat = current_platform();
        assert!(
            matches!(
                plat,
                "windows-x86_64" | "linux-x86_64" | "linux-aarch64" | "macos" | "unsupported"
            ),
            "unexpected platform {plat:?}"
        );
        // FR-97 P7b — an aarch64 Linux build names its own arch, never the
        // x86_64 token (which would install a CLI it cannot run).
        if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            assert_eq!(plat, "linux-aarch64");
        }
    }

    #[test]
    fn artifact_health_deserialises_flavour_alias() {
        // Agent endpoint shape (agent_release.rs): `flavour`.
        //
        // ⚠️ The anchor below once sat INSIDE the raw JSON string, where the
        // name audit reads it as a comment but serde reads it as JSON — the
        // fixture stopped parsing and this test failed for as long as no CI
        // lane ran this crate. Anchors go in Rust comments, never in a literal.
        // RETIRED-NAME-ANCHOR(5): names a PUBLISHED release asset. Filenames are
        // fixed by what is already on GitHub Releases (FR-21 D6); this fixture
        // is a copy of a real GitHub asset list.
        let h: ArtifactHealth = serde_json::from_str(
            r#"{"tag":"agent-v0.3.0-rc.28","flavour":"permachine",
                "filename":"roomler-agent-0.3.0-rc.28-perMachine-x86_64-pc-windows-msvc.msi",
                "size":123,"digest":null,
                "uri":"/api/agent/installer/permachine?version=latest"}"#,
        )
        .unwrap();
        assert_eq!(h.target, "permachine");
    }

    #[test]
    fn artifact_health_deserialises_platform_alias() {
        // Tunnel endpoint shape (tunnel_release.rs): `platform`.
        // RETIRED-NAME-ANCHOR(3): the same — a real published asset's name.
        let h: ArtifactHealth = serde_json::from_str(
            r#"{"tag":"tunnel-v0.3.0-rc.46","platform":"windows-x86_64",
                "filename":"roomler-tunnel-0.3.0-rc.46-x86_64-pc-windows-msvc.zip",
                "size":456,"digest":"sha256:00","uri":"/api/tunnel/installer/windows-x86_64?version=latest"}"#,
        )
        .unwrap();
        assert_eq!(h.target, "windows-x86_64");
        assert_eq!(h.digest.as_deref(), Some("sha256:00"));
    }
}
