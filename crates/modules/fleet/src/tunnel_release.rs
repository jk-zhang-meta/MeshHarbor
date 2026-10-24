// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR-BEGIN
// Serves PUBLISHED release assets. The `tunnel-v*` tag and the
// roomler-tunnel-<version>-<target> asset names are fixed by what is already
// on GitHub Releases — renaming them here serves 404s to every existing
// installer. Release asset names are frozen by FR-21 D6; the test fixtures
// below are copies of real asset lists and must match byte-for-byte.
//! `/api/tunnel/{latest-release,installer/{platform}}` — cached
//! GitHub-Releases proxy for the `roomler-tunnel` binary. Mirrors
//! [`routes::agent_release`] but targets `tunnel-v*` tags and
//! platform-keyed archives instead of perUser/perMachine MSI flavours.
//!
//! Why proxy: same reasoning as the agent side. Operators behind
//! corporate proxies can download a single archive via `roomler.ai`
//! that the AV layer trusts, without pinning to a specific GitHub IP
//! or hitting the 60/hr unauthenticated REST quota.

use axum::{
    Json,
    extract::{Path, Query, State},
    response::Response,
};
use serde::{Deserialize, Serialize};

use roomler_core::ApiError;

use crate::{
    FleetState,
    agent_release::{AgentRelease, AgentReleaseAsset},
    releases,
};

#[derive(Deserialize)]
pub struct InstallerQuery {
    #[serde(default = "default_version_latest")]
    pub version: String,
}

fn default_version_latest() -> String {
    "latest".to_string()
}

#[derive(Debug, Serialize)]
pub struct InstallerHealth {
    pub tag: String,
    pub platform: String,
    pub filename: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub uri: String,
}

/// `GET /api/tunnel/latest-release` — same wire shape as the agent's
/// `latest-release` so the CLI / installer logic can reuse one parser.
///
/// FILTERS to `tunnel-v*` tags. The cache holds the raw repo release list
/// (`agent-v*`, `vendored-ffmpeg-*`, `tunnel-v*`, …); `roomler-tunnel
/// self-update` takes `.first()` as "latest". Without this filter the newest
/// UNRELATED release — e.g. a `vendored-ffmpeg-*` helper published for the
/// agent's HEVC libs — was served as the latest tunnel, so self-update reported
/// a bogus version and failed the SHA-256 check against the wrong asset.
pub async fn latest_release(
    State(state): State<FleetState>,
) -> Result<Json<Vec<AgentRelease>>, ApiError> {
    let base = crate::release_delivery::public_base(&state.settings.app.frontend_url)?;
    let releases = releases::cached(&state).await?;
    Ok(Json(crate::release_delivery::own_urls(
        crate::agent_release::filter_component_releases(releases, "tunnel-v"),
        &base,
    )?))
}

/// `GET /api/tunnel/installer/{platform}/health` — manifest (tag,
/// filename, size, digest, download URI) for the asset matching the
/// requested platform + version.
pub async fn installer_health(
    State(state): State<FleetState>,
    Path(platform): Path<String>,
    Query(params): Query<InstallerQuery>,
) -> Result<Json<InstallerHealth>, ApiError> {
    let normalised = normalise_platform(&platform)?;
    crate::release_delivery::validate_version(&params.version)?;
    let releases = releases::cached(&state).await?;
    let release = pick_release(&releases, &params.version).ok_or_else(|| {
        ApiError::NotFound(format!("no release matching version={}", params.version))
    })?;
    let asset = pick_installer_asset(&release.assets, normalised).ok_or_else(|| {
        ApiError::NotFound(format!(
            "no asset for platform {} in tag {}",
            normalised, release.tag_name
        ))
    })?;
    crate::release_delivery::validate_asset(release, asset)?;
    Ok(Json(InstallerHealth {
        tag: release.tag_name.clone(),
        platform: normalised.to_string(),
        filename: asset.name.clone(),
        size: asset.size,
        digest: asset.digest.clone(),
        uri: crate::release_delivery::health_uri(
            &format!("/api/tunnel/installer/{}", normalised),
            &release.tag_name,
        ),
    }))
}

/// `GET /api/tunnel/installer/{platform}` — streams the archive
/// bytes. Content-Type derived from filename suffix.
pub async fn installer_proxy(
    State(state): State<FleetState>,
    Path(platform): Path<String>,
    Query(params): Query<InstallerQuery>,
) -> Result<Response, ApiError> {
    let normalised = normalise_platform(&platform)?;
    crate::release_delivery::validate_version(&params.version)?;
    let releases = releases::cached(&state).await?;
    let release = pick_release(&releases, &params.version).ok_or_else(|| {
        ApiError::NotFound(format!("no release matching version={}", params.version))
    })?;
    let asset = pick_installer_asset(&release.assets, normalised).ok_or_else(|| {
        ApiError::NotFound(format!(
            "no asset for platform {} in tag {}",
            normalised, release.tag_name
        ))
    })?;

    crate::release_delivery::stream_asset(release, asset, content_type_for(&asset.name)).await
}

#[cfg(test)]
fn sanitise_header_value(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '"'))
        .collect()
}

fn content_type_for(filename: &str) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        "application/gzip"
    } else if lower.ends_with(".deb") {
        "application/vnd.debian.binary-package"
    } else if lower.ends_with(".zip") {
        "application/zip"
    } else {
        "application/octet-stream"
    }
}

fn normalise_platform(s: &str) -> Result<&'static str, ApiError> {
    match s.to_ascii_lowercase().as_str() {
        // The bare `linux` / `deb` stay x86_64: every installer and hint
        // handed out before FR-97 P7b names them and means that arch.
        "linux-x86_64" | "linux" | "linux-tar" => Ok("linux-x86_64"),
        "linux-deb" | "deb" => Ok("linux-deb"),
        // FR-97 P7b — aarch64. `linux-aarch64` is what an aarch64 CLI has
        // always named itself (`roomler-cli`'s update.rs) and what an aarch64
        // wizard asks for (asset_resolver.rs); install.sh asks for both.
        "linux-aarch64" | "linux-arm64" => Ok("linux-aarch64"),
        "linux-deb-aarch64" | "linux-deb-arm64" => Ok("linux-deb-aarch64"),
        "macos" | "macos-universal" | "darwin" => Ok("macos"),
        "windows-x86_64" | "windows" | "win" => Ok("windows-x86_64"),
        other => Err(ApiError::BadRequest(format!(
            "unknown platform {other:?}; expected one of linux-x86_64 / linux-deb / linux-aarch64 / linux-deb-aarch64 / macos / windows-x86_64"
        ))),
    }
}

fn pick_release<'a>(releases: &'a [AgentRelease], version: &str) -> Option<&'a AgentRelease> {
    if version == "latest" {
        releases
            .iter()
            .find(|r| !r.draft && !r.prerelease && r.tag_name.starts_with("tunnel-v"))
            .or_else(|| {
                releases
                    .iter()
                    .find(|r| !r.draft && r.tag_name.starts_with("tunnel-v"))
            })
    } else {
        let target_with_prefix = format!("tunnel-v{}", version.trim_start_matches("tunnel-v"));
        let target_bare = version.trim_start_matches("tunnel-v");
        releases.iter().find(|r| {
            r.tag_name == target_with_prefix || r.tag_name == target_bare || r.tag_name == version
        })
    }
}

/// Pick the asset matching the requested platform. Filename
/// conventions follow `release-tunnel.yml`:
///   - linux-x86_64 → `*-x86_64-unknown-linux-gnu.tar.gz`
///   - linux-deb    → `*-x86_64-unknown-linux-gnu.deb`
///   - linux-aarch64 → `*-aarch64-unknown-linux-gnu.tar.gz` (FR-97 P7b)
///   - linux-deb-aarch64 → `*-aarch64-unknown-linux-gnu.deb` (FR-97 P7b)
///   - macos        → `*-universal-apple-darwin.tar.gz`
///   - windows-x86_64 → `*-x86_64-pc-windows-msvc.zip`
///
/// Every arm names its own target triple, so a Linux arch never takes the
/// other's archive, whatever order GitHub lists the assets in.
pub fn pick_installer_asset<'a>(
    assets: &'a [AgentReleaseAsset],
    platform: &str,
) -> Option<&'a AgentReleaseAsset> {
    assets.iter().find(|a| {
        let name = a.name.to_ascii_lowercase();
        // Exclude sha256 sidecars.
        if name.ends_with(".sha256") {
            return false;
        }
        match platform {
            "linux-x86_64" => {
                name.contains("x86_64-unknown-linux-gnu") && name.ends_with(".tar.gz")
            }
            "linux-deb" => name.contains("x86_64-unknown-linux-gnu") && name.ends_with(".deb"),
            "linux-aarch64" => {
                name.contains("aarch64-unknown-linux-gnu") && name.ends_with(".tar.gz")
            }
            "linux-deb-aarch64" => {
                name.contains("aarch64-unknown-linux-gnu") && name.ends_with(".deb")
            }
            "macos" => name.contains("universal-apple-darwin") && name.ends_with(".tar.gz"),
            "windows-x86_64" => name.contains("x86_64-pc-windows-msvc") && name.ends_with(".zip"),
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> AgentReleaseAsset {
        AgentReleaseAsset {
            name: name.to_string(),
            browser_download_url: format!("https://example.com/{name}"),
            size: 1024,
            digest: None,
        }
    }

    fn release(tag: &str, prerelease: bool, asset_names: &[&str]) -> AgentRelease {
        AgentRelease {
            tag_name: tag.to_string(),
            draft: false,
            prerelease,
            published_at: None,
            assets: asset_names.iter().map(|n| asset(n)).collect(),
        }
    }

    #[test]
    fn normalise_platform_accepts_aliases() {
        assert_eq!(normalise_platform("linux").unwrap(), "linux-x86_64");
        assert_eq!(normalise_platform("LINUX-X86_64").unwrap(), "linux-x86_64");
        assert_eq!(normalise_platform("deb").unwrap(), "linux-deb");
        assert_eq!(
            normalise_platform("linux-aarch64").unwrap(),
            "linux-aarch64"
        );
        assert_eq!(normalise_platform("linux-arm64").unwrap(), "linux-aarch64");
        assert_eq!(
            normalise_platform("linux-deb-aarch64").unwrap(),
            "linux-deb-aarch64"
        );
        assert_eq!(
            normalise_platform("LINUX-DEB-ARM64").unwrap(),
            "linux-deb-aarch64"
        );
        assert_eq!(normalise_platform("Darwin").unwrap(), "macos");
        assert_eq!(normalise_platform("WIN").unwrap(), "windows-x86_64");
    }

    /// FR-97 P7b — a release that carries both Linux arches: each token takes
    /// its own triple, in either listing order (GitHub's order is the upload
    /// order, which nothing here controls), so an x86_64 installer or wizard
    /// already in the field can never be handed an aarch64 archive.
    #[test]
    fn pick_installer_asset_keeps_the_linux_arches_apart() {
        let names = [
            "roomler-tunnel-0.4.148-aarch64-unknown-linux-gnu.tar.gz",
            "roomler-tunnel-0.4.148-aarch64-unknown-linux-gnu.tar.gz.sha256",
            "roomler-tunnel-0.4.148-aarch64-unknown-linux-gnu.deb",
            "roomler-tunnel-0.4.148-x86_64-unknown-linux-gnu.tar.gz",
            "roomler-tunnel-0.4.148-x86_64-unknown-linux-gnu.deb",
        ];
        let arm_first: Vec<_> = names.iter().map(|n| asset(n)).collect();
        let x86_first: Vec<_> = names.iter().rev().map(|n| asset(n)).collect();
        for assets in [&arm_first, &x86_first] {
            let pick = |p| pick_installer_asset(assets, p).unwrap().name.as_str();
            assert_eq!(
                pick("linux-x86_64"),
                "roomler-tunnel-0.4.148-x86_64-unknown-linux-gnu.tar.gz"
            );
            assert_eq!(
                pick("linux-deb"),
                "roomler-tunnel-0.4.148-x86_64-unknown-linux-gnu.deb"
            );
            assert_eq!(
                pick("linux-aarch64"),
                "roomler-tunnel-0.4.148-aarch64-unknown-linux-gnu.tar.gz"
            );
            assert_eq!(
                pick("linux-deb-aarch64"),
                "roomler-tunnel-0.4.148-aarch64-unknown-linux-gnu.deb"
            );
        }
        // A release from before P7b: aarch64 is a clean 404, never x86_64.
        let before = vec![
            asset("roomler-tunnel-0.4.147-x86_64-unknown-linux-gnu.tar.gz"),
            asset("roomler-tunnel-0.4.147-x86_64-unknown-linux-gnu.deb"),
        ];
        assert!(pick_installer_asset(&before, "linux-aarch64").is_none());
        assert!(pick_installer_asset(&before, "linux-deb-aarch64").is_none());
    }

    #[test]
    fn normalise_platform_rejects_unknown() {
        assert!(normalise_platform("freebsd").is_err());
        assert!(normalise_platform("").is_err());
    }

    #[test]
    fn pick_installer_asset_matches_by_triple_and_suffix() {
        let assets = vec![
            asset("roomler-tunnel-0.3.0-x86_64-unknown-linux-gnu.tar.gz"),
            asset("roomler-tunnel-0.3.0-x86_64-unknown-linux-gnu.tar.gz.sha256"),
            asset("roomler-tunnel-0.3.0-x86_64-unknown-linux-gnu.deb"),
            asset("roomler-tunnel-0.3.0-universal-apple-darwin.tar.gz"),
            asset("roomler-tunnel-0.3.0-x86_64-pc-windows-msvc.zip"),
        ];
        assert_eq!(
            pick_installer_asset(&assets, "linux-x86_64").unwrap().name,
            "roomler-tunnel-0.3.0-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            pick_installer_asset(&assets, "linux-deb").unwrap().name,
            "roomler-tunnel-0.3.0-x86_64-unknown-linux-gnu.deb"
        );
        assert_eq!(
            pick_installer_asset(&assets, "macos").unwrap().name,
            "roomler-tunnel-0.3.0-universal-apple-darwin.tar.gz"
        );
        assert_eq!(
            pick_installer_asset(&assets, "windows-x86_64")
                .unwrap()
                .name,
            "roomler-tunnel-0.3.0-x86_64-pc-windows-msvc.zip"
        );
    }

    #[test]
    fn pick_installer_asset_skips_sha256_sidecars() {
        let assets = vec![asset(
            "roomler-tunnel-0.3.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
        )];
        assert!(pick_installer_asset(&assets, "linux-x86_64").is_none());
    }

    #[test]
    fn pick_release_latest_filters_to_tunnel_tags() {
        // Mixed releases — pick_release(version=latest) should ignore
        // agent-v* tags and prefer non-prerelease tunnel-v*.
        let releases = vec![
            release("agent-v0.3.0-rc.46", true, &[]),
            release(
                "tunnel-v0.3.0-rc.5",
                true,
                &["roomler-tunnel-0.3.0-rc.5-x86_64-pc-windows-msvc.zip"],
            ),
            release(
                "tunnel-v0.3.0",
                false,
                &["roomler-tunnel-0.3.0-x86_64-pc-windows-msvc.zip"],
            ),
            release("agent-v0.3.0", false, &[]),
        ];
        let picked = pick_release(&releases, "latest").unwrap();
        assert_eq!(picked.tag_name, "tunnel-v0.3.0");
    }

    #[test]
    fn pick_release_latest_falls_back_to_prerelease_when_no_stable() {
        let releases = vec![
            release("tunnel-v0.3.0-rc.5", true, &[]),
            release("agent-v0.3.0", false, &[]),
        ];
        let picked = pick_release(&releases, "latest").unwrap();
        assert_eq!(picked.tag_name, "tunnel-v0.3.0-rc.5");
    }

    #[test]
    fn pick_release_specific_version_accepts_with_or_without_prefix() {
        let releases = vec![release("tunnel-v0.3.0", false, &[])];
        assert!(pick_release(&releases, "0.3.0").is_some());
        assert!(pick_release(&releases, "tunnel-v0.3.0").is_some());
        assert!(pick_release(&releases, "0.99.0").is_none());
    }

    #[test]
    fn latest_release_filter_drops_non_tunnel_tags() {
        // Regression: the raw repo list is newest-first and mixes components.
        // A `vendored-ffmpeg-*` helper release published newest must NOT be
        // served as the latest tunnel — self-update takes `.first()`.
        let releases = vec![
            release("vendored-ffmpeg-8.1.2", false, &["ffmpeg-libs.zip"]),
            release("agent-v0.3.0-rc.168", false, &[]),
            release(
                "tunnel-v0.3.0-rc.167",
                false,
                &["roomler-tunnel-0.3.0-rc.167-x86_64-pc-windows-msvc.zip"],
            ),
            release("tunnel-v0.3.0-rc.166", false, &[]),
        ];
        let filtered = crate::agent_release::filter_component_releases(releases, "tunnel-v");
        assert_eq!(filtered.len(), 2, "only tunnel-v* survive");
        assert_eq!(
            filtered.first().unwrap().tag_name,
            "tunnel-v0.3.0-rc.167",
            "newest tunnel-v* is first (what self-update's .first() reads)"
        );
    }
}
// RETIRED-NAME-ANCHOR-END
