// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `/api/agent/latest-release` — cached proxy of the GitHub releases
//! list for the agent's auto-updater.
//!
//! Why we proxy: GitHub's unauthenticated REST API allows 60 requests
//! per IP per hour. With many agents behind a single NAT (offices,
//! home networks during rapid testing) the quota gets exhausted in a
//! burst — every agent then sees `403 Forbidden` until the rate
//! resets. Field log 2026-04-27 hit exactly this after 8 successive
//! MSI installs across 5 boxes. By proxying through this endpoint:
//!
//!   - All agents share one cached response per cache window.
//!   - Our API server's IP gets the 60/hr quota (one cache miss per
//!     hour worst-case → trivially under the limit).
//!   - Stale-on-error: if GitHub is down, we serve the last cached
//!     value rather than failing every agent's check simultaneously.
//!
//! Cache lifecycle: lazy + TTL, and shared with the tunnel + setup
//! release routes — see [`crate::releases`], which owns the
//! cache itself and the `POST /api/releases/refresh` cache-bust the
//! release workflows call on every tag push.
//!
//! No auth: agents call this endpoint before they have a session
//! and pretty much all the data is already public anyway via
//! github.com/gjovanov/roomler-ai/releases. CORS-OK by default.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::{Deserialize, Serialize};

use roomler_core::{ApiError, client_ip::PeerAddr};

use crate::{FleetState, install_trace, releases};

/// Subset of GitHub's release JSON the agent actually consults. We
/// don't need authors, body, html_url, or hundreds of bytes of CI
/// metadata. Slimming the response also makes the cache cheap.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
    /// GitHub Releases API exposes a `digest` field per asset of
    /// the form `"sha256:<hex>"` (added late 2024). Forwarded so
    /// the agent can verify the downloaded MSI / .deb / .pkg
    /// against this hash and reject corrupt or tampered files.
    /// Absent on releases that pre-date GitHub adding the field;
    /// the agent falls through to the size-floor check in that
    /// case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRelease {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub assets: Vec<AgentReleaseAsset>,
}

/// `GET /api/agent/latest-release` — returns the cached releases
/// list. No auth.
///
/// Response shape: `Vec<AgentRelease>`, mimicking the agent's
/// existing GitHub-shape parser so the agent-side code change is
/// just a URL swap.
pub async fn latest_release(
    State(state): State<FleetState>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentRelease>>, ApiError> {
    // FR-102 P3 — counted before the upstream read, so an outage at GitHub
    // hides no demand; the updater's own checks are never counted.
    install_trace::count_fetch(
        &state,
        &headers,
        peer,
        install_trace::asset::AGENT_LATEST_RELEASE,
    );
    let base = crate::release_delivery::public_base(&state.settings.app.frontend_url)?;
    let releases = releases::cached(&state).await?;
    Ok(Json(crate::release_delivery::own_urls(
        filter_component_releases(releases, "agent-v"),
        &base,
    )?))
}

/// Keep only non-draft releases whose tag starts with `prefix` (`agent-v` /
/// `tunnel-v`), preserving GitHub's newest-first order so a self-update client's
/// `.first()` is the latest release for THIS component. The releases cache holds
/// the raw repo list (agent, tunnel, AND unrelated helper releases like
/// `vendored-ffmpeg-*`); without this filter a client would treat the newest
/// unrelated release as its own latest and fail the SHA-256 check. Shared by the
/// agent + tunnel `latest_release` handlers.
pub(crate) fn filter_component_releases(
    releases: Vec<AgentRelease>,
    prefix: &str,
) -> Vec<AgentRelease> {
    let mut out: Vec<AgentRelease> = releases
        .into_iter()
        .filter(|r| !r.draft && r.tag_name.starts_with(prefix))
        .collect();
    // ⚠ GitHub's REST `/releases` orders by tag name LEXICOGRAPHICALLY, not by
    // recency — so the "newest first" the doc comment above once relied on is
    // false the moment a patch number reaches two digits: measured 2026-08-27,
    // `agent-v0.4.10` (the newest by every other measure) landed NINTH, between
    // `0.4.2` and `0.4.1`, because "10" < "2" as text. Anything taking
    // `.first()`/`.find()` then serves a stale release, and the rolling
    // `0.4.<counter>` scheme guarantees double digits early.
    //
    // Sorting HERE makes every consumer correct by construction rather than
    // each having to remember. Unparseable tags sort last but keep their
    // relative order (`sort_by_key` is stable), so a hand-made tag is still
    // reachable by explicit version — it just never wins "latest".
    out.sort_by_key(|r| std::cmp::Reverse(crate::agent::release_ord(&r.tag_name)));
    for r in &mut out {
        order_assets_daemon_first(&mut r.assets);
    }
    out
}

// RETIRED-NAME-ANCHOR(60): `roomler-agent-*` is what releases cut BEFORE FR-46 (#1051)
// carry — those files are immutable, so the doc and fixtures below must quote them
// exactly or they assert against names no release ever had. New releases publish
// `roomlerd-…`; this ordering never keyed on the daemon prefix at all, only on the
// `roomler-desktop-` companion one, which is why the rename did not touch it.
/// Push the desktop-companion artifacts to the END of every release's asset
/// list, so a client scanning for "the first `.deb` for my arch" cannot pick
/// one up.
///
/// ⚠️ This is a fix for the INSTALLED BASE, not for current agents. Every
/// released Linux updater up to 0.4.15 selects with
/// `assets.iter().find(|a| name.ends_with(".deb") && name.contains(arch))`,
/// which is only correct while the list happens to be ordered favourably —
/// and this proxy's order is GitHub's, which is neither documented nor by
/// name. FR-27 added `roomler-desktop-<v>-x86_64-unknown-linux-gnu.deb` to
/// `agent-v0.4.16`, it came back FIRST, and on 2026-08-29 both `mars` and
/// `jupiter` apt-installed the companion **as their own daemon update**: the
/// install "succeeded", the version never moved, and jupiter pulled 34
/// packages of webkit/GTK onto a headless cluster node. Silent update freeze,
/// no error anywhere. 0.4.16+ refuses by name (`updater::is_daemon_asset`),
/// but no agent-side fix can reach an agent that cannot update — only this
/// can, because every one of them reads THIS endpoint.
///
/// Ordering rather than filtering: `scripts/install.sh --desktop` and the
/// Windows `companion::refresh_if_stale` both resolve their artifact out of
/// this same payload, so the assets must stay present.
///
/// Stable sort ⇒ everything else keeps GitHub's relative order.
fn order_assets_daemon_first(assets: &mut [AgentReleaseAsset]) {
    assets.sort_by_key(|a| a.name.to_lowercase().starts_with("roomler-desktop-"));
}

// ─── installer download proxy ─────────────────────────────────────────────────
//
// `GET /api/agent/installer/{flavour}/health` — JSON metadata about
// the MSI the wizard would download for this flavour.
//
// `GET /api/agent/installer/{flavour}` — streams the matching MSI
// from GitHub releases through our domain. Two reasons to proxy
// instead of redirecting to github.com:
//   1. Corporate ESET / Defender allow-lists are typically per-domain.
//      `roomler.ai`'s TLS cert is already in IT-managed allow-lists
//      (the agent's signaling traffic uses it); github.com is often
//      blocked outright in locked-down environments. the field-test host field
//      repro 2026-05-11.
//   2. Single source-of-truth for asset selection (perUser vs
//      perMachine). The wizard hits one URL per flavour, never picks
//      the wrong MSI alphabetically.
// Cache-Control: public, max-age=3600 so a CDN in front of roomler.ai
// can coalesce identical requests during a fleet rollout.

/// Query parameter for both `/installer/{flavour}` and
/// `/installer/{flavour}/health`. `version=latest` (default) picks
/// the most recent non-prerelease tag; an explicit tag name pins.
#[derive(Clone, Debug, Deserialize)]
pub struct InstallerQuery {
    #[serde(default = "default_version_latest")]
    pub version: String,
}

fn default_version_latest() -> String {
    "latest".to_string()
}

/// JSON returned by `/installer/{flavour}/health`. The wizard uses
/// `size` to render a download progress bar and `digest` to verify
/// the MSI bytes match the advertised hash before launching msiexec.
#[derive(Clone, Debug, Serialize)]
pub struct InstallerHealth {
    /// Resolved tag, e.g. `agent-v0.3.0-rc.27`.
    pub tag: String,
    /// Normalised flavour: `"peruser"` or `"permachine"`.
    pub flavour: String,
    /// Canonical asset filename, e.g.
    // RETIRED-NAME-ANCHOR-BEGIN
    // Serves PUBLISHED release assets. Their filenames are fixed by what is
    // already on GitHub Releases; the updater matches on extension + arch +
    // the -permachine- infix, never the prefix (FR-21 D6). The fixtures below
    // are copies of real asset lists and must stay byte-for-byte.
    /// `roomler-agent-0.3.0-rc.27-perMachine-x86_64-pc-windows-msvc.msi`.
    pub filename: String,
    /// Asset size in bytes.
    pub size: u64,
    /// `"sha256:<hex>"` from GitHub's `digest` field. `None` on
    /// releases that pre-date the field.
    pub digest: Option<String>,
    /// The URI that, when GET'd, streams the MSI bytes. Always
    /// relative to the API root so the wizard composes it under
    /// roomler.ai (or staging.roomler.ai) transparently.
    pub uri: String,
}

/// `GET /api/agent/installer/{flavour}/health`.
pub async fn installer_health(
    State(state): State<FleetState>,
    Path(flavour): Path<String>,
    Query(params): Query<InstallerQuery>,
) -> Result<Json<InstallerHealth>, ApiError> {
    let normalised = normalise_flavour(&flavour)?;
    crate::release_delivery::validate_version(&params.version)?;
    let releases = releases::cached(&state).await?;
    let release = pick_release(&releases, &params.version).ok_or_else(|| {
        ApiError::NotFound(format!("no release matching version={}", params.version))
    })?;
    let asset = pick_installer_asset(&release.assets, normalised).ok_or_else(|| {
        ApiError::NotFound(format!(
            "no MSI asset for flavour {} in tag {}",
            normalised, release.tag_name
        ))
    })?;
    crate::release_delivery::validate_asset(release, asset)?;
    Ok(Json(InstallerHealth {
        tag: release.tag_name.clone(),
        flavour: normalised.to_string(),
        filename: asset.name.clone(),
        size: asset.size,
        digest: asset.digest.clone(),
        uri: crate::release_delivery::health_uri(
            &format!("/api/agent/installer/{}", normalised),
            &release.tag_name,
        ),
    }))
}

/// `GET /api/agent/installer/{flavour}` — streams the MSI bytes.
pub async fn installer_proxy(
    State(state): State<FleetState>,
    Path(flavour): Path<String>,
    Query(params): Query<InstallerQuery>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let normalised = normalise_flavour(&flavour)?;
    crate::release_delivery::validate_version(&params.version)?;
    // FR-102 P3 — one fetch of this flavour by this client class.
    install_trace::count_fetch(
        &state,
        &headers,
        peer,
        &install_trace::asset::installer(normalised),
    );
    let releases = releases::cached(&state).await?;
    let release = pick_release(&releases, &params.version).ok_or_else(|| {
        ApiError::NotFound(format!("no release matching version={}", params.version))
    })?;
    let asset = pick_installer_asset(&release.assets, normalised).ok_or_else(|| {
        ApiError::NotFound(format!(
            "no MSI asset for flavour {} in tag {}",
            normalised, release.tag_name
        ))
    })?;

    crate::release_delivery::stream_asset(release, asset, "application/x-msi").await
}

/// Strip CR/LF and quote characters from a header value to avoid
/// HTTP header injection if an upstream filename ever contains them.
#[cfg(test)]
fn sanitise_header_value(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '"'))
        .collect()
}

fn normalise_flavour(s: &str) -> Result<&'static str, ApiError> {
    match s.to_ascii_lowercase().as_str() {
        "peruser" => Ok("peruser"),
        "permachine" => Ok("permachine"),
        other => Err(ApiError::BadRequest(format!(
            "unknown flavour {other:?}; expected peruser or permachine"
        ))),
    }
}

fn pick_release<'a>(releases: &'a [AgentRelease], version: &str) -> Option<&'a AgentRelease> {
    if version == "latest" {
        // Filter to `agent-v*` tags — the raw release list mixes components
        // (`tunnel-v*`, unrelated helper releases like `vendored-ffmpeg-*`), and
        // the newest non-prerelease overall may not be an agent release. Without
        // this the wizard / self-update `?version=latest` resolved to an
        // unrelated release and 404'd on the MSI asset (same class as the
        // `latest_release` manifest bug fixed in #90).
        releases
            .iter()
            .find(|r| !r.draft && !r.prerelease && r.tag_name.starts_with("agent-v"))
            .or_else(|| {
                releases
                    .iter()
                    .find(|r| !r.draft && r.tag_name.starts_with("agent-v"))
            })
    } else {
        let target_with_prefix = format!("agent-v{}", version.trim_start_matches("agent-v"));
        let target_bare = version.trim_start_matches("agent-v");
        releases.iter().find(|r| {
            r.tag_name == target_with_prefix || r.tag_name == target_bare || r.tag_name == version
        })
    }
}

/// Pick the matching MSI asset for the given normalised flavour.
/// Mirrors the agent-side `pick_asset_for_windows` decision: an asset
/// with the literal infix `-perMachine-` (any case) is perMachine; any
/// other `.msi` is perUser. Returns `None` when no `.msi` matches.
pub fn pick_installer_asset<'a>(
    assets: &'a [AgentReleaseAsset],
    flavour: &str,
) -> Option<&'a AgentReleaseAsset> {
    assets.iter().find(|a| {
        let name = a.name.to_lowercase();
        if !name.ends_with(".msi") {
            return false;
        }
        let is_permachine = name.contains("-permachine-") || name.contains("permachine.");
        match flavour {
            "permachine" => is_permachine,
            "peruser" => !is_permachine,
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
            browser_download_url: format!("https://example/{name}"),
            size: 1024,
            digest: Some("sha256:deadbeef".to_string()),
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

    // RETIRED-NAME-ANCHOR(55): the asset names below are the PUBLISHED
    // release-asset spellings, frozen on purpose by release-agent.yml, and
    // the point of this test is that a pre-0.4.16 picker matching them wins
    // over the companion. Renaming them here would make it assert nothing.
    /// FR-27 / 2026-08-29 field incident. Every Linux updater up to 0.4.15
    /// takes the FIRST `.deb` matching its arch, and GitHub handed this proxy
    /// the companion first — so `mars` and `jupiter` apt-installed
    /// `roomler-desktop` as their own daemon update and froze at 0.4.15 with
    /// no error. The fix has to live here because a frozen agent is exactly
    /// the one that cannot receive an agent-side fix.
    #[test]
    fn the_daemon_deb_precedes_the_companion_deb_for_a_find_first_client() {
        let releases = filter_component_releases(
            vec![release(
                "agent-v0.4.16",
                false,
                &[
                    "roomler-desktop-0.4.16-x86_64-unknown-linux-gnu.deb",
                    "roomler-agent-0.4.16-aarch64-unknown-linux-gnu.deb",
                    "roomler-agent-0.4.16-x86_64-unknown-linux-gnu.deb",
                    "roomler-desktop-0.4.16-x86_64-pc-windows-msvc.exe",
                ],
            )],
            "agent-v",
        );
        let a = &releases[0].assets;
        // Replay the pre-0.4.16 picker verbatim.
        let picked = a
            .iter()
            .find(|x| {
                let n = x.name.to_lowercase();
                n.ends_with(".deb") && n.contains("x86_64")
            })
            .unwrap();
        assert_eq!(
            picked.name,
            "roomler-agent-0.4.16-x86_64-unknown-linux-gnu.deb"
        );
        // Ordering, NOT filtering: install.sh --desktop and the Windows
        // companion refresher both resolve their artifact from this payload.
        assert!(
            a.iter()
                .any(|x| x.name == "roomler-desktop-0.4.16-x86_64-unknown-linux-gnu.deb")
        );
        assert!(
            a.iter()
                .any(|x| x.name == "roomler-desktop-0.4.16-x86_64-pc-windows-msvc.exe")
        );
        // Non-companion assets keep GitHub's relative order (stable sort).
        let daemon: Vec<&str> = a
            .iter()
            .map(|x| x.name.as_str())
            .filter(|n| n.starts_with("roomler-agent-"))
            .collect();
        assert_eq!(
            daemon,
            [
                "roomler-agent-0.4.16-aarch64-unknown-linux-gnu.deb",
                "roomler-agent-0.4.16-x86_64-unknown-linux-gnu.deb",
            ]
        );
    }

    #[test]
    fn filter_component_releases_keeps_only_matching_prefix_newest_first() {
        // Regression: the raw repo list is newest-first + mixes components.
        // `latest_release` must drop `vendored-ffmpeg-*` / `tunnel-v*` so an
        // agent self-update taking `.first()` sees the newest agent-v* release.
        let releases = vec![
            release("vendored-ffmpeg-8.1.2", false, &[]),
            release("agent-v0.3.0-rc.168", false, &[]),
            release("tunnel-v0.3.0-rc.167", false, &[]),
            release("agent-v0.3.0-rc.166", false, &[]),
        ];
        let agent = filter_component_releases(releases.clone(), "agent-v");
        assert_eq!(agent.len(), 2);
        assert_eq!(agent.first().unwrap().tag_name, "agent-v0.3.0-rc.168");
        // And the same helper serves the tunnel handler.
        let tunnel = filter_component_releases(releases, "tunnel-v");
        assert_eq!(tunnel.len(), 1);
        assert_eq!(tunnel.first().unwrap().tag_name, "tunnel-v0.3.0-rc.167");
    }

    /// Regression, measured on prod 2026-08-27: GitHub's REST `/releases`
    /// orders by tag name as TEXT, so the first double-digit patch of the
    /// rolling `0.4.<counter>` scheme sank below its own predecessors —
    /// `agent-v0.4.10` came back NINTH, between `0.4.2` and `0.4.1`. Every
    /// consumer that took the first match (`?version=latest` for the wizard
    /// and fresh installs, the cache-bust report) then served 0.4.9 while
    /// 0.4.10 was current. This fixture IS the order GitHub returned.
    #[test]
    fn filter_component_releases_orders_by_version_not_github_text_order() {
        let releases = vec![
            release("agent-v0.4.9", false, &[]),
            release("agent-v0.4.2", false, &[]),
            release("agent-v0.4.10", false, &[]),
            release("agent-v0.4.1", false, &[]),
            release("agent-v0.3.0-rc.484", false, &[]),
        ];
        let agent = filter_component_releases(releases, "agent-v");
        assert_eq!(
            agent
                .iter()
                .map(|r| r.tag_name.as_str())
                .collect::<Vec<_>>(),
            [
                "agent-v0.4.10",
                "agent-v0.4.9",
                "agent-v0.4.2",
                "agent-v0.4.1",
                "agent-v0.3.0-rc.484",
            ],
            "double-digit patch must outrank single-digit, and finals outrank rc"
        );
    }

    /// An unparseable tag must not be able to win "latest" by sorting first,
    /// and must not disappear either — explicit `?version=` still finds it.
    #[test]
    fn unparseable_tags_sort_last_but_survive() {
        let releases = vec![
            release("agent-vNIGHTLY", false, &[]),
            release("agent-v0.4.10", false, &[]),
        ];
        let agent = filter_component_releases(releases, "agent-v");
        assert_eq!(agent.first().unwrap().tag_name, "agent-v0.4.10");
        assert_eq!(agent.len(), 2, "the odd tag is still reachable by name");
    }

    #[test]
    fn normalise_flavour_accepts_known_values_case_insensitively() {
        assert_eq!(normalise_flavour("peruser").unwrap(), "peruser");
        assert_eq!(normalise_flavour("PERUSER").unwrap(), "peruser");
        assert_eq!(normalise_flavour("PerUser").unwrap(), "peruser");
        assert_eq!(normalise_flavour("permachine").unwrap(), "permachine");
        assert_eq!(normalise_flavour("PerMachine").unwrap(), "permachine");
    }

    #[test]
    fn normalise_flavour_rejects_unknown() {
        let err = normalise_flavour("system").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn pick_installer_asset_picks_permachine_by_infix() {
        let assets = [
            asset("roomler-agent-0.3.0-x86_64-pc-windows-msvc.msi"),
            asset("roomler-agent-0.3.0-perMachine-x86_64-pc-windows-msvc.msi"),
        ];
        let picked = pick_installer_asset(&assets, "permachine").unwrap();
        assert!(picked.name.contains("perMachine"));
    }

    #[test]
    fn pick_installer_asset_picks_peruser_when_no_permachine_infix() {
        let assets = [
            asset("roomler-agent-0.3.0-perMachine-x86_64-pc-windows-msvc.msi"),
            asset("roomler-agent-0.3.0-x86_64-pc-windows-msvc.msi"),
        ];
        let picked = pick_installer_asset(&assets, "peruser").unwrap();
        assert!(!picked.name.contains("perMachine"));
    }

    #[test]
    fn pick_installer_asset_ignores_non_msi() {
        let assets = [
            asset("roomler-agent-0.3.0-x86_64-unknown-linux-gnu.deb"),
            asset("roomler-agent-0.3.0-tray-x86_64.exe"),
        ];
        assert!(pick_installer_asset(&assets, "peruser").is_none());
    }

    #[test]
    fn pick_installer_asset_returns_none_when_no_match() {
        let assets = [asset(
            "roomler-agent-0.3.0-perMachine-x86_64-pc-windows-msvc.msi",
        )];
        assert!(pick_installer_asset(&assets, "peruser").is_none());
    }

    #[test]
    fn pick_release_latest_skips_prereleases_by_default() {
        let releases = vec![
            release("agent-v0.3.0-rc.27", true, &[]),
            release("agent-v0.2.6", false, &[]),
        ];
        let picked = pick_release(&releases, "latest").unwrap();
        assert_eq!(picked.tag_name, "agent-v0.2.6");
    }

    #[test]
    fn pick_release_latest_falls_back_to_prerelease_when_no_stable() {
        let releases = vec![release("agent-v0.3.0-rc.27", true, &[])];
        let picked = pick_release(&releases, "latest").unwrap();
        assert_eq!(picked.tag_name, "agent-v0.3.0-rc.27");
    }

    #[test]
    fn pick_release_latest_skips_non_agent_tags() {
        // Regression: the raw repo list is newest-first + mixes components. A
        // newer `vendored-ffmpeg-*` / `tunnel-v*` release must NOT be picked as
        // the latest AGENT release (the wizard / self-update `?version=latest`
        // 404'd on the MSI asset otherwise).
        let releases = vec![
            release("vendored-ffmpeg-8.1.2", false, &["ffmpeg-libs.zip"]),
            release("tunnel-v0.3.0-rc.167", false, &[]),
            release(
                "agent-v0.3.0-rc.166",
                true,
                &["roomler-agent-permachine.msi"],
            ),
        ];
        let picked = pick_release(&releases, "latest").unwrap();
        assert_eq!(picked.tag_name, "agent-v0.3.0-rc.166");
    }

    #[test]
    fn pick_release_explicit_tag_with_prefix() {
        let releases = vec![release("agent-v0.3.0-rc.27", true, &[])];
        let picked = pick_release(&releases, "agent-v0.3.0-rc.27").unwrap();
        assert_eq!(picked.tag_name, "agent-v0.3.0-rc.27");
    }

    #[test]
    fn pick_release_explicit_tag_without_prefix() {
        let releases = vec![release("agent-v0.3.0-rc.27", true, &[])];
        let picked = pick_release(&releases, "0.3.0-rc.27").unwrap();
        assert_eq!(picked.tag_name, "agent-v0.3.0-rc.27");
    }

    #[test]
    fn pick_release_returns_none_for_unknown_tag() {
        let releases = vec![release("agent-v0.3.0-rc.27", true, &[])];
        assert!(pick_release(&releases, "agent-v9.9.9").is_none());
    }

    #[test]
    fn sanitise_header_value_strips_crlf_and_quotes() {
        assert_eq!(
            sanitise_header_value("evil\r\n\"injection\".msi"),
            "evilinjection.msi"
        );
    }
}
// RETIRED-NAME-ANCHOR-END
