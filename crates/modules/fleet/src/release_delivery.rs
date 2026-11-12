// SPDX-License-Identifier: AGPL-3.0-only
//! Own-center immutable release URLs and bounded streaming from owned metadata.
use crate::{
    FleetState,
    agent_release::{AgentRelease, AgentReleaseAsset},
    releases,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    response::Response,
};
use futures::{StreamExt, stream};
use meshharbor_core::ApiError;
use reqwest::Url;
use std::time::Duration;

fn bad() -> ApiError {
    ApiError::BadRequest("invalid immutable release path".into())
}
fn safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 240
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
}
pub(crate) fn validate_path(tag: &str, name: &str) -> Result<(), ApiError> {
    if !safe_token(tag)
        || !safe_token(name)
        || !["agent-v", "tunnel-v", "setup-v"]
            .iter()
            .any(|p| tag.starts_with(p) && tag.len() > p.len())
    {
        return Err(bad());
    }
    Ok(())
}
/// Relative health URI: preserve the resolved tag through form-query decoding.
pub(crate) fn health_uri(path: &str, tag: &str) -> String {
    let mut uri = Url::parse("https://health.invalid").expect("static URL");
    uri.set_path(path);
    uri.query_pairs_mut().append_pair("version", tag);
    format!("{}?{}", uri.path(), uri.query().expect("version query"))
}

pub(crate) fn validate_version(raw: &str) -> Result<(), ApiError> {
    if raw == "latest" || safe_token(raw) {
        Ok(())
    } else {
        Err(bad())
    }
}
pub(crate) fn public_base(raw: &str) -> Result<Url, ApiError> {
    let lower = raw.to_ascii_lowercase();
    if raw.contains('\\')
        || raw.chars().any(|c| c.is_control())
        || ["%2e", "%2f", "%5c", "%25", "%00", "%0a", "%0d"]
            .iter()
            .any(|x| lower.contains(x))
        || raw
            .split_once("://")
            .and_then(|(_, p)| p.split_once('/'))
            .is_some_and(|(_, p)| p.split('/').any(|s| s == "." || s == ".."))
    {
        return Err(ApiError::Internal(
            "invalid configured public center base".into(),
        ));
    }
    let mut base =
        Url::parse(raw).map_err(|_| ApiError::Internal("invalid public center base".into()))?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || base.host_str().is_some_and(|h| h.contains('*'))
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(ApiError::Internal(
            "public center base must be explicit HTTPS without credentials/query/fragment".into(),
        ));
    }
    base.set_path(&format!("{}/", base.path().trim_end_matches('/')));
    Ok(base)
}
/// Where an asset's bytes come from. `Local` exists only for assets the
/// server's own directory scan produced (`local_releases`): the path rides a
/// `serde(skip)` field, so no parsed input can ever select it.
pub(crate) enum Source<'a> {
    Github(Url),
    Local(&'a std::path::Path),
}

pub(crate) fn source<'a>(
    release: &AgentRelease,
    asset: &'a AgentReleaseAsset,
) -> Result<Source<'a>, ApiError> {
    validate_path(&release.tag_name, &asset.name)?;
    if release.draft {
        return Err(ApiError::NotFound("draft release unavailable".into()));
    }
    if let Some(path) = asset.local_path.as_deref() {
        return Ok(Source::Local(path));
    }
    let expected = format!(
        "https://github.com/{}/releases/download/{}/{}",
        releases::RELEASES_REPO,
        release.tag_name,
        asset.name
    );
    if asset.browser_download_url != expected {
        return Err(ApiError::BadRequest(
            "asset is not from the exact owned repository/tag/name".into(),
        ));
    }
    Url::parse(&expected).map(Source::Github).map_err(|_| bad())
}
pub(crate) fn own_urls(
    mut items: Vec<AgentRelease>,
    base: &Url,
) -> Result<Vec<AgentRelease>, ApiError> {
    items.retain(|r| !r.draft);
    for release in &mut items {
        // Validate all metadata before changing any URL; never use a request Host.
        for asset in &release.assets {
            source(release, asset)?;
        }
        for asset in &mut release.assets {
            asset.browser_download_url = base
                .join(&format!(
                    "api/agent/artifacts/{}/{}",
                    release.tag_name, asset.name
                ))
                .map_err(|_| bad())?
                .to_string();
        }
    }
    Ok(items)
}
fn paired(release: &AgentRelease, asset: &AgentReleaseAsset) -> Result<(), ApiError> {
    let other = asset
        .name
        .strip_suffix(".asc")
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}.asc", asset.name));
    if !release.assets.iter().any(|a| a.name == other) {
        return Err(ApiError::NotFound(
            "artifact or detached signature is absent from this release".into(),
        ));
    }
    let companion = release
        .assets
        .iter()
        .find(|a| a.name == other)
        .ok_or_else(|| ApiError::NotFound("detached signature absent".into()))?;
    source(release, companion)?;
    Ok(())
}
pub(crate) fn validate_asset(
    release: &AgentRelease,
    asset: &AgentReleaseAsset,
) -> Result<(), ApiError> {
    source(release, asset)?;
    paired(release, asset)
}
fn redirect_allowed(raw: &str, previous: usize) -> bool {
    let path = raw.split('?').next().unwrap_or(raw);
    let lower = path.to_ascii_lowercase();
    if path.contains('\\')
        || raw.chars().any(|c| c.is_control())
        || ["%2e", "%2f", "%5c", "%25", "%00", "%0a", "%0d"]
            .iter()
            .any(|x| lower.contains(x))
        || path
            .split_once("://")
            .and_then(|(_, p)| p.split_once('/'))
            .is_some_and(|(_, p)| p.split('/').any(|s| s == "." || s == ".."))
    {
        return false;
    }
    if previous >= 3 {
        return false;
    }
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && match url.host_str() {
            Some("github.com") => url
                .path()
                .starts_with(&format!("/{}/releases/download/", releases::RELEASES_REPO)),
            Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com") => true,
            _ => false,
        }
}
pub(crate) async fn stream_asset(
    release: &AgentRelease,
    asset: &AgentReleaseAsset,
    content_type: &'static str,
) -> Result<Response, ApiError> {
    let src = source(release, asset)?;
    paired(release, asset)?;
    let cap = if asset.name.ends_with(".asc") {
        1024 * 1024
    } else {
        512 * 1024 * 1024
    };
    if asset.size > cap {
        return Err(ApiError::BadRequest(
            "release asset exceeds delivery size cap".into(),
        ));
    }
    let url = match src {
        Source::Github(url) => url,
        Source::Local(path) => {
            return local_response(path, asset.size, cap, &asset.name, content_type).await;
        }
    };
    let client = reqwest::Client::builder()
        .user_agent(concat!("meshharbor-api/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if redirect_allowed(attempt.url().as_str(), attempt.previous().len()) {
                attempt.follow()
            } else {
                attempt.error("release redirect outside HTTPS allowlist/budget")
            }
        }))
        .build()
        .map_err(|_| ApiError::Internal("release HTTP client unavailable".into()))?;
    let upstream = client
        .get(url)
        .send()
        .await
        .map_err(|_| ApiError::Internal("owned release fetch failed".into()))?;
    if !upstream.status().is_success() {
        return Err(ApiError::NotFound("owned release bytes unavailable".into()));
    }
    if upstream
        .content_length()
        .is_some_and(|n| n > cap || (asset.size > 0 && n != asset.size))
    {
        return Err(ApiError::Internal("release content length mismatch".into()));
    }
    bounded_response(upstream, asset.size, cap, &asset.name, content_type)
}
/// Stream a file from the server's own release directory under the same
/// bounds as an upstream body: the size the scan recorded must still hold,
/// and a file that grows or shrinks mid-stream ends the stream in an error
/// instead of serving bytes nobody hashed.
async fn local_response(
    path: &std::path::Path,
    expected: u64,
    cap: u64,
    name: &str,
    content_type: &'static str,
) -> Result<Response, ApiError> {
    let unavailable = || ApiError::NotFound("owned release bytes unavailable".into());
    // Re-checked at serve time: the scan skipped symlinks, and a file swapped
    // for one since is refused rather than followed.
    let meta = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| unavailable())?;
    if !meta.is_file() {
        return Err(unavailable());
    }
    if meta.len() > cap || (expected > 0 && meta.len() != expected) {
        return Err(ApiError::Internal("release content length mismatch".into()));
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| unavailable())?;
    let chunks = stream::try_unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64 * 1024];
        let n = file.read(&mut buf).await?;
        if n == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        buf.truncate(n);
        Ok(Some((axum::body::Bytes::from(buf), file)))
    });
    bounded_stream_response(chunks, Some(meta.len()), expected, cap, name, content_type)
}
// Kept separate only to exercise the real streaming body against a local HTTP fixture.
fn bounded_response(
    upstream: reqwest::Response,
    expected: u64,
    cap: u64,
    name: &str,
    content_type: &'static str,
) -> Result<Response, ApiError> {
    let length = upstream.content_length();
    bounded_stream_response(
        upstream.bytes_stream(),
        length,
        expected,
        cap,
        name,
        content_type,
    )
}
fn bounded_stream_response<S, E>(
    input: S,
    length: Option<u64>,
    expected: u64,
    cap: u64,
    name: &str,
    content_type: &'static str,
) -> Result<Response, ApiError>
where
    S: futures::Stream<Item = Result<axum::body::Bytes, E>> + Send + 'static,
{
    let stream = stream::try_unfold(
        (Box::pin(input), 0u64),
        move |(mut input, seen)| async move {
            match input.next().await {
                Some(Ok(bytes)) => {
                    let total = seen
                        .checked_add(bytes.len() as u64)
                        .ok_or_else(|| std::io::Error::other("release size overflow"))?;
                    if total > cap || (expected > 0 && total > expected) {
                        return Err(std::io::Error::other(
                            "release stream exceeds declared bound",
                        ));
                    }
                    Ok(Some((bytes, (input, total))))
                }
                Some(Err(_)) => Err(std::io::Error::other("release stream failed")),
                None if expected > 0 && seen != expected => {
                    Err(std::io::Error::other("release stream truncated"))
                }
                None => Ok(None),
            }
        },
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("Cache-Control", "public, max-age=3600")
        .header(
            "Content-Disposition",
            HeaderValue::from_str(&format!("attachment; filename=\"{name}\""))
                .map_err(|_| bad())?,
        );
    if let Some(n) = length {
        builder = builder.header("Content-Length", n);
    }
    builder
        .body(Body::from_stream(stream))
        .map_err(|_| ApiError::Internal("release response unavailable".into()))
}
pub(crate) async fn artifact_proxy(
    State(state): State<FleetState>,
    Path((tag, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    validate_path(&tag, &name)?; // Before any cache miss can perform network I/O.
    let items = releases::cached(&state).await?;
    let release = items
        .iter()
        .find(|r| !r.draft && r.tag_name == tag)
        .ok_or_else(|| ApiError::NotFound("exact release tag unavailable".into()))?;
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| ApiError::NotFound("exact release asset unavailable".into()))?;
    stream_asset(
        release,
        asset,
        if name.ends_with(".asc") {
            "application/pgp-signature"
        } else {
            "application/octet-stream"
        },
    )
    .await
}

/// The server's own release directory through the delivery rules every
/// GitHub asset already obeys: own URLs, the `.asc` pairing, the size bound.
#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::local_releases::{scan, test_support::TempDir};

    const DEB: &str = "meshharbord-0.4.152-x86_64-unknown-linux-gnu.deb";

    fn publish(dir: &TempDir, with_asc: bool) -> AgentRelease {
        let rel = dir.path().join("agent-v0.4.152");
        std::fs::create_dir_all(&rel).unwrap();
        std::fs::write(rel.join(DEB), b"daemon package bytes").unwrap();
        if with_asc {
            std::fs::write(rel.join(format!("{DEB}.asc")), b"detached signature").unwrap();
        }
        scan(dir.path()).unwrap().remove(0)
    }

    async fn body(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[test]
    fn own_urls_rewrites_local_assets_to_the_center_and_hides_the_path() {
        let dir = TempDir::new();
        let release = publish(&dir, true);
        let base = public_base("https://center.example/meshharbor").unwrap();
        let out = own_urls(vec![release], &base).unwrap();
        let urls: Vec<_> = out[0]
            .assets
            .iter()
            .map(|a| a.browser_download_url.as_str())
            .collect();
        assert_eq!(
            urls,
            [
                format!(
                    "https://center.example/meshharbor/api/agent/artifacts/agent-v0.4.152/{DEB}"
                ),
                format!(
                    "https://center.example/meshharbor/api/agent/artifacts/agent-v0.4.152/{DEB}.asc"
                ),
            ]
        );
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains(dir.path().to_str().unwrap()), "{json}");
    }

    /// Same rule as GitHub: an artifact without its detached signature is
    /// not served at all — the agent would refuse it anyway, and serving it
    /// would only turn a publishing mistake into a fleet-wide refusal storm.
    #[tokio::test]
    async fn a_local_artifact_without_its_asc_is_not_served() {
        let dir = TempDir::new();
        let release = publish(&dir, false);
        let asset = &release.assets[0];
        assert!(validate_asset(&release, asset).is_err());
        assert!(
            stream_asset(&release, asset, "application/octet-stream")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_local_artifact_streams_exactly_the_scanned_bytes() {
        let dir = TempDir::new();
        let release = publish(&dir, true);
        let asset = release.assets.iter().find(|a| a.name == DEB).unwrap();
        validate_asset(&release, asset).unwrap();
        let resp = stream_asset(&release, asset, "application/octet-stream")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body(resp).await, b"daemon package bytes");
    }

    /// The scan recorded a size (and the digest the agent checks). A file
    /// replaced after the scan is refused rather than served unhashed.
    #[tokio::test]
    async fn a_local_file_changed_since_the_scan_is_refused() {
        let dir = TempDir::new();
        let release = publish(&dir, true);
        let asset = release.assets.iter().find(|a| a.name == DEB).unwrap();
        std::fs::write(
            asset.local_path.as_ref().unwrap(),
            b"a different, longer payload",
        )
        .unwrap();
        assert!(
            stream_asset(&release, asset, "application/octet-stream")
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_local_file_swapped_for_a_symlink_is_refused() {
        let dir = TempDir::new();
        let release = publish(&dir, true);
        let asset = release.assets.iter().find(|a| a.name == DEB).unwrap();
        let path = asset.local_path.clone().unwrap();
        let outside = TempDir::new();
        let target = outside.path().join("same-size");
        std::fs::write(&target, b"daemon package bytes").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(
            stream_asset(&release, asset, "application/octet-stream")
                .await
                .is_err()
        );
    }
}
