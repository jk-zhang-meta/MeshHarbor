// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Explicit update-channel boundaries, independent of release selection/signatures.
//!
//! By default both manifest and artifacts stay under the enrolled center prefix.
//! UPDATE_URL selects one manifest endpoint, never a fallback chain.
//! UPDATE_ASSET_BASE_URL explicitly delegates artifact hosting to one HTTPS
//! origin + path prefix; it does not delegate the manifest or signing identity.
use reqwest::Url;

pub const DEFAULT_CENTER_URL: &str = "https://www.itachi.fans/meshharbor";

#[derive(Debug, Clone)]
pub struct UpdateOrigin {
    feed: Url,
    feed_base: Url,
    asset_base: Url,
}

fn checked_url(raw: &str) -> Result<Url, String> {
    // Reject ambiguous paths BEFORE URL parsing can normalize dot segments.
    let path = raw.split('?').next().unwrap_or(raw);
    if path.contains('\\') || raw.chars().any(|c| c.is_control()) {
        return Err("update URL contains an ambiguous path".into());
    }
    let lower = path.to_ascii_lowercase();
    for escape in ["%2e", "%2f", "%5c", "%25", "%00", "%0a", "%0d"] {
        if lower.contains(escape) {
            return Err("update URL contains an encoded path separator/traversal".into());
        }
    }
    let raw_path = path.split_once("://").and_then(|(_, s)| s.split_once('/'));
    if raw_path.is_some_and(|(_, p)| p.split('/').any(|s| s == "." || s == "..")) {
        return Err("update URL contains a dot segment".into());
    }
    let url = Url::parse(raw).map_err(|_| "invalid update URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.host_str().is_some_and(|h| h.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("updates require an HTTPS URL without userinfo or fragment".into());
    }
    Ok(url)
}

fn base(raw: &str) -> Result<Url, String> {
    let mut url = checked_url(raw)?;
    if url.query().is_some() {
        return Err("update base must not contain a query".into());
    }
    let path = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}

fn within(url: &Url, boundary: &Url) -> bool {
    url.origin() == boundary.origin() && url.path().starts_with(boundary.path())
}

impl UpdateOrigin {
    pub fn resolve(
        center: &str,
        explicit_feed: Option<&str>,
        explicit_asset_base: Option<&str>,
    ) -> Result<Self, String> {
        let center = base(center)?;
        let feed = match explicit_feed {
            Some(raw) => checked_url(raw)?,
            None => center
                .join("api/agent/latest-release")
                .map_err(|_| "invalid center prefix")?,
        };
        let mut feed_base = feed.clone();
        feed_base.set_query(None);
        let path = feed.path().rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        feed_base.set_path(&format!("{path}/"));
        let asset_base = match explicit_asset_base {
            Some(raw) => base(raw)?,
            None => center,
        };
        Ok(Self {
            feed,
            feed_base,
            asset_base,
        })
    }

    pub fn feed(&self) -> &Url {
        &self.feed
    }

    pub fn asset_url(&self, raw: &str) -> Result<Url, String> {
        let url = checked_url(raw)?;
        if !within(&url, &self.asset_base) {
            return Err("asset URL is outside the explicit update artifact boundary".into());
        }
        Ok(url)
    }

    pub fn permits_redirect(&self, raw: &str, asset: bool, previous: usize) -> bool {
        if previous >= 3 {
            return false;
        }
        checked_url(raw).is_ok_and(|url| {
            within(
                &url,
                if asset {
                    &self.asset_base
                } else {
                    &self.feed_base
                },
            )
        })
    }
}

pub fn validate_asset_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', ':'])
        || name.chars().any(|c| c.is_control())
    {
        return Err("update asset name must be a plain filename".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_default_retains_prefix_and_rejects_upstream_proxy_payload() {
        let p = UpdateOrigin::resolve(DEFAULT_CENTER_URL, None, None).unwrap();
        assert_eq!(
            p.feed().as_str(),
            "https://www.itachi.fans/meshharbor/api/agent/latest-release"
        );
        assert!(
            p.asset_url("https://www.itachi.fans/meshharbor/downloads/agent.deb")
                .is_ok()
        );
        for url in [
            "https://github.com/gjovanov/roomler-ai/releases/download/agent-v9/agent.deb",
            "https://roomler.ai/agent.deb",
            "https://www.itachi.fans/meshharbor-evil/a.deb",
            "https://www.itachi.fans/a.deb",
        ] {
            assert!(p.asset_url(url).is_err(), "{url}");
        }
    }
    #[test]
    fn custom_center_and_endpoint_are_independent_explicit_inputs() {
        let p = UpdateOrigin::resolve(
            "https://center.invalid:8443/owned/v2/",
            Some("https://feed.invalid/release/list?channel=stable"),
            None,
        )
        .unwrap();
        assert_eq!(
            p.feed().as_str(),
            "https://feed.invalid/release/list?channel=stable"
        );
        assert!(
            p.asset_url("https://center.invalid:8443/owned/v2/agent.deb")
                .is_ok()
        );
        assert!(
            p.asset_url("https://feed.invalid/release/agent.deb")
                .is_err()
        );
        let p = UpdateOrigin::resolve("https://center.invalid/prefix", None, None).unwrap();
        assert_eq!(
            p.feed().as_str(),
            "https://center.invalid/prefix/api/agent/latest-release"
        );
    }
    #[test]
    fn cross_origin_artifacts_require_one_explicit_prefix() {
        let p = UpdateOrigin::resolve(
            DEFAULT_CENTER_URL,
            None,
            Some("https://owned-cdn.invalid/releases/meshharbor"),
        )
        .unwrap();
        assert!(
            p.asset_url("https://owned-cdn.invalid/releases/meshharbor/a.deb")
                .is_ok()
        );
        assert!(
            p.asset_url("https://owned-cdn.invalid/releases/else/a.deb")
                .is_err()
        );
        assert!(
            p.asset_url("https://www.itachi.fans/meshharbor/a.deb")
                .is_err()
        );
    }
    #[test]
    fn ambiguous_or_unsecured_urls_are_refused_before_effects() {
        let p = UpdateOrigin::resolve(DEFAULT_CENTER_URL, None, None).unwrap();
        for url in [
            "http://www.itachi.fans/meshharbor/a",
            "https://user@www.itachi.fans/meshharbor/a",
            "https://www.itachi.fans/meshharbor/a#fragment",
            "https://www.itachi.fans/meshharbor/../a",
            "https://www.itachi.fans/meshharbor/%2e%2e/a",
            "https://www.itachi.fans/meshharbor/%252e%252e/a",
            "https://www.itachi.fans/meshharbor/a%2fb",
            "https://www.itachi.fans/meshharbor/a\\b",
        ] {
            assert!(p.asset_url(url).is_err(), "{url}");
        }
        assert!(UpdateOrigin::resolve(DEFAULT_CENTER_URL, Some(""), None).is_err());
        assert!(
            UpdateOrigin::resolve(DEFAULT_CENTER_URL, None, Some("https://*.invalid/releases"))
                .is_err()
        );
        assert!(UpdateOrigin::resolve("http://center.invalid/prefix", None, None).is_err());
        assert!(
            UpdateOrigin::resolve(
                DEFAULT_CENTER_URL,
                None,
                Some("https://cdn.invalid/base?x=y")
            )
            .is_err()
        );
    }
    #[test]
    fn redirects_stay_in_their_own_origin_prefix_and_budget() {
        let p = UpdateOrigin::resolve(DEFAULT_CENTER_URL, None, None).unwrap();
        assert!(p.permits_redirect(
            "https://www.itachi.fans/meshharbor/api/agent/list",
            false,
            1
        ));
        assert!(!p.permits_redirect("https://www.itachi.fans/meshharbor/downloads/a", false, 1));
        assert!(!p.permits_redirect(
            "https://www.itachi.fans/meshharbor/api/agent/list",
            false,
            3
        ));
        assert!(p.permits_redirect("https://www.itachi.fans/meshharbor/downloads/a", true, 1));
        assert!(!p.permits_redirect("https://evil.invalid/meshharbor/downloads/a", true, 1));
        assert!(!p.permits_redirect("https://www.itachi.fans/other/a", true, 1));
    }
    #[test]
    fn staging_names_cannot_escape_or_use_windows_drive_syntax() {
        for name in [
            "", ".", "..", "../a.deb", "a/b", "a\\b", "C:a.deb", "a\n.deb",
        ] {
            assert!(validate_asset_name(name).is_err());
        }
        assert!(validate_asset_name("meshharbor-agent_0.4.151_amd64.deb").is_ok());
    }
}
