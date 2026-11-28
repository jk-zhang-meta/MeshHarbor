// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Pure URL construction and validation for the desktop companion's
//! "Open globe" action (`/tenant/:tenantId/network/globe?embed=1&lang=&theme=`).
//!
//! Kept free of Tauri dependencies so it can be unit-tested directly with
//! standalone `rustc --edition 2024 --test` as well as inside the binary.

/// Normalize a language tag (`en`, `zh-CN`, `zh_Hans`, `en-US`, …) to `"en"` or `"zh-CN"`,
/// falling back to `fallback` (also normalized) when `raw` is absent or unrecognized.
pub fn normalize_globe_lang(raw: Option<&str>, fallback: &str) -> &'static str {
    fn parse_known(s: &str) -> Option<&'static str> {
        let norm = s.trim().replace('_', "-").to_ascii_lowercase();
        let primary = norm.split(['.', '@', ';', ' ']).next().unwrap_or("");
        if primary == "zh" || primary.starts_with("zh-") {
            Some("zh-CN")
        } else if primary == "en" || primary.starts_with("en-") {
            Some("en")
        } else {
            None
        }
    }
    raw.and_then(parse_known)
        .or_else(|| parse_known(fallback))
        .unwrap_or("en")
}

/// Normalize a theme parameter to `"light"`, `"dark"`, or `"system"`.
pub fn normalize_globe_theme(raw: Option<&str>) -> &'static str {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("light") => "light",
        Some("dark") => "dark",
        Some("system") | None => "system",
        _ => "system",
    }
}

/// True when `authority` (host[:port], no userinfo) is a literal loopback IP
/// (`127.0.0.1` or `[::1]`, with optional port). Matches `user_session::trusted_base`.
fn is_literal_loopback_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return false;
        };
        if !after.is_empty()
            && !after
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return false;
        }
        inside
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
            Some(_) => return false,
            None => authority,
        }
    };
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Validate and normalize the MeshHarbor server base URL (HTTPS, or literal
/// loopback HTTP for local testing; no credentials, query, or fragment).
/// Trailing slashes are stripped while preserving any deployment path prefix.
pub fn validate_server_origin(server: &str) -> Result<String, String> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return Err("This device isn't enrolled yet — no server to open.".to_string());
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err("This device's config has no valid server URL.".to_string());
    }

    let (is_https, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(
            "Opening the network globe requires an HTTPS server (or literal loopback HTTP for local testing)."
                .to_string(),
        );
    };

    let (authority, path_rest) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("This device's config has no valid server URL.".to_string());
    }
    if !is_https && !is_literal_loopback_authority(authority) {
        return Err(
            "Opening the network globe requires an HTTPS server (or literal loopback HTTP for local testing)."
                .to_string(),
        );
    }

    let clean_path = path_rest.trim_end_matches('/');
    let scheme = if is_https { "https" } else { "http" };
    Ok(format!("{scheme}://{authority}{clean_path}"))
}

/// Build the embed URL for the primary organization's 3D globe:
/// `{server_url_trimmed}/tenant/{tenant_id}/network/globe?embed=1&lang={en|zh-CN}&theme={light|dark|system}`.
///
/// If `tenant_id` is `None` or empty (e.g., a legacy daemon that did not report
/// a tenant id), falls back gracefully to `{server_url_trimmed}`. A non-empty
/// malformed `tenant_id` is rejected rather than interpolated.
pub fn build_network_globe_url(
    server: &str,
    tenant_id: Option<&str>,
    lang: Option<&str>,
    fallback_lang: &str,
    theme: Option<&str>,
) -> Result<String, String> {
    let base = validate_server_origin(server)?;
    let Some(raw_tid) = tenant_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(base);
    };
    let tid = raw_tid.to_ascii_lowercase();
    if tid.len() != 24 || !tid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("This device's config has no valid organization id for the globe.".to_string());
    }
    let norm_lang = normalize_globe_lang(lang, fallback_lang);
    let norm_theme = normalize_globe_theme(theme);
    Ok(format!(
        "{base}/tenant/{tid}/network/globe?embed=1&lang={norm_lang}&theme={norm_theme}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TID: &str = "65f000000000000000000001";

    #[test]
    fn builds_embed_url_with_trimmed_slashes_and_query_params() {
        assert_eq!(
            build_network_globe_url(
                "https://centre.example.test///",
                Some(VALID_TID),
                Some("zh-CN"),
                "en",
                Some("dark"),
            )
            .unwrap(),
            "https://centre.example.test/tenant/65f000000000000000000001/network/globe?embed=1&lang=zh-CN&theme=dark"
        );
        assert_eq!(
            build_network_globe_url(
                "https://centre.example.test/meshharbor/",
                Some("65F0000000000000000000AB"),
                Some("en-US"),
                "zh-CN",
                Some("light"),
            )
            .unwrap(),
            "https://centre.example.test/meshharbor/tenant/65f0000000000000000000ab/network/globe?embed=1&lang=en&theme=light"
        );
    }

    #[test]
    fn normalizes_lang_fallback_and_theme_defaults() {
        assert_eq!(
            build_network_globe_url(
                "https://centre.example.test",
                Some(VALID_TID),
                None,
                "zh-CN",
                None,
            )
            .unwrap(),
            "https://centre.example.test/tenant/65f000000000000000000001/network/globe?embed=1&lang=zh-CN&theme=system"
        );
        assert_eq!(normalize_globe_lang(Some("zh_Hans"), "en"), "zh-CN");
        assert_eq!(normalize_globe_lang(Some("zh"), "en"), "zh-CN");
        assert_eq!(normalize_globe_lang(Some("EN"), "zh-CN"), "en");
        assert_eq!(normalize_globe_lang(Some("fr-FR"), "zh-CN"), "zh-CN");
        assert_eq!(normalize_globe_lang(None, "unknown"), "en");

        assert_eq!(normalize_globe_theme(Some("LIGHT")), "light");
        assert_eq!(normalize_globe_theme(Some("dark")), "dark");
        assert_eq!(normalize_globe_theme(Some("system")), "system");
        assert_eq!(normalize_globe_theme(Some("sepia")), "system");
        assert_eq!(normalize_globe_theme(None), "system");
    }

    #[test]
    fn falls_back_to_server_origin_when_tenant_id_is_missing() {
        assert_eq!(
            build_network_globe_url(
                "https://centre.example.test/meshharbor/",
                None,
                Some("en"),
                "en",
                Some("dark"),
            )
            .unwrap(),
            "https://centre.example.test/meshharbor"
        );
        assert_eq!(
            build_network_globe_url(
                "https://centre.example.test/",
                Some("   "),
                Some("zh-CN"),
                "en",
                Some("light"),
            )
            .unwrap(),
            "https://centre.example.test"
        );
    }

    #[test]
    fn accepts_loopback_http_and_rejects_unsafe_or_malformed_inputs() {
        assert_eq!(
            build_network_globe_url(
                "http://127.0.0.1:5000/",
                Some(VALID_TID),
                Some("en"),
                "en",
                Some("system"),
            )
            .unwrap(),
            "http://127.0.0.1:5000/tenant/65f000000000000000000001/network/globe?embed=1&lang=en&theme=system"
        );
        assert_eq!(
            build_network_globe_url(
                "http://[::1]:5000/sub/",
                Some(VALID_TID),
                Some("zh-CN"),
                "en",
                Some("dark"),
            )
            .unwrap(),
            "http://[::1]:5000/sub/tenant/65f000000000000000000001/network/globe?embed=1&lang=zh-CN&theme=dark"
        );

        for bad_server in [
            "",
            "   ",
            "http://centre.example.test",
            "http://localhost:5000",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://user:pass@centre.example.test",
            "https://centre.example.test?foo=bar",
            "https://centre.example.test#frag",
            "https://",
        ] {
            assert!(
                build_network_globe_url(
                    bad_server,
                    Some(VALID_TID),
                    Some("en"),
                    "en",
                    Some("dark")
                )
                .is_err(),
                "expected error for server={bad_server:?}"
            );
        }

        for bad_tid in [
            "../admin",
            "short",
            "zzzzzzzzzzzzzzzzzzzzzzzz",
            "65f000000000000000000001/extra",
        ] {
            assert!(
                build_network_globe_url(
                    "https://centre.example.test",
                    Some(bad_tid),
                    Some("en"),
                    "en",
                    Some("dark"),
                )
                .is_err(),
                "expected error for tenant_id={bad_tid:?}"
            );
        }
    }
}
