// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! One definition of "an origin this deployment considers its own".
//!
//! Two places need it and they must not drift:
//!
//! * the CORS layer, which decides whose cross-origin **HTTP** the browser may
//!   read, and
//! * the `/ws` upgrade, which decides whose handshake may authenticate with an
//!   **ambient session cookie**.
//!
//! The second is the reason this module exists. A WebSocket handshake is not
//! subject to CORS at all — any page on the internet may open a socket to us —
//! so once `/ws` accepts a cookie, "who is asking" stops being answered by the
//! credential and has to be answered by the request. `SameSite=Lax` already
//! keeps the cookie off a cross-site handshake, which makes this the second
//! lock rather than the only one; both are cheap and neither is sufficient
//! alone in the presence of a browser bug or a policy change.

use meshharbor_config::Settings;

/// Which origins may authenticate with an ambient credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginPolicy {
    /// The operator explicitly configured `cors_origins = ["*"]`. Their choice,
    /// and it is logged loudly at startup by the CORS layer.
    AnyOrigin,
    /// Exactly these, compared scheme+host+port, ASCII-case-insensitively.
    Only(Vec<String>),
}

/// Resolve the policy from configuration.
///
/// Mirrors the CORS default deliberately: with no `cors_origins` set, the only
/// origin we trust is the frontend's own. See `build_cors_layer`, which is
/// built from this same answer so the two cannot disagree.
pub fn origin_policy(cors_origins: &[String], frontend_url: &str) -> OriginPolicy {
    if cors_origins.iter().any(|o| o == "*") {
        return OriginPolicy::AnyOrigin;
    }
    let mut allowed: Vec<String> = cors_origins
        .iter()
        .map(|o| normalize(o))
        .filter(|o| !o.is_empty())
        .collect();
    if allowed.is_empty() {
        let f = normalize(frontend_url);
        if !f.is_empty() {
            allowed.push(f);
        }
    }
    OriginPolicy::Only(allowed)
}

/// Convenience wrapper over the settings the server actually holds.
pub fn policy_from_settings(settings: &Settings) -> OriginPolicy {
    origin_policy(&settings.app.cors_origins, &settings.app.frontend_url)
}

/// Is `origin` (a raw `Origin` header value) one of ours?
///
/// An **empty allow-list is a DENY**, not a pass. That is the opposite of the
/// CORS layer's behaviour, which falls back to permissive when nothing parses
/// rather than bricking every browser — and the asymmetry is deliberate: a
/// too-loose CORS header lets a page *read* a response it already had the
/// credentials to fetch, whereas a too-loose ambient-cookie check hands an
/// attacker's page an authenticated socket. Failing open is defensible for one
/// and not for the other.
pub fn is_trusted(policy: &OriginPolicy, origin: &str) -> bool {
    match policy {
        OriginPolicy::AnyOrigin => true,
        OriginPolicy::Only(allowed) => {
            let got = normalize(origin);
            !got.is_empty() && allowed.iter().any(|a| a.eq_ignore_ascii_case(&got))
        }
    }
}

/// Strip a trailing slash and any path, leaving scheme://host[:port].
///
/// An `Origin` header is already only scheme+host+port, but `frontend_url` is
/// operator-typed configuration and routinely carries a trailing slash — and
/// occasionally a path. Comparing those raw would silently trust nobody, which
/// on the WS path means "no browser can connect" rather than a loud error.
fn normalize(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() || s == "null" {
        // `Origin: null` is what a sandboxed iframe / `data:` document sends.
        // It is never us.
        return String::new();
    }
    let Some(scheme_end) = s.find("://") else {
        return String::new();
    };
    let after = &s[scheme_end + 3..];
    let host_end = after.find('/').unwrap_or(after.len());
    s[..scheme_end + 3 + host_end]
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_no_cors_origins_only_the_frontend_is_trusted() {
        let p = origin_policy(&[], "https://roomler.ai");
        assert!(is_trusted(&p, "https://roomler.ai"));
        assert!(!is_trusted(&p, "https://evil.example"));
        assert!(!is_trusted(&p, "https://roomler.ai.evil.example"));
    }

    #[test]
    fn a_trailing_slash_or_path_in_config_still_matches() {
        // The operator types a URL, not an Origin. Getting this wrong would
        // mean no browser could open a socket.
        for configured in [
            "https://roomler.ai/",
            "https://roomler.ai",
            "https://roomler.ai/app",
        ] {
            let p = origin_policy(&[], configured);
            assert!(
                is_trusted(&p, "https://roomler.ai"),
                "configured as {configured:?}"
            );
        }
    }

    #[test]
    fn scheme_and_port_are_part_of_the_identity() {
        let p = origin_policy(&[], "https://roomler.ai");
        assert!(!is_trusted(&p, "http://roomler.ai"), "scheme must match");
        assert!(
            !is_trusted(&p, "https://roomler.ai:8443"),
            "port must match"
        );

        let dev = origin_policy(&[], "http://localhost:5000");
        assert!(is_trusted(&dev, "http://localhost:5000"));
        assert!(!is_trusted(&dev, "http://localhost:5001"));
    }

    #[test]
    fn host_comparison_is_case_insensitive() {
        let p = origin_policy(&[], "https://Roomler.AI");
        assert!(is_trusted(&p, "https://roomler.ai"));
    }

    #[test]
    fn an_explicit_star_trusts_everything() {
        let p = origin_policy(&["*".to_string()], "https://roomler.ai");
        assert_eq!(p, OriginPolicy::AnyOrigin);
        assert!(is_trusted(&p, "https://evil.example"));
    }

    #[test]
    fn an_explicit_list_replaces_the_frontend_default() {
        let p = origin_policy(
            &["https://a.example".into(), "https://b.example".into()],
            "https://roomler.ai",
        );
        assert!(is_trusted(&p, "https://a.example"));
        assert!(is_trusted(&p, "https://b.example"));
        // The frontend is NOT implicitly added — an operator who enumerates
        // origins is stating the whole set. (CORS behaves the same way.)
        assert!(!is_trusted(&p, "https://roomler.ai"));
    }

    #[test]
    fn junk_and_null_origins_are_refused() {
        let p = origin_policy(&[], "https://roomler.ai");
        for origin in ["", "   ", "null", "roomler.ai", "://roomler.ai"] {
            assert!(!is_trusted(&p, origin), "{origin:?} must not be trusted");
        }
    }

    #[test]
    fn an_unusable_config_denies_rather_than_falls_open() {
        // The CORS layer falls back to permissive when nothing parses, so it
        // cannot brick every browser. Here the same input must DENY: an
        // ambient cookie is not a credential the caller had to obtain.
        let p = origin_policy(&[], "");
        assert_eq!(p, OriginPolicy::Only(vec![]));
        assert!(!is_trusted(&p, "https://roomler.ai"));
        assert!(!is_trusted(&p, "https://evil.example"));
    }
}
