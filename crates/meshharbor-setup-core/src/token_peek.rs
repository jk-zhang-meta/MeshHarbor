// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Unverified JWT payload peek.
//!
//! Decodes a JWT's middle segment WITHOUT signature verification to
//! read routing-relevant claims client-side. The Roomler server's
//! tunnel-enrollment JWT carries a custom `token_type` claim
//! (snake_case, e.g. `"tunnel_enrollment"`) and NO `aud` claim, so
//! audience-style gating needs this peek. Lifted from the tunnel
//! wizard's inline `parse_token_type` (rc.60) — the "cleaner
//! cross-crate fix" its Cargo.toml comment asked for.
//!
//! SECURITY: this is a UX pre-check only (gate the Continue button,
//! pick the right enrollment flow). The server re-validates the
//! signature + claims on every enrollment POST; nothing trusts the
//! peeked value. The raw token is never logged or echoed.

/// Decode the JWT's middle segment and return its `token_type` custom
/// claim. Returns None for any failure path (malformed token, bad
/// base64, non-JSON payload, missing claim, non-string claim) — the
/// caller treats that as "gate stays closed".
pub fn parse_token_type(token: &str) -> Option<String> {
    use base64::Engine;
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("token_type")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// FR-104 — did the admin mint this enrollment token to also ANCHOR the
/// device it enrolls (`"anchor": true`)? `false` for every failure path and
/// for every token minted without it. A UX pre-check like
/// [`parse_token_type`]: the server decides whether the second use is
/// allowed, for exactly the device this token enrolled.
pub fn parse_anchor_claim(token: &str) -> bool {
    use base64::Engine;
    let Some(payload_b64) = token.split('.').nth(1) else {
        return false;
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|v| v.get("anchor").and_then(|a| a.as_bool()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// FR-104 — the anchor claim reads `true` only when the token says so.
    #[test]
    fn parses_the_anchor_claim() {
        let anchoring = fake_jwt(r#"{"token_type":"enrollment","anchor":true}"#);
        assert!(parse_anchor_claim(&anchoring));
        let plain = fake_jwt(r#"{"token_type":"enrollment"}"#);
        assert!(!parse_anchor_claim(&plain));
        let odd = fake_jwt(r#"{"anchor":"yes"}"#);
        assert!(!parse_anchor_claim(&odd));
        assert!(!parse_anchor_claim("not-a-jwt"));
    }

    /// Build an unsigned test JWT with the given JSON payload — the
    /// header + signature segments are irrelevant to the peek.
    fn fake_jwt(payload_json: &str) -> String {
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
        format!(
            "{}.{}.{}",
            b64("{\"alg\":\"none\"}"),
            b64(payload_json),
            "sig"
        )
    }

    #[test]
    fn parses_token_type_claim() {
        let jwt = fake_jwt(r#"{"token_type":"tunnel_enrollment","iss":"roomler-ai"}"#);
        assert_eq!(parse_token_type(&jwt).as_deref(), Some("tunnel_enrollment"));
    }

    #[test]
    fn missing_claim_returns_none() {
        let jwt = fake_jwt(r#"{"iss":"roomler-ai"}"#);
        assert_eq!(parse_token_type(&jwt), None);
    }

    #[test]
    fn non_string_claim_returns_none() {
        let jwt = fake_jwt(r#"{"token_type":42}"#);
        assert_eq!(parse_token_type(&jwt), None);
    }

    #[test]
    fn malformed_token_returns_none() {
        assert_eq!(parse_token_type("not-a-jwt"), None);
        assert_eq!(parse_token_type(""), None);
        assert_eq!(parse_token_type("a.!!!not-base64!!!.c"), None);
    }
}
