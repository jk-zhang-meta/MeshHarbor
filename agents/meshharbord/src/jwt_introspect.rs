// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Inspect a JWT's claims WITHOUT verifying its signature.
//!
//! The installer wizard parses the operator-pasted enrollment token to
//! show "issuer + expiry" before kicking the actual enrollment HTTP
//! call. Verification is not possible client-side — the agent does not
//! have the server's HS256 secret — and is also not necessary: this
//! is UI-shaping, not authentication. The server's `/api/agent/enroll`
//! handler re-verifies on receipt.
//!
//! Security notes:
//! - The raw token never appears in any field of the returned
//!   [`JwtView`]. Callers pass it in, get back parsed metadata only.
//! - Errors do NOT echo the input back. They describe what failed
//!   without quoting (potentially sensitive) header / payload bytes.

use base64::Engine;
use serde::Deserialize;

/// Parsed claims from a JWT payload. All fields are `Option` so a
/// malformed-but-still-decodable payload doesn't fail the parse —
/// the wizard can still show "we couldn't read the expiry" rather
/// than refusing to display anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtView {
    /// `iss` claim. None when the payload doesn't carry one.
    pub issuer: Option<String>,
    /// `aud` claim. Captured as a single string; if the payload had a
    /// list, the first entry wins. None when missing.
    pub audience: Option<String>,
    /// `exp` claim as Unix seconds. None when missing or non-numeric.
    pub expires_at_unix: Option<i64>,
    /// `iat` claim as Unix seconds. None when missing or non-numeric. FR-103
    /// reads it to learn a token's whole lifetime, so a short-lived token is
    /// renewed at half-life rather than only inside the long horizon.
    pub issued_at_unix: Option<i64>,
    /// `sub` claim. None when missing.
    pub subject: Option<String>,
    /// `jti` claim. None when missing.
    pub jti: Option<String>,
}

/// Errors from [`parse_unverified`].
#[derive(Debug, thiserror::Error)]
pub enum IntrospectError {
    /// Token did not have three dot-separated parts.
    #[error("token does not have three dot-separated parts")]
    Malformed,
    /// Middle segment failed base64url decoding.
    #[error("base64url decode of payload failed: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Payload bytes are not valid JSON.
    #[error("JSON parse of payload failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Decode the middle segment of a JWT and return its claims.
///
/// Does NOT verify the signature — the agent / wizard do not have
/// the signing key. Server-side `/api/agent/enroll` re-verifies on
/// receipt. This function is for UI shaping only.
pub fn parse_unverified(token: &str) -> Result<JwtView, IntrospectError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or(IntrospectError::Malformed)?;
    let payload = parts.next().ok_or(IntrospectError::Malformed)?;
    let _signature = parts.next().ok_or(IntrospectError::Malformed)?;
    // Reject 4-or-more part inputs.
    if parts.next().is_some() {
        return Err(IntrospectError::Malformed);
    }

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?;
    let claims: RawClaims = serde_json::from_slice(&bytes)?;

    Ok(JwtView {
        issuer: claims.iss,
        audience: claims.aud.and_then(audience_first),
        expires_at_unix: claims.exp,
        issued_at_unix: claims.iat,
        subject: claims.sub,
        jti: claims.jti,
    })
}

/// `true` when the token's `exp` claim is in the past (or missing —
/// missing-exp tokens are treated as expired to avoid the wizard
/// presenting a "valid forever" enrollment token).
///
/// `now_unix` is supplied by the caller to keep this function pure
/// + unit-testable.
pub fn is_likely_expired(view: &JwtView, now_unix: i64) -> bool {
    match view.expires_at_unix {
        Some(exp) => exp <= now_unix,
        None => true,
    }
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    jti: Option<String>,
}

/// Coerce a JSON `aud` field (string OR array of strings per RFC 7519
/// §4.1.3) to a single Option<String>.
fn audience_first(value: serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Array(arr) => arr.into_iter().find_map(|v| match v {
            serde_json::Value::String(s) => Some(s),
            _ => None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn forge_token(claims: serde_json::Value) -> String {
        // Header + signature are throwaway — parse_unverified ignores them.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let signature = "fakesig";
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn parses_typical_enrollment_token() {
        let token = forge_token(serde_json::json!({
            "iss": "roomler-ai",
            "aud": "agent-enrollment",
            "exp": 1_900_000_000_i64,
            "sub": "tenant-abc",
            "jti": "deadbeef",
        }));
        let view = parse_unverified(&token).unwrap();
        assert_eq!(view.issuer.as_deref(), Some("roomler-ai"));
        assert_eq!(view.audience.as_deref(), Some("agent-enrollment"));
        assert_eq!(view.expires_at_unix, Some(1_900_000_000));
        assert_eq!(view.subject.as_deref(), Some("tenant-abc"));
        assert_eq!(view.jti.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn parses_token_with_audience_array() {
        let token = forge_token(serde_json::json!({
            "iss": "roomler-ai",
            "aud": ["agent-enrollment", "agent-access"],
            "exp": 1_900_000_000_i64,
        }));
        let view = parse_unverified(&token).unwrap();
        assert_eq!(view.audience.as_deref(), Some("agent-enrollment"));
    }

    #[test]
    fn missing_optional_claims_are_none() {
        let token = forge_token(serde_json::json!({}));
        let view = parse_unverified(&token).unwrap();
        assert_eq!(view, JwtView::default());
    }

    #[test]
    fn malformed_two_part_token_rejected() {
        let err = parse_unverified("aaa.bbb").unwrap_err();
        assert!(matches!(err, IntrospectError::Malformed));
    }

    #[test]
    fn malformed_four_part_token_rejected() {
        let err = parse_unverified("aaa.bbb.ccc.ddd").unwrap_err();
        assert!(matches!(err, IntrospectError::Malformed));
    }

    #[test]
    fn non_base64_payload_rejected() {
        // Middle segment "!!!" cannot decode.
        let err = parse_unverified("aaa.!!!.ccc").unwrap_err();
        assert!(matches!(err, IntrospectError::Base64(_)));
    }

    #[test]
    fn non_json_payload_rejected() {
        // Middle segment is valid base64 but decodes to "not json".
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
        let token = format!("aaa.{payload}.ccc");
        let err = parse_unverified(&token).unwrap_err();
        assert!(matches!(err, IntrospectError::Json(_)));
    }

    #[test]
    fn is_likely_expired_uses_caller_supplied_now() {
        let view = JwtView {
            expires_at_unix: Some(1000),
            ..Default::default()
        };
        assert!(is_likely_expired(&view, 1001));
        assert!(is_likely_expired(&view, 1000)); // boundary: exp <= now
        assert!(!is_likely_expired(&view, 999));
    }

    #[test]
    fn is_likely_expired_treats_missing_exp_as_expired() {
        let view = JwtView::default();
        assert!(is_likely_expired(&view, 0));
        assert!(is_likely_expired(&view, i64::MAX));
    }
}
