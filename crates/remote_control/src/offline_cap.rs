// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Stateless EdDSA offline capabilities (`aud = "mh-offline"`).
//!
//! Modelled on [`crate::derp_ticket`]: the coordination server signs a short,
//! narrowly-scoped Ed25519 JWT when an organization has opted into
//! `TenantSettings::offline_access = true` and an online `rc:ssh.request`
//! (non-ticketed) or `rc:rpc.exec` succeeds. Targets verify the signature
//! offline against the Ed25519 public keys distributed in
//! `OverlayNetworkInfo::offline_cap_keys` (and persisted in the signed local
//! netmap cache).
//!
//! Keying:
//! * Optional explicit private key via `MESHHARBOR__RELAY__OFFLINE_CAP_PRIVATE_KEY`
//!   (base64 PKCS#8 DER Ed25519).
//! * Deterministic fallback derived via RFC 5869 HKDF-SHA256 from
//!   `settings.jwt.secret` (and verification keys also derived from every
//!   entry in `settings.jwt.previous_secrets` so JWT secret rotation never
//!   invalidates live offline capabilities mid-outage).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use ring::hkdf;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::{Deserialize, Serialize};

/// Distinct JWT audience so an offline capability can never be confused with
/// user JWTs, agent JWTs, DERP tickets, or FR-90 SSH tickets.
pub const OFFLINE_CAP_AUDIENCE: &str = "mh-offline";

/// Maximum accepted forward clock skew on `iat` (5 minutes).
pub const OFFLINE_CAP_MAX_SKEW_SECS: u64 = 300;

/// Default offline capability lifetime (24 hours), clamped to tenant
/// `offline_max_age_s` when set.
pub const DEFAULT_OFFLINE_CAP_TTL_SECS: u64 = 24 * 3600;

/// Minimum / maximum offline capability lifetime bounds.
pub const MIN_OFFLINE_CAP_TTL_SECS: u64 = 300;
pub const MAX_OFFLINE_CAP_TTL_SECS: u64 = 14 * 86_400;

pub const VERB_SSH: &str = "ssh";
pub const VERB_EXEC: &str = "exec";

const HKDF_SALT: &[u8] = b"meshharbor/offline-cap/v1";
const HKDF_INFO: &[u8] = b"meshharbor/offline-cap-ed25519-seed/v1";

/// RFC 8410 Ed25519 PKCS#8 v1 prefix preceding the 32-byte seed.
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Claims embedded in a server-signed offline capability JWT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfflineCapClaims {
    /// Always [`OFFLINE_CAP_AUDIENCE`] (`"mh-offline"`).
    pub aud: String,
    /// `"ssh"` or `"exec"` — a capability for one verb can NEVER authorize the other.
    pub verb: String,
    /// Overlay network id (hex) — prevents cross-network replay.
    pub net: String,
    /// Tenant id (hex) — prevents cross-tenant replay.
    pub tid: String,
    /// Target agent id (hex) — prevents replaying against another device.
    pub tgt: String,
    /// Origin agent id (hex) — recorded for offline audit attribution.
    pub org: String,
    /// Origin node's WireGuard static public key (base64) — bound directly to
    /// the authenticated `/32` WG peer key on `p2pctl`.
    pub opk: String,
    /// Human-readable accountable caller string (`"<person> (via <device>)"`).
    pub caller: String,
    /// Unique capability id (hex) — used with `(org, jti, req_id, req_digest)`
    /// for atomic offline exec replay/crash-retry deduplication.
    pub jti: String,
    /// Issued-at Unix seconds.
    pub iat: u64,
    /// Expiration Unix seconds.
    pub exp: u64,

    // ── SSH ceilings (present when verb == "ssh") ─────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_account_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_max_session_secs: Option<u64>,

    // ── Exec ceilings (present when verb == "exec") ───────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_shells: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_run_as: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_max_timeout_ms: Option<u64>,

    // ── Shared policy ceiling ─────────────────────────────────────────────
    /// Wire spelling of the effective [`crate::models::ConsentMode`] enforced
    /// on the target device (`"auto" | "always" | "ask" | "deny"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_mode: Option<String>,
}

/// Server-side Ed25519 signer and active verification public-key set for
/// offline capabilities.
pub struct OfflineCapSigner {
    enc: EncodingKey,
    public_keys_b64: Vec<String>,
}

fn derive_ed25519_from_secret(secret: &str) -> (Vec<u8>, String) {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(secret.as_bytes());
    let okm = prk
        .expand(&[HKDF_INFO], hkdf::HKDF_SHA256)
        .expect("HKDF expand 32 bytes");
    let mut seed = [0u8; 32];
    okm.fill(&mut seed).expect("fill 32-byte Ed25519 seed");
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid 32-byte Ed25519 seed");
    let pub_b64 = B64.encode(pair.public_key().as_ref());
    let mut pkcs8 = Vec::with_capacity(ED25519_PKCS8_V1_PREFIX.len() + 32);
    pkcs8.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
    pkcs8.extend_from_slice(&seed);
    (pkcs8, pub_b64)
}

impl OfflineCapSigner {
    /// Load an explicit Ed25519 private key from base64(PKCS#8 DER), optionally
    /// adding fallback public verification keys derived from JWT rotation secrets.
    pub fn from_pkcs8_b64(private_b64: &str, extra_public_keys_b64: Vec<String>) -> Result<Self, String> {
        let der = B64
            .decode(private_b64.trim())
            .map_err(|e| format!("offline_cap key: invalid base64: {e}"))?;
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
            .map_err(|e| format!("offline_cap key: not an Ed25519 PKCS#8 key: {e}"))?;
        let mut keys = vec![B64.encode(pair.public_key().as_ref())];
        for k in extra_public_keys_b64 {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        Ok(Self {
            enc: EncodingKey::from_ed_der(&der),
            public_keys_b64: keys,
        })
    }

    /// Deterministically derive the primary signing Ed25519 key from
    /// `primary_secret`, and also include public verification keys derived from
    /// every non-empty secret in `previous_secrets` so rolling JWT secret
    /// rotation preserves live offline capabilities.
    pub fn from_jwt_secrets(primary_secret: &str, previous_secrets: &[String]) -> Self {
        let (pkcs8, primary_pub) = derive_ed25519_from_secret(primary_secret);
        let mut keys = vec![primary_pub];
        for prev in previous_secrets {
            let trimmed = prev.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (_, pub_b64) = derive_ed25519_from_secret(trimmed);
            if !keys.contains(&pub_b64) {
                keys.push(pub_b64);
            }
        }
        Self {
            enc: EncodingKey::from_ed_der(&pkcs8),
            public_keys_b64: keys,
        }
    }

    /// Active Ed25519 public verification keys (base64 raw 32-byte keys),
    /// shipped in `OverlayNetworkInfo::offline_cap_keys`.
    pub fn public_keys_b64(&self) -> &[String] {
        &self.public_keys_b64
    }

    /// Sign an [`OfflineCapClaims`] payload with EdDSA.
    pub fn mint(&self, claims: &OfflineCapClaims) -> Result<String, String> {
        if claims.aud != OFFLINE_CAP_AUDIENCE {
            return Err(format!("offline_cap mint: unexpected aud {:?}", claims.aud));
        }
        if claims.verb != VERB_SSH && claims.verb != VERB_EXEC {
            return Err(format!(
                "offline_cap mint: invalid verb {:?}",
                claims.verb
            ));
        }
        if claims.exp <= claims.iat {
            return Err("offline_cap mint: exp must exceed iat".into());
        }
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), claims, &self.enc)
            .map_err(|e| format!("offline_cap mint: {e}"))
    }
}

/// Build an EdDSA [`DecodingKey`] from base64(raw 32-byte Ed25519 public key).
pub fn decoding_key_from_public_b64(public_b64: &str) -> Result<DecodingKey, String> {
    let raw = B64
        .decode(public_b64.trim())
        .map_err(|e| format!("offline_cap public key: invalid base64: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "offline_cap public key: expected 32 raw Ed25519 bytes, got {}",
            raw.len()
        ));
    }
    Ok(DecodingKey::from_ed_der(&raw))
}

/// Context a target device binds an incoming offline capability against.
#[derive(Debug, Clone, Copy)]
pub struct VerifyContext<'a> {
    pub expected_verb: &'a str,
    pub expected_tid: &'a str,
    pub expected_net: &'a str,
    pub expected_tgt: &'a str,
    pub expected_opk: &'a str,
    pub now_secs: u64,
    pub not_before_ms: Option<u64>,
}

/// Verify an offline capability JWT against the tenant's cached Ed25519 public
/// keys and the exact authenticated target/origin/network/verb context.
pub fn verify_offline_cap(
    token: &str,
    public_keys_b64: &[String],
    ctx: VerifyContext<'_>,
) -> Result<OfflineCapClaims, String> {
    if public_keys_b64.is_empty() {
        return Err("offline access is not enabled for this organization".into());
    }
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[OFFLINE_CAP_AUDIENCE]);
    // Enforce explicit `ctx.now_secs` bounds below instead of ambient wall clock.
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let mut decoded: Option<OfflineCapClaims> = None;
    let mut last_err = String::from("no valid verification key");
    for key_b64 in public_keys_b64 {
        let key = match decoding_key_from_public_b64(key_b64) {
            Ok(k) => k,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        match jsonwebtoken::decode::<OfflineCapClaims>(token.trim(), &key, &validation) {
            Ok(data) => {
                decoded = Some(data.claims);
                break;
            }
            Err(e) => {
                last_err = format!("signature/format error: {e}");
            }
        }
    }
    let claims = decoded.ok_or_else(|| format!("offline_cap verify failed: {last_err}"))?;

    if claims.aud != OFFLINE_CAP_AUDIENCE {
        return Err("offline_cap audience mismatch".into());
    }
    if claims.jti.trim().is_empty() {
        return Err("offline_cap missing jti".into());
    }
    if claims.exp <= claims.iat {
        return Err("offline_cap malformed lifetime (exp <= iat)".into());
    }
    if claims.exp <= ctx.now_secs {
        return Err("offline_cap expired".into());
    }
    if claims.iat > ctx.now_secs.saturating_add(OFFLINE_CAP_MAX_SKEW_SECS) {
        return Err("offline_cap issued in the future (clock skew exceeded)".into());
    }
    if let Some(nb_ms) = ctx.not_before_ms
        && claims.iat.saturating_mul(1000) < nb_ms
    {
        return Err("offline_cap revoked by organization not_before cutoff".into());
    }
    if claims.verb != ctx.expected_verb {
        return Err(format!(
            "offline_cap verb mismatch (got {:?}, expected {:?})",
            claims.verb, ctx.expected_verb
        ));
    }
    if claims.tid != ctx.expected_tid {
        return Err("offline_cap tenant mismatch".into());
    }
    if claims.net != ctx.expected_net {
        return Err("offline_cap network mismatch".into());
    }
    if claims.tgt != ctx.expected_tgt {
        return Err("offline_cap target device mismatch".into());
    }
    if claims.opk != ctx.expected_opk {
        return Err("offline_cap origin WireGuard key mismatch".into());
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims(verb: &str, iat: u64, exp: u64) -> OfflineCapClaims {
        OfflineCapClaims {
            aud: OFFLINE_CAP_AUDIENCE.into(),
            verb: verb.into(),
            net: "660000000000000000000001".into(),
            tid: "660000000000000000000002".into(),
            tgt: "660000000000000000000003".into(),
            org: "660000000000000000000004".into(),
            opk: "b3JpZ2luLXdnLXB1YmtleS0xMjM0NTY3ODkwMTIzNDU=".into(),
            caller: "alice (via laptop-a)".into(),
            jti: "660000000000000000000099".into(),
            iat,
            exp,
            ssh_account_mode: (verb == VERB_SSH).then(|| "console_user".into()),
            ssh_account: None,
            ssh_max_session_secs: (verb == VERB_SSH).then_some(3600),
            exec_shells: (verb == VERB_EXEC).then(|| vec!["sh".into(), "bash".into()]),
            exec_run_as: (verb == VERB_EXEC).then(|| "console_user".into()),
            exec_max_timeout_ms: (verb == VERB_EXEC).then_some(60_000),
            consent_mode: Some("auto".into()),
        }
    }

    fn base_ctx(verb: &str, now_secs: u64) -> VerifyContext<'static> {
        VerifyContext {
            expected_verb: match verb {
                "ssh" => VERB_SSH,
                _ => VERB_EXEC,
            },
            expected_tid: "660000000000000000000002",
            expected_net: "660000000000000000000001",
            expected_tgt: "660000000000000000000003",
            expected_opk: "b3JpZ2luLXdnLXB1YmtleS0xMjM0NTY3ODkwMTIzNDU=",
            now_secs,
            not_before_ms: None,
        }
    }

    #[test]
    fn fr139_offline_cap_roundtrip_and_jwt_secret_rotation() {
        let now = 1_770_000_000u64;
        let old_signer = OfflineCapSigner::from_jwt_secrets("secret-v1", &[]);
        let token = old_signer
            .mint(&sample_claims(VERB_SSH, now - 60, now + 3600))
            .unwrap();

        // After rotating jwt.secret from secret-v1 -> secret-v2 (keeping v1 in
        // previous_secrets), the new signer's public_keys_b64 still verifies
        // tokens minted before rotation!
        let rotated =
            OfflineCapSigner::from_jwt_secrets("secret-v2", &[String::from("secret-v1")]);
        assert_eq!(rotated.public_keys_b64().len(), 2);
        let verified = verify_offline_cap(&token, rotated.public_keys_b64(), base_ctx(VERB_SSH, now))
            .expect("rotated key set must verify pre-rotation capability");
        assert_eq!(verified.verb, VERB_SSH);
        assert_eq!(verified.caller, "alice (via laptop-a)");

        // Unrelated signer must reject.
        let foreign = OfflineCapSigner::from_jwt_secrets("foreign-secret", &[]);
        assert!(
            verify_offline_cap(&token, foreign.public_keys_b64(), base_ctx(VERB_SSH, now)).is_err()
        );
    }

    #[test]
    fn fr139_offline_cap_rejects_cross_verb_cross_scope_expiry_skew_and_not_before() {
        let now = 1_770_000_000u64;
        let signer = OfflineCapSigner::from_jwt_secrets("primary-secret", &[]);
        let keys = signer.public_keys_b64();
        let ssh_tok = signer
            .mint(&sample_claims(VERB_SSH, now - 60, now + 3600))
            .unwrap();

        // Cross-verb (ssh cap used for exec) -> refused.
        assert!(verify_offline_cap(&ssh_tok, keys, base_ctx(VERB_EXEC, now)).is_err());

        // Cross-tenant, cross-net, cross-target, wrong opk -> all refused.
        let mut c = base_ctx(VERB_SSH, now);
        c.expected_tid = "other-tid";
        assert!(verify_offline_cap(&ssh_tok, keys, c).is_err());
        let mut c = base_ctx(VERB_SSH, now);
        c.expected_net = "other-net";
        assert!(verify_offline_cap(&ssh_tok, keys, c).is_err());
        let mut c = base_ctx(VERB_SSH, now);
        c.expected_tgt = "other-tgt";
        assert!(verify_offline_cap(&ssh_tok, keys, c).is_err());
        let mut c = base_ctx(VERB_SSH, now);
        c.expected_opk = "wrong-opk";
        assert!(verify_offline_cap(&ssh_tok, keys, c).is_err());

        // Expired -> refused.
        assert!(verify_offline_cap(&ssh_tok, keys, base_ctx(VERB_SSH, now + 3600)).is_err());

        // Future-dated beyond skew -> refused.
        let future_tok = signer
            .mint(&sample_claims(
                VERB_SSH,
                now + OFFLINE_CAP_MAX_SKEW_SECS + 10,
                now + 7200,
            ))
            .unwrap();
        assert!(verify_offline_cap(&future_tok, keys, base_ctx(VERB_SSH, now)).is_err());

        // Revoked via not_before_ms -> refused.
        let mut c = base_ctx(VERB_SSH, now);
        c.not_before_ms = Some((now - 30) * 1000);
        assert!(verify_offline_cap(&ssh_tok, keys, c).is_err());

        // Empty public_keys (offline_access disabled) -> refused.
        assert!(verify_offline_cap(&ssh_tok, &[], base_ctx(VERB_SSH, now)).is_err());
    }
}
