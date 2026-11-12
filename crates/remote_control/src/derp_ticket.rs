// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! DERP relay tickets — EdDSA-signed admission for the standalone regional
//! relays (`crates/derp-relay`).
//!
//! Regional PoPs are cheap VPSes and must hold MINIMAL secrets: never the JWT
//! signing secret (symmetric — holding it means forging any user/agent token).
//! Instead the API mints a short, narrowly-scoped ticket with an Ed25519
//! PRIVATE key, and each relay verifies with the PUBLIC key only. A ticket
//! binds `{network, wg pubkey}`, so a relay can enforce exactly the two
//! invariants the central `/derp` enforces from Mongo — register-your-own-key
//! and same-network forwarding — without any database access.
//!
//! Key format: `MESHHARBOR__RELAY__DERP_TICKET_PRIVATE_KEY` = base64(PKCS#8 DER)
//! (`openssl genpkey -algorithm ed25519 -outform DER | base64 -w0`). The
//! relay's `DERP_TICKET_PUBLIC_KEY` = base64(raw 32-byte public key) — logged
//! by the API at startup for copy-paste.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

/// Re-exported for `crates/derp-relay`, so the relay binary shares this exact
/// jsonwebtoken (no version drift between mint and verify).
pub use jsonwebtoken;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Ticket lifetime. Long — admission is checked at accept-time only (exactly
/// like the central `/derp`'s JWT check), so expiry mid-connection is a
/// non-event; agents refresh at ~90 % anyway.
pub const DERP_TICKET_TTL: Duration = Duration::from_secs(24 * 3600);
/// Clock-skew tolerance on verification (cheap VPSes drift).
pub const DERP_TICKET_LEEWAY_SECS: u64 = 300;
const DERP_AUDIENCE: &str = "derp";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpTicketClaims {
    /// Always `"derp"` — never interchangeable with user/agent JWTs.
    pub aud: String,
    /// Overlay network id (hex) — the relay's forwarding scope.
    pub net: String,
    /// base64 WG public key — the ONLY key this ticket may register.
    pub pk: String,
    pub exp: u64,
    /// MeshHarbor #21: the node's business zone (`mainland` | `non_mainland`).
    /// The API sets it exactly when it ENFORCES business isolation, and then
    /// mints no ticket at all for a node with no known zone. A PoP delivers a
    /// frame only between two registrations whose `zone` is EQUAL, where
    /// absent equals absent. So a zoned node never meets an unzoned one, and
    /// a pre-#21 ticket (absent) keeps working with another pre-#21 ticket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

/// The API-side minting half. Built from the configured private key; derives
/// and exposes the public half so operators can copy it to PoPs.
pub struct DerpTicketSigner {
    enc: EncodingKey,
    public_b64: String,
}

impl DerpTicketSigner {
    /// Load from base64(PKCS#8 DER). Errors on undecodable/non-Ed25519 input.
    pub fn from_pkcs8_b64(private_b64: &str) -> Result<Self, String> {
        let der = B64
            .decode(private_b64.trim())
            .map_err(|e| format!("derp ticket key: invalid base64: {e}"))?;
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
            .map_err(|e| format!("derp ticket key: not an Ed25519 PKCS#8 key: {e}"))?;
        use ring::signature::KeyPair as _;
        let public_b64 = B64.encode(pair.public_key().as_ref());
        Ok(Self {
            enc: EncodingKey::from_ed_der(&der),
            public_b64,
        })
    }

    /// base64(raw 32-byte Ed25519 public key) — what a relay's
    /// `DERP_TICKET_PUBLIC_KEY` must be set to.
    pub fn public_key_b64(&self) -> &str {
        &self.public_b64
    }

    /// Mint a ticket for `(network hex, wg pubkey b64)`. Returns
    /// `(token, exp_unix)`.
    pub fn mint(&self, network_hex: &str, wg_pubkey_b64: &str) -> Result<(String, u64), String> {
        self.mint_in_zone(network_hex, wg_pubkey_b64, None)
    }

    /// [`Self::mint`] carrying the node's business zone (see
    /// [`DerpTicketClaims::zone`]). `None` mints the pre-#21 ticket.
    pub fn mint_in_zone(
        &self,
        network_hex: &str,
        wg_pubkey_b64: &str,
        zone: Option<&str>,
    ) -> Result<(String, u64), String> {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + DERP_TICKET_TTL.as_secs();
        let claims = DerpTicketClaims {
            aud: DERP_AUDIENCE.to_string(),
            net: network_hex.to_string(),
            pk: wg_pubkey_b64.to_string(),
            exp,
            zone: zone.map(str::to_string),
        };
        let token = jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &self.enc)
            .map_err(|e| format!("derp ticket mint: {e}"))?;
        Ok((token, exp))
    }
}

/// Build the relay-side verification key from base64(raw 32-byte public key).
pub fn decoding_key_from_public_b64(public_b64: &str) -> Result<DecodingKey, String> {
    let raw = B64
        .decode(public_b64.trim())
        .map_err(|e| format!("derp ticket public key: invalid base64: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "derp ticket public key: expected 32 raw Ed25519 bytes, got {}",
            raw.len()
        ));
    }
    Ok(DecodingKey::from_ed_der(&raw))
}

/// Verify a ticket: EdDSA signature, `aud == "derp"`, unexpired (with leeway).
/// The CALLER must additionally check the first registration frame's pubkey
/// equals `claims.pk` — that binding is what stops a stolen ticket from
/// registering someone else's key.
pub fn verify(token: &str, key: &DecodingKey) -> Result<DerpTicketClaims, String> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[DERP_AUDIENCE]);
    validation.leeway = DERP_TICKET_LEEWAY_SECS;
    jsonwebtoken::decode::<DerpTicketClaims>(token, key, &validation)
        .map(|d| d.claims)
        .map_err(|e| format!("derp ticket verify: {e}"))
}

/// FR-115 P4a-2 — the audience of a signed over-allowance set. Distinct from
/// a ticket's, so neither can stand in for the other: a set admits nobody,
/// and a ticket says nothing about a throttle.
pub const ALLOWANCE_AUDIENCE: &str = "derp-allowance";
/// Clock-skew tolerance on a set's `exp`. Small, unlike a ticket's: a set is
/// re-pushed every poll and lives a few of them, and a PoP times it from
/// ARRIVAL anyway, so the leeway only bounds how long a captured set replays.
pub const ALLOWANCE_LEEWAY_SECS: u64 = 30;

/// FR-115 P4a-2 — the over-allowance set as the API pushes it to a regional
/// PoP, on the `/stats` poll it already makes, signed with the key the PoP
/// already verifies tickets with. The PoP stays DB-free: it is told which
/// networks to hold back, and at what rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceSetClaims {
    /// Always [`ALLOWANCE_AUDIENCE`].
    pub aud: String,
    /// When the API signed it (unix seconds). A PoP never replaces the set it
    /// holds with an OLDER one, so a captured set cannot be replayed over a
    /// newer one.
    pub iat: u64,
    pub exp: u64,
    /// How long a PoP keeps the set after it ARRIVES, unless a newer one
    /// replaces it; then it lapses and nothing is throttled (fail open).
    pub ttl: u64,
    /// Overlay network id (hex) → throttled rate (bytes/s). Empty: nobody is
    /// throttled, which is also how the API's kill switch reaches a PoP.
    pub set: BTreeMap<String, u64>,
}

impl DerpTicketSigner {
    /// FR-115 P4a-2 — sign the over-allowance set for the PoPs. It lapses
    /// `ttl_secs` after a PoP receives it, and expires (bounding a replay)
    /// `ttl_secs` after it was signed.
    pub fn sign_allowance_set(
        &self,
        set: BTreeMap<String, u64>,
        ttl_secs: u64,
    ) -> Result<String, String> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let claims = AllowanceSetClaims {
            aud: ALLOWANCE_AUDIENCE.to_string(),
            iat,
            exp: iat + ttl_secs,
            ttl: ttl_secs,
            set,
        };
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &self.enc)
            .map_err(|e| format!("allowance set sign: {e}"))
    }
}

/// FR-115 P4a-2 — verify a pushed set: EdDSA signature by the ticket key,
/// `aud == "derp-allowance"`, unexpired within [`ALLOWANCE_LEEWAY_SECS`]. The
/// CALLER keeps the newest `iat` and times the set from its arrival.
pub fn verify_allowance_set(token: &str, key: &DecodingKey) -> Result<AllowanceSetClaims, String> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[ALLOWANCE_AUDIENCE]);
    validation.leeway = ALLOWANCE_LEEWAY_SECS;
    jsonwebtoken::decode::<AllowanceSetClaims>(token, key, &validation)
        .map(|d| d.claims)
        .map_err(|e| format!("allowance set verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> (DerpTicketSigner, DecodingKey) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = DerpTicketSigner::from_pkcs8_b64(&B64.encode(pkcs8.as_ref())).unwrap();
        let key = decoding_key_from_public_b64(signer.public_key_b64()).unwrap();
        (signer, key)
    }

    #[test]
    fn mint_verify_roundtrip() {
        let (signer, key) = test_signer();
        let (token, exp) = signer.mint("6a54bf440b4fd609a7356f97", "cHVia2V5").unwrap();
        let claims = verify(&token, &key).expect("fresh ticket verifies");
        assert_eq!(claims.aud, "derp");
        assert_eq!(claims.net, "6a54bf440b4fd609a7356f97");
        assert_eq!(claims.pk, "cHVia2V5");
        assert_eq!(claims.exp, exp);
        assert_eq!(claims.zone, None, "a plain mint carries no zone");
    }

    /// #21 — the zone claim round-trips, and is absent from a plain mint's
    /// payload, so a ticket minted without isolation is byte-shaped like the
    /// pre-#21 ones.
    #[test]
    fn a_zoned_ticket_carries_its_zone_and_a_plain_one_omits_it() {
        let (signer, key) = test_signer();
        let (zoned, _) = signer
            .mint_in_zone("6a54bf440b4fd609a7356f97", "cHVia2V5", Some("mainland"))
            .unwrap();
        assert_eq!(
            verify(&zoned, &key).unwrap().zone.as_deref(),
            Some("mainland")
        );
        let (plain, _) = signer.mint("6a54bf440b4fd609a7356f97", "cHVia2V5").unwrap();
        let payload = plain.split('.').nth(1).unwrap();
        let json = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap();
        assert!(
            !json.contains("zone"),
            "plain ticket omits the claim: {json}"
        );
    }

    #[test]
    fn wrong_key_and_tampering_rejected() {
        let (signer, _) = test_signer();
        let (_, other_key) = test_signer();
        let (token, _) = signer.mint("net", "pk").unwrap();
        assert!(verify(&token, &other_key).is_err(), "foreign key must fail");
        let mut tampered = token.clone();
        tampered.pop();
        assert!(verify(&tampered, &other_key).is_err());
    }

    /// FR-115 P4a-2 — a set round-trips under the ticket key, and a ticket
    /// and a set can never stand in for each other.
    #[test]
    fn an_allowance_set_is_its_own_audience() {
        let (signer, key) = test_signer();
        let set = BTreeMap::from([("6a54bf440b4fd609a7356f97".to_string(), 125_000u64)]);
        let token = signer.sign_allowance_set(set.clone(), 90).unwrap();
        let claims = verify_allowance_set(&token, &key).expect("a fresh set verifies");
        assert_eq!(claims.aud, ALLOWANCE_AUDIENCE);
        assert_eq!(claims.set, set);
        assert_eq!((claims.ttl, claims.exp - claims.iat), (90, 90));

        assert!(verify(&token, &key).is_err(), "a set admits nobody");
        let (ticket, _) = signer.mint("6a54bf440b4fd609a7356f97", "cHVia2V5").unwrap();
        assert!(
            verify_allowance_set(&ticket, &key).is_err(),
            "a ticket is not a set"
        );
        let (_, other_key) = test_signer();
        assert!(
            verify_allowance_set(&token, &other_key).is_err(),
            "a foreign key"
        );
    }

    /// A set signed long ago is refused past the small leeway.
    #[test]
    fn an_expired_allowance_set_is_refused() {
        let (signer, key) = test_signer();
        let claims = AllowanceSetClaims {
            aud: ALLOWANCE_AUDIENCE.to_string(),
            iat: 1_000,
            exp: 1_090,
            ttl: 90,
            set: BTreeMap::new(),
        };
        let token =
            jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &signer.enc).unwrap();
        assert!(verify_allowance_set(&token, &key).is_err());
    }

    #[test]
    fn public_key_is_raw_32_bytes() {
        let (signer, _) = test_signer();
        let raw = B64.decode(signer.public_key_b64()).unwrap();
        assert_eq!(raw.len(), 32);
        assert!(decoding_key_from_public_b64("not-base64!!").is_err());
        assert!(decoding_key_from_public_b64(&B64.encode([0u8; 16])).is_err());
    }
}
