// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-128 — a management entry's attestation: what a zone gateway that forwards a device's
//! management connection says about that device's address, signed for the centre.
//!
//! The entry forwards the device's TLS to the centre without reading it, so the centre sees the
//! ENTRY's address. Before the device opens its control socket through an entry, it asks the entry
//! (same port, one line) for a token naming the address the entry saw it come from. The centre
//! accepts that address as the connection's origin only after checking the token: HS256 under the
//! entry's own key (`kid` = the entry's agent id), at most [`MAX_AGE_SECS`] old, presented by a
//! connection that really comes from that entry. The entry key is derived from the server secret
//! ([`derive_key`]), so the centre stores nothing, and an entry holds a key that can sign for it
//! alone, never the secret.
//!
//! The line protocol on the entry port: a connection whose first bytes are [`PREFIX`] is a request
//! (`MHE1 attest <nonce>\n`), answered by one line (`MHE1 ok <token>\n` or `MHE1 no <reason>\n`)
//! and closed. Every other connection is forwarded raw.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The first bytes of an attestation request. A TLS ClientHello starts with `0x16`, so the two
/// can never be confused.
pub const PREFIX: &[u8] = b"MHE1 ";
/// The longest line either side reads.
pub const MAX_LINE: usize = 1024;
/// How old a token may be when the centre checks it (also the bound for a clock running ahead).
pub const MAX_AGE_SECS: i64 = 120;
const AUDIENCE: &str = "meshharbor-management-entry";
const KEY_CONTEXT: &[u8] = b"fr128-entry-v1";

/// An entry's signing key on the wire (base64). Its `Debug` never prints it, so a logged frame
/// cannot leak it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryKey(pub String);

impl std::fmt::Debug for EntryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryKey(<redacted>)")
    }
}

impl EntryKey {
    pub fn from_bytes(key: &[u8]) -> Self {
        use base64::Engine;
        Self(base64::engine::general_purpose::STANDARD.encode(key))
    }
    pub fn bytes(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.0)
            .ok()
            .filter(|k| k.len() >= 32)
    }
}

/// What an entry attests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The device's source address, as the entry's socket saw it.
    pub ip: IpAddr,
    /// The device's nonce: binds the token to one request.
    pub n: String,
    /// Unix seconds, entry clock.
    pub iat: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    ip: IpAddr,
    n: String,
    iat: i64,
    exp: i64,
}

/// Why a token was refused. Each one is logged by the centre; none of them is told to the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    NoEntryId,
    BadSignature,
    Stale,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NoEntryId => "no_entry_id",
            Self::BadSignature => "bad_signature",
            Self::Stale => "stale",
        }
    }
}

/// The entry's key: `HMAC-SHA256(server secret, context ‖ entry id ‖ token generation)`.
/// Re-issuing the entry's credentials (a new generation) rotates it.
pub fn derive_key(server_secret: &[u8], entry_id_hex: &str, token_generation: u32) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, server_secret);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(KEY_CONTEXT);
    ctx.update(&[0]);
    ctx.update(entry_id_hex.as_bytes());
    ctx.update(&[0]);
    ctx.update(&token_generation.to_be_bytes());
    ctx.sign().as_ref().to_vec()
}

/// A nonce the entry accepts: 16 to 64 lowercase hex characters.
pub fn valid_nonce(n: &str) -> bool {
    (16..=64).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Entry side: sign what it saw.
pub fn sign(
    key: &[u8],
    entry_id_hex: &str,
    ip: IpAddr,
    nonce: &str,
    now: i64,
) -> Result<String, String> {
    if !valid_nonce(nonce) {
        return Err("nonce".into());
    }
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(entry_id_hex.to_string());
    let claims = Claims {
        aud: AUDIENCE.into(),
        ip,
        n: nonce.into(),
        iat: now,
        exp: now + MAX_AGE_SECS,
    };
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(key))
        .map_err(|e| e.to_string())
}

/// Centre side, step 1: the entry the token claims to come from (unverified — it only picks the key).
pub fn entry_id(token: &str) -> Result<String, Refusal> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| Refusal::Malformed)?;
    if header.alg != Algorithm::HS256 {
        return Err(Refusal::Malformed);
    }
    header
        .kid
        .filter(|k| !k.is_empty())
        .ok_or(Refusal::NoEntryId)
}

/// Centre side, step 2: verify under that entry's key. `now` is the centre's clock; a token
/// issued more than [`MAX_AGE_SECS`] before it, or after it by as much, is stale.
pub fn verify(key: &[u8], token: &str, now: i64) -> Result<Attestation, Refusal> {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_audience(&[AUDIENCE]);
    // Expiry is judged below against the centre's clock and `iat`, both ways.
    v.validate_exp = false;
    v.required_spec_claims.clear();
    let data =
        jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(key), &v).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => Refusal::BadSignature,
                _ => Refusal::Malformed,
            }
        })?;
    let c = data.claims;
    if (now - c.iat).abs() > MAX_AGE_SECS || !valid_nonce(&c.n) {
        return Err(Refusal::Stale);
    }
    Ok(Attestation {
        ip: c.ip,
        n: c.n,
        iat: c.iat,
    })
}

/// `MHE1 attest <nonce>\n`
pub fn request_line(nonce: &str) -> String {
    format!("MHE1 attest {nonce}\n")
}

/// The nonce of a request line (trailing `\r\n` tolerated).
pub fn parse_request(line: &str) -> Option<&str> {
    let n = line
        .trim_end_matches(['\r', '\n'])
        .strip_prefix("MHE1 attest ")?;
    valid_nonce(n).then_some(n)
}

/// `MHE1 ok <token>\n`
pub fn ok_line(token: &str) -> String {
    format!("MHE1 ok {token}\n")
}

/// `MHE1 no <reason>\n` — the entry cannot attest (no key yet, a bad request).
pub fn no_line(reason: &str) -> String {
    format!("MHE1 no {reason}\n")
}

/// The token of an answer line; `Err(reason)` for a refusal or anything else.
pub fn parse_answer(line: &str) -> Result<&str, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(t) = line.strip_prefix("MHE1 ok ") {
        return Ok(t);
    }
    Err(line
        .strip_prefix("MHE1 no ")
        .unwrap_or("unrecognised answer")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn key(entry: &str) -> Vec<u8> {
        derive_key(b"server-secret", entry, 1)
    }

    #[test]
    fn a_token_round_trips_under_its_entrys_key() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t = sign(&key("aa"), "aa", ip, NONCE, 1_000).unwrap();
        assert_eq!(entry_id(&t).unwrap(), "aa");
        let a = verify(&key("aa"), &t, 1_050).unwrap();
        assert_eq!(a.ip, ip);
        assert_eq!(a.n, NONCE);
    }

    #[test]
    fn another_entrys_key_a_new_generation_or_a_forged_tag_is_refused() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t = sign(&key("aa"), "aa", ip, NONCE, 1_000).unwrap();
        assert_eq!(verify(&key("bb"), &t, 1_000), Err(Refusal::BadSignature));
        assert_eq!(
            verify(&derive_key(b"server-secret", "aa", 2), &t, 1_000),
            Err(Refusal::BadSignature)
        );
        // A character inside the tag (the last one may carry only padding bits).
        let mut forged: Vec<char> = t.chars().collect();
        let i = forged.len() - 10;
        forged[i] = if forged[i] == 'A' { 'B' } else { 'A' };
        let forged: String = forged.into_iter().collect();
        assert_eq!(
            verify(&key("aa"), &forged, 1_000),
            Err(Refusal::BadSignature)
        );
    }

    #[test]
    fn a_token_is_stale_past_its_age_either_way() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let t = sign(&key("aa"), "aa", ip, NONCE, 1_000).unwrap();
        assert!(verify(&key("aa"), &t, 1_000 + MAX_AGE_SECS).is_ok());
        assert_eq!(
            verify(&key("aa"), &t, 1_001 + MAX_AGE_SECS),
            Err(Refusal::Stale)
        );
        assert_eq!(
            verify(&key("aa"), &t, 999 - MAX_AGE_SECS),
            Err(Refusal::Stale)
        );
    }

    #[test]
    fn junk_and_a_token_without_an_entry_id_are_refused() {
        assert_eq!(entry_id("not a token"), Err(Refusal::Malformed));
        let claims = Claims {
            aud: AUDIENCE.into(),
            ip: "192.0.2.1".parse().unwrap(),
            n: NONCE.into(),
            iat: 1,
            exp: 2,
        };
        let t = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"k"),
        )
        .unwrap();
        assert_eq!(entry_id(&t), Err(Refusal::NoEntryId));
    }

    #[test]
    fn the_line_protocol_parses_its_own_lines_only() {
        assert_eq!(parse_request(&request_line(NONCE)), Some(NONCE));
        assert_eq!(parse_request("MHE1 attest nothex\n"), None);
        assert_eq!(parse_request("MHE1 attest abc\n"), None);
        assert_eq!(parse_answer(&ok_line("tok")), Ok("tok"));
        assert_eq!(parse_answer(&no_line("no_key")), Err("no_key".to_string()));
        assert!(parse_answer("HTTP/1.1 400").is_err());
        assert!(sign(&key("aa"), "aa", "192.0.2.1".parse().unwrap(), "XYZ", 1).is_err());
    }
}
