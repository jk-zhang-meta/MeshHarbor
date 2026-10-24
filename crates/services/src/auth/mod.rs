// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use bson::oid::ObjectId;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use roomler_ai_config::JwtSettings;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Password hash error: {0}")]
    HashError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub email: String,
    pub username: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
    /// Missing pre-approval JWTs are generation zero for migration compatibility.
    #[serde(default)]
    pub approval_revision: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,
    Refresh,
    /// Single-use, short-lived token used to enroll a remote-control agent.
    Enrollment,
    /// FR-51 P2 — REUSABLE key that enrolls EPHEMERAL agents. Its own
    /// audience so a leaked one can never pass a gate expecting the
    /// single-use kind (or vice versa); the `jti` is checked against the
    /// `enrollment_keys` row on every use — the JWT alone grants nothing.
    EphemeralEnrollment,
    /// Long-lived token carried by an enrolled remote-control agent.
    Agent,
    /// Single-use, short-lived bootstrap token an admin issues to the
    /// operator. Exchanged for a long-lived `TunnelClient` token via
    /// `POST /api/tunnel-client/enroll`.
    TunnelEnrollment,
    /// Long-lived token carried by an enrolled `roomler` client
    /// on its WebSocket connection (`role=tunnel-client`). Audience
    /// distinct from `Agent` — agents serve forwards, clients open them.
    TunnelClient,
    /// FR-94 — the long-lived credential of a Windows device's SYSTEM
    /// service, minted by `POST /api/agent/anchor` for a device an
    /// administrator anchored, and kept in a SYSTEM + Administrators-only
    /// file. It authorises exactly two things, claiming a pending Fleet RPC
    /// for its own device and posting that command's result. Its own audience
    /// because the agent token sits in the signed-in user's writable config
    /// on an attended install: a user who could swap one for the other could
    /// tell SYSTEM what to run (FR-94 §4).
    AgentService,
    /// FR-90 P3-7-1b — the vault's grant of one agent session's own egress
    /// (`rc:vault.net`), which the network module verifies when the device
    /// opens the tunnel. Its own audience, so no other gate accepts it and it
    /// accepts no other credential: it acts for a session, never for the
    /// device or a person.
    NetGrant,
    /// FR-90 P3-8-1a — the vault's ticket for one agent session's command on
    /// another device over Roomler SSH (`rc:vault.ssh`), which the network
    /// module verifies at `rc:ssh.request` (P3-8-1b). Its own audience, so no
    /// other gate accepts it and it accepts no other credential, a net grant
    /// included: it acts for a session, never for the device or a person.
    SshTicket,
}

/// Claims carried by a remote-control enrollment token (aud = enroll).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentClaims {
    pub sub: String, // issuer-user id (admin who created the token)
    pub tenant_id: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
    pub jti: String, // unique id — caller may persist for single-use checks
    /// FR-104 — the admin minted this token to also ANCHOR the device it
    /// enrolls: `POST /api/agent/anchor` accepts it a second time, for that
    /// one device, once. Absent from every older token (and from every token
    /// minted without it), which parses as `false`: one use, as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub anchor: bool,
    /// An administrator explicitly authorized this single-use credential to
    /// approve the device as an org relay. Never a device-supplied role.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub relay_server: bool,
}

/// Claims carried by a remote-control agent token (aud = agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClaims {
    pub sub: String, // agent_id hex
    pub tenant_id: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
    /// FR-103: the device row's token generation when this token was minted.
    /// Removing a device bumps the row's generation, so every token minted
    /// before the removal is refused, even after the same machine re-enrolls
    /// and revives the row. Every token minted before FR-103 has none: 0,
    /// which matches every row that was never removed.
    #[serde(default, rename = "gen")]
    pub generation: u32,
}

/// FR-103: how long past its `exp` an agent or tunnel-client token may still
/// buy a fresh one, on the renew routes ONLY. A device that slept through its
/// anniversary updates (the release routes are unauthenticated), renews and
/// reconnects without hands on the machine. Long enough for a laptop left in
/// a drawer over a holiday quarter, short enough that a year-old stolen token
/// stays dead. Every other route enforces `exp` as before.
pub const RENEWAL_GRACE_SECS: i64 = 90 * 24 * 60 * 60;

/// FR-94 — claims carried by a Windows device's SYSTEM-service credential.
/// The agent token's shape plus `anchor_id`, which names the anchor that
/// minted it: the credential is accepted only while that is still the
/// device's anchor, so re-anchoring revokes it. Required, not optional, so a
/// token without the binding does not even parse as one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentServiceClaims {
    pub sub: String, // agent_id hex
    pub tenant_id: String,
    pub anchor_id: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
}

/// Claims carried by a `roomler` client token. Long-lived,
/// one per enrolled laptop. `owner_user_id` lets the WS handler
/// associate every forward decision with the operating user for
/// audit + policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelClientClaims {
    /// `tunnel_client._id` hex.
    pub sub: String,
    pub tenant_id: String,
    /// User who installed and runs this CLI. Recorded in
    /// `tunnel_audit` rows alongside every forward decision.
    pub owner_user_id: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
    /// FR-103: the client row's token generation, as for [`AgentClaims::generation`].
    #[serde(default, rename = "gen")]
    pub generation: u32,
}

/// FR-90 P3-7-1b — claims carried by a session's egress grant (`net_grant`).
/// It names one session at one fence, running on one device, and the one
/// exit its flows leave through: for a forward one destination, for SOCKS
/// none. It lives at most a lease's ceiling.
///
/// ⚠️ The network module believes a flow under it only from the device it
/// names as the origin: a grant copied to another device opens nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetGrantClaims {
    /// The session's id, hex.
    pub sub: String,
    pub tenant_id: String,
    /// The session's fence when the vault decided.
    pub fence: u64,
    /// The person the session acts for, hex.
    pub owner_user_id: String,
    /// The device the session runs on, hex: the only one that may use it.
    pub origin_agent_id: String,
    /// The device the flows exit through, hex.
    pub exit_agent_id: String,
    /// A `roomler_ai_remote_control::vault::NetKind` word.
    pub net: String,
    /// A forward's one destination, as `canonical_net_host` spells it;
    /// empty for SOCKS.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dst_host: String,
    #[serde(default, skip_serializing_if = "is_zero_port")]
    pub dst_port: u16,
    /// The grant's id, as the vault records its allow (`grant:<jti>`).
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
}

fn is_zero_port(port: &u16) -> bool {
    *port == 0
}

/// FR-90 P3-7-1b — what the vault grants: every claim but the issuer, the
/// audience and the start, which the auth service fills.
#[derive(Debug, Clone, Copy)]
pub struct NetGrant<'a> {
    pub session_id: ObjectId,
    pub tenant_id: ObjectId,
    pub fence: u64,
    pub owner_user_id: ObjectId,
    pub origin_agent_id: ObjectId,
    pub exit_agent_id: ObjectId,
    pub net: roomler_ai_remote_control::vault::NetKind,
    /// A forward's destination, its host canonical; `None` for SOCKS.
    pub dst: Option<(&'a str, u16)>,
    pub grant_id: ObjectId,
    /// When it ends, in seconds since the epoch: at most
    /// `lease_limits::MAX_TTL_SECS` from now.
    pub exp: i64,
}

/// FR-90 P3-8-1a — claims carried by a session's SSH ticket (`ssh_ticket`).
/// It names one session at one fence, running on one device, the one other
/// device its command runs on, and the account that device's SSH policy
/// mapped when the vault decided. It lives at most a lease's ceiling.
///
/// ⚠️ Never the device it runs on: a session already runs there, as its own
/// account, and SSH would run it as whatever that device maps, the daemon's
/// among them. No such ticket is signed, and none is believed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshTicketClaims {
    /// The session's id, hex.
    pub sub: String,
    pub tenant_id: String,
    /// The session's fence when the vault decided.
    pub fence: u64,
    /// The person the session acts for, hex.
    pub owner_user_id: String,
    /// The device the session runs on, hex: the only one that may use it.
    pub origin_agent_id: String,
    /// The device the command runs on, hex: never the origin.
    pub target_agent_id: String,
    /// The account the target's SSH policy mapped when the vault decided, a
    /// `roomler_ai_remote_control::models::SshAccountMode` word.
    pub account: String,
    /// The ticket's id, as the vault records its allow (`ticket:<jti>`).
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
}

/// FR-90 P3-8-1a — what the vault tickets: every claim but the issuer, the
/// audience and the start, which the auth service fills.
#[derive(Debug, Clone, Copy)]
pub struct SshTicket {
    pub session_id: ObjectId,
    pub tenant_id: ObjectId,
    pub fence: u64,
    pub owner_user_id: ObjectId,
    pub origin_agent_id: ObjectId,
    pub target_agent_id: ObjectId,
    pub account: roomler_ai_remote_control::models::SshAccountMode,
    pub ticket_id: ObjectId,
    /// When it ends, in seconds since the epoch: at most
    /// `lease_limits::MAX_TTL_SECS` from now.
    pub exp: i64,
}

/// Claims carried by a tunnel-enrollment token. Mirrors
/// [`EnrollmentClaims`] (single-use via `jti`, short TTL) but its
/// own audience so a leaked agent-enrollment can't bootstrap a
/// tunnel client and vice-versa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEnrollmentClaims {
    /// Admin user id (issuer) as hex.
    pub sub: String,
    pub tenant_id: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub token_type: TokenType,
    /// Unique id — caller may persist for single-use checks.
    pub jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// One HMAC secret, plus the `kid` that names it on the wire.
///
/// The `kid` is DERIVED from the secret rather than configured beside it, so
/// the two cannot drift: an operator sets secrets and nothing else, and a
/// mislabelled key is unrepresentable. It is domain-separated and truncated —
/// publishing it costs nothing (anyone holding a token can already test a
/// candidate secret against its signature, which is the same one-hash oracle),
/// but there is no reason to hand out a bare digest of the secret either.
struct JwtKey {
    kid: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKey {
    fn new(secret: &str) -> Self {
        Self {
            kid: kid_for(secret),
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
        }
    }
}

/// The one place a `jsonwebtoken` failure becomes an `AuthError`. Expiry is
/// separated from every other rejection because callers act on it — a client
/// refreshes on `TokenExpired` and gives up on `InvalidToken`.
fn map_jwt_error(e: jsonwebtoken::errors::Error) -> AuthError {
    match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        _ => AuthError::InvalidToken(e.to_string()),
    }
}

/// Stable short name for a secret. The prefix is domain separation: this digest
/// must never collide with any other use of the same secret.
fn kid_for(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"roomler-jwt-kid-v1\0");
    h.update(secret.as_bytes());
    hex::encode(&h.finalize()[..8])
}

pub struct AuthService {
    jwt_settings: JwtSettings,
    /// The key every NEW token is signed with.
    signing: JwtKey,
    /// Every key a token may be verified against — `signing` first, then the
    /// retired secrets from `jwt.previous_secrets`, deduplicated by `kid`.
    ///
    /// Order matters twice: it is the try-order for a token that carries no
    /// `kid` (see [`AuthService::decode_any`]), and putting the current key
    /// first means the common case is one HMAC.
    verifying: Vec<JwtKey>,
}

impl AuthService {
    pub fn new(jwt_settings: JwtSettings) -> Self {
        let signing = JwtKey::new(&jwt_settings.secret);

        let mut verifying = vec![JwtKey::new(&jwt_settings.secret)];
        for prev in jwt_settings
            .previous_secrets
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let key = JwtKey::new(prev);
            // Dedupe by kid, so re-listing the current secret among the
            // previous ones (the obvious mistake when writing a rotation) is a
            // no-op rather than a duplicated HMAC on every request.
            if verifying.iter().all(|k| k.kid != key.kid) {
                verifying.push(key);
            }
        }

        Self {
            jwt_settings,
            signing,
            verifying,
        }
    }

    /// The `kid` stamped on newly minted tokens, and how many keys are
    /// accepted. Startup logs this so a rotation is visible in the record:
    /// "signing changed, verify count went 1 → 2" is the shape of a correct
    /// rotation, and "1 → 1 with a new kid" is the flag-day mistake.
    pub fn key_summary(&self) -> (String, usize) {
        (self.signing.kid.clone(), self.verifying.len())
    }

    /// Verify against the key the token NAMES, else against every key.
    ///
    /// ⚠️ `kid` is attacker-controlled, so it is only ever used to SELECT from
    /// the server's own configured set — never to locate, fetch or derive key
    /// material. An unknown `kid` falls through to trying everything, so a
    /// forged header buys nothing; a known one only picks a key that would have
    /// been tried anyway.
    ///
    /// Algorithm confusion is closed upstream of this: `Validation::default()`
    /// pins `algorithms` to HS256, so `alg: none` and an RS256 token signed
    /// with the public key are both rejected before a key is chosen.
    fn decode_any<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<T, AuthError> {
        let named = jsonwebtoken::decode_header(token)
            .ok()
            .and_then(|h| h.kid)
            .and_then(|kid| self.verifying.iter().find(|k| k.kid == kid));

        let candidates: Vec<&JwtKey> = match named {
            Some(k) => vec![k],
            None => self.verifying.iter().collect(),
        };

        let mut last = None;
        for key in candidates {
            match decode::<T>(token, &key.decoding, validation) {
                Ok(data) => return Ok(data.claims),
                // A signature mismatch is the ONLY reason to try the next key.
                // Anything else means this key DID sign the token and the
                // claims were rejected — reporting "invalid signature" for an
                // expired token would send the reader somewhere useless.
                Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature) => {
                    last = Some(e);
                }
                Err(e) => return Err(map_jwt_error(e)),
            }
        }
        Err(map_jwt_error(last.unwrap_or_else(|| {
            jsonwebtoken::errors::ErrorKind::InvalidSignature.into()
        })))
    }

    /// The header every token is minted with — HS256 plus the signing `kid`.
    fn header(&self) -> Header {
        Header {
            kid: Some(self.signing.kid.clone()),
            ..Header::default()
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::HashError(e.to_string()))?;
        Ok(hash.to_string())
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| AuthError::HashError(e.to_string()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub fn generate_tokens(
        &self,
        user_id: ObjectId,
        email: &str,
        username: &str,
    ) -> Result<TokenPair, AuthError> {
        self.generate_tokens_at_revision(user_id, email, username, 0)
    }

    /// Native one-shot account login: ordinary account Access authority, NOT a
    /// share-scoped token. Same configured TTL; no refresh credential is minted.
    pub fn generate_access_token_at_revision(
        &self,
        user_id: ObjectId,
        email: &str,
        username: &str,
        approval_revision: u32,
    ) -> Result<(String, u64), AuthError> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_hex(),
            email: email.into(),
            username: username.into(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(self.jwt_settings.access_token_ttl_secs as i64))
                .timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::Access,
            approval_revision,
        };
        let token = encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        Ok((token, self.jwt_settings.access_token_ttl_secs))
    }

    pub fn generate_tokens_at_revision(
        &self,
        user_id: ObjectId,
        email: &str,
        username: &str,
        approval_revision: u32,
    ) -> Result<TokenPair, AuthError> {
        let now = Utc::now();

        let access_claims = Claims {
            sub: user_id.to_hex(),
            email: email.to_string(),
            username: username.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(self.jwt_settings.access_token_ttl_secs as i64))
                .timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::Access,
            approval_revision,
        };

        let refresh_claims = Claims {
            sub: user_id.to_hex(),
            email: email.to_string(),
            username: username.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(self.jwt_settings.refresh_token_ttl_secs as i64))
                .timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::Refresh,
            approval_revision,
        };

        let access_token = encode(&self.header(), &access_claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let refresh_token = encode(&self.header(), &refresh_claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.jwt_settings.access_token_ttl_secs,
        })
    }

    /// Issuer-pinned HS256 validation, shared by every verifier so a rule
    /// added here cannot be missed by one audience.
    fn validation(&self) -> Validation {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.jwt_settings.issuer]);
        validation
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        self.decode_any::<Claims>(token, &self.validation())
    }

    pub fn verify_access_token(&self, token: &str) -> Result<Claims, AuthError> {
        let claims = self.verify_token(token)?;
        if claims.token_type != TokenType::Access {
            return Err(AuthError::InvalidToken("Not an access token".to_string()));
        }
        Ok(claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<Claims, AuthError> {
        let claims = self.verify_token(token)?;
        if claims.token_type != TokenType::Refresh {
            return Err(AuthError::InvalidToken("Not a refresh token".to_string()));
        }
        Ok(claims)
    }

    // ─── Remote-control tokens ────────────────────────────────────────

    /// Mint a single-use enrollment token. The returned `jti` is unique and
    /// may be persisted by the caller for replay protection.
    pub fn issue_enrollment_token(
        &self,
        admin_user_id: ObjectId,
        tenant_id: ObjectId,
        ttl_secs: u64,
    ) -> Result<(String, String), AuthError> {
        self.issue_enrollment_token_with(admin_user_id, tenant_id, ttl_secs, false)
    }

    /// [`Self::issue_enrollment_token`], with FR-104's `anchor` claim: the
    /// token may also anchor the device it enrolls ([`EnrollmentClaims::anchor`]).
    pub fn issue_enrollment_token_with(
        &self,
        admin_user_id: ObjectId,
        tenant_id: ObjectId,
        ttl_secs: u64,
        anchor: bool,
    ) -> Result<(String, String), AuthError> {
        self.issue_enrollment_token_with_relay(admin_user_id, tenant_id, ttl_secs, anchor, false)
    }

    /// Mint the existing single-use enrollment credential with an explicit
    /// relay grant. Callers must enforce MANAGE_AGENTS + EXEC_DEVICE first.
    pub fn issue_enrollment_token_with_relay(
        &self,
        admin_user_id: ObjectId,
        tenant_id: ObjectId,
        ttl_secs: u64,
        anchor: bool,
        relay_server: bool,
    ) -> Result<(String, String), AuthError> {
        let now = Utc::now();
        let jti = uuid_v4_hex();
        let claims = EnrollmentClaims {
            sub: admin_user_id.to_hex(),
            tenant_id: tenant_id.to_hex(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(ttl_secs as i64)).timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::Enrollment,
            jti: jti.clone(),
            anchor,
            relay_server,
        };
        let token = encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        Ok((token, jti))
    }

    pub fn verify_enrollment_token(&self, token: &str) -> Result<EnrollmentClaims, AuthError> {
        let claims = self.decode_any::<EnrollmentClaims>(token, &self.validation())?;
        if claims.token_type != TokenType::Enrollment {
            return Err(AuthError::InvalidToken(
                "Not an enrollment token".to_string(),
            ));
        }
        Ok(claims)
    }

    /// FR-51 P2 — mint the JWT half of an ephemeral enrollment key. `exp` is
    /// passed as an absolute timestamp so it EQUALS the key row's
    /// `expires_at`: the row is the authority (it is what revocation and the
    /// use ceiling live on), the JWT expiry is the belt to that braces.
    pub fn issue_ephemeral_enroll_key_token(
        &self,
        admin_user_id: ObjectId,
        tenant_id: ObjectId,
        jti: &str,
        expires_at_ts: i64,
    ) -> Result<String, AuthError> {
        let claims = EnrollmentClaims {
            sub: admin_user_id.to_hex(),
            tenant_id: tenant_id.to_hex(),
            iat: Utc::now().timestamp(),
            exp: expires_at_ts,
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::EphemeralEnrollment,
            jti: jti.to_string(),
            // Reusable keys grant neither host anchoring nor relay approval.
            anchor: false,
            relay_server: false,
        };
        encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    /// Accept EITHER enrollment credential on the public enroll route and say
    /// which arrived (`true` = the FR-51 ephemeral key). Everything else —
    /// agent, user, tunnel audiences — is refused exactly as before; the two
    /// enrollment kinds stay separate audiences everywhere else.
    pub fn verify_enrollment_token_any(
        &self,
        token: &str,
    ) -> Result<(EnrollmentClaims, bool), AuthError> {
        let claims = self.decode_any::<EnrollmentClaims>(token, &self.validation())?;
        match claims.token_type {
            TokenType::Enrollment => Ok((claims, false)),
            TokenType::EphemeralEnrollment if !claims.relay_server => Ok((claims, true)),
            TokenType::EphemeralEnrollment => Err(AuthError::InvalidToken(
                "Ephemeral enrollment cannot grant relay-server approval".to_string(),
            )),
            _ => Err(AuthError::InvalidToken(
                "Not an enrollment token".to_string(),
            )),
        }
    }

    /// Mint a long-lived agent token at the device row's token generation
    /// `gen` (FR-103). The TTL is one year unless `override_ttl_secs` is
    /// given; the server passes `rc.agent_token_ttl_secs`. A device renews its
    /// token well before then (`POST /api/agent/self/renew`).
    pub fn issue_agent_token(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        generation: u32,
        override_ttl_secs: Option<u64>,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let ttl = override_ttl_secs.unwrap_or(365 * 24 * 60 * 60); // 1 year default
        let claims = AgentClaims {
            sub: agent_id.to_hex(),
            tenant_id: tenant_id.to_hex(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(ttl as i64)).timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::Agent,
            generation,
        };
        encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    pub fn verify_agent_token(&self, token: &str) -> Result<AgentClaims, AuthError> {
        let claims = self.decode_any::<AgentClaims>(token, &self.validation())?;
        if claims.token_type != TokenType::Agent {
            return Err(AuthError::InvalidToken("Not an agent token".to_string()));
        }
        Ok(claims)
    }

    /// FR-103: verify an agent token for the renew route ONLY. The signature,
    /// issuer and audience are checked as everywhere, but `exp` may lie up to
    /// [`RENEWAL_GRACE_SECS`] in the past, so a device that slept through its
    /// anniversary can still buy a fresh token. Every other route uses
    /// [`Self::verify_agent_token`], which enforces `exp`.
    pub fn verify_agent_token_for_renewal(&self, token: &str) -> Result<AgentClaims, AuthError> {
        let claims = self.decode_any::<AgentClaims>(token, &self.renewal_validation())?;
        if claims.token_type != TokenType::Agent {
            return Err(AuthError::InvalidToken("Not an agent token".to_string()));
        }
        Self::within_renewal_grace(claims.exp, Utc::now().timestamp())?;
        Ok(claims)
    }

    /// The validation for the renew routes: [`Self::validation`] without the
    /// `exp` check, which [`Self::within_renewal_grace`] replaces with a
    /// bounded one.
    fn renewal_validation(&self) -> Validation {
        let mut validation = self.validation();
        validation.validate_exp = false;
        validation
    }

    /// A token renews while `exp` is in the future or at most
    /// [`RENEWAL_GRACE_SECS`] in the past. Split out for the tests.
    fn within_renewal_grace(exp: i64, now: i64) -> Result<(), AuthError> {
        if exp + RENEWAL_GRACE_SECS < now {
            return Err(AuthError::TokenExpired);
        }
        Ok(())
    }

    /// FR-94 — mint the credential of a device's SYSTEM service: `sub` = the
    /// agent id, `anchor_id` = the anchor it belongs to, its own audience,
    /// and the agent token's one-year lifetime. The service renews it
    /// (`POST /api/agent/service/renew`) under the same anchor, so the year
    /// is a renewal interval, not the anchor's life; the anchor binding is
    /// what revokes it.
    pub fn issue_agent_service_token(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        anchor_id: &str,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let claims = AgentServiceClaims {
            sub: agent_id.to_hex(),
            tenant_id: tenant_id.to_hex(),
            anchor_id: anchor_id.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(365 * 24 * 60 * 60)).timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::AgentService,
        };
        encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    /// FR-94 — verify a device service's credential. Refuses every other
    /// audience, the agent token included, and [`Self::verify_agent_token`]
    /// refuses this one: the two never stand in for each other. Whether its
    /// `anchor_id` is still the device's anchor is the caller's check, against
    /// the row.
    pub fn verify_agent_service_token(&self, token: &str) -> Result<AgentServiceClaims, AuthError> {
        let claims = self.decode_any::<AgentServiceClaims>(token, &self.validation())?;
        if claims.token_type != TokenType::AgentService {
            return Err(AuthError::InvalidToken(
                "Not an agent service token".to_string(),
            ));
        }
        Ok(claims)
    }

    // ─── tunnel client tokens ─────────────────────────────────

    /// Mint a single-use tunnel-enrollment token. Returned `jti` is
    /// unique; caller may persist for replay protection. Mirrors
    /// [`issue_enrollment_token`] but with a distinct audience.
    pub fn issue_tunnel_enrollment_token(
        &self,
        admin_user_id: ObjectId,
        tenant_id: ObjectId,
        ttl_secs: u64,
    ) -> Result<(String, String), AuthError> {
        let now = Utc::now();
        let jti = uuid_v4_hex();
        let claims = TunnelEnrollmentClaims {
            sub: admin_user_id.to_hex(),
            tenant_id: tenant_id.to_hex(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(ttl_secs as i64)).timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::TunnelEnrollment,
            jti: jti.clone(),
        };
        let token = encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        Ok((token, jti))
    }

    pub fn verify_tunnel_enrollment_token(
        &self,
        token: &str,
    ) -> Result<TunnelEnrollmentClaims, AuthError> {
        let claims = self.decode_any::<TunnelEnrollmentClaims>(token, &self.validation())?;
        if claims.token_type != TokenType::TunnelEnrollment {
            return Err(AuthError::InvalidToken(
                "Not a tunnel-enrollment token".to_string(),
            ));
        }
        Ok(claims)
    }

    /// Mint a long-lived tunnel-client token at the client row's token
    /// generation `gen` (FR-103). Default TTL one year, override via
    /// `override_ttl_secs`. Mirrors [`Self::issue_agent_token`].
    pub fn issue_tunnel_client_token(
        &self,
        tunnel_client_id: ObjectId,
        tenant_id: ObjectId,
        owner_user_id: ObjectId,
        generation: u32,
        override_ttl_secs: Option<u64>,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let ttl = override_ttl_secs.unwrap_or(365 * 24 * 60 * 60);
        let claims = TunnelClientClaims {
            sub: tunnel_client_id.to_hex(),
            tenant_id: tenant_id.to_hex(),
            owner_user_id: owner_user_id.to_hex(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(ttl as i64)).timestamp(),
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::TunnelClient,
            generation,
        };
        encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    /// FR-103: [`Self::verify_tunnel_client_token`] for the renew route ONLY,
    /// with the same bounded grace past `exp` as
    /// [`Self::verify_agent_token_for_renewal`].
    pub fn verify_tunnel_client_token_for_renewal(
        &self,
        token: &str,
    ) -> Result<TunnelClientClaims, AuthError> {
        let claims = self.decode_any::<TunnelClientClaims>(token, &self.renewal_validation())?;
        if claims.token_type != TokenType::TunnelClient {
            return Err(AuthError::InvalidToken(
                "Not a tunnel-client token".to_string(),
            ));
        }
        Self::within_renewal_grace(claims.exp, Utc::now().timestamp())?;
        Ok(claims)
    }

    pub fn verify_tunnel_client_token(&self, token: &str) -> Result<TunnelClientClaims, AuthError> {
        let claims = self.decode_any::<TunnelClientClaims>(token, &self.validation())?;
        if claims.token_type != TokenType::TunnelClient {
            return Err(AuthError::InvalidToken(
                "Not a tunnel-client token".to_string(),
            ));
        }
        Ok(claims)
    }

    // ─── FR-90 P3-7-1b: a session's egress grant ──────────────────────

    /// Sign the vault's grant of a session's egress. Refuses a grant that
    /// does not hold together, before signing anything: a forward with no
    /// destination, or a host not in its canonical spelling, would otherwise
    /// be read as a grant wider than the one decided; SOCKS names no
    /// destination; and none ends past the lease ceiling.
    pub fn issue_net_grant(&self, g: &NetGrant<'_>) -> Result<String, AuthError> {
        let now = Utc::now().timestamp();
        let (dst_host, dst_port) = match g.dst {
            Some((host, port)) => (host.to_string(), port),
            None => (String::new(), 0),
        };
        let claims = NetGrantClaims {
            sub: g.session_id.to_hex(),
            tenant_id: g.tenant_id.to_hex(),
            fence: g.fence,
            owner_user_id: g.owner_user_id.to_hex(),
            origin_agent_id: g.origin_agent_id.to_hex(),
            exit_agent_id: g.exit_agent_id.to_hex(),
            net: g.net.wire().to_string(),
            dst_host,
            dst_port,
            jti: g.grant_id.to_hex(),
            iat: now,
            exp: g.exp,
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::NetGrant,
        };
        net_grant_holds(&claims)?;
        encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    /// Verify a session's egress grant. Refuses every other audience, and
    /// every other verifier refuses this one. Checked as it was issued: its
    /// kind, its destination, its ids and its life.
    ///
    /// ⚠️ No leeway past `exp`: a grant's end is a decision's, at most the
    /// lease ceiling, never the minute of clock skew a year-long token is
    /// given. The tokens are made and checked by the same servers.
    pub fn verify_net_grant(&self, token: &str) -> Result<NetGrantClaims, AuthError> {
        let mut validation = self.validation();
        validation.leeway = 0;
        let claims = self.decode_any::<NetGrantClaims>(token, &validation)?;
        if claims.token_type != TokenType::NetGrant {
            return Err(AuthError::InvalidToken("Not a net grant".to_string()));
        }
        net_grant_holds(&claims)?;
        Ok(claims)
    }

    // ─── FR-90 P3-8-1a: a session's SSH ticket ────────────────────────

    /// Sign the vault's ticket for a session's command on another device.
    /// Refuses a ticket that does not hold together, before signing anything:
    /// one naming the device it runs on as its target would let a session
    /// run as whatever that device maps instead of as itself, and none ends
    /// past the lease ceiling.
    pub fn issue_ssh_ticket(&self, t: &SshTicket) -> Result<String, AuthError> {
        let claims = SshTicketClaims {
            sub: t.session_id.to_hex(),
            tenant_id: t.tenant_id.to_hex(),
            fence: t.fence,
            owner_user_id: t.owner_user_id.to_hex(),
            origin_agent_id: t.origin_agent_id.to_hex(),
            target_agent_id: t.target_agent_id.to_hex(),
            account: t.account.wire().to_string(),
            jti: t.ticket_id.to_hex(),
            iat: Utc::now().timestamp(),
            exp: t.exp,
            iss: self.jwt_settings.issuer.clone(),
            token_type: TokenType::SshTicket,
        };
        ssh_ticket_holds(&claims)?;
        encode(&self.header(), &claims, &self.signing.encoding)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    /// Verify a session's SSH ticket. Refuses every other audience, a net
    /// grant's included, and every other verifier refuses this one. Checked
    /// as it was issued: its ids, its two devices, its account and its life.
    ///
    /// ⚠️ No leeway past `exp`, as for a net grant: a ticket's end is a
    /// decision's.
    pub fn verify_ssh_ticket(&self, token: &str) -> Result<SshTicketClaims, AuthError> {
        let mut validation = self.validation();
        validation.leeway = 0;
        let claims = self.decode_any::<SshTicketClaims>(token, &validation)?;
        if claims.token_type != TokenType::SshTicket {
            return Err(AuthError::InvalidToken("Not an SSH ticket".to_string()));
        }
        ssh_ticket_holds(&claims)?;
        Ok(claims)
    }
}

/// FR-90 P3-8-1a — whether a ticket's claims hold together, at its signing
/// and at every check: every id an id; a target that is not the device it
/// runs on; an account this build names; and a life no longer than a lease's
/// ceiling.
fn ssh_ticket_holds(c: &SshTicketClaims) -> Result<(), AuthError> {
    use roomler_ai_remote_control::{models::SshAccountMode, vault::lease_limits};
    let bad = |why: &str| Err(AuthError::InvalidToken(format!("ssh ticket: {why}")));
    let id = |hex: &str| ObjectId::parse_str(hex).ok();
    let ids = [
        &c.sub,
        &c.tenant_id,
        &c.owner_user_id,
        &c.origin_agent_id,
        &c.target_agent_id,
        &c.jti,
    ];
    if ids.iter().any(|hex| id(hex).is_none()) {
        return bad("an id that is not one");
    }
    // Compared as ids, so no two spellings of one device read as two.
    if id(&c.origin_agent_id) == id(&c.target_agent_id) {
        return bad("a target that is the device it runs on");
    }
    if SshAccountMode::from_wire(&c.account).is_none() {
        return bad("an account this build cannot name");
    }
    if c.exp <= c.iat || c.exp - c.iat > i64::from(lease_limits::MAX_TTL_SECS) {
        return bad("a life past the lease ceiling");
    }
    Ok(())
}

/// FR-90 P3-7-1b — whether a grant's claims hold together, at its signing
/// and at every check: a kind this build names; a forward's destination
/// canonical and whole, and SOCKS naming none; every id an id; and a life no
/// longer than a lease's ceiling.
fn net_grant_holds(c: &NetGrantClaims) -> Result<(), AuthError> {
    use roomler_ai_remote_control::vault::{NetKind, canonical_net_host, lease_limits};
    let bad = |why: &str| Err(AuthError::InvalidToken(format!("net grant: {why}")));
    match NetKind::from_wire(&c.net) {
        None => return bad("a kind this build cannot name"),
        Some(NetKind::Forward) => {
            if c.dst_port == 0
                || canonical_net_host(&c.dst_host).as_deref() != Some(c.dst_host.as_str())
            {
                return bad("a forward names one destination, its host canonical");
            }
        }
        Some(NetKind::Socks) => {
            if !c.dst_host.is_empty() || c.dst_port != 0 {
                return bad("SOCKS names no destination");
            }
        }
    }
    let ids = [
        &c.sub,
        &c.tenant_id,
        &c.owner_user_id,
        &c.origin_agent_id,
        &c.exit_agent_id,
        &c.jti,
    ];
    if ids.iter().any(|id| ObjectId::parse_str(id).is_err()) {
        return bad("an id that is not one");
    }
    if c.exp <= c.iat || c.exp - c.iat > i64::from(lease_limits::MAX_TTL_SECS) {
        return bad("a life past the lease ceiling");
    }
    Ok(())
}

fn uuid_v4_hex() -> String {
    // Use `rand` via argon2's OsRng — avoids pulling in the uuid crate here just for a nonce.
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: &str = "test-secret-for-unit-tests-do-not-use-in-prod";
    const SECRET_B: &str = "the-rotated-to-secret-for-unit-tests";

    fn svc() -> AuthService {
        svc_with(SECRET_A, "")
    }

    fn svc_with(secret: &str, previous: &str) -> AuthService {
        AuthService::new(JwtSettings {
            secret: secret.to_string(),
            previous_secrets: previous.to_string(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 604_800,
            issuer: "roomler-ai-test".to_string(),
        })
    }

    #[test]
    fn native_shared_ssh_access_only_signer_keeps_account_scope_revision_and_ttl() {
        let service = svc();
        let id = ObjectId::new();
        let (access, ttl) = service
            .generate_access_token_at_revision(id, "recipient@test.invalid", "recipient", 7)
            .unwrap();
        let claims = service.verify_access_token(&access).unwrap();
        assert_eq!(claims.sub, id.to_hex());
        assert_eq!(claims.approval_revision, 7);
        assert_eq!(ttl, 3600);
        assert_eq!(claims.exp - claims.iat, 3600);
        assert!(service.verify_refresh_token(&access).is_err());
    }

    #[test]
    fn account_approval_preexisting_claims_default_to_zero_not_a_grant() {
        let claims: Claims = serde_json::from_value(serde_json::json!({
            "sub": ObjectId::new().to_hex(), "email": "legacy@test.invalid", "username": "legacy",
            "iat": 1, "exp": 2, "iss": "test", "token_type": "access"
        }))
        .unwrap();
        assert_eq!(claims.approval_revision, 0);
    }

    #[test]
    fn account_approval_revision_survives_both_token_types() {
        let service = svc();
        let pair = service
            .generate_tokens_at_revision(ObjectId::new(), "owner@test.invalid", "owner", 7)
            .unwrap();
        assert_eq!(
            service
                .verify_access_token(&pair.access_token)
                .unwrap()
                .approval_revision,
            7
        );
        assert_eq!(
            service
                .verify_refresh_token(&pair.refresh_token)
                .unwrap()
                .approval_revision,
            7
        );
        let legacy = service
            .generate_tokens(ObjectId::new(), "legacy@test.invalid", "legacy")
            .unwrap();
        assert_eq!(
            service
                .verify_access_token(&legacy.access_token)
                .unwrap()
                .approval_revision,
            0
        );
    }

    #[test]
    fn agent_token_roundtrip() {
        let s = svc();
        let agent_id = ObjectId::new();
        let tenant_id = ObjectId::new();
        let token = s
            .issue_agent_token(agent_id, tenant_id, 0, Some(60))
            .unwrap();
        let claims = s.verify_agent_token(&token).unwrap();
        assert_eq!(claims.sub, agent_id.to_hex());
        assert_eq!(claims.tenant_id, tenant_id.to_hex());
        assert_eq!(claims.token_type, TokenType::Agent);
    }

    #[test]
    fn enrollment_token_roundtrip() {
        let s = svc();
        let admin = ObjectId::new();
        let tenant = ObjectId::new();
        let (token, jti) = s.issue_enrollment_token(admin, tenant, 600).unwrap();
        let claims = s.verify_enrollment_token(&token).unwrap();
        assert_eq!(claims.sub, admin.to_hex());
        assert_eq!(claims.tenant_id, tenant.to_hex());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.token_type, TokenType::Enrollment);
    }

    #[test]
    fn agent_token_rejects_user_token() {
        let s = svc();
        let user_id = ObjectId::new();
        let pair = s.generate_tokens(user_id, "a@b.c", "u").unwrap();
        let err = s.verify_agent_token(&pair.access_token).unwrap_err();
        matches!(err, AuthError::InvalidToken(_));
    }

    #[test]
    fn enrollment_token_rejects_agent_token() {
        let s = svc();
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let token = s.issue_agent_token(agent_id, tenant, 0, Some(60)).unwrap();
        let err = s.verify_enrollment_token(&token).unwrap_err();
        matches!(err, AuthError::InvalidToken(_));
    }

    /// FR-51 P2 — the ephemeral key roundtrips through `_any`, is refused by
    /// the single-use verifier, and `_any` still refuses non-enrollment
    /// audiences. The audience separation is what stops a leaked credential
    /// of one kind passing a gate built for the other.
    #[test]
    fn ephemeral_key_token_audiences() {
        let s = svc();
        let admin = ObjectId::new();
        let tenant = ObjectId::new();
        let exp = Utc::now().timestamp() + 600;
        let token = s
            .issue_ephemeral_enroll_key_token(admin, tenant, "jti-eph-1", exp)
            .unwrap();

        // _any accepts it and says which kind arrived.
        let (claims, is_ephemeral) = s.verify_enrollment_token_any(&token).unwrap();
        assert!(is_ephemeral);
        assert_eq!(claims.jti, "jti-eph-1");
        assert_eq!(claims.token_type, TokenType::EphemeralEnrollment);

        // The single-use verifier refuses it (it is not that kind).
        assert!(s.verify_enrollment_token(&token).is_err());

        // A standard enrollment token through _any reads as NOT ephemeral.
        let (std_token, _) = s.issue_enrollment_token(admin, tenant, 600).unwrap();
        let (_, is_ephemeral) = s.verify_enrollment_token_any(&std_token).unwrap();
        assert!(!is_ephemeral);

        // And _any refuses every other audience — an agent token here would
        // mean any enrolled device could mint sibling devices.
        let agent_token = s
            .issue_agent_token(ObjectId::new(), tenant, 0, Some(60))
            .unwrap();
        assert!(s.verify_enrollment_token_any(&agent_token).is_err());
    }

    /// FR-94 §4 — the SYSTEM service's credential and the agent token never
    /// stand in for each other, in either direction, and no other verifier
    /// accepts the service credential. On an attended install the agent token
    /// sits in the user's writable config, so a crossing either way would let
    /// FR-104 — the `anchor` claim is carried only when asked for, and a
    /// token without it (every older one) reads as `false`.
    #[test]
    fn an_enrollment_token_carries_anchor_only_when_asked() {
        use base64::Engine as _;
        let s = svc();
        let (admin, tenant) = (ObjectId::new(), ObjectId::new());

        let (anchoring, jti) = s
            .issue_enrollment_token_with(admin, tenant, 600, true)
            .unwrap();
        let claims = s.verify_enrollment_token(&anchoring).unwrap();
        assert!(claims.anchor);
        assert_eq!(claims.jti, jti);

        let (plain, _) = s.issue_enrollment_token(admin, tenant, 600).unwrap();
        assert!(!s.verify_enrollment_token(&plain).unwrap().anchor);
        // Not even written into a plain token's payload: byte-for-byte the
        // tokens minted before FR-104.
        let payload = plain.split('.').nth(1).unwrap();
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        assert!(!String::from_utf8(json).unwrap().contains("anchor"));
    }

    #[test]
    fn relay_enrollment_claim_is_explicit_signed_and_defaults_closed() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let s = svc();
        let (admin, tenant) = (ObjectId::new(), ObjectId::new());
        let (plain, _) = s.issue_enrollment_token(admin, tenant, 600).unwrap();
        assert!(!s.verify_enrollment_token(&plain).unwrap().relay_server);
        let payload = URL_SAFE_NO_PAD
            .decode(plain.split('.').nth(1).unwrap())
            .unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(
            json.get("relay_server").is_none(),
            "legacy tokens omit the claim"
        );
        json["relay_server"] = serde_json::json!(true);
        let parts: Vec<_> = plain.split('.').collect();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap()),
            parts[2]
        );
        assert!(
            s.verify_enrollment_token_any(&forged).is_err(),
            "device cannot edit the signed role"
        );
        let (relay, _) = s
            .issue_enrollment_token_with_relay(admin, tenant, 600, true, true)
            .unwrap();
        let claims = s.verify_enrollment_token(&relay).unwrap();
        assert!(
            claims.relay_server && claims.anchor,
            "independent grants compose"
        );
    }

    #[test]
    fn even_a_signed_ephemeral_credential_cannot_grant_relay_approval() {
        let s = svc();
        let token = s
            .issue_ephemeral_enroll_key_token(
                ObjectId::new(),
                ObjectId::new(),
                "ephemeral-relay",
                Utc::now().timestamp() + 600,
            )
            .unwrap();
        let (mut claims, ephemeral) = s.verify_enrollment_token_any(&token).unwrap();
        assert!(ephemeral && !claims.relay_server);
        claims.relay_server = true;
        let invalid_grant = encode(&s.header(), &claims, &s.signing.encoding).unwrap();
        assert!(s.verify_enrollment_token_any(&invalid_grant).is_err());
    }

    /// that user tell SYSTEM what to run.
    #[test]
    fn agent_service_token_audiences() {
        let s = svc();
        let agent = ObjectId::new();
        let tenant = ObjectId::new();
        let service = s
            .issue_agent_service_token(agent, tenant, "anchor-1")
            .unwrap();

        let claims = s.verify_agent_service_token(&service).unwrap();
        assert_eq!(claims.sub, agent.to_hex());
        assert_eq!(claims.tenant_id, tenant.to_hex());
        assert_eq!(claims.anchor_id, "anchor-1");
        assert_eq!(claims.token_type, TokenType::AgentService);

        // Not an agent token, an access token, or an enrollment of any kind.
        assert!(s.verify_agent_token(&service).is_err());
        assert!(s.verify_access_token(&service).is_err());
        assert!(s.verify_refresh_token(&service).is_err());
        assert!(s.verify_enrollment_token(&service).is_err());
        assert!(s.verify_enrollment_token_any(&service).is_err());
        assert!(s.verify_tunnel_client_token(&service).is_err());

        // And the agent token, the one the user can read, is not a service
        // credential.
        let agent_token = s.issue_agent_token(agent, tenant, 0, Some(60)).unwrap();
        assert!(s.verify_agent_service_token(&agent_token).is_err());
        let (enroll, _) = s
            .issue_enrollment_token(ObjectId::new(), tenant, 600)
            .unwrap();
        assert!(s.verify_agent_service_token(&enroll).is_err());
    }

    #[test]
    fn enrollment_tokens_have_unique_jti() {
        let s = svc();
        let admin = ObjectId::new();
        let tenant = ObjectId::new();
        let (_, jti1) = s.issue_enrollment_token(admin, tenant, 600).unwrap();
        let (_, jti2) = s.issue_enrollment_token(admin, tenant, 600).unwrap();
        assert_ne!(jti1, jti2);
    }

    // ─── tunnel-client + tunnel-enrollment audiences ──────────────────
    //
    // Plan §"What changed from v1" #6 — these audiences are NOT named
    // `Client` / `ClientEnrollment` because "Client" is overloaded
    // across the codebase. The matrix below locks every
    // verify-rejects-the-wrong-audience pair, in both directions, so a
    // leaked Agent token can't bootstrap a tunnel and a leaked
    // TunnelClient token can't drive an agent-side endpoint.

    #[test]
    fn tunnel_client_token_roundtrip() {
        let s = svc();
        let cid = ObjectId::new();
        let tid = ObjectId::new();
        let uid = ObjectId::new();
        let token = s
            .issue_tunnel_client_token(cid, tid, uid, 0, Some(60))
            .unwrap();
        let claims = s.verify_tunnel_client_token(&token).unwrap();
        assert_eq!(claims.sub, cid.to_hex());
        assert_eq!(claims.tenant_id, tid.to_hex());
        assert_eq!(claims.owner_user_id, uid.to_hex());
        assert_eq!(claims.token_type, TokenType::TunnelClient);
    }

    #[test]
    fn tunnel_enrollment_token_roundtrip() {
        let s = svc();
        let admin = ObjectId::new();
        let tenant = ObjectId::new();
        let (token, jti) = s.issue_tunnel_enrollment_token(admin, tenant, 600).unwrap();
        let claims = s.verify_tunnel_enrollment_token(&token).unwrap();
        assert_eq!(claims.sub, admin.to_hex());
        assert_eq!(claims.tenant_id, tenant.to_hex());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.token_type, TokenType::TunnelEnrollment);
    }

    #[test]
    fn tunnel_enrollment_tokens_have_unique_jti() {
        let s = svc();
        let admin = ObjectId::new();
        let tenant = ObjectId::new();
        let (_, jti1) = s.issue_tunnel_enrollment_token(admin, tenant, 600).unwrap();
        let (_, jti2) = s.issue_tunnel_enrollment_token(admin, tenant, 600).unwrap();
        assert_ne!(jti1, jti2);
    }

    // verify_tunnel_client_token rejects every other audience
    #[test]
    fn tunnel_client_verify_rejects_access_token() {
        let s = svc();
        let pair = s.generate_tokens(ObjectId::new(), "a@b.c", "u").unwrap();
        let err = s
            .verify_tunnel_client_token(&pair.access_token)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_client_verify_rejects_refresh_token() {
        let s = svc();
        let pair = s.generate_tokens(ObjectId::new(), "a@b.c", "u").unwrap();
        let err = s
            .verify_tunnel_client_token(&pair.refresh_token)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_client_verify_rejects_agent_token() {
        let s = svc();
        let t = s
            .issue_agent_token(ObjectId::new(), ObjectId::new(), 0, Some(60))
            .unwrap();
        let err = s.verify_tunnel_client_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_client_verify_rejects_enrollment_token() {
        let s = svc();
        let (t, _) = s
            .issue_enrollment_token(ObjectId::new(), ObjectId::new(), 60)
            .unwrap();
        let err = s.verify_tunnel_client_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_client_verify_rejects_tunnel_enrollment_token() {
        let s = svc();
        let (t, _) = s
            .issue_tunnel_enrollment_token(ObjectId::new(), ObjectId::new(), 60)
            .unwrap();
        let err = s.verify_tunnel_client_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    // verify_tunnel_enrollment_token rejects every other audience
    #[test]
    fn tunnel_enrollment_verify_rejects_access_token() {
        let s = svc();
        let pair = s.generate_tokens(ObjectId::new(), "a@b.c", "u").unwrap();
        let err = s
            .verify_tunnel_enrollment_token(&pair.access_token)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_enrollment_verify_rejects_refresh_token() {
        let s = svc();
        let pair = s.generate_tokens(ObjectId::new(), "a@b.c", "u").unwrap();
        let err = s
            .verify_tunnel_enrollment_token(&pair.refresh_token)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_enrollment_verify_rejects_agent_token() {
        let s = svc();
        let t = s
            .issue_agent_token(ObjectId::new(), ObjectId::new(), 0, Some(60))
            .unwrap();
        let err = s.verify_tunnel_enrollment_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_enrollment_verify_rejects_enrollment_token() {
        let s = svc();
        let (t, _) = s
            .issue_enrollment_token(ObjectId::new(), ObjectId::new(), 60)
            .unwrap();
        let err = s.verify_tunnel_enrollment_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn tunnel_enrollment_verify_rejects_tunnel_client_token() {
        let s = svc();
        let t = s
            .issue_tunnel_client_token(
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                0,
                Some(60),
            )
            .unwrap();
        let err = s.verify_tunnel_enrollment_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    // Existing verifiers reject the new audiences (defence in depth —
    // a leaked TunnelClient must not unlock an agent's privileges).
    #[test]
    fn agent_verify_rejects_tunnel_client_token() {
        let s = svc();
        let t = s
            .issue_tunnel_client_token(
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                0,
                Some(60),
            )
            .unwrap();
        let err = s.verify_agent_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn enrollment_verify_rejects_tunnel_enrollment_token() {
        let s = svc();
        let (t, _) = s
            .issue_tunnel_enrollment_token(ObjectId::new(), ObjectId::new(), 60)
            .unwrap();
        let err = s.verify_enrollment_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn access_verify_rejects_tunnel_client_token() {
        let s = svc();
        let t = s
            .issue_tunnel_client_token(
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                0,
                Some(60),
            )
            .unwrap();
        let err = s.verify_access_token(&t).unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    // ── Key rotation (`kid` + previous_secrets) ───────────────────────────

    /// THE compatibility test. Every token minted before this change carries no
    /// `kid` at all, and an agent token lives a **year** — so if a missing
    /// `kid` did not verify, deploying this would knock the entire fleet
    /// offline until every device re-enrolled by hand.
    #[test]
    fn a_token_with_no_kid_still_verifies() {
        let a = svc_with(SECRET_A, "");
        let claims = AgentClaims {
            sub: ObjectId::new().to_hex(),
            tenant_id: ObjectId::new().to_hex(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::seconds(60)).timestamp(),
            iss: "roomler-ai-test".to_string(),
            token_type: TokenType::Agent,
            generation: 0,
        };
        // `Header::default()` is exactly what every pre-rotation mint used.
        let legacy = encode(&Header::default(), &claims, &a.signing.encoding).unwrap();
        assert!(
            jsonwebtoken::decode_header(&legacy).unwrap().kid.is_none(),
            "the fixture must actually lack a kid, or this proves nothing"
        );

        // Unrotated: trivially fine.
        assert_eq!(a.verify_agent_token(&legacy).unwrap().sub, claims.sub);

        // The case that actually bites. A year-old agent token has no `kid`,
        // so nothing on it points at the secret that signed it — the ONLY way
        // it survives a rotation is by trying every configured key. Asserting
        // this against the current key alone would pass with the fallback
        // deleted (measured), which is why it is asserted here instead.
        let rotated = svc_with(SECRET_B, SECRET_A);
        assert_eq!(
            rotated.verify_agent_token(&legacy).unwrap().sub,
            claims.sub,
            "a kid-less token signed by a RETIRED secret must still verify — \
             this is the whole fleet's one-year token on rotation day"
        );
    }

    /// New tokens name their key, and the name is derived from the secret —
    /// two services configured with the same secret agree, which is what makes
    /// the 2-pod deployment work at all.
    #[test]
    fn minted_tokens_carry_a_kid_derived_from_the_secret() {
        let a = svc_with(SECRET_A, "");
        let b = svc_with(SECRET_B, "");
        let t = a
            .issue_agent_token(ObjectId::new(), ObjectId::new(), 0, Some(60))
            .unwrap();
        let kid = jsonwebtoken::decode_header(&t).unwrap().kid.expect("kid");

        assert_eq!(kid, kid_for(SECRET_A));
        assert_eq!(
            kid,
            svc_with(SECRET_A, "").key_summary().0,
            "same secret ⇒ same kid"
        );
        assert_ne!(kid, kid_for(SECRET_B), "different secrets ⇒ different kids");
        assert_ne!(kid, SECRET_A, "the kid must not BE the secret");
        assert!(
            b.verify_agent_token(&t).is_err(),
            "a kid is not a credential"
        );
    }

    /// The whole point: rotate the signing secret and yesterday's tokens keep
    /// working. Without `previous_secrets` this is a flag day that logs out
    /// every user and disconnects every agent.
    #[test]
    fn rotation_keeps_tokens_minted_under_the_previous_secret() {
        let old = svc_with(SECRET_A, "");
        let old_token = old
            .issue_agent_token(ObjectId::new(), ObjectId::new(), 0, Some(60))
            .unwrap();

        // The flag day, for contrast: swap the secret and carry nothing over.
        let naive = svc_with(SECRET_B, "");
        assert!(
            naive.verify_agent_token(&old_token).is_err(),
            "without previous_secrets a rotation MUST invalidate old tokens — \
             if this ever passes, the test below proves nothing"
        );

        // The rotation.
        let rotated = svc_with(SECRET_B, SECRET_A);
        assert!(rotated.verify_agent_token(&old_token).is_ok());

        // …and it signs with the NEW key, not the retired one.
        let fresh = rotated
            .issue_agent_token(ObjectId::new(), ObjectId::new(), 0, Some(60))
            .unwrap();
        assert_eq!(
            jsonwebtoken::decode_header(&fresh).unwrap().kid.unwrap(),
            kid_for(SECRET_B)
        );
        assert!(
            old.verify_agent_token(&fresh).is_err(),
            "the old deployment must NOT accept new tokens — otherwise the \
             retired secret was never actually retired"
        );
    }

    /// `kid` is attacker-controlled. It may only SELECT among the server's own
    /// keys; a forged or unknown one must not authenticate anything, and must
    /// not turn into a lookup that reaches outside the configured set.
    #[test]
    fn a_forged_kid_buys_nothing() {
        let s = svc_with(SECRET_A, "");
        let foreign = svc_with(SECRET_B, "")
            .issue_agent_token(ObjectId::new(), ObjectId::new(), 0, Some(60))
            .unwrap();

        // Signed with B, but re-labelled to name A's key.
        let mut parts = foreign.split('.');
        let hdr = serde_json::json!({"alg":"HS256","typ":"JWT","kid": kid_for(SECRET_A)});
        use base64::Engine as _;
        let relabelled = format!(
            "{}.{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hdr.to_string()),
            parts.nth(1).unwrap(),
            foreign.rsplit('.').next().unwrap(),
        );
        assert!(matches!(
            s.verify_agent_token(&relabelled),
            Err(AuthError::InvalidToken(_))
        ));

        // A kid naming no configured key falls through to trying them all —
        // which for a genuinely-signed token still succeeds, and for this one
        // still fails. Either way the kid decided nothing on its own.
        let hdr = serde_json::json!({"alg":"HS256","typ":"JWT","kid":"deadbeefdeadbeef"});
        let unknown = format!(
            "{}.{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hdr.to_string()),
            foreign.split('.').nth(1).unwrap(),
            foreign.rsplit('.').next().unwrap(),
        );
        assert!(s.verify_agent_token(&unknown).is_err());
    }

    /// Listing the current secret among the previous ones is the obvious
    /// slip when writing a rotation. It must be a no-op, not a doubled HMAC
    /// on every single request.
    #[test]
    fn re_listing_the_current_secret_is_deduplicated() {
        assert_eq!(svc_with(SECRET_A, SECRET_A).key_summary().1, 1);
        assert_eq!(svc_with(SECRET_A, "").key_summary().1, 1);
        assert_eq!(svc_with(SECRET_A, SECRET_B).key_summary().1, 2);
        // Blanks and spacing in a hand-edited env var must not create keys.
        assert_eq!(
            svc_with(SECRET_A, &format!("  {SECRET_B} , ,, "))
                .key_summary()
                .1,
            2
        );
    }

    /// An expired token must report expiry, not "invalid signature", even
    /// though verification walks a key list. A client refreshes on the first
    /// and gives up on the second, so confusing them breaks the refresh flow
    /// for everyone the moment a second key is configured.
    #[test]
    fn an_expired_token_reports_expiry_not_a_signature_failure() {
        let s = svc_with(SECRET_A, SECRET_B);
        let claims = AgentClaims {
            sub: ObjectId::new().to_hex(),
            tenant_id: ObjectId::new().to_hex(),
            iat: (Utc::now() - Duration::seconds(7200)).timestamp(),
            exp: (Utc::now() - Duration::seconds(3600)).timestamp(),
            iss: "roomler-ai-test".to_string(),
            token_type: TokenType::Agent,
            generation: 0,
        };
        let expired = encode(&s.header(), &claims, &s.signing.encoding).unwrap();
        assert!(matches!(
            s.verify_agent_token(&expired),
            Err(AuthError::TokenExpired)
        ));
    }

    /// FR-103: the renew route's verifier takes a token up to
    /// `RENEWAL_GRACE_SECS` past its `exp`, and nothing older. Every other
    /// route keeps refusing an expired token outright.
    #[test]
    fn an_expired_token_renews_within_the_grace_and_not_after() {
        let s = svc_with(SECRET_A, SECRET_B);
        let mint = |exp_offset: i64| {
            let claims = AgentClaims {
                sub: ObjectId::new().to_hex(),
                tenant_id: ObjectId::new().to_hex(),
                iat: Utc::now().timestamp() - 400 * 24 * 3600,
                exp: Utc::now().timestamp() + exp_offset,
                iss: "roomler-ai-test".to_string(),
                token_type: TokenType::Agent,
                generation: 3,
            };
            encode(&s.header(), &claims, &s.signing.encoding).unwrap()
        };
        let day = 24 * 3600;

        let lapsed = mint(-30 * day);
        assert!(
            matches!(s.verify_agent_token(&lapsed), Err(AuthError::TokenExpired)),
            "an ordinary route still refuses it"
        );
        let renewed = s.verify_agent_token_for_renewal(&lapsed).unwrap();
        assert_eq!(
            renewed.generation, 3,
            "the generation survives the round trip"
        );

        let fresh = mint(30 * day);
        assert!(s.verify_agent_token_for_renewal(&fresh).is_ok());

        let too_old = mint(-RENEWAL_GRACE_SECS - day);
        assert!(matches!(
            s.verify_agent_token_for_renewal(&too_old),
            Err(AuthError::TokenExpired)
        ));

        // The renewal verifier is still an AGENT verifier: no other audience.
        let tunnel = s
            .issue_tunnel_client_token(
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                0,
                Some(60),
            )
            .unwrap();
        assert!(s.verify_agent_token_for_renewal(&tunnel).is_err());
        assert!(s.verify_tunnel_client_token_for_renewal(&tunnel).is_ok());
    }

    /// FR-103: every agent and tunnel-client token minted before FR-103 has
    /// no `gen` claim. It must parse as generation 0, which equals every row
    /// that was never removed, or deploying FR-103 would refuse the whole
    /// fleet.
    #[test]
    fn a_token_minted_before_fr103_has_generation_zero() {
        #[derive(Serialize)]
        struct PreFr103 {
            sub: String,
            tenant_id: String,
            iat: i64,
            exp: i64,
            iss: String,
            token_type: TokenType,
        }
        let s = svc_with(SECRET_A, SECRET_B);
        let legacy = encode(
            &s.header(),
            &PreFr103 {
                sub: ObjectId::new().to_hex(),
                tenant_id: ObjectId::new().to_hex(),
                iat: Utc::now().timestamp(),
                exp: Utc::now().timestamp() + 60,
                iss: "roomler-ai-test".to_string(),
                token_type: TokenType::Agent,
            },
            &s.signing.encoding,
        )
        .unwrap();
        assert_eq!(s.verify_agent_token(&legacy).unwrap().generation, 0);
    }

    /// `alg: none` is the oldest JWT forgery there is. `jsonwebtoken` refuses
    /// it unconditionally (`none` is not in its `Algorithm` enum) and
    /// `Validation::default()` additionally pins HS256, so this test is a
    /// GUARD, not a fix — it cannot be made to fail by misconfiguring the
    /// validation, only by replacing the decoder. Kept because "we added a key
    /// list, then hand-rolled header parsing" is precisely how this class
    /// comes back.
    #[test]
    fn the_alg_none_forgery_is_refused() {
        let s = svc();
        let claims = serde_json::json!({
            "sub": ObjectId::new().to_hex(),
            "tenant_id": ObjectId::new().to_hex(),
            "iat": Utc::now().timestamp(),
            "exp": (Utc::now() + Duration::seconds(600)).timestamp(),
            "iss": "roomler-ai-test",
            "token_type": "agent",
        });
        use base64::Engine as _;
        let b64 = |s: String| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let forged = format!(
            "{}.{}.",
            b64(serde_json::json!({"alg":"none","typ":"JWT"}).to_string()),
            b64(claims.to_string()),
        );
        assert!(s.verify_agent_token(&forged).is_err());
    }

    // ─── FR-90 P3-7-1b: a session's egress grant ──────────────────────

    use roomler_ai_remote_control::vault::NetKind;

    fn a_grant<'a>(net: NetKind, dst: Option<(&'a str, u16)>, exp: i64) -> NetGrant<'a> {
        NetGrant {
            session_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            fence: 7,
            owner_user_id: ObjectId::new(),
            origin_agent_id: ObjectId::new(),
            exit_agent_id: ObjectId::new(),
            net,
            dst,
            grant_id: ObjectId::new(),
            exp,
        }
    }

    fn in_secs(s: i64) -> i64 {
        Utc::now().timestamp() + s
    }

    /// A grant names what was decided, and only its own verifier takes it:
    /// no other gate accepts it, and it accepts no other credential.
    #[test]
    fn net_grant_roundtrip_and_audiences() {
        let s = svc();
        let g = a_grant(NetKind::Forward, Some(("db.internal", 5432)), in_secs(300));
        let token = s.issue_net_grant(&g).unwrap();
        let c = s.verify_net_grant(&token).unwrap();
        assert_eq!(
            (c.sub.as_str(), c.tenant_id.as_str(), c.fence),
            (
                g.session_id.to_hex().as_str(),
                g.tenant_id.to_hex().as_str(),
                7
            )
        );
        assert_eq!(c.owner_user_id, g.owner_user_id.to_hex());
        assert_eq!(c.origin_agent_id, g.origin_agent_id.to_hex());
        assert_eq!(c.exit_agent_id, g.exit_agent_id.to_hex());
        assert_eq!(
            (c.net.as_str(), c.dst_host.as_str(), c.dst_port),
            ("forward", "db.internal", 5432)
        );
        assert_eq!(c.jti, g.grant_id.to_hex());
        assert_eq!((c.exp, c.token_type.clone()), (g.exp, TokenType::NetGrant));

        let socks = s
            .issue_net_grant(&a_grant(NetKind::Socks, None, in_secs(60)))
            .unwrap();
        let c = s.verify_net_grant(&socks).unwrap();
        assert_eq!(
            (c.net.as_str(), c.dst_host.as_str(), c.dst_port),
            ("socks", "", 0)
        );

        // No other gate accepts a grant.
        for t in [&token, &socks] {
            assert!(s.verify_token(t).is_err());
            assert!(s.verify_access_token(t).is_err());
            assert!(s.verify_refresh_token(t).is_err());
            assert!(s.verify_enrollment_token(t).is_err());
            assert!(s.verify_enrollment_token_any(t).is_err());
            assert!(s.verify_agent_token(t).is_err());
            assert!(s.verify_agent_token_for_renewal(t).is_err());
            assert!(s.verify_agent_service_token(t).is_err());
            assert!(s.verify_tunnel_enrollment_token(t).is_err());
            assert!(s.verify_tunnel_client_token(t).is_err());
            assert!(s.verify_tunnel_client_token_for_renewal(t).is_err());
        }
        // And a grant is no other credential.
        let (agent, tenant) = (ObjectId::new(), ObjectId::new());
        let pair = s.generate_tokens(ObjectId::new(), "a@b.c", "u").unwrap();
        let others = [
            pair.access_token,
            pair.refresh_token,
            s.issue_enrollment_token(ObjectId::new(), tenant, 600)
                .unwrap()
                .0,
            s.issue_ephemeral_enroll_key_token(ObjectId::new(), tenant, "j", in_secs(600))
                .unwrap(),
            s.issue_agent_token(agent, tenant, 0, Some(60)).unwrap(),
            s.issue_agent_service_token(agent, tenant, "anchor-1")
                .unwrap(),
            s.issue_tunnel_enrollment_token(ObjectId::new(), tenant, 600)
                .unwrap()
                .0,
            s.issue_tunnel_client_token(ObjectId::new(), tenant, ObjectId::new(), 0, Some(60))
                .unwrap(),
        ];
        for t in &others {
            assert!(s.verify_net_grant(t).is_err());
        }
    }

    /// The issuer refuses a grant that does not hold together, so no caller's
    /// slip can sign one wider than the vault decided.
    #[test]
    fn a_net_grant_that_does_not_hold_together_is_never_signed() {
        let s = svc();
        for g in [
            a_grant(NetKind::Forward, None, in_secs(60)),
            a_grant(NetKind::Forward, Some(("db.internal", 0)), in_secs(60)),
            a_grant(NetKind::Forward, Some(("", 5432)), in_secs(60)),
            a_grant(NetKind::Forward, Some(("DB.internal", 5432)), in_secs(60)),
            a_grant(NetKind::Forward, Some(("db.internal.", 5432)), in_secs(60)),
            a_grant(NetKind::Socks, Some(("db.internal", 5432)), in_secs(60)),
            // Past the ceiling by more than a second's tick between the two
            // clocks reads, so never at it by chance.
            a_grant(NetKind::Socks, None, in_secs(905)),
            a_grant(NetKind::Socks, None, in_secs(0)),
            a_grant(NetKind::Socks, None, in_secs(-10)),
        ] {
            assert!(s.issue_net_grant(&g).is_err(), "{g:?}");
        }
        assert!(
            s.issue_net_grant(&a_grant(NetKind::Socks, None, in_secs(900)))
                .is_ok(),
            "the ceiling itself"
        );
    }

    /// A token signed with the server's own key but naming a grant that does
    /// not hold together is refused at the check too, whoever signed it.
    #[test]
    fn a_net_grant_signed_wider_than_it_holds_is_refused() {
        let s = svc();
        let now = Utc::now().timestamp();
        let good = NetGrantClaims {
            sub: ObjectId::new().to_hex(),
            tenant_id: ObjectId::new().to_hex(),
            fence: 1,
            owner_user_id: ObjectId::new().to_hex(),
            origin_agent_id: ObjectId::new().to_hex(),
            exit_agent_id: ObjectId::new().to_hex(),
            net: "forward".into(),
            dst_host: "db.internal".into(),
            dst_port: 5432,
            jti: ObjectId::new().to_hex(),
            iat: now,
            exp: now + 60,
            iss: "roomler-ai-test".into(),
            token_type: TokenType::NetGrant,
        };
        let signed = |c: &NetGrantClaims| encode(&s.header(), c, &s.signing.encoding).unwrap();
        assert!(s.verify_net_grant(&signed(&good)).is_ok());
        let mut wider = Vec::new();
        let mut c = good.clone();
        c.dst_host = String::new();
        c.dst_port = 0;
        wider.push(("a forward with no destination", c));
        let mut c = good.clone();
        c.dst_host = "DB.INTERNAL".into();
        wider.push(("a host not canonical", c));
        let mut c = good.clone();
        c.net = "socks".into();
        wider.push(("SOCKS naming a destination", c));
        let mut c = good.clone();
        c.net = "udp".into();
        wider.push(("a kind this build cannot name", c));
        let mut c = good.clone();
        c.origin_agent_id = "any-device".into();
        wider.push(("an origin that is no id", c));
        let mut c = good.clone();
        c.exp = now + 901;
        wider.push(("a life past the ceiling", c));
        // A grant's every claim, under another audience: no grant at all.
        let mut c = good.clone();
        c.token_type = TokenType::Agent;
        wider.push(("another audience", c));
        for (why, c) in &wider {
            assert!(s.verify_net_grant(&signed(c)).is_err(), "{why}");
        }
    }

    /// A grant ends at its end: none of the leeway every other verifier
    /// gives, which would let a grant decided for 900 s open a flow at 959.
    #[test]
    fn a_net_grant_has_no_leeway_past_its_end() {
        let s = svc();
        let now = Utc::now().timestamp();
        let lapsed = NetGrantClaims {
            sub: ObjectId::new().to_hex(),
            tenant_id: ObjectId::new().to_hex(),
            fence: 1,
            owner_user_id: ObjectId::new().to_hex(),
            origin_agent_id: ObjectId::new().to_hex(),
            exit_agent_id: ObjectId::new().to_hex(),
            net: "socks".into(),
            dst_host: String::new(),
            dst_port: 0,
            jti: ObjectId::new().to_hex(),
            iat: now - 65,
            exp: now - 5,
            iss: "roomler-ai-test".into(),
            token_type: TokenType::NetGrant,
        };
        let t = encode(&s.header(), &lapsed, &s.signing.encoding).unwrap();
        assert!(
            s.decode_any::<NetGrantClaims>(&t, &s.validation()).is_ok(),
            "the default validation's minute of leeway would take it"
        );
        assert!(matches!(
            s.verify_net_grant(&t),
            Err(AuthError::TokenExpired)
        ));
    }

    // ─── FR-90 P3-8-1a: a session's SSH ticket ────────────────────────

    use roomler_ai_remote_control::models::SshAccountMode;

    fn a_ticket(account: SshAccountMode, exp: i64) -> SshTicket {
        SshTicket {
            session_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            fence: 7,
            owner_user_id: ObjectId::new(),
            origin_agent_id: ObjectId::new(),
            target_agent_id: ObjectId::new(),
            account,
            ticket_id: ObjectId::new(),
            exp,
        }
    }

    /// A ticket names what was decided, and only its own verifier takes it:
    /// no other gate accepts it, a net grant's included, and it accepts no
    /// other credential.
    #[test]
    fn ssh_ticket_roundtrip_and_audiences() {
        let s = svc();
        let t = a_ticket(SshAccountMode::ConsoleUser, in_secs(120));
        let token = s.issue_ssh_ticket(&t).unwrap();
        let c = s.verify_ssh_ticket(&token).unwrap();
        assert_eq!(
            (c.sub.as_str(), c.tenant_id.as_str(), c.fence),
            (
                t.session_id.to_hex().as_str(),
                t.tenant_id.to_hex().as_str(),
                7
            )
        );
        assert_eq!(c.owner_user_id, t.owner_user_id.to_hex());
        assert_eq!(c.origin_agent_id, t.origin_agent_id.to_hex());
        assert_eq!(c.target_agent_id, t.target_agent_id.to_hex());
        assert_eq!(c.account, "console_user");
        assert_eq!(c.jti, t.ticket_id.to_hex());
        assert_eq!((c.exp, c.token_type.clone()), (t.exp, TokenType::SshTicket));

        // No other gate accepts a ticket, a net grant's verifier among them.
        assert!(s.verify_net_grant(&token).is_err());
        assert!(s.verify_token(&token).is_err());
        assert!(s.verify_access_token(&token).is_err());
        assert!(s.verify_refresh_token(&token).is_err());
        assert!(s.verify_enrollment_token(&token).is_err());
        assert!(s.verify_enrollment_token_any(&token).is_err());
        assert!(s.verify_agent_token(&token).is_err());
        assert!(s.verify_agent_token_for_renewal(&token).is_err());
        assert!(s.verify_agent_service_token(&token).is_err());
        assert!(s.verify_tunnel_enrollment_token(&token).is_err());
        assert!(s.verify_tunnel_client_token(&token).is_err());
        assert!(s.verify_tunnel_client_token_for_renewal(&token).is_err());

        // And a ticket is no other credential, a net grant least of all.
        let (agent, tenant) = (ObjectId::new(), ObjectId::new());
        let pair = s.generate_tokens(ObjectId::new(), "a@b.c", "u").unwrap();
        let others = [
            pair.access_token,
            pair.refresh_token,
            s.issue_enrollment_token(ObjectId::new(), tenant, 600)
                .unwrap()
                .0,
            s.issue_ephemeral_enroll_key_token(ObjectId::new(), tenant, "j", in_secs(600))
                .unwrap(),
            s.issue_agent_token(agent, tenant, 0, Some(60)).unwrap(),
            s.issue_agent_service_token(agent, tenant, "anchor-1")
                .unwrap(),
            s.issue_tunnel_enrollment_token(ObjectId::new(), tenant, 600)
                .unwrap()
                .0,
            s.issue_tunnel_client_token(ObjectId::new(), tenant, ObjectId::new(), 0, Some(60))
                .unwrap(),
            s.issue_net_grant(&a_grant(NetKind::Socks, None, in_secs(60)))
                .unwrap(),
        ];
        for t in &others {
            assert!(s.verify_ssh_ticket(t).is_err());
        }
    }

    /// The issuer refuses a ticket that does not hold together, so no caller's
    /// slip can sign one for the device the session runs on.
    #[test]
    fn an_ssh_ticket_that_does_not_hold_together_is_never_signed() {
        let s = svc();
        let mut own = a_ticket(SshAccountMode::Daemon, in_secs(60));
        own.target_agent_id = own.origin_agent_id;
        for t in [
            own,
            // Past the ceiling by more than a second's tick between the two
            // clocks reads, so never at it by chance.
            a_ticket(SshAccountMode::Daemon, in_secs(905)),
            a_ticket(SshAccountMode::Daemon, in_secs(0)),
            a_ticket(SshAccountMode::Daemon, in_secs(-10)),
        ] {
            assert!(s.issue_ssh_ticket(&t).is_err(), "{t:?}");
        }
        for account in SshAccountMode::ALL {
            assert!(
                s.issue_ssh_ticket(&a_ticket(account, in_secs(900))).is_ok(),
                "the ceiling itself, as {account:?}"
            );
        }
    }

    /// A token signed with the server's own key but naming a ticket that does
    /// not hold together is refused at the check too, whoever signed it.
    #[test]
    fn an_ssh_ticket_signed_wider_than_it_holds_is_refused() {
        let s = svc();
        let now = Utc::now().timestamp();
        let good = SshTicketClaims {
            sub: ObjectId::new().to_hex(),
            tenant_id: ObjectId::new().to_hex(),
            fence: 1,
            owner_user_id: ObjectId::new().to_hex(),
            origin_agent_id: ObjectId::new().to_hex(),
            target_agent_id: ObjectId::new().to_hex(),
            account: "console_user".into(),
            jti: ObjectId::new().to_hex(),
            iat: now,
            exp: now + 60,
            iss: "roomler-ai-test".into(),
            token_type: TokenType::SshTicket,
        };
        let signed = |c: &SshTicketClaims| encode(&s.header(), c, &s.signing.encoding).unwrap();
        assert!(s.verify_ssh_ticket(&signed(&good)).is_ok());
        let mut wider = Vec::new();
        let mut c = good.clone();
        c.target_agent_id = c.origin_agent_id.clone();
        wider.push(("the device it runs on", c));
        let mut c = good.clone();
        c.target_agent_id = c.origin_agent_id.to_uppercase();
        wider.push(("the device it runs on, spelled another way", c));
        let mut c = good.clone();
        c.target_agent_id = "any-device".into();
        wider.push(("a target that is no id", c));
        let mut c = good.clone();
        c.account = "root".into();
        wider.push(("an account this build cannot name", c));
        let mut c = good.clone();
        c.account = "Daemon".into();
        wider.push(("an account not in its one spelling", c));
        let mut c = good.clone();
        c.exp = now + 901;
        wider.push(("a life past the ceiling", c));
        // A ticket's every claim, under another audience: no ticket at all.
        let mut c = good.clone();
        c.token_type = TokenType::NetGrant;
        wider.push(("a net grant's audience", c));
        for (why, c) in &wider {
            assert!(s.verify_ssh_ticket(&signed(c)).is_err(), "{why}");
        }
    }

    /// A ticket ends at its end: none of the leeway every other verifier
    /// gives, which would let a ticket decided for 900 s ask at 959.
    #[test]
    fn an_ssh_ticket_has_no_leeway_past_its_end() {
        let s = svc();
        let now = Utc::now().timestamp();
        let lapsed = SshTicketClaims {
            sub: ObjectId::new().to_hex(),
            tenant_id: ObjectId::new().to_hex(),
            fence: 1,
            owner_user_id: ObjectId::new().to_hex(),
            origin_agent_id: ObjectId::new().to_hex(),
            target_agent_id: ObjectId::new().to_hex(),
            account: "daemon".into(),
            jti: ObjectId::new().to_hex(),
            iat: now - 65,
            exp: now - 5,
            iss: "roomler-ai-test".into(),
            token_type: TokenType::SshTicket,
        };
        let t = encode(&s.header(), &lapsed, &s.signing.encoding).unwrap();
        assert!(
            s.decode_any::<SshTicketClaims>(&t, &s.validation()).is_ok(),
            "the default validation's minute of leeway would take it"
        );
        assert!(matches!(
            s.verify_ssh_ticket(&t),
            Err(AuthError::TokenExpired)
        ));
    }
}
