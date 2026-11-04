// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-103 — a `roomler` tunnel client renews its own token before it expires,
//! and the ONE rule for when a credential is due, which `roomlerd` uses too.
//!
//! A tunnel-client token lives a year from enrollment. Until FR-103 nothing
//! renewed it, and a tunnel-only host found out on its anniversary, when every
//! `meshharbor forward` was refused. The server (FR-103 P1) answers
//! `POST /api/tunnel-client/renew` with a fresh token for the same client:
//! idempotent, no rotation (the old token stays valid until its own `exp`), and
//! accepted up to 90 days past expiry so a laptop left in a drawer still comes
//! back by itself.
//!
//! The client has no daemon to schedule anything, so it renews when it is
//! USED: [`renew_if_due`] runs before `forward` and `socks5` connect, and
//! costs nothing but a local read of the token's `exp` unless it is due.

use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use serde::Deserialize;

use crate::config::{self, TunnelConfig};

/// Renew once a token has less than this many days left.
pub const DEFAULT_HORIZON_DAYS: u64 = 180;

/// The renewal rule, shared with `roomlerd`: the unix second at which a token
/// expiring at `expires_at` becomes due.
///
/// - `horizon: None` (the default rule): [`DEFAULT_HORIZON_DAYS`] before
///   expiry, or at half the token's lifetime if that comes first. A year-long
///   token renews at 185 days old; a short-lived one (a server minting with a
///   short `rc.agent_token_ttl_secs`) at half-life, rather than being due
///   from birth and renewed on every look.
/// - `horizon: Some(d)`: exactly `d` before expiry, whatever the lifetime.
///   The field-test override: longer than the lifetime makes a fresh token
///   due at once.
pub fn renew_at(expires_at: i64, issued_at: Option<i64>, horizon: Option<Duration>) -> i64 {
    let secs = |d: Duration| i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
    let threshold = match horizon {
        Some(exact) => secs(exact),
        None => {
            let default = secs(Duration::from_secs(DEFAULT_HORIZON_DAYS * 86_400));
            match issued_at {
                Some(issued_at) if expires_at > issued_at => {
                    default.min((expires_at - issued_at) / 2)
                }
                _ => default,
            }
        }
    };
    expires_at.saturating_sub(threshold)
}

/// A token's `exp` and `iat` (unix seconds), read WITHOUT verifying it: for
/// scheduling a renewal, never for trusting anything. `None` when the token
/// is not a JWT or carries no `exp`.
pub fn unverified_times(token: &str) -> Option<(i64, Option<i64>)> {
    #[derive(Deserialize)]
    struct Times {
        exp: Option<i64>,
        iat: Option<i64>,
    }
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let times: Times = serde_json::from_slice(&bytes).ok()?;
    Some((times.exp?, times.iat))
}

/// What [`renew_if_due`] did. The caller carries on whichever it was: a
/// renewal that could not happen never stops a `forward`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewal {
    /// The token is not due, or carries no readable expiry.
    NotDue,
    /// Renewed and saved; `cfg` holds the new token.
    Renewed,
    /// Renewed, but the config could not be saved: `cfg` holds the new token
    /// for this run, and the file's (still valid) token is used next time.
    RenewedUnsaved,
    /// The token comes from `ROOMLER_TUNNEL_SERVER`/`ROOMLER_TUNNEL_TOKEN`:
    /// there is no file to save a renewal to, and the environment's owner
    /// renews it.
    FromEnvironment,
    /// 404: a server older than FR-103, or with renewal switched off.
    Unsupported,
    /// 401/403: removed, quarantined, re-enrolled elsewhere, or past the
    /// grace. Re-enroll the client.
    Refused,
    /// The server did not answer usably; tried again at the next run.
    Failed,
}

#[derive(Deserialize)]
struct RenewBody {
    tunnel_client_token: String,
}

/// Renew `cfg`'s token when it is due (the default rule), save it, and put it
/// in `cfg`. `path` is the config file `cfg` was loaded from (`None` = the
/// default path).
pub async fn renew_if_due(cfg: &mut TunnelConfig, path: Option<&Path>) -> Renewal {
    if config::from_environment() {
        return Renewal::FromEnvironment;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match unverified_times(&cfg.tunnel_client_token) {
        Some((exp, iat)) if now >= renew_at(exp, iat, None) => {}
        _ => return Renewal::NotDue,
    }
    let fresh = match request(&cfg.server_url, &cfg.tunnel_client_token).await {
        Ok(Some(token)) => token,
        Ok(None) => return Renewal::Unsupported,
        Err(RequestError::Refused(status)) => {
            tracing::warn!(
                status,
                "tunnel-client token renewal refused: re-enroll this client (`meshharbor enroll`)"
            );
            return Renewal::Refused;
        }
        Err(RequestError::Other(e)) => {
            tracing::warn!(error = %format!("{e:#}"), "tunnel-client token renewal failed; trying again next run");
            return Renewal::Failed;
        }
    };
    let renewed_from = std::mem::replace(&mut cfg.tunnel_client_token, fresh);
    match config::save_renewed_token(cfg, &renewed_from, path) {
        Ok(()) => {
            tracing::info!("tunnel-client token renewed");
            Renewal::Renewed
        }
        Err(e) => {
            // Nothing is rotated: the file's token is still valid, so this
            // run carries on with the new one and the next run renews again.
            tracing::warn!(
                error = %format!("{e:#}"),
                "tunnel-client token renewed but not saved; using it for this run"
            );
            Renewal::RenewedUnsaved
        }
    }
}

enum RequestError {
    Refused(u16),
    Other(anyhow::Error),
}

/// `POST {server}/api/tunnel-client/renew`. `Ok(None)` = 404 (no route).
async fn request(server_url: &str, token: &str) -> Result<Option<String>, RequestError> {
    let base = server_url.trim().trim_end_matches('/');
    let client = reqwest::Client::builder()
        .user_agent(concat!("roomler-token-renewal/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| RequestError::Other(e.into()))?;
    let resp = client
        .post(format!("{base}/api/tunnel-client/renew"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| {
            RequestError::Other(anyhow::Error::new(e).context("POST /api/tunnel-client/renew"))
        })?;
    match resp.status().as_u16() {
        200..=299 => {
            let body: RenewBody = resp.json().await.map_err(|e| {
                RequestError::Other(anyhow::Error::new(e).context("reading the renewal answer"))
            })?;
            if body.tunnel_client_token.trim().is_empty() {
                return Err(RequestError::Other(anyhow::anyhow!(
                    "the renewal answer carried no token"
                )));
            }
            Ok(Some(body.tunnel_client_token))
        }
        404 => Ok(None),
        status @ (401 | 403) => Err(RequestError::Refused(status)),
        status => Err(RequestError::Other(anyhow::anyhow!(
            "the server answered {status}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    fn token(claims: serde_json::Value) -> String {
        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        format!(
            "{}.{}.sig",
            enc(br#"{"alg":"HS256"}"#),
            enc(claims.to_string().as_bytes())
        )
    }

    #[test]
    fn a_year_long_token_is_due_with_180_days_left() {
        assert_eq!(renew_at(365 * DAY, Some(0), None), 185 * DAY);
        assert_eq!(renew_at(365 * DAY, None, None), 185 * DAY);
    }

    #[test]
    fn a_short_token_is_due_at_half_life() {
        assert_eq!(renew_at(4_600, Some(1_000), None), 2_800);
    }

    #[test]
    fn the_override_is_exact() {
        let long = Some(Duration::from_secs(400 * 86_400));
        assert_eq!(renew_at(365 * DAY, Some(0), long), -35 * DAY);
        let short = Some(Duration::from_secs(10 * 86_400));
        assert_eq!(renew_at(365 * DAY, Some(0), short), 355 * DAY);
    }

    #[test]
    fn times_are_read_without_verifying() {
        let t = token(serde_json::json!({ "exp": 42, "iat": 7 }));
        assert_eq!(unverified_times(&t), Some((42, Some(7))));
        let no_iat = token(serde_json::json!({ "exp": 42 }));
        assert_eq!(unverified_times(&no_iat), Some((42, None)));
        assert_eq!(
            unverified_times(&token(serde_json::json!({ "sub": "x" }))),
            None
        );
        assert_eq!(unverified_times("not-a-jwt"), None);
    }
}
