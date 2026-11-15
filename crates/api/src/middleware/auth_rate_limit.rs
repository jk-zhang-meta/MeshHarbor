// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Brute-force gate for the credential endpoints.
//!
//! The general `/api` limiter is a capacity control: it is keyed on the
//! client address alone and set generously, because a SPA page load fans out
//! to many endpoints and every client behind one NAT shares the bucket.
//! Tightening it far enough to matter against password guessing would lock
//! out whole offices — that is exactly how prod ended up serving 429s on
//! `POST /api/auth/login` on 2026-07-28.
//!
//! So credential endpoints get their own, much stricter budget, keyed on
//! **(client address, account)**. Guessing many passwords for one account
//! burns that account's budget; a shared office address still gets a full
//! budget per person signing in.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::client_ip::client_ip;

/// Auth payloads are a handful of short fields; anything larger is not a
/// login attempt and is refused rather than buffered.
const MAX_AUTH_BODY: usize = 64 * 1024;

/// Drop buckets untouched for this long, so a stream of distinct accounts
/// can't grow the map without bound.
const IDLE_EVICTION: Duration = Duration::from_secs(15 * 60);

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Keyed token bucket. `period` replenishes one token; `burst` is the cap.
#[derive(Debug)]
pub struct AuthRateLimiter {
    period: Duration,
    burst: f64,
    buckets: Mutex<HashMap<(IpAddr, String), Bucket>>,
}

impl AuthRateLimiter {
    pub fn new(period_ms: u64, burst: u32) -> Self {
        Self {
            period: Duration::from_millis(period_ms.max(1)),
            burst: f64::from(burst.max(1)),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Spend one token. `Ok(())` to proceed; `Err(seconds)` to reject with
    /// that `Retry-After`.
    pub fn check(&self, ip: IpAddr, account: &str) -> Result<(), u64> {
        let now = Instant::now();
        let refill_per_sec = 1.0 / self.period.as_secs_f64();

        // A poisoned lock must not wedge sign-in for everyone; recover the
        // map and carry on.
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        buckets.retain(|_, b| now.duration_since(b.last) < IDLE_EVICTION);

        let bucket = buckets
            .entry((ip, account.to_owned()))
            .or_insert_with(|| Bucket {
                tokens: self.burst,
                last: now,
            });

        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(self.burst);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - bucket.tokens;
            Err((deficit / refill_per_sec).ceil().max(1.0) as u64)
        }
    }
}

/// State for [`auth_rate_limit`], kept separate from `AppState` so the
/// limiter can be wired in without touching every `AppState` literal.
#[derive(Clone)]
pub struct AuthRateLimitState {
    pub limiter: Arc<AuthRateLimiter>,
    pub trusted_hops: usize,
}

/// Pull the account an auth request is about, so guessing is charged per
/// account rather than per address.
///
/// Matches `LoginRequest`/`RegisterRequest`, which accept either a username
/// or an email. Case-folded so `Alice` and `alice` share one budget. A body
/// with no account field falls back to an empty account, which simply keys
/// the request on the address.
fn account_key(body: &Bytes) -> String {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::new();
    };
    json.get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default()
}

fn caller_credential_key(headers: &axum::http::HeaderMap) -> String {
    use sha2::{Digest, Sha256};
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .or_else(|| crate::cookies::get(headers, "access_token"));
    match raw.filter(|s| !s.is_empty()) {
        Some(token) => format!("auth:{:x}", Sha256::digest(token.as_bytes())),
        None => String::new(),
    }
}

fn rate_limit_subject(parts: &axum::http::request::Parts, body: &Bytes) -> String {
    if parts.uri.path().ends_with("/email-change/request") {
        caller_credential_key(&parts.headers)
    } else {
        account_key(body)
    }
}

fn too_many_requests(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, retry_after.to_string()),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        format!(
            r#"{{"error":"too_many_requests","message":"Too many attempts for this account. Try again in {retry_after}s."}}"#
        ),
    )
        .into_response()
}

pub async fn auth_rate_limit(
    State(state): State<AuthRateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = client_ip(&req, state.trusted_hops);

    // The body has to be read to learn the account, so buffer it and put it
    // back before handing the request on.
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_AUTH_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"bad_request","message":"Request body too large"}"#,
            )
                .into_response();
        }
    };

    // No address at all means the request reached us outside the expected
    // chain; charge those to one shared bucket rather than waving them past.
    let ip = ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    if let Err(retry_after) = state.limiter.check(ip, &rate_limit_subject(&parts, &bytes)) {
        tracing::warn!(
            %ip,
            path = %parts.uri.path(),
            retry_after,
            "auth rate limit hit"
        );
        return too_many_requests(retry_after);
    }

    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_then_throttle() {
        // 1 token/min, burst 3.
        let rl = AuthRateLimiter::new(60_000, 3);
        let a = ip("203.0.113.9");
        for i in 0..3 {
            assert!(rl.check(a, "alice").is_ok(), "attempt {i} should pass");
        }
        let retry = rl.check(a, "alice").expect_err("4th must be throttled");
        assert!(retry > 0, "Retry-After must be a usable delay");
    }

    /// The reason this limiter is keyed on the account: one person guessing
    /// must not lock out everyone else sharing an office address.
    #[test]
    fn accounts_have_separate_budgets() {
        let rl = AuthRateLimiter::new(60_000, 2);
        let a = ip("203.0.113.9");
        assert!(rl.check(a, "alice").is_ok());
        assert!(rl.check(a, "alice").is_ok());
        assert!(rl.check(a, "alice").is_err());
        // Same address, different account — untouched budget.
        assert!(rl.check(a, "bob").is_ok());
        assert!(rl.check(a, "bob").is_ok());
    }

    /// ...and one address exhausting an account must not lock that account
    /// out from somewhere else, so the address is part of the key too.
    #[test]
    fn addresses_have_separate_budgets() {
        let rl = AuthRateLimiter::new(60_000, 1);
        assert!(rl.check(ip("203.0.113.9"), "alice").is_ok());
        assert!(rl.check(ip("203.0.113.9"), "alice").is_err());
        assert!(rl.check(ip("198.51.100.7"), "alice").is_ok());
    }

    #[test]
    fn tokens_refill_over_time() {
        // 10ms/token, burst 1 — fast enough to observe without a slow test.
        let rl = AuthRateLimiter::new(10, 1);
        let a = ip("203.0.113.9");
        assert!(rl.check(a, "alice").is_ok());
        assert!(rl.check(a, "alice").is_err());
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            rl.check(a, "alice").is_ok(),
            "bucket should have refilled after the period elapsed"
        );
    }

    #[test]
    fn account_key_reads_email_only_case_folded() {
        assert_eq!(
            account_key(&Bytes::from(r#"{"username":"Alice","password":"x"}"#)),
            String::new()
        );
        assert_eq!(
            account_key(&Bytes::from(
                r#"{"email":" Bob@Example.COM ","password":"x"}"#
            )),
            "bob@example.com"
        );
        // No account field (refresh) and non-JSON both key on address alone.
        assert_eq!(
            account_key(&Bytes::from(r#"{"refresh_token":"t"}"#)),
            String::new()
        );
        assert_eq!(account_key(&Bytes::from("not json")), String::new());
    }
}
