// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The per-address limit on `/api`, which a signed-in caller is not subject to.
//!
//! A home or office network puts a browser and every device behind it on one address, and a
//! front that injects the session (the operator's workspace portal) sends every one of its
//! users the same way. One bucket per address for all of them answered the web UI with 429
//! while nothing was wrong (operator, 2026-11-22: signed in through the workspace, nothing
//! should be limited).
//!
//! So a request that carries a credential this server signed — a user access token, an agent
//! token or an agent service token, by signature, issuer, audience and expiry — passes
//! unmetered. That check only exempts the request from the limit: the handler still
//! authorizes it in full (revocation, membership, device status). A request with no
//! credential, or one that does not verify, is metered per client address
//! ([`client_ip`], the server's one address rule). The credential endpoints keep their
//! own per-(address, account) brute-force gate on top
//! ([`super::auth_rate_limit`]).

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use meshharbor_services::auth::AuthService;

use super::{auth_rate_limit::AuthRateLimiter, client_ip::client_ip};

#[derive(Clone)]
pub struct ApiRateLimitState {
    /// Keyed on (address, ""): one bucket per client address.
    pub limiter: Arc<AuthRateLimiter>,
    pub trusted_hops: usize,
    pub auth: Arc<AuthService>,
}

/// Whether the request carries a credential this server signed, from the `Authorization`
/// header or the session cookie — the two places the handlers read one from.
pub(crate) fn signed_in(auth: &AuthService, headers: &HeaderMap) -> bool {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    bearer
        .into_iter()
        .chain(crate::cookies::get(headers, "access_token"))
        .filter(|t| !t.is_empty())
        .any(|t| {
            auth.verify_access_token(&t).is_ok()
                || auth.verify_agent_token(&t).is_ok()
                || auth.verify_agent_service_token(&t).is_ok()
        })
}

pub async fn api_rate_limit(
    State(state): State<ApiRateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if signed_in(&state.auth, req.headers()) {
        return next.run(req).await;
    }
    // No address at all means the request reached us outside the expected chain; charge
    // those to one shared bucket rather than waving them past.
    let ip = client_ip(&req, state.trusted_hops).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if let Err(retry_after) = state.limiter.check(ip, "") {
        tracing::debug!(%ip, path = %req.uri().path(), retry_after, "api rate limit hit");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::RETRY_AFTER, retry_after.to_string()),
                (header::CONTENT_TYPE, "application/json".to_string()),
            ],
            format!(
                r#"{{"error":"too_many_requests","message":"Too many requests from this address without signing in. Try again in {retry_after}s."}}"#
            ),
        )
            .into_response();
    }
    next.run(req).await
}
