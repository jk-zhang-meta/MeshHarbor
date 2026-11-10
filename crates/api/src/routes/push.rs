// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use meshharbor_core::net::is_global_unicast;

use crate::{core_state::Core, error::ApiError, extractors::auth::AuthUser};

/// SSRF guard for the client-supplied Web Push `endpoint`.
///
/// The endpoint is a browser-supplied absolute URL that the SERVER later POSTs
/// to from inside the cluster (every notification fan-out). Unvalidated, any
/// authenticated user could point it at `169.254.169.254`, a pod-internal
/// admin port, or `10.0.0.0/8` and use their own notifications as a blind SSRF
/// / internal port-scan primitive. Require https and refuse any host that
/// resolves into a private, loopback, link-local or otherwise non-global range.
///
/// Resolution is best-effort: a host we cannot resolve is REFUSED rather than
/// allowed, because "unknown destination" is exactly the case this guard
/// exists to stop. (DNS can still rebind between here and send time; the send
/// path should re-check — this closes the trivially reachable hole.)
async fn validate_push_endpoint(endpoint: &str) -> Result<(), ApiError> {
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| ApiError::BadRequest("push endpoint must be an https:// URL".to_string()))?;

    // authority = up to the first '/', '?' or '#'; strip any userinfo.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err(ApiError::BadRequest(
            "push endpoint has no host".to_string(),
        ));
    }

    // Split host/port, handling bracketed IPv6 literals.
    let (host, port) = if let Some(end) = authority.strip_prefix('[') {
        let (h, tail) = end
            .split_once(']')
            .ok_or_else(|| ApiError::BadRequest("malformed IPv6 host".to_string()))?;
        (
            h.to_string(),
            tail.strip_prefix(':').and_then(|p| p.parse().ok()),
        )
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()),
            None => (authority.to_string(), None),
        }
    };

    let addrs: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host((host.as_str(), port.unwrap_or(443)))
            .await
            .map_err(|_| ApiError::BadRequest("push endpoint host does not resolve".to_string()))?
            .map(|s| s.ip())
            .collect(),
    };
    if addrs.is_empty() {
        return Err(ApiError::BadRequest(
            "push endpoint host does not resolve".to_string(),
        ));
    }
    // EVERY resolved address must be public — a name resolving to both a
    // public and an internal address must not slip through.
    if addrs.iter().any(|ip| !is_global_unicast(ip)) {
        return Err(ApiError::BadRequest(
            "push endpoint must be a public address".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub endpoint: String,
    pub keys: PushKeysRequest,
}

#[derive(Debug, Deserialize)]
pub struct PushKeysRequest {
    pub auth: String,
    pub p256dh: String,
}

#[derive(Debug, Deserialize)]
pub struct UnsubscribeRequest {
    pub endpoint: String,
}

#[derive(Debug, Serialize)]
pub struct PushConfigResponse {
    pub vapid_public_key: String,
}

/// GET /push/config — returns the VAPID public key for client-side subscription
pub async fn config(State(state): State<Core>) -> Result<Json<PushConfigResponse>, ApiError> {
    Ok(Json(PushConfigResponse {
        vapid_public_key: state.settings.push.vapid_public_key.clone(),
    }))
}

/// POST /push/subscribe — register a push subscription for the authenticated user
pub async fn subscribe(
    State(state): State<Core>,
    auth: AuthUser,
    Json(body): Json<SubscribeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_push_endpoint(&body.endpoint).await?;

    state
        .push_subscriptions
        .subscribe(
            auth.user_id,
            body.endpoint,
            body.keys.auth,
            body.keys.p256dh,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /push/unsubscribe — remove a push subscription
pub async fn unsubscribe(
    State(state): State<Core>,
    auth: AuthUser,
    Json(body): Json<UnsubscribeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .push_subscriptions
        .unsubscribe(auth.user_id, &body.endpoint)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
mod push_endpoint_tests {
    use super::{is_global_unicast, validate_push_endpoint};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn internal_ranges_are_not_global() {
        // The SSRF targets that matter: cloud metadata, loopback, RFC1918,
        // CGNAT/overlay, and the v6 equivalents.
        for s in [
            "169.254.169.254",
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "100.65.4.2",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_global_unicast(&ip(s)), "{s} must be refused");
        }
    }

    #[test]
    fn public_addresses_are_global() {
        for s in ["1.1.1.1", "142.250.185.100", "2606:4700:4700::1111"] {
            assert!(is_global_unicast(&ip(s)), "{s} must be allowed");
        }
    }

    #[tokio::test]
    async fn rejects_non_https_and_internal_hosts() {
        // http:// is refused outright.
        assert!(
            validate_push_endpoint("http://fcm.googleapis.com/fcm/send/x")
                .await
                .is_err()
        );
        // An https URL naming an internal literal is refused without any DNS.
        assert!(
            validate_push_endpoint("https://169.254.169.254/latest/meta-data/")
                .await
                .is_err()
        );
        assert!(
            validate_push_endpoint("https://127.0.0.1:9000/x")
                .await
                .is_err()
        );
        assert!(validate_push_endpoint("https://[::1]/x").await.is_err());
        // Userinfo must not smuggle a public-looking host past the parser.
        assert!(
            validate_push_endpoint("https://fcm.googleapis.com@127.0.0.1/x")
                .await
                .is_err()
        );
    }
}
