// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use roomler_ai_services::oauth::OAuthUserInfo;
use roomler_core::attribution::{self, AttributionInput};
use serde::Deserialize;
use tracing::debug;
use uuid::Uuid;

use crate::{core_state::Core, error::ApiError};

/// `; Secure` in production, empty in dev — the http://localhost dev/test flow
/// must still receive the cookie, and prod is https end-to-end.
fn secure_attr(state: &Core) -> &'static str {
    if state.settings.app.environment == "production" {
        "; Secure"
    } else {
        ""
    }
}

/// Read one cookie value out of the request `Cookie` header.
///
/// Thin alias over [`crate::cookies::get`] — the parser used to be spelled out
/// here, and in the auth extractor, and in the `/ws` upgrade, each slightly
/// differently. See that module for why one copy is the point.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    crate::cookies::get(headers, name)
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// `GET /api/oauth/{provider}?utm_source=&utm_medium=&utm_campaign=&utm_content=&utm_term=&referrer_host=&landing_path=&self_reported=`
///
/// The query is FR-88's: the register view's provider buttons pass the
/// landing's attribution along, and it is parked in Redis under the CSRF
/// state for the callback to collect. Read as a plain map so that no value,
/// however malformed, can fail the redirect — unknown keys are ignored.
pub async fn oauth_redirect(
    State(state): State<Core>,
    Path(provider): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let oauth = state
        .oauth
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("OAuth not configured".to_string()))?;

    // CSRF: mint a random state, bind it to THIS browser via a short-lived
    // HttpOnly cookie (double-submit), and carry the same value in the auth
    // URL. The callback requires the two to match — without it an attacker
    // could feed a victim a pre-obtained code+state and silently sign them
    // into the ATTACKER's account (login CSRF / forced account takeover).
    let csrf_state = Uuid::new_v4().to_string();

    let auth_url = oauth
        .build_auth_url(&provider, &csrf_state)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // FR-88 — park the attribution under the state the cookie below binds.
    // Same TTL as the cookie, no cookie of its own, and a Redis that is
    // absent, failing or not answering in time costs the attribution, never
    // the sign-in (`park_for_oauth` gives up at `OAUTH_STORE_BUDGET`).
    if let Some(attr) = attribution::sanitize(AttributionInput::from_query(&query)) {
        match state.redis_pubsub.as_ref() {
            Some(redis) => {
                if let Err(e) =
                    attribution::park_for_oauth(redis.as_ref(), &csrf_state, &attr).await
                {
                    debug!(%e, "oauth attribution not parked; continuing without it");
                }
            }
            None => debug!("no redis — oauth attribution dropped"),
        }
    }

    let cookie = format!(
        "oauth_state={}; HttpOnly; Path=/; SameSite=Lax; Max-Age=600{}",
        csrf_state,
        secure_attr(&state)
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie.parse().unwrap());
    headers.insert(header::LOCATION, auth_url.parse().unwrap());
    Ok((StatusCode::TEMPORARY_REDIRECT, headers).into_response())
}

pub async fn oauth_callback(
    State(state): State<Core>,
    Path(provider): Path<String>,
    req_headers: HeaderMap,
    Query(params): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let oauth = state
        .oauth
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("OAuth not configured".to_string()))?;

    // CSRF: the query `state` MUST equal the `oauth_state` cookie we bound to
    // this browser at redirect time. A missing/mismatched value means the flow
    // was not initiated by this browser (login CSRF) — reject before touching
    // the code.
    if params.state.is_empty()
        || cookie_value(&req_headers, "oauth_state").as_deref() != Some(params.state.as_str())
    {
        return Err(ApiError::Forbidden("Invalid OAuth state".to_string()));
    }

    // Exchange code and fetch user info
    let user_info = oauth
        .authenticate(&provider, &params.code)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    if user_info.email.is_empty() {
        return Err(ApiError::BadRequest(
            "Could not retrieve email from OAuth provider".to_string(),
        ));
    }

    complete_sign_in(&state, user_info, &params.state).await
}

/// Everything after the provider has answered: resolve the account
/// (collecting what the redirect parked under the CSRF state), mint the
/// session, and send the browser back to the SPA.
///
/// Split from [`oauth_callback`] so the integration tests can drive it with a
/// hand-built [`OAuthUserInfo`] — the handler itself cannot run without a
/// real provider answering the code exchange. The CSRF check stays in the
/// handler, BEFORE this: nothing in here may weaken it, and nothing in here
/// looks at the attribution to decide anything about the sign-in.
pub async fn complete_sign_in(
    state: &Core,
    user_info: OAuthUserInfo,
    csrf_state: &str,
) -> Result<Response, ApiError> {
    // FR-88 — collect (and delete) whatever the redirect parked under this
    // state. A missing, expired or unreadable key, and a Redis that does not
    // answer within `OAUTH_STORE_BUDGET`, are all `None`; the DAO applies a
    // `Some` only when it CREATES the account.
    let signup_attribution = match state.redis_pubsub.as_ref() {
        Some(redis) => attribution::take_for_oauth(redis.as_ref(), csrf_state).await,
        None => None,
    };

    // Find or create user
    let sign_in = state
        .users
        .find_or_create_by_oauth(
            &user_info.provider,
            &user_info.provider_id,
            &user_info.email,
            &user_info.name,
            user_info.avatar_url.as_deref(),
            user_info.email_verified,
            signup_attribution,
        )
        .await?;
    let user = sign_in.user;
    let user_id = user.id.unwrap();

    roomler_core::admission::require_user(state, &user, None)?;
    // Generate JWT tokens only after the same admission rule as password login.
    let tokens = state.auth.generate_tokens_at_revision(
        user_id,
        &user.email,
        &user.username,
        user.account_approval.revision,
    )?;

    // Set the session cookie (Secure in prod) and clear the one-shot CSRF
    // state cookie now that it has been consumed.
    let cookie = format!(
        "access_token={}; HttpOnly; Path=/; SameSite=Lax; Max-Age={}{}",
        tokens.access_token,
        tokens.expires_in,
        secure_attr(state)
    );
    let clear_state = format!(
        "oauth_state=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0{}",
        secure_attr(state)
    );

    let frontend_url = state.settings.oauth.base_url.replace(":5001", ":5000"); // API → UI port
    let redirect_url = callback_redirect(&frontend_url, sign_in.created);

    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, cookie.parse().unwrap());
    // An OAuth sign-in never got a refresh credential at all: the callback
    // redirect used to carry ONE value in its fragment, so the refresh token
    // was minted and thrown away, and the session simply died after the access
    // token's 7 days. A cookie has no such limit — so OAuth users get the same
    // 30-day renewable session as password users, and get it without anything
    // being written where script can read it.
    headers.append(
        header::SET_COOKIE,
        crate::routes::auth::refresh_cookie(state, &tokens.refresh_token)
            .parse()
            .unwrap(),
    );
    headers.append(header::SET_COOKIE, clear_state.parse().unwrap());
    headers.insert(header::LOCATION, redirect_url.parse().unwrap());

    Ok((StatusCode::FOUND, headers).into_response())
}

/// Where the browser goes after the provider round trip.
///
/// The session rides the two cookies set beside this redirect; the URL
/// itself carries NO token. It used to (`#token=<jwt>`, in the fragment so
/// it stayed out of server logs) — but the SPA's own analytics tracker sends
/// `location.href`, fragment included, and stores it verbatim, so every OAuth
/// login wrote its 7-day JWT into the analytics database (#1799).
/// `OAuthCallbackView` never needed the value; the cookie is the credential.
///
/// FR-88 — `#signup=1` when THIS sign-in created the account, so the SPA can
/// count a sign-up (purestat's `signup` goal); a returning user gets a bare
/// URL. Only ever a marker: nothing about the person and nothing about where
/// they came from travels on it. The function takes no token on purpose —
/// the test below is the structural claim, not a string search.
pub(crate) fn callback_redirect(frontend_url: &str, created: bool) -> String {
    if created {
        format!("{frontend_url}/oauth/callback#signup=1")
    } else {
        format!("{frontend_url}/oauth/callback")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_callback_redirect_carries_a_signup_marker_and_never_a_token() {
        let created = callback_redirect("https://roomler.ai", true);
        assert_eq!(created, "https://roomler.ai/oauth/callback#signup=1");
        let returning = callback_redirect("https://roomler.ai", false);
        assert_eq!(returning, "https://roomler.ai/oauth/callback");
        for url in [&created, &returning] {
            assert!(!url.contains("token"), "{url}");
            assert!(!url.contains('?'), "nothing in the query either: {url}");
        }
    }
}
