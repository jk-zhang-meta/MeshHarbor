// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use bson::oid::ObjectId;
use roomler_ai_services::auth::Claims;

use crate::{Core, error::ApiError};

/// Extracts the authenticated user from JWT (cookie or Authorization header)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthUser {
    pub user_id: ObjectId,
    pub email: String,
    pub username: String,
    pub claims: Claims,
}

impl<S> FromRequestParts<S> for AuthUser
where
    Core: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // FR-69 P1 — only the core is needed here: the JWT verifier. Bounding
        // on `Core` rather than `AppState` is what lets a module crate's
        // router (state = its own struct that derefs to `Core`) use this
        // extractor unchanged.
        let core = Core::from_ref(state);

        // Try Authorization header first, then the session cookie. The SPA is
        // moving to cookie-only, but the header stays accepted: scripts, the
        // e2e helpers and any external caller use it, and it is the only
        // option for a cross-origin client.
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string())
            .or_else(|| crate::cookies::get(&parts.headers, "access_token"))
            .ok_or_else(|| ApiError::Unauthorized("No token provided".to_string()))?;

        let claims = core.auth.verify_access_token(&token)?;
        crate::admission::authorize_claims(&core, &claims).await?;

        let user_id = ObjectId::parse_str(&claims.sub)
            .map_err(|_| ApiError::Unauthorized("Invalid user ID in token".to_string()))?;

        Ok(AuthUser {
            user_id,
            email: claims.email.clone(),
            username: claims.username.clone(),
            claims,
        })
    }
}

/// Optional auth extractor — returns `Option<AuthUser>`, never rejects.
/// Use for endpoints that behave differently for authenticated vs unauthenticated users.
pub struct OptionalAuthUser(pub Option<AuthUser>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    Core: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalAuthUser(
            AuthUser::from_request_parts(parts, state).await.ok(),
        ))
    }
}
