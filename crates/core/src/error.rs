// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use meshharbor_services::auth::AuthError;
use meshharbor_services::dao::base::DaoError;
use serde::Serialize;

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    /// 403, but specifically "you are not in this tenant" — as opposed to
    /// "you are, and you may not do that" ([`ApiError::Forbidden`]).
    ///
    /// FR-82 — the two are the same status code and were the same string, so
    /// the SPA could not tell them apart and treated every 403 as a dead
    /// session: it wiped the login and bounced to `/login`. That is wrong for
    /// both halves — a permission refusal is an answer, not an expired
    /// credential — but only ONE of them has a sensible navigation, which is
    /// why the distinction has to reach the client instead of being inferred
    /// there. Serialises as `error: "not_a_member"`; the client leaves the
    /// tenant and keeps the session.
    ///
    /// ⚠️ TENANT membership only. A room refusal is not this — `chat`'s
    /// "Not a member of this room" stays a plain `Forbidden`, because
    /// leaving the org over a private channel would be absurd.
    NotAMember,
    Conflict(String),
    Internal(String),
    Validation(String),
    ServiceUnavailable(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::NotFound(msg) => write!(f, "Not found: {msg}"),
            ApiError::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            ApiError::Forbidden(msg) => write!(f, "Forbidden: {msg}"),
            ApiError::NotAMember => write!(f, "Forbidden: Not a member"),
            ApiError::Conflict(msg) => write!(f, "Conflict: {msg}"),
            ApiError::Internal(msg) => write!(f, "Internal error: {msg}"),
            ApiError::Validation(msg) => write!(f, "Validation: {msg}"),
            ApiError::ServiceUnavailable(msg) => write!(f, "Service unavailable: {msg}"),
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log the cause of every 5xx into the structured logs so a
        // production 500 can be diagnosed from `kubectl logs` without
        // needing the user to capture the response body. tower_http's
        // trace layer logs `status=500` but discards the body, leaving
        // a recurring "API error 500" report unfixable until someone
        // pastes the response payload. Other status classes use
        // existing tracing of their own (auth middleware logs 401
        // reasons, validation logs 422 fields, etc.).
        if let ApiError::Internal(msg) = &self {
            tracing::error!(message = %msg, "ApiError::Internal -> 500");
        }
        let (status, error_type, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg),
            ApiError::NotAMember => (
                StatusCode::FORBIDDEN,
                "not_a_member",
                "Not a member".to_string(),
            ),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", msg),
            ApiError::Validation(msg) => (StatusCode::UNPROCESSABLE_ENTITY, "validation", msg),
            ApiError::ServiceUnavailable(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", msg)
            }
        };

        let body = ErrorResponse {
            error: error_type.to_string(),
            message,
        };

        (status, Json(body)).into_response()
    }
}

impl From<DaoError> for ApiError {
    fn from(err: DaoError) -> Self {
        match err {
            DaoError::NotFound => ApiError::NotFound("Resource not found".to_string()),
            DaoError::DuplicateKey(msg) => ApiError::Conflict(msg),
            DaoError::Forbidden(msg) => ApiError::Forbidden(msg),
            DaoError::NotAMember => ApiError::NotAMember,
            DaoError::Validation(msg) => ApiError::Validation(msg),
            DaoError::Mongo(e) => ApiError::Internal(e.to_string()),
            DaoError::BsonSer(e) => ApiError::Internal(e.to_string()),
            DaoError::BsonDe(e) => ApiError::Internal(e.to_string()),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials => {
                ApiError::Unauthorized("Invalid credentials".to_string())
            }
            AuthError::TokenExpired => ApiError::Unauthorized("Token expired".to_string()),
            AuthError::InvalidToken(msg) => ApiError::Unauthorized(msg),
            AuthError::HashError(msg) => ApiError::Internal(msg),
        }
    }
}

impl From<meshharbor_services::oauth::OAuthError> for ApiError {
    fn from(err: meshharbor_services::oauth::OAuthError) -> Self {
        match err {
            meshharbor_services::oauth::OAuthError::ProviderNotConfigured(msg) => {
                ApiError::BadRequest(format!("Provider not configured: {msg}"))
            }
            meshharbor_services::oauth::OAuthError::UnknownProvider(msg) => {
                ApiError::BadRequest(format!("Unknown provider: {msg}"))
            }
            meshharbor_services::oauth::OAuthError::InvalidState => {
                ApiError::BadRequest("Invalid OAuth state".to_string())
            }
            other => ApiError::Internal(other.to_string()),
        }
    }
}
