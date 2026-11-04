// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P10 — the READ key (D12): a machine credential for the growth
//! views, so the promotion pipeline and the sessions that run it read the
//! stored digests, the funnel and the tables through the API instead of
//! querying databases by hand.
//!
//! ONE rule, in two halves, and no per-route copy:
//!
//! * [`read_key_gate`] — a layer on the whole `/api/admin/growth` router.
//!   When the bearer is a growth key of any kind (`rgi_…`, `rgr_…`), the
//!   answer is the key's and never the session's: a live READ key on a
//!   **GET** of a growth DATA route opens it (the gate records the use and
//!   marks the request); every other case is the **empty 404** of a path
//!   that does not exist — a write (any non-GET), the admin surface
//!   (`/keys`, `/exclusions`, which stay session-only so a leaked key can
//!   neither list its siblings nor read the admin ids), an ingest key, a
//!   malformed, unknown or revoked key, and `growth.enabled = false`. Never
//!   401 or 403. A database error is a 503, so a Mongo blip never tells the
//!   pipeline its key was revoked. A bearer that is not a growth key (a
//!   JWT) passes through untouched to the session flow.
//! * [`GrowthAuth`] — the extractor every GET view names instead of
//!   `AuthUser`: the mark the gate left, or else a platform admin's session
//!   on a server whose growth surface is on (the same gate as before, 404
//!   either way). A write route keeps `AuthUser` + `require_growth_admin`,
//!   and the gate has already answered a key on it.
//!
//! The key opens exactly what a platform admin's session reads at the same
//! route (AC20): the handler does not know which of the two it serves.

use axum::{
    extract::{FromRef, FromRequestParts, Request, State},
    http::{HeaderMap, Method, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_services::dao::growth_key::{GrowthKeyDao, GrowthKeyKind};
use meshharbor_core::{Core, guards::require_platform_admin};
use tracing::{info, warn};

use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

/// The growth routes a read key never opens, GET or not — as the nested
/// growth router sees them (the `/api/admin/growth` prefix stripped): the
/// admin surface, not the numbers.
pub const SESSION_ONLY: [&str; 2] = ["/keys", "/exclusions"];

/// Which key opened a request — for the use log and nothing else (never
/// the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadKeyAuth {
    pub id: ObjectId,
    pub prefix: String,
}

/// Whether `path` (prefix-stripped) is the admin surface.
pub fn session_only(path: &str) -> bool {
    SESSION_ONLY.iter().any(|p| {
        path == *p
            || path
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// What a growth key may do on `method` + `path`: a READ key on a GET of a
/// data route, and nothing else. Pure, so the rule is unit-tested without
/// a server.
pub fn key_opens(kind: GrowthKeyKind, method: &Method, path: &str) -> bool {
    kind == GrowthKeyKind::Read && *method == Method::GET && !session_only(path)
}

/// The empty 404 of a path that does not exist — every refusal of the gate.
fn absent() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}

/// The gate (a `route_layer` on the growth router). See the module docs.
pub async fn read_key_gate(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(raw) = bearer(req.headers()) else {
        return next.run(req).await;
    };
    let Some(kind) = GrowthKeyKind::claimed_by(&raw) else {
        return next.run(req).await;
    };
    // A growth key was presented: from here the answer is the key's.
    if !state.settings.growth.enabled || !key_opens(kind, req.method(), req.uri().path()) {
        return absent();
    }
    let dao = GrowthKeyDao::new(&state.db);
    match dao.find_live(GrowthKeyKind::Read, &raw).await {
        Ok(Some(key)) => {
            if let Err(e) = dao.touch(key.id, DateTime::now()).await {
                warn!(key = %key.prefix, %e, "growth read key: could not record the key's use");
            }
            // The path only: ids at most, never a query string.
            info!(key = %key.prefix, path = %req.uri().path(), "growth read key");
            req.extensions_mut().insert(ReadKeyAuth {
                id: key.id,
                prefix: key.prefix,
            });
            next.run(req).await
        }
        Ok(None) => absent(),
        Err(e) => {
            warn!(%e, "growth read key: lookup failed");
            (StatusCode::SERVICE_UNAVAILABLE, "try again").into_response()
        }
    }
}

/// Who is reading a growth view.
#[derive(Debug, Clone)]
pub enum GrowthAuth {
    /// A platform admin's session, on a server whose growth surface is on.
    Admin(AuthUser),
    /// A live read key, on a GET of a data route (the gate decided).
    ReadKey(ReadKeyAuth),
}

impl GrowthAuth {
    pub fn is_key(&self) -> bool {
        matches!(self, GrowthAuth::ReadKey(_))
    }
}

impl<S> FromRequestParts<S> for GrowthAuth
where
    Core: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Only the gate inserts this, and only for a live read key on a GET
        // of a data route with the surface on: nothing a client sends can.
        if let Some(k) = parts.extensions.get::<ReadKeyAuth>() {
            return Ok(GrowthAuth::ReadKey(k.clone()));
        }
        let core = Core::from_ref(state);
        let auth = AuthUser::from_request_parts(parts, state).await?;
        // The platform-admin gate first, then the kill switch: both 404,
        // the same answer `require_growth_admin` gives a write route.
        require_platform_admin(&core, &auth)?;
        if !core.settings.growth.enabled {
            return Err(ApiError::NotFound("Not found".to_string()));
        }
        Ok(GrowthAuth::Admin(auth))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read key opens a GET of a data route and nothing else; an ingest
    /// key opens no growth view at all.
    #[test]
    fn a_read_key_opens_gets_of_data_routes_only() {
        let read = GrowthKeyKind::Read;
        for path in [
            "/digest",
            "/digests",
            "/digest/preview",
            "/funnel",
            "/cohorts",
            "/orgs",
            "/org/0123456789abcdef01234567/timeline",
            "/campaigns",
            "/channels",
            "/content",
            "/newsletter",
            "/revenue",
            "/weekly",
            "/weeklies",
            "/alerts",
        ] {
            assert!(key_opens(read, &Method::GET, path), "{path}");
            for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
                assert!(!key_opens(read, &m, path), "{m} {path}");
            }
            assert!(
                !key_opens(GrowthKeyKind::Ingest, &Method::GET, path),
                "{path}"
            );
        }
        // The admin surface: session-only, GET included.
        for path in [
            "/keys",
            "/keys/0123456789abcdef01234567",
            "/exclusions",
            "/exclusions/",
        ] {
            assert!(session_only(path), "{path}");
            assert!(!key_opens(read, &Method::GET, path), "{path}");
        }
        // A data route whose name merely starts like one is not.
        assert!(!session_only("/keysets"));
        assert!(!session_only("/exclusionsx"));
        assert!(key_opens(read, &Method::GET, "/keysets"));
    }

    #[test]
    fn the_bearer_is_read_trimmed_and_only_as_a_bearer() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer(&h), None);
        h.insert(header::AUTHORIZATION, "Bearer  rgr_abc ".parse().unwrap());
        assert_eq!(bearer(&h).as_deref(), Some("rgr_abc"));
        h.insert(header::AUTHORIZATION, "Basic rgr_abc".parse().unwrap());
        assert_eq!(bearer(&h), None);
        h.insert(header::AUTHORIZATION, "bearer rgr_abc".parse().unwrap());
        assert_eq!(
            bearer(&h),
            None,
            "the scheme is case-sensitive here, as the ingest gate's"
        );
    }
}
