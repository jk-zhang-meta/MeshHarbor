// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D5a — the agent-JWT extractor for the HOST's routes.
//!
//! The fleet module's [`meshharbor_mod_fleet::auth_agent::AuthAgent`] is the
//! one place an agent token turns into an authorization decision, and it is
//! an extractor so a handler cannot forget the check. Its bound is
//! `FleetState: FromRef<S>`, which the host's `AppState` cannot satisfy: the
//! fleet module is an `Option` there (`[modules] fleet = false` unmounts it,
//! never a boot refusal), and a `FromRef` that panics on `None` would turn a
//! deliberate unmount into a 500.
//!
//! So the host has its own extractor over the SAME decision — the shared
//! [`authenticate`] — and adds exactly one rule of its own: no fleet module
//! ⇒ 503, the answer every other fleet-dependent surface gives when the
//! module is switched off, so an agent dialling a pod without it learns it is
//! not a credential problem.

use axum::{extract::FromRequestParts, http::request::Parts};
use meshharbor_core::ApiError;
use meshharbor_mod_fleet::auth_agent::{AuthAgent, authenticate};

use crate::state::AppState;

/// An agent that authenticated with its own JWT and still has a row we
/// accept — on a host route. Derefs to the fleet's [`AuthAgent`].
#[derive(Debug, Clone)]
pub struct HostAuthAgent(pub AuthAgent);

impl std::ops::Deref for HostAuthAgent {
    type Target = AuthAgent;

    fn deref(&self) -> &AuthAgent {
        &self.0
    }
}

impl FromRequestParts<AppState> for HostAuthAgent {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(fleet) = state.modules.fleet.as_ref() else {
            return Err(ApiError::ServiceUnavailable(
                "the fleet module is not mounted on this server".to_string(),
            ));
        };
        authenticate(fleet, &parts.headers).await.map(HostAuthAgent)
    }
}
