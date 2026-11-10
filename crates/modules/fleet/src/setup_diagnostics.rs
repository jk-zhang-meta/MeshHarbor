// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P3b — `POST /api/setup/diagnostics`: the setup wizard's opt-in
//! step diagnostics (spec §3e item 5, `docs/growth-observability.md`).
//!
//! The route is **unauthenticated by necessity** — a wizard has no
//! credential until its enroll succeeds, and most of what this is for
//! happens before that — so it trusts nothing: the body is capped at
//! [`MAX_BODY_BYTES`] by the route's layer, parsed as exactly the one record
//! shape (an unknown key fails the parse), and every field is checked
//! against its vocabulary or format
//! ([`SetupDiagnostic::validate`]); anything else is a 422 with a code and
//! nothing stored. A run can hold at most
//! [`meshharbor_services::dao::setup_diagnostics::MAX_ROWS_PER_RUN`] rows.
//!
//! What is stored is the record plus the server's clock. The handler takes
//! the body and nothing else about the request — no `HeaderMap`, no
//! `ConnectInfo` — so an address or a User-Agent cannot reach the row by
//! construction, and a refusal is logged by its code, never with the body.
//!
//! `growth.setup_diagnostics = false` is the kill switch: the route answers
//! the empty 404 of a path that does not exist, the same answer the growth
//! read key meets on a route it may not open. The wizard treats any
//! failure silently, so an operator who switches this off hears nothing
//! from their wizards and stores nothing from them.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bson::DateTime;
use meshharbor_services::dao::setup_diagnostics::Recorded;
use serde::Serialize;
use tracing::{debug, warn};

use crate::FleetState;

pub use meshharbor_remote_control::setup_diagnostics::{MAX_BODY_BYTES, SetupDiagnostic};

/// A refused record: a stable code for the wizard's log, never the value
/// that was refused.
#[derive(Debug, Serialize)]
struct Refusal {
    error: &'static str,
}

fn refuse(status: StatusCode, error: &'static str) -> Response {
    debug!(code = error, "setup diagnostics: refused");
    (status, Json(Refusal { error })).into_response()
}

/// `POST /api/setup/diagnostics` — 202 and nothing in the body on a stored
/// record; 422 `{error}` on a refused one; 429 `run_capped` once a run is
/// at its cap; 503 when the database did not answer (a wizard never
/// retries, so this is only what the log says); the empty 404 when the
/// switch is off.
pub async fn ingest(State(state): State<FleetState>, body: Bytes) -> Response {
    if !state.settings.growth.setup_diagnostics {
        return StatusCode::NOT_FOUND.into_response();
    }
    let d: SetupDiagnostic = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(_) => return refuse(StatusCode::UNPROCESSABLE_ENTITY, "invalid_json"),
    };
    if let Err(code) = d.validate() {
        return refuse(StatusCode::UNPROCESSABLE_ENTITY, code);
    }
    match state.setup_diagnostics.record(&d, DateTime::now()).await {
        Ok(Recorded::Stored) => {
            debug!(
                step = %d.step, outcome = %d.outcome, os = %d.os, wizard_version = %d.wizard_version,
                "setup diagnostics: stored"
            );
            StatusCode::ACCEPTED.into_response()
        }
        Ok(Recorded::RunCapped) => refuse(StatusCode::TOO_MANY_REQUESTS, "run_capped"),
        Err(e) => {
            warn!(error = %e, "setup diagnostics: write failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(Refusal {
                    error: "unavailable",
                }),
            )
                .into_response()
        }
    }
}
