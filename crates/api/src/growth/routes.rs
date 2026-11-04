// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1d — the digest's routes, under `/api/admin/growth` (platform
//! admins; 404 otherwise and when `growth.enabled = false`):
//!
//! * `GET /digest?day=` — a stored day (the latest when `day` is omitted);
//! * `GET /digests?since=&limit=` — the list: day, status, times, headline;
//! * `POST /digest/run?day=&send=false` — recompute and overwrite a day's
//!   sections; mail only with `send=true` AND a day not already `sent`;
//! * `GET /digest/preview?day=&include_internal=` — compute live, store
//!   nothing, mail nothing; `include_internal=true` is the raw totals (AC4).
//!
//! A day is `YYYY-MM-DD` and must be CLOSED: strictly before today (UTC).

use axum::{
    Json,
    extract::{Query, State},
};
use bson::DateTime;
use chrono::NaiveDate;
use meshharbor_services::dao::growth_digest::{DigestStatus, DigestStore, ExcludedCounts};
use meshharbor_core::growth::ExclusionSet;
use serde::{Deserialize, Serialize};

use super::{
    digest::{self, DigestJson, DigestMailer},
    read_key::GrowthAuth,
};
use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

const DEFAULT_LIST_LIMIT: i64 = 30;
const MAX_LIST_LIMIT: i64 = 100;

/// `day`, parsed; defaulting to yesterday (UTC); refused unless closed.
fn closed_day(raw: Option<&str>, now: DateTime) -> Result<NaiveDate, ApiError> {
    let today = digest::utc_date_of(now);
    let day = match raw {
        Some(s) => digest::parse_day(s).map_err(ApiError::BadRequest)?,
        None => today
            .pred_opt()
            .ok_or_else(|| ApiError::BadRequest("no yesterday".into()))?,
    };
    if day >= today {
        return Err(ApiError::BadRequest(format!(
            "day must be a closed UTC day (before {})",
            digest::day_str(today)
        )));
    }
    Ok(day)
}

#[derive(Debug, Deserialize)]
pub struct DayQuery {
    #[serde(default)]
    pub day: Option<String>,
}

/// `GET /api/admin/growth/digest?day=` — a platform admin, or a read key
/// (P10: `GrowthAuth` is the gate).
pub async fn get_digest(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<DayQuery>,
) -> Result<Json<DigestJson>, ApiError> {
    let store = DigestStore::new(&state.db);
    let found = match q.day.as_deref() {
        Some(raw) => {
            let day = digest::parse_day(raw).map_err(ApiError::BadRequest)?;
            store.get(&digest::day_str(day)).await?
        }
        None => store.latest().await?,
    };
    let doc = found.ok_or_else(|| ApiError::NotFound("no digest for that day".into()))?;
    Ok(Json(DigestJson::of(&doc)))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DigestListRow {
    pub day: String,
    pub status: DigestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    pub attempts: u32,
    pub recipients: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub excluded: ExcludedCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headline: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct DigestListResponse {
    pub enabled: bool,
    pub digests: Vec<DigestListRow>,
}

/// `GET /api/admin/growth/digests?since=&limit=`
pub async fn list_digests(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<ListQuery>,
) -> Result<Json<DigestListResponse>, ApiError> {
    let since = match q.since.as_deref() {
        Some(s) => Some(digest::day_str(
            digest::parse_day(s).map_err(ApiError::BadRequest)?,
        )),
        None => None,
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let rows = DigestStore::new(&state.db)
        .list(since.as_deref(), limit)
        .await?;
    let digests = rows
        .iter()
        .map(|d| DigestListRow {
            day: d.day.clone(),
            status: d.status,
            computed_at: d
                .computed_at
                .map(|t| t.try_to_rfc3339_string().unwrap_or_default()),
            sent_at: d
                .sent_at
                .map(|t| t.try_to_rfc3339_string().unwrap_or_default()),
            attempts: d.attempts,
            recipients: d.recipients,
            error: d.error.clone(),
            excluded: d.excluded,
            headline: d
                .sections
                .as_ref()
                .and_then(|s| s.get_document("headline").ok())
                .and_then(|h| serde_json::to_value(h).ok()),
        })
        .collect();
    Ok(Json(DigestListResponse {
        enabled: true,
        digests,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RunQuery {
    #[serde(default)]
    pub day: Option<String>,
    #[serde(default)]
    pub send: bool,
}

/// `POST /api/admin/growth/digest/run?day=&send=false`
pub async fn run_digest(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<RunQuery>,
) -> Result<Json<DigestJson>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let now = DateTime::now();
    let day = closed_day(q.day.as_deref(), now)?;
    let mailer = digest::service_mailer(&state);
    let mailer_ref: Option<&dyn DigestMailer> = mailer.as_ref().map(|m| m as &dyn DigestMailer);
    digest::run_manual(&state, day, q.send, mailer_ref, now).await?;
    let doc = DigestStore::new(&state.db)
        .get(&digest::day_str(day))
        .await?
        .ok_or_else(|| ApiError::Internal("the digest vanished after its run".into()))?;
    Ok(Json(DigestJson::of(&doc)))
}

#[derive(Debug, Deserialize)]
pub struct PreviewQuery {
    #[serde(default)]
    pub day: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

#[derive(Debug, Serialize)]
pub struct PreviewJson {
    pub day: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub sections: serde_json::Value,
}

/// `GET /api/admin/growth/digest/preview?day=&include_internal=`
pub async fn preview_digest(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<PreviewQuery>,
) -> Result<Json<PreviewJson>, ApiError> {
    let now = DateTime::now();
    let day = closed_day(q.day.as_deref(), now)?;
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    let sections = digest::compute(&state, day, &set, now).await?;
    let (users, tenants) = set.counts();
    Ok(Json(PreviewJson {
        day: digest::day_str(day),
        include_internal: q.include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        sections: serde_json::to_value(sections)
            .map_err(|e| ApiError::Internal(format!("sections did not serialise: {e}")))?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_day_must_be_closed() {
        let now = DateTime::parse_rfc3339_str("2026-10-14T10:00:00Z").unwrap();
        assert_eq!(
            closed_day(None, now).unwrap(),
            digest::parse_day("2026-10-13").unwrap()
        );
        assert!(closed_day(Some("2026-10-01"), now).is_ok());
        for bad in ["2026-10-14", "2026-10-15", "2027-01-01", "yesterday"] {
            assert!(
                matches!(closed_day(Some(bad), now), Err(ApiError::BadRequest(_))),
                "{bad}"
            );
        }
    }
}
