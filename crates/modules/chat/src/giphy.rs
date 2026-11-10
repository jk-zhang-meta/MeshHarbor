// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::ChatState;

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Deserialize)]
pub struct TrendingQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    25
}

pub async fn search(
    State(state): State<ChatState>,
    _auth: AuthUser,
    Query(params): Query<SearchQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let giphy = state
        .giphy
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Giphy not configured".to_string()))?;

    let result = giphy
        .search(&params.q, params.limit, params.offset)
        .await
        .map_err(|e| ApiError::Internal(format!("Giphy API error: {e}")))?;

    Ok(Json(serde_json::to_value(result).unwrap()))
}

pub async fn trending(
    State(state): State<ChatState>,
    _auth: AuthUser,
    Query(params): Query<TrendingQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let giphy = state
        .giphy
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Giphy not configured".to_string()))?;

    let result = giphy
        .trending(params.limit, params.offset)
        .await
        .map_err(|e| ApiError::Internal(format!("Giphy API error: {e}")))?;

    Ok(Json(serde_json::to_value(result).unwrap()))
}
