// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P8 — the growth surface's machine keys (D12):
//!
//! * `GET /api/admin/growth/keys` — every key: kind, label, the display
//!   prefix, who minted it and when, last use, revoked — never the key or
//!   its hash;
//! * `POST /api/admin/growth/keys` `{kind: "ingest" | "read", label}` —
//!   mint one; the key itself is in THIS answer and nowhere else, ever
//!   (only its SHA-256 is stored);
//! * `DELETE /api/admin/growth/keys/{key_id}` — revoke (idempotent).
//!
//! Platform admins only — a SESSION, never a key: these three routes are
//! the one place a read key is refused on a GET too (`read_key.rs`), so a
//! leaked key cannot list the other keys' prefixes or mint itself a
//! sibling. 404 otherwise and when `growth.enabled = false` — the same
//! gate as every growth route. The keys live in core (`growth_keys`): an
//! `ingest` key opens the `saas` module's ingest routes and nothing else,
//! so `ingest_mounted` says whether this server has them; a `read` key
//! (P10) opens the growth views' GET routes and nothing else.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_services::dao::growth_key::{GrowthKey, GrowthKeyDao, GrowthKeyKind, MAX_LABEL_LEN};
use serde::Serialize;
use tracing::info;

use super::mounted;
use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

/// The most live keys of one kind: a ceiling that makes a leak-and-remint
/// loop visible, not a quota anyone should meet.
pub const MAX_LIVE_KEYS: u64 = 10;

#[derive(Debug, Serialize, PartialEq)]
pub struct KeyRow {
    pub id: String,
    pub kind: GrowthKeyKind,
    pub label: String,
    /// The key's first characters (`rgi_AbCd1234`) — to recognise it.
    pub prefix: String,
    pub created_by: String,
    /// RFC 3339.
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    pub live: bool,
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

impl KeyRow {
    pub fn of(k: &GrowthKey) -> Self {
        Self {
            id: k.id.to_hex(),
            kind: k.kind,
            label: k.label.clone(),
            prefix: k.prefix.clone(),
            created_by: k.created_by.to_hex(),
            created_at: rfc3339(k.created_at),
            last_used_at: k.last_used_at.map(rfc3339),
            revoked_at: k.revoked_at.map(rfc3339),
            live: k.live(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct KeysResponse {
    pub enabled: bool,
    /// Whether this server mounts the ingest routes an `ingest` key opens
    /// (the `saas` module).
    pub ingest_mounted: bool,
    pub keys: Vec<KeyRow>,
}

/// `GET /api/admin/growth/keys`
pub async fn list_keys(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<KeysResponse>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let keys = GrowthKeyDao::new(&state.db).list().await?;
    Ok(Json(KeysResponse {
        enabled: true,
        ingest_mounted: mounted(&state, "saas"),
        keys: keys.iter().map(KeyRow::of).collect(),
    }))
}

/// A mint request, validated: the kind, and a label of 1–80 printable
/// characters.
pub fn mint_request(v: &serde_json::Value) -> Result<(GrowthKeyKind, String), String> {
    let kind = v
        .get("kind")
        .and_then(|k| k.as_str())
        .and_then(GrowthKeyKind::parse)
        .ok_or_else(|| {
            format!(
                "kind must be one of {}",
                GrowthKeyKind::ALL
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let label = v
        .get("label")
        .and_then(|l| l.as_str())
        .map(str::trim)
        .unwrap_or_default();
    if label.is_empty()
        || label.chars().count() > MAX_LABEL_LEN
        || label.chars().any(|c| c.is_control())
    {
        return Err(format!(
            "label must be 1–{MAX_LABEL_LEN} printable characters"
        ));
    }
    Ok((kind, label.to_string()))
}

#[derive(Debug, Serialize)]
pub struct Minted {
    #[serde(flatten)]
    pub row: KeyRow,
    /// The key itself — shown once, stored nowhere.
    pub key: String,
}

/// `POST /api/admin/growth/keys` `{kind, label}` — 201 with the key once.
/// The body is parsed after the gate, so a non-admin learns nothing from
/// it, malformed or not.
pub async fn mint_key(
    State(state): State<AppState>,
    auth: AuthUser,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Minted>), ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let body: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("the body must be JSON".into()))?;
    let (kind, label) = mint_request(&body).map_err(ApiError::BadRequest)?;
    let dao = GrowthKeyDao::new(&state.db);
    if dao.count_live(kind).await? >= MAX_LIVE_KEYS {
        return Err(ApiError::Conflict(format!(
            "{MAX_LIVE_KEYS} live {} keys already — revoke one first",
            kind.as_str()
        )));
    }
    let (key, raw) = dao
        .mint(kind, &label, auth.user_id, DateTime::now())
        .await?;
    info!(
        admin = %auth.user_id, key_id = %key.id, prefix = %key.prefix, kind = kind.as_str(),
        "growth key minted"
    );
    Ok((
        StatusCode::CREATED,
        Json(Minted {
            row: KeyRow::of(&key),
            key: raw,
        }),
    ))
}

/// `DELETE /api/admin/growth/keys/{key_id}` — 204, also for a key already
/// revoked; 404 for an id no key has.
pub async fn revoke_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(key_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let id =
        ObjectId::parse_str(key_id.trim()).map_err(|_| ApiError::NotFound("no such key".into()))?;
    match GrowthKeyDao::new(&state.db)
        .revoke(id, DateTime::now())
        .await?
    {
        None => Err(ApiError::NotFound("no such key".into())),
        Some(revoked_now) => {
            if revoked_now {
                info!(admin = %auth.user_id, key_id = %id, "growth key revoked");
            }
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_mint_request_names_a_known_kind_and_a_bounded_label() {
        assert_eq!(
            mint_request(&json!({ "kind": "ingest", "label": " promotion pipeline " })).unwrap(),
            (GrowthKeyKind::Ingest, "promotion pipeline".to_string())
        );
        // P10 — the read kind mints too.
        assert_eq!(
            mint_request(&json!({ "kind": "read", "label": "promotion pipeline (read)" })).unwrap(),
            (GrowthKeyKind::Read, "promotion pipeline (read)".to_string())
        );
        for bad in [
            json!({ "kind": "write", "label": "x" }),
            json!({ "kind": "Read", "label": "x" }),
            json!({ "kind": "Ingest", "label": "x" }),
            json!({ "label": "x" }),
            json!({ "kind": "ingest" }),
            json!({ "kind": "ingest", "label": "   " }),
            json!({ "kind": "ingest", "label": "a\nb" }),
            json!({ "kind": "ingest", "label": "x".repeat(MAX_LABEL_LEN + 1) }),
            json!([1]),
        ] {
            assert!(mint_request(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_listed_key_carries_neither_the_key_nor_its_hash() {
        let k = GrowthKey {
            id: ObjectId::new(),
            kind: GrowthKeyKind::Ingest,
            label: "pipeline".into(),
            prefix: "rgi_AbCd1234".into(),
            hash: "f".repeat(64),
            created_by: ObjectId::new(),
            created_at: DateTime::now(),
            revoked_at: None,
            last_used_at: None,
        };
        let json = serde_json::to_value(KeyRow::of(&k)).unwrap();
        assert!(json.get("hash").is_none());
        assert!(!json.to_string().contains(&"f".repeat(64)));
        assert_eq!(json["prefix"], "rgi_AbCd1234");
        assert_eq!(json["kind"], "ingest");
        assert_eq!(json["live"], true);
    }
}
