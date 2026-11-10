// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-51 P2 — ephemeral enrollment keys: mint / list / revoke, plus the org
//! switch that gates the whole credential class.
//!
//! A key is a REUSABLE secret that mints device identities, so the §4
//! controls are enforced here as all-four-or-none: ceiling + expiry are
//! clamped at mint, revocation is a route, and the per-use audit rides the
//! enroll path. The org switch (`ephemeral_keys_enabled`, default off) is
//! `MANAGE_TENANT` like the exec/SSH org switches — deciding whether this
//! credential class exists at all is an org-owner decision — while minting
//! and revoking individual keys is fleet administration (`MANAGE_AGENTS`,
//! the same bit the single-use enroll-token mint requires).

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_db::models::role::permissions;
use serde::{Deserialize, Serialize};
use tracing::warn;

use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};

use crate::FleetState;

/// Ceiling clamps, stated once. The defaults serve the motivating CI case
/// (one key in a secret store, replicas coming and going); the caps keep a
/// fat-fingered mint from being a decade-long credential.
const MAX_USES_DEFAULT: i64 = 100;
const MAX_USES_CAP: i64 = 10_000;
const EXPIRY_DEFAULT_SECS: i64 = 30 * 86_400;
const EXPIRY_MIN_SECS: i64 = 300;
const EXPIRY_CAP_SECS: i64 = 90 * 86_400;
/// Write-time convenience clamp on the per-device reap TTL; the reaper's own
/// read-time floor stays the safety boundary.
const DEVICE_TTL_MIN_SECS: u64 = 60;
const DEVICE_TTL_CAP_SECS: u64 = 7 * 86_400;

fn tenant_of(tenant_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(tenant_id).map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))
}

// ────────────────────────────────────────────────────────────────────────────
// Org switch
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgEphemeralKeySettings {
    pub ephemeral_keys_enabled: bool,
}

/// `GET /api/tenant/{tid}/ephemeral-key-settings`
pub async fn get_org_settings(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<OrgEphemeralKeySettings>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    let tenant = state.tenants.base.find_by_id(tid).await?;
    Ok(Json(OrgEphemeralKeySettings {
        ephemeral_keys_enabled: tenant.settings.ephemeral_keys_enabled,
    }))
}

/// `PUT /api/tenant/{tid}/ephemeral-key-settings` — flip the class switch.
/// Off is an org-wide revocation that burns nothing: the gate is re-checked
/// on every key USE, ahead of the key's own claim.
pub async fn set_org_settings(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<OrgEphemeralKeySettings>,
) -> Result<Json<OrgEphemeralKeySettings>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    let tenant = state
        .tenants
        .set_ephemeral_keys_enabled(tid, body.ephemeral_keys_enabled)
        .await?;
    warn!(
        tenant = %tenant_id, admin = %auth.user_id,
        enabled = body.ephemeral_keys_enabled,
        "fr-51: ephemeral-key org switch changed"
    );
    Ok(Json(OrgEphemeralKeySettings {
        ephemeral_keys_enabled: tenant.settings.ephemeral_keys_enabled,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// Mint / list / revoke
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct MintKeyRequest {
    /// Display label ("ci-runners"). Optional.
    #[serde(default)]
    pub label: Option<String>,
    /// Use ceiling; clamped to `1..=10_000`, default 100.
    #[serde(default)]
    pub max_uses: Option<i64>,
    /// Lifetime from now; clamped to `300..=90 d`, default 30 d.
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
    /// Per-device reap TTL the key stamps on what it mints; clamped to
    /// `60..=7 d`. Absent = the server default at reap time.
    #[serde(default)]
    pub ephemeral_ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct MintKeyResponse {
    /// The key itself — a signed JWT, shown ONCE. It is not stored and
    /// cannot be listed back; losing it means minting a new key.
    pub key: String,
    pub id: String,
    pub jti: String,
    pub label: String,
    pub max_uses: i64,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_ttl_secs: Option<u64>,
}

/// `POST /api/tenant/{tid}/agent/enroll-key` — mint a reusable ephemeral key.
pub async fn mint_key(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<MintKeyRequest>,
) -> Result<Json<MintKeyResponse>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;

    // Gate 1: the class switch. Checked at mint so an admin learns NOW
    // rather than when the first runner fails to come up.
    let tenant = state.tenants.base.find_by_id(tid).await?;
    if !tenant.settings.ephemeral_keys_enabled {
        return Err(ApiError::Forbidden(
            "Ephemeral enrollment keys are disabled for this organization \
             (Settings → enable ephemeral keys first)"
                .to_string(),
        ));
    }

    let max_uses = body
        .max_uses
        .unwrap_or(MAX_USES_DEFAULT)
        .clamp(1, MAX_USES_CAP);
    let expires_in = body
        .expires_in_secs
        .unwrap_or(EXPIRY_DEFAULT_SECS)
        .clamp(EXPIRY_MIN_SECS, EXPIRY_CAP_SECS);
    let ttl = body
        .ephemeral_ttl_secs
        .map(|t| t.clamp(DEVICE_TTL_MIN_SECS, DEVICE_TTL_CAP_SECS));
    let label = body.label.unwrap_or_default();
    let expires_at = DateTime::from_millis(DateTime::now().timestamp_millis() + expires_in * 1000);

    // Row first, token second: a row whose token was never issued is inert
    // (nothing can claim it), whereas the reverse order could hand out a
    // signed credential with no row behind it — unusable, but confusing.
    let jti = uuid::Uuid::new_v4().simple().to_string();
    let key_row = state
        .enrollment_keys
        .create(
            tid,
            jti.clone(),
            label,
            auth.user_id,
            max_uses,
            expires_at,
            ttl,
        )
        .await?;
    let key_id = key_row
        .id
        .ok_or_else(|| ApiError::Internal("enrollment key missing _id".into()))?;

    let token = state
        .auth
        .issue_ephemeral_enroll_key_token(
            auth.user_id,
            tid,
            &jti,
            expires_at.timestamp_millis() / 1000,
        )
        .map_err(ApiError::from)?;

    warn!(
        tenant = %tenant_id, admin = %auth.user_id, key = %key_id, max_uses,
        expires_at = %expires_at, "fr-51: ephemeral enrollment key minted"
    );
    Ok(Json(MintKeyResponse {
        key: token,
        id: key_id.to_hex(),
        jti: key_row.jti,
        label: key_row.label,
        max_uses: key_row.max_uses,
        expires_at: key_row
            .expires_at
            .try_to_rfc3339_string()
            .unwrap_or_default(),
        ephemeral_ttl_secs: key_row.ephemeral_ttl_secs,
    }))
}

#[derive(Debug, Serialize)]
pub struct KeyRow {
    pub id: String,
    pub jti: String,
    pub label: String,
    pub created_by: String,
    pub max_uses: i64,
    pub uses: i64,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    pub created_at: String,
}

/// `GET /api/tenant/{tid}/agent/enroll-key` — the operator's key list. The
/// key SECRET is not here and cannot be: only mint ever returns it.
pub async fn list_keys(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let rows = state.enrollment_keys.list_for_tenant(tid).await?;
    let fmt = |d: DateTime| d.try_to_rfc3339_string().unwrap_or_default();
    let items: Vec<KeyRow> = rows
        .into_iter()
        .map(|k| KeyRow {
            id: k.id.map(|i| i.to_hex()).unwrap_or_default(),
            jti: k.jti,
            label: k.label,
            created_by: k.created_by.to_hex(),
            max_uses: k.max_uses,
            uses: k.uses,
            expires_at: fmt(k.expires_at),
            revoked_at: k.revoked_at.map(fmt),
            ephemeral_ttl_secs: k.ephemeral_ttl_secs,
            last_used_at: k.last_used_at.map(fmt),
            created_at: fmt(k.created_at),
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

/// `DELETE /api/tenant/{tid}/agent/enroll-key/{key_id}` — revoke. Takes
/// effect on the very next use (the claim filter carries `revoked_at: null`);
/// devices the key already minted are untouched — they die by their own TTL.
pub async fn revoke_key(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, key_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    let kid =
        ObjectId::parse_str(&key_id).map_err(|_| ApiError::BadRequest("Invalid key id".into()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let revoked = state.enrollment_keys.revoke(tid, kid).await?;
    if revoked {
        warn!(tenant = %tenant_id, admin = %auth.user_id, key = %key_id,
            "fr-51: ephemeral enrollment key revoked");
    }
    Ok(Json(serde_json::json!({ "revoked": revoked })))
}

/// `GET /api/tenant/{tid}/agent/enroll-key/{key_id}/uses` — control 4 made
/// readable: every device this key minted, surviving the devices themselves.
pub async fn list_key_uses(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, key_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    let kid =
        ObjectId::parse_str(&key_id).map_err(|_| ApiError::BadRequest("Invalid key id".into()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let rows = state.enrollment_keys.list_uses(tid, kid).await?;
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|u| {
            serde_json::json!({
                "agent_id": u.agent_id.to_hex(),
                "machine_id": u.machine_id,
                "machine_name": u.machine_name,
                "created_at": u.created_at.try_to_rfc3339_string().unwrap_or_default(),
                // P4 — the whole lifecycle on one row: null = still alive
                // (or removed before P4 shipped; the row cannot tell).
                "removed_at": u.removed_at.map(|d| d.try_to_rfc3339_string().unwrap_or_default()),
                "removal": u.removal,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}
