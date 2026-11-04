// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `GET /api/user/unread-summary` — the caller's unread state across every
//! org they belong to, in one call.
//!
//! FR-69 P3 — moved from the api crate's `routes/user.rs` unchanged: it
//! counts messages and rooms, which are chat's.

use axum::{Json, extract::State};
use bson::oid::ObjectId;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use serde::Serialize;

use crate::ChatState;

#[derive(Debug, Serialize)]
pub struct TenantUnreadSummary {
    pub tenant_id: String,
    pub name: String,
    /// Unread chat messages across the caller's rooms in this tenant.
    pub unread_messages: u64,
    /// How many of those rooms have ≥1 unread message.
    pub unread_rooms: u64,
    /// Unread bell notifications scoped to this tenant…
    pub notifications: u64,
    /// …of which mentions…
    pub mentions: u64,
    /// …and pending remote-control consent requests.
    pub consents: u64,
}

/// P4 — GET /api/user/unread-summary: the caller's unread state across
/// EVERY org they belong to, in one call. The org switcher's badge seed +
/// the `ws:reconnected` convergence fetch (there is no event replay — a
/// reconnecting client refetches instead). Rows come back for all
/// memberships, zeros included, so the client can render the full switcher
/// without merging.
pub async fn unread_summary(
    State(state): State<ChatState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenants = state.tenants.find_user_tenants(auth.user_id).await?;
    let notif_by_tenant = state.notifications.unread_by_tenant(auth.user_id).await?;

    let mut out: Vec<TenantUnreadSummary> = Vec::with_capacity(tenants.len());
    for t in tenants {
        let Some(tid) = t.id else { continue };
        let rooms = state.rooms.find_user_rooms(tid, auth.user_id).await?;
        let room_ids: Vec<ObjectId> = rooms.iter().filter_map(|r| r.id).collect();
        let (mut unread_messages, mut unread_rooms) = (0u64, 0u64);
        if !room_ids.is_empty() {
            for (_, count) in state
                .messages
                .unread_counts_by_room(&room_ids, auth.user_id)
                .await?
            {
                if count > 0 {
                    unread_rooms += 1;
                    unread_messages += count;
                }
            }
        }
        let notif = notif_by_tenant.iter().find(|n| n.tenant_id == tid);
        out.push(TenantUnreadSummary {
            tenant_id: tid.to_hex(),
            name: t.name,
            unread_messages,
            unread_rooms,
            notifications: notif.map(|n| n.total).unwrap_or(0),
            mentions: notif.map(|n| n.mentions).unwrap_or(0),
            consents: notif.map(|n| n.consents).unwrap_or(0),
        });
    }

    Ok(Json(serde_json::json!({ "tenants": out })))
}
