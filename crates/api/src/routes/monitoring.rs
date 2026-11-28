// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! 0.5.0 — Unified SSH & Remote Control Monitoring API (`/api/tenant/{tenant_id}/monitoring/*`).
//!
//! Replaces passive-only audit views with an operator monitoring console modeled
//! on GhostDesk (`监控中` live view + `监控历史` history view):
//! - Shows ALL live RC sessions and live SSH sessions (classic overlay,
//!   persistent PTY, key-list, and device-shared SSH).
//! - Attributes BOTH parties (initiator/controller AND target/controlled device)
//!   with their owning account, member invitation, device invitation, or
//!   device-share grant — deliberately omitting hardware serial numbers.
//! - Allows authorized admins to actively disconnect ANY active RC or SSH
//!   session (classic + persistent + shared), and to silently watch & take over
//!   active RC sessions.

use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::{
    DeviceShareGrant, TenantMember, User, role::permissions,
};
use meshharbor_mod_fleet::device_invite::{self, DeviceInviteRow};
use meshharbor_remote_control::models::{Agent, EndReason, SessionPhase};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

// ────────────────────────────────────────────────────────────────────────────
// Permissions & wire shapes
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize)]
pub struct MonitoringCapabilities {
    pub can_see_remote: bool,
    pub can_see_ssh: bool,
    pub can_disconnect_remote: bool,
    pub can_disconnect_ssh: bool,
    pub can_watch_takeover: bool,
}

async fn resolve_capabilities(
    state: &AppState,
    tenant_id: ObjectId,
    user_id: ObjectId,
) -> Result<MonitoringCapabilities, ApiError> {
    if !state.tenants.is_member(tenant_id, user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let perms = state
        .tenants
        .get_member_permissions(tenant_id, user_id)
        .await?;
    let is_admin = permissions::has(perms, permissions::ADMINISTRATOR);
    let can_see_remote = permissions::has(perms, permissions::VIEW_REMOTE_AUDIT);
    let can_see_ssh = permissions::has(perms, permissions::VIEW_SSH_AUDIT);
    if !can_see_remote && !can_see_ssh {
        return Err(ApiError::Forbidden(
            "Requires VIEW_REMOTE_AUDIT or VIEW_SSH_AUDIT permission".into(),
        ));
    }
    let can_disconnect_remote =
        is_admin || (can_see_remote && permissions::has(perms, permissions::REMOTE_CONTROL));
    let can_disconnect_ssh =
        is_admin || (can_see_ssh && permissions::has(perms, permissions::MANAGE_AGENTS));
    let can_watch_takeover = can_disconnect_remote;
    Ok(MonitoringCapabilities {
        can_see_remote,
        can_see_ssh,
        can_disconnect_remote,
        can_disconnect_ssh,
        can_watch_takeover,
    })
}

/// Dual-party attribution (account, invite, or device share) — no serial numbers.
#[derive(Debug, Clone, Serialize)]
pub struct PartyAttribution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_username: Option<String>,
    /// `"account"` | `"member_invite"` | `"device_invite"` | `"device_share"` | `"external"` | `"key_list"`
    pub attribution_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_or_share_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_or_owner_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_or_share_id: Option<String>,
}

impl PartyAttribution {
    fn searchable_text(&self) -> String {
        let mut parts = Vec::with_capacity(6);
        if let Some(v) = &self.device_name {
            parts.push(v.as_str());
        }
        if let Some(v) = &self.account_name {
            parts.push(v.as_str());
        }
        if let Some(v) = &self.account_username {
            parts.push(v.as_str());
        }
        if let Some(v) = &self.invite_or_share_label {
            parts.push(v.as_str());
        }
        if let Some(v) = &self.inviter_or_owner_name {
            parts.push(v.as_str());
        }
        parts.join(" ")
    }
}

#[derive(Debug, Serialize)]
pub struct LiveSessionStatsView {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub avg_rtt_ms: f32,
    pub peak_fps: f32,
    pub input_events: u64,
}

#[derive(Debug, Serialize)]
pub struct LiveMonitoringItem {
    /// `"remote"` | `"ssh"`
    pub kind: &'static str,
    /// Session identifier (`session_id` hex for RC; `grant_id` or synthetic key for SSH).
    pub id: String,
    pub agent_id: String,
    pub phase: String,
    pub started_at: String,
    pub started_at_ms: i64,
    pub duration_secs: u64,
    pub initiator: PartyAttribution,
    pub target: PartyAttribution,
    /// Protocol/source detail (`"webrtc"` / `"cli"` / `"api"` / `"device_share"` / `"key_list"`).
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resume_allowed: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admin_watching: bool,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub admin_watcher_count: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admin_taken_over: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<LiveSessionStatsView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_count: Option<u64>,
    pub can_disconnect: bool,
    pub can_watch_takeover: bool,
}

fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

#[derive(Debug, Serialize)]
pub struct LiveMonitoringCounts {
    pub total: usize,
    pub remote: usize,
    pub ssh: usize,
}

#[derive(Debug, Serialize)]
pub struct LiveMonitoringResponse {
    pub server_time_ms: i64,
    pub counts: LiveMonitoringCounts,
    pub capabilities: MonitoringCapabilities,
    pub items: Vec<LiveMonitoringItem>,
}

#[derive(Debug, Deserialize)]
pub struct LiveQuery {
    /// `"all"` (default) | `"remote"` | `"ssh"`
    pub kind: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// `"all"` (default) | `"remote"` | `"ssh"`
    pub kind: Option<String>,
    pub q: Option<String>,
    /// Inclusive start date (`YYYY-MM-DD` or RFC3339).
    pub date_from: Option<String>,
    /// Inclusive end date (`YYYY-MM-DD` or RFC3339).
    pub date_to: Option<String>,
    pub min_duration_secs: Option<u64>,
    pub max_duration_secs: Option<u64>,
    /// `"all"` (default) | `"completed"` | `"live"` | `"denied"`
    pub status: Option<String>,
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
}

fn default_page() -> u64 {
    1
}
fn default_per_page() -> u64 {
    50
}

#[derive(Debug, Serialize)]
pub struct HistoryMonitoringItem {
    /// `"remote"` | `"ssh"`
    pub kind: &'static str,
    pub id: String,
    pub agent_id: String,
    pub status: &'static str,
    pub started_at: String,
    pub started_at_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    pub initiator: PartyAttribution,
    pub target: PartyAttribution,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<LiveSessionStatsView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_count: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HistorySummary {
    pub total_remote: usize,
    pub total_ssh: usize,
    pub denied_ssh: usize,
}

#[derive(Debug, Serialize)]
pub struct HistoryMonitoringResponse {
    pub items: Vec<HistoryMonitoringItem>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
    pub summary: HistorySummary,
    pub capabilities: MonitoringCapabilities,
}

#[derive(Debug, Deserialize)]
pub struct DisconnectRequest {
    /// `"remote"` | `"ssh"`
    pub kind: String,
    /// `session_id` (ObjectId hex) for RC; live key / `grant_id` for SSH.
    pub id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub shared_session_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TakeoverRequest {
    pub session_id: String,
    pub active: bool,
}

#[derive(Debug, Serialize)]
pub struct SshGrantActivityItem {
    pub id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub allowed: bool,
    pub caller: String,
    pub at: String,
}

#[derive(Debug, Serialize)]
pub struct SshGrantActivitiesResponse {
    pub grant_id: String,
    pub items: Vec<SshGrantActivityItem>,
}

// ────────────────────────────────────────────────────────────────────────────
// Batched dual-party attribution context (zero N+1 queries)
// ────────────────────────────────────────────────────────────────────────────

struct AttributionContext {
    agents: HashMap<ObjectId, Agent>,
    users: HashMap<ObjectId, User>,
    members: HashMap<ObjectId, TenantMember>,
    device_invites_by_agent: HashMap<ObjectId, DeviceInviteRow>,
    shares_by_id: HashMap<ObjectId, DeviceShareGrant>,
    shares_by_pair: HashMap<(ObjectId, ObjectId), DeviceShareGrant>,
}

fn db_err(e: mongodb::error::Error) -> ApiError {
    meshharbor_services::dao::base::DaoError::from(e).into()
}

impl AttributionContext {
    async fn load(
        state: &AppState,
        fleet: &meshharbor_mod_fleet::FleetState,
        tenant_id: ObjectId,
        agent_ids: HashSet<ObjectId>,
        mut user_ids: HashSet<ObjectId>,
        share_grant_ids: HashSet<ObjectId>,
        share_pairs: HashSet<(ObjectId, ObjectId)>,
    ) -> Result<Self, ApiError> {
        // 1. Batch-load referenced agents (including removed/ephemeral rows for history).
        let mut agents = HashMap::new();
        if !agent_ids.is_empty() {
            let ids: Vec<ObjectId> = agent_ids.iter().copied().collect();
            let mut cursor = fleet
                .agents
                .base
                .collection()
                .find(doc! { "tenant_id": tenant_id, "_id": { "$in": &ids } })
                .await
                .map_err(db_err)?;
            while let Some(a) = cursor.try_next().await.map_err(db_err)? {
                if let Some(id) = a.id {
                    user_ids.insert(a.owner_user_id);
                    if let Some(eb) = a.enrolled_by {
                        user_ids.insert(eb);
                    }
                    agents.insert(id, a);
                }
            }
        }

        // 2. Batch-load device invites for referenced agents (newest per agent wins).
        let mut device_invites_by_agent: HashMap<ObjectId, DeviceInviteRow> = HashMap::new();
        if !agent_ids.is_empty() {
            let ids: Vec<ObjectId> = agent_ids.iter().copied().collect();
            let coll = state.db.collection::<DeviceInviteRow>(device_invite::COLLECTION);
            let opts = mongodb::options::FindOptions::builder()
                .sort(doc! { "created_at": -1 })
                .build();
            if let Ok(mut cursor) = coll
                .find(doc! { "tenant_id": tenant_id, "agent_id": { "$in": &ids } })
                .with_options(opts)
                .await
            {
                while let Ok(Some(row)) = cursor.try_next().await {
                    if let Some(aid) = row.agent_id {
                        user_ids.insert(row.inviter_user_id);
                        device_invites_by_agent.entry(aid).or_insert(row);
                    }
                }
            }
        }

        // 3. Batch-load device share grants (by explicit id and/or (device_id, recipient_user_id)).
        let mut shares_by_id: HashMap<ObjectId, DeviceShareGrant> = HashMap::new();
        let mut shares_by_pair: HashMap<(ObjectId, ObjectId), DeviceShareGrant> = HashMap::new();
        if !share_grant_ids.is_empty() || !share_pairs.is_empty() {
            let coll = state
                .db
                .collection::<DeviceShareGrant>(DeviceShareGrant::COLLECTION);
            let mut or_clauses = Vec::new();
            if !share_grant_ids.is_empty() {
                let ids: Vec<ObjectId> = share_grant_ids.iter().copied().collect();
                or_clauses.push(doc! { "_id": { "$in": ids } });
            }
            if !share_pairs.is_empty() {
                let dev_ids: Vec<ObjectId> = share_pairs.iter().map(|(d, _)| *d).collect();
                let rec_ids: Vec<ObjectId> = share_pairs.iter().map(|(_, u)| *u).collect();
                or_clauses.push(doc! {
                    "device_id": { "$in": dev_ids },
                    "recipient_user_id": { "$in": rec_ids },
                });
            }
            let opts = mongodb::options::FindOptions::builder()
                .sort(doc! { "created_at": -1 })
                .build();
            if let Ok(mut cursor) = coll
                .find(doc! { "tenant_id": tenant_id, "$or": or_clauses })
                .with_options(opts)
                .await
            {
                while let Ok(Some(g)) = cursor.try_next().await {
                    user_ids.insert(g.owner_user_id);
                    user_ids.insert(g.recipient_user_id);
                    if let Some(id) = g.id {
                        shares_by_id.insert(id, g.clone());
                    }
                    shares_by_pair
                        .entry((g.device_id, g.recipient_user_id))
                        .or_insert(g);
                }
            }
        }

        // 4. Batch-load tenant memberships for referenced users to capture `invited_by`.
        let mut members: HashMap<ObjectId, TenantMember> = HashMap::new();
        if !user_ids.is_empty() {
            let ids: Vec<ObjectId> = user_ids.iter().copied().collect();
            let coll = state
                .db
                .collection::<TenantMember>(TenantMember::COLLECTION);
            if let Ok(mut cursor) = coll
                .find(doc! { "tenant_id": tenant_id, "user_id": { "$in": &ids } })
                .await
            {
                while let Ok(Some(m)) = cursor.try_next().await {
                    if let Some(inv) = m.invited_by {
                        user_ids.insert(inv);
                    }
                    members.insert(m.user_id, m);
                }
            }
        }

        // 5. Batch-load all referenced users in a single query.
        let mut users: HashMap<ObjectId, User> = HashMap::new();
        if !user_ids.is_empty() {
            let ids: Vec<ObjectId> = user_ids.iter().copied().collect();
            let mut cursor = state
                .users
                .base
                .collection()
                .find(doc! { "_id": { "$in": &ids } })
                .await
                .map_err(db_err)?;
            while let Some(u) = cursor.try_next().await.map_err(db_err)? {
                if let Some(id) = u.id {
                    users.insert(id, u);
                }
            }
        }

        Ok(Self {
            agents,
            users,
            members,
            device_invites_by_agent,
            shares_by_id,
            shares_by_pair,
        })
    }

    fn user_display(&self, id: ObjectId) -> (Option<String>, Option<String>) {
        self.users.get(&id).map_or((None, None), |u| {
            let name = if !u.display_name.is_empty() {
                u.display_name.clone()
            } else {
                u.username.clone()
            };
            (Some(name), Some(u.username.clone()))
        })
    }

    fn agent_display(a: &Agent) -> (String, String) {
        let name = a
            .display_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&a.name)
            .to_string();
        let os = format!("{:?}", a.os).to_lowercase();
        (name, os)
    }

    fn build_target(&self, agent_id: ObjectId) -> PartyAttribution {
        let agent = self.agents.get(&agent_id);
        let (device_name, device_os, owner_id) = match agent {
            Some(a) => {
                let (name, os) = Self::agent_display(a);
                (Some(name), Some(os), Some(a.owner_user_id))
            }
            None => (Some(short_id(agent_id)), None, None),
        };
        let (account_name, account_username) = owner_id
            .map(|uid| self.user_display(uid))
            .unwrap_or((None, None));

        if let Some(inv) = self.device_invites_by_agent.get(&agent_id) {
            let (inviter_name, _) = self.user_display(inv.inviter_user_id);
            let label = if inv.label.is_empty() {
                None
            } else {
                Some(inv.label.clone())
            };
            return PartyAttribution {
                device_id: Some(agent_id.to_hex()),
                device_name,
                device_os,
                account_user_id: owner_id.map(|u| u.to_hex()),
                account_name,
                account_username,
                attribution_kind: "device_invite",
                invite_or_share_label: label,
                inviter_or_owner_name: inviter_name,
                invite_or_share_id: Some(inv.id.to_hex()),
            };
        }

        if let Some(uid) = owner_id
            && let Some(member) = self.members.get(&uid)
            && let Some(inv_by) = member.invited_by
        {
            let (inviter_name, _) = self.user_display(inv_by);
            return PartyAttribution {
                device_id: Some(agent_id.to_hex()),
                device_name,
                device_os,
                account_user_id: Some(uid.to_hex()),
                account_name,
                account_username,
                attribution_kind: "member_invite",
                invite_or_share_label: None,
                inviter_or_owner_name: inviter_name,
                invite_or_share_id: None,
            };
        }

        PartyAttribution {
            device_id: Some(agent_id.to_hex()),
            device_name,
            device_os,
            account_user_id: owner_id.map(|u| u.to_hex()),
            account_name,
            account_username,
            attribution_kind: "account",
            invite_or_share_label: None,
            inviter_or_owner_name: None,
            invite_or_share_id: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_initiator(
        &self,
        user_id: Option<ObjectId>,
        fallback_name: Option<&str>,
        origin_agent_id: Option<ObjectId>,
        target_agent_id: ObjectId,
        share_grant_id: Option<ObjectId>,
        external: bool,
        is_key_list: bool,
    ) -> PartyAttribution {
        let (device_id, device_name, device_os) = match origin_agent_id {
            Some(oid) => match self.agents.get(&oid) {
                Some(a) => {
                    let (n, os) = Self::agent_display(a);
                    (Some(oid.to_hex()), Some(n), Some(os))
                }
                None => (Some(oid.to_hex()), Some(short_id(oid)), None),
            },
            None => (None, None, None),
        };

        let (mut account_name, account_username) = user_id
            .map(|uid| self.user_display(uid))
            .unwrap_or((None, None));
        if account_name.is_none() {
            account_name = fallback_name
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| user_id.map(short_id));
        }

        if is_key_list {
            return PartyAttribution {
                device_id,
                device_name,
                device_os,
                account_user_id: None,
                account_name,
                account_username: None,
                attribution_kind: "key_list",
                invite_or_share_label: None,
                inviter_or_owner_name: None,
                invite_or_share_id: None,
            };
        }

        // Check explicit device share grant first (takes precedence over org membership).
        let share = share_grant_id
            .and_then(|gid| self.shares_by_id.get(&gid))
            .or_else(|| {
                user_id.and_then(|uid| self.shares_by_pair.get(&(target_agent_id, uid)))
            });
        if let Some(grant) = share
            && (share_grant_id.is_some()
                || external
                || user_id.is_some_and(|uid| !self.members.contains_key(&uid)))
        {
            let (owner_name, _) = self.user_display(grant.owner_user_id);
            return PartyAttribution {
                device_id,
                device_name,
                device_os,
                account_user_id: user_id.map(|u| u.to_hex()),
                account_name,
                account_username,
                attribution_kind: "device_share",
                invite_or_share_label: grant.ssh_account.clone(),
                inviter_or_owner_name: owner_name,
                invite_or_share_id: grant.id.map(|id| id.to_hex()),
            };
        }

        if external {
            return PartyAttribution {
                device_id,
                device_name,
                device_os,
                account_user_id: user_id.map(|u| u.to_hex()),
                account_name,
                account_username,
                attribution_kind: "external",
                invite_or_share_label: None,
                inviter_or_owner_name: None,
                invite_or_share_id: None,
            };
        }

        // Check whether the origin device itself joined via a device invite.
        if let Some(oid) = origin_agent_id
            && let Some(inv) = self.device_invites_by_agent.get(&oid)
        {
            let (inviter_name, _) = self.user_display(inv.inviter_user_id);
            return PartyAttribution {
                device_id,
                device_name,
                device_os,
                account_user_id: user_id.map(|u| u.to_hex()),
                account_name,
                account_username,
                attribution_kind: "device_invite",
                invite_or_share_label: (!inv.label.is_empty()).then(|| inv.label.clone()),
                inviter_or_owner_name: inviter_name,
                invite_or_share_id: Some(inv.id.to_hex()),
            };
        }

        // Check whether this org member joined via an org invitation (`invited_by`).
        if let Some(uid) = user_id
            && let Some(member) = self.members.get(&uid)
            && let Some(inv_by) = member.invited_by
        {
            let (inviter_name, _) = self.user_display(inv_by);
            return PartyAttribution {
                device_id,
                device_name,
                device_os,
                account_user_id: Some(uid.to_hex()),
                account_name,
                account_username,
                attribution_kind: "member_invite",
                invite_or_share_label: None,
                inviter_or_owner_name: inviter_name,
                invite_or_share_id: None,
            };
        }

        PartyAttribution {
            device_id,
            device_name,
            device_os,
            account_user_id: user_id.map(|u| u.to_hex()),
            account_name,
            account_username,
            attribution_kind: "account",
            invite_or_share_label: None,
            inviter_or_owner_name: None,
            invite_or_share_id: None,
        }
    }
}

fn short_id(id: ObjectId) -> String {
    let hex = id.to_hex();
    hex.chars().take(8).collect()
}

fn parse_date_bound(raw: &str, end_of_day: bool) -> Option<DateTime> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(DateTime::from_millis(dt.timestamp_millis()));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let naive = if end_of_day {
            date.and_hms_milli_opt(23, 59, 59, 999)?
        } else {
            date.and_hms_opt(0, 0, 0)?
        };
        return Some(DateTime::from_millis(naive.and_utc().timestamp_millis()));
    }
    None
}

fn iso_string(dt: DateTime) -> String {
    dt.try_to_rfc3339_string()
        .unwrap_or_else(|_| dt.timestamp_millis().to_string())
}

fn phase_label(p: SessionPhase) -> &'static str {
    match p {
        SessionPhase::Pending | SessionPhase::AwaitingConsent => "pending",
        SessionPhase::Negotiating => "negotiating",
        SessionPhase::Active => "active",
        SessionPhase::Closed => "closed",
    }
}

fn end_reason_label(r: EndReason) -> String {
    serde_json::to_value(r)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{r:?}").to_lowercase())
}

fn matches_query(q: Option<&str>, haystacks: &[&str]) -> bool {
    let Some(needle) = q.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let lower = needle.to_lowercase();
    haystacks.iter().any(|h| h.to_lowercase().contains(&lower))
}

// ────────────────────────────────────────────────────────────────────────────
// GET /api/tenant/{tenant_id}/monitoring/live
// ────────────────────────────────────────────────────────────────────────────

pub async fn live(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(query): Query<LiveQuery>,
) -> Result<Json<LiveMonitoringResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    let caps = resolve_capabilities(&state, tid, auth.user_id).await?;
    let fleet = state
        .modules
        .fleet
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("fleet module unavailable".into()))?;

    let kind_filter = query.kind.as_deref().unwrap_or("all");
    let want_rc = caps.can_see_remote && matches!(kind_filter, "all" | "remote" | "");
    let want_ssh = caps.can_see_ssh && matches!(kind_filter, "all" | "ssh" | "");

    let rc_live = if want_rc {
        fleet.rc_hub.live_rc_sessions(tid)
    } else {
        Vec::new()
    };
    let ssh_live = if want_ssh {
        fleet.rc_hub.live_ssh_sessions(tid)
    } else {
        Vec::new()
    };

    // Collect IDs for batched attribution lookup.
    let mut agent_ids = HashSet::new();
    let mut user_ids = HashSet::new();
    let mut share_ids = HashSet::new();
    let mut share_pairs = HashSet::new();

    for r in &rc_live {
        agent_ids.insert(r.agent_id);
        user_ids.insert(r.controller_user_id);
        if let Some(gid) = r.share_grant_id {
            share_ids.insert(gid);
        } else if r.external {
            share_pairs.insert((r.agent_id, r.controller_user_id));
        }
    }
    for s in &ssh_live {
        agent_ids.insert(s.agent_id);
        if let Some(o) = s.origin_agent_id {
            agent_ids.insert(o);
        }
        if let Some(u) = s.user_id {
            user_ids.insert(u);
        }
        if let Some(gid) = s.share_grant_id {
            share_ids.insert(gid);
        }
    }

    let attr = AttributionContext::load(
        &state,
        fleet,
        tid,
        agent_ids,
        user_ids,
        share_ids,
        share_pairs,
    )
    .await?;

    let now_ms = DateTime::now().timestamp_millis();
    let mut items = Vec::with_capacity(rc_live.len() + ssh_live.len());

    for r in rc_live {
        let start = r.started_at.unwrap_or(r.created_at);
        let start_ms = start.timestamp_millis();
        let duration_secs = ((now_ms - start_ms).max(0) / 1000) as u64;
        let initiator = attr.build_initiator(
            Some(r.controller_user_id),
            Some(&r.controller_name),
            None,
            r.agent_id,
            r.share_grant_id,
            r.external,
            false,
        );
        let target = attr.build_target(r.agent_id);
        let sid_hex = r.session_id.to_hex();
        let init_text = initiator.searchable_text();
        let tgt_text = target.searchable_text();
        if !matches_query(query.q.as_deref(), &[&sid_hex, &init_text, &tgt_text]) {
            continue;
        }
        items.push(LiveMonitoringItem {
            kind: "remote",
            id: sid_hex,
            agent_id: r.agent_id.to_hex(),
            phase: phase_label(r.phase).to_string(),
            started_at: iso_string(start),
            started_at_ms: start_ms,
            duration_secs,
            initiator,
            target,
            source: if r.share_grant_id.is_some() {
                "device_share".to_string()
            } else if r.external {
                "external".to_string()
            } else {
                "webrtc".to_string()
            },
            account_mode: None,
            ran_as: None,
            shared_session_id: None,
            resume_allowed: false,
            admin_watching: r.admin_watching,
            admin_watcher_count: r.admin_watcher_count,
            admin_taken_over: r.admin_taken_over,
            stats: Some(LiveSessionStatsView {
                bytes_sent: r.stats.bytes_sent,
                bytes_recv: r.stats.bytes_recv,
                avg_rtt_ms: r.stats.avg_rtt_ms,
                peak_fps: r.stats.peak_fps,
                input_events: r.stats.input_events,
            }),
            activity_count: None,
            can_disconnect: caps.can_disconnect_remote,
            can_watch_takeover: caps.can_watch_takeover && r.phase == SessionPhase::Active,
        });
    }

    for s in ssh_live {
        let start_ms = s.started_at.timestamp_millis();
        let duration_secs = ((now_ms - start_ms).max(0) / 1000) as u64;
        let is_key_list = s.source == "key_list";
        let initiator = attr.build_initiator(
            s.user_id,
            Some(&s.caller),
            s.origin_agent_id,
            s.agent_id,
            s.share_grant_id,
            false,
            is_key_list,
        );
        let target = attr.build_target(s.agent_id);
        let init_text = initiator.searchable_text();
        let tgt_text = target.searchable_text();
        if !matches_query(
            query.q.as_deref(),
            &[&s.key, &s.caller, &init_text, &tgt_text],
        ) {
            continue;
        }
        items.push(LiveMonitoringItem {
            kind: "ssh",
            id: s.key,
            agent_id: s.agent_id.to_hex(),
            phase: s.phase.to_string(),
            started_at: iso_string(s.started_at),
            started_at_ms: start_ms,
            duration_secs,
            initiator,
            target,
            source: s.source,
            account_mode: s.account_mode,
            ran_as: s.ran_as,
            shared_session_id: s.shared_session_id.map(|id| id.to_hex()),
            resume_allowed: s.resume_allowed,
            admin_watching: false,
            admin_watcher_count: 0,
            admin_taken_over: false,
            stats: None,
            activity_count: Some(s.activity_count),
            can_disconnect: caps.can_disconnect_ssh,
            can_watch_takeover: false,
        });
    }

    items.sort_by(|a, b| b.started_at_ms.cmp(&a.started_at_ms));
    let remote_count = items.iter().filter(|i| i.kind == "remote").count();
    let ssh_count = items.iter().filter(|i| i.kind == "ssh").count();

    Ok(Json(LiveMonitoringResponse {
        server_time_ms: now_ms,
        counts: LiveMonitoringCounts {
            total: items.len(),
            remote: remote_count,
            ssh: ssh_count,
        },
        capabilities: caps,
        items,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// GET /api/tenant/{tenant_id}/monitoring/history
// ────────────────────────────────────────────────────────────────────────────

pub async fn history(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<HistoryMonitoringResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    let caps = resolve_capabilities(&state, tid, auth.user_id).await?;
    let fleet = state
        .modules
        .fleet
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("fleet module unavailable".into()))?;

    let kind_filter = query.kind.as_deref().unwrap_or("all");
    let status_filter = query.status.as_deref().unwrap_or("all");
    let want_rc = caps.can_see_remote && matches!(kind_filter, "all" | "remote" | "");
    let want_ssh = caps.can_see_ssh && matches!(kind_filter, "all" | "ssh" | "");
    let from_dt = query
        .date_from
        .as_deref()
        .and_then(|s| parse_date_bound(s, false));
    let to_dt = query
        .date_to
        .as_deref()
        .and_then(|s| parse_date_bound(s, true));

    const FETCH_CAP: i64 = 500;

    // 1. Fetch RC sessions if enabled & permitted.
    #[cfg(feature = "remote")]
    let rc_rows: Vec<meshharbor_remote_control::models::RemoteSession> = if want_rc
        && let Some(remote) = state.modules.remote.as_ref()
    {
        let mut filter = doc! { "tenant_id": tid };
        if from_dt.is_some() || to_dt.is_some() {
            let mut range = bson::Document::new();
            if let Some(f) = from_dt {
                range.insert("$gte", f);
            }
            if let Some(t) = to_dt {
                range.insert("$lte", t);
            }
            filter.insert("created_at", range);
        }
        let opts = mongodb::options::FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .limit(FETCH_CAP)
            .build();
        let mut cursor = remote
            .remote_sessions
            .base
            .collection()
            .find(filter)
            .with_options(opts)
            .await
            .map_err(db_err)?;
        let mut rows = Vec::new();
        while let Some(r) = cursor.try_next().await.map_err(db_err)? {
            rows.push(r);
        }
        rows
    } else {
        Vec::new()
    };
    #[cfg(not(feature = "remote"))]
    let rc_rows: Vec<meshharbor_remote_control::models::RemoteSession> = {
        let _ = want_rc;
        Vec::new()
    };

    // 2. Fetch SSH audit rows + batched SSH activity envelopes if enabled & permitted.
    #[cfg(feature = "network")]
    let (ssh_rows, ssh_envelopes): (
        Vec<meshharbor_remote_control::models::SshAuditEvent>,
        HashMap<(ObjectId, String), (Option<DateTime>, Option<DateTime>, u64)>,
    ) = if want_ssh
        && let Some(network) = state.modules.network.as_ref()
    {
        let mut filter = doc! { "tenant_id": tid };
        if from_dt.is_some() || to_dt.is_some() {
            let mut range = bson::Document::new();
            if let Some(f) = from_dt {
                range.insert("$gte", f);
            }
            if let Some(t) = to_dt {
                range.insert("$lte", t);
            }
            filter.insert("at", range);
        }
        let opts = mongodb::options::FindOptions::builder()
            .sort(doc! { "at": -1 })
            .limit(FETCH_CAP)
            .build();
        let mut cursor = network
            .ssh_audit
            .base
            .collection()
            .find(filter)
            .with_options(opts)
            .await
            .map_err(db_err)?;
        let mut rows = Vec::new();
        while let Some(r) = cursor.try_next().await.map_err(db_err)? {
            rows.push(r);
        }

        // Batch-load activity envelopes for all grant_ids in one query, keyed
        // by `(agent_id, grant_id)` so a report from a different agent can
        // never alter another target device's SSH history or duration.
        let grant_ids: Vec<String> = rows
            .iter()
            .filter_map(|r| r.grant_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let mut envelopes: HashMap<(ObjectId, String), (Option<DateTime>, Option<DateTime>, u64)> =
            HashMap::new();
        if !grant_ids.is_empty() {
            use meshharbor_remote_control::models::SshActivityKind;
            let a_opts = mongodb::options::FindOptions::builder()
                .sort(doc! { "at": 1 })
                .build();
            if let Ok(mut ac) = network
                .ssh_activity
                .base
                .collection()
                .find(doc! { "tenant_id": tid, "grant_id": { "$in": &grant_ids } })
                .with_options(a_opts)
                .await
            {
                while let Ok(Some(ev)) = ac.try_next().await {
                    let Some(gid) = ev.grant_id else { continue };
                    let entry = envelopes.entry((ev.agent_id, gid)).or_insert((None, None, 0));
                    match ev.kind {
                        SshActivityKind::SessionOpen => {
                            if entry.0.is_none() {
                                entry.0 = Some(ev.at);
                            }
                        }
                        SshActivityKind::SessionClose => {
                            entry.1 = Some(ev.at);
                        }
                        _ => {
                            if entry.0.is_none() {
                                entry.0 = Some(ev.at);
                            }
                            entry.2 = entry.2.saturating_add(1);
                        }
                    }
                }
            }
        }
        (rows, envelopes)
    } else {
        (Vec::new(), HashMap::new())
    };
    #[cfg(not(feature = "network"))]
    let (ssh_rows, ssh_envelopes): (
        Vec<meshharbor_remote_control::models::SshAuditEvent>,
        HashMap<(ObjectId, String), (Option<DateTime>, Option<DateTime>, u64)>,
    ) = {
        let _ = want_ssh;
        (Vec::new(), HashMap::new())
    };

    let live_ssh_keys: HashSet<(ObjectId, String)> = fleet
        .rc_hub
        .live_ssh_sessions(tid)
        .into_iter()
        .map(|s| (s.agent_id, s.key))
        .collect();
    let live_rc_ids: HashSet<ObjectId> = fleet
        .rc_hub
        .live_rc_sessions(tid)
        .into_iter()
        .map(|s| s.session_id)
        .collect();

    // Batch-resolve dual-party attribution for every referenced device/user/share.
    let mut agent_ids = HashSet::new();
    let mut user_ids = HashSet::new();
    let mut share_pairs = HashSet::new();

    for r in &rc_rows {
        agent_ids.insert(r.agent_id);
        user_ids.insert(r.controller_user_id);
        if r.external {
            share_pairs.insert((r.agent_id, r.controller_user_id));
        }
    }
    for s in &ssh_rows {
        agent_ids.insert(s.agent_id);
        if let Some(o) = s.origin_agent_id {
            agent_ids.insert(o);
        }
        user_ids.insert(s.user_id);
        if s.source == "device_share" {
            share_pairs.insert((s.agent_id, s.user_id));
        }
    }

    let attr = AttributionContext::load(
        &state,
        fleet,
        tid,
        agent_ids,
        user_ids,
        HashSet::new(),
        share_pairs,
    )
    .await?;

    let now_ms = DateTime::now().timestamp_millis();
    let mut all_items: Vec<HistoryMonitoringItem> =
        Vec::with_capacity(rc_rows.len() + ssh_rows.len());

    for r in rc_rows {
        let sid = r.id.unwrap_or_default();
        let start = r.started_at.unwrap_or(r.created_at);
        let start_ms = start.timestamp_millis();
        let is_live = live_rc_ids.contains(&sid) || (r.ended_at.is_none() && r.phase != SessionPhase::Closed);
        let duration_secs = match r.ended_at {
            Some(end) => Some(((end.timestamp_millis() - start_ms).max(0) / 1000) as u64),
            None if is_live => Some(((now_ms - start_ms).max(0) / 1000) as u64),
            None => None,
        };
        let status = if is_live { "live" } else { "completed" };
        let initiator = attr.build_initiator(
            Some(r.controller_user_id),
            None,
            None,
            r.agent_id,
            None,
            r.external,
            false,
        );
        let target = attr.build_target(r.agent_id);
        let end_reason = r.end_reason.map(end_reason_label);
        let sid_hex = sid.to_hex();

        if status_filter != "all" && status_filter != status {
            continue;
        }
        if let Some(min_d) = query.min_duration_secs
            && duration_secs.unwrap_or(0) < min_d
        {
            continue;
        }
        if let Some(max_d) = query.max_duration_secs
            && duration_secs.unwrap_or(u64::MAX) > max_d
        {
            continue;
        }
        let init_text = initiator.searchable_text();
        let tgt_text = target.searchable_text();
        let er_str = end_reason.as_deref().unwrap_or("");
        if !matches_query(
            query.q.as_deref(),
            &[&sid_hex, &init_text, &tgt_text, er_str],
        ) {
            continue;
        }

        all_items.push(HistoryMonitoringItem {
            kind: "remote",
            id: sid_hex,
            agent_id: r.agent_id.to_hex(),
            status,
            started_at: iso_string(start),
            started_at_ms: start_ms,
            ended_at: r.ended_at.map(iso_string),
            duration_secs,
            initiator,
            target,
            source: if r.external {
                "external".to_string()
            } else {
                "webrtc".to_string()
            },
            carrier: r.carrier,
            account_mode: None,
            ran_as: None,
            end_reason,
            denied_reason: None,
            grant_id: None,
            stats: Some(LiveSessionStatsView {
                bytes_sent: r.stats.bytes_sent,
                bytes_recv: r.stats.bytes_recv,
                avg_rtt_ms: r.stats.avg_rtt_ms,
                peak_fps: r.stats.peak_fps,
                input_events: r.stats.input_events,
            }),
            activity_count: None,
        });
    }

    for s in ssh_rows {
        let row_id = s
            .id
            .map(|id| id.to_hex())
            .or_else(|| s.grant_id.clone())
            .unwrap_or_default();
        let env = s
            .grant_id
            .as_deref()
            .and_then(|gid| ssh_envelopes.get(&(s.agent_id, gid.to_string())))
            .copied();
        let is_live = s
            .grant_id
            .as_deref()
            .is_some_and(|gid| live_ssh_keys.contains(&(s.agent_id, gid.to_string())));
        let start = env.and_then(|(o, _, _)| o).unwrap_or(s.at);
        let start_ms = start.timestamp_millis();
        let closed_at = env.and_then(|(_, c, _)| c);
        let activity_count = env.map(|(_, _, n)| n).unwrap_or(0);

        let (status, duration_secs) = if s.denied.is_some() {
            ("denied", Some(0))
        } else if is_live {
            ("live", Some(((now_ms - start_ms).max(0) / 1000) as u64))
        } else if let Some(end) = closed_at {
            (
                "completed",
                Some(((end.timestamp_millis() - start_ms).max(0) / 1000) as u64),
            )
        } else {
            ("completed", None)
        };

        let initiator = attr.build_initiator(
            Some(s.user_id),
            Some(&s.caller),
            s.origin_agent_id,
            s.agent_id,
            None,
            s.source == "device_share",
            false,
        );
        let target = attr.build_target(s.agent_id);
        let denied_reason = s.denied.map(|d| d.message().to_string());

        if status_filter != "all" && status_filter != status {
            continue;
        }
        if let Some(min_d) = query.min_duration_secs
            && duration_secs.unwrap_or(0) < min_d
        {
            continue;
        }
        if let Some(max_d) = query.max_duration_secs
            && duration_secs.unwrap_or(u64::MAX) > max_d
        {
            continue;
        }
        let init_text = initiator.searchable_text();
        let tgt_text = target.searchable_text();
        let gid_str = s.grant_id.as_deref().unwrap_or("");
        let dr_str = denied_reason.as_deref().unwrap_or("");
        if !matches_query(
            query.q.as_deref(),
            &[&row_id, gid_str, &s.caller, &init_text, &tgt_text, dr_str],
        ) {
            continue;
        }

        all_items.push(HistoryMonitoringItem {
            kind: "ssh",
            id: row_id,
            agent_id: s.agent_id.to_hex(),
            status,
            started_at: iso_string(start),
            started_at_ms: start_ms,
            ended_at: closed_at.map(iso_string),
            duration_secs,
            initiator,
            target,
            source: s.source,
            carrier: None,
            account_mode: s.account_mode,
            ran_as: s.ran_as,
            end_reason: None,
            denied_reason,
            grant_id: s.grant_id,
            stats: None,
            activity_count: Some(activity_count),
        });
    }

    all_items.sort_by(|a, b| b.started_at_ms.cmp(&a.started_at_ms));

    let total_remote = all_items.iter().filter(|i| i.kind == "remote").count();
    let total_ssh = all_items.iter().filter(|i| i.kind == "ssh").count();
    let denied_ssh = all_items
        .iter()
        .filter(|i| i.kind == "ssh" && i.status == "denied")
        .count();

    let total = all_items.len() as u64;
    let per_page = query.per_page.clamp(1, 200);
    let page = query.page.max(1);
    let total_pages = total.div_ceil(per_page).max(1);
    let start_idx = ((page - 1) * per_page) as usize;
    let items: Vec<HistoryMonitoringItem> = all_items
        .into_iter()
        .skip(start_idx)
        .take(per_page as usize)
        .collect();

    Ok(Json(HistoryMonitoringResponse {
        items,
        total,
        page,
        per_page,
        total_pages,
        summary: HistorySummary {
            total_remote,
            total_ssh,
            denied_ssh,
        },
        capabilities: caps,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// GET /api/tenant/{tenant_id}/monitoring/ssh-grant/{grant_id}/activities
// ────────────────────────────────────────────────────────────────────────────

pub async fn ssh_grant_activities(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((tenant_id, grant_id)): Path<(String, String)>,
) -> Result<Json<SshGrantActivitiesResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    let caps = resolve_capabilities(&state, tid, auth.user_id).await?;
    if !caps.can_see_ssh {
        return Err(ApiError::Forbidden("Requires VIEW_SSH_AUDIT permission".into()));
    }
    #[cfg(feature = "network")]
    let items = if let Some(network) = state.modules.network.as_ref() {
        // Pin the authoritative target agent_id from `ssh_audit` so a report
        // from a different agent claiming the same `grant_id` cannot pollute
        // this session's activity timeline. Fail closed (404) if no audit row
        // exists in this tenant rather than dropping the agent filter.
        let audit_agent = network
            .ssh_audit
            .base
            .collection()
            .find_one(doc! { "tenant_id": tid, "grant_id": &grant_id })
            .await
            .map_err(db_err)?
            .map(|r| r.agent_id)
            .ok_or_else(|| ApiError::NotFound("SSH grant not found in tenant".into()))?;
        let filter = doc! { "tenant_id": tid, "grant_id": &grant_id, "agent_id": audit_agent };
        let opts = mongodb::options::FindOptions::builder()
            .sort(doc! { "at": 1 })
            .limit(200)
            .build();
        let mut cursor = network
            .ssh_activity
            .base
            .collection()
            .find(filter)
            .with_options(opts)
            .await
            .map_err(db_err)?;
        let mut out = Vec::new();
        while let Some(ev) = cursor.try_next().await.map_err(db_err)? {
            out.push(SshGrantActivityItem {
                id: ev.id.map(|i| i.to_hex()).unwrap_or_default(),
                kind: serde_json::to_value(ev.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| format!("{:?}", ev.kind)),
                detail: ev.detail,
                exit_code: ev.exit_code,
                allowed: ev.allowed,
                caller: ev.caller,
                at: iso_string(ev.at),
            });
        }
        out
    } else {
        Vec::new()
    };
    #[cfg(not(feature = "network"))]
    let items = Vec::new();

    Ok(Json(SshGrantActivitiesResponse { grant_id, items }))
}

/// Extract the authentication principal `keylist:<user>` from a key-list
/// display caller string (`ssh:<user>@<peer> (key-list)`), matching both
/// classic `russh` (`ssh.rs`) and persistent PTY descriptors (`ssh_persist`).
fn parse_keylist_principal(caller: &str) -> Option<String> {
    if caller.starts_with("keylist:") {
        return Some(caller.to_string());
    }
    let inner = caller.strip_suffix(" (key-list)").unwrap_or(caller);
    let (user, _peer) = inner.strip_prefix("ssh:")?.rsplit_once('@')?;
    if user.is_empty() {
        return None;
    }
    Some(format!("keylist:{user}"))
}

// ────────────────────────────────────────────────────────────────────────────
// POST /api/tenant/{tenant_id}/monitoring/disconnect
// ────────────────────────────────────────────────────────────────────────────

pub async fn disconnect(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<DisconnectRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    let caps = resolve_capabilities(&state, tid, auth.user_id).await?;
    let fleet = state
        .modules
        .fleet
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("fleet module unavailable".into()))?;

    match body.kind.as_str() {
        "remote" => {
            if !caps.can_disconnect_remote {
                return Err(ApiError::Forbidden(
                    "Requires ADMINISTRATOR or (VIEW_REMOTE_AUDIT + REMOTE_CONTROL)".into(),
                ));
            }
            let sid = ObjectId::parse_str(&body.id)
                .map_err(|_| ApiError::BadRequest("Invalid session_id".into()))?;
            let live = fleet.rc_hub.session_snapshot(sid);
            if let Some((live_tid, _)) = live
                && live_tid != tid
            {
                return Err(ApiError::NotFound("Session not found".into()));
            }
            let delivered_local = live.is_some()
                && fleet
                    .rc_hub
                    .terminate_and_report_delivery(sid, EndReason::AdminTerminated)
                    .unwrap_or(false);
            #[cfg(feature = "remote")]
            let row_end_written = if live.is_none()
                && let Some(remote) = state.modules.remote.as_ref()
            {
                let res = meshharbor_mod_remote::row_end::admin_end(remote, tid, sid).await;
                if res == meshharbor_mod_remote::row_end::Written::Failed {
                    return Err(ApiError::ServiceUnavailable(
                        "Failed to record remote session termination; retry".into(),
                    ));
                }
                matches!(res, meshharbor_mod_remote::row_end::Written::Wrote { .. })
            } else {
                false
            };
            #[cfg(not(feature = "remote"))]
            let row_end_written = false;

            let broadcast = if state.redis_pubsub.is_some() {
                meshharbor_mod_fleet::ctrl::publish_rc_ctrl_checked(
                    &state,
                    "terminate",
                    serde_json::json!({
                        "session_id": sid.to_hex(),
                        "tenant_id": tid.to_hex(),
                    }),
                )
                .await
                .map_err(|e| {
                    ApiError::ServiceUnavailable(format!(
                        "Failed to broadcast disconnect across cluster: {e}"
                    ))
                })?;
                true
            } else {
                false
            };
            if live.is_some() && !delivered_local && !broadcast {
                return Err(ApiError::ServiceUnavailable(
                    "Remote control session closed on server, but target agent was unreachable"
                        .into(),
                ));
            }
            if !delivered_local && !row_end_written && !broadcast {
                return Err(ApiError::NotFound(
                    "Remote control session is no longer active on this server".into(),
                ));
            }
            Ok(Json(serde_json::json!({
                "disconnected": delivered_local,
                "accepted": delivered_local || broadcast || row_end_written,
                "kind": "remote",
                "id": sid.to_hex(),
                "delivered_local": delivered_local,
                "row_end_written": row_end_written,
                "broadcast": broadcast,
            })))
        }
        "ssh" => {
            if !caps.can_disconnect_ssh {
                return Err(ApiError::Forbidden(
                    "Requires ADMINISTRATOR or (VIEW_SSH_AUDIT + MANAGE_AGENTS)".into(),
                ));
            }
            let live = fleet.rc_hub.get_live_ssh(tid, &body.id);
            let reason = body
                .reason
                .filter(|r| !r.trim().is_empty())
                .unwrap_or_else(|| "admin_disconnect".to_string());

            // Verify any caller-supplied (or keylist-encoded) agent_id belongs
            // to `tid` so single-device disconnects never widen to tenant-wide
            // revokes and cannot probe another tenant's device IDs.
            let is_keylist = body.id.starts_with("keylist:");
            let keylist_encoded_aid = body
                .id
                .strip_prefix("keylist:")
                .and_then(|rest| rest.split(':').next())
                .filter(|s| !s.is_empty());
            let raw_agent_id = body
                .agent_id
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .or(keylist_encoded_aid);
            let verified_agent_id = match live.as_ref().map(|l| l.agent_id) {
                Some(aid) => Some(aid),
                None => match raw_agent_id {
                    Some(raw) => {
                        let aid = ObjectId::parse_str(raw)
                            .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
                        fleet
                            .agents
                            .find_any_in_tenant(tid, aid)
                            .await
                            .map_err(|_| ApiError::NotFound("Target device not found in tenant".into()))?;
                        Some(aid)
                    }
                    None => None,
                },
            };
            if is_keylist && verified_agent_id.is_none() {
                return Err(ApiError::BadRequest(
                    "Key-list SSH disconnect requires a valid target agent_id".into(),
                ));
            }

            // Only trust a shared SSH bridge ID when bound to the authoritative
            // live SSH entry on this pod (never allow an arbitrary caller-supplied
            // `shared_session_id` unbound to `body.id` to tear down another bridge).
            let shared_sid = live.as_ref().and_then(|l| l.shared_session_id);

            // 1. Shared SSH bridge teardown if applicable.
            let mut closed_shared_bridge = false;
            #[cfg(feature = "network")]
            if let Some(network) = state.modules.network.as_ref()
                && let Some(ssid) = shared_sid
                && meshharbor_mod_network::shared_ssh::admin_terminate(network, tid, ssid)
            {
                closed_shared_bridge = true;
            }

            // 2. Determine target scope for `ServerMsg::SshRevoke`.
            let (scope, principal, sid) = if let Some(ref entry) = live {
                if let Some(gid) = entry.grant_id.clone() {
                    ("session", None, Some(gid))
                } else {
                    let p = parse_keylist_principal(&entry.caller)
                        .unwrap_or_else(|| entry.caller.clone());
                    ("principal", Some(p), None)
                }
            } else if is_keylist {
                let caller = body.id.splitn(3, ':').nth(2).unwrap_or("");
                let p = parse_keylist_principal(caller).or_else(|| {
                    (!caller.is_empty()).then(|| caller.to_string())
                });
                ("principal", p, None)
            } else {
                ("session", None, Some(body.id.clone()))
            };

            let mut queued_to_agent = false;
            if let Some(aid) = verified_agent_id {
                if fleet.rc_hub.push_ssh_revoke_agent(
                    tid,
                    aid,
                    scope,
                    principal.clone(),
                    sid.clone(),
                    Some(reason.clone()),
                ) {
                    queued_to_agent = true;
                }
            } else {
                let n = fleet.rc_hub.push_ssh_revoke_org_scoped(
                    tid,
                    scope,
                    principal.clone(),
                    sid.clone(),
                    Some(reason.clone()),
                );
                if n > 0 {
                    queued_to_agent = true;
                }
            }

            let broadcast = if state.redis_pubsub.is_some() {
                let mut payload = serde_json::json!({
                    "tenant_id": tid.to_hex(),
                    "scope": scope,
                    "principal": principal,
                    "sid": sid,
                    "reason": reason,
                });
                if let Some(aid) = verified_agent_id {
                    payload["agent_id"] = serde_json::json!(aid.to_hex());
                }
                if let Some(ssid) = shared_sid {
                    payload["shared_session_id"] = serde_json::json!(ssid.to_hex());
                }
                meshharbor_mod_fleet::ctrl::publish_rc_ctrl_checked(&state, "ssh_revoke", payload)
                    .await
                    .map_err(|e| {
                        ApiError::ServiceUnavailable(format!(
                            "Failed to broadcast SSH revoke across cluster: {e}"
                        ))
                    })?;
                true
            } else {
                false
            };

            let matched_local = live.is_some() || closed_shared_bridge;
            let delivered_local = closed_shared_bridge || (queued_to_agent && matched_local);
            if !queued_to_agent && !closed_shared_bridge && !broadcast {
                return Err(ApiError::ServiceUnavailable(
                    "Target device is offline and did not receive SSH disconnect".into(),
                ));
            }

            Ok(Json(serde_json::json!({
                "disconnected": delivered_local,
                "accepted": queued_to_agent || closed_shared_bridge || broadcast,
                "kind": "ssh",
                "id": body.id,
                "delivered_local": delivered_local,
                "matched_local": matched_local,
                "queued_to_agent": queued_to_agent,
                "broadcast": broadcast,
            })))
        }
        _ => Err(ApiError::BadRequest(
            "kind must be 'remote' or 'ssh'".into(),
        )),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// POST /api/tenant/{tenant_id}/monitoring/takeover
// ────────────────────────────────────────────────────────────────────────────

pub async fn takeover(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<TakeoverRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    let caps = resolve_capabilities(&state, tid, auth.user_id).await?;
    if !caps.can_watch_takeover {
        return Err(ApiError::Forbidden(
            "Requires ADMINISTRATOR or (VIEW_REMOTE_AUDIT + REMOTE_CONTROL)".into(),
        ));
    }
    let fleet = state
        .modules
        .fleet
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("fleet module unavailable".into()))?;
    let sid = ObjectId::parse_str(&body.session_id)
        .map_err(|_| ApiError::BadRequest("Invalid session_id".into()))?;

    match fleet
        .rc_hub
        .set_silent_monitor_takeover(tid, sid, auth.user_id, body.active)
    {
        Ok(agent_id) => Ok(Json(serde_json::json!({
            "ok": true,
            "session_id": sid.to_hex(),
            "agent_id": agent_id.to_hex(),
            "active": body.active,
            "delivered_local": true,
        }))),
        Err(meshharbor_remote_control::error::Error::AgentBusy) => Err(ApiError::Conflict(
            "Another administrator currently holds takeover control on this device".into(),
        )),
        Err(meshharbor_remote_control::error::Error::SessionNotFound(_))
            if state.redis_pubsub.is_some() =>
        {
            meshharbor_mod_fleet::ctrl::publish_rc_ctrl_checked(
                &state,
                "admin_takeover",
                serde_json::json!({
                    "tenant_id": tid.to_hex(),
                    "session_id": sid.to_hex(),
                    "user_id": auth.user_id.to_hex(),
                    "active": body.active,
                }),
            )
            .await
            .map_err(|e| {
                ApiError::ServiceUnavailable(format!(
                    "Failed to forward admin takeover across cluster: {e}"
                ))
            })?;
            Ok(Json(serde_json::json!({
                "ok": true,
                "session_id": sid.to_hex(),
                "active": body.active,
                "delivered_local": false,
                "broadcast": true,
            })))
        }
        Err(meshharbor_remote_control::error::Error::SessionNotFound(_)) => {
            Err(ApiError::NotFound("Silent monitor session not found".into()))
        }
        Err(meshharbor_remote_control::error::Error::AgentOffline(_)) => Err(
            ApiError::ServiceUnavailable("Target device is offline".into()),
        ),
        Err(e) => Err(ApiError::Forbidden(e.to_string())),
    }
}
