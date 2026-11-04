// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — the org's keep-busy policy, server side (`docs/keep-busy.md` §7,
//! §12, §13; spec `docs/fr/FR-92-keep-busy.md`).
//!
//! Keep busy is ON by default (operator decision 2026-10-10): a controller
//! with input can leave a device's pointer moving in a pattern to keep it
//! active. Three things live here:
//!
//! - **The DENY (P5).** Some orgs ban that — it defeats a screen-lock policy
//!   — so an org owner can deny it. The server never enforces it on a data
//!   path (the toggle rides the P2P control channel). It DELIVERS it: a
//!   standing `rc:agent.keep_busy_policy` on every connect and, from here,
//!   on every change — to this pod's agents directly and to every other
//!   pod's over the rc ctrl lane. The device enforces it, strictest of every
//!   org it is enrolled in, and persists it.
//! - **The DEFAULT PATTERN (P8).** A preference, not a policy: what a
//!   viewer's menu pre-selects for a device the person has no remembered
//!   choice on. It never reaches the agent, so any member may read it.
//! - **The HISTORY (P7).** A permanent record of every on and off on every
//!   device (the device's claim, derived on the heartbeat path from two
//!   consecutive briefs) and of every change to the two settings above (the
//!   server's own decision, written here, only when a value changed).

use axum::Json;
use axum::extract::{Path, Query, State};
use bson::{DateTime, oid::ObjectId};
use meshharbor_db::models::{TenantSettings, role::permissions};
use meshharbor_remote_control::models::{
    KEEP_BUSY_PATTERNS, KeepBusyBrief, KeepBusyEvent, KeepBusyEventKind, KeepBusyEventSource,
};
use meshharbor_services::dao::{agent::HeartbeatBefore, keep_busy_event::MAX_LIMIT};
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};
use serde::{Deserialize, Deserializer, Serialize};
use tracing::{debug, info, warn};

use crate::FleetState;

fn tenant_of(tenant_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(tenant_id).map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))
}

// ── The settings ────────────────────────────────────────────────────

/// What `GET` returns and what `PUT` answers with: the org's whole
/// keep-busy policy as stored.
#[derive(Debug, Serialize, Deserialize)]
pub struct OrgKeepBusySettings {
    /// `true` = no device in this org may run keep busy, and any already
    /// running stops. `false` (the default) = allowed.
    pub keep_busy_denied: bool,
    /// FR-92 P8 — the org's default pattern, or `null` for the product
    /// default (`circle`). The STORED value, not the resolution: a viewer
    /// resolves `null` itself, and the admin card can tell "left alone" from
    /// "chosen".
    pub keep_busy_default_pattern: Option<String>,
}

impl OrgKeepBusySettings {
    fn of(s: &TenantSettings) -> Self {
        Self {
            keep_busy_denied: s.keep_busy_denied,
            keep_busy_default_pattern: s.keep_busy_default_pattern.clone(),
        }
    }
}

/// The `PUT` body. Every field is optional and an ABSENT field leaves the
/// stored value alone, so the pre-P8 body `{keep_busy_denied}` keeps doing
/// exactly what it did. The default pattern tells absent from `null` apart:
/// `null` clears it back to the product default.
#[derive(Debug, Default, Deserialize)]
pub struct OrgKeepBusySettingsUpdate {
    #[serde(default)]
    pub keep_busy_denied: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    pub keep_busy_default_pattern: Option<Option<String>>,
}

/// `Some(inner)` whenever the field is PRESENT, `null` included — serde's
/// own `Option` would fold a `null` into the absent case.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// FR-92 P8 — is `pattern` one the agent can draw? Equality against the
/// canonical wire list, never a prefix or a case-fold: the word is handed
/// to the agent verbatim, which matches it by equality too.
pub fn validate_pattern(pattern: &str) -> Result<(), ApiError> {
    if KEEP_BUSY_PATTERNS.contains(&pattern) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "Unknown keep-busy pattern; one of: {}",
            KEEP_BUSY_PATTERNS.join(", ")
        )))
    }
}

/// `GET /api/tenant/{tenant_id}/keep-busy-settings` — readable by ANY
/// member of the org (P8). It is only the org's keep-busy policy, which
/// every device and every viewer in the org is already told: the deny
/// reaches each device as a standing frame, and the default pattern exists
/// so a viewer can pre-select it. A non-member gets `not_a_member`.
pub async fn get_org_settings(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<OrgKeepBusySettings>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let tenant = state.tenants.base.find_by_id(tid).await?;
    Ok(Json(OrgKeepBusySettings::of(&tenant.settings)))
}

/// `PUT /api/tenant/{tenant_id}/keep-busy-settings` — set the deny and/or
/// the default pattern.
///
/// `MANAGE_TENANT`, like the exec and SSH switches: it decides for every
/// device in the org at once. A deny the body spoke of reaches devices that
/// are online now (this pod directly, other pods over the ctrl lane) and
/// every other device at its next connect. Each value that actually CHANGED
/// is recorded in the history, naming the admin (P7).
pub async fn set_org_settings(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<OrgKeepBusySettingsUpdate>,
) -> Result<Json<OrgKeepBusySettings>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    if body.keep_busy_denied.is_none() && body.keep_busy_default_pattern.is_none() {
        return Err(ApiError::BadRequest(
            "Nothing to set: keep_busy_denied and/or keep_busy_default_pattern".into(),
        ));
    }
    if let Some(Some(pattern)) = body.keep_busy_default_pattern.as_ref() {
        validate_pattern(pattern)?;
    }

    let before = state.tenants.base.find_by_id(tid).await?.settings;
    let after = state
        .tenants
        .set_keep_busy_settings(
            tid,
            body.keep_busy_denied,
            body.keep_busy_default_pattern.clone(),
        )
        .await?
        .settings;

    // The history: only what changed, and who changed it.
    let mut changed = Vec::new();
    if before.keep_busy_denied != after.keep_busy_denied {
        changed.push((
            if after.keep_busy_denied {
                KeepBusyEventKind::OrgDenied
            } else {
                KeepBusyEventKind::OrgAllowed
            },
            None,
        ));
    }
    if before.keep_busy_default_pattern != after.keep_busy_default_pattern {
        changed.push((
            KeepBusyEventKind::OrgDefaultPattern,
            after.keep_busy_default_pattern.clone(),
        ));
    }
    if !changed.is_empty() {
        let actor_name = actor_name(&state, &auth).await;
        for (kind, pattern) in changed {
            let event = KeepBusyEvent {
                id: None,
                tenant_id: tid,
                agent_id: None,
                agent_name: None,
                at: DateTime::now(),
                kind,
                source: KeepBusyEventSource::Server,
                actor_user_id: Some(auth.user_id),
                actor_name: Some(actor_name.clone()),
                pattern,
                reason: None,
            };
            if let Err(e) = state.keep_busy_events.record(event).await {
                warn!(tenant = %tenant_id, ?kind, %e, "keep-busy history: record failed");
            }
        }
    }

    // The deny is DELIVERED whenever the body spoke of it, changed or not —
    // a re-assert is harmless and is what every pre-P8 PUT did. A pattern
    // alone wakes no device: it never travels.
    if body.keep_busy_denied.is_some() {
        let denied = after.keep_busy_denied;
        let here = state.rc_hub.push_keep_busy_policy(tid, denied);
        crate::ctrl::publish_rc_ctrl(
            &state,
            "keep_busy_policy",
            serde_json::json!({ "tenant_id": tid.to_hex(), "denied": denied }),
        )
        .await;
        warn!(
            tenant = %tenant_id, admin = %auth.user_id, denied, pushed_here = here,
            "keep-busy: org policy changed"
        );
    }
    if body.keep_busy_default_pattern.is_some() {
        info!(
            tenant = %tenant_id, admin = %auth.user_id,
            pattern = after.keep_busy_default_pattern.as_deref().unwrap_or("(product default)"),
            "keep-busy: org default pattern set"
        );
    }
    Ok(Json(OrgKeepBusySettings::of(&after)))
}

/// The admin's display name for a history row, falling back to the
/// username the token carries — a row must name SOMEONE even when the user
/// read fails.
async fn actor_name(state: &FleetState, auth: &AuthUser) -> String {
    match state.users.base.find_by_id(auth.user_id).await {
        Ok(u) if !u.display_name.trim().is_empty() => u.display_name,
        _ => auth.username.clone(),
    }
}

// ── The history ─────────────────────────────────────────────────────

/// `GET …/keep-busy-history?agent_id=&before=&limit=`.
///
/// ⚠️ Declared inline, never `#[serde(flatten)]`: `Query` hands every value
/// to serde as a string, and flatten breaks the integer (`agent_exec.rs`
/// `AuditQuery` has the incident).
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Narrow to one device. Always paired with the tenant in the filter.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Only rows strictly older than this: RFC 3339, or unix milliseconds.
    /// The "load more" cursor is the last row's `at`.
    #[serde(default)]
    pub before: Option<String>,
    /// `1..=200`, default 50; out of range is clamped.
    #[serde(default)]
    pub limit: Option<i64>,
}

pub const DEFAULT_LIMIT: i64 = 50;

/// `before`, as RFC 3339 or unix milliseconds.
pub fn parse_before(s: &str) -> Result<DateTime, ApiError> {
    let s = s.trim();
    if let Ok(ms) = s.parse::<i64>() {
        return Ok(DateTime::from_millis(ms));
    }
    DateTime::parse_rfc3339_str(s)
        .map_err(|_| ApiError::BadRequest("Invalid before: RFC 3339 or unix milliseconds".into()))
}

/// One history row on the wire: ids as hex, the instant as RFC 3339.
#[derive(Debug, Serialize)]
pub struct KeepBusyEventRow {
    pub id: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    pub at: String,
    pub kind: KeepBusyEventKind,
    pub source: KeepBusyEventSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<KeepBusyEvent> for KeepBusyEventRow {
    fn from(e: KeepBusyEvent) -> Self {
        Self {
            id: e.id.map(|i| i.to_hex()).unwrap_or_default(),
            tenant_id: e.tenant_id.to_hex(),
            agent_id: e.agent_id.map(|i| i.to_hex()),
            agent_name: e.agent_name,
            at: e.at.try_to_rfc3339_string().unwrap_or_default(),
            kind: e.kind,
            source: e.source,
            actor_user_id: e.actor_user_id.map(|i| i.to_hex()),
            actor_name: e.actor_name,
            pattern: e.pattern,
            reason: e.reason,
        }
    }
}

/// `GET /api/tenant/{tenant_id}/keep-busy-history` — newest first.
/// `MANAGE_AGENTS`, like the device list the rows are about. Every query is
/// scoped by the tenant AND the device: a device id alone is never a key,
/// so another org's device id answers with nothing (CLAUDE.md, Security
/// Baseline).
pub async fn history(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Vec<KeepBusyEventRow>>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let agent_id = q
        .agent_id
        .as_deref()
        .map(|a| {
            ObjectId::parse_str(a).map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))
        })
        .transpose()?;
    let before = q.before.as_deref().map(parse_before).transpose()?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let rows = state
        .keep_busy_events
        .list(tid, agent_id, before, limit)
        .await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

// ── The device's edges ──────────────────────────────────────────────

/// FR-92 P7 — what two consecutive briefs say happened on a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceEdge {
    On {
        pattern: Option<String>,
        set_by: Option<String>,
    },
    Off {
        reason: Option<String>,
    },
}

/// The edge between the previous stored brief and the one this heartbeat
/// carries. Pure, so the table is testable without a database.
///
/// - off, or absent (unknown) → on: **on**;
/// - on → off: **off**, with the new brief's reason;
/// - on → absent: nothing — a device that stops saying is unknown, never
///   off (P5b's rule, kept here);
/// - the same state twice, absent → off, absent → absent: nothing.
///
/// On → on with a different pattern or `set_by` is NOT an edge: the history
/// records ons and offs, and the current brief on the device row carries
/// what is drawn now.
pub fn device_edge(
    prev: Option<&KeepBusyBrief>,
    new: Option<&KeepBusyBrief>,
) -> Option<DeviceEdge> {
    let prev_on = prev.is_some_and(|b| b.on);
    match new {
        Some(n) if n.on && !prev_on => Some(DeviceEdge::On {
            pattern: n.pattern.clone(),
            set_by: n.set_by.clone(),
        }),
        Some(n) if !n.on && prev_on => Some(DeviceEdge::Off {
            reason: n.reason.clone(),
        }),
        _ => None,
    }
}

/// After a gap in reporting (the previous brief ABSENT), an "off" is an edge
/// only while the history's newest row about the device is still an `on`.
/// Pure. Without the history check, every restart of a device that was never
/// on would write an "off".
pub fn off_after_gap(
    last: Option<KeepBusyEventKind>,
    new: Option<&KeepBusyBrief>,
) -> Option<DeviceEdge> {
    match (last, new) {
        (Some(KeepBusyEventKind::On), Some(n)) if !n.on => Some(DeviceEdge::Off {
            reason: n.reason.clone(),
        }),
        _ => None,
    }
}

/// Record the edge this heartbeat makes, if any. Called on the agent's read
/// loop right after `touch_heartbeat` handed back the row as it was.
///
/// **The restart dedupe.** When the previous brief was ABSENT (unknown) and
/// the new one is on, the newest row about this device decides: if it is
/// already `on` with the same pattern and the same `set_by`, this is the
/// same keep busy seen again after a gap in reporting (a daemon update that
/// briefly reported nothing, a rollback and re-update), not a new one, and
/// nothing is written. A failed lookup records anyway — a duplicate row
/// beats a lost edge.
///
/// Never fails the heartbeat: every error is logged and swallowed.
pub async fn record_device_edge(
    state: &FleetState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    before: &HeartbeatBefore,
    new: Option<&KeepBusyBrief>,
) {
    let edge = match device_edge(before.keep_busy.as_ref(), new) {
        Some(edge) => edge,
        // Unknown → off is not an edge by itself — but if the history still
        // says ON, the off happened inside the gap (stopped at the device, or
        // an auto-off, while it was not reporting) and is recorded now;
        // otherwise the history would end on an "on" that is long over.
        None if before.keep_busy.is_none() && new.is_some_and(|n| !n.on) => {
            match state
                .keep_busy_events
                .latest_for_agent(tenant_id, agent_id)
                .await
            {
                Ok(last) => match off_after_gap(last.map(|e| e.kind), new) {
                    Some(edge) => edge,
                    None => return,
                },
                Err(e) => {
                    warn!(%agent_id, %e, "keep-busy history: gap lookup failed; an off may be missing");
                    return;
                }
            }
        }
        None => return,
    };
    if let DeviceEdge::On { pattern, set_by } = &edge
        && before.keep_busy.is_none()
    {
        match state
            .keep_busy_events
            .latest_for_agent(tenant_id, agent_id)
            .await
        {
            Ok(Some(last))
                if last.kind == KeepBusyEventKind::On
                    && last.pattern == *pattern
                    && last.actor_name == *set_by =>
            {
                debug!(%agent_id, "keep-busy history: same keep busy seen again after a gap; not recorded");
                return;
            }
            Ok(_) => {}
            Err(e) => {
                warn!(%agent_id, %e, "keep-busy history: dedupe lookup failed; recording anyway");
            }
        }
    }
    let (kind, actor_name, pattern, reason) = match edge {
        DeviceEdge::On { pattern, set_by } => (KeepBusyEventKind::On, set_by, pattern, None),
        DeviceEdge::Off { reason } => (KeepBusyEventKind::Off, None, None, reason),
    };
    let label = before.label();
    let event = KeepBusyEvent {
        id: None,
        tenant_id,
        agent_id: Some(agent_id),
        agent_name: (!label.is_empty()).then(|| label.to_string()),
        at: DateTime::now(),
        kind,
        source: KeepBusyEventSource::Device,
        actor_user_id: None,
        actor_name,
        pattern,
        reason,
    };
    if let Err(e) = state.keep_busy_events.record(event).await {
        warn!(%agent_id, ?kind, %e, "keep-busy history: record failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brief(
        on: bool,
        pattern: Option<&str>,
        set_by: Option<&str>,
        reason: Option<&str>,
    ) -> KeepBusyBrief {
        KeepBusyBrief {
            on,
            phase: if on { "running" } else { "off" }.to_string(),
            reason: reason.map(str::to_string),
            pattern: pattern.map(str::to_string),
            set_by: set_by.map(str::to_string),
        }
    }

    #[test]
    fn an_on_edge_from_off_or_from_unknown() {
        let on = brief(true, Some("heart"), Some("Alice"), None);
        let want = Some(DeviceEdge::On {
            pattern: Some("heart".into()),
            set_by: Some("Alice".into()),
        });
        assert_eq!(device_edge(None, Some(&on)), want, "unknown → on");
        assert_eq!(
            device_edge(Some(&brief(false, None, None, None)), Some(&on)),
            want,
            "off → on"
        );
    }

    #[test]
    fn an_off_edge_carries_the_reason_and_only_follows_an_on() {
        let on = brief(true, Some("heart"), Some("Alice"), None);
        let off = brief(false, None, None, Some("stopped_by_controller"));
        assert_eq!(
            device_edge(Some(&on), Some(&off)),
            Some(DeviceEdge::Off {
                reason: Some("stopped_by_controller".into())
            })
        );
        assert_eq!(
            device_edge(None, Some(&off)),
            None,
            "unknown → off is nothing"
        );
        assert_eq!(
            device_edge(Some(&off), Some(&off)),
            None,
            "off → off is nothing"
        );
    }

    /// An off that happened while the device was not reporting is recorded
    /// when it reports again — but only while the history still says on.
    #[test]
    fn an_off_after_a_gap_is_an_edge_only_while_the_history_says_on() {
        let off = brief(false, None, None, Some("stopped_locally"));
        let on = brief(true, Some("heart"), Some("Alice"), None);
        assert_eq!(
            off_after_gap(Some(KeepBusyEventKind::On), Some(&off)),
            Some(DeviceEdge::Off {
                reason: Some("stopped_locally".into())
            })
        );
        assert_eq!(
            off_after_gap(Some(KeepBusyEventKind::Off), Some(&off)),
            None
        );
        assert_eq!(off_after_gap(None, Some(&off)), None, "a device never on");
        assert_eq!(off_after_gap(Some(KeepBusyEventKind::On), Some(&on)), None);
        assert_eq!(off_after_gap(Some(KeepBusyEventKind::On), None), None);
    }

    /// P5b's rule, kept: a device that stops saying is UNKNOWN, never off.
    #[test]
    fn a_device_that_stops_saying_makes_no_edge() {
        let on = brief(true, Some("heart"), Some("Alice"), None);
        assert_eq!(device_edge(Some(&on), None), None);
        assert_eq!(device_edge(None, None), None);
    }

    /// The same state twice is a repeated beat, not an edge — including an
    /// on whose pattern or `set_by` changed, which the device row shows.
    #[test]
    fn a_repeated_on_is_not_an_edge() {
        let a = brief(true, Some("heart"), Some("Alice"), None);
        let b = brief(true, Some("star"), Some("Bob"), None);
        assert_eq!(device_edge(Some(&a), Some(&a)), None);
        assert_eq!(device_edge(Some(&a), Some(&b)), None);
    }

    /// Equality, never a prefix or a case-fold: the word reaches the agent
    /// verbatim.
    #[test]
    fn the_default_pattern_is_validated_by_equality() {
        for p in KEEP_BUSY_PATTERNS {
            assert!(validate_pattern(p).is_ok(), "{p}");
        }
        for p in ["hearts", "hea", "Heart", "circle ", "", "shuffle2"] {
            assert!(validate_pattern(p).is_err(), "{p:?} must be refused");
        }
    }

    /// Absent, `null` and a value are three different bodies.
    #[test]
    fn the_put_body_tells_absent_from_null() {
        let absent: OrgKeepBusySettingsUpdate =
            serde_json::from_str(r#"{"keep_busy_denied": true}"#).unwrap();
        assert_eq!(absent.keep_busy_denied, Some(true));
        assert_eq!(absent.keep_busy_default_pattern, None);

        let cleared: OrgKeepBusySettingsUpdate =
            serde_json::from_str(r#"{"keep_busy_default_pattern": null}"#).unwrap();
        assert_eq!(cleared.keep_busy_denied, None);
        assert_eq!(cleared.keep_busy_default_pattern, Some(None));

        let set: OrgKeepBusySettingsUpdate =
            serde_json::from_str(r#"{"keep_busy_default_pattern": "heart"}"#).unwrap();
        assert_eq!(set.keep_busy_default_pattern, Some(Some("heart".into())));

        let empty: OrgKeepBusySettingsUpdate = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.keep_busy_denied, None);
        assert_eq!(empty.keep_busy_default_pattern, None);
    }

    #[test]
    fn before_parses_rfc3339_and_unix_millis() {
        let ms = parse_before("1760000000000").unwrap();
        assert_eq!(ms.timestamp_millis(), 1_760_000_000_000);
        let iso = parse_before("2026-10-11T12:00:00.250Z").unwrap();
        assert_eq!(iso.timestamp_millis() % 1000, 250, "the fraction survives");
        assert_eq!(
            iso,
            DateTime::from_millis(parse_before("1791720000250").unwrap().timestamp_millis()),
            "one instant, both spellings"
        );
        assert!(parse_before("yesterday").is_err());
        assert!(parse_before("").is_err());
    }

    /// The admin panel's and the viewer's exact requests go through axum's
    /// real `Query` extractor — the extractor is where the flatten bug hid.
    #[test]
    fn history_query_parses_the_real_requests() {
        let uri: axum::http::Uri =
            "/api/tenant/69a1dbbad2000f26adc875ce/keep-busy-history?agent_id=69a1dbbad2000f26adc875cf&before=2026-10-11T12:00:00Z&limit=50"
                .parse()
                .unwrap();
        let q: Query<HistoryQuery> = Query::try_from_uri(&uri).expect("must parse");
        assert_eq!(q.agent_id.as_deref(), Some("69a1dbbad2000f26adc875cf"));
        assert_eq!(q.before.as_deref(), Some("2026-10-11T12:00:00Z"));
        assert_eq!(q.limit, Some(50));
        let bare: axum::http::Uri = "/api/tenant/x/keep-busy-history".parse().unwrap();
        let q: Query<HistoryQuery> = Query::try_from_uri(&bare).expect("bare must parse");
        assert!(q.agent_id.is_none() && q.before.is_none() && q.limit.is_none());
    }
}
