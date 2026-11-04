// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-101 P2a — the org's remote-desktop session policy: for each sensitive
//! feature (clipboard, files, audio), `on | ask | off` (spec
//! `docs/fr/FR-101-rc-session-hygiene.md` §3a).
//!
//! Stored on the tenant (`TenantSettings.rc_session`). The authz gate reads it
//! from the row it already loads ([`crate::controller::resolve_session_authz`])
//! and the hub applies it (`meshharbor_mod_fleet::hub::feature_grant`): it
//! strips what the policy refuses and says why, in `rc:session.created` and
//! in the session's audit row. The device enforcing it too (P2b) is what
//! survives a hub that was bypassed.
//!
//! A change applies to sessions that START after it. A live session keeps the
//! grant it was created with.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};
use meshharbor_db::models::{RcFeaturePolicy, RcSessionLimits, RcSessionPolicy, role::permissions};
use meshharbor_remote_control::models::{FeaturePolicy, SessionPolicy};
use serde::Deserialize;
use tracing::warn;

use crate::RemoteState;

/// The stored policy in the wire's terms. A `match` per value rather than a
/// cast, so a variant added on one side only fails to compile here instead of
/// mapping to the wrong one.
pub fn wire(p: &RcSessionPolicy) -> SessionPolicy {
    fn one(f: RcFeaturePolicy) -> FeaturePolicy {
        match f {
            RcFeaturePolicy::On => FeaturePolicy::On,
            RcFeaturePolicy::Ask => FeaturePolicy::Ask,
            RcFeaturePolicy::Off => FeaturePolicy::Off,
        }
    }
    SessionPolicy {
        clipboard: one(p.clipboard),
        files: one(p.files),
        audio: one(p.audio),
    }
}

fn tenant_of(tenant_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(tenant_id).map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))
}

/// The `PUT` body. Every field is optional, and an ABSENT field leaves the
/// stored value alone: a body naming one feature must never re-allow
/// another. ⚠️ Unknown keys are refused: a misspelt `clipbaord` that quietly
/// changed nothing is the wrong failure for a security setting.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RcSessionPolicyUpdate {
    #[serde(default)]
    pub clipboard: Option<String>,
    #[serde(default)]
    pub files: Option<String>,
    #[serde(default)]
    pub audio: Option<String>,
}

/// One value from an admin, read STRICTLY. The stored and wire types read an
/// unknown value as `off`, which is right for a row a newer server wrote, but
/// a typo in a request deserves a refusal, not a silent `off`.
fn strict(field: &str, value: &str) -> Result<RcFeaturePolicy, ApiError> {
    match value {
        "on" => Ok(RcFeaturePolicy::On),
        "ask" => Ok(RcFeaturePolicy::Ask),
        "off" => Ok(RcFeaturePolicy::Off),
        _ => Err(ApiError::BadRequest(format!(
            "Invalid {field}: one of on, ask, off"
        ))),
    }
}

/// `GET /api/tenant/{tenant_id}/rc-session-policy` — readable by ANY member.
/// Every session in the org is told the policy's effect on it anyway
/// (`features_refused`), and a viewer reads this to explain a greyed control
/// before it asks. A non-member gets `not_a_member`.
pub async fn get_policy(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<RcSessionPolicy>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let tenant = state.tenants.base.find_by_id(tid).await?;
    Ok(Json(tenant.settings.rc_session))
}

/// `PUT /api/tenant/{tenant_id}/rc-session-policy` — set one or more features.
///
/// `MANAGE_TENANT`, like the keep-busy deny and the exec and SSH switches: it
/// decides for every session in the org at once. Answers with the stored
/// policy. Each change is logged naming the admin; the per-session effect is
/// in each session's `session_requested` audit row (`features_stripped`).
pub async fn set_policy(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<RcSessionPolicyUpdate>,
) -> Result<Json<RcSessionPolicy>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    let clipboard = body
        .clipboard
        .as_deref()
        .map(|v| strict("clipboard", v))
        .transpose()?;
    let files = body
        .files
        .as_deref()
        .map(|v| strict("files", v))
        .transpose()?;
    let audio = body
        .audio
        .as_deref()
        .map(|v| strict("audio", v))
        .transpose()?;
    if clipboard.is_none() && files.is_none() && audio.is_none() {
        return Err(ApiError::BadRequest(
            "Nothing to set: clipboard, files and/or audio".into(),
        ));
    }

    let before = state
        .tenants
        .base
        .find_by_id(tid)
        .await?
        .settings
        .rc_session;
    let after = state
        .tenants
        .set_rc_session_policy(tid, clipboard, files, audio)
        .await?
        .settings
        .rc_session;
    if before != after {
        warn!(
            tenant = %tenant_id, admin = %auth.user_id, ?before, ?after,
            "rc session policy changed"
        );
    }
    Ok(Json(after))
}

// ── FR-101 P4b — the session limits ─────────────────────────────────────────

/// The shortest and longest maximum session length an admin may set: a
/// minute, and a day. A stored value outside it still works (the hub reads
/// whatever is there); the range is for people, not for the timer.
pub const MAX_SECS_RANGE: std::ops::RangeInclusive<u32> = 60..=86_400;

/// P4b-2 — the same range for the idle limit, for the same reason: the agent
/// enforces whatever reaches it.
pub const IDLE_SECS_RANGE: std::ops::RangeInclusive<u32> = 60..=86_400;

/// What the limits route answers: every limit, `null` when unset.
#[derive(Debug, serde::Serialize, Deserialize, PartialEq, Eq)]
pub struct RcSessionLimitsDto {
    pub max_secs: Option<u32>,
    /// P4b-2 — the org's idle limit. Enforced by the device, so only by
    /// devices that advertise `idle-timeout`; an older agent ignores it.
    pub idle_secs: Option<u32>,
}

impl From<RcSessionLimits> for RcSessionLimitsDto {
    fn from(l: RcSessionLimits) -> Self {
        Self {
            max_secs: l.max_secs,
            idle_secs: l.idle_secs,
        }
    }
}

/// The `PUT` body. An ABSENT field leaves the limit alone; `null` clears it.
/// Unknown keys are refused, as on the policy route.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RcSessionLimitsUpdate {
    #[serde(default, deserialize_with = "present")]
    pub max_secs: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present")]
    pub idle_secs: Option<Option<u32>>,
}

/// A limit in the body, checked against its range. `null` (clear) always
/// passes.
fn check_limit(
    name: &str,
    value: Option<Option<u32>>,
    range: &std::ops::RangeInclusive<u32>,
) -> Result<(), ApiError> {
    if let Some(Some(secs)) = value
        && !range.contains(&secs)
    {
        return Err(ApiError::BadRequest(format!(
            "Invalid {name}: {} to {} seconds, or null for no limit",
            range.start(),
            range.end()
        )));
    }
    Ok(())
}

/// `Some(inner)` whenever the field is PRESENT, `null` included: serde's own
/// `Option` would fold a `null` into the absent case.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<u32>>, D::Error> {
    Option::<u32>::deserialize(d).map(Some)
}

/// `GET /api/tenant/{tenant_id}/rc-session-limits` — any member, like the
/// policy: a session in the org is ended by it, so its members may know it.
pub async fn get_limits(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<RcSessionLimitsDto>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let tenant = state.tenants.base.find_by_id(tid).await?;
    Ok(Json(tenant.settings.rc_limits.into()))
}

/// `PUT /api/tenant/{tenant_id}/rc-session-limits` — `MANAGE_TENANT`. A new
/// limit applies to sessions that go live after it; a live session keeps the
/// one it started with.
pub async fn set_limits(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<RcSessionLimitsUpdate>,
) -> Result<Json<RcSessionLimitsDto>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    if body.max_secs.is_none() && body.idle_secs.is_none() {
        return Err(ApiError::BadRequest(
            "Nothing to set: max_secs, idle_secs".into(),
        ));
    }
    check_limit("max_secs", body.max_secs, &MAX_SECS_RANGE)?;
    check_limit("idle_secs", body.idle_secs, &IDLE_SECS_RANGE)?;
    let before = state.tenants.base.find_by_id(tid).await?.settings.rc_limits;
    let after = state
        .tenants
        .set_rc_session_limits(tid, body.max_secs, body.idle_secs)
        .await?
        .settings
        .rc_limits;
    if before != after {
        warn!(
            tenant = %tenant_id, admin = %auth.user_id, ?before, ?after,
            "rc session limits changed"
        );
    }
    Ok(Json(after.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-101 P4b — the limits body: absent is "leave it", `null` is
    /// "clear it", a number sets it; anything else fails the body.
    #[test]
    fn the_limits_body_tells_absent_from_null() {
        let absent: RcSessionLimitsUpdate = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(absent.max_secs, None);
        let clear: RcSessionLimitsUpdate =
            serde_json::from_value(serde_json::json!({ "max_secs": null })).unwrap();
        assert_eq!(clear.max_secs, Some(None));
        let set: RcSessionLimitsUpdate =
            serde_json::from_value(serde_json::json!({ "max_secs": 3600 })).unwrap();
        assert_eq!(set.max_secs, Some(Some(3600)));
        assert_eq!(
            set.idle_secs, None,
            "a body naming one limit leaves the other"
        );
        // P4b-2 — the idle limit reads the same way, on its own.
        let idle: RcSessionLimitsUpdate =
            serde_json::from_value(serde_json::json!({ "idle_secs": 900 })).unwrap();
        assert_eq!((idle.max_secs, idle.idle_secs), (None, Some(Some(900))));
        let idle_clear: RcSessionLimitsUpdate =
            serde_json::from_value(serde_json::json!({ "idle_secs": null })).unwrap();
        assert_eq!(idle_clear.idle_secs, Some(None));
        for bad in [
            serde_json::json!({ "max_secs": -1 }),
            serde_json::json!({ "max_secs": "1h" }),
            serde_json::json!({ "max_sec": 60 }),
            serde_json::json!({ "idle_secs": "15m" }),
            serde_json::json!({ "idle": 900 }),
        ] {
            assert!(
                serde_json::from_value::<RcSessionLimitsUpdate>(bad.clone()).is_err(),
                "{bad}"
            );
        }
        assert!(MAX_SECS_RANGE.contains(&60) && MAX_SECS_RANGE.contains(&86_400));
        assert!(!MAX_SECS_RANGE.contains(&59) && !MAX_SECS_RANGE.contains(&86_401));
        assert!(check_limit("idle_secs", Some(Some(59)), &IDLE_SECS_RANGE).is_err());
        assert!(check_limit("idle_secs", Some(Some(60)), &IDLE_SECS_RANGE).is_ok());
        assert!(check_limit("idle_secs", Some(None), &IDLE_SECS_RANGE).is_ok());
        assert!(check_limit("idle_secs", None, &IDLE_SECS_RANGE).is_ok());
    }

    /// Every stored value maps to the same wire value, field by field.
    #[test]
    fn the_stored_policy_maps_to_the_wire_one_to_one() {
        let all = [
            RcFeaturePolicy::On,
            RcFeaturePolicy::Ask,
            RcFeaturePolicy::Off,
        ];
        let want = [FeaturePolicy::On, FeaturePolicy::Ask, FeaturePolicy::Off];
        for (i, c) in all.into_iter().enumerate() {
            for (j, f) in all.into_iter().enumerate() {
                for (k, a) in all.into_iter().enumerate() {
                    let got = wire(&RcSessionPolicy {
                        clipboard: c,
                        files: f,
                        audio: a,
                    });
                    assert_eq!(
                        got,
                        SessionPolicy {
                            clipboard: want[i],
                            files: want[j],
                            audio: want[k],
                        }
                    );
                }
            }
        }
    }

    /// And both sides spell the values alike, so a stored row and an
    /// `rc:request` read the same words.
    #[test]
    fn both_twins_spell_the_values_alike() {
        for (s, w) in [
            (RcFeaturePolicy::On, FeaturePolicy::On),
            (RcFeaturePolicy::Ask, FeaturePolicy::Ask),
            (RcFeaturePolicy::Off, FeaturePolicy::Off),
        ] {
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::to_value(w).unwrap()
            );
        }
    }

    /// A request's values are read strictly; a typo is refused, not `off`.
    #[test]
    fn a_request_value_is_read_strictly() {
        assert_eq!(strict("files", "on").unwrap(), RcFeaturePolicy::On);
        assert_eq!(strict("files", "ask").unwrap(), RcFeaturePolicy::Ask);
        assert_eq!(strict("files", "off").unwrap(), RcFeaturePolicy::Off);
        for typo in ["Off", "of", "", "no", "false"] {
            assert!(strict("files", typo).is_err(), "{typo:?}");
        }
    }

    /// An unknown key fails the body.
    #[test]
    fn a_misspelt_key_fails_the_body() {
        assert!(
            serde_json::from_value::<RcSessionPolicyUpdate>(
                serde_json::json!({ "clipbaord": "off" })
            )
            .is_err()
        );
        let ok: RcSessionPolicyUpdate =
            serde_json::from_value(serde_json::json!({ "files": "off" })).unwrap();
        assert_eq!(ok.files.as_deref(), Some("off"));
        assert!(ok.clipboard.is_none() && ok.audio.is_none());
    }
}
