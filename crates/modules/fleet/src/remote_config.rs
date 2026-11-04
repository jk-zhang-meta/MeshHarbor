// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `PUT /api/tenant/{tenant_id}/agent/{agent_id}/desired-config` — record the
//! device config an operator wants, for the agent to reconcile when it next
//! connects. Step 2 of `docs/remote-config.md`.
//!
//! This route writes an INTENT, never a fact. The device is free to ignore it
//! (and does, unless it has opted in via `remote_config_enabled`), so nothing
//! here may be read back as "this device has exec on".

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::models::DesiredConfig;
use serde::{Deserialize, Serialize};

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::FleetState;

#[derive(Debug, Deserialize)]
pub struct DesiredConfigBody {
    #[serde(default)]
    pub exec_enabled: Option<bool>,
    #[serde(default)]
    pub ssh_enabled: Option<bool>,
    #[serde(default)]
    pub ssh_authorized_keys: Option<Vec<String>>,
    #[serde(default)]
    pub ssh_account_mode: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub encoder_cells_deny: Option<String>,
    #[serde(default)]
    pub fps_deny: Option<String>,
}

/// ⚠️ `desired` is the SAME projection the listing returns
/// ([`DesiredConfigView`]), not the stored model.
///
/// Returning the model here shipped `{"$oid": …}` / `{"$date": …}` extended
/// JSON — measured against prod on 2026-08-24 — while `GET …/agent` returned
/// hex + RFC3339 for the identical object. The client keeps the WRITE's answer
/// in its store, so its `updated_at` was an object where its own type said
/// string. A write and a read must not describe one object two ways.
///
/// [`DesiredConfigView`]: crate::agent::DesiredConfigView
#[derive(Debug, Serialize)]
pub struct DesiredConfigResponse {
    pub revision: u64,
    pub desired: crate::agent::DesiredConfigView,
}

/// Why a desired-config write was refused. Enumerated rather than stringly
/// typed for the same reason `SshDenyReason` is: every arm has to be auditable,
/// and a refusal nobody can query is a refusal nobody will notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDenyReason {
    /// Not a member, or missing `MANAGE_AGENTS`.
    NotDeviceAdmin,
    /// Asked to change exec without holding `EXEC_DEVICE`.
    CannotGrantExec,
    /// Asked to change SSH without holding `SSH_DEVICE`.
    CannotGrantSsh,
}

impl ConfigDenyReason {
    pub fn wire(self) -> &'static str {
        match self {
            Self::NotDeviceAdmin => "not_device_admin",
            Self::CannotGrantExec => "cannot_grant_exec",
            Self::CannotGrantSsh => "cannot_grant_ssh",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NotDeviceAdmin => "Missing MANAGE_AGENTS permission",
            Self::CannotGrantExec => {
                "Enabling exec on a device requires EXEC_DEVICE — you cannot open a door you \
                 cannot walk through"
            }
            Self::CannotGrantSsh => {
                "Changing SSH access on a device requires SSH_DEVICE — you cannot open a door \
                 you cannot walk through"
            }
        }
    }
}

/// The whole policy, as one pure function so it can be tested without a
/// database and so every refusal has exactly one place to come from.
///
/// `MANAGE_AGENTS` alone is NOT enough. Enabling exec or SSH on a device is
/// *granting a power*, and #600/#605 established the rule that governs
/// granting: **you cannot grant a permission you do not hold.** An admin who
/// lacks `EXEC_DEVICE` must not be able to open exec on a fleet device for
/// somebody else — that is the same escalation those PRs closed, one level of
/// indirection away.
///
/// Both bits are deliberately absent from `DEFAULT_ADMIN`, which is what makes
/// this a real constraint rather than a formality. `ADMINISTRATOR` bypasses, as
/// everywhere else.
pub fn decide(
    caller_permissions: u64,
    current: &DesiredConfig,
    requested: &DesiredConfig,
) -> Result<(), ConfigDenyReason> {
    if !permissions::has(caller_permissions, permissions::MANAGE_AGENTS) {
        return Err(ConfigDenyReason::NotDeviceAdmin);
    }
    // An UNCHANGED family is not a grant, and #600's `check_grant` says so in
    // the same words: it gates `requested & !current & !held` — only bits being
    // ADDED. Without this carve-out the two grant bits stop composing, which is
    // the whole reason they are separate: on a device where one admin manages
    // exec, an `SSH_DEVICE`-only admin cannot edit SSH at all, because the
    // request necessarily re-states the exec field it must not drop. (Omitting
    // it is not an option — an absent key means UNMANAGED, so a partial body
    // would silently delete the other admin's setting.)
    //
    // Deliberately equality, not an escalation analysis. "Is `["A"]` → `["A",
    // "B"]` a grant?" has an obvious answer and "is `console_user` → `daemon`?"
    // does too, but the general form is a per-field judgement call and getting
    // one wrong opens a hole. Byte-identical is unambiguous, and it is exactly
    // the case that was blocked.
    if !requested.same_exec_as(current)
        && requested.touches_exec()
        && !permissions::has(caller_permissions, permissions::EXEC_DEVICE)
    {
        return Err(ConfigDenyReason::CannotGrantExec);
    }
    if !requested.same_ssh_as(current)
        && requested.touches_ssh()
        && !permissions::has(caller_permissions, permissions::SSH_DEVICE)
    {
        return Err(ConfigDenyReason::CannotGrantSsh);
    }
    Ok(())
}

pub async fn set_desired_config(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<DesiredConfigBody>,
) -> Result<Json<DesiredConfigResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;

    // Membership first: `get_member_permissions` is the membership check too,
    // so a non-member never reaches the policy below.
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;

    // Tenant-scoped, so an agent id from another org is a 404 rather than a
    // cross-tenant read — and LIVE, so a removed device's tombstone cannot
    // keep taking configuration intents nothing will ever reconcile (#1821).
    let agent = state.agents.find_live_in_tenant(tid, aid).await?;

    let requested = DesiredConfig {
        exec_enabled: body.exec_enabled,
        ssh_enabled: body.ssh_enabled,
        ssh_authorized_keys: body.ssh_authorized_keys,
        ssh_account_mode: body.ssh_account_mode,
        ssh_port: body.ssh_port,
        encoder_cells_deny: body.encoder_cells_deny,
        fps_deny: body.fps_deny,
        revision: agent.desired_config.revision + 1,
        updated_by: Some(auth.user_id),
        updated_at: Some(DateTime::now()),
    };

    // ONE call site records both arms. `decide` returning a Result rather than
    // a bool is what makes "a new refusal that forgets to audit itself"
    // unrepresentable — the same shape as `agent_ssh::dispatch`.
    let verdict = decide(perms, &agent.desired_config, &requested);
    if let Err(e) = state
        .config_audit
        .record(
            tid,
            aid,
            auth.user_id,
            &requested,
            verdict.as_ref().err().map(|r| r.wire()),
        )
        .await
    {
        // Best-effort, exactly like ssh_audit: an audit insert must never be
        // what stops a legitimate config change.
        tracing::warn!(%e, "config audit write failed");
    }

    if let Err(reason) = verdict {
        return Err(ApiError::Forbidden(reason.message().to_string()));
    }

    let bson = bson::to_bson(&requested)
        .map_err(|e| ApiError::Internal(format!("serialising desired_config: {e}")))?;
    state
        .agents
        .base
        .update_by_id(aid, doc! { "$set": { "desired_config": bson } })
        .await?;

    Ok(Json(DesiredConfigResponse {
        revision: requested.revision,
        desired: requested.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use permissions::*;

    fn exec_req() -> DesiredConfig {
        DesiredConfig {
            exec_enabled: Some(true),
            ..Default::default()
        }
    }
    fn ssh_req() -> DesiredConfig {
        DesiredConfig {
            ssh_enabled: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn a_non_device_admin_is_refused_before_anything_else() {
        assert_eq!(
            decide(DEFAULT_MEMBER, &DesiredConfig::default(), &exec_req()),
            Err(ConfigDenyReason::NotDeviceAdmin)
        );
        // Even an empty request: managing a device's desired config at all is
        // a MANAGE_AGENTS action.
        assert_eq!(
            decide(0, &DesiredConfig::default(), &DesiredConfig::default()),
            Err(ConfigDenyReason::NotDeviceAdmin)
        );
    }

    #[test]
    fn manage_agents_alone_cannot_open_exec_or_ssh() {
        // The whole point. `DEFAULT_ADMIN` carries MANAGE_AGENTS but neither
        // grant bit — so a default admin may rename a device and may not open
        // a root shell on it.
        assert_eq!(
            decide(DEFAULT_ADMIN, &DesiredConfig::default(), &exec_req()),
            Err(ConfigDenyReason::CannotGrantExec)
        );
        assert_eq!(
            decide(DEFAULT_ADMIN, &DesiredConfig::default(), &ssh_req()),
            Err(ConfigDenyReason::CannotGrantSsh)
        );
    }

    #[test]
    fn holding_the_matching_grant_is_enough() {
        decide(
            DEFAULT_ADMIN | EXEC_DEVICE,
            &DesiredConfig::default(),
            &exec_req(),
        )
        .unwrap();
        decide(
            DEFAULT_ADMIN | SSH_DEVICE,
            &DesiredConfig::default(),
            &ssh_req(),
        )
        .unwrap();
        decide(ADMINISTRATOR, &DesiredConfig::default(), &exec_req()).unwrap();
        decide(ADMINISTRATOR, &DesiredConfig::default(), &ssh_req()).unwrap();
    }

    #[test]
    fn the_grants_do_not_substitute_for_each_other() {
        // EXEC_DEVICE and SSH_DEVICE are separate bits precisely because an
        // SSH session is strictly more than a bounded command.
        assert_eq!(
            decide(
                DEFAULT_ADMIN | EXEC_DEVICE,
                &DesiredConfig::default(),
                &ssh_req()
            ),
            Err(ConfigDenyReason::CannotGrantSsh)
        );
        assert_eq!(
            decide(
                DEFAULT_ADMIN | SSH_DEVICE,
                &DesiredConfig::default(),
                &exec_req()
            ),
            Err(ConfigDenyReason::CannotGrantExec)
        );
    }

    #[test]
    fn every_ssh_key_counts_as_granting_ssh() {
        // Not just `ssh_enabled`: authorized keys decide WHO may connect and
        // `ssh_account_mode` decides what a key-list session may RUN. Handing
        // either out is granting SSH.
        for req in [
            DesiredConfig {
                ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA…".into()]),
                ..Default::default()
            },
            DesiredConfig {
                ssh_account_mode: Some("daemon".into()),
                ..Default::default()
            },
            DesiredConfig {
                ssh_port: Some(2222),
                ..Default::default()
            },
        ] {
            assert_eq!(
                decide(DEFAULT_ADMIN, &DesiredConfig::default(), &req),
                Err(ConfigDenyReason::CannotGrantSsh),
                "{req:?} must require SSH_DEVICE"
            );
        }
    }

    #[test]
    fn an_untouched_surface_needs_only_manage_agents() {
        // Clearing the form is a legitimate MANAGE_AGENTS action and must not
        // demand grant bits the caller never uses.
        decide(
            DEFAULT_ADMIN,
            &DesiredConfig::default(),
            &DesiredConfig::default(),
        )
        .unwrap();
        assert!(DesiredConfig::default().is_empty());
    }

    /// The WRITE must describe an object the same way the READ does.
    ///
    /// Caught in prod on 2026-08-24: `PUT …/desired-config` answered
    /// `"updated_by":{"$oid":…}` / `"updated_at":{"$date":{"$numberLong":…}}`
    /// while `GET …/agent` returned hex + RFC3339 for the identical object.
    /// The client keeps the write's answer in its store, so its `updated_at`
    /// was an object where its own type said string — the same extended-JSON
    /// trap `SshAuditRow` / `ExecAuditRow` were created to avoid, re-opened by
    /// a response type nobody projected.
    #[test]
    fn the_put_response_is_the_same_shape_the_listing_returns() {
        let requested = DesiredConfig {
            exec_enabled: Some(true),
            revision: 1,
            updated_by: Some(bson::oid::ObjectId::new()),
            updated_at: Some(DateTime::now()),
            ..Default::default()
        };
        let body = DesiredConfigResponse {
            revision: requested.revision,
            desired: requested.into(),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(
            !json.contains("$oid") && !json.contains("$date"),
            "extended JSON leaked into the write response: {json}"
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v["desired"]["updated_by"]
                .as_str()
                .is_some_and(|s| s.len() == 24),
            "updated_by must be a 24-char hex id: {json}"
        );
        assert!(
            v["desired"]["updated_at"]
                .as_str()
                .is_some_and(|s| s.contains('T') && s.ends_with('Z')),
            "updated_at must be an RFC3339 string: {json}"
        );
    }

    #[test]
    fn the_opt_in_is_not_expressible_here() {
        // `DesiredConfig` has no `remote_config_enabled` field, so the server
        // cannot ask for it. This test exists to fail loudly if someone adds
        // one: serialising a request must never mention it.
        let json = serde_json::to_string(&exec_req()).unwrap();
        assert!(
            !json.contains("remote_config"),
            "the device opt-in must not be server-settable: {json}"
        );
    }

    /// The two grant bits have to COMPOSE, or making them separate was
    /// pointless.
    ///
    /// The PUT replaces the whole `DesiredConfig`, so an SSH admin editing a
    /// device where somebody else manages exec must re-state the exec field —
    /// omitting it means UNMANAGED, which would silently delete the other
    /// admin's setting. Gating on any *mention* therefore locked them out of
    /// the device entirely. Re-stating a value unchanged grants nothing, which
    /// is the same rule `check_grant` applies to role masks: only bits being
    /// ADDED count.
    #[test]
    fn re_stating_another_admins_setting_unchanged_is_not_granting_it() {
        let current = DesiredConfig {
            exec_enabled: Some(true),
            ..Default::default()
        };
        // An SSH_DEVICE-only admin turns SSH on, carrying exec through as-is.
        let requested = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ..Default::default()
        };
        decide(DEFAULT_ADMIN | SSH_DEVICE, &current, &requested).unwrap();
    }

    /// …and the carve-out is EQUALITY, nothing looser. The moment the value
    /// actually moves, the bit is required again — including the case that
    /// matters most, flipping exec from off to on.
    #[test]
    fn changing_the_value_still_needs_the_bit() {
        let off = DesiredConfig {
            exec_enabled: Some(false),
            ..Default::default()
        };
        let on = DesiredConfig {
            exec_enabled: Some(true),
            ..Default::default()
        };
        assert_eq!(
            decide(DEFAULT_ADMIN | SSH_DEVICE, &off, &on),
            Err(ConfigDenyReason::CannotGrantExec)
        );
        // Adding a key to an existing list is a change, so it needs SSH_DEVICE
        // even though `ssh_enabled` itself did not move.
        let one_key = DesiredConfig {
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA…A".into()]),
            ..Default::default()
        };
        let two_keys = DesiredConfig {
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec![
                "ssh-ed25519 AAAA…A".into(),
                "ssh-ed25519 AAAA…B".into(),
            ]),
            ..Default::default()
        };
        assert_eq!(
            decide(DEFAULT_ADMIN | EXEC_DEVICE, &one_key, &two_keys),
            Err(ConfigDenyReason::CannotGrantSsh)
        );
        // The whole SSH family counts, not just the key list: an account-mode
        // change on an otherwise-identical request is still an SSH change.
        let daemon = DesiredConfig {
            ssh_account_mode: Some("daemon".into()),
            ..one_key.clone()
        };
        assert_eq!(
            decide(DEFAULT_ADMIN | EXEC_DEVICE, &one_key, &daemon),
            Err(ConfigDenyReason::CannotGrantSsh)
        );
    }

    /// Unmanaging a key is not a grant — it stops asking, and the device keeps
    /// whatever it already has. "Stop managing this device" must not require
    /// bits the caller only needed in order to open something.
    #[test]
    fn clearing_the_form_never_needs_a_grant_bit() {
        let current = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA…A".into()]),
            ..Default::default()
        };
        decide(DEFAULT_ADMIN, &current, &DesiredConfig::default()).unwrap();
    }

    /// FR-77 P3 — the cell denylist is the matrix's kill switch, not a
    /// security gate: it only ever REMOVES cells, so a device admin without
    /// either grant bit may push it, and pushing it grants nothing.
    #[test]
    fn the_encoder_denylist_needs_only_manage_agents() {
        let deny = DesiredConfig {
            encoder_cells_deny: Some("hevc_qsv:yuv444,vp9_qsv:yuv444".into()),
            ..Default::default()
        };
        decide(DEFAULT_ADMIN, &DesiredConfig::default(), &deny)
            .expect("MANAGE_AGENTS alone may set the denylist");
        assert!(!deny.touches_exec() && !deny.touches_ssh());
        assert!(!deny.is_empty(), "a denylist-only request is a request");
        assert_eq!(
            decide(0, &DesiredConfig::default(), &deny),
            Err(ConfigDenyReason::NotDeviceAdmin)
        );
    }

    /// FR-119 P2b — the frame-rate denylist is a kill switch the same way:
    /// it only ever REMOVES rates, so `MANAGE_AGENTS` alone may push it.
    #[test]
    fn the_frame_rate_denylist_needs_only_manage_agents() {
        let deny = DesiredConfig {
            fps_deny: Some("hevc_qsv:120,*:144".into()),
            ..Default::default()
        };
        decide(DEFAULT_ADMIN, &DesiredConfig::default(), &deny)
            .expect("MANAGE_AGENTS alone may set the frame-rate denylist");
        assert!(!deny.touches_exec() && !deny.touches_ssh());
        assert!(!deny.is_empty(), "a denylist-only request is a request");
        assert_eq!(
            decide(0, &DesiredConfig::default(), &deny),
            Err(ConfigDenyReason::NotDeviceAdmin)
        );
    }
}
