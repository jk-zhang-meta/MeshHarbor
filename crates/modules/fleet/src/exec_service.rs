// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-94 — Fleet RPC as SYSTEM on Windows: the anchor, the claim and the
//! result (`docs/fr/FR-94-fleet-rpc-system-on-windows.md`).
//!
//! On an attended Windows install the worker, the process that holds the
//! agent socket, runs as the signed-in user, and its config (agent token,
//! server origin, `exec_enabled`) sits in that user's writable `%APPDATA%`.
//! The SYSTEM service in session 0 therefore takes NOTHING from the worker
//! but a request id:
//!
//! 1. `dispatch` writes the command to `exec_pending` and pushes
//!    `rc:rpc.exec` with `via_service` to the worker.
//! 2. The worker asks for consent as before, then rings the service's
//!    doorbell with the request id alone.
//! 3. The service claims the command HERE with its own credential
//!    (`TokenType::AgentService`, from an anchor only an administrator can
//!    write). The credential is live only while it names the device's
//!    CURRENT anchor, so a re-anchor or an un-anchor revokes it. The claim is
//!    single use and bound to the credential's device. It closes early enough
//!    that what starts can also finish while the caller waits, and the
//!    worker's own answer (a refusal, a declined prompt) withdraws it.
//! 4. The service runs it and posts the outcome HERE, so SYSTEM's output
//!    never passes through a process the user owns.
//!
//! ⚠️ The invariant (FR-94 §4): **nothing the signed-in user can write may
//! decide what SYSTEM runs**. Every check below is on the server side of
//! that line: the device a credential is for, the row's state, the deadline.
//! The doorbell carries no authority at all.

use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::error::Error as HubError;
use meshharbor_remote_control::models::{
    Agent, ExecAnchor, ExecAuditEvent, ExecDenyReason, ExecOutcome, ExecPending, OsKind,
};

use crate::FleetState;
use crate::auth_agent::AuthAgentService;
use crate::hub::StartedExec;

/// Does a command for `agent` go through its SYSTEM service? Only a Windows
/// device that an administrator anchored (the server's record), that is
/// connected to THIS pod and advertising `exec-system` (the device's own
/// word that its service holds that anchor), and only while the server's
/// kill switch (`rc.exec_via_service`) is on.
///
/// Both halves, because each alone routes a command into a timeout: a worker
/// can advertise the word with no anchor behind it, and an anchored device
/// whose service lost its anchor file stops advertising it. Either way the
/// command takes the worker path, or `exec_require_system` refuses it.
pub fn routes_via_service(state: &FleetState, agent: &Agent) -> bool {
    state.settings.rc.exec_via_service
        && matches!(agent.os, OsKind::Windows)
        && agent
            .exec_anchor
            .as_ref()
            .is_some_and(|a| !a.anchor_id.is_empty())
        && agent
            .id
            .is_some_and(|id| state.rc_hub.agent_supports_exec_system(id) == Some(true))
}

// ────────────────────────────────────────────────────────────────────────────
// The anchor
// ────────────────────────────────────────────────────────────────────────────

/// `POST /api/agent/anchor` — body of `meshharbord anchor`, run elevated by an
/// administrator on the device.
#[derive(Debug, Deserialize)]
pub struct AnchorRequest {
    /// A single-use enrollment token from the org's admin. Never the
    /// reusable ephemeral key: anchoring a device for SYSTEM exec is a
    /// deliberate act.
    pub enrollment_token: String,
    /// The device to anchor, as the dashboard shows it. Named explicitly
    /// because the agent's `machine_id` hashes its config path, which on an
    /// attended install lies in the user's profile. An elevated
    /// administrator re-enrolling "this machine" would mint a DIFFERENT row.
    pub agent_id: String,
    /// This host's name. It must match the device's own, so a mistyped id
    /// cannot anchor this host to someone else's device.
    pub host_name: String,
    /// Anchor although `host_name` differs (a host renamed since it
    /// enrolled).
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnchorResponse {
    pub agent_id: String,
    pub tenant_id: String,
    /// The device's name, for `meshharbord anchor` to confirm what it anchored.
    pub name: String,
    /// The SYSTEM service's credential (`TokenType::AgentService`). Shown
    /// once. The server keeps who anchored the device, when, and the anchor's
    /// id, never the credential.
    pub service_token: String,
}

/// Anchor a Windows device for SYSTEM exec: mint its service credential.
///
/// What it checks, in order:
/// - the token is a single-use enrollment token, and the org is not
///   archived;
/// - the device is LIVE in that same org, and is Windows;
/// - the host name matches the device, unless `force`.
///
/// Only then is the token claimed, so a mistake does not burn it.
pub async fn anchor(
    State(state): State<FleetState>,
    Json(body): Json<AnchorRequest>,
) -> Result<Json<AnchorResponse>, ApiError> {
    let claims = state.auth.verify_enrollment_token(&body.enrollment_token)?;
    let tid = ObjectId::parse_str(&claims.tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id claim".to_string()))?;
    let admin_uid = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::BadRequest("Invalid admin user id claim".to_string()))?;

    if state
        .tenants
        .base
        .find_by_id(tid)
        .await
        .map(|t| t.is_archived)
        .unwrap_or(false)
    {
        return Err(ApiError::Forbidden(
            "This organization is archived and anchors no devices".to_string(),
        ));
    }

    let agent_id = ObjectId::parse_str(body.agent_id.trim())
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;
    let agent = state
        .agents
        .find_live_in_tenant(tid, agent_id)
        .await
        .map_err(|e| match e {
            meshharbor_services::dao::base::DaoError::NotFound => {
                ApiError::NotFound("No such device in this organization".to_string())
            }
            other => ApiError::Internal(format!("agent lookup: {other}")),
        })?;
    if !matches!(agent.os, OsKind::Windows) {
        return Err(ApiError::BadRequest(
            "Only a Windows device runs commands through a SYSTEM service. A Linux or macOS \
             daemon already runs them as root"
                .to_string(),
        ));
    }
    let host = body.host_name.trim();
    if !body.force && !host.eq_ignore_ascii_case(agent.name.trim()) {
        return Err(ApiError::Conflict(format!(
            "this device is named {:?}, but this host is {:?}. Check the device id, or pass \
             --force for a host renamed since it enrolled",
            agent.name, host
        )));
    }

    // FR-104 — a token minted with `anchor: true` that ENROLLED this very
    // device may anchor it too: a second use, under its own key, so it
    // happens once. Any other token, and this one for any other device, is
    // the single use it always was (its enrollment already spent it).
    let second_use =
        claims.anchor && agent.enrolled_with_jti.as_deref() == Some(claims.jti.as_str());
    let use_key = if second_use {
        format!("{}:anchor", claims.jti)
    } else {
        claims.jti.clone()
    };
    state
        .used_tokens
        .claim(&use_key, "agent-anchor")
        .await
        .map_err(|e| match e {
            meshharbor_services::dao::base::DaoError::Validation(_) => {
                ApiError::Unauthorized("This enrollment token has already been used".into())
            }
            _ => ApiError::ServiceUnavailable(
                "Could not verify this enrollment token is unused; please retry".into(),
            ),
        })?;

    // A fresh id per anchor: writing it revokes every credential an earlier
    // anchor of this device minted. It binds a signed token, so it needs to
    // be unique, not secret.
    let anchor_id = ObjectId::new().to_hex();
    let service_token = state
        .auth
        .issue_agent_service_token(agent_id, tid, &anchor_id)?;
    let anchor = bson::to_bson(&ExecAnchor {
        anchored_at: DateTime::now(),
        anchored_by: admin_uid,
        anchor_id,
    })
    .map_err(|e| ApiError::Internal(format!("anchor record: {e}")))?;
    state
        .agents
        .base
        .update_by_id(agent_id, doc! { "$set": { "exec_anchor": anchor } })
        .await
        .map_err(|e| ApiError::Internal(format!("anchor record: {e}")))?;
    info!(
        agent = %agent_id, tenant = %tid, admin = %admin_uid,
        with_enrolling_token = second_use,
        "fleet-rpc: device anchored for SYSTEM exec"
    );
    Ok(Json(AnchorResponse {
        agent_id: agent_id.to_hex(),
        tenant_id: tid.to_hex(),
        name: agent.name,
        service_token,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RenewResponse {
    pub service_token: String,
}

/// `POST /api/agent/service/renew`: a fresh credential under the SAME anchor,
/// for a service whose credential is still live. The anchor id does not
/// change, so a lost response costs nothing: the old credential keeps working
/// and the service asks again. What ends a credential is the anchor, never
/// the calendar.
pub async fn renew(
    State(state): State<FleetState>,
    svc: AuthAgentService,
) -> Result<Json<RenewResponse>, ApiError> {
    // `AuthAgentService` has already proved the credential names the current
    // anchor, so this is that anchor's id.
    let anchor_id = svc
        .agent
        .exec_anchor
        .as_ref()
        .map(|a| a.anchor_id.as_str())
        .unwrap_or_default();
    let service_token =
        state
            .auth
            .issue_agent_service_token(svc.agent_id, svc.tenant_id, anchor_id)?;
    info!(agent = %svc.agent_id, "fleet-rpc: SYSTEM service renewed its credential");
    Ok(Json(RenewResponse { service_token }))
}

/// `DELETE /api/tenant/{tenant_id}/agent/{agent_id}/exec-anchor`: revoke the
/// device's SYSTEM service without removing the device. Its credential stops
/// working at once, commands take the worker path again (or are refused under
/// `exec_require_system`), and anchoring again mints a new one.
pub async fn unanchor(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;
    let agent = state.agents.find_live_in_tenant(tid, aid).await?;
    let was_anchored = agent.exec_anchor.is_some();
    state
        .agents
        .base
        .update_by_id(aid, doc! { "$unset": { "exec_anchor": "" } })
        .await
        .map_err(|e| ApiError::Internal(format!("anchor record: {e}")))?;
    warn!(
        agent = %aid, tenant = %tid, admin = %auth.user_id, was_anchored,
        "fleet-rpc: device un-anchored; its SYSTEM service credential is revoked"
    );
    Ok(Json(
        serde_json::json!({ "ok": true, "was_anchored": was_anchored }),
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// The claim and the result
// ────────────────────────────────────────────────────────────────────────────

/// What a claim hands the SYSTEM service: the command, from the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimedExec {
    pub request_id: String,
    pub shell: String,
    pub command: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub caller: String,
    /// `system` or `console_user`.
    pub run_as: String,
}

/// `POST /api/agent/service/rpc/{request_id}/claim`, authenticated with the
/// service's own credential. Single use, this device's only, before the
/// caller's deadline.
///
/// Anything else is a 404 and an audit row (`claim_refused`) with no user
/// and no command: unknown, claimed already, withdrawn, expired, another
/// device's. The reasons are not told apart, so a forged doorbell learns
/// nothing (FR-94 AC4).
pub async fn claim(
    State(state): State<FleetState>,
    svc: AuthAgentService,
    Path(request_id): Path<String>,
) -> Result<Json<ClaimedExec>, ApiError> {
    match state
        .exec_pending
        .claim(&request_id, svc.agent_id, svc.tenant_id)
        .await
    {
        Ok(Some(row)) => {
            info!(
                agent = %svc.agent_id, %request_id, run_as = %row.run_as,
                "fleet-rpc: SYSTEM service claimed a command"
            );
            Ok(Json(ClaimedExec {
                request_id: row.request_id,
                shell: row.shell,
                command: row.command,
                timeout_ms: row.timeout_ms,
                max_output_bytes: row.max_output_bytes,
                cwd: row.cwd,
                caller: row.caller,
                run_as: row.run_as,
            }))
        }
        Ok(None) => {
            warn!(
                agent = %svc.agent_id, %request_id,
                "fleet-rpc: SYSTEM service claimed a command that is not pending for it"
            );
            let audit = ExecAuditEvent {
                id: None,
                tenant_id: svc.tenant_id,
                agent_id: svc.agent_id,
                // No user asked for this: the device's service did.
                user_id: ObjectId::from_bytes([0; 12]),
                origin_agent_id: None,
                request_id: request_id.clone(),
                source: "service-claim".to_string(),
                shell: String::new(),
                command: String::new(),
                at: DateTime::now(),
                exit_code: None,
                duration_ms: None,
                denied: Some(ExecDenyReason::ClaimRefused),
                output_sample: String::new(),
                output_sha256: String::new(),
                output_bytes: 0,
                truncated: false,
                ran_as: None,
            };
            if let Err(e) = state.exec_audit.record(audit).await {
                warn!(agent = %svc.agent_id, %e, "fleet-rpc: audit write failed");
            }
            Err(ApiError::NotFound(
                "no such command is pending for this device".to_string(),
            ))
        }
        Err(e) => Err(ApiError::Internal(format!("exec claim: {e}"))),
    }
}

/// `POST /api/agent/service/rpc/{request_id}/result`: the outcome of a
/// command this device's service claimed. Stored on the shared row, and handed
/// straight to the caller when it waits on this pod.
pub async fn result(
    State(state): State<FleetState>,
    svc: AuthAgentService,
    Path(request_id): Path<String>,
    Json(outcome): Json<ExecOutcome>,
) -> Result<Json<serde_json::Value>, ApiError> {
    match state
        .exec_pending
        .complete(&request_id, svc.agent_id, svc.tenant_id, &outcome)
        .await
    {
        Ok(true) => {
            let delivered_here = state.rc_hub.deliver_exec_result(&request_id, outcome);
            Ok(Json(
                serde_json::json!({ "ok": true, "delivered_here": delivered_here }),
            ))
        }
        Ok(false) => Err(ApiError::NotFound(
            "no such command was claimed by this device".to_string(),
        )),
        Err(e) => Err(ApiError::Internal(format!("exec result: {e}"))),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Waiting
// ────────────────────────────────────────────────────────────────────────────

/// How often a caller re-reads the shared row, in case the result was posted
/// to another pod.
const RESULT_POLL: Duration = Duration::from_millis(400);

/// Wait for the outcome of a command routed through a SYSTEM service. It
/// resolves on whichever comes first:
/// - the waiter registered by [`crate::hub::Hub::start_exec`]: the worker's
///   own `rc:rpc.result` (a refusal, a declined prompt, an unanswered
///   doorbell), or the result route on this pod;
/// - the row turning `done`, after a result posted to any other pod.
///
/// A worker socket that dies does NOT end the wait. The service runs without
/// it, and its result still arrives through the row.
pub(crate) async fn await_service_result(
    state: &FleetState,
    mut started: StartedExec,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    request_id: &str,
    deadline: Duration,
) -> Result<ExecOutcome, HubError> {
    let deadline_at = tokio::time::Instant::now() + deadline;
    let mut waiter_open = true;
    loop {
        tokio::select! {
            r = &mut started.rx, if waiter_open => match r {
                Ok(outcome) => match settle_waiter_answer(state, tenant_id, request_id).await {
                    Settled::Answer => return Ok(outcome),
                    Settled::Row(row_outcome) => return Ok(row_outcome),
                    Settled::Running => waiter_open = false,
                },
                Err(_) => waiter_open = false,
            },
            () = tokio::time::sleep(RESULT_POLL) => {
                match state.exec_pending.outcome(request_id).await {
                    Ok(Some(outcome)) => return Ok(outcome),
                    Ok(None) => {}
                    Err(e) => warn!(%request_id, %e, "fleet-rpc: result poll failed"),
                }
            }
            () = tokio::time::sleep_until(deadline_at) => {
                return Err(HubError::ExecTimeout(agent_id.to_hex()));
            }
        }
    }
}

/// What the waiter's answer means for the row behind it.
enum Settled {
    /// The waiter's answer stands: the row was withdrawn before any claim,
    /// or was never there to claim.
    Answer,
    /// The row is `done`, and its outcome is the answer. If the result route
    /// on this pod fired the waiter they are the same; if the worker spoke
    /// while the service's result landed on another pod, the row is right.
    Row(ExecOutcome),
    /// The service claimed it first: the command IS running, so its result,
    /// not the worker's, is the answer. Keep waiting on the row.
    Running,
}

/// The waiter answers for two senders: the result route on this pod (the row
/// is already `done`), or the WORKER, with a refusal, a declined prompt or a
/// doorbell nobody answered. In the second case the row may still be
/// pending, so it is withdrawn here: a late claim must never run what the
/// caller is about to be told did not run.
async fn settle_waiter_answer(
    state: &FleetState,
    tenant_id: ObjectId,
    request_id: &str,
) -> Settled {
    match state.exec_pending.cancel(request_id, tenant_id).await {
        Ok(true) => return Settled::Answer,
        Ok(false) => {}
        Err(e) => {
            // `claim_by` still bounds how late a claim can come.
            warn!(%request_id, %e, "fleet-rpc: could not withdraw the command");
            return Settled::Answer;
        }
    }
    match state.exec_pending.find(request_id).await {
        Ok(Some(row)) if row.state == ExecPending::CLAIMED => {
            info!(
                %request_id,
                "fleet-rpc: the worker answered, but the SYSTEM service is running the command; \
                 waiting for its result"
            );
            Settled::Running
        }
        Ok(Some(row)) if row.state == ExecPending::DONE => {
            row.outcome.map_or(Settled::Answer, Settled::Row)
        }
        Ok(_) => Settled::Answer,
        Err(e) => {
            warn!(%request_id, %e, "fleet-rpc: could not read the command's row");
            Settled::Answer
        }
    }
}
