// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Fleet RPC — the server side of remote command execution.
//!
//! This module is the POLICY DECISION POINT. The agent decides what happens on
//! the box (bounds, redaction, its own `exec_enabled` gate); everything about
//! *who may ask* is decided here, in one place, and written to `exec_audit`
//! whichever way it goes.
//!
//! ## The four gates
//!
//! A request runs only if all four pass. Each is owned by a different party,
//! so no single compromise is sufficient:
//!
//! 1. `TenantSettings.remote_exec_enabled` — the org kill-switch, default off.
//! 2. `permissions::EXEC_DEVICE` on the caller's role. Deliberately not
//!    implied by `MANAGE_AGENTS`, and not part of `DEFAULT_ADMIN`.
//! 3. The device's `ExecPolicy` — mode, allowed users/roles, allowed shells,
//!    and (for the CLI leg) `can_originate` on the ORIGINATING device.
//! 4. The agent's own `exec_enabled` config key, enforced agent-side.
//!
//! Gates 1–3 are evaluated by [`authorize`]; gate 4 comes back as an
//! `ExecOutcome::error`, which is why a refusal is still a 200 with an error
//! body rather than a transport failure.
//!
//! ## Why refusals are audited
//!
//! Every path through [`dispatch`] writes a row. A denied exec is the
//! interesting one — without the row, someone probing which devices will run
//! things for them leaves no trace at all.
//!
//! ## Privilege
//!
//! Root under systemd. On Windows, SYSTEM through the device's service once
//! an administrator anchored it, or the signed-in user if its policy says
//! `console_user` (FR-94, `crate::exec_service`); a device that is not
//! anchored runs commands as its console-session worker, the signed-in user
//! on an attended install and SYSTEM in SystemContext mode. Enabling gate 3 on
//! a device is granting root on it, and the admin UI says so in those words.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::{
    error::Error as HubError,
    models::{
        Agent, ExecAuditEvent, ExecDenyReason, ExecMode, ExecOutcome, ExecPending, ExecPolicy,
        ExecRunAs, OsKind, RpcCap, exec_limits,
    },
    signaling::ServerMsg,
};
use meshharbor_services::dao::base::PaginationParams;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};

use crate::FleetState;

/// How long the server waits for a device's answer beyond the command's own
/// budget. Generous on purpose: the agent answers its OWN timeout, and
/// "timed out after 30000ms" from the device is strictly more useful than the
/// server giving up first and reporting nothing about what happened.
const RESULT_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// Extra patience for a device whose policy PROMPTS: the agent waits for a
/// human before the command's own budget even starts.
///
/// Mirrors `meshharbord::consent::DEFAULT_PROMPT_TIMEOUT` (30 s), duplicated
/// rather than imported because the API crate must not depend on the agent
/// binary's crate. Without it, an attended device would routinely report a
/// false "no answer within Ns" while the command was in fact running — the
/// worst kind of diagnostic, one that lies about the thing being diagnosed.
const CONSENT_GRACE: std::time::Duration = std::time::Duration::from_secs(35);

/// Cap on a bulk fan-out, so one request can't tie up every worker.
const MAX_BULK_TARGETS: usize = 64;
/// How many devices a bulk request talks to at once.
const BULK_CONCURRENCY: usize = 8;

// ────────────────────────────────────────────────────────────────────────────
// Wire types
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExecRequestBody {
    /// `pwsh` | `powershell` | `cmd` | `bash` | `sh`. Empty ⇒ the host default.
    #[serde(default)]
    pub shell: String,
    pub command: String,
    /// 0 ⇒ the built-in default; clamped to [`exec_limits::MAX_TIMEOUT_MS`].
    #[serde(default)]
    pub timeout_ms: u64,
    /// 0 ⇒ the built-in default; clamped to [`exec_limits::MAX_OUTPUT_BYTES`].
    #[serde(default)]
    pub max_output_bytes: u64,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecResponse {
    /// Echoed so the caller can address a cancel.
    pub request_id: String,
    pub agent_id: String,
    pub agent_name: String,
    #[serde(flatten)]
    pub outcome: ExecOutcome,
}

#[derive(Debug, Deserialize)]
pub struct BulkExecRequestBody {
    /// Devices to run on, by hex id. Empty ⇒ every device in the org whose
    /// `ExecPolicy` is on — "run this everywhere it's allowed", which is the
    /// fleet-sweep the feature exists for.
    #[serde(default)]
    pub agent_ids: Vec<String>,
    #[serde(flatten)]
    pub exec: ExecRequestBody,
}

#[derive(Debug, Serialize)]
pub struct BulkExecResponse {
    pub results: Vec<ExecResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecPolicyBody {
    #[serde(default)]
    pub mode: ExecMode,
    #[serde(default)]
    pub can_originate: bool,
    #[serde(default)]
    pub allowed_user_ids: Vec<String>,
    #[serde(default)]
    pub allowed_role_ids: Vec<String>,
    #[serde(default)]
    pub consent_mode: Option<meshharbor_remote_control::models::ConsentMode>,
    #[serde(default)]
    pub shells: Vec<String>,
    /// FR-94 P4 — `system` or `console_user`. Always present when read back.
    /// In a PUT, absent means "leave it as it is": this PUT is a full replace,
    /// and a client from before FR-94 (or a stale tab) saving the policy must
    /// not turn `console_user` back into SYSTEM, a quiet escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as: Option<ExecRunAs>,
}

impl From<ExecPolicy> for ExecPolicyBody {
    /// The stored policy as the dashboard reads it back — hex ids, because
    /// bson's `ObjectId` serialises to `{"$oid": …}` and no client here parses
    /// that.
    ///
    /// The source is destructured EXHAUSTIVELY on purpose, the same rule
    /// `SshPolicy::split` follows: this projection is what a dialog re-saves,
    /// so a field added to [`ExecPolicy`] and forgotten here would not be a
    /// missing readout — it would be a field the next save silently resets to
    /// its default. Failing to compile is the cheap version of that bug.
    fn from(p: ExecPolicy) -> Self {
        let ExecPolicy {
            mode,
            can_originate,
            allowed_user_ids,
            allowed_role_ids,
            consent_mode,
            shells,
            run_as,
        } = p;
        Self {
            mode,
            can_originate,
            allowed_user_ids: allowed_user_ids.iter().map(|i| i.to_hex()).collect(),
            allowed_role_ids: allowed_role_ids.iter().map(|i| i.to_hex()).collect(),
            consent_mode,
            shells,
            run_as: Some(run_as),
        }
    }
}

/// One audit row as the API renders it.
///
/// Deliberately NOT `ExecAuditEvent` straight off the wire: bson's `ObjectId`
/// and `DateTime` serialise to extended JSON (`{"$oid": …}` / `{"$date": …}`),
/// which no client here parses. Every other route in this codebase projects
/// through a DTO with hex ids + RFC3339 timestamps, and this one has to as
/// well or the audit table renders `[object Object]`.
#[derive(Debug, Serialize)]
pub struct ExecAuditRow {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_agent_id: Option<String>,
    pub request_id: String,
    pub source: String,
    pub shell: String,
    pub command: String,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<ExecDenyReason>,
    pub output_sample: String,
    pub output_sha256: String,
    pub output_bytes: u64,
    pub truncated: bool,
    /// FR-94 — `system` / `console_user` / `worker`; absent on a refusal and
    /// on rows written before FR-94.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<String>,
}

impl From<ExecAuditEvent> for ExecAuditRow {
    fn from(e: ExecAuditEvent) -> Self {
        Self {
            id: e.id.map(|i| i.to_hex()).unwrap_or_default(),
            tenant_id: e.tenant_id.to_hex(),
            agent_id: e.agent_id.to_hex(),
            user_id: e.user_id.to_hex(),
            origin_agent_id: e.origin_agent_id.map(|i| i.to_hex()),
            request_id: e.request_id,
            source: e.source,
            shell: e.shell,
            command: e.command,
            at: e.at.try_to_rfc3339_string().unwrap_or_default(),
            exit_code: e.exit_code,
            duration_ms: e.duration_ms,
            denied: e.denied,
            output_sample: e.output_sample,
            output_sha256: e.output_sha256,
            output_bytes: e.output_bytes,
            truncated: e.truncated,
            ran_as: e.ran_as,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ExecAuditResponse {
    pub items: Vec<ExecAuditRow>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

// ────────────────────────────────────────────────────────────────────────────
// Authorization
// ────────────────────────────────────────────────────────────────────────────

/// The acting principal, and how it reached us.
pub struct Caller {
    pub user_id: ObjectId,
    pub display: String,
    /// Set on the CLI leg — the device whose LocalAPI originated the request.
    pub origin_agent_id: Option<ObjectId>,
    /// `cli` | `ui` | `api`.
    pub source: &'static str,
}

/// Evaluate gates 1–3. `Ok(())` means the command may be pushed; `Err` carries
/// the reason, which the caller must audit before returning it.
///
/// Split out from [`dispatch`] so the whole decision is testable as a table
/// and so no path can accidentally skip a gate by taking a different route
/// into the push.
pub async fn authorize(
    state: &FleetState,
    tenant_id: ObjectId,
    agent: &Agent,
    caller: &Caller,
    shell: &str,
) -> Result<(), ExecDenyReason> {
    // Gate 1 — the org kill-switch. Checked first because it is the cheapest
    // and the most likely reason a fleet says no.
    let tenant = match state.tenants.base.find_by_id(tenant_id).await {
        Ok(t) => t,
        Err(_) => return Err(ExecDenyReason::OrgDisabled),
    };
    if !tenant.settings.remote_exec_enabled {
        return Err(ExecDenyReason::OrgDisabled);
    }

    // Gate 2 — the caller's role.
    let perms = state
        .tenants
        .get_member_permissions(tenant_id, caller.user_id)
        .await
        .unwrap_or(0);
    if !permissions::has(perms, permissions::EXEC_DEVICE) {
        return Err(ExecDenyReason::NoPermission);
    }

    // Gate 3 — the target device's own policy.
    let policy = &agent.exec_policy;
    if policy.mode != ExecMode::On {
        return Err(ExecDenyReason::DeviceDisabled);
    }
    if !policy.allowed_user_ids.is_empty() && !policy.allowed_user_ids.contains(&caller.user_id) {
        return Err(ExecDenyReason::CallerNotAllowed);
    }
    if !policy.allowed_role_ids.is_empty() {
        let role_ids = state
            .tenants
            .member_role_ids(tenant_id, caller.user_id)
            .await
            .unwrap_or_default();
        if !role_ids.iter().any(|r| policy.allowed_role_ids.contains(r)) {
            return Err(ExecDenyReason::CallerNotAllowed);
        }
    }
    if !policy.allows_shell(shell) {
        return Err(ExecDenyReason::ShellNotAllowed);
    }

    // The CLI leg only: the ORIGINATING device must be blessed. Without this,
    // compromising any enrolled laptop would inherit its owner's exec rights
    // across the whole fleet. LIVE: a removed device cannot originate,
    // whatever `can_originate` its tombstone still says (#1821).
    if let Some(origin) = caller.origin_agent_id {
        match state.agents.find_live_in_tenant(tenant_id, origin).await {
            Ok(a) if a.exec_policy.can_originate => {}
            _ => return Err(ExecDenyReason::OriginNotAllowed),
        }
    }

    // FR-94 — the org requires Windows commands to run as SYSTEM, and this
    // Windows device cannot: refuse rather than run as the signed-in user.
    // Here, inside `authorize`, so every entry point (the HTTP route, a bulk
    // fan-out, a device's `rc:rpc.request`) obeys it. A gate applied at one
    // entry point only would be a courtesy.
    if matches!(agent.os, OsKind::Windows)
        && !crate::exec_service::routes_via_service(state, agent)
        && state
            .tenants
            .base
            .find_by_id(tenant_id)
            .await
            .map(|t| t.settings.exec_require_system)
            // A failed read cannot prove the org allows the worker. Refuse.
            .unwrap_or(true)
    {
        return Err(ExecDenyReason::SystemRequired);
    }

    // FR-94 P4 — a policy that runs commands as the signed-in user needs the
    // device's SYSTEM service on Windows: only SYSTEM may ask for the console
    // user's token. Without that path the command would run as the worker,
    // which in SystemContext mode is SYSTEM, the opposite of what the policy
    // says. FR-97 P5a — a Linux or macOS daemon drops to the person at its
    // screen itself, which only a build advertising `console-user` does.
    if agent.exec_policy.run_as == ExecRunAs::ConsoleUser
        && !crate::exec_service::routes_via_service(state, agent)
        && !drops_to_console_user(state, agent)
    {
        return Err(ExecDenyReason::RunAsUnavailable);
    }

    // Ceiling, enforced LAST so a refusal is attributable to an identity that
    // already passed the gates (and is audited by `dispatch`) rather than an
    // anonymous throttle. This is the one place both the HTTP route and the
    // device's `rc:rpc.request` leg pass through — the WS leg never touches
    // the per-IP HTTP governor, so without this it had no ceiling at all.
    if !state.exec_rate_limiter.check(
        caller.user_id,
        agent.id.unwrap_or_default(),
        exec_limits::RATE_LIMIT_PER_MINUTE,
    ) {
        return Err(ExecDenyReason::RateLimited);
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Dispatch
// ────────────────────────────────────────────────────────────────────────────

/// Gate, push, await, audit. The ONE path a command takes, whether it came
/// from the browser, the CLI, or a bulk fan-out.
pub async fn dispatch(
    state: &FleetState,
    tenant_id: ObjectId,
    agent: &Agent,
    caller: &Caller,
    body: &ExecRequestBody,
) -> ExecResponse {
    let agent_id = agent.id.unwrap_or_default();
    let request_id = ObjectId::new().to_hex();
    // Resolve BEFORE the allowlist check, and send the resolved name on the
    // wire, so the policy decision and the execution can never disagree about
    // which shell ran. An empty request means "the host default", which the
    // allowlist must be compared against by NAME — not as a literal "".
    let shell = ExecPolicy::resolve_shell(&body.shell, agent.os);
    let timeout_ms = exec_limits::clamp_timeout_ms(body.timeout_ms);
    let max_output_bytes = exec_limits::clamp_output_bytes(body.max_output_bytes);

    let mut audit = ExecAuditEvent {
        id: None,
        tenant_id,
        agent_id,
        user_id: caller.user_id,
        origin_agent_id: caller.origin_agent_id,
        request_id: request_id.clone(),
        source: caller.source.to_string(),
        shell: shell.clone(),
        command: body.command.clone(),
        at: DateTime::now(),
        exit_code: None,
        duration_ms: None,
        denied: None,
        output_sample: String::new(),
        output_sha256: String::new(),
        output_bytes: 0,
        truncated: false,
        // Set once the command runs; a refusal names no identity.
        ran_as: None,
    };

    let deny = |mut audit: ExecAuditEvent, reason: ExecDenyReason, message: String| {
        audit.denied = Some(reason);
        (
            audit,
            ExecOutcome {
                error: Some(message),
                ..Default::default()
            },
        )
    };

    let (audit, outcome) = match authorize(state, tenant_id, agent, caller, &shell).await {
        Err(reason) => {
            let message = deny_message(reason, agent.os);
            warn!(
                %agent_id, user = %caller.user_id, ?reason,
                "fleet-rpc: refused"
            );
            deny(audit, reason, message)
        }
        Ok(()) => {
            let consent_mode = agent.exec_policy.effective_consent_mode();
            // FR-94 — a Windows device anchored for SYSTEM exec gets the
            // command through its service; every other device, as before.
            let via_service = crate::exec_service::routes_via_service(state, agent);
            let run_as = agent.exec_policy.run_as;
            // FR-97 P5a — a `console_user` command that takes no SYSTEM
            // service goes to a Linux or macOS daemon that drops to the person
            // at its screen (`authorize` refused every other device), told so
            // in the frame. The hub refuses the push to a connection without
            // the word.
            let as_person = run_as == ExecRunAs::ConsoleUser && !via_service;
            let msg = ServerMsg::RpcExec {
                request_id: request_id.clone(),
                shell: shell.clone(),
                command: body.command.clone(),
                timeout_ms,
                max_output_bytes,
                cwd: body.cwd.clone(),
                caller: caller.display.clone(),
                consent_mode: Some(consent_mode),
                via_service,
                run_as: as_person.then(|| run_as.wire().to_string()),
            };
            // An attended device spends up to the prompt window waiting for a
            // human BEFORE the command's own budget starts, so the two are
            // additive — not overlapping.
            let mut deadline = std::time::Duration::from_millis(timeout_ms) + RESULT_GRACE;
            if consent_mode != meshharbor_remote_control::models::ConsentMode::Auto {
                deadline += CONSENT_GRACE;
            }
            let result = if via_service {
                run_via_service(
                    state,
                    tenant_id,
                    agent_id,
                    &request_id,
                    &shell,
                    body,
                    caller,
                    (timeout_ms, max_output_bytes),
                    run_as,
                    msg,
                    deadline,
                )
                .await
            } else {
                state
                    .rc_hub
                    .exec_on_agent(agent_id, tenant_id, request_id.clone(), msg, deadline)
                    .await
            };
            match result {
                Ok(outcome) => {
                    // FR-94 — the server's own routing decision. The device's
                    // claim about its identity rides in `outcome.ran_as`.
                    // FR-97 P5a — and a daemon told to drop to the person at
                    // its screen ran it as `console_user`.
                    audit.ran_as = Some(
                        if via_service || as_person {
                            run_as.wire()
                        } else {
                            "worker"
                        }
                        .to_string(),
                    );
                    audit.exit_code = outcome.exit_code;
                    audit.duration_ms = Some(outcome.duration_ms);
                    audit.truncated = outcome.truncated;
                    let combined = format!("{}{}", outcome.stdout, outcome.stderr);
                    audit.output_bytes = combined.len() as u64;
                    audit.output_sha256 = hex::encode(Sha256::digest(combined.as_bytes()));
                    audit.output_sample = truncate_sample(&combined);
                    info!(
                        %agent_id, user = %caller.user_id,
                        exit_code = ?outcome.exit_code,
                        duration_ms = outcome.duration_ms,
                        "fleet-rpc: ran"
                    );
                    (audit, outcome)
                }
                // FR-97 P5a — the connection the push found does not drop to
                // the person at the screen (a rollback since `authorize`
                // looked), so the hub sent nothing.
                Err(HubError::ExecUnsupported(_)) if as_person => deny(
                    audit,
                    ExecDenyReason::RunAsUnavailable,
                    deny_message(ExecDenyReason::RunAsUnavailable, agent.os),
                ),
                // The device is online but too old to understand the frame.
                // A distinct reason, because "upgrade the agent" is a
                // completely different action from "turn the feature on".
                Err(HubError::ExecUnsupported(_)) => deny(
                    audit,
                    ExecDenyReason::Unsupported,
                    format!(
                        "device runs agent {} which predates Fleet RPC — update it to use \
                         the device console",
                        agent.agent_version
                    ),
                ),
                Err(HubError::ExecTimeout(_)) => deny(
                    audit,
                    ExecDenyReason::Offline,
                    format!("no answer from the device within {}s", deadline.as_secs()),
                ),
                Err(HubError::AgentOffline(_)) => deny(
                    audit,
                    ExecDenyReason::Offline,
                    "device is offline".to_string(),
                ),
                Err(e) => deny(audit, ExecDenyReason::Offline, e.to_string()),
            }
        }
    };

    // Best-effort: the audit write must never gate the command's result. A
    // dropped row is logged loudly because it is the record someone will look
    // for later.
    if let Err(e) = state.exec_audit.record(audit).await {
        warn!(%agent_id, %e, "fleet-rpc: audit write failed");
    }

    ExecResponse {
        request_id,
        agent_id: agent_id.to_hex(),
        agent_name: agent.name.clone(),
        outcome,
    }
}

/// FR-94 — how long a pending row outlives its claim deadline, so that a
/// result arriving late still finds it before the TTL monitor deletes it.
const PENDING_RETAIN_MS: i64 = 10 * 60 * 1000;

/// FR-94 — how long after the dispatch (and after any consent prompt) the
/// SYSTEM service may still claim a command. Shorter than [`RESULT_GRACE`]
/// on purpose: a command claimed at the last moment still gets its full
/// `timeout_ms`, and its result the difference, before the caller gives up.
const CLAIM_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// FR-94 — the SYSTEM-service path: queue the command where the service
/// will claim it, push the frame, and wait on both this pod's waiter and the
/// shared row ([`crate::exec_service::await_service_result`]).
///
/// The claim closes early enough that whatever starts can also finish while
/// the caller still waits: the consent window if there is one, then
/// [`CLAIM_WINDOW`]. Nothing may start that nobody will hear the end of.
#[allow(clippy::too_many_arguments)]
async fn run_via_service(
    state: &FleetState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    request_id: &str,
    shell: &str,
    body: &ExecRequestBody,
    caller: &Caller,
    (timeout_ms, max_output_bytes): (u64, u64),
    run_as: ExecRunAs,
    msg: ServerMsg,
    deadline: std::time::Duration,
) -> Result<ExecOutcome, HubError> {
    let now_ms = DateTime::now().timestamp_millis();
    let ms = |d: std::time::Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX / 4);
    // `deadline` is `timeout + RESULT_GRACE`, plus `CONSENT_GRACE` when a
    // prompt comes first; take the command's own budget and the result
    // grace back out, and what is left is the prompt.
    let prompt =
        deadline.saturating_sub(std::time::Duration::from_millis(timeout_ms) + RESULT_GRACE);
    let claim_by_ms = now_ms + ms(prompt + CLAIM_WINDOW);
    let row = ExecPending {
        id: None,
        request_id: request_id.to_string(),
        tenant_id,
        agent_id,
        shell: shell.to_string(),
        command: body.command.clone(),
        timeout_ms,
        max_output_bytes,
        cwd: body.cwd.clone(),
        caller: caller.display.clone(),
        run_as: run_as.wire().to_string(),
        state: ExecPending::PENDING.to_string(),
        created_at: DateTime::from_millis(now_ms),
        claim_by: DateTime::from_millis(claim_by_ms),
        expires_at: DateTime::from_millis(now_ms + ms(deadline) + PENDING_RETAIN_MS),
        claimed_at: None,
        outcome: None,
    };
    if let Err(e) = state.exec_pending.insert(&row).await {
        // Nothing was pushed, so nothing can run. Reported as a failed send,
        // which is what it is from the caller's side.
        warn!(
            %agent_id, %request_id, %e,
            "fleet-rpc: could not queue the command for the device's SYSTEM service"
        );
        return Err(HubError::SendFailed);
    }
    let started = match state
        .rc_hub
        .start_exec(agent_id, tenant_id, request_id.to_string(), msg)
    {
        Ok(started) => started,
        Err(e) => {
            // The frame never left, so no doorbell can ring; withdraw the row
            // anyway, so "pending" only ever means "may still run".
            if let Err(ce) = state.exec_pending.cancel(request_id, tenant_id).await {
                warn!(%request_id, %ce, "fleet-rpc: could not withdraw an unsent command");
            }
            return Err(e);
        }
    };
    crate::exec_service::await_service_result(
        state, started, tenant_id, agent_id, request_id, deadline,
    )
    .await
}

/// What the caller reads for a refusal. `os` is the device's: FR-97 P5a's
/// `console_user` is a different path on Windows and off it.
fn deny_message(reason: ExecDenyReason, os: OsKind) -> String {
    match reason {
        ExecDenyReason::OrgDisabled => {
            "remote execution is disabled for this organization".to_string()
        }
        ExecDenyReason::NoPermission => {
            "you do not have the EXEC_DEVICE permission in this organization".to_string()
        }
        ExecDenyReason::DeviceDisabled => {
            "remote execution is not enabled on this device".to_string()
        }
        ExecDenyReason::CallerNotAllowed => {
            "this device does not allow remote execution by you".to_string()
        }
        ExecDenyReason::ShellNotAllowed => "this device does not allow that shell".to_string(),
        ExecDenyReason::OriginNotAllowed => {
            "this device is not permitted to originate remote execution".to_string()
        }
        ExecDenyReason::Unsupported => "device does not support Fleet RPC".to_string(),
        ExecDenyReason::Offline => "device is offline".to_string(),
        ExecDenyReason::ConsentDenied => {
            "the operator at the device did not approve the command".to_string()
        }
        ExecDenyReason::RateLimited => "too many commands for this device".to_string(),
        ExecDenyReason::AgentDisabled => {
            "remote execution is disabled on the device itself".to_string()
        }
        ExecDenyReason::SystemRequired => {
            "this organization requires Windows commands to run as SYSTEM, and this device \
             cannot: an administrator has not anchored it (`meshharbord anchor`), or its service \
             is not running"
                .to_string()
        }
        ExecDenyReason::ClaimRefused => {
            "the device's service claimed a command that is not pending for it".to_string()
        }
        ExecDenyReason::RunAsUnavailable if matches!(os, OsKind::Windows) => {
            "this device's policy runs commands as the signed-in user, which only its SYSTEM \
             service can do: an administrator has not anchored it (`meshharbord anchor`), or its \
             service is not running"
                .to_string()
        }
        // FR-97 P5a — off Windows the daemon itself drops to that person, and
        // only a build that advertises `console-user` does.
        ExecDenyReason::RunAsUnavailable => {
            "this device's policy runs commands as the person at its screen, and the agent it \
             runs cannot: update the agent"
                .to_string()
        }
    }
}

/// FR-97 P5a — may a `console_user` command go to this device's own process,
/// which drops to the person at its screen? A Linux or macOS device whose
/// connection here advertises `console-user`, or one connected to no pod
/// here: its push answers "offline", which is the truth, and the hub checks
/// the word again at the push (`Hub::exec_on_agent`). Windows reaches that
/// person only through its SYSTEM service (FR-94).
fn drops_to_console_user(state: &FleetState, agent: &Agent) -> bool {
    if matches!(agent.os, OsKind::Windows) {
        return false;
    }
    // Not connected here (`None`): let the push say "offline".
    agent
        .id
        .and_then(|id| state.rc_hub.agent_supports_console_user(id))
        .unwrap_or(true)
}

/// Trim the persisted output sample on a CHARACTER boundary — a byte-slice of
/// UTF-8 output would panic the moment a command prints anything non-ASCII,
/// which on a German-locale Windows host is immediately.
fn truncate_sample(s: &str) -> String {
    if s.len() <= ExecAuditEvent::SAMPLE_BYTES {
        return s.to_string();
    }
    let mut end = ExecAuditEvent::SAMPLE_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP handlers
// ────────────────────────────────────────────────────────────────────────────

async fn tenant_of(tenant_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(tenant_id).map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))
}

/// Parse the tenant AND require the caller to be a member of it.
///
/// Gate 2 (`EXEC_DEVICE`) is evaluated inside [`authorize`] so a refusal is
/// AUDITED rather than turned into a bare 403 — but that means the handler
/// would otherwise reach the device lookup on behalf of a total stranger, and
/// the response body names devices (`agent_name`, and on a bulk sweep the
/// whole roster). Membership is the cheap check that stops a non-member
/// enumerating a fleet by asking it to run something.
async fn member_tenant(
    state: &FleetState,
    tenant_id: &str,
    auth: &AuthUser,
) -> Result<ObjectId, ApiError> {
    let tid = tenant_of(tenant_id).await?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    Ok(tid)
}

async fn load_agent(
    state: &FleetState,
    tenant_id: ObjectId,
    agent_id: &str,
) -> Result<Agent, ApiError> {
    let aid = ObjectId::parse_str(agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
    // LIVE: the exec target, the cancel target and the policy write all come
    // through here, and none of them has a meaning for a removed device.
    Ok(state.agents.find_live_in_tenant(tenant_id, aid).await?)
}

/// Resolve the acting principal for a browser/API caller.
async fn http_caller(state: &FleetState, auth: &AuthUser) -> Caller {
    let display = state
        .users
        .base
        .find_by_id(auth.user_id)
        .await
        .map(|u| u.display_name)
        .unwrap_or_else(|_| auth.user_id.to_hex());
    Caller {
        user_id: auth.user_id,
        display,
        origin_agent_id: None,
        source: "ui",
    }
}

/// `POST /api/tenant/{tenant_id}/agent/{agent_id}/exec`
///
/// Always 200 when the request itself was well-formed: a policy refusal is a
/// result (`outcome.error`), not a transport error, so the caller renders one
/// consistent shape and the audit row is the source of truth either way.
pub async fn exec(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<ExecRequestBody>,
) -> Result<Json<ExecResponse>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    if body.command.trim().is_empty() {
        return Err(ApiError::BadRequest("command must not be empty".into()));
    }
    let agent = load_agent(&state, tid, &agent_id).await?;
    let caller = http_caller(&state, &auth).await;
    Ok(Json(dispatch(&state, tid, &agent, &caller, &body).await))
}

/// `POST /api/tenant/{tenant_id}/agent/exec` — the fleet sweep.
///
/// An empty `agent_ids` means "every device whose policy allows it", which is
/// the whole point: `meshharbor exec --all -- <probe>` across a heterogeneous
/// fleet in one round-trip.
pub async fn exec_bulk(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<BulkExecRequestBody>,
) -> Result<Json<BulkExecResponse>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    if body.exec.command.trim().is_empty() {
        return Err(ApiError::BadRequest("command must not be empty".into()));
    }

    let agents: Vec<Agent> = if body.agent_ids.is_empty() {
        // One page wide enough to cover any fleet we'd sweep in a single
        // request — the MAX_BULK_TARGETS check below is the real bound, and
        // silently paginating here would make "--all" quietly mean "the first
        // 20 devices", which is exactly the kind of unannounced cap that
        // makes a sweep look complete when it isn't.
        let page = state
            .agents
            .list_for_tenant(
                tid,
                &PaginationParams {
                    page: 1,
                    per_page: (MAX_BULK_TARGETS + 1) as u64,
                    before: None,
                },
            )
            .await?;
        page.items
            .into_iter()
            .filter(|a| a.exec_policy.mode == ExecMode::On)
            .collect()
    } else {
        let mut out = Vec::new();
        for id in &body.agent_ids {
            out.push(load_agent(&state, tid, id).await?);
        }
        out
    };

    if agents.len() > MAX_BULK_TARGETS {
        return Err(ApiError::BadRequest(format!(
            "too many devices ({}); the per-request limit is {MAX_BULK_TARGETS}",
            agents.len()
        )));
    }

    let caller = http_caller(&state, &auth).await;
    let exec_body = &body.exec;
    // Bounded concurrency: a fleet sweep must not open one task per device and
    // starve the rest of the pod.
    let mut results = Vec::with_capacity(agents.len());
    for chunk in agents.chunks(BULK_CONCURRENCY) {
        let runs = chunk
            .iter()
            .map(|a| dispatch(&state, tid, a, &caller, exec_body));
        results.extend(futures::future::join_all(runs).await);
    }
    Ok(Json(BulkExecResponse { results }))
}

/// `POST /api/tenant/{tenant_id}/agent/{agent_id}/exec/{request_id}/cancel`
pub async fn cancel(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id, request_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::EXEC_DEVICE,
        "EXEC_DEVICE",
    )
    .await?;
    let agent = load_agent(&state, tid, &agent_id).await?;
    let aid = agent.id.unwrap_or_default();
    // FR-94 — withdraw a command no SYSTEM service has claimed yet, so a late
    // doorbell can never start it. A claimed one is the device's to stop,
    // through the `rc:rpc.cancel` below. Best-effort: there is no row unless
    // the command took the service path.
    if let Err(e) = state.exec_pending.cancel(&request_id, tid).await {
        warn!(%aid, %request_id, %e, "fleet-rpc: could not withdraw a pending command");
    }
    match state.rc_hub.cancel_exec(aid, tid, request_id) {
        Ok(()) => Ok(Json(serde_json::json!({ "ok": true }))),
        Err(e) => Err(ApiError::BadRequest(e.to_string())),
    }
}

/// `PUT /api/tenant/{tenant_id}/agent/{agent_id}/exec-policy` — gate 3.
///
/// `MANAGE_AGENTS`, like every other device-policy edit. Note this does NOT
/// require `EXEC_DEVICE`: deciding a device may be exec'd is a management act,
/// performing the exec is a separate power.
pub async fn set_policy(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<ExecPolicyBody>,
) -> Result<Json<ExecPolicyBody>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let agent = load_agent(&state, tid, &agent_id).await?;

    let parse_ids = |v: &[String], what: &str| -> Result<Vec<ObjectId>, ApiError> {
        v.iter()
            .map(|s| {
                ObjectId::parse_str(s)
                    .map_err(|_| ApiError::BadRequest(format!("Invalid {what}: {s}")))
            })
            .collect()
    };

    // FR-94 P4 — absent keeps what is stored (see `ExecPolicyBody::run_as`).
    let run_as = body.run_as.unwrap_or(agent.exec_policy.run_as);
    // FR-97 P5a — off Windows the daemon drops to the person at the screen
    // itself, which only a build advertising `console-user` does. Read from
    // the stored hello: a policy is a standing rule, and the hub checks the
    // live connection again at every command.
    if run_as == ExecRunAs::ConsoleUser
        && !matches!(agent.os, OsKind::Windows)
        && !agent.capabilities.has_rpc(RpcCap::ConsoleUser)
    {
        return Err(ApiError::BadRequest(
            "this device's agent cannot run commands as the person at its screen: update it, \
             or run commands as root"
                .into(),
        ));
    }
    let policy = ExecPolicy {
        mode: body.mode,
        can_originate: body.can_originate,
        allowed_user_ids: parse_ids(&body.allowed_user_ids, "user id")?,
        allowed_role_ids: parse_ids(&body.allowed_role_ids, "role id")?,
        consent_mode: body.consent_mode,
        shells: body.shells.clone(),
        run_as,
    };
    state
        .agents
        .update_exec_policy(tid, agent.id.unwrap_or_default(), &policy)
        .await?;
    info!(
        agent = %agent_id, admin = %auth.user_id, mode = ?policy.mode, run_as = run_as.wire(),
        "fleet-rpc: exec policy updated"
    );
    // The policy as stored, so a PUT that left `run_as` out still hears it.
    Ok(Json(ExecPolicyBody::from(policy)))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgExecSettings {
    pub remote_exec_enabled: bool,
    /// FR-94 — refuse a Windows command that cannot run as SYSTEM rather than
    /// run it as the signed-in user. Always present in a response. In a PUT,
    /// absent means "leave it as it is": every client written before FR-94
    /// sends only the kill-switch, and must not reset this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_require_system: Option<bool>,
}

/// `GET /api/tenant/{tenant_id}/exec-settings` — gate 1's current state.
/// Readable by any `MANAGE_AGENTS` admin so the device console can explain
/// *why* every device is refusing before anyone starts editing per-device
/// policy.
pub async fn get_org_settings(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<OrgExecSettings>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let tenant = state.tenants.base.find_by_id(tid).await?;
    Ok(Json(OrgExecSettings {
        remote_exec_enabled: tenant.settings.remote_exec_enabled,
        exec_require_system: Some(tenant.settings.exec_require_system),
    }))
}

/// `PUT /api/tenant/{tenant_id}/exec-settings` — flip gate 1.
///
/// `MANAGE_TENANT`, not `MANAGE_AGENTS`: this one switch decides whether the
/// org's devices can be shelled into at all, which is an org-owner decision
/// rather than a fleet-admin one.
pub async fn set_org_settings(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<OrgExecSettings>,
) -> Result<Json<OrgExecSettings>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await?;
    let mut tenant = state
        .tenants
        .set_remote_exec_enabled(tid, body.remote_exec_enabled)
        .await?;
    warn!(
        tenant = %tenant_id, admin = %auth.user_id,
        enabled = body.remote_exec_enabled,
        "fleet-rpc: org kill-switch changed"
    );
    if let Some(required) = body.exec_require_system {
        tenant = state.tenants.set_exec_require_system(tid, required).await?;
        warn!(
            tenant = %tenant_id, admin = %auth.user_id, required,
            "fleet-rpc: org exec_require_system changed"
        );
    }
    Ok(Json(OrgExecSettings {
        remote_exec_enabled: tenant.settings.remote_exec_enabled,
        exec_require_system: Some(tenant.settings.exec_require_system),
    }))
}

/// ⚠️ The pagination fields are declared INLINE, deliberately not
/// `#[serde(flatten)] page: PaginationParams`.
///
/// `Query` deserializes with `serde_urlencoded`, which hands every value to
/// serde as a **string**. `flatten` forces the fields behind it through
/// `deserialize_any`, and `u64` then rejects `"1"` with "invalid type: string,
/// expected u64" — so the extractor rejected EVERY request with 400 and the
/// admin Command-audit panel showed "API error 400" permanently. It read as
/// "no commands attempted yet", which is why it survived review: the empty
/// state and the broken state look identical.
///
/// Every other paginated route takes `Query<PaginationParams>` directly, with
/// no flatten, which is why this was the only one affected. The other
/// `serde(flatten)` uses in this file are on JSON bodies/responses, where it
/// works fine — it is specifically flatten + urlencoded that breaks.
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_page")]
    pub page: u64,
    #[serde(default = "default_audit_per_page")]
    pub per_page: u64,
    /// ISO 8601 — return only entries created before this instant.
    #[serde(default)]
    pub before: Option<String>,
    /// Narrow to one device.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Narrow to one person — where an incident review starts.
    #[serde(default)]
    pub user_id: Option<String>,
}

fn default_audit_page() -> u64 {
    1
}

fn default_audit_per_page() -> u64 {
    25
}

impl AuditQuery {
    /// The DAO's pagination view of this query.
    fn pagination(&self) -> PaginationParams {
        PaginationParams {
            page: self.page,
            per_page: self.per_page,
            before: self.before.clone(),
        }
    }
}

/// `GET /api/tenant/{tenant_id}/exec-audit`
pub async fn audit(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<ExecAuditResponse>, ApiError> {
    let tid = tenant_of(&tenant_id).await?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::VIEW_EXEC_AUDIT,
        "VIEW_EXEC_AUDIT",
    )
    .await?;

    let pg = q.pagination();
    let page = match (&q.agent_id, &q.user_id) {
        (Some(a), _) => {
            let aid = ObjectId::parse_str(a)
                .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
            state.exec_audit.list_for_agent(tid, aid, &pg).await?
        }
        (None, Some(u)) => {
            let uid = ObjectId::parse_str(u)
                .map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;
            state.exec_audit.list_for_user(tid, uid, &pg).await?
        }
        (None, None) => state.exec_audit.list_for_tenant(tid, &pg).await?,
    };
    Ok(Json(ExecAuditResponse {
        items: page.items.into_iter().map(Into::into).collect(),
        total: page.total,
        page: page.page,
        per_page: page.per_page,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admin panel's exact request. Went through axum's real `Query`
    /// extractor, because the bug was in the EXTRACTOR — `serde_urlencoded`
    /// hands values over as strings and `#[serde(flatten)]` made the `u64`
    /// pagination fields reject them, 400-ing every call. A test that
    /// deserialized the struct some other way would have passed throughout.
    #[test]
    fn audit_query_parses_the_admin_panels_request() {
        use axum::extract::Query;
        let uri: axum::http::Uri =
            "/api/tenant/69a1dbbad2000f26adc875ce/exec-audit?page=1&per_page=50"
                .parse()
                .unwrap();
        let q: Query<AuditQuery> = Query::try_from_uri(&uri).expect("admin panel query must parse");
        assert_eq!(q.page, 1);
        assert_eq!(q.per_page, 50);
        assert!(q.agent_id.is_none());
        assert!(q.user_id.is_none());
        assert_eq!(q.pagination().per_page, 50);
    }

    /// The filters the console history and incident review use, plus the
    /// no-params case (defaults must apply, not 400).
    #[test]
    fn audit_query_parses_filters_and_bare_request() {
        use axum::extract::Query;
        let uri: axum::http::Uri =
            "/x?page=2&per_page=10&agent_id=6a6bd082f326868c85708cea&user_id=69a1dbbad2000f26adc875ce"
                .parse()
                .unwrap();
        let q: Query<AuditQuery> = Query::try_from_uri(&uri).unwrap();
        assert_eq!((q.page, q.per_page), (2, 10));
        assert_eq!(q.agent_id.as_deref(), Some("6a6bd082f326868c85708cea"));
        assert_eq!(q.user_id.as_deref(), Some("69a1dbbad2000f26adc875ce"));

        let bare: axum::http::Uri = "/x".parse().unwrap();
        let q: Query<AuditQuery> = Query::try_from_uri(&bare).expect("no params must default");
        assert_eq!((q.page, q.per_page), (1, 25));
    }

    #[test]
    fn sample_truncation_never_splits_a_char() {
        // A German-locale Windows host prints non-ASCII in the first line of
        // half its diagnostics; a byte-slice here would panic on the first
        // real command.
        let s = "ä".repeat(ExecAuditEvent::SAMPLE_BYTES);
        let out = truncate_sample(&s);
        assert!(out.len() <= ExecAuditEvent::SAMPLE_BYTES);
        assert!(out.chars().all(|c| c == 'ä'));
        // Round-trips as valid UTF-8 by construction — the point of the test.
        assert_eq!(out, String::from_utf8(out.clone().into_bytes()).unwrap());
    }

    #[test]
    fn short_output_is_kept_verbatim() {
        assert_eq!(truncate_sample("hello"), "hello");
        assert_eq!(truncate_sample(""), "");
    }

    #[test]
    fn every_deny_reason_has_an_operator_message() {
        for r in [
            ExecDenyReason::OrgDisabled,
            ExecDenyReason::NoPermission,
            ExecDenyReason::DeviceDisabled,
            ExecDenyReason::CallerNotAllowed,
            ExecDenyReason::ShellNotAllowed,
            ExecDenyReason::OriginNotAllowed,
            ExecDenyReason::Unsupported,
            ExecDenyReason::Offline,
            ExecDenyReason::ConsentDenied,
            ExecDenyReason::RateLimited,
            ExecDenyReason::AgentDisabled,
            ExecDenyReason::SystemRequired,
            ExecDenyReason::ClaimRefused,
            ExecDenyReason::RunAsUnavailable,
        ] {
            for os in [OsKind::Windows, OsKind::Linux, OsKind::Macos] {
                let m = deny_message(r, os);
                assert!(!m.is_empty(), "{r:?} has no message");
                // "Forbidden" tells an operator nothing about which of four
                // gates said no, which is the entire diagnostic value here.
                assert!(m.len() > 15, "{r:?} message is too terse: {m}");
            }
        }
    }

    /// FR-97 P5a — `console_user` unavailable reads as the path that device
    /// takes: its SYSTEM service on Windows, its agent's own drop elsewhere.
    #[test]
    fn console_user_unavailable_names_the_path_its_os_takes() {
        let windows = deny_message(ExecDenyReason::RunAsUnavailable, OsKind::Windows);
        assert!(windows.contains("meshharbord anchor"), "{windows}");
        for os in [OsKind::Linux, OsKind::Macos] {
            let m = deny_message(ExecDenyReason::RunAsUnavailable, os);
            assert!(m.contains("person at its screen"), "{m}");
            assert!(!m.contains("anchor"), "{m}");
        }
    }
}
