//! FR-129 — switching a device's two-factor on or off, from the admin page.
//!
//! The device keeps the secret and checks every code itself; this route only relays the admin's
//! step (`begin` / `confirm` / `disable`) over the device's control socket and waits for the
//! answer, like exec. Nothing secret is stored here: the secret and the recovery codes pass
//! through once, to the admin's browser, and the code a `confirm` or `disable` carries is checked
//! by the device.

use std::sync::LazyLock;
use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::{
    models::{Confidential, RpcCap},
    signaling::{ServerMsg, TwoFactorOp},
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{info, warn};

use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};

use crate::FleetState;

/// How long the admin's request waits for the device.
const DEVICE_ANSWER: Duration = Duration::from_secs(15);

/// The device's answer, as it came.
#[derive(Debug, Clone, Default)]
pub struct DeviceAnswer {
    pub refused: Option<String>,
    pub retry_after_secs: Option<u64>,
    pub enabled: bool,
    pub secret: Option<Confidential>,
    pub otpauth_uri: Option<Confidential>,
    pub setup_id: Option<String>,
    pub recovery_codes: Vec<Confidential>,
}

/// Requests parked on a device's answer, by request id. Pod-local, like the agent socket the
/// answer arrives on (tenant affinity puts both on one pod).
/// Each waiter is bound to the device it asked: an answer on any other agent's socket is
/// ignored, so no other device can answer for this one (or make the page show it on).
static WAITERS: LazyLock<DashMap<String, (ObjectId, oneshot::Sender<DeviceAnswer>)>> =
    LazyLock::new(DashMap::new);

/// Removes a waiter on every return path.
struct WaiterGuard(String);

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        WAITERS.remove(&self.0);
    }
}

/// The agent socket's half: a device's `rc:agent.two_factor_result`, from the agent `from`.
/// `false` when nothing was waiting for that device (late, a request id this pod never issued,
/// or another agent's socket).
pub fn deliver(request_id: &str, from: ObjectId, answer: DeviceAnswer) -> bool {
    match WAITERS.remove_if(request_id, |_, (agent, _)| *agent == from) {
        Some((_, (_, tx))) => tx.send(answer).is_ok(),
        None => false,
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TwoFactorBody {
    Begin,
    Confirm {
        code: Confidential,
        /// The `setup_id` the `begin` answered.
        #[serde(default)]
        setup_id: String,
    },
    Disable {
        code: Confidential,
    },
}

/// What the admin page gets. A refusal by the device is an answer (200, `refused` set), not an
/// HTTP error: the page shows it and lets the person try again.
#[derive(Debug, Serialize, Default)]
pub struct TwoFactorResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otpauth_uri: Option<String>,
    /// `begin`: what the page sends back with `confirm`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recovery_codes: Vec<String>,
}

fn message_for(refused: &str, retry_after: Option<u64>) -> String {
    match refused {
        "already_on" => "two-factor is already on: switch it off first (that needs a code)".into(),
        "already_off" => "two-factor is already off".into(),
        "no_pending" => "the setup expired (10 min) or was never started: start again".into(),
        "not_primary" => {
            "two-factor is machine-wide: switch it from the organization the device joined first"
                .into()
        }
        "storage" => "the device could not save its two-factor state".into(),
        "two_factor_required" => "enter the 6-digit code from the authenticator app".into(),
        "two_factor_invalid" => "the code is wrong, expired or already used".into(),
        "two_factor_locked" => match retry_after {
            Some(s) => format!("too many wrong codes: try again in {s} s"),
            None => "too many wrong codes: try again later".into(),
        },
        "two_factor_unavailable" => "the device cannot read its two-factor state".into(),
        other => format!("refused by the device: {other}"),
    }
}

/// `POST /api/tenant/{tid}/agent/{aid}/two-factor`
pub async fn two_factor(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Json(body): Json<TwoFactorBody>,
) -> Result<Json<TwoFactorResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))?;
    require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_AGENTS,
        "MANAGE_AGENTS",
    )
    .await?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".into()))?;
    let agent = state.agents.find_live_in_tenant(tid, aid).await?;
    // The centre's switch stops new setups. It cannot switch off a device that has two-factor
    // on: only that device's own code (or its local reset) does.
    if !state.settings.app.device_two_factor && !matches!(body, TwoFactorBody::Disable { .. }) {
        return Err(ApiError::Forbidden(
            "two-factor setup is switched off on this server".into(),
        ));
    }
    if !agent.capabilities.has_rpc(RpcCap::TwoFactor) {
        return Err(ApiError::Conflict(
            "this device's agent does not support two-factor: update it first".into(),
        ));
    }
    let step = match &body {
        TwoFactorBody::Begin => "begin",
        TwoFactorBody::Confirm { .. } => "confirm",
        TwoFactorBody::Disable { .. } => "disable",
    };
    let op = match body {
        TwoFactorBody::Begin => TwoFactorOp::Begin {
            account: agent.name.clone(),
        },
        TwoFactorBody::Confirm { code, setup_id } => TwoFactorOp::Confirm { code, setup_id },
        TwoFactorBody::Disable { code } => TwoFactorOp::Disable { code },
    };
    let request_id = ObjectId::new().to_hex();
    let (tx, rx) = oneshot::channel();
    WAITERS.insert(request_id.clone(), (aid, tx));
    let _guard = WaiterGuard(request_id.clone());
    state
        .rc_hub
        .send_to_agent_in_tenant(
            aid,
            tid,
            ServerMsg::TwoFactorSetup {
                request_id: request_id.clone(),
                op,
            },
        )
        .map_err(|_| ApiError::Conflict("the device is not connected".into()))?;
    let answer = match tokio::time::timeout(DEVICE_ANSWER, rx).await {
        Ok(Ok(a)) => a,
        _ => {
            warn!(%aid, user = %auth.user_id, step, "two-factor: the device did not answer");
            return Err(ApiError::ServiceUnavailable(
                "the device did not answer in time".into(),
            ));
        }
    };
    match &answer.refused {
        None => {
            info!(%aid, user = %auth.user_id, step, enabled = answer.enabled, "two-factor: step done")
        }
        Some(r) => {
            warn!(%aid, user = %auth.user_id, step, refused = %r, "two-factor: step refused by the device")
        }
    }
    // The device reports its state in every hello; set it now so the admin page shows it
    // without waiting for a reconnect.
    if answer.refused.is_none()
        && answer.enabled != agent.capabilities.two_factor
        && let Err(e) = state
            .agents
            .set_two_factor_reported(aid, answer.enabled)
            .await
    {
        warn!(%aid, error = %e, "two-factor: could not record the device's state");
    }
    let message = answer
        .refused
        .as_deref()
        .map(|r| message_for(r, answer.retry_after_secs));
    Ok(Json(TwoFactorResponse {
        enabled: answer.enabled,
        refused: answer.refused,
        message,
        retry_after_secs: answer.retry_after_secs,
        secret: answer.secret.map(|s| s.0),
        otpauth_uri: answer.otpauth_uri.map(|s| s.0),
        setup_id: answer.setup_id,
        recovery_codes: answer.recovery_codes.into_iter().map(|c| c.0).collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_late_unknown_or_foreign_answer_finds_no_waiter() {
        let (device, other) = (ObjectId::new(), ObjectId::new());
        assert!(!deliver("nobody-asked", device, DeviceAnswer::default()));
        let (tx, mut rx) = oneshot::channel();
        WAITERS.insert("r1".into(), (device, tx));
        let on = || DeviceAnswer {
            enabled: true,
            ..Default::default()
        };
        assert!(!deliver("r1", other, on()), "another agent cannot answer");
        assert!(deliver("r1", device, on()));
        assert!(rx.try_recv().unwrap().enabled);
        assert!(
            !deliver("r1", device, DeviceAnswer::default()),
            "answered once"
        );
    }

    #[test]
    fn the_body_is_tagged_by_op() {
        let b: TwoFactorBody = serde_json::from_str(r#"{"op":"begin"}"#).unwrap();
        assert!(matches!(b, TwoFactorBody::Begin));
        let b: TwoFactorBody = serde_json::from_str(r#"{"op":"disable","code":"123456"}"#).unwrap();
        assert!(matches!(b, TwoFactorBody::Disable { code } if code.0 == "123456"));
        assert!(serde_json::from_str::<TwoFactorBody>(r#"{"op":"steal"}"#).is_err());
    }
}
