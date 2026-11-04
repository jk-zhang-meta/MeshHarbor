// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor — a device owner lists, or creates, the device's login accounts,
//! to choose what an SSH share runs as.
//!
//! Only the device's actual owner — never `MANAGE_AGENTS`, an org admin or a
//! platform admin, the same rule as sharing itself. The device keeps the last
//! word (`agents/meshharbord/src/local_accounts.rs`): nothing unless its own
//! `ssh_enabled` is on, and no administrator under its root ceiling.
use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::device_share::valid_share_account;
use meshharbor_remote_control::{
    error::Error as RcError,
    models::{Agent, AgentStatus, OsKind, RpcCap},
    signaling::{LocalAccount, LocalAccountOp},
};
use meshharbor_services::dao::agent::AgentDao;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::state::AppState;

#[derive(Serialize)]
pub struct AccountsView {
    pub accounts: Vec<LocalAccount>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccount {
    pub name: String,
    #[serde(default)]
    pub admin: bool,
}

/// The device, if the caller actually owns it and it can answer at all.
async fn owned_device(state: &AppState, auth: &AuthUser, id: &str) -> Result<Agent, ApiError> {
    let id =
        ObjectId::parse_str(id).map_err(|_| ApiError::BadRequest("Invalid device ID".into()))?;
    let agent = AgentDao::new(&state.db).base.find_by_id(id).await?;
    if agent.owner_user_id != auth.user_id
        || agent.deleted_at.is_some()
        || agent.status == AgentStatus::Quarantined
    {
        return Err(ApiError::Forbidden(
            "Only the active device owner may do this".into(),
        ));
    }
    let owner = state.users.base.find_by_id(auth.user_id).await?;
    meshharbor_core::admission::require_user(state, &owner, None)?;
    if agent.os == OsKind::Windows {
        return Err(ApiError::BadRequest(
            "Choosing an account for SSH sharing is available on Linux and macOS devices".into(),
        ));
    }
    if !agent.capabilities.has_rpc(RpcCap::LocalAccounts) {
        return Err(ApiError::BadRequest(
            "This device's MeshHarbor version cannot list accounts; update it".into(),
        ));
    }
    Ok(agent)
}

async fn ask(
    state: &AppState,
    agent: &Agent,
    op: LocalAccountOp,
    deadline: Duration,
) -> Result<Vec<LocalAccount>, ApiError> {
    let Some(fleet) = state.modules.fleet.as_ref() else {
        return Err(ApiError::ServiceUnavailable(
            "the fleet module is not mounted on this server".into(),
        ));
    };
    let agent_id = agent
        .id
        .ok_or_else(|| ApiError::Internal("device row without an id".into()))?;
    match fleet
        .rc_hub
        .local_accounts(agent_id, agent.tenant_id, op, deadline)
        .await
    {
        Ok(Ok(accounts)) => Ok(accounts),
        // The device's own refusal, for its owner to read. Bounded: it is text
        // from the device, shown in a page.
        Ok(Err(reason)) => Err(ApiError::BadRequest(format!(
            "The device refused: {}",
            reason.chars().take(300).collect::<String>()
        ))),
        Err(RcError::AgentOffline(_)) => Err(ApiError::Conflict(
            "The device is not connected to this server".into(),
        )),
        Err(RcError::ExecTimeout(_)) => Err(ApiError::ServiceUnavailable(
            "The device did not answer in time".into(),
        )),
        Err(e) => Err(ApiError::Internal(format!("asking the device: {e}"))),
    }
}

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AccountsView>, ApiError> {
    let agent = owned_device(&state, &auth, &id).await?;
    let accounts = ask(
        &state,
        &agent,
        LocalAccountOp::List,
        Duration::from_secs(10),
    )
    .await?;
    Ok(Json(AccountsView { accounts }))
}

pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<CreateAccount>,
) -> Result<Json<AccountsView>, ApiError> {
    let name = body.name.trim().to_string();
    if !valid_share_account(&name) || name == "root" {
        return Err(ApiError::BadRequest(
            "The account name must be a new Linux/macOS user name (lowercase letters, digits, _ and -)"
                .into(),
        ));
    }
    let agent = owned_device(&state, &auth, &id).await?;
    tracing::info!(
        device = %id, owner = %auth.user_id, account = %name, admin = body.admin,
        "local accounts: owner asked the device to create a share account"
    );
    let accounts = ask(
        &state,
        &agent,
        LocalAccountOp::Create {
            name,
            admin: body.admin,
        },
        Duration::from_secs(30),
    )
    .await?;
    Ok(Json(AccountsView { accounts }))
}
