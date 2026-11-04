// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-2b — the vault's gate on a session's role ([`SessionGate`]).
//!
//! `hive` owns the session and never calls the vault, so it asks through
//! core's hook registry at every start that names a role, and at every move
//! (promote, teleport) or fork of a session that holds one: the device the
//! session would run on is part of the question, and a policy may well say
//! "on a build box only".
//!
//! | The ask | Answer |
//! |---|---|
//! | the vault does not serve the organization | deny, `not_served` |
//! | the role is not one of its live roles | deny, `unknown_role` |
//! | the device's `os` is not a spelling the rows store | deny, the reason |
//! | otherwise | Cedar's `role:assume`, with the person in a `Group` per meshharbor role they hold |
//!
//! ⚠️ The decision is RECORDED before it is answered, with the request as
//! it was decided (for `simulate`'s replay): a decision that cannot be
//! recorded is an `Err`, and hive refuses on it.

use async_trait::async_trait;
use bson::DateTime;
use meshharbor_core::{RoleAsk, RoleVerdict, SessionGate};

use crate::VaultState;
use crate::model::VaultAuditEvent;
use crate::policy::{self, Ask, DeviceFacts};
use crate::policy_routes::{decide_for_org, groups_of_member};

pub struct VaultGate {
    pub state: VaultState,
}

impl VaultGate {
    /// Record the decision; the caller answers only once this succeeds.
    async fn record(
        &self,
        ask: &RoleAsk,
        allow: bool,
        reason: &str,
        request: Option<&Ask>,
    ) -> anyhow::Result<()> {
        let ev = VaultAuditEvent {
            id: None,
            tenant_id: ask.tenant_id,
            principal: "user".into(),
            user_id: ask.user_id,
            action: policy::ACTION_ASSUME.into(),
            op: ask.purpose.into(),
            decision: if allow { "allow" } else { "deny" }.into(),
            reason: reason.into(),
            secret_id: None,
            rrn: None,
            field: None,
            n: None,
            target: Some(format!("role:{}", ask.role)),
            session_id: Some(ask.session_id),
            device_id: Some(ask.device_id),
            request: request.map(Ask::to_doc),
            at: DateTime::now(),
        };
        self.state.audit.record(&ev).await?;
        Ok(())
    }

    async fn refuse(&self, ask: &RoleAsk, reason: &str) -> anyhow::Result<RoleVerdict> {
        self.record(ask, false, reason, None).await?;
        Ok(RoleVerdict {
            allow: false,
            reason: reason.into(),
        })
    }
}

#[async_trait]
impl SessionGate for VaultGate {
    async fn role_assume(&self, ask: &RoleAsk) -> anyhow::Result<RoleVerdict> {
        if !self.state.scope.serves(ask.tenant_id) {
            return self.refuse(ask, "not_served").await;
        }
        let roles = self.state.roles.list_live(ask.tenant_id).await?;
        if !roles.iter().any(|r| r.name == ask.role) {
            return self.refuse(ask, "unknown_role").await;
        }
        let device = match DeviceFacts::new(&ask.device_os, &ask.device_tags, ask.device_owner) {
            Ok(d) => d,
            Err(why) => return self.refuse(ask, &format!("device: {why}")).await,
        };
        let request = Ask::AssumeRole {
            user: ask.user_id,
            groups: groups_of_member(&self.state, ask.tenant_id, ask.user_id).await?,
            role: ask.role.clone(),
            device,
        };
        let verdict = decide_for_org(&self.state, ask.tenant_id, &request).await;
        let reason = if !verdict.determining.is_empty() {
            verdict.determining.join(",")
        } else if !verdict.errors.is_empty() {
            format!("undecided: {}", verdict.errors.join("; "))
        } else {
            "default_deny".to_string()
        };
        self.record(ask, verdict.allow, &reason, Some(&request))
            .await?;
        Ok(RoleVerdict {
            allow: verdict.allow,
            reason,
        })
    }
}
