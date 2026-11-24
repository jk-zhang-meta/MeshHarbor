// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-133 — a device changes hands.
//!
//! A person from another organization signs in on a personal device and
//! chooses to move it there. The device enrolls into the new organization
//! through an ordinary device-login approval (the new org's `MANAGE_AGENTS`),
//! rebinds its primary enrollment, and then asks THIS route to remove its old
//! organization's row.
//!
//! `POST /api/agent/self/unenroll` refuses a permanent device on purpose: a
//! compromised host must not erase its own fleet record. That refusal stays.
//! This route is narrower. It removes the old row only when the request
//! carries BOTH credentials, and the server itself can confirm the new one:
//!
//! ```text
//!   Authorization: Bearer <old agent token>     ── AuthAgent: live row, generation, owner admitted
//!   { "agent_token": <new agent token> }        ── verify + accepted_agent: the same checks
//!        │
//!        ├─ old row: permanent, personal, not temporary, no two-factor
//!        ├─ new row: another tenant, the SAME machine_id, not ephemeral
//!        ├─ new row.enrolled_with_jti ──▶ device_login_requests
//!        │     { enrollment_jti, state: consumed, tenant_id: new tenant,
//!        │       approved_by: new row's owner, decided_at < 10 min ago }
//!        │   claimed ONCE (compare-and-set `moved_agent_id`)
//!        ▼
//!   removal::remove_agent_device(old, "moved_to_other_org")
//!   → audit row in the OLD tenant, notice to its device admins
//! ```
//!
//! Every link of the proof is a row the server wrote: the new row's
//! `enrolled_with_jti` (stamped by `/api/agent/enroll` from the signed token
//! it consumed) and the device-login decision (stamped at the exchange that
//! minted that token). The device asserts nothing but the two credentials it
//! holds. ⚠️ Nothing the old organization records or is told names the new
//! organization, its people or its device: "moved to another organization by
//! a person signed in at the device" is the whole story there.

use axum::{Json, extract::State};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_core::ApiError;
use meshharbor_db::models::role::permissions;
use meshharbor_db::models::{NotificationSource, NotificationType};
use meshharbor_remote_control::models::Agent;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::FleetState;

/// The audit collection: one row per decision this route took about a device
/// of the tenant it is written in. Indexed in `FleetModule::indexes`.
pub const AUDIT_COLLECTION: &str = "device_move_audit";

/// How old the device-login decision behind the new enrollment may be. The
/// exchange stamps `decided_at`, and the request row's TTL (`expires_at`,
/// exchange + 10 min) removes it soon after anyway; the bound is checked
/// here rather than trusted to the TTL monitor's schedule.
pub const PROOF_WINDOW_SECS: i64 = 600;

/// The body. No `deny_unknown_fields`: a newer device may say more.
#[derive(Debug, Deserialize)]
pub struct MoveRequest {
    /// The agent token the NEW enrollment answered with.
    pub agent_token: String,
}

/// What a refusal from the old row alone, or from the pair, says. `None`
/// lets the move go on to the proof. Pure, so every rule has a unit test.
pub fn pair_refusal(
    old: &Agent,
    old_personal: bool,
    old_temporary: bool,
    new: &Agent,
) -> Option<&'static str> {
    if old.ephemeral {
        return Some("an ephemeral device removes itself with self/unenroll");
    }
    if old_temporary {
        return Some("a temporary device leaves its invitation with `mh leave`");
    }
    if !old_personal {
        return Some(
            "only a personal device can move itself; removing this device is an \
             admin action in its organization",
        );
    }
    if old.capabilities.two_factor {
        return Some(
            "this device asks for a two-factor code; switch two-factor off on it \
             before moving it to another organization",
        );
    }
    if new.ephemeral {
        return Some("the new enrollment is ephemeral");
    }
    if new.tenant_id == old.tenant_id {
        return Some("the new enrollment is in the same organization");
    }
    if new.machine_id != old.machine_id {
        return Some("the new enrollment is a different machine");
    }
    None
}

/// The text the old organization's admins are told, and nothing more: the
/// device by its own name in their org, and that a person at it moved it.
pub fn notice_text(device: &str) -> (String, String) {
    (
        "A device left this organization".to_string(),
        format!(
            "\u{201c}{device}\u{201d} was moved to another organization by a person signed in \
             at the device."
        ),
    )
}

fn label_of(agent: &Agent) -> String {
    agent
        .display_name
        .as_deref()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or(&agent.name)
        .to_string()
}

/// One audit row in the device's OWN tenant. Best-effort: a failed write is
/// logged, never a reason to refuse or to undo a removal that happened.
async fn audit(state: &FleetState, old: &Agent, decision: &str, reason: &str) {
    let row = doc! {
        "tenant_id": old.tenant_id,
        "agent_id": old.id,
        "machine_name": &old.name,
        "decision": decision,
        "reason": reason,
        "created_at": DateTime::now(),
    };
    if let Err(e) = state
        .core
        .db
        .collection::<bson::Document>(AUDIT_COLLECTION)
        .insert_one(row)
        .await
    {
        tracing::warn!(tenant_id = %old.tenant_id, agent_id = ?old.id, %e,
            "fr-133: could not write the device-move audit row");
    }
}

async fn refuse(state: &FleetState, old: &Agent, reason: &str) -> ApiError {
    audit(state, old, "refused", reason).await;
    tracing::info!(tenant_id = %old.tenant_id, agent_id = ?old.id, reason,
        "fr-133: device move refused");
    ApiError::Forbidden(format!(
        "This device cannot remove its old organization's record: {reason}"
    ))
}

/// The old organization's members who may manage its devices.
async fn device_admins(state: &FleetState, tenant: ObjectId) -> Vec<ObjectId> {
    let members = state
        .core
        .tenants
        .member_user_ids(tenant)
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for uid in members.into_iter().take(500) {
        if let Ok(p) = state.core.tenants.get_member_permissions(tenant, uid).await
            && permissions::has(p, permissions::MANAGE_AGENTS)
        {
            out.push(uid);
        }
    }
    out
}

/// Claim the device-login decision behind the new row's enrollment, ONCE.
/// The filter is the proof; the `$set` is what makes it single-use.
async fn claim_proof(state: &FleetState, new: &Agent, old_id: ObjectId) -> Result<bool, ApiError> {
    let Some(jti) = new.enrolled_with_jti.as_deref().filter(|j| !j.is_empty()) else {
        return Ok(false);
    };
    let now = DateTime::now();
    let cutoff = DateTime::from_millis(now.timestamp_millis() - PROOF_WINDOW_SECS * 1000);
    let claimed = state
        .core
        .db
        .collection::<bson::Document>(crate::device_login::COLLECTION)
        .update_one(
            doc! {
                "enrollment_jti": jti,
                "state": "consumed",
                "tenant_id": new.tenant_id,
                "approved_by": new.owner_user_id,
                "decided_at": { "$gt": cutoff },
                "expires_at": { "$gt": now },
                "moved_agent_id": { "$exists": false },
            },
            doc! { "$set": { "moved_agent_id": old_id, "moved_at": now } },
        )
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Could not verify the new enrollment".into()))?;
    Ok(claimed.modified_count == 1)
}

/// `POST /api/agent/self/move` — FR-133: a personal device that moved to
/// another organization removes its old organization's row (module docs).
pub async fn self_move(
    State(state): State<FleetState>,
    agent: crate::auth_agent::AuthAgent,
    Json(body): Json<MoveRequest>,
) -> Result<Json<Value>, ApiError> {
    // The kill switch: exactly what a permanent device asking to remove
    // itself hears today.
    if !state.settings.auth.native_device_move_enabled {
        return Err(ApiError::Forbidden(
            crate::agent::PERMANENT_SELF_REMOVAL_REFUSAL.to_string(),
        ));
    }
    let old = &agent.agent;
    let old_id = agent.agent_id;

    // The new credential gets the old one's checks: signature + audience,
    // a live row, its generation, an admitted owner. A refusal is a 403 here
    // — the CALLER's credential (the old one) is fine, and a 401 would tell
    // the device its own enrollment is dead.
    let token = body.agent_token.trim();
    if token.is_empty() || token.len() > 16 * 1024 {
        return Err(refuse(&state, old, "the new enrollment's credential is missing").await);
    }
    let new = match state.auth.verify_agent_token(token) {
        Ok(claims) => crate::auth_agent::accepted_agent(
            &state,
            &claims.sub,
            &claims.tenant_id,
            Some(claims.generation),
        )
        .await
        .map(|(_, _, a)| a),
        Err(_) => Err(ApiError::Unauthorized(String::new())),
    };
    let new = match new {
        Ok(a) => a,
        Err(ApiError::Internal(e)) => return Err(ApiError::Internal(e)),
        Err(_) => {
            return Err(refuse(
                &state,
                old,
                "the new enrollment's credential is not accepted",
            )
            .await);
        }
    };

    let raw = state
        .core
        .db
        .collection::<bson::Document>("agents")
        .find_one(doc! { "_id": old_id })
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Could not read the device".into()))?;
    let old_personal = raw
        .as_ref()
        .and_then(|r| r.get_object_id("personal_access_owner_id").ok())
        .is_some();
    let old_temporary = crate::device_invite::grant_for_agent(&state, old_id)
        .await?
        .is_some();
    if let Some(reason) = pair_refusal(old, old_personal, old_temporary, &new) {
        return Err(refuse(&state, old, reason).await);
    }

    if !claim_proof(&state, &new, old_id).await? {
        return Err(refuse(
            &state,
            old,
            "no fresh, person-approved enrollment of this machine into another organization \
             (or it was already used)",
        )
        .await);
    }

    let released =
        crate::removal::remove_agent_device(&state, old, crate::removal::MOVED_REASON).await?;
    audit(&state, old, "moved", crate::removal::MOVED_REASON).await;

    let (title, body_text) = notice_text(&label_of(old));
    let admins = device_admins(&state, old.tenant_id).await;
    meshharbor_core::notify::notify_users(
        &state.core,
        &meshharbor_core::notify::NotifyParams {
            tenant_id: old.tenant_id,
            notification_type: NotificationType::DeviceMoved,
            title,
            body: body_text,
            link: format!("/tenant/{}/devices", old.tenant_id.to_hex()),
            source: NotificationSource {
                entity_type: "agent".to_string(),
                entity_id: old_id,
                actor_id: None,
            },
            ws_type_label: "device_moved",
        },
        &admins,
        meshharbor_core::notify::PushTo::Offline,
    )
    .await;

    // The new side is named in the operator's log only — never in anything
    // the old organization can read.
    tracing::info!(
        tenant_id = %old.tenant_id, agent_id = %old_id,
        new_tenant_id = %new.tenant_id, new_agent_id = ?new.id,
        overlay_released = released.is_some(), admins_told = admins.len(),
        "fr-133: device moved to another organization; old row removed"
    );
    Ok(Json(json!({
        "removed": true,
        "overlay_released": released.is_some(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::models::OsKind;
    use meshharbor_services::dao::agent::AgentDao;

    fn agent(tenant: ObjectId, machine: &str) -> Agent {
        let mut a = AgentDao::new_row(
            tenant,
            ObjectId::new(),
            "laptop".into(),
            machine.into(),
            OsKind::Linux,
            "0.0.0".into(),
            String::new(),
            None,
        );
        a.id = Some(ObjectId::new());
        a
    }

    #[test]
    fn a_personal_device_moves_only_to_the_same_machine_in_another_org() {
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let old = agent(a, "m-1");
        assert_eq!(pair_refusal(&old, true, false, &agent(b, "m-1")), None);
        assert!(
            pair_refusal(&old, true, false, &agent(a, "m-1")).is_some(),
            "same org is not a move"
        );
        assert!(
            pair_refusal(&old, true, false, &agent(b, "m-2")).is_some(),
            "another machine's enrollment proves nothing about this one"
        );
    }

    #[test]
    fn what_stays_an_admin_decision_is_refused() {
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let new = agent(b, "m-1");
        let old = agent(a, "m-1");
        assert!(
            pair_refusal(&old, false, false, &new).is_some(),
            "an admin-enrolled device is not the person's to move"
        );
        assert!(pair_refusal(&old, true, true, &new).is_some(), "temporary");
        let mut eph = agent(a, "m-1");
        eph.ephemeral = true;
        assert!(pair_refusal(&eph, true, false, &new).is_some(), "ephemeral");
        let mut tf = agent(a, "m-1");
        tf.capabilities.two_factor = true;
        assert!(pair_refusal(&tf, true, false, &new).is_some(), "two-factor");
        let mut new_eph = agent(b, "m-1");
        new_eph.ephemeral = true;
        assert!(pair_refusal(&old, true, false, &new_eph).is_some());
    }

    #[test]
    fn the_notice_names_the_device_and_nothing_of_the_other_side() {
        let (title, body) = notice_text("Laptop 7");
        assert!(body.contains("Laptop 7"));
        assert!(body.contains("another organization by a person signed in at the device"));
        assert!(!title.is_empty());
    }
}
