// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The ONE device-removal sequence behind the admin `DELETE …/agent/{id}`
//! route, the ephemeral self-unenroll and the ephemeral reaper — factored so
//! they cannot drift (FR-51 F3).
//!
//! FR-69 P5a — moved from the host's `ws/ephemeral.rs`. The overlay release
//! that opened the sequence is `network`'s, which fleet cannot call (the
//! module graph is a DAG); it now runs through the core hook registry
//! ([`meshharbor_core::hooks::FleetLifecycle::agent_removed`]), in
//! [`meshharbor_core::hooks::HOOK_ORDER`] — session holders, then lease holders,
//! then this, the record owner. Same order as before, one owner per step.

use bson::oid::ObjectId;
use meshharbor_remote_control::models::Agent;
use meshharbor_services::dao::base::{DaoError, DaoResult};
use meshharbor_core::hooks::ReleasedLease;

use crate::FleetState;

/// Remove ONE device from the fleet: holders release (overlay lease first) →
/// row delete → hub kick, in that order.
///
/// The ORDER is inherited from `delete_agent` and is load-bearing: the
/// holders run while the device is still addressable (a hook's last frame to
/// it, P2g-4a's purge, is queued before the kick), and the lease is released
/// before the row goes, so no `removes` fan races a second release.
///
/// The kick takes the device out of the hub and, since #2267, tells a
/// connected one with `rc:goodbye AgentDeleted` ([`Hub::kick_removed_agent`]):
/// its daemon stops as it would at its next connection, instead of keeping
/// its socket until something else drops it. The socket's own teardown is
/// then not the hub removal's owner, so it writes no Offline, releases no
/// presence and runs no overlay leave. The row and the lease are already
/// gone.
///
/// [`Hub::kick_removed_agent`]: crate::Hub::kick_removed_agent
///
/// The row delete is chosen by the ROW's own nature, not by the caller: an
/// ephemeral row is hard-deleted (its tombstone would reserve a random
/// machine_id forever — FR-51 F4), a permanent row is tombstoned exactly as
/// before. Returns what the lease holders freed, for the route's response.
pub async fn remove_agent_device(
    state: &FleetState,
    agent: &Agent,
    reason: &str,
) -> DaoResult<Option<ReleasedLease>> {
    let aid = agent
        .id
        .ok_or_else(|| DaoError::Validation("agent missing _id".into()))?;

    // Holders first (remote: sessions; network: the overlay lease). A holder
    // that fails stops the cascade — deleting the row while a lease is still
    // held is the state this order exists to prevent.
    let released = state
        .hooks
        .agent_removed(agent.tenant_id, aid, &agent.machine_id, reason)
        .await
        .map_err(|e| DaoError::Validation(format!("removal hook failed: {e}")))?;

    if agent.ephemeral {
        state
            .agents
            .hard_delete_ephemeral(agent.tenant_id, aid)
            .await?;
        // The use row is the trail that survives the hard delete; stamping it
        // is best-effort (a missing stamp loses a detail, not the removal).
        match state
            .enrollment_keys
            .record_removal(agent.tenant_id, aid, reason)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(agent_id = %aid, %e, "ephemeral removal stamp failed")
            }
        }
    } else {
        state.agents.soft_delete(agent.tenant_id, aid).await?;
    }

    // Kick the socket last — locally, and on whichever pod holds it.
    kick(
        state,
        aid,
        tells_the_device(reason, state.settings.rc.removal_goodbye),
    )
    .await;

    Ok(released)
}

/// #2267 — the kick, on this pod and through the control channel on the pod
/// that holds the socket. Shared by the removal sequence and an archive's
/// revocation, so the two cannot drift.
pub async fn kick(state: &FleetState, aid: ObjectId, goodbye: bool) {
    let outcome = state.rc_hub.kick_removed_agent(aid, goodbye);
    tracing::debug!(agent_id = %aid, goodbye, ?outcome, "removed device kicked");
    crate::ctrl::publish_rc_ctrl(
        &state.core,
        "kick",
        serde_json::json!({ "agent_id": aid.to_hex(), "goodbye": goodbye }),
    )
    .await;
}

/// #2267 — whether a removal tells the connected device it was removed.
/// Not an ephemeral device that unenrolled itself: it is mid-shutdown, and a
/// goodbye racing its graceful exit would turn its clean stop into exit 7.
/// `enabled` is `rc.removal_goodbye`, the kill switch.
pub fn tells_the_device(reason: &str, enabled: bool) -> bool {
    enabled && reason != SELF_UNENROLL_REASON
}

/// The reason an ephemeral device's own unenroll removes it with
/// (`agent::self_unenroll`).
pub const SELF_UNENROLL_REASON: &str = "ephemeral_self_unenroll";

/// The agent id the reaper and the routes log; kept next to the sequence so
/// its callers do not each re-derive it.
pub fn agent_id_of(agent: &Agent) -> Option<ObjectId> {
    agent.id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_removal_tells_the_device_unless_it_is_leaving_by_itself() {
        assert!(tells_the_device("agent_delete", true));
        assert!(tells_the_device("ephemeral_expired", true));
        assert!(!tells_the_device(SELF_UNENROLL_REASON, true));
        assert!(
            !tells_the_device("agent_delete", false),
            "rc.removal_goodbye = false is the kill switch"
        );
    }
}
