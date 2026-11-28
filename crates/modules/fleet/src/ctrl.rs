// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! C-2 — rc control events on the global channel: IDEMPOTENT hub operations
//! every pod applies locally (the one holding the session/agent acts; the
//! rest no-op), which makes consent delivery and admin kicks
//! location-transparent. FR-69 P5a — moved from the host's `ws/remote_control.rs`:
//! the publisher needs only the core (Redis), the applier only the Hub.

use bson::oid::ObjectId;
use meshharbor_core::Core;
use tracing::{debug, info};

use crate::Hub;

/// C-2 — publish an rc control event on the global channel. Control
/// events are IDEMPOTENT hub operations every pod applies locally (the
/// one holding the session/agent acts; the rest no-op), which makes
/// consent delivery and admin kicks location-transparent: the HTTP
/// request can land on any pod. The publisher already applied locally —
/// the self-echo guard in the forwarder skips its own envelope.
pub async fn publish_rc_ctrl(state: &Core, evt: &str, mut fields: serde_json::Value) {
    let Some(redis) = &state.redis_pubsub else {
        return;
    };
    if let Some(obj) = fields.as_object_mut() {
        obj.insert("class".into(), serde_json::json!("rc"));
        obj.insert("evt".into(), serde_json::json!(evt));
        // ponytail: stamp the publisher's DB once here so no caller can omit it
        // and contaminate sibling DBs sharing one Redis pub/sub channel.
        obj.entry("db")
            .or_insert_with(|| serde_json::json!(state.db.name()));
    }
    let env = serde_json::json!({ "origin": redis.instance_id(), "ctrl": fields });
    if let Err(e) = redis.publish(&env.to_string()).await {
        debug!(%evt, %e, "rc ctrl publish failed (cross-pod delivery degraded)");
    }
}

/// Strict publication for capability changes. None means configured single-pod
/// operation; an enabled Redis transport failure is never degraded to success.
pub async fn publish_rc_ctrl_checked(
    state: &Core,
    evt: &str,
    mut fields: serde_json::Value,
) -> anyhow::Result<()> {
    let Some(redis) = &state.redis_pubsub else {
        return Ok(());
    };
    let obj = fields
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("control payload must be an object"))?;
    obj.insert("class".into(), serde_json::json!("rc"));
    obj.insert("evt".into(), serde_json::json!(evt));
    obj.entry("db")
        .or_insert_with(|| serde_json::json!(state.db.name()));
    let env = serde_json::json!({"origin":redis.instance_id(),"ctrl":fields});
    redis.publish(&env.to_string()).await?;
    Ok(())
}

/// C-2 — apply a received rc control event to THIS pod's hub. Idempotent:
/// misses are no-ops (the entity lives elsewhere or is already gone).
pub fn apply_rc_ctrl(hub: &Hub, ctrl: &serde_json::Value) {
    match ctrl.get("evt").and_then(|v| v.as_str()) {
        // FR-92 — an org admin changed the keep-busy deny on another pod:
        // push it to this pod's agents of that tenant (the ones that parse it).
        Some("device_name_sync") => {
            let (Some(tid), Some(aid), Some(msg)) = (
                ctrl["tenant_id"]
                    .as_str()
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl["agent_id"]
                    .as_str()
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("message"),
            ) else {
                return;
            };
            if let Ok(
                message @ meshharbor_remote_control::signaling::ServerMsg::DeviceNameSync { .. },
            ) = serde_json::from_value(msg.clone())
            {
                let _ = hub.send_to_agent_in_tenant(aid, tid, message);
            }
        }
        Some("overlay_self_name") => {
            let (Some(tid), Some(aid), Some(msg)) = (
                ctrl["tenant_id"]
                    .as_str()
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl["agent_id"]
                    .as_str()
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("message"),
            ) else {
                return;
            };
            if let Ok(
                message @ meshharbor_remote_control::signaling::ServerMsg::OverlaySelfName {
                    ..
                },
            ) = serde_json::from_value(msg.clone())
                && msg["agent_id"] == aid.to_hex()
                && msg["tenant_id"] == tid.to_hex()
            {
                let _ = hub.send_to_agent_in_tenant(aid, tid, message);
            }
        }
        Some("keep_busy_policy") => {
            let (Some(tid), Some(denied)) = (
                ctrl.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("denied").and_then(|v| v.as_bool()),
            ) else {
                return;
            };
            let n = hub.push_keep_busy_policy(tid, denied);
            if n > 0 {
                info!(tenant = %tid, denied, agents = n, "rc ctrl: keep-busy policy applied from another pod");
            }
        }
        Some("admin_takeover") => {
            let (Some(tid), Some(sid), Some(uid), Some(active)) = (
                ctrl.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("session_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("user_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("active").and_then(|v| v.as_bool()),
            ) else {
                return;
            };
            match hub.set_silent_monitor_takeover(tid, sid, uid, active) {
                Ok(aid) => {
                    info!(tenant = %tid, session = %sid, agent = %aid, active, "rc ctrl: admin takeover applied from another pod");
                }
                Err(e) => {
                    debug!(tenant = %tid, session = %sid, %e, "rc ctrl: admin takeover ignored on non-owner pod");
                }
            }
        }
        Some("ssh_revoke") => {
            let Some(tid) = ctrl
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .and_then(|s| ObjectId::parse_str(s).ok())
            else {
                return;
            };
            let scope = ctrl.get("scope").and_then(|v| v.as_str()).unwrap_or("org");
            let principal = ctrl
                .get("principal")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let sid = ctrl.get("sid").and_then(|v| v.as_str()).map(str::to_string);
            let reason = ctrl
                .get("reason")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if let Some(aid) = ctrl
                .get("agent_id")
                .and_then(|v| v.as_str())
                .and_then(|s| ObjectId::parse_str(s).ok())
            {
                if hub.push_ssh_revoke_agent(tid, aid, scope, principal, sid, reason.clone()) {
                    info!(tenant = %tid, agent = %aid, scope, ?reason, "rc ctrl: ssh_revoke applied to agent from another pod");
                }
            } else {
                let n = hub.push_ssh_revoke_org_scoped(
                    tid,
                    scope,
                    principal,
                    sid,
                    reason
                        .clone()
                        .or_else(|| Some("org_ssh_disabled".to_string())),
                );
                if n > 0 {
                    info!(tenant = %tid, scope, ?reason, agents = n, "rc ctrl: ssh_revoke applied to org agents from another pod");
                }
            }
        }
        Some("peer_relay_serve") => {
            let (Some(tid), Some(aid), Some(serve)) = (
                ctrl.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("agent_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("serve").and_then(|v| v.as_bool()),
            ) else {
                return;
            };
            let revision = ctrl.get("revision").and_then(|v| v.as_u64());
            let backbone_endpoints = ctrl
                .get("backbone_endpoints")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if hub.push_peer_relay_serve(tid, aid, serve, revision, backbone_endpoints) {
                info!(tenant = %tid, agent = %aid, serve, ?revision, "rc ctrl: peer-relay serve applied from another pod");
            }
        }
        Some("management_path") => {
            let (Some(tid), Some(aid), Some(direct)) = (
                ctrl.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("agent_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("direct").and_then(|v| v.as_bool()),
            ) else {
                return;
            };
            let entries = ctrl
                .get("entries")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if hub.push_management_path(tid, aid, direct, entries) {
                info!(tenant = %tid, agent = %aid, direct, "rc ctrl: management path applied from another pod");
            }
        }
        Some("management_entry_key") => {
            let (Some(tid), Some(aid), Some(key)) = (
                ctrl.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("agent_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("key").and_then(|v| v.as_str()),
            ) else {
                return;
            };
            let revoking = key.is_empty();
            if hub.push_management_entry_key(
                tid,
                aid,
                meshharbor_remote_control::management_entry::EntryKey(key.to_string()),
            ) {
                info!(tenant = %tid, agent = %aid, revoking, "rc ctrl: management entry key applied from another pod");
            }
        }
        Some("zone_policy") => {
            let (Some(aid), Some(policy_revision), Some(strict)) = (
                ctrl.get("agent_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("policy_revision").and_then(|v| v.as_u64()),
                ctrl.get("strict").and_then(|v| v.as_bool()),
            ) else {
                return;
            };
            let allowed_countries = ctrl
                .get("allowed_countries")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_ascii_uppercase()))
                        .collect::<std::collections::HashSet<_>>()
                })
                .unwrap_or_default();
            let (zone, zones) = crate::hub::AgentZoneIcePolicy::zone_from_json(ctrl);
            if hub.set_agent_zone_ice_policy(
                aid,
                crate::hub::AgentZoneIcePolicy {
                    policy_revision,
                    strict,
                    allowed_countries,
                    zone,
                    zones,
                },
            ) && let Some(tid) = ctrl
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .and_then(|s| ObjectId::parse_str(s).ok())
            {
                hub.push_relay_regions_for_agent(tid, aid);
            }
        }
        Some("consent") => {
            let (Some(sid), Some(granted)) = (
                ctrl.get("session_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("granted").and_then(|v| v.as_bool()),
            ) else {
                return;
            };
            // Cross-pod replay of an approve-link decision: a human clicked a
            // button, so there is no deny REASON to carry (FR-27).
            if hub.deliver_consent(sid, granted, None).is_ok() {
                info!(session = %sid, granted, "rc ctrl: consent applied from another pod");
            }
        }
        // A device's removal, on the pod that holds its socket. #2267 — the
        // removing pod decided whether the device is told (`goodbye`); an
        // envelope without it comes from a pod before #2267, and keeps that
        // pod's behaviour: out of the hub, not told.
        Some("kick") => {
            let Some(aid) = ctrl
                .get("agent_id")
                .and_then(|v| v.as_str())
                .and_then(|s| ObjectId::parse_str(s).ok())
            else {
                return;
            };
            let goodbye = ctrl
                .get("goodbye")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let outcome = hub.kick_removed_agent(aid, goodbye);
            if outcome != crate::hub::KickOutcome::NotRegistered {
                info!(agent = %aid, ?outcome, "rc ctrl: kick applied from another pod");
            }
        }
        // P3 — admin/controller force-close for a session homed on another
        // pod (the HTTP terminate route already authz'd against the named
        // tenant; the local terminate there was a silent no-op cross-pod).
        // The tenant re-check here stops a forged/mismatched envelope from
        // killing an identically-numbered session in a different tenant.
        Some("terminate") => {
            let (Some(sid), Some(tid)) = (
                ctrl.get("session_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
            ) else {
                return;
            };
            if hub.session_snapshot(sid).is_some_and(|(t, _)| t == tid)
                && hub
                    .terminate(
                        sid,
                        meshharbor_remote_control::models::EndReason::AdminTerminated,
                    )
                    .is_ok()
            {
                info!(session = %sid, "rc ctrl: terminate applied from another pod");
            }
        }
        // FR-130 P1b-2 — the controller's own end (its `rc:terminate`, or a
        // redial's `replaces`) of a session the pod it reached did not hold:
        // that pod wrote the end to the row, and the pod that holds the
        // session ends it here. The tenant AND the controller are re-checked,
        // so an envelope cannot end another person's session. The reason is
        // the one the hub records for a controller (`host_disconnect` is the
        // device's alone); an absent or unknown one reads `controller_hangup`.
        Some("controller_terminate") => {
            let oid = |key: &str| {
                ctrl.get(key)
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok())
            };
            let (Some(sid), Some(tid), Some(uid)) =
                (oid("session_id"), oid("tenant_id"), oid("user_id"))
            else {
                return;
            };
            use meshharbor_remote_control::models::EndReason;
            let reason = match ctrl
                .get("reason")
                .cloned()
                .and_then(|v| serde_json::from_value::<EndReason>(v).ok())
            {
                None | Some(EndReason::HostDisconnect) => EndReason::ControllerHangup,
                Some(r) => r,
            };
            if hub.session_snapshot(sid) == Some((tid, uid)) && hub.terminate(sid, reason).is_ok() {
                info!(session = %sid, "rc ctrl: a controller's end applied from another pod");
            }
        }
        // P2b — cycle an agent's WS so it re-establishes its overlay session
        // on the tenant's NEW block (self_ip binds once, at establish). Rides
        // the ctrl lane rather than a directed RPC because the renumber
        // touches a whole tenant at once and the HTTP call can land on any
        // pod: every pod applies, the one holding the socket acts.
        Some("overlay_cycle") => {
            let Some(aid) = ctrl
                .get("agent_id")
                .and_then(|v| v.as_str())
                .and_then(|s| ObjectId::parse_str(s).ok())
            else {
                return;
            };
            if hub.cycle_agent_ws(aid) {
                info!(agent = %aid, "rc ctrl: overlay renumber cycle applied from another pod");
            }
        }
        // Multi-org — deliver a cross-org join push to an agent homed on
        // whichever pod holds its socket. `send_to_agent_in_tenant` re-checks
        // the tenant: this envelope carries a live enrollment token and every
        // pod applies it, so a mismatched one must not be able to hand a
        // different tenant's device a token for an org it never asked to join.
        Some("agent_join_org") => {
            let (Some(aid), Some(tid), Some(token)) = (
                ctrl.get("agent_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok()),
                ctrl.get("enrollment_token")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            ) else {
                return;
            };
            let msg = meshharbor_remote_control::signaling::ServerMsg::JoinOrg {
                enrollment_token: token,
                label: ctrl
                    .get("label")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                overlay_mode: ctrl
                    .get("overlay_mode")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            };
            if hub.send_to_agent_in_tenant(aid, tid, msg).is_ok() {
                info!(agent = %aid, "rc ctrl: cross-org join delivered from another pod");
            }
        }
        // FR-130 P1b-2 — `resume_scope` is read from the store, which the hub
        // does not reach: [`apply_rc_ctrl_on`] takes it.
        _ => {}
    }
}

/// C-2 — [`apply_rc_ctrl`], with the module's state at hand for the events
/// that need more than the hub. FR-130 P1b-2 (review 2, N2): a change to the
/// resume scope made on another pod is only a nudge. This pod reads the store
/// itself and tells its connections under its OWN window
/// ([`crate::resume_scope::nudge`]), whatever the event carries: one that
/// arrives late or twice applies the newest list, and a pod at window 0
/// announces nothing.
pub fn apply_rc_ctrl_on(state: &crate::FleetState, ctrl: &serde_json::Value) {
    if ctrl.get("evt").and_then(|v| v.as_str()) == Some("resume_scope") {
        crate::resume_scope::nudge(state);
    } else {
        apply_rc_ctrl(&state.rc_hub, ctrl);
    }
}
