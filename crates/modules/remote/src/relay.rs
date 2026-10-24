// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! PR-2 — cross-pod rc signalling relay: `rc.cmd` / `rc.conn_closed` /
//! `rc.conn_alive`.
//!
//! PR-1 made cross-pod rc misses CONVERGE (re-key the controller, nudge
//! a provably-parked idle agent). This module makes them WORK in the
//! meantime: a controller whose WS sits on pod A can run a session with
//! an agent homed on pod B by forwarding its raw `rc:*` frames over the
//! per-pod bus; every server->controller message routes back over the
//! C-4 conn-addressed lane (`send_to_connection_routed` is
//! payload-agnostic). Co-location then becomes a latency optimization,
//! not a correctness requirement: the relay adds one bus hop to
//! SIGNALLING only — media and input always ride the P2P WebRTC planes.
//!
//! Topology per relayed controller connection:
//!
//! ```text
//! browser ==ws== pod A                         pod B ==ws== agent
//!    rc:* frame --> rc.cmd{conn,frame,...} --> proxy DispatchCtx
//!                                              -> Hub::dispatch
//!    <-- global channel conn-envelope <-- proxy pump <- ClientTx
//! ```
//!
//! Lifecycle: the owner pod keeps ONE proxy controller (Hub
//! registration + pump task) per origin `conn`, created lazily on the
//! first `rc.cmd`. It dies on: the origin pod's WS-close notice
//! (`rc.conn_closed` - the primary path, mirroring C-4's
//! `remote_media_conns` forwarding), or the janitor sweep discovering
//! the origin conn gone / origin pod dead (`rc.conn_alive` probe, the
//! belt for a crashed origin pod that could never send the notice).
//! The rc.185 orphan reap in `create_session` remains the last-resort
//! braces.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use dashmap::DashMap;
use roomler_ai_mod_fleet::hub::{DispatchCtx, OrgPolicy};
use roomler_ai_remote_control::models::{ConsentMode, InputMode, SessionPolicy};
use roomler_ai_remote_control::signaling::{ClientMsg, Role};
use tracing::{debug, info, warn};

use crate::RemoteState;

/// One live proxy controller on the OWNER pod, keyed by the origin
/// connection id.
pub struct ProxyController {
    pub user_id: ObjectId,
    /// The Hub-registered ClientTx (identity key for unregister).
    pub tx: roomler_ai_remote_control::session::ClientTx,
    /// Pod that holds the real browser socket (sweep probe target).
    pub origin_pod: String,
    /// Refreshed on every forwarded frame; the sweep only probes
    /// entries that went quiet (a HEALTHY session is signalling-quiet,
    /// so quiet alone is never grounds for teardown).
    pub last_seen: std::sync::Mutex<Instant>,
    pump: tokio::task::JoinHandle<()>,
}

/// origin conn id -> proxy.
pub type ProxyControllers = DashMap<String, ProxyController>;

/// Sweep cadence + probe threshold. Quiet entries get an
/// `rc.conn_alive` probe at most once per sweep; only a NEGATIVE or
/// dead-pod answer tears down.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
const PROBE_WHEN_QUIET_FOR: Duration = Duration::from_secs(120);

/// Register the owner-side bus verbs + the janitor sweep. Called once
/// from the module's init (needs the full state), the way the host wires
/// `wire_media_cluster` / `wire_derp_cluster`.
pub fn wire_rc_relay(state: &RemoteState) {
    let Some(bus) = state.cluster_bus.clone() else {
        return;
    };

    // rc.cmd - dispatch one forwarded controller frame into the local
    // Hub under a proxy identity. Reply: {dispatched: bool, code?,
    // message?} - a dispatch error is a NORMAL reply (the caller
    // forwards it to its browser as rc:error); NACK/deadline mean the
    // relay itself failed and the caller falls back to the PR-1 rehome
    // answer.
    {
        let state = state.clone();
        bus.register("rc.cmd", move |body| {
            let state = state.clone();
            Box::pin(async move {
                let conn = body
                    .get("conn")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing conn".to_string())?
                    .to_string();
                let user_id = body
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok())
                    .ok_or_else(|| "bad user_id".to_string())?;
                let origin_pod = body
                    .get("origin")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let controller_name = body
                    .get("controller_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("remote user")
                    .to_string();
                let consent_mode: ConsentMode = body
                    .get("consent_mode")
                    .cloned()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default();
                let override_reason = body
                    .get("override_reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let input_mode: Option<InputMode> = body
                    .get("input_mode")
                    .cloned()
                    .and_then(|v| serde_json::from_value(v).ok());
                // Multi-org — the asking org's name rides the relayed frame so
                // a CROSS-POD session request still names it in the host's
                // consent prompt. Resolved on the ORIGIN pod (it ran the authz
                // gate); the owner pod only forwards what it was told.
                let tenant_name = body
                    .get("tenant_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                // FR-85 P3 — resolved by the ORIGIN pod's authz gate. ⚠️ An
                // absent field (a pod still on an older build) reads as
                // FALSE: the hub then strips RECORD, which fails closed.
                let may_record = body
                    .get("may_record")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // #1882 — the device's `AccessPolicy.rc_overlay`, resolved by
                // the same ORIGIN-pod gate. Absent (an older pod) reads OFF,
                // the policy's own default.
                let rc_overlay = body
                    .get("rc_overlay")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // FR-101 P2 — the org's session policy, read by the ORIGIN
                // pod's gate. See `session_policy_from_relay` for absent.
                let session_policy = session_policy_from_relay(body.get("session_policy"));
                // FR-101 P4b — the org's maximum session length, in seconds.
                // Absent (an older origin pod) is no limit, what that pod
                // would have applied itself.
                let max_duration = body
                    .get("max_secs")
                    .and_then(|v| v.as_u64())
                    .map(std::time::Duration::from_secs);
                // P4b-2 — the idle limit, in seconds, resolved by the same
                // gate. Absent (an older origin pod) is no idle limit, what
                // that pod would have applied itself.
                let idle_secs = body
                    .get("idle_secs")
                    .and_then(|v| v.as_u64())
                    .and_then(|s| u32::try_from(s).ok());
                // FR-99 P3b — the device's lock ask, resolved by the same
                // gate. Absent or null (an older origin pod, or nothing
                // asked) is no ask, what that pod would have applied itself.
                let lock_on_end = lock_ask_from_relay(body.get("lock_on_end"));
                // FR-115 P3 — the device org's session cap, resolved by the
                // same gate. Absent (an older origin pod) or null is no cap,
                // what that pod would have applied itself.
                let org_session_cap = body
                    .get("org_session_cap")
                    .and_then(|v| v.as_u64())
                    .and_then(|n| u32::try_from(n).ok());
                let frame: ClientMsg = serde_json::from_value(
                    body.get("frame")
                        .cloned()
                        .ok_or_else(|| "missing frame".to_string())?,
                )
                .map_err(|e| format!("bad frame: {e}"))?;

                if matches!(&frame, ClientMsg::SessionRequest { share_grant_id: Some(_), .. }) {
                    return Ok(serde_json::json!({"dispatched": false,"code":"permission_denied","message":"Cross-pod device shares are not supported"}));
                }

                // Get-or-create the proxy for this origin conn.
                let tx = {
                    let entry = state.rc_proxy_controllers.entry(conn.clone());
                    match entry {
                        dashmap::mapref::entry::Entry::Occupied(o) => {
                            *o.get().last_seen.lock().unwrap() = Instant::now();
                            o.get().tx.clone()
                        }
                        dashmap::mapref::entry::Entry::Vacant(v) => {
                            let (tx, mut rx) = state.fleet.rc_hub.register_controller(user_id);
                            let pump_state = state.clone();
                            let pump_conn = conn.clone();
                            let pump = tokio::spawn(async move {
                                while let Some(msg) = rx.recv().await {
                                    let Ok(val) = serde_json::to_value(&msg) else {
                                        continue;
                                    };
                                    roomler_core::ws::dispatcher::send_to_connection_routed(
                                        &pump_state.ws_storage,
                                        &pump_state.redis_pubsub,
                                        &pump_conn,
                                        &val,
                                    )
                                    .await;
                                }
                            });
                            info!(%user_id, conn = %conn, "rc relay: proxy controller created");
                            v.insert(ProxyController {
                                user_id,
                                tx: tx.clone(),
                                origin_pod,
                                last_seen: std::sync::Mutex::new(Instant::now()),
                                pump,
                            });
                            tx
                        }
                    }
                };

                // FR-52 P3d — an external-access login the origin pod forwarded
                // because the device is homed HERE. Handled by the extauth relay,
                // not the Hub, and answered through this proxy sender — whose
                // pump already routes every reply back to the browser's socket.
                if let Some(handled) =
                    crate::extauth::on_relayed(&state, user_id, &controller_name, &tx, &frame)
                {
                    return Ok(serde_json::json!({ "dispatched": handled }));
                }

                // FR-115 P3b — this pod owns the device, so the org's slot is
                // claimed here, exactly as the local path claims it.
                let mut org_session_cap = org_session_cap;
                let mut slot = None;
                if let ClientMsg::SessionRequest { agent_id, .. } = &frame
                    && let Some(cap) = org_session_cap
                    && crate::slots::enabled(&state)
                    && let Some(org) = state.fleet.rc_hub.agent_org(*agent_id)
                {
                    use crate::slots::SlotDecision;
                    use roomler_core::cluster::session_slots::SlotScope;
                    match crate::slots::claim(&state, SlotScope::Org(org), user_id, *agent_id, cap)
                        .await
                    {
                        SlotDecision::Claimed(lease) => {
                            slot = Some(lease);
                            org_session_cap = None;
                        }
                        SlotDecision::Fallback => {}
                        SlotDecision::Full {
                            cap,
                            holder_user,
                            holder_agent,
                        } => {
                            let e = roomler_ai_remote_control::Error::OrgSessionLimit {
                                cap,
                                holder_user,
                                holder_agent,
                            };
                            return Ok(serde_json::json!({
                                "dispatched": false,
                                "code": crate::controller::error_code(&e),
                                "message": crate::controller::refusal_message(&state, &e).await,
                            }));
                        }
                    }
                }
                let ctx = DispatchCtx {
                    role: Role::Controller,
                    user_id: Some(user_id),
                    agent_id: None,
                    controller_name: Some(controller_name),
                    controller_tx: Some(tx),
                    consent_mode,
                    override_reason,
                    input_mode,
                    tenant_name,
                    may_record,
                    rc_overlay,
                    session_policy,
                    max_duration,
                    idle_secs,
                    lock_on_end,
                    org_session_cap,
                    slot: slot.clone(),
                };
                let dispatched = state.fleet.rc_hub.dispatch(&ctx, frame);
                if let Some(lease) = &slot {
                    let created = state
                        .fleet
                        .rc_hub
                        .session_snapshot(lease.session)
                        .map(|_| lease.session);
                    crate::slots::release_unused(&state, lease, created).await;
                }
                match dispatched {
                    Ok(()) => Ok(serde_json::json!({ "dispatched": true })),
                    Err(e) => Ok(serde_json::json!({
                        "dispatched": false,
                        "code": crate::controller::error_code(&e),
                        // FR-115 P3 — the same words the local path sends
                        // (who holds the slot, on which device).
                        "message": crate::controller::refusal_message(&state, &e).await,
                    })),
                }
            })
        });
    }

    // rc.conn_closed - the origin pod's browser socket died; tear the
    // proxy down (unregister terminates the conn's sessions, freeing
    // the agent's slot, exactly like a local tab close).
    {
        let state = state.clone();
        bus.register("rc.conn_closed", move |body| {
            let state = state.clone();
            Box::pin(async move {
                let conn = body
                    .get("conn")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing conn".to_string())?;
                let removed = remove_proxy(&state, conn);
                Ok(serde_json::json!({ "removed": removed }))
            })
        });
    }

    // rc.conn_alive - "does this connection id still have a live
    // socket here?" (sweep probe; answered by the ORIGIN pod).
    {
        let state = state.clone();
        bus.register("rc.conn_alive", move |body| {
            let state = state.clone();
            Box::pin(async move {
                let conn = body
                    .get("conn")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing conn".to_string())?;
                let alive = state.ws_storage.get_sender_by_connection(conn).is_some();
                Ok(serde_json::json!({ "alive": alive }))
            })
        });
    }

    // Janitor sweep: probe QUIET proxies' origin pods; tear down on a
    // negative answer or a dead origin (deadline). A healthy quiet
    // session keeps its proxy as long as the origin conn answers alive.
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(bus) = state.cluster_bus.clone() else {
                    continue;
                };
                let quiet: Vec<(String, String)> = state
                    .rc_proxy_controllers
                    .iter()
                    .filter(|e| {
                        e.value().last_seen.lock().unwrap().elapsed() > PROBE_WHEN_QUIET_FOR
                    })
                    .map(|e| (e.key().clone(), e.value().origin_pod.clone()))
                    .collect();
                for (conn, origin) in quiet {
                    if origin.is_empty() {
                        continue;
                    }
                    let alive = match bus
                        .request(
                            &origin,
                            "rc.conn_alive",
                            serde_json::json!({ "conn": conn }),
                        )
                        .await
                    {
                        Ok(rep) => rep.get("alive").and_then(|v| v.as_bool()).unwrap_or(false),
                        // Deadline = origin pod presumed dead; its
                        // sockets died with it.
                        Err(_) => false,
                    };
                    if !alive {
                        warn!(conn = %conn, %origin, "rc relay: origin conn gone; reaping proxy");
                        remove_proxy(&state, &conn);
                    } else {
                        // Alive: push last_seen forward so the next
                        // sweep does not re-probe immediately.
                        if let Some(p) = state.rc_proxy_controllers.get(&conn) {
                            *p.last_seen.lock().unwrap() = Instant::now();
                        }
                    }
                }
            }
        });
    }
}

/// Tear down one proxy: Hub unregister (terminates its sessions +
/// notifies both sides) + pump abort. Returns whether it existed.
pub fn remove_proxy(state: &RemoteState, conn: &str) -> bool {
    let Some((_, proxy)) = state.rc_proxy_controllers.remove(conn) else {
        return false;
    };
    state
        .fleet
        .rc_hub
        .unregister_controller(proxy.user_id, &proxy.tx);
    proxy.pump.abort();
    debug!(conn = %conn, "rc relay: proxy controller removed");
    true
}

/// Controller-pod side: forward one raw rc frame to `owner_pod`.
/// Returns:
/// - `Ok(None)`: dispatched remotely - suppress local error handling
///   (replies stream back conn-addressed).
/// - `Ok(Some((code, message)))`: the owner's Hub refused - surface it
///   locally as `rc:error` (same as a local dispatch failure).
/// - `Err(())`: the relay itself failed (no bus / deadline / NACK) -
///   fall back to the PR-1 rehome path.
#[allow(clippy::too_many_arguments)]
pub async fn relay_rc_frame(
    state: &RemoteState,
    owner_pod: &str,
    conn: &str,
    user_id: ObjectId,
    controller_name: &str,
    consent_mode: ConsentMode,
    override_reason: &Option<String>,
    input_mode: Option<InputMode>,
    tenant_name: &Option<String>,
    // FR-85 P3 — the origin pod ran the authz gate; the owner pod's hub
    // strips RECORD without it.
    may_record: bool,
    // #1882 — resolved by the same gate; the owner pod reads absent as off.
    rc_overlay: bool,
    // FR-101 P2 — the org's session policy, read by the same gate. ⚠️ The
    // owner pod's hub applies it; without this a cross-pod session would
    // skip the org's switches.
    session_policy: OrgPolicy,
    // FR-101 P4b — the org's maximum session length; the owner pod's hub
    // arms it when the session goes live.
    max_duration: Option<std::time::Duration>,
    // P4b-2 — the idle limit; the owner pod's hub sends it to the agent.
    idle_secs: Option<u32>,
    // FR-99 P3b — the device's lock ask; the owner pod's hub sends it to an
    // agent that honours it.
    lock_on_end: Option<roomler_ai_remote_control::models::LockOnEnd>,
    // FR-115 P3 — the device org's concurrent-session cap; the owner pod's
    // hub counts the org's live sessions against it. ⚠️ Without it a
    // session landing on the other pod would skip the cap.
    org_session_cap: Option<u32>,
    raw_frame: &serde_json::Value,
) -> Result<Option<(String, String)>, ()> {
    let Some(bus) = state.cluster_bus.clone() else {
        return Err(());
    };
    if owner_pod.is_empty() {
        return Err(());
    }
    let body = serde_json::json!({
        "conn": conn,
        "origin": state.pod.pod_id,
        "user_id": user_id.to_hex(),
        "controller_name": controller_name,
        "consent_mode": consent_mode,
        "override_reason": override_reason,
        "input_mode": input_mode,
        "tenant_name": tenant_name,
        "may_record": may_record,
        "rc_overlay": rc_overlay,
        "session_policy": session_policy_to_relay(session_policy),
        "max_secs": max_duration.map(|d| d.as_secs()),
        "idle_secs": idle_secs,
        "lock_on_end": lock_on_end,
        "org_session_cap": org_session_cap,
        "frame": raw_frame,
    });
    match bus.request(owner_pod, "rc.cmd", body).await {
        Ok(rep) => {
            if rep
                .get("dispatched")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                // Remember the remote home so (a) later session-scoped
                // frames route there and (b) the WS close forwards the
                // teardown notice.
                state
                    .remote_rc_conns
                    .entry(conn.to_string())
                    .or_default()
                    .insert(owner_pod.to_string());
                roomler_core::cluster::metrics::bump(
                    &roomler_core::cluster::metrics::RC_RELAY_TOTAL,
                );
                Ok(None)
            } else {
                let code = rep
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("relay_error")
                    .to_string();
                let message = rep
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("remote dispatch failed")
                    .to_string();
                Ok(Some((code, message)))
            }
        }
        Err(e) => {
            debug!(%owner_pod, %e, "rc relay: rc.cmd failed; falling back to rehome");
            // The owner may have moved meanwhile - forget this route.
            if let Some(mut set) = state.remote_rc_conns.get_mut(conn) {
                set.remove(owner_pod);
            }
            state.remote_rc_conns.remove_if(conn, |_, s| s.is_empty());
            Err(())
        }
    }
}

/// Controller-pod side: the browser socket closed - notify every owner
/// pod that hosted proxied sessions for this conn (fire-and-forget;
/// the janitor sweep is the belt if the notice is lost).
pub fn forward_conn_closed(state: &RemoteState, conn: &str) {
    let Some((_, owners)) = state.remote_rc_conns.remove(conn) else {
        return;
    };
    let Some(bus) = state.cluster_bus.clone() else {
        return;
    };
    for owner in owners {
        let bus = bus.clone();
        let conn = conn.to_string();
        tokio::spawn(async move {
            let _ = bus
                .request(
                    &owner,
                    "rc.conn_closed",
                    serde_json::json!({ "conn": conn }),
                )
                .await;
        });
    }
}

/// conn id -> owner pods hosting proxied rc sessions for it.
pub type RemoteRcConns = DashMap<String, HashSet<String>>;

/// FR-101 P2 — the gate's [`OrgPolicy`] in the relay body: the policy as an
/// object, or `"unavailable"` when the origin pod could not read it.
fn session_policy_to_relay(policy: OrgPolicy) -> serde_json::Value {
    match policy {
        OrgPolicy::Read(p) => serde_json::to_value(p).unwrap_or(serde_json::Value::Null),
        OrgPolicy::Unavailable => serde_json::Value::from("unavailable"),
    }
}

/// FR-101 P2 — the owner pod's reading of the relay body's `session_policy`.
///
/// ⚠️ ABSENT reads as unrestricted, unlike `may_record`'s absent-is-false:
/// it comes from an origin pod older than the feature, which applied no
/// policy and would have granted these features itself. Mid-roll, a pair of
/// pods on different builds cannot promise the policy in either direction
/// (an older OWNER pod ignores the field just as surely), and failing closed
/// here would take clipboard and files from every cross-pod session during
/// each roll, of orgs that set nothing. Anything present but unreadable is
/// our own pod's garbage and fails closed.
fn session_policy_from_relay(v: Option<&serde_json::Value>) -> OrgPolicy {
    match v {
        None | Some(serde_json::Value::Null) => OrgPolicy::Read(SessionPolicy::default()),
        Some(v @ serde_json::Value::Object(_)) => serde_json::from_value(v.clone())
            .map(OrgPolicy::Read)
            .unwrap_or(OrgPolicy::Unavailable),
        Some(_) => OrgPolicy::Unavailable,
    }
}

/// FR-99 P3b — the device's lock ask on the owner pod's side of the relay.
/// Absent or null is no ask: an origin pod older than the field asked
/// nothing of the device itself. `never` asks nothing either. A value this
/// build cannot read reads as `always`, the stricter side, as
/// `LockOnEnd` reads one everywhere.
fn lock_ask_from_relay(
    v: Option<&serde_json::Value>,
) -> Option<roomler_ai_remote_control::models::LockOnEnd> {
    use roomler_ai_remote_control::models::LockOnEnd;
    match v {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => serde_json::from_value::<LockOnEnd>(v.clone())
            .ok()
            .filter(|l| *l > LockOnEnd::Never),
    }
}

#[cfg(test)]
mod lock_ask_relay_tests {
    use super::*;
    use roomler_ai_remote_control::models::LockOnEnd;

    /// The ask crosses the relay as the origin's gate resolved it; an older
    /// origin pod's body (no field) asks nothing.
    #[test]
    fn the_lock_ask_crosses_the_relay_as_asked() {
        assert_eq!(lock_ask_from_relay(None), None);
        assert_eq!(lock_ask_from_relay(Some(&serde_json::Value::Null)), None);
        assert_eq!(lock_ask_from_relay(Some(&serde_json::json!("never"))), None);
        assert_eq!(
            lock_ask_from_relay(Some(&serde_json::json!("auto"))),
            Some(LockOnEnd::Auto)
        );
        assert_eq!(
            lock_ask_from_relay(Some(&serde_json::json!("always"))),
            Some(LockOnEnd::Always)
        );
        assert_eq!(
            lock_ask_from_relay(Some(&serde_json::json!("on_tuesdays"))),
            Some(LockOnEnd::Always)
        );
        // What `relay_rc_frame` writes reads back the same.
        let body = serde_json::json!({ "lock_on_end": Some(LockOnEnd::Auto) });
        assert_eq!(
            lock_ask_from_relay(body.get("lock_on_end")),
            Some(LockOnEnd::Auto)
        );
    }
}

#[cfg(test)]
mod session_policy_relay_tests {
    use super::*;
    use roomler_ai_remote_control::models::FeaturePolicy;

    /// The origin pod's reading reaches the owner pod unchanged, both ways.
    #[test]
    fn the_policy_crosses_the_relay_as_read() {
        let p = SessionPolicy {
            clipboard: FeaturePolicy::Ask,
            files: FeaturePolicy::Off,
            audio: FeaturePolicy::On,
        };
        for policy in [
            OrgPolicy::Read(p),
            OrgPolicy::Read(SessionPolicy::default()),
            OrgPolicy::Unavailable,
        ] {
            let body = serde_json::json!({ "session_policy": session_policy_to_relay(policy) });
            assert_eq!(
                session_policy_from_relay(body.get("session_policy")),
                policy
            );
        }
    }

    /// An older origin pod sends no field: what it would have done itself.
    #[test]
    fn an_absent_policy_from_an_older_pod_is_unrestricted() {
        let body = serde_json::json!({ "may_record": false });
        assert_eq!(
            session_policy_from_relay(body.get("session_policy")),
            OrgPolicy::Read(SessionPolicy::default())
        );
    }

    /// Present but unreadable fails closed: a number, or a string other than
    /// `unavailable`. Inside an object, a value of the wrong type refuses that
    /// one feature, as `FeaturePolicy` reads it everywhere.
    #[test]
    fn a_present_but_unreadable_policy_refuses() {
        for bad in [serde_json::json!(7), serde_json::json!("on")] {
            assert_eq!(
                session_policy_from_relay(Some(&bad)),
                OrgPolicy::Unavailable,
                "{bad}"
            );
        }
        assert_eq!(
            session_policy_from_relay(Some(&serde_json::json!({ "files": 3 }))),
            OrgPolicy::Read(SessionPolicy {
                files: FeaturePolicy::Off,
                ..SessionPolicy::default()
            })
        );
    }
}
