// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The controller's side of remote desktop (FR-69 P6): the `rc:*` frames a
//! browser tab sends over the user socket — the authz + consent-mode gate
//! for `rc:session.request`, the dispatch into the Hub, and the cross-pod
//! paths when the agent is homed on another pod (relay first, rehome
//! second). The host's user socket keeps the upgrade, the Hub registration
//! of the controller's sender and the pump; it hands each `rc:*` text frame
//! to [`handle_controller_frame`] with that sender, and treats a `false` as
//! "not ours".

use bson::oid::ObjectId;
use roomler_ai_mod_fleet::hub::{DispatchCtx, OrgPolicy};
use roomler_ai_mod_fleet::nudge::{note_agent_offline_evidence, spawn_agent_nudge};
use roomler_ai_remote_control::{
    models::ConsentMode,
    signaling::{ClientMsg, Role, ServerMsg},
};
use tracing::{info, warn};

use crate::RemoteState;

/// One controller frame, with what the socket knows about the connection
/// that sent it.
pub struct ControllerFrame<'a> {
    pub user_id: ObjectId,
    /// The controller's display name (what the host's consent prompt shows).
    pub controller_name: &'a str,
    /// The Hub-registered sender for this browser connection: how replies
    /// and errors reach the tab.
    pub controller_tx: &'a roomler_ai_remote_control::session::ClientTx,
    /// The raw text frame (parsed here, not by the socket).
    pub text: &'a str,
    /// PR-1 rehome — the affinity key this connection dialed with (`None` =
    /// a key-less dial) and when it established.
    pub dialed_tid: Option<&'a str>,
    pub conn_established_ms: i64,
    /// PR-2 relay — the connection id the owner pod's proxy routes replies to.
    pub connection_id: &'a str,
}

/// FR-101 P4a — how many session requests one caller may send one device in a
/// minute. No legitimate client comes near it. The viewer's reconnect ladder
/// (250 ms doubling to a steady 8 s, `RC_RECONNECT_LADDER_MS`) asks about a
/// dozen times in its first minute, so this leaves room for several tabs at
/// once. A refusal still spends a slot (`RateLimiter::check`), so a caller who
/// keeps hammering stays refused for the window, and `rate_limited` is not a
/// code the viewer retries.
pub const SESSION_REQUESTS_PER_MINUTE: u32 = 60;

/// The whole controller path for one `rc:*` frame: the authz gate, the
/// session-request ceiling, then the dispatch. Returns `false` when the frame
/// was not an `rc:*` message at all
/// (the socket then runs its other arms); a denial is answered on the
/// controller's sender and counts as handled.
pub async fn handle_controller_frame(state: &RemoteState, frame: ControllerFrame<'_>) -> bool {
    if matches!(
        serde_json::from_str::<ClientMsg>(frame.text),
        Ok(ClientMsg::SharedLeaseChallenge { .. })
    ) {
        let _ = frame.controller_tx.try_send(ServerMsg::Error {
            session_id: None,
            code: "permission_denied".into(),
            message: "Shared lease challenges are authenticated-agent-only".into(),
            open_nonce: None,
        });
        return true;
    }
    // FR-52 P3c — an external-access login is not a session: it has its own
    // gates and never reaches the Hub. Before the authz gate below, which
    // would judge an outsider by a membership they do not have.
    if let Some(handled) = crate::extauth::intercept(state, &frame) {
        return handled;
    }
    // Authorization + consent-mode gate for `rc:session.request`
    // (self-control / admin / REMOTE_CONTROL + per-device allowlist +
    // quarantine). A non-request rc:* message resolves to `Ok(Prompt)` and
    // falls straight through to dispatch (the mode is unused for it).
    let authz = match resolve_session_authz(state, frame.user_id, frame.text).await {
        Ok(a) => a,
        Err(reason) => {
            warn!(user_id = ?frame.user_id, %reason, "rc:session.request denied by authz gate");
            let _ = frame.controller_tx.try_send(ServerMsg::Error {
                session_id: None,
                code: "permission_denied".to_string(),
                message: reason,
                open_nonce: None,
            });
            return true;
        }
    };
    // FR-101 P4a — the ceiling, checked AFTER the authz gate, as exec's is.
    // A refusal then names a caller who was allowed to ask at all, and a
    // caller who was not never spends a slot. Session requests ride the
    // control WS, which the per-IP HTTP governor never sees: without this a
    // signed-in caller could ask one device for sessions as fast as the socket
    // carries them, each a consent prompt in front of the person there.
    if let Ok(ClientMsg::SessionRequest { agent_id, .. }) =
        serde_json::from_str::<ClientMsg>(frame.text)
        && !state.session_request_limiter.check(
            frame.user_id,
            agent_id,
            SESSION_REQUESTS_PER_MINUTE,
        )
    {
        warn!(
            user_id = %frame.user_id,
            %agent_id,
            limit = SESSION_REQUESTS_PER_MINUTE,
            "rc:session.request refused: over the per-device ceiling"
        );
        let _ = frame.controller_tx.try_send(ServerMsg::Error {
            session_id: None,
            code: "rate_limited".to_string(),
            message: format!(
                "Too many session requests to this device: at most {SESSION_REQUESTS_PER_MINUTE} a \
                 minute. Wait a minute and connect again."
            ),
            open_nonce: None,
        });
        return true;
    }
    dispatch_controller_rc(
        state,
        frame.user_id,
        frame.controller_name,
        frame.controller_tx,
        frame.text,
        authz.mode,
        authz.override_reason,
        authz.input_mode,
        authz.tenant_name,
        authz.may_record,
        authz.rc_overlay,
        authz.session_policy,
        authz.max_duration,
        authz.idle_secs,
        authz.lock_on_end,
        authz.org_session_cap,
        frame.dialed_tid,
        frame.conn_established_ms,
        frame.connection_id,
    )
    .await
}

/// Route a parsed `rc:*` message coming from a controller browser tab.
/// Returns `true` if the message was handled, `false` if it wasn't rc:*.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_controller_rc(
    state: &RemoteState,
    user_id: ObjectId,
    controller_name: &str,
    controller_tx: &roomler_ai_remote_control::session::ClientTx,
    text: &str,
    consent_mode: ConsentMode,
    override_reason: Option<String>,
    // P6 — the device's `AccessPolicy.input_mode` (resolved by the authz
    // gate alongside `consent_mode`); forwarded to the agent's arbiter.
    input_mode: Option<roomler_ai_remote_control::models::InputMode>,
    // Multi-org — the org name the host's consent prompt should name
    // (resolved by the same gate).
    tenant_name: Option<String>,
    // FR-85 P3 — may this controller record (resolved by the same gate)?
    may_record: bool,
    // #1882 — may the session use the overlay (the device's policy, resolved
    // by the same gate)?
    rc_overlay: bool,
    // FR-101 P2 — the org's session policy (resolved by the same gate).
    session_policy: OrgPolicy,
    // FR-101 P4b — the org's maximum session length (the same gate).
    max_duration: Option<std::time::Duration>,
    // P4b-2 — the idle limit, org's and device's (the same gate).
    idle_secs: Option<u32>,
    // FR-99 P3b — the device's lock ask (the same gate).
    lock_on_end: Option<roomler_ai_remote_control::models::LockOnEnd>,
    // FR-115 P3 — the device org's concurrent-session cap (the same gate).
    org_session_cap: Option<u32>,
    // PR-1 rehome direction inputs: the affinity key this conn DIALED
    // with (None = key-less legacy/racy dial) and when it established.
    dialed_tid: Option<&str>,
    conn_established_ms: i64,
    // PR-2 relay: this browser socket's connection id - the address the
    // owner pod's proxy pump routes replies back to.
    connection_id: &str,
) -> bool {
    let hub = &state.fleet.rc_hub;
    let Ok(parsed) = serde_json::from_str::<ClientMsg>(text) else {
        return false;
    };
    let is_session_request = matches!(&parsed, ClientMsg::SessionRequest { .. });
    // FR-115 P3b — on the pod that owns the device, the org's cap is a
    // cluster-wide slot, claimed here because the hub is synchronous: the
    // org's own sessions and the external ones run for it share one count.
    // A device on another pod is claimed for there, when the relay lands.
    let mut org_session_cap = org_session_cap;
    let mut slot = None;
    if let ClientMsg::SessionRequest { agent_id, .. } = &parsed
        && let Some(cap) = org_session_cap
        && crate::slots::enabled(state)
        && let Some(org) = hub.agent_org(*agent_id)
    {
        use crate::slots::SlotDecision;
        use roomler_core::cluster::session_slots::SlotScope;
        match crate::slots::claim(state, SlotScope::Org(org), user_id, *agent_id, cap).await {
            SlotDecision::Claimed(lease) => {
                slot = Some(lease);
                org_session_cap = None; // the slot IS the count
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
                let _ = controller_tx.try_send(ServerMsg::Error {
                    session_id: None,
                    code: error_code(&e).to_string(),
                    message: refusal_message(state, &e).await,
                    open_nonce: None,
                });
                return true;
            }
        }
    }
    let ctx = DispatchCtx {
        role: Role::Controller,
        user_id: Some(user_id),
        agent_id: None,
        controller_name: Some(controller_name.to_string()),
        controller_tx: Some(controller_tx.clone()),
        consent_mode,
        // PR-2: the relay needs its own copy after ctx takes this one.
        override_reason: override_reason.clone(),
        input_mode,
        tenant_name: tenant_name.clone(),
        may_record,
        rc_overlay,
        session_policy,
        max_duration,
        idle_secs,
        lock_on_end,
        org_session_cap,
        slot: slot.clone(),
    };
    // …and so does the cross-pod relay, for the same reason.
    let relay_tenant_name = tenant_name;
    // Recheck the share at the actual creation site, not just a UI/check endpoint.
    let shared_scope = match crate::device_share::scope_for_request(state, user_id, &parsed).await {
        Ok(v) => v.map(|(mut scope, _)| {
            scope.consent_mode = ctx.consent_mode;
            scope
        }),
        Err(reason) => {
            if let Some(lease) = &slot {
                crate::slots::release_unused(state, lease, None).await;
            }
            let _ = controller_tx.try_send(ServerMsg::Error {
                session_id: None,
                code: "permission_denied".into(),
                message: reason,
                open_nonce: None,
            });
            return true;
        }
    };
    let mut created_session = None;
    let dispatched = if shared_scope.is_some() {
        hub.dispatch_capturing_session(&ctx, parsed, &mut created_session)
    } else {
        hub.dispatch(&ctx, parsed)
    };
    if dispatched.is_ok()
        && let (Some(scope), Some(session)) = (shared_scope, created_session)
    {
        crate::device_share::watch_session(state.clone(), session, scope);
    }
    // FR-115 P3b — a slot the hub did not take (it refused, or coalesced the
    // request into a session that already exists) goes back now.
    if let Some(lease) = &slot {
        let created = hub.session_snapshot(lease.session).map(|_| lease.session);
        crate::slots::release_unused(state, lease, created).await;
    }
    if let Err(e) = dispatched {
        warn!(%user_id, %e, "rc:* dispatch failed (controller)");
        // C-2 rehome: a SessionRequest that missed the LOCAL hub while a
        // FOREIGN pod holds a fresh presence record is a cross-pod split,
        // not a real offline. Tell the controller which state it's in
        // (`agent_on_other_pod` → the UI force-redials its WS and retries
        // once) and nudge the owning pod to cycle the agent's WS if idle —
        // both ends then re-land at the current LB hash. Probe budget
        // 250 ms; on any probe failure fall through to the honest
        // `agent_offline`.
        if is_session_request
            && let roomler_ai_remote_control::error::Error::AgentOffline(agent_hex) = &e
            && let Some(redis) = &state.redis_pubsub
            && let Ok(Ok(Some(owner))) = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                redis.agent_presence_foreign(agent_hex),
            )
            .await
        {
            note_agent_offline_evidence(state, agent_hex.clone(), "controller_session");
            roomler_core::cluster::metrics::bump(&roomler_core::cluster::metrics::RC_REHOME_TOTAL);
            let record = roomler_core::cluster::directory::OwnerRecord::parse(&owner);
            let owner_pod = record
                .as_ref()
                .map(|r| r.pod_id.clone())
                .unwrap_or_default();
            let agent_since_ms = record.map(|r| r.since_ms).unwrap_or(0);
            // PR-2 relay FIRST: make the cross-pod session WORK now;
            // convergence (controller re-key, or the agent's own next
            // natural reconnect) proceeds without user-visible errors.
            // No nudge on the relay path - an idle-nudge racing the
            // relayed create would tear the session it just built.
            if let Ok(frame_val) = serde_json::from_str::<serde_json::Value>(text) {
                match crate::relay::relay_rc_frame(
                    state,
                    &owner_pod,
                    connection_id,
                    user_id,
                    controller_name,
                    consent_mode,
                    &override_reason,
                    input_mode,
                    &relay_tenant_name,
                    may_record,
                    rc_overlay,
                    session_policy,
                    max_duration,
                    idle_secs,
                    lock_on_end,
                    org_session_cap,
                    &frame_val,
                )
                .await
                {
                    Ok(None) => {
                        info!(
                            %user_id,
                            agent = %agent_hex,
                            %owner_pod,
                            "cross-pod rc miss: relayed to owner pod"
                        );
                        return true;
                    }
                    Ok(Some((code, message))) => {
                        // The owner's Hub answered authoritatively
                        // (agent_busy, permission_denied, ...) - same
                        // surface as a local dispatch failure.
                        let _ = controller_tx.try_send(ServerMsg::Error {
                            session_id: None,
                            code,
                            message,
                            open_nonce: None,
                        });
                        return true;
                    }
                    Err(()) => { /* relay unavailable - PR-1 path below */ }
                }
            }
            // PR-1 direction rule: only a correctly-keyed conn that is
            // provably NEWER than the agent's registration justifies
            // nudging the agent; every other shape means the CONTROLLER
            // is the mis-placed party (the 2026-08-04 incident) and a
            // nudge would bounce a correctly-homed, possibly busy agent.
            // One agent lookup for its tenant; on failure the helper
            // falls back to controller-moves (never nudge on doubt).
            let agent_tenant_hex = match ObjectId::parse_str(agent_hex) {
                Ok(aid) => state
                    .fleet
                    .agents
                    .base
                    .find_by_id(aid)
                    .await
                    .map(|a| a.tenant_id.to_hex())
                    .unwrap_or_default(),
                Err(_) => String::new(),
            };
            let direction = roomler_ai_mod_fleet::nudge::rehome_direction(
                dialed_tid,
                &agent_tenant_hex,
                conn_established_ms,
                agent_since_ms,
                state.settings.rc.rehome_direction_guard_ms,
            );
            match direction {
                roomler_ai_mod_fleet::nudge::RehomeDirection::ControllerMove { reason } => {
                    roomler_core::cluster::metrics::bump(
                        &roomler_core::cluster::metrics::RC_REHOME_CONTROLLER_TOTAL,
                    );
                    info!(
                        %user_id,
                        agent = %agent_hex,
                        %owner_pod,
                        ?dialed_tid,
                        reason,
                        "cross-pod rc miss: controller re-dials (nudge suppressed)"
                    );
                }
                roomler_ai_mod_fleet::nudge::RehomeDirection::NudgeAgent => {
                    info!(
                        %user_id,
                        agent = %agent_hex,
                        %owner_pod,
                        "cross-pod rc miss: agent judged parked; nudging owner pod"
                    );
                    spawn_agent_nudge(&state.fleet, owner_pod, agent_hex.clone());
                }
            }
            // Pod identity stays in server logs; the wire carries only
            // the actionable fact (the UI re-keys + redials on it).
            let _ = controller_tx.try_send(ServerMsg::Error {
                session_id: None,
                code: "agent_on_other_pod".to_string(),
                message: "agent is homed on another pod; re-dial and retry".to_string(),
                open_nonce: None,
            });
            return true;
        }
        // PR-2: a session-scoped frame (answer / ice / terminate) whose
        // session lives on another pod - this conn relayed its create
        // there. Forward it: the owner holding the session dispatches;
        // an owner that lost it answers session_not_found, which is the
        // honest surface either way.
        if matches!(
            &e,
            roomler_ai_remote_control::error::Error::SessionNotFound(_)
        ) {
            let owners: Vec<String> = state
                .remote_rc_conns
                .get(connection_id)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            if !owners.is_empty()
                && let Ok(frame_val) = serde_json::from_str::<serde_json::Value>(text)
            {
                let mut refusal: Option<(String, String)> = None;
                for owner in owners {
                    match crate::relay::relay_rc_frame(
                        state,
                        &owner,
                        connection_id,
                        user_id,
                        controller_name,
                        consent_mode,
                        &override_reason,
                        input_mode,
                        &relay_tenant_name,
                        may_record,
                        rc_overlay,
                        session_policy,
                        max_duration,
                        idle_secs,
                        lock_on_end,
                        org_session_cap,
                        &frame_val,
                    )
                    .await
                    {
                        Ok(None) => return true,
                        Ok(Some(cm)) => refusal = Some(cm),
                        Err(()) => {}
                    }
                }
                if let Some((code, message)) = refusal {
                    let _ = controller_tx.try_send(ServerMsg::Error {
                        session_id: error_session_id(&e),
                        code,
                        message,
                        open_nonce: None,
                    });
                    return true;
                }
            }
        }
        // Phase A-1 split-evidence probe for the remaining offline paths
        // (non-session-request messages, probe timeouts).
        if let roomler_ai_remote_control::error::Error::AgentOffline(agent_hex) = &e {
            note_agent_offline_evidence(state, agent_hex.clone(), "controller_session");
        }
        // Surface the failure to the controller so the UI can exit its
        // "Requesting session…" spinner instead of hanging. Best-effort —
        // the controller may already be closing.
        let message = refusal_message(state, &e).await;
        let _ = controller_tx.try_send(ServerMsg::Error {
            session_id: error_session_id(&e),
            code: error_code(&e).to_string(),
            message,
            open_nonce: None,
        });
    }
    true
}

/// The message a refused controller reads. `e.to_string()` for every error
/// but FR-115's session cap, where the hub hands over only ids: those become
/// who holds the slot and on which device, so the person asking can end
/// that session or upgrade. A lookup that fails falls back to the plain
/// sentence, never to an error of its own.
pub(crate) async fn refusal_message(
    state: &RemoteState,
    e: &roomler_ai_remote_control::Error,
) -> String {
    let roomler_ai_remote_control::Error::OrgSessionLimit {
        cap,
        holder_user,
        holder_agent,
    } = e
    else {
        return e.to_string();
    };
    let who = match ObjectId::parse_str(holder_user) {
        Ok(uid) => state
            .users
            .base
            .find_by_id(uid)
            .await
            .ok()
            .map(|u| u.display_name)
            .filter(|n| !n.trim().is_empty()),
        Err(_) => None,
    };
    let device = match ObjectId::parse_str(holder_agent) {
        Ok(aid) => state
            .fleet
            .agents
            .base
            .find_by_id(aid)
            .await
            .ok()
            .map(|a| a.display_name.unwrap_or(a.name))
            .filter(|n| !n.trim().is_empty()),
        Err(_) => None,
    };
    let at_a_time = if *cap == 1 {
        "one remote session at a time".to_string()
    } else {
        format!("{cap} remote sessions at a time")
    };
    let holder = match (who, device) {
        (Some(w), Some(d)) => format!("{w} is connected to {d} right now"),
        (Some(w), None) => format!("{w} is in a session right now"),
        (None, Some(d)) => format!("a session to {d} is open right now"),
        (None, None) => "a session is open right now".to_string(),
    };
    // A cap above one is Pro's, one per billed seat: it already has "one per
    // user", so the way past it is a session ending or Business.
    let way_out = if *cap == 1 {
        "End that session, or upgrade the plan for one remote session per user."
    } else {
        "End a session, or move to Business for sessions without a cap."
    };
    format!("Your organization's plan runs {at_a_time}, and {holder}. {way_out}")
}

/// Result of the session authz gate: the effective consent mode plus a VALIDATED
/// admin break-glass reason (Phase 5). `override_reason` is `Some` only when an
/// `ADMINISTRATOR` force-started a device they don't own with a non-empty reason
/// — in which case `mode` is `Auto` (consent skipped) and the Hub records an
/// `AdminOverride` audit.
pub struct SessionAuthz {
    pub mode: ConsentMode,
    pub override_reason: Option<String>,
    /// P6 — the device's `AccessPolicy.input_mode` (None = free default).
    pub input_mode: Option<roomler_ai_remote_control::models::InputMode>,
    /// Multi-org — display name of the organization this session happens in,
    /// so the host's consent prompt can say WHICH org is asking. Resolved
    /// from the agent row the gate already loads. `None` on the early-out
    /// paths (non-session-request, unknown agent) where no prompt follows.
    pub tenant_name: Option<String>,
    /// FR-85 P3 — may this controller RECORD the device's screen? The
    /// device's owner, an ADMINISTRATOR, or a holder of
    /// `RECORD_REMOTE_SCREEN` — and ⚠️ never under break-glass: that path
    /// forces `ConsentMode::Auto`, and a forced, unconsented session that
    /// could also record would be covert monitoring (docs §11.4). The hub
    /// strips `Permissions::RECORD` from the grant when this is false.
    pub may_record: bool,
    /// #1882 — the device's `AccessPolicy.rc_overlay`, resolved: may the
    /// session's ICE use the WireGuard overlay? Like `input_mode` it is the
    /// DEVICE's setting and rides every allowed outcome; `false` on the
    /// early-out paths, which never build a session.
    pub rc_overlay: bool,
    /// FR-101 P2 — the org's session policy for clipboard, files and audio,
    /// from the tenant row this gate already reads. It binds every
    /// controller, the owner and break-glass included (the hub decides what
    /// `ask` means for each). [`OrgPolicy::Unavailable`] on the early-out
    /// paths and when the row could not be read, so a database blip refuses
    /// the features instead of granting them on a guess.
    pub session_policy: OrgPolicy,
    /// FR-101 P4b — the org's maximum session length, from the same tenant
    /// row; every controller is bound by it. `None` when unset, on the
    /// early-out paths, and when the row could not be read: no limit, the
    /// behaviour from before it, rather than ending sessions on a guess.
    pub max_duration: Option<std::time::Duration>,
    /// FR-101 P4b-2 — the idle limit in seconds: the shorter of the org's
    /// (the same tenant row) and the device's own
    /// (`AccessPolicy::auto_terminate_idle_minutes`). The device keeps it.
    /// `None` when neither sets one and on the early-out paths; an unreadable
    /// tenant row leaves the device's own, never a guess at the org's.
    pub idle_secs: Option<u32>,
    /// FR-99 P3b — what the device's access policy asks of the session's end
    /// (`AccessPolicy::lock_on_end_ask`). It binds every controller, the
    /// owner and break-glass included: it describes the device, not who is
    /// asking. `None` when nothing is asked and on the early-out paths.
    pub lock_on_end: Option<roomler_ai_remote_control::models::LockOnEnd>,
    /// FR-115 P3 — how many remote sessions the device's org may run at once
    /// ([`org_session_cap_of`]), counted by the hub that owns the device. It
    /// binds every controller, the owner and break-glass included. `None`
    /// for an unlimited plan, with the kill switch off, on the early-out
    /// paths, and when the tenant row could not be read.
    pub org_session_cap: Option<u32>,
}

impl SessionAuthz {
    fn allow(mode: ConsentMode) -> Self {
        Self {
            mode,
            override_reason: None,
            input_mode: None,
            tenant_name: None,
            may_record: false,
            rc_overlay: false,
            session_policy: OrgPolicy::Unavailable,
            max_duration: None,
            idle_secs: None,
            lock_on_end: None,
            org_session_cap: None,
        }
    }
    fn allow_with_input(
        mode: ConsentMode,
        input_mode: Option<roomler_ai_remote_control::models::InputMode>,
        tenant_name: Option<String>,
        rc_overlay: bool,
        session_policy: OrgPolicy,
    ) -> Self {
        Self {
            mode,
            override_reason: None,
            input_mode,
            tenant_name,
            may_record: false,
            rc_overlay,
            session_policy,
            max_duration: None,
            idle_secs: None,
            lock_on_end: None,
            org_session_cap: None,
        }
    }
    /// FR-85 P3 — set whether this allowed controller may record.
    fn recording(mut self, may_record: bool) -> Self {
        self.may_record = may_record;
        self
    }
    /// FR-101 P4b — set the org's maximum session length and (P4b-2) the
    /// idle limit.
    fn limited(
        mut self,
        max_duration: Option<std::time::Duration>,
        idle_secs: Option<u32>,
    ) -> Self {
        self.max_duration = max_duration;
        self.idle_secs = idle_secs;
        self
    }
    /// FR-99 P3b — set the device's lock ask.
    fn lock_ask(
        mut self,
        lock_on_end: Option<roomler_ai_remote_control::models::LockOnEnd>,
    ) -> Self {
        self.lock_on_end = lock_on_end;
        self
    }
    /// FR-115 P3 — set the org's concurrent-session cap.
    fn capped(mut self, org_session_cap: Option<u32>) -> Self {
        self.org_session_cap = org_session_cap;
        self
    }
}

/// FR-115 P3 — an org's concurrent-session cap from its plan and billed seats
/// (Free: one; Pro: one per seat); `None` for an unlimited plan.
/// ESTABLISHED like the device cap: `plan_enforcement` does not soften it.
/// It landed with no org over it (the FR-115 census: peaks of four and three,
/// both on unlimited plans), so no grandfathering arises.
pub(crate) fn org_session_cap_of(t: &roomler_ai_db::models::Tenant) -> Option<u32> {
    let n = t.limits().max_concurrent_sessions;
    (n != u32::MAX).then_some(n)
}

/// Authorization + consent-mode gate for `rc:session.request` — the Hub can't
/// do this because the `remote_control` crate sits below `services` in the dep
/// graph and has no access to tenant roles. Returns `Ok(SessionAuthz)` for an
/// allowed request, or `Err(reason)` to DENY. A non-`SessionRequest` rc:* message
/// returns `Ok(allow(Prompt))` — those are intra-session and the mode is unused.
///
/// Layers (coarse→fine authz): quarantine → self-control → tenant capability
/// (`ADMINISTRATOR` / `REMOTE_CONTROL`) → per-agent allowlist (empty = no
/// per-device restriction). Consent mode: self-control → `Auto`; else the
/// device's `effective_consent_mode()`. **Break-glass (Phase 5):** an
/// `ADMINISTRATOR` who sends a non-empty `override_reason` for a device they
/// don't own gets `Auto` (consent skipped) + the reason carried through for the
/// `AdminOverride` audit.
pub async fn resolve_session_authz(
    state: &RemoteState,
    controller_user_id: ObjectId,
    text: &str,
) -> Result<SessionAuthz, String> {
    use roomler_ai_db::models::role::permissions;
    use roomler_ai_remote_control::models::AgentStatus;

    if let Ok(
        msg @ ClientMsg::SessionRequest {
            share_grant_id: Some(_),
            ..
        },
    ) = serde_json::from_str::<ClientMsg>(text)
    {
        return crate::device_share::session_authz(state, controller_user_id, &msg).await;
    }

    let (agent_id, override_reason) = match serde_json::from_str::<ClientMsg>(text) {
        Ok(ClientMsg::SessionRequest {
            agent_id,
            override_reason,
            ..
        }) => (agent_id, override_reason),
        // Not a session request → the mode is unused; allow through.
        _ => return Ok(SessionAuthz::allow(ConsentMode::Prompt)),
    };

    // Unknown / soft-deleted agent → let the Hub answer with a clean
    // AgentNotFound rather than surfacing a permission error (the mode is moot —
    // create_session will fail on the agent lookup).
    let agent = match state.fleet.agents.base.find_by_id(agent_id).await {
        Ok(a) if a.deleted_at.is_none() => a,
        _ => return Ok(SessionAuthz::allow(ConsentMode::Prompt)),
    };

    if agent.status == AgentStatus::Quarantined {
        return Err("device is quarantined; new sessions are blocked".to_string());
    }

    // P6 — the device's input arbitration mode rides every allowed outcome.
    let input_mode = agent.access_policy.input_mode;
    // #1882 — and so does whether its sessions may use the overlay.
    let rc_overlay = agent.access_policy.rc_overlay_allowed();
    // FR-99 P3b — and what its sessions ask of their end. The device takes
    // the stricter of this and its own setting, so it can only tighten.
    let lock_on_end = agent.access_policy.lock_on_end_ask();

    // Multi-org — the organization name the host's consent prompt will show.
    // One extra read, and only on a real session request (the early-outs above
    // never reach here). A failed lookup degrades the prompt to the agent's own
    // org label rather than failing the session.
    // The SAME read answers "is this org archived?", which must refuse the
    // session: an archived org stops acting (`routes::tenant::archive`).
    // A failed lookup degrades the prompt to the agent's own org label
    // rather than failing the session — it must not, however, be read as
    // "not archived" on a row we could not see, so only a successful read
    // can refuse.
    let tenant = state.tenants.base.find_by_id(agent.tenant_id).await.ok();
    if tenant.as_ref().is_some_and(|t| t.is_archived) {
        return Err("this organization is archived; new sessions are blocked".to_string());
    }
    // FR-101 P2 — the org's session policy, from the same read. A row we
    // could not see refuses the features rather than guessing they are on.
    let session_policy = match tenant.as_ref() {
        Some(t) => OrgPolicy::Read(crate::session_policy::wire(&t.settings.rc_session)),
        None => OrgPolicy::Unavailable,
    };
    // FR-101 P4b — and its maximum session length, if it set one.
    let max_duration = tenant
        .as_ref()
        .and_then(|t| t.settings.rc_limits.max_secs)
        .map(|secs| std::time::Duration::from_secs(u64::from(secs)));
    // P4b-2 — and its idle limit, held to the device's own when that one is
    // shorter: a device may tighten its org's limit, never loosen it. A row
    // we could not see leaves the device's own, never a guess at the org's.
    let idle_secs = roomler_ai_remote_control::models::stricter_idle_limit(
        tenant.as_ref().and_then(|t| t.settings.rc_limits.idle_secs),
        agent.access_policy.idle_limit_secs(),
    );
    // FR-115 P3 — the org's concurrent-session cap, from its plan and billed
    // seats; the hub that owns the device counts against it. A row we could
    // not see is no cap (never refuse on a guess), and `rc.org_session_cap`
    // is the kill switch. A server that sells no plans caps nobody
    // (`Core::plans_sold`: self-hosting is unlimited).
    let org_session_cap = if state.settings.rc.org_session_cap && state.plans_sold {
        tenant.as_ref().and_then(org_session_cap_of)
    } else {
        None
    };
    let tenant_name = tenant.map(|t| t.name);

    // Controlling your OWN device is always allowed. Whether it also
    // auto-consents is now the DEVICE's call (FR-27): `prompt_owner` unset —
    // every pre-FR-27 row, and the default — keeps the historical shortcut,
    // because unattended access to your own headless boxes is the common case
    // and prompting them asks a machine nobody is sitting at.
    //
    // ⚠️ This shortcut is why the consent picker looked broken. It short-circuits
    // BEFORE `effective_consent_mode()` is ever read, so on a fleet where one
    // person owns every device the setting had no observable effect at all —
    // and nothing on screen said so. The UI now labels it, and this flag is how
    // an owner opts into being asked (a shared workstation, or field-testing the
    // attended modes without a second account).
    if agent.owner_user_id == controller_user_id {
        // FR-85 P3 — the owner may record their own device.
        return Ok(SessionAuthz::allow_with_input(
            agent.access_policy.owner_consent_mode(),
            input_mode,
            tenant_name,
            rc_overlay,
            session_policy,
        )
        .recording(true)
        .limited(max_duration, idle_secs)
        .lock_ask(lock_on_end)
        .capped(org_session_cap));
    }

    // The effective mode for an allowed non-owner controller (attended default).
    let mode = agent.access_policy.effective_consent_mode();

    let perms = state
        .tenants
        .get_member_permissions(agent.tenant_id, controller_user_id)
        .await
        .unwrap_or(0);
    if permissions::has(perms, permissions::ADMINISTRATOR) {
        // Phase 5 break-glass: an ADMINISTRATOR may SKIP consent, but only with a
        // non-empty reason. A blank/absent reason ⇒ the admin gets the device's
        // normal consent mode (no forced override).
        if let Some(reason) = override_reason.filter(|r| !r.trim().is_empty()) {
            return Ok(SessionAuthz {
                mode: ConsentMode::Auto,
                override_reason: Some(reason),
                input_mode,
                tenant_name,
                // ⚠️ FR-85 P3 — never record under break-glass (§11.4): the
                // consent was skipped, so recording would be covert.
                may_record: false,
                rc_overlay,
                // FR-101 P2 — the org's policy binds break-glass too; its
                // `Auto` keeps no `ask` feature, since nobody was asked.
                session_policy,
                // FR-101 P4b — and so does its maximum session length.
                max_duration,
                // P4b-2 — and the idle limit: an unattended forced session
                // left open is the forgotten session the limit exists for.
                idle_secs,
                // FR-99 P3b — and the lock ask: a forced session is the one
                // whose end most needs the screen locked behind it.
                lock_on_end,
                // FR-115 P3 — and the org's session cap: break-glass is a
                // session like any other, and the refusal names the session
                // holding the slot, which an ADMINISTRATOR can end.
                org_session_cap,
            });
        }
        return Ok(SessionAuthz::allow_with_input(
            mode,
            input_mode,
            tenant_name.clone(),
            rc_overlay,
            session_policy,
        )
        .recording(true)
        .limited(max_duration, idle_secs)
        .lock_ask(lock_on_end)
        .capped(org_session_cap));
    }
    if !permissions::has(perms, permissions::REMOTE_CONTROL) {
        return Err("you don't have permission to control others' devices".to_string());
    }
    // FR-85 P3 — past the ADMINISTRATOR branch, recording is its own grant.
    let may_record = permissions::has(perms, permissions::RECORD_REMOTE_SCREEN);

    // Per-agent allowlist. Empty ⇒ no per-device restriction (any operator may
    // request; consent is the real gate). Non-empty ⇒ user or a role must match.
    let policy = &agent.access_policy;
    if policy.allowed_user_ids.is_empty() && policy.allowed_role_ids.is_empty() {
        return Ok(SessionAuthz::allow_with_input(
            mode,
            input_mode,
            tenant_name.clone(),
            rc_overlay,
            session_policy,
        )
        .recording(may_record)
        .limited(max_duration, idle_secs)
        .lock_ask(lock_on_end)
        .capped(org_session_cap));
    }
    if policy.allowed_user_ids.contains(&controller_user_id) {
        return Ok(SessionAuthz::allow_with_input(
            mode,
            input_mode,
            tenant_name.clone(),
            rc_overlay,
            session_policy,
        )
        .recording(may_record)
        .limited(max_duration, idle_secs)
        .lock_ask(lock_on_end)
        .capped(org_session_cap));
    }
    let role_ids = state
        .tenants
        .member_role_ids(agent.tenant_id, controller_user_id)
        .await
        .unwrap_or_default();
    if policy.allowed_role_ids.iter().any(|r| role_ids.contains(r)) {
        return Ok(SessionAuthz::allow_with_input(
            mode,
            input_mode,
            tenant_name.clone(),
            rc_overlay,
            session_policy,
        )
        .recording(may_record)
        .limited(max_duration, idle_secs)
        .lock_ask(lock_on_end)
        .capped(org_session_cap));
    }
    Err("you're not on this device's control allowlist".to_string())
}
/// Stable short code for the wire. Exhaustive match so a new
/// `remote_control::Error` variant triggers a compile error here rather
/// than silently being reported as "internal".
pub fn error_code(e: &roomler_ai_remote_control::Error) -> &'static str {
    use roomler_ai_remote_control::Error::*;
    match e {
        AgentOffline(_) => "agent_offline",
        AgentNotFound(_) => "agent_not_found",
        AgentBusy => "agent_busy",
        // FR-115 P3 — a code of its own: the action is "end a session or
        // upgrade", not "the device is busy", and the viewer must not retry.
        OrgSessionLimit { .. } => "org_session_limit",
        SessionNotFound(_) => "session_not_found",
        BadPhase(_, _) => "bad_phase",
        ConsentDenied => "consent_denied",
        ConsentTimeout => "consent_timeout",
        PermissionDenied(_) => "permission_denied",
        BadMessage(_) => "bad_message",
        SendFailed => "send_failed",
        // Fleet RPC. Distinct codes because the operator actions differ:
        // "update the agent" vs "the device stopped answering".
        ExecUnsupported(_) => "exec_unsupported",
        ExecTimeout(_) => "exec_timeout",
        Mongo(_) => "internal",
        Bson(_) => "internal",
        Json(_) => "internal",
    }
}

/// If the underlying error references a specific session, extract its id
/// so the controller UI can route the error to the right spinner instead
/// of assuming it's about the most recently attempted session.
fn error_session_id(e: &roomler_ai_remote_control::Error) -> Option<bson::oid::ObjectId> {
    use roomler_ai_remote_control::Error::*;
    match e {
        SessionNotFound(hex) => bson::oid::ObjectId::parse_str(hex).ok(),
        BadPhase(hex, _) => bson::oid::ObjectId::parse_str(hex).ok(),
        _ => None,
    }
}
