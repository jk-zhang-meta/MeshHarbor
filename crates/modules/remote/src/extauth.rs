// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-52 P3c — the server's half of an external-access login: a BLIND relay.
//!
//! An outsider's browser and a device run an OPAQUE login through this pod. The
//! server resolves the connect code, applies the two gates it owns (the org's
//! switch, the per-device approval), forwards the three login messages, and
//! learns nothing it could use: not the password, nothing to attack offline, no
//! proof it could replay. The device verifies; the server only carries.
//!
//! # Two rules that shape every function here
//!
//! 1. **One answer for every refusal the outsider must not tell apart** —
//!    [`ExtauthRefusal::Unavailable`] for no-such-code, gate 1 off, gate 2
//!    closed or expired, offline, too old. The org's audit log is where they
//!    are told apart (`login_detail`); the outsider never sees the difference.
//!    And the same LATENCY as far as that is cheap to buy: the reply goes out
//!    BEFORE the audit write (a write only resolvable codes trigger), and an
//!    unresolvable code still pays the tenant read a resolvable one does.
//! 2. **Park before the push.** The device can answer faster than this
//!    function gets back from `send_to_agent`; the waiter is registered first,
//!    so an early answer finds somewhere to land (FR-83's rule).
//!
//! # Across pods (P3d)
//!
//! An outsider has no tenant, so tenant affinity cannot put their socket on the
//! pod that holds the device, and roughly half of them land elsewhere. Both
//! controller frames carry the connect code rather than an agent id so the pod
//! they land on can re-resolve it and, when the device is not here, forward the
//! raw frame ONCE over the PR-2 rc relay ([`Hop`]). The owner pod handles it
//! with the relay's proxy sender, whose replies route back to the browser's own
//! connection. `finish` resolves the code BEFORE the attempt table for the same
//! reason: an attempt started cross-pod lives on the other pod.
//!
//! # The session (P4)
//!
//! A VERIFIED login is kept here, single-use, for [`VERIFIED_TTL`], and
//! `rc:extauth.session` spends it: the server proves the login was verified on
//! THIS pod, for THIS principal and THIS device, re-checks gates 1 and 2, clamps
//! the grant to the org's ceiling, and asks the Hub for a session whose
//! `rc:request` names the login. It decides nothing else — the device binds the
//! session to that login or refuses it, asks its own consent, applies its own
//! ceiling, and checks the offer's MAC (`agents/meshharbord/src/extauth.rs`). What
//! the server holds here is a bookkeeping entry, not a credential: without the
//! device's key it can neither open the session nor impersonate either end.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_mod_fleet::hub::OrgPolicy;
use meshharbor_remote_control::connect_code;
use meshharbor_remote_control::models::{
    Agent, AgentStatus, ConsentMode, ExtauthRefusal, ExternalRcAuditAction, ExternalRcAuditEvent,
    RpcCap,
};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::session::ClientTx;
use meshharbor_remote_control::signaling::{ExternalGrant, ServerMsg};
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::RemoteState;

/// How long the server waits for the device to answer one login step. The
/// device's own work is an OPRF evaluation and a 3DH; this covers a slow
/// relayed path to it, not computation.
pub const DEVICE_ANSWER_BOUND: Duration = Duration::from_secs(10);
/// How long an attempt may sit between the challenge and the controller's
/// KE3. Longer than the device's own pending TTL (60 s), so the device — the
/// party that counts guesses — is always the one that expires it first.
pub const ATTEMPT_TTL: Duration = Duration::from_secs(90);
/// The server's own ceiling on starts per principal per minute: the SECOND
/// limit (§4b). The device's budget is the one that protects the password;
/// this one bounds relay traffic and audit rows per account.
pub const STARTS_PER_MINUTE: u32 = 10;
/// How long a VERIFIED login may wait here for its `rc:extauth.session`.
/// Longer than the device's own hold on it (120 s): the device holds the key,
/// so it should be the party that lets a login lapse.
pub const VERIFIED_TTL: Duration = Duration::from_secs(150);

/// What the device said about one login step.
#[derive(Debug)]
pub enum DeviceAnswer {
    Ke2(String),
    Outcome {
        refused: Option<ExtauthRefusal>,
        retry_after_secs: Option<u32>,
    },
}

struct Waiter {
    agent_id: ObjectId,
    tx: oneshot::Sender<DeviceAnswer>,
}

struct Attempt {
    agent_id: ObjectId,
    principal: ObjectId,
    started: Instant,
}

/// P4 — a login the device VERIFIED, waiting for the session it earns.
struct Verified {
    agent_id: ObjectId,
    principal: ObjectId,
    verified: Instant,
}

/// Attempts in flight and the waiters for the device's answers. Pod-local.
#[derive(Default)]
pub struct ExtauthRelay {
    waiters: DashMap<String, Waiter>,
    attempts: DashMap<String, Attempt>,
    /// P4 — attempt id → a verified login not yet spent on a session.
    verified: DashMap<String, Verified>,
    /// principal → (window start, starts in it).
    starts: std::sync::Mutex<HashMap<ObjectId, (Instant, u32)>>,
}

impl ExtauthRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the waiter for `attempt_id`'s next answer — BEFORE the push.
    fn expect(self: &Arc<Self>, attempt_id: &str, agent_id: ObjectId) -> PendingAnswer {
        let (tx, rx) = oneshot::channel();
        self.waiters
            .insert(attempt_id.to_string(), Waiter { agent_id, tx });
        PendingAnswer {
            relay: Arc::clone(self),
            attempt_id: attempt_id.to_string(),
            rx,
        }
    }

    /// Hand the device's answer to whoever is waiting for it.
    ///
    /// ⚠️ Honoured ONLY from the agent the step was sent to. Attempt ids are
    /// relayed to both parties and are not secret; `from_agent` comes from the
    /// authenticated socket, never from the frame.
    pub fn deliver(&self, attempt_id: &str, from_agent: ObjectId, answer: DeviceAnswer) -> bool {
        match self
            .waiters
            .remove_if(attempt_id, |_, w| w.agent_id == from_agent)
        {
            Some((_, w)) => w.tx.send(answer).is_ok(),
            None => false,
        }
    }

    /// The server's second limit. Fixed one-minute windows per principal.
    fn allow_start(&self, principal: ObjectId, now: Instant) -> bool {
        let mut starts = self
            .starts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Bounded: a window older than a minute is dead weight.
        starts.retain(|_, (since, _)| {
            now.saturating_duration_since(*since) < Duration::from_secs(60)
        });
        let entry = starts.entry(principal).or_insert((now, 0));
        if entry.1 >= STARTS_PER_MINUTE {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Drop attempts nobody finished. Ages via `saturating_duration_since`,
    /// never `now - d`.
    fn prune(&self, now: Instant) {
        self.attempts
            .retain(|_, a| now.saturating_duration_since(a.started) <= ATTEMPT_TTL);
        self.verified
            .retain(|_, v| now.saturating_duration_since(v.verified) <= VERIFIED_TTL);
    }

    /// P4 — spend `attempt_id`'s verified login: once, by its own principal,
    /// for its own device. Anyone else leaves it in place and is told it does
    /// not exist.
    fn take_verified(
        &self,
        attempt_id: &str,
        principal: ObjectId,
        device: ObjectId,
        now: Instant,
    ) -> bool {
        self.prune(now);
        self.verified
            .remove_if(attempt_id, |_, v| {
                v.principal == principal && v.agent_id == device
            })
            .is_some()
    }

    /// Attempts currently in flight. For tests and gauges.
    pub fn attempts_in_flight(&self) -> usize {
        self.attempts.len()
    }
}

/// A registered waiter. Dropping it deregisters, so an early return anywhere
/// cannot leave a slot a late answer would land in.
struct PendingAnswer {
    relay: Arc<ExtauthRelay>,
    attempt_id: String,
    rx: oneshot::Receiver<DeviceAnswer>,
}

impl PendingAnswer {
    async fn wait(mut self, bound: Duration) -> Option<DeviceAnswer> {
        tokio::time::timeout(bound, &mut self.rx).await.ok()?.ok()
    }
}

impl Drop for PendingAnswer {
    fn drop(&mut self) {
        self.relay.waiters.remove(&self.attempt_id);
    }
}

/// Where a frame came from — which decides whether it may be forwarded.
///
/// An outsider has no tenant, so tenant affinity cannot put their socket on the
/// pod that holds the device, and `/ws` refuses a `tid` they are not a member
/// of: with two replicas, roughly half of them land on a pod that cannot reach
/// it. So a frame that arrives on the wrong pod is forwarded ONCE, over the
/// PR-2 rc relay, to the pod that holds the device, and handled there with a
/// proxy sender whose replies route back to the browser's own connection.
pub enum Hop {
    /// Straight off this pod's user socket: may be forwarded, once.
    Origin {
        connection_id: String,
        frame: serde_json::Value,
    },
    /// Already forwarded by another pod: handled here or refused, NEVER
    /// forwarded again — or a device moving between pods mid-login would turn
    /// one login into a loop between them.
    Relayed,
}

/// Forward a frame to the pod that holds `agent_id`. `true` = the owner pod
/// took it, and its replies will reach the browser without us.
async fn forward(
    state: &RemoteState,
    hop: &Hop,
    agent_id: ObjectId,
    principal: ObjectId,
    actor: &str,
) -> bool {
    let Hop::Origin {
        connection_id,
        frame,
    } = hop
    else {
        return false;
    };
    let Some(redis) = &state.redis_pubsub else {
        return false;
    };
    // The same presence probe, with the same 250 ms budget, the session path
    // uses before it relays.
    let Ok(Ok(Some(owner))) = tokio::time::timeout(
        Duration::from_millis(250),
        redis.agent_presence_foreign(&agent_id.to_hex()),
    )
    .await
    else {
        return false;
    };
    let Some(pod) =
        meshharbor_core::cluster::directory::OwnerRecord::parse(&owner).map(|r| r.pod_id)
    else {
        return false;
    };
    matches!(
        crate::relay::relay_rc_frame(
            state,
            &pod,
            connection_id,
            principal,
            actor,
            Default::default(),
            &None,
            None,
            &None,
            // The authz gate's verdicts for an ORDINARY frame; an outsider's
            // frame is the extauth relay's on the owner pod, which never
            // records one and never puts one on the org's overlay.
            false,
            false,
            // FR-101 / FR-99 — nor are these read for it: the owner pod hands
            // an `rc:extauth.*` frame to `on_relayed` before its Hub sees the
            // frame, and `handle_session` there reads the org's policy and
            // limits off the tenant row its own gate 1 reads. `Unavailable`
            // is the reading that refuses, were anything ever to consult it.
            OrgPolicy::Unavailable,
            None,
            None,
            None,
            // FR-115 — nor the org's concurrent-session cap: `handle_session`
            // opens an outsider's session uncapped (P3b decides whose plan it
            // counts against).
            None,
            frame,
        )
        .await,
        Ok(None)
    )
}

fn result(
    attempt_id: Option<String>,
    refused: Option<ExtauthRefusal>,
    retry_after_secs: Option<u32>,
) -> ServerMsg {
    ServerMsg::ExtauthResult {
        attempt_id,
        refused,
        retry_after_secs,
        message: None,
    }
}

fn unavailable(attempt_id: Option<String>) -> ServerMsg {
    result(attempt_id, Some(ExtauthRefusal::Unavailable), None)
}

/// Gates 1 and 2, plus "can this device do it at all". `Err` carries what the
/// org's audit log records; the outsider sees only `unavailable`.
///
/// Answers with the tenant row it read, so a session admitted on it is bound by
/// what that same row says (`handle_session`).
async fn gates(
    state: &RemoteState,
    agent: &Agent,
) -> Result<meshharbor_db::models::tenant::Tenant, &'static str> {
    // The two refusals the org's OWN session gate applies before anything
    // else (`controller::resolve_session_authz`) — an outsider must not get
    // into a device a colleague could not. A tenant that cannot be read is a
    // refusal: this gate opens only on a row it has seen.
    if agent.status == AgentStatus::Quarantined {
        return Err("the device is quarantined");
    }
    let Ok(tenant) = state.fleet.tenants.base.find_by_id(agent.tenant_id).await else {
        return Err("gate 1: the organization could not be read");
    };
    if tenant.is_archived {
        return Err("the organization is archived");
    }
    if !tenant.settings.external_rc_enabled {
        return Err("gate 1: the organization has external access switched off");
    }
    let (gates, _) = agent.external_access_policy.clone().split();
    if !gates.is_open_at(bson::DateTime::now()) {
        return Err(
            "gate 2: the device is not approved for external access, or the approval expired",
        );
    }
    // The same source gate 2's APPROVAL read (P1): the capabilities the agent
    // reported on its last hello. A device downgraded since then still claims
    // the verb here; it then never answers, and the bound below turns that into
    // `unavailable` — slower, never wrong.
    if !agent.capabilities.has_rpc(RpcCap::ExternalAccess) {
        return Err("the device's agent is too old to be sent an external login");
    }
    Ok(tenant)
}

/// Resolve a connect code to its live device.
///
/// ⚠️ An unresolvable code still pays one tenant read, so it costs roughly
/// what a resolvable-but-gated code costs before the reply goes out. Cheap to
/// buy, and it keeps "no such code" from being the one fast answer.
async fn resolve(state: &RemoteState, typed: &str) -> Option<Agent> {
    let found = match connect_code::normalize(typed) {
        Some(code) => state
            .fleet
            .agents
            .find_by_connect_code(&code)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    if found.is_none() {
        let _ = state
            .fleet
            .tenants
            .base
            .find_by_id(ObjectId::from_bytes([0; 12]))
            .await;
    }
    found
}

/// A `login` row. Written AFTER the reply, so its latency is not part of the
/// answer (§5).
#[allow(clippy::too_many_arguments)]
fn audit(
    state: &RemoteState,
    agent: &Agent,
    agent_id: ObjectId,
    principal: ObjectId,
    actor: &str,
    attempt_id: Option<String>,
    refused: Option<ExtauthRefusal>,
    detail: Option<&str>,
) {
    audit_row(
        state,
        ExternalRcAuditAction::Login,
        agent,
        agent_id,
        principal,
        actor,
        attempt_id,
        refused,
        detail,
        None,
    );
}

/// P4 — a `session` row: a verified login admitted into `session_id`, or
/// refused (`refused` / `detail`, and no session).
#[allow(clippy::too_many_arguments)]
fn audit_session(
    state: &RemoteState,
    agent: &Agent,
    agent_id: ObjectId,
    principal: ObjectId,
    actor: &str,
    attempt_id: String,
    refused: Option<ExtauthRefusal>,
    detail: Option<&str>,
    session_id: Option<ObjectId>,
) {
    audit_row(
        state,
        ExternalRcAuditAction::Session,
        agent,
        agent_id,
        principal,
        actor,
        Some(attempt_id),
        refused,
        detail,
        session_id,
    );
}

#[allow(clippy::too_many_arguments)]
fn audit_row(
    state: &RemoteState,
    action: ExternalRcAuditAction,
    agent: &Agent,
    agent_id: ObjectId,
    principal: ObjectId,
    actor: &str,
    attempt_id: Option<String>,
    refused: Option<ExtauthRefusal>,
    detail: Option<&str>,
    session_id: Option<ObjectId>,
) {
    let event = ExternalRcAuditEvent {
        id: None,
        tenant_id: agent.tenant_id,
        action,
        agent_id,
        user_id: principal,
        actor: actor.to_string(),
        approved: None,
        max_permissions: None,
        expires_at: None,
        at: bson::DateTime::now(),
        denied: None,
        attempt_id,
        login_refused: refused,
        login_detail: detail.map(str::to_string),
        session_id,
    };
    let dao = Arc::clone(&state.fleet.external_rc_audit);
    tokio::spawn(async move {
        if let Err(e) = dao.record(event).await {
            warn!(%e, "extauth: the login audit row could not be written");
        }
    });
}

/// `rc:extauth.start` — resolve, gate, relay KE1, relay the device's answer.
#[allow(clippy::too_many_arguments)]
pub async fn handle_start(
    state: &RemoteState,
    principal: ObjectId,
    actor: &str,
    tx: &ClientTx,
    connect_code: &str,
    ke1: String,
    hop: Hop,
) {
    let relay = &state.extauth;
    let now = Instant::now();
    relay.prune(now);
    if !relay.allow_start(principal, now) {
        let _ = tx.try_send(result(None, Some(ExtauthRefusal::RateLimited), None));
        return;
    }
    let Some(agent) = resolve(state, connect_code).await else {
        let _ = tx.try_send(unavailable(None));
        return;
    };
    let Some(agent_id) = agent.id else {
        let _ = tx.try_send(unavailable(None));
        return;
    };
    if let Err(detail) = gates(state, &agent).await {
        let _ = tx.try_send(unavailable(None));
        info!(%principal, agent = %agent_id, detail, "extauth: start refused");
        audit(
            state,
            &agent,
            agent_id,
            principal,
            actor,
            None,
            Some(ExtauthRefusal::Unavailable),
            Some(detail),
        );
        return;
    }
    if !state.fleet.rc_hub.is_agent_online(agent_id) {
        // Not here. If another pod holds the device, hand the frame over once;
        // its replies reach the browser over the conn-addressed lane.
        if forward(state, &hop, agent_id, principal, actor).await {
            return;
        }
        let detail = match hop {
            Hop::Origin { .. } => "the device is offline (no pod holds it)",
            Hop::Relayed => "forwarded here, but the device is no longer on this pod",
        };
        let _ = tx.try_send(unavailable(None));
        audit(
            state,
            &agent,
            agent_id,
            principal,
            actor,
            None,
            Some(ExtauthRefusal::Unavailable),
            Some(detail),
        );
        return;
    }

    let attempt_id = ObjectId::new().to_hex();
    relay.attempts.insert(
        attempt_id.clone(),
        Attempt {
            agent_id,
            principal,
            started: now,
        },
    );
    // Park BEFORE the push (module docs, rule 2).
    let pending = relay.expect(&attempt_id, agent_id);
    let push = ServerMsg::ExtauthKe1 {
        attempt_id: attempt_id.clone(),
        principal: principal.to_hex(),
        ke1,
    };
    if state
        .fleet
        .rc_hub
        .send_to_agent_in_tenant(agent_id, agent.tenant_id, push)
        .is_err()
    {
        relay.attempts.remove(&attempt_id);
        let _ = tx.try_send(unavailable(None));
        audit(
            state,
            &agent,
            agent_id,
            principal,
            actor,
            Some(attempt_id),
            Some(ExtauthRefusal::Unavailable),
            Some("the device went away before KE1 could be sent"),
        );
        return;
    }

    match pending.wait(DEVICE_ANSWER_BOUND).await {
        Some(DeviceAnswer::Ke2(ke2)) => {
            // The attempt stays for the controller's KE3.
            let _ = tx.try_send(ServerMsg::ExtauthChallenge { attempt_id, ke2 });
        }
        Some(DeviceAnswer::Outcome {
            refused,
            retry_after_secs,
        }) => {
            relay.attempts.remove(&attempt_id);
            // ⚠️ "Verified" in answer to a KE1 is protocol nonsense — nothing
            // has been proven yet. Relayed as a refusal, never as a login.
            let refused = Some(refused.unwrap_or(ExtauthRefusal::Other));
            let _ = tx.try_send(result(Some(attempt_id.clone()), refused, retry_after_secs));
            audit(
                state,
                &agent,
                agent_id,
                principal,
                actor,
                Some(attempt_id),
                refused,
                None,
            );
        }
        None => {
            relay.attempts.remove(&attempt_id);
            let _ = tx.try_send(unavailable(Some(attempt_id.clone())));
            audit(
                state,
                &agent,
                agent_id,
                principal,
                actor,
                Some(attempt_id),
                Some(ExtauthRefusal::Unavailable),
                Some("the device did not answer KE1 in time"),
            );
        }
    }
}

/// `rc:extauth.finish` — relay KE3, relay the verdict.
#[allow(clippy::too_many_arguments)]
pub async fn handle_finish(
    state: &RemoteState,
    principal: ObjectId,
    actor: &str,
    tx: &ClientTx,
    connect_code: &str,
    attempt_id: String,
    ke3: String,
    hop: Hop,
) {
    let relay = &state.extauth;
    relay.prune(Instant::now());
    let unknown =
        |attempt_id: String| result(Some(attempt_id), Some(ExtauthRefusal::UnknownAttempt), None);
    // The code FIRST, before the attempt table: on the pod the browser landed
    // on, an attempt that was started cross-pod lives on the OTHER pod, and a
    // local lookup would wrongly answer "no such attempt".
    let Some(agent) = resolve(state, connect_code).await else {
        let _ = tx.try_send(unknown(attempt_id));
        return;
    };
    let Some(device) = agent.id else {
        let _ = tx.try_send(unknown(attempt_id));
        return;
    };
    if !state.fleet.rc_hub.is_agent_online(device) {
        if forward(state, &hop, device, principal, actor).await {
            return;
        }
        let _ = tx.try_send(unavailable(Some(attempt_id)));
        return;
    }
    // Taken, not read: whatever happens next, this attempt ends here. Only its
    // own principal can take it — anyone else leaves it in place and is told
    // it does not exist.
    let Some((_, attempt)) = relay
        .attempts
        .remove_if(&attempt_id, |_, a| a.principal == principal)
    else {
        let _ = tx.try_send(unknown(attempt_id));
        return;
    };
    // The code must still name the attempt's device, and the gates must still
    // be open: an admin who revokes mid-login must not see it complete.
    if attempt.agent_id != device {
        let _ = tx.try_send(unknown(attempt_id));
        return;
    }
    let agent_id = attempt.agent_id;
    if let Err(detail) = gates(state, &agent).await {
        let _ = tx.try_send(unavailable(Some(attempt_id.clone())));
        audit(
            state,
            &agent,
            agent_id,
            principal,
            actor,
            Some(attempt_id),
            Some(ExtauthRefusal::Unavailable),
            Some(detail),
        );
        return;
    }

    let pending = relay.expect(&attempt_id, agent_id);
    let push = ServerMsg::ExtauthKe3 {
        attempt_id: attempt_id.clone(),
        principal: principal.to_hex(),
        ke3,
    };
    if state
        .fleet
        .rc_hub
        .send_to_agent_in_tenant(agent_id, agent.tenant_id, push)
        .is_err()
    {
        let _ = tx.try_send(unavailable(Some(attempt_id.clone())));
        audit(
            state,
            &agent,
            agent_id,
            principal,
            actor,
            Some(attempt_id),
            Some(ExtauthRefusal::Unavailable),
            Some("the device went away before KE3 could be sent"),
        );
        return;
    }

    match pending.wait(DEVICE_ANSWER_BOUND).await {
        Some(DeviceAnswer::Outcome {
            refused,
            retry_after_secs,
        }) => {
            if refused.is_none() {
                // P4 — kept for the session it earns, BEFORE the outsider is
                // told: their `rc:extauth.session` can follow at once.
                relay.verified.insert(
                    attempt_id.clone(),
                    Verified {
                        agent_id,
                        principal,
                        verified: Instant::now(),
                    },
                );
                info!(%principal, agent = %agent_id, %attempt_id, "extauth: login VERIFIED by the device");
            }
            let _ = tx.try_send(result(Some(attempt_id.clone()), refused, retry_after_secs));
            audit(
                state,
                &agent,
                agent_id,
                principal,
                actor,
                Some(attempt_id),
                refused,
                None,
            );
        }
        // A KE2 in answer to a KE3 is protocol nonsense: a refusal.
        Some(DeviceAnswer::Ke2(_)) => {
            let refused = Some(ExtauthRefusal::Other);
            let _ = tx.try_send(result(Some(attempt_id.clone()), refused, None));
            audit(
                state,
                &agent,
                agent_id,
                principal,
                actor,
                Some(attempt_id),
                refused,
                Some("the device answered KE3 with a KE2"),
            );
        }
        None => {
            let _ = tx.try_send(unavailable(Some(attempt_id.clone())));
            audit(
                state,
                &agent,
                agent_id,
                principal,
                actor,
                Some(attempt_id),
                Some(ExtauthRefusal::Unavailable),
                Some("the device did not answer KE3 in time"),
            );
        }
    }
}

/// P4 — what `rc:extauth.session` asks for.
pub struct SessionAsk {
    pub connect_code: String,
    pub attempt_id: String,
    pub permissions: Permissions,
    pub browser_caps: Vec<String>,
    pub preferred_transport: Option<String>,
    pub chroma_pref: Option<String>,
    pub chunk_framing: Option<bool>,
    pub audio_enabled: bool,
    /// FR-115 P3b (O6) — the org the outsider says the session is for (hex),
    /// honoured only when they belong to it ([`charge_scope`]).
    pub charge_org: Option<String>,
}

/// FR-115 P3b (O6 + O7, decided 2026-10-20) — whose concurrent-session
/// slots an external session takes, and how many there are. No paid org is
/// needed:
///
/// * the org the outsider named (`charge_org`), when they belong to it;
/// * else their only org;
/// * else (in no org, or in several and naming none) the account itself,
///   with Free's quota.
///
/// An archived org stops acting, so it is never charged. The cap is the
/// org's `max_concurrent_sessions` for its plan and seats, the same number
/// its own sessions use; `None` = unlimited (no slot to claim). An unreadable
/// membership answers `None` overall: the session runs as before P3b rather
/// than being counted against a guess.
pub async fn charge_scope(
    state: &RemoteState,
    principal: ObjectId,
    charge_org: Option<&str>,
) -> Option<(
    meshharbor_core::cluster::session_slots::SlotScope,
    Option<u32>,
)> {
    use meshharbor_core::cluster::session_slots::SlotScope;
    let orgs: Vec<_> = state
        .tenants
        .find_user_tenants(principal)
        .await
        .ok()?
        .into_iter()
        .filter(|t| !t.is_archived)
        .collect();
    let named = charge_org
        .and_then(|h| ObjectId::parse_str(h).ok())
        .and_then(|id| orgs.iter().find(|t| t.id == Some(id)));
    let chosen = named.or_else(|| (orgs.len() == 1).then(|| &orgs[0]));
    Some(match chosen.and_then(|t| Some((t.id?, t))) {
        Some((id, t)) => (SlotScope::Org(id), crate::controller::org_session_cap_of(t)),
        None => (
            SlotScope::User(principal),
            Some(
                meshharbor_db::models::Plan::Free
                    .limits_for(1)
                    .max_concurrent_sessions,
            ),
        ),
    })
}

/// FR-115 P3b — the words an outsider refused by the slot count reads: who
/// holds the slot and on which device. An org's is P3's own sentence; an
/// account in no org gets its own, since no org plan is involved.
async fn session_limit_message(
    state: &RemoteState,
    scope: meshharbor_core::cluster::session_slots::SlotScope,
    cap: u32,
    holder_user: String,
    holder_agent: String,
) -> String {
    use meshharbor_core::cluster::session_slots::SlotScope;
    if let SlotScope::Org(_) = scope {
        let e = meshharbor_remote_control::Error::OrgSessionLimit {
            cap,
            holder_user,
            holder_agent,
        };
        return crate::controller::refusal_message(state, &e).await;
    }
    let device = match ObjectId::parse_str(&holder_agent) {
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
    let holder = match device {
        Some(d) => format!("you are connected to {d} right now"),
        None => "a session of yours is open right now".to_string(),
    };
    format!(
        "Without an organization, an account runs one remote session at a time, and {holder}. \
         End that session, or run this one for an organization you belong to."
    )
}

/// `rc:extauth.session` — open the session a verified login earned.
///
/// Thin on purpose (module docs, "The session"). Every refusal before the Hub
/// is one the outsider sees as `unknown_attempt` or `unavailable`, told apart
/// only in the org's audit log; a refusal FROM the Hub (the device is busy, or
/// went away) is relayed as what it is.
pub async fn handle_session(
    state: &RemoteState,
    principal: ObjectId,
    actor: &str,
    tx: &ClientTx,
    ask: SessionAsk,
    hop: Hop,
) {
    let relay = &state.extauth;
    let attempt_id = ask.attempt_id;
    let unknown =
        |attempt_id: String| result(Some(attempt_id), Some(ExtauthRefusal::UnknownAttempt), None);
    // The code FIRST, as in `finish`: a login verified cross-pod is held on the
    // pod that holds the device, and a local lookup here would miss it.
    let Some(agent) = resolve(state, &ask.connect_code).await else {
        let _ = tx.try_send(unknown(attempt_id));
        return;
    };
    let Some(device) = agent.id else {
        let _ = tx.try_send(unknown(attempt_id));
        return;
    };
    if !state.fleet.rc_hub.is_agent_online(device) {
        if forward(state, &hop, device, principal, actor).await {
            return;
        }
        let _ = tx.try_send(unavailable(Some(attempt_id.clone())));
        audit_session(
            state,
            &agent,
            device,
            principal,
            actor,
            attempt_id,
            Some(ExtauthRefusal::Unavailable),
            Some("the device is offline (no pod holds it)"),
            None,
        );
        return;
    }
    // Spent, not read: one verified login opens one session, whatever happens
    // below — a refusal here sends the outsider back to log in again, which is
    // the cheap direction to be wrong in.
    if !relay.take_verified(&attempt_id, principal, device, Instant::now()) {
        let _ = tx.try_send(unknown(attempt_id));
        return;
    }
    // Gates 1 and 2 again: an admin who revokes between the login and the
    // session must not see the session open.
    let refuse = |detail: &'static str, attempt_id: String| {
        let _ = tx.try_send(unavailable(Some(attempt_id.clone())));
        info!(%principal, agent = %device, %attempt_id, detail, "extauth: session refused");
        audit_session(
            state,
            &agent,
            device,
            principal,
            actor,
            attempt_id,
            Some(ExtauthRefusal::Unavailable),
            Some(detail),
            None,
        );
    };
    let tenant = match gates(state, &agent).await {
        Ok(tenant) => tenant,
        Err(detail) => {
            refuse(detail, attempt_id);
            return;
        }
    };
    // ⚠️ A device that cannot bind a session to its login would take
    // `Request.external` as an unknown field and serve the outsider as an
    // ordinary controller. Its `external-access` says it can LOG ONE IN, which
    // is not the same promise.
    if !agent.capabilities.has_rpc(RpcCap::ExternalSession) {
        refuse(
            "the device's agent can verify an external login but is too old to admit the session",
            attempt_id,
        );
        return;
    }
    // Gate 2's ceiling. The device applies its own on top; the grant only
    // ever narrows.
    let (_, spec) = agent.external_access_policy.clone().split();
    let permissions = spec.clamp(ask.permissions);
    if permissions.is_empty() {
        refuse(
            "nothing the outsider asked for is within the org's ceiling for this device",
            attempt_id,
        );
        return;
    }
    // FR-101 / FR-99 — what binds every controller of this device binds an
    // outsider too, read off the row gate 1 just read, exactly as
    // `controller::resolve_session_authz` reads it for a colleague: the org's
    // session policy, its maximum session length, the idle limit held to the
    // device's own, and the device's lock ask. The outside door is never the
    // looser one (§Goal, property 2).
    let session_policy = OrgPolicy::Read(crate::session_policy::wire(&tenant.settings.rc_session));
    let max_duration = tenant
        .settings
        .rc_limits
        .max_secs
        .map(|secs| Duration::from_secs(u64::from(secs)));
    let idle_secs = meshharbor_remote_control::models::stricter_idle_limit(
        tenant.settings.rc_limits.idle_secs,
        agent.access_policy.idle_limit_secs(),
    );
    let lock_on_end = agent.access_policy.lock_on_end_ask();
    // FR-115 P3b (O6 + O7) — an external session takes a slot of the org it
    // is for, at that org's tier, or Free's one of an account in no org
    // ([`charge_scope`]). Before P3b it ran uncapped, and with slots off (or
    // Redis unable to answer) it still does: never refused on a guess.
    let mut slot = None;
    if crate::slots::enabled(state)
        && let Some((scope, Some(cap))) =
            charge_scope(state, principal, ask.charge_org.as_deref()).await
    {
        use crate::slots::SlotDecision;
        match crate::slots::claim(state, scope, principal, device, cap).await {
            SlotDecision::Claimed(lease) => slot = Some(lease),
            SlotDecision::Fallback => {}
            SlotDecision::Full {
                cap,
                holder_user,
                holder_agent,
            } => {
                let message =
                    session_limit_message(state, scope, cap, holder_user, holder_agent).await;
                let _ = tx.try_send(ServerMsg::ExtauthResult {
                    attempt_id: Some(attempt_id.clone()),
                    refused: Some(ExtauthRefusal::SessionLimit),
                    retry_after_secs: None,
                    message: Some(message),
                });
                info!(%principal, agent = %device, %attempt_id, ?scope, "extauth: refused by the session slots");
                audit_session(
                    state,
                    &agent,
                    device,
                    principal,
                    actor,
                    attempt_id,
                    Some(ExtauthRefusal::SessionLimit),
                    Some("every concurrent-session slot of the payer is held"),
                    None,
                );
                return;
            }
        }
    }
    let session = state.fleet.rc_hub.create_session_full(
        device,
        principal,
        actor.to_string(),
        tx.clone(),
        permissions,
        ask.browser_caps,
        ask.preferred_transport,
        ask.chroma_pref,
        ask.chunk_framing,
        // System audio leaves the host: only under a grant that says so.
        ask.audio_enabled && permissions.contains(Permissions::AUDIO),
        // The device ignores this for an external session and asks by its own
        // `external_consent_mode`. `Prompt` gives the Hub the attended window
        // to wait, which is the longest the device can take.
        ConsentMode::Prompt,
        // No break-glass from outside the org, and no relay descriptor (F4):
        // the frame cannot carry either, and neither is invented here.
        None,
        None,
        // #1882 — never the org's overlay: an outsider is not on its mesh, and
        // F4 already keeps every overlay relay off this session.
        false,
        agent.access_policy.input_mode,
        // The device labels an outsider itself; no org name to show.
        None,
        // FR-85 — never recorded: recording an outsider's session is out of
        // FR-52's scope (§10), so RECORD is stripped whatever was asked.
        false,
        session_policy,
        max_duration,
        idle_secs,
        lock_on_end,
        Some(ExternalGrant {
            attempt_id: attempt_id.clone(),
        }),
        None,
        slot.clone(),
    );
    // FR-115 P3b — a slot the hub did not take goes back now.
    if let Some(lease) = &slot {
        crate::slots::release_unused(state, lease, session.as_ref().ok().copied()).await;
    }
    match session {
        Ok(session_id) => {
            info!(%principal, agent = %device, %attempt_id, %session_id, "extauth: session opened");
            audit_session(
                state,
                &agent,
                device,
                principal,
                actor,
                attempt_id,
                None,
                None,
                Some(session_id),
            );
        }
        Err(e) => {
            let refused = match e {
                meshharbor_remote_control::Error::AgentBusy => ExtauthRefusal::Busy,
                _ => ExtauthRefusal::Unavailable,
            };
            let _ = tx.try_send(result(Some(attempt_id.clone()), Some(refused), None));
            warn!(%principal, agent = %device, %attempt_id, %e, "extauth: the hub could not open the session");
            audit_session(
                state,
                &agent,
                device,
                principal,
                actor,
                attempt_id,
                Some(refused),
                Some("the hub could not open the session"),
                None,
            );
        }
    }
}

/// Route a controller frame here if it is an `rc:extauth.*` frame. `None` =
/// not ours; `Some(true)` = handled (or deliberately swallowed).
///
/// Runs BEFORE the session authz gate: an outsider has no membership for that
/// gate to check — their gates are the org's switch, the device's approval and
/// the password. And each step is SPAWNED: it waits on the device for up to
/// [`DEVICE_ANSWER_BOUND`], and the rest of this socket's frames must not
/// queue behind it.
pub fn intercept(
    state: &RemoteState,
    frame: &crate::controller::ControllerFrame<'_>,
) -> Option<bool> {
    // Cheap pre-filter: most rc:* traffic is SDP and ICE.
    if !frame.text.contains("rc:extauth.") {
        return None;
    }
    let msg =
        serde_json::from_str::<meshharbor_remote_control::signaling::ClientMsg>(frame.text).ok()?;
    // The raw frame too: if the device is on another pod, THIS is what the PR-2
    // relay forwards.
    let raw = serde_json::from_str::<serde_json::Value>(frame.text).ok()?;
    let hop = Hop::Origin {
        connection_id: frame.connection_id.to_string(),
        frame: raw,
    };
    dispatch(
        state,
        frame.user_id,
        frame.controller_name,
        frame.controller_tx,
        msg,
        hop,
    )
}

/// The OWNER pod's entry: a frame another pod forwarded over the PR-2 relay,
/// answered through `tx`, the relay's proxy sender (its replies route back to
/// the browser's connection on the origin pod). `None` = not an extauth frame.
pub fn on_relayed(
    state: &RemoteState,
    principal: ObjectId,
    actor: &str,
    tx: &ClientTx,
    msg: &meshharbor_remote_control::signaling::ClientMsg,
) -> Option<bool> {
    use meshharbor_remote_control::signaling::ClientMsg;
    if !matches!(
        msg,
        ClientMsg::ExtauthStart { .. }
            | ClientMsg::ExtauthFinish { .. }
            | ClientMsg::ExtauthSession { .. }
            | ClientMsg::ExtauthKe2 { .. }
            | ClientMsg::ExtauthOutcome { .. }
    ) {
        return None;
    }
    dispatch(state, principal, actor, tx, msg.clone(), Hop::Relayed)
}

fn dispatch(
    state: &RemoteState,
    principal: ObjectId,
    actor: &str,
    tx: &ClientTx,
    msg: meshharbor_remote_control::signaling::ClientMsg,
    hop: Hop,
) -> Option<bool> {
    use meshharbor_remote_control::signaling::ClientMsg;
    let (state, actor, tx) = (state.clone(), actor.to_string(), tx.clone());
    match msg {
        ClientMsg::ExtauthStart { connect_code, ke1 } => {
            tokio::spawn(async move {
                handle_start(&state, principal, &actor, &tx, &connect_code, ke1, hop).await;
            });
            Some(true)
        }
        ClientMsg::ExtauthFinish {
            connect_code,
            attempt_id,
            ke3,
        } => {
            tokio::spawn(async move {
                handle_finish(
                    &state,
                    principal,
                    &actor,
                    &tx,
                    &connect_code,
                    attempt_id,
                    ke3,
                    hop,
                )
                .await;
            });
            Some(true)
        }
        ClientMsg::ExtauthSession {
            connect_code,
            attempt_id,
            permissions,
            browser_caps,
            preferred_transport,
            chroma_pref,
            chunk_framing,
            audio_enabled,
            charge_org,
        } => {
            let ask = SessionAsk {
                connect_code,
                attempt_id,
                permissions,
                browser_caps,
                preferred_transport,
                chroma_pref,
                chunk_framing,
                audio_enabled,
                charge_org,
            };
            tokio::spawn(async move {
                handle_session(&state, principal, &actor, &tx, ask, hop).await;
            });
            Some(true)
        }
        // A DEVICE's frames arriving from a USER — on a socket or through the
        // relay: a browser trying to speak for a device. Swallowed — never
        // delivered, never dispatched.
        ClientMsg::ExtauthKe2 { .. } | ClientMsg::ExtauthOutcome { .. } => {
            warn!(%principal, "extauth: a device frame arrived from a user — dropped");
            Some(true)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn the_devices_answer_resolves_the_wait() {
        let relay = Arc::new(ExtauthRelay::new());
        let device = ObjectId::new();
        let pending = relay.expect("a1", device);
        assert!(relay.deliver("a1", device, DeviceAnswer::Ke2("k2".into())));
        assert!(matches!(pending.wait(SHORT).await, Some(DeviceAnswer::Ke2(k)) if k == "k2"));
    }

    /// Attempt ids are not secret: an answer from any OTHER agent confirms
    /// nothing and leaves the slot for the right one.
    #[tokio::test]
    async fn an_answer_from_another_agent_lands_nowhere() {
        let relay = Arc::new(ExtauthRelay::new());
        let (device, stranger) = (ObjectId::new(), ObjectId::new());
        let pending = relay.expect("a1", device);
        let verified = || DeviceAnswer::Outcome {
            refused: None,
            retry_after_secs: None,
        };
        assert!(
            !relay.deliver("a1", stranger, verified()),
            "a stranger's verdict"
        );
        assert!(relay.deliver("a1", device, verified()));
        assert!(matches!(
            pending.wait(SHORT).await,
            Some(DeviceAnswer::Outcome { refused: None, .. })
        ));
    }

    #[tokio::test]
    async fn silence_is_no_answer_and_the_slot_is_released() {
        let relay = Arc::new(ExtauthRelay::new());
        let pending = relay.expect("a1", ObjectId::new());
        assert!(pending.wait(SHORT).await.is_none());
        assert!(relay.waiters.is_empty());
    }

    #[test]
    fn the_server_limit_counts_per_principal_and_resets_each_minute() {
        let relay = ExtauthRelay::new();
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let t0 = Instant::now();
        for _ in 0..STARTS_PER_MINUTE {
            assert!(relay.allow_start(a, t0));
        }
        assert!(!relay.allow_start(a, t0), "the eleventh start in a minute");
        assert!(
            relay.allow_start(b, t0),
            "another principal has its own window"
        );
        assert!(
            relay.allow_start(a, t0 + Duration::from_secs(61)),
            "a new window"
        );
    }
}
