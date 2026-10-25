// SPDX-License-Identifier: AGPL-3.0-only
//! Bilateral candidate orchestration, extending the existing org-relay owner.
//! Metadata and active legacy sessions are never substituted for a candidate.
use super::*;
use roomler_core::rate_limit::RateLimiter;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use tokio::sync::watch;

const MAX_TRIALS: usize = 128;
const MAX_TENANT_TRIALS: usize = 16;
const PREPARE_TIMEOUT: Duration = Duration::from_secs(30);
const READY_FRESH: Duration = Duration::from_secs(10);
const RETURN_TOMBSTONE: Duration = Duration::from_secs(120);
const MAX_RETURN_ATTEMPTS: usize = 64;

#[derive(Clone, Copy)]
pub enum PathTrialReturnUpdate {
    Request,
    Ready,
    Returned,
    Abort,
}

#[derive(Clone)]
enum ReturnPhase {
    Preparing([Option<Instant>; 2]),
    Committing([bool; 2]),
    Finalized,
}

struct ReturnState {
    id: ObjectId,
    phase: ReturnPhase,
    started: Instant,
}

#[derive(Clone, Copy)]
pub enum PathTrialUpdate {
    Ready,
    Committed,
    Abort,
}

#[derive(Clone)]
enum Phase {
    Preparing([Option<Instant>; 2]),
    Committing([bool; 2]),
    Finalized,
}

struct BackboneTrial {
    exit: OrgRelaySession,
    private_endpoint: String,
}

struct Trial {
    id: ObjectId,
    request_id: u64,
    session: OrgRelaySession,
    backbone: Option<BackboneTrial>,
    phase: Phase,
    started: Instant,
    return_state: Option<ReturnState>,
    // Bounded replay protection: never reuse an aborted return id during this
    // trial. Authenticated requester IDs, not attacker-chosen keys, rate-limit.
    return_ids: HashSet<ObjectId>,
    cancel: watch::Sender<bool>,
}

#[derive(Default)]
pub(super) struct PathTrials {
    // All phase transitions + nonblocking pushes are serialized. No DB or
    // awaited send occurs while held, so Abort cannot be overtaken by Commit.
    entries: Mutex<HashMap<ObjectId, Trial>>,
    rate: RateLimiter,
    return_rate: RateLimiter,
}

impl PathTrials {
    pub(super) fn sessions_on_relay(&self, relay: ObjectId, now: Instant) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|t| {
                (t.session.relay.node_id == relay
                    || t.backbone
                        .as_ref()
                        .is_some_and(|b| b.exit.relay.node_id == relay))
                    && t.session.expires_at > now
                    && !returned(t)
            })
            .count()
    }
    pub(super) fn vnis_on_relay(&self, relay: ObjectId) -> Vec<u32> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .flat_map(|t| {
                let mut out = Vec::with_capacity(2);
                if t.session.relay.node_id == relay {
                    out.push(t.session.vni);
                }
                if let Some(b) = t.backbone.as_ref() {
                    if b.exit.relay.node_id == relay {
                        out.push(b.exit.vni);
                    }
                }
                out
            })
            .collect()
    }
    pub(super) fn sessions_for_tenant(&self, tenant: ObjectId) -> Vec<OrgRelaySession> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|t| t.session.tenant_id == tenant)
            .flat_map(|t| {
                let mut out = vec![t.session.clone()];
                if let Some(b) = t.backbone.as_ref() {
                    out.push(b.exit.clone());
                }
                out
            })
            .collect()
    }
    pub(super) fn revoke_where(
        &self,
        state: &NetworkState,
        reason: &str,
        pred: &impl Fn(&OrgRelaySession) -> bool,
    ) -> Vec<PeerRelayAuditEvent> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<_> = entries
            .values()
            .filter(|t| pred(&t.session) || t.backbone.as_ref().is_some_and(|b| pred(&b.exit)))
            .map(|t| t.id)
            .collect();
        ids.into_iter()
            .filter_map(|id| entries.remove(&id))
            .map(|trial| {
                notify_abort(state, &trial);
                revoke_event(&trial, reason)
            })
            .collect()
    }
}

pub(super) fn revoke_backbone_node(
    state: &NetworkState,
    tenant: ObjectId,
    node: ObjectId,
    member_withdrawn: bool,
    ingress_withdrawn: bool,
) -> Vec<PeerRelayAuditEvent> {
    let mut entries = state
        .org_relay
        .trials
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let ids: Vec<_> = entries
        .values()
        .filter(|t| {
            !returned(t)
                && t.session.tenant_id == tenant
                && t.backbone.is_some()
                && ((member_withdrawn && t.session.member_index(node).is_some())
                    || (ingress_withdrawn && t.session.relay.node_id == node))
        })
        .map(|t| t.id)
        .collect();
    ids.into_iter()
        .filter_map(|id| entries.remove(&id))
        .map(|t| {
            notify_abort(state, &t);
            revoke_event(&t, "backbone_capability_withdrawn")
        })
        .collect()
}

pub(super) fn revoke_removed_backbone_edges(
    state: &NetworkState,
    tenant: ObjectId,
    source: ObjectId,
    approved: &[roomler_ai_remote_control::models::PeerRelayBackboneEdge],
) -> Vec<PeerRelayAuditEvent> {
    let mut entries = state
        .org_relay
        .trials
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let ids: Vec<_> = entries
        .values()
        .filter(|t| {
            !returned(t) && t.session.tenant_id == tenant && t.session.relay_agent_id == source
        })
        .filter_map(|t| {
            let path = t.backbone.as_ref()?;
            let keep = approved.iter().any(|e| {
                ObjectId::parse_str(&e.relay_agent_id).ok() == Some(path.exit.relay_agent_id)
                    && e.endpoint == path.private_endpoint
            });
            (!keep).then_some(t.id)
        })
        .collect();
    ids.into_iter()
        .filter_map(|id| entries.remove(&id))
        .map(|t| {
            notify_abort(state, &t);
            revoke_event(&t, "backbone_edge_revoked")
        })
        .collect()
}

fn notify_abort(state: &NetworkState, trial: &Trial) {
    trial.cancel.send_replace(true);
    for member in &trial.session.members {
        push_control(
            state,
            &member.party.node_ref,
            ServerMsg::OverlayPathTrialAbort { trial_id: trial.id },
        );
    }
    retire_relays(state, trial);
}

fn retire_relays(state: &NetworkState, trial: &Trial) {
    push_control(
        state,
        &trial.session.relay.node_ref,
        ServerMsg::OverlayRelayRevoke {
            vni: trial.session.vni,
        },
    );
    if let Some(path) = trial.backbone.as_ref() {
        push_control(
            state,
            &path.exit.relay.node_ref,
            ServerMsg::OverlayRelayRevoke { vni: path.exit.vni },
        );
        push_control(
            state,
            &trial.session.relay.node_ref,
            ServerMsg::OverlayRelayBridgeRevoke {
                trial_id: trial.id,
                generation: trial.session.generation,
            },
        );
    }
}

fn revoke_event(trial: &Trial, reason: &str) -> PeerRelayAuditEvent {
    let s = &trial.session;
    PeerRelayAuditEvent {
        id: None,
        tenant_id: s.tenant_id,
        action: PeerRelayAuditAction::Revoke,
        agent_id: Some(s.relay_agent_id),
        user_id: None,
        requester_node_id: Some(s.members[0].party.node_id),
        peer_node_id: Some(s.members[1].party.node_id),
        relay_node_id: Some(s.relay.node_id),
        serve: None,
        vni: Some(s.vni),
        warn_only: false,
        at: DateTime::now(),
        denied: None,
        reason: Some(reason.to_string()),
    }
}

fn start_message(trial: &Trial, index: usize) -> ServerMsg {
    let s = if index == 1 {
        trial
            .backbone
            .as_ref()
            .map(|b| &b.exit)
            .unwrap_or(&trial.session)
    } else {
        &trial.session
    };
    ServerMsg::OverlayPathTrialStart {
        trial_id: trial.id,
        request_id: trial.request_id,
        peer_node_id: s.members[1 - index].party.node_id,
        peer_wg_public_key: s.members[1 - index].wg_public_key.clone(),
        vni: s.vni,
        generation: s.generation,
        relay_node_id: s.relay.node_id,
        relay_endpoints: s.endpoints.clone(),
        bind_secret: s.members[index].bind_secret.clone(),
        bind_secs: limits::BIND_SECS,
        max_lifetime_secs: limits::MAX_LIFETIME_SECS,
    }
}

fn push_members(state: &NetworkState, trial: &Trial, message: ServerMsg) -> bool {
    // Always try BOTH; short-circuiting would strand the second participant.
    let a = push_control(
        state,
        &trial.session.members[0].party.node_ref,
        message.clone(),
    );
    let b = push_control(state, &trial.session.members[1].party.node_ref, message);
    a && b
}

pub async fn request(
    state: &NetworkState,
    ident: NodeIdentity,
    peer_id: ObjectId,
    relay_id: ObjectId,
    request_id: u64,
    exit_relay_node_id: Option<ObjectId>,
) {
    let authorization_epoch = state.org_relay.eligibility_generation();
    let Some(requester) = current_node(state, ident).await else {
        return;
    };
    let Some(req_id) = requester.id else { return };
    if !state.org_relay.trials.rate.check_bounded(req_id, req_id, 2) {
        return;
    }
    let Ok(peer) = state.overlay_nodes.base.find_by_id(peer_id).await else {
        return;
    };
    if req_id == peer_id || peer.tenant_id != requester.tenant_id || peer.deleted_at.is_some() {
        return;
    }
    if peer_relay_mode(state, requester.tenant_id).await != PeerRelayMode::On {
        return;
    }
    if !state.org_relay.join_extras(req_id).supports_path_trial_v1
        || !state.org_relay.join_extras(peer_id).supports_path_trial_v1
    {
        return;
    }
    // Pair authorization is separate from each member's grant to the relay.
    let Ok(acl) = try_load_acl(state, requester.tenant_id, PolicyLoad::Always).await else {
        return;
    };
    let Ok(source) = try_overlay_source_of(state, &requester).await else {
        return;
    };
    let routes = peer.effective_routes();
    if acl.enforcing()
        && !evaluate_overlay(
            &acl.policies,
            &source,
            OverlayPeerRef {
                node_id: peer_id,
                overlay_ip: &peer.overlay_ip,
                approved_routes: &routes,
            },
        )
        .visible
    {
        return;
    }
    let (plan, backbone_plan) = if let Some(exit_id) = exit_relay_node_id {
        let Ok(path) = plan_backbone(state, &requester, &peer, relay_id, exit_id).await else {
            return;
        };
        (path.ingress, Some((path.exit, path.private_endpoint)))
    } else {
        let Ok(plans) = plan_mint_candidates(state, &requester, &peer).await else {
            return;
        };
        // The client may legitimately try a non-first discovery hint. Re-run
        // every shared authorization gate, then require this EXACT relay; do
        // not replace its requested path with the server's current first pick.
        let Some(plan) = plans.into_iter().find(|p| p.relay.id == Some(relay_id)) else {
            return;
        };
        (plan, None)
    };
    // Metadata is only a hint: eligibility is re-evaluated now, never trusted
    // from a client-provided relay id or stale discovery cache.
    if plan.relay.id != Some(relay_id) {
        return;
    }
    let pair = pair_key(req_id, peer_id);
    let tenant = requester.tenant_id;
    let (trial_id, cancel_rx) = {
        let mut entries = state
            .org_relay
            .trials
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let reserved_for = |id: ObjectId| {
            entries
                .values()
                .flat_map(|t| {
                    let mut out = Vec::with_capacity(2);
                    if t.session.relay.node_id == id {
                        out.push(t.session.vni);
                    }
                    if let Some(b) = t.backbone.as_ref() {
                        if b.exit.relay.node_id == id {
                            out.push(b.exit.vni);
                        }
                    }
                    out
                })
                .collect::<Vec<_>>()
        };
        let reserved = reserved_for(relay_id);
        let exit_reserved = backbone_plan
            .as_ref()
            .map(|(p, _)| reserved_for(p.relay.id.unwrap_or_default()));
        let admission = admit_trial(
            &mut entries,
            &pair,
            tenant,
            req_id,
            request_id,
            authorization_epoch,
            state.org_relay.eligibility_generation(),
            || {
                let vni = state
                    .org_relay
                    .alloc_vni_with_reserved(relay_id, &reserved)?;
                let now = Instant::now();
                let (cancel, _) = watch::channel(false);
                let session = OrgRelaySession {
                    tenant_id: tenant,
                    pair_key: pair.clone(),
                    vni,
                    generation: state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1,
                    relay: SessionParty {
                        node_id: relay_id,
                        node_ref: plan.relay.node_ref,
                    },
                    relay_agent_id: plan.relay_agent_id,
                    implicit: plan.implicit,
                    members: [
                        SessionMember {
                            party: SessionParty {
                                node_id: req_id,
                                node_ref: requester.node_ref,
                            },
                            wg_public_key: requester.wg_public_key,
                            bind_secret: random_secret(),
                        },
                        SessionMember {
                            party: SessionParty {
                                node_id: peer_id,
                                node_ref: peer.node_ref,
                            },
                            wg_public_key: peer.wg_public_key,
                            bind_secret: random_secret(),
                        },
                    ],
                    endpoints: plan.endpoints.into_iter().take(4).collect(),
                    expires_at: now + Duration::from_secs(u64::from(limits::MAX_LIFETIME_SECS)),
                    bind_by: now + Duration::from_secs(u64::from(limits::BIND_SECS)),
                };
                let backbone = if let Some((exit, private_endpoint)) = backbone_plan {
                    let exit_id = exit.relay.id?;
                    let mut secondary = session.clone();
                    secondary.vni = state.org_relay.alloc_vni_with_reserved(
                        exit_id,
                        exit_reserved.as_deref().unwrap_or(&[]),
                    )?;
                    secondary.generation =
                        state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1;
                    secondary.relay = SessionParty {
                        node_id: exit_id,
                        node_ref: exit.relay.node_ref,
                    };
                    secondary.relay_agent_id = exit.relay_agent_id;
                    secondary.endpoints = exit.endpoints.into_iter().take(4).collect();
                    for m in &mut secondary.members {
                        m.bind_secret = random_secret();
                    }
                    Some(BackboneTrial {
                        exit: secondary,
                        private_endpoint,
                    })
                } else {
                    None
                };
                Some(Trial {
                    id: ObjectId::new(),
                    request_id,
                    session,
                    backbone,
                    phase: Phase::Preparing([None, None]),
                    started: now,
                    return_state: None,
                    return_ids: HashSet::new(),
                    cancel,
                })
            },
        );
        let id = match admission {
            Admission::Rejected => return,
            Admission::Existing(id) => {
                let existing = &entries[&id];
                if existing.session.relay.node_id != relay_id
                    || existing.backbone.as_ref().map(|b| b.exit.relay.node_id)
                        != exit_relay_node_id
                {
                    return;
                }
                let message = if let Some(r) = existing.return_state.as_ref() {
                    return_message(existing.id, r)
                } else if matches!(existing.phase, Phase::Finalized) {
                    ServerMsg::OverlayPathTrialFinalize { trial_id: id }
                } else {
                    start_message(existing, 0)
                };
                push_control(state, &existing.session.members[0].party.node_ref, message);
                return;
            }
            Admission::Created(id) => id,
        };
        let trial = &entries[&id];
        let s = &trial.session;
        let serve = |session: &OrgRelaySession| ServerMsg::OverlayRelayServe {
            vni: session.vni,
            generation: session.generation,
            members: session
                .members
                .iter()
                .map(|m| RelayMemberWire {
                    wg_public_key: m.wg_public_key.clone(),
                    bind_secret: m.bind_secret.clone(),
                })
                .collect(),
            bind_secs: limits::BIND_SECS,
            idle_secs: limits::IDLE_SECS,
            max_lifetime_secs: limits::MAX_LIFETIME_SECS,
        };
        let mut relay_sent = push_control(state, &s.relay.node_ref, serve(s));
        if let Some(path) = trial.backbone.as_ref() {
            let exit_sent = push_control(state, &path.exit.relay.node_ref, serve(&path.exit));
            let bridge_sent = push_control(
                state,
                &s.relay.node_ref,
                ServerMsg::OverlayRelayBridgeServe {
                    bridge: roomler_ai_remote_control::signaling::RelayBridgeWire {
                        trial_id: trial.id,
                        generation: s.generation,
                        source_agent_id: s.relay_agent_id,
                        target_agent_id: path.exit.relay_agent_id,
                        local_vni: s.vni,
                        local_generation: s.generation,
                        local_bind_secret: s.members[1].bind_secret.clone(),
                        remote_endpoint: path.private_endpoint.clone(),
                        remote_vni: path.exit.vni,
                        remote_generation: path.exit.generation,
                        remote_bind_secret: path.exit.members[0].bind_secret.clone(),
                        max_lifetime_secs: limits::MAX_LIFETIME_SECS,
                    },
                },
            );
            relay_sent = relay_sent && exit_sent && bridge_sent;
        }
        let a = relay_sent
            && push_control(state, &s.members[0].party.node_ref, start_message(trial, 0));
        let b = relay_sent
            && push_control(state, &s.members[1].party.node_ref, start_message(trial, 1));
        if !(relay_sent && a && b) {
            if let Some(trial) = entries.remove(&id) {
                notify_abort(state, &trial);
            }
            return;
        }
        (id, trial.cancel.subscribe())
    };
    let state = state.clone();
    tokio::spawn(async move {
        timer(state, trial_id, cancel_rx).await;
    });
}

enum Admission {
    Rejected,
    Existing(ObjectId),
    Created(ObjectId),
}

#[allow(clippy::too_many_arguments)]
fn admit_trial(
    entries: &mut HashMap<ObjectId, Trial>,
    pair: &str,
    tenant: ObjectId,
    requester: ObjectId,
    request_id: u64,
    expected_epoch: u64,
    current_epoch: u64,
    allocate: impl FnOnce() -> Option<Trial>,
) -> Admission {
    if expected_epoch != current_epoch {
        return Admission::Rejected;
    }
    if let Some(existing) = entries.values().find(|t| {
        t.session.pair_key == pair
            && t.session.members[0].party.node_id == requester
            && t.request_id == request_id
    }) {
        return Admission::Existing(existing.id);
    }
    if entries.len() >= MAX_TRIALS
        || entries
            .values()
            .filter(|t| t.session.tenant_id == tenant)
            .count()
            >= MAX_TENANT_TRIALS
        || entries.values().any(|t| {
            t.session.pair_key == pair
                && (!matches!(t.phase, Phase::Finalized)
                    || t.return_state
                        .as_ref()
                        .is_some_and(|r| !matches!(r.phase, ReturnPhase::Finalized)))
        })
    {
        return Admission::Rejected;
    }
    let Some(trial) = allocate() else {
        return Admission::Rejected;
    };
    let id = trial.id;
    entries.insert(id, trial);
    Admission::Created(id)
}

// This is a protocol rendezvous, not a server-side RTT score. Ready asserts
// that the authenticated member's local same-metric/fresh-window check passed.
fn advance(
    phase: &mut Phase,
    member: usize,
    update: PathTrialUpdate,
    now: Instant,
) -> Option<Result<bool, ()>> {
    match (phase, update) {
        (Phase::Preparing(ready), PathTrialUpdate::Ready) => {
            ready[member].get_or_insert(now);
            if ready.iter().all(Option::is_some) {
                if ready
                    .iter()
                    .any(|t| now.duration_since(t.unwrap()) > READY_FRESH)
                {
                    return Some(Err(()));
                }
                Some(Ok(false)) // caller installs Committing state
            } else {
                None
            }
        }
        (Phase::Committing(acked), PathTrialUpdate::Committed) => {
            acked[member] = true;
            acked.iter().all(|v| *v).then_some(Ok(true))
        }
        (Phase::Committing(_), PathTrialUpdate::Ready) => Some(Ok(false)),
        (Phase::Finalized, PathTrialUpdate::Ready | PathTrialUpdate::Committed) => Some(Ok(true)),
        (Phase::Finalized, PathTrialUpdate::Abort) => None, // late preparation failure cannot undo finalization
        (_, PathTrialUpdate::Abort) => Some(Err(())),
        _ => None,
    }
}

pub async fn update(
    state: &NetworkState,
    ident: NodeIdentity,
    id: ObjectId,
    update: PathTrialUpdate,
) {
    let Some(node) = current_node(state, ident).await else {
        return;
    };
    let Some(node_id) = node.id else { return };
    let mut entries = state
        .org_relay
        .trials
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(trial) = entries.get_mut(&id) else {
        return;
    };
    let Some(member) = trial.session.member_index(node_id) else {
        return;
    };
    let identity_matches = trial.session.tenant_id == node.tenant_id
        && trial.session.members[member].wg_public_key == node.wg_public_key;
    let now = Instant::now();
    if identity_matches && trial.return_state.is_some() {
        return;
    }
    let action = if !identity_matches
        || trial.session.expires_at <= now
        || (!matches!(trial.phase, Phase::Finalized)
            && now.duration_since(trial.started) >= PREPARE_TIMEOUT)
    {
        Some(Err(()))
    } else {
        advance(&mut trial.phase, member, update, now)
    };
    match action {
        Some(Err(())) => {
            if let Some(trial) = entries.remove(&id) {
                notify_abort(state, &trial);
            }
        }
        Some(Ok(finalize)) => {
            // Duplicate Ready during Committing must not clear an existing ACK.
            if finalize {
                trial.phase = Phase::Finalized;
            } else if !matches!(trial.phase, Phase::Committing(_)) {
                trial.phase = Phase::Committing([false, false]);
            }
            let msg = if finalize {
                ServerMsg::OverlayPathTrialFinalize { trial_id: id }
            } else {
                ServerMsg::OverlayPathTrialCommit { trial_id: id }
            };
            if !push_members(state, trial, msg) && !finalize {
                if let Some(trial) = entries.remove(&id) {
                    notify_abort(state, &trial);
                }
                return;
            }
            // Both participants have already committed before Finalize. A
            // dropped Finalize must retain that decision, never send Abort
            // after one participant legitimately released its old peer.

            if finalize {
                let pair = entries[&id].session.pair_key.clone();
                let old: Vec<_> = entries
                    .values()
                    .filter(|t| {
                        t.id != id
                            && t.session.pair_key == pair
                            && matches!(t.phase, Phase::Finalized)
                    })
                    .map(|t| t.id)
                    .collect();
                for old_id in old {
                    if let Some(old) = entries.remove(&old_id) {
                        notify_abort(state, &old);
                    }
                }
            }
        }
        None => {}
    }
}

fn returned(trial: &Trial) -> bool {
    trial
        .return_state
        .as_ref()
        .is_some_and(|r| matches!(r.phase, ReturnPhase::Finalized))
}

fn return_message(id: ObjectId, r: &ReturnState) -> ServerMsg {
    match r.phase {
        ReturnPhase::Preparing(_) => ServerMsg::OverlayPathTrialReturnPrepare {
            trial_id: id,
            return_id: r.id,
        },
        ReturnPhase::Committing(_) => ServerMsg::OverlayPathTrialReturnCommit {
            trial_id: id,
            return_id: r.id,
        },
        ReturnPhase::Finalized => ServerMsg::OverlayPathTrialReturnFinalize {
            trial_id: id,
            return_id: r.id,
        },
    }
}

fn cancel_return(state: &NetworkState, trial: &mut Trial) {
    if let Some(r) = trial.return_state.take() {
        // Not TrialAbort: both endpoints still retain the healthy relay sender
        // and receive path until bilateral ReturnFinalize.
        push_members(
            state,
            trial,
            ServerMsg::OverlayPathTrialReturnAbort {
                trial_id: trial.id,
                return_id: r.id,
            },
        );
    }
}

fn advance_return(
    phase: &mut ReturnPhase,
    member: usize,
    update: PathTrialReturnUpdate,
    now: Instant,
) -> Option<Result<bool, ()>> {
    match (phase, update) {
        (ReturnPhase::Preparing(ready), PathTrialReturnUpdate::Ready) => {
            ready[member].get_or_insert(now);
            if ready.iter().all(Option::is_some) {
                if ready
                    .iter()
                    .any(|t| now.duration_since(t.unwrap()) > READY_FRESH)
                {
                    Some(Err(()))
                } else {
                    Some(Ok(false))
                }
            } else {
                None
            }
        }
        (ReturnPhase::Committing(acked), PathTrialReturnUpdate::Returned) => {
            acked[member] = true;
            acked.iter().all(|v| *v).then_some(Ok(true))
        }
        (ReturnPhase::Committing(_), PathTrialReturnUpdate::Ready) => Some(Ok(false)),
        (
            ReturnPhase::Finalized,
            PathTrialReturnUpdate::Ready | PathTrialReturnUpdate::Returned,
        ) => Some(Ok(true)),
        (ReturnPhase::Finalized, PathTrialReturnUpdate::Abort) => None,
        (_, PathTrialReturnUpdate::Abort) => Some(Err(())),
        _ => None,
    }
}

pub async fn return_update(
    state: &NetworkState,
    ident: NodeIdentity,
    id: ObjectId,
    return_id: ObjectId,
    update: PathTrialReturnUpdate,
) {
    let epoch = state.org_relay.eligibility_generation();
    let Some(node) = current_node(state, ident).await else {
        return;
    };
    let Some(node_id) = node.id else { return };
    let mut entries = state
        .org_relay
        .trials
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if epoch != state.org_relay.eligibility_generation() {
        return;
    }
    let Some(trial) = entries.get_mut(&id) else {
        return;
    };
    let Some(member) = trial.session.member_index(node_id) else {
        return;
    };
    let now = Instant::now();
    if trial.session.tenant_id != node.tenant_id
        || trial.session.members[member].wg_public_key != node.wg_public_key
        || (trial.session.expires_at <= now && !returned(trial))
    {
        if let Some(trial) = entries.remove(&id) {
            notify_abort(state, &trial);
        }
        return;
    }
    // Only a fully agreed relay choice has a retained direct shadow to return
    // to. Discovery or a half-committed trial cannot initiate a return.
    if !matches!(trial.phase, Phase::Finalized) {
        return;
    }
    // A dropped ReturnAbort must be recoverable. The bounded remembered-id
    // set is also an abort-decision log: retransmitted phase updates for an
    // aborted attempt replay Abort, never silently strand a committed member.
    let active_return = trial.return_state.as_ref().map(|r| r.id);
    if active_return != Some(return_id) && trial.return_ids.contains(&return_id) {
        push_members(
            state,
            trial,
            ServerMsg::OverlayPathTrialReturnAbort {
                trial_id: id,
                return_id,
            },
        );
        return;
    }
    if matches!(update, PathTrialReturnUpdate::Request) {
        if let Some(r) = trial.return_state.as_ref() {
            if r.id == return_id {
                push_members(state, trial, return_message(id, r));
            }
            return;
        }
        if trial.return_ids.len() >= MAX_RETURN_ATTEMPTS
            || trial.return_ids.contains(&return_id)
            || !state
                .org_relay
                .trials
                .return_rate
                .check_bounded(node_id, node_id, 2)
        {
            return;
        }
        trial.return_ids.insert(return_id);
        trial.return_state = Some(ReturnState {
            id: return_id,
            phase: ReturnPhase::Preparing([None, None]),
            started: now,
        });
        let sent = push_members(
            state,
            trial,
            return_message(id, trial.return_state.as_ref().unwrap()),
        );
        if !sent {
            cancel_return(state, trial);
        }
        trial.cancel.send_replace(false); // wake this trial's one cancellable timer
        return;
    }
    let Some(r) = trial.return_state.as_mut() else {
        return;
    };
    if r.id != return_id {
        return;
    } // stale attempt cannot affect a newer return
    let action = if !matches!(r.phase, ReturnPhase::Finalized)
        && now.duration_since(r.started) >= PREPARE_TIMEOUT
    {
        Some(Err(()))
    } else {
        advance_return(&mut r.phase, member, update, now)
    };
    match action {
        Some(Err(())) => cancel_return(state, trial),
        Some(Ok(finalize)) => {
            let r = trial.return_state.as_mut().unwrap();
            let first_finalize = finalize && !matches!(r.phase, ReturnPhase::Finalized);
            if finalize {
                r.phase = ReturnPhase::Finalized;
                if first_finalize {
                    r.started = now;
                }
            } else if !matches!(r.phase, ReturnPhase::Committing(_)) {
                r.phase = ReturnPhase::Committing([false, false]);
            }
            let message = return_message(id, trial.return_state.as_ref().unwrap());
            if !push_members(state, trial, message) && !finalize {
                cancel_return(state, trial);
            }
            if first_finalize {
                // Both have acknowledged their direct sender before releasing
                // the candidate VNI. A partial Finalize retains this decision;
                // duplicate Returned replays it and late ReturnAbort is ignored.
                retire_relays(state, trial);
            }
        }
        None => {}
    }
    trial.cancel.send_replace(false);
}

fn expire_tick(state: &NetworkState, id: ObjectId) -> Option<Duration> {
    let mut entries = state
        .org_relay
        .trials
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let trial = entries.get_mut(&id)?;
    let now = Instant::now();
    // A returned tombstone only supports bounded idempotent Finalize replay.
    // It has no allocated relay and expires without tearing down healthy direct.
    if let Some(r) = trial.return_state.as_ref() {
        if matches!(r.phase, ReturnPhase::Finalized) {
            let deadline = r.started + RETURN_TOMBSTONE;
            if now < deadline {
                return Some(deadline - now);
            }
            let trial = entries.remove(&id).unwrap();
            trial.cancel.send_replace(true);
            return None;
        }
    }
    if trial.session.expires_at <= now
        || (!matches!(trial.phase, Phase::Finalized)
            && now.duration_since(trial.started) >= PREPARE_TIMEOUT)
    {
        if let Some(trial) = entries.remove(&id) {
            notify_abort(state, &trial);
        }
        return None;
    }
    let mut deadline = trial.session.expires_at;
    if !matches!(trial.phase, Phase::Finalized) {
        deadline = deadline.min(trial.started + PREPARE_TIMEOUT);
    }
    if let Some(r) = trial.return_state.as_ref() {
        let return_deadline = r.started + PREPARE_TIMEOUT;
        if now >= return_deadline {
            cancel_return(state, trial);
        } else {
            deadline = deadline.min(return_deadline);
        }
    }
    Some(deadline - now)
}

async fn timer(state: NetworkState, id: ObjectId, mut cancel: watch::Receiver<bool>) {
    loop {
        let Some(delay) = expire_tick(&state, id) else {
            return;
        };
        tokio::select! {
            _ = tokio::time::sleep(delay) => {},
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() { return; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bilateral_trial_needs_both_fresh_ready_then_both_commit_acks() {
        let now = Instant::now();
        let mut phase = Phase::Preparing([None, None]);
        assert!(advance(&mut phase, 0, PathTrialUpdate::Committed, now).is_none());
        assert!(advance(&mut phase, 0, PathTrialUpdate::Ready, now).is_none());
        assert!(matches!(
            advance(&mut phase, 1, PathTrialUpdate::Ready, now),
            Some(Ok(false))
        ));
        phase = Phase::Committing([false, false]);
        assert!(advance(&mut phase, 0, PathTrialUpdate::Committed, now).is_none());
        assert!(matches!(
            advance(&mut phase, 1, PathTrialUpdate::Committed, now),
            Some(Ok(true))
        ));
        phase = Phase::Finalized;
        assert!(advance(&mut phase, 0, PathTrialUpdate::Abort, now).is_none());
    }
    #[test]
    fn repeated_ready_does_not_refresh_stale_measurement_window() {
        let now = Instant::now();
        let mut phase = Phase::Preparing([None, None]);
        assert!(advance(&mut phase, 0, PathTrialUpdate::Ready, now).is_none());
        assert!(advance(&mut phase, 0, PathTrialUpdate::Ready, now + READY_FRESH).is_none());
        assert!(matches!(
            advance(
                &mut phase,
                1,
                PathTrialUpdate::Ready,
                now + READY_FRESH + Duration::from_millis(1)
            ),
            Some(Err(()))
        ));
    }

    fn fixture_trial(
        tenant: ObjectId,
        requester: ObjectId,
        peer: ObjectId,
        relay: ObjectId,
        request_id: u64,
        vni: u32,
        generation: u64,
    ) -> Trial {
        let now = Instant::now();
        Trial {
            id: ObjectId::new(),
            request_id,
            phase: Phase::Preparing([None, None]),
            started: now,
            return_state: None,
            return_ids: HashSet::new(),
            cancel: watch::channel(false).0,
            backbone: None,
            session: OrgRelaySession {
                tenant_id: tenant,
                pair_key: pair_key(requester, peer),
                vni,
                generation,
                relay: SessionParty {
                    node_id: relay,
                    node_ref: NodeRef::Agent { agent_id: relay },
                },
                relay_agent_id: relay,
                implicit: false,
                members: [
                    SessionMember {
                        party: SessionParty {
                            node_id: requester,
                            node_ref: NodeRef::Agent {
                                agent_id: requester,
                            },
                        },
                        wg_public_key: "a".into(),
                        bind_secret: "a".into(),
                    },
                    SessionMember {
                        party: SessionParty {
                            node_id: peer,
                            node_ref: NodeRef::Agent { agent_id: peer },
                        },
                        wg_public_key: "b".into(),
                        bind_secret: "b".into(),
                    },
                ],
                endpoints: vec!["8.8.8.8:3478".into()],
                expires_at: now + Duration::from_secs(60),
                bind_by: now + Duration::from_secs(30),
            },
        }
    }

    #[test]
    fn revocation_epoch_rejects_delayed_authorization_before_allocating_anything() {
        let state = OrgRelayState::new();
        let expected = state.eligibility_generation();
        state.invalidate_eligibility(); // revoke occurred while plan_mint awaited storage
        let mut entries = HashMap::new();
        let id = ObjectId::new();
        let admission = admit_trial(
            &mut entries,
            "pair",
            id,
            id,
            1,
            expected,
            state.eligibility_generation(),
            || {
                state.lamport.fetch_add(1, Ordering::Relaxed);
                state.alloc_vni_with_reserved(id, &[]);
                panic!("revoked authorization must not run the session factory");
            },
        );
        assert!(matches!(admission, Admission::Rejected));
        assert!(entries.is_empty() && state.next_vni.is_empty());
        assert_eq!(state.lamport.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn duplicate_and_inflight_requests_do_not_burn_vni_or_generation() {
        let state = OrgRelayState::new();
        let (tenant, requester, peer, relay) = (
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
        );
        let pair = pair_key(requester, peer);
        let mut entries = HashMap::new();
        let allocate = |request_id| {
            let vni = state.alloc_vni_with_reserved(relay, &[]).unwrap();
            let generation = state.lamport.fetch_add(1, Ordering::Relaxed) + 1;
            Some(fixture_trial(
                tenant, requester, peer, relay, request_id, vni, generation,
            ))
        };
        let Admission::Created(id) =
            admit_trial(&mut entries, &pair, tenant, requester, 1, 0, 0, || {
                allocate(1)
            })
        else {
            panic!("first admission");
        };
        assert_eq!(entries[&id].session.vni, 1);
        assert!(
            matches!(admit_trial(&mut entries, &pair, tenant, requester, 1, 0, 0, || allocate(1)), Admission::Existing(existing) if existing == id)
        );
        assert!(matches!(
            admit_trial(
                &mut entries,
                &pair,
                tenant,
                requester,
                2,
                0,
                0,
                || allocate(2)
            ),
            Admission::Rejected
        ));
        entries.get_mut(&id).unwrap().phase = Phase::Finalized;
        assert!(
            matches!(admit_trial(&mut entries, &pair, tenant, requester, 1, 0, 0, || allocate(1)), Admission::Existing(existing) if existing == id)
        );
        assert_eq!(state.lamport.load(Ordering::Relaxed), 1);
        assert_eq!(*state.next_vni.get(&relay).unwrap(), 2);
        let Admission::Created(next) =
            admit_trial(&mut entries, &pair, tenant, requester, 2, 0, 0, || {
                allocate(2)
            })
        else {
            panic!("next trial");
        };
        assert_eq!(
            entries[&next].session.vni, 2,
            "no duplicate consumed cursor values"
        );
        assert_eq!(entries[&next].session.generation, 2);
    }
    #[test]
    fn return_requires_bilateral_fresh_ready_and_both_returned_before_retirement() {
        let now = Instant::now();
        let mut phase = ReturnPhase::Preparing([None, None]);
        assert!(advance_return(&mut phase, 0, PathTrialReturnUpdate::Returned, now).is_none());
        assert!(advance_return(&mut phase, 0, PathTrialReturnUpdate::Ready, now).is_none());
        assert!(matches!(
            advance_return(&mut phase, 1, PathTrialReturnUpdate::Ready, now),
            Some(Ok(false))
        ));
        phase = ReturnPhase::Committing([false, false]);
        assert!(advance_return(&mut phase, 0, PathTrialReturnUpdate::Returned, now).is_none());
        assert!(matches!(
            advance_return(&mut phase, 1, PathTrialReturnUpdate::Returned, now),
            Some(Ok(true))
        ));
        phase = ReturnPhase::Finalized;
        assert!(advance_return(&mut phase, 0, PathTrialReturnUpdate::Abort, now).is_none());
        assert!(matches!(
            advance_return(&mut phase, 0, PathTrialReturnUpdate::Returned, now),
            Some(Ok(true))
        ));
    }

    #[test]
    fn duplicate_return_ready_does_not_renew_old_quality_or_clear_return_ack() {
        let now = Instant::now();
        let mut phase = ReturnPhase::Preparing([None, None]);
        assert!(advance_return(&mut phase, 0, PathTrialReturnUpdate::Ready, now).is_none());
        assert!(
            advance_return(
                &mut phase,
                0,
                PathTrialReturnUpdate::Ready,
                now + READY_FRESH
            )
            .is_none()
        );
        assert!(matches!(
            advance_return(
                &mut phase,
                1,
                PathTrialReturnUpdate::Ready,
                now + READY_FRESH + Duration::from_millis(1)
            ),
            Some(Err(()))
        ));
        phase = ReturnPhase::Committing([true, false]);
        assert!(matches!(
            advance_return(&mut phase, 1, PathTrialReturnUpdate::Ready, now),
            Some(Ok(false))
        ));
        assert!(matches!(phase, ReturnPhase::Committing([true, false])));
        assert!(matches!(
            advance_return(&mut phase, 0, PathTrialReturnUpdate::Abort, now),
            Some(Err(()))
        ));
    }
}
