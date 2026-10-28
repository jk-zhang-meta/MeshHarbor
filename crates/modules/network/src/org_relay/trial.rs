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
    requires_cross_border_approval: bool,
    source_zone: BusinessZone,
    exit_zone: BusinessZone,
}

struct Trial {
    id: ObjectId,
    request_id: u64,
    requester_node_id: ObjectId,
    requester_at_exit: bool,
    relay_zones: Vec<BusinessZone>,
    member_zones: Option<[BusinessZone; 2]>,
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
                (t.session.relay_nodes().any(|id| id == relay)
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
                let mut out: Vec<u32> = t.session.vnis_on(relay).collect();
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
                && (t.backbone.is_some() || !t.session.hops.is_empty())
                && ((member_withdrawn && t.session.member_index(node).is_some())
                    || (ingress_withdrawn && (t.session.relay.node_id == node
                        || t.session.hops.iter().take(t.session.hops.len().saturating_sub(1)).any(|h| h.relay.node_id == node))))
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
    let ids: Vec<_> = entries.values().filter(|t| {
        if returned(t) || t.session.tenant_id != tenant { return false; }
        if t.session.has_removed_line_edge(source, approved) { return true; }
        if t.session.relay_agent_id != source { return false; }
        t.backbone.as_ref().is_some_and(|path| !approved.iter().any(|e| {
            ObjectId::parse_str(&e.relay_agent_id).ok() == Some(path.exit.relay_agent_id)
                && e.endpoint == path.private_endpoint
                && (!path.requires_cross_border_approval || e.cross_border)
        }))
    }).map(|t| t.id).collect();
    ids.into_iter()
        .filter_map(|id| entries.remove(&id))
        .map(|t| {
            notify_abort(state, &t);
            revoke_event(&t, "backbone_edge_revoked")
        })
        .collect()
}

// Isolated from admission/delivery so N-hop zone validation can evolve
// independently while sharing the trial mutex and revoke ordering.
#[path = "trial_zone.rs"]
mod trial_zone;
pub(super) use trial_zone::recheck_relay_zones;
#[cfg(feature = "path-planner-test-support")]
pub(super) use trial_zone::insert_trial_fixture;

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
    for (target, message) in trial.session.hop_revocations() {
        push_control(state, &target, message);
    }
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

fn trial_path(trial: &Trial) -> roomler_ai_remote_control::signaling::RelayPathWire {
    let mut nodes: Vec<_> = trial.session.relay_nodes().collect();
    if let Some(backbone) = trial.backbone.as_ref() { nodes.push(backbone.exit.relay.node_id); }
    roomler_ai_remote_control::signaling::RelayPathWire::new(nodes).expect("admitted trial path is nonempty and unique")
}

fn start_message(trial: &Trial, index: usize) -> ServerMsg {
    if !trial.session.hops.is_empty() {
        let s = &trial.session;
        let leg = s.member_leg(index);
        return ServerMsg::OverlayPathTrialStart {
            trial_id: trial.id, request_id: trial.request_id,
            path: trial_path(trial), requester_at_exit: trial.requester_at_exit,
            peer_node_id: s.members[1 - index].party.node_id,
            peer_wg_public_key: s.members[1 - index].wg_public_key.clone(),
            vni: leg.vni, generation: leg.generation, relay_node_id: leg.relay_node_id,
            relay_endpoints: leg.endpoints.to_vec(), bind_secret: s.members[index].bind_secret.clone(),
            bind_secs: limits::BIND_SECS, max_lifetime_secs: limits::MAX_LIFETIME_SECS,
        };
    }
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
        path: trial_path(trial), requester_at_exit: trial.requester_at_exit,
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

/// Record each cross-zone trial attempt before any capacity or grant escapes.
/// Rows denote attempts, not successful installation or delivery.
async fn audit_trial_path(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    plan: &path_trial_plan::TrialPathPlan,
) -> bool {
    let (Some(a), Some(b)) = (requester.id, peer.id) else { return false };
    let pair = pair_key(a, b);
    for (i, edge) in plan.edges.iter().enumerate().filter(|(_, edge)| edge.requires_cross_border_approval) {
        let source = &plan.relays[i];
        let target = &plan.relays[i + 1];
        let event = PeerRelayAuditEvent {
            id: None, tenant_id: requester.tenant_id, action: PeerRelayAuditAction::Mint,
            agent_id: Some(source.agent_id), user_id: None, requester_node_id: Some(a),
            peer_node_id: Some(b), relay_node_id: Some(source.node_id), serve: None,
            vni: None, warn_only: false, at: DateTime::now(), denied: None,
            reason: Some(format!("cross_border_edge:{}", target.agent_id)),
        };
        let write = async {
            #[cfg(feature = "path-planner-test-support")]
            match candidate_test_support::take_trial_crossing_audit_fault(&pair) {
                Some(candidate_test_support::TrialCrossingAuditFault::Error) => return false,
                Some(candidate_test_support::TrialCrossingAuditFault::Timeout) => std::future::pending::<()>().await,
                None => {}
            }
            state.peer_relay_audit.record(event).await.is_ok()
        };
        if !matches!(tokio::time::timeout(Duration::from_secs(3), write).await, Ok(true)) { return false; }
    }
    true
}

/// The plan is freshly authorized; a retained trial must still match every
/// node, edge, member and zone before any idempotent reply can reuse it.
fn trial_matches_plan(trial: &Trial, plan: &path_trial_plan::TrialPathPlan, requester: &OverlayNode, peer: &OverlayNode) -> bool {
    if trial.backbone.is_some() || trial.requester_at_exit != plan.requester_at_exit
        || trial_path(trial) != plan.path || trial.relay_zones != plan.relays.iter().map(|relay| relay.zone).collect::<Vec<_>>()
        || trial.member_zones != plan.member_zones { return false; }
    let session = &trial.session;
    let (first, last) = if plan.requester_at_exit { (peer, requester) } else { (requester, peer) };
    for (stored, fresh) in session.members.iter().zip([first, last]) {
        if Some(stored.party.node_id) != fresh.id || stored.party.node_ref != fresh.node_ref
            || stored.wg_public_key != fresh.wg_public_key { return false; }
    }
    if plan.relays.len() != session.hops.len() + 1 || plan.edges.len() != session.hops.len() { return false; }
    let first_relay = &plan.relays[0];
    if session.relay.node_id != first_relay.node_id || session.relay.node_ref != first_relay.node_ref
        || session.relay_agent_id != first_relay.agent_id || session.endpoints != first_relay.endpoints { return false; }
    for ((hop, relay), edge) in session.hops.iter().zip(plan.relays.iter().skip(1)).zip(&plan.edges) {
        if hop.relay.node_id != relay.node_id || hop.relay.node_ref != relay.node_ref
            || hop.relay_agent_id != relay.agent_id || hop.endpoints != relay.endpoints
            || hop.private_endpoint != edge.endpoint || hop.requires_cross_border_approval != edge.requires_cross_border_approval { return false; }
    }
    true
}

pub async fn request(
    state: &NetworkState,
    ident: NodeIdentity,
    peer_id: ObjectId,
    request_id: u64,
    path: roomler_ai_remote_control::signaling::RelayPathWire,
    requester_at_exit: bool,
) {
    let Some(requester) = current_node(state, ident).await else { return };
    let Some(req_id) = requester.id else { return };
    if !state.org_relay.trials.rate.check_bounded(req_id, req_id, 2) { return; }
    let Ok(peer) = state.overlay_nodes.base.find_by_id(peer_id).await else { return };
    if req_id == peer_id || peer.tenant_id != requester.tenant_id || peer.deleted_at.is_some() { return; }
    if peer_relay_mode(state, requester.tenant_id).await != PeerRelayMode::On { return; }
    if !state.org_relay.join_extras(req_id).supports_path_trial_v1 || !state.org_relay.join_extras(peer_id).supports_path_trial_v1 { return; }
    let nodes = path.relay_node_ids();
    if nodes.len() == 1 && requester_at_exit { return; }
    let pair = pair_key(req_id, peer_id);
    if crate::overlay::org_fallback_forced_derp(state, &pair) { return; }
    let existing = {
        let entries = state.org_relay.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.values().find(|t| t.session.pair_key == pair && t.requester_node_id == req_id && t.request_id == request_id)
            .map(|t| (t.id, t.session.clone()))
    };
    let reuse = existing.as_ref().map(|(id, session)| (*id, session));
    let mut candidate = None;
    let mut single_plan = None;
    let epoch;
    if nodes.len() >= 2 {
        let Ok(first) = path_trial_plan::plan_reusing(state, &requester, &peer, &path, requester_at_exit, reuse).await else { return };
        if !audit_trial_path(state, &requester, &peer, &first).await { return; }
        let Ok(fresh) = path_trial_plan::reauthorize_reusing(state, &requester, &peer, &first, reuse).await else { return };
        epoch = fresh.epoch;
        candidate = Some(fresh);
    } else {
        let auth_epoch = state.org_relay.eligibility_generation();
        let Ok(acl) = try_load_acl(state, requester.tenant_id, PolicyLoad::Always).await else { return };
        let Ok(source) = try_overlay_source_of(state, &requester).await else { return };
        let routes = peer.effective_routes();
        if acl.enforcing() && !evaluate_overlay(&acl.policies, &source,
            OverlayPeerRef { node_id: peer_id, overlay_ip: &peer.overlay_ip, approved_routes: &routes }).visible { return; }
        let Ok(plans) = plan_mint_candidates_reusing(state, &requester, &peer, reuse.map(|(_, session)| session), ZoneScope::Pair).await else { return };
        let Some(plan) = plans.into_iter().find(|p| p.relay.id == Some(nodes[0])) else { return };
        epoch = auth_epoch;
        single_plan = Some(plan);
    }
    let tenant = requester.tenant_id;
    let (trial_id, cancel_rx) = {
        let mut entries = state.org_relay.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
        if epoch != state.org_relay.eligibility_generation() || crate::overlay::org_fallback_forced_derp(state, &pair) { return; }
        let reserved: Vec<Vec<u32>> = nodes.iter().map(|node| entries.values().flat_map(|t| {
            let mut held: Vec<u32> = t.session.vnis_on(*node).collect();
            if let Some(backbone) = t.backbone.as_ref() { if backbone.exit.relay.node_id == *node { held.push(backbone.exit.vni); } }
            held
        }).collect()).collect();
        let mut delivery = None;
        let admission = admit_trial(&state.org_relay, &mut entries, nodes, &pair, tenant, req_id, request_id,
            epoch, state.org_relay.eligibility_generation(), || {
                let mut vnis = Vec::with_capacity(nodes.len());
                for (node, reserved) in nodes.iter().zip(&reserved) {
                    vnis.push(state.org_relay.alloc_vni_with_reserved(*node, reserved)?);
                }
                let now = Instant::now(); let (cancel, _) = watch::channel(false);
                let trial_id = ObjectId::new();
                let (first, last) = if requester_at_exit { (&peer, &requester) } else { (&requester, &peer) };
                let member = |n: &OverlayNode| SessionMember {
                    party: SessionParty { node_id: n.id.unwrap_or_default(), node_ref: n.node_ref.clone() },
                    wg_public_key: n.wg_public_key.clone(), bind_secret: random_secret(),
                };
                let (relay, relay_agent_id, endpoints, implicit) = if let Some(plan) = candidate.as_ref() {
                    let r = &plan.relays[0]; (SessionParty { node_id: r.node_id, node_ref: r.node_ref.clone() }, r.agent_id, r.endpoints.clone(), false)
                } else {
                    let p = single_plan.as_ref()?; (SessionParty { node_id: p.relay.id?, node_ref: p.relay.node_ref.clone() }, p.relay_agent_id, p.endpoints.iter().take(4).cloned().collect(), p.implicit)
                };
                let mut session = OrgRelaySession { tenant_id: tenant, pair_key: pair.clone(), vni: vnis[0],
                    generation: state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1,
                    relay, relay_agent_id, implicit, members: [member(first), member(last)], endpoints,
                    expires_at: now + Duration::from_secs(u64::from(limits::MAX_LIFETIME_SECS)),
                    bind_by: now + Duration::from_secs(u64::from(limits::BIND_SECS)), hops: Vec::new() };
                if let Some(plan) = candidate.as_ref() {
                    for (i, (relay, edge)) in plan.relays.iter().skip(1).zip(&plan.edges).enumerate() {
                        session.hops.push(LineLeg { relay: SessionParty { node_id: relay.node_id, node_ref: relay.node_ref.clone() },
                            relay_agent_id: relay.agent_id, vni: vnis[i + 1],
                            generation: state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1,
                            endpoints: relay.endpoints.clone(), private_endpoint: edge.endpoint.clone(),
                            requires_cross_border_approval: edge.requires_cross_border_approval,
                            bridge_id: if i == 0 { trial_id } else { ObjectId::new() },
                            bridge_secrets: [random_secret(), random_secret()] });
                    }
                }
                delivery = path_delivery::build(&session, now).ok();
                delivery.as_ref()?;
                Some(Trial { id: trial_id, request_id, requester_node_id: req_id, requester_at_exit,
                    relay_zones: candidate.as_ref().map(|p| p.relays.iter().map(|r| r.zone).collect()).unwrap_or_default(),
                    member_zones: candidate.as_ref().and_then(|p| p.member_zones), session, backbone: None,
                    phase: Phase::Preparing([None, None]), started: now, return_state: None,
                    return_ids: HashSet::new(), cancel })
            });
        let id = match admission {
            Admission::Rejected => return,
            Admission::Existing(id) => {
                let existing = &entries[&id];
                if trial_path(existing) != path || existing.requester_at_exit != requester_at_exit
                    || candidate.as_ref().is_some_and(|plan| !trial_matches_plan(existing, plan, &requester, &peer)) { return; }
                if let Some(plan) = single_plan.as_ref() {
                    let session = &existing.session;
                    let matches = session.hops.is_empty() && existing.backbone.is_none()
                        && session.relay.node_id == nodes[0] && session.relay.node_ref == plan.relay.node_ref
                        && session.relay_agent_id == plan.relay_agent_id && session.endpoints == plan.endpoints.iter().take(4).cloned().collect::<Vec<_>>()
                        && session.implicit == plan.implicit
                        && [(&requester, req_id), (&peer, peer_id)].iter().all(|(node, id)|
                            session.member_index(*id).is_some_and(|i| session.members[i].party.node_ref == node.node_ref
                                && session.members[i].wg_public_key == node.wg_public_key));
                    if !matches { return; }
                }
                let message = if let Some(r) = existing.return_state.as_ref() { return_message(existing.id, r) }
                    else if matches!(existing.phase, Phase::Finalized) { ServerMsg::OverlayPathTrialFinalize { trial_id: id } }
                    else if matches!(existing.phase, Phase::Committing(_)) { ServerMsg::OverlayPathTrialCommit { trial_id: id } }
                    else { let Some(index) = existing.session.member_index(req_id) else { return }; start_message(existing, index) };
                push_control(state, &requester.node_ref, message);
                return;
            }
            Admission::Created(id) => id,
        };
        let trial = &entries[&id];
        let Some(delivery) = delivery else { return };
        let mut sent = true;
        for (target, message) in delivery.relays.into_iter().chain(delivery.bridges) {
            if epoch != state.org_relay.eligibility_generation() || crate::overlay::org_fallback_forced_derp(state, &pair)
                || !push_control(state, &target, message) { sent = false; break; }
        }
        let a = sent && push_control(state, &trial.session.members[0].party.node_ref, start_message(trial, 0));
        let b = sent && push_control(state, &trial.session.members[1].party.node_ref, start_message(trial, 1));
        if !(sent && a && b) {
            if let Some(trial) = entries.remove(&id) { notify_abort(state, &trial); }
            return;
        }
        (id, trial.cancel.subscribe())
    };
    let state = state.clone(); tokio::spawn(async move { timer(state, trial_id, cancel_rx).await; });
}

enum Admission {
    Rejected,
    Existing(ObjectId),
    Created(ObjectId),
}

#[allow(clippy::too_many_arguments)]
fn admit_trial(
    state: &OrgRelayState,
    entries: &mut HashMap<ObjectId, Trial>,
    relay_nodes: &[ObjectId],
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
            && t.requester_node_id == requester
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
    // The trial lock is held from capacity inspection through insertion.
    if !has_capacity(state, entries, relay_nodes) {
        return Admission::Rejected;
    }
    let Some(trial) = allocate() else {
        return Admission::Rejected;
    };
    let id = trial.id;
    entries.insert(id, trial);
    Admission::Created(id)
}

/// A transient capacity snapshot. A trial still has to claim capacity later.
pub(super) fn path_has_capacity_snapshot(state: &OrgRelayState, relay_nodes: &[ObjectId]) -> bool {
    path_has_capacity_reusing(state, relay_nodes, None)
}

pub(super) fn path_has_capacity_reusing(state: &OrgRelayState, relay_nodes: &[ObjectId], trial_id: Option<ObjectId>) -> bool {
    let entries = state.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
    has_capacity_except(state, &entries, relay_nodes, trial_id)
}

/// Called only while `PathTrials.entries` is held. Every session creator must
/// use the same lock for this count to be an admission guarantee.
fn has_capacity(state: &OrgRelayState, entries: &HashMap<ObjectId, Trial>, relay_nodes: &[ObjectId]) -> bool {
    has_capacity_except(state, entries, relay_nodes, None)
}

fn has_capacity_except(state: &OrgRelayState, entries: &HashMap<ObjectId, Trial>, relay_nodes: &[ObjectId], skip: Option<ObjectId>) -> bool {
    let now = Instant::now();
    let mut seen = HashSet::new();
    !relay_nodes.is_empty() && relay_nodes.iter().all(|relay| {
        if !seen.insert(*relay) { return false; }
        let active = state.sessions.iter()
            .filter(|session| session.expires_at > now && session.relay_nodes().any(|node| node == *relay))
            .count();
        let trials = entries.values().filter(|trial| {
            Some(trial.id) != skip && trial.session.expires_at > now && !returned(trial)
                && (trial.session.relay_nodes().any(|id| id == *relay)
                    || trial.backbone.as_ref().is_some_and(|b| b.exit.relay.node_id == *relay))
        }).count();
        active.saturating_add(trials) < limits::MAX_SESSIONS_PER_RELAY
    })
}

pub(super) enum MintClaim {
    Inserted,
    Existing(OrgRelaySession),
    Full,
    Rejected,
}

/// Synchronous only: do not await, send or access storage while holding this
/// lock. The callback may apply local admission fences and consume a rate slot.
pub(super) fn claim_mint(
    state: &OrgRelayState,
    session: &mut OrgRelaySession,
    allow: impl FnOnce(&OrgRelaySession) -> bool,
) -> MintClaim {
    let entries = state.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = state.sessions.get(&session.pair_key).map(|entry| entry.value().clone()) {
        if existing.expires_at > Instant::now() {
            return MintClaim::Existing(existing);
        }
    }
    let nodes: Vec<_> = session.relay_nodes().collect();
    if !has_capacity(state, &entries, &nodes) {
        return MintClaim::Full;
    }
    // Allocate under the same lock as trial admissions and the final insert.
    // Trial VNIs (including still-retained expired entries) are excluded just
    // as in the existing trial allocator; allocations are scoped per relay.
    let mut allocated = Vec::with_capacity(nodes.len());
    for relay in &nodes {
        let reserved: Vec<u32> = entries.values().flat_map(|trial| {
            let mut out: Vec<u32> = trial.session.vnis_on(*relay).collect();
            if let Some(backbone) = trial.backbone.as_ref() {
                if backbone.exit.relay.node_id == *relay { out.push(backbone.exit.vni); }
            }
            out
        }).collect();
        let Some(vni) = state.alloc_vni_with_reserved(*relay, &reserved) else {
            return MintClaim::Full;
        };
        allocated.push(vni);
    }
    session.vni = allocated[0];
    for (hop, vni) in session.hops.iter_mut().zip(allocated.into_iter().skip(1)) {
        hop.vni = vni;
    }
    if !allow(session) {
        return MintClaim::Rejected;
    }
    match state.sessions.entry(session.pair_key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            if entry.get().expires_at > Instant::now() {
                return MintClaim::Existing(entry.get().clone());
            }
            entry.insert(session.clone());
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => { entry.insert(session.clone()); }
    }
    MintClaim::Inserted
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
            requester_node_id: requester,
            requester_at_exit: false,
            relay_zones: Vec::new(),
            member_zones: None,
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
                hops: Vec::new(),
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
            &state,
            &mut entries,
            &[id],
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
            admit_trial(&state, &mut entries, &[relay], &pair, tenant, requester, 1, 0, 0, || {
                allocate(1)
            })
        else {
            panic!("first admission");
        };
        assert_eq!(entries[&id].session.vni, 1);
        assert!(
            matches!(admit_trial(&state, &mut entries, &[relay], &pair, tenant, requester, 1, 0, 0, || allocate(1)), Admission::Existing(existing) if existing == id)
        );
        assert!(matches!(
            admit_trial(
                &state,
                &mut entries,
                &[relay],
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
            matches!(admit_trial(&state, &mut entries, &[relay], &pair, tenant, requester, 1, 0, 0, || allocate(1)), Admission::Existing(existing) if existing == id)
        );
        assert_eq!(state.lamport.load(Ordering::Relaxed), 1);
        assert_eq!(*state.next_vni.get(&relay).unwrap(), 2);
        let Admission::Created(next) =
            admit_trial(&state, &mut entries, &[relay], &pair, tenant, requester, 2, 0, 0, || {
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
    fn concurrent_trials_cannot_claim_the_same_last_relay_slot() {
        use std::sync::{Arc, Barrier, atomic::AtomicUsize};
        let state = Arc::new(OrgRelayState::new());
        let relay = ObjectId::new();
        for i in 0..limits::MAX_SESSIONS_PER_RELAY - 1 {
            let session = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), relay, i as u64, i as u32 + 1, i as u64 + 1).session;
            state.sessions.insert(format!("active-{i}"), session);
        }
        let barrier = Arc::new(Barrier::new(24));
        let allocations = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..24).map(|i| {
            let (state, barrier, allocations) = (Arc::clone(&state), Arc::clone(&barrier), Arc::clone(&allocations));
            std::thread::spawn(move || {
                let (tenant, requester, peer) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
                let pair = pair_key(requester, peer);
                barrier.wait();
                let mut entries = state.trials.entries.lock().unwrap();
                admit_trial(&state, &mut entries, &[relay], &pair, tenant, requester, i, 0, 0, || {
                    allocations.fetch_add(1, Ordering::Relaxed);
                    Some(fixture_trial(tenant, requester, peer, relay, i, 1000 + i as u32, 1000 + i))
                })
            })
        }).collect();
        let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(outcomes.iter().filter(|a| matches!(a, Admission::Created(_))).count(), 1);
        assert_eq!(outcomes.iter().filter(|a| matches!(a, Admission::Rejected)).count(), 23);
        assert_eq!(allocations.load(Ordering::Relaxed), 1);
        assert_eq!(state.sessions_on_relay(relay), limits::MAX_SESSIONS_PER_RELAY);
        let mut entries = state.trials.entries.lock().unwrap();
        let trial = entries.values().next().unwrap();
        let (id, pair, tenant, requester, request_id) = (trial.id, trial.session.pair_key.clone(), trial.session.tenant_id, trial.session.members[0].party.node_id, trial.request_id);
        assert!(matches!(admit_trial(&state, &mut entries, &[relay], &pair, tenant, requester, request_id, 0, 0, || panic!("idempotent retry must not allocate")), Admission::Existing(existing) if existing == id));
    }

    #[test]
    fn trial_refuses_full_exit_without_allocating_either_leg() {
        let state = OrgRelayState::new();
        let (ingress, exit) = (ObjectId::new(), ObjectId::new());
        for i in 0..limits::MAX_SESSIONS_PER_RELAY {
            let session = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), exit, i as u64, i as u32 + 1, i as u64 + 1).session;
            state.sessions.insert(format!("exit-{i}"), session);
        }
        let mut entries = HashMap::new();
        let id = ObjectId::new();
        let admission = admit_trial(&state, &mut entries, &[ingress, exit], "pair", id, id, 1, 0, 0, || panic!("full exit must not allocate"));
        assert!(matches!(admission, Admission::Rejected));
        assert!(entries.is_empty());
        assert!(state.next_vni.is_empty());
        assert!(matches!(admit_trial(&state, &mut entries, &[ingress, ingress], "pair", id, id, 1, 0, 0, || panic!("duplicate relay must not allocate")), Admission::Rejected));
    }

    #[test]
    fn concurrent_mint_and_trial_share_the_last_capacity_slot() {
        use std::sync::{Arc, Barrier, atomic::AtomicUsize};
        let state = Arc::new(OrgRelayState::new());
        let relay = ObjectId::new();
        for i in 0..limits::MAX_SESSIONS_PER_RELAY - 1 {
            let session = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), relay, i as u64, i as u32 + 1, i as u64 + 1).session;
            state.sessions.insert(format!("active-{i}"), session);
        }
        let barrier = Arc::new(Barrier::new(24));
        let allocated = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..24).map(|i| {
            let (state, barrier, allocated) = (Arc::clone(&state), Arc::clone(&barrier), Arc::clone(&allocated));
            std::thread::spawn(move || {
                let (tenant, requester, peer) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
                let mut fixture = fixture_trial(tenant, requester, peer, relay, i, 1000 + i as u32, 1000 + i);
                let pair = fixture.session.pair_key.clone();
                barrier.wait();
                if i % 2 == 0 {
                    matches!(claim_mint(&state, &mut fixture.session, |_| { allocated.fetch_add(1, Ordering::Relaxed); true }), MintClaim::Inserted)
                } else {
                    let mut entries = state.trials.entries.lock().unwrap();
                    matches!(admit_trial(&state, &mut entries, &[relay], &pair, tenant, requester, i, 0, 0, || {
                        allocated.fetch_add(1, Ordering::Relaxed); Some(fixture)
                    }), Admission::Created(_))
                }
            })
        }).collect();
        assert_eq!(threads.into_iter().map(|t| t.join().unwrap()).filter(|won| *won).count(), 1);
        assert_eq!(allocated.load(Ordering::Relaxed), 1);
        assert_eq!(state.sessions_on_relay(relay), limits::MAX_SESSIONS_PER_RELAY);
    }

    #[test]
    fn mint_pair_reuses_winner_and_full_second_leg_claims_nothing() {
        let state = OrgRelayState::new();
        let (ingress, exit) = (ObjectId::new(), ObjectId::new());
        let mut new = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), ingress, 1, 300, 301).session;
        assert!(matches!(claim_mint(&state, &mut new, |_| true), MintClaim::Inserted));
        let winner_vni = new.vni;
        let mut duplicate = new.clone();
        duplicate.vni = 301;
        duplicate.generation = 302;
        assert!(matches!(claim_mint(&state, &mut duplicate, |_| panic!("winner must be reused")), MintClaim::Existing(existing) if existing.vni == winner_vni));
        for i in 0..limits::MAX_SESSIONS_PER_RELAY {
            let session = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), exit, i as u64, i as u32 + 1, i as u64 + 1).session;
            state.sessions.insert(format!("exit-{i}"), session);
        }
        new.pair_key = "new-pair".into();
        new.hops.push(LineLeg { relay: SessionParty { node_id: exit, node_ref: NodeRef::Agent { agent_id: exit } }, relay_agent_id: exit, vni: 500, generation: 501, endpoints: vec!["exit".into()], private_endpoint: "10.0.0.2:3478".into(), requires_cross_border_approval: true, bridge_id: ObjectId::new(), bridge_secrets: ["a".into(), "b".into()] });
        assert!(matches!(claim_mint(&state, &mut new, |_| panic!("full second leg must not allocate")), MintClaim::Full));
        assert!(state.sessions.get("new-pair").is_none());
    }

    #[test]
    fn mint_vni_wrap_skips_both_live_sessions_and_trial_reservations() {
        let state = OrgRelayState::new();
        let relay = ObjectId::new();
        state.next_vni.insert(relay, limits::VNI_MAX);
        let old = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), relay, 1, 1, 1).session;
        state.sessions.insert(old.pair_key.clone(), old);
        let reserved = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), relay, 2, limits::VNI_MAX, 2);
        state.trials.entries.lock().unwrap().insert(reserved.id, reserved);
        let mut new = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), relay, 3, 999, 3).session;
        assert!(matches!(claim_mint(&state, &mut new, |_| true), MintClaim::Inserted));
        assert_eq!(new.vni, 2);
        assert_eq!(state.sessions.get(&new.pair_key).unwrap().vni, 2);
    }

    #[test]
    fn failed_second_vni_allocation_does_not_publish_partial_path() {
        let state = OrgRelayState::new();
        let (ingress, exit) = (ObjectId::new(), ObjectId::new());
        // Retained expired trials still reserve their VNIs, although they do
        // not consume live capacity. Fill the allocator's bounded probe range.
        {
            let mut entries = state.trials.entries.lock().unwrap();
            for i in 1..=(limits::MAX_SESSIONS_PER_RELAY + 4) {
                let mut trial = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), exit, i as u64, i as u32, i as u64);
                trial.session.expires_at = Instant::now() - Duration::from_secs(1);
                entries.insert(trial.id, trial);
            }
        }
        let mut new = fixture_trial(ObjectId::new(), ObjectId::new(), ObjectId::new(), ingress, 1, 700, 701).session;
        new.hops.push(LineLeg { relay: SessionParty { node_id: exit, node_ref: NodeRef::Agent { agent_id: exit } }, relay_agent_id: exit, vni: 800, generation: 801, endpoints: vec!["exit".into()], private_endpoint: "10.0.0.2:3478".into(), requires_cross_border_approval: true, bridge_id: ObjectId::new(), bridge_secrets: ["a".into(), "b".into()] });
        assert!(matches!(claim_mint(&state, &mut new, |_| panic!("allocation must fail before validation")), MintClaim::Full));
        assert!(state.sessions.get(&new.pair_key).is_none());
        assert_eq!((new.vni, new.hops[0].vni), (700, 800));
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
