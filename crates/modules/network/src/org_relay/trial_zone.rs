// SPDX-License-Identifier: AGPL-3.0-only
//! Live region checks for every relay and constrained member of a trial.
//! Zone reads are outside the trial mutex; only the exact snapshot may be
//! removed and its control revocations remain ordered by that mutex.

use super::*;

#[derive(Clone, PartialEq)]
struct RelayFingerprint {
    node_id: ObjectId,
    agent_id: ObjectId,
    node_ref: NodeRef,
    vni: u32,
    generation: u64,
    endpoints: Vec<String>,
}

#[derive(Clone, PartialEq)]
struct EdgeFingerprint {
    endpoint: String,
    requires_cross_border_approval: bool,
    bridge_id: ObjectId,
}

#[derive(Clone, PartialEq)]
struct MemberFingerprint {
    node_id: ObjectId,
    node_ref: NodeRef,
    wg_public_key: String,
}

#[derive(Clone, PartialEq)]
struct TrialZoneSnapshot {
    id: ObjectId,
    tenant_id: ObjectId,
    pair_key: String,
    request_id: u64,
    requester_node_id: ObjectId,
    requester_at_exit: bool,
    expires_at: Instant,
    bind_by: Instant,
    relays: Vec<RelayFingerprint>,
    edges: Vec<EdgeFingerprint>,
    relay_zones: Vec<BusinessZone>,
    members: [MemberFingerprint; 2],
    member_zones: Option<[BusinessZone; 2]>,
}

impl TrialZoneSnapshot {
    /// Invalid or inconsistent staged N-hop metadata must never silently skip
    /// its recheck. This is not a hop cap; the path size follows the session.
    fn shape_valid(&self) -> bool {
        if self.relays.len() < 2
            || self.relays.len() != self.relay_zones.len()
            || self.edges.len() + 1 != self.relays.len()
        {
            return false;
        }
        if let Some(member_zones) = self.member_zones
            && (member_zones[0] != self.relay_zones[0]
                || member_zones[1] != self.relay_zones[self.relay_zones.len() - 1]) {
            return false;
        }
        let mut node_ids = HashSet::new();
        let mut agent_ids = HashSet::new();
        for relay in &self.relays {
            if !node_ids.insert(relay.node_id)
                || !agent_ids.insert(relay.agent_id)
                || relay.node_ref
                    != (NodeRef::Agent {
                        agent_id: relay.agent_id,
                    })
            {
                return false;
            }
        }
        self.edges.iter().enumerate().all(|(i, edge)| {
            edge.requires_cross_border_approval == (self.relay_zones[i] != self.relay_zones[i + 1])
        })
    }

    fn involves(&self, identity: ObjectId) -> bool {
        self.relays.iter().any(|r| r.agent_id == identity)
            || self.members.iter().any(|m| match &m.node_ref {
                    NodeRef::Agent { agent_id } => *agent_id == identity,
                    NodeRef::TunnelClient { tunnel_client_id } => *tunnel_client_id == identity,
                })
    }
}

/// Capture the complete unified path identity, not only the changed relay.
fn capture(trial: &Trial) -> Option<TrialZoneSnapshot> {
    if returned(trial) {
        return None;
    }
    let s = &trial.session;
    let mut relays = vec![RelayFingerprint {
        node_id: s.relay.node_id,
        agent_id: s.relay_agent_id,
        node_ref: s.relay.node_ref.clone(),
        vni: s.vni,
        generation: s.generation,
        endpoints: s.endpoints.clone(),
    }];
    let mut edges = Vec::with_capacity(s.hops.len());
    // A single relay has no private backbone zone to recheck here.
    if s.hops.is_empty() {
        return None;
    }
    for hop in &s.hops {
        relays.push(RelayFingerprint {
            node_id: hop.relay.node_id,
            agent_id: hop.relay_agent_id,
            node_ref: hop.relay.node_ref.clone(),
            vni: hop.vni,
            generation: hop.generation,
            endpoints: hop.endpoints.clone(),
        });
        edges.push(EdgeFingerprint {
            endpoint: hop.private_endpoint.clone(),
            requires_cross_border_approval: hop.requires_cross_border_approval,
            bridge_id: hop.bridge_id,
        });
    }
    let relay_zones = trial.relay_zones.clone();
    let member_zones = trial.member_zones;
    let member = |m: &SessionMember| MemberFingerprint {
        node_id: m.party.node_id,
        node_ref: m.party.node_ref.clone(),
        wg_public_key: m.wg_public_key.clone(),
    };
    Some(TrialZoneSnapshot {
        id: trial.id,
        tenant_id: s.tenant_id,
        pair_key: s.pair_key.clone(),
        request_id: trial.request_id,
        requester_node_id: trial.requester_node_id,
        requester_at_exit: trial.requester_at_exit,
        expires_at: s.expires_at,
        bind_by: s.bind_by,
        relays,
        edges,
        relay_zones,
        members: [member(&s.members[0]), member(&s.members[1])],
        member_zones,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::org_relay) enum PartyZone {
    Known(BusinessZone),
    Unknown,
    Invalid,
    ValidUnconstrained,
}

fn zone_fits(actual: PartyZone, issued: BusinessZone) -> bool {
    match actual {
        PartyZone::Known(zone) => zone == issued,
        PartyZone::Unknown => true,
        PartyZone::Invalid => false,
        PartyZone::ValidUnconstrained => true,
    }
}

fn observe_zone(actual: PartyZone, issued: BusinessZone, fits: &mut bool, unavailable: &mut bool) {
    *unavailable |= actual == PartyZone::Unknown;
    *fits &= zone_fits(actual, issued);
}

/// A confirmed absent/live-filtered row is invalid; operational and decoding
/// errors do not prove removal and must retain the existing trial for retry.
fn trial_lookup<T>(result: roomler_ai_services::dao::base::DaoResult<T>) -> Result<Option<T>, ()> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(roomler_ai_services::dao::base::DaoError::NotFound) => Ok(None),
        Err(_) => Err(()),
    }
}

/// A hung dependency is uncertainty, not evidence of deletion.
async fn bounded_party_read<F>(read: F, timeout: Duration) -> Result<PartyZone, ()>
where
    F: std::future::Future<Output = Result<PartyZone, ()>>,
{
    tokio::time::timeout(timeout, read).await.unwrap_or(Err(()))
}

/// Unknown geography preserves an existing trial, unlike a confirmed invalid
/// identity or a known conflicting region. Storage errors remain retryable.
pub(in crate::org_relay) async fn current_party_zone(
    state: &NetworkState,
    tenant: ObjectId,
    node_id: ObjectId,
    node_ref: &NodeRef,
    require_zone: bool,
) -> Result<PartyZone, ()> {
    let identity = match node_ref {
        NodeRef::Agent { agent_id } => *agent_id,
        NodeRef::TunnelClient { tunnel_client_id } => *tunnel_client_id,
    };
    let Some(node) = trial_lookup(state
        .overlay_nodes
        .base
        .find_by_id(node_id)
        .await)? else { return Ok(PartyZone::Invalid) };
    if node.tenant_id != tenant || node.deleted_at.is_some() || &node.node_ref != node_ref {
        return Ok(PartyZone::Invalid);
    }
    let device = match node_ref {
        NodeRef::Agent { agent_id } => {
            let Some(agent) = trial_lookup(state
                .fleet
                .agents
                .find_live_in_tenant(tenant, *agent_id)
                .await)? else { return Ok(PartyZone::Invalid) };
            let Ok(device) = AuthenticatedDevice::from_agent(&agent) else {
                return Ok(PartyZone::Invalid);
            };
            device
        }
        NodeRef::TunnelClient { tunnel_client_id } => {
            let Some(client) = trial_lookup(state
                .tunnel_clients
                .find_live_in_tenant(tenant, *tunnel_client_id)
                .await)? else { return Ok(PartyZone::Invalid) };
            let Ok(device) = AuthenticatedDevice::from_tunnel_client(&client) else {
                return Ok(PartyZone::Invalid);
            };
            device
        }
    };
    let unknown_role_mode = crate::business_isolation::unknown_role_mode(state);
    if crate::business_isolation::mode(state) == crate::business_isolation::Mode::Enforce
        && (!require_zone || unknown_role_mode != crate::business_isolation::Mode::Off)
    {
        let (kind, dev_id) = crate::business_isolation::Lines::ref_identity(node_ref);
        match roomler_core::business_authority::trial_device_role_evidence(
            &state.core,
            tenant,
            kind,
            dev_id,
        )
        .await
        {
            roomler_core::business_authority::TrialServerEvidence::ObservedServer => {}
            roomler_core::business_authority::TrialServerEvidence::ObservedClient
                if require_zone => {}
            roomler_core::business_authority::TrialServerEvidence::Unknown => return Err(()),
            _ if !require_zone
                || unknown_role_mode == crate::business_isolation::Mode::Enforce =>
            {
                return Ok(PartyZone::Invalid);
            }
            _ => {
                let unknown_devices = vec![crate::business_isolation::Lines::node_label(&node)];
                crate::business_isolation::log_unknown_role_with_peers(
                    tenant,
                    "current_party_zone",
                    &unknown_devices,
                );
            }
        }
    }
    if !require_zone { return Ok(PartyZone::ValidUnconstrained); }
    let (connection, bound_at) = {
        let Some(live) = state.org_relay.live_conns.get(&identity) else {
            return Ok(PartyZone::Unknown);
        };
        (live.id.clone(), live.bound_at)
    };
    let Some(zone) =
        roomler_core::business_authority::connection_zone(&state.core, &device, &connection)
    else {
        if bound_at.elapsed() < crate::business_isolation::JOIN_ZONE_WAIT {
            return Err(());
        }
        return Ok(PartyZone::Unknown);
    };
    Ok(if addresses_agree(state, &node, zone) {
        PartyZone::Known(zone)
    } else {
        PartyZone::Invalid
    })
}

/// Return exact trials needing retry. No I/O is awaited while the trial table
/// is locked; removal compares the entire path again.
pub(in crate::org_relay) fn trial_ids_for_identity(state: &NetworkState, identity: ObjectId) -> HashSet<ObjectId> {
    let entries = state.org_relay.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
    entries.values().filter_map(capture).filter(|s| s.involves(identity)).map(|s| s.id).collect()
}

pub(in crate::org_relay) async fn recheck_relay_zones(
    state: &NetworkState,
    identity: ObjectId,
    reason: &str,
) -> HashSet<ObjectId> {
    let ids = trial_ids_for_identity(state, identity);
    let mut retry = HashSet::new();
    for id in ids {
        loop {
            match recheck_trial_zone_slice(state, id, reason).await {
                TrialZoneSlice::Complete => break,
                TrialZoneSlice::Continue => {},
                TrialZoneSlice::Retry => { retry.insert(id); break; }
            }
        }
    }
    retry
}

/// A worker continuation is valid only for this exact trial and epoch. It
/// never persists beyond the owning process or survives an epoch change.
pub(in crate::org_relay) struct TrialZoneCursor {
    snapshot: TrialZoneSnapshot,
    epoch: u64,
    next: usize,
    unavailable: bool,
}

pub(in crate::org_relay) enum TrialZoneSlice { Complete, Continue, Retry }

struct TrialZoneSliceGuard {
    owner: std::sync::Arc<OrgRelayState>,
    id: ObjectId,
}

impl Drop for TrialZoneSliceGuard {
    fn drop(&mut self) {
        self.owner.trial_zone_inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

async fn limited_party_read<F>(state: &NetworkState, read: F) -> Result<PartyZone, ()>
where
    F: std::future::Future<Output = Result<PartyZone, ()>>,
{
    let permits = state.org_relay.trial_zone_io_permits.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(4))).clone();
    let Ok(_permit) = permits.try_acquire_owned() else { return Err(()) };
    if !state.org_relay.trial_zone_io_budget.lock().unwrap_or_else(|e| e.into_inner()).admit(Instant::now()) { return Err(()); }
    bounded_party_read(read, Duration::from_secs(3)).await
}

pub(in crate::org_relay) fn prune_trial_zone_cursors(state: &NetworkState) {
    let entries = state.org_relay.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
    let mut cursors = state.org_relay.trial_zone_cursors.lock().unwrap_or_else(|e| e.into_inner());
    cursors.retain(|id, _| entries.contains_key(id));
}

/// Read at most one party per invocation. Concurrent same-trial slices are
/// coalesced as retry, and all callers share the same continuation.
/// No fixed path-length limit is imposed. The caller bounds batch size.
pub(in crate::org_relay) async fn recheck_trial_zone_slice(
    state: &NetworkState,
    id: ObjectId,
    reason: &str,
) -> TrialZoneSlice {
    {
        let mut inflight = state.org_relay.trial_zone_inflight.lock().unwrap_or_else(|e| e.into_inner());
        if !inflight.insert(id) { return TrialZoneSlice::Retry; }
    }
    let _guard = TrialZoneSliceGuard { owner: state.org_relay.clone(), id };
    let epoch = state.org_relay.eligibility_generation();
    let current = {
        let entries = state.org_relay.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(&id).and_then(capture)
    };
    let Some(current) = current else {
        state.org_relay.trial_zone_cursors.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        return TrialZoneSlice::Complete;
    };
    let previous = {
        let mut cursors = state.org_relay.trial_zone_cursors.lock().unwrap_or_else(|e| e.into_inner());
        if epoch != state.org_relay.eligibility_generation() { cursors.remove(&id); return TrialZoneSlice::Retry; }
        cursors.remove(&id)
    };
    let mut cursor = match previous {
        Some(cursor) if cursor.epoch == epoch && cursor.snapshot == current => cursor,
        Some(_) => return TrialZoneSlice::Retry,
        None => TrialZoneCursor { snapshot: current, epoch, next: 0, unavailable: false },
    };
    let snap = &cursor.snapshot;
    let mut invalid = !snap.shape_valid();
    let count = snap.relays.len() + snap.members.len();
    if !invalid && cursor.next < count {
        let (node_id, node_ref, expected) = if cursor.next < snap.relays.len() {
            let relay = &snap.relays[cursor.next];
            (relay.node_id, &relay.node_ref, Some(snap.relay_zones[cursor.next]))
        } else {
            let index = cursor.next - snap.relays.len();
            let member = &snap.members[index];
            (member.node_id, &member.node_ref, snap.member_zones.map(|zones| zones[index]))
        };
        let read = {
            #[cfg(feature = "path-planner-test-support")]
            let injected = if cursor.next == 0 {
                super::super::candidate_test_support::take_trial_zone_read_failure(id)
            } else if cursor.next == snap.relays.len() {
                super::super::candidate_test_support::take_trial_member_zone_read_failure(id)
            } else { false };
            #[cfg(not(feature = "path-planner-test-support"))]
            let injected = false;
            #[cfg(feature = "path-planner-test-support")]
            let stalled = cursor.next == 0 && super::super::candidate_test_support::take_trial_zone_read_stall(id);
            #[cfg(not(feature = "path-planner-test-support"))]
            let stalled = false;
            if injected { Err(()) } else {
                limited_party_read(state, async {
                    if stalled { std::future::pending::<Result<PartyZone, ()>>().await }
                    else { current_party_zone(state, snap.tenant_id, node_id, node_ref, expected.is_some()).await }
                }).await
            }
        };
        match read {
            Ok(actual) => {
                if let Some(zone) = expected {
                    let mut fits = true;
                    observe_zone(actual, zone, &mut fits, &mut cursor.unavailable);
                    invalid |= !fits;
                } else if actual == PartyZone::Invalid {
                    invalid = true;
                }
            }
            Err(()) => cursor.unavailable = true,
        }
        cursor.next += 1;
    }
    if epoch != state.org_relay.eligibility_generation() { return TrialZoneSlice::Retry; }
    if invalid {
        #[cfg(feature = "path-planner-test-support")]
        super::super::candidate_test_support::pause_trial_zone_revoke_if_armed(id).await;
        let event = {
            let mut entries = state.org_relay.trials.entries.lock().unwrap_or_else(|e| e.into_inner());
            if epoch != state.org_relay.eligibility_generation() {
                return TrialZoneSlice::Retry;
            }
            match entries.get(&id).and_then(capture) {
                Some(now) if now == cursor.snapshot => {
                    state.org_relay.invalidate_eligibility();
                    entries.remove(&id).map(|trial| { notify_abort(state, &trial); revoke_event(&trial, reason) })
                }
                Some(_) => return TrialZoneSlice::Retry,
                None => None,
            }
        };
        if let Some(event) = event
            && !matches!(tokio::time::timeout(Duration::from_secs(3), state.peer_relay_audit.record(event)).await, Ok(Ok(_))) {
            warn!("org-relay: trial zone retry revoke audit failed or timed out");
        }
        return TrialZoneSlice::Complete;
    }
    if cursor.next >= count {
        return if cursor.unavailable { TrialZoneSlice::Retry } else { TrialZoneSlice::Complete };
    }
    state.org_relay.trial_zone_cursors.lock().unwrap_or_else(|e| e.into_inner()).insert(id, cursor);
    TrialZoneSlice::Continue
}

/// Fixtures own the path and receive no serve or member grants from this
/// helper. Production admission and capacity are tested separately.
#[cfg(feature = "path-planner-test-support")]
pub(in crate::org_relay) fn insert_trial_fixture(
    state: &NetworkState,
    session: OrgRelaySession,
    relay_zones: Vec<BusinessZone>,
    member_zones: Option<[BusinessZone; 2]>,
) -> ObjectId {
    let id = ObjectId::new();
    let trial = Trial {
        id,
        request_id: 1,
        requester_node_id: session.members[0].party.node_id,
        requester_at_exit: false,
        relay_zones,
        member_zones,
        session,
        backbone: None,
        phase: Phase::Preparing([None, None]),
        started: Instant::now(),
        return_state: None,
        return_ids: HashSet::new(),
        cancel: watch::channel(false).0,
    };
    let mut entries = state
        .org_relay
        .trials
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert!(entries.insert(id, trial).is_none());
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use BusinessZone::{Mainland, NonMainland};

    #[test]
    fn confirmed_missing_is_invalid_but_decode_errors_are_retryable() {
        use roomler_ai_services::dao::base::DaoError;
        assert_eq!(trial_lookup::<u32>(Ok(7)), Ok(Some(7)));
        assert_eq!(trial_lookup::<u32>(Err(DaoError::NotFound)), Ok(None));
        let bad_decode = bson::from_bson::<u32>(bson::Bson::String("invalid".into())).unwrap_err();
        assert_eq!(trial_lookup::<u32>(Err(DaoError::BsonDe(bad_decode))), Err(()));
    }

    #[tokio::test]
    async fn hung_party_read_is_uncertain_not_invalid() {
        let never = std::future::pending::<Result<PartyZone, ()>>();
        assert_eq!(bounded_party_read(never, Duration::from_millis(10)).await, Err(()));
        assert_eq!(bounded_party_read(async { Ok(PartyZone::Invalid) }, Duration::from_secs(1)).await, Ok(PartyZone::Invalid));
    }

    #[test]
    fn unknown_preserves_trial_but_other_known_or_invalid_parties_still_fail() {
        assert!(zone_fits(PartyZone::Unknown, Mainland));
        assert!(zone_fits(PartyZone::Known(Mainland), Mainland));
        assert!(!zone_fits(PartyZone::Known(NonMainland), Mainland));
        assert!(!zone_fits(PartyZone::Invalid, Mainland));
        assert!(zone_fits(PartyZone::ValidUnconstrained, Mainland));
        let observations = [PartyZone::Unknown, PartyZone::Known(NonMainland)];
        assert!(!observations.into_iter().fold(true, |fits, actual| {
            fits & zone_fits(actual, Mainland)
        }));
        let (mut fits, mut unavailable) = (true, false);
        observe_zone(PartyZone::Unknown, Mainland, &mut fits, &mut unavailable);
        assert!(fits && unavailable, "unknown retains the trial and requests a retry");
        observe_zone(PartyZone::Known(NonMainland), Mainland, &mut fits, &mut unavailable);
        assert!(!fits && unavailable, "an unknown must not hide a later known violation");
    }

    fn fixture(length: usize) -> TrialZoneSnapshot {
        let relays: Vec<_> = (0..length)
            .map(|i| {
                let id = ObjectId::new();
                RelayFingerprint {
                    node_id: ObjectId::new(),
                    agent_id: id,
                    node_ref: NodeRef::Agent { agent_id: id },
                    vni: i as u32 + 100,
                    generation: i as u64 + 200,
                    endpoints: vec![format!("relay-{i}")],
                }
            })
            .collect();
        let relay_zones: Vec<_> = (0..length)
            .map(|i| if i % 2 == 0 { Mainland } else { NonMainland })
            .collect();
        let edges = (0..length.saturating_sub(1))
            .map(|i| EdgeFingerprint {
                endpoint: format!("edge-{i}"),
                requires_cross_border_approval: true,
                bridge_id: ObjectId::new(),
            })
            .collect();
        let member = || {
            let id = ObjectId::new();
            MemberFingerprint {
                node_id: ObjectId::new(),
                node_ref: NodeRef::Agent { agent_id: id },
                wg_public_key: "member-key".into(),
            }
        };
        let now = Instant::now();
        TrialZoneSnapshot {
            id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            pair_key: "pair".into(),
            request_id: 1,
            requester_node_id: ObjectId::new(),
            requester_at_exit: false,
            expires_at: now,
            bind_by: now,
            members: [member(), member()],
            member_zones: Some([relay_zones[0], relay_zones[length - 1]]),
            relays,
            edges,
            relay_zones,
        }
    }

    #[test]
    fn all_relay_zones_and_constrained_members_are_checked_without_a_fixed_hop_cap() {
        for n in [2, 3, 4, 128, 257] {
            let valid = fixture(n);
            assert!(valid.shape_valid());
            for relay in &valid.relays {
                assert!(valid.involves(relay.agent_id));
            }
            let mut missing = valid.clone();
            missing.relay_zones.pop();
            assert!(!missing.shape_valid());
            let mut missing_member = valid.clone();
            missing_member.member_zones = None;
            assert!(missing_member.shape_valid());
            let mut wrong_member = valid.clone();
            wrong_member.member_zones.as_mut().unwrap()[0] = NonMainland;
            assert!(!wrong_member.shape_valid());
            let mut crossing_removed = valid.clone();
            crossing_removed.edges[n / 2 - 1].requires_cross_border_approval = false;
            assert!(!crossing_removed.shape_valid());
            let mut repeated = valid.clone();
            repeated.relays[n - 1] = repeated.relays[0].clone();
            assert!(!repeated.shape_valid());
        }
    }

    #[test]
    fn every_intermediate_identity_endpoint_generation_and_member_is_in_the_snapshot() {
        let valid = fixture(4);
        let mut changed = valid.clone();
        changed.relays[1].generation += 1;
        assert!(valid != changed);
        let mut changed = valid.clone();
        changed.relays[2].vni += 1;
        assert!(valid != changed);
        let mut changed = valid.clone();
        changed.relays[1].endpoints.push("new".into());
        assert!(valid != changed);
        let mut changed = valid.clone();
        changed.edges[1].endpoint.push('x');
        assert!(valid != changed);
        let mut changed = valid.clone();
        changed.edges[2].bridge_id = ObjectId::new();
        assert!(valid != changed);
        let mut changed = valid.clone();
        changed.members[1].wg_public_key.push('x');
        assert!(valid != changed);
        let mut changed = valid.clone();
        changed.relay_zones[1] = Mainland;
        assert!(valid != changed);
        let tunnel_id = ObjectId::new();
        let mut tunnel = valid.clone();
        tunnel.members[1].node_ref = NodeRef::TunnelClient {
            tunnel_client_id: tunnel_id,
        };
        assert!(tunnel.involves(tunnel_id));
        tunnel.member_zones = None;
        assert!(tunnel.involves(tunnel_id));
    }
}
