// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P3c — the org-relay MINT: the server's decision to route one pair of
//! nodes through a third, tenant-owned node (`docs/fr/FR-19-peer-relays.md`
//! §1–§7).
//!
//! The server decides and pushes; it never carries a byte. A mint is three
//! frames — `rc:overlay.relay_serve` to the relay with both members' secrets,
//! `rc:overlay.relay_session` to each member with its own — and then the
//! server's involvement ends: the members bind at the relay over a path the
//! server is not on. That is why every refusal is enumerated
//! ([`PeerRelayDenyReason`]) and written to `peer_relay_audit`: the asker never
//! gets a synchronous answer, so the row IS the answer.
//!
//! ## Gates, in order
//!
//! 1. `peer_relay_mode` — `off` ⇒ nothing: no rows, no reads past the cached
//!    mode; `warn` ⇒ decide and audit exactly as `on` would, push nothing;
//!    `on` ⇒ mint.
//! 2. Both ends advertised `supports_org_relay` and joined from their PRIMARY
//!    org. An absent flag is treated as "not primary": fail closed.
//! 3. The overlay ACL grants EACH member the relay node — an affirmative
//!    capability evaluated regardless of `acl_mode` (§4, decision "taken"),
//!    read through [`try_load_acl`] so an unreadable policy set is a refusal
//!    with its own reason and never a grant.
//! 4. A relay candidate: approved (`peer_relay_policy.serve`), advertising
//!    `relay-server` on its last hello, online on this pod, joined from its
//!    primary org, with at least one public endpoint, under its session cap.
//! 5. The per-(requester, relay) mint ceiling — after the identity gates, so
//!    a refusal is attributable.
//!
//! ## What is pod-local, and why that is right
//!
//! Sessions, VNI cursors, the generation clock, join extras and probe reports
//! live in this process. Tenant affinity puts a tenant's nodes — requester,
//! peer, relay — on ONE pod (`CLAUDE.md`, S6), so the mint and every party's
//! WS share a process, exactly as `relay_pair_churn` does. After a pod restart
//! the relay's own table is the truth: its sessions run out their
//! `max_lifetime`, the members re-request, and a fresh mint issues a fresh VNI.
//! Bounding that window is what `MAX_LIFETIME_SECS` is for.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::{DateTime, oid::ObjectId};
use dashmap::DashMap;
use rand::RngCore;
use roomler_ai_remote_control::{
    models::{
        Agent, NodeRef, OverlayNode, PeerRelayAuditAction, PeerRelayAuditEvent,
        PeerRelayDenyReason, PeerRelayMode, RpcCap, peer_relay_limits as limits,
    },
    signaling::{OrgRelayCandidateWire, OrgRelayDiscoveryCursorWire, RelayMemberWire, ServerMsg},
};
use tracing::{debug, info, warn};
use tunnel_core::policy::{OverlayPeerRef, OverlaySource, evaluate_overlay};

use crate::NetworkState;
use crate::overlay::{
    NodeIdentity, PolicyLoad, current_node, pair_key, send_to_node, send_to_node_ref, try_load_acl,
    try_overlay_source_of,
};
use roomler_core::business_authority::{AuthenticatedDevice, BusinessZone};
use roomler_core::net::is_global_unicast;

mod trial;
pub use trial::{
    PathTrialReturnUpdate, PathTrialUpdate, request as path_trial_request,
    return_update as path_trial_return_update, update as path_trial_update,
};

/// How long a cached `peer_relay_mode` read stands. The org switch route
/// invalidates on write (same pod, by tenant affinity), so this only bounds
/// the window after an out-of-band edit.
const MODE_CACHE_TTL: Duration = Duration::from_secs(30);
/// Reports per (reporter, relay) kept; older ones fall off.
const PROBES_PER_KEY: usize = 8;

/// What a join tells the mint that the persisted row does not carry.
#[derive(Clone, Copy, Default)]
pub struct JoinExtras {
    /// `Some(true)` = joined from the device's primary org. `None` = the
    /// build did not say; treated as NOT primary everywhere it matters.
    pub org_primary: Option<bool>,
    /// The node's org-relay listening port, when it serves.
    pub relay_port: Option<u16>,
    /// Explicit loss after advertising a listener. Kept across further empty
    /// joins, while legacy clients which never supplied a port retain fallback.
    pub relay_withdrawn: bool,
    pub supports_org_relay_multi_candidate: bool,
    pub supports_org_relay_discovery_cursor: bool,
    pub supports_path_trial_v1: bool,
    pub supports_path_backbone_v1: bool,
    pub relay_backbone_ready: bool,
    /// MeshHarbor #21 — rides a cross-zone peer over its line alone.
    pub supports_backbone_only_v1: bool,
}

#[derive(Clone)]
pub struct SessionParty {
    pub node_id: ObjectId,
    pub node_ref: NodeRef,
}

#[derive(Clone)]
pub struct SessionMember {
    pub party: SessionParty,
    pub wg_public_key: String,
    /// base64 of the 32-byte bind secret. Kept so an idempotent re-request
    /// re-pushes the SAME session instead of minting a second one.
    pub bind_secret: String,
}

#[derive(Clone)]
pub struct OrgRelaySession {
    pub tenant_id: ObjectId,
    pub pair_key: String,
    pub vni: u32,
    pub generation: u64,
    pub relay: SessionParty,
    /// The relay's backing agent — the device an audit row is ABOUT.
    pub relay_agent_id: ObjectId,
    /// MeshHarbor `auto`: granted by the relay's central Server role and one
    /// shared business zone, not by an overlay policy. It rests on the three
    /// live connections that zone was observed on, so it ends with any of
    /// them, with the role and with `auto`; a policy edit neither grants nor
    /// revokes it.
    pub implicit: bool,
    pub members: [SessionMember; 2],
    pub endpoints: Vec<String>,
    pub expires_at: Instant,
    /// The relay drops every Bind for a session not fully bound by its bind
    /// deadline (`BIND_SECS` after the install), and later reaps it. Past
    /// this instant a re-push can no longer bind, so a fallback re-request
    /// mints a fresh session instead (`maybe_mint_fallback`).
    pub bind_by: Instant,
    /// MeshHarbor #21 — a cross-border line: `relay` serves `members[0]` in
    /// its zone, this leg's relay serves `members[1]` in the other, and
    /// `relay`'s bridge joins the two over the approved private line.
    pub line: Option<LineLeg>,
}

/// The exit half of a cross-border line session (`mint_line`).
#[derive(Clone)]
pub struct LineLeg {
    pub relay: SessionParty,
    pub relay_agent_id: ObjectId,
    pub vni: u32,
    pub generation: u64,
    /// The exit relay's public endpoints, for `members[1]`.
    pub endpoints: Vec<String>,
    /// The exit relay's address on the private line (the approved edge's).
    pub private_endpoint: String,
    /// Keys the ingress relay's bridge (`rc:overlay.relay_bridge_*`).
    pub bridge_id: ObjectId,
    /// The bridge's bind secrets: `members[1]`'s slot on the ingress session
    /// and `members[0]`'s on the exit session. No member ever holds them.
    pub bridge_secrets: [String; 2],
}

/// What one member binds: its relay, VNI and endpoints.
struct MemberLeg<'a> {
    relay_node_id: ObjectId,
    vni: u32,
    generation: u64,
    endpoints: &'a [String],
}

impl OrgRelaySession {
    fn member_index(&self, node_id: ObjectId) -> Option<usize> {
        self.members.iter().position(|m| m.party.node_id == node_id)
    }
    fn involves(&self, node_id: ObjectId) -> bool {
        self.relay.node_id == node_id
            || self.member_index(node_id).is_some()
            || self.line.as_ref().is_some_and(|l| l.relay.node_id == node_id)
    }
    fn involves_agent(&self, agent_id: ObjectId) -> bool {
        let is = |n: &NodeRef| matches!(n, NodeRef::Agent { agent_id: id } if *id == agent_id);
        is(&self.relay.node_ref)
            || self.members.iter().any(|m| is(&m.party.node_ref))
            || self.line.as_ref().is_some_and(|l| is(&l.relay.node_ref))
    }
    /// Whether `agent_id` relays this session (either leg of a line).
    fn relayed_by_agent(&self, agent_id: ObjectId) -> bool {
        self.relay_agent_id == agent_id
            || self.line.as_ref().is_some_and(|l| l.relay_agent_id == agent_id)
    }
    /// The relay nodes, one or (a line) two.
    fn relay_nodes(&self) -> impl Iterator<Item = ObjectId> + '_ {
        std::iter::once(self.relay.node_id).chain(self.line.as_ref().map(|l| l.relay.node_id))
    }
    /// The VNIs held on `relay_node_id`.
    fn vnis_on(&self, relay_node_id: ObjectId) -> impl Iterator<Item = u32> + '_ {
        (self.relay.node_id == relay_node_id)
            .then_some(self.vni)
            .into_iter()
            .chain(
                self.line
                    .as_ref()
                    .filter(|l| l.relay.node_id == relay_node_id)
                    .map(|l| l.vni),
            )
    }
    /// What member `i` binds: on a line, `members[1]` binds the exit leg.
    fn member_leg(&self, i: usize) -> MemberLeg<'_> {
        match self.line.as_ref() {
            Some(l) if i == 1 => MemberLeg {
                relay_node_id: l.relay.node_id,
                vni: l.vni,
                generation: l.generation,
                endpoints: &l.endpoints,
            },
            _ => MemberLeg {
                relay_node_id: self.relay.node_id,
                vni: self.vni,
                generation: self.generation,
                endpoints: &self.endpoints,
            },
        }
    }
}

#[derive(Clone)]
pub struct ProbeRecord {
    pub endpoint: String,
    pub reachable: bool,
    pub rtt_ms: Option<u32>,
    pub at: Instant,
}

/// One member's measured standing toward one relay, for ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeVerdict {
    /// A fresh report says at least one endpoint answered.
    Reachable(u32),
    /// Every fresh report says no.
    Unreachable,
    /// Never measured, or only stale reports.
    Unknown,
}

#[derive(Default)]
pub struct OrgRelayState {
    sessions: DashMap<String, OrgRelaySession>,
    next_vni: DashMap<ObjectId, u32>,
    /// The server-wide logical clock the reference design calls `LamportID`:
    /// monotonic across every (pair, relay), so it is monotonic per one too.
    lamport: AtomicU64,
    join_extras: DashMap<ObjectId, JoinExtras>,
    probes: DashMap<(ObjectId, ObjectId), Vec<ProbeRecord>>,
    mode_cache: DashMap<ObjectId, (PeerRelayMode, Instant)>,
    /// MeshHarbor `auto` and #21: each agent's (`hello` binds, `closing`
    /// unbinds) and each tunnel client's (its WS binds and unbinds) live
    /// connection on this pod, whose opening observation is its zone
    /// evidence. Keyed by the device's ObjectId, unique across both kinds.
    live_conns: DashMap<ObjectId, String>,
    trials: trial::PathTrials,
    /// (pair key, relay node) a member measured lossy, until when: the
    /// planner skips that relay for that pair (see [`Self::mark_lossy`]).
    lossy: DashMap<(String, ObjectId), Instant>,
    // Conservative generation for membership/policy decisions spanning async IO.
    eligibility_epoch: AtomicU64,
}

impl OrgRelayState {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn invalidate_eligibility(&self) {
        self.eligibility_epoch.fetch_add(1, Ordering::AcqRel);
    }
    fn eligibility_generation(&self) -> u64 {
        self.eligibility_epoch.load(Ordering::Acquire)
    }

    /// Bind `agent_id`'s live connection; returns the one it displaced.
    pub fn bind_live_conn(&self, agent_id: ObjectId, conn_id: &str) -> Option<String> {
        self.invalidate_eligibility();
        self.live_conns
            .insert(agent_id, conn_id.to_owned())
            .filter(|old| old != conn_id)
    }

    /// Unbind only while the binding still names `conn_id`: a displaced
    /// connection's late teardown must not unbind its replacement.
    pub fn unbind_live_conn(&self, agent_id: ObjectId, conn_id: &str) -> bool {
        let gone = self
            .live_conns
            .remove_if(&agent_id, |_, bound| bound == conn_id)
            .is_some();
        if gone {
            self.invalidate_eligibility();
        }
        gone
    }

    fn live_conn(&self, agent_id: ObjectId) -> Option<String> {
        self.live_conns.get(&agent_id).map(|c| c.value().clone())
    }

    /// Record what a join said beyond the row. Overwrites on every rejoin so a
    /// build that stops advertising a port, or an org that stops being
    /// primary, is not remembered as it was.
    pub fn note_join(&self, node_id: ObjectId, mut extras: JoinExtras) -> bool {
        self.invalidate_eligibility();
        let mut entry = self.join_extras.entry(node_id).or_default();
        let previous = *entry;
        let changed_listener =
            previous.relay_port.is_some() && previous.relay_port != extras.relay_port;
        extras.relay_withdrawn = extras.relay_port.is_none()
            && (previous.relay_port.is_some() || previous.relay_withdrawn);
        *entry = extras;
        changed_listener
    }

    pub fn forget_node(&self, node_id: ObjectId) {
        self.invalidate_eligibility();
        self.join_extras.remove(&node_id);
        self.probes.retain(|(reporter, _), _| *reporter != node_id);
    }

    pub fn join_extras(&self, node_id: ObjectId) -> JoinExtras {
        self.join_extras
            .get(&node_id)
            .map(|e| *e)
            .unwrap_or_default()
    }

    pub fn invalidate_mode(&self, tenant_id: ObjectId) {
        self.invalidate_eligibility();
        self.mode_cache.remove(&tenant_id);
    }

    /// The live session for a pair, if any. Expired sessions are reaped on
    /// the way out so a stale entry can never be re-pushed.
    pub fn active_session(&self, pair_key: &str) -> Option<OrgRelaySession> {
        let now = Instant::now();
        let s = self.sessions.get(pair_key).map(|e| e.value().clone())?;
        if s.expires_at <= now {
            self.sessions.remove(pair_key);
            return None;
        }
        Some(s)
    }

    /// Test hook: as if `pair_key`'s session had outlived its bind window.
    #[doc(hidden)]
    pub fn age_past_bind_window(&self, pair_key: &str) {
        if let Some(mut s) = self.sessions.get_mut(pair_key) {
            s.bind_by = Instant::now() - Duration::from_secs(1);
        }
    }

    /// A member measured `relay_node_id` lossy for the pair `pair_key`: the
    /// planner skips that relay for that pair until `until`, so the pair
    /// moves to another relay in its zone, and to DERP only when none is
    /// left. Other pairs keep the relay.
    pub fn mark_lossy(&self, pair_key: &str, relay_node_id: ObjectId, until: Instant) {
        self.lossy
            .insert((pair_key.to_string(), relay_node_id), until);
    }

    pub fn is_lossy(&self, pair_key: &str, relay_node_id: ObjectId, now: Instant) -> bool {
        let key = (pair_key.to_string(), relay_node_id);
        match self.lossy.get(&key).map(|u| *u) {
            Some(until) if until > now => true,
            Some(_) => {
                self.lossy.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn sessions_on_relay(&self, relay_node_id: ObjectId) -> usize {
        let now = Instant::now();
        self.sessions
            .iter()
            .filter(|e| e.relay_nodes().any(|r| r == relay_node_id) && e.expires_at > now)
            .count()
            + self.trials.sessions_on_relay(relay_node_id, now)
    }

    /// Next free 24-bit VNI on a relay — globally unique PER RELAY NODE, never
    /// per tenant (§2: the Geneve header has no tenant field, so a shared
    /// node's demux key must be unambiguous across tenants). Skips 0 and the
    /// STUN magic cookie (which the relay never mints, so a STUN packet can
    /// never alias a session), and any VNI a live session on that relay
    /// still holds.
    fn alloc_vni(&self, relay_node_id: ObjectId) -> Option<u32> {
        let reserved = self.trials.vnis_on_relay(relay_node_id);
        self.alloc_vni_with_reserved(relay_node_id, &reserved)
    }

    fn alloc_vni_with_reserved(&self, relay_node_id: ObjectId, reserved: &[u32]) -> Option<u32> {
        let mut in_use: Vec<u32> = self
            .sessions
            .iter()
            .flat_map(|e| e.vnis_on(relay_node_id).collect::<Vec<_>>())
            .collect();
        in_use.extend_from_slice(reserved);
        let mut cursor = self.next_vni.entry(relay_node_id).or_insert(1);
        // At most `MAX_SESSIONS_PER_RELAY` live VNIs plus the two reserved
        // values can stand in the way; bound the walk accordingly.
        for _ in 0..(limits::MAX_SESSIONS_PER_RELAY + 4) {
            let candidate = *cursor;
            *cursor = if candidate >= limits::VNI_MAX {
                1
            } else {
                candidate + 1
            };
            if candidate == 0 || candidate == limits::STUN_COOKIE_VNI {
                continue;
            }
            if in_use.contains(&candidate) {
                continue;
            }
            return Some(candidate);
        }
        None
    }

    /// Accept a reachability report ONLY about a relay + endpoint the server
    /// minted for that node: a device cannot inject claims about arbitrary
    /// targets, and the server never asked it to probe anything else.
    pub fn record_probe(
        &self,
        reporter: ObjectId,
        relay_node_id: ObjectId,
        endpoint: String,
        reachable: bool,
        rtt_ms: Option<u32>,
    ) -> bool {
        let minted_for_it = self.sessions.iter().any(|e| {
            e.member_index(reporter).is_some_and(|i| {
                let leg = e.member_leg(i);
                leg.relay_node_id == relay_node_id && leg.endpoints.contains(&endpoint)
            })
        });
        if !minted_for_it {
            return false;
        }
        let mut v = self.probes.entry((reporter, relay_node_id)).or_default();
        v.push(ProbeRecord {
            endpoint,
            reachable,
            rtt_ms,
            at: Instant::now(),
        });
        if v.len() > PROBES_PER_KEY {
            let excess = v.len() - PROBES_PER_KEY;
            v.drain(..excess);
        }
        true
    }

    fn probe_verdict(
        &self,
        reporter: ObjectId,
        relay_node_id: ObjectId,
        now: Instant,
    ) -> ProbeVerdict {
        let Some(v) = self.probes.get(&(reporter, relay_node_id)) else {
            return ProbeVerdict::Unknown;
        };
        let ttl = Duration::from_secs(limits::PROBE_TTL_SECS);
        let fresh: Vec<&ProbeRecord> = v
            .iter()
            .filter(|p| now.duration_since(p.at) < ttl)
            .collect();
        if fresh.is_empty() {
            return ProbeVerdict::Unknown;
        }
        let best = fresh
            .iter()
            .filter(|p| p.reachable)
            .map(|p| p.rtt_ms.unwrap_or(0))
            .min();
        match best {
            Some(rtt) => ProbeVerdict::Reachable(rtt),
            None => ProbeVerdict::Unreachable,
        }
    }
}

/// The tenant's peer-relay posture, cached briefly. A read failure is `Off`:
/// the wrong answer here costs one un-minted relay session (the pair stays
/// on TURN/DERP), while the wrong answer in the other direction would mint
/// against a posture nobody set.
pub async fn peer_relay_mode(state: &NetworkState, tenant_id: ObjectId) -> PeerRelayMode {
    let now = Instant::now();
    if let Some(e) = state.org_relay.mode_cache.get(&tenant_id)
        && now.duration_since(e.1) < MODE_CACHE_TTL
    {
        return e.0;
    }
    let mode = match state.overlay_networks.get_or_create(tenant_id).await {
        Ok(n) => n.peer_relay_mode,
        Err(e) => {
            warn!(%tenant_id, %e, "org-relay: network read failed; treating peer_relay_mode as off");
            return PeerRelayMode::Off;
        }
    };
    state.org_relay.mode_cache.insert(tenant_id, (mode, now));
    mode
}

/// A relay chosen for a pair, with everything the frames need.
#[derive(Clone)]
struct Plan {
    relay: OverlayNode,
    relay_agent_id: ObjectId,
    endpoints: Vec<String>,
    backbone_edges: Vec<roomler_ai_remote_control::models::PeerRelayBackboneEdge>,
    /// Granted by role and zone (`auto`), not by an overlay policy.
    implicit: bool,
}

/// The relay's dialable `ip:port`s: its own public addresses (srflx first —
/// the mapping its NAT actually exposes — then a public NIC, then the relay
/// trickle bucket), each paired with the relay-server port, then the admin's
/// static endpoints. `Err` = a static endpoint failed the SSRF rule, which
/// refuses the mint outright rather than quietly dropping the entry: the
/// admin wrote it, and a mint that silently ignores policy is worse than one
/// that says why it did not happen.
fn relay_endpoints(
    node: &OverlayNode,
    port: u16,
    static_endpoints: &[String],
) -> Result<Vec<String>, ()> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    for cand in node
        .srflx_endpoints
        .iter()
        .chain(node.lan_endpoints.iter())
        .chain(node.endpoints.iter())
    {
        if let Ok(sa) = cand.parse::<SocketAddr>()
            && is_global_unicast(&sa.ip())
        {
            push(SocketAddr::new(sa.ip(), port).to_string());
        }
    }
    for s in static_endpoints {
        let sa: SocketAddr = s.parse().map_err(|_| ())?;
        if !is_global_unicast(&sa.ip()) {
            return Err(());
        }
        push(sa.to_string());
    }
    Ok(out)
}

/// Is `s` a public `ip:port` literal? The approval route's validator — a
/// name is refused too, because a name can resolve to something else by the
/// time the mint re-checks it.
pub fn valid_static_endpoint(s: &str) -> bool {
    s.parse::<SocketAddr>()
        .map(|sa| sa.port() != 0 && is_global_unicast(&sa.ip()))
        .unwrap_or(false)
}

/// The business zone `agent`'s live connection on this pod was observed in
/// when it opened. `None` (no live connection here, or no zone) refuses.
pub(crate) fn agent_zone(state: &NetworkState, agent: &Agent) -> Option<BusinessZone> {
    let conn = state.org_relay.live_conn(agent.id?)?;
    let device = AuthenticatedDevice::from_agent(agent).ok()?;
    roomler_core::business_authority::connection_zone(&state.core, &device, &conn)
}

/// The business zone of the device behind an overlay node: its live
/// connection's opening observation on this pod. `None` (no live connection
/// here, or no zone) refuses wherever a zone gates anything — the auto relay
/// gate here, and the #21 isolation in netmap shaping.
pub(crate) async fn node_zone(state: &NetworkState, node: &OverlayNode) -> Option<BusinessZone> {
    party_zone(state, node.tenant_id, &node.node_ref).await
}

/// [`node_zone`] for a session party, known by its tenant and reference.
async fn party_zone(
    state: &NetworkState,
    tenant_id: ObjectId,
    node_ref: &NodeRef,
) -> Option<BusinessZone> {
    match node_ref {
        NodeRef::Agent { agent_id } => {
            let agent = state
                .fleet
                .agents
                .find_live_in_tenant(tenant_id, *agent_id)
                .await
                .ok()?;
            agent_zone(state, &agent)
        }
        NodeRef::TunnelClient { tunnel_client_id } => {
            let client = state
                .tunnel_clients
                .find_live_in_tenant(tenant_id, *tunnel_client_id)
                .await
                .ok()?;
            let conn = state.org_relay.live_conn(*tunnel_client_id)?;
            let device = AuthenticatedDevice::from_tunnel_client(&client).ok()?;
            roomler_core::business_authority::connection_zone(&state.core, &device, &conn)
        }
    }
}

/// Which zone a plan's relays must be in under #21 isolation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ZoneScope {
    /// The zone the pair shares (the rule).
    Pair,
    /// One side of a cross-border line: relays in this zone, explicit
    /// grants only (an implicit `auto` grant rests on one shared zone).
    Side(BusinessZone),
}

/// Shared candidate authorization (gates 2–4). Discovery only returns metadata;
/// the mint caller additionally applies gate 5 and audits its verdict.
async fn plan_mint(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Result<Plan, PeerRelayDenyReason> {
    plan_mint_candidates(state, requester, peer)
        .await?
        .into_iter()
        .next()
        .ok_or(PeerRelayDenyReason::NoRelay)
}

async fn plan_mint_candidates(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Result<Vec<Plan>, PeerRelayDenyReason> {
    plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Pair).await
}

/// The relay the planner would mint the pair on now, if any; a relay marked
/// lossy for the pair is not among the candidates.
pub(crate) async fn next_relay(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Option<ObjectId> {
    plan_mint_candidates(state, requester, peer)
        .await
        .ok()?
        .into_iter()
        .next()?
        .relay
        .id
}

async fn plan_mint_candidates_reusing(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    reuse: Option<&OrgRelaySession>,
    scope: ZoneScope,
) -> Result<Vec<Plan>, PeerRelayDenyReason> {
    use PeerRelayDenyReason as D;
    let tenant_id = requester.tenant_id;
    if peer.tenant_id != tenant_id {
        return Err(D::CrossTenant);
    }
    if !requester.supports_org_relay {
        return Err(D::RequesterUnsupported);
    }
    if !peer.supports_org_relay {
        return Err(D::PeerUnsupported);
    }
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return Err(D::RequesterUnsupported);
    };
    if state.org_relay.join_extras(req_id).org_primary != Some(true)
        || state.org_relay.join_extras(peer_id).org_primary != Some(true)
    {
        return Err(D::SecondaryOrg);
    }
    // #21 — the pair must share one zone, and every candidate relay must be
    // in it (below): no grant, explicit or implicit, carries a pair across
    // the mainland line. Under `warn` both are only logged.
    use crate::business_isolation::{self as iso, Mode};
    let iso_mode = iso::mode(state);
    let iso_zone = match (iso_mode, scope) {
        (Mode::Off, _) => None,
        (_, ZoneScope::Side(z)) => Some(z),
        _ => iso::pair_zone(state, iso_mode, requester, peer).await,
    };
    if iso_mode != Mode::Off && iso_zone.is_none() {
        if iso_mode == Mode::Enforce {
            warn!(%tenant_id, requester = %req_id, peer = %peer_id, "org-relay: pair not in one business zone; refusing");
            return Err(D::ZoneDenied);
        }
        info!(%tenant_id, requester = %req_id, peer = %peer_id, "org-relay [isolation warn]: would refuse a pair not in one business zone");
    }

    // Gate 2's inputs — every read fails CLOSED, each with the reason that
    // distinguishes "the rules said no" from "the rules could not be read".
    let acl = try_load_acl(state, tenant_id, PolicyLoad::Always)
        .await
        .map_err(|e| {
            warn!(%tenant_id, %e, "org-relay: policies unreadable; refusing");
            D::PolicyUnreadable
        })?;
    let req_src = try_overlay_source_of(state, requester).await.map_err(|e| {
        warn!(%tenant_id, node = %req_id, %e, "org-relay: requester identity unreadable; refusing");
        D::PolicyUnreadable
    })?;
    let peer_src = try_overlay_source_of(state, peer).await.map_err(|e| {
        warn!(%tenant_id, node = %peer_id, %e, "org-relay: peer identity unreadable; refusing");
        D::PolicyUnreadable
    })?;
    let mut relays = state
        .fleet
        .agents
        .list_relay_approved(tenant_id)
        .await
        .map_err(|e| {
            warn!(%tenant_id, %e, "org-relay: approved-relay list unreadable; refusing");
            D::PolicyUnreadable
        })?;
    // MeshHarbor `auto`: a device whose central Server role is current is a
    // candidate without gate 3, and stands in for gate 2 only inside one
    // business zone (below). An unreadable role list can only withhold an
    // implicit grant, never widen one.
    let mut servers: Vec<ObjectId> = Vec::new();
    let mut servers_unreadable = false;
    if peer_relay_mode(state, tenant_id).await == PeerRelayMode::Auto {
        match roomler_core::business_authority::current_server_agents(&state.core, tenant_id)
            .await
        {
            Ok(agents) => {
                for agent in agents {
                    let Some(id) = agent.id else { continue };
                    servers.push(id);
                    if !relays.iter().any(|r| r.id == Some(id)) {
                        relays.push(agent);
                    }
                }
            }
            Err(e) => {
                warn!(%tenant_id, %e, "org-relay: server roles unreadable; no implicit grant");
                servers_unreadable = true;
            }
        }
    }
    // The zone both members share, read once and only when an implicit grant
    // is in play: `Some(None)` = they share none.
    let mut member_zone: Option<Option<BusinessZone>> = None;

    let now = Instant::now();
    let pk = pair_key(req_id, peer_id);
    let mut candidates: Vec<Plan> = Vec::new();
    let mut acl_denied = 0usize;
    let mut zone_denied = 0usize;
    let mut bad_static = false;
    for agent in relays {
        let Some(agent_id) = agent.id else { continue };
        // Gate 4 as the device last advertised it, and liveness on this pod.
        if !agent.capabilities.has_rpc(RpcCap::RelayServer)
            || !state.fleet.rc_hub.is_agent_online(agent_id)
        {
            continue;
        }
        let Ok(Some(node)) = state
            .overlay_nodes
            .find_live_by_tenant_and_machine(tenant_id, &agent.machine_id)
            .await
        else {
            continue;
        };
        let Some(relay_id) = node.id else { continue };
        if relay_id == req_id || relay_id == peer_id {
            continue;
        }
        // A relay a member measured lossy for this pair sits out its pin.
        if state.org_relay.is_lossy(&pk, relay_id, now) {
            continue;
        }
        let extras = state.org_relay.join_extras(relay_id);
        // Serving is primary-only: a UDP listener is host-global.
        if extras.org_primary != Some(true) || extras.relay_withdrawn {
            continue;
        }
        if state.org_relay.sessions_on_relay(relay_id) >= limits::MAX_SESSIONS_PER_RELAY
            && !reuse.is_some_and(|session| session.relay.node_id == relay_id)
        {
            continue;
        }
        // Gate 2 — BOTH members must be granted this relay; each binds to it.
        // FR-97 P0b — granted from the routes the relay OFFERS.
        let relay_routes = node.effective_routes();
        let relay_ref = OverlayPeerRef {
            node_id: relay_id,
            overlay_ip: &node.overlay_ip,
            approved_routes: &relay_routes,
        };
        let granted = agent.peer_relay_policy.serve
            && evaluate_overlay(&acl.policies, &req_src, relay_ref).visible
            && evaluate_overlay(&acl.policies, &peer_src, relay_ref).visible;
        // `auto`: requester, peer and relay all observed in ONE zone on their
        // live connections; unknown anywhere refuses (hard isolation).
        let implicit = !granted && scope == ZoneScope::Pair && servers.contains(&agent_id) && {
            if member_zone.is_none() {
                let a = node_zone(state, requester).await;
                let b = node_zone(state, peer).await;
                member_zone = Some(a.filter(|_| a == b));
            }
            let relay_zone = agent_zone(state, &agent);
            debug!(%tenant_id, relay = %relay_id, ?relay_zone, ?member_zone, "org-relay: implicit grant zones");
            relay_zone.is_some() && member_zone == Some(relay_zone)
        };
        if !granted && !implicit {
            if agent.peer_relay_policy.serve {
                acl_denied += 1;
            } else {
                zone_denied += 1;
            }
            continue;
        }
        if iso_mode != Mode::Off && (iso_zone.is_none() || agent_zone(state, &agent) != iso_zone) {
            if iso_mode == Mode::Enforce {
                zone_denied += 1;
                continue;
            }
            info!(%tenant_id, relay = %relay_id, "org-relay [isolation warn]: would skip a relay outside the pair's zone");
        }
        let port = extras.relay_port.unwrap_or(limits::DEFAULT_RELAY_PORT);
        let endpoints =
            match relay_endpoints(&node, port, &agent.peer_relay_policy.static_endpoints) {
                Ok(e) => e,
                Err(()) => {
                    bad_static = true;
                    continue;
                }
            };
        if endpoints.is_empty() {
            debug!(%tenant_id, relay = %relay_id, "org-relay: candidate has no public endpoint; skipped");
            continue;
        }
        candidates.push(Plan {
            relay: node,
            relay_agent_id: agent_id,
            endpoints,
            backbone_edges: agent.peer_relay_policy.approved_backbone_edges,
            implicit,
        });
    }
    if candidates.is_empty() {
        return Err(if bad_static {
            D::NonRoutableEndpoint
        } else if acl_denied > 0 {
            D::AclDenied
        } else if zone_denied > 0 {
            D::ZoneDenied
        } else if servers_unreadable {
            D::PolicyUnreadable
        } else {
            D::NoRelay
        });
    }

    // Rank: a relay BOTH members have measured reachable wins, by RTT; never
    // measured next; one a member measured unreachable last — last, not
    // excluded, because a stale negative must not starve the only relay.
    candidates.sort_by_key(|c| {
        let relay_id = c.relay.id.unwrap_or_default();
        let a = state.org_relay.probe_verdict(req_id, relay_id, now);
        let b = state.org_relay.probe_verdict(peer_id, relay_id, now);
        let class = match (a, b) {
            (ProbeVerdict::Unreachable, _) | (_, ProbeVerdict::Unreachable) => 2u8,
            (ProbeVerdict::Reachable(_), ProbeVerdict::Reachable(_)) => 0,
            _ => 1,
        };
        let rtt = |v: ProbeVerdict| match v {
            ProbeVerdict::Reachable(r) => r,
            _ => 0,
        };
        (
            class,
            rtt(a) + rtt(b),
            state.org_relay.sessions_on_relay(relay_id),
        )
    });
    Ok(candidates)
}

pub fn revoke_backbone_node_sync(
    state: &NetworkState,
    tenant: ObjectId,
    node: ObjectId,
    member_withdrawn: bool,
    ingress_withdrawn: bool,
) -> Vec<PeerRelayAuditEvent> {
    trial::revoke_backbone_node(state, tenant, node, member_withdrawn, ingress_withdrawn)
}

/// #21 — `node` stopped riding line-only peers, or (as an ingress relay)
/// stopped being backbone-ready: the lines it takes part in end.
pub fn revoke_line_node_sync(
    state: &NetworkState,
    tenant: ObjectId,
    node: ObjectId,
) -> Vec<PeerRelayAuditEvent> {
    revoke_matching_sync(state, "backbone_capability_withdrawn", |s| {
        s.tenant_id == tenant && s.line.is_some() && s.involves(node)
    })
}

/// `source`'s approved edges changed: the two-leg trials and the lines over
/// an edge that is gone (or no longer `cross_border`) end.
pub fn revoke_removed_backbone_edges_sync(
    state: &NetworkState,
    tenant: ObjectId,
    source: ObjectId,
    approved: &[roomler_ai_remote_control::models::PeerRelayBackboneEdge],
) -> Vec<PeerRelayAuditEvent> {
    let mut events = trial::revoke_removed_backbone_edges(state, tenant, source, approved);
    events.extend(revoke_matching_sync(state, "backbone_edge_revoked", |s| {
        s.tenant_id == tenant
            && s.relay_agent_id == source
            && s.line.as_ref().is_some_and(|l| {
                !approved.iter().any(|e| {
                    e.cross_border
                        && e.endpoint == l.private_endpoint
                        && ObjectId::parse_str(&e.relay_agent_id).ok() == Some(l.relay_agent_id)
                })
            })
    }));
    events
}

struct BackbonePlan {
    ingress: Plan,
    exit: Plan,
    private_endpoint: String,
}

/// The audit `reason` of a mint planned over a cross-border line (#21).
pub const CROSS_BORDER_REASON: &str = "cross_border_line";

async fn plan_backbone(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    ingress_id: ObjectId,
    exit_id: ObjectId,
) -> Result<BackbonePlan, PeerRelayDenyReason> {
    use PeerRelayDenyReason as D;
    let (Some(a), Some(b)) = (requester.id, peer.id) else {
        return Err(D::RequesterUnsupported);
    };
    if ingress_id == exit_id
        || !state.org_relay.join_extras(a).supports_path_backbone_v1
        || !state.org_relay.join_extras(b).supports_path_backbone_v1
        || !state.org_relay.join_extras(ingress_id).relay_backbone_ready
    {
        return Err(D::RequesterUnsupported);
    }
    let network = state
        .overlay_networks
        .get_or_create(requester.tenant_id)
        .await
        .map_err(|_| D::PolicyUnreadable)?;
    if network.mtu > limits::BACKBONE_MAX_OVERLAY_MTU {
        return Err(D::RequesterUnsupported);
    }
    // #21: a pair in two zones may ride only a cross-border line, each relay
    // in its own member's zone.
    let line = cross_border_zones(state, requester, peer).await;
    let (ingress, exit) = match line {
        None => {
            let mut plans = plan_mint_candidates(state, requester, peer).await?;
            let Some(exit_index) = plans.iter().position(|p| p.relay.id == Some(exit_id)) else {
                return Err(D::NoRelay);
            };
            let exit = plans.remove(exit_index);
            let Some(ingress_index) = plans.iter().position(|p| p.relay.id == Some(ingress_id))
            else {
                return Err(D::NoRelay);
            };
            (plans.remove(ingress_index), exit)
        }
        Some((za, zb)) => {
            let pick = |plans: Vec<Plan>, id: ObjectId| plans.into_iter().find(|p| p.relay.id == Some(id));
            let ingress = pick(
                plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(za)).await?,
                ingress_id,
            )
            .ok_or(D::ZoneDenied)?;
            let exit = pick(
                plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(zb)).await?,
                exit_id,
            )
            .ok_or(D::ZoneDenied)?;
            (ingress, exit)
        }
    };
    let endpoint = ingress
        .backbone_edges
        .iter()
        .take(8)
        .find(|edge| {
            ObjectId::parse_str(&edge.relay_agent_id).ok() == Some(exit.relay_agent_id)
                && crate::routes::peer_relay::valid_backbone_endpoint(&edge.endpoint)
                && (line.is_none() || edge.cross_border)
        })
        .map(|e| e.endpoint.clone())
        .ok_or(if line.is_some() { D::ZoneDenied } else { D::NoRelay })?;
    if !crate::routes::peer_relay::backbone_endpoint_outside_overlay(&endpoint, &network.cidr) {
        return Err(D::NonRoutableEndpoint);
    }
    if line.is_some() {
        // #21 rule 5: every crossing is audited, on top of the trial's own rows.
        info!(tenant_id = %requester.tenant_id, requester = %a, peer = %b, ingress = %ingress_id,
            exit = %exit_id, "org-relay: a cross-border pair rides its approved line");
        let event = PeerRelayAuditEvent {
            id: None,
            tenant_id: requester.tenant_id,
            action: PeerRelayAuditAction::Mint,
            agent_id: Some(ingress.relay_agent_id),
            user_id: None,
            requester_node_id: Some(a),
            peer_node_id: Some(b),
            relay_node_id: Some(ingress_id),
            serve: None,
            vni: None,
            warn_only: false,
            at: DateTime::now(),
            denied: None,
            reason: Some(CROSS_BORDER_REASON.into()),
        };
        if let Err(e) = state.peer_relay_audit.record(event).await {
            warn!(%e, "org-relay: cross-border audit write failed");
        }
    }
    Ok(BackbonePlan {
        ingress,
        exit,
        private_endpoint: endpoint,
    })
}

/// The zone pairs the tenant's approved cross-border lines connect: an
/// approved relay with a `cross_border` edge to another approved relay, both
/// live here with a known zone, and the zones different.
pub(crate) async fn cross_border_lines(
    state: &NetworkState,
    tenant_id: ObjectId,
) -> Vec<(BusinessZone, BusinessZone)> {
    let Ok(relays) = state.fleet.agents.list_relay_approved(tenant_id).await else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for r in &relays {
        let mut edges = r
            .peer_relay_policy
            .approved_backbone_edges
            .iter()
            .filter(|e| e.cross_border)
            .peekable();
        if edges.peek().is_none() {
            continue;
        }
        let Some(from) = agent_zone(state, r) else { continue };
        for e in edges {
            let Ok(t) = ObjectId::parse_str(&e.relay_agent_id) else { continue };
            let Some(to) = relays.iter().find(|x| x.id == Some(t)).and_then(|x| agent_zone(state, x))
            else {
                continue;
            };
            if from != to && !out.contains(&(from, to)) {
                out.push((from, to));
            }
        }
    }
    out
}

/// The two zones of a pair that only a cross-border line may carry: both
/// known, different, and the rule enforced. `None` means the ordinary rule
/// applies (one zone, or `warn`/`off`, which refuse nothing).
async fn cross_border_zones(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
) -> Option<(BusinessZone, BusinessZone)> {
    use crate::business_isolation as iso;
    let mode = iso::mode(state);
    if mode != iso::Mode::Enforce {
        return None;
    }
    let (za, zb) = (
        iso::zone_of(state, mode, requester).await?,
        iso::zone_of(state, mode, peer).await?,
    );
    (za != zb).then_some((za, zb))
}

/// A cross-border line for a pair (#21 rule 2): an approved relay in one
/// member's zone with an approved `cross_border` edge to an approved relay in
/// the other's, each granted to both members (explicit grants only, as in
/// [`plan_backbone`]). The edge's source holds the bridge, so whichever
/// member asked, the member in the source's zone binds there.
struct LinePlan {
    ingress: Plan,
    exit: Plan,
    private_endpoint: String,
    /// The member in the ingress relay's zone is the peer, not the requester.
    flipped: bool,
}

async fn plan_line(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    (za, zb): (BusinessZone, BusinessZone),
) -> Result<LinePlan, PeerRelayDenyReason> {
    use PeerRelayDenyReason as D;
    let (Some(a), Some(b)) = (requester.id, peer.id) else {
        return Err(D::RequesterUnsupported);
    };
    // The exception applies only where a line connects the two zones, toward
    // members that both ride line-only peers (rule 4: a line to a member
    // that cannot would be a session nobody binds). Anywhere else the zone
    // rule's own refusal stands.
    let connected = cross_border_lines(state, requester.tenant_id)
        .await
        .iter()
        .any(|&line| line == (za, zb) || line == (zb, za));
    if !connected
        || !state.org_relay.join_extras(a).supports_backbone_only_v1
        || !state.org_relay.join_extras(b).supports_backbone_only_v1
    {
        return Err(D::ZoneDenied);
    }
    let network = state
        .overlay_networks
        .get_or_create(requester.tenant_id)
        .await
        .map_err(|_| D::PolicyUnreadable)?;
    if network.mtu > limits::BACKBONE_MAX_OVERLAY_MTU {
        return Err(D::ZoneDenied);
    }
    let side_a = plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(za)).await;
    let side_b = plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(zb)).await;
    for (ingresses, exits, flipped) in [(&side_a, &side_b, false), (&side_b, &side_a, true)] {
        let (Ok(ingresses), Ok(exits)) = (ingresses, exits) else {
            continue;
        };
        for ingress in ingresses {
            let Some(ingress_id) = ingress.relay.id else { continue };
            if !state.org_relay.join_extras(ingress_id).relay_backbone_ready {
                continue;
            }
            for edge in ingress
                .backbone_edges
                .iter()
                .take(roomler_ai_remote_control::models::MAX_PEER_RELAY_BACKBONE_EDGES)
                .filter(|e| e.cross_border)
            {
                if !crate::routes::peer_relay::valid_backbone_endpoint(&edge.endpoint)
                    || !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                        &edge.endpoint,
                        &network.cidr,
                    )
                {
                    continue;
                }
                let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id) else { continue };
                if let Some(exit) = exits.iter().find(|p| p.relay_agent_id == target) {
                    return Ok(LinePlan {
                        ingress: ingress.clone(),
                        exit: exit.clone(),
                        private_endpoint: edge.endpoint.clone(),
                        flipped,
                    });
                }
            }
        }
    }
    // A side's own refusal names its gate; two usable sides with no line
    // between them are what the zone rule refuses.
    match (side_a, side_b) {
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Err(D::ZoneDenied),
    }
}

/// `relay_request` / fallback for a pair only a line may carry: re-push the
/// live line to the asker while it can still bind, else mint one (or audit
/// the refusal). A member asks only while it has no working carrier, so a
/// line past its bind window is revoked and minted afresh, as a fallback
/// does for a one-hop session.
async fn maybe_mint_line(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    zones: (BusinessZone, BusinessZone),
    warn_only: bool,
) {
    let tenant_id = requester.tenant_id;
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else { return };
    let pk = pair_key(req_id, peer_id);
    if !warn_only && let Some(s) = state.org_relay.active_session(&pk) {
        let Some(i) = s.member_index(req_id) else { return };
        if s.line.is_some() && Instant::now() + BIND_REUSE_MARGIN < s.bind_by {
            push_member(state, &s, i).await;
            debug!(%tenant_id, %pk, vni = s.member_leg(i).vni,
                "org-relay: re-pushed the live line to a re-requesting member");
            return;
        }
        revoke_where(state, "org-line-rebind", |c| {
            c.pair_key == pk && c.vni == s.vni && c.generation == s.generation
        })
        .await;
    }
    match plan_line(state, requester, peer, zones).await {
        Ok(plan) => mint_line(state, requester, peer, plan, warn_only).await,
        Err(reason) => {
            info!(%tenant_id, requester = %req_id, peer = %peer_id, ?reason, warn_only,
                "org-relay: cross-border line refused");
            audit_mint(state, tenant_id, req_id, peer_id, None, None, warn_only, Some(reason))
                .await;
        }
    }
}

/// Mint a cross-border line (#21): the ingress relay serves `members[0]` and
/// the bridge, the exit relay serves the bridge and `members[1]`, and the
/// ingress relay's bridge joins the two sessions over the private line. Each
/// member is pushed only its own relay and rides it as an ordinary org-relay
/// session; WireGuard stays end to end, the relays see ciphertext. Both legs
/// are audited `cross_border_line` (rule 5).
async fn mint_line(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    plan: LinePlan,
    warn_only: bool,
) {
    let tenant_id = requester.tenant_id;
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else { return };
    let pk = pair_key(req_id, peer_id);
    let (Some(ingress_id), Some(exit_id)) = (plan.ingress.relay.id, plan.exit.relay.id) else {
        return;
    };
    let refuse = |reason| audit_mint(state, tenant_id, req_id, peer_id, None, None, warn_only, Some(reason));
    if !warn_only
        && !state
            .relay_rate_limiter
            .check(req_id, ingress_id, limits::MINT_RATE_LIMIT_PER_MINUTE)
    {
        refuse(PeerRelayDenyReason::RateLimited).await;
        return;
    }
    let (Some(vni), Some(exit_vni)) = (
        state.org_relay.alloc_vni(ingress_id),
        state.org_relay.alloc_vni(exit_id),
    ) else {
        refuse(PeerRelayDenyReason::NoRelay).await;
        return;
    };
    let (m0, m1) = if plan.flipped { (peer, requester) } else { (requester, peer) };
    let member = |n: &OverlayNode| SessionMember {
        party: SessionParty {
            node_id: n.id.unwrap_or_default(),
            node_ref: n.node_ref.clone(),
        },
        wg_public_key: n.wg_public_key.clone(),
        bind_secret: random_secret(),
    };
    let now = Instant::now();
    let generation = state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1;
    let exit_generation = state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1;
    let session = OrgRelaySession {
        tenant_id,
        pair_key: pk.clone(),
        vni,
        generation,
        relay: SessionParty {
            node_id: ingress_id,
            node_ref: plan.ingress.relay.node_ref.clone(),
        },
        relay_agent_id: plan.ingress.relay_agent_id,
        implicit: false,
        members: [member(m0), member(m1)],
        endpoints: plan.ingress.endpoints.clone(),
        expires_at: now + Duration::from_secs(u64::from(limits::MAX_LIFETIME_SECS)),
        bind_by: now + Duration::from_secs(u64::from(limits::BIND_SECS)),
        line: Some(LineLeg {
            relay: SessionParty {
                node_id: exit_id,
                node_ref: plan.exit.relay.node_ref.clone(),
            },
            relay_agent_id: plan.exit.relay_agent_id,
            vni: exit_vni,
            generation: exit_generation,
            endpoints: plan.exit.endpoints.clone(),
            private_endpoint: plan.private_endpoint.clone(),
            bridge_id: ObjectId::new(),
            bridge_secrets: [random_secret(), random_secret()],
        }),
    };
    audit_line(state, &session, warn_only).await;
    if warn_only {
        info!(%tenant_id, requester = %req_id, peer = %peer_id, ingress = %ingress_id,
            exit = %exit_id, "org-relay [warn]: would mint a cross-border line; pushing nothing");
        return;
    }
    // One live session per pair: a concurrent winner is re-pushed instead.
    let current = match state.org_relay.sessions.entry(pk.clone()) {
        dashmap::mapref::entry::Entry::Occupied(e) if e.get().expires_at > Instant::now() => {
            Some(e.get().clone())
        }
        dashmap::mapref::entry::Entry::Occupied(mut e) => {
            e.insert(session.clone());
            None
        }
        dashmap::mapref::entry::Entry::Vacant(e) => {
            e.insert(session.clone());
            None
        }
    };
    if let Some(current) = current {
        if let Some(i) = current.member_index(req_id) {
            push_member(state, &current, i).await;
        }
        return;
    }
    let Some(line) = session.line.as_ref() else { return };
    info!(%tenant_id, requester = %req_id, peer = %peer_id, ingress = %ingress_id, vni,
        exit = %exit_id, exit_vni, line = %line.private_endpoint,
        "org-relay: a cross-border pair rides its approved line");
    let serve = |vni, generation, secrets: [&String; 2]| ServerMsg::OverlayRelayServe {
        vni,
        generation,
        members: session
            .members
            .iter()
            .zip(secrets)
            .map(|(m, secret)| RelayMemberWire {
                wg_public_key: m.wg_public_key.clone(),
                bind_secret: secret.clone(),
            })
            .collect(),
        bind_secs: limits::BIND_SECS,
        idle_secs: limits::IDLE_SECS,
        max_lifetime_secs: limits::MAX_LIFETIME_SECS,
    };
    // Both relays first, then the bridge, so its binds find both sessions
    // (it retries within its own budget), then each member.
    let [m0_secret, m1_secret] = [&session.members[0].bind_secret, &session.members[1].bind_secret];
    send_to_node(state, &plan.ingress.relay, serve(vni, generation, [m0_secret, &line.bridge_secrets[0]])).await;
    send_to_node(state, &plan.exit.relay, serve(exit_vni, exit_generation, [&line.bridge_secrets[1], m1_secret])).await;
    send_to_node(
        state,
        &plan.ingress.relay,
        ServerMsg::OverlayRelayBridgeServe {
            bridge: roomler_ai_remote_control::signaling::RelayBridgeWire {
                trial_id: line.bridge_id,
                generation,
                source_agent_id: session.relay_agent_id,
                target_agent_id: line.relay_agent_id,
                local_vni: vni,
                local_generation: generation,
                local_bind_secret: line.bridge_secrets[0].clone(),
                remote_endpoint: line.private_endpoint.clone(),
                remote_vni: exit_vni,
                remote_generation: exit_generation,
                remote_bind_secret: line.bridge_secrets[1].clone(),
                max_lifetime_secs: limits::MAX_LIFETIME_SECS,
            },
        },
    )
    .await;
    push_member(state, &session, 0).await;
    push_member(state, &session, 1).await;
}

/// Rule 5: one `mint` row per leg of a line, each naming its relay and VNI,
/// with reason `cross_border_line`.
async fn audit_line(state: &NetworkState, s: &OrgRelaySession, warn_only: bool) {
    let Some(line) = s.line.as_ref() else { return };
    for (agent_id, relay_node_id, vni) in [
        (s.relay_agent_id, s.relay.node_id, s.vni),
        (line.relay_agent_id, line.relay.node_id, line.vni),
    ] {
        let event = PeerRelayAuditEvent {
            id: None,
            tenant_id: s.tenant_id,
            action: PeerRelayAuditAction::Mint,
            agent_id: Some(agent_id),
            user_id: None,
            requester_node_id: Some(s.members[0].party.node_id),
            peer_node_id: Some(s.members[1].party.node_id),
            relay_node_id: Some(relay_node_id),
            serve: None,
            vni: Some(vni),
            warn_only,
            at: DateTime::now(),
            denied: None,
            reason: Some(CROSS_BORDER_REASON.into()),
        };
        if let Err(e) = state.peer_relay_audit.record(event).await {
            warn!(%e, "org-relay: cross-border audit write failed");
        }
    }
}

/// Discovery hints for a cross-border pair: each ingress relay in the
/// requester's zone with an approved `cross_border` edge to an exit relay in
/// the peer's zone, both authorized for the pair. At most two.
async fn cross_border_hints(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    overlay_cidr: &str,
) -> Vec<OrgRelayCandidateWire> {
    let Some((za, zb)) = cross_border_zones(state, requester, peer).await else {
        return Vec::new();
    };
    let Ok(ingresses) =
        plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(za)).await
    else {
        return Vec::new();
    };
    let Ok(exits) =
        plan_mint_candidates_reusing(state, requester, peer, None, ZoneScope::Side(zb)).await
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ingress in &ingresses {
        let Some(ingress_id) = ingress.relay.id else { continue };
        if !state.org_relay.join_extras(ingress_id).relay_backbone_ready {
            continue;
        }
        for edge in ingress.backbone_edges.iter().take(8).filter(|e| e.cross_border) {
            if !crate::routes::peer_relay::backbone_endpoint_outside_overlay(&edge.endpoint, overlay_cidr) {
                continue;
            }
            let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id) else { continue };
            let Some(exit) = exits.iter().find(|p| p.relay_agent_id == target) else {
                continue;
            };
            out.push(OrgRelayCandidateWire {
                relay_node_id: ingress_id,
                endpoints: ingress.endpoints.iter().take(4).cloned().collect(),
                exit_relay_node_id: exit.relay.id,
            });
            if out.len() >= 2 {
                return out;
            }
        }
    }
    out
}

fn discovery_key(c: &OrgRelayCandidateWire) -> (ObjectId, Option<ObjectId>) {
    (c.relay_node_id, c.exit_relay_node_id)
}
fn discovery_cursor(c: &OrgRelayCandidateWire) -> OrgRelayDiscoveryCursorWire {
    OrgRelayDiscoveryCursorWire {
        relay_node_id: c.relay_node_id,
        exit_relay_node_id: c.exit_relay_node_id,
    }
}
/// At most six hints retained while scanning the already-authorized planner.
/// Ring order provides coverage; output order remains planner preference order.
fn discovery_page(
    hints: impl Iterator<Item = OrgRelayCandidateWire>,
    cursor: OrgRelayDiscoveryCursorWire,
) -> (
    Vec<OrgRelayCandidateWire>,
    Option<OrgRelayDiscoveryCursorWire>,
) {
    let key = (cursor.relay_node_id, cursor.exit_relay_node_id);
    let mut first = Vec::new();
    let mut after = Vec::new();
    for (rank, hint) in hints.enumerate() {
        let k = discovery_key(&hint);
        fn keep(
            window: &mut Vec<(usize, OrgRelayCandidateWire)>,
            rank: usize,
            hint: OrgRelayCandidateWire,
        ) {
            if window
                .iter()
                .any(|(_, c)| discovery_key(c) == discovery_key(&hint))
            {
                return;
            }
            window.push((rank, hint));
            window.sort_by_key(|(_, c)| discovery_key(c));
            window.truncate(3);
        }
        keep(&mut first, rank, hint.clone());
        if k > key {
            keep(&mut after, rank, hint);
        }
    }
    for entry in first {
        if after.len() == 3 {
            break;
        }
        if !after
            .iter()
            .any(|(_, c)| discovery_key(c) == discovery_key(&entry.1))
        {
            after.push(entry);
        }
    }
    // Last traversed, NOT maximum key: a page may wrap through the origin.
    let next = after.last().map(|(_, c)| discovery_cursor(c));
    after.sort_by_key(|(rank, _)| *rank);
    (after.into_iter().map(|(_, c)| c).collect(), next)
}

/// Return a short-lived selection hint using the SAME candidate authorization
/// as session minting. No VNI, secret, session, TURN allocation, or peer push.
/// The caller already bounded requests and checked the pair's visibility.
pub async fn discover(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    request_id: u64,
    cursor: Option<OrgRelayDiscoveryCursorWire>,
) {
    let Some(peer_id) = peer.id else { return };
    let mut candidates = Vec::new();
    let extras = requester
        .id
        .map(|id| state.org_relay.join_extras(id))
        .unwrap_or_default();
    let traversal =
        extras.supports_org_relay_multi_candidate && extras.supports_org_relay_discovery_cursor;
    let mut next_cursor = None;
    let mut backbone_cidr = None;
    let enabled = matches!(
        peer_relay_mode(state, requester.tenant_id).await,
        PeerRelayMode::On | PeerRelayMode::Auto
    );
    if enabled {
        let path_caps = requester
            .id
            .is_some_and(|id| state.org_relay.join_extras(id).supports_path_backbone_v1)
            && state
                .org_relay
                .join_extras(peer_id)
                .supports_path_backbone_v1;
        let path_network = if path_caps {
            state
                .overlay_networks
                .get_or_create(requester.tenant_id)
                .await
                .ok()
                .filter(|n| n.mtu <= limits::BACKBONE_MAX_OVERLAY_MTU)
        } else {
            None
        };
        if let Some(path_network) = path_network.as_ref() {
            // A cross-border pair gets only its line's hints.
            candidates.extend(cross_border_hints(state, requester, peer, &path_network.cidr).await);
        }
        if let Some(path_network) = path_network {
            backbone_cidr = Some(path_network.cidr.clone());
            if let Ok(plans) = plan_mint_candidates(state, requester, peer).await {
                // Ordering is only a discovery hint, NEVER a path-quality
                // decision. A bilateral same-metric trial must prove the full
                // path including the private backbone before application use.
                'sources: for ingress in &plans {
                    let Some(ingress_id) = ingress.relay.id else {
                        continue;
                    };
                    if !state.org_relay.join_extras(ingress_id).relay_backbone_ready {
                        continue;
                    }
                    for edge in ingress.backbone_edges.iter().take(8) {
                        if !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                            &edge.endpoint,
                            &path_network.cidr,
                        ) {
                            continue;
                        }
                        let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id) else {
                            continue;
                        };
                        let Some(exit) = plans
                            .iter()
                            .find(|p| p.relay_agent_id == target && p.relay.id != Some(ingress_id))
                        else {
                            continue;
                        };
                        candidates.push(OrgRelayCandidateWire {
                            relay_node_id: ingress_id,
                            endpoints: ingress.endpoints.iter().take(4).cloned().collect(),
                            exit_relay_node_id: exit.relay.id,
                        });
                        if candidates.len() >= 2 {
                            break 'sources;
                        }
                    }
                }
            }
        }
        if requester.id.is_some_and(|id| {
            state
                .org_relay
                .join_extras(id)
                .supports_org_relay_multi_candidate
        }) {
            // Metadata only: preserve the existing authorized ordering, and
            // fill unused slots after the original (at most two) backbone
            // hints. Failure/cooldown and trials remain client-owned; discovery
            // never establishes or promotes a path. Old clients retain their
            // exact single-one-hop response because they reject this shape.
            if let Ok(plans) = plan_mint_candidates(state, requester, peer).await {
                for plan in plans {
                    if candidates.len() >= 3 {
                        break;
                    }
                    let Some(relay_node_id) = plan.relay.id else {
                        continue;
                    };
                    if candidates
                        .iter()
                        .any(|c| c.relay_node_id == relay_node_id && c.exit_relay_node_id.is_none())
                    {
                        continue;
                    }
                    candidates.push(OrgRelayCandidateWire {
                        relay_node_id,
                        exit_relay_node_id: None,
                        endpoints: plan.endpoints.into_iter().take(4).collect(),
                    });
                }
            }
        } else if let Ok(plan) = plan_mint(state, requester, peer).await {
            if let Some(relay_node_id) = plan.relay.id {
                candidates.push(OrgRelayCandidateWire {
                    relay_node_id,
                    exit_relay_node_id: None,
                    endpoints: plan.endpoints.into_iter().take(4).collect(),
                });
            }
        }
    }
    if traversal && enabled {
        if let Some(cursor) = cursor {
            // Existing two-hop scope is unchanged: only the original at-most-two
            // backbone hints participate. All one-hop plans are freshly filtered.
            match plan_mint_candidates(state, requester, peer).await {
                Ok(plans) => {
                    // Never carry a backbone hint across the await into this
                    // fresh page snapshot: approval, ACL or approved edges may
                    // have changed. Rebuild only the existing <=2 hint scope.
                    let mut backbone = Vec::new();
                    let current_path_caps = requester.id.is_some_and(|id| {
                        state.org_relay.join_extras(id).supports_path_backbone_v1
                    }) && state
                        .org_relay
                        .join_extras(peer_id)
                        .supports_path_backbone_v1;
                    if let Some(cidr) = backbone_cidr.as_deref().filter(|_| current_path_caps) {
                        'sources: for ingress in &plans {
                            let Some(ingress_id) = ingress.relay.id else {
                                continue;
                            };
                            if !state.org_relay.join_extras(ingress_id).relay_backbone_ready {
                                continue;
                            }
                            for edge in ingress.backbone_edges.iter().take(8) {
                                if !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                                    &edge.endpoint,
                                    cidr,
                                ) {
                                    continue;
                                }
                                let Ok(target) = ObjectId::parse_str(&edge.relay_agent_id) else {
                                    continue;
                                };
                                let Some(exit) = plans.iter().find(|p| {
                                    p.relay_agent_id == target && p.relay.id != Some(ingress_id)
                                }) else {
                                    continue;
                                };
                                let hint = OrgRelayCandidateWire {
                                    relay_node_id: ingress_id,
                                    endpoints: ingress.endpoints.iter().take(4).cloned().collect(),
                                    exit_relay_node_id: exit.relay.id,
                                };
                                if !backbone
                                    .iter()
                                    .any(|c| discovery_key(c) == discovery_key(&hint))
                                {
                                    backbone.push(hint);
                                }
                                if backbone.len() == 2 {
                                    break 'sources;
                                }
                            }
                        }
                    }
                    let onehop = plans.into_iter().filter_map(|p| {
                        p.relay.id.map(|id| OrgRelayCandidateWire {
                            relay_node_id: id,
                            exit_relay_node_id: None,
                            endpoints: p.endpoints.into_iter().take(4).collect(),
                        })
                    });
                    (candidates, next_cursor) =
                        discovery_page(backbone.into_iter().chain(onehop), cursor);
                }
                Err(_) => candidates.clear(), // no stale-page fallback on authorization failure
            }
        } else {
            // Preserve the original preferred first page, including backbone reservation.
            next_cursor = candidates
                .iter()
                .max_by_key(|c| discovery_key(c))
                .map(discovery_cursor);
        }
    }
    let ttl_secs = if candidates.is_empty() { 0 } else { 30 };
    send_to_node(
        state,
        requester,
        ServerMsg::OverlayOrgRelayCandidates {
            peer_node_id: peer_id,
            request_id,
            candidates,
            ttl_secs,
            next_cursor,
        },
    )
    .await;
}

fn random_secret() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    BASE64.encode(b)
}

/// The entry point, called from `handle_overlay_relay_request` after its own
/// cross-tenant and ACL-enforce checks. Never blocks the TURN grant: the
/// client cascade (P4) picks Org over Turn/Derp when a session arrives.
pub async fn maybe_mint(state: &NetworkState, requester: &OverlayNode, peer: &OverlayNode) {
    let tenant_id = requester.tenant_id;
    let mode = peer_relay_mode(state, tenant_id).await;
    if mode == PeerRelayMode::Off {
        // Gate 1 — zero rows, zero further reads.
        return;
    }
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else {
        return;
    };
    let warn_only = mode == PeerRelayMode::Warn;
    let pk = pair_key(req_id, peer_id);
    // A pair pinned to DERP (TURN churn, or a lossy ORG carrier) rides DERP
    // whatever is minted, so a session now would never bind.
    if crate::overlay::org_fallback_forced_derp(state, &pk) {
        return;
    }
    // #21 — a pair in two zones rides a cross-border line or nothing.
    if let Some(zones) = cross_border_zones(state, requester, peer).await {
        maybe_mint_line(state, requester, peer, zones, warn_only).await;
        return;
    }

    // Idempotent per pair: a live session is re-pushed to the ASKER only —
    // the peer and the relay already hold it. Not audited: nothing was
    // decided, and a retrying client must not fill the log.
    if !warn_only && let Some(s) = state.org_relay.active_session(&pk) {
        if let Some(i) = s.member_index(req_id) {
            push_member(state, &s, i).await;
            debug!(%tenant_id, %pk, vni = s.vni, "org-relay: re-pushed the live session to a re-requesting member");
        }
        return;
    }

    // An implicit plan rests on live connections, so it mints under the
    // eligibility fence, whose claim also spends its rate budget (once).
    let epoch = state.org_relay.eligibility_generation();
    let verdict = plan_mint(state, requester, peer).await.and_then(|plan| {
        let relay_id = plan.relay.id.unwrap_or_default();
        // Gate 5 belongs to minting, not metadata discovery. Preserve its
        // existing requester->relay ceiling and audited refusal behavior.
        if plan.implicit
            || state
                .relay_rate_limiter
                .check(req_id, relay_id, limits::MINT_RATE_LIMIT_PER_MINUTE)
        {
            Ok(plan)
        } else {
            Err(PeerRelayDenyReason::RateLimited)
        }
    });
    let plan = match verdict {
        Ok(plan) => plan,
        Err(reason) => {
            info!(%tenant_id, requester = %req_id, peer = %peer_id, ?reason, warn_only, "org-relay: mint refused");
            audit_mint(
                state,
                tenant_id,
                req_id,
                peer_id,
                None,
                None,
                warn_only,
                Some(reason),
            )
            .await;
            return;
        }
    };
    let fence = plan.implicit.then_some(epoch);
    mint_plan(state, requester, peer, plan, warn_only, fence).await;
}

/// Time a re-pushed session needs to bind before the relay's bind deadline:
/// the member's bind sends and the push latency.
const BIND_REUSE_MARGIN: Duration = Duration::from_secs(8);

/// A fallback query reauthorizes cached leases, and never allocates TURN.
/// In particular a stale but unexpired relay lease cannot suppress reselection.
pub async fn maybe_mint_fallback(state: &NetworkState, requester: &OverlayNode, peer: &OverlayNode) {
    let tenant_id = requester.tenant_id;
    let mode = peer_relay_mode(state, tenant_id).await;
    if mode == PeerRelayMode::Off { return; }
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else { return };
    let pk = pair_key(req_id, peer_id);
    if crate::overlay::org_fallback_forced_derp(state, &pk) { return; }
    if let Some(zones) = cross_border_zones(state, requester, peer).await {
        maybe_mint_line(state, requester, peer, zones, mode == PeerRelayMode::Warn).await;
        return;
    }
    let cached = state.org_relay.active_session(&pk);
    let mut epoch = state.org_relay.eligibility_generation();
    let mut verdict =
        plan_mint_candidates_reusing(state, requester, peer, cached.as_ref(), ZoneScope::Pair).await;
    if epoch != state.org_relay.eligibility_generation()
        || crate::overlay::org_fallback_forced_derp(state, &pk) { return; }
    if let Some(session) = cached {
        let authorized = verdict.as_ref().is_ok_and(|plans| plans.iter().any(|plan| {
            plan.relay.id == Some(session.relay.node_id)
                && plan.relay_agent_id == session.relay_agent_id
                && plan.relay.node_ref == session.relay.node_ref
                && plan.endpoints == session.endpoints
                && plan.implicit == session.implicit
                && [(req_id, requester), (peer_id, peer)].iter().all(|(id, node)| {
                    session.member_index(*id).is_some_and(|i| {
                        session.members[i].wg_public_key == node.wg_public_key
                            && session.members[i].party.node_ref == node.node_ref
                    })
                })
        }));
        // A member asks again only while it has no working org link. Within
        // the bind window the same session can still bind, so re-push it;
        // past it the relay drops its Binds (an unbound session dies at its
        // bind deadline), and re-pushing it stranded the pair until some
        // other event revoked it (field, 2026-10-25: 6 and 26 minutes).
        let bindable = Instant::now() + BIND_REUSE_MARGIN < session.bind_by;
        if authorized && bindable && mode != PeerRelayMode::Warn {
            if let Some(i) = session.member_index(req_id) { push_member(state, &session, i).await; }
            return;
        }
        if authorized && !bindable && mode != PeerRelayMode::Warn {
            revoke_where(state, "org-fallback-bind-window-passed", |current| {
                current.pair_key == pk
                    && current.vni == session.vni
                    && current.generation == session.generation
            })
            .await;
            epoch = state.org_relay.eligibility_generation();
            verdict = plan_mint_candidates(state, requester, peer).await;
        }
        if !authorized {
            revoke_where(state, "org-fallback-reauthorization", |current| {
                current.pair_key == pk && current.vni == session.vni
                    && current.generation == session.generation
            }).await;
            // Revocation changes the epoch. Re-read after its audit await so
            // a concurrent approval/ACL/membership change cannot reuse a plan.
            epoch = state.org_relay.eligibility_generation();
            verdict = plan_mint_candidates(state, requester, peer).await;
        }
    }
    if epoch != state.org_relay.eligibility_generation()
        || crate::overlay::org_fallback_forced_derp(state, &pk) { return; }
    let verdict = verdict.and_then(|plans| plans.into_iter().next().ok_or(PeerRelayDenyReason::NoRelay));
    match verdict {
        Ok(plan) => mint_plan(state, requester, peer, plan, mode == PeerRelayMode::Warn, Some(epoch)).await,
        Err(reason) => audit_mint(state, tenant_id, req_id, peer_id, None, None,
            mode == PeerRelayMode::Warn, Some(reason)).await,
    }
}

async fn mint_plan(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    plan: Plan,
    warn_only: bool,
    fallback_epoch: Option<u64>,
) {
    let tenant_id = requester.tenant_id;
    let (Some(req_id), Some(peer_id)) = (requester.id, peer.id) else { return };
    let pk = pair_key(req_id, peer_id);
    let relay_id = plan.relay.id.unwrap_or_default();
    let Some(vni) = state.org_relay.alloc_vni(relay_id) else {
        // Every VNI on that relay is held: it is full in a way the session
        // count did not show. Same answer as no relay at all.
        audit_mint(
            state,
            tenant_id,
            req_id,
            peer_id,
            Some((plan.relay_agent_id, relay_id)),
            None,
            warn_only,
            Some(PeerRelayDenyReason::NoRelay),
        )
        .await;
        return;
    };
    let generation = state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1;
    let session = OrgRelaySession {
        tenant_id,
        pair_key: pk.clone(),
        vni,
        generation,
        relay: SessionParty {
            node_id: relay_id,
            node_ref: plan.relay.node_ref.clone(),
        },
        relay_agent_id: plan.relay_agent_id,
        implicit: plan.implicit,
        members: [
            SessionMember {
                party: SessionParty {
                    node_id: req_id,
                    node_ref: requester.node_ref.clone(),
                },
                wg_public_key: requester.wg_public_key.clone(),
                bind_secret: random_secret(),
            },
            SessionMember {
                party: SessionParty {
                    node_id: peer_id,
                    node_ref: peer.node_ref.clone(),
                },
                wg_public_key: peer.wg_public_key.clone(),
                bind_secret: random_secret(),
            },
        ],
        endpoints: plan.endpoints.clone(),
        expires_at: Instant::now() + Duration::from_secs(u64::from(limits::MAX_LIFETIME_SECS)),
        bind_by: Instant::now() + Duration::from_secs(u64::from(limits::BIND_SECS)),
        line: None,
    };
    // Legacy ordering stays intact; fallback audits only its winning claim.
    if fallback_epoch.is_none() || warn_only {
        if fallback_epoch.is_some() && !state.relay_rate_limiter.check(req_id, relay_id, limits::MINT_RATE_LIMIT_PER_MINUTE) {
            audit_mint(state, tenant_id, req_id, peer_id, None, None, warn_only,
                Some(PeerRelayDenyReason::RateLimited)).await;
            return;
        }
        audit_mint(state, tenant_id, req_id, peer_id, Some((plan.relay_agent_id, relay_id)),
            Some(vni), warn_only, None).await;
    }
    if warn_only {
        info!(%tenant_id, requester = %req_id, peer = %peer_id, relay = %relay_id, vni, "org-relay [warn]: would mint; pushing nothing");
        return;
    }
    if let Some(epoch) = fallback_epoch {
        if epoch != state.org_relay.eligibility_generation()
            || crate::overlay::org_fallback_forced_derp(state, &pk) { return; }
        // Both members can cross policy IO with cached=None. Claim under the
        // pair entry, consume mint budget only for the winner, and release the
        // guard before any push/audit await. Never overwrite a live generation.
        let claim = match state.org_relay.sessions.entry(pk.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if entry.get().expires_at > Instant::now() {
                    Ok(Some(entry.get().clone()))
                } else if state.relay_rate_limiter.check(req_id, relay_id, limits::MINT_RATE_LIMIT_PER_MINUTE) {
                    entry.insert(session.clone());
                    Ok(None)
                } else { Err(PeerRelayDenyReason::RateLimited) }
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                if state.relay_rate_limiter.check(req_id, relay_id, limits::MINT_RATE_LIMIT_PER_MINUTE) {
                    entry.insert(session.clone());
                    Ok(None)
                } else { Err(PeerRelayDenyReason::RateLimited) }
            }
        };
        match claim {
            Ok(Some(current)) => {
                // A concurrent winner may have used a different authorization
                // snapshot. Only this freshly authorized exact lease is reused.
                if current.relay.node_id == relay_id && current.relay.node_ref == plan.relay.node_ref
                    && current.endpoints == plan.endpoints && current.implicit == plan.implicit
                    && [(req_id, requester), (peer_id, peer)].iter().all(|(id,node)| {
                        current.member_index(*id).is_some_and(|i| current.members[i].wg_public_key == node.wg_public_key
                            && current.members[i].party.node_ref == node.node_ref)
                    })
                    && epoch == state.org_relay.eligibility_generation()
                    && !crate::overlay::org_fallback_forced_derp(state, &pk)
                    && let Some(i) = current.member_index(req_id)
                { push_member(state, &current, i).await; }
                return;
            }
            Err(reason) => {
                audit_mint(state, tenant_id, req_id, peer_id, None, None, false, Some(reason)).await;
                return;
            }
            Ok(None) => {}
        }
    } else {
        state.org_relay.sessions.insert(pk.clone(), session.clone());
    }
    info!(%tenant_id, requester = %req_id, peer = %peer_id, relay = %relay_id, vni, generation,
        endpoints = ?session.endpoints, "org-relay: minted");

    // The relay FIRST, so it can verify the binds by the time the members
    // arrive; then each member with its own secret.
    send_to_node(
        state,
        &plan.relay,
        ServerMsg::OverlayRelayServe {
            vni,
            generation,
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
        },
    )
    .await;
    push_member(state, &session, 0).await;
    push_member(state, &session, 1).await;
    if fallback_epoch.is_some() {
        audit_mint(state, tenant_id, req_id, peer_id, Some((plan.relay_agent_id, relay_id)),
            Some(vni), false, None).await;
    }
}

/// `rc:overlay.relay_session` to member `i`, naming the OTHER member as its
/// peer and carrying only its own secret and its own relay (on a line, each
/// member's is in its own zone).
async fn push_member(state: &NetworkState, s: &OrgRelaySession, i: usize) {
    let remaining = s.expires_at.saturating_duration_since(Instant::now()).as_secs()
        .min(u64::from(limits::MAX_LIFETIME_SECS)) as u32;
    if remaining == 0 { return; }
    let me = &s.members[i];
    let other = &s.members[1 - i];
    let leg = s.member_leg(i);
    send_to_node_ref(
        state,
        &me.party.node_ref,
        ServerMsg::OverlayRelaySession {
            vni: leg.vni,
            generation: leg.generation,
            peer_node_id: other.party.node_id,
            relay_node_id: leg.relay_node_id,
            relay_endpoints: leg.endpoints.to_vec(),
            bind_secret: me.bind_secret.clone(),
            bind_secs: limits::BIND_SECS,
            max_lifetime_secs: remaining,
        },
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn audit_mint(
    state: &NetworkState,
    tenant_id: ObjectId,
    requester: ObjectId,
    peer: ObjectId,
    relay: Option<(ObjectId, ObjectId)>,
    vni: Option<u32>,
    warn_only: bool,
    denied: Option<PeerRelayDenyReason>,
) {
    let event = PeerRelayAuditEvent {
        id: None,
        tenant_id,
        action: PeerRelayAuditAction::Mint,
        agent_id: relay.map(|r| r.0),
        user_id: None,
        requester_node_id: Some(requester),
        peer_node_id: Some(peer),
        relay_node_id: relay.map(|r| r.1),
        serve: None,
        vni,
        warn_only,
        at: DateTime::now(),
        denied,
        reason: None,
    };
    if let Err(e) = state.peer_relay_audit.record(event).await {
        warn!(%e, "org-relay: audit write failed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Revocation — a push, never an expiry (§7)
// ─────────────────────────────────────────────────────────────────────────────

/// Tear down every live session `pred` selects: `rc:overlay.relay_revoke` to
/// the relay and both members, the record dropped, one audit row per session
/// naming the trigger. Returns how many were revoked.
/// Send control messages without DB access or awaited channel capacity. A
/// failed push is not an acknowledgment; the authoritative state is already
/// removed and the normal reconnect/receiver liveness paths remain in force.
fn push_control(state: &NetworkState, node: &NodeRef, msg: ServerMsg) -> bool {
    match node {
        NodeRef::Agent { agent_id } => state.fleet.rc_hub.send_to_agent(*agent_id, msg).is_ok(),
        NodeRef::TunnelClient { tunnel_client_id } => state
            .overlay_nodes_by_id
            .get(tunnel_client_id)
            .is_some_and(|tx| tx.try_send(msg).is_ok()),
    }
}

fn revoke_matching_sync(
    state: &NetworkState,
    reason: &str,
    pred: impl Fn(&OrgRelaySession) -> bool,
) -> Vec<PeerRelayAuditEvent> {
    // Even zero current sessions must invalidate an in-flight authorization.
    state.org_relay.invalidate_eligibility();
    let victims: Vec<OrgRelaySession> = state
        .org_relay
        .sessions
        .iter()
        .filter(|entry| pred(entry.value()))
        .map(|entry| entry.value().clone())
        .collect();
    let mut events = Vec::new();
    for session in victims {
        // Do not remove a newer generation which replaced the selected row.
        if state
            .org_relay
            .sessions
            .remove_if(&session.pair_key, |_, current| {
                current.vni == session.vni && current.generation == session.generation
            })
            .is_none()
        {
            continue;
        }
        let revoke = |vni| ServerMsg::OverlayRelayRevoke { vni };
        push_control(state, &session.relay.node_ref, revoke(session.vni));
        for (i, member) in session.members.iter().enumerate() {
            push_control(state, &member.party.node_ref, revoke(session.member_leg(i).vni));
        }
        // A line also holds the exit relay's session and the ingress bridge.
        if let Some(line) = session.line.as_ref() {
            push_control(state, &line.relay.node_ref, revoke(line.vni));
            push_control(
                state,
                &session.relay.node_ref,
                ServerMsg::OverlayRelayBridgeRevoke {
                    trial_id: line.bridge_id,
                    generation: session.generation,
                },
            );
        }
        events.push(PeerRelayAuditEvent {
            id: None,
            tenant_id: session.tenant_id,
            action: PeerRelayAuditAction::Revoke,
            agent_id: Some(session.relay_agent_id),
            user_id: None,
            requester_node_id: Some(session.members[0].party.node_id),
            peer_node_id: Some(session.members[1].party.node_id),
            relay_node_id: Some(session.relay.node_id),
            serve: None,
            vni: Some(session.vni),
            warn_only: false,
            at: DateTime::now(),
            denied: None,
            reason: Some(reason.to_string()),
        });
    }
    events.extend(state.org_relay.trials.revoke_where(state, reason, &pred));
    events
}

/// Admission revocation: no current_node lookup, storage operation or await
/// precedes terminating every session in which this authenticated agent acts.
/// The caller owns bounded persistence of the returned audit events.
pub fn revoke_agent_sync(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    reason: &str,
) -> Vec<PeerRelayAuditEvent> {
    revoke_matching_sync(state, reason, |session| {
        session.tenant_id == tenant_id && session.involves_agent(agent_id)
    })
}

pub async fn revoke_where(
    state: &NetworkState,
    reason: &str,
    pred: impl Fn(&OrgRelaySession) -> bool,
) -> usize {
    // Complete ALL removals and notifications before the first audit IO.
    let events = revoke_matching_sync(state, reason, pred);
    let count = events.len();
    for event in events {
        if !matches!(
            tokio::time::timeout(Duration::from_secs(3), state.peer_relay_audit.record(event))
                .await,
            Ok(Ok(_))
        ) {
            warn!("org-relay: revoke audit failed or timed out after control revocation");
        }
    }
    count
}

/// Trigger 1 — the org switched peer relays off.
pub async fn revoke_tenant(state: &NetworkState, tenant_id: ObjectId, reason: &str) -> usize {
    revoke_where(state, reason, |s| s.tenant_id == tenant_id).await
}

/// Trigger 3 — a relay's approval was cleared (either leg of a line).
pub async fn revoke_relay_agent(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    reason: &str,
) -> usize {
    revoke_where(state, reason, |s| {
        s.tenant_id == tenant_id && s.relayed_by_agent(agent_id)
    })
    .await
}

/// How long a cross-border line outlives one party's closed or displaced
/// control connection. A line carries its traffic without the control plane,
/// so a reconnect inside the grace, or a center restart, keeps it; once the
/// grace has passed the parties' zones are read again ([`line_zones_fit`]).
pub const LINE_RECONNECT_GRACE: Duration = Duration::from_secs(20);

/// MeshHarbor `auto` and #21: an implicit session and a cross-border line
/// rest on the zone each party's live connection was observed in. That
/// connection closing or being displaced ends an implicit session at once,
/// and a line after [`LINE_RECONNECT_GRACE`] unless every party is connected
/// again in a zone that still fits it (field, 2026-10-26: revoking at once
/// tore a line down on one relay only while a restarting center closed its
/// connections, and the members kept the dead half).
pub async fn connection_ended(state: &NetworkState, agent_id: ObjectId, reason: &'static str) {
    revoke_where(state, reason, |s| s.implicit && s.involves_agent(agent_id)).await;
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(LINE_RECONNECT_GRACE).await;
        recheck_lines(&state, agent_id, reason).await;
    });
}

/// End `agent_id`'s lines whose parties' zones no longer fit them.
async fn recheck_lines(state: &NetworkState, agent_id: ObjectId, reason: &str) {
    let lines: Vec<OrgRelaySession> = state
        .org_relay
        .sessions
        .iter()
        .filter(|e| e.line.is_some() && e.involves_agent(agent_id))
        .map(|e| e.value().clone())
        .collect();
    for s in lines {
        if line_zones_fit(state, &s).await {
            continue;
        }
        revoke_where(state, reason, |c| {
            c.pair_key == s.pair_key && c.vni == s.vni && c.generation == s.generation
        })
        .await;
    }
}

/// Every party of line `s` is connected here, `members[0]` in the ingress
/// relay's zone, `members[1]` in the exit relay's, and the two zones differ.
async fn line_zones_fit(state: &NetworkState, s: &OrgRelaySession) -> bool {
    let Some(line) = s.line.as_ref() else {
        return false;
    };
    let zone = |r| party_zone(state, s.tenant_id, r);
    let (Some(m0), Some(m1), Some(r0), Some(r1)) = (
        zone(&s.members[0].party.node_ref).await,
        zone(&s.members[1].party.node_ref).await,
        zone(&s.relay.node_ref).await,
        zone(&line.relay.node_ref).await,
    ) else {
        return false;
    };
    m0 == r0 && m1 == r1 && m0 != m1
}

/// Trigger 4 — a party (member or relay) was removed from the overlay.
pub async fn revoke_node(state: &NetworkState, node_id: ObjectId, reason: &str) -> usize {
    state.org_relay.forget_node(node_id);
    revoke_where(state, reason, |s| s.involves(node_id)).await
}

/// Trigger 2 — the tenant's policies changed: re-run gate 2 for every live
/// session and revoke the pairs no longer granted their relay.
///
/// A read failure here does NOTHING, deliberately. Refusing a NEW mint on a
/// blip costs one session; tearing down every LIVE session on a blip is the
/// "spurious deny takes the mesh down" failure `load_acl` fails open to avoid.
pub async fn reconcile_acl(state: &NetworkState, tenant_id: ObjectId) {
    state.org_relay.invalidate_eligibility();
    let acl = match try_load_acl(state, tenant_id, PolicyLoad::Always).await {
        Ok(a) => a,
        Err(e) => {
            warn!(%tenant_id, %e, "org-relay: policies unreadable during reconcile; leaving sessions as they are");
            return;
        }
    };
    let mut live: Vec<OrgRelaySession> = state
        .org_relay
        .sessions
        .iter()
        .filter(|e| e.tenant_id == tenant_id)
        .map(|e| e.value().clone())
        .collect();
    live.extend(state.org_relay.trials.sessions_for_tenant(tenant_id));
    for s in live {
        // Granted by role and zone, not by a policy: an edit cannot touch it.
        if s.implicit {
            continue;
        }
        // Both members must still be granted every relay of the session (a
        // line's two, as its planner requires).
        let mut granted = true;
        'relays: for relay_id in s.relay_nodes() {
            let Ok(relay) = state.overlay_nodes.base.find_by_id(relay_id).await else {
                continue;
            };
            // FR-97 P0b — granted from the routes the relay OFFERS.
            let relay_routes = relay.effective_routes();
            let relay_ref = OverlayPeerRef {
                node_id: relay_id,
                overlay_ip: &relay.overlay_ip,
                approved_routes: &relay_routes,
            };
            for m in &s.members {
                let Ok(node) = state.overlay_nodes.base.find_by_id(m.party.node_id).await else {
                    granted = false;
                    break 'relays;
                };
                let src: OverlaySource = match try_overlay_source_of(state, &node).await {
                    Ok(src) => src,
                    Err(_) => continue, // unreadable identity: not evidence of revocation
                };
                if !evaluate_overlay(&acl.policies, &src, relay_ref).visible {
                    granted = false;
                    break 'relays;
                }
            }
        }
        if !granted {
            let pk = s.pair_key.clone();
            revoke_where(state, "acl_revoked", |x| x.pair_key == pk).await;
        }
    }
}

/// `rc:overlay.relay_probe` — a member's own measurement toward a relay the
/// server minted for it. Accepted only for (relay, endpoint) pairs that
/// appear in one of its sessions.
pub async fn handle_relay_probe(
    state: &NetworkState,
    ident: NodeIdentity,
    relay_node_id: ObjectId,
    endpoint: String,
    reachable: bool,
    rtt_ms: Option<u32>,
) {
    let Some(node) = current_node(state, ident).await else {
        return;
    };
    let Some(node_id) = node.id else { return };
    let accepted =
        state
            .org_relay
            .record_probe(node_id, relay_node_id, endpoint.clone(), reachable, rtt_ms);
    debug!(reporter = %node_id, relay = %relay_node_id, %endpoint, reachable, ?rtt_ms, accepted,
        "org-relay: reachability report");
}

/// The live session a member's loss report names: the reporter's own pair
/// with `peer`, under the VNI it rides. `None` for anything else (a stale
/// VNI, a session it is not a member of), and the report is dropped.
pub(crate) fn reported_session(
    state: &NetworkState,
    reporter: ObjectId,
    peer: ObjectId,
    vni: u32,
) -> Option<OrgRelaySession> {
    let s = state.org_relay.active_session(&pair_key(reporter, peer))?;
    let i = s.member_index(reporter)?;
    (s.member_leg(i).vni == vni).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_with(srflx: &[&str], lan: &[&str], endpoints: &[&str]) -> OverlayNode {
        let mut n: OverlayNode = serde_json::from_value(serde_json::json!({
            "tenant_id": ObjectId::new(),
            "node_ref": { "kind": "agent", "id": ObjectId::new() },
            "network_id": ObjectId::new(),
            "machine_id": "m",
            "name": "n",
            "overlay_ip": "100.64.0.9",
            "wg_public_key": "k",
            "status": "online",
            "last_seen_at": DateTime::now(),
            "created_at": DateTime::now(),
            "updated_at": DateTime::now(),
        }))
        .expect("a minimal node row deserialises");
        n.srflx_endpoints = srflx.iter().map(|s| s.to_string()).collect();
        n.lan_endpoints = lan.iter().map(|s| s.to_string()).collect();
        n.endpoints = endpoints.iter().map(|s| s.to_string()).collect();
        n
    }

    /// Public addresses are re-paired with the relay port, private ones are
    /// dropped, and a static entry keeps its own port.
    #[test]
    fn relay_endpoints_pairs_public_addresses_with_the_relay_port() {
        let n = node_with(
            &["62.210.194.66:41641"],
            &["192.168.1.7:41641", "62.210.194.66:41641"],
            &["10.10.10.11:12000"],
        );
        let out = relay_endpoints(&n, 3478, &["8.8.8.8:5000".to_string()]).unwrap();
        assert_eq!(out, vec!["62.210.194.66:3478", "8.8.8.8:5000"]);
    }

    /// A static endpoint that fails the SSRF rule refuses the whole plan —
    /// the metadata service, RFC1918, the overlay range, a name.
    #[test]
    fn a_non_routable_static_endpoint_is_an_error_not_a_skip() {
        let n = node_with(&["62.210.194.66:41641"], &[], &[]);
        for bad in [
            "169.254.169.254:80",
            "10.0.0.5:3478",
            "100.64.0.1:3478",
            "127.0.0.1:3478",
            "relay.example.com:3478",
        ] {
            assert!(
                relay_endpoints(&n, 3478, &[bad.to_string()]).is_err(),
                "{bad} must refuse"
            );
            assert!(!valid_static_endpoint(bad), "{bad} must not validate");
        }
        assert!(valid_static_endpoint("62.210.194.66:3478"));
        assert!(!valid_static_endpoint("62.210.194.66:0"));
    }

    /// VNIs are per relay, never 0 or the STUN cookie, and never one a live
    /// session on that relay still holds.
    #[test]
    fn vni_allocation_skips_reserved_and_in_use_values() {
        let st = OrgRelayState::new();
        let relay = ObjectId::new();
        // Park the cursor just below the STUN cookie and check it is skipped.
        st.next_vni.insert(relay, limits::STUN_COOKIE_VNI - 1);
        assert_eq!(st.alloc_vni(relay), Some(limits::STUN_COOKIE_VNI - 1));
        assert_eq!(st.alloc_vni(relay), Some(limits::STUN_COOKIE_VNI + 1));
        // Wrap at the 24-bit ceiling, skipping 0.
        st.next_vni.insert(relay, limits::VNI_MAX);
        assert_eq!(st.alloc_vni(relay), Some(limits::VNI_MAX));
        assert_eq!(st.alloc_vni(relay), Some(1));
        // Another relay has its own space.
        assert_eq!(st.alloc_vni(ObjectId::new()), Some(1));
    }

    /// A report is accepted only about a relay + endpoint the server minted
    /// for that node.
    #[test]
    fn probes_are_accepted_only_for_minted_targets() {
        let st = OrgRelayState::new();
        let (a, b, relay) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let party = |id| SessionParty {
            node_id: id,
            node_ref: NodeRef::Agent { agent_id: id },
        };
        st.sessions.insert(
            "pk".into(),
            OrgRelaySession {
                tenant_id: ObjectId::new(),
                pair_key: "pk".into(),
                vni: 7,
                generation: 1,
                relay: party(relay),
                relay_agent_id: relay,
                implicit: false,
                members: [
                    SessionMember {
                        party: party(a),
                        wg_public_key: "a".into(),
                        bind_secret: "s".into(),
                    },
                    SessionMember {
                        party: party(b),
                        wg_public_key: "b".into(),
                        bind_secret: "t".into(),
                    },
                ],
                endpoints: vec!["8.8.8.8:3478".into()],
                expires_at: Instant::now() + Duration::from_secs(60),
                bind_by: Instant::now() + Duration::from_secs(30),
                line: None,
            },
        );
        assert!(st.record_probe(a, relay, "8.8.8.8:3478".into(), true, Some(12)));
        assert!(
            !st.record_probe(a, relay, "8.8.4.4:3478".into(), true, None),
            "an endpoint never minted"
        );
        assert!(
            !st.record_probe(ObjectId::new(), relay, "8.8.8.8:3478".into(), true, None),
            "a stranger"
        );
        assert_eq!(
            st.probe_verdict(a, relay, Instant::now()),
            ProbeVerdict::Reachable(12)
        );
        assert_eq!(
            st.probe_verdict(b, relay, Instant::now()),
            ProbeVerdict::Unknown
        );
        assert!(st.record_probe(b, relay, "8.8.8.8:3478".into(), false, None));
        assert_eq!(
            st.probe_verdict(b, relay, Instant::now()),
            ProbeVerdict::Unreachable
        );
    }

    #[test]
    fn multi_candidate_capability_is_replaced_not_latched_on_rejoin() {
        let state = OrgRelayState::new();
        let node = ObjectId::new();
        state.note_join(
            node,
            JoinExtras {
                supports_org_relay_multi_candidate: true,
                ..Default::default()
            },
        );
        assert!(state.join_extras(node).supports_org_relay_multi_candidate);
        state.note_join(node, JoinExtras::default());
        assert!(!state.join_extras(node).supports_org_relay_multi_candidate);
    }

    #[test]
    fn listener_withdrawal_stays_withdrawn_but_legacy_missing_port_is_supported() {
        let state = OrgRelayState::new();
        let node = ObjectId::new();
        let extras = |port| JoinExtras {
            org_primary: Some(true),
            relay_port: port,
            relay_withdrawn: false,
            supports_org_relay_multi_candidate: false,
            supports_org_relay_discovery_cursor: false,
            supports_path_trial_v1: false,
            supports_path_backbone_v1: false,
            relay_backbone_ready: false,
            supports_backbone_only_v1: false,
        };
        assert!(!state.note_join(node, extras(None)));
        assert!(
            !state.join_extras(node).relay_withdrawn,
            "legacy missing port still uses default"
        );
        assert!(!state.note_join(node, extras(Some(3478))));
        assert!(state.note_join(node, extras(None)));
        assert!(state.join_extras(node).relay_withdrawn);
        assert!(!state.note_join(node, extras(None)));
        assert!(
            state.join_extras(node).relay_withdrawn,
            "empty repeated join cannot resurrect listener"
        );
        assert!(!state.note_join(node, extras(Some(3479))));
        assert!(!state.join_extras(node).relay_withdrawn);
        assert!(
            state.note_join(node, extras(Some(3480))),
            "port replacement retires old sessions"
        );
    }
}

#[cfg(test)]
mod discovery_traversal_tests {
    use super::*;
    fn hint(n: u8) -> OrgRelayCandidateWire {
        OrgRelayCandidateWire {
            relay_node_id: ObjectId::from_bytes([n; 12]),
            exit_relay_node_id: None,
            endpoints: vec!["8.8.8.8:3478".into()],
        }
    }
    #[test]
    fn discovery_traversal_five_relays_preserves_preference_and_wraps() {
        let all: Vec<_> = [5, 2, 4, 1, 3].into_iter().map(hint).collect();
        // Initial response is the original planner preference, not lowest IDs.
        let preferred = all[..3].to_vec();
        let mut cursor = preferred
            .iter()
            .max_by_key(|c| discovery_key(c))
            .map(discovery_cursor)
            .unwrap();
        let mut seen: std::collections::HashSet<_> = preferred.iter().map(discovery_key).collect();
        for _ in 0..2 {
            let (page, next) = discovery_page(all.clone().into_iter(), cursor);
            assert_eq!(page.len(), 3);
            assert_eq!(
                page.iter()
                    .map(discovery_key)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                3
            );
            // Every page presents hints in original planner preference order.
            assert!(
                page.windows(2)
                    .all(|p| all.iter().position(|c| c == &p[0])
                        < all.iter().position(|c| c == &p[1]))
            );
            seen.extend(page.iter().map(discovery_key));
            cursor = next.unwrap();
        }
        assert_eq!(seen.len(), 5);
        // Wrapped cursor is the last canonical traversal entry, not max or last displayed.
        let (page, next) = discovery_page(all.into_iter(), discovery_cursor(&hint(4)));
        assert_eq!(next.unwrap(), discovery_cursor(&hint(2)));
        assert_eq!(
            page.iter().map(|c| c.relay_node_id).collect::<Vec<_>>(),
            vec![
                hint(5).relay_node_id,
                hint(2).relay_node_id,
                hint(1).relay_node_id
            ]
        );
    }
    #[test]
    fn discovery_traversal_dynamic_set_unknown_cursor_empty_and_duplicate_bounds() {
        let cursor = discovery_cursor(&hint(3));
        let mut all = vec![hint(1), hint(2), hint(4), hint(5)]; // revoked 3 absent
        all.push(hint(6)); // newly joined relay, no leaf address input
        let mut next = cursor;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            let (page, c) = discovery_page(all.clone().into_iter().chain(all.clone()), next);
            assert!(
                page.len() <= 3
                    && page
                        .iter()
                        .all(|c| c.relay_node_id != hint(3).relay_node_id)
            );
            assert_eq!(
                page.iter()
                    .map(discovery_key)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                page.len()
            );
            seen.extend(page.iter().map(discovery_key));
            next = c.unwrap();
        }
        assert_eq!(seen.len(), 5);
        let (page, next) = discovery_page(std::iter::empty(), cursor);
        assert!(page.is_empty() && next.is_none());
        let (page, _) = discovery_page(vec![hint(1)].into_iter(), discovery_cursor(&hint(99)));
        assert_eq!(page, vec![hint(1)]);
    }
}
