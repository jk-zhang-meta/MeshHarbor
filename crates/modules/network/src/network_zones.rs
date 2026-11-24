// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Logical Network Zones (`OverlayNetwork::zones` + `Agent::pinned_zone_id`).
//!
//! Single authoritative domain seam for:
//! - Deterministic device-to-zone resolution (`Pinned` -> `Auto` GeoIP -> `is_default` -> `UnresolvedStrict`)
//! - Symmetric pair transport strictness (`RouterOnly` / `UnresolvedStrict` -> `backbone_only = true`, DERP/TURN denied)
//! - Exact `OrgRelay` ingress/egress gateway sets (`gateway_relay_ids`)
//! - Zone-scoped STUN/TURN infrastructure countries (`auto_countries ∪ gateway router countries`)
//! - Revisioned Hub / cross-pod `RelayRegions` synchronization.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use bson::oid::ObjectId;
use meshharbor_core::business_authority::{AuthenticatedDevice, connection_zone};
use meshharbor_core::ice_zones::host_of;
use meshharbor_core::user_analytics::{GeoIp, canonical_public_ip};
use meshharbor_mod_fleet::hub::AgentZoneIcePolicy;
use meshharbor_mod_fleet::socket::{
    agent_effective_country, effective_peer_relay_serve_revision, physical_ip_country,
};
use meshharbor_remote_control::models::{
    Agent, CrossZoneMode, DeviceZoneInputs, DeviceZoneResolution, NetworkZone, NodeRef,
    OverlayNode, ZoneSource, resolve_device_zone, resolve_device_zone_with_source,
};
use tracing::warn;

use crate::NetworkState;

/// Process-local per-tenant mutex serializing zone policy & backbone endpoint publications.
pub fn tenant_zone_publish_lock(tenant_id: ObjectId) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<dashmap::DashMap<ObjectId, Arc<tokio::sync::Mutex<()>>>> =
        std::sync::OnceLock::new();
    LOCKS
        .get_or_init(dashmap::DashMap::new)
        .entry(tenant_id)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .value()
        .clone()
}

#[derive(Clone, Debug)]
pub struct AgentZoneFacts {
    pub pinned_zone_id: Option<String>,
    pub country_code: Option<String>,
    pub physical_country: Option<String>,
    pub physical_seen_at_ms: Option<i64>,
    pub default_route_vpn: bool,
    pub last_clean_zone_id: Option<String>,
}

/// Immutable per-tenant snapshot of Logical Network Zones and active agent facts.
#[derive(Clone, Default)]
pub struct TenantZoneSnapshot {
    pub revision: u64,
    pub zones: Vec<NetworkZone>,
    /// True when reading `OverlayNetwork` or active `Agent` rows failed:
    /// new admissions fail closed; reconcile/DERP rebuild preserves live state.
    pub read_failed: bool,
    /// True when concurrent `zone_revision` bumps prevented a linearizable
    /// snapshot after bounded retries; never publishes stale Hub/WS state.
    pub superseded: bool,
    agents_loaded: bool,
    agents: HashMap<ObjectId, AgentZoneFacts>,
    /// Active approved (`serve == true`) gateway `agent_id`s per `zone.id` (preserving config order).
    zone_gateways_ordered: HashMap<String, Vec<ObjectId>>,
    zone_gateways: HashMap<String, HashSet<ObjectId>>,
    /// Uppercase ISO-3166-1 alpha-2 STUN/TURN countries permitted for `zone.id`.
    zone_infra_countries: HashMap<String, HashSet<String>>,
    /// FR-124 — per `zone.id`: may its devices relay through THIS server's
    /// `/derp` (the centre)? `true` for a zone that is not `RouterOnly`;
    /// for a strict zone, only when the centre's public host sits in the
    /// zone's countries. A missing entry is `false` (fail closed).
    zone_central_relay_ok: HashMap<String, bool>,
    geoip: Option<Arc<GeoIp>>,
    captured_at_ms: i64,
}

impl std::fmt::Debug for TenantZoneSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantZoneSnapshot")
            .field("revision", &self.revision)
            .field("zones", &self.zones)
            .field("read_failed", &self.read_failed)
            .field("superseded", &self.superseded)
            .finish_non_exhaustive()
    }
}

impl TenantZoneSnapshot {
    pub fn empty(revision: u64) -> Self {
        Self {
            revision,
            ..Self::default()
        }
    }

    pub fn failed() -> Self {
        Self {
            read_failed: true,
            ..Self::default()
        }
    }

    pub fn superseded() -> Self {
        Self {
            superseded: true,
            ..Self::default()
        }
    }

    pub fn has_zones(&self) -> bool {
        !self.zones.is_empty()
    }

    pub fn from_parts(
        state: &NetworkState,
        revision: u64,
        zones: Vec<NetworkZone>,
        active_agents: &[Agent],
    ) -> Self {
        let captured_at_ms = bson::DateTime::now().timestamp_millis();
        let mut agents = HashMap::with_capacity(active_agents.len());
        let mut serving_countries: HashMap<ObjectId, Option<String>> = HashMap::new();
        for a in active_agents {
            let Some(aid) = a.id else { continue };
            let cc = agent_effective_country(&state.fleet, a);
            let phys_cc = physical_ip_country(&state.fleet, a.physical_public_ip.as_deref());
            if a.peer_relay_policy.serve {
                serving_countries.insert(aid, cc.clone());
            }
            agents.insert(
                aid,
                AgentZoneFacts {
                    pinned_zone_id: a.pinned_zone_id.clone(),
                    country_code: cc,
                    physical_country: phys_cc,
                    physical_seen_at_ms: a.physical_seen_at.map(|dt| dt.timestamp_millis()),
                    default_route_vpn: a.capabilities.default_route_vpn,
                    last_clean_zone_id: a.last_clean_zone_id.clone(),
                },
            );
        }
        if zones.is_empty() {
            return Self {
                revision,
                zones,
                read_failed: false,
                superseded: false,
                agents_loaded: true,
                agents,
                zone_gateways_ordered: HashMap::new(),
                zone_gateways: HashMap::new(),
                zone_infra_countries: HashMap::new(),
                zone_central_relay_ok: HashMap::new(),
                geoip: Some(state.core.geoip.clone()),
                captured_at_ms,
            };
        }
        let central = central_relay_url(state);

        let mut zone_gateways_ordered = HashMap::with_capacity(zones.len());
        let mut zone_gateways = HashMap::with_capacity(zones.len());
        let mut zone_infra_countries = HashMap::with_capacity(zones.len());
        let mut zone_central_relay_ok = HashMap::with_capacity(zones.len());
        for z in &zones {
            let mut ordered = Vec::new();
            let mut set = HashSet::new();
            let mut gateway_countries = Vec::new();
            for gw_hex in &z.gateway_relay_ids {
                if let Ok(gw_id) = ObjectId::parse_str(gw_hex)
                    && let Some(gw_cc) = serving_countries.get(&gw_id)
                {
                    if set.insert(gw_id) {
                        ordered.push(gw_id);
                    }
                    if let Some(cc) = gw_cc {
                        gateway_countries.push(cc.clone());
                    }
                }
            }
            zone_gateways_ordered.insert(z.id.clone(), ordered);
            zone_gateways.insert(z.id.clone(), set);
            let infra = meshharbor_mod_fleet::hub::zone_infra_countries(
                &z.auto_countries,
                gateway_countries,
            );
            zone_central_relay_ok.insert(
                z.id.clone(),
                z.cross_zone_mode != CrossZoneMode::RouterOnly
                    || url_matches_countries(state, &central, &infra),
            );
            zone_infra_countries.insert(z.id.clone(), infra);
        }

        Self {
            revision,
            zones,
            read_failed: false,
            superseded: false,
            agents_loaded: true,
            agents,
            zone_gateways_ordered,
            zone_gateways,
            zone_infra_countries,
            zone_central_relay_ok,
            geoip: Some(state.core.geoip.clone()),
            captured_at_ms,
        }
    }

    /// Linearizable double-checked snapshot loader (`net1 -> active_agents -> net2`
    /// with `net1.zone_revision == net2.zone_revision`, up to 5 attempts).
    /// Returns `Self::failed()` (`read_failed = true`) on DB I/O errors and
    /// `Self::superseded()` (`superseded = true`, `read_failed = false`) when
    /// concurrent `zone_revision` bumps race all 5 attempts.
    pub async fn load_consistent(state: &NetworkState, tenant_id: ObjectId) -> Self {
        for _ in 0..5 {
            let net1 = match state.overlay_networks.find_for_tenant(tenant_id).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(%tenant_id, %e, "network zones: overlay_networks read failed");
                    return Self::failed();
                }
            };
            let active_agents = match state.fleet.agents.list_all_active_for_tenant(tenant_id).await
            {
                Ok(rows) => rows,
                Err(e) => {
                    warn!(%tenant_id, %e, "network zones: active agents read failed");
                    return Self::failed();
                }
            };
            let net2 = match state.overlay_networks.find_for_tenant(tenant_id).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(%tenant_id, %e, "network zones: overlay_networks confirm read failed");
                    return Self::failed();
                }
            };
            match (net1, net2) {
                (None, None) => {
                    return Self::from_parts(state, 0, Vec::new(), &active_agents);
                }
                (Some(n1), Some(n2)) if n1.zone_revision == n2.zone_revision => {
                    return Self::from_parts(state, n1.zone_revision, n1.zones, &active_agents);
                }
                _ => continue,
            }
        }
        Self::superseded()
    }

    pub async fn load(state: &NetworkState, tenant_id: ObjectId) -> Self {
        let snap = Self::load_consistent(state, tenant_id).await;
        if snap.superseded {
            // Read-only callers (`derp_acl`, `business_isolation`, `path_candidate`)
            // check `read_failed` to fail closed on new admissions and preserve live tables.
            return Self::failed();
        }
        snap
    }

    async fn is_still_current_for_publish(&self, state: &NetworkState, tenant_id: ObjectId) -> bool {
        if self.read_failed || self.superseded {
            return false;
        }
        match state.overlay_networks.find_for_tenant(tenant_id).await {
            Ok(None) => self.revision == 0 && self.zones.is_empty(),
            Ok(Some(cur)) => {
                cur.zone_revision <= self.revision && (!self.zones.is_empty() || cur.zones.is_empty())
            }
            Err(_) => false,
        }
    }

    pub fn resolve_agent_with_source_and_fallback_country(
        &self,
        agent_id: ObjectId,
        fallback_cc: Option<&str>,
    ) -> (DeviceZoneResolution<'_>, Option<ZoneSource>) {
        if self.read_failed || self.superseded {
            return (DeviceZoneResolution::UnresolvedStrict, None);
        }
        if !self.has_zones() {
            return (DeviceZoneResolution::Unconfigured, None);
        }
        let Some(facts) = self.agents.get(&agent_id) else {
            return (DeviceZoneResolution::UnresolvedStrict, None);
        };
        let cc = facts.country_code.as_deref().or(fallback_cc);
        let now_ms = if self.captured_at_ms > 0 {
            self.captured_at_ms
        } else {
            bson::DateTime::now().timestamp_millis()
        };
        resolve_device_zone_with_source(
            &self.zones,
            &DeviceZoneInputs {
                pinned_zone_id: facts.pinned_zone_id.as_deref(),
                physical_country: facts.physical_country.as_deref(),
                physical_seen_at_ms: facts.physical_seen_at_ms,
                egress_country: cc,
                default_route_vpn: facts.default_route_vpn,
                last_clean_zone_id: facts.last_clean_zone_id.as_deref(),
                now_ms,
            },
        )
    }

    pub fn resolve_agent_with_source(
        &self,
        agent_id: ObjectId,
    ) -> (DeviceZoneResolution<'_>, Option<ZoneSource>) {
        self.resolve_agent_with_source_and_fallback_country(agent_id, None)
    }

    pub fn resolve_agent_with_fallback_country(
        &self,
        agent_id: ObjectId,
        fallback_cc: Option<&str>,
    ) -> DeviceZoneResolution<'_> {
        self.resolve_agent_with_source_and_fallback_country(agent_id, fallback_cc)
            .0
    }

    pub fn resolve_agent(&self, agent_id: ObjectId) -> DeviceZoneResolution<'_> {
        self.resolve_agent_with_fallback_country(agent_id, None)
    }

    pub fn resolve_node_sync<'a>(&'a self, node: &OverlayNode) -> DeviceZoneResolution<'a> {
        if self.read_failed || self.superseded {
            return DeviceZoneResolution::UnresolvedStrict;
        }
        if !self.has_zones() {
            return DeviceZoneResolution::Unconfigured;
        }
        let fallback_cc = self
            .geoip
            .as_deref()
            .and_then(|g| node_public_country_with_geoip(g, node));
        match &node.node_ref {
            NodeRef::Agent { agent_id } => {
                self.resolve_agent_with_fallback_country(*agent_id, fallback_cc.as_deref())
            }
            NodeRef::TunnelClient { .. } => {
                resolve_device_zone(&self.zones, None, fallback_cc.as_deref())
            }
        }
    }

    pub fn resolve_node<'a>(
        &'a self,
        _state: &NetworkState,
        node: &OverlayNode,
    ) -> DeviceZoneResolution<'a> {
        self.resolve_node_sync(node)
    }

    pub fn nodes_require_backbone_only_sync(&self, a: &OverlayNode, b: &OverlayNode) -> bool {
        Self::pair_requires_backbone_only(self.resolve_node_sync(a), self.resolve_node_sync(b))
    }

    pub async fn resolve_ref<'a>(
        &'a self,
        state: &NetworkState,
        tenant_id: ObjectId,
        node_ref: &NodeRef,
    ) -> DeviceZoneResolution<'a> {
        if self.read_failed || self.superseded {
            return DeviceZoneResolution::UnresolvedStrict;
        }
        if !self.has_zones() {
            return DeviceZoneResolution::Unconfigured;
        }
        match node_ref {
            NodeRef::Agent { agent_id } => self.resolve_agent(*agent_id),
            NodeRef::TunnelClient { tunnel_client_id } => {
                let cc = tunnel_client_country(state, tenant_id, *tunnel_client_id).await;
                resolve_device_zone(&self.zones, None, cc.as_deref())
            }
        }
    }

    /// Symmetric cross-zone strictness (Codex Invariant #5):
    /// - Legacy (`zones = []`): `false`
    /// - Same resolved zone (`za.id == zb.id`): `false`
    /// - Either endpoint `UnresolvedStrict` or `RouterOnly` across different zones: `true`
    /// - Different resolved zones where BOTH are `DirectPreferred`: `false`
    pub fn pair_requires_backbone_only(
        a: DeviceZoneResolution<'_>,
        b: DeviceZoneResolution<'_>,
    ) -> bool {
        match (a, b) {
            (DeviceZoneResolution::Unconfigured, DeviceZoneResolution::Unconfigured) => {
                false
            }
            (DeviceZoneResolution::UnresolvedStrict, _)
            | (_, DeviceZoneResolution::UnresolvedStrict) => true,
            (DeviceZoneResolution::Resolved(za), DeviceZoneResolution::Resolved(zb)) => {
                if za.id == zb.id {
                    false
                } else {
                    za.cross_zone_mode == CrossZoneMode::RouterOnly
                        || zb.cross_zone_mode == CrossZoneMode::RouterOnly
                }
            }
            _ => true,
        }
    }

    /// FR-124 — may a device of this resolution relay through the centre's
    /// `/derp`? A zone is a boundary: a strict zone's device uses only relays
    /// inside its countries, and the centre is one relay among them. No zones:
    /// yes; unresolved (or unreadable) under zones: no.
    pub fn central_relay_allowed(&self, res: DeviceZoneResolution<'_>) -> bool {
        match res {
            DeviceZoneResolution::Unconfigured => true,
            DeviceZoneResolution::UnresolvedStrict => false,
            DeviceZoneResolution::Resolved(z) => self
                .zone_central_relay_ok
                .get(&z.id)
                .copied()
                .unwrap_or(false),
        }
    }

    pub fn node_central_relay_allowed_sync(&self, node: &OverlayNode) -> bool {
        self.central_relay_allowed(self.resolve_node_sync(node))
    }

    /// FR-124 — may a device of this resolution relay through the DERP at
    /// `url` (`None` = the centre's)? A regional relay is judged by its own
    /// host's country, as STUN and TURN are.
    pub fn derp_url_allowed(
        &self,
        state: &NetworkState,
        res: DeviceZoneResolution<'_>,
        url: Option<&str>,
    ) -> bool {
        let Some(url) = url else {
            return self.central_relay_allowed(res);
        };
        match res {
            DeviceZoneResolution::Unconfigured => true,
            DeviceZoneResolution::UnresolvedStrict => false,
            DeviceZoneResolution::Resolved(_) => {
                let policy = self.ice_policy_for(res);
                !policy.strict || url_matches_countries(state, url, &policy.allowed_countries)
            }
        }
    }

    pub fn nodes_require_backbone_only(
        &self,
        state: &NetworkState,
        a: &OverlayNode,
        b: &OverlayNode,
    ) -> bool {
        Self::pair_requires_backbone_only(
            self.resolve_node(state, a),
            self.resolve_node(state, b),
        )
    }

    pub async fn refs_require_backbone_only(
        &self,
        state: &NetworkState,
        tenant_id: ObjectId,
        a: &NodeRef,
        b: &NodeRef,
    ) -> bool {
        let ra = self.resolve_ref(state, tenant_id, a).await;
        let rb = self.resolve_ref(state, tenant_id, b).await;
        Self::pair_requires_backbone_only(ra, rb)
    }

    /// Exact gateway relay `agent_id` set for a device when `zones` is configured.
    /// `None` means `zones` is empty (`LegacyUnrestricted`).
    pub fn gateway_set_for(&self, res: DeviceZoneResolution<'_>) -> Option<HashSet<ObjectId>> {
        match res {
            DeviceZoneResolution::Unconfigured => None,
            DeviceZoneResolution::UnresolvedStrict => Some(HashSet::new()),
            DeviceZoneResolution::Resolved(z) => {
                Some(self.zone_gateways.get(&z.id).cloned().unwrap_or_default())
            }
        }
    }

    pub fn gateway_order_for(&self, res: DeviceZoneResolution<'_>) -> Option<&[ObjectId]> {
        match res {
            DeviceZoneResolution::Unconfigured => None,
            DeviceZoneResolution::UnresolvedStrict => Some(&[]),
            DeviceZoneResolution::Resolved(z) => Some(
                self.zone_gateways_ordered
                    .get(&z.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            ),
        }
    }

    pub fn ice_policy_for(&self, res: DeviceZoneResolution<'_>) -> AgentZoneIcePolicy {
        let zones = self.zone_route_infos();
        match res {
            DeviceZoneResolution::Unconfigured => AgentZoneIcePolicy {
                policy_revision: self.revision,
                strict: false,
                allowed_countries: HashSet::new(),
                zone: None,
                zones: Arc::new(Vec::new()),
            },
            DeviceZoneResolution::UnresolvedStrict => AgentZoneIcePolicy {
                policy_revision: self.revision,
                strict: true,
                allowed_countries: HashSet::new(),
                zone: None,
                zones,
            },
            DeviceZoneResolution::Resolved(z) => AgentZoneIcePolicy {
                policy_revision: self.revision,
                strict: z.cross_zone_mode == CrossZoneMode::RouterOnly,
                allowed_countries: self
                    .zone_infra_countries
                    .get(&z.id)
                    .cloned()
                    .unwrap_or_default(),
                zone: Some(z.id.clone()),
                zones,
            },
        }
    }

    /// FR-121 — the tenant's zones as the hub routes a remote-desktop session.
    pub fn zone_route_infos(&self) -> Arc<Vec<meshharbor_mod_fleet::hub::ZoneRouteInfo>> {
        meshharbor_mod_fleet::hub::zone_route_infos(&self.zones)
    }

    /// Filter overlay `stun_urls` for `node` and return `(filtered_urls, strict_stun)`.
    pub fn filter_stun_urls_for_node(
        &self,
        state: &NetworkState,
        node: &OverlayNode,
        stun_urls: Vec<String>,
    ) -> (Vec<String>, bool) {
        if self.read_failed || self.superseded {
            return (Vec::new(), true);
        }
        if !self.has_zones() {
            return (stun_urls, false);
        }
        let policy = self.ice_policy_for(self.resolve_node(state, node));
        if !policy.strict {
            return (stun_urls, false);
        }
        let kept = stun_urls
            .into_iter()
            .filter(|u| url_matches_countries(state, u, &policy.allowed_countries))
            .collect();
        (kept, true)
    }

    async fn sync_hub_policy_for_agent_locked(
        &self,
        state: &NetworkState,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) {
        if !self.is_still_current_for_publish(state, tenant_id).await {
            return;
        }
        let policy = self.ice_policy_for(self.resolve_agent(agent_id));
        let countries_vec: Vec<String> = policy.allowed_countries.iter().cloned().collect();
        if state
            .fleet
            .rc_hub
            .set_agent_zone_ice_policy(agent_id, policy.clone())
        {
            state
                .fleet
                .rc_hub
                .push_relay_regions_for_agent(tenant_id, agent_id);
        }
        meshharbor_mod_fleet::ctrl::publish_rc_ctrl(
            &state.fleet,
            "zone_policy",
            serde_json::json!({
                "tenant_id": tenant_id.to_hex(),
                "agent_id": agent_id.to_hex(),
                "policy_revision": policy.policy_revision,
                "strict": policy.strict,
                "allowed_countries": countries_vec,
                "zone": policy.zone_json().0,
                "zones": policy.zone_json().1,
            }),
        )
        .await;
    }

    /// Push revisioned Hub ICE policy + `RelayRegions` to a single agent (local + cross-pod).
    pub async fn sync_hub_policy_for_agent(
        &self,
        state: &NetworkState,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) {
        if self.read_failed || self.superseded {
            return;
        }
        let lock = tenant_zone_publish_lock(tenant_id);
        let _guard = lock.lock().await;
        self.sync_hub_policy_for_agent_locked(state, tenant_id, agent_id)
            .await;
    }

    pub fn same_resolved_zone(&self, agent_a: ObjectId, agent_b: ObjectId) -> bool {
        if !self.has_zones() || self.read_failed || self.superseded {
            return false;
        }
        matches!(
            (self.resolve_agent(agent_a), self.resolve_agent(agent_b)),
            (DeviceZoneResolution::Resolved(za), DeviceZoneResolution::Resolved(zb)) if za.id == zb.id
        )
    }

    /// FR-125 — does a link between relays `agent_a` and `agent_b` join
    /// exactly the zones `zone_x` and `zone_y`, in either direction? The one
    /// rule an automatic crossing obeys, checked when it is built
    /// (`path_candidate`) and again whenever the installed session is reused.
    pub fn link_joins_zones(
        &self,
        agent_a: ObjectId,
        agent_b: ObjectId,
        zone_x: &str,
        zone_y: &str,
    ) -> bool {
        if !self.has_zones() || self.read_failed || self.superseded {
            return false;
        }
        let (DeviceZoneResolution::Resolved(za), DeviceZoneResolution::Resolved(zb)) =
            (self.resolve_agent(agent_a), self.resolve_agent(agent_b))
        else {
            return false;
        };
        (za.id == zone_x && zb.id == zone_y) || (za.id == zone_y && zb.id == zone_x)
    }

    /// Compute effective `backbone_endpoints` for serving relay `agent` (explicit
    /// `approved_backbone_edges` plus synthesized same-zone router endpoints when
    /// `OverlayNetwork.zones` is non-empty).
    pub async fn effective_backbone_endpoints_for_relay(
        &self,
        state: &NetworkState,
        tenant_id: ObjectId,
        agent: &Agent,
    ) -> Vec<String> {
        if !agent.peer_relay_policy.serve || agent.id.is_none() {
            return Vec::new();
        }
        let overlay_cidr = state
            .overlay_networks
            .find_for_tenant(tenant_id)
            .await
            .ok()
            .flatten()
            .map(|n| n.cidr)
            .unwrap_or_else(|| "100.64.0.0/10".to_string());
        let mut relays = Vec::new();
        let mut live_nodes = HashMap::new();
        if self.has_zones() && !self.read_failed && !self.superseded
            && let Ok(rows) = state.fleet.agents.list_relay_approved(tenant_id).await
        {
            for peer in &rows {
                let Some(peer_aid) = peer.id else { continue };
                if let Ok(Some(node)) = state
                    .overlay_nodes
                    .find_live_by_tenant_and_machine(tenant_id, &peer.machine_id)
                    .await
                {
                    live_nodes.insert(peer_aid, node);
                }
            }
            relays = rows;
        }
        self.effective_backbone_endpoints_from_consistent_parts(
            state,
            &overlay_cidr,
            agent,
            &relays,
            &live_nodes,
        )
    }

    fn effective_backbone_endpoints_from_consistent_parts(
        &self,
        state: &NetworkState,
        overlay_cidr: &str,
        agent: &Agent,
        relays: &[Agent],
        live_nodes: &HashMap<ObjectId, OverlayNode>,
    ) -> Vec<String> {
        use meshharbor_remote_control::models::{
            MAX_PEER_RELAY_BACKBONE_EDGES, peer_relay_limits as limits,
        };
        if !agent.peer_relay_policy.serve {
            return Vec::new();
        }
        let Some(own_id) = agent.id else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        let mut explicit_targets = HashSet::new();
        for edge in agent
            .peer_relay_policy
            .approved_backbone_edges
            .iter()
            .take(MAX_PEER_RELAY_BACKBONE_EDGES)
        {
            if let Ok(tid) = ObjectId::parse_str(&edge.relay_agent_id) {
                explicit_targets.insert(tid);
            }
            if crate::routes::peer_relay::valid_backbone_endpoint(&edge.endpoint)
                && crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                    &edge.endpoint,
                    overlay_cidr,
                )
                && !out.contains(&edge.endpoint)
            {
                out.push(edge.endpoint.clone());
            }
        }
        if !self.has_zones() || self.read_failed || self.superseded {
            return out;
        }
        let DeviceZoneResolution::Resolved(own_zone) = self.resolve_agent(own_id) else {
            return out;
        };
        let auto_links = crate::org_relay::relay_auto_links(state);
        // Each other relay's valid endpoints, and whether it shares our zone.
        let mut per_relay: Vec<(bool, Vec<String>)> = Vec::new();
        for peer in relays {
            let Some(peer_aid) = peer.id else { continue };
            if peer_aid == own_id || explicit_targets.contains(&peer_aid) {
                continue;
            }
            let DeviceZoneResolution::Resolved(peer_zone) = self.resolve_agent(peer_aid) else {
                continue;
            };
            let same_zone = peer_zone.id == own_zone.id;
            // FR-125: with auto links a relay may dial any other relay, in
            // any zone; the zone rule is applied where a pair's path is built.
            if !same_zone && !auto_links {
                continue;
            }
            let mut candidate_eps: Vec<String> = Vec::new();
            if let Some(node) = live_nodes.get(&peer_aid) {
                let port = node
                    .id
                    .and_then(|nid| state.org_relay.relay_port_of(nid))
                    .unwrap_or(limits::DEFAULT_RELAY_PORT);
                if let Ok(eps) = crate::org_relay::relay_endpoints(
                    node,
                    port,
                    &peer.peer_relay_policy.static_endpoints,
                ) {
                    candidate_eps.extend(eps);
                }
            } else {
                candidate_eps.extend(peer.peer_relay_policy.static_endpoints.iter().cloned());
            }
            if candidate_eps.is_empty()
                && let Some(pub_ip) = peer
                    .public_ip
                    .as_deref()
                    .and_then(|s| s.parse::<IpAddr>().ok())
                    .and_then(canonical_public_ip)
            {
                candidate_eps.push(
                    std::net::SocketAddr::new(pub_ip, limits::DEFAULT_RELAY_PORT).to_string(),
                );
            }
            let valid: Vec<String> = candidate_eps
                .into_iter()
                .filter(|ep| {
                    crate::routes::peer_relay::valid_backbone_endpoint(ep)
                        && crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                            ep,
                            overlay_cidr,
                        )
                })
                .collect();
            per_relay.push((same_zone, valid));
        }
        let push = |out: &mut Vec<String>, ep: &String| {
            if out.len() < MAX_PEER_RELAY_BACKBONE_EDGES && !out.contains(ep) {
                out.push(ep.clone());
            }
        };
        // The pre-FR-125 entries first — each same-zone relay's first
        // endpoint — so nothing FR-125 adds can crowd one out.
        for (same_zone, valid) in &per_relay {
            if *same_zone && let Some(ep) = valid.first() {
                push(&mut out, ep);
            }
        }
        // FR-125: then every relay's further endpoints, up to four per relay
        // (an address that admits nobody may come first); a crossing only
        // ever dials a public address.
        if auto_links {
            for (same_zone, valid) in &per_relay {
                for ep in valid
                    .iter()
                    .filter(|ep| *same_zone || crate::org_relay::valid_static_endpoint(ep))
                    .take(4)
                {
                    push(&mut out, ep);
                }
            }
        }
        out
    }

    /// Push composite-revisioned `ServerMsg::PeerRelayServe` from a version-consistent
    /// `(net_before -> active_agents + relays + live overlay_nodes -> net_after)` snapshot
    /// (`net_before.zone_revision == net_after.zone_revision`), serialized per tenant and
    /// fenced before publication.
    pub async fn sync_relay_backbone_endpoints_at_current_revision(
        &self,
        state: &NetworkState,
        tenant_id: ObjectId,
        include_agent: Option<ObjectId>,
    ) {
        if self.read_failed || self.superseded {
            return;
        }
        let lock = tenant_zone_publish_lock(tenant_id);
        let _guard = lock.lock().await;

        let mut consistent_state = None;
        for _ in 0..5 {
            let net_before = match state.overlay_networks.find_for_tenant(tenant_id).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let Ok(active_agents) = state.fleet.agents.list_all_active_for_tenant(tenant_id).await
            else {
                return;
            };
            let relays: Vec<Agent> = active_agents
                .iter()
                .filter(|a| a.peer_relay_policy.serve)
                .cloned()
                .collect();
            let has_zones = net_before.as_ref().is_some_and(|n| !n.zones.is_empty());
            let mut live_nodes = HashMap::new();
            if has_zones {
                let mut node_err = false;
                for peer in &relays {
                    let Some(peer_aid) = peer.id else { continue };
                    match state
                        .overlay_nodes
                        .find_live_by_tenant_and_machine(tenant_id, &peer.machine_id)
                        .await
                    {
                        Ok(Some(node)) => {
                            live_nodes.insert(peer_aid, node);
                        }
                        Ok(None) => {}
                        Err(_) => {
                            node_err = true;
                            break;
                        }
                    }
                }
                if node_err {
                    return;
                }
            }
            let net_after = match state.overlay_networks.find_for_tenant(tenant_id).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let matched = match (&net_before, &net_after) {
                (None, None) => true,
                (Some(a), Some(b)) => a.zone_revision == b.zone_revision,
                _ => false,
            };
            if matched {
                consistent_state = Some((net_before, active_agents, relays, live_nodes));
                break;
            }
        }
        let Some((net, active_agents, relays, live_nodes)) = consistent_state else {
            return;
        };
        let zone_rev = net.as_ref().map(|n| n.zone_revision).unwrap_or(0);
        let zones = net.as_ref().map(|n| n.zones.clone()).unwrap_or_default();
        let overlay_cidr = net
            .as_ref()
            .map(|n| n.cidr.as_str())
            .unwrap_or("100.64.0.0/10");
        let snap = Self::from_parts(state, zone_rev, zones, &active_agents);

        // Republish ALL approved serving relays even when `zones` becomes empty (`[]`),
        // so removing the final zone immediately replaces synthesized same-zone endpoints
        // with each router's explicit-only `approved_backbone_edges`.
        let mut targets: Vec<Agent> = relays.clone();
        if let Some(extra_aid) = include_agent
            && !targets.iter().any(|r| r.id == Some(extra_aid))
            && let Some(extra_row) = active_agents.iter().find(|a| a.id == Some(extra_aid))
        {
            targets.push(extra_row.clone());
        }

        for relay in &targets {
            let Some(aid) = relay.id else { continue };
            let still_current = match state.overlay_networks.find_for_tenant(tenant_id).await {
                Ok(None) => zone_rev == 0 && !snap.has_zones(),
                Ok(Some(cur)) => {
                    cur.zone_revision <= zone_rev && (snap.has_zones() || cur.zones.is_empty())
                }
                Err(_) => false,
            };
            if !still_current {
                return;
            }
            let endpoints = snap.effective_backbone_endpoints_from_consistent_parts(
                state,
                overlay_cidr,
                relay,
                &relays,
                &live_nodes,
            );
            let rev = effective_peer_relay_serve_revision(zone_rev, relay.peer_relay_revision);
            state.fleet.rc_hub.push_peer_relay_serve(
                tenant_id,
                aid,
                relay.peer_relay_policy.serve,
                Some(rev),
                endpoints.clone(),
            );
            meshharbor_mod_fleet::ctrl::publish_rc_ctrl(
                &state.fleet,
                "peer_relay_serve",
                serde_json::json!({
                    "tenant_id": tenant_id.to_hex(),
                    "agent_id": aid.to_hex(),
                    "serve": relay.peer_relay_policy.serve,
                    "revision": rev,
                    "backbone_endpoints": endpoints,
                }),
            )
            .await;
        }
    }

    /// Re-push `ServerMsg::PeerRelayServe` with up-to-date `backbone_endpoints`
    /// (explicit + same-zone router mesh) to all active serving relays in `tenant_id`
    /// after bumping `zone_revision` so dynamic endpoint refreshes advance monotonically.
    pub async fn sync_relay_backbone_endpoints_for_tenant(
        &self,
        state: &NetworkState,
        tenant_id: ObjectId,
    ) {
        if self.read_failed || self.superseded {
            return;
        }
        if let Ok(Some(_)) = state.overlay_networks.find_for_tenant(tenant_id).await {
            let _ = state.overlay_networks.bump_zone_revision(tenant_id).await;
        }
        self.sync_relay_backbone_endpoints_at_current_revision(state, tenant_id, None)
            .await;
    }

    /// Push revisioned Hub ICE policy + `RelayRegions` to all active agents in `tenant_id`.
    pub async fn sync_hub_policies_for_tenant(&self, state: &NetworkState, tenant_id: ObjectId) {
        if self.read_failed || self.superseded {
            return;
        }
        let lock = tenant_zone_publish_lock(tenant_id);
        let _guard = lock.lock().await;
        if !self.is_still_current_for_publish(state, tenant_id).await {
            return;
        }
        let ids: Vec<ObjectId> = if self.agents_loaded {
            self.agents.keys().copied().collect()
        } else {
            match state.fleet.agents.list_all_active_for_tenant(tenant_id).await {
                Ok(rows) => rows.into_iter().filter_map(|a| a.id).collect(),
                Err(_) => return,
            }
        };
        for aid in ids {
            self.sync_hub_policy_for_agent_locked(state, tenant_id, aid)
                .await;
        }
    }
}

/// FR-124 — the URL the centre's `/derp` is reached at: the deployment's
/// public origin, whose host the ICE-zone refresh resolves and geolocates
/// (`meshharbor_core::ice_zones::spawn_refresh`, fleet's boot).
pub fn central_relay_url(state: &NetworkState) -> String {
    state.core.settings.app.frontend_url.clone()
}

pub fn url_matches_countries(
    state: &NetworkState,
    url: &str,
    allowed: &HashSet<String>,
) -> bool {
    if allowed.is_empty() {
        return false;
    }
    if state.fleet.rc_hub.url_matches_allowed_countries(url, allowed) {
        return true;
    }
    if let Some((host, _)) = host_of(url)
        && let Ok(ip) = host.parse::<IpAddr>()
        && let Some(clean) = canonical_public_ip(ip)
    {
        return state
            .core
            .geoip
            .security_lookup(clean)
            .country_code
            .is_some_and(|cc| allowed.contains(&cc.to_ascii_uppercase()));
    }
    false
}

pub fn node_public_country_with_geoip(geoip: &GeoIp, node: &OverlayNode) -> Option<String> {
    for ep in node.srflx_endpoints.iter().chain(node.lan_endpoints.iter()) {
        if let Ok(sa) = ep.parse::<std::net::SocketAddr>()
            && let Some(ip) = canonical_public_ip(sa.ip())
            && let Some(cc) = geoip.security_lookup(ip).country_code
        {
            return Some(cc.to_ascii_uppercase());
        }
    }
    None
}

pub fn node_public_country(state: &NetworkState, node: &OverlayNode) -> Option<String> {
    node_public_country_with_geoip(&state.core.geoip, node)
}

async fn tunnel_client_country(
    state: &NetworkState,
    tenant_id: ObjectId,
    tunnel_client_id: ObjectId,
) -> Option<String> {
    let client = state
        .tunnel_clients
        .find_live_in_tenant(tenant_id, tunnel_client_id)
        .await
        .ok()?;
    if let Ok(Some(node)) = state
        .overlay_nodes
        .find_live_by_tenant_and_machine(tenant_id, &client.machine_id)
        .await
        && let Some(cc) = node_public_country(state, &node)
    {
        return Some(cc);
    }
    if let Some(conn) = state.org_relay.live_conn(tunnel_client_id)
        && let Ok(dev) = AuthenticatedDevice::from_tunnel_client(&client)
        && let Some(bz) = connection_zone(&state.core, &dev, &conn)
    {
        return match bz {
            meshharbor_core::business_authority::BusinessZone::Mainland => Some("CN".to_string()),
            meshharbor_core::business_authority::BusinessZone::NonMainland => None,
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superseded_and_failed_snapshots_stay_distinct_while_both_fail_closed_on_resolution() {
        let failed = TenantZoneSnapshot::failed();
        assert!(failed.read_failed);
        assert!(!failed.superseded);
        assert_eq!(
            failed.resolve_agent(ObjectId::new()),
            DeviceZoneResolution::UnresolvedStrict
        );

        let superseded = TenantZoneSnapshot::superseded();
        assert!(!superseded.read_failed);
        assert!(superseded.superseded);
        assert_eq!(
            superseded.resolve_agent(ObjectId::new()),
            DeviceZoneResolution::UnresolvedStrict
        );
    }
}
