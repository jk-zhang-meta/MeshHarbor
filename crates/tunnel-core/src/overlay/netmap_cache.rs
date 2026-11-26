// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Signed local netmap cache envelope, verification, offline replay
//! sanitization, authority-narrowing detection, and bounded endpoint recovery.
//!
//! Pure module (no filesystem I/O, no ambient wall clock — every timestamp is
//! passed explicitly so unit tests are deterministic).
//!
//! Security invariants:
//! 1. **Identity-bound integrity**: HMAC-SHA256 key is derived via RFC 5869
//!    HKDF-SHA256 from this node's local WireGuard private key +
//!    `(tenant_id, self_wg_pubkey, node_id)`. Copying a cache file across
//!    tenants, nodes, or rotated keys always fails MAC verification.
//! 2. **Anti-rollback & bounded age**: `last_authoritative_at_ms` and
//!    `last_authoritative_revision` are updated ONLY on server-authoritative
//!    netmaps/deltas — NEVER on offline restarts or learned-endpoint flushes.
//!    `monotonic_clock_floor_ms` prevents bypassing max-age expiry by setting
//!    the system clock backward.
//! 3. **Exact policy fidelity on offline replay**: `sanitize_for_offline_replay`
//!    overrides `reachable = true` ONLY for `!backbone_only` peers, preserves
//!    `backbone_only`, `central_relay_denied`, and `Some(vec![])` vs `None`
//!    `ingress_rules` verbatim, and strips stale relay-only state
//!    (`endpoints`, `warm_relay_endpoint`, `relay_strategy`, `prefer_relay_ms`).
//! 4. **Immediate flush on authority reduction**: `is_authority_reducing` and
//!    `delta_is_authority_reducing` detect dropped peers, tighter/changed
//!    `ingress_rules`, newly set `backbone_only`, lost routes, key/IP changes,
//!    or tighter network flags so the agent flushes synchronously instead of
//!    waiting for any write debounce.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bson::oid::ObjectId;
use hmac::{Hmac, Mac};
use meshharbor_remote_control::signaling::{NetmapPeer, OverlayNetworkInfo};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::candidates::{LanCandidate, LanEgress, LanPathKind};
use super::direct::{
    DEFAULT_DIRECT_PORT, DIRECT_PORT_BAND, PUBLIC_DIAL_PORT_OFFSET, SECOND_BAND_OFFSET,
};
use super::netmap::PeerConfig;

type HmacSha256 = Hmac<Sha256>;

/// Envelope / payload schema version.
pub const CACHE_SCHEMA_VERSION: u32 = 1;

/// Default maximum offline cache age in days (config `overlay_netmap_cache_max_days`).
pub const DEFAULT_MAX_CACHE_AGE_DAYS: u32 = 14;

/// Default maximum offline cache age in milliseconds (14 days).
pub const DEFAULT_MAX_CACHE_AGE_MS: u64 = DEFAULT_MAX_CACHE_AGE_DAYS as u64 * 86_400 * 1_000;

/// Small NTP slew tolerance before treating wall-clock regression as rollback.
pub const CLOCK_ROLLBACK_TOLERANCE_MS: u64 = 60_000;

/// Maximum learned direct endpoints persisted per peer.
pub const MAX_LEARNED_PER_PEER: usize = 4;

/// Maximum bounded offline endpoint-recovery candidates generated per peer.
pub const MAX_OFFLINE_RECOVERY_CANDIDATES: usize = 16;

const HKDF_SALT: &[u8] = b"meshharbor/netmap-cache/v1";
const MAC_DOMAIN: &[u8] = b"meshharbor/netmap-cache-mac/v1\0";

/// Node & tenant identity bound cryptographically into the cache MAC key and
/// checked against the signed payload on open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheIdentity<'a> {
    pub tenant_id: &'a str,
    pub node_id: &'a str,
    pub self_wg_pubkey: &'a str,
}

/// One Disco-verified direct endpoint persisted alongside the cached netmap so
/// cold offline boot can probe a peer's last known LAN/loopback address before
/// falling back to bounded port-band recovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LearnedPeerEndpoint {
    pub addr: String,
    pub last_verified_at_ms: u64,
}

/// Signed netmap cache payload stored inside [`SignedNetmapCache`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetmapCachePayload {
    pub schema_version: u32,
    pub tenant_id: String,
    pub node_id: String,
    pub self_wg_pubkey: String,
    pub self_ip: String,
    pub network: OverlayNetworkInfo,
    pub peers: Vec<NetmapPeer>,
    /// Last server-authoritative `auth_revision` applied before writing.
    /// Offline restarts and learned-endpoint flushes MUST preserve this value.
    pub last_authoritative_revision: u64,
    /// Wall-clock epoch ms when the last server-authoritative full netmap or
    /// delta was received. Offline restarts and learned-endpoint flushes MUST
    /// NEVER extend this timestamp.
    pub last_authoritative_at_ms: u64,
    /// Monotonic wall-clock high-water mark (`max(prev_floor, now_ms)`).
    /// Defeats setting the host clock backward to bypass max-age expiry.
    pub monotonic_clock_floor_ms: u64,
    /// Bounded last-verified direct LAN/loopback endpoints keyed by peer
    /// `node_id` hex string (deterministic `BTreeMap` order).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub learned_endpoints: BTreeMap<String, Vec<LearnedPeerEndpoint>>,
}

/// Integrity-protected on-disk envelope.
///
/// The exact `payload_json` string is authenticated so field ordering or serde
/// whitespace differences can never introduce canonicalization bugs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedNetmapCache {
    pub version: u32,
    pub payload_json: String,
    pub mac_hex: String,
}

/// Verification / sealing failure reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CacheError {
    #[error("unsupported netmap cache version {0}")]
    UnsupportedVersion(u32),
    #[error("netmap cache MAC verification failed")]
    InvalidMac,
    #[error("netmap cache payload decode failed: {0}")]
    InvalidPayload(String),
    #[error("netmap cache identity mismatch")]
    IdentityMismatch,
    #[error("netmap cache refused: wall clock rolled back below monotonic floor")]
    ClockRollback,
    #[error("netmap cache expired (age {age_ms} ms > max {max_age_ms} ms)")]
    Expired { age_ms: u64, max_age_ms: u64 },
    #[error("netmap cache stale (revision {cached} < minimum {min_required})")]
    StaleRevision { cached: u64, min_required: u64 },
    #[error("netmap cache contains invalid self_ip or network cidr")]
    InvalidNetworkState,
}

/// RFC 5869 HKDF-SHA256 (Extract + single-block Expand) binding the cache MAC
/// key to the node's WireGuard private key and `(tenant_id, self_wg_pubkey, node_id)`.
pub fn derive_cache_mac_key(wg_secret: &[u8; 32], id: &CacheIdentity<'_>) -> [u8; 32] {
    // HKDF-Extract(salt, IKM)
    let mut extract =
        <HmacSha256 as Mac>::new_from_slice(HKDF_SALT).expect("HMAC-SHA256 accepts any key size");
    extract.update(wg_secret);
    let prk: [u8; 32] = extract.finalize().into_bytes().into();

    // HKDF-Expand(PRK, info, 32) -> T(1) = HMAC(PRK, info || 0x01)
    let mut expand =
        <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC-SHA256 accepts any key size");
    expand.update(HKDF_SALT);
    expand.update(&[0u8]);
    expand.update(id.tenant_id.as_bytes());
    expand.update(&[0u8]);
    expand.update(id.self_wg_pubkey.as_bytes());
    expand.update(&[0u8]);
    expand.update(id.node_id.as_bytes());
    expand.update(&[1u8]);
    expand.finalize().into_bytes().into()
}

fn compute_envelope_mac(key: &[u8; 32], payload_json: &str) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key size");
    mac.update(MAC_DOMAIN);
    mac.update(payload_json.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Normalize & bound `learned_endpoints` before sealing: keep only peers
/// present in `peers`, valid private/loopback `SocketAddr`s, deduplicated by
/// address (freshest timestamp wins), capped at [`MAX_LEARNED_PER_PEER`].
pub fn bound_learned_endpoints(
    peers: &[NetmapPeer],
    raw: &BTreeMap<String, Vec<LearnedPeerEndpoint>>,
) -> BTreeMap<String, Vec<LearnedPeerEndpoint>> {
    let valid_ids: HashSet<String> = peers
        .iter()
        .filter(|p| !p.backbone_only)
        .map(|p| p.node_id.to_hex())
        .collect();
    let mut out = BTreeMap::new();
    for (nid, list) in raw {
        if !valid_ids.contains(nid) {
            continue;
        }
        let mut by_addr: HashMap<SocketAddr, u64> = HashMap::new();
        for item in list {
            let Ok(sa) = item.addr.parse::<SocketAddr>() else {
                continue;
            };
            if !is_cacheable_direct_addr(sa) {
                continue;
            }
            by_addr
                .entry(sa)
                .and_modify(|ts| *ts = (*ts).max(item.last_verified_at_ms))
                .or_insert(item.last_verified_at_ms);
        }
        let mut entries: Vec<(SocketAddr, u64)> = by_addr.into_iter().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries.truncate(MAX_LEARNED_PER_PEER);
        if !entries.is_empty() {
            out.insert(
                nid.clone(),
                entries
                    .into_iter()
                    .map(|(sa, ts)| LearnedPeerEndpoint {
                        addr: sa.to_string(),
                        last_verified_at_ms: ts,
                    })
                    .collect(),
            );
        }
    }
    out
}

fn is_cacheable_direct_addr(sa: SocketAddr) -> bool {
    if sa.port() == 0 {
        return false;
    }
    match sa.ip() {
        IpAddr::V4(v4) => v4.is_loopback() || super::direct::is_rfc1918(v4) || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

/// Seal a [`NetmapCachePayload`] into a [`SignedNetmapCache`] bound to `id`.
pub fn seal(
    wg_secret: &[u8; 32],
    id: &CacheIdentity<'_>,
    payload: &NetmapCachePayload,
) -> Result<SignedNetmapCache, CacheError> {
    if payload.schema_version != CACHE_SCHEMA_VERSION {
        return Err(CacheError::UnsupportedVersion(payload.schema_version));
    }
    if payload.tenant_id != id.tenant_id
        || payload.node_id != id.node_id
        || payload.self_wg_pubkey != id.self_wg_pubkey
    {
        return Err(CacheError::IdentityMismatch);
    }
    if payload.self_ip.parse::<Ipv4Addr>().is_err() || payload.network.cidr.trim().is_empty() {
        return Err(CacheError::InvalidNetworkState);
    }
    let mut normalized = payload.clone();
    normalized.learned_endpoints =
        bound_learned_endpoints(&normalized.peers, &normalized.learned_endpoints);
    let payload_json =
        serde_json::to_string(&normalized).map_err(|e| CacheError::InvalidPayload(e.to_string()))?;
    let key = derive_cache_mac_key(wg_secret, id);
    let mac = compute_envelope_mac(&key, &payload_json);
    Ok(SignedNetmapCache {
        version: CACHE_SCHEMA_VERSION,
        payload_json,
        mac_hex: hex::encode(mac),
    })
}

/// Verify MAC, identity binding, monotonic clock floor, max age, and minimum
/// revision floor before returning the authenticated [`NetmapCachePayload`].
pub fn open_and_verify(
    wg_secret: &[u8; 32],
    expected_id: &CacheIdentity<'_>,
    envelope: &SignedNetmapCache,
    now_ms: u64,
    max_age_ms: u64,
    min_authoritative_revision: Option<u64>,
) -> Result<NetmapCachePayload, CacheError> {
    if envelope.version != CACHE_SCHEMA_VERSION {
        return Err(CacheError::UnsupportedVersion(envelope.version));
    }
    let decoded_mac = hex::decode(envelope.mac_hex.trim()).map_err(|_| CacheError::InvalidMac)?;
    if decoded_mac.len() != 32 {
        return Err(CacheError::InvalidMac);
    }
    let key = derive_cache_mac_key(wg_secret, expected_id);
    let expected_mac = compute_envelope_mac(&key, &envelope.payload_json);
    if !bool::from(decoded_mac.as_slice().ct_eq(&expected_mac)) {
        return Err(CacheError::InvalidMac);
    }
    let payload: NetmapCachePayload = serde_json::from_str(&envelope.payload_json)
        .map_err(|e| CacheError::InvalidPayload(e.to_string()))?;
    if payload.schema_version != CACHE_SCHEMA_VERSION {
        return Err(CacheError::UnsupportedVersion(payload.schema_version));
    }
    if payload.tenant_id != expected_id.tenant_id
        || payload.node_id != expected_id.node_id
        || payload.self_wg_pubkey != expected_id.self_wg_pubkey
    {
        return Err(CacheError::IdentityMismatch);
    }
    if payload.self_ip.parse::<Ipv4Addr>().is_err() || payload.network.cidr.trim().is_empty() {
        return Err(CacheError::InvalidNetworkState);
    }
    let floor = payload
        .monotonic_clock_floor_ms
        .max(payload.last_authoritative_at_ms);
    if now_ms.saturating_add(CLOCK_ROLLBACK_TOLERANCE_MS) < floor {
        return Err(CacheError::ClockRollback);
    }
    let age_ms = now_ms.saturating_sub(payload.last_authoritative_at_ms);
    if age_ms > max_age_ms {
        return Err(CacheError::Expired { age_ms, max_age_ms });
    }
    if let Some(min_required) = min_authoritative_revision
        && payload.last_authoritative_revision < min_required
    {
        return Err(CacheError::StaleRevision {
            cached: payload.last_authoritative_revision,
            min_required,
        });
    }
    Ok(payload)
}

/// Sanitize cached peers before handing them to `OverlayRuntime` on a cold
/// offline start:
///
/// * Strips ephemeral / server-only relay fields (`endpoints`,
///   `warm_relay_endpoint`, `relay_strategy`, `prefer_relay_ms`).
/// * Sets `reachable = true` ONLY for `!backbone_only` peers so live Disco / WG
///   probing decides peer reachability without waiting on the server.
/// * Preserves `backbone_only`, `ingress_rules` (`Some([])` vs `None`),
///   `ingress_rules_preview`, `routes`, `lan_endpoints`, `srflx_endpoints`, and
///   all identity fields verbatim.
pub fn sanitize_for_offline_replay(peers: &[NetmapPeer]) -> Vec<NetmapPeer> {
    peers
        .iter()
        .map(|orig| {
            let mut p = orig.clone();
            p.endpoints.clear();
            p.warm_relay_endpoint = None;
            p.relay_strategy = None;
            p.prefer_relay_ms = None;
            p.reachable = !p.backbone_only;
            p
        })
        .collect()
}

/// Sanitize cached `OverlayNetworkInfo` for offline cold boot while preserving
/// `central_relay_denied`, `strict_stun`, `cidr`, `cidrs`, `magic_domain`,
/// `self_name`, `nameservers`, and `auth_revision` verbatim.
pub fn sanitize_network_for_offline_replay(network: &OverlayNetworkInfo) -> OverlayNetworkInfo {
    let mut net = network.clone();
    net.org_relay_fallback_v1 = false;
    net.org_relay_loss_v1 = false;
    net.path_quality_v1 = false;
    net.relay_probe_targets.clear();
    net.backbone_probe_targets.clear();
    net
}

/// Extract parsed valid learned endpoints per peer `node_id` hex from a
/// verified cache payload.
pub fn learned_socket_addrs(
    payload: &NetmapCachePayload,
) -> BTreeMap<String, Vec<SocketAddr>> {
    let mut out = BTreeMap::new();
    for (nid, list) in &payload.learned_endpoints {
        let addrs: Vec<SocketAddr> = list
            .iter()
            .filter_map(|e| e.addr.parse::<SocketAddr>().ok())
            .filter(|&sa| is_cacheable_direct_addr(sa))
            .collect();
        if !addrs.is_empty() {
            out.insert(nid.clone(), addrs);
        }
    }
    out
}

/// Return `true` when `new` narrows or alters the security authority of `old`
/// for the same peer.
pub fn peer_authority_narrowed(old: &NetmapPeer, new: &NetmapPeer) -> bool {
    if old.wg_public_key != new.wg_public_key || old.overlay_ip != new.overlay_ip {
        return true;
    }
    if !old.backbone_only && new.backbone_only {
        return true;
    }
    // Any change to server-compiled ingress rules (including None -> Some([]),
    // Some(allow) -> Some([]), or rule edits) flushes immediately so a crash
    // cannot resurrect stale permissive rules.
    if old.ingress_rules != new.ingress_rules || old.ingress_rules_preview != new.ingress_rules_preview
    {
        return true;
    }
    // Any previously approved subnet/exit route removed from this peer.
    if old.routes.iter().any(|r| !new.routes.contains(r)) {
        return true;
    }
    false
}

/// Return `true` when a full netmap update reduces or narrows authority
/// relative to the previous state (requiring an immediate synchronous cache
/// flush bypassing write debounce).
pub fn is_authority_reducing(
    old_net: &OverlayNetworkInfo,
    old_peers: &HashMap<ObjectId, NetmapPeer>,
    new_net: &OverlayNetworkInfo,
    new_peers: &HashMap<ObjectId, NetmapPeer>,
) -> bool {
    if (!old_net.central_relay_denied && new_net.central_relay_denied)
        || (!old_net.strict_stun && new_net.strict_stun)
        || old_net.cidr != new_net.cidr
        || old_net.cidrs != new_net.cidrs
    {
        return true;
    }
    for (nid, old_peer) in old_peers {
        let Some(new_peer) = new_peers.get(nid) else {
            // Peer vanished / revoked / ACL'd out.
            return true;
        };
        if peer_authority_narrowed(old_peer, new_peer) {
            return true;
        }
    }
    false
}

/// Return `true` when an incremental netmap delta removes any peer or narrows
/// authority on any upserted peer (requiring an immediate synchronous flush).
pub fn delta_is_authority_reducing(
    old_peers: &HashMap<ObjectId, NetmapPeer>,
    upserts: &[NetmapPeer],
    removes: &[ObjectId],
) -> bool {
    if !removes.is_empty() {
        return true;
    }
    for new_peer in upserts {
        if let Some(old_peer) = old_peers.get(&new_peer.node_id)
            && peer_authority_narrowed(old_peer, new_peer)
        {
            return true;
        }
    }
    false
}

/// Given an observed peer direct port, derive the 8-port stable band base(s)
/// to scan when recovering from an offline peer restart that shifted within
/// its band or jumped to band 2 (`+512`).
fn recovery_ports_for(port: u16, include_public_band: bool) -> Vec<u16> {
    let mut ports = Vec::new();
    let base_band = if port >= DEFAULT_DIRECT_PORT
        && port < DEFAULT_DIRECT_PORT.saturating_add(1024)
    {
        let offset = port - DEFAULT_DIRECT_PORT;
        let slot_offset = offset % PUBLIC_DIAL_PORT_OFFSET;
        let aligned_slot = (slot_offset / DIRECT_PORT_BAND) * DIRECT_PORT_BAND;
        DEFAULT_DIRECT_PORT + aligned_slot
    } else {
        // Non-standard / custom direct port: probe a small +0..+3 neighborhood.
        for delta in 0..4u16 {
            if let Some(p) = port.checked_add(delta) {
                ports.push(p);
            }
        }
        return ports;
    };

    // Primary 8-port LAN band, then band-2 (+512) first 4 slots.
    for delta in 0..DIRECT_PORT_BAND {
        if let Some(p) = base_band.checked_add(delta) {
            ports.push(p);
        }
    }
    for delta in 0..4u16 {
        if let Some(p) = base_band
            .checked_add(SECOND_BAND_OFFSET)
            .and_then(|b| b.checked_add(delta))
        {
            ports.push(p);
        }
    }
    if include_public_band {
        for delta in 0..4u16 {
            if let Some(p) = base_band
                .checked_add(PUBLIC_DIAL_PORT_OFFSET)
                .and_then(|b| b.checked_add(delta))
            {
                ports.push(p);
            }
        }
        for delta in 0..2u16 {
            if let Some(p) = base_band
                .checked_add(SECOND_BAND_OFFSET)
                .and_then(|b| b.checked_add(PUBLIC_DIAL_PORT_OFFSET))
                .and_then(|b| b.checked_add(delta))
            {
                ports.push(p);
            }
        }
    }
    ports
}

/// Generate bounded Disco-only (`requires_disco = true`) recovery candidates
/// for an offline peer whose cached port may have shifted across a reboot.
///
/// Only probes private RFC 1918 / loopback IPs already known for this peer
/// (from `learned` hints or cached `lan_endpoints`) across its stable direct
/// port bands, strictly capped at [`MAX_OFFLINE_RECOVERY_CANDIDATES`] (16).
pub(crate) fn offline_recovery_candidates(
    peer: &PeerConfig,
    learned: &[SocketAddr],
    already_advertised: &[LanCandidate],
    classify: impl Fn(SocketAddr) -> Option<(LanEgress, LanPathKind)>,
) -> Vec<LanCandidate> {
    let mut seen: HashSet<SocketAddr> = already_advertised.iter().map(|c| c.dst).collect();
    let mut seeds: Vec<(IpAddr, u16)> = Vec::new();
    for &sa in learned {
        if is_cacheable_direct_addr(sa) && !seeds.iter().any(|(ip, _)| *ip == sa.ip()) {
            seeds.push((sa.ip(), sa.port()));
        }
    }
    for s in &peer.lan_endpoints {
        if let Ok(sa) = s.parse::<SocketAddr>()
            && is_cacheable_direct_addr(sa)
            && !seeds.iter().any(|(ip, _)| *ip == sa.ip())
        {
            seeds.push((sa.ip(), sa.port()));
        }
    }

    let mut out = Vec::new();
    for (ip, seed_port) in seeds {
        let include_public_band = ip.is_loopback();
        for port in recovery_ports_for(seed_port, include_public_band) {
            if out.len() >= MAX_OFFLINE_RECOVERY_CANDIDATES {
                return out;
            }
            let dst = SocketAddr::new(ip, port);
            if !seen.insert(dst) {
                continue;
            }
            if let Some((egress, kind)) = classify(dst) {
                out.push(LanCandidate {
                    dst,
                    egress,
                    kind,
                    requires_disco: true,
                    learned: true,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::models::{OverlayRule, PortRange, ProtocolKind};
    use meshharbor_remote_control::signaling::RelayStrategyWire;

    fn sample_network() -> OverlayNetworkInfo {
        OverlayNetworkInfo {
            org_relay_fallback_v1: true,
            org_relay_loss_v1: true,
            path_quality_v1: true,
            cidr: "100.64.0.0/10".into(),
            cidrs: vec!["100.64.0.0/10".into()],
            mtu: 1280,
            magic_domain: Some("example.mesh.test".into()),
            nameservers: vec!["198.51.100.53".into()],
            self_name: Some("node-alpha".into()),
            self_node_id: Some(ObjectId::new()),
            self_name_revision: Some("1".into()),
            stun_urls: vec!["stun:198.51.100.10:3478".into()],
            strict_stun: false,
            central_relay_denied: false,
            relay_probe_targets: vec![],
            backbone_probe_targets: vec![],
            auth_revision: 7,
        }
    }

    fn sample_peer(
        ip: &str,
        ingress_rules: Option<Vec<OverlayRule>>,
        backbone_only: bool,
    ) -> NetmapPeer {
        NetmapPeer {
            node_id: ObjectId::new(),
            overlay_ip: ip.into(),
            name: "peer-bravo".into(),
            wg_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            endpoints: vec!["203.0.113.20:51234".into()],
            lan_endpoints: vec!["192.168.50.20:43648".into()],
            srflx_endpoints: vec!["198.51.100.20:43904".into()],
            srflx_nat: Some("cone".into()),
            supports_org_relay: true,
            caps: None,
            udp_dialer_ok: Some(true),
            relay_home: None,
            warm_relay_endpoint: Some("203.0.113.99:49152".into()),
            reachable: false,
            supports_quic: true,
            supports_relay_single: true,
            supports_derp: true,
            supports_forced_derp: true,
            relay_strategy: Some(RelayStrategyWire::Derp),
            prefer_relay_ms: Some(60_000),
            backbone_only,
            supports_overlay_echo: true,
            supports_p2pctl: false,
            supports_derp_floor: true,
            routes: vec!["10.20.0.0/24".into()],
            agent_id: None,
            ingress_rules,
            ingress_rules_preview: None,
        }
    }

    fn sample_payload(id: &CacheIdentity<'_>, peers: Vec<NetmapPeer>) -> NetmapCachePayload {
        NetmapCachePayload {
            schema_version: CACHE_SCHEMA_VERSION,
            tenant_id: id.tenant_id.into(),
            node_id: id.node_id.into(),
            self_wg_pubkey: id.self_wg_pubkey.into(),
            self_ip: "100.64.0.1".into(),
            network: sample_network(),
            peers,
            last_authoritative_revision: 7,
            last_authoritative_at_ms: 1_700_000_000_000,
            monotonic_clock_floor_ms: 1_700_000_100_000,
            learned_endpoints: BTreeMap::new(),
        }
    }

    #[test]
    fn fr139_cache_roundtrip_preserves_some_empty_vs_none_ingress_rules_and_sanitizes() {
        let secret = [0x42u8; 32];
        let id = CacheIdentity {
            tenant_id: "tenant-a",
            node_id: "507f1f77bcf86cd799439011",
            self_wg_pubkey: "self-pubkey-b64",
        };
        let deny_all = sample_peer("100.64.0.2", Some(vec![]), false);
        let acl_off = sample_peer("100.64.0.3", None, false);
        let backbone = sample_peer("100.64.0.4", Some(vec![]), true);
        let mut payload = sample_payload(&id, vec![deny_all.clone(), acl_off.clone(), backbone.clone()]);
        payload.network.central_relay_denied = true;

        let sealed = seal(&secret, &id, &payload).expect("seal succeeds");
        let opened = open_and_verify(
            &secret,
            &id,
            &sealed,
            1_700_000_200_000,
            DEFAULT_MAX_CACHE_AGE_MS,
            Some(7),
        )
        .expect("open succeeds");

        assert!(opened.network.central_relay_denied);
        assert_eq!(opened.peers[0].ingress_rules, Some(vec![]));
        assert_eq!(opened.peers[1].ingress_rules, None);

        let replayed = sanitize_for_offline_replay(&opened.peers);
        // !backbone_only peers become reachable=true; ephemeral relay fields stripped.
        assert!(replayed[0].reachable);
        assert!(replayed[0].endpoints.is_empty());
        assert_eq!(replayed[0].warm_relay_endpoint, None);
        assert_eq!(replayed[0].relay_strategy, None);
        assert_eq!(replayed[0].prefer_relay_ms, None);
        assert_eq!(replayed[0].ingress_rules, Some(vec![]));
        assert_eq!(replayed[0].lan_endpoints, vec!["192.168.50.20:43648"]);

        assert!(replayed[1].reachable);
        assert_eq!(replayed[1].ingress_rules, None);

        // backbone_only peers NEVER become directly reachable offline.
        assert!(replayed[2].backbone_only);
        assert!(!replayed[2].reachable);
        assert!(replayed[2].endpoints.is_empty());

        let replayed_net = sanitize_network_for_offline_replay(&opened.network);
        assert!(replayed_net.central_relay_denied);
        assert!(!replayed_net.path_quality_v1);
    }

    #[test]
    fn fr139_cache_refuses_tamper_identity_mismatch_rollback_expiry_and_stale_rev() {
        let secret = [0x11u8; 32];
        let other_secret = [0x22u8; 32];
        let id = CacheIdentity {
            tenant_id: "tenant-a",
            node_id: "507f1f77bcf86cd799439011",
            self_wg_pubkey: "self-pubkey-b64",
        };
        let payload = sample_payload(&id, vec![sample_peer("100.64.0.2", None, false)]);
        let sealed = seal(&secret, &id, &payload).expect("seal");

        // 1. Payload tampering fails MAC.
        let mut tampered = sealed.clone();
        tampered.payload_json = tampered.payload_json.replace("100.64.0.2", "100.64.0.9");
        assert_eq!(
            open_and_verify(
                &secret,
                &id,
                &tampered,
                1_700_000_200_000,
                DEFAULT_MAX_CACHE_AGE_MS,
                None,
            ),
            Err(CacheError::InvalidMac)
        );

        // 2. Wrong WG key fails MAC.
        assert_eq!(
            open_and_verify(
                &other_secret,
                &id,
                &sealed,
                1_700_000_200_000,
                DEFAULT_MAX_CACHE_AGE_MS,
                None,
            ),
            Err(CacheError::InvalidMac)
        );

        // 3. Cross-tenant / cross-node / cross-pubkey identity fails MAC.
        let other_tenant = CacheIdentity {
            tenant_id: "tenant-b",
            ..id
        };
        assert_eq!(
            open_and_verify(
                &secret,
                &other_tenant,
                &sealed,
                1_700_000_200_000,
                DEFAULT_MAX_CACHE_AGE_MS,
                None,
            ),
            Err(CacheError::InvalidMac)
        );

        // 4. Clock rollback below monotonic_clock_floor_ms - tolerance fails closed.
        assert_eq!(
            open_and_verify(
                &secret,
                &id,
                &sealed,
                payload.monotonic_clock_floor_ms - CLOCK_ROLLBACK_TOLERANCE_MS - 1,
                DEFAULT_MAX_CACHE_AGE_MS,
                None,
            ),
            Err(CacheError::ClockRollback)
        );

        // 5. Expired past max_age_ms fails closed.
        let expired_now = payload.last_authoritative_at_ms + DEFAULT_MAX_CACHE_AGE_MS + 1;
        assert!(matches!(
            open_and_verify(
                &secret,
                &id,
                &sealed,
                expired_now,
                DEFAULT_MAX_CACHE_AGE_MS,
                None,
            ),
            Err(CacheError::Expired { .. })
        ));

        // 6. Stale revision below minimum floor fails closed.
        assert_eq!(
            open_and_verify(
                &secret,
                &id,
                &sealed,
                1_700_000_200_000,
                DEFAULT_MAX_CACHE_AGE_MS,
                Some(8),
            ),
            Err(CacheError::StaleRevision {
                cached: 7,
                min_required: 8,
            })
        );
    }

    #[test]
    fn fr139_authority_narrowing_detects_removes_acl_tightening_backbone_and_route_loss() {
        let net = sample_network();
        let allow_rule = OverlayRule {
            expires_at_ms: None,
            cidr: "100.64.0.1/32".into(),
            port_range: PortRange { low: 22, high: 22 },
            proto: ProtocolKind::Tcp,
        };
        let peer_a = sample_peer("100.64.0.2", Some(vec![allow_rule]), false);
        let peer_b = sample_peer("100.64.0.3", None, false);
        let old_map: HashMap<ObjectId, NetmapPeer> = [
            (peer_a.node_id, peer_a.clone()),
            (peer_b.node_id, peer_b.clone()),
        ]
        .into_iter()
        .collect();

        // Identical map is NOT narrowing.
        assert!(!is_authority_reducing(&net, &old_map, &net, &old_map));
        assert!(!delta_is_authority_reducing(&old_map, std::slice::from_ref(&peer_a), &[]));

        // 1. Removed peer -> urgent flush.
        let mut dropped = old_map.clone();
        dropped.remove(&peer_b.node_id);
        assert!(is_authority_reducing(&net, &old_map, &net, &dropped));
        assert!(delta_is_authority_reducing(&old_map, &[], &[peer_b.node_id]));

        // 2. Tighter ingress_rules -> urgent flush.
        let mut tighter = peer_a.clone();
        tighter.ingress_rules = Some(vec![]);
        assert!(delta_is_authority_reducing(&old_map, &[tighter], &[]));

        // 3. Newly backbone_only -> urgent flush.
        let mut bb = peer_b.clone();
        bb.backbone_only = true;
        assert!(delta_is_authority_reducing(&old_map, &[bb], &[]));

        // 4. Route removed -> urgent flush.
        let mut lost_route = peer_a.clone();
        lost_route.routes.clear();
        assert!(delta_is_authority_reducing(&old_map, &[lost_route], &[]));

        // 5. central_relay_denied flipped on -> urgent flush.
        let mut stricter_net = net.clone();
        stricter_net.central_relay_denied = true;
        assert!(is_authority_reducing(&net, &old_map, &stricter_net, &old_map));
    }

    #[test]
    fn fr139_offline_recovery_candidates_bounded_and_requires_disco() {
        let mut np = sample_peer("100.64.0.2", None, false);
        np.reachable = true;
        np.lan_endpoints = vec![
            "192.168.50.20:43648".into(),
            "198.51.100.20:43648".into(), // public IP must be excluded
        ];
        let peer = super::super::netmap::peer_config_from_netmap(&np).unwrap();
        let advertised = vec![LanCandidate::subnet(
            Ipv4Addr::new(192, 168, 50, 10),
            "192.168.50.20:43648".parse().unwrap(),
        )];
        let cands = offline_recovery_candidates(&peer, &[], &advertised, |_sa| {
            Some((
                LanEgress::Owned(Ipv4Addr::new(192, 168, 50, 10)),
                LanPathKind::Subnet,
            ))
        });
        assert!(!cands.is_empty());
        assert!(cands.len() <= MAX_OFFLINE_RECOVERY_CANDIDATES);
        // Never duplicates the already-advertised port, never probes public IP,
        // and ALWAYS requires Disco verification.
        assert!(cands.iter().all(|c| c.requires_disco && c.learned));
        assert!(cands.iter().all(|c| c.dst.ip() == IpAddr::V4(Ipv4Addr::new(192, 168, 50, 20))));
        assert!(cands.iter().all(|c| c.dst.port() != 43648));
        assert!(cands.iter().any(|c| c.dst.port() == 43649));
        assert!(cands.iter().any(|c| c.dst.port() == 43648 + SECOND_BAND_OFFSET));
    }
}
