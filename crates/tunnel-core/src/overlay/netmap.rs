// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Netmap → routable peer config.
//!
//! Converts a wire [`NetmapPeer`] (base64 pubkey + dotted overlay IP)
//! into a [`PeerConfig`] the [`WgDevice`](super::wg::WgDevice) can
//! install. Carrier selection (direct vs relay) is the node runtime's
//! job (Phase 3) — this module only decodes identity + address.

use std::net::Ipv4Addr;

use roomler_ai_remote_control::signaling::NetmapPeer;

use super::decode_public;
use super::router::Cidr;

/// A peer reduced to what the WG device needs: its static public key and
/// its single-host overlay address (`allowed_ips = overlay_ip/32`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub overlay_ip: Ipv4Addr,
    /// Human-facing node name (Phase 0), for MagicDNS name→IP. Empty when the
    /// server predates Phase 0.
    pub name: String,
    /// Phase 1 — approved subnet routes this peer is a router for. Installed into
    /// the local [`Router`](super::router::Router) (allowed_ips) + OS route table
    /// so LAN behind the peer is reachable over the overlay. Empty for a normal
    /// peer.
    pub subnets: Vec<Cidr>,
    /// Dialable endpoints (host/srflx/relay), priority order — the
    /// runtime picks one to build the carrier.
    pub endpoints: Vec<String>,
    /// Phase A — the peer's join-time NIC-derived endpoints (server
    /// `lan_endpoints` bucket, no relay addresses mixed in). A public IP here
    /// is a direct-to-public dial candidate. Empty from a pre-Phase-A server.
    pub lan_endpoints: Vec<String>,
    /// Phase B — the peer's server-reflexive (srflx) endpoints (server
    /// `srflx_endpoints` bucket): its public NAT mapping learned via STUN. A
    /// public IP here is a srflx dial candidate (a 1:1/cone-NAT'd peer whose NIC
    /// is private). Empty from a pre-Phase-B server or a peer with no srflx.
    pub srflx_endpoints: Vec<String>,
    /// Phase C — the peer's probed NAT mapping type (`"cone"` / `"symmetric"`),
    /// or `None` when unknown. The runtime skips the srflx punch only when BOTH
    /// this peer and we are `"symmetric"`; any other combination attempts.
    pub srflx_nat: Option<String>,
    /// Dialer honesty — whether this peer can raw-UDP-dial arbitrary
    /// relay-band ports (the single-relay DIALER's job). `Some(false)` = it
    /// proved it can't; `None` = pre-honesty peer, in which case BOTH ends
    /// keep the legacy srflx-only role inputs (field presence is the
    /// capability gate — a mixed-version pair can never split roles).
    pub udp_dialer_ok: Option<bool>,
    /// B3 — the peer's MEASURED relay-band verdict (netcheck's
    /// `relay_band_udp`, probed over the exact single-relay dial path),
    /// surfaced only while the server's freshness gate holds (≤3× the
    /// 20-min cadence). When BOTH ends carry the measured bit it supersedes
    /// the srflx/latch-derived role inputs; `None` = pre-vector peer or
    /// stale vector ⇒ legacy rules on both ends (field presence is the
    /// symmetry gate, exactly like `udp_dialer_ok`).
    pub relay_band_udp: Option<bool>,
    /// rc.142 — the peer advertised it can carry WG over QUIC-over-TURN. The
    /// runtime only attempts the QUIC relay carrier when this is set (both
    /// ends must agree, else the pair falls back to raw relay).
    pub supports_quic: bool,
    /// Phase D (v1 single-relay) — the peer advertised it can run the
    /// single-relay carrier: ONE anchor allocation + a raw dialer, instead of
    /// today's both-allocate hairpin. The runtime picks single-relay only when
    /// BOTH ends advertise this AND our `OVERLAY_RELAY_SINGLE` flag is on; else
    /// the pair uses both-allocate. Wired to the `NetmapPeer` field in D1c —
    /// `false` until then keeps a mixed fleet on the proven path.
    pub supports_relay_single: bool,
    /// Phase D (DERP) — the peer advertised it can carry WG over the
    /// pubkey-addressed `/derp` relay. The runtime falls to DERP only when BOTH
    /// ends advertise this AND both are UDP-blocked AND our `OVERLAY_DERP` flag
    /// is on; else the `(false,false)` pair stays on both-allocate.
    pub supports_derp: bool,
    /// U2 — the peer advertised `supports_forced_derp` (echoed per-peer only
    /// from U2 onward). Part of the both-ends gate for applying a
    /// server-computed `relay_strategy`.
    pub supports_forced_derp: bool,
    /// Phase A (overlay v3) — the peer runs the DERP always-on floor (its
    /// central /derp mux is open + registered for the whole session). A pair
    /// is floored at birth only when BOTH ends carry this.
    pub supports_derp_floor: bool,
    /// Data-probe — the peer's overlay ENGINE answers the overlay-native
    /// echo probe inline (guaranteed responder, netstack included). The
    /// carrier data-probe uses the engine echo toward such peers and the
    /// ICMP echo toward the rest. Pre-capability peer ⇒ `false` ⇒ ICMP.
    pub supports_overlay_echo: bool,
    /// U2 — the server's relay-tier verdict for this edge, or `None` when the
    /// server didn't stamp one (pre-U2 server, or either end unflagged). When
    /// present AND our own `server_relay_strategy_enabled()` is on, the
    /// coordinator uses it verbatim in place of its local derivation.
    pub relay_strategy: Option<roomler_ai_remote_control::signaling::RelayStrategyWire>,
    /// U2 — the peer's coturn region hint (server `relay_home`), previously
    /// DROPPED by this conversion. Carried so the client's region/worker
    /// selection matches the server's when it computes the strategy.
    pub relay_home: Option<String>,
    /// C4 stage 2 (PR-B) — the peer's STANDING warm TURN allocation's relayed
    /// address, refreshed by its heartbeats while the leg is live. A
    /// single-relay DIALER falls back to this when the anchor's per-pair
    /// relay advert hasn't landed (or can't — its control WS is captured);
    /// validated against the coturn worker set like any anchor advert.
    pub warm_relay_endpoint: Option<String>,
    /// MeshHarbor #21 — the peer is in the other business zone and rides its
    /// cross-border line alone: no direct dial or inbound direct adoption, no
    /// DERP (a server pin included), no TURN. The server mints the line as an
    /// org-relay session on our side of it.
    pub backbone_only: bool,
}

/// Decode a netmap peer. `None` if the pubkey isn't valid base64/length
/// or the overlay IP isn't a v4 address. Unreachable peers are dropped
/// by the server before they reach the netmap, but a defensive
/// `reachable == false` is also skipped here.
pub fn peer_config_from_netmap(peer: &NetmapPeer) -> Option<PeerConfig> {
    if !peer.reachable {
        return None;
    }
    let public_key = decode_public(&peer.wg_public_key)?;
    let overlay_ip: Ipv4Addr = peer.overlay_ip.parse().ok()?;
    Some(PeerConfig {
        public_key,
        overlay_ip,
        name: peer.name.clone(),
        subnets: peer.routes.iter().filter_map(|r| Cidr::parse(r)).collect(),
        endpoints: peer.endpoints.clone(),
        lan_endpoints: peer.lan_endpoints.clone(),
        srflx_endpoints: peer.srflx_endpoints.clone(),
        srflx_nat: peer.srflx_nat.clone(),
        udp_dialer_ok: peer.udp_dialer_ok,
        relay_band_udp: peer.caps.as_ref().and_then(|c| c.relay_band_udp),
        supports_quic: peer.supports_quic,
        supports_relay_single: peer.supports_relay_single,
        supports_derp: peer.supports_derp,
        supports_forced_derp: peer.supports_forced_derp,
        supports_derp_floor: peer.supports_derp_floor,
        supports_overlay_echo: peer.supports_overlay_echo,
        relay_strategy: peer.relay_strategy,
        relay_home: peer.relay_home.clone(),
        warm_relay_endpoint: peer.warm_relay_endpoint.clone(),
        backbone_only: peer.backbone_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::WgKeypair;
    use bson::oid::ObjectId;

    fn netmap_peer(pubkey_b64: &str, ip: &str, reachable: bool) -> NetmapPeer {
        NetmapPeer {
            node_id: ObjectId::new(),
            overlay_ip: ip.into(),
            name: String::new(),
            wg_public_key: pubkey_b64.into(),
            endpoints: vec!["203.0.113.5:51820".into()],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            caps: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            supports_org_relay: false,
            supports_overlay_echo: false,
            relay_strategy: None,
            routes: vec![],
            agent_id: None,
            ingress_rules: None,
            backbone_only: false,
        }
    }

    #[test]
    fn decodes_valid_peer() {
        let kp = WgKeypair::generate();
        let p = netmap_peer(&kp.public_base64(), "100.64.0.5", true);
        let cfg = peer_config_from_netmap(&p).unwrap();
        assert_eq!(cfg.public_key, kp.public.to_bytes());
        assert_eq!(cfg.overlay_ip, Ipv4Addr::new(100, 64, 0, 5));
        assert_eq!(cfg.endpoints.len(), 1);
    }

    /// B3 — the measured relay-band bit rides `NetmapPeer.caps` (already
    /// freshness-gated by the server) into `PeerConfig.relay_band_udp`;
    /// absent caps ⇒ `None` ⇒ legacy role inputs.
    #[test]
    fn maps_measured_relay_band_from_caps() {
        let kp = WgKeypair::generate();
        let mut p = netmap_peer(&kp.public_base64(), "100.64.0.5", true);
        assert_eq!(peer_config_from_netmap(&p).unwrap().relay_band_udp, None);
        p.caps = Some(roomler_ai_remote_control::signaling::CapVectorWire {
            stun_udp: true,
            relay_band_udp: Some(false),
            derp_ws_ok: true,
        });
        assert_eq!(
            peer_config_from_netmap(&p).unwrap().relay_band_udp,
            Some(false)
        );
    }

    #[test]
    fn rejects_unreachable_or_malformed() {
        let kp = WgKeypair::generate();
        assert!(
            peer_config_from_netmap(&netmap_peer(&kp.public_base64(), "100.64.0.5", false))
                .is_none()
        );
        assert!(peer_config_from_netmap(&netmap_peer("bad!!", "100.64.0.5", true)).is_none());
        assert!(
            peer_config_from_netmap(&netmap_peer(&kp.public_base64(), "not-an-ip", true)).is_none()
        );
    }
}
