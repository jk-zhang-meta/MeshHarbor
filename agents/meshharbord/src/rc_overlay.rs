// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #1882 — may a remote-desktop session use the WireGuard overlay, and the
//! filters that keep it off when it may not.
//!
//! The DEVICE decides: `AccessPolicy.rc_overlay`, default off, delivered per
//! session in `rc:request` (an older server never sends it, which reads off).
//! Off means no ICE pair of the session touches an overlay address. That
//! takes three filters, because the overlay reaches a session's ICE three
//! ways, and the interface-name rule RC always had covers only part of the
//! first:
//!
//! | how the overlay gets in | filter |
//! |---|---|
//! | a HOST candidate on the overlay interface — on macOS a kernel-named `utunN` the name rule cannot see | [`RcOverlay::keeps_local`], the `SettingEngine` IP filter |
//! | a REMOTE candidate on a mesh address, when the controller's browser runs on an overlay node; the agent's srflx and relay sockets are bound to `0.0.0.0`, so a check to it routes into the TUN no matter which candidates the agent offered | [`RcOverlay::keeps_remote_candidate`] on every trickled candidate, [`RcOverlay::strip_sdp`] on the offer, plus the same `SettingEngine` IP filter ([`RcOverlay::keeps_local`]) inside `webrtc-ice` after `.local` mDNS resolution and on inbound `prflx` synthesis |
//! | an ICE SERVER on a mesh address — the loopback-TURN relay the Hub appends for a corp controller | [`RcOverlay::ice_servers`] (the Hub also withholds it) |
//!
//! "Overlay address" is exact: the blocks this daemon's overlay routes
//! ([`tunnel_core::overlay_footprint`]) and the derived-v6 ULA — never the
//! whole CGNAT `/10`, which LTE modems, cloud VPCs and other meshes use too.
//!
//! On, nothing is filtered beyond the name rule: the behaviour from before
//! the switch existed.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

use meshharbor_remote_control::signaling::IceServer;
use serde::{Deserialize, Serialize};
use tunnel_core::overlay_footprint as footprint;

/// The overlay decision for ONE session, resolved when it is requested.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RcOverlay {
    /// The device's `AccessPolicy.rc_overlay`. `false`, the default, keeps the
    /// session off the overlay.
    pub allow: bool,
    /// The overlay's v4 blocks, snapshotted by the DAEMON when the session is
    /// requested. Carried rather than re-read so a delegated session's GUI
    /// worker, which runs no overlay of its own, filters the same addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub v4_nets: Vec<(Ipv4Addr, u8)>,
    /// FR-121 — the device sits in a STRICT logical network zone
    /// (`rc:request` `zone_strict`). The server already dropped every
    /// controller candidate outside the zone; this side then lets ICE touch
    /// no public address but those candidates' and its own, so neither a
    /// stray candidate nor an inbound check from an address it was never
    /// given (a would-be `prflx`) takes the media out of the zone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zone_strict: bool,
    /// FR-121 — this host's own public interface addresses, snapshotted with
    /// the decision (carried, like `v4_nets`, to a delegated worker).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub own_ips: Vec<IpAddr>,
    /// FR-121 — public addresses of the candidates the server handed over.
    #[serde(skip)]
    pub zone_peers: ZonePeers,
    /// FR-121 — the zones let this session also relay inside the mesh
    /// (`direct_mesh`): the agent's own loopback TURN joins its servers and
    /// overlay addresses are no longer kept out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zone_mesh_fallback: bool,
    /// FR-121 — the zones let this session meet ONLY inside the mesh
    /// (`mesh`): relay candidates only, through the agent's own TURN only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zone_mesh_only: bool,
    /// FR-121 — that TURN (`turn:127.0.0.1:<port>`), resolved by the daemon
    /// and carried, like `v4_nets`, to a delegated worker on the same host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_turn: Option<IceServer>,
}

/// FR-121 — the session's admitted public peer addresses, shared by the IP
/// filter `webrtc-ice` holds and the signalling path that learns them.
/// Compared as always-equal: it is session state, not part of the decision.
#[derive(Debug, Clone, Default)]
pub struct ZonePeers(Arc<RwLock<HashSet<IpAddr>>>);

impl PartialEq for ZonePeers {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for ZonePeers {}

impl ZonePeers {
    fn insert(&self, ip: IpAddr) {
        self.0.write().unwrap_or_else(|e| e.into_inner()).insert(ip);
    }
    fn contains(&self, ip: &IpAddr) -> bool {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(ip)
    }
}

/// FR-121 — is `ip` publicly routable, i.e. could it sit in another country?
/// The same rule as the server's `ice_zones::is_public_ip`: private,
/// loopback, link-local, CGNAT (the mesh too), unique-local, multicast and
/// unspecified addresses are not; documentation ranges count as public.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

impl RcOverlay {
    /// The decision for a session THIS process resolves: the device's policy,
    /// plus this process's overlay blocks when they are needed.
    pub fn resolve(allow: bool) -> Self {
        Self {
            allow,
            v4_nets: if allow {
                Vec::new()
            } else {
                footprint::v4_nets()
            },
            ..Self::default()
        }
    }

    /// FR-121 — the same decision under the session's zone route
    /// (`rc:request` `zone_route`): absent, nothing changes; `direct`, only
    /// public addresses the server handed over (and this host's own) are
    /// admitted; `direct_mesh`, that plus a relay inside the mesh through
    /// this daemon's own loopback TURN (`self_turn`); `mesh` — or a word this
    /// build does not know, the strictest reading — that relay only.
    pub fn with_zone(
        mut self,
        route: Option<&str>,
        self_turn: impl FnOnce() -> Option<IceServer>,
    ) -> Self {
        let Some(route) = route else {
            return self;
        };
        self.zone_strict = true;
        self.own_ips = if_addrs::get_if_addrs()
            .map(|v| {
                v.into_iter()
                    .map(|i| i.ip())
                    .filter(|ip| is_public_ip(*ip))
                    .collect()
            })
            .unwrap_or_default();
        match route {
            "direct" => {}
            "direct_mesh" => self.zone_mesh_fallback = true,
            _ => self.zone_mesh_only = true,
        }
        // Resolved on every zoned route, `direct` included: the offer may
        // still move the session onto the mesh, and a delegated worker only
        // has what the daemon resolved here.
        self.zone_turn = self_turn();
        self
    }

    /// FR-121 — the same decision under a route settled later (the offer's),
    /// keeping the TURN the request resolved: a delegated worker cannot reach
    /// the daemon's registry, only what the daemon carried to it.
    pub fn rezone(mut self, route: &str, self_turn: impl FnOnce() -> Option<IceServer>) -> Self {
        let turn = self.zone_turn.take();
        self.zone_strict = false;
        self.zone_mesh_fallback = false;
        self.zone_mesh_only = false;
        self.with_zone(Some(route), move || turn.or_else(self_turn))
    }

    /// FR-121 — must this session gather relay candidates only?
    pub fn relay_only(&self) -> bool {
        self.zone_mesh_only
    }

    /// FR-121 — may ICE touch `ip` under the zone rule? Always, off a strict
    /// zone; on one, a non-public address, one of this host's own, or one the
    /// server handed over in a candidate.
    pub fn zone_admits(&self, ip: IpAddr) -> bool {
        !self.zone_strict
            || !is_public_ip(ip)
            || self.own_ips.contains(&ip)
            || self.zone_peers.contains(&ip)
    }

    fn blocks(&self, ip: IpAddr) -> bool {
        // FR-121 — a zone route through the mesh IS an overlay path.
        let mesh = self.zone_mesh_fallback || self.zone_mesh_only;
        !self.allow && !mesh && footprint::is_overlay_addr(&self.v4_nets, ip)
    }

    /// The `SettingEngine` IP filter: may ICE gather a host candidate on `ip`?
    ///
    /// `webrtc-ice` asks it of local interfaces, remote candidates and inbound
    /// `prflx` sources alike, which is what lets FR-121's zone rule hold there.
    pub fn keeps_local(&self, ip: IpAddr) -> bool {
        !self.blocks(ip) && self.zone_admits(ip)
    }

    /// May this remote candidate (`candidate:… <addr> <port> typ …`) be added?
    /// A candidate whose address is not an IP literal — an mDNS `.local` name
    /// — passes, and the caller asks again once it has resolved it.
    ///
    /// FR-121 — in a strict zone, a public address that arrives here was
    /// vetted by the server, so it is admitted for the session's ICE.
    pub fn keeps_remote_candidate(&self, candidate: &str) -> bool {
        let Some(ip) = candidate_ip(candidate) else {
            return true;
        };
        if self.blocks(ip) {
            return false;
        }
        if self.zone_strict && is_public_ip(ip) {
            self.zone_peers.insert(ip);
        }
        true
    }

    /// The session's ICE servers minus every URL whose host is an overlay
    /// address, and minus any server left with no URL.
    pub fn ice_servers(&self, servers: &[IceServer]) -> Vec<IceServer> {
        // FR-121 — through the mesh the session's servers are this daemon's
        // own TURN: alone on `mesh`, first on `direct_mesh`.
        if self.zone_mesh_only {
            return self.zone_turn.iter().cloned().collect();
        }
        if self.zone_mesh_fallback {
            let mut out: Vec<IceServer> = self.zone_turn.iter().cloned().collect();
            out.extend(servers.iter().cloned());
            return out;
        }
        if self.allow {
            return servers.to_vec();
        }
        servers
            .iter()
            .filter_map(|s| {
                let urls: Vec<String> = s
                    .urls
                    .iter()
                    .filter(|u| url_host_ip(u).is_none_or(|ip| !self.blocks(ip)))
                    .cloned()
                    .collect();
                (!urls.is_empty()).then(|| IceServer {
                    urls,
                    username: s.username.clone(),
                    credential: s.credential.clone(),
                })
            })
            .collect()
    }

    /// `sdp` without its overlay-addressed `a=candidate:` lines. A browser
    /// trickles its candidates, so an offer normally carries none; one that
    /// gathered first carries them all, and they would be added with no
    /// trickle to filter.
    pub fn strip_sdp(&self, sdp: &str) -> String {
        if self.allow && !self.zone_strict {
            return sdp.to_string();
        }
        sdp.split_inclusive('\n')
            .filter(|line| {
                let l = line.trim_start();
                !l.starts_with("a=candidate:") || self.keeps_remote_candidate(l)
            })
            .collect()
    }

    /// The decision in words, for the one line a session logs, so "why did
    /// it not take the overlay pair" has an answer in the device's log.
    pub fn describe(&self) -> &'static str {
        if self.allow {
            "allowed (device policy rc_overlay=on)"
        } else {
            "excluded (device policy rc_overlay=off, the default)"
        }
    }
}

/// The connection address of an ICE candidate line, if it is an IP literal.
/// The address is the fifth token in both shapes — a trickled
/// `candidate:<foundation> <component> <transport> <priority> <addr> …` and
/// an SDP `a=candidate:…` line.
pub fn candidate_ip(candidate: &str) -> Option<IpAddr> {
    candidate.split_whitespace().nth(4)?.parse().ok()
}

/// The host of a `stun:`/`turn:`/`turns:` URL, if it is an IP literal:
/// `turn:100.64.0.9:47989`, `turns:[fd72:6f6f:6d6c::1]:443?transport=tcp`.
fn url_host_ip(url: &str) -> Option<IpAddr> {
    let (_, rest) = url.split_once(':')?;
    let hostport = rest.split('?').next()?.trim_start_matches("//");
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        hostport.rsplit_once(':').map_or(hostport, |(h, _)| h)
    };
    host.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn off() -> RcOverlay {
        RcOverlay {
            allow: false,
            v4_nets: vec![(Ipv4Addr::new(100, 65, 4, 0), 22)],
            ..RcOverlay::default()
        }
    }

    fn on() -> RcOverlay {
        RcOverlay {
            allow: true,
            v4_nets: vec![(Ipv4Addr::new(100, 65, 4, 0), 22)],
            ..RcOverlay::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The macOS case #1882 was filed for: the `utunN` carries the overlay v4
    /// and the derived v6, and neither may become a host candidate. A LAN
    /// address, a CGNAT address OUTSIDE our blocks (an LTE modem) and a home
    /// router's ULA stay.
    #[test]
    fn local_filter_drops_only_overlay_addresses() {
        let p = off();
        assert!(!p.keeps_local(ip("100.65.4.34")));
        assert!(!p.keeps_local(ip("fd72:6f6f:6d6c::6441:422")));
        assert!(p.keeps_local(ip("192.168.1.20")));
        assert!(p.keeps_local(ip("100.80.1.2")));
        assert!(p.keeps_local(ip("fd00::1")));
        assert!(on().keeps_local(ip("100.65.4.34")), "on = no filter");
    }

    /// FR-121 — in a strict zone ICE may touch no public address but its
    /// own and those the server handed over: a would-be `prflx` source or a
    /// candidate that never came through signalling is refused, LAN and the
    /// mesh rule are unchanged, and outside a strict zone nothing changes.
    #[test]
    fn a_strict_zone_admits_only_handed_over_public_addresses() {
        let p = RcOverlay {
            own_ips: vec![ip("203.0.113.10")],
            ..off()
        }
        .with_zone_for_test(true);
        let stranger = ip("198.51.100.77");
        assert!(!p.keeps_local(stranger), "an address nobody handed over");
        assert!(p.keeps_local(ip("203.0.113.10")), "this host's own address");
        assert!(p.keeps_local(ip("192.168.1.30")), "LAN");
        assert!(
            !p.keeps_local(ip("100.65.4.34")),
            "the overlay rule still holds"
        );
        let srflx =
            "candidate:4 1 udp 1686052607 198.51.100.77 54323 typ srflx raddr 10.0.0.2 rport 1";
        assert!(p.keeps_remote_candidate(srflx));
        assert!(
            p.keeps_local(stranger),
            "admitted once the server handed it over"
        );
        // the same through an offer's SDP
        let q = off().with_zone_for_test(true);
        let sdp = "v=0\r\na=candidate:1 1 udp 1 198.51.100.88 9 typ host\r\n";
        assert_eq!(q.strip_sdp(sdp), sdp);
        assert!(q.keeps_local(ip("198.51.100.88")));
        // not strict: nothing changes
        let r = off().with_zone_for_test(false);
        assert!(r.keeps_local(stranger));
        // the clone `webrtc-ice` holds sees what signalling learns later
        let held = q.clone();
        assert!(!held.keeps_local(ip("198.51.100.99")));
        q.keeps_remote_candidate("candidate:9 1 udp 1 198.51.100.99 9 typ host");
        assert!(held.keeps_local(ip("198.51.100.99")));
    }

    /// FR-121 — the mesh routes: `mesh` relays only, through this daemon's
    /// own TURN alone, and overlay addresses (the relay pair) pass;
    /// `direct_mesh` puts that TURN first and keeps the other servers; an
    /// unknown word reads as `mesh`; no route changes nothing.
    #[test]
    fn the_mesh_routes_relay_through_the_daemons_own_turn() {
        let own = IceServer {
            urls: vec!["turn:127.0.0.1:41000?transport=udp".into()],
            username: Some("u".into()),
            credential: Some("c".into()),
        };
        let coturn = IceServer {
            urls: vec!["turn:198.51.100.3:3478".into()],
            username: None,
            credential: None,
        };
        let mesh = off().with_zone(Some("mesh"), || Some(own.clone()));
        assert!(mesh.relay_only() && mesh.zone_strict);
        assert_eq!(
            mesh.ice_servers(std::slice::from_ref(&coturn)),
            vec![own.clone()]
        );
        assert!(
            mesh.keeps_local(ip("100.65.4.34")),
            "the relay pair is on the overlay"
        );
        let relay =
            "candidate:2 1 udp 41885439 100.65.4.33 61000 typ relay raddr 127.0.0.1 rport 5000";
        assert!(mesh.keeps_remote_candidate(relay));

        let fb = off().with_zone(Some("direct_mesh"), || Some(own.clone()));
        assert!(!fb.relay_only());
        assert_eq!(
            fb.ice_servers(std::slice::from_ref(&coturn)),
            vec![own.clone(), coturn.clone()]
        );

        assert!(
            off()
                .with_zone(Some("from-a-newer-server"), || None)
                .relay_only()
        );
        let direct = off().with_zone(Some("direct"), || Some(own.clone()));
        assert!(direct.zone_strict && !direct.relay_only());
        assert!(
            !direct.keeps_local(ip("100.65.4.34")),
            "the overlay rule holds off the mesh routes"
        );
        let none = off().with_zone(None, || panic!("no route, no TURN"));
        assert_eq!(none, off());
        // the offer moves a direct session onto the mesh, keeping its TURN
        let moved = direct.rezone("mesh", || panic!("the request's TURN is kept"));
        assert!(moved.relay_only());
        assert_eq!(moved.ice_servers(&[]), vec![own.clone()]);
    }

    impl RcOverlay {
        /// `with_zone` without reading this machine's interfaces.
        fn with_zone_for_test(mut self, strict: bool) -> Self {
            self.zone_strict = strict;
            self
        }
    }

    #[test]
    fn remote_candidates_on_the_mesh_are_dropped_and_names_pass() {
        let p = off();
        let host = "candidate:1 1 udp 2122260223 100.65.4.33 54321 typ host generation 0";
        let relay =
            "candidate:2 1 udp 41885439 100.65.4.33 61000 typ relay raddr 127.0.0.1 rport 5000";
        let lan = "candidate:3 1 udp 2122260223 192.168.1.30 54322 typ host";
        let srflx = "candidate:4 1 udp 1686052607 37.63.112.129 54323 typ srflx raddr 192.168.1.30 rport 54322";
        let mdns = "candidate:5 1 udp 2122260223 4a5b6c7d-0000-1111-2222-333344445555.local 54324 typ host";
        let v6 = "candidate:6 1 udp 2122262783 fd72:6f6f:6d6c::6441:421 54325 typ host";
        assert!(!p.keeps_remote_candidate(host));
        assert!(!p.keeps_remote_candidate(relay), "the loopback-TURN relay");
        assert!(!p.keeps_remote_candidate(v6));
        assert!(p.keeps_remote_candidate(lan));
        assert!(p.keeps_remote_candidate(srflx));
        assert!(
            p.keeps_remote_candidate(mdns),
            "a name passes; it is re-checked after resolution"
        );
        assert!(p.keeps_remote_candidate("garbage"));
        assert!(on().keeps_remote_candidate(host));
    }

    #[test]
    fn the_overlay_turn_server_is_dropped_and_coturn_is_kept() {
        let servers = vec![
            IceServer {
                urls: vec![
                    "stun:turn.meshharbor.itachi.fans:3478".into(),
                    "turn:turn.meshharbor.itachi.fans:3478?transport=udp".into(),
                    "turns:turn.meshharbor.itachi.fans:443?transport=tcp".into(),
                ],
                username: Some("u".into()),
                credential: Some("c".into()),
            },
            IceServer {
                urls: vec!["turn:100.65.4.33:47989".into()],
                username: Some("lu".into()),
                credential: Some("lc".into()),
            },
            IceServer {
                urls: vec![
                    "turn:[fd72:6f6f:6d6c::6441:421]:47989".into(),
                    "turn:203.0.113.7:3478".into(),
                ],
                username: None,
                credential: None,
            },
        ];
        let kept = off().ice_servers(&servers);
        let urls: Vec<&str> = kept
            .iter()
            .flat_map(|s| s.urls.iter().map(String::as_str))
            .collect();
        assert_eq!(
            urls,
            [
                "stun:turn.meshharbor.itachi.fans:3478",
                "turn:turn.meshharbor.itachi.fans:3478?transport=udp",
                "turns:turn.meshharbor.itachi.fans:443?transport=tcp",
                "turn:203.0.113.7:3478",
            ]
        );
        assert_eq!(kept.len(), 2, "a server left with no URL is dropped");
        assert_eq!(kept[0].username.as_deref(), Some("u"), "creds survive");
        assert_eq!(on().ice_servers(&servers).len(), 3, "on = unchanged");
    }

    #[test]
    fn url_hosts_parse_in_every_shape() {
        assert_eq!(url_host_ip("turn:100.64.0.9:47989"), Some(ip("100.64.0.9")));
        assert_eq!(
            url_host_ip("turns:[fd72:6f6f:6d6c::1]:443?transport=tcp"),
            Some(ip("fd72:6f6f:6d6c::1"))
        );
        assert_eq!(url_host_ip("stun:100.64.0.9"), Some(ip("100.64.0.9")));
        assert_eq!(url_host_ip("stun:stun.l.google.com:19302"), None);
        assert_eq!(url_host_ip("nonsense"), None);
    }

    #[test]
    fn sdp_loses_only_its_overlay_candidate_lines() {
        let sdp = "v=0\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                   a=candidate:1 1 udp 2122260223 100.65.4.33 54321 typ host\r\n\
                   a=candidate:3 1 udp 2122260223 192.168.1.30 54322 typ host\r\n\
                   a=end-of-candidates\r\n";
        let out = off().strip_sdp(sdp);
        assert!(!out.contains("100.65.4.33"), "{out}");
        assert!(out.contains("a=candidate:3 1 udp 2122260223 192.168.1.30 54322 typ host\r\n"));
        assert!(out.starts_with("v=0\r\n") && out.ends_with("a=end-of-candidates\r\n"));
        assert_eq!(on().strip_sdp(sdp), sdp);
    }

    /// The delegation channel carries the decision to a macOS GUI worker. An
    /// older daemon sends no field at all, and that must read OFF.
    #[test]
    fn serde_round_trips_and_absent_reads_off() {
        let p = off();
        let back: RcOverlay = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
        let empty: RcOverlay = serde_json::from_str(r#"{"allow":false}"#).unwrap();
        assert_eq!(empty, RcOverlay::default());
        assert!(!RcOverlay::default().allow);
    }

    /// Locks the post-fix behavior for 18:42 Section 4: when `resolve_mdns_candidate`
    /// returns `None` (OS resolver timeout after 750 ms), `peer.rs:1885-1904` passes
    /// the `.local` candidate to `webrtc-ice`, and `webrtc-ice` enforces the
    /// `SettingEngine` `ip_filter` (`RcOverlay::keeps_local`, which shares the exact
    /// `!self.blocks(ip)` predicate with `RcOverlay::keeps_remote_candidate`) after
    /// resolving `.local` and before admitting the remote candidate (or synthesizing
    /// a `prflx` candidate). When `rc_overlay=off`, overlay-resolved `.local`
    /// candidates are dropped fail-closed; when `rc_overlay=on`, they are kept.
    #[tokio::test]
    async fn mdns_os_timeout_fallback_to_webrtc_ice_is_rejected_by_rc_overlay_ip_filter() {
        use std::sync::Arc;
        use webrtc::ice::agent::Agent;
        use webrtc::ice::agent::agent_config::AgentConfig;
        use webrtc::ice::candidate::Candidate;
        use webrtc::ice::candidate::candidate_base::CandidateBaseConfig;
        use webrtc::ice::candidate::candidate_host::CandidateHostConfig;
        use webrtc::ice::mdns::MulticastDnsMode;
        use webrtc::ice::network_type::NetworkType;

        let p_off = off();
        let raw_mdns = "candidate:5 1 udp 2122260223 4a5b6c7d-0000-1111-2222-333344445555.local 54324 typ host";

        // Step 1: pre-resolution check passes `.local` name so `webrtc-ice` can
        // resolve it when OS `lookup_host` times out (750 ms).
        assert_eq!(candidate_ip(raw_mdns), None);
        assert!(p_off.keeps_remote_candidate(raw_mdns));

        // Step 2 (`rc_overlay=off`): `peer.rs:488` wires `keeps_local` into
        // `setting.set_ip_filter(...)`, which `webrtc-ice` enforces on remote
        // candidates after `.local` resolution.
        let keep_off = p_off.clone();
        let agent_off = Agent::new(AgentConfig {
            is_controlling: false,
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ip_filter: Arc::new(Some(Box::new(move |ip| keep_off.keeps_local(ip)))),
            ..Default::default()
        })
        .await
        .unwrap();

        let overlay_v4_mdns: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: "4a5b6c7d-0000-1111-2222-333344445555.local".into(),
                    port: 54324,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap(),
        );
        overlay_v4_mdns.set_ip(&ip("100.65.4.33")).unwrap();
        assert_eq!(
            p_off.keeps_local(ip("100.65.4.33")),
            p_off.keeps_remote_candidate("candidate:5 1 udp 2122260223 100.65.4.33 54324 typ host")
        );
        agent_off.add_remote_candidate(&overlay_v4_mdns).unwrap();

        let lan_mdns: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: "9b8a7c6d-0000-1111-2222-333344445555.local".into(),
                    port: 59501,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap(),
        );
        lan_mdns.set_ip(&ip("192.168.1.42")).unwrap();
        agent_off.add_remote_candidate(&lan_mdns).unwrap();

        // Give the spawned `add_remote_candidate` tasks a turn to run.
        tokio::task::yield_now().await;
        let stats_off = agent_off.get_remote_candidates_stats().await;
        assert!(
            !stats_off.iter().any(|s| s.ip == "100.65.4.33"),
            "overlay .local candidate must be dropped when rc_overlay=off: {stats_off:?}"
        );
        assert_eq!(stats_off.len(), 1);
        assert_eq!(stats_off[0].network_type, NetworkType::Udp4);
        let _ = agent_off.close().await;

        // Step 3 (`rc_overlay=on`): overlay `.local` candidate IS retained.
        let p_on = on();
        let keep_on = p_on.clone();
        let agent_on = Agent::new(AgentConfig {
            is_controlling: false,
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ip_filter: Arc::new(Some(Box::new(move |ip| keep_on.keeps_local(ip)))),
            ..Default::default()
        })
        .await
        .unwrap();
        agent_on.add_remote_candidate(&overlay_v4_mdns).unwrap();
        tokio::task::yield_now().await;
        let stats_on = agent_on.get_remote_candidates_stats().await;
        assert_eq!(
            stats_on.len(),
            1,
            "overlay .local candidate must be kept when rc_overlay=on"
        );
        let _ = agent_on.close().await;
    }
}
