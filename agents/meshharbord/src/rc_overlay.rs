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

use std::net::{IpAddr, Ipv4Addr};

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
        }
    }

    fn blocks(&self, ip: IpAddr) -> bool {
        !self.allow && footprint::is_overlay_addr(&self.v4_nets, ip)
    }

    /// The `SettingEngine` IP filter: may ICE gather a host candidate on `ip`?
    pub fn keeps_local(&self, ip: IpAddr) -> bool {
        !self.blocks(ip)
    }

    /// May this remote candidate (`candidate:… <addr> <port> typ …`) be added?
    /// A candidate whose address is not an IP literal — an mDNS `.local` name
    /// — passes, and the caller asks again once it has resolved it.
    pub fn keeps_remote_candidate(&self, candidate: &str) -> bool {
        candidate_ip(candidate).is_none_or(|ip| !self.blocks(ip))
    }

    /// The session's ICE servers minus every URL whose host is an overlay
    /// address, and minus any server left with no URL.
    pub fn ice_servers(&self, servers: &[IceServer]) -> Vec<IceServer> {
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
        if self.allow {
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
        }
    }

    fn on() -> RcOverlay {
        RcOverlay {
            allow: true,
            v4_nets: vec![(Ipv4Addr::new(100, 65, 4, 0), 22)],
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
    async fn mdns_os_timeout_fallback_to_webrtc_ice_bypasses_rc_overlay_gate() {
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
