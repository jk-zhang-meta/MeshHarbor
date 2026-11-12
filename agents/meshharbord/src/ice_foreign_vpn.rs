// SPDX-License-Identifier: MPL-2.0
//! Keep a third-party mesh VPN's addresses out of a remote-desktop session's
//! ICE host candidates.
//!
//! Field 2026-11-11 (V0027, Surface controlled ↔ MacBook browser on one LAN,
//! both running Tailscale): in 3 of 5 sessions the FIRST selected pair was
//! `host <-> prflx` on the two hosts' Tailscale addresses, and media only
//! moved to `srflx` and then to the LAN `host` pair 0.5–1.5 s later — two
//! pair switches per session, and the first frames carried inside somebody
//! else's WireGuard tunnel (DERP-relayed whenever Tailscale itself is).
//!
//! Why this is not a CIDR rule: `100.64.0.0/10` is real CGNAT space that ISPs,
//! LTE modems and cloud VPCs hand out on a physical NIC, so stripping the `/10`
//! would remove a legitimate host candidate (the same caveat as the overlay
//! interface-name rule in `peer.rs`). And it cannot be an interface-NAME rule
//! in `webrtc-ice`: on Windows `webrtc-util` reports every interface name as
//! `""`, so the `SettingEngine` interface filter never sees "Tailscale" there.
//!
//! So the interface is identified HERE, from `if-addrs` (which carries the
//! Windows FriendlyName), and only its ADDRESSES go into the `SettingEngine`
//! IP filter. An interface is Tailscale's when either
//! - its name contains `tailscale` (Windows `Tailscale`, Linux `tailscale0`), or
//! - it carries an address in Tailscale's fixed ULA `fd7a:115c:a1e0::/48`
//!   (also on macOS, whose kernel-named `utunN` says nothing about its owner).
//!
//! Our own overlay interface is never matched (`peer::is_overlay_iface`), and
//! the overlay's own ULA (`fd72:6f6f:6d6c::/48`) is a different prefix.
//!
//! Default OFF (opt-in: `MESHHARBORD_ICE_SKIP_TAILSCALE_HOST=1`/`true`/`yes`/`on`).
//! Field A/B 2026-11-11, interleaved 3 vs 3 on that same LAN: ON removed the
//! Tailscale pair every time (0/3 first pairs on it vs 3/3 OFF), but ttff got
//! WORSE (1.24–1.52 s ON vs 0.85–0.90 s OFF): the next pair the browser
//! nominates is srflx or relay, not the LAN host pair, which arrives late in
//! both arms. Until the LAN pair is first, the Tailscale pair is the faster
//! start, so the skip stays opt-in.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};

use tunnel_core::env::node_env;
use webrtc::ice::agent::agent_config::IpFilterFn;

use crate::rc_overlay::RcOverlay;

/// Tailscale's ULA, assigned on every OS next to the node's `100.x` address.
const TAILSCALE_ULA: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0);
const TAILSCALE_ULA_PREFIX: u32 = 48;

fn in_tailscale_ula(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            let mask = u128::MAX << (128 - TAILSCALE_ULA_PREFIX);
            (u128::from(*v6) & mask) == (u128::from(TAILSCALE_ULA) & mask)
        }
        IpAddr::V4(_) => false,
    }
}

/// `MESHHARBORD_ICE_SKIP_TAILSCALE_HOST`: default off; only `1`/`true`/`yes`/`on` turn it on.
pub fn parse_skip_enabled(raw: Option<&str>) -> bool {
    matches!(
        raw.map(str::trim),
        Some(v) if v == "1"
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
    )
}

pub fn skip_enabled_from_env() -> bool {
    let val = node_env("ICE_SKIP_TAILSCALE_HOST")
        .or_else(|| std::env::var("MESHHARBOR_ICE_SKIP_TAILSCALE_HOST").ok());
    parse_skip_enabled(val.as_deref())
}

/// Every address of every Tailscale interface in `ifaces` (`(name, ip)` rows,
/// one per address, as `if-addrs` lists them).
pub fn tailscale_ips<I>(ifaces: I) -> HashSet<IpAddr>
where
    I: IntoIterator<Item = (String, IpAddr)>,
{
    let mut by_iface: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for (name, ip) in ifaces {
        by_iface.entry(name).or_default().push(ip);
    }
    let mut out = HashSet::new();
    for (name, ips) in by_iface {
        if crate::peer::is_overlay_iface(&name) {
            continue;
        }
        let named = name.to_ascii_lowercase().contains("tailscale");
        if named || ips.iter().any(in_tailscale_ula) {
            out.extend(ips);
        }
    }
    out
}

/// This host's Tailscale addresses to leave out of ICE host candidates; empty
/// when the switch is off or the interfaces cannot be listed (fail open to the
/// old behaviour: a listing error must never cost a session its candidates).
pub fn host_ips_to_skip() -> HashSet<IpAddr> {
    if !skip_enabled_from_env() {
        return HashSet::new();
    }
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => tailscale_ips(ifaces.into_iter().map(|i| (i.name.clone(), i.ip()))),
        Err(_) => HashSet::new(),
    }
}

/// The session's `SettingEngine` IP filter: the overlay rule from
/// [`RcOverlay::keeps_local`] (only when the device keeps RC off the overlay)
/// AND not one of `skip`. `None` when neither applies, so no filter is
/// installed, exactly as before.
pub fn local_ip_filter(rc_overlay: &RcOverlay, skip: HashSet<IpAddr>) -> Option<IpFilterFn> {
    if rc_overlay.allow && skip.is_empty() {
        return None;
    }
    let keep = rc_overlay.clone();
    Some(Box::new(move |ip: IpAddr| {
        keep.keeps_local(ip) && !skip.contains(&ip)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn row(name: &str, ip: &str) -> (String, IpAddr) {
        (name.to_string(), ip.parse().unwrap())
    }

    #[test]
    fn windows_friendly_name_tailscale_is_skipped_and_lan_kept() {
        let s = tailscale_ips(vec![
            row("Tailscale", "100.101.102.103"),
            row("Tailscale", "fd7a:115c:a1e0::aa"),
            row("Wi-Fi", "192.168.1.50"),
        ]);
        assert_eq!(s.len(), 2);
        assert!(s.contains(&"100.101.102.103".parse().unwrap()));
        assert!(!s.contains(&"192.168.1.50".parse().unwrap()));
    }

    #[test]
    fn linux_tailscale0_is_skipped() {
        let s = tailscale_ips(vec![
            row("tailscale0", "100.90.1.2"),
            row("eth0", "10.0.0.5"),
        ]);
        assert_eq!(s, HashSet::from(["100.90.1.2".parse().unwrap()]));
    }

    #[test]
    fn macos_utun_is_identified_by_the_tailscale_ula_only() {
        let s = tailscale_ips(vec![
            row("utun4", "100.90.1.2"),
            row("utun4", "fd7a:115c:a1e0:ab12::1"),
            // Another VPN's utun with a CGNAT address but no Tailscale ULA: kept.
            row("utun2", "100.70.0.5"),
            row("en0", "192.168.1.10"),
        ]);
        assert_eq!(
            s,
            HashSet::from([
                "100.90.1.2".parse().unwrap(),
                "fd7a:115c:a1e0:ab12::1".parse().unwrap()
            ])
        );
    }

    #[test]
    fn isp_cgnat_address_on_a_physical_nic_is_kept() {
        let s = tailscale_ips(vec![
            row("Ethernet", "100.72.3.4"),
            row("wlan0", "100.100.9.9"),
        ]);
        assert!(s.is_empty(), "{s:?}");
    }

    #[test]
    fn our_overlay_interface_is_never_skipped() {
        let s = tailscale_ips(vec![
            row("MeshHarbor", "100.64.0.7"),
            // Even a (hypothetical) Tailscale-prefix address on our own adapter.
            row("MeshHarbor", "fd7a:115c:a1e0::7"),
            row("meshharbor0", "100.64.0.8"),
        ]);
        assert!(s.is_empty(), "{s:?}");
    }

    #[test]
    fn the_overlay_mesh_ula_is_not_tailscale() {
        assert!(!in_tailscale_ula(&"fd72:6f6f:6d6c::1".parse().unwrap()));
        assert!(in_tailscale_ula(&"fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(!in_tailscale_ula(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    }

    #[test]
    fn switch_defaults_off_and_only_explicit_values_turn_it_on() {
        assert!(!parse_skip_enabled(None));
        assert!(!parse_skip_enabled(Some("")));
        assert!(!parse_skip_enabled(Some("0")));
        assert!(!parse_skip_enabled(Some("garbage")));
        for on in ["1", "true", "ON", " yes "] {
            assert!(parse_skip_enabled(Some(on)), "{on}");
        }
    }

    #[test]
    fn filter_is_absent_when_overlay_is_allowed_and_nothing_to_skip() {
        let allow = RcOverlay {
            allow: true,
            v4_nets: Vec::new(),
        };
        assert!(local_ip_filter(&allow, HashSet::new()).is_none());
    }

    #[test]
    fn filter_drops_only_the_skipped_addresses_when_overlay_is_allowed() {
        let allow = RcOverlay {
            allow: true,
            v4_nets: Vec::new(),
        };
        let ts: IpAddr = "100.101.102.103".parse().unwrap();
        let f = local_ip_filter(&allow, HashSet::from([ts])).expect("filter");
        assert!(!f(ts));
        assert!(f("192.168.1.50".parse().unwrap()));
        assert!(
            f("100.72.3.4".parse().unwrap()),
            "other CGNAT addresses stay"
        );
    }

    #[test]
    fn filter_keeps_the_overlay_rule_and_adds_the_skip_set() {
        let off = RcOverlay {
            allow: false,
            v4_nets: vec![(Ipv4Addr::new(100, 64, 0, 0), 24)],
        };
        let ts: IpAddr = "100.101.102.103".parse().unwrap();
        let f = local_ip_filter(&off, HashSet::from([ts])).expect("filter");
        assert!(
            !f("100.64.0.9".parse().unwrap()),
            "overlay block still filtered"
        );
        assert!(!f(ts), "tailscale address filtered");
        assert!(f("192.168.1.50".parse().unwrap()));
    }
}
