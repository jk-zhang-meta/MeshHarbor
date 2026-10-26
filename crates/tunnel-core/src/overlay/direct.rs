// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Direct (LAN) carrier discovery for the overlay (rc.131).
//!
//! The overlay was relay-only: every peer connection rode a coturn TURN
//! allocation, even two machines on the same Wi-Fi LAN. That made it fragile
//! (it dies whenever a node can't reach coturn — UDP-blocked / TLS-inspected
//! corporate nets, carrier-CGNAT cellular) and added a relay hop's latency to
//! same-LAN peers. This module adds the **direct LAN path** (Tailscale's
//! direct-first model): a node advertises its LAN endpoint, and two peers on
//! the **same /24** build a direct UDP [`Carrier`](super::wg::Carrier) and skip
//! the relay entirely.
//!
//! Scope: **same-subnet only** (reliable L2 reachability — no NAT hole-punch,
//! no handshake-timeout fallback). Peers NOT on a shared subnet still use the
//! relay exactly as before. rc.131 advertised one interface (a connect-trick);
//! **rc.132 enumerates ALL interfaces** (a multi-homed host advertises every
//! LAN IP — field host WINHOST-A routes the internet via corporate Ethernet but
//! its peer is on the Wi-Fi). srflx hole-punch + an AP-isolation relay-fallback
//! are later follow-ups. See `docs/overlay-wfp.md` siblings.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

/// `ROOMLERD_OVERLAY_DIRECT` (the older `ROOMLER_NODE_OVERLAY_DIRECT` still
/// honoured — see [`crate::env::node_env`]) — default **ON**. Set
/// `0`/`false`/`no`/`off` to disable the direct LAN path and force pure relay
/// (the pre-rc.131 behaviour) if a field host misbehaves. Matches the node's
/// truthy convention (and the WFP gate's).
pub fn direct_enabled() -> bool {
    match crate::env::node_env("OVERLAY_DIRECT") {
        Some(v) => {
            let t = v.trim();
            !(t.eq_ignore_ascii_case("0")
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        None => true,
    }
}

/// Built-in stable base port for the direct sockets (see [`direct_port`]).
/// Deliberately NOT 41641 (Tailscale's WireGuard port — fleet hosts run both)
/// and not 51820 (kernel WireGuard's default).
///
/// ⚠️ Chosen ABOVE the Hyper-V / WSL2-mirrored / HNS reservation zone. Those
/// stacks reserve large port pools that are invisible to BOTH `netstat` AND
/// `netsh interface ipv4 show excludedportrange` — the same trap
/// `rc_local_turn`'s fallback band documents. Field-measured on DEVBOX
/// (WSL-mirrored) 2026-08-05: **41000–41800+ all unbindable**, 41989 and up
/// free — which swallowed the original 41648 default whole. The zones are
/// allocated dynamically and MOVE between boots, so the band walk below is
/// the real defense; this constant only picks a good starting point.
pub const DEFAULT_DIRECT_PORT: u16 = 43648;

/// How many consecutive ports [`direct_port_candidates`] walks before giving
/// up on a stable port. A swallowed base costs us one port, not the feature.
pub const DIRECT_PORT_BAND: u16 = 8;

/// Offset from the LAN band to the public/srflx dialer's band. The dialer
/// binds `0.0.0.0`, which collides with the interface-specific LAN binds on
/// the SAME port (no SO_REUSEADDR — its Windows UDP semantics allow unsafe
/// double delivery), so it needs its own band, far enough away that a LAN
/// walk can never run into it.
///
/// 256 (was 32, then 128, 2026-08-15): the agent DERIVES its default base
/// from the machine id — 32 slots of stride 8 spanning `43648..=43896` —
/// so two nodes behind ONE NAT pick distinct stable ports by construction
/// (the household-siblings collision: only one host's external 43648
/// could be destination-independent; the other's srflx went
/// per-destination and every inbound punch landed on the sibling). The
/// offset must clear the WHOLE derived direct region: +256 lands every
/// public band in `43904..44159`, disjoint from all 32 direct bands and
/// from each other. Public-dial flows are cold in the field (rx=0 on
/// every host inspected), so the one-time port move on upgrade costs
/// nothing.
pub const PUBLIC_DIAL_PORT_OFFSET: u16 = 256;

/// Fallback jump when a base's ENTIRE walk band is locally unbindable
/// (a Hyper-V/WSL dynamic reservation swallowing all 8 ports — the zones
/// MOVE between boots): before surrendering to ephemeral ports (which
/// forfeits 5-tuple stability), [`direct_port_candidates`] retries the
/// same walk in a SECOND region at `base + 512`. The jump clears the
/// whole primary layout (direct `43648..43903` + public `43904..44159`),
/// landing band-2 direct in `44160..44415` and its public twin in
/// `44416..44671` — all still under the ~49152 dynamic-range floor and
/// far above the measured 41000-41800 reservation cluster. Siblings stay
/// de-conflicted in band 2 because the slot offset is preserved.
pub const SECOND_BAND_OFFSET: u16 = 512;

/// The stable-port candidates for one socket, in a FIXED order: the same
/// host re-binds the same port after a restart as long as availability is
/// unchanged — which is the whole point (a reproducible UDP 5-tuple that a
/// stateful corp firewall keeps treating as the flow it already
/// grandfathered). `base == 0` yields nothing (ephemeral opt-out).
///
/// Walks the primary band, then the SAME walk in the second derived
/// region (`base + `[`SECOND_BAND_OFFSET`]) — a dynamic Hyper-V/WSL
/// reservation that swallows the whole primary band costs a region jump,
/// not the stable-port feature. Fixed order both times, so band-2 binds
/// are just as reproducible across restarts.
pub fn direct_port_candidates(base: u16) -> impl Iterator<Item = u16> + Clone {
    let n = if base == 0 { 0 } else { DIRECT_PORT_BAND };
    (0..n)
        .filter_map(move |i| base.checked_add(i))
        .chain((0..n).filter_map(move |i| {
            base.checked_add(SECOND_BAND_OFFSET)
                .and_then(|b| b.checked_add(i))
        }))
}

/// Stable UDP port for the overlay's direct sockets
/// (`ROOMLERD_OVERLAY_DIRECT_PORT`; config key `overlay_direct_port`).
///
/// Per-interface LAN sockets bind `(iface_ip, port)`; the public/srflx
/// dialer binds `(0.0.0.0, port+1)` (a wildcard bind on the SAME port as a
/// specific-IP bind fails without SO_REUSEADDR). `0` = ephemeral ports, the
/// pre-rc.307 behavior.
///
/// Why a stable port: stateful corp firewalls (Check Point on winhost-a)
/// GRANDFATHER UDP flows that predate the VPN's session table — direct
/// carriers established before the VPN connects keep working, but any
/// rebuild (agent update, control-WS reconnect on a server deploy) used to
/// bind fresh ephemeral ports, presenting a NEW 5-tuple the VPN then drops,
/// relay-locking the node until the next VPN-off window. With both fleet
/// ends on stable ports, a rebuilt carrier reproduces the SAME 5-tuple and
/// keeps riding the grandfathered session (2026-08-05 field diagnosis:
/// 7/7 VPN-off rebuilds promoted LAN direct, 10/10 VPN-on rebuilds never).
///
/// Unparseable values fall back to the default (a typo must not silently
/// turn the feature off fleet-wide).
pub fn direct_port() -> u16 {
    match crate::env::node_env("OVERLAY_DIRECT_PORT") {
        Some(v) => match v.trim().parse::<u32>() {
            // W5 close-out (2026-08-18) — `0` (ephemeral ports) is
            // DEPRECATED: the stable port is what lets srflx mappings and
            // firewall-grandfathered flows survive VPN cycles and daemon
            // restarts (field-proven: recovery in seconds with a
            // near-identical mapping vs a fresh random 5-tuple the corp
            // session table drops). Honored for now; warned once per
            // process; scheduled for removal.
            Ok(0) => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(
                        "overlay_direct_port=0 (ephemeral ports) is DEPRECATED and will be \
                         removed — the stable port keeps srflx mappings + grandfathered \
                         corp-firewall flows alive across VPN cycles and restarts; unset \
                         the key to use the stable default"
                    );
                });
                0
            }
            // Cap leaves room for the public dialer's band
            // (`base + PUBLIC_DIAL_PORT_OFFSET + DIRECT_PORT_BAND`).
            Ok(n) if n <= MAX_DIRECT_PORT_BASE as u32 => n as u16,
            _ => DEFAULT_DIRECT_PORT,
        },
        None => DEFAULT_DIRECT_PORT,
    }
}

/// Largest accepted `overlay_direct_port` base — the whole public-dial band
/// must still fit under 65535. Mirrored by the agent's config-surface
/// validation.
pub const MAX_DIRECT_PORT_BASE: u16 =
    u16::MAX - SECOND_BAND_OFFSET - PUBLIC_DIAL_PORT_OFFSET - DIRECT_PORT_BAND;

/// Enumerate this node's usable LAN IPv4 addresses across **all** interfaces,
/// so a multi-homed host advertises every LAN endpoint and a peer matches
/// whichever is on its subnet.
///
/// rc.132 — replaces the rc.131 connect-trick (default-route IP only), which
/// picked the WRONG interface on a multi-homed host: field host WINHOST-A routes
/// the internet via its corporate Ethernet (`172.30.x`) but its overlay peer
/// (DEVBOX) is on the Wi-Fi (`192.168.68.x`), so the single default-route IP it
/// advertised was unreachable by the peer → no same-subnet match → fell back
/// to the (failing) relay. Enumerating all interfaces advertises both, so the
/// peer finds the `192.168.68.x` one.
///
/// Excludes loopback / link-local / CGNAT (`100.64.0.0/10` — the overlay's own
/// range + some cellular carriers). Order is `get_if_addrs`' (stable enough);
/// dups removed. Empty if enumeration fails (→ relay only, as before).
/// Every IPv4 network directly connected to this host (each interface's
/// address and netmask, masked), loopback and the overlay's own CGNAT space
/// excluded. Unlike [`gather_lan_interfaces`] nothing is filtered as virtual:
/// a subnet route over ANY connected network would cut the host off from it.
pub fn local_lan_cidrs() -> Vec<crate::overlay::router::Cidr> {
    let mut out = Vec::new();
    let Ok(addrs) = if_addrs::get_if_addrs() else {
        return out;
    };
    for a in addrs {
        let if_addrs::IfAddr::V4(v4) = a.addr else {
            continue;
        };
        let o = v4.ip.octets();
        if v4.ip.is_loopback() || (o[0] == 100 && (o[1] & 0xc0) == 0x40) {
            continue;
        }
        let prefix = u32::from(v4.netmask).leading_ones();
        if let Some(c) = crate::overlay::router::Cidr::parse(&format!("{}/{prefix}", v4.ip))
            && !out.contains(&c)
        {
            out.push(c);
        }
    }
    out
}

pub fn gather_lan_ips() -> Vec<Ipv4Addr> {
    gather_lan_interfaces()
        .into_iter()
        .map(|(ip, _)| ip)
        .collect()
}

/// Like [`gather_lan_ips`] but also returns each interface's OS index (for
/// `IP_UNICAST_IF` egress pinning — rc.144). The index is `None` when
/// `if-addrs` can't supply one (then egress can't be pinned — the socket falls
/// back to rc.143 source-IP binding only). Deduped by IP.
pub fn gather_lan_interfaces() -> Vec<(Ipv4Addr, Option<u32>)> {
    let mut out: Vec<(Ipv4Addr, Option<u32>)> = Vec::new();
    let filter = lan_iface_filter_enabled();
    // A WSL2 guest under MIRRORED networking has NO LAN identity of its own:
    // every address it can see is the Windows host's, mirrored in. Gathering
    // them is actively harmful, not merely useless —
    //
    //   * the guest binds `(host_lan_ip, port)` and STARVES the host agent's
    //     own socket. Field 2026-08-14: devbox went 8/8 direct → 0/8, every
    //     peer `saw_inbound=false`, until the guest's agent was stopped. A
    //     different port did NOT help; the address is what matters.
    //   * the host, seeing the guest advertise the host's own address, gets a
    //     phantom LAN candidate — which then suppresses srflx as a same-NAT
    //     hairpin, leaving the pair with no tier that can ever promote (#436).
    //
    // The guest keeps srflx + relay, which is the honest reachability of a
    // machine with no independent network presence.
    if wsl_mirrored_guard_enabled() && wsl2_mirrored_networking() {
        return out;
    }
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for a in addrs {
            if let std::net::IpAddr::V4(ip) = a.ip()
                && is_usable_lan_ipv4(ip)
                && !out.iter().any(|(existing, _)| *existing == ip)
            {
                // rc.275 hygiene — skip virtual / host-only / other-VPN
                // interfaces (see `lan_iface_denied`). Field: winhost-a
                // advertised its WSL vEthernet `172.31.176.1` (a host-only
                // NAT address no peer can ever reach) and its Check Point
                // VPN `172.30.x` as "LAN" endpoints, each with a pinned
                // per-interface socket — poisoning the same-/24 match for
                // every peer that happens to share those private ranges.
                if filter {
                    let info = a.index.and_then(iface_info);
                    let desc = info.as_ref().map(|(d, _)| d.as_str()).unwrap_or_default();
                    let hardware = info.as_ref().map(|(_, h)| *h);
                    // rc.281 — `hardware == Some(false)` fails CLOSED for VPN
                    // vendors the deny-list has never heard of (the list only
                    // grows after a field incident; the hardware bit needs no
                    // vendor knowledge). Caveat: NIC-teaming/VLAN child
                    // adapters also report non-hardware and would be skipped —
                    // rare on the fleet, benign direction (not advertised ⇒
                    // relay still works), and `overlay_lan_iface_filter=0`
                    // restores the unfiltered gather. `None` (lookup failed /
                    // non-Windows) keeps the name-only checks as the deciders.
                    let tunnel = linux_tunnel_iface(&a.name);
                    if lan_iface_denied(&a.name, desc) || hardware == Some(false) || tunnel {
                        tracing::debug!(
                            iface = %a.name, %ip, desc = %desc, hardware = ?hardware, tunnel,
                            "overlay: LAN gather — skipping virtual/host-only interface"
                        );
                        continue;
                    }
                }
                out.push((ip, a.index));
            }
        }
    }
    out
}

/// §6 item 5 — `OVERLAY_IPV6` (default on): bind an IPv6 direct socket and
/// advertise this node's global IPv6 addresses among its srflx candidates, so
/// two IPv6-capable peers go direct with no NAT in the way. Only a stateful
/// firewall can stand between them, and the simultaneous dial of a srflx
/// punch opens that the same way it opens a NAT's filter.
pub fn ipv6_enabled() -> bool {
    crate::env::flag("OVERLAY_IPV6", true)
}

/// A global-unicast IPv6 (`2000::/3`): routable across the internet. This
/// excludes link-local, ULA (`fc00::/7`, which includes other mesh VPNs'
/// ranges), loopback, multicast and the IPv4-mapped range.
pub fn is_public_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xe000) == 0x2000
}

/// This host's global IPv6 addresses, deduplicated, from the same interface
/// hygiene as [`gather_lan_interfaces`] (no virtual, host-only or other-VPN
/// interfaces; nothing under the WSL2 mirrored guard).
pub fn gather_global_v6() -> Vec<Ipv6Addr> {
    let mut out = Vec::new();
    if wsl_mirrored_guard_enabled() && wsl2_mirrored_networking() {
        return out;
    }
    let filter = lan_iface_filter_enabled();
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for a in addrs {
            let std::net::IpAddr::V6(ip) = a.ip() else {
                continue;
            };
            if !is_public_v6(ip) || out.contains(&ip) {
                continue;
            }
            if filter {
                let info = a.index.and_then(iface_info);
                let desc = info.as_ref().map(|(d, _)| d.as_str()).unwrap_or_default();
                if lan_iface_denied(&a.name, desc) || info.as_ref().map(|(_, h)| *h) == Some(false) {
                    continue;
                }
            }
            out.push(ip);
        }
    }
    out
}

/// The srflx candidates for our IPv6 socket: `[addr]:port` per address.
pub fn v6_candidates(addrs: &[Ipv6Addr], port: u16) -> Vec<String> {
    addrs
        .iter()
        .map(|ip| SocketAddrV6::new(*ip, port, 0, 0).to_string())
        .collect()
}

/// How many srflx-tier strikes the peer's IPv6 candidates get before the
/// dialer falls back to its IPv4 ones (a success resets strikes, so IPv6 is
/// tried first again).
pub const V6_FIRST_STRIKES: u32 = 2;

/// [`pick_public_endpoint_rotated`]'s IPv6 twin: the peer's global IPv6
/// srflx candidates, never one of our own addresses.
pub fn pick_v6_endpoint_rotated(
    my_v6: &[Ipv6Addr],
    candidates: &[String],
    attempt: u32,
) -> Option<SocketAddr> {
    let viable: Vec<SocketAddr> = candidates
        .iter()
        .filter_map(|ep| match ep.trim().parse::<SocketAddr>() {
            Ok(SocketAddr::V6(sa)) if is_public_v6(*sa.ip()) && !my_v6.contains(sa.ip()) => {
                Some(SocketAddr::V6(sa))
            }
            _ => None,
        })
        .collect();
    viable.get(attempt as usize % viable.len().max(1)).copied()
}

/// First `(ip, ifindex)` from the deny-listed LAN gather — the physical-uplink
/// egress candidate for a TURN/STUN client socket on a corp-VPN-captured host.
/// An UNSPECIFIED-bound socket source-selects the captured default route and
/// its UDP dies inside the tunnel; binding this IP (+ the `IP_UNICAST_IF` pin
/// when the index is known) escapes the capture exactly like the direct socks
/// do. Field 2026-08-15 winhost-b: srflx `cone via 5.9.157.221:3478` from the
/// bound direct sock while the unbound warm TURN allocate to the SAME host
/// failed every candidate. `None` when the gather is empty (enumeration
/// failure or a WSL-mirrored guest) — callers then keep the unbound behaviour.
pub fn first_non_vpn_uplink() -> Option<(Ipv4Addr, Option<u32>)> {
    gather_lan_interfaces().into_iter().next()
}

/// Net-change poke acceleration — gate for arming forced revalidation pokes on
/// every established direct carrier when an OS addr/iface event fires
/// (`ROOMLERD_OVERLAY_NETCHANGE_POKE`). Default **ON**; set
/// `0`/`false`/`no`/`off` to fall back to the passive gates
/// (`POKE_SILENCE_AFTER` + rx-stale) if forced pokes ever misbehave in the
/// field. The mechanism is safe by construction — an answered poke clears with
/// no side effects — so this exists as an emergency valve, not a rollout gate.
pub fn netchange_poke_enabled() -> bool {
    match crate::env::node_env("OVERLAY_NETCHANGE_POKE") {
        Some(v) => {
            let t = v.trim();
            !(t.eq_ignore_ascii_case("0")
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        None => true,
    }
}

/// rc.275 hygiene — gate for the LAN-gather virtual-interface filter
/// (`ROOMLERD_OVERLAY_LAN_IFACE_FILTER` — see [`crate::env::node_env`]).
/// Default **ON**; set `0`/`false`/`no`/`off` to restore the unfiltered
/// pre-rc.275 gather if the deny-list ever misclassifies a real NIC in the
/// field (the failure mode is benign either way — a skipped interface just
/// isn't advertised, and the relay path still works).
pub fn lan_iface_filter_enabled() -> bool {
    match crate::env::node_env("OVERLAY_LAN_IFACE_FILTER") {
        Some(v) => {
            let t = v.trim();
            !(t.eq_ignore_ascii_case("0")
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        None => true,
    }
}

/// Gate for the WSL2 **mirrored-networking** guard
/// (`ROOMLERD_OVERLAY_WSL_MIRRORED_GUARD`; config `overlay_wsl_mirrored_guard`).
/// Default **ON**; set `0`/`false`/`no`/`off` to restore the pre-guard gather.
pub fn wsl_mirrored_guard_enabled() -> bool {
    crate::env::flag("OVERLAY_WSL_MIRRORED_GUARD", true)
}

/// The loopback-scoped address WSL2 assigns for host access. Its presence
/// alongside a WSL2 kernel is the marker for **mirrored** networking — in NAT
/// mode the guest gets a private `172.x` on `eth0` and no such loopback alias.
#[cfg(target_os = "linux")]
const WSL_MIRRORED_HOST_ACCESS: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 254);

/// Pure half of [`wsl2_mirrored_networking`] so the classification is testable
/// without `/proc` or a WSL kernel. cfg-gated to its callers (the Linux
/// detector + tests) — on Windows/macOS non-test builds it would otherwise
/// be dead code, and those builds are exactly the ones CI's Linux matrix
/// never lints.
#[cfg(any(target_os = "linux", test))]
fn wsl2_mirrored_from_parts(osrelease: &str, has_host_access_alias: bool) -> bool {
    osrelease.to_ascii_lowercase().contains("wsl2") && has_host_access_alias
}

/// Are we a WSL2 guest running **mirrored** networking?
///
/// Mirrored mode gives the guest the HOST's adapters verbatim, so every
/// non-overlay address it can see belongs to the Windows host, not to it.
/// Field 2026-08-14, devbox's guest:
///
/// ```text
/// lo    10.255.255.254/32   ← the marker
/// eth2  192.168.68.126/24   ← the host's Wi-Fi address
/// eth3  100.65.0.6/22       ← the host's OVERLAY address
/// eth4  100.65.4.2/22       ← the host's OVERLAY address
/// ```
///
/// Cached: mirrored-vs-NAT cannot change without restarting the guest.
#[cfg(target_os = "linux")]
pub fn wsl2_mirrored_networking() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let alias = if_addrs::get_if_addrs().is_ok_and(|addrs| {
            addrs.iter().any(|a| match a.ip() {
                std::net::IpAddr::V4(ip) => ip == WSL_MIRRORED_HOST_ACCESS,
                _ => false,
            })
        });
        let mirrored = wsl2_mirrored_from_parts(&osrelease, alias);
        if mirrored {
            tracing::warn!(
                "overlay: WSL2 MIRRORED networking detected — this guest shares the Windows \
                 host's adapters, so its visible LAN addresses belong to the HOST. Skipping \
                 them for LAN candidates and direct binds; the guest reaches the mesh via \
                 srflx/relay. Binding them starves the host agent's own sockets (2026-08-14)."
            );
        }
        mirrored
    })
}

/// Non-Linux hosts are never a WSL guest.
#[cfg(not(target_os = "linux"))]
pub fn wsl2_mirrored_networking() -> bool {
    false
}

/// rc.275 hygiene — `true` when an interface must NOT be advertised as a LAN
/// endpoint (nor given a pinned per-interface direct socket): virtual
/// switches, host-only NATs, container bridges, and OTHER VPNs' adapters.
/// Their addresses are unreachable by any real peer, and advertising them
/// poisons the same-/24 LAN match (rc.204 family). Matched case-insensitively
/// against the interface NAME and (Windows) the driver DESCRIPTION — the
/// Check Point adapter's friendly name is just "Ethernet"; only its
/// description ("Check Point Virtual Network Adapter …") gives it away.
/// webrtc-ice solves this with an application `interface_filter` callback;
/// the overlay gathers directly, so the deny-list lives here. Pure.
pub fn lan_iface_denied(name: &str, description: &str) -> bool {
    // Substring matches — vendor-grade names/descriptions (either field).
    const SUBSTRING: &[&str] = &[
        "vethernet", // Hyper-V "vEthernet (WSL …)" / "vEthernet (Default Switch)"
        "hyper-v",   // "Hyper-V Virtual Ethernet Adapter"
        "wsl",       // WSL switch names
        "virtual",   // "… Virtual Network Adapter" (Check Point, VMware, …)
        "vmware",
        "vmnet",
        "virtualbox",
        "vbox",
        "wintun", // stale/orphaned Wintun stubs ("Wintun Userspace Tunnel")
        "wireguard",
        "tailscale",
        "zerotier",
        "openvpn",
        "ovpn",
        "tap-windows",
        "check point",
        "pangp",
        "fortissl",
        "juniper",
        "loopback",
    ];
    // Prefix matches on the NAME — kernel/driver naming conventions
    // (Linux/macOS/BSD: docker0, veth*, virbr0, br-*, tun0, tap0, utun3,
    // wg0, ppp0, bridge100). Prefix (not substring) so real adapters whose
    // names merely CONTAIN these stay allowed.
    const NAME_PREFIX: &[&str] = &[
        "docker", "veth", "virbr", "br-", "bridge", "tun", "tap", "utun", "wg", "ppp", "roomler",
    ];
    let n = name.to_ascii_lowercase();
    let d = description.to_ascii_lowercase();
    SUBSTRING.iter().any(|s| n.contains(s) || d.contains(s))
        || NAME_PREFIX.iter().any(|p| n.starts_with(p))
}

/// Windows — the interface DESCRIPTION + hardware bit for an OS ifindex via
/// `GetIfEntry2`. The description ("Check Point Virtual Network Adapter For
/// Endpoint VPN Client") feeds the deny-list — the friendly name alone can't
/// classify these (the Check Point adapter is named just "Ethernet"). The
/// `HardwareInterface` flag (rc.281) is the STRUCTURAL signal the deny-list
/// can't be: every virtual adapter — Wintun, Hyper-V vSwitch, any VPN vendor
/// we've never heard of — reports `false`, while physical Ethernet/Wi-Fi
/// report `true`, so unknown vendors now fail CLOSED instead of open.
/// `None` on lookup failure (then the name-only checks still apply).
#[cfg(all(windows, feature = "overlay-l3"))]
fn iface_info(ifindex: u32) -> Option<(String, bool)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
    // SAFETY: zeroed row + InterfaceIndex is the documented lookup-by-index
    // call shape; GetIfEntry2 fills the row on NO_ERROR (0).
    unsafe {
        let mut row: MIB_IF_ROW2 = std::mem::zeroed();
        row.InterfaceIndex = ifindex;
        if GetIfEntry2(&mut row) != 0 {
            return None;
        }
        let len = row
            .Description
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(row.Description.len());
        // `InterfaceAndOperStatusFlags` is a packed C bitfield byte;
        // `HardwareInterface` is its FIRST member, and MSVC allocates
        // bitfields low-to-high ⇒ bit 0.
        let hardware = row.InterfaceAndOperStatusFlags._bitfield & 0x01 != 0;
        Some((String::from_utf16_lossy(&row.Description[..len]), hardware))
    }
}

/// No-op off Windows — Linux/macOS interface NAMES mostly follow the
/// conventions the prefix list catches (docker0, veth*, utun*, wg*…); a Linux
/// device that does not is caught by [`linux_tunnel_iface`].
#[cfg(not(all(windows, feature = "overlay-l3")))]
fn iface_info(_ifindex: u32) -> Option<(String, bool)> {
    None
}

/// Linux — `true` for a tunnel device of ANY name, the structural signal the
/// name prefixes assume away: every TUN/TAP has `tun_flags` in sysfs, and an L3
/// tunnel reports its link type (`ARPHRD_NONE` for WireGuard and an L3 TUN,
/// PPP, IPIP, SIT, GRE). Field 2026-10-25: EasyTier names its TUN `etitachi0`,
/// so its private address was gathered as a LAN endpoint and three nodes "went
/// LAN" over the other mesh instead of the internet. Ethernet-type devices
/// (a container's veth, a bridge) stay allowed: they are a pod's real network.
#[cfg(target_os = "linux")]
fn linux_tunnel_iface(name: &str) -> bool {
    tunnel_iface_at(std::path::Path::new("/sys/class/net"), name)
}

#[cfg(not(target_os = "linux"))]
fn linux_tunnel_iface(_name: &str) -> bool {
    false
}

/// [`linux_tunnel_iface`] against a given sysfs `class/net` root (tests).
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn tunnel_iface_at(sys_class_net: &std::path::Path, name: &str) -> bool {
    // ARPHRD_PPP, _TUNNEL, _TUNNEL6, _SIT, _IPGRE, _IP6GRE, _NONE.
    const TUNNEL_TYPES: &[u32] = &[512, 768, 769, 776, 778, 823, 65534];
    let dir = sys_class_net.join(name);
    dir.join("tun_flags").exists()
        || std::fs::read_to_string(dir.join("type"))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
            .is_some_and(|t| TUNNEL_TYPES.contains(&t))
}

/// rc.144 — force outbound datagrams on `sock` out the interface with OS index
/// `ifindex` via Windows `IP_UNICAST_IF`. Binding the source IP (rc.143) sets
/// the address but NOT the egress NIC on Windows (the "weak host model" — the
/// routing table picks the NIC), so a full-tunnel VPN's default route still
/// steals egress and same-WiFi direct oscillates (field: 4-7ms when it wins the
/// race, timeouts otherwise). `IP_UNICAST_IF` pins the NIC deterministically —
/// the Windows equivalent of `SO_BINDTODEVICE`. Best-effort: warns + continues
/// (a clean host routes fine, and the source-IP bind still helps).
#[cfg(all(windows, feature = "overlay-l3"))]
pub fn force_egress_interface(sock: &tokio::net::UdpSocket, ifindex: u32) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{IPPROTO_IP, SOCKET, setsockopt};
    // IP_UNICAST_IF = 31. For IPv4 the value is the interface index in NETWORK
    // byte order (the classic gotcha — IPv6's IPV6_UNICAST_IF uses host order).
    const IP_UNICAST_IF: i32 = 31;
    let optval: u32 = ifindex.to_be();
    let ret = unsafe {
        setsockopt(
            sock.as_raw_socket() as SOCKET,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&optval as *const u32).cast::<u8>(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if ret == 0 {
        tracing::info!(
            ifindex,
            "overlay: pinned direct-socket egress to interface (IP_UNICAST_IF)"
        );
    } else {
        tracing::warn!(
            ifindex,
            "overlay: IP_UNICAST_IF failed; egress may follow the VPN default route"
        );
    }
}

/// No-op off Windows / without the WinSock bindings — the interface-bound
/// socket (rc.143) is the portable part; egress pinning is Windows-specific.
#[cfg(not(all(windows, feature = "overlay-l3")))]
pub fn force_egress_interface(_sock: &tokio::net::UdpSocket, _ifindex: u32) {}

/// Gate for **bind-to-interface-by-route** LAN-carrier egress selection
/// (`ROOMLERD_OVERLAY_BIND_BY_ROUTE`). **Default OFF** until field-proven,
/// mirroring the QUIC / `public_direct` arc. When on, a LAN direct carrier's
/// egress interface is chosen per-destination from the OS route table (the
/// connect-trick, [`os_src_ip_for`]) + [`classify_egress`], and the socket is
/// re-pinned to the CURRENT ifindex — instead of relying on the same-subnet
/// heuristic and a pin computed once at startup. This is Tailscale's
/// `bindToInterfaceByRoute` (net/netns) adapted to roomler: an on-link `/24`
/// beats a full-tunnel VPN's `/1` default, so a genuine same-LAN peer stays on
/// the physical NIC even under a corporate VPN, and a peer the OS routes
/// elsewhere (VPN-captured) falls to relay honestly instead of flapping a
/// one-way "direct".
pub fn bind_by_route_enabled() -> bool {
    match crate::env::node_env("OVERLAY_BIND_BY_ROUTE") {
        Some(v) => {
            let t = v.trim();
            t.eq_ignore_ascii_case("1")
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

/// Gate for **VPN-bypass** carrier egress (`ROOMLERD_OVERLAY_VPN_BYPASS`).
/// **Default OFF** opt-in. When on (and an uplink ifindex is resolved), EVERY
/// overlay underlay carrier socket — the `public_sock`, the single-relay
/// dialer, and the coturn TURN underlay — has its egress pinned
/// (`IP_UNICAST_IF`) to the host's real PHYSICAL uplink, forcing the overlay's
/// own transport out the physical NIC instead of a full-tunnel corporate VPN's
/// captured default route. Confirmed on CORP1 winhost-a (2026-07-30): a Check
/// Point full-tunnel VPN captured ALL egress (`Find-NetRoute` → every dst via
/// `172.30.x/Ethernet`), so its carriers rode the VPN one-way; pinning to the
/// physical Wi-Fi bypasses it. This is Tailscale's `net/netns` "bind to the
/// physical interface, not another VPN's tunnel" applied to the whole
/// underlay. Mirrors the `public_direct` opt-in arc; flips default-ON after
/// the winhost-a field-proof.
pub fn vpn_bypass_enabled() -> bool {
    match crate::env::node_env("OVERLAY_VPN_BYPASS") {
        Some(v) => {
            let t = v.trim();
            t.eq_ignore_ascii_case("1")
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

/// Operator-pinned physical-uplink OS interface index for [`vpn_bypass_enabled`]
/// (`ROOMLERD_OVERLAY_UPLINK_IF` = a numeric ifindex, e.g. the Wi-Fi
/// adapter's index from `Get-NetIPInterface`). This explicit override
/// field-proves the bypass mechanism before auto-discovery of the physical
/// uplink beneath a captured VPN is built. `None` when unset/unparseable.
pub fn uplink_ifindex_override() -> Option<u32> {
    crate::env::node_env("OVERLAY_UPLINK_IF").and_then(|v| v.trim().parse::<u32>().ok())
}

/// The physical-uplink ifindex a carrier underlay socket should pin its egress
/// to, or `None` to leave egress on the OS default route (today's behaviour).
/// `Some` only when VPN-bypass is enabled AND an uplink ifindex is resolved
/// (currently the explicit [`uplink_ifindex_override`]; auto-discovery later).
pub fn vpn_bypass_ifindex() -> Option<u32> {
    if vpn_bypass_enabled() {
        uplink_ifindex_override()
    } else {
        None
    }
}

/// The OS's chosen egress for a LAN direct destination, classified against the
/// interfaces we hold a bound socket on. Pure output of [`classify_egress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {
    /// The OS routes `dst` via an interface we hold a socket on (its source
    /// IP). Use that socket, re-pinned to its current ifindex.
    Use(Ipv4Addr),
    /// The OS routes `dst` back into the overlay's own CGNAT range (our TUN) —
    /// binding there would loop. Skip direct (the loop-guard).
    Loop,
    /// The OS routes `dst` via an interface we do NOT hold a LAN socket on
    /// (e.g. a full-tunnel VPN captured this destination). The same-subnet LAN
    /// carrier would be one-way → skip direct, fall to relay honestly.
    Foreign,
    /// The route query failed / gave no answer → caller keeps the pre-existing
    /// same-subnet behaviour (never worse than today).
    Unknown,
}

/// Classify the OS's chosen source IP for a LAN destination against the set of
/// interface IPs we hold a bound direct socket on. Pure (no I/O) so the
/// decision is unit-tested on synthetic data, exactly like
/// [`pick_same_subnet_endpoint`]. The loop-guard is [`is_cgnat`]: the overlay's
/// own TUN carries a `100.64.0.0/10` address, so an OS source-IP in that range
/// means the route resolves back into the overlay itself.
///
/// - `None` (query failed) → [`Egress::Unknown`].
/// - CGNAT source → [`Egress::Loop`].
/// - source ∈ `our_socket_ips` → [`Egress::Use`].
/// - any other source → [`Egress::Foreign`].
pub fn classify_egress(src_ip: Option<Ipv4Addr>, our_socket_ips: &[Ipv4Addr]) -> Egress {
    match src_ip {
        None => Egress::Unknown,
        Some(ip) if is_cgnat(ip) => Egress::Loop,
        Some(ip) if our_socket_ips.contains(&ip) => Egress::Use(ip),
        Some(_) => Egress::Foreign,
    }
}

/// The OS's chosen SOURCE IPv4 for reaching `dst` — the portable "which
/// interface would this packet leave from?" query (Tailscale's `connect()`
/// trick, `net/netns`): bind a throwaway UDP socket to `0.0.0.0:0`,
/// `connect(dst)` (which sends **no** packet — on a UDP socket it only sets the
/// default peer and makes the kernel resolve the route + assign a local
/// address), then read `local_addr()`. The kernel honours the full routing
/// table, so an on-link `/24` wins over a VPN's `/1` split-default and a genuine
/// same-LAN `dst` resolves to the physical NIC even under a full-tunnel VPN.
/// Works on every platform (including Windows, where it complements
/// `IP_UNICAST_IF`). `None` on any error → caller falls back to the same-subnet
/// heuristic.
pub async fn os_src_ip_for(dst: SocketAddr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    sock.connect(dst).await.ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() => Some(*a.ip()),
        _ => None,
    }
}

/// The CURRENT OS interface index for one of our LAN interface IPs, re-read
/// from [`gather_lan_interfaces`] at call time so the egress pin reflects the
/// live interface table (a VPN connect can add interfaces / renumber). `None`
/// if the IP is no longer present or `if-addrs` supplies no index.
pub fn ifindex_for(ip: Ipv4Addr) -> Option<u32> {
    gather_lan_interfaces()
        .into_iter()
        .find(|(i, _)| *i == ip)
        .and_then(|(_, ix)| ix)
}

/// True for an IPv4 that can serve as a same-LAN endpoint: not loopback, not
/// link-local (169.254), not unspecified/broadcast, and not in the overlay
/// CGNAT range `100.64.0.0/10` (which collides with both the overlay itself
/// and some cellular carriers).
pub fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !is_cgnat(ip)
}

/// `100.64.0.0/10` (RFC 6598 carrier-grade NAT) — also the overlay's own
/// address range.
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// NAT-traversal Phase A — opt-in gate for the **direct-to-public** carrier
/// tier (`ROOMLERD_OVERLAY_PUBLIC_DIRECT` — see [`crate::env::node_env`]).
/// **Default OFF** until field-proven, mirroring the QUIC gate's arc (CC8 in
/// the NAT-traversal plan). Gates the whole tier: dialing a peer's public
/// endpoint, AND the accept side (the runtime only wires the inbound-handshake
/// receiver when this is on). The accept path doubles as a roaming fix for
/// restarted same-LAN peers, but it rides this flag too so the fleet default
/// stays byte-identical until the tier is field-proven per-host.
pub fn public_direct_enabled() -> bool {
    match crate::env::node_env("OVERLAY_PUBLIC_DIRECT") {
        Some(v) => {
            let t = v.trim();
            t.eq_ignore_ascii_case("1")
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

/// Gate for **make-before-break** carrier upgrades (`ROOMLERD_OVERLAY_MBB`).
/// **Default ON since rc.210** — field-proven 2026-07-25 on the netns NAT lab
/// (buildhost↔fleet-host-2, the false-same-/24-LAN-match freeze scenario):
/// MBB=1 held the relay while a doomed direct upgrade was probed then dropped
/// it ("kept relay (no stall)"), where MBB=0 tore the relay down ("upgrading
/// relay peer to direct LAN carrier"). Disable per-host with
/// `ROOMLERD_OVERLAY_MBB=0` (kill-switch): only an explicit
/// `0`/`false`/`no`/`off` turns it back off; unset / truthy / anything else
/// keeps the default ON.
///
/// A relay→direct UPGRADE installs the candidate direct carrier as a SHADOW
/// PROBE (its own `Tunn`, in `WgDevice::probes`) while the working relay keeps
/// routing, and only cuts over once the probe's handshake latches (proof the
/// direct path works both ways). If the probe never latches within the tier's
/// deadline it is dropped and the relay is untouched — so a peer that can only
/// ever relay (same-NAT AP-isolation / no hairpin) never suffers the ~15–38 s
/// freeze the old break-before-make upgrade caused every re-upgrade tick (it
/// tore the relay down, gambled on an unreachable direct path, then
/// re-established relay). `=0` ⇒ the pre-rc.208 destructive upgrade, byte-for-
/// byte. Covers BOTH the outbound upgrade AND the inbound-accept path
/// (`handle_direct_inbound`) since rc.209.
/// Birth probe: a peer whose first carrier is the DERP floor and that has a LAN
/// candidate starts its make-before-break LAN probe at birth, instead of waiting
/// for the next ~30 s re-upgrade walk. F0 measured every LAN pair spending ~30 s
/// on the floor first. `=0` restores the walk-only upgrade.
pub fn birth_lan_probe_enabled() -> bool {
    crate::env::flag("OVERLAY_BIRTH_LAN_PROBE", true)
}

/// A make-before-break probe that has LATCHED is promoted on the next 1 s
/// business-scout tick instead of waiting for the 5 s fallback sweep, which
/// was most of a fresh LAN pair's remaining time on the floor (F0). Expiry
/// stays on the fallback sweep. `=0` restores fallback-only promotion.
pub fn fast_probe_promote_enabled() -> bool {
    crate::env::flag("OVERLAY_FAST_PROBE_PROMOTE", true)
}

/// F4 — while an upgrade probe is in flight, check its latch every 100 ms and
/// promote it then, instead of on the 1 s scout tick: the responder promotes
/// as soon as the initiator's first direct packet lands, and the initiator's
/// lag behind it is a dark window for its own direction (F0-WAN measured up
/// to 0.73 s). Needs `OVERLAY_FAST_PROBE_PROMOTE`. `=0` restores the 1 s tick.
pub fn probe_watch_enabled() -> bool {
    crate::env::flag("OVERLAY_PROBE_WATCH", true)
}

/// F2 — standby copies: while a business or Major proof for a direct peer is
/// pending, that peer's data is ALSO sent over `/derp`, tagged so its receiver
/// takes it into the session without following us onto DERP. Only to a peer
/// that announced it takes copies. `=0`: no sinks, no hellos, no copies.
pub fn standby_copies_enabled() -> bool {
    crate::env::flag("OVERLAY_STANDBY_COPIES", true)
}

pub fn make_before_break_enabled() -> bool {
    match crate::env::node_env("OVERLAY_MBB") {
        Some(v) => {
            let t = v.trim();
            // Explicit kill-switch only; everything else keeps the default ON.
            !(t.eq_ignore_ascii_case("0")
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        None => true,
    }
}

/// NAT-traversal Phase B/C — gate for the **srflx** carrier tier
/// (`ROOMLERD_OVERLAY_SRFLX`). **Default ON** since 2026-07-20 (field-proven:
/// a cone↔cone pair hole-punches to a DIRECT carrier — buildhost↔fleet-host-2
/// netns lab, 0% loss, ~0.6 ms, half the relay RTT). Turns on the whole srflx
/// tier: gathering + advertising this node's own server-reflexive candidates
/// (via STUN), AND dialing a peer's advertised srflx (a 1:1/cone-NAT node
/// whose NIC IP is private). The tier FALLS THROUGH — a failed/both-symmetric
/// punch degrades to the relay tier — so default-ON only adds a direct-connect
/// fast path, never removes reachability. Set the env to
/// `0`/`false`/`no`/`off` to disable.
pub fn srflx_enabled() -> bool {
    match crate::env::node_env("OVERLAY_SRFLX") {
        Some(v) => {
            let t = v.trim();
            !(t.eq_ignore_ascii_case("0")
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        None => true,
    }
}

/// NAT-traversal Phase D — gate for the **single-relay** carrier tier
/// (`ROOMLERD_OVERLAY_RELAY_SINGLE`). **Default ON** since 2026-07-20. When on
/// (and both ends advertise the capability), a relay-tier pair uses ONE coturn
/// allocation — the ANCHOR (smaller pubkey) allocates + runs the QUIC server +
/// permits the dialer's IP; the DIALER (larger pubkey) sends raw UDP to the
/// anchor's relayed address as a plain TURN peer (no allocation). This avoids
/// the both-allocate coturn hairpin (the open REKEY_TIMEOUT relay bug) and
/// carries symmetric NAT (permissions are IP-only). Field-proven in the full
/// runtime (sym↔sym buildhost↔fleet-host-2 netns lab, 2026-07-20:
/// `single_relay=true` → QUIC-over-TURN up both ways → WG 0% loss); default-ON
/// is net-positive since both-allocate was already broken cross-NAT. v1 serves
/// BOTH-UDP-OK pairs; a UDP-blocked dialer (raw UDP can't reach coturn) stays
/// dark on the relay tier — the documented v1 limitation, no worse than the
/// broken both-allocate it replaces. Set `0`/`false`/`no`/`off` to disable.
pub fn relay_single_enabled() -> bool {
    match crate::env::node_env("OVERLAY_RELAY_SINGLE") {
        Some(v) => {
            let t = v.trim();
            !(t.eq_ignore_ascii_case("0")
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        None => true,
    }
}

/// rc.276 (B-probe) — force ALL overlay coturn allocations onto the
/// **TURNS/TCP (TLS) tier** (`ROOMLERD_OVERLAY_RELAY_TLS`). **Default OFF**
/// opt-in (positive truthy only), mirroring `public_direct_enabled` — this is
/// the field-diagnostic twin of remote-control's `ROOMLERD_ICE_RELAY_TCP`: the
/// WebRTC screen-share survives corp endpoint VPNs via `turns:coturn:443?tcp`
/// (real TLS + SNI, OS-native trust — indistinguishable from HTTPS), while the
/// overlay's Tier-2 UDP allocate "succeeds" and then runs silently one-way, so
/// the TLS tier never engages on its own. Forcing it answers the gating
/// question for the auto-demotion follow-up: does a WG handshake complete over
/// a TLS-TURN carrier on the affected host at all? (DERP — also WG-in-TLS —
/// did NOT survive there, so this is a genuine experiment, not a foregone
/// conclusion.)
///
/// Side effect: while forced, the node also advertises
/// `supports_relay_single=false` and turns its local single-relay flag off —
/// the raw-UDP DIALER role is exactly the flow shape the affected hosts can't
/// send, and both ends must compute the same strategy (the peer reads our
/// capability from the join, so the veto stays pair-symmetric).
pub fn relay_tls_forced() -> bool {
    match crate::env::node_env("OVERLAY_RELAY_TLS") {
        Some(v) => {
            let t = v.trim();
            t.eq_ignore_ascii_case("1")
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

/// Phase D (DERP) — is the pubkey-addressed `/derp` relay carrier ENABLED?
/// (`ROOMLERD_OVERLAY_DERP`.) **Default ON** since 2026-07-21 (field-proven).
/// DERP is the last-resort carrier for two BOTH-UDP-blocked peers (a strict
/// corp firewall that permits only TCP/TLS-443), which no other tier can
/// serve; both peers dial OUT to the relay over WSS:443 and WG rides
/// end-to-end. Only CHOSEN when both ends advertise `supports_derp` AND both
/// are UDP-blocked (the single-relay `(false,false)` arm), so a UDP-capable
/// pair never touches it — default-ON just means an overlay node keeps a
/// `/derp` WS available in case a both-UDP-blocked peer appears. Field-proven
/// 2026-07-21 (buildhost↔fleet-host-2 netns, both UDP+coturn-TCP-blocked → WG
/// over `/derp` at 0% loss, ~2.7 ms). Set `0`/`false`/`no`/`off` to disable.
/// (Follow-up: open the `/derp` WS lazily — only when this node is itself
/// UDP-blocked — so UDP-capable nodes don't hold an idle WS.)
pub fn derp_enabled() -> bool {
    match crate::env::node_env("OVERLAY_DERP") {
        Some(v) => {
            let t = v.trim();
            !(t.eq_ignore_ascii_case("0")
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        None => true,
    }
}

/// U2 — does this node accept a SERVER-COMPUTED relay-tier verdict
/// (`ROOMLERD_OVERLAY_SERVER_RELAY_STRATEGY`) in place of its own local
/// `relay_strategy()` derivation? **Default-OFF** (the inverse polarity of
/// `derp_enabled`): server-authoritative tier selection is the U2 program,
/// and it stays inert until deliberately enabled per host for soak, then
/// fleet-wide. The capability is advertised in `OverlayJoin` only when this
/// is on, and the server only stamps a per-edge verdict when BOTH ends
/// advertise it — so an unset host, or a host talking to an unset peer,
/// keeps the exact pre-U2 client-authoritative path.
///
/// D1 (overlay v3) — default ON: the server's verdict core is a verbatim
/// transcription of the client rules (locked by the parity matrix), its
/// inputs are the measured vectors (B3) with D0's reverse fan keeping both
/// ends on one verdict generation, and the flip was soaked on
/// devbox+corplap+fleet-host-2 (relay + direct pair classes) before landing. The env
/// var / config key `overlay_server_relay_strategy` remains the per-host
/// off-switch; the server still withholds stamps unless BOTH ends
/// advertise, so one opted-out host cleanly reverts its pairs.
pub fn server_relay_strategy_enabled() -> bool {
    crate::env::flag("OVERLAY_SERVER_RELAY_STRATEGY", true)
}

/// FR-19 P4b — ride a tenant-owned org relay when the server mints a session
/// for a pair (`docs/fr/FR-19-peer-relays.md`). Advertised on the join as
/// `supports_org_relay`, so a build with this off is never pushed a session.
///
/// **MeshHarbor: on by default** (§6 item 4c). A member rides only a session
/// the server minted under its org's own mode and gates 1–4, through a relay
/// that sees ciphertext only, so riding is not where the consent lives:
/// serving is, and `relay_server_enabled` (gate 4) stays opt-in. Only
/// `0|false|no|off` opts this host out, and that stays its last word.
pub fn org_relay_enabled() -> bool {
    crate::env::flag("OVERLAY_ORG_RELAY", true)
}

/// Phase A (overlay v3) — DERP always-on floor: open this node's central
/// `/derp` mux at startup UNCONDITIONALLY (not just when the srflx gather
/// came up empty), advertise `supports_derp_floor`, and (A2) install the
/// DERP carrier as every fresh pair's floor while better tiers upgrade over
/// it MBB-style. `ROOMLERD_OVERLAY_DERP_FLOOR`, config-surface key
/// `overlay_derp_floor`. **Default-ON since rc.400** (devbox+corplap soak
/// 08-17: floor pairs carried straight through corplap's latch re-earn windows
/// — the class that used to block ~2 min per 30 — and the rc.398 post-roll
/// carrier-less wedge is structurally impossible with a floor); explicit
/// `false` is the per-host off-switch. The floor is additionally gated
/// per-pair on the PEER advertising the capability — a pre-floor peer
/// whose srflx gather succeeded holds no mux and never registers, so a
/// floor toward it would blackhole.
pub fn derp_floor_enabled() -> bool {
    crate::env::flag("OVERLAY_DERP_FLOOR", true)
}

/// Phase B (overlay v3) — netcheck: periodically MEASURE this host's
/// egress capabilities (relay-band reachability over the exact dialer
/// path, STUN/NAT snapshot, `/derp` WS health) and publish the
/// [`CapVector`](super::netcheck::CapVector) selection consumes instead of
/// presence folklore. `ROOMLERD_OVERLAY_NETCHECK`, config-surface key
/// `overlay_netcheck`. Default-ON: measurement-only in PR-B1 (nothing
/// selects on it until PR-B3), one dedicated TURN allocation per ~20 min.
pub fn netcheck_enabled() -> bool {
    crate::env::flag("OVERLAY_NETCHECK", true)
}

/// Phase D — should this node GATHER + ADVERTISE its own srflx candidates? True
/// when the srflx-direct tier is on OR single-relay is on. Single-relay needs it
/// even with srflx-direct OFF: a single-relay DIALER (larger pubkey) runs no
/// coturn allocation, so the ANCHOR can only permit its inbound by IP — and it
/// learns that IP from the dialer's advertised srflx. So a node opting into
/// single-relay MUST advertise its srflx (it may be the dialer for any
/// larger-pubkey peer), else the anchor withholds forever. This gates ONLY the
/// gather+advertise machinery — it does NOT turn on the srflx-direct DIAL tier
/// (that stays [`srflx_enabled`], so single-relay can be field-tested in
/// isolation: srflx advertised, direct-dial off ⇒ pairs fall to the relay tier).
pub fn srflx_gather_active() -> bool {
    srflx_enabled() || relay_single_enabled()
}

/// Phase C — the srflx keepalive/re-gather interval in seconds
/// (`ROOMLERD_OVERLAY_SRFLX_KEEPALIVE_SECS`, default 20). The task re-runs a
/// STUN Binding on the punch socket every interval to (a) hold the NAT mapping
/// open on an idle link and (b) detect + re-advertise a changed mapping. **`0`
/// disables the task entirely** — the startup gather still advertises once, but
/// there's no in-band refresh (the mapping then relies on WG keepalives for
/// active links only). A malformed value falls back to the default.
pub fn srflx_keepalive_secs() -> u64 {
    match crate::env::node_env("OVERLAY_SRFLX_KEEPALIVE_SECS") {
        Some(v) => v.trim().parse::<u64>().unwrap_or(20),
        None => 20,
    }
}

/// Phase A — a globally-routable IPv4: the address classes that can never be
/// dialled across the internet are excluded (RFC1918 private, loopback,
/// link-local, CGNAT/overlay `100.64/10`, `0/8`, multicast `224/4`, and
/// `240/4` incl. broadcast). v4-only by design — v6 exit egress rides the v4
/// carrier (CC7). NB the TEST-NET ranges (`203.0.113.0/24` etc.) are
/// deliberately NOT excluded: they never appear on real NICs and double as
/// "public" space in unit fixtures.
pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_cgnat(ip)
        || o[0] == 0
        || o[0] >= 240)
}

/// Pick the first **public** `ip:port` from a peer's candidate bucket — used
/// for BOTH the Phase A public-NIC tier (the netmap's `lan_endpoints`, the
/// peer's NIC holding a public IP, dialable without STUN) and the Phase B srflx
/// tier (`srflx_endpoints`, the peer's public NAT mapping learned via STUN).
/// Either way the address is globally routable, so the same public dial path
/// (over `public_sock`) applies. Candidates equal to one of OUR OWN interface
/// IPs are skipped (a same-host / stale record can't be a peer dial target; a
/// genuinely same-subnet peer was already taken by the LAN tier, which runs
/// first). `None` → the caller falls through to the next tier or the relay.
pub fn pick_public_endpoint(my_ips: &[Ipv4Addr], candidates: &[String]) -> Option<SocketAddr> {
    pick_public_endpoint_rotated(my_ips, candidates, 0)
}

/// A2 — [`pick_public_endpoint`] with dial-attempt ROTATION: viable candidate
/// `attempt % viable.len()` instead of always the first. A multi-homed peer
/// advertises several public/srflx candidates, but the dialer only ever tried
/// `[0]` — the rest were dead candidate space (field 2026-08-10: buildhost's
/// second public IP was advertised and never dialed). The caller passes the
/// PathMonitor's per-(peer, tier) strike count as `attempt`, so each failed
/// probe advances to the peer's next candidate and a success (strikes reset)
/// returns to the primary.
pub fn pick_public_endpoint_rotated(
    my_ips: &[Ipv4Addr],
    candidates: &[String],
    attempt: u32,
) -> Option<SocketAddr> {
    let viable: Vec<SocketAddr> = candidates
        .iter()
        .filter_map(|ep| match ep.trim().parse::<SocketAddr>() {
            Ok(SocketAddr::V4(sa)) if is_public_v4(*sa.ip()) && !my_ips.contains(sa.ip()) => {
                Some(SocketAddr::V4(sa))
            }
            _ => None,
        })
        .collect();
    if viable.is_empty() {
        return None;
    }
    viable.get(attempt as usize % viable.len()).copied()
}

/// Same-/24 test: two IPv4s share the top 24 bits. A strong, conservative
/// signal of same-L2-segment reachability for home/office LANs (good enough
/// for v1; a netmask-aware check is a refinement).
pub fn same_subnet_24(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    let (a, b) = (a.octets(), b.octets());
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2]
}

/// From a peer's advertised `endpoints` (host/srflx/relay strings), pick the
/// first that is a directly-dialable host endpoint **on one of our LANs** —
/// i.e. an `IP:port` whose IP shares a /24 with one of our interface IPs.
/// Returns `(our matching interface IP, the peer's endpoint)` so the caller can
/// send from the socket bound to THAT interface (rc.143 — binding to the
/// interface forces egress out the right NIC, so a same-subnet peer is reached
/// over the LAN even when a full-tunnel VPN has hijacked the default route).
/// `None` if the peer advertised no same-subnet endpoint (→ caller falls back
/// to the relay).
///
/// A peer advertising one of **our own** addresses is skipped. That is not a
/// hypothetical: WSL in mirrored mode shares the host's NICs, so the guest
/// advertises the host's Wi-Fi address verbatim, and the /24 test passes
/// trivially against ourselves. Dialling it cannot work by construction — the
/// packet is delivered to this host's own stack and never reaches the peer.
///
/// Field 2026-08-14, devbox: `dst=192.168.68.126:43648` (its OWN Wi-Fi address)
/// probed every 90 s for 14 days across two WSL peers — 12 684 consecutive
/// failures, zero successes. The wasted probes were the visible half. The
/// expensive half was silent: [`srflx_hairpin_pointless`] takes "a LAN
/// candidate exists" as its same-NAT signal, so the phantom candidate also
/// SUPPRESSED the srflx tier, leaving the pair pinned to the relay with no
/// tier left that could ever promote. Two hosts on the same machine were
/// relaying through a TCP DERP server because of it.
pub fn pick_same_subnet_endpoint(
    my_ips: &[Ipv4Addr],
    endpoints: &[String],
) -> Option<(Ipv4Addr, SocketAddr)> {
    for ep in endpoints {
        // Tolerate scheme-ish prefixes defensively; we only emit bare IP:port.
        let raw = ep.trim();
        if let Ok(SocketAddr::V4(sa)) = raw.parse::<SocketAddr>()
            && is_usable_lan_ipv4(*sa.ip())
            // Skip THIS endpoint rather than abandoning the search: a peer can
            // advertise several, and a self-address must not shadow a usable
            // one later in the list.
            && !my_ips.contains(sa.ip())
            && let Some(local) = my_ips.iter().find(|me| same_subnet_24(**me, *sa.ip()))
        {
            return Some((*local, SocketAddr::V4(sa)));
        }
    }
    None
}

/// Phase B — parse a STUN endpoint from a `stun:` / `stuns:` URL (or a bare
/// `host:port`) **when the host is an IPv4 literal**. Strips the scheme and any
/// `?transport=…` / `#…` suffix. Returns `None` for a hostname (the caller
/// resolves those via DNS — this stays sync + allocation-light) or a
/// malformed / IPv6 value (v4-only, CC7). Coturn workers double as STUN
/// servers, so a `turn:` URL's host also works if the scheme is stripped first.
pub fn parse_stun_url(url: &str) -> Option<SocketAddr> {
    let s = url.trim();
    let s = s
        .strip_prefix("stun:")
        .or_else(|| s.strip_prefix("stuns:"))
        .or_else(|| s.strip_prefix("turn:"))
        .or_else(|| s.strip_prefix("turns:"))
        .unwrap_or(s);
    // Drop a `?transport=udp` query or `#frag`.
    let s = s.split(['?', '#']).next().unwrap_or(s);
    match s.parse::<SocketAddr>() {
        Ok(sa @ SocketAddr::V4(_)) => Some(sa),
        _ => None,
    }
}

/// Phase B — discover this node's **server-reflexive** candidates by querying
/// `stun_server` on EACH of its interface sockets. The query MUST ride the same
/// socket the overlay traffic will later use, or the NAT mapping won't match
/// (see [`crate::transport::stun`]) — so this takes the live `DirectCtx`
/// sockets and MUST run BEFORE their demux recv loops start (else the STUN
/// response races the loop's `recv`). Returns the deduped set of **public**
/// srflx `ip:port` strings to advertise; a socket whose query fails, times out,
/// or maps to a non-public address (STUN server on the LAN, a hairpin) is
/// skipped. v4-only.
///
/// Phase C — each candidate is returned WITH the interface socket it was
/// gathered on. The overlay must later DIAL a peer's srflx from the socket that
/// owns OUR advertised srflx (so our outbound INITs ride the same NAT mapping we
/// advertised, opening our filter toward the peer — the hole-punch); pairing the
/// candidate with its socket lets the caller pick that "punch socket". The first
/// pair is the punch socket (its candidate is advertised at index 0, which the
/// peer's dial-side picks first). Deduped by candidate string.
pub async fn gather_srflx(
    socks: &[(Ipv4Addr, Arc<UdpSocket>)],
    stun_server: SocketAddr,
    attempt_timeout: Duration,
) -> Vec<(String, Arc<UdpSocket>)> {
    let mut out: Vec<(String, Arc<UdpSocket>)> = Vec::new();
    for (_ip, sock) in socks {
        match crate::transport::stun::srflx_query(sock, stun_server, attempt_timeout).await {
            Ok(SocketAddr::V4(srflx)) if is_public_v4(*srflx.ip()) => {
                let ep = SocketAddr::V4(srflx).to_string();
                if !out.iter().any(|(e, _)| e == &ep) {
                    out.push((ep, sock.clone()));
                }
            }
            Ok(other) => {
                tracing::debug!(%other, "overlay: srflx candidate not public — skipping");
            }
            Err(e) => {
                tracing::debug!(%e, "overlay: srflx query failed on a socket — skipping");
            }
        }
    }
    out
}

/// The `host:port` a `stun:`/`turn:` URL resolves through — scheme stripped,
/// `?transport=` / `#frag` removed.
///
/// Shared by all three resolvers so the cache key and the thing actually looked
/// up can never drift apart (they were three copies of this before).
fn stun_hostport(url: &str) -> &str {
    let s = url.trim();
    let s = s
        .strip_prefix("stun:")
        .or_else(|| s.strip_prefix("stuns:"))
        .or_else(|| s.strip_prefix("turn:"))
        .or_else(|| s.strip_prefix("turns:"))
        .unwrap_or(s);
    s.split(['?', '#']).next().unwrap_or(s)
}

/// A STUN/TURN name through [`crate::ctl_dns`]. Two rules come with it:
/// - FR-48: within its TTL a name is not looked up again. A settled node used to
///   grow ~6.5 UDP sockets/hour, because each `getaddrinfo` pins its resolver
///   socket to a blocking-pool thread for the life of the process.
/// - #2187: a remembered name never waits on a resolver that has stopped
///   answering. These run on the overlay loop, and a dead exit DNS once held it
///   for 48 s on a direct-plane rebuild.
///
/// Empty = no answer, matching the old `if let Ok(..)` call sites.
async fn lookup_host_cached(hostport: &str) -> Vec<SocketAddr> {
    crate::ctl_dns::resolve(hostport).await
}

/// Phase B — resolve the FIRST usable STUN server from the netmap's `stun_urls`
/// to a concrete v4 `SocketAddr`. An IP-literal URL is parsed synchronously
/// ([`parse_stun_url`], no DNS); a hostname URL (the fleet's
/// `stun:coturn.roomler.ai:3478`) is resolved via DNS and the first IPv4 answer
/// taken (v4-only, CC7). Tries each URL in order; `None` if none resolve to an
/// IPv4 endpoint. Any single reachable STUN worker suffices — srflx doesn't need
/// the coturn worker-pinning that the relay hairpin does.
pub async fn resolve_stun_server(stun_urls: &[String], exclude: &[Ipv4Addr]) -> Option<SocketAddr> {
    // Never STUN a coturn worker that is one of THIS host's own IPs: on the
    // fleet the coturn workers ARE the hosts (buildhost `.74`, fleet-host-1 `.221`, fleet-host-2
    // `.226`), so a co-located host STUNning its own worker hairpins on the
    // local host DNAT and gets no public mapping back → the node falsely reads
    // as UDP-blocked (empty srflx). Real clients are never co-located with
    // coturn, so this only ever prunes the fleet's self-referential target.
    let usable = |sa: &SocketAddr| !matches!(sa, SocketAddr::V4(v4) if exclude.contains(v4.ip()));
    for url in stun_urls {
        // Fast path: an IP literal (or already-resolved worker) needs no DNS.
        if let Some(sa) = parse_stun_url(url) {
            if usable(&sa) {
                return Some(sa);
            }
            continue;
        }
        // Hostname → DNS, through the FR-48 TTL cache.
        if let Some(v4) = lookup_host_cached(stun_hostport(url))
            .await
            .into_iter()
            .filter(SocketAddr::is_ipv4)
            .find(usable)
        {
            return Some(v4);
        }
    }
    None
}

/// Diagnostic (`ROOMLERD_OVERLAY_SESSION_TRACE`, default **off**): emit
/// per-session INFO traces from the plane demux (inbound src vs expected_src
/// vs verdict) and the carrier-health sweep (poke/proof/rx state per direct
/// carrier). For field-diagnosing a specific peer's carrier (e.g. a
/// uni-directional secondary-org srflx carrier that black-holes the initiator
/// direction). Verbose — enable briefly on the affected host only.
pub fn session_trace_enabled() -> bool {
    crate::env::flag("OVERLAY_SESSION_TRACE", false)
}

/// C2 — PROBE peers with out-of-tunnel disco echoes and record per-path
/// loss + RTT (`ROOMLERD_OVERLAY_DISCO_PROBE`; default **ON** since A).
///
/// Strictly measurement: the table it fills is read by the LocalAPI and the
/// summary log, never by anything that moves traffic. Scoring is C3 and
/// authority is C6, each behind its own flag — that separation is why a bug
/// here cannot repeat rc.346.
///
/// Default flipped ON once the C1 responder was measured live on both ends of
/// a real pair (`disco_answered` 365 and 500 on 2026-08-26) — the gate this
/// stage always had was "every peer can answer", and answering is what that
/// counter proves. A prober shipped before that measures nothing but its own
/// deployment order, which is why it waited.
///
/// It costs one small UDP frame per DIRECT peer per 5 s tick and cannot
/// disturb a relay-parked pair, because [`disco_round`] only walks carriers
/// that are already direct. ⚠️ That is also its present LIMIT: it can measure
/// a direct path in use, but it cannot yet tell you whether a CANDIDATE path
/// would work for a pair currently parked on relay — which is exactly the
/// question the neo16↔MacBook investigation needed. Probing candidates is A2.
pub fn disco_probe_enabled() -> bool {
    crate::env::flag("OVERLAY_DISCO_PROBE", true)
}

/// C1 — answer out-of-tunnel disco echoes on the carrier socket
/// (`ROOMLERD_OVERLAY_DISCO_RESPOND`; default **ON**). Answering is
/// unconditional and costs a map lookup + one X25519 per verified ping;
/// nothing on this node ASKS yet (the prober is C2).
///
/// Default-ON on purpose, and it is the deployment barrier the rc.346
/// regression paid for: a prober that punishes non-answer must ship at least
/// one release AFTER every peer can answer. Responder first, always.
pub fn disco_respond_enabled() -> bool {
    crate::env::flag("OVERLAY_DISCO_RESPOND", true)
}

/// B4 — carrier-plane socket-liveness watchdog
/// (`ROOMLERD_OVERLAY_PLANE_WATCHDOG`; default **ON**): when the plane's
/// punch-socket keepalive fails [`PLANE_WATCHDOG_FAILS`] consecutive cycles (a
/// reader-less / wedged socket — the 2026-08-10 class of bug B1 fixed
/// structurally), self-heal by requesting a debounced plane rebuild that
/// re-binds fresh sockets. The kill switch reverts to "warn only, never
/// auto-rebuild".
pub fn plane_watchdog_enabled() -> bool {
    crate::env::flag("OVERLAY_PLANE_WATCHDOG", true)
}

/// B4 — consecutive plane-keepalive failures before the watchdog forces a
/// rebuild. At the ~20 s keepalive interval this is ~2 min of a dead socket
/// before self-heal — long enough that a transient STUN outage (which the
/// re-resolve at 3 handles) never trips it, short enough to bound the wedge.
pub const PLANE_WATCHDOG_FAILS: u32 = 6;

/// A3 — WG-style endpoint roaming (`ROOMLERD_OVERLAY_ROAM`; default **ON**):
/// adopt a peer's observed source after an AUTHENTICATED inbound from it,
/// repointing the carrier in place. The kill switch reverts to the strict
/// no-roam demux. Off ⇒ a symmetric-NAT peer whose real per-destination
/// mapping differs from its advert stays on relay, and a mid-session NAT
/// rebind waits out the rx-staleness rebuild.
pub fn roam_enabled() -> bool {
    crate::env::flag("OVERLAY_ROAM", true)
}

/// W5 — srflx SEEKING mode (`ROOMLERD_OVERLAY_SRFLX_SEEK`; default **ON**):
/// when the plane's srflx gather yields NO candidate, keep the plane srflx
/// task alive in a query-only state that periodically re-gathers (backoff 20 s
/// → ×3 → 300 s cap, plus an immediate poke on interface events). Before this,
/// a NONE gather returned the STUN sink and NOTHING ever re-queried — `srflx
/// NONE` was sticky for the daemon's lifetime (field 2026-08-14: winhost-a on
/// the corp VPN stayed NONE across VPN cycles, which also made it the
/// universal relay ANCHOR). The B4 watchdog stays INERT in SEEKING (there is
/// no advertised mapping to defend; on a genuinely UDP-blocked host it would
/// otherwise force a full plane rebuild every few cycles forever). The kill
/// switch restores the old return-the-sink behaviour.
pub fn srflx_seek_enabled() -> bool {
    crate::env::flag("OVERLAY_SRFLX_SEEK", true)
}

/// C4 stage 1 — the standing warm TURN/UDP allocation
/// (`ROOMLERD_OVERLAY_WARM_RELAY`; default **OFF**): established
/// whenever the srflx tier proves UDP egress works, kept alive so
/// corp-VPN flow-grandfathering preserves a UDP relay leg across a VPN
/// connect. Measurement-only in stage 1 — nothing routes over it; see
/// `docs/overlay-warm-relay.md`.
pub fn warm_relay_enabled() -> bool {
    crate::env::flag("OVERLAY_WARM_RELAY", false)
}

/// R2 (corp-laptop program) — rescue the srflx gather via the wildcard
/// PUBLIC-DIAL socket when every LAN-bound vantage yields nothing
/// (`ROOMLERD_OVERLAY_VPN_VANTAGE`; default **ON**). A full-tunnel
/// endpoint VPN (field 2026-08-15: corplap-3, Cisco AnyConnect with
/// local-LAN access disabled) filters the physical NICs BOTH directions
/// while the tunnel itself passes UDP — so the LAN-bound socks are dead but
/// the UNSPECIFIED-bound public dialer (routed via the captured default =
/// the tunnel) can still reach STUN. It is queried only after every LAN
/// vantage came up empty, so healthy hosts are byte-identical.
pub fn vpn_vantage_enabled() -> bool {
    crate::env::flag("OVERLAY_VPN_VANTAGE", true)
}

/// W6 phase 3 — raw-first QUIC-over-TURN upgrade
/// (`ROOMLERD_OVERLAY_QUIC_ASYNC`; default **ON**): commit the raw
/// relay carrier immediately and run the QUIC rendezvous in the
/// background with a 90 s window, swapping in on success. OFF restores
/// the blocking 8 s pre-install window (the pair is dark for the whole
/// window on a dead-carrier rebuild, and two UNSYNCHRONIZED 8 s windows
/// on ~60 s retry clocks overlap ~11-25% of the time — field 2026-08-15:
/// 22/201 carrier-ups on a VPN host).
pub fn quic_async_enabled() -> bool {
    crate::env::flag("OVERLAY_QUIC_ASYNC", true)
}

/// Auth-first type-1 routing on a MULTI-ORG carrier plane
/// (`ROOMLERD_OVERLAY_INIT_AUTH_FIRST`; default **ON**): with more than one
/// engine attached, an inbound handshake initiation is routed by
/// trial-authentication against each engine's static
/// (candidates-with-a-session-at-that-source first), never by the source-keyed
/// shortcut alone. With N orgs sharing ONE socket on both hosts, both orgs'
/// sessions arrive from the SAME remote `ip:port`, and the shortcut
/// deterministically delivered the second org's inits into the first org's
/// `Tunn` — the dual-org direct mutual-exclusion lockout (field 2026-08-14:
/// buildhost/fleet-host-1/fleet-host-2 direct on exactly one org each, the
/// loser pinned to relay until a restart swapped the winner). Single-engine
/// planes keep the shortcut either way. The kill switch restores the legacy
/// shortcut on multi-org planes too. Read once at plane construction.
pub fn init_auth_first_enabled() -> bool {
    crate::env::flag("OVERLAY_INIT_AUTH_FIRST", true)
}

/// A3 — minimum interval between endpoint adoptions for ONE session: bounds
/// roam thrash / a spoof-probe storm to ≤1 move/session/interval. A genuine
/// symmetric-NAT punch adopts once and settles; a rebind is rare.
pub(crate) const ROAM_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Phase C — resolve up to THREE DISTINCT STUN targets for the NAT-type probe.
/// The probe compares our mapped address as different servers see it: all the
/// same ⇒ endpoint-independent mapping (cone — hole-punchable); ANY pairwise
/// difference ⇒ symmetric (address/port-dependent — the peer can't predict our
/// port). A1 (NAT honesty): extra vantages are ranked by topological SPREAD —
/// different /16 (another datacenter) > different IP > different port — because
/// a NAT whose mapping is stable toward one subnet but per-destination
/// elsewhere classifies as cone when every vantage shares that subnet (field
/// 2026-08-10: winhost-a advertised `:51668` learned via the 5.9.157.x workers,
/// while its REAL mapping toward a 94.130.141.x worker was `:43648` — the
/// 2-same-/24-vantage probe said "cone" and every peer punched a dead port).
/// v4 only. 0-3 results; fewer than 2 ⇒ the caller can't classify (→
/// "unknown", stays optimistic and still attempts the punch).
pub async fn resolve_stun_targets(stun_urls: &[String], exclude: &[Ipv4Addr]) -> Vec<SocketAddr> {
    // Same self-referential-worker skip as `resolve_stun_server` (see its doc):
    // a fleet host co-located with a coturn worker must not probe against its
    // own IP, or the NAT-type probe hairpins on the local host DNAT.
    let usable = |sa: &SocketAddr| !matches!(sa, SocketAddr::V4(v4) if exclude.contains(v4.ip()));
    let mut all: Vec<SocketAddr> = Vec::new();
    for url in stun_urls {
        if let Some(sa) = parse_stun_url(url) {
            if usable(&sa) && !all.contains(&sa) {
                all.push(sa);
            }
            continue;
        }
        for a in lookup_host_cached(stun_hostport(url))
            .await
            .into_iter()
            .filter(SocketAddr::is_ipv4)
        {
            if usable(&a) && !all.contains(&a) {
                all.push(a);
            }
        }
    }
    let mut out: Vec<SocketAddr> = Vec::new();
    if let Some(&first) = all.first() {
        out.push(first);
        // A1 — pick up to two more vantages by topological spread: a /16 no
        // picked vantage sits in, else an unpicked IP. DISTINCT IPs ONLY —
        // the old last-resort "any distinct endpoint (diff port)" pick is
        // gone. Two ports on ONE server are worthless for typing (same NAT
        // path — they can never disagree about OUR mapping honestly) and
        // actively poisonous with coturn behind DNAT: field 2026-08-15/16,
        // the cluster's udp/443 alias DNATs onto the SAME VM tuple as
        // :3478, so a socket that queries both gets a conntrack reply-tuple
        // CLASH and nf_nat is FORCED to rewrite the second flow's source
        // port — the #487 typing line caught it red-handed
        // (`5.9.157.221:3478=>…:43680` vs `5.9.157.221:443=>…:30151`) and
        // every public-IP cluster node classified "symmetric", vetoing the
        // srflx tier fleet-wide against them. Fewer than 2 distinct IPs ⇒
        // shorter list; `classify_nat_mappings` treats <2 mappings as
        // unknown, which stays optimistic (punch still attempted) — the
        // honest verdict when there is only one vantage worth asking.
        let slash16 = |a: &SocketAddr| match a {
            SocketAddr::V4(v) => {
                let o = v.ip().octets();
                Some((o[0], o[1]))
            }
            SocketAddr::V6(_) => None,
        };
        while out.len() < 3 {
            let pick = all
                .iter()
                .find(|a| !out.contains(a) && out.iter().all(|o| slash16(a) != slash16(o)))
                .or_else(|| {
                    all.iter()
                        .find(|a| !out.contains(a) && out.iter().all(|o| a.ip() != o.ip()))
                });
            match pick {
                Some(&p) => out.push(p),
                None => break,
            }
        }
    }
    out
}

/// W6 phase-2 — EVERY distinct coturn worker IP behind the STUN urls: the
/// full A-record set, uncapped (unlike [`resolve_stun_targets`]'s ≤3
/// probing vantages, and with no self-exclusion — a co-located worker is
/// still a valid relay for OTHER pairs). The single-relay DIALER uses it
/// to positively identify the anchor's relayed address `R` among
/// advertised endpoints; an incomplete set would withhold legitimate
/// relays, so completeness beats spread here.
pub async fn resolve_stun_worker_ips(stun_urls: &[String]) -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = Vec::new();
    for url in stun_urls {
        if let Some(sa) = parse_stun_url(url) {
            if !out.contains(&sa.ip()) {
                out.push(sa.ip());
            }
            continue;
        }
        for a in lookup_host_cached(stun_hostport(url))
            .await
            .into_iter()
            .filter(SocketAddr::is_ipv4)
        {
            if !out.contains(&a.ip()) {
                out.push(a.ip());
            }
        }
    }
    out
}

/// W5(b) — drop typing vantages that ARE this host. A cluster node
/// co-hosting a coturn/PoP STUNs itself through the kernel hairpin, whose
/// observed mapping differs from the NIC-path mappings — and ANY pairwise
/// mismatch classifies "symmetric". Field 2026-08-15: all three cluster
/// nodes (public-IP, NO NAT) flipped cone→symmetric at the rc.379 boot from
/// exactly this. The own-IP set comes from `if_addrs` at call time (typing
/// runs only at boot/rebuild/regather). Pure core; the callers pass the
/// live set via [`exclude_self_vantages`].
pub fn exclude_vantages_in(
    targets: &[SocketAddr],
    own: &std::collections::HashSet<std::net::IpAddr>,
) -> Vec<SocketAddr> {
    let (kept, dropped): (Vec<SocketAddr>, Vec<SocketAddr>) =
        targets.iter().partition(|t| !own.contains(&t.ip()));
    if !dropped.is_empty() {
        tracing::info!(
            ?dropped,
            kept = kept.len(),
            "NAT typing: excluded self-hosted vantages (hairpin mappings fake symmetric)"
        );
    }
    kept
}

/// [`exclude_vantages_in`] against this host's live interface addresses.
/// Loopback stays OUT of the own-set: the hairpin problem is the host's
/// routable IPs (a co-hosted PoP), and loopback vantages only exist in
/// tests' local responders.
pub fn exclude_self_vantages(targets: &[SocketAddr]) -> Vec<SocketAddr> {
    let own: std::collections::HashSet<std::net::IpAddr> = if_addrs::get_if_addrs()
        .map(|v| {
            v.into_iter()
                .map(|i| i.ip())
                .filter(|ip| !ip.is_loopback())
                .collect()
        })
        .unwrap_or_default();
    exclude_vantages_in(targets, &own)
}

/// A1 — classify a NAT from ≥2 observed mappings of ONE local socket toward
/// distinct vantages: ANY pairwise difference ⇒ endpoint-dependent mapping
/// (`"symmetric"` — peers cannot punch the advertised port); all equal ⇒
/// `"cone"`. `None` with fewer than two mappings (vantage failures) — unknown
/// stays optimistic. Pure; shared by [`probe_nat_type`] and the carrier
/// plane's sink-driven twin.
pub fn classify_nat_mappings(mappings: &[SocketAddr]) -> Option<&'static str> {
    let (first, rest) = mappings.split_first()?;
    if rest.is_empty() {
        return None;
    }
    Some(if rest.iter().all(|m| m == first) {
        "cone"
    } else {
        "symmetric"
    })
}

/// Phase C — classify this node's NAT mapping by STUNning `sock` against the
/// (2-3, see [`resolve_stun_targets`]) distinct `targets` and comparing the
/// observed mappings via [`classify_nat_mappings`]: all equal ⇒ `"cone"`
/// (hole-punchable); ANY difference ⇒ `"symmetric"` (not punchable at the
/// advertised port). `None` when fewer than two vantages ANSWER — with three
/// targets one dead vantage is tolerated (A1); the caller then advertises no
/// NAT type and still ATTEMPTS the punch ("unknown" is optimistic). MUST run
/// on the punch socket BEFORE its demux loop starts (same socket-read race as
/// [`gather_srflx`]).
pub async fn probe_nat_type(
    sock: &UdpSocket,
    targets: &[SocketAddr],
    attempt_timeout: Duration,
) -> Option<&'static str> {
    // W5(b) — self-hosted vantages produce hairpin mappings that fake
    // "symmetric" on NAT-less hosts; typing must never consult them.
    let targets = exclude_self_vantages(targets);
    if targets.len() < 2 {
        return None;
    }
    let mut mappings: Vec<SocketAddr> = Vec::with_capacity(targets.len());
    for t in &targets {
        if let Ok(m) = crate::transport::stun::srflx_query(sock, *t, attempt_timeout).await {
            mappings.push(m);
        }
    }
    classify_nat_mappings(&mappings)
}

/// Phase C — should we ATTEMPT a srflx hole-punch given both ends' NAT types?
/// Skip only when we're CONFIDENT it can't work: BOTH ends symmetric (neither
/// can predict the other's per-destination port). Any `None`/"unknown" stays
/// optimistic and attempts (the tight handshake deadline bounds a wasted try).
pub fn srflx_punch_worth_trying(mine: Option<&str>, peer: Option<&str>) -> bool {
    !(mine == Some("symmetric") && peer == Some("symmetric"))
}

/// P8 — is a srflx punch toward this peer a pointless HAIRPIN? `true` when
/// every srflx candidate the peer advertises maps to the SAME public IP as our
/// own srflx (both ends behind one NAT — the punch would need router
/// hairpinning, which consumer NATs rarely do) AND the peer also advertises a
/// LAN candidate on one of our subnets (the tier that actually works for a
/// same-site pair). Saves the futile 12 s attempt + its probe noise on every
/// re-upgrade tick. A same-IP pair WITHOUT a usable LAN candidate still tries
/// — on an isolated segment the hairpin may be all there is. Pure.
///
/// `peer_has_lan_candidate` is a USABILITY verdict, not mere presence: the
/// caller (`resolve_direct_candidates`) passes `false` once the LAN tier has
/// accumulated `LAN_DEAD_STRIKES` consecutive probe failures — an AP with
/// client isolation (2026-08-15 field: raw same-subnet UDP + ICMP dead both
/// directions while candidates stayed advertised, and mesh-node roaming made
/// it flap) otherwise turns this gate into a permanent relay-lock for
/// same-NAT pairs.
pub fn srflx_hairpin_pointless(
    my_srflx: Option<&str>,
    peer_srflx: &[String],
    peer_has_lan_candidate: bool,
) -> bool {
    if !peer_has_lan_candidate || peer_srflx.is_empty() {
        return false;
    }
    let Some(my_ip) = my_srflx
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .map(|s| s.ip())
    else {
        return false;
    };
    peer_srflx
        .iter()
        .all(|e| e.parse::<SocketAddr>().ok().map(|s| s.ip()) == Some(my_ip))
}

/// Bind one direct socket on a STABLE port so a rebuilt carrier reproduces
/// the UDP 5-tuple a stateful corp firewall already grandfathered (rc.307).
/// Lives here (not in the runtime) since multi-org v2: the shared carrier
/// plane binds the process-wide socket set with exactly this policy.
///
/// Three tiers, in order:
/// 1. **The base port, retried briefly.** During a runtime hand-over (MSI
///    upgrade, service restart) the exiting worker may still hold it for a
///    moment; retrying beats walking, because walking would silently change
///    the port and forfeit the very 5-tuple we are protecting.
/// 2. **The rest of the band** ([`direct_port_candidates`]). Hyper-V / WSL2 /
///    HNS reserve large port pools that are invisible to `netstat` AND
///    `netsh excludedportrange`, and they MOVE between boots — a base can be
///    swallowed whole (field-measured on a WSL-mirrored host, 2026-08-05).
///    A band walk keeps a stable port instead of losing the feature.
/// 3. **Ephemeral**, the pre-rc.307 behaviour, so the interface always works.
///
/// `base == 0` skips straight to ephemeral (explicit opt-out). `None` only
/// when even the ephemeral bind fails.
///
/// FR-110: every socket this returns has asked for carrier-sized buffers
/// ([`super::sockbuf::tune_carrier`]). At the OS default the kernel dropped
/// bursts before the daemon read them.
pub(crate) async fn bind_direct_socket(
    ip: Ipv4Addr,
    base: u16,
    what: &'static str,
) -> Option<UdpSocket> {
    let sock = bind_on_band(ip, base, what).await?;
    super::sockbuf::tune_carrier(&sock, what);
    Some(sock)
}

/// §6 item 5 — the IPv6 direct socket: `[::]:base` (any port when that is
/// taken), IPV6_V6ONLY so it never collides with the IPv4 binds on the same
/// port number.
pub(crate) async fn bind_direct_socket_v6(base: u16, what: &'static str) -> Option<UdpSocket> {
    for port in [base, 0] {
        match bind_v6only(port) {
            Ok(s) => {
                super::sockbuf::tune_carrier(&s, what);
                return Some(s);
            }
            Err(e) => tracing::debug!(port, %e, what, "overlay: IPv6 direct bind failed"),
        }
        if base == 0 {
            break;
        }
    }
    None
}

fn bind_v6only(port: u16) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    UdpSocket::from_std(s.into())
}

/// The stable-port policy itself (the three tiers above), unchanged by FR-110.
async fn bind_on_band(ip: Ipv4Addr, base: u16, what: &'static str) -> Option<UdpSocket> {
    let mut candidates = direct_port_candidates(base);
    if let Some(first) = candidates.next() {
        for attempt in 0u8..3 {
            match UdpSocket::bind((ip, first)).await {
                Ok(s) => return Some(s),
                Err(_) if attempt < 2 => {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
                Err(_) => {}
            }
        }
        // The base is held by something that isn't just a slow hand-over.
        for port in candidates {
            if let Ok(s) = UdpSocket::bind((ip, port)).await {
                // PR-B1 tripwire — on a host with a stable port this walk is
                // either an external squatter or a second in-process binder
                // colliding with leaked sockets (the 2026-08-10 ensure_bound
                // race). Counted so `roomler status` shows it as a number.
                crate::evidence::DIRECT_BIND_WALKS
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    %ip, base, port, what,
                    "overlay: stable direct-port base unavailable (Hyper-V/WSL reservation, or \
                     another in-process binder?) — using the next port in the band"
                );
                return Some(s);
            }
        }
        tracing::warn!(
            %ip, base, band = DIRECT_PORT_BAND, what,
            "overlay: the whole stable direct-port band is unavailable; falling back to an \
             ephemeral port (carriers will not survive a corp-firewall session table)"
        );
    }
    match UdpSocket::bind((ip, 0)).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(%ip, %e, what, "overlay: direct socket bind failed; skipping");
            None
        }
    }
}

/// PR-B1 — per-bound-socket receive liveness, bumped by the recv loop that
/// owns the socket (plane or per-device demux) and snapshotted into
/// `NodeStatus.direct_socks`. Exists so a bound-but-reader-less socket (the
/// 2026-08-10 ensure_bound-race wedge: advertised endpoint, Recv-Q pegged at
/// rmem, zero reads) is visible in `roomler status` instead of only in
/// `ss -uanp` queue depths.
pub(crate) struct SockStat {
    pub local: String,
    pub rx_pkts: std::sync::atomic::AtomicU64,
    /// Unix epoch millis of the last received datagram; 0 = never.
    pub last_rx_ms: std::sync::atomic::AtomicU64,
}

impl SockStat {
    pub fn new(local: String) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            local,
            rx_pkts: std::sync::atomic::AtomicU64::new(0),
            last_rx_ms: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// One datagram received on this socket.
    pub fn bump(&self) {
        use std::sync::atomic::Ordering;
        self.rx_pkts.fetch_add(1, Ordering::Relaxed);
        self.last_rx_ms.store(epoch_ms_now(), Ordering::Relaxed);
    }

    /// Snapshot for the LocalAPI (age computed against the wall clock the
    /// stamps were taken with).
    pub fn status(&self) -> crate::localapi::DirectSockStatus {
        use std::sync::atomic::Ordering;
        let last = self.last_rx_ms.load(Ordering::Relaxed);
        crate::localapi::DirectSockStatus {
            local: self.local.clone(),
            rx_pkts: self.rx_pkts.load(Ordering::Relaxed),
            last_rx_age_s: (last > 0).then(|| epoch_ms_now().saturating_sub(last) / 1000),
        }
    }
}

/// Wall-clock millis since the Unix epoch (0 on a pre-1970 clock).
fn epoch_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// #33 — answer a peer's direct handshake initiation even while that tier is
/// suppressed, when accepting cannot cost us the relay
/// (`ROOMLERD_OVERLAY_ANSWER_WHILE_FOLLOWED`; default **ON** since 0.4.2).
///
/// The #30 demote-follow hold-down exists to stop us PROMOTING into a flap. It
/// also made `PathMonitor::inbound_init` refuse — and that verdict is
/// authoritative for inbound, so the node stopped ANSWERING the peer's
/// initiations entirely, on a window that escalates to 15 minutes. Two ends
/// that have both followed therefore go mutually deaf.
///
/// Measured 2026-08-26, neo16 ↔ a MacBook on the same Wi-Fi, one metre apart:
/// 3370 probe failures with `saw_inbound=false` against 3 with `true`, and
/// WireGuard initiations visible in `tcpdump` flowing BOTH ways with zero
/// responses — while disco, whose responder has no such gate, measured that
/// same LAN path at 8 % loss. The path was never the problem.
///
/// ⚠️ Not entirely free: the accept occupies the peer's single probe slot for
/// up to the handshake deadline, so a peer initiating on a genuinely bad tier
/// can delay probing a better one. Indefinite mutual deafness is strictly
/// worse, and the field measurements below bear that out, but the slot cost is
/// real — set the key to `false` on a host where it ever looks like the
/// problem.
///
/// Default flipped **ON** 2026-08-27 after the soak and field gate. Measured
/// on hosts that ran it against hosts that did not, same LAN, same hour:
///
/// | pair | before | after |
/// |---|---|---|
/// | neo16 ↔ CORPLAP-1 | 80 probe failures, all `saw_inbound=false`; relay 108 ms | direct, **6.7 ms** |
/// | neo16 ↔ MacBook | relay, 113 ms avg | direct, **4 ms** floor |
///
/// The `false` value remains the kill switch, per this crate's convention for
/// default-ON overlay keys.
pub fn answer_while_followed() -> bool {
    crate::env::flag("OVERLAY_ANSWER_WHILE_FOLLOWED", true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P8 — the hairpin skip: all-peer-srflx-on-our-IP + a LAN candidate ⇒
    /// pointless; any differing IP, no LAN candidate, or unknown own srflx ⇒
    /// still worth trying.
    #[test]
    fn srflx_hairpin_pointless_cases() {
        let mine = Some("37.63.112.129:58770");
        let same = vec!["37.63.112.129:63669".to_string()];
        let mixed = vec![
            "37.63.112.129:63669".to_string(),
            "203.0.113.9:40000".to_string(),
        ];
        assert!(srflx_hairpin_pointless(mine, &same, true));
        assert!(
            !srflx_hairpin_pointless(mine, &same, false),
            "no LAN candidate ⇒ the hairpin may be all there is"
        );
        assert!(
            !srflx_hairpin_pointless(mine, &mixed, true),
            "a differing srflx IP ⇒ a real cross-NAT punch exists"
        );
        assert!(
            !srflx_hairpin_pointless(None, &same, true),
            "own srflx unknown"
        );
        assert!(
            !srflx_hairpin_pointless(mine, &[], true),
            "peer has no srflx"
        );
    }

    /// rc.210 — make-before-break is DEFAULT-ON with an explicit kill-switch.
    /// (Serialises env mutation; the overlay-l3 suite runs `--test-threads=1`.)
    #[test]
    fn make_before_break_defaults_on_with_kill_switch() {
        let n = "ROOMLERD_OVERLAY_MBB";
        let a = "ROOMLERD_OVERLAY_MBB";
        let (rn, ra) = (std::env::var(n).ok(), std::env::var(a).ok());
        unsafe {
            std::env::remove_var(n);
            std::env::remove_var(a);
        }
        assert!(make_before_break_enabled(), "unset → default ON");
        for v in ["1", "true", "on", "yes", "", "  ", "anything"] {
            unsafe { std::env::set_var(n, v) };
            assert!(make_before_break_enabled(), "{v:?} → ON");
        }
        for v in ["0", "false", "FALSE", "No", "off", " off "] {
            unsafe { std::env::set_var(n, v) };
            assert!(!make_before_break_enabled(), "{v:?} → kill-switch OFF");
        }
        unsafe {
            match rn {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
            match ra {
                Some(v) => std::env::set_var(a, v),
                None => std::env::remove_var(a),
            }
        }
    }

    /// Band-2 fallback: the candidate walk covers the primary band, then
    /// the SAME walk at `base + SECOND_BAND_OFFSET` — a Hyper-V/WSL
    /// reservation swallowing all 8 primary ports costs a region jump,
    /// not the stable-port feature. Fixed order, so band-2 binds are just
    /// as reproducible across restarts; `0` stays the ephemeral opt-out.
    #[test]
    fn candidates_walk_the_primary_band_then_the_second_region() {
        let got: Vec<u16> = direct_port_candidates(43648).collect();
        let mut expect: Vec<u16> = (43648..43656).collect();
        expect.extend(44160..44168);
        assert_eq!(got, expect);
        assert_eq!(
            direct_port_candidates(0).count(),
            0,
            "ephemeral opt-out yields nothing"
        );
        // Near the top of u16 the chain must saturate, never wrap.
        assert!(direct_port_candidates(u16::MAX - 4).all(|p| p >= u16::MAX - 4));
    }

    /// rc.307 — stable direct-port resolution: unset → the built-in default;
    /// a number → itself; `0` → ephemeral opt-out; 65535 (would overflow the
    /// public dialer's `port+1`) and garbage → the default, NEVER silently
    /// ephemeral (a typo must not turn the feature off fleet-wide).
    #[test]
    fn direct_port_resolution() {
        let n = "ROOMLERD_OVERLAY_DIRECT_PORT";
        let a = "ROOMLERD_OVERLAY_DIRECT_PORT";
        let (rn, ra) = (std::env::var(n).ok(), std::env::var(a).ok());
        unsafe {
            std::env::remove_var(n);
            std::env::remove_var(a);
        }
        assert_eq!(direct_port(), DEFAULT_DIRECT_PORT, "unset → default");
        for (v, want) in [
            ("43648", 43648u16),
            (" 12345 ", 12345),
            ("0", 0),
            ("65535", DEFAULT_DIRECT_PORT),
            ("70000", DEFAULT_DIRECT_PORT),
            ("porty", DEFAULT_DIRECT_PORT),
            ("", DEFAULT_DIRECT_PORT),
        ] {
            unsafe { std::env::set_var(n, v) };
            assert_eq!(direct_port(), want, "{v:?}");
        }
        // A base whose public-dial band would overflow is rejected → default.
        unsafe { std::env::set_var(n, MAX_DIRECT_PORT_BASE.to_string()) };
        assert_eq!(direct_port(), MAX_DIRECT_PORT_BASE, "max base accepted");
        unsafe { std::env::set_var(n, (MAX_DIRECT_PORT_BASE as u32 + 1).to_string()) };
        assert_eq!(
            direct_port(),
            DEFAULT_DIRECT_PORT,
            "base past the band cap → default"
        );
        unsafe {
            match rn {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
            match ra {
                Some(v) => std::env::set_var(a, v),
                None => std::env::remove_var(a),
            }
        }
    }

    /// rc.307 — the stable-port BAND: a fixed order (so a restart re-binds
    /// the same port), the base first, and nothing at all when disabled.
    #[test]
    fn direct_port_candidates_walk_in_fixed_order() {
        let c: Vec<u16> = direct_port_candidates(43648).collect();
        // Two bands now: the primary walk, then the SAME walk at
        // base+SECOND_BAND_OFFSET (see candidates_walk_the_primary_band…).
        assert_eq!(c.len(), 2 * DIRECT_PORT_BAND as usize);
        assert_eq!(c[0], 43648, "the base must be tried FIRST (stability)");
        assert!(
            c[..DIRECT_PORT_BAND as usize]
                .windows(2)
                .all(|w| w[1] == w[0] + 1),
            "primary band consecutive: {c:?}"
        );
        assert_eq!(
            c[DIRECT_PORT_BAND as usize],
            43648 + SECOND_BAND_OFFSET,
            "band 2 starts at the derived jump"
        );
        assert_eq!(
            direct_port_candidates(43648).collect::<Vec<_>>(),
            c,
            "the walk must be deterministic across calls"
        );
        assert_eq!(
            direct_port_candidates(0).count(),
            0,
            "0 = ephemeral opt-out: no stable candidates"
        );
        // Never overflows off the end of the port space (band 2 saturates
        // away entirely up here).
        assert!(direct_port_candidates(u16::MAX).all(|p| p >= u16::MAX - DIRECT_PORT_BAND));
    }

    /// rc.275 hygiene — the LAN-gather deny-list over the field-observed
    /// interface inventory: winhost-a's WSL vEthernet + Check Point adapter
    /// (whose friendly name is just "Ethernet" — only the DESCRIPTION gives
    /// it away) must be denied; every real physical NIC stays allowed.
    /// §6 item 5 — IPv6 candidates: only global unicast counts, the v4 and v6
    /// pickers each see their own family, and our own address is skipped.
    #[test]
    fn ipv6_candidates_are_global_only_and_family_separated() {
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        assert!(is_public_v6(v6("2001:db8::1")) && is_public_v6(v6("240e:3a1::5")));
        for not in ["fe80::1", "fd7a:115c:a1e0::1", "::1", "::ffff:1.2.3.4", "ff02::1", "::"] {
            assert!(!is_public_v6(v6(not)), "{not}");
        }
        assert_eq!(v6_candidates(&[v6("2001:db8::5")], 45200), vec!["[2001:db8::5]:45200".to_string()]);
        let cands: Vec<String> = ["203.0.113.7:1", "[2001:db8::5]:45200", "[fe80::1]:1", "[2001:db8::9]:7"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let at = |s: &str| Some(s.parse::<SocketAddr>().unwrap());
        assert_eq!(pick_v6_endpoint_rotated(&[], &cands, 0), at("[2001:db8::5]:45200"));
        assert_eq!(pick_v6_endpoint_rotated(&[], &cands, 1), at("[2001:db8::9]:7"), "rotated");
        assert_eq!(pick_v6_endpoint_rotated(&[v6("2001:db8::5")], &cands, 0), at("[2001:db8::9]:7"), "own skipped");
        assert_eq!(pick_public_endpoint(&[], &cands), at("203.0.113.7:1"), "the v4 picker ignores v6");
        assert_eq!(pick_v6_endpoint_rotated(&[], &cands[..1], 0), None);
    }

    /// The IPv6 socket is V6ONLY, so it takes the same port number as an
    /// IPv4 bind (both families on the stable direct port).
    #[tokio::test]
    async fn the_ipv6_socket_shares_the_port_number_with_ipv4() {
        let v4 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        // `None` = no IPv6 in this sandbox; nothing to check then.
        if let Some(s) = bind_direct_socket_v6(port, "test").await {
            assert_eq!(s.local_addr().unwrap().port(), port);
            assert!(s.local_addr().unwrap().is_ipv6());
        }
    }

    #[test]
    fn lan_iface_denied_matrix() {
        // (name, description, denied) — descriptions verbatim from the field.
        let cases: &[(&str, &str, bool)] = &[
            // winhost-a's poison trio (2026-07-30):
            (
                "vEthernet (WSL (Hyper-V firewall))",
                "Hyper-V Virtual Ethernet Adapter",
                true,
            ),
            (
                "Ethernet",
                "Check Point Virtual Network Adapter For Endpoint VPN Client",
                true,
            ),
            ("LAN-Verbindung", "Wintun Userspace Tunnel", true),
            // Real NICs across the fleet — must stay allowed:
            ("WLAN", "Intel(R) Wi-Fi 6E AX211 160MHz", false),
            ("WLAN", "Intel(R) Wi-Fi 7 BE200 320MHz", false),
            ("Ethernet", "Intel(R) Ethernet Controller I226-LM", false),
            ("Ethernet", "Realtek PCIe GbE Family Controller", false),
            ("Local Area Connection", "Broadcom NetXtreme Gigabit", false),
            ("Mobilfunk", "Intel(R)XMM(TM)7560R+ LTE-A Pro", false),
            // Unix naming conventions (no description available):
            ("eth0", "", false),
            ("enp3s0", "", false),
            ("wlp2s0", "", false),
            ("wlan0", "", false),
            ("en0", "", false),
            ("docker0", "", true),
            ("veth1a2b3c", "", true),
            ("virbr0", "", true),
            ("br-4f5e6d", "", true),
            ("bridge100", "", true),
            ("tun0", "", true),
            ("tap0", "", true),
            ("utun3", "", true),
            ("wg0", "", true),
            ("ppp0", "", true),
            ("roomler0", "", true),
            ("tailscale0", "", true),
            // TAP/OpenVPN on Windows hides behind a generic name too:
            ("Ethernet 2", "TAP-Windows Adapter V9", true),
        ];
        for (name, desc, want) in cases {
            assert_eq!(
                lan_iface_denied(name, desc),
                *want,
                "name={name:?} desc={desc:?}"
            );
        }
    }

    /// A tunnel device is recognised by what sysfs says it is, not by its
    /// name: a TUN/TAP of any name (`tun_flags`), WireGuard (`ARPHRD_NONE`),
    /// PPP, IPIP, SIT, GRE. Ethernet-type devices stay allowed.
    #[test]
    fn tunnel_iface_is_structural_not_by_name() {
        let root = std::env::temp_dir().join(format!("mh-sysnet-{}", std::process::id()));
        let dev = |name: &str, kind: &str, tun: bool| {
            let d = root.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("type"), format!("{kind}\n")).unwrap();
            if tun {
                std::fs::write(d.join("tun_flags"), "0x1001\n").unwrap();
            }
        };
        dev("etitachi0", "65534", true); // EasyTier's TUN, field 2026-10-25
        dev("mytap", "1", true); // a TAP is Ethernet-type but still a TUN/TAP
        dev("office-wg", "65534", false); // kernel WireGuard
        dev("sit1", "776", false);
        dev("gre9", "778", false);
        dev("pppoe-wan", "512", false);
        dev("eth0", "1", false);
        dev("veth9", "1", false); // a pod's own network
        for (name, want) in [
            ("etitachi0", true),
            ("mytap", true),
            ("office-wg", true),
            ("sit1", true),
            ("gre9", true),
            ("pppoe-wan", true),
            ("eth0", false),
            ("veth9", false),
            ("absent0", false),
        ] {
            assert_eq!(tunnel_iface_at(&root, name), want, "{name}");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// rc.275 hygiene — the filter is DEFAULT-ON with an explicit kill-switch,
    /// mirroring `direct_enabled`. (Serialises env mutation; the overlay-l3
    /// suite runs `--test-threads=1`.)
    #[test]
    fn lan_iface_filter_defaults_on_with_kill_switch() {
        let n = "ROOMLERD_OVERLAY_LAN_IFACE_FILTER";
        let a = "ROOMLERD_OVERLAY_LAN_IFACE_FILTER";
        let (rn, ra) = (std::env::var(n).ok(), std::env::var(a).ok());
        unsafe {
            std::env::remove_var(n);
            std::env::remove_var(a);
        }
        assert!(lan_iface_filter_enabled(), "unset → default ON");
        for v in ["1", "true", "on", "yes", "", "  ", "anything"] {
            unsafe { std::env::set_var(n, v) };
            assert!(lan_iface_filter_enabled(), "{v:?} → ON");
        }
        for v in ["0", "false", "FALSE", "No", "off", " off "] {
            unsafe { std::env::set_var(n, v) };
            assert!(!lan_iface_filter_enabled(), "{v:?} → kill-switch OFF");
        }
        unsafe {
            match rn {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
            match ra {
                Some(v) => std::env::set_var(a, v),
                None => std::env::remove_var(a),
            }
        }
    }

    /// rc.276 (B-probe) — forced TLS-relay is DEFAULT-OFF opt-in (positive
    /// truthy only), mirroring `public_direct_enabled`. (Serialises env
    /// mutation; the overlay-l3 suite runs `--test-threads=1`.)
    #[test]
    fn relay_tls_forced_defaults_off_with_opt_in() {
        let n = "ROOMLERD_OVERLAY_RELAY_TLS";
        let a = "ROOMLERD_OVERLAY_RELAY_TLS";
        let (rn, ra) = (std::env::var(n).ok(), std::env::var(a).ok());
        unsafe {
            std::env::remove_var(n);
            std::env::remove_var(a);
        }
        assert!(!relay_tls_forced(), "unset → default OFF");
        for v in ["1", "true", "On", "yes"] {
            unsafe { std::env::set_var(n, v) };
            assert!(relay_tls_forced(), "{v:?} → opt-in ON");
        }
        for v in ["0", "false", "off", "", "  ", "anything"] {
            unsafe { std::env::set_var(n, v) };
            assert!(!relay_tls_forced(), "{v:?} → stays OFF");
        }
        unsafe {
            match rn {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
            match ra {
                Some(v) => std::env::set_var(a, v),
                None => std::env::remove_var(a),
            }
        }
    }

    /// bind-to-interface-by-route is DEFAULT-OFF opt-in (positive truthy only),
    /// mirroring `public_direct_enabled`. (Serialises env mutation.)
    #[test]
    fn bind_by_route_defaults_off_with_opt_in() {
        let n = "ROOMLERD_OVERLAY_BIND_BY_ROUTE";
        let a = "ROOMLERD_OVERLAY_BIND_BY_ROUTE";
        let (rn, ra) = (std::env::var(n).ok(), std::env::var(a).ok());
        unsafe {
            std::env::remove_var(n);
            std::env::remove_var(a);
        }
        assert!(!bind_by_route_enabled(), "unset → default OFF");
        for v in ["1", "true", "On", "yes"] {
            unsafe { std::env::set_var(n, v) };
            assert!(bind_by_route_enabled(), "{v:?} → opt-in ON");
        }
        for v in ["0", "false", "off", "", "  ", "anything"] {
            unsafe { std::env::set_var(n, v) };
            assert!(!bind_by_route_enabled(), "{v:?} → stays OFF");
        }
        unsafe {
            match rn {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
            match ra {
                Some(v) => std::env::set_var(a, v),
                None => std::env::remove_var(a),
            }
        }
    }

    /// VPN-bypass is DEFAULT-OFF opt-in; `vpn_bypass_ifindex` resolves only when
    /// the gate is ON **and** an uplink ifindex override is set. (Serialises
    /// env mutation; the overlay-l3 suite runs `--test-threads=1`.)
    #[test]
    fn vpn_bypass_gate_and_ifindex_override() {
        let g = "ROOMLERD_OVERLAY_VPN_BYPASS";
        let ga = "ROOMLERD_OVERLAY_VPN_BYPASS";
        let u = "ROOMLERD_OVERLAY_UPLINK_IF";
        let ua = "ROOMLERD_OVERLAY_UPLINK_IF";
        let save = [g, ga, u, ua].map(|k| (k, std::env::var(k).ok()));
        unsafe {
            for k in [g, ga, u, ua] {
                std::env::remove_var(k);
            }
        }
        assert!(!vpn_bypass_enabled(), "unset → OFF");
        assert_eq!(uplink_ifindex_override(), None);
        assert_eq!(vpn_bypass_ifindex(), None);

        // Uplink set but gate off → no pin.
        unsafe { std::env::set_var(u, "25") };
        assert_eq!(uplink_ifindex_override(), Some(25));
        assert_eq!(
            vpn_bypass_ifindex(),
            None,
            "gate off → no pin even with uplink"
        );

        // Gate on + uplink set → pin to the uplink ifindex.
        unsafe { std::env::set_var(g, "1") };
        assert!(vpn_bypass_enabled());
        assert_eq!(vpn_bypass_ifindex(), Some(25), "gate on + uplink → pin");

        // Gate on but no/garbage uplink → None (nothing to pin to yet).
        unsafe {
            std::env::remove_var(u);
            std::env::set_var(u, "notanumber");
        }
        assert_eq!(vpn_bypass_ifindex(), None, "unparseable uplink → None");

        unsafe {
            for (k, v) in save {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// The pure egress classifier: the OS-chosen source IP mapped against the
    /// interfaces we hold a socket on, with the CGNAT loop-guard.
    #[test]
    fn classify_egress_cases() {
        let wifi: Ipv4Addr = "192.168.68.106".parse().unwrap();
        let eth: Ipv4Addr = "172.30.224.45".parse().unwrap();
        let ours = [wifi, eth]; // a multi-homed host's real LAN sockets
        // On-link /24 wins over the VPN default → the OS sources from the WiFi
        // NIC → Use it (the winhost-a-through-VPN happy path).
        assert_eq!(classify_egress(Some(wifi), &ours), Egress::Use(wifi));
        // Multi-homed: whichever real interface the OS picks is used verbatim.
        assert_eq!(classify_egress(Some(eth), &ours), Egress::Use(eth));
        // The OS routes the dst via an interface we don't hold a LAN socket on
        // (a full-tunnel VPN captured it) → Foreign → skip direct → relay.
        let vpn: Ipv4Addr = "10.66.24.53".parse().unwrap();
        assert_eq!(classify_egress(Some(vpn), &ours), Egress::Foreign);
        // The route resolves back into the overlay's own CGNAT TUN → Loop.
        assert_eq!(
            classify_egress(Some("100.64.0.2".parse().unwrap()), &ours),
            Egress::Loop
        );
        // Query failed → Unknown → caller keeps the same-subnet behaviour.
        assert_eq!(classify_egress(None, &ours), Egress::Unknown);
        // Empty socket set (relay-only host) → any real source is Foreign.
        assert_eq!(classify_egress(Some(wifi), &[]), Egress::Foreign);
    }

    /// The connect()-trick resolves a plausible source IP for a routable dst on
    /// any platform (no packet is sent; we only read the bound local address).
    #[tokio::test]
    async fn os_src_ip_for_returns_a_source_on_a_routable_dst() {
        // 8.8.8.8 resolves via the default route on any host with networking;
        // loopback is the fallback that always works in a sandbox.
        let via_loopback = os_src_ip_for("127.0.0.1:9".parse().unwrap()).await;
        assert_eq!(
            via_loopback,
            Some(Ipv4Addr::LOCALHOST),
            "a loopback dst sources from loopback"
        );
    }

    #[test]
    fn cgnat_and_lan_classification() {
        assert!(is_usable_lan_ipv4("192.168.68.103".parse().unwrap()));
        assert!(is_usable_lan_ipv4("10.16.6.34".parse().unwrap()));
        assert!(!is_usable_lan_ipv4("127.0.0.1".parse().unwrap()));
        assert!(!is_usable_lan_ipv4("169.254.1.2".parse().unwrap()));
        assert!(!is_usable_lan_ipv4("0.0.0.0".parse().unwrap()));
        // CGNAT / overlay range rejected (the cellular-carrier collision).
        assert!(!is_usable_lan_ipv4("100.64.0.1".parse().unwrap()));
        assert!(!is_usable_lan_ipv4("100.127.255.1".parse().unwrap()));
        assert!(is_usable_lan_ipv4("100.128.0.1".parse().unwrap())); // just outside /10
    }

    #[test]
    fn same_subnet_24_matches_lan_pairs() {
        let a: Ipv4Addr = "192.168.68.103".parse().unwrap();
        let b: Ipv4Addr = "192.168.68.110".parse().unwrap();
        let c: Ipv4Addr = "192.168.69.110".parse().unwrap();
        assert!(same_subnet_24(a, b), "WINHOST-A + DEVBOX are same /24");
        assert!(!same_subnet_24(a, c), "different /24");
    }

    #[test]
    fn picks_same_subnet_host_endpoint_else_none() {
        let me: [Ipv4Addr; 1] = ["192.168.68.103".parse().unwrap()];
        // Mixed endpoint list: a far srflx, the relay, and the LAN host.
        let eps = vec![
            "37.63.112.129:49358".to_string(),  // srflx (different /24) — skip
            "94.130.141.74:3478".to_string(),   // relay — skip
            "192.168.68.110:51820".to_string(), // same /24 — pick this
        ];
        let got = pick_same_subnet_endpoint(&me, &eps).unwrap();
        assert_eq!(
            got,
            (
                "192.168.68.103".parse::<Ipv4Addr>().unwrap(),
                "192.168.68.110:51820".parse::<SocketAddr>().unwrap()
            )
        );

        // No same-subnet endpoint → None (caller uses relay).
        let only_far = vec!["37.63.112.129:49358".to_string()];
        assert!(pick_same_subnet_endpoint(&me, &only_far).is_none());

        // A same-subnet but CGNAT endpoint is rejected.
        let cgnat = vec!["100.64.0.110:51820".to_string()];
        assert!(pick_same_subnet_endpoint(&["100.64.0.103".parse().unwrap()], &cgnat).is_none());
    }

    /// WSL2 mirrored networking is detected only when BOTH markers agree.
    ///
    /// The kernel string alone is not enough: a WSL2 guest in the DEFAULT NAT
    /// mode has its own private `172.x` on `eth0` and a genuine (if host-only)
    /// LAN identity — suppressing its gather there would be a regression for
    /// every NAT-mode guest on the fleet. The `10.255.255.254` loopback alias
    /// is what WSL adds specifically for mirrored host access.
    #[test]
    fn wsl2_mirrored_needs_both_the_kernel_and_the_host_access_alias() {
        let wsl = "6.6.87.2-microsoft-standard-WSL2"; // devbox's guest, verbatim
        assert!(
            wsl2_mirrored_from_parts(wsl, true),
            "WSL2 kernel + host-access alias = mirrored"
        );
        assert!(
            !wsl2_mirrored_from_parts(wsl, false),
            "WSL2 kernel WITHOUT the alias is NAT mode — it keeps its own LAN gather"
        );
        assert!(
            !wsl2_mirrored_from_parts("6.8.0-51-generic", true),
            "a bare-metal Linux host that happens to hold 10.255.255.254 is NOT WSL"
        );
        assert!(!wsl2_mirrored_from_parts("", false));
        // Case-insensitive: the kernel string's casing is not a contract.
        assert!(wsl2_mirrored_from_parts(
            "5.15.0-microsoft-standard-wsl2",
            true
        ));
    }

    /// The guard is default-ON with a kill switch, matching every other
    /// overlay gate — a misdetection must be recoverable without a rebuild.
    #[test]
    fn wsl_mirrored_guard_defaults_on_with_kill_switch() {
        // SAFETY: single-threaded test, restored before returning.
        let key = "ROOMLERD_OVERLAY_WSL_MIRRORED_GUARD";
        unsafe { std::env::remove_var(key) };
        assert!(wsl_mirrored_guard_enabled(), "default ON");
        unsafe { std::env::set_var(key, "0") };
        assert!(!wsl_mirrored_guard_enabled(), "0 disables");
        unsafe { std::env::set_var(key, "off") };
        assert!(!wsl_mirrored_guard_enabled(), "off disables");
        unsafe { std::env::remove_var(key) };
    }

    /// Non-Linux can never be a WSL guest, so the guard must be inert there —
    /// this is what keeps the Windows/macOS gather untouched.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn wsl_detection_is_inert_off_linux() {
        assert!(!wsl2_mirrored_networking());
        // …and therefore the gather is NOT short-circuited on this platform.
        // (Can't assert non-empty: CI runners may have no usable LAN NIC.)
    }

    /// A peer advertising OUR OWN address is not a LAN candidate — dialling it
    /// never leaves this host.
    ///
    /// Field 2026-08-14, devbox (192.168.68.126 on Wi-Fi): both WSL peers run in
    /// mirrored mode, which shares the host's NICs, so each advertised the
    /// host's own address on its own port. The /24 test passed against
    /// ourselves and the LAN probe ran every 90 s for 14 days — 12 684
    /// failures, zero successes. Worse, the phantom candidate fed
    /// `srflx_hairpin_pointless`, suppressing srflx too, so the pair could
    /// never promote off `relay:derp/tcp` by ANY tier.
    #[test]
    fn our_own_address_is_never_a_lan_candidate() {
        let me: [Ipv4Addr; 1] = ["192.168.68.126".parse().unwrap()];

        // Exactly what devbox probed 12 684 times. Different port, same host.
        let wsl_mirrored = vec!["192.168.68.126:43648".to_string()];
        assert!(
            pick_same_subnet_endpoint(&me, &wsl_mirrored).is_none(),
            "our own address cannot be dialled off-box, whatever the port"
        );

        // A real neighbour on the same /24 is still picked — the guard must not
        // disable the LAN tier generally.
        let neighbour = vec!["192.168.68.119:43648".to_string()];
        assert!(pick_same_subnet_endpoint(&me, &neighbour).is_some());

        // And a self-address earlier in the list must not shadow a usable one
        // after it: the guard skips the endpoint, it does not end the search.
        let both = vec![
            "192.168.68.126:43648".to_string(),
            "192.168.68.119:43648".to_string(),
        ];
        let (local, ep) = pick_same_subnet_endpoint(&me, &both).expect("neighbour still reachable");
        assert_eq!(local, me[0]);
        assert_eq!(ep, "192.168.68.119:43648".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn public_v4_classification() {
        let public = ["5.9.157.226", "94.130.141.98", "203.0.113.9", "8.8.8.8"];
        for p in public {
            assert!(is_public_v4(p.parse().unwrap()), "{p} must classify public");
        }
        let not_public = [
            "192.168.68.103", // RFC1918
            "10.16.6.34",     // RFC1918
            "172.16.0.1",     // RFC1918
            "127.0.0.1",      // loopback
            "169.254.1.2",    // link-local
            "100.64.0.1",     // CGNAT / overlay
            "0.0.0.0",        // unspecified
            "0.1.2.3",        // 0/8
            "224.0.0.1",      // multicast
            "240.0.0.1",      // 240/4 reserved
            "255.255.255.255",
        ];
        for p in not_public {
            assert!(!is_public_v4(p.parse().unwrap()), "{p} must NOT be public");
        }
    }

    #[test]
    fn picks_first_public_endpoint_skipping_private_and_self() {
        let my_ips: [Ipv4Addr; 2] = [
            "94.130.141.98".parse().unwrap(),
            "192.168.150.1".parse().unwrap(),
        ];
        // Peer join bucket: its LAN address, then its public NIC address.
        let eps = vec![
            "192.168.7.23:41000".to_string(), // peer's private LAN — not dialable x-net
            "5.9.157.226:41234".to_string(),  // peer's public NIC — pick this
        ];
        assert_eq!(
            pick_public_endpoint(&my_ips, &eps),
            Some("5.9.157.226:41234".parse().unwrap())
        );

        // Our OWN public IP in a peer record is never a dial target.
        let self_ep = vec!["94.130.141.98:41000".to_string()];
        assert!(pick_public_endpoint(&my_ips, &self_ep).is_none());

        // All-private bucket → None (NAT'd peer; passive/relay handles it).
        let private_only = vec![
            "192.168.7.23:41000".to_string(),
            "10.0.0.5:41001".to_string(),
        ];
        assert!(pick_public_endpoint(&my_ips, &private_only).is_none());
    }

    #[test]
    fn gather_lan_ips_returns_only_usable_uniques() {
        // Exercises the real if-addrs enumeration on this host/CI runner. We
        // can't assert a specific set (host-dependent), only the invariants:
        // every gathered IP is usable, and there are no duplicates.
        let ips = gather_lan_ips();
        for ip in &ips {
            assert!(
                is_usable_lan_ipv4(*ip),
                "gather returned a non-usable IP: {ip}"
            );
        }
        let mut deduped = ips.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            ips.len(),
            "gather_lan_ips returned duplicates"
        );
    }

    #[test]
    fn multi_homed_host_matches_on_the_right_interface() {
        // rc.132 regression guard: WINHOST-A's bug. The node is multi-homed —
        // corporate Ethernet 172.30.x (the default route) + Wi-Fi 192.168.68.x.
        // The peer is on the Wi-Fi; we must match the 192.168.68 endpoint even
        // though 172.30 is "primary".
        let my_ips: [Ipv4Addr; 2] = [
            "172.30.239.96".parse().unwrap(), // corporate Ethernet (default route)
            "192.168.68.103".parse().unwrap(), // Wi-Fi (where the peer lives)
        ];
        // The peer (DEVBOX) advertises only ITS interfaces — a far srflx and its
        // Wi-Fi host. We must match the Wi-Fi endpoint against our SECONDARY
        // (non-default-route) Wi-Fi IP — the rc.131 connect-trick advertised
        // only 172.30 and so never matched.
        let peer_eps = vec![
            "37.63.112.129:49358".to_string(),  // peer srflx (far) — skip
            "192.168.68.110:58307".to_string(), // peer Wi-Fi — same /24 as our .103
        ];
        let got = pick_same_subnet_endpoint(&my_ips, &peer_eps).unwrap();
        assert_eq!(
            got,
            (
                "192.168.68.103".parse::<Ipv4Addr>().unwrap(),
                "192.168.68.110:58307".parse::<SocketAddr>().unwrap()
            )
        );
    }

    #[test]
    fn parse_stun_url_handles_schemes_and_rejects_hostnames() {
        let want: SocketAddr = "5.9.157.221:3478".parse().unwrap();
        assert_eq!(parse_stun_url("stun:5.9.157.221:3478"), Some(want));
        assert_eq!(parse_stun_url("stuns:5.9.157.221:3478"), Some(want));
        assert_eq!(
            parse_stun_url("turn:5.9.157.221:3478?transport=udp"),
            Some(want)
        );
        assert_eq!(parse_stun_url("5.9.157.221:3478"), Some(want));
        assert_eq!(parse_stun_url("  stun:5.9.157.221:3478  "), Some(want));
        // Hostnames need async DNS → the sync parser declines (caller resolves).
        assert_eq!(parse_stun_url("stun:coturn.roomler.ai:3478"), None);
        // IPv6 is out of scope (v4-only cascade).
        assert_eq!(parse_stun_url("stun:[2a01:4f8::2]:3478"), None);
        assert_eq!(parse_stun_url("garbage"), None);
    }

    /// FR-48 — `stun_hostport` is now the SINGLE scheme-stripper behind all
    /// three `resolve_stun_*` fns and behind the DNS cache key. If it drifts,
    /// every vantage resolver drifts with it and the cache keys stop matching
    /// what is actually looked up, so lock the shape here.
    #[test]
    fn stun_hostport_strips_scheme_and_query_for_every_form() {
        for url in [
            "stun:coturn-us-east.roomler.ai:3478",
            "stuns:coturn-us-east.roomler.ai:3478",
            "turn:coturn-us-east.roomler.ai:3478",
            "turns:coturn-us-east.roomler.ai:3478",
            "turn:coturn-us-east.roomler.ai:3478?transport=udp",
            "turns:coturn-us-east.roomler.ai:3478#frag",
            "  stun:coturn-us-east.roomler.ai:3478  ",
            "coturn-us-east.roomler.ai:3478",
        ] {
            assert_eq!(
                stun_hostport(url),
                "coturn-us-east.roomler.ai:3478",
                "hostport for {url:?}"
            );
        }
    }

    /// Minimal STUN Binding Success carrying an XOR-MAPPED-ADDRESS (IPv4), so
    /// the gather test needs no real STUN server. Mirrors RFC 5389 §15.2.
    fn stun_success(txn: [u8; 12], ip: [u8; 4], port: u16) -> Vec<u8> {
        const COOKIE: u32 = 0x2112_A442;
        let cookie = COOKIE.to_be_bytes();
        let xport = port ^ ((COOKIE >> 16) as u16);
        let mut r = Vec::new();
        r.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
        r.extend_from_slice(&12u16.to_be_bytes()); // one 12-byte attribute
        r.extend_from_slice(&cookie);
        r.extend_from_slice(&txn);
        r.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        r.extend_from_slice(&8u16.to_be_bytes());
        r.push(0);
        r.push(0x01); // family IPv4
        r.extend_from_slice(&xport.to_be_bytes());
        r.extend_from_slice(&[
            ip[0] ^ cookie[0],
            ip[1] ^ cookie[1],
            ip[2] ^ cookie[2],
            ip[3] ^ cookie[3],
        ]);
        r
    }

    /// Spawn a fake STUN server that answers every Binding Request with a
    /// success carrying `reply_ip:reply_port`. Returns its addr + the task
    /// handle (kept alive by the caller for the test's duration).
    async fn fake_stun_server(
        reply_ip: [u8; 4],
        reply_port: u16,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = srv.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = srv.recv_from(&mut buf).await {
                if n >= 20 {
                    let txn: [u8; 12] = buf[8..20].try_into().unwrap();
                    let _ = srv
                        .send_to(&stun_success(txn, reply_ip, reply_port), from)
                        .await;
                }
            }
        });
        (addr, h)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gather_srflx_captures_public_filters_private_and_dead() {
        // A PUBLIC srflx reply is captured.
        let (pub_srv, _h1) = fake_stun_server([203, 0, 113, 9], 40000).await;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socks = vec![("127.0.0.1".parse().unwrap(), sock.clone())];
        let got = gather_srflx(&socks, pub_srv, Duration::from_millis(500)).await;
        assert_eq!(got.len(), 1, "one public srflx");
        assert_eq!(got[0].0, "203.0.113.9:40000".to_string());
        assert!(
            Arc::ptr_eq(&got[0].1, &sock),
            "candidate carries its own socket"
        );

        // A PRIVATE srflx (STUN on the LAN / hairpin) is filtered out.
        let (priv_srv, _h2) = fake_stun_server([192, 168, 1, 5], 41000).await;
        let sock2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socks2 = vec![("127.0.0.1".parse().unwrap(), sock2)];
        assert!(
            gather_srflx(&socks2, priv_srv, Duration::from_millis(500))
                .await
                .is_empty()
        );

        // A dead STUN server yields no candidates (fast timeout, no hang).
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let sock3 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socks3 = vec![("127.0.0.1".parse().unwrap(), sock3)];
        assert!(
            gather_srflx(&socks3, dead, Duration::from_millis(150))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn resolve_stun_server_prefers_ip_literals_and_skips_bad_entries() {
        let want: SocketAddr = "5.9.157.221:3478".parse().unwrap();
        // An IP-literal URL resolves synchronously — no DNS.
        assert_eq!(
            resolve_stun_server(&["stun:5.9.157.221:3478".to_string()], &[]).await,
            Some(want)
        );
        // Empty → None (srflx tier inert).
        assert_eq!(resolve_stun_server(&[], &[]).await, None);
        // A malformed leading entry (no `host:port`, so `lookup_host` errors
        // immediately without network I/O) is skipped → the usable IP literal
        // behind it wins.
        assert_eq!(
            resolve_stun_server(
                &[
                    "not-a-host-port".to_string(),
                    "stun:5.9.157.221:3478".to_string(),
                ],
                &[]
            )
            .await,
            Some(want)
        );
        // A worker CO-LOCATED with this host (its IP is in `exclude`) is skipped
        // → the next worker wins. Prevents a fleet host from STUNning itself.
        assert_eq!(
            resolve_stun_server(
                &[
                    "stun:94.130.141.74:3478".to_string(),
                    "stun:5.9.157.221:3478".to_string(),
                ],
                &["94.130.141.74".parse().unwrap()],
            )
            .await,
            Some(want)
        );
        // ALL targets co-located → None (correctly: this host truly can't STUN a
        // NON-self worker, so it has no usable srflx from this set).
        assert_eq!(
            resolve_stun_server(
                &["stun:94.130.141.74:3478".to_string()],
                &["94.130.141.74".parse().unwrap()],
            )
            .await,
            None
        );
    }

    #[tokio::test]
    async fn resolve_stun_targets_requires_distinct_ips() {
        // Two IP-literal URLs on distinct IPs → both returned (strongest probe).
        let t = resolve_stun_targets(
            &[
                "stun:5.9.157.221:3478".to_string(),
                "stun:94.130.141.98:3478".to_string(),
            ],
            &[],
        )
        .await;
        assert_eq!(t.len(), 2);
        assert_ne!(t[0].ip(), t[1].ip());
        // Same IP, two ports → ONE target only. Two ports on one server share
        // the NAT path (can never honestly disagree about our mapping) and
        // with the cluster's :443→:3478 DNAT alias the two flows COLLIDE in
        // conntrack, forcing a source-port rewrite on the second — the false
        // "symmetric" that vetoed the srflx tier fleet-wide (2026-08-15/16;
        // caught by the #487 typing line). The classifier abstains below two
        // mappings, which is the honest outcome for a one-IP vantage set.
        let t2 = resolve_stun_targets(
            &[
                "stun:5.9.157.221:3478".to_string(),
                "stun:5.9.157.221:443".to_string(),
            ],
            &[],
        )
        .await;
        assert_eq!(
            t2.len(),
            1,
            "same-IP port variants must not be typing vantages"
        );
        // Port variants still lose to a genuine second IP: variants of the
        // first IP never crowd out the distinct-IP pick.
        let t2b = resolve_stun_targets(
            &[
                "stun:5.9.157.221:3478".to_string(),
                "stun:5.9.157.221:443".to_string(),
                "stun:94.130.141.98:3478".to_string(),
            ],
            &[],
        )
        .await;
        assert_eq!(t2b.len(), 2);
        assert_ne!(t2b[0].ip(), t2b[1].ip());
        // A single target → len 1 (the caller can't classify).
        assert_eq!(
            resolve_stun_targets(&["stun:5.9.157.221:3478".to_string()], &[])
                .await
                .len(),
            1
        );
        // Empty → empty.
        assert!(resolve_stun_targets(&[], &[]).await.is_empty());
        // A co-located worker is excluded → only the non-self target remains.
        let t3 = resolve_stun_targets(
            &[
                "stun:94.130.141.74:3478".to_string(),
                "stun:5.9.157.221:3478".to_string(),
            ],
            &["94.130.141.74".parse().unwrap()],
        )
        .await;
        assert_eq!(t3.len(), 1);
        assert_eq!(t3[0].ip().to_string(), "5.9.157.221");
    }

    /// W5(b) — the self-vantage filter: targets whose IP is one of the
    /// host's own drop from the TYPING set; everything else survives in
    /// order. Pure core tested with a synthetic own-set (the `if_addrs`
    /// wrapper is environment-dependent by nature).
    #[test]
    fn exclude_vantages_in_drops_own_ips_and_keeps_the_rest() {
        use std::collections::HashSet;
        use std::net::IpAddr;
        let own: HashSet<IpAddr> = ["94.130.141.74", "10.10.20.11"]
            .into_iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let t = |s: &str| -> SocketAddr { s.parse().unwrap() };
        let targets = [
            t("94.130.141.74:3478"), // self (buildhost-style co-hosted PoP)
            t("5.9.157.221:3478"),
            t("10.10.20.11:3478"), // self (pod IP)
            t("5.9.157.226:3478"),
        ];
        let kept = exclude_vantages_in(&targets, &own);
        assert_eq!(kept, vec![t("5.9.157.221:3478"), t("5.9.157.226:3478")]);
        // No own-IPs ⇒ untouched; all-own ⇒ empty (typing then abstains —
        // `None`/unknown beats a hairpin-forged "symmetric").
        assert_eq!(exclude_vantages_in(&targets, &HashSet::new()), targets);
        let all_own: HashSet<IpAddr> = targets.iter().map(|t| t.ip()).collect();
        assert!(exclude_vantages_in(&targets, &all_own).is_empty());
    }

    #[tokio::test]
    async fn probe_nat_type_cone_vs_symmetric_else_none() {
        // Cone: both servers observe the SAME public mapping.
        let (a, _h1) = fake_stun_server([203, 0, 113, 9], 5000).await;
        let (b, _h2) = fake_stun_server([203, 0, 113, 9], 5000).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            probe_nat_type(&sock, &[a, b], Duration::from_millis(500)).await,
            Some("cone")
        );

        // Symmetric: the two servers observe DIFFERENT ports.
        let (c, _h3) = fake_stun_server([203, 0, 113, 9], 5000).await;
        let (d, _h4) = fake_stun_server([203, 0, 113, 9], 6000).await;
        let sock2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            probe_nat_type(&sock2, &[c, d], Duration::from_millis(500)).await,
            Some("symmetric")
        );

        // Fewer than two targets → can't classify.
        let sock3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            probe_nat_type(&sock3, &[a], Duration::from_millis(200)).await,
            None
        );
        // A dead target → None (caller stays optimistic and attempts anyway).
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let sock4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            probe_nat_type(&sock4, &[a, dead], Duration::from_millis(150)).await,
            None
        );
    }

    /// A1 — the winhost-a case: with three vantages available, the second pick
    /// must be the CROSS-DC one (different /16), not the same-/24 sibling —
    /// otherwise a per-destination-subnet NAT looks cone.
    #[tokio::test]
    async fn resolve_stun_targets_prefers_cross_dc_third_vantage() {
        let t = resolve_stun_targets(
            &[
                "stun:5.9.157.221:3478".to_string(),
                "stun:5.9.157.226:3478".to_string(),
                "stun:94.130.141.74:3478".to_string(),
            ],
            &[],
        )
        .await;
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].ip().to_string(), "5.9.157.221");
        // Different /16 beats the same-/24 sibling for the second vantage…
        assert_eq!(t[1].ip().to_string(), "94.130.141.74");
        // …and the sibling still joins as the third.
        assert_eq!(t[2].ip().to_string(), "5.9.157.226");
    }

    /// A1 — three vantages: one dead vantage is tolerated (2 answers still
    /// classify), and a mapping that only differs toward the THIRD vantage
    /// (per-destination-subnet NAT, the winhost-a signature) is caught.
    #[tokio::test]
    async fn probe_nat_type_third_vantage_tolerance_and_detection() {
        // Dead middle vantage, agreeing outer two → cone (tolerated).
        let (a, _h1) = fake_stun_server([203, 0, 113, 9], 5000).await;
        let (b, _h2) = fake_stun_server([203, 0, 113, 9], 5000).await;
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            probe_nat_type(&sock, &[a, dead, b], Duration::from_millis(300)).await,
            Some("cone")
        );

        // Two agreeing vantages + a third observing a DIFFERENT mapping →
        // symmetric (the 2-vantage probe would have said cone).
        let (c, _h3) = fake_stun_server([203, 0, 113, 9], 5000).await;
        let (d, _h4) = fake_stun_server([203, 0, 113, 9], 5000).await;
        let (e, _h5) = fake_stun_server([203, 0, 113, 9], 6000).await;
        let sock2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            probe_nat_type(&sock2, &[c, d, e], Duration::from_millis(500)).await,
            Some("symmetric")
        );
    }

    #[test]
    fn classify_nat_mappings_cases() {
        let a: SocketAddr = "198.51.100.7:5000".parse().unwrap();
        let b: SocketAddr = "198.51.100.7:6000".parse().unwrap();
        assert_eq!(classify_nat_mappings(&[]), None);
        assert_eq!(classify_nat_mappings(&[a]), None);
        assert_eq!(classify_nat_mappings(&[a, a]), Some("cone"));
        assert_eq!(classify_nat_mappings(&[a, a, a]), Some("cone"));
        assert_eq!(classify_nat_mappings(&[a, b]), Some("symmetric"));
        assert_eq!(classify_nat_mappings(&[a, a, b]), Some("symmetric"));
    }

    /// A2 — rotation walks every VIABLE candidate (non-public/self entries
    /// never counted), wraps, and offset 0 is byte-identical to
    /// [`pick_public_endpoint`].
    #[test]
    fn pick_public_endpoint_rotates_by_attempt() {
        let my_ips: Vec<Ipv4Addr> = vec!["10.0.0.5".parse().unwrap()];
        let cands = vec![
            "94.130.141.98:43648".to_string(),
            "192.168.1.10:43648".to_string(), // private — never viable
            "94.130.141.74:43648".to_string(),
        ];
        let p0 = pick_public_endpoint_rotated(&my_ips, &cands, 0).unwrap();
        let p1 = pick_public_endpoint_rotated(&my_ips, &cands, 1).unwrap();
        let p2 = pick_public_endpoint_rotated(&my_ips, &cands, 2).unwrap();
        assert_eq!(p0.ip().to_string(), "94.130.141.98");
        assert_eq!(p1.ip().to_string(), "94.130.141.74");
        assert_eq!(p2, p0, "offset wraps over the viable set");
        assert_eq!(Some(p0), pick_public_endpoint(&my_ips, &cands));
        assert_eq!(pick_public_endpoint_rotated(&my_ips, &[], 3), None);
    }

    #[test]
    fn srflx_punch_worth_trying_skips_only_both_symmetric() {
        // Skip ONLY when both ends are confidently symmetric.
        assert!(!srflx_punch_worth_trying(
            Some("symmetric"),
            Some("symmetric")
        ));
        // Any cone / unknown side → attempt.
        assert!(srflx_punch_worth_trying(Some("symmetric"), Some("cone")));
        assert!(srflx_punch_worth_trying(Some("cone"), Some("symmetric")));
        assert!(srflx_punch_worth_trying(Some("cone"), Some("cone")));
        assert!(srflx_punch_worth_trying(Some("symmetric"), None));
        assert!(srflx_punch_worth_trying(None, Some("symmetric")));
        assert!(srflx_punch_worth_trying(None, None));
    }
}
