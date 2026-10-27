// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! L3 TUN surface for the overlay (Phase 3).
//!
//! [`TunIo`] is the seam between the WireGuard bridge ([`super::bridge`])
//! and the OS virtual NIC. Production uses [`SystemTun`] (the `tun` crate
//! → Wintun on Windows, `/dev/net/tun` on Linux, utun on macOS), behind
//! the `overlay-l3` feature; tests use an in-memory mock, so the bridge
//! is exercised end-to-end with no kernel driver and no privilege.
//!
//! Routing note: a node brings the device up with its own overlay IP and
//! the *network* netmask (e.g. `100.64.0.3` / `255.192.0.0` for a `/10`),
//! which makes the whole overlay CIDR on-link via this interface — the OS
//! installs the connected route automatically on Linux + Windows, so
//! there is no explicit route-table call here. Per-peer reachability is
//! still exact-match `/32` in [`super::router::Router`]; a packet to an
//! overlay address with no installed peer is dropped by
//! [`super::wg::WgDevice::send_ip_packet`]. (macOS utun is point-to-point
//! and may need an explicit `route add` for the CIDR — refined when 3b/3c
//! field-test there.)
//!
//! Dual-stack: the device also carries the node's *derived* overlay IPv6
//! ([`super::router::derive_overlay_v6`]) on the ULA `/96`, assigned
//! best-effort at bring-up — the connected `/96` route makes every peer's
//! derived v6 on-link, and the WG bridge routes those packets by unmapping
//! the ULA destination to its embedded v4 (no v6 route table anywhere).

use async_trait::async_trait;

/// One IP packet in / one IP packet out. Implemented by [`SystemTun`]
/// (real device, `overlay-l3`) and, in tests, an in-memory mock — so
/// [`super::bridge::run_bridge`] is agnostic to the underlying NIC.
#[async_trait]
pub trait TunIo: Send + Sync {
    /// Read the next IP packet from the device. Blocks until one is
    /// available; `Err` means the device is gone and the bridge's
    /// outbound loop should exit.
    async fn read_packet(&self) -> std::io::Result<Vec<u8>>;

    /// Write one IP packet to the device.
    async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()>;

    /// Read the IP packets of the next device read, appended to `out` (at
    /// least one). A Linux offload device (`overlay::tun_offload`) returns
    /// every segment of a TSO super-packet from one read; the default is one
    /// [`read_packet`](Self::read_packet).
    async fn read_packets(&self, out: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
        out.push(self.read_packet().await?);
        Ok(())
    }

    /// Write a burst of IP packets in order, draining `packets`. A Linux
    /// offload device coalesces TCP runs into super-packets first; the
    /// default writes each with [`write_packet`](Self::write_packet).
    async fn write_packets(&self, packets: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
        for p in packets.drain(..) {
            self.write_packet(&p).await?;
        }
        Ok(())
    }

    /// The OS interface name backing this device, when it has one (SystemTun);
    /// `None` for mocks/netstack. Multi-org v2: per-adapter consumers (subnet-
    /// router NAT) must name THIS device, not the historical singleton.
    fn os_name(&self) -> Option<String> {
        None
    }

    /// Install a host (`/32`) route for a peer's overlay IP via this device,
    /// so overlay traffic out-specifics any colliding *less*-specific route on
    /// the host's uplink — e.g. an ISP/corp **CGNAT `100.64.0.0/10`** that
    /// otherwise swallows the packets. The connected-CIDR route alone is not
    /// enough on such a host (field bug 2026-06-10: WINHOST-A's pings to peers
    /// leaked to its carrier's CGNAT until a manual `/32` was added). Default
    /// no-op (the in-memory mock + platforms where the connected route is
    /// sufficient). **Best-effort:** a failure is logged by the caller, not
    /// fatal — direct/clean hosts route fine via the `/10` regardless.
    async fn add_peer_route(&self, _peer: std::net::Ipv4Addr) -> std::io::Result<()> {
        Ok(())
    }

    /// Remove the `/32` installed by [`add_peer_route`] (the peer left the
    /// mesh). Best-effort; never fails the caller.
    async fn del_peer_route(&self, _peer: std::net::Ipv4Addr) {}

    /// rc.278 — evict any FOREIGN `/32` for **our own** overlay address.
    ///
    /// [`add_peer_route`] has evicted VPN-installed competing `/32`s for every
    /// PEER since rc.208, but our own address was never defended — and a
    /// full-tunnel VPN installs a `/32` for it too. Field (winhost-a, Check Point
    /// Endpoint, 2026-07-31):
    ///
    /// ```text
    /// 100.64.0.28/32  ifIndex 46 (roomler)      0.0.0.0          metric 256
    /// 100.64.0.28/32  ifIndex 17 (Check Point)  172.30.226.132   metric 1   ← WINS
    /// ```
    ///
    /// Ours is only Windows' auto-generated on-link entry (metric 256) derived
    /// from the interface address, so the VPN's metric-1 `/32` out-ranks it at
    /// equal prefix length. Every packet destined to our own overlay IP — i.e.
    /// **the reply to everything we initiate**, plus every inbound packet — is
    /// then FORWARDED INTO THE CORP TUNNEL instead of delivered locally. The
    /// host looks totally dead on IPv4 (100 % loss both directions) while its
    /// WireGuard carriers are perfectly healthy and IPv6 works fine, which is
    /// exactly how it evaded six wrong diagnoses. Deleting that one route
    /// restored connectivity instantly with the VPN still connected.
    ///
    /// Eviction ONLY — we deliberately do NOT add our own `/32`: the on-link
    /// route Windows derives from the interface address already serves local
    /// delivery once the competitor is gone (field-proven), and installing a
    /// route to our own address via the TUN risks a forwarding loop.
    /// Best-effort, idempotent, called from the route guard + route-change
    /// events, so a VPN that re-adds its `/32` loses it again within ~2 s.
    async fn defend_self_route(&self, _self_ip: std::net::Ipv4Addr) {}

    /// Phase 1 — install an OS route for a subnet `cidr` (e.g. `"192.168.1.0/24"`)
    /// via this device, so LAN behind a router-peer is reachable over the
    /// overlay. Default no-op; best-effort.
    async fn add_cidr_route(&self, _cidr: &str) -> std::io::Result<()> {
        Ok(())
    }

    /// Remove a CIDR route installed by [`add_cidr_route`]. Best-effort.
    async fn del_cidr_route(&self, _cidr: &str) {}

    /// Change B (corp-gateway leak) — maintain the BLOCK-FLOOR routes: the
    /// four `plen+2` sub-prefixes of the connected overlay block, installed
    /// via this device. A full-tunnel VPN that claims a LONGER prefix than the
    /// block (Check Point installs `100.64.0.0/11` at metric 1) out-specifics
    /// both the connected `/10` and the rc.288 metric-0 defense — longest
    /// prefix wins BEFORE metric — so whenever a peer's `/32` is momentarily
    /// absent (netmap churn, carrier rebuild), packets for it leak to the
    /// CORP GATEWAY (field 2026-08-08, winhost-a: `Antwort von 10.16.6.34:
    /// Zielhost nicht erreichbar`). The `/12` floors out-specific the `/11`,
    /// so absent-`/32` traffic drops locally at the TUN instead.
    ///
    /// ⚠️ WITHHELD (and actively retracted) when the host's own uplink lives
    /// inside the block: some ISPs assign CGNAT (`100.64.0.0/10`) WAN
    /// addresses, and claiming the block there can blackhole the host's own
    /// internet — the self-wedge the per-peer-`/32` design exists to avoid.
    /// The gate fails toward WITHHOLD (an unreadable interface table installs
    /// nothing). Default no-op (mock, netstack, platforms without the
    /// route-war doctrine).
    async fn defend_block_floor(&self) {}

    /// Multi-org twin of [`defend_block_floor`](Self::defend_block_floor) —
    /// maintain the floors of the GIVEN block instead of the device's own
    /// connected block. Historically the shared-TUN mux ports forwarded here with
    /// ITS org's block: the shared device's connected block is the CREATOR
    /// org's only, so the plain method would floor one org's block and
    /// silently skip every sibling's. Default no-op, like the plain method.
    async fn defend_block_floor_of(&self, _net: std::net::Ipv4Addr, _plen: u8) {}

    /// corplap route war v3 (#23) — verify the overlay actually WINS the OS
    /// forwarding decision for each installed peer, and re-assert the
    /// tie-breaking interface metric if it doesn't.
    ///
    /// The route war's decisive lever is the adapter's INTERFACE metric (see
    /// the pin in `SystemTun::up_with`): a corp endpoint manager mirrors our
    /// prefixes at equal route metric on an equally-pinned interface, so
    /// eviction alone only ever produced a tie that Windows broke by lower
    /// ifIndex — the VPN's — and the per-destination pick is sticky, which is
    /// how peers stayed captured across restarts (corplap, 2026-08-18/19). With
    /// the metric pinned to 0 our rows win outright, so this step is the
    /// CHECK rather than the fight: ask the FIB which interface it would use
    /// per peer, and if any answer is foreign, re-pin the metric (a network
    /// profile change or an adapter reset can revert it) and log what the
    /// competitor is doing. Purely diagnostic when everything is healthy.
    /// Default no-op (mock, netstack, non-Windows).
    async fn verify_peer_path_ownership(&self, _peers: &[std::net::Ipv4Addr]) {}

    /// P5 exit-node — install a `/32` (host) **exemption** route for `ip` via the
    /// host's ORIGINAL default gateway (captured at TUN bring-up), NOT via this
    /// overlay device. When an exit-node client installs the split-default
    /// (`0.0.0.0/1` + `128.0.0.0/1`) via the overlay, these longer-prefix `/32`s
    /// keep the carrier-critical endpoints — the coordination server, the coturn
    /// relay, and the exit peer's own WG endpoint — flowing over the real uplink,
    /// so the default capture can never sever the very tunnel that carries it.
    /// Best-effort; a failure is surfaced by the split-tunnel check.
    ///
    /// ⚠️ The default `Ok(())` reads as "pinned", so it is safe ONLY for a
    /// device that installs no OS routes: the in-memory mock, and netstack,
    /// whose exit "routes" live in WireGuard's allowed-ips alone, out of the
    /// carrier sockets' path. A device whose [`add_cidr_route`](Self::add_cidr_route)
    /// reaches the kernel MUST override this and return `Err` where it cannot
    /// pin, or the exit gate installs the split-default with nothing exempted
    /// and the host wedges itself (#2081: macOS inherited this default).
    async fn add_host_exemption(&self, _ip: std::net::IpAddr) -> std::io::Result<()> {
        Ok(())
    }

    /// Remove a `/32` exemption installed by [`add_host_exemption`]. Best-effort.
    async fn del_host_exemption(&self, _ip: std::net::IpAddr) {}

    /// FR-97 P1a — which of `pinned` (exemptions this device reported pinned)
    /// no longer hold: the uplink they were pinned through has moved (Wi-Fi ↔
    /// Ethernet, a new network) or the route is gone or repointed. The exit
    /// gate re-pins each one through [`add_host_exemption`](Self::add_host_exemption),
    /// which also re-reads the uplink, and removes any it cannot re-pin: a
    /// host route left on a next hop that no longer answers black-holes the
    /// endpoint it was pinned for, the coordination server among them.
    ///
    /// Default: none. Right for the devices that install no OS routes (mocks,
    /// netstack). Every `SystemTun` arm overrides it: macOS since P1a, Linux
    /// and Windows since FR-97 P0e (N12), which re-read the uplink the same
    /// way instead of pinning through the one captured at bring-up forever.
    async fn stale_host_exemptions(&self, _pinned: &[std::net::IpAddr]) -> Vec<std::net::IpAddr> {
        Vec::new()
    }
}

/// Change B — the four block-floor CIDRs for a connected block `net/plen`:
/// its `plen+2` sub-prefixes (a `/10` → four `/12`s). Two bits longer beats
/// any VPN claim of `plen+1` (the observed Check Point `/11`) by longest
/// prefix while staying a fixed, tiny set. `None` when the block can't be
/// floored (`plen` 0 or > 30). Pure — unit-tested against the real overlay
/// block.
#[cfg(any(windows, test))]
pub(crate) fn floor_cidrs(net: std::net::Ipv4Addr, plen: u8) -> Option<[String; 4]> {
    if plen == 0 || plen > 30 {
        return None;
    }
    let base = u32::from(net) & (u32::MAX << (32 - plen));
    let step = 1u32 << (32 - plen - 2);
    Some(std::array::from_fn(|i| {
        format!(
            "{}/{}",
            std::net::Ipv4Addr::from(base + i as u32 * step),
            plen + 2
        )
    }))
}

/// Change B — may the block floor be installed? `false` (WITHHOLD) when any
/// non-overlay interface address OR the original default gateway sits inside
/// the block — the ISP-CGNAT-uplink case where claiming the block would
/// blackhole the host's own internet. Pure; the caller supplies the gathered
/// addresses and fails toward withhold when it cannot gather.
#[cfg(any(windows, test))]
pub(crate) fn floor_safe(
    non_overlay_v4: &[std::net::Ipv4Addr],
    orig_gateway_v4: Option<std::net::Ipv4Addr>,
    block: (std::net::Ipv4Addr, u8),
) -> bool {
    let (net, plen) = block;
    if plen == 0 {
        return false;
    }
    let mask = u32::MAX << (32 - plen);
    let net = u32::from(net) & mask;
    let inside = |ip: std::net::Ipv4Addr| (u32::from(ip) & mask) == net;
    !non_overlay_v4.iter().copied().any(inside) && !orig_gateway_v4.is_some_and(inside)
}

/// macOS — one `route -n get` answer, reduced to the fields a re-assert or the
/// uplink decides on. BSD `route` prints `key: value` lines; a host route has
/// no `mask:` line, a lookup that fell through prints the COVERING route
/// (`destination: default`), and one that matched nothing at all prints no
/// `destination:` (`not in table`) ⇒ `None`.
///
/// ⚠️ A lookup is never the read-back of an exemption pin: it can answer with
/// a scoped clone instead (see [`BsdTableRow`]).
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BsdRouteGet {
    pub(crate) destination: String,
    pub(crate) mask: Option<String>,
    /// As printed: an address, a link-local v6 with its `%zone`, or `link#N`
    /// for a route with no next hop.
    pub(crate) gateway: Option<String>,
    pub(crate) interface: Option<String>,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_bsd_route_get(out: &str) -> Option<BsdRouteGet> {
    let mut got = BsdRouteGet::default();
    let mut destination = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("destination:") {
            destination = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("mask:") {
            got.mask = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("gateway:") {
            got.gateway = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("interface:") {
            got.interface = Some(v.trim().to_string());
        }
    }
    destination.map(|destination| BsdRouteGet { destination, ..got })
}

/// FR-97 P1a — the uplink a macOS carrier exemption is pinned through: the
/// next hop and interface of one address family's default route.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BsdUplink {
    /// The next hop, zone stripped, for comparing with a read-back.
    pub(crate) gateway: std::net::IpAddr,
    /// The next hop as route(8) printed it, and as `route add` takes it back:
    /// a link-local v6 gateway keeps its `%en0` zone, without which the
    /// kernel cannot tell which link it is on.
    pub(crate) gateway_arg: String,
    pub(crate) interface: String,
}

/// An address as route(8) prints one: `default` for ANY all-zeros address
/// (whatever its mask), and a link-local v6 with its `%zone`. `None` for
/// what is not an address of the wanted family (`link#14`, an interface
/// name, a v4 answer to a v6 question).
#[cfg(any(target_os = "macos", test))]
fn bsd_addr(s: &str, v6: bool) -> Option<std::net::IpAddr> {
    let s = s.trim();
    let addr = if s == "default" {
        if v6 {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        } else {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        }
    } else {
        s.split('%').next()?.parse().ok()?
    };
    (addr.is_ipv6() == v6).then_some(addr)
}

/// FR-97 P1a — the uplink a `route -n get [-inet6] default` answer names.
///
/// `None`, so that family's exemptions are refused and its exit egress is
/// withheld, for: no answer; a route narrower than `/0` (a `/1` prints
/// `destination: default` too, and only its mask gives it away); a route on
/// `overlay_if`, because nothing is ever exempted through ourselves; and a
/// default with no next-hop address (the interface route a PPP link or
/// another VPN's utun installs), which `route add -host <ip> <gateway>`
/// cannot express.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn bsd_default_uplink(
    got: Option<&BsdRouteGet>,
    v6: bool,
    overlay_if: &str,
) -> Option<BsdUplink> {
    let got = got?;
    if !bsd_addr(&got.destination, v6)?.is_unspecified() {
        return None;
    }
    // The field Mac prints `mask: default`. A mask that parses to anything
    // but zero belongs to a narrower route that merely starts at zero.
    if let Some(mask) = got.mask.as_deref().and_then(|m| bsd_addr(m, v6))
        && !mask.is_unspecified()
    {
        return None;
    }
    let interface = got
        .interface
        .clone()
        .filter(|i| !i.is_empty() && i != overlay_if)?;
    let gateway_arg = got.gateway.clone()?;
    let gateway = bsd_addr(&gateway_arg, v6).filter(|g| !g.is_unspecified())?;
    Some(BsdUplink {
        gateway,
        gateway_arg,
        interface,
    })
}

/// FR-97 P1a — one row of `netstat -rnW -f inet[6]`: the routing TABLE, not a
/// lookup.
///
/// ⚠️ A pin is read from the table because a lookup does not show it. Once a
/// connection has gone out through the default route, the kernel keeps an
/// interface-scoped clone for its destination (`WASCLONED,IFSCOPE`), and an
/// unscoped `route -n get` answers with that clone even after an unscoped
/// static host route for the same address went in: the lookup prefers a
/// route scoped to the primary interface over an unscoped one of the same
/// length. Field, a tart Mac on 0.4.133, 2026-10-13: `route -n add -host`
/// returned 0 and `netstat` listed the pin (`UGHS en0`), while `route -n get`
/// still answered `WASCLONED,IFSCOPE`. Read back by lookup, every pin for the
/// coordination server, whose WebSocket always holds such a clone, was
/// refused, and each refused pin stayed in the table untracked. `route
/// change` resolves its target the same way and left the pin as it was.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BsdTableRow {
    pub(crate) destination: String,
    pub(crate) gateway: String,
    pub(crate) flags: String,
    pub(crate) netif: String,
}

/// Parse `netstat -rnW -f inet[6]`: four columns per route (destination,
/// gateway, flags, netif; an expiry may follow). Section titles, the header
/// row and anything shorter are skipped.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_bsd_netstat(out: &str) -> Vec<BsdTableRow> {
    out.lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let (destination, gateway, flags, netif) =
                (cols.next()?, cols.next()?, cols.next()?, cols.next()?);
            if destination == "Destination" || !flags.chars().all(|c| c.is_ascii_alphanumeric()) {
                return None;
            }
            Some(BsdTableRow {
                destination: destination.into(),
                gateway: gateway.into(),
                flags: flags.into(),
                netif: netif.into(),
            })
        })
        .collect()
}

/// FR-97 P1a — the pin this device keeps for `ip`: the UNSCOPED static host
/// route for exactly that address. Never a clone (`W`) or a scoped route
/// (`I`), which the kernel makes on its own. A clone shows the same gateway
/// and interface as a pin, but it expires, and the one replacing it comes from
/// whatever covers the address by then: our `/1`, under an exit.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn bsd_pin_row(rows: &[BsdTableRow], ip: std::net::IpAddr) -> Option<&BsdTableRow> {
    rows.iter().find(|r| {
        bsd_addr(&r.destination, ip.is_ipv6()) == Some(ip)
            && r.flags.contains('H')
            && r.flags.contains('S')
            && !r.flags.contains('W')
            && !r.flags.contains('I')
    })
}

/// FR-97 P1a — does that pin go through `uplink`: flagged as a gateway route,
/// through the uplink's next hop, on its interface?
#[cfg(any(target_os = "macos", test))]
pub(crate) fn bsd_pin_holds(row: Option<&BsdTableRow>, uplink: &BsdUplink) -> bool {
    row.is_some_and(|r| {
        r.flags.contains('G')
            && bsd_addr(&r.gateway, uplink.gateway.is_ipv6()) == Some(uplink.gateway)
            && r.netif == uplink.interface
    })
}

/// FR-97 P0e (N12) — an uplink as the Linux and Windows pin code compares it:
/// the interface (Linux `dev`, Windows ifIndex) and the next hop.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UplinkKey {
    pub(crate) interface: String,
    pub(crate) gateway: std::net::IpAddr,
}

/// FR-97 P0e (N12) — the Linux and Windows sweep of the pins, as a pure
/// decision; the macOS arm of `stale_host_exemptions` makes the same one from
/// its routing table. `held` is the uplink the pins were made through; `now`
/// the one the table shows at this moment, `None` when it shows no usable one
/// (the held one then stands: a network in transit is no reason to touch the
/// pins); `host_routes` every gateway host route in the table. Returns the
/// uplink to adopt, when it moved, and every pin the table does not show
/// through the uplink in force: through the old one after a network change,
/// or gone (an interface that went down takes its routes with it).
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(crate) fn stale_pins(
    pins: &[std::net::IpAddr],
    held: Option<&UplinkKey>,
    now: Option<&UplinkKey>,
    host_routes: &[(std::net::IpAddr, UplinkKey)],
) -> (Option<UplinkKey>, Vec<std::net::IpAddr>) {
    let adopt = now.filter(|n| held != Some(*n)).cloned();
    let in_force = now.or(held);
    let stale = pins
        .iter()
        .copied()
        .filter(|ip| {
            !in_force.is_some_and(|u| host_routes.iter().any(|(d, via)| d == ip && via == u))
        })
        .collect();
    (adopt, stale)
}

/// FR-97 P0e (N12) — the gateway host routes in `ip -4|-6 route show`: the
/// lines whose destination is a bare address (iproute2 prints a `/32` or a
/// `/128` without its length) and that carry a `via` and a `dev`. Pure.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_linux_host_routes(output: &str) -> Vec<(std::net::IpAddr, UplinkKey)> {
    output
        .lines()
        .filter_map(|line| {
            let toks: Vec<&str> = line.split_whitespace().collect();
            let dest: std::net::IpAddr = toks.first()?.parse().ok()?;
            let after = |key: &str| {
                toks.iter()
                    .position(|t| *t == key)
                    .and_then(|i| toks.get(i + 1).copied())
            };
            let gateway: std::net::IpAddr = after("via")?.parse().ok()?;
            let interface = after("dev")?.to_string();
            Some((dest, UplinkKey { interface, gateway }))
        })
        .collect()
}

/// Is the route a `route -n get` for `dest/plen` matched EXACTLY our route on
/// `if_name` — same destination, same prefix length, same interface?
///
/// #1856 — BSD `route` has no idempotent write: re-asserting a route meant
/// delete-then-add, two processes apart, and the guard did that for every
/// peer on every wave. Between the two the `/32` does not exist, and a socket
/// BOUND to the overlay address (WebRTC's host candidate on the utun) gets
/// `EHOSTUNREACH` from macOS's interface-scoped route lookup instead of
/// falling through to the default route. Measured on the MacBook (0.4.117):
/// a 2.5–3.0 ms hole in every peer's route every 3 s — and each hole's
/// RTM_DELETE/RTM_ADD fed `route -n monitor`, which armed the next wave.
/// Remote-desktop sessions riding the overlay died a few seconds in, over and
/// over. Skipping a route that is already ours is what Linux's
/// `ip route replace` and Windows' `winroute::ensure` already do.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn bsd_route_is_ours(
    got: Option<&BsdRouteGet>,
    dest: std::net::IpAddr,
    plen: u8,
    if_name: &str,
) -> bool {
    let Some(got) = got else {
        return false;
    };
    // route(8) prints ANY all-zeros address as `default`, whatever its mask:
    // the exit split-default half `0.0.0.0/1` reads back as `destination:
    // default` with `mask: 128.0.0.0`, and the real default route as
    // `default` / `default`. Only the mask tells them apart.
    let unspecified = if dest.is_ipv4() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let addr = |s: &str| {
        if s == "default" {
            Some(unspecified)
        } else {
            s.parse::<std::net::IpAddr>().ok()
        }
    };
    if addr(&got.destination) != Some(dest) {
        return false;
    }
    let host_plen = if dest.is_ipv4() { 32 } else { 128 };
    let got_plen = match got.mask.as_deref() {
        // `route -n get` prints no mask for a host route.
        None => Some(host_plen),
        Some(m) => addr(m)
            .filter(|m| m.is_ipv4() == dest.is_ipv4())
            .and_then(mask_plen),
    };
    got_plen == Some(plen) && got.interface.as_deref() == Some(if_name)
}

/// The prefix length of a contiguous netmask; `None` for a non-contiguous one.
#[cfg(any(target_os = "macos", test))]
fn mask_plen(mask: std::net::IpAddr) -> Option<u8> {
    let (ones, total) = match mask {
        std::net::IpAddr::V4(m) => {
            let bits = u32::from(m);
            (bits.leading_ones(), bits.count_ones())
        }
        std::net::IpAddr::V6(m) => {
            let bits = u128::from(m);
            (bits.leading_ones(), bits.count_ones())
        }
    };
    (ones == total).then_some(ones as u8)
}

#[cfg(test)]
mod uplink_pin_tests {
    use super::{UplinkKey, parse_linux_host_routes, stale_pins};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn via(interface: &str, gateway: &str) -> UplinkKey {
        UplinkKey {
            interface: interface.into(),
            gateway: ip(gateway),
        }
    }

    /// The table as `ip -4 route show` prints it on a client under an exit:
    /// the physical default, our `/1`s, two pins and an on-link LAN route.
    const LINUX_V4: &str = "\
default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.5 metric 600
0.0.0.0/1 dev roomler scope link
94.130.141.98 via 192.168.1.1 dev wlan0
5.9.157.226 via 192.168.1.1 dev wlan0 onlink
128.0.0.0/1 dev roomler scope link
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.5 metric 600
";

    #[test]
    fn host_routes_are_the_bare_addresses_with_a_next_hop() {
        assert_eq!(
            parse_linux_host_routes(LINUX_V4),
            vec![
                (ip("94.130.141.98"), via("wlan0", "192.168.1.1")),
                (ip("5.9.157.226"), via("wlan0", "192.168.1.1")),
            ]
        );
        let v6 = "2a01:4f8::1 via fe80::1 dev eth0 metric 1024 pref medium\n\
                  default via fe80::1 dev eth0 proto ra metric 100 pref medium\n";
        assert_eq!(
            parse_linux_host_routes(v6),
            vec![(ip("2a01:4f8::1"), via("eth0", "fe80::1"))]
        );
    }

    #[test]
    fn pins_through_the_uplink_in_force_hold() {
        let pins = [ip("94.130.141.98"), ip("5.9.157.226")];
        let wifi = via("wlan0", "192.168.1.1");
        let routes = parse_linux_host_routes(LINUX_V4);
        assert_eq!(
            stale_pins(&pins, Some(&wifi), Some(&wifi), &routes),
            (None, vec![])
        );
    }

    /// N12 — Wi-Fi to Ethernet under an active exit: every pin still goes
    /// through the old next hop, so every pin is stale and the new uplink is
    /// adopted for the re-pin.
    #[test]
    fn a_moved_uplink_makes_every_pin_through_the_old_one_stale() {
        let pins = [ip("94.130.141.98"), ip("5.9.157.226")];
        let wifi = via("wlan0", "192.168.1.1");
        let eth = via("eth0", "10.0.0.1");
        let routes = parse_linux_host_routes(LINUX_V4);
        assert_eq!(
            stale_pins(&pins, Some(&wifi), Some(&eth), &routes),
            (Some(eth), pins.to_vec())
        );
    }

    /// The same network back after a drop: the uplink did not move, but the
    /// interface took its routes with it when it went down.
    #[test]
    fn a_pin_gone_from_the_table_is_stale_on_the_same_uplink() {
        let pins = [ip("94.130.141.98"), ip("203.0.113.9")];
        let wifi = via("wlan0", "192.168.1.1");
        let routes = parse_linux_host_routes(LINUX_V4);
        assert_eq!(
            stale_pins(&pins, Some(&wifi), Some(&wifi), &routes),
            (None, vec![ip("203.0.113.9")])
        );
    }

    /// No usable default at this moment (a network in transit): nothing is
    /// adopted, and the pins are judged against the held uplink.
    #[test]
    fn no_uplink_now_keeps_the_held_one() {
        let pins = [ip("94.130.141.98")];
        let wifi = via("wlan0", "192.168.1.1");
        let routes = parse_linux_host_routes(LINUX_V4);
        assert_eq!(
            stale_pins(&pins, Some(&wifi), None, &routes),
            (None, vec![])
        );
        assert_eq!(
            stale_pins(&pins, Some(&wifi), None, &[]),
            (None, pins.to_vec())
        );
        assert_eq!(
            stale_pins(&pins, None, None, &routes),
            (None, pins.to_vec())
        );
    }
}

#[cfg(test)]
mod bsd_route_tests {
    use super::{
        BsdRouteGet, BsdUplink, bsd_default_uplink, bsd_pin_holds, bsd_pin_row, bsd_route_is_ours,
        parse_bsd_netstat, parse_bsd_route_get,
    };
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The answers below are verbatim `route -n get` output from the field
    /// MacBook (macOS 27.0.1), recvpipe table omitted.
    const OURS_HOST: &str = "   route to: 100.65.4.2
destination: 100.65.4.2
  interface: utun0
      flags: <UP,HOST,DONE,STATIC>
";
    const FELL_TO_DEFAULT: &str = "   route to: 100.65.4.99
destination: default
       mask: default
    gateway: 192.168.8.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
";
    const LAN_NET: &str = "   route to: 192.168.8.0
destination: 192.168.8.0
       mask: 255.255.255.0
  interface: en0
      flags: <UP,DONE,CLONING,STATIC>
";
    const OURS_V6_NET: &str = "   route to: fd72:6f6f:6d6c::6441:400
destination: fd72:6f6f:6d6c::6441:400
       mask: ffff:ffff:ffff:ffff:ffff:ffff:ffff:fc00
  interface: utun0
      flags: <UP,DONE,PRCLONING>
";

    #[test]
    fn parses_host_net_and_not_in_table() {
        assert_eq!(
            parse_bsd_route_get(OURS_HOST),
            Some(BsdRouteGet {
                destination: "100.65.4.2".into(),
                mask: None,
                gateway: None,
                interface: Some("utun0".into()),
            })
        );
        let lan = parse_bsd_route_get(LAN_NET).unwrap();
        assert_eq!(lan.mask.as_deref(), Some("255.255.255.0"));
        assert_eq!(lan.interface.as_deref(), Some("en0"));
        // `route: writing to routing socket: not in table` goes to stderr;
        // stdout is empty.
        assert_eq!(parse_bsd_route_get(""), None);
    }

    /// The case the fix exists for: our `/32` already on our utun ⇒ leave it
    /// alone. Every other shape must still be (re-)installed.
    #[test]
    fn only_our_exact_route_is_left_alone() {
        let ours = parse_bsd_route_get(OURS_HOST);
        assert!(bsd_route_is_ours(
            ours.as_ref(),
            ip("100.65.4.2"),
            32,
            "utun0"
        ));
        // Same /32 on ANOTHER interface — a competing VPN route, or our own
        // from a utun the daemon has since replaced.
        assert!(!bsd_route_is_ours(
            ours.as_ref(),
            ip("100.65.4.2"),
            32,
            "utun5"
        ));
        // The lookup for an absent peer falls through to the default route.
        let fell = parse_bsd_route_get(FELL_TO_DEFAULT);
        assert!(!bsd_route_is_ours(
            fell.as_ref(),
            ip("100.65.4.99"),
            32,
            "utun0"
        ));
        // Nothing matched at all.
        assert!(!bsd_route_is_ours(None, ip("100.65.4.99"), 32, "utun0"));
    }

    #[test]
    fn net_routes_compare_destination_and_prefix_length() {
        let v6 = parse_bsd_route_get(OURS_V6_NET);
        let net = ip("fd72:6f6f:6d6c::6441:400");
        assert!(bsd_route_is_ours(v6.as_ref(), net, 118, "utun0"));
        // A covering route with the same network address is not this prefix.
        assert!(!bsd_route_is_ours(v6.as_ref(), net, 96, "utun0"));
        let lan = parse_bsd_route_get(LAN_NET);
        assert!(bsd_route_is_ours(
            lan.as_ref(),
            ip("192.168.8.0"),
            24,
            "en0"
        ));
        assert!(!bsd_route_is_ours(
            lan.as_ref(),
            ip("192.168.8.0"),
            16,
            "en0"
        ));
        // A host route is not our net route of the same address.
        let host = parse_bsd_route_get(OURS_HOST);
        assert!(!bsd_route_is_ours(
            host.as_ref(),
            ip("100.65.4.2"),
            24,
            "utun0"
        ));
        // A garbage or non-contiguous mask never reads as ours.
        let odd = BsdRouteGet {
            destination: "10.66.0.0".into(),
            mask: Some("255.0.255.0".into()),
            interface: Some("utun0".into()),
            ..Default::default()
        };
        assert!(!bsd_route_is_ours(Some(&odd), ip("10.66.0.0"), 16, "utun0"));
        // A /0 is never one of the /1 halves, however its address prints.
        let zero_net = BsdRouteGet {
            destination: "0.0.0.0".into(),
            mask: Some("0.0.0.0".into()),
            interface: Some("utun0".into()),
            ..Default::default()
        };
        assert!(!bsd_route_is_ours(
            Some(&zero_net),
            ip("0.0.0.0"),
            1,
            "utun0"
        ));
    }

    /// The exit split-default halves. route(8) prints any all-zeros address
    /// as `default`, so `0.0.0.0/1` and `::/1` read back with
    /// `destination: default`, and only the mask separates them from the
    /// real default route (`mask: default`, verbatim from the field Mac when
    /// no `/1` is installed).
    #[test]
    fn split_default_halves_read_back_as_default_with_a_mask() {
        let real_default = parse_bsd_route_get(FELL_TO_DEFAULT);
        assert!(!bsd_route_is_ours(
            real_default.as_ref(),
            ip("0.0.0.0"),
            1,
            "utun0"
        ));
        // …and that answer IS the default route, /0, on en0.
        assert!(bsd_route_is_ours(
            real_default.as_ref(),
            ip("0.0.0.0"),
            0,
            "en0"
        ));

        let our_low_half = BsdRouteGet {
            destination: "default".into(),
            mask: Some("128.0.0.0".into()),
            interface: Some("utun0".into()),
            ..Default::default()
        };
        assert!(bsd_route_is_ours(
            Some(&our_low_half),
            ip("0.0.0.0"),
            1,
            "utun0"
        ));
        let our_high_half = BsdRouteGet {
            destination: "128.0.0.0".into(),
            mask: Some("128.0.0.0".into()),
            interface: Some("utun0".into()),
            ..Default::default()
        };
        assert!(bsd_route_is_ours(
            Some(&our_high_half),
            ip("128.0.0.0"),
            1,
            "utun0"
        ));
        let our_v6_low_half = BsdRouteGet {
            destination: "default".into(),
            mask: Some("8000::".into()),
            interface: Some("utun0".into()),
            ..Default::default()
        };
        assert!(bsd_route_is_ours(
            Some(&our_v6_low_half),
            ip("::"),
            1,
            "utun0"
        ));
        // A v4 `default` never satisfies a v6 prefix, and vice versa.
        assert!(!bsd_route_is_ours(
            Some(&our_low_half),
            ip("::"),
            1,
            "utun0"
        ));
    }

    fn uplink(gateway: &str, interface: &str) -> BsdUplink {
        BsdUplink {
            gateway: ip(gateway.split('%').next().unwrap()),
            gateway_arg: gateway.into(),
            interface: interface.into(),
        }
    }

    /// FR-97 P1a — the uplink is read from the default route's answer, which
    /// has the shape of [`FELL_TO_DEFAULT`] (verbatim from the field Mac).
    #[test]
    fn the_default_route_names_the_uplink() {
        assert_eq!(
            bsd_default_uplink(
                parse_bsd_route_get(FELL_TO_DEFAULT).as_ref(),
                false,
                "utun4"
            ),
            Some(uplink("192.168.8.1", "en0"))
        );
        // v6: route(8) prints the unspecified destination as `::` or as
        // `default`, and a link-local next hop with its zone, which is kept
        // for `route add` and stripped for comparing.
        for dest in ["::", "default"] {
            let v6 = parse_bsd_route_get(&format!(
                "   route to: ::\ndestination: {dest}\n       mask: default\n    \
                 gateway: fe80::1%en0\n  interface: en0\n      \
                 flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n"
            ));
            assert_eq!(
                bsd_default_uplink(v6.as_ref(), true, "utun4"),
                Some(uplink("fe80::1%en0", "en0")),
                "{dest}"
            );
            // The same answer is no v4 uplink.
            assert_eq!(bsd_default_uplink(v6.as_ref(), false, "utun4"), None);
        }
        // Nothing matched: no default route at all.
        assert_eq!(bsd_default_uplink(None, false, "utun4"), None);
    }

    /// What must never become the uplink, because an exemption pinned
    /// through it would not leave the host the way the real default does.
    #[test]
    fn our_own_half_and_an_interface_route_are_not_an_uplink() {
        // Our own `/1`, should a lookup ever answer with it: `default` with a
        // non-zero mask, on our utun, with no next hop.
        let our_half = BsdRouteGet {
            destination: "default".into(),
            mask: Some("128.0.0.0".into()),
            interface: Some("utun4".into()),
            ..Default::default()
        };
        assert_eq!(bsd_default_uplink(Some(&our_half), false, "utun4"), None);
        // The mask alone rules it out, whatever interface it is on.
        let narrow = BsdRouteGet {
            interface: Some("en0".into()),
            gateway: Some("192.168.8.1".into()),
            ..our_half.clone()
        };
        assert_eq!(bsd_default_uplink(Some(&narrow), false, "utun4"), None);
        // A real default on our own utun.
        let on_us = BsdRouteGet {
            mask: Some("default".into()),
            gateway: Some("100.65.0.1".into()),
            ..our_half.clone()
        };
        assert_eq!(bsd_default_uplink(Some(&on_us), false, "utun4"), None);
        // Another VPN's interface route: no next-hop address to pin through.
        for gw in [None, Some("link#14".to_string()), Some("utun7".to_string())] {
            let iface_route = BsdRouteGet {
                destination: "default".into(),
                mask: Some("default".into()),
                gateway: gw.clone(),
                interface: Some("utun7".into()),
            };
            assert_eq!(
                bsd_default_uplink(Some(&iface_route), false, "utun4"),
                None,
                "{gw:?}"
            );
        }
    }

    /// `netstat -rnW -f inet`. The pin row is verbatim from the field (a tart
    /// Mac on 0.4.133, after `route -n add -host`); the others are
    /// constructed in netstat's format, one per shape the table can hold for
    /// a pinned address.
    const TABLE_V4: &str = "Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.64.1       UGScg                 en0
94.130.141.98      192.168.64.1       UGHS                  en0
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
192.168.64         link#4             UCS                   en0      !
192.168.64.1       ae:7f:23:0:44:64   UHLWIir               en0   1186
203.0.113.8        192.168.64.1       UGHWIig               en0
203.0.113.9        192.168.64.1       UGHSI                 en0
203.0.113.10       127.0.0.1          UGHS                  lo0
203.0.113.11       link#1             UHS                   lo0
";

    const TABLE_V6: &str = "Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::1%en0                             UGcg                  en0
2a01:4f8::1                             fe80::1%en0                             UGHS                  en0
";

    #[test]
    fn the_table_parses_routes_and_skips_titles() {
        let rows = parse_bsd_netstat(TABLE_V4);
        assert_eq!(rows.len(), 10, "{rows:#?}");
        assert!(rows.iter().all(|r| r.destination != "Destination"));
        assert_eq!(rows[1].destination, "94.130.141.98");
        assert_eq!(rows[1].flags, "UGHS");
        assert!(parse_bsd_netstat("").is_empty());
    }

    /// FR-97 P1a — the pin is read from the table; see `BsdTableRow` for why a
    /// lookup cannot show it.
    #[test]
    fn the_pin_is_the_unscoped_static_host_route_through_the_uplink() {
        let rows = parse_bsd_netstat(TABLE_V4);
        let server = ip("94.130.141.98");
        let pin = bsd_pin_row(&rows, server);
        assert_eq!(pin.map(|r| r.netif.as_str()), Some("en0"));
        assert!(bsd_pin_holds(pin, &uplink("192.168.64.1", "en0")));
        // The uplink moved: a new next hop, or the same one on another NIC.
        assert!(!bsd_pin_holds(pin, &uplink("10.0.0.1", "en0")));
        assert!(!bsd_pin_holds(pin, &uplink("192.168.64.1", "en7")));
        assert!(!bsd_pin_holds(None, &uplink("192.168.64.1", "en0")));
        // v6, through a zoned link-local next hop.
        let rows6 = parse_bsd_netstat(TABLE_V6);
        assert!(bsd_pin_holds(
            bsd_pin_row(&rows6, ip("2a01:4f8::1")),
            &uplink("fe80::1%en0", "en0")
        ));
    }

    /// The kernel's own entries for an address are never the pin, so they
    /// never satisfy the read-back and are never deleted as one.
    #[test]
    fn a_clone_or_a_scoped_route_is_never_the_pin() {
        let rows = parse_bsd_netstat(TABLE_V4);
        assert_eq!(bsd_pin_row(&rows, ip("203.0.113.8")), None, "a clone (W)");
        assert_eq!(
            bsd_pin_row(&rows, ip("203.0.113.9")),
            None,
            "a scoped route (I)"
        );
        assert_eq!(
            bsd_pin_row(&rows, ip("203.0.113.99")),
            None,
            "no row at all"
        );
    }

    /// A pin through another next hop, or an interface route for the address,
    /// is found (so it can be replaced) and does not hold.
    #[test]
    fn a_pin_elsewhere_is_found_and_does_not_hold() {
        let rows = parse_bsd_netstat(TABLE_V4);
        let up = uplink("192.168.64.1", "en0");
        let stale = bsd_pin_row(&rows, ip("203.0.113.10"));
        assert!(stale.is_some());
        assert!(!bsd_pin_holds(stale, &up));
        let iface = bsd_pin_row(&rows, ip("203.0.113.11"));
        assert!(
            iface.is_some(),
            "an interface route is a static host route too"
        );
        assert!(
            !bsd_pin_holds(iface, &up),
            "with no gateway flag it is no pin"
        );
    }
}

#[cfg(test)]
mod floor_tests {
    use std::net::Ipv4Addr;

    use super::{floor_cidrs, floor_safe};

    const BLOCK: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 10);

    /// The real overlay block floors to exactly the four /12s that
    /// out-specific a corp `/11`, covering the /10 with no gap.
    #[test]
    fn floors_of_the_overlay_block() {
        let got = floor_cidrs(BLOCK.0, BLOCK.1).unwrap();
        assert_eq!(
            got,
            [
                "100.64.0.0/12".to_string(),
                "100.80.0.0/12".to_string(),
                "100.96.0.0/12".to_string(),
                "100.112.0.0/12".to_string(),
            ]
        );
        // Unfloorable blocks: /0 (nonsense) and /31 (can't add two bits).
        assert!(floor_cidrs(Ipv4Addr::UNSPECIFIED, 0).is_none());
        assert!(floor_cidrs(Ipv4Addr::new(10, 0, 0, 0), 31).is_none());
        // A host-bit-dirty net is normalized, not shifted.
        assert_eq!(
            floor_cidrs(Ipv4Addr::new(100, 64, 0, 28), 10).unwrap()[0],
            "100.64.0.0/12"
        );
        // A carved /22 floors to its four /24s — the multi-org case, where
        // each org's port forwards its OWN block.
        assert_eq!(
            floor_cidrs(Ipv4Addr::new(100, 65, 4, 0), 22).unwrap(),
            [
                "100.65.4.0/24".to_string(),
                "100.65.5.0/24".to_string(),
                "100.65.6.0/24".to_string(),
                "100.65.7.0/24".to_string(),
            ]
        );
    }

    /// The withhold gate: an ordinary uplink installs; a CGNAT WAN address or
    /// a CGNAT default gateway withholds; boundary addresses are classified
    /// exactly.
    #[test]
    fn floor_gate_withholds_on_cgnat_uplink() {
        let lan = [Ipv4Addr::new(192, 168, 68, 5), Ipv4Addr::new(172, 30, 1, 2)];
        let gw = Some(Ipv4Addr::new(192, 168, 68, 1));
        assert!(floor_safe(&lan, gw, BLOCK));
        // An ISP CGNAT WAN address inside the block ⇒ withhold.
        let cgnat = [lan[0], Ipv4Addr::new(100, 91, 3, 7)];
        assert!(!floor_safe(&cgnat, gw, BLOCK));
        // A CGNAT default gateway alone ⇒ withhold.
        assert!(!floor_safe(
            &lan,
            Some(Ipv4Addr::new(100, 127, 255, 254)),
            BLOCK
        ));
        // Block boundaries: 100.63.255.255 is outside, 100.64.0.0 inside,
        // 100.127.255.255 inside, 100.128.0.0 outside.
        assert!(floor_safe(&[Ipv4Addr::new(100, 63, 255, 255)], None, BLOCK));
        assert!(!floor_safe(&[Ipv4Addr::new(100, 64, 0, 0)], None, BLOCK));
        assert!(!floor_safe(
            &[Ipv4Addr::new(100, 127, 255, 255)],
            None,
            BLOCK
        ));
        assert!(floor_safe(&[Ipv4Addr::new(100, 128, 0, 0)], None, BLOCK));
        // No gateway captured is NOT itself a reason to withhold.
        assert!(floor_safe(&lan, None, BLOCK));
    }
}

/// The LEGACY/PRIMARY overlay NIC name — what [`SystemTun::up`] has always
/// requested, and the fallback consumers use when a device cannot name
/// itself ([`TunIo::os_name`] → `None`: mocks, netstack). Multi-org v2
/// parameterizes every per-adapter code path on an instance name; this
/// const stays as the single-adapter identity and the historical default.
///
/// Lives at module top level (not inside the `overlay-l3`-gated `system`
/// module) because the runtime's NAT fallback needs it under plain
/// `overlay` too.
#[cfg(target_os = "windows")]
pub const IF_NAME: &str = "roomler";

#[cfg(target_os = "linux")]
pub const IF_NAME: &str = "roomler0";

/// macOS (and any other non-Windows/Linux platform) ignores a requested
/// name — utun numbers are kernel-assigned — so this is only the REQUESTED
/// name and a logging fallback. The real one comes from
/// `SystemTun::if_name()`. That macOS had no `IF_NAME` at all is the reason
/// its whole routing surface was a set of no-ops: there was nothing to
/// address, so nothing addressed anything.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub const IF_NAME: &str = "utun";

/// The real OS TUN device. Behind `overlay-l3` so the WG core + the
/// bridge logic stay device-free (and dependency-free) under plain
/// `overlay`.
#[cfg(feature = "overlay-l3")]
pub use system::{
    SystemTun, TunOptions, org_tun_guid, purge_pins, purge_split_default, purge_stale_peer_routes,
};
#[cfg(feature = "overlay-l3")]
pub(crate) use system::{is_own_ifref, uplink_beneath};

#[cfg(feature = "overlay-l3")]
mod system {
    use std::net::Ipv4Addr;
    // v6 exemptions + default-route discovery (S3b) are linux/windows-only.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    use std::net::Ipv6Addr;
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::{IF_NAME, TunIo};

    // rc.208 — `AsyncDevice::tun_luid` (the wintun interface LUID) for the
    // IP Helper route ops; also used by the WFP guard in `up()`.
    #[cfg(target_os = "windows")]
    use tun::AbstractDeviceExt as _;

    /// `(address, prefix_len)` from a `"addr/len"` CIDR string (v4 or v6).
    #[cfg(windows)]
    fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
        let (ip, len) = s.split_once('/')?;
        Some((ip.parse().ok()?, len.parse().ok()?))
    }

    #[cfg(all(test, windows))]
    mod winroute_tests {
        use super::parse_cidr;
        use std::net::IpAddr;

        #[test]
        fn parse_cidr_v4_v6_and_rejects_junk() {
            let ip = |s: &str| s.parse::<IpAddr>().unwrap();
            assert_eq!(parse_cidr("0.0.0.0/1"), Some((ip("0.0.0.0"), 1)));
            assert_eq!(parse_cidr("128.0.0.0/1"), Some((ip("128.0.0.0"), 1)));
            assert_eq!(parse_cidr("100.64.0.2/32"), Some((ip("100.64.0.2"), 32)));
            assert_eq!(parse_cidr("::/1"), Some((ip("::"), 1)));
            assert_eq!(parse_cidr("8000::/1"), Some((ip("8000::"), 1)));
            assert_eq!(parse_cidr("no-slash"), None);
            assert_eq!(parse_cidr("1.2.3.4/999"), None); // prefix > u8::MAX
            assert_eq!(parse_cidr("not-an-ip/8"), None);
        }
    }

    /// rc.208 — Windows overlay route ops via the IP Helper API instead of
    /// spawning `route.exe`/`netsh`. A netsh route add/delete costs ~0.3–2 s
    /// (process spawn + servicing), and firing 8 peers × delete-then-add every
    /// 2 s (the route-guard) periodically stalled the Windows overlay DATA plane
    /// for ~2 s — the field-observed ~1.8 s RTT (raw internet to the same host:
    /// ~40 ms). `CreateIpForwardEntry2` / `DeleteIpForwardEntry2` are in-memory
    /// FIB calls (~µs), so the stall disappears. Routes are on-link `/N`s on the
    /// wintun adapter (looked up by LUID via `AsyncDevice::tun_luid`).
    #[cfg(windows)]
    mod winroute {
        use std::net::{IpAddr, Ipv4Addr};
        use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
            DeleteIpForwardEntry2, FreeMibTable, GetIpForwardEntry2, GetIpForwardTable2,
            InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, SetIpForwardEntry2,
        };
        use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

        /// A zeroed `SOCKADDR_INET` carrying `ip`'s family + address only.
        /// `pub(super)`: [`winaddr`](super::winaddr) keys its rows the same way.
        pub(super) fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
            // SAFETY: SOCKADDR_INET is a POD union; zero it, then write the
            // active v4/v6 arm's family + address (the documented init pattern).
            unsafe {
                let mut sa: SOCKADDR_INET = std::mem::zeroed();
                match ip {
                    IpAddr::V4(v4) => {
                        sa.Ipv4.sin_family = AF_INET;
                        sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        sa.Ipv6.sin6_family = AF_INET6;
                        sa.Ipv6.sin6_addr.u.Byte = v6.octets();
                    }
                }
                sa
            }
        }

        /// A route row for `dest/plen` on `luid`, next-hop unspecified (on-link).
        fn make_row(luid: u64, dest: IpAddr, plen: u8, metric: u32) -> MIB_IPFORWARD_ROW2 {
            // SAFETY: InitializeIpForwardEntry fills a zeroed row with valid
            // defaults; we override the LUID / prefix / next-hop / metric.
            unsafe {
                let mut r: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
                InitializeIpForwardEntry(&mut r);
                r.InterfaceLuid = NET_LUID_LH { Value: luid };
                r.DestinationPrefix.Prefix = sockaddr(dest);
                r.DestinationPrefix.PrefixLength = plen;
                let mut nh: SOCKADDR_INET = std::mem::zeroed();
                nh.si_family = if dest.is_ipv4() { AF_INET } else { AF_INET6 };
                r.NextHop = nh;
                r.Metric = metric;
                r
            }
        }

        /// Add (idempotent) an on-link route `dest/plen` via `luid`.
        pub fn add(luid: u64, dest: IpAddr, plen: u8, metric: u32) -> std::io::Result<()> {
            let r = make_row(luid, dest, plen, metric);
            // SAFETY: `r` is a fully-initialised row; the API copies it.
            let rc = unsafe { CreateIpForwardEntry2(&r) };
            if rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(rc as i32))
            }
        }

        /// #1282 — is our `dest/plen` on `luid` installed at exactly `metric`?
        /// One in-memory `Get`, and unlike [`ensure`] no #1328 strike
        /// bookkeeping: a caller that re-asserts every wave uses it to skip a
        /// write that would change nothing, because every write is a
        /// route-change event the route guard reacts to.
        pub fn is_installed(luid: u64, dest: IpAddr, plen: u8, metric: u32) -> bool {
            let mut probe = make_row(luid, dest, plen, 0);
            // SAFETY: GetIpForwardEntry2 matches on LUID + prefix + next-hop
            // and fills the row on success.
            let rc = unsafe { GetIpForwardEntry2(&mut probe) };
            rc == NO_ERROR && probe.Metric == metric
        }

        /// Delete our `dest/plen` route on `luid` (best-effort — a missing route
        /// is fine).
        pub fn del(luid: u64, dest: IpAddr, plen: u8) {
            let r = make_row(luid, dest, plen, 0);
            // SAFETY: `r` carries the LUID + prefix the API matches on.
            unsafe { DeleteIpForwardEntry2(&r) };
        }

        /// rc.287 — add-or-RECONCILE our `dest/plen` on `luid` to `metric`.
        ///
        /// `add` alone can never CHANGE an existing row's metric —
        /// `CreateIpForwardEntry2` returns ALREADY_EXISTS and the old metric
        /// silently masks the new one (exactly the trap the rc.208 constancy
        /// comment predicted). Read the current row first; the steady state is
        /// one in-memory `Get` (~µs) with zero route churn.
        ///
        /// rc.288 — a metric mismatch is fixed **IN PLACE** via
        /// `SetIpForwardEntry2`, NOT delete-then-re-add. The delete opened a
        /// window with NO route for the prefix, and on a host whose corp VPN
        /// runs a route monitor that window is fatal: CORPLAP-3 (AnyConnect)
        /// came back from the rc.287 update with **no `/32` at all** for any
        /// peer — ours never got re-added and Cisco withdrew its mirrors once
        /// ours vanished — so every peer fell through to Cisco's captured
        /// `100.64.0.0/10`. In-place metric update never unroutes the prefix.
        /// Delete-then-add remains the fallback for the (unexpected) case
        /// where `Set` fails, and a failure to restore is WARNed rather than
        /// swallowed.
        /// rc.289 — latched once a metric-0 write has repeatedly failed to
        /// STICK (see [`note_absent`]): every later `ensure` silently
        /// downgrades to metric 1, the pre-rc.287 behaviour that a
        /// route-monitoring VPN tolerates.
        static METRIC0_REJECTED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);

        /// Per-prefix "we wrote it, it is gone again" state.
        ///
        /// #1328 — `n` alone was enough while the only remedy was the
        /// metric-0 downgrade. A metric-1 war has no lower metric to fall
        /// back to, so it also needs a STAND-DOWN, which needs the two extra
        /// fields: how many times we have already stood down for this prefix
        /// (drives the backoff) and until when the current stand-down runs.
        #[derive(Default)]
        struct Strike {
            n: u32,
            yields: u32,
            yielded_until: Option<std::time::Instant>,
        }

        /// ⚠️ Keyed by PREFIX ONLY, not by adapter LUID, and that is deliberate.
        ///
        /// With `v6_defend_narrow` on (the default since #1246) each org's
        /// adapter defends a disjoint `/(96+block_plen)`, so two orgs never
        /// share a key and the ladders are independent anyway. With the
        /// `OVERLAY_V6_DEFEND_NARROW=0` fallback they DO share the whole `/96`
        /// — and there a shared ladder is the behaviour we want: that is the
        /// pre-#1237 shape where both runtimes fought over one prefix, so one
        /// org standing down should stand the other down too rather than let
        /// the sibling keep the fight alive under a different LUID.
        static WRITE_STRIKES: std::sync::Mutex<
            Option<std::collections::HashMap<(IpAddr, u8), Strike>>,
        > = std::sync::Mutex::new(None);

        /// Consecutive futile re-assertions before this node stands down from
        /// a prefix at ANY metric. Equal to [`STRIKES_TO_WARN`] on purpose: the
        /// operator gets the explanation and the stand-down in the same breath.
        /// One MORE than [`METRIC0_STRIKES_TO_YIELD`], so the cheap remedy
        /// (drop metric 0 → 1) is always tried before the expensive one.
        const STRIKES_TO_YIELD: u32 = 4;

        /// #1328 — is this prefix currently stood down?
        ///
        /// Expiry deliberately does NOT clear the entry: the next wave writes
        /// once as a PROBE, and if that write is reaped too, `note_absent`
        /// stands down again at the next rung. Clearing here would reset the
        /// ladder every cooldown and re-create a slow version of the war.
        fn yielded(key: (IpAddr, u8)) -> bool {
            if !super::route_yield_enabled() {
                return false;
            }
            WRITE_STRIKES
                .lock()
                .ok()
                .and_then(|g| {
                    g.as_ref()?
                        .get(&key)?
                        .yielded_until
                        .map(|t| std::time::Instant::now() < t)
                })
                .unwrap_or(false)
        }

        /// Consecutive guard waves that may find a written prefix missing
        /// before metric-0 is abandoned. Three waves ≈ 6 s — long enough to
        /// ride out a single VPN route storm, short enough that a host never
        /// spends a minute unrouted.
        const METRIC0_STRIKES_TO_YIELD: u32 = 3;

        /// Consecutive waves finding a written prefix missing before the
        /// route-reaping WARN fires. One more than the yield threshold so a
        /// metric-0 host reports the specific remedy (yield) before the
        /// general one.
        const STRIKES_TO_WARN: u32 = 4;

        /// Record that `key` is ABSENT on a wave that follows a successful
        /// write.
        ///
        /// rc.291 — this fires for EVERY metric, not just 0. Field
        /// (CORPLAP-3 / Cisco AnyConnect, 2026-08-02): `New-NetRoute`
        /// succeeds and the row is gone within ~1 s, for both a v4 `/32` and a
        /// v6 `/128`. The agent's own adds meet the same fate, and because
        /// `add_peer_route`'s result is `.ok()`d by the caller, the host
        /// simply went quiet — no error, no route, no clue. That silence cost
        /// a multi-hour hunt, so the condition now NAMES ITSELF once per
        /// prefix per streak. The metric-0 yield below is the narrower,
        /// automatic remedy layered on top.
        fn note_absent(key: (IpAddr, u8), metric: u32) {
            let mut g = WRITE_STRIKES.lock().unwrap();
            let map = g.get_or_insert_with(std::collections::HashMap::new);
            let st = map.entry(key).or_default();
            st.n += 1;
            let n = st.n;
            let already_yielded = st
                .yielded_until
                .is_some_and(|t| std::time::Instant::now() < t);

            // #1328 — stand down from a prefix we keep losing, at ANY metric.
            //
            // 🔑 Safe because a strike means the route is ALREADY absent: we
            // stop RE-ADDING it, we do not remove anything. Reachability is
            // lost either way, so the only thing yielding costs is the fight,
            // and the fight is what burned 437 evictions/min on CORPLAP-3.
            //
            // Re-armable on purpose (probe → back off further), because a
            // competitor is usually transient — a VPN that disconnects must
            // get its prefixes handed straight back.
            if super::route_yield_enabled() && !already_yielded && n >= STRIKES_TO_YIELD {
                st.yields = st.yields.saturating_add(1);
                let back = super::yield_backoff(st.yields);
                st.yielded_until = Some(std::time::Instant::now() + back);
                crate::evidence::ROUTE_YIELDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    dest = %key.0, plen = key.1, metric,
                    yields = st.yields, backoff_s = back.as_secs(),
                    "overlay: STANDING DOWN from this prefix — re-asserting it has been \
                     futile and something outside this agent keeps deleting it. We stop \
                     re-adding AND stop evicting the competitor's row for the backoff, \
                     then probe once. The route was already gone each time, so this \
                     costs no reachability; it bounds a fight neither side can win."
                );
            }

            // `==` so a permanently-reaped prefix warns ONCE per streak;
            // `note_present` clears the entry, which re-arms it if the route
            // ever survives again (e.g. the VPN disconnects).
            if n == STRIKES_TO_WARN {
                tracing::warn!(
                    dest = %key.0, plen = key.1, metric,
                    "overlay: a defended route we install keeps DISAPPEARING within \
                     seconds — something outside this agent (typically a corp VPN's \
                     route monitor, e.g. Cisco AnyConnect) is deleting routes to the \
                     overlay prefixes. Node-INITIATED traffic to this peer falls through \
                     to the VPN; INBOUND and source-bound traffic (bind to the overlay \
                     address) still work. Remedy: ask the VPN administrator to \
                     split-exclude the overlay prefixes."
                );
            }
            if metric == 0
                && n >= METRIC0_STRIKES_TO_YIELD
                && !METRIC0_REJECTED.swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::warn!(
                    dest = %key.0, plen = key.1,
                    "overlay: metric-0 defended routes do NOT survive on this host — \
                     yielding to metric 1 for the rest of this process (the metric a \
                     route-monitoring VPN has been observed to tolerate)."
                );
            }
        }

        /// Clear `key`'s strikes — the row is present as written.
        fn note_present(key: (IpAddr, u8)) {
            if let Ok(mut g) = WRITE_STRIKES.lock()
                && let Some(map) = g.as_mut()
            {
                map.remove(&key);
            }
        }

        pub fn ensure(luid: u64, dest: IpAddr, plen: u8, metric: u32) -> std::io::Result<()> {
            // rc.289 — once metric 0 has proven not to stick on this host,
            // every defended route falls back to the metric the VPN tolerates.
            let metric =
                if metric == 0 && METRIC0_REJECTED.load(std::sync::atomic::Ordering::Relaxed) {
                    1
                } else {
                    metric
                };
            let key = (dest, plen);
            // #1328 — stood down from this prefix: do not re-assert it until
            // the backoff expires. Ok(()) rather than an error because nothing
            // is wrong from the caller's point of view — the guard's job for
            // this prefix is deliberately paused, and every caller `.ok()`s
            // this anyway.
            if yielded(key) {
                return Ok(());
            }
            let mut probe = make_row(luid, dest, plen, 0);
            // SAFETY: GetIpForwardEntry2 matches on LUID + prefix + next-hop
            // and fills the row on success.
            let rc = unsafe { GetIpForwardEntry2(&mut probe) };
            if rc != NO_ERROR {
                // Absent. Normal on the FIRST install; a STRIKE afterwards —
                // something outside this process deleted a row we wrote (CORPLAP
                // 2026-08-01: AnyConnect's monitor removes any route that
                // would out-rank its own, leaving the prefix unrouted and
                // killing even inbound REPLIES).
                note_absent(key, metric);
                return add(luid, dest, plen, metric);
            }
            note_present(key);
            if probe.Metric == metric {
                return Ok(());
            }
            probe.Metric = metric;
            // SAFETY: `probe` is an OS-filled row we only re-metric; the API
            // matches it by LUID + prefix + next-hop.
            let set_rc = unsafe { SetIpForwardEntry2(&probe) };
            if set_rc == NO_ERROR {
                return Ok(());
            }
            // Fallback: the old delete-then-add. Never silent — losing the
            // route here is exactly the CORPLAP failure mode.
            del(luid, dest, plen);
            let re = add(luid, dest, plen, metric);
            if let Err(e) = &re {
                tracing::warn!(
                    dest = %dest, plen, metric, %e,
                    set_error = set_rc,
                    "overlay: route metric reconcile FAILED and the route could not be \
                     restored — this prefix is now unrouted via the overlay NIC"
                );
            }
            re
        }

        /// rc.287 — eviction-WARN throttle state. The rc.279 WARN assumed a
        /// competitor re-adds at most once per VPN connect ("self-limiting");
        /// Cisco AnyConnect's route monitor re-adds within MILLISECONDS of
        /// every deletion (CORPLAP-3, 2026-08-01: 25,197 WARNs in one day).
        /// Emit at most one WARN per prefix per minute, carrying the count of
        /// evictions suppressed since the last one — the war stays visible,
        /// the log stays readable.
        struct EvictThrottle {
            last: std::collections::HashMap<(IpAddr, u8), (std::time::Instant, u64)>,
        }

        impl EvictThrottle {
            /// Record one ACTUAL eviction of `key`. `Some(suppressed)` when a
            /// WARN should be emitted now; `None` inside the quiet window.
            fn note(&mut self, key: (IpAddr, u8), now: std::time::Instant) -> Option<u64> {
                const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
                match self.last.get_mut(&key) {
                    Some((at, n)) if now.duration_since(*at) < WINDOW => {
                        *n += 1;
                        None
                    }
                    Some((at, n)) => {
                        let suppressed = *n;
                        *at = now;
                        *n = 0;
                        Some(suppressed)
                    }
                    None => {
                        self.last.insert(key, (now, 0));
                        Some(0)
                    }
                }
            }
        }

        static EVICT_THROTTLE: std::sync::Mutex<Option<EvictThrottle>> =
            std::sync::Mutex::new(None);

        /// Emit the eviction WARN (or a throttled `debug!`) for one actual
        /// deletion of a competing route.
        fn evict_warn(dest: IpAddr, plen: u8, ifindex: u32, luid_val: u64) {
            // FR-68 — counted BEFORE the throttle, because the throttle is a
            // logging decision (1 WARN/min/prefix) and a rate that only shows
            // up in suppressed-line arithmetic is not measurable. Every
            // successful delete reaches here, so this is the one site.
            crate::evidence::ROUTE_EVICTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut g = EVICT_THROTTLE.lock().unwrap();
            let t = g.get_or_insert_with(|| EvictThrottle {
                last: std::collections::HashMap::new(),
            });
            match t.note((dest, plen), std::time::Instant::now()) {
                // #1237 — carry the competitor's alias so a reader (and the
                // acceptance grep) can tell a real foreign product from a
                // sibling roomler adapter that slipped the exemption.
                Some(suppressed) => tracing::warn!(
                    dest = %dest,
                    plen,
                    competitor_ifindex = ifindex,
                    competitor_luid = format_args!("{:#x}", luid_val),
                    competitor_alias = alias_for_luid(luid_val).as_deref().unwrap_or("?"),
                    suppressed_since_last = suppressed,
                    "overlay: evicted a competing route installed by another product"
                ),
                None => tracing::debug!(
                    dest = %dest,
                    plen,
                    "overlay: evicted a competing route (WARN throttled, 1/min/prefix)"
                ),
            }
        }

        /// #1405 — per-prefix eviction futility. Its own table, not
        /// `WRITE_STRIKES`: `note_present` clears that entry whenever OUR route
        /// is present, which in this war it always is, so a pause kept there
        /// would be lifted on the very next wave.
        static EVICT_STREAKS: std::sync::Mutex<
            Option<std::collections::HashMap<(IpAddr, u8), super::EvictStreak>>,
        > = std::sync::Mutex::new(None);

        fn eviction_paused(key: (IpAddr, u8)) -> bool {
            if !super::route_yield_enabled() {
                return false;
            }
            EVICT_STREAKS
                .lock()
                .ok()
                .and_then(|g| {
                    g.as_ref()?
                        .get(&key)
                        .map(|s| s.paused(std::time::Instant::now()))
                })
                .unwrap_or(false)
        }

        fn note_eviction(key: (IpAddr, u8)) {
            if !super::route_yield_enabled() {
                return;
            }
            let Ok(mut g) = EVICT_STREAKS.lock() else {
                return;
            };
            let s = g
                .get_or_insert_with(std::collections::HashMap::new)
                .entry(key)
                .or_default();
            if let Some(back) = s.evicted(std::time::Instant::now()) {
                crate::evidence::ROUTE_YIELDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    dest = %key.0,
                    plen = key.1,
                    backoff_s = back.as_secs(),
                    "overlay: STANDING DOWN from evicting a competing route — it is back on \
                     every wave and wins every lookup between deletions, so deleting it only \
                     churns the FIB (and each deletion re-arms the route guard). Leaving it \
                     for the backoff, then probing once (#1405)"
                );
            }
        }

        /// #1405 — does a competitor actually win the FIB decision for
        /// `dest/plen`? A foreign row that loses every lookup carries no
        /// traffic, and deleting it is a route-change event that re-arms the
        /// guard; AnyConnect then re-adds it within milliseconds. A failed
        /// lookup fails toward the old behaviour (evict).
        fn competitor_wins(ours: u64, dest: IpAddr, plen: u8) -> bool {
            if !super::route_evict_winners_only_enabled() {
                return true;
            }
            best_route_luid(super::eviction_probe(dest, plen))
                .is_none_or(|luid| !super::adapter_is_ours(luid, ours))
        }

        /// Evict any `dest/plen` route on an interface OTHER than `ours` — the
        /// full-tunnel-VPN route war (Check Point installs a competing `/32` per
        /// overlay peer). Snapshots the v4 FIB (in-memory, ~µs) and deletes the
        /// competing entries so our wintun route wins.
        ///
        /// #1405 — only when the competitor actually wins the lookup, and not
        /// while a futility pause holds for this prefix.
        pub fn evict_competing_v4(ours: u64, dest: Ipv4Addr, plen: u8) {
            // rc.279 kill-switch — deleting ANOTHER product's routes is the
            // right default (the overlay is unusable under a hostile
            // full-tunnel VPN without it), but some managed sites alarm on
            // route deletion; `overlay_route_evict=0` trades overlay
            // reachability under such VPNs for leaving foreign routes alone.
            if !super::route_evict_enabled() {
                return;
            }
            // #1328 — the other half of the stand-down; see the v6 twin.
            if yielded((IpAddr::V4(dest), plen)) {
                return;
            }
            let key = (IpAddr::V4(dest), plen);
            if eviction_paused(key) || !competitor_wins(ours, key.0, plen) {
                return;
            }
            let mut evicted_any = false;
            let want = u32::from_ne_bytes(dest.octets());
            // SAFETY: GetIpForwardTable2 allocates a snapshot we iterate then
            // free; every union read is guarded by the `si_family` check.
            unsafe {
                let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
                if GetIpForwardTable2(AF_INET, &mut table) != NO_ERROR || table.is_null() {
                    return;
                }
                let n = (*table).NumEntries as usize;
                let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
                for r in rows {
                    if r.DestinationPrefix.PrefixLength == plen
                        && r.DestinationPrefix.Prefix.si_family == AF_INET
                        && r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr == want
                        && !super::route_belongs_to_us(r.InterfaceLuid.Value, ours)
                    {
                        // rc.279 — the route war used to be completely
                        // silent: an operator could not tell "healthy" from
                        // "winning an eviction fight on every VPN reconnect"
                        // (the invisibility that fed the winhost-a hunt's six
                        // wrong diagnoses). Emit only on an ACTUAL deletion,
                        // so the every-2s no-op guard ticks stay quiet;
                        // rc.287 throttles the emit to 1 WARN/min/prefix
                        // because AnyConnect re-adds within milliseconds.
                        if DeleteIpForwardEntry2(r) == NO_ERROR {
                            evicted_any = true;
                            evict_warn(
                                IpAddr::V4(dest),
                                plen,
                                r.InterfaceIndex,
                                r.InterfaceLuid.Value,
                            );
                        }
                    }
                }
                FreeMibTable(table as *const core::ffi::c_void);
            }
            if evicted_any {
                note_eviction(key);
            }
        }

        /// corplap route war, 08-18 — is `row_net/row_plen` ENTIRELY inside
        /// `net/plen`? The in-block eviction's targeting rule, split out
        /// pure so the subset math is unit-tested without a FIB. Requiring
        /// the row's plen to be at least the block's structurally excludes
        /// broader routes (defaults, /1 split-halves, corp LANs): only
        /// prefixes that fit inside the overlay block can ever match.
        pub(crate) fn row_in_block(row_net: u32, row_plen: u8, net: u32, plen: u8) -> bool {
            // A broader-or-equal-scope rival (row_plen < plen) is never
            // in-block; a zero/invalid block plen matches nothing (an
            // uninitialized block must fail toward touching nothing).
            if row_plen < plen || plen == 0 || plen > 32 {
                return false;
            }
            let mask: u32 = if plen == 32 {
                u32::MAX
            } else {
                !(u32::MAX >> plen)
            };
            (row_net & mask) == (net & mask)
        }

        /// corplap route war, 08-18 — evict EVERY foreign v4 route whose prefix
        /// lies INSIDE `net/plen`, at ANY prefix length. Generalizes
        /// [`evict_competing_v4`], which matches its exact defended plen
        /// (/32 peers, the block floor) — and which the Check Point endpoint
        /// manager learned to sidestep by shadowing the overlay block with
        /// **/24s** (plus broadcast /32s and learned per-flow host routes):
        /// prefixes we never defended, out-prefixing the /22 floor for any
        /// destination without a /32 winner, steering overlay traffic into
        /// the corp gateway where it dies (field: CORPLAP-3, four peers
        /// unreachable while their carriers ran). Same kill-switch
        /// (`overlay_route_evict`) and the same WARN-on-actual-deletion
        /// contract; the CALLER gates on `floor_safe` so a CGNAT uplink
        /// (whose real routes live inside the block) is never touched.
        pub fn evict_foreign_in_block_v4(ours: u64, net: Ipv4Addr, plen: u8) {
            if !super::route_evict_enabled() {
                return;
            }
            let block = u32::from_be_bytes(net.octets());
            // SAFETY: same snapshot-iterate-free shape as `evict_competing_v4`;
            // every union read is guarded by the `si_family` check.
            unsafe {
                let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
                if GetIpForwardTable2(AF_INET, &mut table) != NO_ERROR || table.is_null() {
                    return;
                }
                let n = (*table).NumEntries as usize;
                let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
                for r in rows {
                    if r.DestinationPrefix.Prefix.si_family == AF_INET
                        && !super::route_belongs_to_us(r.InterfaceLuid.Value, ours)
                        && row_in_block(
                            u32::from_be(r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr),
                            r.DestinationPrefix.PrefixLength,
                            block,
                            plen,
                        )
                        && DeleteIpForwardEntry2(r) == NO_ERROR
                    {
                        evict_warn(
                            IpAddr::V4(Ipv4Addr::from(u32::from_be(
                                r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr,
                            ))),
                            r.DestinationPrefix.PrefixLength,
                            r.InterfaceIndex,
                            r.InterfaceLuid.Value,
                        );
                    }
                }
                FreeMibTable(table as *const core::ffi::c_void);
            }
        }

        /// corplap route war v3 (#23) — order-insensitive fold of one foreign
        /// in-block row into a set fingerprint (FNV-1a per row, XOR across
        /// rows: commutative, so FIB iteration order can never fake a
        /// change). Pure; the debounce decision is exactly "did this value
        /// change since the last wave".
        pub(crate) fn fp_fold(acc: u64, net: u32, plen: u8, luid: u64) -> u64 {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in net
                .to_be_bytes()
                .into_iter()
                .chain([plen])
                .chain(luid.to_be_bytes())
            {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            acc ^ h
        }

        /// corplap route war v3 (#23) — fingerprint of the current FOREIGN
        /// in-block route set (the exact rows [`evict_foreign_in_block_v4`]
        /// would delete). `0` = empty set. The caller compares waves and
        /// skips the blind eviction when nothing changed — see
        /// `SystemTun::in_block_fp` for why an unchanged competing set is
        /// left alone.
        pub fn foreign_in_block_fp(ours: u64, net: Ipv4Addr, plen: u8) -> u64 {
            let block = u32::from_be_bytes(net.octets());
            let mut fp = 0u64;
            // SAFETY: same snapshot-iterate-free shape; union reads guarded
            // by the `si_family` check.
            unsafe {
                let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
                if GetIpForwardTable2(AF_INET, &mut table) != NO_ERROR || table.is_null() {
                    return fp;
                }
                let n = (*table).NumEntries as usize;
                let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
                for r in rows {
                    // FR-68 C2(a) — #1246 converted the three EVICTION helpers
                    // to `route_belongs_to_us` but left this raw `== ours`
                    // behind (its commit message says all four). The result on
                    // a multi-org host: a sibling org's peer churn changes this
                    // fingerprint, the debounce reads "something moved", and a
                    // full FIB walk runs every wave. It deletes nothing — the
                    // eviction itself is correctly exempted — so it is not a
                    // war, but the anti-flap guard is defeated on exactly the
                    // host it was written for.
                    //
                    // `adapter_is_ours` and not `route_belongs_to_us`: this is
                    // a read-only scan and must not move the spare counter.
                    if r.DestinationPrefix.Prefix.si_family != AF_INET
                        || super::adapter_is_ours(r.InterfaceLuid.Value, ours)
                    {
                        continue;
                    }
                    let rn = u32::from_be(r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
                    let rp = r.DestinationPrefix.PrefixLength;
                    if row_in_block(rn, rp, block, plen) {
                        fp = fp_fold(fp, rn, rp, r.InterfaceLuid.Value);
                    }
                }
                FreeMibTable(table as *const core::ffi::c_void);
            }
            fp
        }

        /// corplap route war v3 (#23) — reclaim-outcome log throttle (the same
        /// 1/min/destination discipline as [`evict_warn`]; a host whose
        /// competitor wins the pin race would otherwise emit every wave).
        /// `Some(suppressed)` = log now; `None` = inside the quiet window.
        pub(super) fn reclaim_note(dest: IpAddr) -> Option<u64> {
            static RECLAIM_THROTTLE: std::sync::Mutex<Option<EvictThrottle>> =
                std::sync::Mutex::new(None);
            let mut g = RECLAIM_THROTTLE.lock().unwrap();
            let t = g.get_or_insert_with(|| EvictThrottle {
                last: std::collections::HashMap::new(),
            });
            t.note((dest, 32), std::time::Instant::now())
        }

        /// rc.281 — v6 twin of [`evict_competing_v4`]: same route war, ULA
        /// prefixes. Shares the `overlay_route_evict` kill-switch and the
        /// WARN-on-actual-deletion observability contract.
        pub fn evict_competing_v6(ours: u64, dest: std::net::Ipv6Addr, plen: u8) {
            if !super::route_evict_enabled() {
                return;
            }
            // #1328 — the other half of the stand-down. Pausing only our own
            // re-assertion would leave us still deleting the competitor's row
            // every wave, which is most of the cost and all of the churn.
            if yielded((IpAddr::V6(dest), plen)) {
                return;
            }
            // #1405 — only a winner, and not while this prefix is paused. The
            // ULA `/96` behind AnyConnect is the case this was found on: their
            // mirror wins (26 vs our 261), comes back within milliseconds, and
            // deleting it ~20×/min held nothing (v6 stayed 100% lost).
            let key = (IpAddr::V6(dest), plen);
            if eviction_paused(key) || !competitor_wins(ours, key.0, plen) {
                return;
            }
            let mut evicted_any = false;
            let want = dest.octets();
            // SAFETY: same snapshot-iterate-free shape as the v4 walk; every
            // union read is guarded by the `si_family` check.
            unsafe {
                let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
                if GetIpForwardTable2(AF_INET6, &mut table) != NO_ERROR || table.is_null() {
                    return;
                }
                let n = (*table).NumEntries as usize;
                let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
                for r in rows {
                    if r.DestinationPrefix.PrefixLength == plen
                        && r.DestinationPrefix.Prefix.si_family == AF_INET6
                        && r.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte == want
                        && !super::route_belongs_to_us(r.InterfaceLuid.Value, ours)
                        && DeleteIpForwardEntry2(r) == NO_ERROR
                    {
                        evicted_any = true;
                        evict_warn(
                            IpAddr::V6(dest),
                            plen,
                            r.InterfaceIndex,
                            r.InterfaceLuid.Value,
                        );
                    }
                }
                FreeMibTable(table as *const core::ffi::c_void);
            }
            if evicted_any {
                note_eviction(key);
            }
        }

        /// The address inside a `SOCKADDR_INET`, per its own family tag.
        /// `None` for an unset/foreign family (a zeroed union reads AF 0).
        fn ip_of(sa: &SOCKADDR_INET) -> Option<IpAddr> {
            // SAFETY: reading the union arm selected by its family tag; the
            // in-memory byte order IS network order, so the raw bytes are the
            // address octets.
            unsafe {
                match sa.si_family {
                    AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                        sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                    ))),
                    AF_INET6 => Some(IpAddr::V6(std::net::Ipv6Addr::from(
                        sa.Ipv6.sin6_addr.u.Byte,
                    ))),
                    _ => None,
                }
            }
        }

        /// N3 — the LUID for an interface ALIAS (`"roomler"`), for callers
        /// with NO live device handle: the boot reconciler and the last-gasp
        /// crash-path purge, which previously targeted the alias through
        /// `netsh`/PowerShell spawns — from a process that was, by
        /// definition, already wedged. `None` when no such adapter exists
        /// (nothing to purge — the honest answer).
        pub fn luid_for_alias(alias: &str) -> Option<u64> {
            use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
            let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
            let mut luid = NET_LUID_LH { Value: 0 };
            // SAFETY: `wide` is NUL-terminated; the API writes the out-param
            // only on success, and `Value` covers the whole union.
            unsafe {
                (ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) == NO_ERROR)
                    .then_some(luid.Value)
            }
        }

        /// #1237 — the friendly interface alias for a LUID (`roomler`,
        /// `roomler-6a712a5`, `Ethernet 2`, …). The cross-process belt for the
        /// sibling-exemption: a second co-tenant daemon's adapters are not in
        /// this process's own-LUID registry, but their alias carries our
        /// naming. `None` when the LUID has no alias (a gone adapter).
        pub fn alias_for_luid(luid: u64) -> Option<String> {
            use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToAlias;
            use windows_sys::Win32::NetworkManagement::Ndis::IF_MAX_STRING_SIZE;
            let l = NET_LUID_LH { Value: luid };
            let mut buf = [0u16; IF_MAX_STRING_SIZE as usize + 1];
            // SAFETY: `buf` is a fixed NUL-terminatable buffer of the size the
            // API documents; it writes a wide string on success only.
            unsafe {
                if ConvertInterfaceLuidToAlias(&l, buf.as_mut_ptr(), buf.len()) != NO_ERROR {
                    return None;
                }
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            Some(String::from_utf16_lossy(&buf[..end]))
        }

        /// N3 — every route prefix currently on `luid`, both families, as
        /// `"addr/plen"` strings (the shape `purge_one` consumes). The typed
        /// twin of the retired `Get-NetRoute` PowerShell spawn: an in-memory
        /// FIB snapshot instead of a 0.5–2 s process launch on bring-up and
        /// on every crash-path exit.
        pub fn list_cidrs(luid: u64) -> Vec<String> {
            let mut out = Vec::new();
            // SAFETY: GetIpForwardTable2 allocates a snapshot we iterate then
            // free — the same idiom as `evict_competing_v4`.
            unsafe {
                for family in [AF_INET, AF_INET6] {
                    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
                    if GetIpForwardTable2(family, &mut table) != NO_ERROR || table.is_null() {
                        continue;
                    }
                    let n = (*table).NumEntries as usize;
                    let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
                    for r in rows {
                        if r.InterfaceLuid.Value != luid {
                            continue;
                        }
                        if let Some(ip) = ip_of(&r.DestinationPrefix.Prefix) {
                            out.push(format!("{ip}/{}", r.DestinationPrefix.PrefixLength));
                        }
                    }
                    FreeMibTable(table as *const core::ffi::c_void);
                }
            }
            out
        }

        /// rc.410 (#23) — the interface LUID the FIB would pick for `dst`
        /// right now. Unlike [`best_route`] it does NOT filter on-link
        /// results away: our TUN routes ARE on-link, and "does the overlay
        /// actually win this destination?" is precisely the ownership check
        /// the defense wave runs. `GetBestRoute2` is the honest oracle for
        /// it — the OS PATH table only holds destinations with live
        /// conversations, so it reports nothing for relay-carried peers
        /// (which is exactly the set that was captured on corplap).
        pub fn best_route_luid(dst: IpAddr) -> Option<u64> {
            use windows_sys::Win32::NetworkManagement::IpHelper::GetBestRoute2;
            // SAFETY: out-params are written on success; the destination is
            // a fully-initialised SOCKADDR_INET.
            unsafe {
                let dest = sockaddr(dst);
                let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
                let mut src: SOCKADDR_INET = std::mem::zeroed();
                (GetBestRoute2(
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    &dest,
                    0,
                    &mut row,
                    &mut src,
                ) == NO_ERROR)
                    .then_some(row.InterfaceLuid.Value)
            }
        }

        /// N2 — the host's best route toward `dst` as `(ifIndex, gateway)`,
        /// straight from the FIB (`GetBestRoute2`) — the typed replacement
        /// for parsing `netsh interface ipv{4,6} show route`'s LOCALIZED,
        /// position-keyed table (the most fragile parse the tree had).
        /// `None` on error or when the best route is on-link (unspecified
        /// next-hop): no usable gateway, same verdict the parser reached by
        /// skipping non-address gateway columns.
        pub fn best_route(dst: IpAddr) -> Option<(u32, IpAddr)> {
            use windows_sys::Win32::NetworkManagement::IpHelper::GetBestRoute2;
            // SAFETY: out-params are written on success; the destination is a
            // fully-initialised SOCKADDR_INET.
            unsafe {
                let dest = sockaddr(dst);
                let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
                let mut src: SOCKADDR_INET = std::mem::zeroed();
                if GetBestRoute2(
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    &dest,
                    0,
                    &mut row,
                    &mut src,
                ) != NO_ERROR
                {
                    return None;
                }
                let gw = ip_of(&row.NextHop)?;
                let unspecified = match gw {
                    IpAddr::V4(v) => v.is_unspecified(),
                    IpAddr::V6(v) => v.is_unspecified(),
                };
                if unspecified {
                    return None;
                }
                Some((row.InterfaceIndex, gw))
            }
        }

        /// FR-97 P0e (N12) — one FIB snapshot of a family, as an exit
        /// client's pins see it: the uplink, `(ifIndex, gateway)`, and every
        /// gateway host route, `(dest, ifIndex, gateway)`.
        ///
        /// The uplink is the route the OS would carry a default-bound packet
        /// over if none of OUR adapters' routes existed: the longest prefix
        /// covering the unspecified address, then the lowest route plus
        /// interface metric (how Windows ranks), on a connected interface.
        /// That is what [`best_route`] answers at bring-up, before our
        /// adapter has a route; once an exit's `/1`s are in they out-match
        /// any default toward the unspecified address, so it can no longer
        /// say. `None` for the uplink when the best such route is on-link,
        /// as there.
        #[allow(clippy::type_complexity)]
        pub fn exemption_view(
            v6: bool,
        ) -> Option<(Option<(u32, IpAddr)>, Vec<(IpAddr, u32, IpAddr)>)> {
            let family = if v6 { AF_INET6 } else { AF_INET };
            let host_plen: u8 = if v6 { 128 } else { 32 };
            let mut best: Option<(u8, u64, u32, Option<IpAddr>)> = None;
            let mut hosts = Vec::new();
            // SAFETY: GetIpForwardTable2 allocates a snapshot we iterate then
            // free — the same idiom as `evict_competing_v4`.
            unsafe {
                let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
                if GetIpForwardTable2(family, &mut table) != NO_ERROR || table.is_null() {
                    return None;
                }
                let n = (*table).NumEntries as usize;
                let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
                for r in rows {
                    let Some(dest) = ip_of(&r.DestinationPrefix.Prefix) else {
                        continue;
                    };
                    let gw = ip_of(&r.NextHop).filter(|g| !g.is_unspecified());
                    let plen = r.DestinationPrefix.PrefixLength;
                    if plen == host_plen {
                        if let Some(gw) = gw {
                            hosts.push((dest, r.InterfaceIndex, gw));
                        }
                        continue;
                    }
                    if !dest.is_unspecified() || is_ours_or_roomler(r.InterfaceLuid.Value) {
                        continue;
                    }
                    let Some((if_metric, connected)) = iface_metric(r.InterfaceLuid.Value, family)
                    else {
                        continue;
                    };
                    if !connected {
                        continue;
                    }
                    let cost = u64::from(r.Metric) + u64::from(if_metric);
                    let better =
                        best.is_none_or(|(bp, bc, _, _)| plen > bp || (plen == bp && cost < bc));
                    if better {
                        best = Some((plen, cost, r.InterfaceIndex, gw));
                    }
                }
                FreeMibTable(table as *const core::ffi::c_void);
            }
            let uplink = best.and_then(|(_, _, ifindex, gw)| gw.map(|g| (ifindex, g)));
            Some((uplink, hosts))
        }

        /// One of this process's adapters, or any adapter named like ours.
        /// Never an uplink, whatever the sibling-exempt switch says.
        pub(super) fn is_ours_or_roomler(luid: u64) -> bool {
            super::own_adapters::is_own_luid(luid)
                || alias_for_luid(luid).is_some_and(|a| super::is_roomler_adapter_name(&a))
        }

        /// FR-97 N14 — the LUID of interface `ifindex`: netstate names an
        /// interface by its index.
        pub(super) fn luid_of_index(ifindex: u32) -> Option<u64> {
            use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
            // SAFETY: an out-param the call fills on NO_ERROR; the union's
            // `Value` view is the whole 64 bits.
            unsafe {
                let mut luid = NET_LUID_LH { Value: 0 };
                (ConvertInterfaceIndexToLuid(ifindex, &mut luid) == NO_ERROR).then_some(luid.Value)
            }
        }

        /// An interface's metric for `family`, and whether it is connected.
        fn iface_metric(luid: u64, family: u16) -> Option<(u32, bool)> {
            use windows_sys::Win32::NetworkManagement::IpHelper::{
                GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
            };
            // SAFETY: Initialize fills valid defaults; Get fills the row for
            // (family, luid).
            unsafe {
                let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
                InitializeIpInterfaceEntry(&mut row);
                row.Family = family;
                row.InterfaceLuid = NET_LUID_LH { Value: luid };
                (GetIpInterfaceEntry(&mut row) == NO_ERROR).then_some((row.Metric, row.Connected))
            }
        }

        /// N3 — a gateway-routed row keyed by interface INDEX (what
        /// `OrigDefaultRoute` carries): the host-exemption shape. Unlike
        /// [`make_row`] the next-hop is a REAL gateway, and the interface is
        /// the ORIGINAL uplink's, never ours.
        fn make_gw_row(
            ifindex: u32,
            dest: IpAddr,
            plen: u8,
            gateway: IpAddr,
            metric: u32,
        ) -> MIB_IPFORWARD_ROW2 {
            // SAFETY: InitializeIpForwardEntry fills valid defaults; we
            // override index / prefix / next-hop / metric.
            unsafe {
                let mut r: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
                InitializeIpForwardEntry(&mut r);
                r.InterfaceIndex = ifindex;
                r.DestinationPrefix.Prefix = sockaddr(dest);
                r.DestinationPrefix.PrefixLength = plen;
                r.NextHop = sockaddr(gateway);
                r.Metric = metric;
                r
            }
        }

        /// N3 — add (idempotent) `dest/plen` via `gateway` on interface
        /// index `ifindex` — the typed host-exemption install.
        pub fn add_gateway_route(
            ifindex: u32,
            dest: IpAddr,
            plen: u8,
            gateway: IpAddr,
            metric: u32,
        ) -> std::io::Result<()> {
            let r = make_gw_row(ifindex, dest, plen, gateway, metric);
            // SAFETY: fully-initialised row; the API copies it.
            let rc = unsafe { CreateIpForwardEntry2(&r) };
            if rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(rc as i32))
            }
        }

        /// N3 — remove a host-exemption row (best-effort; absent is fine).
        /// `true` when a row was there and went.
        pub fn del_gateway_route(ifindex: u32, dest: IpAddr, plen: u8, gateway: IpAddr) -> bool {
            let r = make_gw_row(ifindex, dest, plen, gateway, 0);
            // SAFETY: the row carries the (interface, prefix, next-hop) key
            // the API matches on.
            unsafe { DeleteIpForwardEntry2(&r) == NO_ERROR }
        }

        /// N5 — pin the adapter's IPv4 interface METRIC (the route-war
        /// priority: our connected `/10` + peer `/32`s must outrank a
        /// full-tunnel VPN's captured routes). Typed replacement for the
        /// blocking `netsh set interface metric=` in `up()`. The
        /// `SitePrefixLength = 0` reset before `Set` is a documented API
        /// quirk (`Get` returns a value `Set` rejects) — same handling as
        /// the in-tree wintun-bindings `set_adapter_mtu`.
        pub fn set_iface_metric_v4(luid: u64, metric: u32) -> std::io::Result<()> {
            set_iface_metric_family(luid, AF_INET, metric)
        }

        /// #1342 — the IPv6 twin. It did not exist until now, and its absence
        /// was the whole bug: Windows ranks by `route metric + INTERFACE
        /// metric`, the v4 side pins the interface to 0 and wins every
        /// contested prefix, and v6 was left on Windows' automatic assignment.
        /// Measured on a corp laptop under AnyConnect: ours 5, the VPN's 25 —
        /// so with the ULA asserted at route metric 256 we sat at 261 against
        /// the VPN's 26 and lost outright, forever, on the same host where v4
        /// was quiet.
        pub fn set_iface_metric_v6(luid: u64, metric: u32) -> std::io::Result<()> {
            set_iface_metric_family(luid, AF_INET6, metric)
        }

        /// FR-97 P0b-2c — is IPv4 forwarding on for `luid`? Read-only.
        pub fn forwarding_enabled_v4(luid: u64) -> std::io::Result<bool> {
            use windows_sys::Win32::NetworkManagement::IpHelper::{
                GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
            };
            // SAFETY: Initialize fills valid defaults; Get fills the row for
            // (AF_INET, luid).
            unsafe {
                let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
                InitializeIpInterfaceEntry(&mut row);
                row.Family = AF_INET;
                row.InterfaceLuid = NET_LUID_LH { Value: luid };
                let rc = GetIpInterfaceEntry(&mut row);
                if rc != NO_ERROR {
                    return Err(std::io::Error::from_raw_os_error(rc as i32));
                }
                Ok(row.ForwardingEnabled)
            }
        }

        fn set_iface_metric_family(luid: u64, family: u16, metric: u32) -> std::io::Result<()> {
            use windows_sys::Win32::NetworkManagement::IpHelper::{
                GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
                SetIpInterfaceEntry,
            };
            // SAFETY: Initialize fills valid defaults; Get fills the row for
            // (family, luid); Set writes the mutated copy back.
            unsafe {
                let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
                InitializeIpInterfaceEntry(&mut row);
                row.Family = family;
                row.InterfaceLuid = NET_LUID_LH { Value: luid };
                let rc = GetIpInterfaceEntry(&mut row);
                if rc != NO_ERROR {
                    return Err(std::io::Error::from_raw_os_error(rc as i32));
                }
                row.SitePrefixLength = 0;
                row.Metric = metric;
                row.UseAutomaticMetric = false;
                let rc = SetIpInterfaceEntry(&mut row);
                if rc != NO_ERROR {
                    return Err(std::io::Error::from_raw_os_error(rc as i32));
                }
            }
            Ok(())
        }

        /// rc.279 — the OS-observed identity for our adapter LUID:
        /// `(ifIndex, "{GUID}")`. Diagnostics only (the bring-up identity
        /// log); `0` / `"?"` on conversion failure.
        pub fn identity(luid: u64) -> (u32, String) {
            let l = NET_LUID_LH { Value: luid };
            let mut idx: u32 = 0;
            // SAFETY: out-params written by the APIs; inputs are plain
            // values. Failure leaves the zeroed defaults — fine for a log.
            unsafe {
                ConvertInterfaceLuidToIndex(&l, &mut idx);
                let mut g: windows_sys::core::GUID = std::mem::zeroed();
                if ConvertInterfaceLuidToGuid(&l, &mut g) == NO_ERROR {
                    (
                        idx,
                        format!(
                            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                            g.data1,
                            g.data2,
                            g.data3,
                            g.data4[0],
                            g.data4[1],
                            g.data4[2],
                            g.data4[3],
                            g.data4[4],
                            g.data4[5],
                            g.data4[6],
                            g.data4[7]
                        ),
                    )
                } else {
                    (idx, "?".to_string())
                }
            }
        }

        #[cfg(test)]
        mod evict_throttle_tests {
            use super::*;
            use std::time::{Duration, Instant};

            /// rc.288 — the netmask→prefix-length derivation behind the
            /// defended connected route. A wrong length would defend the
            /// WRONG prefix, so the contiguity check is part of the contract.
            #[test]
            fn prefix_len_of_mask_handles_the_overlay_masks() {
                use super::super::prefix_len_of_mask;
                assert_eq!(
                    prefix_len_of_mask(Ipv4Addr::new(255, 192, 0, 0)),
                    Some(10),
                    "the overlay's 100.64.0.0/10"
                );
                assert_eq!(
                    prefix_len_of_mask(Ipv4Addr::new(255, 255, 255, 255)),
                    Some(32)
                );
                assert_eq!(prefix_len_of_mask(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
                assert_eq!(prefix_len_of_mask(Ipv4Addr::new(255, 255, 0, 0)), Some(16));
                assert_eq!(
                    prefix_len_of_mask(Ipv4Addr::new(255, 0, 255, 0)),
                    None,
                    "non-contiguous masks are rejected, never guessed"
                );
            }

            /// First eviction WARNs; the flood inside the window is counted,
            /// not logged; the first eviction past the window WARNs again and
            /// carries the suppressed count.
            #[test]
            fn throttle_warns_once_per_window_and_carries_the_count() {
                let mut t = EvictThrottle {
                    last: std::collections::HashMap::new(),
                };
                let k = (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), 32u8);
                let t0 = Instant::now();
                assert_eq!(t.note(k, t0), Some(0), "first eviction always WARNs");
                for i in 1..=500u64 {
                    assert_eq!(
                        t.note(k, t0 + Duration::from_millis(i * 100)),
                        None,
                        "inside the window: suppressed"
                    );
                }
                assert_eq!(
                    t.note(k, t0 + Duration::from_secs(61)),
                    Some(500),
                    "past the window: WARN with the suppressed count"
                );
                // A different prefix throttles independently.
                let k2 = (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 4)), 32u8);
                assert_eq!(t.note(k2, t0 + Duration::from_secs(61)), Some(0));
            }
        }
    }

    /// Track N1 — typed unicast-ADDRESS management on the overlay adapter,
    /// the sibling of [`winroute`] (routes). IP Helper end to end: no
    /// `netsh`, no subprocess, no output parsing — which retires the two
    /// production incident classes the netsh path accumulated:
    ///
    /// * **#373 (locale)** — "is this error 'already exists'?" was answered
    ///   by matching English prose; a German host's "Das Objekt ist bereits
    ///   vorhanden." escaped and aborted the whole org runtime. Here the
    ///   answer is the numeric `ERROR_OBJECT_ALREADY_EXISTS`, invariant by
    ///   construction.
    /// * **#388 (read-after-write race)** — `netsh add` and `netsh show`
    ///   don't see the interface at the same instant, so a single-sample
    ///   presence probe declared a just-created address ABSENT and the
    ///   caller's rollback deleted it (winhost-a, every restart). `Create…` and
    ///   `Get…UnicastIpAddressEntry` operate on the SAME in-memory MIB table,
    ///   so the skew — and the 4×150 ms polling loop that tolerated it —
    ///   cannot exist here.
    ///
    /// (The multi-org `SkipAsSource` reconcile that lived here died with the
    /// shared-TUN mux in W7c: per-org adapters hold ONE address each, so the
    /// nested-block source-selection geometry cannot exist.)
    #[cfg(windows)]
    mod winaddr {
        use std::net::IpAddr;

        use windows_sys::Win32::Foundation::{
            ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR,
        };
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry,
            InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
        };
        use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

        /// A minimal row identifying `ip` on `luid` — the (luid, address) pair
        /// is the key every Get/Delete matches on.
        fn row_for(luid: u64, ip: IpAddr) -> MIB_UNICASTIPADDRESS_ROW {
            // SAFETY: POD row; Initialize fills valid defaults, then the key
            // fields are written (same init pattern as `winroute::make_row`).
            unsafe {
                let mut r: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
                InitializeUnicastIpAddressEntry(&mut r);
                r.InterfaceLuid = NET_LUID_LH { Value: luid };
                r.Address = super::winroute::sockaddr(ip);
                r
            }
        }

        /// Add `ip/plen` to `luid` (idempotent — an already-present address is
        /// success, decided by the NUMERIC error, never the message). Returns
        /// `true` when the address was newly created.
        pub fn ensure(luid: u64, ip: IpAddr, plen: u8) -> std::io::Result<bool> {
            let mut r = row_for(luid, ip);
            r.OnLinkPrefixLength = plen;
            // Mirror the `tun` crate's field-proven primary-address settings:
            // manual origins, infinite lifetimes, DAD pre-passed (wintun does
            // no ARP/NS, so waiting on DAD would only delay bring-up).
            r.PrefixOrigin = 1; // IpPrefixOriginManual
            r.SuffixOrigin = 1; // IpSuffixOriginManual
            r.ValidLifetime = u32::MAX;
            r.PreferredLifetime = u32::MAX;
            r.DadState = 4; // IpDadStatePreferred
            // SAFETY: fully-initialised row; the API copies it.
            let rc = unsafe { CreateUnicastIpAddressEntry(&r) };
            match rc {
                NO_ERROR => Ok(true),
                ERROR_OBJECT_ALREADY_EXISTS => Ok(false),
                _ => Err(std::io::Error::from_raw_os_error(rc as i32)),
            }
        }

        /// Take `ip` off `luid`. Best-effort: absent is fine, and a failure
        /// only leaves an idle address behind (the caller's contract).
        pub fn remove(luid: u64, ip: IpAddr) {
            let r = row_for(luid, ip);
            // SAFETY: `r` carries the (luid, address) key the API matches on.
            let rc = unsafe { DeleteUnicastIpAddressEntry(&r) };
            if rc != NO_ERROR && rc != ERROR_NOT_FOUND {
                tracing::debug!(%ip, code = rc, "overlay: address delete reported an error");
            }
        }

        /// Every IPv4 `(address, prefix_len, skip_as_source)` currently on
        /// `luid`. Test-only since W7c removed its production caller (the
        /// SkipAsSource reconcile): the manual `manual_list_v4_probe` keeps
        /// it as the live-field FFI diagnostic that caught the 2.0.64.100
        /// byte-flip a unit test structurally can't.
        #[cfg(test)]
        pub fn list_v4(luid: u64) -> std::io::Result<Vec<(std::net::Ipv4Addr, u8, bool)>> {
            use std::net::Ipv4Addr;
            use windows_sys::Win32::NetworkManagement::IpHelper::{
                FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_TABLE,
            };
            use windows_sys::Win32::Networking::WinSock::AF_INET;
            let mut out = Vec::new();
            // SAFETY: GetUnicastIpAddressTable allocates a snapshot we iterate
            // then free — same idiom as `winroute::evict_competing_v4`.
            unsafe {
                let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
                let rc = GetUnicastIpAddressTable(AF_INET, &mut table);
                if rc != NO_ERROR || table.is_null() {
                    return Err(std::io::Error::from_raw_os_error(rc as i32));
                }
                let n = (*table).NumEntries as usize;
                let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
                for row in rows {
                    if row.InterfaceLuid.Value != luid {
                        continue;
                    }
                    // `S_addr`'s in-memory bytes ARE the network-order octets;
                    // read them as `[u8; 4]`. Round-tripping through
                    // `Ipv4Addr::from(u32)` instead byte-flips on
                    // little-endian (field 2026-08-09: `list_v4` returned
                    // 2.0.64.100 for 100.64.0.2, so the SkipAsSource
                    // reconcile compared garbage geometry and silently
                    // no-opped on the very host it exists for). Locked by
                    // `sockaddr_v4_roundtrip`.
                    let a = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
                    out.push((a, row.OnLinkPrefixLength, row.SkipAsSource));
                }
                FreeMibTable(table as _);
            }
            Ok(out)
        }
    }

    /// rc.288 — prefix length of an IPv4 netmask, e.g. `255.192.0.0` yields
    /// `Some(10)`. Pure. `None` for a non-contiguous mask (never produced by
    /// the server's CIDR, but a wrong guess would mis-target a defended
    /// route, so it is rejected rather than approximated).
    ///
    /// `cfg(windows)`: the only caller is the Windows connected-route
    /// defense, so an ungated definition is dead code on Linux — which the
    /// Linux-only clippy lane rejects and a Windows-only local gate can never
    /// see (the inverse of the usual "CI never compiles cfg(windows)" trap).
    #[cfg(windows)]
    fn prefix_len_of_mask(mask: Ipv4Addr) -> Option<u8> {
        let m = u32::from_be_bytes(mask.octets());
        let ones = m.leading_ones();
        (m == if ones == 0 { 0 } else { !0u32 << (32 - ones) }).then_some(ones as u8)
    }

    /// A live OS TUN device. `tun::AsyncDevice::{recv,send}` take `&self`,
    /// so a single `Arc<AsyncDevice>` backs the bridge's concurrent read
    /// + write loops.
    pub struct SystemTun {
        dev: Arc<tun::AsyncDevice>,
        /// The interface name the OS actually gave this device.
        ///
        /// On Windows and Linux it is the REQUESTED name ([`IF_NAME`] for
        /// the legacy [`up`](Self::up); per-org names via
        /// [`up_with`](Self::up_with)), because the device is
        /// created BY that name. On macOS it cannot be: utun numbers are
        /// kernel-assigned (`utun3`, `utun7`, …), so a hardcoded name meant
        /// every `ifconfig`/`route` call there addressed an interface that
        /// does not exist — which is exactly why the whole macOS routing
        /// surface used to be a set of no-ops. Captured once at bring-up.
        if_name: String,
        /// Multi-org v2 — the derived-ULA on-link prefix length assigned to
        /// THIS adapter (96 = the whole ULA, the single-adapter legacy;
        /// per-org adapters carry 96 + their v4 block plen). Stored so
        /// per-adapter consumers can read the device's v6 geometry — see
        /// [`Self::v6_onlink_plen`].
        v6_onlink_plen: u8,
        /// rc.288 — the CONNECTED overlay prefix (`100.64.0.0/10`), derived at
        /// bring-up from the assigned address + netmask. Defended at metric 0
        /// alongside the peer `/32`s: when a `/32` is momentarily missing,
        /// traffic falls through to this prefix, and a corp VPN that mirrors
        /// the whole `/10` (AnyConnect) otherwise captures it — the CORPLAP
        /// failure mode. `None` on a non-contiguous mask.
        #[cfg(windows)]
        connected_v4: Option<(Ipv4Addr, u8)>,
        /// P5 — the host's ORIGINAL default route (gateway + interface), captured
        /// at bring-up BEFORE any overlay route can shadow it. Used to pin
        /// exit-node carrier-endpoint exemption `/32`s via the real uplink (see
        /// [`TunIo::add_host_exemption`]). `None` when discovery failed — the
        /// split-tunnel check (S4) then surfaces a WARN rather than wedging.
        ///
        /// FR-97 P0e (N12) — no longer final: [`TunIo::stale_host_exemptions`]
        /// re-reads it on every sweep and adopts an uplink that moved, so the
        /// pins follow the host to another network as they do on macOS. A
        /// family with no usable default at the moment keeps the one it had.
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        orig_default: std::sync::Mutex<Option<OrigDefaultRoute>>,
        /// P5/S3b — the host's ORIGINAL IPv6 default route (gateway + interface),
        /// captured at bring-up. Pins v6 `/128` carrier exemptions (the
        /// coordination server's AAAA) so the WS control channel stays direct
        /// while global v6 routes through the exit. `None` when the host has no v6
        /// default (v4-only uplink) — v6 egress then stays fail-closed.
        /// Re-read like `orig_default` (N12).
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        orig_default_v6: std::sync::Mutex<Option<OrigDefaultRoute6>>,
        /// FR-97 P1a — the macOS twin of `orig_default` / `orig_default_v6`:
        /// the uplink each family's exemptions are pinned through. Captured
        /// at bring-up like them, but re-read before every pin and by
        /// [`TunIo::stale_host_exemptions`], because a Mac changes networks
        /// under a running daemon (Wi-Fi ↔ Ethernet, a new SSID) and a `/32`
        /// left on the old next hop black-holes the endpoint it was pinned
        /// for. A family that has no usable default at the moment keeps the
        /// one it had: a network in transit is no reason to touch the pins.
        #[cfg(target_os = "macos")]
        uplinks: std::sync::Mutex<BsdUplinks>,
        /// WFP hard-permit guard. Holds a dynamic WFP session whose `Drop`
        /// reaps the `roomler`-adapter permit filters, so it must live as
        /// long as the device. `None` when disabled
        /// (`ROOMLERD_WFP_PERMIT=0`) or when install failed
        /// (best-effort — the overlay still works on non-locked hosts).
        #[cfg(windows)]
        _wfp: Option<crate::overlay::wfp::WfpGuard>,
        /// Change B — the last block-floor decision per BLOCK (1 = safe /
        /// asserted, 2 = withheld), so the defense wave logs the DECISION
        /// only when it flips instead of once per 2–30 s wave. Keyed by
        /// block because a shared multi-org device floors one block per org
        /// (historically one per shared-mux org port), and
        /// their decisions flip independently.
        #[cfg(windows)]
        floor_state: std::sync::Mutex<Vec<((Ipv4Addr, u8), u8)>>,
        /// corplap route war v3 (#23) — fingerprint of the FOREIGN in-block route
        /// set per block, from the last wave that ran the blind in-block
        /// eviction. The wave re-evicts only when the set CHANGED: a corp
        /// route monitor re-adds the same rows within seconds of every
        /// deletion, so the unconditional per-wave eviction was a permanent
        /// route-table flap (delete → re-add → delete …) feeding the
        /// netstate watcher a Major every few waves and forcing carrier
        /// pokes fleet-wide on the host. An UNCHANGED competing set sits in
        /// the table losing every lookup (the reclaim step repoints any
        /// destination it actually captures), which is a stable détente the
        /// OS never reports as change. Keyed by block, like `floor_state`.
        #[cfg(windows)]
        in_block_fp: std::sync::Mutex<Vec<((Ipv4Addr, u8), u64)>>,
        /// rc.411 (#23) — peers whose `/32` has been ESCALATED to route
        /// metric 0 because a foreign interface out-ranked us for them even
        /// at our pinned interface metric (the equal-interface-metric tie:
        /// winhost-a's Check Point NIC and winhost-b's both sit at interface
        /// metric 0 like ours, so a mirrored row at route metric 1 would tie
        /// our route-1 + interface-0 total and win on lower ifIndex —
        /// exactly what corplap demonstrated at 1-vs-1).
        ///
        /// Sticky for the process, and consulted by
        /// [`TunIo::add_peer_route`]: the defense wave re-asserts every
        /// `/32` on each pass, so without this the escalated metric would be
        /// reset to 1 and re-escalated every wave — a delete-then-add flap
        /// on the very prefix we are trying to stabilise (the churn the
        /// in-block debounce exists to prevent). Never shrinks: metric 0
        /// stays correct once the competitor withdraws, and
        /// `winroute::ensure` auto-yields to 1 on hosts where metric-0 rows
        /// do not survive (rc.289).
        #[cfg(windows)]
        escalated: std::sync::Mutex<std::collections::HashSet<Ipv4Addr>>,
        /// Linux — the virtio-net framing and TSO/GRO state of a device opened
        /// with offload; `None` is the plain one-packet-per-call device.
        #[cfg(target_os = "linux")]
        vnet: Option<crate::overlay::tun_offload::VnetIo>,
    }

    /// rc.209 — bounded retry-with-backoff around a fallible create. Returns the
    /// first `Ok`; otherwise the LAST `Err` after `attempts` tries. Sleeps
    /// `backoff` between attempts (never after the final one), and calls
    /// `on_retry(attempt, &err)` before each backoff (for logging). Extracted so
    /// the Wintun-adapter retry policy — the fix for the transient
    /// device-install-mutex "Access is denied" on a rapid restart — is
    /// unit-tested without a real device. `attempts` is clamped to ≥1.
    fn retry_create<T, E>(
        attempts: usize,
        backoff: std::time::Duration,
        mut f: impl FnMut() -> Result<T, E>,
        mut on_retry: impl FnMut(usize, &E),
    ) -> Result<T, E> {
        let attempts = attempts.max(1);
        let mut last_err = None;
        for attempt in 1..=attempts {
            match f() {
                Ok(t) => return Ok(t),
                Err(e) => {
                    if attempt < attempts {
                        on_retry(attempt, &e);
                        std::thread::sleep(backoff);
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("attempts >= 1 ⇒ f ran at least once"))
    }

    /// P9 — one-shot Windows network hygiene at TUN bring-up (call site in
    /// [`SystemTun::up`]). Two consumer-box gaps, both field-hit 2026-07-28:
    ///
    /// * **Inbound-allow firewall rule for THIS binary's UDP** (the WG socket
    ///   on the PHYSICAL adapters): a fresh install has none, so unsolicited
    ///   WG dials (LAN direct, srflx punch) die at the Public profile's
    ///   default-deny. A home laptop could not accept LAN-direct until exactly
    ///   this rule was added by hand. Rule name carries the exe stem so
    ///   `roomlerd` and the `roomler` tunnel client don't fight; delete+add
    ///   keeps the recorded program path current across upgrades. The ONE
    ///   definition is [`crate::winfw::UdpInAllowRule`], shared with the SCM
    ///   service host — #1698: P9's premise that "a Windows *service* never
    ///   gets the interactive prompt" holds for a SYSTEM worker only. The
    ///   ATTENDED worker runs in the signed-in user's session, bound its UDP
    ///   before this detached thread had added the rule, got the prompt, and
    ///   the prompt's Block rules beat this Allow on every Public network. So
    ///   the host now installs the rule BEFORE the first worker spawn, and this
    ///   pass is the self-heal — which heals only when the store does not
    ///   already hold exactly our rule, because delete+add is not atomic and a
    ///   bind landing in that gap is the same prompt again.
    /// * **`NetworkCategory=Private` for the roomler adapter**: belt and
    ///   braces for hosts where the WFP hard-permit could not install
    ///   (GPO-locked) — an Unidentified-network TUN otherwise lands in the
    ///   Public profile.
    ///
    /// Detached thread: netsh/PowerShell are slow and the connection-profile
    /// registration can lag the adapter by seconds — bring-up must not block.
    /// Every step best-effort (an unelevated tunnel client simply can't do
    /// this; the overlay still runs — relay-side — without it).
    ///
    /// Multi-org v2 — `if_name` is THIS adapter's OS name (the
    /// Private-profile set addresses the alias); the firewall rule half is
    /// per-binary and unaffected.
    #[cfg(windows)]
    fn spawn_windows_net_hygiene(if_name: String) {
        if crate::winfw::hygiene_disabled(crate::env::node_env("TUN_HYGIENE").as_deref()) {
            tracing::info!("overlay: Windows net hygiene disabled via ROOMLERD_TUN_HYGIENE");
            return;
        }
        std::thread::spawn(move || {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            // Per netsh call. This thread is detached, so the bound only
            // keeps a wedged firewall service from pinning the thread forever.
            const NETSH_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
            // 1) Inbound-allow for this binary's UDP, all profiles — the ONE
            //    definition in `crate::winfw`, shared with the SCM service host
            //    (#1698). Heal only when the store does not already hold
            //    exactly our rule: delete+add is not atomic, and in the gap an
            //    attended worker's next bind has no rule for its path.
            if let Some(rule) = crate::winfw::UdpInAllowRule::for_current_exe() {
                if crate::winfw::current_rule_present(&rule) == Some(true) {
                    tracing::debug!(
                        rule = %rule.name,
                        "overlay: firewall inbound-UDP allow already current; nothing to heal"
                    );
                } else {
                    use crate::winfw::EnsureOutcome;
                    match crate::winfw::ensure_udp_in_allow(&rule, NETSH_CALL_TIMEOUT) {
                        EnsureOutcome::Installed => tracing::info!(
                            rule = %rule.name,
                            "overlay: firewall inbound-UDP allow installed for this binary"
                        ),
                        EnsureOutcome::AddFailed { status, stderr } => tracing::debug!(
                            rule = %rule.name, ?status, %stderr,
                            "overlay: firewall rule add failed (unelevated?)"
                        ),
                        EnsureOutcome::Failed(e) => {
                            tracing::debug!(rule = %rule.name, %e, "overlay: netsh unavailable")
                        }
                    }
                }
            }
            // 2) THIS overlay adapter → Private profile (registration lags
            //    the adapter, so retry over ~12 s before giving up quietly).
            let alias = if_name.replace('\'', "''");
            for attempt in 1..=6u32 {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let ok = std::process::Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &format!(
                            "Set-NetConnectionProfile -InterfaceAlias '{alias}' \
                             -NetworkCategory Private -ErrorAction Stop"
                        ),
                    ])
                    .creation_flags(CREATE_NO_WINDOW)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok {
                    tracing::info!(
                        attempt,
                        adapter = %if_name,
                        "overlay: overlay adapter profile set to Private"
                    );
                    return;
                }
            }
            tracing::debug!(
                adapter = %if_name,
                "overlay: could not set the overlay adapter profile to Private \
                 (unelevated, or no connection profile registered)"
            );
        });
    }

    /// rc.279 — the roomler overlay adapter's constant requested GUID (see
    /// the `device_guid` call in [`SystemTun::up_with`]). The value is
    /// arbitrary but MUST stay fixed forever: Windows keys the interface's
    /// persistent identity on it (the ifIndex/LUID mapping and the NLA
    /// network signature that decides the firewall profile).
    ///
    /// Ungated (multi-org v2): [`TunOptions::legacy`] and [`org_tun_guid`]
    /// reference it on every platform; only the `device_guid` platform call
    /// itself is Windows-only.
    const ROOMLER_TUN_GUID: u128 = 0xB5A7_D160_53F8_4E2D_9A6B_2C4E_71A0_D5C3;

    /// Multi-org v2 — a stable per-(machine,org) Wintun GUID: SHA-256 of
    /// "roomler-tun-v1" ‖ base GUID ‖ tenant_id, truncated to 128 bits with the
    /// RFC 4122 version/variant bits forced (version 4 shape). Stable across
    /// restarts and adapter recreates — the rc.279 identity property, per org.
    pub fn org_tun_guid(tenant_id: &str) -> u128 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"roomler-tun-v1");
        h.update(ROOMLER_TUN_GUID.to_be_bytes());
        h.update(tenant_id.as_bytes());
        let digest = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&digest[..16]);
        b[6] = (b[6] & 0x0F) | 0x40; // version 4 shape
        b[8] = (b[8] & 0x3F) | 0x80; // RFC 4122 variant
        u128::from_be_bytes(b)
    }

    /// Multi-org v2 — per-adapter identity for [`SystemTun::up_with`]. The
    /// legacy [`SystemTun::up`] fills the historical single-adapter values
    /// (via [`TunOptions::legacy`]), so single-org behavior is byte-identical.
    /// macOS ignores `name`/`guid` (utun names are kernel-assigned).
    pub struct TunOptions {
        pub name: String,
        pub guid: u128,
        pub ip: Ipv4Addr,
        pub netmask: Ipv4Addr,
        pub mtu: u16,
        /// The derived-ULA on-link prefix length for THIS adapter. 96 = the whole
        /// ULA (single-adapter legacy). Per-org adapters pass 96 + v4_plen so N
        /// adapters hold disjoint embedded v6 prefixes (a /22 org block → /118).
        pub v6_onlink_plen: u8,
    }

    impl TunOptions {
        /// The historical single-adapter identity — exactly what
        /// [`SystemTun::up`] has always requested ([`IF_NAME`], the rc.279
        /// constant GUID, the whole-ULA `/96`), so `up()` delegating through
        /// here stays byte-identical single-org behavior. Pure, so the
        /// legacy values are locked by a unit test without a real device.
        pub fn legacy(ip: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> Self {
            Self {
                name: IF_NAME.to_string(),
                guid: ROOMLER_TUN_GUID,
                ip,
                netmask,
                mtu,
                v6_onlink_plen: crate::overlay::router::OVERLAY_V6_ONLINK_PREFIX,
            }
        }
    }

    /// rc.279 — kill-switch for the stable adapter identity (constant
    /// requested GUID + boot stray-adapter sweep):
    /// `ROOMLERD_OVERLAY_TUN_STABLE_GUID` (the older `ROOMLER_NODE_…`
    /// honoured; config key `overlay_tun_stable_guid`). Default **ON**;
    /// `0`/`false`/`no`/`off` reverts to the pre-rc.279 random-GUID
    /// adapters if the undocumented requested-GUID path ever misbehaves on
    /// some host (the wintun README flags sysprep/clone interop).
    #[cfg(target_os = "windows")]
    fn stable_guid_enabled() -> bool {
        crate::env::flag("OVERLAY_TUN_STABLE_GUID", true)
    }

    /// rc.279 — kill-switch for the route-war eviction (peer `/32`s since
    /// rc.208, our own `/32` since rc.278): `ROOMLERD_OVERLAY_ROUTE_EVICT`
    /// (the older `ROOMLER_NODE_…` honoured; config key `overlay_route_evict`).
    /// Default **ON** — without it the overlay is unusable under a hostile
    /// full-tunnel VPN — but managed sites whose security tooling alarms on
    /// route deletion can turn it off and accept that trade.
    #[cfg(windows)]
    fn route_evict_enabled() -> bool {
        crate::env::flag("OVERLAY_ROUTE_EVICT", true)
    }

    /// #1405 — evict a competing route only when it WINS the FIB decision
    /// (`ROOMLERD_OVERLAY_ROUTE_EVICT_WINNERS_ONLY`, config
    /// `overlay_route_evict_winners_only`). Default **ON**. A competitor row
    /// that loses every lookup carries no traffic, while deleting it is a
    /// route-change event that re-arms the guard. `0` restores evicting every
    /// competing row on every wave.
    #[cfg(windows)]
    fn route_evict_winners_only_enabled() -> bool {
        crate::env::flag("OVERLAY_ROUTE_EVICT_WINNERS_ONLY", true)
    }

    /// #1328 — how long to stand down from a prefix after `yields` consecutive
    /// futile defend-cycles: 30 s, doubling, capped at 15 min.
    ///
    /// Deliberately OUTSIDE `#[cfg(windows)]` even though its only caller is
    /// the Windows route guard. It is pure arithmetic with no OS dependency,
    /// and CI's Rust lane is **Linux** — a windows-gated ladder would compile
    /// and test nowhere that CI can see, which is how the `Own::luid`
    /// dead-code failure got in earlier in this arc.
    ///
    /// The shape, and why each end is where it is:
    /// - **30 s floor.** A stand-down costs nothing while the route is already
    ///   gone, but it delays recovery once the competitor leaves, and the
    ///   common competitor (a VPN) disconnects on human timescales.
    /// - **15 min cap.** ⚠️ The ladder must never grow unbounded: a host that
    ///   yielded for hours would look identical to a host whose guard is
    ///   broken, and a returning VPN-free window would go unused.
    /// - ⚠️ **Never 0.** A zero cooldown restores the unbounded fight this
    ///   exists to stop, so the floor is a `max`, not a comment.
    ///
    /// ⚠️ The `allow` is the price of that placement: CI's workspace clippy
    /// runs WITHOUT `--all-targets`, so the `#[cfg(test)]` module below is not
    /// compiled there and the only non-test caller is `#[cfg(windows)]` — i.e.
    /// on the Linux lane this really is dead, and honestly so.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn yield_backoff(yields: u32) -> std::time::Duration {
        // `1 << yields` with `yields` clamped first: shifting by ≥64 is UB-adjacent
        // (a debug panic, a wrapped shift in release), and this takes a
        // saturating counter.
        let step = 30u64.saturating_mul(1u64 << yields.min(5));
        std::time::Duration::from_secs(step.clamp(30, 900))
    }

    /// #1405 — the address a competing-route eviction asks the FIB about: the
    /// destination itself for a host route, else the first address inside the
    /// prefix. Pure and outside `cfg(windows)` for the same reason as
    /// [`yield_backoff`]: CI's Rust lane is Linux.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn eviction_probe(dest: std::net::IpAddr, plen: u8) -> std::net::IpAddr {
        match dest {
            std::net::IpAddr::V4(a) if plen < 32 => {
                std::net::IpAddr::V4(Ipv4Addr::from(u32::from(a) | 1))
            }
            std::net::IpAddr::V6(a) if plen < 128 => {
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(a) | 1))
            }
            other => other,
        }
    }

    /// #1405 — consecutive waves on which this prefix had to be evicted
    /// AGAIN: the competitor put its row straight back after the last delete.
    #[cfg_attr(not(windows), allow(dead_code))]
    const EVICTIONS_TO_STAND_DOWN: u32 = 4;
    /// #1405 — an eviction this soon after the previous one continues the
    /// streak: 3 heartbeats, so a war at the 30 s heartbeat counts as
    /// consecutive while a competitor that returns an hour later does not.
    #[cfg_attr(not(windows), allow(dead_code))]
    const EVICT_STREAK_GAP: std::time::Duration = std::time::Duration::from_secs(90);
    /// #1405 — this long without a single eviction resets the backoff ladder:
    /// the competitor left, and the next one gets a fresh hearing.
    #[cfg_attr(not(windows), allow(dead_code))]
    const EVICT_LADDER_RESET: std::time::Duration = std::time::Duration::from_secs(1800);

    /// #1405 — eviction futility for one prefix.
    ///
    /// AnyConnect mirrors our prefixes onto its miniport and re-adds a deleted
    /// mirror within milliseconds. A competitor row that WINS every lookup and
    /// comes straight back is therefore never actually beaten by deleting it.
    /// The deletion only churns the FIB, and every deletion is a route-change
    /// event that re-arms the route guard 3 s later. Field, CORPLAP-3 on
    /// 0.4.121: ~200 evictions/min, `pulled == tick`. After
    /// [`EVICTIONS_TO_STAND_DOWN`] consecutive evictions the prefix pauses for
    /// [`yield_backoff`] (1 min, doubling, capped at 15 min). The pause costs
    /// nothing, because between evictions the competitor was winning anyway.
    #[derive(Debug, Default, Clone, Copy)]
    #[cfg_attr(not(windows), allow(dead_code))]
    struct EvictStreak {
        n: u32,
        yields: u32,
        last: Option<std::time::Instant>,
        paused_until: Option<std::time::Instant>,
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    impl EvictStreak {
        fn paused(&self, now: std::time::Instant) -> bool {
            self.paused_until.is_some_and(|t| now < t)
        }

        /// Record one eviction at `now`. `Some(backoff)` when this one makes
        /// the streak futile and evicting this prefix should pause.
        fn evicted(&mut self, now: std::time::Instant) -> Option<std::time::Duration> {
            let gap = self.last.map(|t| now.saturating_duration_since(t));
            if gap.is_none_or(|g| g > EVICT_LADDER_RESET) {
                self.yields = 0;
            }
            self.n = if gap.is_some_and(|g| g <= EVICT_STREAK_GAP) {
                self.n + 1
            } else {
                1
            };
            self.last = Some(now);
            if self.n < EVICTIONS_TO_STAND_DOWN {
                return None;
            }
            self.yields = self.yields.saturating_add(1);
            let back = yield_backoff(self.yields);
            self.paused_until = Some(now + back);
            self.n = 0;
            Some(back)
        }
    }

    #[cfg(test)]
    mod evict_futility_tests {
        use super::{EvictStreak, eviction_probe};
        use std::net::IpAddr;
        use std::time::{Duration, Instant};

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        /// A host route is probed as itself; a prefix by its first address, so
        /// the lookup lands INSIDE the contested prefix (the ULA `/96`, a
        /// narrowed org prefix, a floor) and not on its network address.
        #[test]
        fn probe_is_the_host_or_the_first_address_inside_the_prefix() {
            assert_eq!(eviction_probe(ip("100.65.4.14"), 32), ip("100.65.4.14"));
            assert_eq!(eviction_probe(ip("100.65.7.0"), 24), ip("100.65.7.1"));
            assert_eq!(
                eviction_probe(ip("fd72:6f6f:6d6c::"), 96),
                ip("fd72:6f6f:6d6c::1")
            );
            assert_eq!(
                eviction_probe(ip("fd72:6f6f:6d6c::6441:400"), 118),
                ip("fd72:6f6f:6d6c::6441:401")
            );
            assert_eq!(
                eviction_probe(ip("fd72:6f6f:6d6c::6441:41e"), 128),
                ip("fd72:6f6f:6d6c::6441:41e")
            );
        }

        /// The CORPLAP-3 shape: an eviction every 3 s wave stands down on the
        /// 4th, pauses for the ladder's rung, then probes once and climbs.
        #[test]
        fn evictions_that_keep_coming_back_stand_down_and_climb_the_ladder() {
            let t0 = Instant::now();
            let at = |s: u64| t0 + Duration::from_secs(s);
            let mut s = EvictStreak::default();
            assert_eq!(s.evicted(at(0)), None);
            assert_eq!(s.evicted(at(3)), None);
            assert_eq!(s.evicted(at(6)), None);
            assert_eq!(s.evicted(at(9)), Some(Duration::from_secs(60)));
            assert!(s.paused(at(10)) && s.paused(at(68)) && !s.paused(at(69)));
            // After the pause the competitor is still there: the next streak
            // stands down again, one rung higher.
            for t in [70, 73, 76] {
                assert_eq!(s.evicted(at(t)), None);
            }
            assert_eq!(s.evicted(at(79)), Some(Duration::from_secs(120)));
        }

        /// An eviction that sticks (the competitor does not come back) never
        /// pauses anything, and a long quiet spell resets the ladder.
        #[test]
        fn evictions_spread_out_never_pause_and_quiet_resets_the_ladder() {
            let t0 = Instant::now();
            let at = |s: u64| t0 + Duration::from_secs(s);
            let mut s = EvictStreak::default();
            for k in 0..10 {
                assert_eq!(
                    s.evicted(at(k * 120)),
                    None,
                    "2-minute gaps are not a streak"
                );
            }
            let mut w = EvictStreak::default();
            for t in [0, 3, 6] {
                w.evicted(at(t));
            }
            assert_eq!(w.evicted(at(9)), Some(Duration::from_secs(60)));
            // 2 h later a new competitor: a fresh hearing, rung 1 again.
            let later = 9 + 7200;
            for t in [later, later + 3, later + 6] {
                assert_eq!(w.evicted(at(t)), None);
            }
            assert_eq!(w.evicted(at(later + 9)), Some(Duration::from_secs(60)));
        }
    }

    #[cfg(test)]
    mod yield_backoff_tests {
        use super::yield_backoff;

        /// The ladder's contract: monotone, bounded at both ends, and — the
        /// load-bearing one — never zero at any input including the saturated
        /// tail, because a 0 s cooldown is the unbounded route war again.
        #[test]
        fn ladder_is_monotone_bounded_and_never_zero() {
            assert_eq!(yield_backoff(1).as_secs(), 60);
            assert_eq!(yield_backoff(2).as_secs(), 120);
            assert_eq!(yield_backoff(3).as_secs(), 240);
            assert_eq!(yield_backoff(4).as_secs(), 480);
            // Rung 5 would be 960 s; the cap bites here and holds forever after.
            assert_eq!(yield_backoff(5).as_secs(), 900);
            assert_eq!(yield_backoff(6).as_secs(), 900);
            assert_eq!(yield_backoff(u32::MAX).as_secs(), 900);

            let mut prev = 0;
            for y in 0..64u32 {
                let s = yield_backoff(y).as_secs();
                assert!((30..=900).contains(&s), "rung {y} left the bounds: {s}");
                assert!(s >= prev, "rung {y} went backwards");
                prev = s;
            }
        }

        /// `yields` is 1 on the first stand-down (it is incremented before the
        /// call), so rung 0 is unreachable in production — but it must still be
        /// a legal 30 s rather than 0, since nothing in the type system stops a
        /// future caller from passing it.
        #[test]
        fn rung_zero_is_the_floor_not_zero() {
            assert_eq!(yield_backoff(0).as_secs(), 30);
        }
    }

    /// #1328 — kill-switch for the generalised stand-down:
    /// `ROOMLERD_OVERLAY_ROUTE_YIELD`. Default **ON**.
    ///
    /// Default-on because the alternative is measured, not hypothetical: with
    /// the yield gated to metric-0 (and metric-0 itself default-off), a
    /// metric-1 war could never self-limit, and CORPLAP-3 was recorded at
    /// **437 evictions/min — ~629 k/day**, roughly 20x the previous worst.
    ///
    /// ⚠️ Turning it OFF restores an unbounded fight. It exists for a site
    /// that would rather burn the CPU than ever leave a competitor holding a
    /// prefix — not as a routine tuning knob.
    #[cfg(windows)]
    fn route_yield_enabled() -> bool {
        crate::env::flag("OVERLAY_ROUTE_YIELD", true)
    }

    /// #1237 — a multi-org host runs ONE daemon with N overlay adapters
    /// (`roomler`, `roomler-<org>`, …). The route-eviction helpers below were
    /// written for one adapter per host (the corp-VPN route war) and delete
    /// any competing row on "an interface other than ours" — so on a multi-org
    /// host each org runtime's guard wave deletes the OTHER org's derived-ULA
    /// `/96` (and block on-link) routes, the other re-asserts them, and the two
    /// ping-pong ~40×/min per prefix. Every deletion is a route-change
    /// notification that force-rekeys every peer (neo16 2026-09-02: 718
    /// evictions/day → ~100 revalidations/min). Default ON = exempt sibling
    /// roomler adapters (this process's own LUIDs, plus any adapter whose alias
    /// matches our naming — the belt for a second co-tenant process). OFF =
    /// the pre-#1237 "only the exact `ours` LUID is spared" behaviour.
    #[cfg(windows)]
    fn sibling_exempt_enabled() -> bool {
        crate::env::flag("OVERLAY_SIBLING_EXEMPT", true)
    }

    /// #1237 — default ON: `defend_self_route` asserts/evicts only THIS
    /// adapter's narrowed derived-ULA prefix (`v6_onlink_plen`: `/96` for the
    /// legacy single-org identity, `/(96+block_plen)` for a per-org adapter),
    /// so two orgs defend DISJOINT v6 prefixes instead of both fighting over
    /// the whole `fd72:6f6f:6d6c::/96`. OFF = the pre-#1237 whole-`/96`
    /// assertion (byte-identical for a single-org host either way).
    #[cfg(windows)]
    fn v6_defend_narrow_enabled() -> bool {
        crate::env::flag("OVERLAY_V6_DEFEND_NARROW", true)
    }

    /// #1237 — process-wide registry of the daemon's OWN overlay TUN adapters,
    /// so the eviction helpers never delete a sibling org adapter's route and
    /// the block-floor gate never counts a sibling's overlay address as a
    /// foreign CGNAT address. Keyed by interface name (unique per adapter:
    /// `roomler`, `roomler-<org>`, `utunN`); the value is the Windows LUID
    /// (`0` off-Windows, where the registry is populated but unconsumed). An
    /// entry is added at the end of [`SystemTun::up_with`] and removed by
    /// [`SystemTun`]'s `Drop`; the Windows caches hold each `Arc<SystemTun>`
    /// for the process lifetime, so the registry stays populated exactly while
    /// the adapter is live.
    mod own_adapters {
        use std::collections::BTreeMap;
        use std::net::Ipv4Addr;
        use std::sync::Mutex;

        /// One live adapter of ours: its LUID, and the connected v4 block it
        /// serves (`None` when the mask was unknown at bring-up).
        struct Own {
            /// Read only by [`is_own_luid`], which is Windows-only — so on
            /// every other target this reads as dead code while still being
            /// written on both. Same shape (and same reason) as
            /// `defended_ula_prefix`'s `cfg_attr` below.
            #[cfg_attr(not(windows), allow(dead_code))]
            luid: u64,
            block: Option<(Ipv4Addr, u8)>,
        }

        static OWN: Mutex<BTreeMap<String, Own>> = Mutex::new(BTreeMap::new());

        /// Do two v4 blocks overlap? True when either contains the other —
        /// mask both to the SHORTER prefix and compare. Nesting counts: a
        /// legacy `/10` org and a carved `/22` inside it are "disjoint" under
        /// no useful definition.
        fn blocks_overlap(a: (Ipv4Addr, u8), b: (Ipv4Addr, u8)) -> bool {
            let p = a.1.min(b.1);
            if p == 0 {
                return true;
            }
            if p > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - u32::from(p));
            (u32::from(a.0) & mask) == (u32::from(b.0) & mask)
        }

        /// The already-registered sibling whose block overlaps `mine`, if any.
        ///
        /// Split out of [`register`] so the DECISION is unit-testable without a
        /// tracing capture — `register` then only formats the WARN. That
        /// matters more than usual here: the field condition this guards
        /// (a legacy `/10` org beside a carved `/22`) is currently
        /// unreachable in production, because FR-47 moved every org onto a
        /// carved block and the registry hands out disjoint ones. Without a
        /// test the guard would be unverifiable code protecting against a
        /// regression nobody can stage.
        fn overlapping_sibling(
            existing: &BTreeMap<String, Own>,
            if_name: &str,
            mine: (Ipv4Addr, u8),
        ) -> Option<(String, (Ipv4Addr, u8))> {
            existing.iter().find_map(|(name, other)| {
                if name == if_name {
                    return None;
                }
                let theirs = other.block?;
                blocks_overlap(mine, theirs).then(|| (name.clone(), theirs))
            })
        }

        pub(super) fn register(if_name: &str, luid: u64, block: Option<(Ipv4Addr, u8)>) {
            if let Ok(mut g) = OWN.lock() {
                // FR-68 C2(b) — FR-64 C2 asked for a WARN when two orgs' blocks
                // overlap and it was never implemented. It matters because
                // `defended_ula_prefix` derives each adapter's defended v6
                // prefix FROM this block: disjoint blocks give disjoint
                // prefixes and the #1237 sibling war stays closed, but NESTED
                // blocks (a legacy /10 org beside a carved /22) give nested
                // prefixes and it can silently re-open.
                //
                // ⚠️ This is a detector, not a fix — the prefixes are still
                // nested afterwards. It makes the condition attributable
                // instead of silent, which is the whole reason the CORPLAP-3
                // diagnosis was cheap and this one was not.
                if let Some(mine) = block
                    && let Some((sibling, theirs)) = overlapping_sibling(&g, if_name, mine)
                {
                    tracing::warn!(
                        adapter = %if_name,
                        block = %format_args!("{}/{}", mine.0, mine.1),
                        sibling = %sibling,
                        sibling_block = %format_args!("{}/{}", theirs.0, theirs.1),
                        "overlay: two of our adapters serve OVERLAPPING v4 blocks — \
                         their derived-ULA v6 prefixes nest instead of being disjoint, \
                         so the per-adapter route defense can fight itself (#1237). \
                         Renumber one org onto its own block."
                    );
                }
                g.insert(if_name.to_string(), Own { luid, block });
            }
        }

        pub(super) fn deregister(if_name: &str) {
            if let Ok(mut g) = OWN.lock() {
                g.remove(if_name);
            }
        }

        /// Is `luid` one of our own live adapters? (Never matches `0`, the
        /// off-Windows placeholder, so a stray `0`-LUID row is not exempted.)
        #[cfg(windows)]
        pub(super) fn is_own_luid(luid: u64) -> bool {
            luid != 0
                && OWN
                    .lock()
                    .map(|g| g.values().any(|v| v.luid == luid))
                    .unwrap_or(false)
        }

        /// FR-97 N14 — is `name` one of our own live adapters? Off Windows
        /// the registry key is the device name netstate's lookup reports
        /// (`roomler0`, or the kernel-assigned `utunN`).
        #[cfg(not(windows))]
        pub(super) fn is_own_name(name: &str) -> bool {
            OWN.lock().map(|g| g.contains_key(name)).unwrap_or(false)
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn nested_blocks_count_as_overlapping() {
                let legacy = (Ipv4Addr::new(100, 64, 0, 0), 10);
                let carved = (Ipv4Addr::new(100, 65, 4, 0), 22);
                assert!(
                    blocks_overlap(legacy, carved),
                    "a carved /22 sits INSIDE the legacy /10 — the case that \
                     re-opens #1237, and the reason this is not an equality test"
                );
                assert!(blocks_overlap(carved, legacy), "and symmetrically");
            }

            #[test]
            fn disjoint_carved_blocks_do_not_warn() {
                let a = (Ipv4Addr::new(100, 65, 4, 0), 22);
                let b = (Ipv4Addr::new(100, 65, 8, 0), 22);
                assert!(!blocks_overlap(a, b));
                assert!(!blocks_overlap(b, a));
            }

            #[test]
            fn a_block_overlaps_itself() {
                let a = (Ipv4Addr::new(100, 65, 4, 0), 22);
                assert!(blocks_overlap(a, a));
            }

            fn reg(entries: &[(&str, Option<(Ipv4Addr, u8)>)]) -> BTreeMap<String, Own> {
                entries
                    .iter()
                    .map(|(n, b)| ((*n).to_string(), Own { luid: 1, block: *b }))
                    .collect()
            }

            /// FR-68 AC9 — the case the WARN exists for: a legacy `/10` org
            /// beside a carved `/22` nested inside it. Their derived-ULA
            /// prefixes nest instead of being disjoint, which is how the
            /// #1237 sibling war re-opens.
            #[test]
            fn a_carved_block_nested_in_a_legacy_ten_is_reported() {
                let existing = reg(&[("roomler", Some((Ipv4Addr::new(100, 64, 0, 0), 10)))]);
                let mine = (Ipv4Addr::new(100, 65, 4, 0), 22);
                let hit = overlapping_sibling(&existing, "roomler-abc", mine);
                assert_eq!(
                    hit,
                    Some(("roomler".to_string(), (Ipv4Addr::new(100, 64, 0, 0), 10))),
                    "the nested pair must be named, and by the SIBLING's block so the \
                     operator knows which org to renumber"
                );
            }

            /// The shipped fleet shape: two carved `/22`s from the global
            /// registry, which is disjoint by construction. A WARN here would
            /// fire on every healthy multi-org host and train people to ignore it.
            #[test]
            fn two_carved_blocks_are_silent() {
                let existing = reg(&[("roomler", Some((Ipv4Addr::new(100, 65, 4, 0), 22)))]);
                let mine = (Ipv4Addr::new(100, 65, 8, 0), 22);
                assert_eq!(overlapping_sibling(&existing, "roomler-abc", mine), None);
            }

            /// A re-registration of the SAME adapter (a reconnect reuses the
            /// name) must not report itself: its block trivially overlaps its
            /// own, which would make every bring-up log a false war.
            #[test]
            fn an_adapter_does_not_report_itself() {
                let mine = (Ipv4Addr::new(100, 65, 4, 0), 22);
                let existing = reg(&[("roomler", Some(mine))]);
                assert_eq!(overlapping_sibling(&existing, "roomler", mine), None);
            }

            /// A sibling registered with an UNKNOWN mask carries no block, and
            /// "unknown" is not "overlapping" — treating it as a hit would warn
            /// about a pairing nobody can act on.
            #[test]
            fn a_sibling_without_a_block_is_not_a_hit() {
                let existing = reg(&[("roomler", None)]);
                let mine = (Ipv4Addr::new(100, 65, 4, 0), 22);
                assert_eq!(overlapping_sibling(&existing, "roomler-abc", mine), None);
            }
        }
    }

    /// #1237 — the derived-ULA v6 prefix THIS adapter should defend/evict for:
    /// the connected v4 block mapped into the ULA and masked to
    /// `v6_onlink_plen` (`/96` for the legacy single-org identity,
    /// `/(96+block_plen)` for a per-org adapter). `connected_v4 == None` (the
    /// v4 mask was unknown at bring-up) falls back to the whole
    /// `fd72:6f6f:6d6c::/96` — the pre-#1237 behaviour. Pure, so the golden
    /// vectors below test it on every platform. Its only non-test caller
    /// (`defend_self_route`) is Windows-only, so it reads as dead code on
    /// other targets while the tests still exercise it.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn defended_ula_prefix(
        connected_v4: Option<(Ipv4Addr, u8)>,
        v6_onlink_plen: u8,
    ) -> (std::net::Ipv6Addr, u8) {
        let whole = || {
            (
                crate::overlay::router::derive_overlay_v6(Ipv4Addr::UNSPECIFIED),
                96u8,
            )
        };
        let Some((net, _)) = connected_v4 else {
            return whole();
        };
        let plen = v6_onlink_plen.min(128);
        (
            mask_v6(crate::overlay::router::derive_overlay_v6(net), plen),
            plen,
        )
    }

    /// Zero every bit of `ip` below prefix length `plen`.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn mask_v6(ip: std::net::Ipv6Addr, plen: u8) -> std::net::Ipv6Addr {
        let bits = u128::from(ip);
        let plen = plen.min(128);
        let mask = if plen == 0 {
            0
        } else {
            u128::MAX << (128 - plen as u32)
        };
        std::net::Ipv6Addr::from(bits & mask)
    }

    #[cfg(test)]
    mod sibling_route_tests {
        use super::{defended_ula_prefix, mask_v6};
        use std::net::{Ipv4Addr, Ipv6Addr};

        #[test]
        fn mask_v6_edges() {
            let ip: Ipv6Addr = "fd72:6f6f:6d6c::6441:400".parse().unwrap();
            assert_eq!(mask_v6(ip, 0), Ipv6Addr::UNSPECIFIED);
            assert_eq!(mask_v6(ip, 128), ip);
            assert_eq!(
                mask_v6(ip, 96),
                "fd72:6f6f:6d6c::".parse::<Ipv6Addr>().unwrap()
            );
        }

        #[test]
        fn legacy_single_org_defends_the_whole_96() {
            // (100.64.0.0/10, plen 96) — byte-identical to the pre-#1237 whole
            // `fd72:6f6f:6d6c::/96` assertion, so a single-org host is unchanged.
            let (net, plen) = defended_ula_prefix(Some((Ipv4Addr::new(100, 64, 0, 0), 10)), 96);
            assert_eq!(net, "fd72:6f6f:6d6c::".parse::<Ipv6Addr>().unwrap());
            assert_eq!(plen, 96);
        }

        #[test]
        fn per_org_defends_its_own_disjoint_block() {
            // A carved /22 block at 100.65.4.0 → v6_onlink_plen 118; two orgs
            // then defend DISJOINT prefixes instead of both fighting the /96.
            let (net_a, plen_a) =
                defended_ula_prefix(Some((Ipv4Addr::new(100, 65, 4, 0), 22)), 118);
            let (net_b, plen_b) =
                defended_ula_prefix(Some((Ipv4Addr::new(100, 65, 8, 0), 22)), 118);
            assert_eq!(plen_a, 118);
            assert_eq!(plen_b, 118);
            assert_ne!(net_a, net_b, "each org's v6 block is distinct");
            // ...and neither is the whole /96.
            assert_ne!(net_a, "fd72:6f6f:6d6c::".parse::<Ipv6Addr>().unwrap());
        }

        #[test]
        fn unknown_mask_falls_back_to_the_whole_96() {
            let (net, plen) = defended_ula_prefix(None, 118);
            assert_eq!(net, "fd72:6f6f:6d6c::".parse::<Ipv6Addr>().unwrap());
            assert_eq!(plen, 96);
        }
    }

    /// #1237 — an interface name that belongs to a roomler overlay adapter:
    /// the primary [`IF_NAME`] or a `roomler-<org>` sibling. Used as the
    /// cross-process belt (a second co-tenant daemon's adapters are not in
    /// THIS process's [`own_adapters`] registry, but they carry our naming)
    /// and by the block-floor gate.
    #[cfg(windows)]
    fn is_roomler_adapter_name(name: &str) -> bool {
        let n = name.trim();
        n == IF_NAME || n.starts_with(&format!("{IF_NAME}-"))
    }

    /// #1237 — may an eviction helper delete a competing row on `row_luid`
    /// while defending `ours`? A row is spared when it is our own adapter, a
    /// sibling org adapter in this process, or (the belt) any adapter whose
    /// alias matches our naming. The kill switch collapses this to the
    /// pre-#1237 exact-LUID test.
    #[cfg(windows)]
    fn route_belongs_to_us(row_luid: u64, ours: u64) -> bool {
        let belongs = adapter_is_ours(row_luid, ours);
        if belongs && row_luid != ours {
            // FR-68 — the exemption FIRING is the observable, not a sibling
            // eviction: after #1246 that row is spared, so an eviction counter
            // reads zero whether the fix works or was reverted. Paired with
            // ROUTE_EVICTIONS this is falsifiable — spares climb while
            // evictions stay flat, and OVERLAY_SIBLING_EXEMPT=0 inverts it.
            //
            // ⚠️ Counted HERE and not in `adapter_is_ours`, because only the
            // eviction path turns a spare into a route that survives. The
            // read-only fingerprint scan asks the same question many times per
            // wave and must not inflate the number.
            crate::evidence::ROUTE_SIBLING_SPARES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        belongs
    }

    /// The same question, with no side effects — for read-only scans that must
    /// not move [`crate::evidence::ROUTE_SIBLING_SPARES`].
    #[cfg(windows)]
    fn adapter_is_ours(row_luid: u64, ours: u64) -> bool {
        if row_luid == ours {
            return true;
        }
        if !sibling_exempt_enabled() {
            return false;
        }
        own_adapters::is_own_luid(row_luid)
            || winroute::alias_for_luid(row_luid).is_some_and(|a| is_roomler_adapter_name(&a))
    }

    /// corplap route war v3 (#23) — gate for the stolen-path reclaim (detect →
    /// targeted evict → pin, [`TunIo::reclaim_stolen_peer_paths`]) AND the
    /// in-block eviction debounce that rides on it (blind per-wave eviction
    /// is what fed the route-flap → netstate-Major → forced-poke treadmill;
    /// with reclaim covering genuine theft on demand, the blind wave only
    /// needs to fire when the foreign row SET changes).
    /// `ROOMLERD_OVERLAY_ROUTE_RECLAIM` (config key
    /// `overlay_route_reclaim`). Default **ON**; OFF restores the pre-rc.409
    /// behaviour exactly (evict every wave, never pin). Subordinate to
    /// [`route_evict_enabled`] — reclaim deletes foreign rows, so the master
    /// eviction kill-switch also disables it.
    #[cfg(windows)]
    fn route_reclaim_enabled() -> bool {
        crate::env::flag("OVERLAY_ROUTE_RECLAIM", true)
    }

    /// rc.287 — install defended peer `/32`s (and assert the ULA `/96` + the
    /// connected `/10`) at route metric **0** instead of 1:
    /// `ROOMLERD_OVERLAY_ROUTE_METRIC0` (config key
    /// `overlay_route_metric0`).
    ///
    /// **rc.289: default flipped to OFF.** Field result on the only host that
    /// motivated it (CORPLAP-3, Cisco AnyConnect): the VPN's route monitor
    /// DELETES any route of ours that would out-rank its own, so metric 0
    /// bought nothing there — and left the prefix unrouted, which broke even
    /// INBOUND replies (remote support into the host stopped working). No
    /// host has yet been shown to benefit: the Check Point fleet
    /// (winhost-a/winhost-b) already wins with eviction at metric 1. A default
    /// with zero demonstrated benefit and one demonstrated regression does
    /// not belong on the fleet — it stays as an opt-in experiment, now
    /// protected by the [`METRIC0_REJECTED`] auto-yield.
    ///
    /// Windows picks routes by `route metric + interface metric`. Cisco
    /// AnyConnect MIRRORS every peer `/32` we install (plus the `/10` and our
    /// ULA `/96`) at metric 1 on its own miniport, whose interface metric is
    /// 1 — a FULL tie against our metric-1 rows that Windows breaks in
    /// Cisco's favor (lower ifIndex), and its route monitor re-adds within
    /// milliseconds of an eviction, so the 2 s guard can never hold the FIB
    /// (CORPLAP-3, 2026-08-01: 25,197 evictions in one day; node-initiated
    /// egress 100 % captured while REPLIES escaped via strong-host
    /// source-constrained routing). Metric 0 wins outright (0+1 < 1+1): no
    /// tie-break, no deletion race. Inert on hosts with no competing routes.
    #[cfg(windows)]
    fn route_metric0_enabled() -> bool {
        crate::env::flag("OVERLAY_ROUTE_METRIC0", false)
    }

    /// The defended-route metric under the rc.287 gate.
    #[cfg(windows)]
    fn defended_route_metric() -> u32 {
        if route_metric0_enabled() { 0 } else { 1 }
    }

    /// #1342 — WIN the contested prefixes outright instead of evicting a
    /// competitor off them forever: `ROOMLERD_OVERLAY_ROUTE_WIN` (config key
    /// `overlay_route_win`), default **OFF**.
    ///
    /// ⚠️ It is named `route`, not `v6`, because it moves BOTH prefixes that
    /// share [`ula_route_metric`] — the derived-ULA `/96` **and the CONNECTED
    /// v4 prefix** (the carved block, or the legacy `/10`).
    ///
    /// The v4 half is rc.288's unfinished business. That comment already
    /// records the failure — *"AnyConnect mirrors the whole /10 at effective
    /// metric 2 while our connected route sits at 257, so the fall-through
    /// lands in the corp tunnel"* — and reached for metric 0, which rc.289
    /// then had to revert. Measured on a corp laptop today: the VPN holds
    /// `100.65.4.0/22` at effective 2 while ours sits at 256, so any block
    /// address outside the `/24`s separately defended (`100.65.7.x`, which
    /// this tenant has simply not grown into yet) resolves into the corp
    /// tunnel. Latent rather than biting, and closed by the same line.
    ///
    /// Windows ranks by `route metric + INTERFACE metric`. v4 pins the overlay
    /// adapter's interface metric to 0 and asserts its prefixes at route
    /// metric 1, so it wins every contested prefix at effective 1 against a
    /// VPN's 2. v6 got neither half: `set_iface_metric_v4` was v4-only, so the
    /// adapter kept Windows' AUTOMATIC v6 metric, and the ULA was asserted at
    /// route metric 256.
    ///
    /// Measured on a corp laptop under AnyConnect, both families at the same
    /// moment — one missing lever, not two problems:
    ///
    /// | | our route | our iface | eff | VPN route | VPN iface | eff | wins |
    /// |---|---|---|---|---|---|---|---|
    /// | v4 | 1 | 0 pinned | **1** | 1 | 1 | 2 | us |
    /// | v6 | 256 | 5 automatic | **261** | 1 | 25 | 26 | the VPN |
    ///
    /// Losing the `/96` is why the guard evicts the VPN's mirror ~20/min
    /// forever: eviction is the only way to hold a prefix we cannot win on
    /// metric. Winning it outright ends the war instead of managing it.
    ///
    /// ⚠️ **Default OFF, on rc.289's own precedent** — *a default with zero
    /// demonstrated benefit and one demonstrated regression does not belong on
    /// the fleet*. The demonstrated regression there was metric **0** routes,
    /// which the VPN deleted outright, leaving the prefix unrouted and killing
    /// inbound remote support. This is deliberately NOT that: it uses the same
    /// metric 1 that v4 has run fleet-wide for months, and on the measured
    /// host v4's metric-1 rows out-rank the VPN's mirrors and are **not**
    /// being deleted — so rc.289's "the monitor deletes anything that
    /// out-ranks it" does not generalise. Prove that per host before flipping
    /// the default: `evicted` must go flat and stay flat.
    #[cfg(windows)]
    fn route_win_enabled() -> bool {
        crate::env::flag("OVERLAY_ROUTE_WIN", false)
    }

    /// The metric the ULA `/96` (and the connected v4 prefix) is asserted at.
    ///
    /// ⚠️ Gate-off is **256, never `del`**: that row is Windows' own auto
    /// CONNECTED route and shares the exact `(LUID, prefix, on-link)` key, so
    /// deleting it would take the connected route with it and kill v6
    /// entirely. Every path here only ever re-METRICS an existing row.
    #[cfg(windows)]
    fn ula_route_metric() -> u32 {
        if route_metric0_enabled() {
            0
        } else if route_win_enabled() {
            defended_route_metric()
        } else {
            256
        }
    }

    /// rc.410 (#23) — the overlay NIC's IPv4 INTERFACE metric.
    /// `ROOMLERD_OVERLAY_IFACE_METRIC` (config key
    /// `overlay_iface_metric`), default **0**.
    ///
    /// This is the route war's decisive lever, and the one a corp endpoint
    /// manager cannot counter. Windows ranks routes by `route metric +
    /// interface metric`; Check Point / AnyConnect mirror our prefixes at
    /// route metric 1 on an interface pinned to metric 1, so the historical
    /// pin of 1 produced an exact tie at every prefix length and Windows
    /// broke it by lower ifIndex — the VPN's. Metric-0 ROUTES (rc.287) were
    /// the previous attempt and get deleted by those same managers (rc.289
    /// auto-yield). An interface metric is a property of OUR adapter: the
    /// VPN has no route-monitor hook for it, and `0 + 1` beats `1 + 1`
    /// outright.
    ///
    /// Values above 0 are honoured verbatim for operators who need the
    /// overlay to LOSE against a specific higher-priority interface; the
    /// value is clamped to a sane ceiling so a typo cannot make the overlay
    /// unroutable.
    #[cfg(windows)]
    fn iface_metric() -> u32 {
        crate::env::node_env("OVERLAY_IFACE_METRIC")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .map(|v| v.min(9999))
            .unwrap_or(0)
    }

    /// rc.279 — one-shot per process: remove stray roomler Wintun devices
    /// left by crashed prior runs (hard exits skip `Drop`, so
    /// close-of-created never removed them; the boot reconciler cleans
    /// routes/DNS only). `Status -ne 'Up'` protects any LIVE adapter (an
    /// orphan with no owning process reports Disconnected), and
    /// once-per-process means a WS-reconnect bring-up can't touch the
    /// previous session's still-closing adapter. A leftover suffixed dupe
    /// ("roomler 2") would otherwise capture the alias-targeted config (the
    /// metric pin, derived v6, and Private-profile set all address the
    /// NAME). Best-effort: `pnputil /remove-device` needs admin; unelevated
    /// it just leaves the strays in place.
    ///
    /// Multi-org v2 — `expected` is the set of adapter NAMES that must
    /// SURVIVE the sweep: with per-org adapters, a sibling org's persisted
    /// adapter between sessions (its runtime not yet started, so the device
    /// reports non-Up) is NOT a stray, and removing it would discard that
    /// org's stable interface identity. Only `^roomler` Wintun devices NOT
    /// in the set are removed. The legacy caller passes just its own
    /// requested name — with the stable requested GUID, create re-binds the
    /// surviving orphan's identity by name+GUID, so protecting it is
    /// equivalent to the old remove-and-recreate. NOTE the `Once` guard:
    /// the FIRST bring-up's expected set is the one that runs.
    ///
    /// Per-org adapters (`roomler-<suffix>`, Phase 2c) are structurally
    /// EXEMPT (`-notmatch '^roomler-'`) rather than enumerated into
    /// `expected`: orgs come up at their own pace, so the first org's sweep
    /// cannot know its siblings' names — and a per-org adapter is
    /// deliberately persistent anyway (explicit org REMOVAL owns its
    /// cleanup, not the boot sweep). The sweep therefore only ever removes
    /// legacy-shaped strays ("roomler", Windows duplicate-name "roomler 2",
    /// "roomler0", …).
    #[cfg(target_os = "windows")]
    fn sweep_stray_adapters_once(expected: &[String]) {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            // PowerShell array literal of survivors, single-quote escaped
            // (`'` → `''` — names come from our own constants/config, but a
            // quote must never break out of the literal).
            let keep = expected
                .iter()
                .map(|n| format!("'{}'", n.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",");
            let script = format!(
                "$keep = @({keep}); Get-NetAdapter -IncludeHidden | Where-Object {{ \
                 $_.PnPDeviceID -like 'SWD\\WINTUN\\*' -and \
                 $_.Name -match '^roomler' -and $_.Name -notmatch '^roomler-' -and \
                 $_.Status -ne 'Up' -and \
                 ($keep -notcontains $_.Name) }} | \
                 ForEach-Object {{ \
                 pnputil /remove-device \"$($_.PnPDeviceID)\" > $null 2>&1; \
                 if ($LASTEXITCODE -eq 0) {{ $_.Name }} }}"
            );
            match std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
            {
                Ok(o) => {
                    let removed: Vec<String> = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string)
                        .collect();
                    if !removed.is_empty() {
                        tracing::info!(
                            ?removed,
                            "overlay: swept stray roomler Wintun adapters from prior runs"
                        );
                    }
                }
                Err(e) => tracing::debug!(%e, "overlay: stray-adapter sweep unavailable"),
            }
        });
    }

    impl SystemTun {
        /// rc.280 — cheap liveness probe for the process-lifetime TUN cache:
        /// does the OS still know our LUID? A user disabling/removing the
        /// adapter out from under a cached device must force a fresh create
        /// instead of wedging every future session on a dead handle.
        pub fn is_alive(&self) -> bool {
            #[cfg(target_os = "windows")]
            {
                winroute::identity(self.dev.tun_luid()).0 != 0
            }
            #[cfg(not(target_os = "windows"))]
            {
                true
            }
        }

        /// The interface name the OS gave this device — the requested name
        /// ([`IF_NAME`] for the legacy [`up`](Self::up)) on Windows/Linux,
        /// the kernel-assigned `utunN` on macOS.
        pub fn if_name(&self) -> &str {
            &self.if_name
        }

        /// Multi-org v2 — the derived-ULA on-link prefix length this device
        /// was brought up with (96 for the legacy single-adapter identity;
        /// 96 + the org block's v4 plen for a per-org adapter).
        pub fn v6_onlink_plen(&self) -> u8 {
            self.v6_onlink_plen
        }

        /// Multi-org P2c — assign an ADDITIONAL local address (a secondary
        /// org's self-IP with its block's prefix) to the live device.
        ///
        /// ⚠️ No production caller since W7c deleted the shared TUN: every org
        /// now has an adapter of its own, holding one address (N10). The macOS
        /// kernel test below still puts a second address on a utun through it.
        /// Idempotent: re-adding an address the device already holds succeeds.
        /// Sync + blocking by design, like the bring-up work in [`up`] itself;
        /// its P2c callers ran it inside the TUN factory, on every reconnect's
        /// re-registration.
        ///
        /// [`up`]: Self::up
        pub fn add_address_sync(&self, ip: Ipv4Addr, prefix: u8) -> std::io::Result<()> {
            let run = |prog: &str, args: &[String]| -> std::io::Result<String> {
                let out = std::process::Command::new(prog).args(args).output()?;
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if out.status.success() {
                    Ok(stdout)
                } else {
                    Err(std::io::Error::other(format!(
                        "{prog} {args:?} exited {}: {stderr} {stdout}",
                        out.status
                    )))
                }
            };
            #[cfg(target_os = "windows")]
            {
                let _ = run; // Linux/macOS shell out; Windows is typed (N1).
                // Track N1 — typed IP Helper, replacing `netsh add address` +
                // the locale-string tolerance (#373) + the listing-race
                // presence poll (#388). Idempotence is decided by the NUMERIC
                // `ERROR_OBJECT_ALREADY_EXISTS` inside `ensure`, and there is
                // no delete-first, so the connected route never flaps under
                // live traffic (the original reason the netsh path tolerated
                // "already exists" at all).
                let luid = self.dev.tun_luid();
                winaddr::ensure(luid, std::net::IpAddr::V4(ip), prefix)?;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            {
                // `replace` is add-or-update — naturally idempotent.
                let args: Vec<String> = vec![
                    "addr".into(),
                    "replace".into(),
                    format!("{ip}/{prefix}"),
                    "dev".into(),
                    self.if_name.clone(),
                ];
                run("ip", &args).map(|_| ())
            }
            #[cfg(target_os = "macos")]
            {
                // A utun is a POINT-TO-POINT interface: `ifconfig utunN inet
                // A B netmask M alias` needs BOTH a local and a peer address.
                // Using the address as its own peer is what makes the block's
                // prefix land on this interface, which is what the connected
                // route needs — the same shape `up` uses for the first
                // address.
                let mask = Ipv4Addr::from(if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - u32::from(prefix.min(32)))
                });
                let args: Vec<String> = vec![
                    self.if_name.clone(),
                    "inet".into(),
                    ip.to_string(),
                    ip.to_string(),
                    "netmask".into(),
                    mask.to_string(),
                    "alias".into(),
                ];
                match run("ifconfig", &args) {
                    Ok(_) => Ok(()),
                    // Same lesson as the Windows path: never parse the
                    // message (`ifconfig` says "File exists" for a duplicate,
                    // and that text is not a contract). Ask the interface.
                    Err(e) => {
                        let listed = run("ifconfig", &[self.if_name.clone()]).unwrap_or_default();
                        if listing_mentions_address(&listed, ip) {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            {
                let _ = (ip, prefix, run);
                Err(std::io::Error::other(
                    "multi-address TUN is not supported on this platform",
                ))
            }
        }

        /// Multi-org P2c — take a secondary org's address back off the device
        /// ([`Self::add_address_sync`]'s inverse). ⚠️ No production caller since
        /// W7c, as for that. Best-effort: a failure here only leaves an idle
        /// address behind, never breaks a live org.
        pub fn del_address_sync(&self, ip: Ipv4Addr, prefix: u8) {
            let run = |prog: &str, args: &[String]| {
                let _ = std::process::Command::new(prog).args(args).output();
            };
            #[cfg(target_os = "windows")]
            {
                let _ = (prefix, &run); // Linux/macOS shell out; Windows is typed (N1).
                let luid = self.dev.tun_luid();
                winaddr::remove(luid, std::net::IpAddr::V4(ip));
            }
            #[cfg(target_os = "linux")]
            run(
                "ip",
                &[
                    "addr".into(),
                    "del".into(),
                    format!("{ip}/{prefix}"),
                    "dev".into(),
                    self.if_name.clone(),
                ],
            );
            #[cfg(target_os = "macos")]
            {
                let _ = prefix;
                run(
                    "ifconfig",
                    &[
                        self.if_name.clone(),
                        "inet".into(),
                        ip.to_string(),
                        "-alias".into(),
                    ],
                );
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            {
                let _ = (ip, prefix, run);
            }
        }

        /// Create the device, assign `self_ip` with `netmask`, set `mtu`,
        /// and bring it up. `netmask` is the overlay *network* mask (e.g.
        /// `/10` → `255.192.0.0`) so the whole overlay CIDR routes here
        /// via the OS-installed connected route. Must be called inside a
        /// Tokio runtime (the async device registers with the reactor).
        ///
        /// Dual-stack: the device also gets this node's *derived* overlay
        /// IPv6 ([`derive_overlay_v6`](crate::overlay::router::derive_overlay_v6))
        /// on the ULA `/96` (best-effort, on
        /// Linux, Windows and macOS) — the OS-TUN mirror of the netstack's
        /// dual-addressed iface. The connected `/96` route auto-installs,
        /// making every peer's derived v6 on-link; the WG bridge routes it
        /// by unmapping the ULA destination to its embedded v4
        /// ([`Router::dst_of_ip_packet`](crate::overlay::router::Router::dst_of_ip_packet)).
        /// No per-peer v6 `/128`s and no v6 metric pin: unlike the CGNAT
        /// `100.64.0.0/10`, nothing else on a host claims our random ULA, so
        /// there is no route war to win (the reason the v4 side needs both).
        pub fn up(self_ip: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> std::io::Result<Self> {
            Self::up_with(TunOptions::legacy(self_ip, netmask, mtu))
        }

        /// Multi-org v2 — [`up`](Self::up) with an explicit per-adapter
        /// identity ([`TunOptions`]): name, requested GUID, and the derived-
        /// ULA on-link prefix length all become instance parameters, so N
        /// org adapters can coexist. The legacy `up()` delegates here with
        /// [`TunOptions::legacy`] — byte-identical single-org behavior.
        pub fn up_with(opts: TunOptions) -> std::io::Result<Self> {
            let mut config = tun::Configuration::default();
            config
                .address(opts.ip)
                .netmask(opts.netmask)
                .mtu(opts.mtu)
                .up();

            // Stable adapter name (Wintun's `open` keys by name) + a STABLE
            // requested GUID. The name alone never gave reuse: a clean
            // teardown REMOVES a created adapter (Wintun contract), so every
            // bring-up re-created it — and without a requested GUID wintun
            // rolls a RANDOM one per create, minting a brand-new interface
            // identity each time: a new ifIndex/LUID (the winhost-a
            // 83→70→46→75→29→46 trail) and a brand-new "Unidentified
            // network" landing in the Public firewall profile (why the
            // Private-profile retry + WFP permit below exist). A constant
            // GUID makes Windows re-bind the SAME interface identity across
            // recreation — Tailscale ships the same pattern.
            #[cfg(target_os = "windows")]
            {
                config.tun_name(opts.name.as_str());
                if stable_guid_enabled() {
                    config.platform_config(|p| p.device_guid(opts.guid));
                }
            }
            #[cfg(target_os = "linux")]
            config.tun_name(opts.name.as_str());
            // Linux — a virtio-net header on every read and write lets the
            // device carry TCP super-packets both ways (`tun_offload`).
            // `ROOMLERD_OVERLAY_TUN_OFFLOAD=0` opens the plain device instead,
            // exactly the pre-offload behaviour.
            #[cfg(target_os = "linux")]
            let offload = crate::env::flag("OVERLAY_TUN_OFFLOAD", true);
            #[cfg(target_os = "linux")]
            if offload {
                config.platform_config(|p| {
                    p.vnet_hdr(true);
                });
            }

            // rc.209 — Wintun's `WintunCreateAdapter` can transiently fail with
            // "device installation mutex: Access is denied" when a PRIOR adapter
            // (from a rapid service restart / MSI upgrade) hasn't fully released
            // its device-install lock yet — the overlay then aborts and the node
            // won't join the mesh until the next reconnect. The old adapter
            // releases within ~a second, so retry a few times with a short
            // backoff (Windows only; the create is reliable elsewhere → one
            // attempt). No added latency on the normal path (first attempt wins);
            // the backoff sleeps ONLY on the transient-failure path, which is
            // exactly when waiting is correct. Blocking sleep is fine here — this
            // is the one-time TUN bring-up, same as the metric-pin `netsh` below.
            #[cfg(target_os = "windows")]
            const CREATE_ATTEMPTS: usize = 5;
            #[cfg(not(target_os = "windows"))]
            const CREATE_ATTEMPTS: usize = 1;
            // rc.279 — before this process's first create, sweep stray
            // roomler Wintun devices left by crashed prior runs; see
            // [`sweep_stray_adapters_once`]. This adapter's own requested
            // name survives the sweep (multi-org v2 expected-set semantics).
            #[cfg(target_os = "windows")]
            if stable_guid_enabled() {
                sweep_stray_adapters_once(std::slice::from_ref(&opts.name));
            }

            let dev = retry_create(
                CREATE_ATTEMPTS,
                std::time::Duration::from_millis(400),
                || tun::create_as_async(&config).map_err(|e| std::io::Error::other(e.to_string())),
                |attempt, e| {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "overlay: TUN adapter create failed; retrying after backoff \
                         (a prior adapter may not have released after a rapid restart)"
                    );
                },
            )?;
            let dev = Arc::new(dev);
            #[cfg(target_os = "linux")]
            let vnet = offload.then(|| {
                use std::os::fd::AsRawFd as _;
                crate::overlay::tun_offload::VnetIo::new(
                    dev.as_raw_fd(),
                    crate::env::flag("OVERLAY_TUN_USO", false),
                )
            });

            // Ask the OS what it named this device. Windows/Linux answer with
            // the name we asked for; macOS answers `utunN`, which is the only
            // way to address the interface in `ifconfig`/`route`.
            let if_name = {
                use tun::AbstractDevice;
                match dev.tun_name() {
                    Ok(n) if !n.is_empty() => n,
                    other => {
                        if let Err(e) = &other {
                            tracing::debug!(
                                %e,
                                requested = %opts.name,
                                "overlay: TUN name query failed; assuming the requested name"
                            );
                        }
                        opts.name.clone()
                    }
                }
            };
            if if_name != opts.name {
                tracing::info!(%if_name, "overlay: OS-assigned TUN interface name");
            }

            // Pin the overlay NIC's interface metric so its routes (the
            // connected block + the per-peer `/32`s) are preferred over a
            // full-tunnel VPN's captured routes for the overlay range.
            // N5 — typed (`Get/SetIpInterfaceEntry`, in-memory µs) instead of
            // the old blocking `netsh` spawn. Still best-effort: a failure
            // just leaves the default metric.
            //
            // rc.410 (#23) — the value is [`overlay_iface_metric`] (0 by
            // default), NOT 1. Windows ranks a route by `route metric +
            // INTERFACE metric`, and Check Point / AnyConnect mirror our
            // prefixes at route metric 1 on a NIC whose own interface metric
            // is also 1 — a FULL tie at every prefix length, which Windows
            // breaks by lower ifIndex, i.e. reliably in the VPN's favour
            // (corplap: Ethernet 2 = ifIndex 10 vs roomler = 20). At a tie the
            // per-destination pick is also STICKY, so peers stayed captured
            // across restarts: node-initiated traffic died 100 % while
            // strong-host source pinning kept replies flowing, and the RTT
            // prober (which shells the OS `ping`) showed a dash — the
            // "one-way carrier" that was never a carrier fault at all.
            // The rc.287 answer was metric-0 ROUTES, which those VPNs simply
            // delete (the rc.289 auto-yield, re-observed on corplap 2026-08-19).
            // An INTERFACE metric is not a route: the VPN cannot delete it,
            // and 0 + 1 beats 1 + 1 outright with no tie-break — field-proven
            // on corplap, where all four captured peers flipped to the overlay NIC
            // instantly (0 % loss, 24-26 ms) with every competing `/32` still
            // in the table.
            #[cfg(target_os = "windows")]
            {
                use tun::AbstractDeviceExt as _;
                let m = iface_metric();
                if let Err(e) = winroute::set_iface_metric_v4(dev.tun_luid(), m) {
                    tracing::warn!(%e, metric = m, "overlay: interface metric pin failed; keeping the default");
                }
                // #1342 — the same pin for IPv6, which never had one. Left on
                // Windows' AUTOMATIC metric the adapter drew 5 against a VPN
                // miniport's 25, and the ULA's route metric 256 then put us at
                // 261 vs 26: lost outright, hence the endless eviction of the
                // VPN's mirrored `/96`. Best-effort like its v4 twin.
                if route_win_enabled()
                    && let Err(e) = winroute::set_iface_metric_v6(dev.tun_luid(), m)
                {
                    tracing::warn!(%e, metric = m, "overlay: IPv6 interface metric pin failed; keeping the automatic metric");
                }
                // FR-97 P0b-2c — our adapter starts NOT forwarding; a subnet
                // router or exit turns it on when it serves, and its revert
                // turns it off. A run that ended without that revert (a crash,
                // a kill) leaves it on, and the boot purge cannot reach it:
                // the adapter goes with the process, and Windows re-applies
                // the setting when it is created again (field, the P0b-2b
                // candidate on Windows 11: Enabled after `taskkill /F`). Off
                // through the router's own revert, which writes the setting
                // Windows keeps for the adapter.
                match winroute::forwarding_enabled_v4(dev.tun_luid()) {
                    Ok(true) => {
                        let (ifindex, guid) = winroute::identity(dev.tun_luid());
                        let id = if ifindex != 0 {
                            format!("if:{ifindex}")
                        } else {
                            format!("guid:{guid}")
                        };
                        crate::overlay::nat::restore_forwarding(&[id]);
                        tracing::warn!(
                            ifindex,
                            "overlay: our adapter came up forwarding (a run that ended \
                             without its router's revert) — switched it off"
                        );
                    }
                    Ok(false) => {}
                    Err(e) => tracing::debug!(%e, "overlay: adapter forwarding state unreadable"),
                }
            }

            // Dual-stack: assign the derived overlay v6 on the ULA /96 (the
            // `tun` crate's Configuration is v4-only, so this is an OS call —
            // sync + best-effort like the metric pin; a failure leaves the
            // node v4-only, which keeps working unchanged).
            #[cfg(target_os = "windows")]
            let tun_luid = dev.tun_luid();
            #[cfg(not(target_os = "windows"))]
            let tun_luid = 0u64;
            assign_derived_v6(opts.ip, &if_name, tun_luid, opts.v6_onlink_plen);

            // Program WFP so the overlay's inbound survives a GPO-locked
            // Defender Firewall (Tailscale's approach). Best-effort: a
            // failure is logged and the overlay still comes up — it only
            // matters on hosts where the firewall is the blocker.
            #[cfg(windows)]
            let _wfp = if crate::overlay::wfp::wfp_enabled() {
                let luid = dev.tun_luid();
                match crate::overlay::wfp::WfpGuard::install(luid) {
                    Ok(g) => {
                        tracing::info!(
                            luid = format_args!("{luid:#x}"),
                            adapter = %if_name,
                            filters = crate::overlay::wfp::FILTERS_PER_ADAPTER,
                            "overlay: WFP hard-permit installed for the roomler adapter"
                        );
                        Some(g)
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "overlay: WFP permit NOT installed; if inbound traffic fails behind a \
                             GPO-locked firewall, request an IT-managed exception for the roomler adapter"
                        );
                        None
                    }
                }
            } else {
                tracing::info!("overlay: WFP permit disabled via ROOMLERD_WFP_PERMIT");
                None
            };

            // P9 — consumer-box hygiene: the daemon's inbound-UDP firewall
            // allow (WG on the physical NICs) + the adapter's Private profile.
            // Fire-and-forget; see `spawn_windows_net_hygiene`.
            #[cfg(windows)]
            spawn_windows_net_hygiene(if_name.clone());

            // rc.279 — log the OS-observed adapter identity. Nothing logged
            // this before (the ifIndex-churn hunt had to reconstruct it from
            // route dumps); with the stable requested GUID above, this line
            // should repeat identical values across restarts.
            #[cfg(windows)]
            {
                let luid = dev.tun_luid();
                let (ifindex, guid) = winroute::identity(luid);
                tracing::info!(
                    luid = format_args!("{luid:#x}"),
                    ifindex,
                    guid = %guid,
                    "overlay: TUN adapter identity"
                );
            }

            // P5 — snapshot the host's original default route NOW, before any
            // overlay route is installed, so exit-node exemptions can later pin
            // carrier-critical endpoints via the real uplink.
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let orig_default = {
                let d = discover_default_route(&if_name);
                match &d {
                    Some(r) => tracing::info!(
                        gateway = %r.gateway, interface = %r.interface,
                        "overlay: captured original default route (exit-node exemptions available)"
                    ),
                    None => tracing::warn!(
                        "overlay: no original default route found; \
                         exit-node carrier exemptions will be unavailable"
                    ),
                }
                d
            };

            // P5/S3b — likewise snapshot the original IPv6 default route (for v6
            // `/128` carrier exemptions). `None` on a v4-only-uplink host — v6
            // exit egress then stays fail-closed (never leaks).
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let orig_default_v6 = {
                let d = discover_default_route_v6(&if_name);
                match &d {
                    Some(r) => tracing::info!(
                        gateway = %r.gateway, interface = %r.interface,
                        "overlay: captured original IPv6 default route (v6 exit exemptions available)"
                    ),
                    None => tracing::info!(
                        "overlay: no IPv6 default route; v6 exit egress will stay fail-closed"
                    ),
                }
                d
            };

            // FR-97 P1a — the macOS twin of both captures above. Not final:
            // every pin re-reads its family's uplink, so a Mac that booted
            // without a network still pins once it has one.
            #[cfg(target_os = "macos")]
            let uplinks = {
                let mut found = BsdUplinks::default();
                for v6 in [false, true] {
                    let up = discover_bsd_uplink(v6, &if_name);
                    match (&up, v6) {
                        (Some(u), false) => tracing::info!(
                            gateway = %u.gateway_arg, interface = %u.interface,
                            "overlay: captured original default route (exit-node exemptions available)"
                        ),
                        (Some(u), true) => tracing::info!(
                            gateway = %u.gateway_arg, interface = %u.interface,
                            "overlay: captured original IPv6 default route (v6 exit exemptions available)"
                        ),
                        (None, false) => tracing::info!(
                            "overlay: no default route through a gateway yet; exit-node exemptions \
                             wait for one"
                        ),
                        (None, true) => tracing::info!(
                            "overlay: no IPv6 default route; v6 exit egress will stay fail-closed"
                        ),
                    }
                    *found.slot(v6) = up;
                }
                std::sync::Mutex::new(found)
            };

            // #1237 — record this adapter as one of ours so the eviction
            // helpers and the block-floor gate never mistake a sibling org
            // adapter for a foreign product. `Drop` removes it. (`tun_luid`
            // is `0` off-Windows, where the registry is unconsumed.)
            // FR-68 C2(b) — computed BEFORE registering so the registry can
            // compare this adapter's block against its siblings' and warn on
            // an overlap. Off-Windows there is no mask helper and no route
            // guard, so it is honestly `None`.
            #[cfg(windows)]
            let connected_v4_block = prefix_len_of_mask(opts.netmask).map(|plen| {
                let net = u32::from_be_bytes(opts.ip.octets())
                    & u32::from_be_bytes(opts.netmask.octets());
                (Ipv4Addr::from(net), plen)
            });
            #[cfg(not(windows))]
            let connected_v4_block: Option<(Ipv4Addr, u8)> = None;

            own_adapters::register(&if_name, tun_luid, connected_v4_block);

            Ok(Self {
                dev,
                if_name,
                v6_onlink_plen: opts.v6_onlink_plen,
                #[cfg(windows)]
                connected_v4: connected_v4_block,
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                orig_default: std::sync::Mutex::new(orig_default),
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                orig_default_v6: std::sync::Mutex::new(orig_default_v6),
                #[cfg(target_os = "macos")]
                uplinks,
                #[cfg(windows)]
                _wfp,
                #[cfg(windows)]
                floor_state: std::sync::Mutex::new(Vec::new()),
                #[cfg(windows)]
                in_block_fp: std::sync::Mutex::new(Vec::new()),
                #[cfg(windows)]
                escalated: std::sync::Mutex::new(std::collections::HashSet::new()),
                #[cfg(target_os = "linux")]
                vnet,
            })
        }

        /// Linux — what the TUN offload has done on this device, `None` for a
        /// device opened without it (`ROOMLERD_OVERLAY_TUN_OFFLOAD=0`).
        #[cfg(target_os = "linux")]
        pub fn offload_stats(&self) -> Option<crate::overlay::tun_offload::OffloadStats> {
            self.vnet.as_ref().map(|v| v.stats())
        }
    }

    /// Change B — every IPv4 address on every interface EXCEPT the overlay
    /// adapter itself (matched by interface NAME, as are the sibling orgs' own
    /// adapters, #1237 below) and loopback. Deliberately
    /// UNFILTERED otherwise — unlike `direct::gather_lan_ips`, which *skips*
    /// CGNAT addresses, because an ISP-CGNAT WAN address is exactly what the
    /// floor gate must detect. `None` when enumeration fails OR the overlay
    /// adapter can't be identified — the caller treats both as WITHHOLD.
    #[cfg(windows)]
    fn non_overlay_v4_addrs(overlay_if: &str) -> Option<Vec<Ipv4Addr>> {
        let addrs = if_addrs::get_if_addrs().ok()?;
        // #1237 — a per-org SIBLING adapter (`roomler-<org>`) carries an
        // overlay address on a DIFFERENT interface than `overlay_if`, so the
        // old single-name filter counted it as a foreign CGNAT address and
        // WITHHELD the primary's block floor on every multi-org host. Treat
        // any roomler adapter as ours.
        let is_ours = |name: &str| name == overlay_if || is_roomler_adapter_name(name);
        if !addrs.iter().any(|a| a.name == overlay_if) {
            return None;
        }
        Some(
            addrs
                .into_iter()
                .filter(|a| !is_ours(&a.name))
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v) if !v.is_loopback() => Some(v),
                    _ => None,
                })
                .collect(),
        )
    }

    // #1237 — drop this adapter from the own-adapter registry when the device
    // is torn down (a genuine reap or an `is_alive`-false recreate). The
    // Windows caches hold each `Arc<SystemTun>` for the process lifetime, so
    // in practice this fires at process exit or when an adapter is replaced —
    // exactly when the LUID stops being ours.
    impl Drop for SystemTun {
        fn drop(&mut self) {
            own_adapters::deregister(&self.if_name);
        }
    }

    #[async_trait]
    impl TunIo for SystemTun {
        async fn read_packet(&self) -> std::io::Result<Vec<u8>> {
            #[cfg(target_os = "linux")]
            if let Some(v) = &self.vnet {
                return v.read_one(&self.dev).await;
            }
            // Overlay MTU is 1280; 1600 covers it plus any platform
            // packet-information headroom the crate may surface.
            let mut buf = vec![0u8; 1600];
            let n = self
                .dev
                .recv(&mut buf)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            buf.truncate(n);
            Ok(buf)
        }

        async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
            #[cfg(target_os = "linux")]
            if let Some(v) = &self.vnet {
                return v.write_one(&self.dev, packet).await;
            }
            self.dev
                .send(packet)
                .await
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string()))
        }

        async fn read_packets(&self, out: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
            #[cfg(target_os = "linux")]
            if let Some(v) = &self.vnet {
                return v.read(&self.dev, out).await;
            }
            out.push(self.read_packet().await?);
            Ok(())
        }

        async fn write_packets(&self, packets: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
            #[cfg(target_os = "linux")]
            if let Some(v) = &self.vnet {
                return v.write(&self.dev, packets).await;
            }
            for p in packets.drain(..) {
                self.write_packet(&p).await?;
            }
            Ok(())
        }

        fn os_name(&self) -> Option<String> {
            Some(self.if_name.clone())
        }

        /// Add an on-link `/32` for `peer` via the overlay NIC. Windows uses
        /// `netsh` (by adapter name, so no LUID/index lookup); Linux uses
        /// `ip route replace` (idempotent). macOS utun is left to the
        /// connected route for now (refined when 3b/3c field-test there). The
        /// agent runs privileged (service), so the route call has rights.
        async fn add_peer_route(&self, peer: Ipv4Addr) -> std::io::Result<()> {
            #[cfg(target_os = "windows")]
            {
                // rc.208 — IP Helper instead of `route.exe`/`netsh` (see
                // `winroute`). A full-tunnel VPN (Check Point Endpoint) installs a
                // competing `/32` for each overlay peer via its own NIC at metric
                // 1, which swallows overlay traffic. The overlay OWNS
                // 100.64.0.0/10, so any non-wintun `/32` for a peer is wrong by
                // construction: evict competing `/32`s on OTHER interfaces, then
                // (re-)add ours on the wintun so it wins even if the VPN re-adds
                // later. Both calls are in-memory FIB ops (~µs), so they no longer
                // head-of-line-stall the data plane.
                let luid = self.dev.tun_luid();
                winroute::evict_competing_v4(luid, peer, 32);
                // rc.411 (#23) — an ESCALATED peer keeps route metric 0 (see
                // `SystemTun::escalated`); re-asserting it at 1 here would
                // undo the escalation on every wave.
                let metric = if self
                    .escalated
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&peer)
                {
                    0
                } else {
                    defended_route_metric()
                };
                // rc.287 — the metric became dynamic (0 under the metric0
                // gate, 1 with it off), which is exactly the case the old
                // constancy comment warned about: `add` skips on
                // ALREADY_EXISTS, so a metric change would be silently
                // MASKED by the pre-existing row. `ensure` reconciles —
                // one in-memory Get per wave, delete-then-re-add only on an
                // actual mismatch (i.e. once, when the gate flips or an old
                // agent's metric-1 rows are inherited).
                winroute::ensure(luid, std::net::IpAddr::V4(peer), 32, metric)
            }
            #[cfg(target_os = "linux")]
            {
                run_cmd(
                    "ip",
                    vec![
                        "route".into(),
                        "replace".into(),
                        format!("{peer}/32"),
                        "dev".into(),
                        self.if_name.clone(),
                    ],
                )
                .await
            }
            #[cfg(target_os = "macos")]
            {
                // #1856 — every wave re-asserts every peer, and the
                // delete-then-add below leaves the `/32` absent for ~3 ms in
                // between. A socket bound to our overlay address gets
                // EHOSTUNREACH in that hole, and the write itself feeds the
                // route monitor that arms the next wave. A route that is
                // already ours is left alone.
                if super::bsd_route_is_ours(
                    bsd_route_get(vec![
                        "-n".into(),
                        "get".into(),
                        "-inet".into(),
                        peer.to_string(),
                    ])
                    .await
                    .as_ref(),
                    std::net::IpAddr::V4(peer),
                    32,
                    &self.if_name,
                ) {
                    return Ok(());
                }
                // BSD `route` has no idempotent form: `add` fails once the
                // entry exists. Delete-then-add is the portable equivalent
                // of `ip route replace`, and the delete is expected to fail
                // on the first call — its result is deliberately ignored.
                // A hole here costs nothing: this peer's traffic was not
                // reaching the overlay anyway.
                let _ = run_cmd(
                    "route",
                    vec![
                        "-n".into(),
                        "delete".into(),
                        "-inet".into(),
                        peer.to_string(),
                    ],
                )
                .await;
                run_cmd(
                    "route",
                    vec![
                        "-n".into(),
                        "add".into(),
                        "-inet".into(),
                        peer.to_string(),
                        "-interface".into(),
                        self.if_name.clone(),
                    ],
                )
                .await
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            {
                let _ = peer;
                Ok(())
            }
        }

        /// rc.278 — see [`TunIo::defend_self_route`]. Windows-only: a VPN's
        /// metric-1 `/32` for OUR OWN overlay address out-ranks the metric-256
        /// on-link route Windows derives from the interface address, diverting
        /// every packet meant for us into the corp tunnel. Same eviction the
        /// peer path has used since rc.208, now applied to our own address.
        async fn defend_self_route(&self, self_ip: Ipv4Addr) {
            #[cfg(target_os = "windows")]
            {
                let luid = self.dev.tun_luid();
                winroute::evict_competing_v4(luid, self_ip, 32);
                // rc.281 — the v6 twin. IPv6 survived the winhost-a hijack only
                // because that VPN didn't claim ULA space — an assumption, not
                // a guarantee (the v4 CGNAT hijack was "impossible" too), and
                // v6 was the diagnostic control channel that cracked the case;
                // losing it to the same trick would hurt twice. Defend our own
                // derived `/128` AND the connected `/96` (v6 has no per-peer
                // routes — the `/96` IS the peer path).
                let self_v6 = crate::overlay::router::derive_overlay_v6(self_ip);
                winroute::evict_competing_v6(luid, self_v6, 128);
                // #1237 — defend only THIS adapter's narrowed derived-ULA
                // prefix, so two orgs' guard waves no longer fight over the
                // whole `/96`. Legacy single-org resolves to the same
                // `fd72:6f6f:6d6c::/96` it always used.
                let (ula_net, ula_plen) = if v6_defend_narrow_enabled() {
                    defended_ula_prefix(self.connected_v4, self.v6_onlink_plen)
                } else {
                    (
                        crate::overlay::router::derive_overlay_v6(Ipv4Addr::UNSPECIFIED),
                        96,
                    )
                };
                winroute::evict_competing_v6(luid, ula_net, ula_plen);
                // rc.287 — ASSERT the ULA /96 at metric 0, don't just evict
                // competitors for it. AnyConnect mirrors the /96 on its
                // miniport at effective metric 2; our auto CONNECTED route
                // sits at 256+1 and loses outright, so v6 node-initiated
                // egress was captured exactly like v4 (CORPLAP: v6 ping
                // "Allgemeiner Fehler"). A metric-0 row wins with no
                // tie-break. Reconciled every wave. Gate OFF reconciles to
                // 256 — the connected-route default — NOT `del`: the auto
                // connected row shares the exact (LUID, prefix, on-link)
                // key, so a delete would take the CONNECTED route with it
                // and kill v6 entirely; metric-256 restores stock
                // precedence without that risk.
                let ula_metric = ula_route_metric();
                winroute::ensure(luid, std::net::IpAddr::V6(ula_net), ula_plen, ula_metric).ok();
                // rc.288 — defend the CONNECTED v4 prefix (100.64.0.0/10) the
                // same way. A peer /32 that is momentarily absent (install
                // order, a reap, a failed reconcile) falls through to this
                // prefix — and AnyConnect mirrors the whole /10 at effective
                // metric 2 while our connected route sits at 257, so the
                // fall-through lands in the corp tunnel. That is exactly how
                // CORPLAP-3 looked after rc.287: no /32 anywhere, every
                // peer resolving to Cisco's /10. Metric 0 makes the overlay
                // win the fall-through too; gate-off restores 256.
                if let Some((net, plen)) = self.connected_v4 {
                    winroute::ensure(luid, std::net::IpAddr::V4(net), plen, ula_metric).ok();
                }
            }
            #[cfg(not(target_os = "windows"))]
            let _ = self_ip;
        }

        async fn del_peer_route(&self, peer: Ipv4Addr) {
            #[cfg(target_os = "windows")]
            winroute::del(self.dev.tun_luid(), std::net::IpAddr::V4(peer), 32);
            #[cfg(target_os = "linux")]
            let _ = run_cmd(
                "ip",
                vec![
                    "route".into(),
                    "del".into(),
                    format!("{peer}/32"),
                    "dev".into(),
                    self.if_name.clone(),
                ],
            )
            .await;
            #[cfg(target_os = "macos")]
            let _ = run_cmd(
                "route",
                vec![
                    "-n".into(),
                    "delete".into(),
                    "-inet".into(),
                    peer.to_string(),
                ],
            )
            .await;
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            let _ = peer;
        }

        /// Phase 1 — install an OS route for `cidr` via the overlay NIC (a
        /// subnet a router-peer serves). Idempotent (delete-then-add on Windows;
        /// `ip route replace` on Linux). Low metric so it wins a colliding uplink
        /// route, mirroring the per-peer `/32` path.
        ///
        /// Dual-stack (P5): `cidr` may be IPv4 or IPv6 — the family is picked from
        /// the string. Exit-node routing uses this for BOTH the v4 split-default
        /// (`0.0.0.0/1` + `128.0.0.0/1`, which encapsulate to the exit peer) AND
        /// the v6 fail-closed halves (`::/1` + `8000::/1`, which the crypto-router
        /// drops because global v6 is unroutable over the overlay — so v6 can't
        /// leak out the physical uplink while v4 egress is captured).
        async fn add_cidr_route(&self, cidr: &str) -> std::io::Result<()> {
            let v6 = is_v6_cidr(cidr);
            #[cfg(target_os = "windows")]
            {
                // rc.208 — IP Helper (see `winroute`); mirrors the old
                // netsh delete-then-add on OUR interface, but in-memory (~µs).
                let _ = v6;
                let (addr, plen) = parse_cidr(cidr).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad cidr")
                })?;
                let luid = self.dev.tun_luid();
                // #1282 — leave a route that is already ours alone. The wave
                // re-asserts the block floors (and an exit client's /1s) every
                // time, and this delete-then-add rewrote them every time: each
                // write is a `NotifyRouteChange2` event, the event arms the next
                // wave 3 s later, and that was the ~20 waves/min per adapter.
                // Field, NEO16 on 0.4.119: every floor /24's route Age read
                // 0–2 s, while the peer /32s that `ensure` leaves alone read 6 h.
                // Deliberately NOT `ensure`: its #1328 strike/yield would stop
                // re-asserting an exit /1 that a VPN keeps deleting; a route that
                // is missing or wrong still gets the same delete-then-add as before.
                if winroute::is_installed(luid, addr, plen, 1) {
                    return Ok(());
                }
                winroute::del(luid, addr, plen);
                winroute::add(luid, addr, plen, 1)
            }
            #[cfg(target_os = "linux")]
            {
                let mut args: Vec<String> = Vec::new();
                if v6 {
                    args.push("-6".into());
                }
                args.extend([
                    "route".into(),
                    "replace".into(),
                    cidr.to_string(),
                    "dev".into(),
                    self.if_name.clone(),
                ]);
                run_cmd("ip", args).await
            }
            #[cfg(target_os = "macos")]
            {
                // BSD `route` wants `-net <prefix> -prefixlen <n>`; the
                // family flag picks v4 vs v6. Delete-then-add for the same
                // reason as the peer `/32`s: `add` is not idempotent.
                let (net, plen) = cidr.split_once('/').unwrap_or((cidr, ""));
                let family = if v6 { "-inet6" } else { "-inet" };
                // #1856 — and skipped for the same reason as the peer `/32`s:
                // the exit `/1`s are re-asserted on every wave, and a hole in
                // them sends that instant's egress out the physical uplink.
                if let (Ok(dest), Ok(len)) = (net.parse::<std::net::IpAddr>(), plen.parse::<u8>()) {
                    let got = bsd_route_get(vec![
                        "-n".into(),
                        "get".into(),
                        family.into(),
                        "-net".into(),
                        net.into(),
                        "-prefixlen".into(),
                        plen.into(),
                    ])
                    .await;
                    if super::bsd_route_is_ours(got.as_ref(), dest, len, &self.if_name) {
                        return Ok(());
                    }
                }
                let mut del: Vec<String> = vec![
                    "-n".into(),
                    "delete".into(),
                    family.into(),
                    "-net".into(),
                    net.into(),
                ];
                let mut add: Vec<String> = vec![
                    "-n".into(),
                    "add".into(),
                    family.into(),
                    "-net".into(),
                    net.into(),
                ];
                if !plen.is_empty() {
                    for v in [&mut del, &mut add] {
                        v.push("-prefixlen".into());
                        v.push(plen.into());
                    }
                }
                add.push("-interface".into());
                add.push(self.if_name.clone());
                let _ = run_cmd("route", del).await;
                run_cmd("route", add).await
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            {
                let _ = (cidr, v6);
                Ok(())
            }
        }

        async fn defend_block_floor(&self) {
            #[cfg(windows)]
            {
                let Some((net, plen)) = self.connected_v4 else {
                    return;
                };
                self.defend_block_floor_of(net, plen).await;
            }
        }

        async fn defend_block_floor_of(&self, net: Ipv4Addr, plen: u8) {
            #[cfg(windows)]
            {
                let Some(floors) = super::floor_cidrs(net, plen) else {
                    return;
                };
                // The gate FAILS TOWARD WITHHOLD: an unreadable interface
                // table (or an adapter whose own address isn't visible yet —
                // the #388 listing race) installs nothing this wave and
                // retries on the next.
                let safe = non_overlay_v4_addrs(&self.if_name).is_some_and(|addrs| {
                    super::floor_safe(&addrs, self.uplink_v4().map(|r| r.gateway), (net, plen))
                });
                // Log the DECISION only on a flip — the wave re-runs this
                // every 2–30 s, per block (a shared multi-org device carries
                // one independently-flipping decision per org's block).
                let state = if safe { 1u8 } else { 2u8 };
                let flipped = {
                    let mut st = self.floor_state.lock().unwrap_or_else(|e| e.into_inner());
                    match st.iter_mut().find(|(b, _)| *b == (net, plen)) {
                        Some((_, s)) if *s == state => false,
                        Some((_, s)) => {
                            *s = state;
                            true
                        }
                        None => {
                            st.push(((net, plen), state));
                            true
                        }
                    }
                };
                if flipped {
                    if safe {
                        tracing::info!(
                            block = %format!("{net}/{plen}"),
                            "overlay: installing block-floor routes (corp-VPN /11 leak guard)"
                        );
                    } else {
                        tracing::warn!(
                            block = %format!("{net}/{plen}"),
                            "overlay: WITHHOLDING block-floor routes — the uplink or default \
                             gateway sits inside the overlay block (ISP CGNAT?); absent-peer \
                             traffic may reach the physical gateway instead of dropping locally"
                        );
                    }
                }
                for c in &floors {
                    if safe {
                        let _ = self.add_cidr_route(c).await;
                    } else {
                        self.del_cidr_route(c).await;
                    }
                }
                // corplap route war, 08-18 — with the floor SAFE (the uplink
                // provably lives outside the block), also evict every
                // foreign route INSIDE the block at any prefix length: the
                // Check Point manager shadows the overlay with /24s +
                // learned host routes that the exact-plen per-/32 eviction
                // never matched, steering per-destination traffic into the
                // corp gateway. Under `!safe` (CGNAT uplink inside the
                // block) we touch nothing — the same fail-toward-withhold
                // stance as the floor itself.
                //
                // v3 (#23) — DEBOUNCED: the manager re-adds the same rows
                // within seconds of every deletion, so the unconditional
                // per-wave eviction was a permanent delete→re-add flap that
                // fed the netstate watcher a Major every few waves and
                // force-poked every direct carrier on the host. Evict only
                // when the foreign row SET changed; an unchanged set sits in
                // the table losing every lookup (stolen destinations are
                // repointed by the reclaim step, which brings its own
                // targeted eviction). Reclaim OFF restores the blind wave.
                if safe {
                    let ours = self.dev.tun_luid();
                    if !route_reclaim_enabled() {
                        winroute::evict_foreign_in_block_v4(ours, net, plen);
                    } else {
                        let fp = winroute::foreign_in_block_fp(ours, net, plen);
                        let changed = {
                            let mut st = self.in_block_fp.lock().unwrap_or_else(|e| e.into_inner());
                            match st.iter_mut().find(|(b, _)| *b == (net, plen)) {
                                Some((_, s)) if *s == fp => false,
                                Some((_, s)) => {
                                    *s = fp;
                                    true
                                }
                                None => {
                                    st.push(((net, plen), fp));
                                    true
                                }
                            }
                        };
                        if changed && fp != 0 {
                            winroute::evict_foreign_in_block_v4(ours, net, plen);
                        }
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (net, plen);
            }
        }

        /// corplap route war v3 (#23) — see
        /// [`TunIo::verify_peer_path_ownership`]. Windows-only, and a
        /// two-rung escalation rather than a fight: ask the FIB who owns
        /// each peer, and on a foreign winner (1) re-assert the INTERFACE
        /// metric, which is the rung that decides same-prefix ties and which
        /// a network-profile change or adapter reset can revert underneath
        /// us, then (2) for anything still lost — meaning the competitor is
        /// pinned as low as we can go and takes the ifIndex tie-break —
        /// escalate that peer's own ROUTE metric to 0, which wins outright.
        /// Everything fails toward no-op + a throttled report.
        async fn verify_peer_path_ownership(&self, peers: &[Ipv4Addr]) {
            #[cfg(windows)]
            {
                if !route_reclaim_enabled() {
                    return;
                }
                let ours = self.dev.tun_luid();
                // Ask the FIB, per peer, which interface it would actually
                // use. `GetBestRoute2` is the honest oracle here — unlike the
                // OS path table it answers for every destination, not only
                // ones with live conversations (the path table is empty for
                // relay-carried peers, which is exactly the set that was
                // captured on corplap).
                let stolen: Vec<Ipv4Addr> = peers
                    .iter()
                    .copied()
                    .filter(|ip| {
                        winroute::best_route_luid(std::net::IpAddr::V4(*ip))
                            .is_some_and(|luid| luid != ours)
                    })
                    .collect();
                if stolen.is_empty() {
                    return;
                }
                // Something outranks us for real destinations. The metric is
                // the lever that decides ties, so re-assert it first (a
                // network-profile change or an adapter reset reverts it) and
                // re-check: if the peers flip back, the pin was simply stale.
                let want = iface_metric();
                let _ = winroute::set_iface_metric_v4(ours, want);
                // #1342 — re-assert the v6 pin on the same trigger. It is
                // reverted by the same events (a network-profile change, an
                // adapter reset), and a pin that is only ever set at startup
                // is a pin that is quietly gone by the time it matters.
                if route_win_enabled() {
                    let _ = winroute::set_iface_metric_v6(ours, want);
                }
                let still: Vec<Ipv4Addr> = stolen
                    .iter()
                    .copied()
                    .filter(|ip| {
                        winroute::best_route_luid(std::net::IpAddr::V4(*ip))
                            .is_some_and(|luid| luid != ours)
                    })
                    .collect();
                // rc.411 (#23) — still losing at our lowest INTERFACE metric
                // means the competitor's interface is pinned as low as ours
                // (winhost-a's Check Point NIC and winhost-b's both sit at 0),
                // so the totals TIE and Windows breaks it on lower ifIndex —
                // theirs, since our adapter is created later. The interface
                // metric has no lower rung, so escalate the ROUTE metric for
                // exactly these peers: 0 + 0 beats their 1 + 0 outright.
                // `ensure` auto-yields to 1 on hosts where metric-0 rows do
                // not survive (rc.289), and the escalation is remembered so
                // the next defense wave re-asserts 0 instead of resetting to
                // 1 (which would flap the prefix every wave).
                let escalated: Vec<Ipv4Addr> = if still.is_empty() {
                    Vec::new()
                } else {
                    let mut done = Vec::new();
                    for ip in &still {
                        {
                            let mut set = self.escalated.lock().unwrap_or_else(|e| e.into_inner());
                            if !set.insert(*ip) {
                                continue; // already escalated; nothing new to try
                            }
                        }
                        let _ = winroute::ensure(ours, std::net::IpAddr::V4(*ip), 32, 0);
                        if winroute::best_route_luid(std::net::IpAddr::V4(*ip)) == Some(ours) {
                            done.push(*ip);
                        }
                    }
                    done
                };
                let unresolved: Vec<Ipv4Addr> = still
                    .iter()
                    .copied()
                    .filter(|ip| !escalated.contains(ip))
                    .collect();
                if !escalated.is_empty()
                    && let Some(first) = escalated.first()
                    && let Some(suppressed) = winroute::reclaim_note(std::net::IpAddr::V4(*first))
                {
                    tracing::warn!(
                        recovered = escalated.len(),
                        example = %first,
                        suppressed_since_last = suppressed,
                        "overlay: a competing interface is pinned as low as ours, so the \
                         interface metric only TIED (they win the ifIndex tie-break) — \
                         escalated these peers' routes to metric 0, which wins outright"
                    );
                }
                if still.is_empty() {
                    // The re-assert alone recovered them: the pin had been
                    // reverted underneath us.
                    if let Some(first) = stolen.first()
                        && let Some(suppressed) =
                            winroute::reclaim_note(std::net::IpAddr::V4(*first))
                    {
                        tracing::warn!(
                            recovered = stolen.len(),
                            metric = want,
                            suppressed_since_last = suppressed,
                            "overlay: the interface-metric pin had been reverted (network \
                             profile change / adapter reset?) — re-asserted, and the peers \
                             it had cost us are back on the overlay NIC"
                        );
                    }
                } else if let Some(first) = unresolved.first()
                    && let Some(suppressed) = winroute::reclaim_note(std::net::IpAddr::V4(*first))
                {
                    // Neither the interface metric nor a metric-0 route won:
                    // the competitor matches us at both rungs (or holds a
                    // LONGER prefix than any route of ours — longest match is
                    // evaluated before metric, so a rival /32 beats our /24
                    // floor at any metric until our own /32 for that peer is
                    // installed).
                    tracing::warn!(
                        stolen = unresolved.len(), metric = want,
                        example = %first,
                        suppressed_since_last = suppressed,
                        "overlay: another interface OUTRANKS the overlay for installed \
                         peers even at metric 0 — it either matches us at every metric \
                         rung or holds a longer prefix. Node-initiated traffic to them \
                         uses that interface (inbound still works). Split-exclude the \
                         overlay prefixes on the competing product"
                    );
                }
            }
            #[cfg(not(windows))]
            {
                let _ = peers;
            }
        }

        async fn del_cidr_route(&self, cidr: &str) {
            let v6 = is_v6_cidr(cidr);
            #[cfg(target_os = "windows")]
            {
                // rc.208 — IP Helper (see `winroute`).
                let _ = v6;
                if let Some((addr, plen)) = parse_cidr(cidr) {
                    winroute::del(self.dev.tun_luid(), addr, plen);
                }
            }
            #[cfg(target_os = "linux")]
            {
                let mut args: Vec<String> = Vec::new();
                if v6 {
                    args.push("-6".into());
                }
                args.extend([
                    "route".into(),
                    "del".into(),
                    cidr.to_string(),
                    "dev".into(),
                    self.if_name.clone(),
                ]);
                let _ = run_cmd("ip", args).await;
            }
            #[cfg(target_os = "macos")]
            {
                let (net, plen) = cidr.split_once('/').unwrap_or((cidr, ""));
                let family = if v6 { "-inet6" } else { "-inet" };
                let mut args: Vec<String> = vec![
                    "-n".into(),
                    "delete".into(),
                    family.into(),
                    "-net".into(),
                    net.into(),
                ];
                if !plen.is_empty() {
                    args.push("-prefixlen".into());
                    args.push(plen.into());
                }
                let _ = run_cmd("route", args).await;
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            let _ = (cidr, v6);
        }

        /// P5 — install a host exemption for `ip` (a `/32` for v4, `/128` for v6)
        /// via the host's ORIGINAL default gateway of the matching family (captured
        /// at bring-up), NOT the overlay NIC, so the exit-node split-default can't
        /// capture this carrier-critical endpoint. `Err` when no default route of
        /// that family was discovered — the caller's exemption gate then withholds
        /// that family's exit routing (v4 or v6) rather than wedging.
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        async fn add_host_exemption(&self, ip: std::net::IpAddr) -> std::io::Result<()> {
            let Some(pin) = self.pin_through_uplink(ip) else {
                return Err(std::io::Error::other(if ip.is_ipv6() {
                    "no original IPv6 default route captured; cannot exempt v6 carrier endpoint"
                } else {
                    "no original IPv4 default route captured; cannot exempt carrier endpoint"
                }));
            };
            install_pin_route(&pin).await?;
            // FR-97 P0e (N12) — a pin this run made through another uplink
            // comes out once the new one is in. Linux's `replace` has already
            // superseded it (one route per prefix), but Windows keys a route
            // by (interface, prefix, next hop), so the old one would stay
            // beside the new and could still win the lookup.
            #[cfg(target_os = "windows")]
            if let Some(prev) = crate::overlay::host_ledger::pin_record(ip)
                && prev != pin
            {
                remove_pin_route(&prev).await;
            }
            // FR-97 P0e — recorded the moment it is in, so no exit of the
            // daemon, clean or not, can leave it behind unrecorded.
            crate::overlay::host_ledger::record_pin(pin);
            Ok(())
        }

        /// FR-97 P1a — the macOS arm: a static host route through the CURRENT
        /// uplink's next hop, which counts only once the routing TABLE shows
        /// it. Never a lookup: `route -n get` answers with the scoped clone a
        /// connection left for the address, even once the pin is in (see
        /// [`super::BsdTableRow`]; field, a tart Mac on 0.4.133).
        ///
        /// BSD `route` has no idempotent write, so this looks first (#1856):
        /// - a pin that already holds is left alone. The gate re-pins after
        ///   every carrier change, and a re-write is a route-monitor event;
        /// - a pin that does not hold (through the old uplink after a network
        ///   change, a pin a crashed run left, an interface route for the
        ///   address) is deleted, then added. Its traffic was not reaching the
        ///   uplink anyway, so the gap costs nothing. `route change` cannot do
        ///   it: it resolves its target the way the lookup does, and on the
        ///   field Mac it left the pin untouched;
        /// - anything else gets `route add`.
        ///
        /// Then the table decides, whatever the write said: an `add` that lost
        /// a race may still have left the right route, and a write that
        /// succeeded proves nothing about where it went. A route this call
        /// wrote that does not hold comes out again: the gate withholds on the
        /// `Err`, and a route nobody tracks is the one a later network change
        /// turns into a black hole.
        ///
        /// #2081 was this arm's absence: the trait's `Ok(())` told the gate
        /// every exemption was pinned, and the `/1`s then captured the WS,
        /// coturn and the exit's own endpoint.
        #[cfg(target_os = "macos")]
        async fn add_host_exemption(&self, ip: std::net::IpAddr) -> std::io::Result<()> {
            if !exit_client_macos_enabled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "the macOS exit client is switched off (ROOMLERD_EXIT_CLIENT_MACOS=0)",
                ));
            }
            let v6 = ip.is_ipv6();
            let Some(uplink) = self.current_uplink(v6).await else {
                return Err(std::io::Error::other(if v6 {
                    "no IPv6 default route through a gateway to pin it on"
                } else {
                    "no IPv4 default route through a gateway to pin it on"
                }));
            };
            // FR-97 P0e — a pin that holds is recorded, whether it was just
            // written or a previous run's that this run now owns.
            let record = |up: &super::BsdUplink| {
                crate::overlay::host_ledger::record_pin(crate::overlay::host_ledger::PinRecord {
                    ip,
                    gateway: up.gateway_arg.clone(),
                    interface: up.interface.clone(),
                    onlink: false,
                })
            };
            let rows = bsd_table(v6).await;
            let pin = super::bsd_pin_row(&rows, ip);
            if super::bsd_pin_holds(pin, &uplink) {
                record(&uplink);
                return Ok(());
            }
            if pin.is_some() {
                bsd_unpin(ip).await;
            }
            let wrote = bsd_route_write(vec![
                "-n".into(),
                "add".into(),
                bsd_family(v6).into(),
                "-host".into(),
                ip.to_string(),
                uplink.gateway_arg.clone(),
            ])
            .await;
            let rows = bsd_table(v6).await;
            let pin = super::bsd_pin_row(&rows, ip);
            if super::bsd_pin_holds(pin, &uplink) {
                record(&uplink);
                return Ok(());
            }
            let want = format!("{} on {}", uplink.gateway_arg, uplink.interface);
            let why = match (wrote, pin) {
                (Err(e), _) => format!("route refused the pin through {want}: {e}"),
                (Ok(()), Some(row)) => {
                    format!(
                        "the pin went via {} on {}, not {want}",
                        row.gateway, row.netif
                    )
                }
                (Ok(()), None) => {
                    format!("no pin in the routing table after `route add` through {want}")
                }
            };
            // Whatever pin the table still shows comes out: the one this call
            // wrote, or the one it failed to replace. Neither is tracked.
            if pin.is_some_and(|row| row.netif != self.if_name) {
                bsd_unpin(ip).await;
            }
            crate::overlay::host_ledger::forget_pin(ip);
            Err(std::io::Error::other(why))
        }

        /// Remove a macOS exemption: our pin for `ip`, as the table shows it,
        /// never a route on this utun (a peer route). The table comes first
        /// because `route delete` keys on the destination alone, and with no
        /// unscoped pin left it removed something else on the field Mac.
        #[cfg(target_os = "macos")]
        async fn del_host_exemption(&self, ip: std::net::IpAddr) {
            let rows = bsd_table(ip.is_ipv6()).await;
            if super::bsd_pin_row(&rows, ip).is_some_and(|row| row.netif != self.if_name) {
                bsd_unpin(ip).await;
            }
            crate::overlay::host_ledger::forget_pin(ip);
        }

        /// FR-97 P1a — every pin the table does not show through its family's
        /// CURRENT uplink. Re-reads the uplinks first, which is what notices a
        /// network change, then reads one table per family.
        #[cfg(target_os = "macos")]
        async fn stale_host_exemptions(
            &self,
            pinned: &[std::net::IpAddr],
        ) -> Vec<std::net::IpAddr> {
            let mut stale = Vec::new();
            for v6 in [false, true] {
                let family: Vec<std::net::IpAddr> = pinned
                    .iter()
                    .copied()
                    .filter(|ip| ip.is_ipv6() == v6)
                    .collect();
                if family.is_empty() {
                    continue;
                }
                let uplink = self.current_uplink(v6).await;
                let rows = bsd_table(v6).await;
                for ip in family {
                    let holds = uplink
                        .as_ref()
                        .is_some_and(|u| super::bsd_pin_holds(super::bsd_pin_row(&rows, ip), u));
                    if !holds {
                        stale.push(ip);
                    }
                }
            }
            stale
        }

        /// #2081 — no host-exemption arm on this platform, so REFUSE.
        ///
        /// This device installs real OS routes, so inheriting the trait's
        /// `Ok(())` would tell `reconcile_exit_routing` that every carrier
        /// exemption was pinned when none was, and it would then route the WS,
        /// coturn and the exit's own endpoint into the device that carries
        /// them: the self-wedge the exemption gate exists to stop. An `Err`
        /// makes the gate WITHHOLD, and `meshharbor status` says why.
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        async fn add_host_exemption(&self, ip: std::net::IpAddr) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("no host-exemption route support on this platform; cannot exempt {ip}"),
            ))
        }

        /// Remove a host exemption installed by [`Self::add_host_exemption`]
        /// (`/32` v4 or `/128` v6). Best-effort. FR-97 P0e — the route as
        /// it was installed, from the record, so a pin still on an uplink the
        /// host has left comes out too; the uplink in force only for a pin
        /// with no record.
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        async fn del_host_exemption(&self, ip: std::net::IpAddr) {
            if let Some(pin) =
                crate::overlay::host_ledger::pin_record(ip).or_else(|| self.pin_through_uplink(ip))
            {
                remove_pin_route(&pin).await;
            }
            crate::overlay::host_ledger::forget_pin(ip);
        }

        /// FR-97 P0e (N12) — every pin the table does not show through its
        /// family's CURRENT uplink: the Linux and Windows twin of the macOS
        /// sweep. Re-reads each family's uplink and adopts one that moved,
        /// so the re-pin that follows goes through it; one table read per
        /// family, and an unreadable table changes nothing.
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        async fn stale_host_exemptions(
            &self,
            pinned: &[std::net::IpAddr],
        ) -> Vec<std::net::IpAddr> {
            let mut stale = Vec::new();
            for v6 in [false, true] {
                let family: Vec<std::net::IpAddr> = pinned
                    .iter()
                    .copied()
                    .filter(|ip| ip.is_ipv6() == v6)
                    .collect();
                if family.is_empty() {
                    continue;
                }
                let if_name = self.if_name.clone();
                let Some(table) =
                    tokio::task::spawn_blocking(move || exemption_table(v6, &if_name))
                        .await
                        .ok()
                        .flatten()
                else {
                    continue;
                };
                stale.extend(self.sweep_family(v6, &family, table));
            }
            stale
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    impl SystemTun {
        /// The v4 uplink exemptions pin through right now.
        fn uplink_v4(&self) -> Option<OrigDefaultRoute> {
            self.orig_default
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// The v6 uplink exemptions pin through right now.
        fn uplink_v6(&self) -> Option<OrigDefaultRoute6> {
            self.orig_default_v6
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// The pin `ip` would get through its family's uplink in force.
        fn pin_through_uplink(
            &self,
            ip: std::net::IpAddr,
        ) -> Option<crate::overlay::host_ledger::PinRecord> {
            let (gateway, interface, onlink) = if ip.is_ipv6() {
                let up = self.uplink_v6()?;
                #[cfg(target_os = "linux")]
                let onlink = up.onlink;
                #[cfg(not(target_os = "linux"))]
                let onlink = false;
                (up.gateway.to_string(), up.interface, onlink)
            } else {
                let up = self.uplink_v4()?;
                #[cfg(target_os = "linux")]
                let onlink = up.onlink;
                #[cfg(not(target_os = "linux"))]
                let onlink = false;
                (up.gateway.to_string(), up.interface, onlink)
            };
            Some(crate::overlay::host_ledger::PinRecord {
                ip,
                gateway,
                interface,
                onlink,
            })
        }

        /// FR-97 P0e (N12) — one family's sweep: adopt the uplink the table
        /// shows when it moved (logged), and name the pins that do not hold.
        fn sweep_family(
            &self,
            v6: bool,
            pins: &[std::net::IpAddr],
            table: ExemptionTable,
        ) -> Vec<std::net::IpAddr> {
            let ExemptionTable { now, hosts } = table;
            let held = if v6 {
                self.uplink_v6().map(|r| r.key())
            } else {
                self.uplink_v4().map(|r| r.key())
            };
            let now_key = now.as_ref().map(SeenUplink::key);
            let (adopt, stale) = super::stale_pins(pins, held.as_ref(), now_key.as_ref(), &hosts);
            if let (Some(to), Some(seen)) = (adopt, now) {
                tracing::info!(
                    family = if v6 { "v6" } else { "v4" },
                    was = ?held.map(|k| format!("{} on {}", k.gateway, k.interface)),
                    gateway = %to.gateway,
                    interface = %to.interface,
                    "overlay exit-node: carrier exemptions now pin through this uplink"
                );
                match seen {
                    SeenUplink::V4(r) => {
                        *self.orig_default.lock().unwrap_or_else(|e| e.into_inner()) = Some(r)
                    }
                    SeenUplink::V6(r) => {
                        *self
                            .orig_default_v6
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = Some(r)
                    }
                }
            }
            stale
        }
    }

    /// FR-97 P0e (N12) — one family's routing table as the sweep reads it:
    /// the uplink it shows now (`None`: no usable one at the moment), and
    /// every gateway host route in it.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    struct ExemptionTable {
        now: Option<SeenUplink>,
        hosts: Vec<(std::net::IpAddr, super::UplinkKey)>,
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    enum SeenUplink {
        V4(OrigDefaultRoute),
        V6(OrigDefaultRoute6),
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    impl SeenUplink {
        fn key(&self) -> super::UplinkKey {
            match self {
                SeenUplink::V4(r) => r.key(),
                SeenUplink::V6(r) => r.key(),
            }
        }
    }

    /// FR-97 P0e (N12) — read one family's table: `ip -4|-6 route show` (the
    /// main table, where the default and our pins live), parsed for both.
    #[cfg(target_os = "linux")]
    fn exemption_table(v6: bool, overlay_if: &str) -> Option<ExemptionTable> {
        let out = std::process::Command::new("ip")
            .args([if v6 { "-6" } else { "-4" }, "route", "show"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let now = if v6 {
            parse_linux_default_route_v6(&text, overlay_if).map(SeenUplink::V6)
        } else {
            parse_linux_default_route(&text, overlay_if).map(SeenUplink::V4)
        };
        Some(ExemptionTable {
            now,
            hosts: super::parse_linux_host_routes(&text),
        })
    }

    /// FR-97 P0e (N12) — read one family's FIB ([`winroute::exemption_view`]).
    #[cfg(target_os = "windows")]
    fn exemption_table(v6: bool, _overlay_if: &str) -> Option<ExemptionTable> {
        let (uplink, hosts) = winroute::exemption_view(v6)?;
        let hosts: Vec<(std::net::IpAddr, super::UplinkKey)> = hosts
            .into_iter()
            .map(|(dest, ifindex, gateway)| {
                (
                    dest,
                    super::UplinkKey {
                        interface: ifindex.to_string(),
                        gateway,
                    },
                )
            })
            .collect();
        let now = match uplink {
            Some((ifindex, std::net::IpAddr::V6(gateway))) if v6 => {
                Some(SeenUplink::V6(OrigDefaultRoute6 {
                    gateway,
                    interface: ifindex.to_string(),
                }))
            }
            Some((ifindex, std::net::IpAddr::V4(gateway))) if !v6 => {
                Some(SeenUplink::V4(OrigDefaultRoute {
                    gateway,
                    interface: ifindex.to_string(),
                }))
            }
            _ => None,
        };
        Some(ExemptionTable { now, hosts })
    }

    /// FR-97 P0e — install `pin` (Linux `ip route replace`, Windows a typed
    /// IP Helper row, idempotent by AlreadyExists).
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    async fn install_pin_route(
        pin: &crate::overlay::host_ledger::PinRecord,
    ) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            run_cmd("ip", linux_pin_args("replace", pin)).await
        }
        #[cfg(target_os = "windows")]
        {
            let (ifindex, gateway) = windows_pin_route(pin).ok_or_else(|| {
                std::io::Error::other("the uplink's ifIndex or next hop is not an address")
            })?;
            winroute::add_gateway_route(ifindex, pin.ip, pin_plen(pin.ip), gateway, 1)
        }
    }

    /// FR-97 P0e — remove `pin`, exactly as it was installed. Best-effort.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    async fn remove_pin_route(pin: &crate::overlay::host_ledger::PinRecord) {
        #[cfg(target_os = "linux")]
        {
            let _ = run_cmd("ip", linux_pin_args("del", pin)).await;
        }
        #[cfg(target_os = "windows")]
        if let Some((ifindex, gateway)) = windows_pin_route(pin) {
            winroute::del_gateway_route(ifindex, pin.ip, pin_plen(pin.ip), gateway);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn pin_plen(ip: std::net::IpAddr) -> u8 {
        if ip.is_ipv6() { 128 } else { 32 }
    }

    /// `ip [-6] route <verb> <ip>/<plen> via <gw> dev <if> [onlink]`. Carry
    /// `onlink` when the default did, or the kernel rejects a `via` gateway
    /// that is not on a connected subnet ("Nexthop has invalid gateway").
    #[cfg(target_os = "linux")]
    fn linux_pin_args(verb: &str, pin: &crate::overlay::host_ledger::PinRecord) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();
        if pin.ip.is_ipv6() {
            args.push("-6".into());
        }
        args.extend([
            "route".into(),
            verb.into(),
            format!("{}/{}", pin.ip, pin_plen(pin.ip)),
            "via".into(),
            pin.gateway.clone(),
            "dev".into(),
            pin.interface.clone(),
        ]);
        if pin.onlink {
            args.push("onlink".into());
        }
        args
    }

    /// A Windows pin's (ifIndex, next hop), as recorded.
    #[cfg(target_os = "windows")]
    fn windows_pin_route(
        pin: &crate::overlay::host_ledger::PinRecord,
    ) -> Option<(u32, std::net::IpAddr)> {
        Some((pin.interface.parse().ok()?, pin.gateway.parse().ok()?))
    }

    /// Does an interface listing mention `ip`?
    ///
    /// "Ask the interface instead of reading the error", for the ONE platform
    /// still on subprocess address ops: `ifconfig <utun>` on macOS. (Windows
    /// moved to typed IP Helper in N1 — `winaddr` — so its netsh listing
    /// probe is gone.) Everything `ifconfig` SAYS is localized — labels and
    /// errors alike — but an IPv4 literal is not, so the address is the only
    /// token worth reading. Split on everything that cannot appear inside a
    /// dotted quad and compare whole tokens: a substring test would let
    /// `100.64.0.2` match a listed `100.64.0.28`.
    ///
    /// Compiled everywhere so every platform's test run covers it.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn listing_mentions_address(listed: &str, ip: Ipv4Addr) -> bool {
        let want = ip.to_string();
        listed
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .any(|tok| tok == want)
    }

    /// Is `cidr` an IPv6 CIDR? A colon only ever appears in the v6 textual form
    /// (`"::/1"`, `"8000::/1"`, `"fd72:6f6f:6d6c::/96"`), never in a v4 one
    /// (`"0.0.0.0/1"`) — so this cheap check picks the right OS route family for
    /// [`TunIo::add_cidr_route`] / [`TunIo::del_cidr_route`] without pulling in a
    /// parser. Pure, so it unit-tests directly.
    fn is_v6_cidr(cidr: &str) -> bool {
        cidr.contains(':')
    }

    /// P5 exit-node crash-safety (A2) — synchronously delete the split-default
    /// routes (the v4 + v6 `/1` halves) from the overlay NIC WITHOUT a live
    /// [`SystemTun`]. Removes EXACTLY the
    /// [`SPLIT_DEFAULT_V4`](crate::overlay::runtime::SPLIT_DEFAULT_V4) and
    /// [`SPLIT_DEFAULT_V6`](crate::overlay::runtime::SPLIT_DEFAULT_V6) the
    /// installer installs (one source of truth), scoped to the roomler NIC so it
    /// never touches another VPN's `/1`.
    ///
    /// Two callers, both bypassing the runtime's RAII teardown:
    ///
    /// - the **boot-time reconciler** — heals a `/1` a crash / kill / unclean
    ///   reboot left behind. Critical on Windows: Wintun's adapter persists by
    ///   name across a crash, so a stale `0.0.0.0/1 interface=roomler` blackholes
    ///   ALL egress to a dead NIC until the next clean run. (On Linux a
    ///   `dev`-scoped route auto-culls when the TUN dies, but a kill mid-reroute
    ///   can still leave one, so we heal there too.)
    /// - the **pre-`process::exit` cleanup** on the paths that skip `Drop`
    ///   (watchdog stall, self-update, agent-deleted).
    ///
    /// Best-effort (an absent route just errors, ignored); sync `std::process` so
    /// it runs at boot and as a last gasp with no async runtime.
    ///
    /// Multi-org v2 — `if_name` scopes the purge to ONE adapter; legacy
    /// callers pass [`IF_NAME`] (the historical singleton).
    pub fn purge_split_default(if_name: &str) {
        for cidr in crate::overlay::runtime::SPLIT_DEFAULT_V4
            .iter()
            .chain(crate::overlay::runtime::SPLIT_DEFAULT_V6.iter())
        {
            purge_one(if_name, cidr);
        }
    }

    /// Boot reconciler for STALE PEER/SUBNET ROUTES on a persisted TUN.
    ///
    /// `install_subnets` writes an OS route **and** the crypto-router entry in
    /// one call, so within a single runtime generation the two cannot diverge.
    /// They diverge ACROSS generations: with `overlay_tun_persist` the wintun
    /// device (and its routing table entries) outlive the runtime that created
    /// them, while the router is rebuilt from scratch on every WS session. A
    /// route left behind by an older generation therefore points at an
    /// interface whose router has no matching `allowed_ips` — packets reach the
    /// TUN and are dropped locally, never even leaving the host.
    ///
    /// That is a SILENT black hole: the OS route looks correct, the peer is
    /// online, the carrier is up, and only the traffic disappears. Field case
    /// 2026-08-03 — `10.66.24.53/32` and `10.66.51.147/32` sat on ifIndex 61
    /// with a healthy carrier while every connection timed out; a daemon
    /// restart (which re-ran `install_peers`) fixed it instantly.
    ///
    /// Called at TUN bring-up, BEFORE any peer is installed. At that instant the
    /// router is empty by construction, so every route on the device except its
    /// own connected prefixes is a leftover — which is why this needs no
    /// keep-set and cannot race a legitimate install. `install_peers` then
    /// re-adds exactly what the current netmap says.
    ///
    /// Best-effort and sync, like [`purge_split_default`]: a failure just leaves
    /// the pre-existing (broken) state, never a worse one.
    ///
    /// Multi-org v2 — `if_name` scopes the reconcile to ONE adapter; legacy
    /// callers pass [`IF_NAME`] (the historical singleton).
    pub fn purge_stale_peer_routes(if_name: &str) {
        let stale: Vec<String> = enumerate_if_routes(if_name)
            .into_iter()
            .filter(|c| !is_derived_prefix(c))
            .collect();
        if stale.is_empty() {
            return;
        }
        for cidr in &stale {
            purge_one(if_name, cidr);
        }
        tracing::info!(
            count = stale.len(), routes = ?stale,
            "overlay: boot reconcile — dropped stale routes left by a previous generation \
             on a persisted TUN (their crypto-router entries are gone, so they black-hole)"
        );
    }

    /// FR-97 N14 — is `ifref` one of this process's live adapters? `ifref` is
    /// in netstate's identity space: the interface index on Windows (where any
    /// adapter NAMED like ours counts too, as for the pins), the device name
    /// elsewhere.
    pub(crate) fn is_own_ifref(ifref: &str) -> bool {
        #[cfg(windows)]
        {
            ifref
                .parse::<u32>()
                .ok()
                .and_then(winroute::luid_of_index)
                .is_some_and(winroute::is_ours_or_roomler)
        }
        #[cfg(not(windows))]
        {
            own_adapters::is_own_name(ifref)
        }
    }

    /// FR-97 N14 — the default route BENEATH our adapters, as `(ifref,
    /// gateway)` in netstate's identity space: the uplink the exit's carrier
    /// pins go through, read by the code that pins them (Windows: the FIB
    /// view; Linux: the main table's best `/0`; macOS: `route -n get default`,
    /// which answers with the `/0` itself while our `/1`s are in — a lookup of
    /// a far address answers with a `/1`, tart 2026-10-14). Our adapters
    /// never hold a `/0`. `None` when there is no such route right now.
    pub(crate) fn uplink_beneath(v6: bool) -> Option<(String, Option<std::net::IpAddr>)> {
        #[cfg(windows)]
        {
            let (uplink, _) = winroute::exemption_view(v6)?;
            uplink.map(|(ifindex, gateway)| (ifindex.to_string(), Some(gateway)))
        }
        #[cfg(target_os = "linux")]
        {
            let out = std::process::Command::new("ip")
                .args([if v6 { "-6" } else { "-4" }, "route", "show", "default"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let text = String::from_utf8_lossy(&out.stdout);
            if v6 {
                parse_linux_default_route_v6(&text, IF_NAME)
                    .map(|r| (r.interface, Some(std::net::IpAddr::V6(r.gateway))))
            } else {
                parse_linux_default_route(&text, IF_NAME)
                    .map(|r| (r.interface, Some(std::net::IpAddr::V4(r.gateway))))
            }
        }
        #[cfg(target_os = "macos")]
        {
            discover_bsd_uplink(v6, "").map(|u| (u.interface, Some(u.gateway)))
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = v6;
            None
        }
    }

    /// FR-97 P0e — remove the exit-client pins a run recorded and did not
    /// remove (see [`crate::overlay::host_ledger::purge`], the one caller).
    /// Synchronous and context-free like the purges above. Each arm removes a
    /// route only while it still matches the record: Linux and Windows delete
    /// the exact (address, next hop, interface) route, and macOS deletes only
    /// an unscoped static host route the table shows through the recorded next
    /// hop and interface (`route delete` keys on the destination alone).
    pub fn purge_pins(pins: &[crate::overlay::host_ledger::PinRecord]) {
        if pins.is_empty() {
            return;
        }
        // Only what the table still held. After a reboot that is nothing: the
        // kernel dropped the routes and only the ledger remembers them, so a
        // count of RECORDS here read as "the reboot left N pins" (FR-97 §8,
        // 2026-10-16).
        #[cfg_attr(
            not(any(target_os = "linux", target_os = "windows", target_os = "macos")),
            allow(unused_mut)
        )]
        let mut removed = 0usize;
        for p in pins {
            #[cfg(target_os = "linux")]
            if std::process::Command::new("ip")
                .args(linux_pin_args("del", p))
                .output()
                .is_ok_and(|o| o.status.success())
            {
                removed += 1;
            }
            #[cfg(target_os = "windows")]
            if let Some((ifindex, gw)) = windows_pin_route(p)
                && winroute::del_gateway_route(ifindex, p.ip, pin_plen(p.ip), gw)
            {
                removed += 1;
            }
            #[cfg(target_os = "macos")]
            {
                let v6 = p.ip.is_ipv6();
                let rows = std::process::Command::new("netstat")
                    .args(["-rnW", "-f", if v6 { "inet6" } else { "inet" }])
                    .output()
                    .map(|o| super::parse_bsd_netstat(&String::from_utf8_lossy(&o.stdout)))
                    .unwrap_or_default();
                let recorded = super::bsd_addr(&p.gateway, v6).map(|gateway| super::BsdUplink {
                    gateway,
                    gateway_arg: p.gateway.clone(),
                    interface: p.interface.clone(),
                });
                if recorded
                    .is_some_and(|up| super::bsd_pin_holds(super::bsd_pin_row(&rows, p.ip), &up))
                    && std::process::Command::new("route")
                        .args(["-n", "delete", bsd_family(v6), "-host", &p.ip.to_string()])
                        .output()
                        .is_ok_and(|o| o.status.success())
                {
                    removed += 1;
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            let _ = p;
        }
        tracing::info!(
            recorded = pins.len(),
            removed,
            pins = ?pins.iter().map(|p| p.ip).collect::<Vec<_>>(),
            "overlay: cleared the exit-client pins the host ledger recorded (removed = still in the routing table)"
        );
    }

    /// Entries the OS DERIVES from the interface address rather than routes we
    /// installed: the on-link overlay prefixes plus the multicast / broadcast /
    /// link-local rows Windows adds to every NIC. Deleting these would break the
    /// overlay itself (or churn state the OS immediately recreates).
    ///
    /// Peer `/32`s are deliberately NOT protected — a stale peer route is
    /// exactly what this reconciler exists to remove, and `install_peers`
    /// re-adds the live ones moments later.
    ///
    /// Multi-org P2a forward-compat: the v4 keep-rule is "any on-link BLOCK
    /// (prefix < 32) inside the CGNAT `100.64.0.0/10`", NOT the literal
    /// `100.64.0.0/…` string it used to be. Tenant-block addressing (P2b)
    /// hands tenants sub-blocks like `100.68.12.0/22`; under the old literal
    /// this boot reconciler would have purged a renumbered tenant's own
    /// connected route — a host-wide mesh blackhole on every start. This rc
    /// must be fleet-wide BEFORE any tenant migrates. Same reasoning for the
    /// ULA: prefix-match the base, not the exact `/96` const.
    fn is_derived_prefix(cidr: &str) -> bool {
        let c = cidr.trim();
        v4_block_in_cgnat(c)                    // any on-link v4 block within 100.64/10
            || c.starts_with("fd72:6f6f:6d6c:") // the overlay ULA (any block size)
            || c.starts_with("224.")            // v4 multicast
            || c == "255.255.255.255/32"        // v4 broadcast
            || c.starts_with("ff00:")           // v6 multicast
            || c.starts_with("fe80:") // v6 link-local
    }

    /// `true` iff `cidr` parses as `A.B.C.D/len`, lies within `100.64.0.0/10`,
    /// and is a BLOCK (`len < 32`) — i.e. an on-link/connected prefix, never a
    /// peer host route. Unparseable input is NOT derived (the reconciler then
    /// treats it as stale, matching the pre-P2a behavior for junk).
    fn v4_block_in_cgnat(cidr: &str) -> bool {
        let Some((addr, len)) = cidr.split_once('/') else {
            return false;
        };
        let Ok(len) = len.parse::<u8>() else {
            return false;
        };
        let Ok(ip) = addr.parse::<Ipv4Addr>() else {
            return false;
        };
        // 100.64.0.0/10 ⇔ the top 10 bits equal 100.64's.
        let in_cgnat = (u32::from(ip) & 0xFFC0_0000) == 0x6440_0000;
        in_cgnat && len < 32
    }

    /// macOS: empty, and correctly so — there is nothing to reconcile.
    ///
    /// This reconciler exists for a PERSISTED device: Wintun adapters (and a
    /// cached Linux tun) outlive the process, so a previous generation's
    /// routes can still be installed at the next boot with no crypto-router
    /// entries behind them. A utun is bound to the file descriptor that
    /// created it — when the process dies the interface goes, and the kernel
    /// takes its routes with it. So the orphan-route class this cleans up
    /// cannot occur on macOS.
    ///
    /// (The previous reason given here was that `netstat -rn` abbreviates
    /// destinations — `10.66/16` — and mis-parsing them would make
    /// `purge_one` delete the wrong route. True, and a good reason not to
    /// guess; but the real answer is that there is nothing to enumerate.)
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn enumerate_if_routes(_if_name: &str) -> Vec<String> {
        Vec::new()
    }

    #[cfg(target_os = "linux")]
    fn enumerate_if_routes(if_name: &str) -> Vec<String> {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "dev", if_name])
            .output();
        let Ok(out) = out else { return Vec::new() };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|p| p.contains('/'))
            .map(str::to_string)
            .collect()
    }

    #[cfg(target_os = "windows")]
    fn enumerate_if_routes(if_name: &str) -> Vec<String> {
        // N3 — typed FIB walk. The old `Get-NetRoute` PowerShell spawn cost
        // 0.5–2 s at bring-up AND inside `purge_exit_routes()` on every
        // `process::exit` path — launched from a process that was, by
        // definition, already wedged.
        winroute::luid_for_alias(if_name)
            .map(winroute::list_cidrs)
            .unwrap_or_default()
    }

    #[cfg(target_os = "linux")]
    fn purge_one(if_name: &str, cidr: &str) {
        let mut args: Vec<&str> = Vec::new();
        if is_v6_cidr(cidr) {
            args.push("-6");
        }
        args.extend(["route", "del", cidr, "dev", if_name]);
        let _ = std::process::Command::new("ip").args(&args).output();
    }

    #[cfg(target_os = "windows")]
    fn purge_one(if_name: &str, cidr: &str) {
        // N3 — typed delete (was the last Windows route MUTATION on netsh,
        // kept only because this path has no live SystemTun/LUID in hand).
        let Some((ip, plen)) = parse_cidr(cidr) else {
            return;
        };
        if let Some(luid) = winroute::luid_for_alias(if_name) {
            winroute::del(luid, ip, plen);
        }
    }

    #[cfg(target_os = "macos")]
    fn purge_one(_if_name: &str, cidr: &str) {
        let (net, plen) = cidr.split_once('/').unwrap_or((cidr, ""));
        let family = if is_v6_cidr(cidr) { "-inet6" } else { "-inet" };
        // Interface-less delete: BSD `route delete` keys on the destination,
        // and the caller has already decided this prefix should not exist.
        let mut args: Vec<String> = vec![
            "-n".into(),
            "delete".into(),
            family.into(),
            "-net".into(),
            net.into(),
        ];
        if !plen.is_empty() {
            args.push("-prefixlen".into());
            args.push(plen.into());
        }
        let _ = std::process::Command::new("route").args(&args).output();
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn purge_one(_if_name: &str, _cidr: &str) {}

    /// Assign this node's derived overlay IPv6 (`fd72:6f6f:6d6c::<v4>`,
    /// `/plen` on-link — `/96` for the legacy single adapter, `96 + v4_plen`
    /// for a per-org one) to the overlay NIC. Sync + best-effort (`up` isn't
    /// async): the
    /// `tun` crate's `Configuration` carries no v6 surface, so Linux uses
    /// `ip -6 addr replace` (idempotent) and Windows the typed
    /// [`winaddr::ensure`] (N1 — idempotent by numeric error, which also
    /// retires the old delete-then-add's per-bring-up flap of the v6
    /// connected route; the Wintun adapter persists across reconnects, so
    /// the address is usually already present). macOS utun stays v4-only for
    /// now, matching the per-peer-route stance.
    fn assign_derived_v6(
        self_ip: Ipv4Addr,
        #[allow(unused_variables)] if_name: &str,
        #[allow(unused_variables)] luid: u64,
        #[allow(unused_variables)] plen: u8,
    ) {
        let v6 = crate::overlay::router::derive_overlay_v6(self_ip);
        #[cfg(target_os = "linux")]
        {
            let cidr = format!("{v6}/{plen}");
            match std::process::Command::new("ip")
                .args(["-6", "addr", "replace", &cidr, "dev", if_name])
                .output()
            {
                Ok(out) if out.status.success() => {
                    tracing::info!(addr = %cidr, "overlay: derived IPv6 assigned to the TUN");
                }
                Ok(out) => tracing::warn!(
                    addr = %cidr,
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "overlay: derived-IPv6 assign failed; node stays v4-only"
                ),
                // A minimal container has no iproute2: say so, because the bare
                // ENOENT reads as a missing TUN, and the same absence also turns
                // the IPv6 default route "missing", so an exit serves no IPv6.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => tracing::warn!(
                    addr = %cidr,
                    "overlay: derived-IPv6 assign failed; node stays v4-only: `ip` is not \
                     installed (iproute2), and without it an exit cannot serve IPv6 either"
                ),
                Err(e) => tracing::warn!(
                    addr = %cidr,
                    error = %e,
                    "overlay: derived-IPv6 assign failed; node stays v4-only"
                ),
            }
        }
        #[cfg(target_os = "windows")]
        {
            match winaddr::ensure(luid, std::net::IpAddr::V6(v6), plen) {
                Ok(created) => {
                    tracing::info!(
                        addr = %format!("{v6}/{plen}"), created,
                        "overlay: derived IPv6 assigned to the TUN"
                    );
                }
                Err(e) => tracing::warn!(
                    addr = %format!("{v6}/{plen}"),
                    error = %e,
                    "overlay: derived-IPv6 assign failed; node stays v4-only"
                ),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let plen = plen.to_string();
            // `-alias` first so a re-bring-up replaces rather than stacks;
            // it fails harmlessly when the address isn't there yet.
            let _ = std::process::Command::new("ifconfig")
                .args([if_name, "inet6", &v6.to_string(), "-alias"])
                .output();
            match std::process::Command::new("ifconfig")
                .args([
                    if_name,
                    "inet6",
                    &v6.to_string(),
                    "prefixlen",
                    &plen,
                    "alias",
                ])
                .output()
            {
                Ok(out) if out.status.success() => {
                    tracing::info!(addr = %v6, %plen, "overlay: derived IPv6 assigned to the TUN");
                }
                Ok(out) => tracing::warn!(
                    addr = %v6,
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "overlay: derived-IPv6 assign failed; node stays v4-only"
                ),
                Err(e) => tracing::warn!(
                    addr = %v6,
                    error = %e,
                    "overlay: derived-IPv6 assign failed; node stays v4-only"
                ),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            let _ = (v6, if_name, plen);
        }
    }

    /// Run an OS route command off the async reactor (`std::process` in a
    /// blocking task — avoids pulling in tokio's `process` feature). Non-zero
    /// exit → `Err` with the captured stderr. Linux/macOS only since N2/N3:
    /// every Windows route/address operation goes through the typed
    /// `winroute`/`winaddr` IP Helper layers now.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn run_cmd(prog: &'static str, args: Vec<String>) -> std::io::Result<()> {
        tokio::task::spawn_blocking(move || {
            let out = std::process::Command::new(prog).args(&args).output()?;
            if out.status.success() {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "{prog} {args:?} exited {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                )))
            }
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
    }

    /// macOS — run one `route -n get …` and parse what it matched. `None` on
    /// any failure, which every caller reads as "not ours" and so falls back
    /// to the write it always did. A lookup is never a table change (#1856).
    #[cfg(target_os = "macos")]
    async fn bsd_route_get(args: Vec<String>) -> Option<super::BsdRouteGet> {
        tokio::task::spawn_blocking(move || bsd_route_get_blocking(&args))
            .await
            .ok()
            .flatten()
    }

    /// [`bsd_route_get`] for the synchronous bring-up path.
    #[cfg(target_os = "macos")]
    fn bsd_route_get_blocking(args: &[String]) -> Option<super::BsdRouteGet> {
        let out = std::process::Command::new("route")
            .args(args)
            .output()
            .ok()?;
        super::parse_bsd_route_get(&String::from_utf8_lossy(&out.stdout))
    }

    /// FR-97 P1a — the routing table of one family, from `netstat -rnW`: where
    /// a pin is read (see [`super::BsdTableRow`]). Empty on any failure, which
    /// reads as "no pin" and so fails toward withhold.
    #[cfg(target_os = "macos")]
    async fn bsd_table(v6: bool) -> Vec<super::BsdTableRow> {
        tokio::task::spawn_blocking(move || {
            std::process::Command::new("netstat")
                .args(["-rnW", "-f", if v6 { "inet6" } else { "inet" }])
                .output()
                .map(|out| super::parse_bsd_netstat(&String::from_utf8_lossy(&out.stdout)))
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    }

    /// FR-97 P1a — delete the unscoped host route for `ip`. Callers check the
    /// table first: with no such route left, `route delete` removes something
    /// else of the kernel's (field, a tart Mac on 0.4.133).
    #[cfg(target_os = "macos")]
    async fn bsd_unpin(ip: std::net::IpAddr) {
        let _ = bsd_route_write(vec![
            "-n".into(),
            "delete".into(),
            bsd_family(ip.is_ipv6()).into(),
            "-host".into(),
            ip.to_string(),
        ])
        .await;
    }

    #[cfg(target_os = "macos")]
    fn bsd_family(v6: bool) -> &'static str {
        if v6 { "-inet6" } else { "-inet" }
    }

    /// FR-97 P1a — one `route` write for a host exemption: `Err` carries the
    /// tool's own words (its first stderr line), which end up in the gate's
    /// WARN and in `meshharbor status`.
    #[cfg(target_os = "macos")]
    async fn bsd_route_write(args: Vec<String>) -> Result<(), String> {
        tokio::task::spawn_blocking(move || {
            let out = std::process::Command::new("route")
                .args(&args)
                .output()
                .map_err(|e| format!("route could not run: {e}"))?;
            if out.status.success() {
                return Ok(());
            }
            let err = String::from_utf8_lossy(&out.stderr);
            Err(err
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map_or_else(|| format!("route exited {}", out.status), str::to_string))
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// FR-97 P1a — the uplink `route -n get [-inet6] default` names right now,
    /// or `None` when there is none to pin through (see
    /// [`super::bsd_default_uplink`]).
    #[cfg(target_os = "macos")]
    fn discover_bsd_uplink(v6: bool, overlay_if: &str) -> Option<super::BsdUplink> {
        let got = bsd_route_get_blocking(&[
            "-n".into(),
            "get".into(),
            bsd_family(v6).into(),
            "default".into(),
        ]);
        super::bsd_default_uplink(got.as_ref(), v6, overlay_if)
    }

    /// FR-97 P1a — see [`SystemTun`]'s `uplinks`.
    #[cfg(target_os = "macos")]
    #[derive(Debug, Default)]
    struct BsdUplinks {
        v4: Option<super::BsdUplink>,
        v6: Option<super::BsdUplink>,
    }

    #[cfg(target_os = "macos")]
    impl BsdUplinks {
        fn slot(&mut self, v6: bool) -> &mut Option<super::BsdUplink> {
            if v6 { &mut self.v6 } else { &mut self.v4 }
        }
    }

    /// FR-97 P1a — `ROOMLERD_EXIT_CLIENT_MACOS=0` puts the macOS exit client
    /// back where P0a left it: every exemption is refused, so the exit is
    /// withheld and `meshharbor status` says why. Default ON.
    #[cfg(target_os = "macos")]
    fn exit_client_macos_enabled() -> bool {
        crate::env::flag("EXIT_CLIENT_MACOS", true)
    }

    #[cfg(target_os = "macos")]
    impl SystemTun {
        /// FR-97 P1a — the uplink `v6`'s exemptions pin through right now:
        /// re-read, and adopted (logged) when it is not the one held. A family
        /// with no usable default at this moment keeps the one it had.
        async fn current_uplink(&self, v6: bool) -> Option<super::BsdUplink> {
            let if_name = self.if_name.clone();
            let found = tokio::task::spawn_blocking(move || discover_bsd_uplink(v6, &if_name))
                .await
                .ok()
                .flatten();
            let mut held = self.uplinks.lock().unwrap_or_else(|e| e.into_inner());
            let slot = held.slot(v6);
            if let Some(found) = found
                && slot.as_ref() != Some(&found)
            {
                tracing::info!(
                    family = if v6 { "v6" } else { "v4" },
                    was = ?slot.as_ref().map(|u| format!("{} on {}", u.gateway_arg, u.interface)),
                    gateway = %found.gateway_arg,
                    interface = %found.interface,
                    "overlay exit-node: carrier exemptions now pin through this uplink"
                );
                *slot = Some(found);
            }
            slot.clone()
        }
    }

    /// The host's original default route — the gateway + interface that carried
    /// its traffic BEFORE the overlay installed any route. Captured once in
    /// [`SystemTun::up`]; used to pin exit-node exemption `/32`s via the real
    /// uplink. `interface` is the Linux `dev` name / the Windows interface index.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OrigDefaultRoute {
        gateway: Ipv4Addr,
        interface: String,
        /// P5 — the original default route was installed `onlink` (the gateway
        /// isn't in any connected subnet, as on Hetzner + many clouds). A `/32`
        /// carrier exemption via such a gateway MUST also carry `onlink`, or the
        /// kernel rejects it with "Nexthop has invalid gateway" (found in the P5
        /// field-test). Linux-only concept; Windows `netsh` resolves the next-hop.
        #[cfg(target_os = "linux")]
        onlink: bool,
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    impl OrigDefaultRoute {
        /// FR-97 P0e (N12) — what the sweep compares: interface + next hop.
        fn key(&self) -> super::UplinkKey {
            super::UplinkKey {
                interface: self.interface.clone(),
                gateway: std::net::IpAddr::V4(self.gateway),
            }
        }
    }

    /// Query the OS for the active IPv4 default route, picking the lowest-metric
    /// one on a multi-homed host. `None` on any error or when there is none.
    /// `overlay_if` is THIS device's name — a default via the overlay itself is
    /// never a valid exemption path (multi-org v2: the instance name, so a
    /// sibling org's adapter still counts as a real uplink for filtering
    /// purposes exactly as any other NIC would).
    #[cfg(target_os = "linux")]
    fn discover_default_route(overlay_if: &str) -> Option<OrigDefaultRoute> {
        let out = std::process::Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_linux_default_route(&String::from_utf8_lossy(&out.stdout), overlay_if)
    }

    #[cfg(target_os = "windows")]
    fn discover_default_route(_overlay_if: &str) -> Option<OrigDefaultRoute> {
        // N2 — `GetBestRoute2` toward the unspecified address answers "which
        // route would carry a default-bound packet right now" as a STRUCT,
        // replacing the fixed-position parse of `netsh show route`'s
        // LOCALIZED table (the most fragile parse the tree had). On-link
        // defaults (unspecified next-hop) yield `None`, same as the parser's
        // skip. Ordering contract unchanged: this runs in `up()` BEFORE the
        // adapter exists, so the best route cannot be our own.
        let (ifindex, gw) =
            winroute::best_route(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))?;
        let std::net::IpAddr::V4(gateway) = gw else {
            return None;
        };
        Some(OrigDefaultRoute {
            gateway,
            interface: ifindex.to_string(),
        })
    }

    /// Parse `ip -4 route show default` → the lowest-metric default route. Pure
    /// (OS-call-free) so it unit-tests against captured output. A default via our
    /// own overlay NIC (`overlay_if`) is ignored (never exempt via ourselves).
    #[cfg(target_os = "linux")]
    fn parse_linux_default_route(output: &str, overlay_if: &str) -> Option<OrigDefaultRoute> {
        fn tok_after<'a>(toks: &[&'a str], key: &str) -> Option<&'a str> {
            toks.iter()
                .position(|t| *t == key)
                .and_then(|i| toks.get(i + 1).copied())
        }
        let mut best: Option<(u32, OrigDefaultRoute)> = None;
        for line in output.lines() {
            let line = line.trim();
            if !line.starts_with("default") {
                continue;
            }
            let toks: Vec<&str> = line.split_whitespace().collect();
            let gateway = tok_after(&toks, "via").and_then(|s| s.parse::<Ipv4Addr>().ok());
            let interface = tok_after(&toks, "dev").map(str::to_string);
            let (Some(gateway), Some(interface)) = (gateway, interface) else {
                continue;
            };
            if interface == overlay_if {
                continue; // never exempt via the overlay itself
            }
            // `onlink` default routes (Hetzner + many clouds) force the same flag
            // onto any `/32` exemption pinned via this gateway — see the struct doc.
            let onlink = toks.contains(&"onlink");
            let metric = tok_after(&toks, "metric")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            if best.as_ref().is_none_or(|(m, _)| metric < *m) {
                best = Some((
                    metric,
                    OrigDefaultRoute {
                        gateway,
                        interface,
                        #[cfg(target_os = "linux")]
                        onlink,
                    },
                ));
            }
        }
        best.map(|(_, r)| r)
    }

    /// P5/S3b — the host's original IPv6 default route: the v6 gateway + interface
    /// that carried its v6 traffic before the overlay. Pins v6 `/128` exit
    /// exemptions. `gateway` is frequently a link-local (`fe80::`) next-hop, which
    /// is fine — the `interface` disambiguates it.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OrigDefaultRoute6 {
        gateway: Ipv6Addr,
        interface: String,
        /// See [`OrigDefaultRoute::onlink`] — the v6 default is likewise often
        /// `onlink` (a `fe80::` next-hop on a point-to-point uplink), so `/128`
        /// exemptions via it need the flag too. Linux-only.
        #[cfg(target_os = "linux")]
        onlink: bool,
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    impl OrigDefaultRoute6 {
        /// FR-97 P0e (N12) — what the sweep compares: interface + next hop.
        fn key(&self) -> super::UplinkKey {
            super::UplinkKey {
                interface: self.interface.clone(),
                gateway: std::net::IpAddr::V6(self.gateway),
            }
        }
    }

    /// Query the OS for the active IPv6 default route (lowest-metric). `None` on
    /// error or when the host has no v6 default (v4-only uplink). `overlay_if`
    /// as in [`discover_default_route`].
    #[cfg(target_os = "linux")]
    fn discover_default_route_v6(overlay_if: &str) -> Option<OrigDefaultRoute6> {
        let out = std::process::Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_linux_default_route_v6(&String::from_utf8_lossy(&out.stdout), overlay_if)
    }

    #[cfg(target_os = "windows")]
    fn discover_default_route_v6(_overlay_if: &str) -> Option<OrigDefaultRoute6> {
        // N2 — v6 twin of the typed discovery above. A link-local (`fe80::`)
        // next-hop comes back as an ADDRESS from the FIB — no `%zone` string
        // to strip; the ifIndex disambiguates it, as before.
        let (ifindex, gw) =
            winroute::best_route(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))?;
        let std::net::IpAddr::V6(gateway) = gw else {
            return None;
        };
        Some(OrigDefaultRoute6 {
            gateway,
            interface: ifindex.to_string(),
        })
    }

    /// Parse `ip -6 route show default` → the lowest-metric v6 default (gateway +
    /// dev). Pure. A default via our own overlay NIC (`overlay_if`) is ignored;
    /// a link-local (`fe80::`) gateway is accepted (the dev disambiguates its
    /// zone).
    #[cfg(target_os = "linux")]
    fn parse_linux_default_route_v6(output: &str, overlay_if: &str) -> Option<OrigDefaultRoute6> {
        fn tok_after<'a>(toks: &[&'a str], key: &str) -> Option<&'a str> {
            toks.iter()
                .position(|t| *t == key)
                .and_then(|i| toks.get(i + 1).copied())
        }
        let mut best: Option<(u32, OrigDefaultRoute6)> = None;
        for line in output.lines() {
            let line = line.trim();
            if !line.starts_with("default") {
                continue;
            }
            let toks: Vec<&str> = line.split_whitespace().collect();
            let gateway = tok_after(&toks, "via").and_then(|s| s.parse::<Ipv6Addr>().ok());
            let interface = tok_after(&toks, "dev").map(str::to_string);
            let (Some(gateway), Some(interface)) = (gateway, interface) else {
                continue;
            };
            if interface == overlay_if {
                continue; // never exempt via the overlay itself
            }
            let onlink = toks.contains(&"onlink");
            let metric = tok_after(&toks, "metric")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            if best.as_ref().is_none_or(|(m, _)| metric < *m) {
                best = Some((
                    metric,
                    OrigDefaultRoute6 {
                        gateway,
                        interface,
                        #[cfg(target_os = "linux")]
                        onlink,
                    },
                ));
            }
        }
        best.map(|(_, r)| r)
    }

    #[cfg(test)]
    mod tests {
        use std::cell::Cell;
        use std::time::Duration;

        /// corplap route war — the in-block eviction's targeting rule. The
        /// safety property under test: ONLY prefixes that fit entirely
        /// inside the overlay block match; anything broader (defaults, /1
        /// split-halves, corp LANs, an adjacent CGNAT block) never does.
        #[cfg(windows)]
        #[test]
        fn row_in_block_targets_only_subsets_of_the_block() {
            use super::winroute::row_in_block;
            let block = u32::from_be_bytes([100, 65, 4, 0]); // 100.65.4.0/22
            // The observed Check Point shadows: /24s inside the /22,
            // broadcast /32s, learned per-host /32s — all in-block.
            for (net, plen) in [
                ([100, 65, 4, 0], 24),
                ([100, 65, 5, 0], 24),
                ([100, 65, 7, 0], 24),
                ([100, 65, 4, 4], 32),
                ([100, 65, 6, 255], 32),
                ([100, 65, 4, 0], 22), // an exact-block rival
            ] {
                assert!(
                    row_in_block(u32::from_be_bytes(net), plen, block, 22),
                    "{net:?}/{plen} must be in-block"
                );
            }
            // Never touched: broader scopes and out-of-block prefixes.
            for (net, plen) in [
                ([0, 0, 0, 0], 0),      // default
                ([0, 0, 0, 0], 1),      // split-default half
                ([100, 64, 0, 0], 10),  // the whole CGNAT /10 (broader)
                ([100, 65, 0, 0], 22),  // the ADJACENT block (jovanov)
                ([100, 65, 8, 0], 24),  // outside the /22
                ([10, 138, 80, 0], 24), // corp LAN
                ([100, 65, 4, 0], 21),  // broader than the block
            ] {
                assert!(
                    !row_in_block(u32::from_be_bytes(net), plen, block, 22),
                    "{net:?}/{plen} must NOT match"
                );
            }
            // An uninitialized/invalid block plen matches nothing.
            assert!(!row_in_block(
                u32::from_be_bytes([100, 65, 4, 4]),
                32,
                block,
                0
            ));
            assert!(!row_in_block(
                u32::from_be_bytes([100, 65, 4, 4]),
                32,
                block,
                33
            ));
        }

        /// rc.411 (#23) — the escalation must be STICKY, because the defense
        /// wave re-asserts every peer `/32` on each pass: if
        /// `add_peer_route` ignored the escalated set it would reset the
        /// metric to 1, the ownership check would escalate to 0 again, and
        /// the prefix would delete-then-re-add forever — the exact churn the
        /// in-block debounce exists to prevent, on the one prefix we are
        /// trying to stabilise. This locks the contract that the metric
        /// choice reads the set (the FIB half needs a real adapter, so the
        /// set membership is what the unit test can hold).
        #[cfg(windows)]
        #[test]
        fn escalated_peers_keep_metric_zero_across_waves() {
            use std::net::Ipv4Addr;
            let set: std::sync::Mutex<std::collections::HashSet<Ipv4Addr>> =
                std::sync::Mutex::new(std::collections::HashSet::new());
            let escalated_ip = Ipv4Addr::new(100, 65, 4, 14);
            let plain_ip = Ipv4Addr::new(100, 65, 4, 15);
            // The wave's metric choice, mirrored from `add_peer_route`.
            let metric_for = |ip: Ipv4Addr| -> u32 {
                if set.lock().unwrap().contains(&ip) {
                    0
                } else {
                    1
                }
            };
            assert_eq!(metric_for(escalated_ip), 1, "not escalated yet");
            set.lock().unwrap().insert(escalated_ip);
            // Re-running the wave must NOT reset the escalated peer to 1.
            for wave in 0..3 {
                assert_eq!(
                    metric_for(escalated_ip),
                    0,
                    "wave {wave} reset an escalated peer to metric 1 — that flaps the \
                     prefix (delete-then-re-add) on every wave"
                );
                assert_eq!(
                    metric_for(plain_ip),
                    1,
                    "wave {wave} escalated a peer that never lost its path"
                );
            }
            // Escalation is per-peer and idempotent (a second insert is a
            // no-op, which is what suppresses repeated `ensure` calls).
            assert!(
                !set.lock().unwrap().insert(escalated_ip),
                "already escalated"
            );
        }

        /// rc.410 (#23) — the interface metric must default to 0, the value
        /// that wins the route war outright. A regression to 1 restores the
        /// exact tie (route 1 + iface 1 on both sides) that let Check Point
        /// capture corplap's peers by ifIndex tie-break for weeks, and the
        /// failure is INVISIBLE without a hostile VPN present — so the
        /// default is locked here rather than left to field observation.
        #[cfg(windows)]
        #[test]
        fn interface_metric_defaults_to_zero() {
            // No env override in the test process ⇒ the built-in default.
            assert_eq!(
                super::iface_metric(),
                0,
                "the overlay interface metric must default to 0: Windows ranks by \
                 route metric + INTERFACE metric, so 1 ties with a corp VPN's mirrored \
                 rows and loses the ifIndex tie-break (corplap, 2026-08-18)"
            );
        }

        /// #1342 — the ULA metric ladder, and specifically that the DEFAULT is
        /// still the stock connected-route 256.
        ///
        /// ⚠️ The default is the load-bearing assertion. Asserting only that
        /// the gate produces 1 would pass just as happily if the gate had been
        /// flipped default-ON, which is the change that must never happen by
        /// accident: it re-metrics Windows' own connected route on every
        /// enrolled machine. rc.289 is the precedent — metric-0 routes shipped
        /// as a default, got deleted by the VPN, and left the prefix unrouted.
        ///
        /// ⚠️ `#[cfg(windows)]`, like its neighbour above: every gate it reads
        /// is Windows-only, so without it the macOS and Linux lanes fail to
        /// COMPILE. Nothing run locally catches that — a Windows `cargo test`
        /// has the functions, and the workspace clippy runs without
        /// `--all-targets` so it never builds this module at all. Only a
        /// cross-platform `cargo check --all-targets` sees it.
        #[cfg(windows)]
        #[test]
        fn ula_metric_defaults_to_the_stock_connected_route() {
            // No env override in the test process ⇒ every gate reads its
            // built-in default.
            assert!(
                !super::route_win_enabled(),
                "OVERLAY_ROUTE_WIN must default OFF: it re-metrics the auto CONNECTED \
                 route on every Windows host, and it has not been field-proven"
            );
            assert!(!super::route_metric0_enabled(), "rc.289 left metric-0 OFF");
            assert_eq!(
                super::ula_route_metric(),
                256,
                "with both gates off the ULA must reconcile to the stock connected-route \
                 metric 256 — and to 256 rather than a delete, because that row shares \
                 the (LUID, prefix, on-link) key with Windows' own connected route and \
                 deleting it kills v6 entirely"
            );
            // The gated value is the one v4 already runs fleet-wide, NOT 0.
            assert_eq!(
                super::defended_route_metric(),
                1,
                "the gated ULA metric must be v4's field-proven 1; 0 is the rc.289 \
                 variant the VPN deletes outright"
            );
        }

        /// corplap route war v3 (#23) — the eviction-debounce fingerprint:
        /// order-insensitive (FIB iteration order can never fake a change),
        /// sensitive to every component of a row (prefix, plen, luid), and
        /// zero only for the empty set — the exact properties the
        /// evict-on-change decision rests on.
        #[cfg(windows)]
        #[test]
        fn foreign_row_fingerprint_is_order_insensitive_and_component_sensitive() {
            use super::winroute::fp_fold;
            let a = (u32::from_be_bytes([100, 65, 4, 0]), 24u8, 7u64);
            let b = (u32::from_be_bytes([100, 65, 4, 14]), 32u8, 7u64);
            let ab = fp_fold(fp_fold(0, a.0, a.1, a.2), b.0, b.1, b.2);
            let ba = fp_fold(fp_fold(0, b.0, b.1, b.2), a.0, a.1, a.2);
            assert_eq!(ab, ba, "iteration order must not matter");
            assert_ne!(ab, 0, "a non-empty set never fingerprints as empty");
            let just_a = fp_fold(0, a.0, a.1, a.2);
            assert_ne!(ab, just_a, "adding a row changes the set");
            assert_ne!(
                just_a,
                fp_fold(0, a.0, 25, a.2),
                "plen is part of the row identity"
            );
            assert_ne!(
                just_a,
                fp_fold(0, a.0, a.1, 8),
                "the owning interface is part of the row identity"
            );
        }

        /// Live field probe against the local `roomler` adapter — run
        /// manually with `--ignored --nocapture`. This is the probe that
        /// caught the `list_v4` byte-flip (2.0.64.100 for 100.64.0.2) that
        /// unit tests structurally can't: the FFI read only lies against a
        /// REAL table.
        #[cfg(windows)]
        #[test]
        #[ignore]
        fn manual_list_v4_probe() {
            let luid = super::winroute::luid_for_alias("roomler").expect("no roomler adapter");
            println!("luid={luid}");
            let addrs = super::winaddr::list_v4(luid);
            println!("list_v4 -> {addrs:?}");
        }

        /// The endianness lock for every SOCKADDR_INET v4 read/write pair:
        /// what `winroute::sockaddr` stores, a memory-order byte read gets
        /// back EXACTLY — on any endianness. (`Ipv4Addr::from(u32)` is the
        /// trap: it interprets big-endian, so an ne-identity round-trip
        /// byte-flips on little-endian hosts.)
        #[cfg(windows)]
        #[test]
        fn sockaddr_v4_roundtrip() {
            use std::net::{IpAddr, Ipv4Addr};
            for ip in [
                Ipv4Addr::new(100, 64, 0, 2),
                Ipv4Addr::new(100, 65, 0, 5),
                Ipv4Addr::new(1, 2, 3, 4),
            ] {
                let sa = super::winroute::sockaddr(IpAddr::V4(ip));
                // SAFETY: reading the arm sockaddr() just wrote.
                let raw = unsafe { sa.Ipv4.sin_addr.S_un.S_addr };
                assert_eq!(
                    Ipv4Addr::from(raw.to_ne_bytes()),
                    ip,
                    "memory-order byte read must round-trip"
                );
            }
        }

        /// "Ask the interface, don't read the error" — now macOS-only (N1
        /// moved Windows address ops to typed IP Helper, deleting the netsh
        /// listing probe, its German/English captures, and the #388 polling
        /// loop; the race those tolerated cannot exist against the MIB table
        /// the create itself writes).
        #[test]
        fn listings_are_read_by_address_literal_not_by_label() {
            use super::listing_mentions_address as m;
            use std::net::Ipv4Addr;

            // macOS `ifconfig utun4` — point-to-point inet lines, one per org.
            let mac = "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n\
                       \tinet 100.64.0.28 --> 100.64.0.28 netmask 0xffc00000\n\
                       \tinet 100.65.0.5 --> 100.65.0.5 netmask 0xfffffc00\n";

            assert!(m(mac, Ipv4Addr::new(100, 64, 0, 28)));
            // The substring trap: `100.64.0.2` must NOT match a listed
            // `100.64.0.28`, or a real failure gets swallowed.
            assert!(!m(mac, Ipv4Addr::new(100, 64, 0, 2)));
            assert!(!m(mac, Ipv4Addr::new(10, 0, 0, 1)));
            // The second org's address is listed too — the whole point of
            // the multi-address path.
            assert!(m(mac, Ipv4Addr::new(100, 65, 0, 5)));
            assert!(!m("", Ipv4Addr::new(100, 64, 0, 28)));
        }

        /// Multi-org P2a — the boot-reconciler keep-set accepts ANY on-link
        /// block inside 100.64.0.0/10 (tenant-block forward-compat), keeps
        /// the ULA/multicast family, and still treats peer host routes +
        /// junk as purgeable.
        #[test]
        fn derived_prefix_keeps_any_cgnat_block_purges_host_routes() {
            use super::is_derived_prefix;
            // Legacy whole-range on-link + future tenant blocks: kept.
            assert!(is_derived_prefix("100.64.0.0/10"));
            assert!(is_derived_prefix("100.68.12.0/22"));
            assert!(is_derived_prefix("100.127.255.0/24"));
            assert!(is_derived_prefix(" 100.65.0.0/16 "), "trimmed");
            // Peer host routes inside the range: purgeable (the point of
            // the reconciler).
            assert!(!is_derived_prefix("100.64.0.7/32"));
            assert!(!is_derived_prefix("100.68.12.9/32"));
            // Outside the CGNAT range: purgeable even as a block.
            assert!(!is_derived_prefix("100.128.0.0/22"));
            assert!(!is_derived_prefix("10.66.0.0/16"));
            assert!(!is_derived_prefix("0.0.0.0/1"));
            // ULA (exact const + any future sub-block) kept; junk not.
            assert!(is_derived_prefix(
                crate::overlay::router::OVERLAY_ULA_V6_CIDR
            ));
            assert!(is_derived_prefix("fd72:6f6f:6d6c::/96"));
            assert!(!is_derived_prefix("fd00:dead::/64"));
            // OS-derived families kept; garbage not.
            assert!(is_derived_prefix("224.0.0.0/4"));
            assert!(is_derived_prefix("255.255.255.255/32"));
            assert!(is_derived_prefix("ff00::/8"));
            assert!(is_derived_prefix("fe80::/64"));
            assert!(!is_derived_prefix("not-a-cidr"));
            assert!(!is_derived_prefix("100.64.0.0"));
        }

        /// Multi-org v2 — the per-org GUID derivation is deterministic (an
        /// adapter must re-bind the SAME interface identity across restarts
        /// and recreates — the rc.279 property, per org), org-distinct, and
        /// RFC 4122-shaped (version 4 + variant bits forced).
        #[test]
        fn org_tun_guid_is_stable_distinct_and_rfc4122_shaped() {
            use super::org_tun_guid;
            let a = org_tun_guid("665f1c0001a2b3c4d5e6f708");
            let b = org_tun_guid("665f1c0001a2b3c4d5e6f708");
            let c = org_tun_guid("77aa000001a2b3c4d5e6f7ff");
            // Determinism: same tenant → same GUID, across calls (and, since
            // the derivation is SHA-256 of fixed inputs, across builds).
            assert_eq!(a, b);
            // Distinctness: two tenants must never collide onto one adapter
            // identity.
            assert_ne!(a, c);
            // Neither derived GUID may collide with the legacy base GUID —
            // the primary adapter keeps it.
            assert_ne!(a, super::ROOMLER_TUN_GUID);
            assert_ne!(c, super::ROOMLER_TUN_GUID);
            for g in [a, c] {
                let bytes = g.to_be_bytes();
                assert_eq!(bytes[6] & 0xF0, 0x40, "version nibble must be 4");
                assert_eq!(bytes[8] & 0xC0, 0x80, "variant bits must be 10x");
            }
            // The empty tenant id still yields a valid, distinct value (never
            // panics — config-shape errors are caught elsewhere).
            assert_ne!(org_tun_guid(""), a);
        }

        /// Multi-org v2 — the legacy [`super::TunOptions::legacy`] carries
        /// EXACTLY the historical single-adapter identity, so `up()`
        /// delegating through `up_with` is byte-identical single-org
        /// behavior: the platform IF_NAME, the rc.279 constant GUID, and the
        /// whole-ULA `/96` on-link prefix.
        #[test]
        fn legacy_tun_options_lock_the_single_adapter_identity() {
            use std::net::Ipv4Addr;
            let o = super::TunOptions::legacy(
                Ipv4Addr::new(100, 64, 0, 2),
                Ipv4Addr::new(255, 192, 0, 0),
                1280,
            );
            assert_eq!(o.name, super::IF_NAME);
            assert_eq!(o.guid, super::ROOMLER_TUN_GUID);
            assert_eq!(o.ip, Ipv4Addr::new(100, 64, 0, 2));
            assert_eq!(o.netmask, Ipv4Addr::new(255, 192, 0, 0));
            assert_eq!(o.mtu, 1280);
            assert_eq!(
                o.v6_onlink_plen,
                crate::overlay::router::OVERLAY_V6_ONLINK_PREFIX
            );
            assert_eq!(o.v6_onlink_plen, 96);
        }

        // P9's `hygiene_kill_switch_parse` moved to `crate::winfw::tests`
        // with the parser (#1698), where it runs on every platform.

        /// rc.209 — the Wintun create-retry policy: succeed as soon as a try
        /// returns `Ok`, without running further attempts or sleeping.
        #[test]
        fn retry_create_succeeds_after_transient_failures() {
            let calls = Cell::new(0);
            let retries = Cell::new(0);
            // Fails twice (mutex not released yet), succeeds on the 3rd try.
            let r: Result<&str, &str> = super::retry_create(
                5,
                Duration::ZERO,
                || {
                    let n = calls.get() + 1;
                    calls.set(n);
                    if n < 3 {
                        Err("device installation mutex: Access is denied")
                    } else {
                        Ok("adapter")
                    }
                },
                |_a, _e| retries.set(retries.get() + 1),
            );
            assert_eq!(r, Ok("adapter"));
            assert_eq!(calls.get(), 3, "stopped the instant a try succeeded");
            assert_eq!(
                retries.get(),
                2,
                "logged a retry before each of the 2 backoffs"
            );
        }

        /// rc.209 — exhausting every attempt returns the LAST error (so the
        /// caller still surfaces a real failure after a genuinely-broken create).
        #[test]
        fn retry_create_exhausts_and_returns_last_error() {
            let calls = Cell::new(0);
            let retries = Cell::new(0);
            let r: Result<&str, String> = super::retry_create(
                4,
                Duration::ZERO,
                || {
                    let n = calls.get() + 1;
                    calls.set(n);
                    Err(format!("attempt {n} failed"))
                },
                |_a, _e| retries.set(retries.get() + 1),
            );
            assert_eq!(r, Err("attempt 4 failed".to_string()));
            assert_eq!(calls.get(), 4, "ran every attempt");
            assert_eq!(
                retries.get(),
                3,
                "backed off between attempts, not after the last"
            );
        }

        /// `attempts` is clamped to ≥1 — a 0 still runs the closure once.
        #[test]
        fn retry_create_runs_at_least_once() {
            let calls = Cell::new(0);
            let r: Result<u8, ()> = super::retry_create(
                0,
                Duration::ZERO,
                || {
                    calls.set(calls.get() + 1);
                    Ok(7)
                },
                |_a, _e| {},
            );
            assert_eq!(r, Ok(7));
            assert_eq!(calls.get(), 1);
        }

        #[test]
        fn v6_cidr_detection_picks_route_family() {
            use super::is_v6_cidr;
            // v6 exit-node fail-closed halves + the derived-ULA prefix.
            assert!(is_v6_cidr("::/1"));
            assert!(is_v6_cidr("8000::/1"));
            assert!(is_v6_cidr("fd72:6f6f:6d6c::/96"));
            // v4 split-default halves + a normal subnet route.
            assert!(!is_v6_cidr("0.0.0.0/1"));
            assert!(!is_v6_cidr("128.0.0.0/1"));
            assert!(!is_v6_cidr("192.168.1.0/24"));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_default_route_lowest_metric_skips_overlay() {
            use std::net::Ipv4Addr;
            // Legacy instance name, as the single-adapter `up()` passes it.
            let parse = |o: &str| super::parse_linux_default_route(o, "roomler0");
            // Lowest metric wins on a multi-homed host.
            let out = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n\
                       default via 10.8.0.1 dev tun0 metric 50\n";
            let r = parse(out).unwrap();
            assert_eq!(r.gateway, Ipv4Addr::new(10, 8, 0, 1));
            assert_eq!(r.interface, "tun0");
            // Missing metric == 0 == wins.
            let r2 = parse("default via 192.168.1.1 dev eth0\n").unwrap();
            assert_eq!(r2.gateway, Ipv4Addr::new(192, 168, 1, 1));
            // A default via our own overlay NIC is ignored.
            let out3 = "default via 100.64.0.1 dev roomler0 metric 1\n\
                        default via 192.168.1.1 dev eth0 metric 100\n";
            assert_eq!(parse(out3).unwrap().interface, "eth0");
            // Multi-org v2 — the filter keys on the INSTANCE name: a per-org
            // adapter skips itself, and the legacy name is then an ordinary
            // (if implausible) uplink like any other NIC.
            let out_org = "default via 100.65.4.1 dev roomler-acme metric 1\n\
                           default via 192.168.1.1 dev eth0 metric 100\n";
            assert_eq!(
                super::parse_linux_default_route(out_org, "roomler-acme")
                    .unwrap()
                    .interface,
                "eth0"
            );
            // Hetzner/cloud `onlink` default is captured so the exemption /32
            // carries the flag (P5 field-test regression: without it the kernel
            // rejects the /32 with "Nexthop has invalid gateway").
            let r_onlink = parse("default via 172.31.1.1 dev eth0 proto static onlink\n").unwrap();
            assert_eq!(r_onlink.gateway, Ipv4Addr::new(172, 31, 1, 1));
            assert!(r_onlink.onlink);
            // A normal (non-onlink) default is not flagged.
            assert!(!parse("default via 192.168.1.1 dev eth0\n").unwrap().onlink);
            // No default route present.
            assert!(parse("").is_none());
            assert!(parse("10.0.0.0/8 dev eth0\n").is_none());
        }

        // N2 — the Windows default-route parsers (and these fixed-position
        // captures of a LOCALIZED netsh table) are gone: discovery now reads
        // the FIB via `GetBestRoute2` as a struct. Only the Linux `ip route`
        // parsers remain text-based.

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_default_route_v6_lowest_metric_skips_overlay() {
            use std::net::Ipv6Addr;
            // Legacy instance name, as the single-adapter `up()` passes it.
            let parse = |o: &str| super::parse_linux_default_route_v6(o, "roomler0");
            // Lowest metric wins; a link-local gateway is accepted.
            let out = "default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n\
                       default via 2a01:4f8::1 dev eth0 metric 100\n";
            let r = parse(out).unwrap();
            assert_eq!(r.gateway, "2a01:4f8::1".parse::<Ipv6Addr>().unwrap());
            assert_eq!(r.interface, "eth0");
            // A default via our own overlay NIC is ignored.
            let out2 = "default via fe80::a dev roomler0 metric 1\n\
                        default via fe80::1 dev eth0 metric 100\n";
            assert_eq!(parse(out2).unwrap().interface, "eth0");
            // An `onlink` v6 default (point-to-point uplink) is flagged so the
            // /128 exemption carries the flag (P5 field-test regression).
            assert!(
                parse("default via fe80::1 dev eth0 proto static metric 100 onlink pref medium\n")
                    .unwrap()
                    .onlink
            );
            // None present.
            assert!(parse("").is_none());
            assert!(parse("2001:db8::/64 dev eth0\n").is_none());
        }
    }
}
/// macOS overlay networking against a REAL utun.
///
/// Everything in the macOS arms — address aliasing, peer `/32`s, subnet
/// routes, the derived v6 — was a no-op until now, so none of it has ever
/// run. Writing it unverified would have been worse than the loud refusal
/// it replaces, and the recorded blocker was "needs a Mac, and the fleet
/// has none". That stopped being true: a `macos-latest` runner has sudo and
/// utun, so the code is exercised on every push instead of being trusted.
///
/// Needs root, hence the `ROOMLER_TUN_KERNEL_TEST=1` opt-in; skips silently
/// everywhere else, including on non-macOS hosts.
#[cfg(all(test, feature = "overlay-l3"))]
mod macos_kernel_tests {
    use super::SystemTun;
    use crate::overlay::tun::TunIo;
    use std::net::Ipv4Addr;

    const MASK_22: Ipv4Addr = Ipv4Addr::new(255, 255, 252, 0);

    fn sh(prog: &str, args: &[&str]) -> String {
        let out = std::process::Command::new(prog)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("{prog} {args:?}: {e}"));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Whole-token match so `100.65.0.5` never matches `100.65.0.50`.
    fn mentions(haystack: &str, needle: &str) -> bool {
        haystack
            .split(|c: char| !(c.is_ascii_digit() || c == '.' || c == ':'))
            .any(|t| t == needle)
    }

    #[tokio::test]
    async fn utun_carries_addresses_peer_routes_and_subnet_routes() {
        if !cfg!(target_os = "macos") {
            eprintln!("skipping: macOS-only (utun + BSD route/ifconfig)");
            return;
        }
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").as_deref() != Ok("1") {
            eprintln!("skipping: set ROOMLER_TUN_KERNEL_TEST=1 (needs root)");
            return;
        }

        let tun =
            SystemTun::up(Ipv4Addr::new(100, 65, 0, 5), MASK_22, 1280).expect("utun bring-up");
        let iface = tun.if_name().to_string();
        assert!(
            iface.starts_with("utun"),
            "the kernel names utuns; a hardcoded name is why this all used to \
             address a nonexistent interface (got {iface:?})"
        );

        let cfg = sh("ifconfig", &[&iface]);
        assert!(
            mentions(&cfg, "100.65.0.5"),
            "the device's own address must be up:\n{cfg}"
        );

        // A SECOND address — the multi-org case, and the one `add_address_sync`
        // used to refuse outright on this platform.
        tun.add_address_sync(Ipv4Addr::new(100, 66, 0, 7), 22)
            .expect("second address");
        let cfg = sh("ifconfig", &[&iface]);
        assert!(
            mentions(&cfg, "100.66.0.7"),
            "a second org's address must land on the same utun:\n{cfg}"
        );
        // Idempotent: the reconnect path re-adds every session.
        tun.add_address_sync(Ipv4Addr::new(100, 66, 0, 7), 22)
            .expect("re-adding an existing address is a no-op, not an error");

        // A peer /32. Without this macOS had NO per-peer routes at all and
        // leaned entirely on the connected route.
        tun.add_peer_route(Ipv4Addr::new(100, 65, 0, 9))
            .await
            .expect("peer route");
        let routes = sh("netstat", &["-rn", "-f", "inet"]);
        assert!(
            routes.contains(&iface) && mentions(&routes, "100.65.0.9"),
            "the peer /32 must be in the table on {iface}:\n{routes}"
        );

        // A subnet route (what a subnet-router peer advertises).
        tun.add_cidr_route("10.66.0.0/16")
            .await
            .expect("cidr route");
        let routes = sh("netstat", &["-rn", "-f", "inet"]);
        assert!(
            // macOS abbreviates: 10.66.0.0/16 prints as `10.66`.
            routes.contains("10.66") && routes.contains(&iface),
            "the subnet route must be in the table on {iface}:\n{routes}"
        );

        // …and every one of them comes back off.
        tun.del_cidr_route("10.66.0.0/16").await;
        tun.del_peer_route(Ipv4Addr::new(100, 65, 0, 9)).await;
        tun.del_address_sync(Ipv4Addr::new(100, 66, 0, 7), 22);

        let cfg = sh("ifconfig", &[&iface]);
        assert!(
            !mentions(&cfg, "100.66.0.7"),
            "a released address must be gone:\n{cfg}"
        );
        assert!(
            mentions(&cfg, "100.65.0.5"),
            "and only that one — the device's own address stays:\n{cfg}"
        );
        let routes = sh("netstat", &["-rn", "-f", "inet"]);
        assert!(
            !mentions(&routes, "100.65.0.9"),
            "a deleted peer route must be gone:\n{routes}"
        );
    }

    /// #1856 — the route guard re-asserts every installed route on every
    /// wave. Re-asserting a route that is already ours must not WRITE: the
    /// old delete-then-add left the `/32` absent for ~3 ms per wave (an
    /// overlay-bound socket gets EHOSTUNREACH in that hole), and each write
    /// fed `route -n monitor`, which armed the next wave, every 3 s forever.
    /// Watches the routing socket while the guard re-asserts, and then
    /// checks that a route that is NOT ours is still repaired.
    #[tokio::test]
    async fn reasserting_our_routes_writes_nothing_and_still_repairs_foreign_ones() {
        if !cfg!(target_os = "macos") {
            eprintln!("skipping: macOS-only (utun + BSD route/ifconfig)");
            return;
        }
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").as_deref() != Ok("1") {
            eprintln!("skipping: set ROOMLER_TUN_KERNEL_TEST=1 (needs root)");
            return;
        }

        let tun =
            SystemTun::up(Ipv4Addr::new(100, 65, 0, 5), MASK_22, 1280).expect("utun bring-up");
        let iface = tun.if_name().to_string();
        let peer = Ipv4Addr::new(100, 65, 0, 9);
        tun.add_peer_route(peer).await.expect("peer route");
        tun.add_cidr_route("10.66.0.0/16")
            .await
            .expect("cidr route");

        // Our own child, killed by its own handle — never by pattern: the
        // daemon's netstate backend is a `route -n monitor` too.
        let mut mon = std::process::Command::new("route")
            .args(["-n", "monitor"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("route monitor");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        for _ in 0..3 {
            tun.add_peer_route(peer)
                .await
                .expect("re-assert peer route");
            tun.add_cidr_route("10.66.0.0/16")
                .await
                .expect("re-assert cidr route");
        }
        // Positive control: a write the monitor MUST see, so the absence
        // asserted below cannot come from a monitor that saw nothing.
        sh(
            "route",
            &["-n", "add", "-inet", "100.65.0.250", "-interface", "lo0"],
        );
        sh("route", &["-n", "delete", "-inet", "100.65.0.250"]);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = mon.kill();
        let out = mon.wait_with_output().expect("route monitor output");
        let text = String::from_utf8_lossy(&out.stdout);
        // One block per routing message, opened by its `got message` banner.
        let is_write = |block: &str| {
            let kind = block.lines().find(|l| l.starts_with("RTM_")).unwrap_or("");
            kind.starts_with("RTM_ADD")
                || kind.starts_with("RTM_DELETE")
                || kind.starts_with("RTM_CHANGE")
        };
        let blocks: Vec<&str> = text.split("got message of size").collect();
        assert!(
            blocks
                .iter()
                .any(|b| is_write(b) && mentions(b, "100.65.0.250")),
            "the monitor did not even see the control write — this run proves nothing:\n{text}"
        );
        // Only our two destinations count: the runner's own ARP churn is
        // not ours to judge.
        let writes: Vec<&str> = blocks
            .iter()
            .copied()
            .filter(|b| {
                is_write(b)
                    && (mentions(b, "100.65.0.9")
                        || mentions(b, "10.66.0.0")
                        || mentions(b, "10.66"))
            })
            .collect();
        assert!(
            writes.is_empty(),
            "re-asserting routes that are already ours must not write the table:\n{}",
            writes.join("\n---\n")
        );

        // A route that is NOT ours is still taken back: the same /32, but
        // via loopback, as a competing product's capture would look.
        sh("route", &["-n", "delete", "-inet", "100.65.0.9"]);
        sh(
            "route",
            &["-n", "add", "-inet", "100.65.0.9", "-interface", "lo0"],
        );
        tun.add_peer_route(peer).await.expect("repair peer route");
        let got = sh("route", &["-n", "get", "100.65.0.9"]);
        assert!(
            got.lines()
                .any(|l| l.trim() == format!("interface: {iface}")),
            "a foreign /32 must be repointed at {iface}:\n{got}"
        );

        tun.del_cidr_route("10.66.0.0/16").await;
        tun.del_peer_route(peer).await;
    }

    /// #1856 follow-up — route(8) prints ANY all-zeros destination as
    /// `default`, which is how an exit client's `0.0.0.0/1` reads back. A real
    /// `/1` would capture half of the runner's traffic, so this uses
    /// `0.0.0.0/8` ("this network", never routed): the same `default`
    /// destination, with a mask that tells it apart from the real default
    /// route. Proves the parser's `default` mapping on a real kernel, which
    /// the `/16` above cannot.
    #[tokio::test]
    async fn an_all_zeros_prefix_reads_back_as_ours_and_is_not_rewritten() {
        if !cfg!(target_os = "macos") {
            eprintln!("skipping: macOS-only (utun + BSD route/ifconfig)");
            return;
        }
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").as_deref() != Ok("1") {
            eprintln!("skipping: set ROOMLER_TUN_KERNEL_TEST=1 (needs root)");
            return;
        }

        let tun =
            SystemTun::up(Ipv4Addr::new(100, 65, 0, 5), MASK_22, 1280).expect("utun bring-up");
        let iface = tun.if_name().to_string();
        tun.add_cidr_route("0.0.0.0/8")
            .await
            .expect("all-zeros route");
        let got = sh(
            "route",
            &["-n", "get", "-net", "0.0.0.0", "-prefixlen", "8"],
        );
        assert!(
            got.lines().any(|l| l.trim() == "destination: default"),
            "route(8) prints an all-zeros destination as `default`, the case the parser maps:\n{got}"
        );
        assert!(
            got.lines()
                .any(|l| l.trim() == format!("interface: {iface}")),
            "the all-zeros route must be ours on {iface}:\n{got}"
        );

        let mut mon = std::process::Command::new("route")
            .args(["-n", "monitor"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("route monitor");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        for _ in 0..3 {
            tun.add_cidr_route("0.0.0.0/8")
                .await
                .expect("re-assert all-zeros route");
        }
        // Positive control, as above.
        sh(
            "route",
            &["-n", "add", "-inet", "100.65.0.251", "-interface", "lo0"],
        );
        sh("route", &["-n", "delete", "-inet", "100.65.0.251"]);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = mon.kill();
        let out = mon.wait_with_output().expect("route monitor output");
        let text = String::from_utf8_lossy(&out.stdout);
        let is_write = |block: &str| {
            let kind = block.lines().find(|l| l.starts_with("RTM_")).unwrap_or("");
            kind.starts_with("RTM_ADD")
                || kind.starts_with("RTM_DELETE")
                || kind.starts_with("RTM_CHANGE")
        };
        let blocks: Vec<&str> = text.split("got message of size").collect();
        assert!(
            blocks
                .iter()
                .any(|b| is_write(b) && mentions(b, "100.65.0.251")),
            "the monitor did not even see the control write — this run proves nothing:\n{text}"
        );
        // A write to a `default`-printed destination on OUR utun can only be
        // the 0.0.0.0/8 re-assert: the runner's real default is on en0.
        let writes: Vec<&str> = blocks
            .iter()
            .copied()
            .filter(|b| is_write(b) && b.contains("default") && b.contains(&iface))
            .collect();
        assert!(
            writes.is_empty(),
            "re-asserting an all-zeros prefix that is already ours must not write the table:\n{}",
            writes.join("\n---\n")
        );

        tun.del_cidr_route("0.0.0.0/8").await;
    }

    fn route_get(family: &str, dest: &str) -> Option<super::BsdRouteGet> {
        super::parse_bsd_route_get(&sh("route", &["-n", "get", family, dest]))
    }

    /// The routing table of `family` (`inet` | `inet6`): where a pin is
    /// read, because a lookup can answer with a clone instead (see
    /// `BsdTableRow`).
    fn table(family: &str) -> Vec<super::BsdTableRow> {
        super::parse_bsd_netstat(&sh("netstat", &["-rnW", "-f", family]))
    }

    fn pin_holds(family: &str, ip: std::net::IpAddr, uplink: &super::BsdUplink) -> bool {
        super::bsd_pin_holds(super::bsd_pin_row(&table(family), ip), uplink)
    }

    /// FR-97 P1a, found in the field. A destination a connection has gone to
    /// keeps an interface-scoped clone of the default route
    /// (`WASCLONED,IFSCOPE`), and an unscoped `route -n get` answers with that
    /// clone even once the pin is in. The coordination server always has one,
    /// held by the control WebSocket. On a tart Mac on 0.4.133 a read-back by
    /// lookup refused that pin and left it in the table untracked. Staged here
    /// with connection attempts to TEST-NET-3, before any capture, which is
    /// the order the exit gate pins in.
    #[tokio::test]
    async fn a_pin_holds_beside_the_scoped_clone_a_connection_leaves() {
        if !cfg!(target_os = "macos") {
            eprintln!("skipping: macOS-only (utun + BSD route/ifconfig)");
            return;
        }
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").as_deref() != Ok("1") {
            eprintln!("skipping: set ROOMLER_TUN_KERNEL_TEST=1 (needs root)");
            return;
        }
        /// Whatever happens, the host route this test makes is removed.
        struct Unpin(&'static str);
        impl Drop for Unpin {
            fn drop(&mut self) {
                let _ = std::process::Command::new("route")
                    .args(["-n", "delete", "-inet", "-host", self.0])
                    .output();
            }
        }

        let tun =
            SystemTun::up(Ipv4Addr::new(100, 65, 0, 5), MASK_22, 1280).expect("utun bring-up");
        let iface = tun.if_name().to_string();
        let dest = "203.0.113.8";
        let ip: std::net::IpAddr = dest.parse().unwrap();
        let uplink =
            super::bsd_default_uplink(route_get("-inet", "default").as_ref(), false, &iface)
                .expect("a macOS runner has an IPv4 default route through a gateway");
        let _unpin = Unpin("203.0.113.8");

        // Out through the default route, as the WebSocket goes: the kernel
        // clones the route for the destination, scoped to the uplink.
        let _ = std::net::TcpStream::connect_timeout(
            &"203.0.113.8:9".parse().unwrap(),
            std::time::Duration::from_millis(800),
        );
        let udp = std::net::UdpSocket::bind("0.0.0.0:0").expect("udp socket");
        let _ = udp.connect("203.0.113.8:9");
        let _ = udp.send(b"fr97");
        let staged = sh("route", &["-n", "get", "-inet", dest]);
        assert!(
            staged.contains("WASCLONED") && staged.contains("IFSCOPE"),
            "no scoped clone was staged, so this run proves nothing:\n{staged}"
        );

        tun.add_host_exemption(ip)
            .await
            .expect("a pin beside a scoped clone must pin");
        assert!(
            pin_holds("inet", ip, &uplink),
            "the table must hold the pin through {uplink:?}:\n{}",
            sh("netstat", &["-rnW", "-f", "inet"])
        );
        assert!(
            tun.stale_host_exemptions(&[ip]).await.is_empty(),
            "a pin beside a clone is not stale"
        );

        // The capture goes in over it, as the `/1`s do, and the address
        // still leaves through the uplink.
        tun.add_cidr_route("203.0.113.0/24")
            .await
            .expect("the staged capture");
        assert_eq!(
            route_get("-inet", dest).and_then(|g| g.interface),
            Some(uplink.interface.clone()),
            "under the capture the pin must carry {dest} out the uplink"
        );

        tun.del_host_exemption(ip).await;
        assert!(
            super::bsd_pin_row(&table("inet"), ip).is_none(),
            "the pin must be gone:\n{}",
            sh("netstat", &["-rnW", "-f", "inet"])
        );
        tun.del_cidr_route("203.0.113.0/24").await;
        drop(udp);
    }

    /// FR-97 P1a — the macOS exemption arm on a real kernel (#2081 was its
    /// absence). A real `/1` would take half of the runner's own traffic, so
    /// the exit's capture is staged one size down: TEST-NET-3 (RFC 5737)
    /// routed into the utun, as everything is under an exit. The exemption
    /// must take one address of it back out through the runner's uplink,
    /// leave a pin that holds alone, and repoint the two shapes a pin that
    /// stopped holding takes.
    #[tokio::test]
    async fn an_exemption_pins_through_the_uplink_and_outranks_an_overlay_capture() {
        if !cfg!(target_os = "macos") {
            eprintln!("skipping: macOS-only (utun + BSD route/ifconfig)");
            return;
        }
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").as_deref() != Ok("1") {
            eprintln!("skipping: set ROOMLER_TUN_KERNEL_TEST=1 (needs root)");
            return;
        }

        let tun =
            SystemTun::up(Ipv4Addr::new(100, 65, 0, 5), MASK_22, 1280).expect("utun bring-up");
        let iface = tun.if_name().to_string();
        let dest = "203.0.113.7";
        let ip: std::net::IpAddr = dest.parse().unwrap();
        // The runner's uplink, read independently of the code under test.
        let uplink =
            super::bsd_default_uplink(route_get("-inet", "default").as_ref(), false, &iface)
                .expect("a macOS runner has an IPv4 default route through a gateway");

        tun.add_cidr_route("203.0.113.0/24")
            .await
            .expect("the staged capture");
        assert_eq!(
            route_get("-inet", dest).and_then(|g| g.interface),
            Some(iface.clone()),
            "the capture must hold before the exemption means anything"
        );

        tun.add_host_exemption(ip)
            .await
            .expect("the exemption pins");
        assert!(
            pin_holds("inet", ip, &uplink),
            "the table must hold the pin through {uplink:?}"
        );
        assert_eq!(
            route_get("-inet", dest).and_then(|g| g.interface),
            Some(uplink.interface.clone()),
            "and the pin must outrank the capture"
        );
        assert!(
            tun.stale_host_exemptions(&[ip]).await.is_empty(),
            "a pin that holds is not stale"
        );

        // #1856 — re-pinning a pin that holds writes nothing. Our own child,
        // killed by its own handle: the daemon's netstate backend is a
        // `route -n monitor` too.
        let mut mon = std::process::Command::new("route")
            .args(["-n", "monitor"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("route monitor");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        for _ in 0..3 {
            tun.add_host_exemption(ip).await.expect("re-pin");
        }
        sh(
            "route",
            &["-n", "add", "-inet", "100.65.0.252", "-interface", "lo0"],
        );
        sh("route", &["-n", "delete", "-inet", "100.65.0.252"]);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = mon.kill();
        let out = mon.wait_with_output().expect("route monitor output");
        let text = String::from_utf8_lossy(&out.stdout);
        let is_write = |block: &str| {
            let kind = block.lines().find(|l| l.starts_with("RTM_")).unwrap_or("");
            kind.starts_with("RTM_ADD")
                || kind.starts_with("RTM_DELETE")
                || kind.starts_with("RTM_CHANGE")
        };
        let blocks: Vec<&str> = text.split("got message of size").collect();
        assert!(
            blocks
                .iter()
                .any(|b| is_write(b) && mentions(b, "100.65.0.252")),
            "the monitor did not even see the control write — this run proves nothing:\n{text}"
        );
        let writes: Vec<&str> = blocks
            .iter()
            .copied()
            .filter(|b| is_write(b) && mentions(b, dest))
            .collect();
        assert!(
            writes.is_empty(),
            "re-pinning a pin that holds must not write the table:\n{}",
            writes.join("\n---\n")
        );

        // The shape a network change leaves: a static host route through
        // another next hop. Named stale, then pinned through the uplink again.
        sh(
            "route",
            &["-n", "change", "-inet", "-host", dest, "127.0.0.1"],
        );
        let rows = table("inet");
        let moved = super::bsd_pin_row(&rows, ip);
        assert!(
            moved.is_some() && !super::bsd_pin_holds(moved, &uplink),
            "staging a stale pin failed: {moved:?}"
        );
        assert_eq!(tun.stale_host_exemptions(&[ip]).await, vec![ip]);
        tun.add_host_exemption(ip).await.expect("re-pinned");
        assert!(
            pin_holds("inet", ip, &uplink),
            "re-pinned through {uplink:?}"
        );

        // The address captured into another interface by a host route of its
        // own, as another product would: taken back the same way.
        sh("route", &["-n", "delete", "-inet", "-host", dest]);
        sh(
            "route",
            &["-n", "add", "-inet", "-host", dest, "-interface", "lo0"],
        );
        assert!(!pin_holds("inet", ip, &uplink), "staging a capture failed");
        tun.add_host_exemption(ip).await.expect("taken back");
        assert!(
            pin_holds("inet", ip, &uplink),
            "taken back through {uplink:?}"
        );

        // Removed, the address falls back into the capture.
        tun.del_host_exemption(ip).await;
        assert!(
            super::bsd_pin_row(&table("inet"), ip).is_none(),
            "the pin must be gone"
        );
        assert_eq!(
            route_get("-inet", dest).and_then(|g| g.interface),
            Some(iface.clone())
        );

        // Removal never touches a host route on our own utun: that is a peer
        // route, the peer path's to manage.
        let peerish = "203.0.113.9";
        sh(
            "route",
            &["-n", "add", "-inet", "-host", peerish, "-interface", &iface],
        );
        tun.del_host_exemption(peerish.parse().unwrap()).await;
        let kept = route_get("-inet", peerish);
        assert!(
            kept.as_ref().is_some_and(
                |g| g.destination == peerish && g.interface.as_deref() == Some(iface.as_str())
            ),
            "a host route on our utun must survive: {kept:?}"
        );
        sh("route", &["-n", "delete", "-inet", "-host", peerish]);
        tun.del_cidr_route("203.0.113.0/24").await;
    }

    /// FR-97 P1a — a `/128` pins only where the uplink has v6. Without an
    /// IPv6 default it is refused, never reported pinned, so v6 exit egress
    /// stays fail-closed while v4 still routes through the exit.
    #[tokio::test]
    async fn a_v6_exemption_needs_a_v6_uplink() {
        if !cfg!(target_os = "macos") {
            eprintln!("skipping: macOS-only (utun + BSD route/ifconfig)");
            return;
        }
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").as_deref() != Ok("1") {
            eprintln!("skipping: set ROOMLER_TUN_KERNEL_TEST=1 (needs root)");
            return;
        }

        let tun =
            SystemTun::up(Ipv4Addr::new(100, 65, 0, 5), MASK_22, 1280).expect("utun bring-up");
        let iface = tun.if_name().to_string();
        let dest = "2001:db8::7";
        let ip: std::net::IpAddr = dest.parse().unwrap();
        let uplink =
            super::bsd_default_uplink(route_get("-inet6", "default").as_ref(), true, &iface);
        let res = tun.add_host_exemption(ip).await;
        match uplink {
            None => {
                let err = res.expect_err("no v6 uplink: refused, never reported pinned");
                assert!(err.to_string().contains("no IPv6 default route"), "{err}");
                assert!(super::bsd_pin_row(&table("inet6"), ip).is_none());
            }
            Some(u) => {
                res.expect("a v6 uplink pins the /128");
                assert!(pin_holds("inet6", ip, &u), "pinned through {u:?}");
                tun.del_host_exemption(ip).await;
            }
        }
    }

    /// FR-97 P1a — `ROOMLERD_EXIT_CLIENT_MACOS=0` puts the client back where
    /// P0a left it: every exemption refused, so the gate withholds, and
    /// nothing written. Safe to set here: the kernel lane runs with
    /// `--test-threads=1`, every other lane returns above, and nothing off
    /// macOS reads the variable.
    #[tokio::test]
    async fn the_kill_switch_refuses_every_exemption() {
        if !cfg!(target_os = "macos") {
            eprintln!("skipping: macOS-only (utun + BSD route/ifconfig)");
            return;
        }
        if std::env::var("ROOMLER_TUN_KERNEL_TEST").as_deref() != Ok("1") {
            eprintln!("skipping: set ROOMLER_TUN_KERNEL_TEST=1 (needs root)");
            return;
        }
        let _restore = crate::env::test_env::Saved::cleared("EXIT_CLIENT_MACOS");
        // SAFETY: see the doc comment; no other thread reads this variable.
        unsafe { crate::env::test_env::set("EXIT_CLIENT_MACOS", "0") };

        let tun =
            SystemTun::up(Ipv4Addr::new(100, 65, 0, 5), MASK_22, 1280).expect("utun bring-up");
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let err = tun
            .add_host_exemption(ip)
            .await
            .expect_err("switched off: refused");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{err}");
        assert!(
            super::bsd_pin_row(&table("inet"), ip).is_none(),
            "and nothing written"
        );
    }
}
