// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! A host's OWN LAN route, broken underneath it: detected and repaired.
//!
//! **Field (CORPLAP-3, Cisco AnyConnect in split-exclude, 2026-10-10).** The
//! Wi-Fi's own `192.168.8.0/24` row, a stack-owned DIRECT route, carried the
//! next hop `192.168.0.1`. That is a gateway from another network, and ARP left
//! it `Incomplete` on this one. Windows skipped the row, so a packet to a LAN
//! neighbour fell through to the VPN's `0.0.0.0/0`. FR-33 then read the LAN as
//! captured, and every LAN peer went to relay, though the VPN listed the LAN as
//! split-EXCLUDED and a ping over an on-link route answered in 1 ms.
//! AnyConnect's own "Routing table - Original" snapshot already held the stale
//! row, so reconnecting the VPN does not cure it.
//!
//! FR-33 is detect-and-report, because routing around a VPN's capture is
//! policy evasion. This module does not do that: its signature is narrow, and
//! it concerns the owning interface's OWN row:
//!
//! 1. The interface holding the address has a row for exactly its prefix whose
//!    next hop is set and lies OUTSIDE the prefix. A next hop has to be on-link,
//!    so that row can never carry a packet.
//! 2. No OTHER interface holds a route for the prefix or for anything inside
//!    it. A VPN that captures the LAN does so with rows of its own, and then
//!    this module stands aside, and also removes any halves it installed.
//! 3. The dead next hop belongs to no other interface: it is not the next hop
//!    of any of their rows, and it does not lie inside any of their connected
//!    subnets. A LAN row pointed INTO a VPN's tunnel is how a VPN could block a
//!    LAN it does not exclude, and that is a capture too. A stale gateway from
//!    a network the host has left belongs to nobody.
//!
//! The repair restores what the stack holds for a healthy interface: the prefix
//! on-link, written as its two halves (`/plen+1`). They outrank the dead row by
//! length without deleting it, so nobody's row is touched.
//!
//! It is stateless on purpose. Every pass re-derives the verdict from the
//! table, so a restart, a crash or a move to another network leaves nothing
//! behind: the same pass removes halves whose parent is no longer this
//! interface's prefix, or whose own row is healthy again.

use std::net::Ipv4Addr;

/// One IPv4 route row: as much of it as the verdict needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub ifindex: u32,
    pub net: Ipv4Addr,
    pub plen: u8,
    /// `0.0.0.0` = on-link.
    pub next_hop: Ipv4Addr,
    pub metric: u32,
    /// Added as a static route (`MIB_IPPROTO_NETMGMT`), the only kind this
    /// module installs and therefore the only kind it will remove.
    pub static_route: bool,
}

/// One address this host holds on a LAN interface (VPN adapters excluded by
/// the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnAddr {
    pub ifindex: u32,
    pub addr: Ipv4Addr,
    pub plen: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Add both on-link halves of `net/plen` on `ifindex`. `dead_gw` is the
    /// impossible next hop that made the own row unusable.
    Install {
        ifindex: u32,
        net: Ipv4Addr,
        plen: u8,
        dead_gw: Ipv4Addr,
    },
    /// Remove one half row of ours, `net/plen` (the HALF's length).
    Remove {
        ifindex: u32,
        net: Ipv4Addr,
        plen: u8,
        why: RemoveWhy,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveWhy {
    /// The interface's own row for the prefix is on-link again.
    Healed,
    /// The interface no longer holds an address in the parent prefix (it
    /// moved to another network).
    Moved,
    /// Another interface now routes the prefix: a VPN capture, which is
    /// never ours to route around (FR-33).
    Captured,
    /// The repair is switched off.
    Disabled,
}

pub fn network_of(ip: Ipv4Addr, plen: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & mask(plen))
}

fn mask(plen: u8) -> u32 {
    if plen == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(plen.min(32)))
    }
}

fn contains(net: Ipv4Addr, plen: u8, ip: Ipv4Addr) -> bool {
    network_of(ip, plen) == network_of(net, plen)
}

/// The two halves of `net/plen` (requires `plen < 32`).
pub fn halves(net: Ipv4Addr, plen: u8) -> [(Ipv4Addr, u8); 2] {
    let net = network_of(net, plen);
    let half = plen + 1;
    let upper = Ipv4Addr::from(u32::from(net) | (1u32 << (32 - u32::from(half))));
    [(net, half), (upper, half)]
}

/// The interface's own row for its prefix, if the table holds one.
fn own_row(ifindex: u32, net: Ipv4Addr, plen: u8, rows: &[Row]) -> Option<&Row> {
    rows.iter()
        .find(|r| r.ifindex == ifindex && r.plen == plen && r.net == net)
}

/// The own row on `ifindex` for `net/plen` is unusable: its next hop is set
/// and lies outside the prefix. Returns that next hop.
fn dead_gateway(ifindex: u32, net: Ipv4Addr, plen: u8, rows: &[Row]) -> Option<Ipv4Addr> {
    own_row(ifindex, net, plen, rows)
        .map(|r| r.next_hop)
        .filter(|gw| !gw.is_unspecified() && !contains(net, plen, *gw))
}

/// A dead next hop that belongs to ANOTHER interface's domain: the next hop
/// of one of its rows, or an address inside one of its connected subnets (a
/// VPN adapter's tunnel network). That is the LAN pointed INTO another
/// interface, which is how a VPN could block a LAN it does not exclude, and
/// is treated as a capture. A stale gateway from a network this host has
/// left (CORPLAP-3's `192.168.0.1`) belongs to nobody.
fn foreign_gateway(ifindex: u32, gw: Ipv4Addr, rows: &[Row]) -> bool {
    rows.iter().any(|r| {
        r.ifindex != ifindex
            && (r.next_hop == gw
                || (r.next_hop.is_unspecified() && r.plen > 0 && contains(r.net, r.plen, gw)))
    })
}

/// Another interface routes the prefix or something inside it: a capture.
/// Rows on the owning interface (its own `/32`s, its broadcast, our halves)
/// never count, and nor does anything less specific than the prefix (a VPN's
/// `0.0.0.0/0` is not a claim on the LAN, only on everything else).
fn foreign_claims(ifindex: u32, net: Ipv4Addr, plen: u8, rows: &[Row]) -> bool {
    rows.iter()
        .any(|r| r.ifindex != ifindex && r.plen >= plen && contains(net, plen, r.net))
}

/// A row this module could have installed: static, on-link, metric 0.
fn half_like(r: &Row) -> bool {
    r.static_route && r.next_hop.is_unspecified() && r.metric == 0 && (9..=31).contains(&r.plen)
}

/// Which repairs to install and which halves to remove, from the table alone.
pub fn plan(own: &[OwnAddr], rows: &[Row], enabled: bool) -> Vec<Action> {
    let mut actions = Vec::new();
    // The prefixes that need (or keep) their halves.
    let mut wanted: Vec<(u32, Ipv4Addr, u8)> = Vec::new();
    if enabled {
        for o in own {
            if o.plen == 0 || o.plen >= 31 || o.addr.is_loopback() || o.addr.is_link_local() {
                continue;
            }
            let net = network_of(o.addr, o.plen);
            if wanted.contains(&(o.ifindex, net, o.plen)) {
                continue;
            }
            let Some(dead_gw) = dead_gateway(o.ifindex, net, o.plen, rows) else {
                continue;
            };
            if foreign_claims(o.ifindex, net, o.plen, rows)
                || foreign_gateway(o.ifindex, dead_gw, rows)
            {
                continue;
            }
            wanted.push((o.ifindex, net, o.plen));
            let present = halves(net, o.plen).iter().all(|&(hn, hp)| {
                rows.iter()
                    .any(|r| r.ifindex == o.ifindex && r.net == hn && r.plen == hp && half_like(r))
            });
            if !present {
                actions.push(Action::Install {
                    ifindex: o.ifindex,
                    net,
                    plen: o.plen,
                    dead_gw,
                });
            }
        }
    }
    // Halves to remove: a complete PAIR of half-like rows on one interface
    // whose parent is not wanted. A lone half-like row is never ours (we only
    // ever install both), which keeps an operator's own static route out of
    // reach.
    for r in rows.iter().filter(|r| half_like(r)) {
        let parent_plen = r.plen - 1;
        let parent = network_of(r.net, parent_plen);
        if r.net != parent {
            continue; // visit each pair once, from its lower half
        }
        let [_, (upper, _)] = halves(parent, parent_plen);
        let pair = rows
            .iter()
            .any(|u| u.ifindex == r.ifindex && u.net == upper && u.plen == r.plen && half_like(u));
        if !pair || wanted.contains(&(r.ifindex, parent, parent_plen)) {
            continue;
        }
        let own_here = own.iter().any(|o| {
            o.ifindex == r.ifindex && o.plen == parent_plen && network_of(o.addr, o.plen) == parent
        });
        let own = own_row(r.ifindex, parent, parent_plen, rows);
        let why = if !enabled {
            RemoveWhy::Disabled
        } else if !own_here {
            RemoveWhy::Moved
        } else if foreign_claims(r.ifindex, parent, parent_plen, rows)
            || dead_gateway(r.ifindex, parent, parent_plen, rows)
                .is_some_and(|gw| foreign_gateway(r.ifindex, gw, rows))
        {
            RemoveWhy::Captured
        } else if own.is_some_and(|o| o.next_hop.is_unspecified()) {
            RemoveWhy::Healed
        } else {
            // The own row is missing altogether, rather than dead: leave the
            // halves alone. They are the interface's only on-link route for
            // its prefix, and the stack re-adds its own row in due course.
            continue;
        };
        for (net, plen) in halves(parent, parent_plen) {
            actions.push(Action::Remove {
                ifindex: r.ifindex,
                net,
                plen,
                why,
            });
        }
    }
    actions
}

/// The repair switch: `MESHHARBORD_OVERLAY_LAN_ROUTE_REPAIR` / config
/// `overlay_lan_route_repair`. Default ON. Off removes every pair of halves
/// this module could have installed.
pub fn enabled() -> bool {
    crate::env::flag("OVERLAY_LAN_ROUTE_REPAIR", true)
}

/// Read the IPv4 table, plan, and apply. Called from the network-state sample
/// with the host's LAN addresses (`(name, ifindex, addr, plen)`, VPN adapters
/// already excluded), BEFORE the FR-33 capture probe runs, so the probe sees
/// the repaired table in the same sample.
#[cfg(windows)]
pub fn reconcile(lan_v4: &[(String, Option<u32>, Ipv4Addr, u8)]) {
    let own: Vec<OwnAddr> = lan_v4
        .iter()
        .filter_map(|(_, idx, addr, plen)| {
            idx.map(|ifindex| OwnAddr {
                ifindex,
                addr: *addr,
                plen: *plen,
            })
        })
        .collect();
    let Some(rows) = win::rows_v4() else {
        return;
    };
    for action in plan(&own, &rows, enabled()) {
        let name = |ifindex: u32| {
            lan_v4
                .iter()
                .find(|(_, i, _, _)| *i == Some(ifindex))
                .map(|(n, _, _, _)| n.as_str())
                .unwrap_or("?")
                .to_string()
        };
        match action {
            Action::Install {
                ifindex,
                net,
                plen,
                dead_gw,
            } => {
                let results: Vec<_> = halves(net, plen)
                    .iter()
                    .map(|&(hn, hp)| win::add_onlink(ifindex, hn, hp))
                    .collect();
                if results.iter().all(|r| r.is_ok()) {
                    tracing::warn!(
                        prefix = %format_args!("{net}/{plen}"),
                        interface = %name(ifindex),
                        dead_next_hop = %dead_gw,
                        "overlay: this interface's own LAN route points at a next hop that is \
                         not on its LAN, so the OS sent LAN traffic to the default route (a VPN's \
                         stale gateway?) — added the prefix on-link as two halves, so LAN peers \
                         are direct again; the dead row is left as it is"
                    );
                } else {
                    tracing::warn!(
                        prefix = %format_args!("{net}/{plen}"),
                        interface = %name(ifindex),
                        dead_next_hop = %dead_gw,
                        errors = ?results.iter().filter_map(|r| r.as_ref().err()).collect::<Vec<_>>(),
                        "overlay: could not repair a dead own LAN route"
                    );
                }
            }
            Action::Remove {
                ifindex,
                net,
                plen,
                why,
            } => {
                win::del_onlink(ifindex, net, plen);
                tracing::info!(
                    half = %format_args!("{net}/{plen}"),
                    interface = %name(ifindex),
                    why = ?why,
                    "overlay: removed a LAN-route repair half"
                );
            }
        }
    }
}

#[cfg(windows)]
mod win {
    use super::Row;
    use std::net::Ipv4Addr;
    use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
        InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT, SOCKADDR_INET};

    fn v4_of(a: &SOCKADDR_INET) -> Option<Ipv4Addr> {
        // SAFETY: the union is read only after the family tag says it is v4.
        unsafe {
            (a.si_family == AF_INET)
                .then(|| Ipv4Addr::from(a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))
        }
    }

    fn sockaddr_v4(ip: Ipv4Addr) -> SOCKADDR_INET {
        // SAFETY: a zeroed SOCKADDR_INET is valid; we set the v4 arm.
        unsafe {
            let mut s: SOCKADDR_INET = std::mem::zeroed();
            s.Ipv4.sin_family = AF_INET;
            s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            s
        }
    }

    /// The whole IPv4 forward table, as [`Row`]s.
    pub(super) fn rows_v4() -> Option<Vec<Row>> {
        // SAFETY: GetIpForwardTable2 allocates the table, we read
        // NumEntries rows from it and free it with FreeMibTable.
        unsafe {
            let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
            if GetIpForwardTable2(AF_INET, &mut table) != NO_ERROR || table.is_null() {
                return None;
            }
            let n = (*table).NumEntries as usize;
            let first = (*table).Table.as_ptr();
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let r = &*first.add(i);
                let (Some(net), Some(next_hop)) =
                    (v4_of(&r.DestinationPrefix.Prefix), v4_of(&r.NextHop))
                else {
                    continue;
                };
                out.push(Row {
                    ifindex: r.InterfaceIndex,
                    net,
                    plen: r.DestinationPrefix.PrefixLength,
                    next_hop,
                    metric: r.Metric,
                    static_route: r.Protocol == MIB_IPPROTO_NETMGMT,
                });
            }
            FreeMibTable(table as *const core::ffi::c_void);
            Some(out)
        }
    }

    fn onlink_row(ifindex: u32, net: Ipv4Addr, plen: u8) -> MIB_IPFORWARD_ROW2 {
        // SAFETY: InitializeIpForwardEntry fills valid defaults (static
        // protocol, infinite lifetimes); we set index, prefix, an on-link
        // next hop and metric 0.
        unsafe {
            let mut r: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            InitializeIpForwardEntry(&mut r);
            r.InterfaceIndex = ifindex;
            r.DestinationPrefix.Prefix = sockaddr_v4(net);
            r.DestinationPrefix.PrefixLength = plen;
            r.NextHop = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
            r.Metric = 0;
            r
        }
    }

    /// Add `net/plen` on-link on `ifindex` (active store only: a reboot
    /// clears it). Already present counts as success.
    pub(super) fn add_onlink(ifindex: u32, net: Ipv4Addr, plen: u8) -> std::io::Result<()> {
        let r = onlink_row(ifindex, net, plen);
        // SAFETY: a fully initialised row; the API copies it.
        let rc = unsafe { CreateIpForwardEntry2(&r) };
        if rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(rc as i32))
        }
    }

    /// Remove `net/plen` on-link from `ifindex`; absent is fine.
    pub(super) fn del_onlink(ifindex: u32, net: Ipv4Addr, plen: u8) {
        let r = onlink_row(ifindex, net, plen);
        // SAFETY: the row carries the (interface, prefix, next hop) key.
        unsafe { DeleteIpForwardEntry2(&r) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn row(ifindex: u32, net: &str, plen: u8, nh: &str, metric: u32, static_route: bool) -> Row {
        Row {
            ifindex,
            net: ip(net),
            plen,
            next_hop: ip(nh),
            metric,
            static_route,
        }
    }

    const WLAN: u32 = 26;
    const VPN: u32 = 11;

    fn wlan_addr() -> OwnAddr {
        OwnAddr {
            ifindex: WLAN,
            addr: ip("192.168.8.112"),
            plen: 24,
        }
    }

    /// CORPLAP-3 on 2026-10-10, row for row: the Wi-Fi's own `/24` carries a
    /// next hop from another network, the VPN holds only `0.0.0.0/0`, and its
    /// split-exclude routes ride the Wi-Fi.
    fn corplap3() -> Vec<Row> {
        vec![
            row(WLAN, "192.168.8.0", 24, "192.168.0.1", 0, false),
            row(WLAN, "192.168.8.112", 32, "0.0.0.0", 256, false),
            row(WLAN, "192.168.8.1", 32, "0.0.0.0", 1, true),
            row(WLAN, "192.168.0.0", 23, "192.168.8.1", 0, true),
            row(WLAN, "192.168.178.0", 24, "192.168.8.1", 0, true),
            row(WLAN, "0.0.0.0", 0, "192.168.8.1", 0, true),
            row(VPN, "0.0.0.0", 0, "10.138.80.1", 1, true),
        ]
    }

    #[test]
    fn halves_split_a_prefix_at_its_next_bit() {
        assert_eq!(
            halves(ip("192.168.8.77"), 24),
            [(ip("192.168.8.0"), 25), (ip("192.168.8.128"), 25)]
        );
        assert_eq!(
            halves(ip("10.20.0.0"), 16),
            [(ip("10.20.0.0"), 17), (ip("10.20.128.0"), 17)]
        );
    }

    #[test]
    fn a_dead_own_route_is_repaired_with_both_halves() {
        let plan = plan(&[wlan_addr()], &corplap3(), true);
        assert_eq!(
            plan,
            [Action::Install {
                ifindex: WLAN,
                net: ip("192.168.8.0"),
                plen: 24,
                dead_gw: ip("192.168.0.1"),
            }]
        );
    }

    #[test]
    fn once_repaired_the_halves_are_kept_and_nothing_is_reinstalled() {
        let mut rows = corplap3();
        rows.push(row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, true));
        rows.push(row(WLAN, "192.168.8.128", 25, "0.0.0.0", 0, true));
        assert_eq!(plan(&[wlan_addr()], &rows, true), []);
    }

    /// FR-33: a VPN that captures the LAN does it with its own rows. Then the
    /// LAN is not ours to route around: no repair, and halves already in
    /// place come out.
    #[test]
    fn a_capture_by_another_interface_is_never_routed_around() {
        let mut rows = corplap3();
        rows.push(row(VPN, "192.168.8.0", 25, "10.138.80.1", 1, true));
        rows.push(row(VPN, "192.168.8.128", 25, "10.138.80.1", 1, true));
        assert_eq!(plan(&[wlan_addr()], &rows, true), [], "no repair");

        rows.push(row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, true));
        rows.push(row(WLAN, "192.168.8.128", 25, "0.0.0.0", 0, true));
        let plan = plan(&[wlan_addr()], &rows, true);
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|a| matches!(
            a,
            Action::Remove {
                ifindex: WLAN,
                why: RemoveWhy::Captured,
                ..
            }
        )));
    }

    #[test]
    fn a_healthy_own_route_needs_nothing_and_heals_away_old_halves() {
        let mut rows = corplap3();
        rows[0] = row(WLAN, "192.168.8.0", 24, "0.0.0.0", 256, false);
        assert_eq!(plan(&[wlan_addr()], &rows, true), [], "healthy: no repair");
        rows.push(row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, true));
        rows.push(row(WLAN, "192.168.8.128", 25, "0.0.0.0", 0, true));
        let plan = plan(&[wlan_addr()], &rows, true);
        assert_eq!(
            plan,
            [
                Action::Remove {
                    ifindex: WLAN,
                    net: ip("192.168.8.0"),
                    plen: 25,
                    why: RemoveWhy::Healed
                },
                Action::Remove {
                    ifindex: WLAN,
                    net: ip("192.168.8.128"),
                    plen: 25,
                    why: RemoveWhy::Healed
                },
            ]
        );
    }

    /// The laptop moved to another network: the halves' parent is no longer
    /// the interface's prefix, so they would only black-hole that range.
    #[test]
    fn halves_left_behind_by_a_move_are_removed() {
        let rows = vec![
            row(WLAN, "10.1.2.0", 24, "0.0.0.0", 256, false),
            row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, true),
            row(WLAN, "192.168.8.128", 25, "0.0.0.0", 0, true),
        ];
        let moved = OwnAddr {
            ifindex: WLAN,
            addr: ip("10.1.2.3"),
            plen: 24,
        };
        let plan = plan(&[moved], &rows, true);
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|a| matches!(
            a,
            Action::Remove {
                why: RemoveWhy::Moved,
                ..
            }
        )));
    }

    /// Only a complete pair is ever ours. A lone static on-link route, or a
    /// pair at another metric, is somebody else's and is left alone.
    #[test]
    fn a_lone_or_unlike_row_is_never_removed() {
        let lone = vec![row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, true)];
        assert_eq!(plan(&[], &lone, true), []);
        let metric5 = vec![
            row(WLAN, "192.168.8.0", 25, "0.0.0.0", 5, true),
            row(WLAN, "192.168.8.128", 25, "0.0.0.0", 5, true),
        ];
        assert_eq!(plan(&[], &metric5, true), []);
        let stack_owned = vec![
            row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, false),
            row(WLAN, "192.168.8.128", 25, "0.0.0.0", 0, false),
        ];
        assert_eq!(plan(&[], &stack_owned, true), [], "not a static route");
    }

    /// A next hop INSIDE the prefix is a routed LAN, odd but reachable: not
    /// dead, not repaired. Nor is a row whose own route is missing entirely.
    #[test]
    fn a_reachable_next_hop_or_a_missing_row_is_not_repaired() {
        let mut rows = corplap3();
        rows[0] = row(WLAN, "192.168.8.0", 24, "192.168.8.1", 0, false);
        assert_eq!(plan(&[wlan_addr()], &rows, true), []);
        rows.remove(0);
        assert_eq!(plan(&[wlan_addr()], &rows, true), []);
    }

    /// A VPN that blocks a LAN it does not exclude could do it by pointing the
    /// LAN's own row INTO the tunnel: at its gateway, or at an address on its
    /// tunnel network. That row is just as dead to the LAN, but it is a
    /// capture, so no repair, and halves already in place come out.
    #[test]
    fn a_lan_row_pointed_into_another_interface_is_a_capture() {
        for gw in ["10.138.80.1", "10.138.80.200"] {
            let mut rows = corplap3();
            rows[0] = row(WLAN, "192.168.8.0", 24, gw, 0, false);
            rows.push(row(VPN, "10.138.80.0", 24, "0.0.0.0", 256, false));
            assert_eq!(plan(&[wlan_addr()], &rows, true), [], "{gw}: no repair");

            rows.push(row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, true));
            rows.push(row(WLAN, "192.168.8.128", 25, "0.0.0.0", 0, true));
            let plan = plan(&[wlan_addr()], &rows, true);
            assert_eq!(plan.len(), 2, "{gw}");
            assert!(plan.iter().all(|a| matches!(
                a,
                Action::Remove {
                    why: RemoveWhy::Captured,
                    ..
                }
            )));
        }
    }

    /// Switched off: nothing is installed, and every pair of ours comes out.
    #[test]
    fn disabled_installs_nothing_and_removes_ours() {
        let mut rows = corplap3();
        assert_eq!(plan(&[wlan_addr()], &rows, false), []);
        rows.push(row(WLAN, "192.168.8.0", 25, "0.0.0.0", 0, true));
        rows.push(row(WLAN, "192.168.8.128", 25, "0.0.0.0", 0, true));
        let plan = plan(&[wlan_addr()], &rows, false);
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|a| matches!(
            a,
            Action::Remove {
                why: RemoveWhy::Disabled,
                ..
            }
        )));
    }

    /// A docked laptop with Wi-Fi and Ethernet on one LAN: the Ethernet's own
    /// on-link row is "another interface routing the prefix". Stand aside, as
    /// FR-33 does for a sibling; the sibling reaches the LAN anyway.
    #[test]
    fn a_same_lan_sibling_is_left_alone() {
        let mut rows = corplap3();
        rows.push(row(18, "192.168.8.0", 24, "0.0.0.0", 256, false));
        assert_eq!(plan(&[wlan_addr()], &rows, true), []);
    }

    #[test]
    fn point_to_point_and_link_local_addresses_are_skipped() {
        let rows = vec![row(WLAN, "169.254.0.0", 16, "10.0.0.1", 0, false)];
        let ll = OwnAddr {
            ifindex: WLAN,
            addr: ip("169.254.3.4"),
            plen: 16,
        };
        assert_eq!(plan(&[ll], &rows, true), []);
        let p2p = OwnAddr {
            ifindex: WLAN,
            addr: ip("10.9.9.1"),
            plen: 31,
        };
        let rows = vec![row(WLAN, "10.9.9.0", 31, "10.0.0.1", 0, false)];
        assert_eq!(plan(&[p2p], &rows, true), []);
    }
}
