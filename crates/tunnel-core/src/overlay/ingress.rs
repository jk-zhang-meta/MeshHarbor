// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P4 — per-source ingress rules: the finest tier of the overlay ACL.
//!
//! [`LocalScope`](super::router::LocalScope) already limits every peer to the
//! subnets this node advertises, and [`Router::rpf_check`](super::router::Router::rpf_check)
//! stops source forgery. Neither can express *"**Alice** may reach 10.66.0.0/24,
//! but only on :22"* — that needs a per-(recipient, peer) rule set, which the
//! server compiles from `overlay_policies` and ships on the peer's netmap entry.
//!
//! This module is the pure half: parse what a packet is addressed to, and decide
//! whether a rule set permits it. No I/O, no state — so the whole decision table
//! is unit-testable against synthetic packets.
//!
//! # Why the parser has to exist
//!
//! `Router::dst_of_ip_packet` reads the destination and nothing else. Port and
//! protocol were carried on `OverlayRule` from the start but were **stored and
//! distributed, never enforced**, precisely because no layer could see an L4
//! header. This is that layer.

use std::net::IpAddr;

use meshharbor_remote_control::models::{OverlayRule, ProtocolKind};

/// IP protocol numbers we care about. Anything else is `Other` — matched only
/// by a rule that doesn't narrow protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
    Other(u8),
}

/// What the ACL needs from a packet beyond its destination address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L4 {
    pub proto: L4Proto,
    /// `None` when the packet carries no reachable L4 header: ICMP, a non-first
    /// IPv4 fragment, an unparseable v6 extension-header chain, or a truncated
    /// packet. A port-narrowed rule must NOT match such a packet — see
    /// [`rules_permit`].
    pub dst_port: Option<u16>,
}

/// Max IPv6 extension headers to walk before giving up. A real packet has ≤2;
/// the bound exists so a hostile header chain can't spin the recv loop.
const MAX_V6_EXT_HEADERS: usize = 8;

/// IPv6 extension-header next-header values that carry a `(next, len)` pair.
fn v6_ext_len(nh: u8, buf: &[u8], off: usize) -> Option<usize> {
    match nh {
        // Hop-by-hop, routing, destination options, mobility: len is in
        // 8-octet units NOT counting the first 8.
        0 | 43 | 60 | 135 => buf.get(off + 1).map(|l| (*l as usize + 1) * 8),
        // Fragment header is a fixed 8 bytes.
        44 => Some(8),
        // Authentication header: len is in 4-octet units, not counting 2.
        51 => buf.get(off + 1).map(|l| (*l as usize + 2) * 4),
        _ => None,
    }
}

/// Where a packet's L4 header starts, with its IP protocol number. The offset
/// is `None` when the header is out of reach: a non-first IPv4 fragment, or any
/// IPv6 fragment (we cannot tell the first from here). `None` overall only when
/// the packet is not a recognisable IP packet.
fn l4_header(packet: &[u8]) -> Option<(u8, Option<usize>)> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            // IHL is in 32-bit words and must cover the base header.
            let ihl = ((packet[0] & 0x0f) as usize) * 4;
            if ihl < 20 {
                return None;
            }
            // A non-first fragment (offset != 0) has no L4 header to read.
            let frag_off = (((packet[6] & 0x1f) as u16) << 8) | packet[7] as u16;
            Some((packet[9], (frag_off == 0).then_some(ihl)))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut nh = packet[6];
            let mut off = 40usize;
            for _ in 0..MAX_V6_EXT_HEADERS {
                match v6_ext_len(nh, packet, off) {
                    Some(len) => {
                        // A fragment header means the rest may not be here.
                        let is_frag = nh == 44;
                        let next = *packet.get(off)?;
                        off = off.checked_add(len)?;
                        nh = next;
                        if is_frag {
                            // Only the FIRST fragment carries the L4 header, and
                            // we can't tell from here — treat as portless.
                            return Some((nh, None));
                        }
                    }
                    None => break,
                }
            }
            Some((nh, Some(off)))
        }
        _ => None,
    }
}

/// Parse the protocol + destination port of a raw IP packet.
///
/// Length-guarded throughout: every index is bounds-checked, so a truncated or
/// hostile packet yields `None`/`dst_port: None` rather than panicking on the
/// recv path. Returns `None` only when the packet isn't a recognisable IP
/// packet at all.
pub fn parse_l4(packet: &[u8]) -> Option<L4> {
    let (nh, off) = l4_header(packet)?;
    let proto = proto_of(nh);
    Some(L4 {
        proto,
        dst_port: off.and_then(|o| port_at(packet, o, proto)),
    })
}

/// The packet's source as written on the wire.
fn src_ip_of(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(std::net::Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => {
            let raw: [u8; 16] = packet[8..24].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(raw)))
        }
        _ => None,
    }
}

/// The packet's destination as written on the wire.
///
/// Distinct from [`Router::dst_of_ip_packet`](super::router::Router::dst_of_ip_packet),
/// which *unmaps* a derived-ULA v6 to its embedded v4 because it answers a
/// ROUTING question. Rule matching must see the real address so an admin's v6
/// CIDR matches a v6 packet.
pub fn dst_ip_of(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(std::net::Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let raw: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(raw)))
        }
        _ => None,
    }
}

fn proto_of(n: u8) -> L4Proto {
    match n {
        6 => L4Proto::Tcp,
        17 => L4Proto::Udp,
        other => L4Proto::Other(other),
    }
}

/// Destination port lives at bytes 2..4 of both TCP and UDP headers.
fn port_at(packet: &[u8], off: usize, proto: L4Proto) -> Option<u16> {
    if !matches!(proto, L4Proto::Tcp | L4Proto::Udp) {
        return None;
    }
    let hi = *packet.get(off + 2)?;
    let lo = *packet.get(off + 3)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Does a rule constrain ports at all? `1..=65535` is the stored "any" default
/// ([`OverlayRule::all_ports`]), so a rule that never narrowed ports must still
/// match a portless packet (ICMP, a fragment).
fn narrows_ports(rule: &OverlayRule) -> bool {
    rule.port_range.low > 1 || rule.port_range.high < u16::MAX
}

fn proto_matches(rule: &OverlayRule, proto: L4Proto) -> bool {
    match rule.proto {
        ProtocolKind::Any => true,
        ProtocolKind::Tcp => proto == L4Proto::Tcp,
        ProtocolKind::Udp => proto == L4Proto::Udp,
    }
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    cidr.trim()
        .parse::<ipnet::IpNet>()
        .map(|n| n.contains(&ip))
        .unwrap_or(false)
}

/// Does `rules` permit a packet to `dst` with this L4 view?
///
/// **First match wins is irrelevant here — these are pure grants**: the server
/// has already collapsed the tenant's policies into the set of rules this peer
/// may use against this node, so any single match is an allow and no match is a
/// deny.
///
/// An **empty** rule set means the server compiled no grant for this peer, which
/// is a DENY under enforcement. Callers must therefore distinguish "no rules
/// shipped at all" (a pre-P4 server / ACL off → don't call this) from "rules
/// shipped and empty" (genuinely denied) — see the `Option` on the peer's
/// stored rules in `wg.rs`.
///
/// A port-narrowed or proto-narrowed rule never matches a packet whose L4 header
/// we couldn't read (`dst_port: None`). That is deliberate and fail-closed: a
/// fragmented packet must not be able to slip past a `:22`-only rule by hiding
/// its port.
pub fn rules_permit(rules: &[OverlayRule], dst: IpAddr, l4: Option<&L4>) -> bool {
    rules.iter().any(|r| {
        if !cidr_contains(&r.cidr, dst) {
            return false;
        }
        let Some(l4) = l4 else {
            // Unparseable packet: only a rule that narrows neither dimension.
            return matches!(r.proto, ProtocolKind::Any) && !narrows_ports(r);
        };
        if !proto_matches(r, l4.proto) {
            return false;
        }
        if !narrows_ports(r) {
            return true;
        }
        match l4.dst_port {
            Some(p) => p >= r.port_range.low && p <= r.port_range.high,
            None => false,
        }
    })
}

// ── #18: the stateful half, for packets addressed to this node itself ───────

const FLOW_SHARDS: usize = 16;
const FLOWS_PER_SHARD: usize = 4096;
/// How long a UDP flow or ICMP echo this node sent keeps admitting replies
/// after its last outbound packet.
pub const REPLY_FLOW_IDLE_MS: u64 = 120_000;

/// One flow from this node's side: UDP ports, or an ICMP echo identifier
/// (`remote_id` 0).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    local: IpAddr,
    remote: IpAddr,
    local_id: u16,
    remote_id: u16,
}

fn u16_at(packet: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]))
}

/// The UDP flows and ICMP echoes this node sent toward peers whose ingress
/// the tenant's ACL governs, so their replies are not judged as new traffic.
/// Bounded: a full shard drops what has gone idle, and is emptied if that is
/// not enough (a forgotten flow's replies are judged by the rules again, so
/// the bound fails closed).
#[derive(Default)]
pub struct ReplyFlows {
    shards: [std::sync::Mutex<std::collections::HashMap<FlowKey, u64>>; FLOW_SHARDS],
}

impl ReplyFlows {
    fn shard(&self, key: &FlowKey) -> &std::sync::Mutex<std::collections::HashMap<FlowKey, u64>> {
        use std::hash::{BuildHasher, BuildHasherDefault};
        let h = BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default()
            .hash_one(key);
        &self.shards[(h as usize) % FLOW_SHARDS]
    }

    /// Remember the flow an outbound packet belongs to, if it is one whose
    /// replies need remembering (a UDP datagram or an ICMP echo request).
    pub fn note_outbound(&self, packet: &[u8], now_ms: u64) {
        let Some((nh, Some(off))) = l4_header(packet) else {
            return;
        };
        let (Some(local), Some(remote)) = (src_ip_of(packet), dst_ip_of(packet)) else {
            return;
        };
        let key = match nh {
            17 => match (u16_at(packet, off), u16_at(packet, off + 2)) {
                (Some(local_id), Some(remote_id)) => FlowKey {
                    proto: 17,
                    local,
                    remote,
                    local_id,
                    remote_id,
                },
                _ => return,
            },
            1 | 58 if packet.get(off) == Some(&if nh == 1 { 8 } else { 128 }) => {
                let Some(id) = u16_at(packet, off + 4) else {
                    return;
                };
                FlowKey {
                    proto: nh,
                    local,
                    remote,
                    local_id: id,
                    remote_id: 0,
                }
            }
            _ => return,
        };
        let mut m = self.shard(&key).lock().unwrap();
        if m.len() >= FLOWS_PER_SHARD && !m.contains_key(&key) {
            m.retain(|_, at| now_ms.saturating_sub(*at) < REPLY_FLOW_IDLE_MS);
            if m.len() >= FLOWS_PER_SHARD {
                m.clear();
            }
        }
        m.insert(key, now_ms);
    }

    fn admits(&self, key: FlowKey, now_ms: u64) -> bool {
        self.shard(&key)
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|at| now_ms.saturating_sub(*at) < REPLY_FLOW_IDLE_MS)
    }
}

/// #18 — is an inbound packet addressed to this node itself part of a flow
/// already admitted, so the per-source rules need not judge it?
///
/// Modelled on Tailscale's packet filter. A TCP segment other than a bare SYN
/// belongs to a connection whose SYN was judged where it arrived; a UDP
/// datagram or an ICMP echo reply answers a flow this node sent
/// ([`ReplyFlows`]); an ICMP error passes so path-MTU discovery keeps working.
/// A new TCP connection, an unsolicited datagram, a fragment or anything else
/// is judged by the rules.
///
/// ⚠️ Unlike Tailscale, an echo REQUEST to the node itself passes too. The
/// mesh measures itself with it (meshharbord's RTT prober pings every live peer's
/// overlay address and feeds the path monitor), so a port-narrowed tenant ACL
/// would otherwise blind path quality. It reaches no service, and the netmap
/// already tells the peer this node is online. Only the node itself: an echo
/// aimed past a subnet router is still judged.
pub fn admitted_reply(packet: &[u8], flows: &ReplyFlows, now_ms: u64) -> bool {
    let Some((nh, Some(off))) = l4_header(packet) else {
        return false;
    };
    let (Some(remote), Some(local)) = (src_ip_of(packet), dst_ip_of(packet)) else {
        return false;
    };
    match nh {
        // Flags: SYN 0x02, ACK 0x10. Only a SYN without ACK opens a connection.
        6 => packet
            .get(off + 13)
            .is_some_and(|f| f & 0x02 == 0 || f & 0x10 != 0),
        17 => match (u16_at(packet, off), u16_at(packet, off + 2)) {
            (Some(remote_id), Some(local_id)) => flows.admits(
                FlowKey {
                    proto: 17,
                    local,
                    remote,
                    local_id,
                    remote_id,
                },
                now_ms,
            ),
            _ => false,
        },
        1 | 58 => {
            let Some(&ty) = packet.get(off) else {
                return false;
            };
            let (request, reply, errors): (u8, u8, &[u8]) = if nh == 1 {
                (8, 0, &[3, 11, 12])
            } else {
                (128, 129, &[1, 2, 3, 4])
            };
            if ty == request {
                true
            } else if ty == reply {
                u16_at(packet, off + 4).is_some_and(|id| {
                    flows.admits(
                        FlowKey {
                            proto: nh,
                            local,
                            remote,
                            local_id: id,
                            remote_id: 0,
                        },
                        now_ms,
                    )
                })
            } else {
                errors.contains(&ty)
            }
        }
        _ => false,
    }
}

fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry_byte: Option<u8> = None;
    for chunk in chunks {
        let mut slice = *chunk;
        if let Some(prev) = carry_byte.take() {
            if let Some((&first, rest)) = slice.split_first() {
                sum += u16::from_be_bytes([prev, first]) as u32;
                slice = rest;
            } else {
                carry_byte = Some(prev);
                continue;
            }
        }
        let mut chunks_exact = slice.chunks_exact(2);
        for pair in &mut chunks_exact {
            sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        if let Some(&rem) = chunks_exact.remainder().first() {
            carry_byte = Some(rem);
        }
    }
    if let Some(rem) = carry_byte {
        sum += u16::from_be_bytes([rem, 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_tcp_rst_l4(l4: &[u8]) -> Option<[u8; 20]> {
    if l4.len() < 20 {
        return None;
    }
    let flags = l4[13];
    // RFC 793 §3.4: an incoming segment carrying RST must NEVER elicit a RST.
    if flags & 0x04 != 0 {
        return None;
    }
    let in_seq = u32::from_be_bytes(l4[4..8].try_into().ok()?);
    let in_ack = u32::from_be_bytes(l4[8..12].try_into().ok()?);
    let tcp_hdr_len = ((l4[12] >> 4) as usize) * 4;
    if tcp_hdr_len < 20 || l4.len() < tcp_hdr_len {
        return None;
    }
    let seg_data_len = (l4.len() - tcp_hdr_len) as u32;
    let (out_seq, out_ack, out_flags) = if flags & 0x10 != 0 {
        (in_ack, 0u32, 0x04u8)
    } else {
        let syn_fin = u32::from(flags & 0x02 != 0) + u32::from(flags & 0x01 != 0);
        (
            0u32,
            in_seq.wrapping_add(seg_data_len).wrapping_add(syn_fin),
            0x14u8,
        )
    };
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&l4[2..4]);
    tcp[2..4].copy_from_slice(&l4[0..2]);
    tcp[4..8].copy_from_slice(&out_seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&out_ack.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = out_flags;
    Some(tcp)
}

/// T9-2 — build a minimal, checksum-valid L3/L4 reject packet (TCP RST for
/// non-RST TCP segments; ICMPv4 Type 3 Code 13 / ICMPv6 Type 1 Code 1
/// Administratively Prohibited for non-TCP packets that are not themselves
/// ICMP errors) to return over the source WireGuard carrier when an inbound
/// packet is dropped by `IngressDeny::NotPermitted`.
pub fn build_acl_reject_packet(packet: &[u8]) -> Option<Vec<u8>> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = ((packet[0] & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            let pkt_len = if total_len >= ihl {
                total_len.min(packet.len())
            } else {
                packet.len()
            };
            let packet = &packet[..pkt_len];
            // RFC 1812 §4.3.2.7: never generate an error/reject for a non-first fragment.
            let frag_off = (((packet[6] & 0x1f) as u16) << 8) | packet[7] as u16;
            if frag_off != 0 {
                return None;
            }
            let src: [u8; 4] = packet[12..16].try_into().ok()?;
            let dst: [u8; 4] = packet[16..20].try_into().ok()?;
            if src == [0, 0, 0, 0]
                || src == [255, 255, 255, 255]
                || dst == [255, 255, 255, 255]
                || (src[0] & 0xf0) == 0xe0
                || (dst[0] & 0xf0) == 0xe0
            {
                return None;
            }
            let proto = packet[9];
            let l4 = &packet[ihl..];
            if proto == 6 {
                let mut tcp = build_tcp_rst_l4(l4)?;
                let pseudo = [
                    dst[0], dst[1], dst[2], dst[3], src[0], src[1], src[2], src[3], 0, 6, 0, 20,
                ];
                let tcp_csum = internet_checksum(&[&pseudo, &tcp]);
                tcp[16..18].copy_from_slice(&tcp_csum.to_be_bytes());
                let mut out = vec![0u8; 40];
                out[0] = 0x45;
                out[2..4].copy_from_slice(&40u16.to_be_bytes());
                out[6] = 0x40; // DF
                out[8] = 64; // TTL
                out[9] = 6; // TCP
                out[12..16].copy_from_slice(&dst);
                out[16..20].copy_from_slice(&src);
                let ip_csum = internet_checksum(&[&out[..20]]);
                out[10..12].copy_from_slice(&ip_csum.to_be_bytes());
                out[20..40].copy_from_slice(&tcp);
                Some(out)
            } else {
                // RFC 1812 §4.3.2.7: never emit an ICMP error for any ICMP packet
                // other than an Echo Request (type 8).
                if proto == 1 && l4.first() != Some(&8) {
                    return None;
                }
                let quote_len = packet.len().min(ihl + 64).min(576 - 28);
                let quoted = &packet[..quote_len];
                let icmp_len = 8 + quoted.len();
                let total = (20 + icmp_len) as u16;
                let mut out = vec![0u8; total as usize];
                out[0] = 0x45;
                out[2..4].copy_from_slice(&total.to_be_bytes());
                out[6] = 0x40;
                out[8] = 64;
                out[9] = 1; // ICMPv4
                out[12..16].copy_from_slice(&dst);
                out[16..20].copy_from_slice(&src);
                let ip_csum = internet_checksum(&[&out[..20]]);
                out[10..12].copy_from_slice(&ip_csum.to_be_bytes());
                out[20] = 3; // Destination Unreachable
                out[21] = 13; // Communication Administratively Prohibited
                out[28..].copy_from_slice(quoted);
                let icmp_csum = internet_checksum(&[&out[20..]]);
                out[22..24].copy_from_slice(&icmp_csum.to_be_bytes());
                Some(out)
            }
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let pkt_len = 40usize.saturating_add(payload_len).min(packet.len());
            if pkt_len < 40 {
                return None;
            }
            let packet = &packet[..pkt_len];
            let (nh, Some(off)) = l4_header(packet)? else {
                return None;
            };
            if off > packet.len() {
                return None;
            }
            let src: [u8; 16] = packet[8..24].try_into().ok()?;
            let dst: [u8; 16] = packet[24..40].try_into().ok()?;
            if src == [0u8; 16] || src[0] == 0xff || dst[0] == 0xff {
                return None;
            }
            let l4 = &packet[off..];
            if nh == 6 {
                let mut tcp = build_tcp_rst_l4(l4)?;
                let upper_len = 20u32.to_be_bytes();
                let next_hdr = [0, 0, 0, 6u8];
                let tcp_csum = internet_checksum(&[&dst, &src, &upper_len, &next_hdr, &tcp]);
                tcp[16..18].copy_from_slice(&tcp_csum.to_be_bytes());
                let mut out = vec![0u8; 60];
                out[0] = 0x60;
                out[4..6].copy_from_slice(&20u16.to_be_bytes());
                out[6] = 6;
                out[7] = 64;
                out[8..24].copy_from_slice(&dst);
                out[24..40].copy_from_slice(&src);
                out[40..60].copy_from_slice(&tcp);
                Some(out)
            } else {
                // RFC 4443 §2.4(e): only allow ICMPv6 Echo Request (type 128)
                // among ICMPv6 inputs; never reply to ICMPv6 errors or ND.
                if nh == 58 && l4.first() != Some(&128) {
                    return None;
                }
                let quote_len = packet.len().min(off + 64).min(1280 - 48);
                let quoted = &packet[..quote_len];
                let icmp_len = 8 + quoted.len();
                let mut out = vec![0u8; 40 + icmp_len];
                out[0] = 0x60;
                out[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
                out[6] = 58; // ICMPv6
                out[7] = 64;
                out[8..24].copy_from_slice(&dst);
                out[24..40].copy_from_slice(&src);
                out[40] = 1; // Destination Unreachable
                out[41] = 1; // Communication with destination administratively prohibited
                out[48..].copy_from_slice(quoted);
                let upper_len = (icmp_len as u32).to_be_bytes();
                let next_hdr = [0, 0, 0, 58u8];
                let icmp_csum = internet_checksum(&[&dst, &src, &upper_len, &next_hdr, &out[40..]]);
                out[42..44].copy_from_slice(&icmp_csum.to_be_bytes());
                Some(out)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 packet carrying `l4` as protocol `proto`.
    fn pkt4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p.extend_from_slice(l4);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }
    fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[12] = 0x50;
        h[13] = flags;
        h
    }
    fn udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut h = vec![0u8; 8];
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h
    }
    fn icmp(ty: u8, id: u16) -> Vec<u8> {
        let mut h = vec![ty, 0, 0, 0, 0, 0, 0, 0];
        h[4..6].copy_from_slice(&id.to_be_bytes());
        h
    }
    const ME: [u8; 4] = [100, 64, 0, 2];
    const PEER: [u8; 4] = [100, 64, 0, 1];

    #[test]
    fn only_a_bare_tcp_syn_is_judged() {
        let f = ReplyFlows::default();
        assert!(
            !admitted_reply(&pkt4(6, PEER, ME, &tcp(40000, 443, 0x02)), &f, 0),
            "SYN opens a connection"
        );
        assert!(
            admitted_reply(&pkt4(6, PEER, ME, &tcp(443, 40000, 0x12)), &f, 0),
            "SYN+ACK answers ours"
        );
        assert!(
            admitted_reply(&pkt4(6, PEER, ME, &tcp(443, 40000, 0x10)), &f, 0),
            "ACK is established"
        );
        assert!(
            !admitted_reply(&pkt4(6, PEER, ME, &[0u8; 4]), &f, 0),
            "no flags to read: judged"
        );
    }

    #[test]
    fn a_udp_reply_passes_only_for_a_flow_this_node_sent_and_only_while_fresh() {
        let f = ReplyFlows::default();
        let reply = pkt4(17, PEER, ME, &udp(53, 40000));
        assert!(!admitted_reply(&reply, &f, 1_000), "unsolicited");
        f.note_outbound(&pkt4(17, ME, PEER, &udp(40000, 53)), 1_000);
        assert!(admitted_reply(&reply, &f, 2_000));
        assert!(
            !admitted_reply(&pkt4(17, PEER, ME, &udp(53, 40001)), &f, 2_000),
            "another local port"
        );
        assert!(
            !admitted_reply(&pkt4(17, [100, 64, 0, 9], ME, &udp(53, 40000)), &f, 2_000),
            "another peer"
        );
        assert!(
            !admitted_reply(&reply, &f, 1_000 + REPLY_FLOW_IDLE_MS),
            "idle flows expire"
        );
    }

    #[test]
    fn icmp_echo_replies_need_our_echo_and_requests_and_errors_always_pass() {
        let f = ReplyFlows::default();
        assert!(!admitted_reply(&pkt4(1, PEER, ME, &icmp(0, 7)), &f, 0));
        f.note_outbound(&pkt4(1, ME, PEER, &icmp(8, 7)), 0);
        assert!(admitted_reply(&pkt4(1, PEER, ME, &icmp(0, 7)), &f, 1));
        assert!(
            admitted_reply(&pkt4(1, PEER, ME, &icmp(8, 9)), &f, 1),
            "the mesh's own RTT probe is never cut by a tenant ACL"
        );
        assert!(
            admitted_reply(&pkt4(1, PEER, ME, &icmp(3, 0)), &f, 1),
            "unreachable / frag needed"
        );
    }

    #[test]
    fn a_fragment_is_always_judged() {
        let f = ReplyFlows::default();
        let mut p = pkt4(6, PEER, ME, &tcp(443, 40000, 0x10));
        p[6] = 0x00;
        p[7] = 0x10; // fragment offset 16
        assert!(!admitted_reply(&p, &f, 0));
    }
    use meshharbor_remote_control::models::PortRange;

    fn rule(cidr: &str, low: u16, high: u16, proto: ProtocolKind) -> OverlayRule {
        OverlayRule {
            cidr: cidr.into(),
            port_range: PortRange { low, high },
            proto,
        }
    }

    fn any_rule(cidr: &str) -> OverlayRule {
        rule(cidr, 1, u16::MAX, ProtocolKind::Any)
    }

    /// IPv4 with a settable IHL so the options case is covered.
    fn v4(proto: u8, dst_port: u16, ihl_words: u8, frag_off: u16) -> Vec<u8> {
        let ihl = ihl_words as usize * 4;
        let mut p = vec![0u8; ihl + 8];
        p[0] = 0x40 | ihl_words;
        p[6] = ((frag_off >> 8) & 0x1f) as u8;
        p[7] = (frag_off & 0xff) as u8;
        p[9] = proto;
        p[12..16].copy_from_slice(&[100, 64, 0, 1]);
        p[16..20].copy_from_slice(&[10, 66, 51, 147]);
        p[ihl + 2..ihl + 4].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn parses_tcp_and_udp_ports_from_ipv4() {
        let l4 = parse_l4(&v4(6, 22, 5, 0)).unwrap();
        assert_eq!(l4.proto, L4Proto::Tcp);
        assert_eq!(l4.dst_port, Some(22));

        let l4 = parse_l4(&v4(17, 53, 5, 0)).unwrap();
        assert_eq!(l4.proto, L4Proto::Udp);
        assert_eq!(l4.dst_port, Some(53));
    }

    #[test]
    fn honours_ipv4_options_via_ihl() {
        // IHL=7 ⇒ 8 bytes of options; the port must be read past them, not at
        // the fixed offset 20.
        let l4 = parse_l4(&v4(6, 443, 7, 0)).unwrap();
        assert_eq!(l4.dst_port, Some(443));
    }

    #[test]
    fn a_non_first_fragment_has_no_port() {
        let l4 = parse_l4(&v4(6, 22, 5, 185)).unwrap();
        assert_eq!(l4.proto, L4Proto::Tcp);
        assert_eq!(l4.dst_port, None, "a fragment's L4 header isn't here");
    }

    #[test]
    fn icmp_has_a_proto_but_no_port() {
        let l4 = parse_l4(&v4(1, 0, 5, 0)).unwrap();
        assert_eq!(l4.proto, L4Proto::Other(1));
        assert_eq!(l4.dst_port, None);
    }

    #[test]
    fn truncated_and_garbage_packets_never_panic() {
        assert!(parse_l4(&[]).is_none());
        assert!(parse_l4(&[0x45]).is_none());
        assert!(parse_l4(&[0x60; 39]).is_none());
        // IHL smaller than the base header is malformed.
        let mut bad = v4(6, 22, 5, 0);
        bad[0] = 0x44;
        assert!(parse_l4(&bad).is_none());
        // Truncated L4: header claims TCP but the ports aren't present.
        let short = &v4(6, 22, 5, 0)[..21];
        assert_eq!(parse_l4(short).unwrap().dst_port, None);
    }

    #[test]
    fn parses_ipv6_through_a_hop_by_hop_header() {
        let mut p = vec![0u8; 40 + 8 + 8];
        p[0] = 0x60;
        p[6] = 0; // hop-by-hop
        p[40] = 6; // next = TCP
        p[41] = 0; // len 0 ⇒ 8 bytes
        p[48 + 2..48 + 4].copy_from_slice(&8080u16.to_be_bytes());
        let l4 = parse_l4(&p).unwrap();
        assert_eq!(l4.proto, L4Proto::Tcp);
        assert_eq!(l4.dst_port, Some(8080));
    }

    #[test]
    fn a_plain_ipv6_packet_reads_ports_at_40() {
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[6] = 17;
        p[40 + 2..40 + 4].copy_from_slice(&53u16.to_be_bytes());
        let l4 = parse_l4(&p).unwrap();
        assert_eq!(l4.proto, L4Proto::Udp);
        assert_eq!(l4.dst_port, Some(53));
    }

    // -----------------------------------------------------------------------
    // Rule matching
    // -----------------------------------------------------------------------

    fn dst() -> IpAddr {
        "10.66.51.147".parse().unwrap()
    }

    #[test]
    fn an_empty_rule_set_denies() {
        assert!(!rules_permit(&[], dst(), None));
    }

    #[test]
    fn a_cidr_only_rule_permits_any_port_and_proto() {
        let rules = [any_rule("10.66.0.0/16")];
        let tcp = parse_l4(&v4(6, 22, 5, 0)).unwrap();
        assert!(rules_permit(&rules, dst(), Some(&tcp)));
        // …and a portless packet too, since it narrows nothing.
        assert!(rules_permit(&rules, dst(), None));
    }

    #[test]
    fn a_cidr_outside_the_rule_never_matches() {
        let rules = [any_rule("10.66.0.0/16")];
        let outside: IpAddr = "10.84.6.5".parse().unwrap();
        let tcp = parse_l4(&v4(6, 22, 5, 0)).unwrap();
        assert!(!rules_permit(&rules, outside, Some(&tcp)));
    }

    #[test]
    fn a_port_narrowed_rule_admits_only_that_port() {
        let rules = [rule("10.66.0.0/16", 22, 22, ProtocolKind::Any)];
        let ssh = parse_l4(&v4(6, 22, 5, 0)).unwrap();
        let https = parse_l4(&v4(6, 443, 5, 0)).unwrap();
        assert!(rules_permit(&rules, dst(), Some(&ssh)));
        assert!(!rules_permit(&rules, dst(), Some(&https)));
    }

    #[test]
    fn a_port_narrowed_rule_rejects_a_packet_hiding_its_port() {
        // The fail-closed case that matters: a fragment must not slip past a
        // :22-only rule just because its port isn't readable.
        let rules = [rule("10.66.0.0/16", 22, 22, ProtocolKind::Any)];
        let frag = parse_l4(&v4(6, 22, 5, 185)).unwrap();
        assert!(!rules_permit(&rules, dst(), Some(&frag)));
        assert!(!rules_permit(&rules, dst(), None));
    }

    #[test]
    fn proto_narrowing_discriminates() {
        let tcp_only = [rule("10.66.0.0/16", 1, u16::MAX, ProtocolKind::Tcp)];
        let tcp = parse_l4(&v4(6, 22, 5, 0)).unwrap();
        let udp = parse_l4(&v4(17, 22, 5, 0)).unwrap();
        let icmp = parse_l4(&v4(1, 0, 5, 0)).unwrap();
        assert!(rules_permit(&tcp_only, dst(), Some(&tcp)));
        assert!(!rules_permit(&tcp_only, dst(), Some(&udp)));
        assert!(!rules_permit(&tcp_only, dst(), Some(&icmp)));
    }

    #[test]
    fn any_matching_rule_grants_regardless_of_order() {
        // These are grants, not a first-match-wins chain: a later rule can
        // widen what an earlier one didn't cover.
        let rules = [
            rule("10.66.0.0/16", 22, 22, ProtocolKind::Tcp),
            rule("10.66.0.0/16", 443, 443, ProtocolKind::Tcp),
        ];
        let https = parse_l4(&v4(6, 443, 5, 0)).unwrap();
        assert!(rules_permit(&rules, dst(), Some(&https)));
    }

    #[test]
    fn v6_destinations_match_v6_cidrs() {
        let rules = [any_rule("fd72:6f6f:6d6c::/96")];
        let d: IpAddr = "fd72:6f6f:6d6c::6440:7".parse().unwrap();
        assert!(rules_permit(&rules, d, None));
        let outside: IpAddr = "2606:4700::1111".parse().unwrap();
        assert!(!rules_permit(&rules, outside, None));
    }

    #[test]
    fn a_malformed_cidr_never_grants() {
        let rules = [any_rule("not-a-cidr")];
        assert!(!rules_permit(&rules, dst(), None));
    }

    #[test]
    fn t9_2_build_acl_reject_packet_tcp_rst_and_icmp_admin_prohibited() {
        let flows = ReplyFlows::default();

        // 1. Bare TCP SYN (IPv4) -> 40-byte IPv4 TCP RST|ACK with ack = seq + 1,
        //    admitted as a reply on the initiator's side.
        let mut syn = pkt4(6, PEER, ME, &tcp(51234, 3389, 0x02));
        syn[24..28].copy_from_slice(&1000u32.to_be_bytes());
        let rst = build_acl_reject_packet(&syn).expect("TCP SYN must yield TCP RST");
        assert_eq!(rst.len(), 40);
        assert_eq!(rst[9], 6);
        assert_eq!(&rst[12..16], &ME, "src swapped to responder");
        assert_eq!(&rst[16..20], &PEER, "dst swapped to initiator");
        assert_eq!(u16::from_be_bytes([rst[20], rst[21]]), 3389);
        assert_eq!(u16::from_be_bytes([rst[22], rst[23]]), 51234);
        assert_eq!(rst[33], 0x14, "RST|ACK for bare SYN");
        assert_eq!(u32::from_be_bytes(rst[28..32].try_into().unwrap()), 1001);
        assert!(
            admitted_reply(&rst, &flows, 0),
            "generated TCP RST must pass admitted_reply on the initiator"
        );

        // 2. Incoming TCP RST must NEVER elicit a reply RST (RFC 793 loop guard).
        let in_rst = pkt4(6, PEER, ME, &tcp(51234, 3389, 0x04));
        assert!(build_acl_reject_packet(&in_rst).is_none());

        // 3. Denied UDP datagram (IPv4) -> ICMPv4 Type 3 Code 13 (Admin Prohibited),
        //    admitted as an ICMP error on the initiator's side.
        let u = pkt4(17, PEER, ME, &udp(53000, 9999));
        let ic = build_acl_reject_packet(&u).expect("UDP must yield ICMPv4 Admin Prohibited");
        assert_eq!(ic[9], 1, "ICMPv4");
        assert_eq!(ic[20], 3, "Destination Unreachable");
        assert_eq!(ic[21], 13, "Communication Administratively Prohibited");
        assert!(
            admitted_reply(&ic, &flows, 0),
            "generated ICMPv4 Admin Prohibited must pass admitted_reply on the initiator"
        );

        // 4. Incoming ICMP error must NEVER elicit an ICMP error (RFC 1812 loop guard).
        let in_icmp_err = pkt4(1, PEER, ME, &icmp(3, 0));
        assert!(build_acl_reject_packet(&in_icmp_err).is_none());

        // 5. Checksums verify cleanly (ones-complement folded sum == 0) + IPv6 coverage.
        assert_eq!(internet_checksum(&[&rst[..20]]), 0, "IPv4 header csum");
        assert_eq!(internet_checksum(&[&ic[..20]]), 0, "ICMPv4 IPv4 hdr csum");
        assert_eq!(internet_checksum(&[&ic[20..]]), 0, "ICMPv4 body csum");
        let me6: [u8; 16] = "fd72:6f6f:6d6c::6440:2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let peer6: [u8; 16] = "fd72:6f6f:6d6c::6440:7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let mut syn6 = vec![0u8; 40];
        syn6[0] = 0x60;
        syn6[4..6].copy_from_slice(&20u16.to_be_bytes());
        syn6[6] = 6;
        syn6[7] = 64;
        syn6[8..24].copy_from_slice(&peer6);
        syn6[24..40].copy_from_slice(&me6);
        syn6.extend_from_slice(&tcp(49000, 3389, 0x02));
        let rst6 = build_acl_reject_packet(&syn6).expect("IPv6 TCP SYN must yield TCP RST");
        assert_eq!(rst6.len(), 60);
        assert_eq!(rst6[6], 6);
        assert!(admitted_reply(&rst6, &flows, 0));
        let mut u6 = vec![0u8; 40];
        u6[0] = 0x60;
        u6[4..6].copy_from_slice(&8u16.to_be_bytes());
        u6[6] = 17;
        u6[7] = 64;
        u6[8..24].copy_from_slice(&peer6);
        u6[24..40].copy_from_slice(&me6);
        u6.extend_from_slice(&udp(49001, 9999));
        let ic6 =
            build_acl_reject_packet(&u6).expect("IPv6 UDP must yield ICMPv6 Admin Prohibited");
        assert_eq!(ic6[6], 58);
        assert_eq!(ic6[40], 1);
        assert_eq!(ic6[41], 1);
        assert!(admitted_reply(&ic6, &flows, 0));
    }
}
