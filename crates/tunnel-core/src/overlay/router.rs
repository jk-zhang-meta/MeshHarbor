// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Overlay crypto-routing table.
//!
//! boringtun's [`Tunn`](boringtun::noise::Tunn) is **single-peer** — it
//! has no notion of `allowed_ips`. The mesh's routing therefore lives
//! here: a map from a peer's overlay address to its WireGuard public
//! key. Because every overlay peer is advertised with a single-host
//! `allowed_ips` (its `overlay_ip/32`), this is an exact-match
//! `HashMap<Ipv4Addr, [u8; 32]>` rather than a longest-prefix trie.
//!
//! Outbound path: read the destination address out of the IP packet
//! header → [`Router::route`] → the peer's pubkey → the peer's `Tunn`.
//!
//! **IPv6 (dual-stack)**: a node's overlay v6 is *derived* from its overlay
//! v4 — the v4 embedded in the low 32 bits of Roomler's ULA `/96`
//! ([`derive_overlay_v6`], `docs/overlay-communication.md`). Routing therefore
//! needs **no v6 table**: [`Router::dst_of_ip_packet`] unmaps a derived-ULA
//! destination back to its embedded v4 and routes on the existing v4 entries,
//! covering every present and future peer with zero per-peer state and zero
//! netmap change. A v6 destination outside the ULA (link-local/multicast OS
//! noise, genuine internet v6) is unroutable by construction and dropped.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Roomler's overlay IPv6 ULA — `fd72:6f6f:6d6c::/48` (`fd` + ASCII "rooml").
/// A node's overlay v6 is its overlay v4 embedded in the low 32 bits of the
/// fixed `/96` inside this ULA, so v6 is *derived*, never separately allocated
/// (see `docs/overlay-communication.md`). Pinned once — every derived address
/// bakes it in, so it must never change.
const OVERLAY_ULA_HEXTETS: [u16; 6] = [0xfd72, 0x6f6f, 0x6d6c, 0, 0, 0];
/// On-link prefix for the derived-v6 network: the fixed `/96` (48-bit ULA + 48
/// zero bits). Assigning an iface this prefix makes every peer's
/// `fd72:6f6f:6d6c::<their-v4>` on-link — the v6 mirror of how the v4 network
/// prefix makes peers on-link — so no OS/netstack route table is needed for
/// peer traffic.
pub const OVERLAY_V6_ONLINK_PREFIX: u8 = 96;

/// P5 exit-node (S3b) — the overlay's IPv6 ULA as a CIDR string, used as the
/// SOURCE scope for the exit node's v6 MASQUERADE (`ip6tables -t nat POSTROUTING
/// -s <this> -j MASQUERADE`). Scoped to the derived-v6 `/96` (NOT the `/48` ULA
/// block) so it exactly matches the on-link prefix every overlay node's derived
/// v6 falls in ([`derive_overlay_v6`]) and can't over-broadly masquerade a
/// co-located non-overlay ULA (Docker/WSL2/another VPN).
pub const OVERLAY_ULA_V6_CIDR: &str = "fd72:6f6f:6d6c::/96";

/// Derive a node's overlay IPv6 from its overlay IPv4: embed the 32-bit v4 in
/// the low 32 bits of Roomler's ULA `/96` (`fd72:6f6f:6d6c::<v4>`). Deterministic
/// and reversible ([`embedded_v4_of_overlay_v6`]), so a node self-derives its
/// own v6 and every peer's v6 from the v4 the server already assigns — no
/// server allocation, no wire change.
pub fn derive_overlay_v6(v4: Ipv4Addr) -> Ipv6Addr {
    let o = v4.octets();
    let [a, b, c, d, e, f] = OVERLAY_ULA_HEXTETS;
    Ipv6Addr::new(
        a,
        b,
        c,
        d,
        e,
        f,
        u16::from_be_bytes([o[0], o[1]]),
        u16::from_be_bytes([o[2], o[3]]),
    )
}

/// The inverse of [`derive_overlay_v6`]: the overlay v4 embedded in a
/// derived-ULA v6, or `None` if `v6` is not inside Roomler's ULA `/96`.
pub fn embedded_v4_of_overlay_v6(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    if seg[..6] != OVERLAY_ULA_HEXTETS {
        return None;
    }
    let hi = seg[6].to_be_bytes();
    let lo = seg[7].to_be_bytes();
    Some(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]))
}

/// P4 — reverse-path filtering mode (`overlay_rpf` config /
/// `ROOMLERD_OVERLAY_RPF`): `off` (deliver everything — the pre-P4
/// behaviour) | `warn` (evaluate + count + throttled-log, still deliver — the
/// built-in default) | `enforce` (drop).
///
/// Warn-first deliberately, mirroring B2's `shadow` default: this is a
/// data-plane gate on EVERY inbound packet of every node in the fleet, and a
/// false deny is a silent blackhole. `warn` costs one routing-table lookup per
/// packet and can't drop anything, so the fleet reports what `enforce` WOULD
/// have killed before anyone flips it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RpfMode {
    Off,
    #[default]
    Warn,
    Enforce,
}

impl RpfMode {
    /// Parse the config/env value. Unset — or anything unrecognised — is the
    /// safe `Warn` default, so a typo can never silently disable the counter
    /// NOR silently start dropping traffic.
    pub fn parse(v: Option<&str>) -> Self {
        match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("off") | Some("0") | Some("false") => RpfMode::Off,
            Some("enforce") | Some("on") | Some("1") | Some("true") => RpfMode::Enforce,
            _ => RpfMode::Warn,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RpfMode::Off => "off",
            RpfMode::Warn => "warn",
            RpfMode::Enforce => "enforce",
        }
    }
}

/// P4 — what this node accepts as a DESTINATION from a peer: its own overlay
/// address, plus the subnets it advertises.
///
/// The other half of the ingress gap. [`Router::rpf_check`] stops a peer
/// FORGING a source; this stops it ADDRESSING somewhere we were never meant to
/// carry it. Without it, any peer that can reach a subnet router at all can
/// aim a packet at anything that router's own routing table can resolve —
/// approval bought nothing beyond the first hop.
///
/// Scope comes from the node's OWN `advertised_routes`, which is already what
/// `overlay::nat::enable` provisions forwarding + NAT for. So this enforces
/// exactly the set the data plane was configured to carry — no wire change, no
/// server round-trip, and it cannot disagree with the forwarding it guards.
///
/// ⚠️ Deliberately NOT per-source. Narrowing "which peer may reach which subset,
/// on which ports" needs server-compiled per-peer rules that the netmap has no
/// field for yet. This is the coarse tier: everyone who may reach this router
/// may reach everything it advertises, but nothing beyond.
#[derive(Debug, Clone)]
pub struct LocalScope {
    self_ip: Option<Ipv4Addr>,
    advertised: Vec<Cidr>,
    /// `true` when scope can't be represented (an advertised route we couldn't
    /// parse as a v4 CIDR — e.g. a v6 prefix), or when this node is an exit.
    /// Then EVERY destination is accepted: refusing to guess is the only safe
    /// posture, because a too-narrow scope silently blackholes a legitimate
    /// subnet router.
    unconstrained: bool,
}

impl Default for LocalScope {
    /// **Unconstrained**, deliberately — this is what a device holds before
    /// bring-up calls [`WgDevice::set_local_scope`]. An empty-but-enforcing
    /// default would deny every destination (not even the self IP is known
    /// yet), so under `enforce` a node would blackhole all traffic in the
    /// window before its scope is published. Fail open until we actually know
    /// the scope, exactly as every other tier of this ACL does.
    fn default() -> Self {
        Self {
            self_ip: None,
            advertised: Vec::new(),
            unconstrained: true,
        }
    }
}

impl LocalScope {
    /// Build from the node's own overlay IP and its advertised route strings.
    /// An unparseable route, or a default route (exit node — it legitimately
    /// carries the whole internet), makes the scope unconstrained.
    pub fn new(self_ip: Option<Ipv4Addr>, advertised_routes: &[String]) -> Self {
        let mut advertised = Vec::new();
        let mut unconstrained = false;
        for r in advertised_routes {
            match Cidr::parse(r) {
                Some(c) if c.is_default_route() => unconstrained = true,
                Some(c) => advertised.push(c),
                // v6 prefix or malformed — can't represent it, so don't pretend.
                None => unconstrained = true,
            }
        }
        Self {
            self_ip,
            advertised,
            unconstrained,
        }
    }

    /// May a peer address this packet's destination through us?
    ///
    /// `dst` is [`Router::dst_of_ip_packet`]'s v4 routing key, so a derived
    /// overlay ULA v6 is already unmapped to its v4. `None` (a non-overlay v6)
    /// is accepted only by an unconstrained scope, mirroring the fail-closed
    /// stance on global v6 elsewhere.
    pub fn permits_dst(&self, dst: Option<Ipv4Addr>) -> bool {
        if self.unconstrained {
            return true;
        }
        let Some(v4) = dst else {
            return false;
        };
        // Traffic TO us is always in scope — the overwhelmingly common case,
        // and checked first so a plain peer-to-peer node never walks the list.
        if self.self_ip == Some(v4) {
            return true;
        }
        self.advertised.iter().any(|c| c.contains(v4))
    }

    /// `true` when this scope accepts everything (no advertised routes to
    /// enforce, an exit node, or an unrepresentable route).
    pub fn is_unconstrained(&self) -> bool {
        self.unconstrained
    }

    /// Is `dst` this node's OWN overlay address (rather than something it would
    /// forward)? Per-source ingress rules govern what a peer may reach
    /// *through* us; talking *to* us is already governed by netmap visibility,
    /// so a policy that grants only LAN access must not also make the router
    /// itself unpingable.
    pub fn is_self_dst(&self, dst: Option<Ipv4Addr>) -> bool {
        matches!((self.self_ip, dst), (Some(a), Some(b)) if a == b)
    }
}

/// Why a decapsulated packet's source address failed the reverse-path check.
/// Carried into the log line + counters so a field report distinguishes "a
/// subnet router is forwarding a range it never advertised" (`NoRoute` — an
/// approval/config gap) from "a peer is forging a sibling's address"
/// (`OtherPeer` — the actual attack).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RpfDeny {
    /// No installed peer owns this source address.
    NoRoute,
    /// A DIFFERENT installed peer owns it.
    OtherPeer,
    /// A non-overlay IPv6 source from a peer that is not this node's v6 exit.
    NonOverlayV6,
}

/// The reverse-path verdict for one decapsulated packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RpfVerdict {
    Allow,
    Deny(RpfDeny),
}

/// An IPv4 CIDR — Phase 1 subnet routes. Hand-rolled (no dep): the overlay only
/// needs `contains` + `parse` for a handful of advertised subnets per peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// Network address, already masked to `prefix` bits.
    base: u32,
    prefix: u8,
}

impl Cidr {
    /// Parse `"a.b.c.d/nn"`. `None` on malformed input or `nn > 32`.
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, pfx) = s.split_once('/')?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let prefix: u8 = pfx.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = Self::mask(prefix);
        Some(Self {
            base: u32::from(ip) & mask,
            prefix,
        })
    }

    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }

    /// Does this CIDR contain `ip`?
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & Self::mask(self.prefix)) == self.base
    }

    /// True for a **default route** — the `0.0.0.0/0` default OR either half of
    /// the split-default (`0.0.0.0/1`, `128.0.0.0/1`). Any prefix ≤ 1 is exactly
    /// one of these three (a `/1` masks to base `0` or `0x8000_0000`), and none
    /// is ever a legitimate LAN subnet worth routing per-peer. The client-side
    /// subnet-install path (P5/A1) drops these so an admin-approved exit-node
    /// `0.0.0.0/0` never auto-installs a default route on every peer; opt-in
    /// exit-node routing installs the split-default via a separate,
    /// exemption-aware path.
    pub fn is_default_route(&self) -> bool {
        self.prefix <= 1
    }

    /// Do the two CIDRs share any address (one contains the other)?
    pub fn overlaps(&self, other: &Cidr) -> bool {
        let m = Self::mask(self.prefix.min(other.prefix));
        self.base & m == other.base & m
    }
}

impl std::fmt::Display for Cidr {
    /// Canonical `network/prefix` (the base is already masked), e.g.
    /// `"192.168.1.0/24"` — used to hand the route to the OS.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }
}

/// Overlay crypto-routing table: exact-match `/32` host routes (the fast path
/// every peer carries) plus optional per-peer subnet CIDRs (Phase 1 subnet
/// router), resolved by longest-prefix on a host-route miss.
#[derive(Debug, Default, Clone)]
pub struct Router {
    by_ip: HashMap<Ipv4Addr, [u8; 32]>,
    subnets: Vec<(Cidr, [u8; 32])>,
    /// P5 exit-node (S3b) — when set, the pubkey of the peer that carries this
    /// node's GLOBAL IPv6 egress. Any global-unicast v6 destination (that isn't
    /// an overlay-internal derived ULA) encapsulates to it. `None` (default) =
    /// global v6 is dropped ([`WgDevice::send_ip_packet`]) — the fail-closed
    /// stance. A single Option rather than a v6 subnet table because P5 is
    /// single-exit / all-global-v6-to-one-peer.
    v6_exit: Option<[u8; 32]>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install / replace the host route for `ip` → `pubkey`.
    ///
    /// Returns the pubkey the address previously pointed at when that was a
    /// DIFFERENT peer — an overlay-IP REASSIGNMENT. The server recycles a
    /// removed device's address to the tenant's pool, so this is expected after
    /// the old owner is gone, but seeing it while the old owner is still
    /// installed means two peers claim one address and the caller should say so
    /// loudly.
    pub fn upsert(&mut self, ip: Ipv4Addr, pubkey: [u8; 32]) -> Option<[u8; 32]> {
        self.by_ip.insert(ip, pubkey).filter(|prev| *prev != pubkey)
    }

    /// Phase 1 — replace `pubkey`'s advertised subnet routes (empty clears them).
    ///
    /// Returns every claim that is now DUPLICATED — an identical CIDR also held
    /// by a different peer, i.e. two subnet routers approved for the same
    /// prefix. Both claims stay in the table (each claimant's RPF authority
    /// must survive so its own return traffic isn't dropped by a table edit),
    /// [`route`](Self::route) picks one winner deterministically, and the
    /// CALLER must surface the conflict loudly: a duplicate claim is an admin
    /// error the data plane cannot resolve, only expose. Field 2026-08-25: a
    /// stale approval left two routers claiming the same corp `/32`s and
    /// insertion order decided which one carried the traffic — a restart
    /// lottery between a working and a dead egress.
    pub fn set_subnets(&mut self, pubkey: [u8; 32], cidrs: &[Cidr]) -> Vec<(Cidr, [u8; 32])> {
        self.subnets.retain(|(_, pk)| *pk != pubkey);
        let conflicts: Vec<(Cidr, [u8; 32])> = self
            .subnets
            .iter()
            .filter(|(c, _)| cidrs.contains(c))
            .map(|(c, pk)| (*c, *pk))
            .collect();
        self.subnets.extend(cidrs.iter().map(|c| (*c, pubkey)));
        conflicts
    }

    /// P5 exit-node (S3b) — set (or clear) the peer that carries this node's
    /// global IPv6 egress. `None` restores the fail-closed drop of global v6.
    pub fn set_v6_exit(&mut self, pubkey: Option<[u8; 32]>) {
        self.v6_exit = pubkey;
    }

    /// The current global-v6 exit peer's pubkey, if any.
    pub fn v6_exit(&self) -> Option<[u8; 32]> {
        self.v6_exit
    }

    /// The subnet routes `pubkey` holds right now — what [`set_subnets`]
    /// last left for it (`remove`/a re-install may have cleared them).
    ///
    /// [`set_subnets`]: Self::set_subnets
    pub fn subnets_of(&self, pubkey: &[u8; 32]) -> Vec<Cidr> {
        self.subnets
            .iter()
            .filter(|(_, pk)| pk == pubkey)
            .map(|(c, _)| *c)
            .collect()
    }

    /// Drop EVERY route owned by `pubkey` — its `/32` host route(s) AND its
    /// subnet routes. `true` if anything was removed.
    ///
    /// Keyed by PUBKEY, never by IP. Overlay addresses are RECYCLED: the server
    /// returns a removed device's host number to the tenant's pool, so by the
    /// time a stale peer is reaped `by_ip[its_ip]` may already point at the
    /// address's NEW owner. Removing by IP then deleted the LIVE peer's host
    /// route — and, because the old code fed the *returned* pubkey to
    /// `subnets.retain`, the live peer's subnet routes with it — blackholing
    /// that address with no self-heal until the process restarted.
    pub fn remove_by_pubkey(&mut self, pubkey: &[u8; 32]) -> bool {
        let before = self.by_ip.len() + self.subnets.len();
        self.by_ip.retain(|_, pk| pk != pubkey);
        self.subnets.retain(|(_, pk)| pk != pubkey);
        before != self.by_ip.len() + self.subnets.len()
    }

    /// Which peer owns the overlay destination `ip`? Exact `/32` first, else the
    /// longest-prefix subnet route that contains it.
    ///
    /// Equal-prefix ties (two routers claiming the SAME prefix — see
    /// [`set_subnets`](Self::set_subnets)) break on the pubkey, so the winner
    /// is a function of the claims alone. It used to be positional (last
    /// `set_subnets` won), which made the winner depend on peer-establish
    /// order: every restart re-rolled which claimant carried the traffic AND
    /// which one's replies [`rpf_check`](Self::rpf_check) denied (field
    /// 2026-08-25, the `rx_denied` climb on the honest router). The choice
    /// stays arbitrary — only the ADMIN can resolve a duplicate claim — but it
    /// no longer flaps.
    pub fn route(&self, ip: &Ipv4Addr) -> Option<[u8; 32]> {
        if let Some(pk) = self.by_ip.get(ip) {
            return Some(*pk);
        }
        self.subnets
            .iter()
            .filter(|(c, _)| c.contains(*ip))
            .max_by_key(|(c, pk)| (c.prefix, *pk))
            .map(|(_, pk)| *pk)
    }

    /// P4 — **reverse-path check**: may the peer `from` originate a packet whose
    /// SOURCE address is `src`?
    ///
    /// This is the ingress half of cryptokey routing, and until P4 it simply
    /// did not exist: [`route`](Self::route) was consulted only on EGRESS
    /// (`WgSender::send_ip_packet`), so any peer holding a live WireGuard
    /// session could write a packet with ANY source and ANY destination
    /// straight into this node's TUN. Real WireGuard treats `allowed_ips` as
    /// bidirectional — an inbound packet whose source isn't in the sending
    /// peer's allowed range is dropped — and this restores that semantic on
    /// the same table, so a peer's authority to SEND AS an address is exactly
    /// its authority to RECEIVE for it. No new state, and a subnet router or
    /// exit node stays legitimate for its whole approved range for free.
    ///
    /// The address is boringtun's own `WriteToTunnelV4`/`V6` source field
    /// (already length-validated against the IP header), never re-parsed here.
    ///
    /// * v4, or a derived-ULA v6 (unmapped to its embedded v4) → must resolve
    ///   through the v4 table to `from` — its `/32`, or any subnet/exit CIDR it
    ///   advertised (an exit peer carries the split-default `/1`s, so internet
    ///   return traffic passes without a special case).
    /// * any other v6 → only this node's v6 exit may originate it; with no exit
    ///   configured that's nobody, mirroring the fail-closed drop
    ///   [`WgSender::send_ip_packet`] already applies to global v6 on egress.
    pub fn rpf_check(&self, from: &[u8; 32], src: IpAddr) -> RpfVerdict {
        let v4 = match src {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => embedded_v4_of_overlay_v6(v6),
        };
        if let Some(v4) = v4 {
            return match self.route(&v4) {
                Some(pk) if pk == *from => RpfVerdict::Allow,
                Some(_) => RpfVerdict::Deny(RpfDeny::OtherPeer),
                None => RpfVerdict::Deny(RpfDeny::NoRoute),
            };
        }
        match self.v6_exit {
            Some(pk) if pk == *from => RpfVerdict::Allow,
            _ => RpfVerdict::Deny(RpfDeny::NonOverlayV6),
        }
    }

    /// The **v4 routing key** for a raw IP packet's destination, or `None` if
    /// it is unroutable. The TUN/netstack bridge hands raw IP packets here to
    /// pick a peer:
    /// * IPv4 → the dst field (bytes 16..20).
    /// * IPv6 → the dst field (bytes 24..40 of the fixed header) **unmapped**
    ///   to its embedded v4 iff it is a derived-ULA address
    ///   ([`embedded_v4_of_overlay_v6`]) — so v6 routes on the same v4 table.
    ///   Any other v6 (link-local/multicast OS noise, internet v6) → `None`.
    pub fn dst_of_ip_packet(packet: &[u8]) -> Option<Ipv4Addr> {
        match packet.first()? >> 4 {
            4 if packet.len() >= 20 => Some(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
            6 if packet.len() >= 40 => {
                let dst: [u8; 16] = packet[24..40].try_into().ok()?;
                embedded_v4_of_overlay_v6(Ipv6Addr::from(dst))
            }
            _ => None,
        }
    }

    /// P5 exit-node (S3b) — the GLOBAL-UNICAST IPv6 destination of a raw IP
    /// packet, or `None` if it isn't one. "Global unicast" = `2000::/3`
    /// (`seg0 & 0xe000 == 0x2000`), which by construction EXCLUDES our overlay
    /// ULA (`fc00::/7`), any other ULA, link-local (`fe80::/10`), multicast
    /// (`ff00::/8`), loopback, unspecified, and v4-mapped (`::ffff:0:0/96`). Only
    /// such a global dst is routed to the [`v6_exit`](Self::v6_exit) peer; every
    /// other non-overlay v6 is dropped fail-closed by the caller. Overlay-internal
    /// (derived-ULA) v6 never reaches here — [`dst_of_ip_packet`](Self::dst_of_ip_packet)
    /// resolves it to v4 first. Pure, so the classification is unit-tested directly.
    pub fn is_global_v6_dst(packet: &[u8]) -> Option<Ipv6Addr> {
        if packet.first()? >> 4 != 6 || packet.len() < 40 {
            return None;
        }
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
        // 2000::/3 — the IANA global-unicast range.
        (dst.segments()[0] & 0xe000 == 0x2000).then_some(dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_round_trips() {
        let mut r = Router::new();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let key = [9u8; 32];
        assert_eq!(
            r.upsert(ip, key),
            None,
            "nothing displaced on a fresh insert"
        );
        assert_eq!(r.route(&ip), Some(key));
        assert_eq!(r.route(&Ipv4Addr::new(100, 64, 0, 8)), None);
        assert!(r.remove_by_pubkey(&key));
        assert_eq!(r.route(&ip), None);
        assert!(!r.remove_by_pubkey(&key), "second removal is a no-op");
    }

    /// Overlay addresses are recycled between machines, so reaping a stale peer
    /// must not touch the routes the address's NEW owner installed. Removing by
    /// IP used to delete both the live peer's `/32` AND its subnets.
    #[test]
    fn remove_by_pubkey_leaves_a_recycled_ip_with_its_new_owner() {
        let (old, new) = ([1u8; 32], [2u8; 32]);
        let ip = Ipv4Addr::new(100, 64, 0, 5);
        let mut r = Router::new();
        r.upsert(ip, old);
        r.set_subnets(old, &[Cidr::parse("192.168.7.0/24").unwrap()]);

        // The server released `ip` and handed it to a different machine.
        assert_eq!(
            r.upsert(ip, new),
            Some(old),
            "a reassignment surfaces the displaced peer"
        );
        r.set_subnets(new, &[Cidr::parse("10.9.0.0/16").unwrap()]);

        // …and only NOW is the stale peer reaped.
        assert!(r.remove_by_pubkey(&old));
        assert_eq!(r.route(&ip), Some(new), "the live peer keeps its /32");
        assert_eq!(
            r.route(&Ipv4Addr::new(10, 9, 1, 1)),
            Some(new),
            "…and its subnets"
        );
        assert_eq!(
            r.route(&Ipv4Addr::new(192, 168, 7, 1)),
            None,
            "the stale peer's subnets are gone"
        );
    }

    #[test]
    fn subnet_routes_longest_prefix_and_removal() {
        let mut r = Router::new();
        let gw = [1u8; 32];
        let other = [2u8; 32];
        r.upsert(Ipv4Addr::new(100, 64, 0, 1), gw); // gw's own /32
        r.upsert(Ipv4Addr::new(100, 64, 0, 2), other);
        r.set_subnets(gw, &[Cidr::parse("192.168.0.0/16").unwrap()]);
        r.set_subnets(other, &[Cidr::parse("192.168.1.0/24").unwrap()]);

        // Exact host route wins.
        assert_eq!(r.route(&Ipv4Addr::new(100, 64, 0, 1)), Some(gw));
        // /16 catches 192.168.2.5.
        assert_eq!(r.route(&Ipv4Addr::new(192, 168, 2, 5)), Some(gw));
        // Longest-prefix: 192.168.1.9 → other (/24 beats /16).
        assert_eq!(r.route(&Ipv4Addr::new(192, 168, 1, 9)), Some(other));
        // Unknown → None.
        assert_eq!(r.route(&Ipv4Addr::new(10, 0, 0, 1)), None);

        // Removing gw also drops its /16; other's /24 survives.
        assert!(r.remove_by_pubkey(&gw));
        assert_eq!(r.route(&Ipv4Addr::new(192, 168, 2, 5)), None);
        assert_eq!(r.route(&Ipv4Addr::new(192, 168, 1, 9)), Some(other));
    }

    /// Two routers approved for the SAME prefix (field 2026-08-25: a stale
    /// approval left both the old and the new CORP1 router claiming the corp
    /// `/32`s). The winner must be a function of the claims, not of which peer
    /// happened to establish last — and the duplicate must be REPORTED so the
    /// caller can log it.
    #[test]
    fn duplicate_subnet_claim_is_reported_and_tie_breaks_deterministically() {
        let (lo, hi) = ([1u8; 32], [2u8; 32]);
        let c = Cidr::parse("10.66.51.147/32").unwrap();
        let dst = Ipv4Addr::new(10, 66, 51, 147);

        // Same claims, both insertion orders → same winner (higher pubkey).
        let mut a = Router::new();
        assert_eq!(a.set_subnets(lo, &[c]), vec![], "first claim is clean");
        assert_eq!(
            a.set_subnets(hi, &[c]),
            vec![(c, lo)],
            "the second claimant is told who it collides with"
        );
        let mut b = Router::new();
        b.set_subnets(hi, &[c]);
        assert_eq!(b.set_subnets(lo, &[c]), vec![(c, hi)]);
        assert_eq!(a.route(&dst), Some(hi));
        assert_eq!(
            b.route(&dst),
            Some(hi),
            "insertion order must not pick the winner"
        );

        // Re-setting a peer's OWN claims is not a conflict…
        assert_eq!(a.set_subnets(hi, &[c]), vec![(c, lo)]);
        let mut solo = Router::new();
        solo.set_subnets(hi, &[c]);
        assert_eq!(solo.set_subnets(hi, &[c]), vec![], "self re-set is clean");

        // …a DIFFERENT prefix is not a conflict…
        assert_eq!(
            a.set_subnets([3u8; 32], &[Cidr::parse("10.66.51.0/24").unwrap()]),
            vec![],
            "overlap without equality routes by longest-prefix, no conflict"
        );

        // …and removing the winner hands the CIDR to the surviving claimant.
        assert!(a.remove_by_pubkey(&hi));
        assert_eq!(a.route(&dst), Some(lo), "the loser takes over on removal");
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(Ipv4Addr::new(10, 5, 6, 7)));
        assert!(!c.contains(Ipv4Addr::new(11, 0, 0, 1)));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert!(Cidr::parse("bad").is_none());
        assert!(Cidr::parse("1.2.3.4/33").is_none());
    }

    #[test]
    fn is_default_route_catches_default_and_split_halves() {
        // The /0 default and both split-default /1 halves.
        assert!(Cidr::parse("0.0.0.0/0").unwrap().is_default_route());
        assert!(Cidr::parse("0.0.0.0/1").unwrap().is_default_route());
        assert!(Cidr::parse("128.0.0.0/1").unwrap().is_default_route());
        // Host bits in the input still canonicalize to a /1 half.
        assert!(Cidr::parse("200.1.2.3/1").unwrap().is_default_route());
        // Real LAN subnets are NOT default routes.
        assert!(!Cidr::parse("192.168.1.0/24").unwrap().is_default_route());
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().is_default_route());
        assert!(!Cidr::parse("0.0.0.0/2").unwrap().is_default_route());
    }

    #[test]
    fn dst_of_ip_packet_reads_v4_header() {
        // Minimal IPv4 header: version/IHL=0x45, then 12 bytes, then
        // src (4) at offset 12, dst (4) at offset 16.
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[16..20].copy_from_slice(&[100, 64, 0, 9]);
        assert_eq!(
            Router::dst_of_ip_packet(&pkt),
            Some(Ipv4Addr::new(100, 64, 0, 9))
        );
        // Short / empty buffers reject.
        assert_eq!(Router::dst_of_ip_packet(&[0u8; 10]), None);
        assert_eq!(Router::dst_of_ip_packet(&[]), None);
        // A version nibble that is neither 4 nor 6 rejects.
        let mut junk = [0u8; 40];
        junk[0] = 0x50;
        assert_eq!(Router::dst_of_ip_packet(&junk), None);
    }

    #[test]
    fn derive_and_unmap_overlay_v6_round_trip() {
        let v4 = Ipv4Addr::new(100, 64, 3, 129);
        let v6 = derive_overlay_v6(v4);
        // The textual form pins the ULA scheme (fd72:6f6f:6d6c::/96).
        assert_eq!(v6.to_string(), "fd72:6f6f:6d6c::6440:381");
        assert_eq!(embedded_v4_of_overlay_v6(v6), Some(v4));
        // Outside the ULA → not an overlay v6.
        assert_eq!(embedded_v4_of_overlay_v6("fe80::1".parse().unwrap()), None);
        assert_eq!(
            embedded_v4_of_overlay_v6("fd00::6440:381".parse().unwrap()),
            None
        );
    }

    #[test]
    fn dst_of_ip_packet_unmaps_derived_v6_and_drops_other_v6() {
        let v4 = Ipv4Addr::new(100, 64, 0, 9);
        // Minimal IPv6 fixed header: version nibble 6; dst at bytes 24..40.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60;
        pkt[24..40].copy_from_slice(&derive_overlay_v6(v4).octets());
        assert_eq!(Router::dst_of_ip_packet(&pkt), Some(v4));

        // A non-ULA v6 destination (OS link-local noise) is unroutable.
        let mut ll = [0u8; 40];
        ll[0] = 0x60;
        ll[24..40].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(Router::dst_of_ip_packet(&ll), None);

        // A truncated v6 header rejects.
        assert_eq!(Router::dst_of_ip_packet(&[0x60; 39]), None);
    }

    #[test]
    fn is_global_v6_dst_only_matches_global_unicast() {
        fn v6_pkt(dst: &str) -> [u8; 40] {
            let mut p = [0u8; 40];
            p[0] = 0x60;
            p[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
            p
        }
        // Global unicast 2000::/3 → routed to the exit.
        assert!(Router::is_global_v6_dst(&v6_pkt("2606:4700::1111")).is_some());
        assert!(Router::is_global_v6_dst(&v6_pkt("2001:db8::1")).is_some());
        assert!(Router::is_global_v6_dst(&v6_pkt("2002::1")).is_some()); // 6to4
        // Overlay ULA, other ULA, link-local, multicast, loopback → dropped
        // fail-closed (NOT sent to the exit).
        assert!(Router::is_global_v6_dst(&v6_pkt("fd72:6f6f:6d6c::6440:1")).is_none());
        assert!(Router::is_global_v6_dst(&v6_pkt("fd00::1")).is_none());
        assert!(Router::is_global_v6_dst(&v6_pkt("fe80::1")).is_none());
        assert!(Router::is_global_v6_dst(&v6_pkt("ff02::1")).is_none());
        assert!(Router::is_global_v6_dst(&v6_pkt("::1")).is_none());
        // A v4 packet, or a truncated v6 header → None.
        let mut v4 = [0u8; 40];
        v4[0] = 0x45;
        assert!(Router::is_global_v6_dst(&v4).is_none());
        assert!(Router::is_global_v6_dst(&[0x60u8; 39]).is_none());
    }

    #[test]
    fn v6_exit_set_and_clear() {
        let mut r = Router::new();
        assert!(r.v6_exit().is_none());
        r.set_v6_exit(Some([7u8; 32]));
        assert_eq!(r.v6_exit(), Some([7u8; 32]));
        r.set_v6_exit(None);
        assert!(r.v6_exit().is_none());
    }

    // -----------------------------------------------------------------------
    // P4 — reverse-path filtering
    // -----------------------------------------------------------------------

    const PEER_A: [u8; 32] = [0xaa; 32];
    const PEER_B: [u8; 32] = [0xbb; 32];

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn rpf_allows_a_peer_its_own_host_route() {
        let mut r = Router::new();
        r.upsert(Ipv4Addr::new(100, 64, 0, 7), PEER_A);
        assert_eq!(r.rpf_check(&PEER_A, v4("100.64.0.7")), RpfVerdict::Allow);
    }

    #[test]
    fn rpf_denies_a_peer_forging_a_siblings_address() {
        let mut r = Router::new();
        r.upsert(Ipv4Addr::new(100, 64, 0, 7), PEER_A);
        r.upsert(Ipv4Addr::new(100, 64, 0, 8), PEER_B);
        // B claims A's overlay IP — the spoofing case the filter exists for.
        assert_eq!(
            r.rpf_check(&PEER_B, v4("100.64.0.7")),
            RpfVerdict::Deny(RpfDeny::OtherPeer)
        );
    }

    #[test]
    fn rpf_denies_an_address_no_peer_owns() {
        let r = Router::new();
        assert_eq!(
            r.rpf_check(&PEER_A, v4("10.66.51.147")),
            RpfVerdict::Deny(RpfDeny::NoRoute)
        );
    }

    #[test]
    fn rpf_allows_a_subnet_router_its_whole_advertised_range() {
        // The CORP3/CORP1 shape: a router peer forwards replies FROM hosts inside
        // the LAN it advertised, so every such source must pass on its behalf.
        let mut r = Router::new();
        r.upsert(Ipv4Addr::new(100, 64, 0, 30), PEER_A);
        r.set_subnets(PEER_A, &[Cidr::parse("10.66.0.0/16").unwrap()]);
        assert_eq!(r.rpf_check(&PEER_A, v4("10.66.51.147")), RpfVerdict::Allow);
        // …but only that peer: a sibling can't source the same LAN.
        assert_eq!(
            r.rpf_check(&PEER_B, v4("10.66.51.147")),
            RpfVerdict::Deny(RpfDeny::OtherPeer)
        );
        // …and only within the range it actually advertised.
        assert_eq!(
            r.rpf_check(&PEER_A, v4("10.67.0.1")),
            RpfVerdict::Deny(RpfDeny::NoRoute)
        );
    }

    #[test]
    fn rpf_allows_exit_node_internet_return_traffic() {
        // P5 exit clients install the split-default `/1`s as the exit peer's
        // allowed_ips, so arbitrary internet sources legitimately arrive from
        // it. Without this the filter would blackhole every exit-node client.
        let mut r = Router::new();
        r.upsert(Ipv4Addr::new(100, 64, 0, 2), PEER_A);
        r.set_subnets(
            PEER_A,
            &[
                Cidr::parse("0.0.0.0/1").unwrap(),
                Cidr::parse("128.0.0.0/1").unwrap(),
            ],
        );
        assert_eq!(r.rpf_check(&PEER_A, v4("1.1.1.1")), RpfVerdict::Allow);
        assert_eq!(r.rpf_check(&PEER_A, v4("203.0.113.9")), RpfVerdict::Allow);
    }

    #[test]
    fn rpf_unmaps_derived_ula_v6_onto_the_v4_table() {
        let mut r = Router::new();
        r.upsert(Ipv4Addr::new(100, 64, 0, 7), PEER_A);
        // fd72:6f6f:6d6c::6440:7 == 100.64.0.7 embedded.
        assert_eq!(
            r.rpf_check(&PEER_A, v6("fd72:6f6f:6d6c::6440:7")),
            RpfVerdict::Allow
        );
        assert_eq!(
            r.rpf_check(&PEER_B, v6("fd72:6f6f:6d6c::6440:7")),
            RpfVerdict::Deny(RpfDeny::OtherPeer)
        );
    }

    #[test]
    fn rpf_non_overlay_v6_only_from_the_v6_exit() {
        let mut r = Router::new();
        r.upsert(Ipv4Addr::new(100, 64, 0, 2), PEER_A);
        // No exit configured → fail-closed, mirroring egress.
        assert_eq!(
            r.rpf_check(&PEER_A, v6("2606:4700::1111")),
            RpfVerdict::Deny(RpfDeny::NonOverlayV6)
        );
        r.set_v6_exit(Some(PEER_A));
        assert_eq!(
            r.rpf_check(&PEER_A, v6("2606:4700::1111")),
            RpfVerdict::Allow
        );
        // …and still nobody else.
        assert_eq!(
            r.rpf_check(&PEER_B, v6("2606:4700::1111")),
            RpfVerdict::Deny(RpfDeny::NonOverlayV6)
        );
        // Link-local / multicast OS noise is not overlay traffic either.
        assert_eq!(
            r.rpf_check(&PEER_B, v6("fe80::1")),
            RpfVerdict::Deny(RpfDeny::NonOverlayV6)
        );
    }

    // -----------------------------------------------------------------------
    // P4 — local destination scope
    // -----------------------------------------------------------------------

    fn ip4(s: &str) -> Option<Ipv4Addr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn scope_of_a_leaf_node_accepts_only_traffic_to_itself() {
        let s = LocalScope::new(ip4("100.64.0.7"), &[]);
        assert!(s.permits_dst(ip4("100.64.0.7")));
        // Transit toward another peer is not this node's business.
        assert!(!s.permits_dst(ip4("100.64.0.8")));
        // The hole this closes: a LAN address a leaf node never advertised.
        assert!(!s.permits_dst(ip4("10.66.51.147")));
        assert!(!s.is_unconstrained());
    }

    #[test]
    fn scope_of_a_subnet_router_accepts_exactly_what_it_advertises() {
        let s = LocalScope::new(ip4("100.64.0.30"), &["10.66.0.0/16".to_string()]);
        assert!(s.permits_dst(ip4("100.64.0.30")));
        assert!(s.permits_dst(ip4("10.66.51.147")));
        // One octet outside the advertised range — previously forwarded by the
        // OS if it had any route for it.
        assert!(!s.permits_dst(ip4("10.67.0.1")));
        assert!(!s.permits_dst(ip4("10.84.6.5")));
    }

    #[test]
    fn scope_unmaps_derived_ula_v6_and_rejects_other_v6() {
        let s = LocalScope::new(ip4("100.64.0.7"), &[]);
        // dst_of_ip_packet already unmaps a derived ULA to its v4.
        assert!(s.permits_dst(embedded_v4_of_overlay_v6(
            "fd72:6f6f:6d6c::6440:7".parse().unwrap()
        )));
        // A non-overlay v6 arrives as None and is fail-closed.
        assert!(!s.permits_dst(None));
    }

    #[test]
    fn an_exit_node_scope_is_unconstrained() {
        // A default route means this node legitimately carries the whole
        // internet; enforcing a scope would blackhole every exit client.
        let s = LocalScope::new(ip4("100.64.0.2"), &["0.0.0.0/0".to_string()]);
        assert!(s.is_unconstrained());
        assert!(s.permits_dst(ip4("1.1.1.1")));
        assert!(s.permits_dst(None));
        // The split-default halves count too.
        assert!(
            LocalScope::new(ip4("100.64.0.2"), &["128.0.0.0/1".to_string()]).is_unconstrained()
        );
    }

    #[test]
    fn an_unrepresentable_route_fails_open_rather_than_blackholing() {
        // A v6 prefix can't be expressed by the v4-only Cidr. Refusing to
        // guess is the only safe posture: a too-narrow scope would silently
        // break a legitimate v6 subnet router.
        let s = LocalScope::new(ip4("100.64.0.30"), &["fd00:dead::/48".to_string()]);
        assert!(s.is_unconstrained());
        assert!(s.permits_dst(ip4("10.66.51.147")));
        let s = LocalScope::new(ip4("100.64.0.30"), &["not-a-cidr".to_string()]);
        assert!(s.is_unconstrained());
    }

    #[test]
    fn rpf_mode_parses_every_spelling_and_defaults_to_warn() {
        assert_eq!(RpfMode::parse(Some("off")), RpfMode::Off);
        assert_eq!(RpfMode::parse(Some("0")), RpfMode::Off);
        assert_eq!(RpfMode::parse(Some("FALSE")), RpfMode::Off);
        assert_eq!(RpfMode::parse(Some("enforce")), RpfMode::Enforce);
        assert_eq!(RpfMode::parse(Some(" ON ")), RpfMode::Enforce);
        assert_eq!(RpfMode::parse(Some("1")), RpfMode::Enforce);
        assert_eq!(RpfMode::parse(Some("warn")), RpfMode::Warn);
        // Unset or a typo lands on the safe default — never a silent enforce,
        // never a silent off.
        assert_eq!(RpfMode::parse(None), RpfMode::Warn);
        assert_eq!(RpfMode::parse(Some("maybe")), RpfMode::Warn);
        assert_eq!(RpfMode::default(), RpfMode::Warn);
        assert_eq!(RpfMode::Enforce.as_str(), "enforce");
    }
}
