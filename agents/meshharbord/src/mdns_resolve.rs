// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! mDNS ICE-candidate resolution — the relay-escape root-cause fix.
//!
//! # Why this exists
//!
//! Chrome hides the browser's LAN IPs in ICE host candidates behind mDNS
//! names (`<uuid>.local`) unless the page holds a cam/mic permission — and
//! the remote-control controller page never requests one. The agent's ICE
//! stack (vendored webrtc-ice) defaults to `MulticastDnsMode::QueryOnly`,
//! i.e. it *tries* to resolve those names itself over raw multicast — but
//! that in-process resolver is unreliable on Windows (the native mDNS
//! resolver owns udp/5353, doubly so under the SYSTEM service), so the
//! browser's host candidates were effectively discarded. Direct LAN
//! connectivity then depended entirely on peer-reflexive discovery (the
//! browser's STUN checks arriving at the agent's host candidate) racing the
//! pre-warmed TURN relay pair — and Chrome, as the controlling side,
//! nominates whichever check succeeds first. Field 2026-07-13
//! (DEVBOX hosting, same-LAN viewers): sessions flipped between
//! `Host↔Host` and the Germany TURN relay across reconnects seconds apart,
//! with the relay winning most rolls — 3 Mbps clamp, 30 fps, +100-150 ms
//! mouse RTT.
//!
//! # The fix
//!
//! Resolve the `.local` name via:
//! 1. **Bounded OS-resolver retries** (`getaddrinfo`, via
//!    `tokio::net::lookup_host`, up to `MAX_RESOLVE_ATTEMPTS = 4` attempts of
//!    `ATTEMPT_TIMEOUT = 1500 ms` each). Under RFC 6762 §8.1 a newly registered
//!    `<uuid>.local` record probes for 750 ms (`3 × 250 ms`) before the peer's
//!    mDNS responder answers, and Windows `GetAddrInfoW` sends its third mDNS
//!    burst at ~840–1000 ms (~1100–1300 ms warm reply, up to ~4.8 s cold); a
//!    single 750 ms timeout systematically expired before the post-probing
//!    burst completed.
//! 2. **Parallel per-interface mDNS `A` queries** (`IP_MULTICAST_IF`) on every
//!    eligible non-overlay LAN IPv4 interface. `webrtc-mdns` binds a single
//!    `0.0.0.0:5353` socket without `set_multicast_if_v4`, so on multi-NIC
//!    Windows hosts (Wi-Fi Direct virtual adapters, Hyper-V switches, VPN/TUN
//!    interfaces) its multicast queries can egress exclusively on a virtual
//!    interface and never reach the LAN peer. Binding per-interface sockets
//!    with `set_multicast_if_v4(iface_ip)` guarantees queries egress on each
//!    physical LAN interface without modifying any OS routes or settings.
//!
//! Every attempt is raced against the session's `CancellationToken` so session
//! teardown aborts resolution immediately (preserving #1740), overlay
//! interfaces are never queried, and every resolved IP must pass the session's
//! `ip_filter` (`RcOverlay::keeps_local`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Per-attempt timeout. Must exceed RFC 6762 §8.1's 750 ms probing window plus
/// Windows `GetAddrInfoW`'s ~840–1000 ms third mDNS burst so warm resolutions
/// complete on Attempt 1 (~0.8–1.3 s).
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Maximum bounded attempts (4 × 1.5 s = 6.0 s worst-case for an unresolvable
/// name, covering cold ~4.8 s responder wakeups while remaining strictly
/// bounded and immediately cancelled on session close).
const MAX_RESOLVE_ATTEMPTS: usize = 4;

/// Intra-attempt per-interface query burst offsets (ms) to straddle RFC 6762
/// 750 ms probing and mitigate 802.11 multicast packet loss.
const IFACE_QUERY_BURST_OFFSETS_MS: [u64; 4] = [0, 300, 650, 1000];

const MDNS_PORT: u16 = 5353;
const MDNS_MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Token index of the connection-address in an ICE candidate string:
/// `candidate:<foundation> <component> <transport> <priority> <address>
/// <port> typ <type> ...` (RFC 8839 §5.1 `candidate-attribute`).
const ADDR_TOKEN_IDX: usize = 4;
const PORT_TOKEN_IDX: usize = 5;

/// If `cand` is a `typ host` candidate whose connection-address is an mDNS
/// name (`*.local`), return that name. `None` for every other candidate
/// shape — srflx/relay candidates carry real IPs (their `raddr` may be
/// obfuscated but is irrelevant for pairing), and malformed strings are
/// left for `add_ice_candidate` to reject.
pub fn candidate_mdns_name(cand: &str) -> Option<&str> {
    let mut tokens = cand.split_whitespace();
    let addr = tokens.nth(ADDR_TOKEN_IDX)?;
    tokens.next()?; // port
    if !tokens.next()?.eq_ignore_ascii_case("typ") {
        return None;
    }
    if !tokens.next()?.eq_ignore_ascii_case("host") {
        return None;
    }
    if addr.to_ascii_lowercase().ends_with(".local") {
        Some(addr)
    } else {
        None
    }
}

/// Replace the connection-address token with `new_addr`, preserving every
/// other token. Whitespace is normalised to single spaces — candidate
/// grammar only ever uses single spaces, so this is shape-preserving.
fn rewrite_candidate_address(cand: &str, new_addr: &str) -> String {
    cand.split_whitespace()
        .enumerate()
        .map(|(i, tok)| if i == ADDR_TOKEN_IDX { new_addr } else { tok })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `iface_name` (`ip`) is an eligible non-overlay LAN IPv4 interface
/// for sending direct per-interface mDNS queries.
///
/// Never sends mDNS queries on:
/// - MeshHarbor overlay interfaces (`crate::peer::is_overlay_iface`)
/// - Loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`, incl. Tailscale
///   tunnel link-local), unspecified, broadcast, or multicast addresses
/// - CGNAT / WireGuard / Tailscale range (`100.64.0.0/10`)
/// - Active overlay footprint subnets (`overlay_v4_nets`)
/// - Any address rejected by the session's `keeps_ip` filter
pub fn is_eligible_mdns_query_interface(
    iface_name: &str,
    ip: Ipv4Addr,
    overlay_v4_nets: &[(Ipv4Addr, u8)],
    keeps_ip: impl Fn(IpAddr) -> bool,
) -> bool {
    if crate::peer::is_overlay_iface(iface_name) {
        return false;
    }
    if ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
    {
        return false;
    }
    let oct = ip.octets();
    if oct[0] == 100 && (oct[1] & 0xC0) == 64 {
        return false;
    }
    if tunnel_core::overlay_footprint::is_overlay_addr(overlay_v4_nets, IpAddr::V4(ip)) {
        return false;
    }
    keeps_ip(IpAddr::V4(ip))
}

/// Build an RFC 6762 mDNS `A` query packet for `name` (e.g. `<uuid>.local`).
/// When `unicast_response` is true, sets the `QU` bit (`0x8001`); otherwise
/// sends standard `QM` (`0x0001`).
pub(crate) fn build_mdns_a_query(name: &str, unicast_response: bool) -> Option<Vec<u8>> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let mut pkt = Vec::with_capacity(64);
    // Header: ID=0, Flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        pkt.push(bytes.len() as u8);
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A (1)
    let qclass: u16 = if unicast_response { 0x8001 } else { 0x0001 };
    pkt.extend_from_slice(&qclass.to_be_bytes());
    Some(pkt)
}

fn read_dns_name(pkt: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = 0usize;
    let mut hops = 0usize;

    loop {
        if offset >= pkt.len() || hops > 32 {
            return None;
        }
        hops += 1;
        let len = pkt[offset];
        if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= pkt.len() {
                return None;
            }
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            let ptr = (((len as usize) & 0x3F) << 8) | (pkt[offset + 1] as usize);
            offset = ptr;
            continue;
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        let label_len = len as usize;
        offset += 1;
        if offset + label_len > pkt.len() {
            return None;
        }
        let s = std::str::from_utf8(&pkt[offset..offset + label_len]).ok()?;
        labels.push(s.to_string());
        offset += label_len;
    }

    Some((labels.join("."), end_offset))
}

/// Parse an mDNS response packet and return the first `A` record matching
/// `expected_name` that passes `keeps_ip`.
pub(crate) fn parse_mdns_a_response(
    pkt: &[u8],
    expected_name: &str,
    keeps_ip: impl Fn(IpAddr) -> bool,
) -> Option<Ipv4Addr> {
    if pkt.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    if (flags & 0x8000) == 0 {
        return None; // Must be a DNS response (QR=1)
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let nscount = u16::from_be_bytes([pkt[8], pkt[9]]) as usize;
    let arcount = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;
    let total_rr = ancount.saturating_add(nscount).saturating_add(arcount);
    if total_rr == 0 {
        return None;
    }

    let want = expected_name.trim_end_matches('.');
    let mut offset = 12usize;
    for _ in 0..qdcount {
        let (_, next) = read_dns_name(pkt, offset)?;
        if next + 4 > pkt.len() {
            return None;
        }
        offset = next + 4;
    }

    for _ in 0..total_rr {
        let (rr_name, next) = read_dns_name(pkt, offset)?;
        if next + 10 > pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([pkt[next], pkt[next + 1]]);
        let rclass = u16::from_be_bytes([pkt[next + 2], pkt[next + 3]]) & 0x7FFF;
        let rdlength = u16::from_be_bytes([pkt[next + 8], pkt[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > pkt.len() {
            return None;
        }
        if rtype == 1
            && rclass == 1
            && rdlength == 4
            && rr_name.trim_end_matches('.').eq_ignore_ascii_case(want)
        {
            let ip = Ipv4Addr::new(
                pkt[rdata_start],
                pkt[rdata_start + 1],
                pkt[rdata_start + 2],
                pkt[rdata_start + 3],
            );
            if keeps_ip(IpAddr::V4(ip)) {
                return Some(ip);
            }
        }
        offset = rdata_end;
    }
    None
}

fn bind_mdns_udp_v4(
    bind_ip: Ipv4Addr,
    port: u16,
    multicast_if: Option<Ipv4Addr>,
) -> Option<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    if port != 0 {
        let _ = sock.set_reuse_address(true);
    }
    let _ = sock.set_nonblocking(true);
    let addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    sock.bind(&addr.into()).ok()?;
    if let Some(mif) = multicast_if {
        let _ = sock.set_multicast_if_v4(&mif);
        let _ = sock.set_multicast_loop_v4(true);
    }
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock).ok()
}

async fn lookup_host_filtered(
    name: &str,
    port: &str,
    keeps_ip: &(impl Fn(IpAddr) -> bool + Send + Sync),
) -> Option<IpAddr> {
    loop {
        if let Ok(addrs) = tokio::net::lookup_host(format!("{name}:{port}")).await {
            let mut v4: Option<IpAddr> = None;
            let mut v6: Option<IpAddr> = None;
            for sa in addrs {
                let ip = sa.ip();
                if !keeps_ip(ip) {
                    continue;
                }
                match ip {
                    IpAddr::V4(_) => {
                        let _ = v4.get_or_insert(ip);
                    }
                    IpAddr::V6(_) => {
                        let _ = v6.get_or_insert(ip);
                    }
                }
            }
            if let Some(ip) = v4.or(v6) {
                return Some(ip);
            }
        }
        tokio::time::sleep(Duration::from_millis(350)).await;
    }
}

async fn query_mdns_interfaces_v4(
    name: &str,
    overlay_v4_nets: &[(Ipv4Addr, u8)],
    keeps_ip: impl Fn(IpAddr) -> bool + Clone + Send + Sync + 'static,
) -> Option<(IpAddr, &'static str)> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    let mut eligible_ips = Vec::new();
    for iface in ifaces {
        if let IpAddr::V4(ip) = iface.ip()
            && is_eligible_mdns_query_interface(&iface.name, ip, overlay_v4_nets, &keeps_ip)
            && !eligible_ips.contains(&ip)
        {
            eligible_ips.push(ip);
        }
    }
    if eligible_ips.is_empty() {
        std::future::pending::<()>().await;
        return None;
    }

    let qu_pkt = build_mdns_a_query(name, true)?;
    let qm_pkt = build_mdns_a_query(name, false)?;
    let dst = SocketAddr::V4(SocketAddrV4::new(MDNS_MCAST_V4, MDNS_PORT));

    let mut unicast_socks = Vec::new();
    let mut mcast_send_socks = Vec::new();
    for &ip in &eligible_ips {
        if let Some(s) = bind_mdns_udp_v4(ip, 0, Some(ip)) {
            unicast_socks.push(std::sync::Arc::new(s));
        }
        if let Some(s5353) = bind_mdns_udp_v4(ip, MDNS_PORT, Some(ip)) {
            mcast_send_socks.push(std::sync::Arc::new(s5353));
        }
    }

    let mcast_recv_sock = bind_mdns_udp_v4(Ipv4Addr::UNSPECIFIED, MDNS_PORT, None).map(|s| {
        for &ip in &eligible_ips {
            let _ = s.join_multicast_v4(MDNS_MCAST_V4, ip);
        }
        std::sync::Arc::new(s)
    });

    if unicast_socks.is_empty() && mcast_send_socks.is_empty() {
        std::future::pending::<()>().await;
        return None;
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(IpAddr, &'static str)>();
    let mut recv_tasks = Vec::new();

    for s in &unicast_socks {
        let s = std::sync::Arc::clone(s);
        let tx = tx.clone();
        let name_owned = name.to_string();
        let keep = keeps_ip.clone();
        recv_tasks.push(tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, _)) = s.recv_from(&mut buf).await {
                if let Some(ip) = parse_mdns_a_response(&buf[..n], &name_owned, &keep) {
                    let _ = tx.send((IpAddr::V4(ip), "if_mdns_unicast"));
                    break;
                }
            }
        }));
    }

    if let Some(s) = mcast_recv_sock {
        let tx = tx.clone();
        let name_owned = name.to_string();
        let keep = keeps_ip.clone();
        recv_tasks.push(tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, _)) = s.recv_from(&mut buf).await {
                if let Some(ip) = parse_mdns_a_response(&buf[..n], &name_owned, &keep) {
                    let _ = tx.send((IpAddr::V4(ip), "if_mdns_mcast"));
                    break;
                }
            }
        }));
    }
    drop(tx);

    let send_loop = async {
        let mut prev_ms = 0u64;
        for &offset_ms in &IFACE_QUERY_BURST_OFFSETS_MS {
            let wait_ms = offset_ms.saturating_sub(prev_ms);
            if wait_ms > 0 {
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            }
            prev_ms = offset_ms;
            for s in &unicast_socks {
                let _ = s.send_to(&qu_pkt, dst).await;
                if mcast_send_socks.is_empty() {
                    let _ = s.send_to(&qm_pkt, dst).await;
                }
            }
            for s in &mcast_send_socks {
                let _ = s.send_to(&qm_pkt, dst).await;
            }
        }
        std::future::pending::<()>().await;
    };

    let result = tokio::select! {
        res = rx.recv() => res,
        _ = send_loop => None,
    };

    for t in recv_tasks {
        t.abort();
    }
    result
}

async fn resolve_once(
    name: &str,
    port: &str,
    overlay_v4_nets: &[(Ipv4Addr, u8)],
    keeps_ip: impl Fn(IpAddr) -> bool + Clone + Send + Sync + 'static,
) -> Option<(IpAddr, &'static str)> {
    let keep_os = keeps_ip.clone();
    tokio::select! {
        Some(ip) = lookup_host_filtered(name, port, &keep_os) => Some((ip, "os_resolver")),
        Some(res) = query_mdns_interfaces_v4(name, overlay_v4_nets, keeps_ip) => Some(res),
    }
}

/// Resolve the mDNS name in a `typ host` candidate with bounded retries and
/// parallel per-interface mDNS `A` queries on eligible non-overlay LAN
/// interfaces, aborting immediately when `cancel` is triggered.
pub async fn resolve_mdns_candidate_with_policy(
    cand: &str,
    cancel: &CancellationToken,
    overlay_v4_nets: &[(Ipv4Addr, u8)],
    keeps_ip: impl Fn(IpAddr) -> bool + Clone + Send + Sync + 'static,
) -> Option<String> {
    let name = candidate_mdns_name(cand)?.to_string();
    let port = cand.split_whitespace().nth(PORT_TOKEN_IDX)?.to_string();
    let started = std::time::Instant::now();

    for attempt in 1..=MAX_RESOLVE_ATTEMPTS {
        let keep = keeps_ip.clone();
        let attempt_res = tokio::select! {
            biased;
            _ = cancel.cancelled() => return None,
            res = tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                resolve_once(&name, &port, overlay_v4_nets, keep),
            ) => res,
        };

        if let Ok(Some((ip, source))) = attempt_res {
            tracing::info!(
                mdns_name = %name,
                resolved = %ip,
                attempt,
                source,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "mDNS host candidate resolved via OS resolver (relay-escape)"
            );
            return Some(rewrite_candidate_address(cand, &ip.to_string()));
        }
    }
    None
}

/// Resolve the mDNS name in a `typ host` candidate via the OS resolver and
/// per-interface mDNS queries, returning the rewritten candidate.
pub async fn resolve_mdns_candidate(cand: &str) -> Option<String> {
    let cancel = CancellationToken::new();
    resolve_mdns_candidate_with_policy(cand, &cancel, &[], |_| true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDNS_HOST: &str = "candidate:842163049 1 udp 1677729535 4e8b9a2c-1f3d-4c5e-9a7b-2d6f8e0c1a3b.local 54321 typ host generation 0 ufrag Xy4z network-cost 999";
    const PLAIN_HOST: &str =
        "candidate:842163049 1 udp 1677729535 192.168.68.110 54321 typ host generation 0";
    const SRFLX: &str = "candidate:1234 1 udp 1685987071 94.130.141.98 61000 typ srflx raddr 0.0.0.0 rport 0 generation 0";

    #[test]
    fn detects_mdns_host_candidate() {
        assert_eq!(
            candidate_mdns_name(MDNS_HOST),
            Some("4e8b9a2c-1f3d-4c5e-9a7b-2d6f8e0c1a3b.local")
        );
    }

    #[test]
    fn plain_ip_host_candidate_is_not_mdns() {
        assert_eq!(candidate_mdns_name(PLAIN_HOST), None);
    }

    #[test]
    fn srflx_candidate_is_never_mdns_even_with_local_raddr() {
        // srflx carries a real IP in the address slot; only `typ host`
        // qualifies. (An srflx with a `.local` raddr must NOT match.)
        assert_eq!(candidate_mdns_name(SRFLX), None);
        let srflx_local_raddr =
            "candidate:1 1 udp 1685987071 94.130.141.98 61000 typ srflx raddr aaaa.local rport 0";
        assert_eq!(candidate_mdns_name(srflx_local_raddr), None);
    }

    #[test]
    fn malformed_candidates_are_ignored_without_panic() {
        for c in ["", "candidate:1 1 udp", "gibberish", "a b c d e f g"] {
            assert_eq!(candidate_mdns_name(c), None, "input: {c:?}");
        }
    }

    #[test]
    fn rewrite_replaces_only_the_address_token() {
        let out = rewrite_candidate_address(MDNS_HOST, "192.168.68.104");
        assert_eq!(
            out,
            "candidate:842163049 1 udp 1677729535 192.168.68.104 54321 typ host generation 0 ufrag Xy4z network-cost 999"
        );
        // Every other token preserved verbatim, incl. trailing attrs.
        assert!(out.contains("ufrag Xy4z"));
        assert!(out.ends_with("network-cost 999"));
    }

    #[tokio::test]
    async fn resolve_passes_through_non_mdns_and_unresolvable() {
        // Non-mDNS candidate → None fast (no lookup at all). Deterministic.
        assert_eq!(resolve_mdns_candidate(PLAIN_HOST).await, None);
        // An mDNS name that shouldn't exist → normally resolver
        // error/timeout → None. Some corporate/CI resolvers answer
        // anything, so don't assert None hard — assert the bounded
        // no-panic contract, and IF an answer came back, that the rewrite
        // put a parseable IP in the address slot.
        let unresolvable = "candidate:1 1 udp 1677729535 00000000-dead-beef-0000-000000000000.local 54321 typ host";
        if let Some(rewritten) = resolve_mdns_candidate(unresolvable).await {
            let addr = rewritten.split_whitespace().nth(ADDR_TOKEN_IDX).unwrap();
            assert!(
                addr.parse::<IpAddr>().is_ok(),
                "rewrite must place an IP literal, got {addr:?}"
            );
        }
    }

    #[test]
    fn eligible_mdns_interface_excludes_overlay_loopback_linklocal_cgnat_and_ip_filter() {
        let overlay_nets = vec![(Ipv4Addr::new(100, 64, 0, 0), 10)];
        // Physical Wi-Fi LAN IP passes
        assert!(is_eligible_mdns_query_interface(
            "Wi-Fi",
            Ipv4Addr::new(192, 168, 1, 253),
            &overlay_nets,
            |_| true,
        ));
        // MeshHarbor overlay interface names are excluded even with a private IP
        assert!(!is_eligible_mdns_query_interface(
            "meshharbor",
            Ipv4Addr::new(192, 168, 1, 253),
            &overlay_nets,
            |_| true,
        ));
        assert!(!is_eligible_mdns_query_interface(
            "meshharbor-corp",
            Ipv4Addr::new(192, 168, 1, 253),
            &overlay_nets,
            |_| true,
        ));
        // Loopback, link-local (Tailscale 169.254.0.107), and CGNAT (100.64.0.0/10) are excluded
        assert!(!is_eligible_mdns_query_interface(
            "lo",
            Ipv4Addr::new(127, 0, 0, 1),
            &overlay_nets,
            |_| true,
        ));
        assert!(!is_eligible_mdns_query_interface(
            "Tailscale",
            Ipv4Addr::new(169, 254, 0, 107),
            &overlay_nets,
            |_| true,
        ));
        assert!(!is_eligible_mdns_query_interface(
            "utun4",
            Ipv4Addr::new(100, 65, 4, 34),
            &overlay_nets,
            |_| true,
        ));
        // Rejected by session ip_filter
        assert!(!is_eligible_mdns_query_interface(
            "Wi-Fi",
            Ipv4Addr::new(192, 168, 1, 253),
            &overlay_nets,
            |_| false,
        ));
    }

    #[test]
    fn dns_a_query_and_response_parser_round_trip_and_ip_filter() {
        let name = "4e8b9a2c-1f3d-4c5e-9a7b-2d6f8e0c1a3b.local";
        let q_qu = build_mdns_a_query(name, true).expect("valid query");
        let q_qm = build_mdns_a_query(name, false).expect("valid query");
        assert_eq!(&q_qu[q_qu.len() - 2..], &[0x80, 0x01]);
        assert_eq!(&q_qm[q_qm.len() - 2..], &[0x00, 0x01]);

        // Build a synthetic mDNS response with 2 A records:
        // Record 1: 100.64.0.9 (overlay IP)
        // Record 2: 192.168.1.42 (LAN IP, using DNS name pointer 0xC00C)
        let mut resp = Vec::new();
        // Header: ID=0, Flags=0x8400 (QR=1, AA=1), QDCOUNT=0, ANCOUNT=2, NSCOUNT=0, ARCOUNT=0
        resp.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 2, 0, 0, 0, 0]);
        // Answer 1: full name at offset 12 (0x000C)
        for label in name.split('.') {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&0x8001u16.to_be_bytes()); // CLASS IN + cache-flush
        resp.extend_from_slice(&120u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&[100, 64, 0, 9]);

        // Answer 2: compressed pointer 0xC00C -> 192.168.1.42
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&0x8001u16.to_be_bytes()); // CLASS IN + cache-flush
        resp.extend_from_slice(&120u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&[192, 168, 1, 42]);

        // Unfiltered takes first record (100.64.0.9)
        assert_eq!(
            parse_mdns_a_response(&resp, name, |_| true),
            Some(Ipv4Addr::new(100, 64, 0, 9))
        );
        // With overlay ip_filter rejecting 100.64.0.9, skips to 192.168.1.42
        assert_eq!(
            parse_mdns_a_response(&resp, name, |ip| ip
                != IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))),
            Some(Ipv4Addr::new(192, 168, 1, 42))
        );
        // Rejecting all returns None
        assert_eq!(parse_mdns_a_response(&resp, name, |_| false), None);
    }

    #[tokio::test]
    async fn session_cancellation_aborts_resolution_immediately() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });
        let started = std::time::Instant::now();
        let unresolvable = "candidate:1 1 udp 1677729535 00000000-dead-beef-0000-000000000000.local 54321 typ host";
        let res = resolve_mdns_candidate_with_policy(unresolvable, &cancel, &[], |_| true).await;
        assert_eq!(res, None);
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "cancellation must abort immediately, took {:?}",
            started.elapsed()
        );
    }
}
