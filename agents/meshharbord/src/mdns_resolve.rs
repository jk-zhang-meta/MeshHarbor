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
//! Resolve the `.local` name via the **OS resolver** (`getaddrinfo`, via
//! `tokio::net::lookup_host`) and rewrite the candidate's
//! connection-address before handing it to `add_ice_candidate`. The OS
//! resolver coexists with the system mDNS service (it *is* the system mDNS
//! service on Windows 10+ / macOS; avahi / `systemd-resolved` on Linux
//! where enabled), so it succeeds where the in-process listener can't.
//! With a real IP in place the agent forms a genuine host↔host pair and
//! initiates its own checks — the direct pair reliably completes before
//! nomination instead of depending on prflx luck.
//!
//! Failure is always safe: on timeout / no-answer the candidate is added
//! unmodified (status quo — prflx discovery still applies). Resolution is
//! spawned by the caller so signaling never blocks on the ~750 ms timeout.
//!
//! ⚠️ An unmodified `.local` candidate goes on to webrtc-ice's own resolver,
//! which asks once a second until answered, and a browser off this LAN never
//! answers. Until #1740 that resolution outlived its session and held the
//! closed ICE agent with every socket it owned; the vendored webrtc-ice now
//! ends it with the agent, locked by `ice_lifetime_tests`.

use std::net::IpAddr;
use std::time::Duration;

/// How long to wait for the OS resolver before passing the candidate
/// through unmodified. System mDNS answers in tens of ms when the peer is
/// present; 750 ms bounds the no-answer case (name absent / mDNS blocked)
/// without holding the (spawned) add back noticeably.
const RESOLVE_TIMEOUT: Duration = Duration::from_millis(750);

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

/// Resolve the mDNS name in a `typ host` candidate via the OS resolver and
/// return the rewritten candidate. `None` when the candidate isn't an mDNS
/// host candidate, or resolution fails/times out (caller adds the original
/// unmodified). Prefers an IPv4 answer (the LAN pair we're after); falls
/// back to IPv6. IPv6 is emitted bare (no brackets) per candidate grammar.
pub async fn resolve_mdns_candidate(cand: &str) -> Option<String> {
    let name = candidate_mdns_name(cand)?.to_string();
    // lookup_host needs a port; reuse the candidate's own (value is
    // irrelevant to A/AAAA resolution — a garbled port just fails the
    // lookup and we pass through).
    let port = cand.split_whitespace().nth(PORT_TOKEN_IDX)?;
    let started = std::time::Instant::now();
    let addrs = tokio::time::timeout(
        RESOLVE_TIMEOUT,
        tokio::net::lookup_host(format!("{name}:{port}")),
    )
    .await
    .ok()?
    .ok()?;

    let mut v4: Option<IpAddr> = None;
    let mut v6: Option<IpAddr> = None;
    for sa in addrs {
        match sa.ip() {
            ip @ IpAddr::V4(_) => {
                let _ = v4.get_or_insert(ip);
            }
            ip @ IpAddr::V6(_) => {
                let _ = v6.get_or_insert(ip);
            }
        }
    }
    let ip = v4.or(v6)?;
    tracing::info!(
        mdns_name = %name,
        resolved = %ip,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "mDNS host candidate resolved via OS resolver (relay-escape)"
    );
    Some(rewrite_candidate_address(cand, &ip.to_string()))
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
}
