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
//! Resolve the `.local` name via bounded OS-resolver retries (`getaddrinfo`,
//! via `tokio::net::lookup_host`, up to `MAX_RESOLVE_ATTEMPTS = 4` attempts of
//! `ATTEMPT_TIMEOUT = 1500 ms` each, for a maximum total budget of `6.0 s`).
//! Measured on Windows 11 (`Surface`): a single `750 ms` timeout expired
//! before `GetAddrInfoW` returned, whereas with a `1500 ms` per-attempt
//! timeout the OS resolver returned in `1228–1318 ms` on Attempt 1 across 30
//! live sessions (and up to `~4.8 s` on cold standalone `Resolve-DnsName`
//! calls).
//!
//! Every attempt is raced against the session's `CancellationToken` so session
//! teardown aborts resolution immediately (preserving #1740), and every
//! resolved IP must pass the session's `keeps_ip` filter
//! (`RcOverlay::keeps_local`).

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Per-attempt timeout (`1500 ms`). Measured on Windows 11: OS `.local`
/// resolution via `GetAddrInfoW` completed in `1228–1318 ms` on Attempt 1
/// across 30 live sessions, which a `750 ms` timeout cut off prematurely.
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Maximum bounded attempts (`4 × 1.5 s = 6.0 s` worst-case for an
/// unresolvable name, immediately cancelled on session close).
const MAX_RESOLVE_ATTEMPTS: usize = 4;

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

async fn os_lookup_host(name: String, port: String) -> io::Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host(format!("{name}:{port}")).await?;
    Ok(addrs.map(|sa| sa.ip()).collect())
}

async fn resolve_mdns_candidate_with_lookup<L, Fut>(
    cand: &str,
    cancel: &CancellationToken,
    keeps_ip: impl Fn(IpAddr) -> bool,
    mut lookup: L,
) -> Option<String>
where
    L: FnMut(String, String) -> Fut,
    Fut: Future<Output = io::Result<Vec<IpAddr>>>,
{
    let name = candidate_mdns_name(cand)?.to_string();
    let port = cand.split_whitespace().nth(PORT_TOKEN_IDX)?.to_string();
    let started = std::time::Instant::now();

    for attempt in 1..=MAX_RESOLVE_ATTEMPTS {
        let attempt_res = tokio::select! {
            biased;
            _ = cancel.cancelled() => return None,
            res = tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                lookup(name.clone(), port.clone()),
            ) => res,
        };

        if let Ok(Ok(ips)) = attempt_res {
            let mut v4: Option<IpAddr> = None;
            let mut v6: Option<IpAddr> = None;
            for ip in ips {
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
                tracing::info!(
                    mdns_name = %name,
                    resolved = %ip,
                    attempt,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "mDNS host candidate resolved via OS resolver (relay-escape)"
                );
                return Some(rewrite_candidate_address(cand, &ip.to_string()));
            }
        }
    }
    None
}

/// Resolve the mDNS name in a `typ host` candidate via the OS resolver with
/// bounded retries (`<= 6.0 s`), filtering resolved addresses with `keeps_ip`
/// and aborting immediately when `cancel` is triggered.
pub async fn resolve_mdns_candidate_with_policy(
    cand: &str,
    cancel: &CancellationToken,
    keeps_ip: impl Fn(IpAddr) -> bool,
) -> Option<String> {
    resolve_mdns_candidate_with_lookup(cand, cancel, keeps_ip, os_lookup_host).await
}

/// Resolve the mDNS name in a `typ host` candidate via the OS resolver with
/// no cancellation token or IP filter (finishes after at most `6.0 s`).
pub async fn resolve_mdns_candidate(cand: &str) -> Option<String> {
    let cancel = CancellationToken::new();
    resolve_mdns_candidate_with_policy(cand, &cancel, |_| true).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    async fn non_mdns_candidate_skips_lookup_entirely() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&calls);
        let cancel = CancellationToken::new();
        let res = resolve_mdns_candidate_with_lookup(
            PLAIN_HOST,
            &cancel,
            |_| true,
            move |_name, _port| {
                calls_ref.fetch_add(1, Ordering::SeqCst);
                async { Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))]) }
            },
        )
        .await;
        assert_eq!(res, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn session_cancellation_aborts_in_flight_lookup_without_retries() {
        let cancel = CancellationToken::new();
        let entered = Arc::new(tokio::sync::Notify::new());
        let entered_lookup = Arc::clone(&entered);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_lookup = Arc::clone(&calls);

        let cancel_trigger = cancel.clone();
        tokio::spawn(async move {
            entered.notified().await;
            cancel_trigger.cancel();
        });

        let res = resolve_mdns_candidate_with_lookup(
            MDNS_HOST,
            &cancel,
            |_| true,
            move |_name, _port| {
                calls_lookup.fetch_add(1, Ordering::SeqCst);
                let entered_lookup = Arc::clone(&entered_lookup);
                async move {
                    entered_lookup.notify_one();
                    std::future::pending::<io::Result<Vec<IpAddr>>>().await
                }
            },
        )
        .await;
        assert_eq!(res, None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_after_failure_and_timeout_then_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_lookup = Arc::clone(&calls);
        let cancel = CancellationToken::new();

        let res = resolve_mdns_candidate_with_lookup(
            MDNS_HOST,
            &cancel,
            |_| true,
            move |_name, _port| {
                let n = calls_lookup.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    match n {
                        1 => Err(io::Error::new(io::ErrorKind::NotFound, "no record yet")),
                        2 => std::future::pending::<io::Result<Vec<IpAddr>>>().await,
                        _ => Ok(vec![
                            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4)),
                            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
                        ]),
                    }
                }
            },
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            res.as_deref(),
            Some(
                "candidate:842163049 1 udp 1677729535 192.168.1.42 54321 typ host generation 0 ufrag Xy4z network-cost 999"
            )
        );
    }

    #[tokio::test]
    async fn all_attempts_fail_returns_none_for_fallback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_lookup = Arc::clone(&calls);
        let cancel = CancellationToken::new();

        let res = resolve_mdns_candidate_with_lookup(
            MDNS_HOST,
            &cancel,
            |_| true,
            move |_name, _port| {
                calls_lookup.fetch_add(1, Ordering::SeqCst);
                async { Err(io::Error::new(io::ErrorKind::NotFound, "unresolvable")) }
            },
        )
        .await;

        assert_eq!(res, None);
        assert_eq!(calls.load(Ordering::SeqCst), MAX_RESOLVE_ATTEMPTS);
    }

    #[tokio::test]
    async fn keeps_ip_filters_rejected_addresses_and_retries_until_allowed_ip() {
        let overlay_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9));
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        let cancel = CancellationToken::new();

        // Case 1: Attempt 1 returns only an overlay IP (filtered out), Attempt 2
        // returns both the overlay IP and the LAN IP -> selects the LAN IP.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_lookup = Arc::clone(&calls);
        let res = resolve_mdns_candidate_with_lookup(
            MDNS_HOST,
            &cancel,
            |ip| ip != overlay_ip,
            move |_name, _port| {
                let n = calls_lookup.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if n == 1 {
                        Ok(vec![overlay_ip])
                    } else {
                        Ok(vec![overlay_ip, lan_ip])
                    }
                }
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            res.as_deref(),
            Some(
                "candidate:842163049 1 udp 1677729535 192.168.1.42 54321 typ host generation 0 ufrag Xy4z network-cost 999"
            )
        );

        // Case 2: Every attempt returns only the filtered overlay IP -> returns None
        // after MAX_RESOLVE_ATTEMPTS.
        let calls_all_filtered = Arc::new(AtomicUsize::new(0));
        let calls_all_ref = Arc::clone(&calls_all_filtered);
        let res_filtered = resolve_mdns_candidate_with_lookup(
            MDNS_HOST,
            &cancel,
            |ip| ip != overlay_ip,
            move |_name, _port| {
                calls_all_ref.fetch_add(1, Ordering::SeqCst);
                async move { Ok(vec![overlay_ip]) }
            },
        )
        .await;
        assert_eq!(res_filtered, None);
        assert_eq!(
            calls_all_filtered.load(Ordering::SeqCst),
            MAX_RESOLVE_ATTEMPTS
        );
    }
}
