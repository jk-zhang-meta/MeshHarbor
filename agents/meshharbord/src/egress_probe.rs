// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-138 — physical-path egress probe and default-route VPN detection.
//!
//! On each control-socket connect and on each major network change, the daemon
//! fires one small background HTTPS `POST /api/agent/self/egress-probe` bound
//! to a physical non-VPN uplink (`tunnel_core::overlay::direct::non_vpn_uplinks_named`)
//! so the centre observes the device's real physical egress IP even while a
//! TUN-mode VPN owns the OS default route.
//!
//! Invariants:
//! - FR-135: always builds its HTTP client through `http_client::builder_with(false)`
//!   (no system or environment proxies).
//! - FR-134: follows the active management path (`management_path::plan`); when
//!   traversing a zone management entry, fetches an `MHE1` attestation over the
//!   SAME physical-bound socket and passes `?entry=<token>`.
//! - Silent & non-blocking: runs on a detached task; missing uplinks, non-root
//!   Linux installs (no `SO_BINDTODEVICE`), bind errors, and timeouts log only
//!   at `debug!` and never stall or fail control-socket connect.

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
use std::net::SocketAddr;
use std::sync::RwLock;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
use std::time::Duration;

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
use serde::Deserialize;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
use tokio::net::{TcpListener, TcpStream};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
use tracing::debug;
use tunnel_core::localapi::EgressProbeStatus;

/// Per-attempt timeout for TCP connect, attestation, and HTTP response.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
const PROBE_TIMEOUT: Duration = Duration::from_secs(6);

/// Process-wide latest egress probe observation surfaced by `NodeStatus.egress`.
static LAST_STATUS: RwLock<Option<EgressProbeStatus>> = RwLock::new(None);

/// Prevents concurrent probe storms on bursty network-change notifications.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
static PROBE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
#[derive(Debug, Deserialize)]
struct EgressProbeReply {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    physical_public_ip: Option<String>,
    #[serde(default)]
    current_public_ip: Option<String>,
    #[serde(default)]
    zone_id: Option<String>,
    #[serde(default)]
    zone_name: Option<String>,
    #[serde(default)]
    zone_source: Option<String>,
}

/// FR-138 — whether this host's OS IPv4/IPv6 default route currently sits on a
/// VPN or virtual interface. Used in `AgentHello` / `AgentHeartbeat` caps and
/// `mh status`.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub fn default_route_vpn() -> bool {
    tunnel_core::overlay::direct::default_route_is_vpn()
}

#[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
pub fn default_route_vpn() -> bool {
    false
}

/// Snapshot of the latest physical-egress probe state for `NodeStatus.egress`.
/// Refreshes `default_route_vpn` from live routing state so `mh status` reflects
/// VPN toggles immediately without discarding the last observed physical IP.
pub fn current_status() -> Option<EgressProbeStatus> {
    let vpn_now = default_route_vpn();
    let guard = LAST_STATUS.read().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(prev) => {
            let mut out = prev.clone();
            out.default_route_vpn = vpn_now;
            Some(out)
        }
        None => vpn_now.then(|| EgressProbeStatus {
            default_route_vpn: true,
            ..EgressProbeStatus::default()
        }),
    }
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn record_reply(reply: EgressProbeReply, default_route_vpn: bool) {
    let status = EgressProbeStatus {
        physical_ip: reply.physical_public_ip,
        current_ip: reply.current_public_ip,
        zone_id: reply.zone_id,
        zone_name: reply.zone_name,
        zone_source: reply.zone_source,
        default_route_vpn,
    };
    *LAST_STATUS.write().unwrap_or_else(|e| e.into_inner()) = Some(status);
}

/// Fire-and-forget physical-path egress probe. Never awaits network I/O on the
/// caller's task, never returns an error, and deduplicates concurrent triggers.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub fn spawn_probe(server_url: String, token: String, local_entries: Vec<String>) {
    if server_url.trim().is_empty() || token.trim().is_empty() {
        return;
    }
    if PROBE_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        debug!("egress probe: already in flight, skipping duplicate trigger");
        return;
    }
    tokio::spawn(async move {
        struct ResetGuard;
        impl Drop for ResetGuard {
            fn drop(&mut self) {
                PROBE_IN_FLIGHT.store(false, Ordering::Release);
            }
        }
        let _guard = ResetGuard;
        run_probe(&server_url, &token, &local_entries).await;
    });
}

#[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
pub fn spawn_probe(_server_url: String, _token: String, _local_entries: Vec<String>) {}

/// Build the local splice URL and original `Host` header so `reqwest` connects
/// to our 1-shot loopback splice while preserving the centre's TLS SNI and
/// virtual-host `Host` header.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
fn build_splice_request_target(
    base_url: &reqwest::Url,
    local_addr: SocketAddr,
    entry_token: Option<&str>,
) -> Option<(reqwest::Url, Option<String>, String)> {
    let scheme = base_url.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let orig_host = base_url.host_str()?.trim_matches(['[', ']']).to_string();
    let orig_port = base_url.port();
    let host_header = match orig_port {
        Some(p) => format!("{orig_host}:{p}"),
        None => orig_host.clone(),
    };
    let is_ip_literal = orig_host.parse::<std::net::IpAddr>().is_ok();
    let connect_host = if is_ip_literal {
        "127.0.0.1".to_string()
    } else {
        orig_host.clone()
    };
    let base_path = base_url.path().trim_end_matches('/');
    let mut url = reqwest::Url::parse(&format!(
        "{scheme}://{connect_host}:{}{base_path}/api/agent/self/egress-probe",
        local_addr.port()
    ))
    .ok()?;
    if let Some(tok) = entry_token.filter(|t| !t.is_empty()) {
        url.query_pairs_mut().append_pair("entry", tok);
    }
    let resolve_domain = (!is_ip_literal).then_some(orig_host);
    Some((url, resolve_domain, host_header))
}

/// Send one `POST /api/agent/self/egress-probe` over an already-connected
/// physical-bound `TcpStream` via an ephemeral 1-shot `127.0.0.1:0` splice.
///
/// Using `http_client::builder_with(false)` guarantees FR-135 no-proxy
/// compliance and uniform TLS/CA/SNI behavior across Linux, macOS, and Windows.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack", test))]
async fn post_probe_over_stream(
    base_url: &reqwest::Url,
    token: &str,
    entry_token: Option<&str>,
    mut bound_stream: TcpStream,
) -> Option<EgressProbeReply> {
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let local_addr = listener.local_addr().ok()?;
    let (url, resolve_domain, host_header) =
        build_splice_request_target(base_url, local_addr, entry_token)?;

    let splice_task = tokio::spawn(async move {
        let work = async {
            if let Ok((mut client_side, _)) = listener.accept().await {
                let _ = client_side.set_nodelay(true);
                let _ = tokio::io::copy_bidirectional(&mut client_side, &mut bound_stream).await;
            }
        };
        let _ = tokio::time::timeout(PROBE_TIMEOUT * 2, work).await;
    });

    // FR-135 — always build via http_client::builder_with(false) (no system/env proxies).
    let mut builder = meshharbor_node_core::http_client::builder_with(false)
        .timeout(PROBE_TIMEOUT)
        .connect_timeout(PROBE_TIMEOUT);
    if let Some(domain) = resolve_domain {
        builder = builder.resolve(&domain, local_addr);
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            splice_task.abort();
            debug!(%e, "egress probe: failed to build HTTP client");
            return None;
        }
    };

    let resp = client
        .post(url)
        .header(reqwest::header::HOST, host_header)
        .bearer_auth(token)
        .send()
        .await;

    let result = match resp {
        Ok(r) if r.status().is_success() => r.json::<EgressProbeReply>().await.ok(),
        Ok(r) => {
            debug!(status = %r.status(), "egress probe: non-success HTTP status");
            None
        }
        Err(e) => {
            debug!(%e, "egress probe: HTTP request failed");
            None
        }
    };
    splice_task.abort();
    result
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
async fn run_probe(server_url: &str, token: &str, local_entries: &[String]) {
    use meshharbor_node_core::management_path as mp;
    use tunnel_core::overlay::direct::{
        connect_tcp_bound, linux_can_bind_to_device, non_vpn_uplinks_named,
    };

    if !linux_can_bind_to_device() {
        debug!("egress probe: skipped (unprivileged Linux install without SO_BINDTODEVICE)");
        return;
    }

    let Ok(base_url) = reqwest::Url::parse(server_url) else {
        debug!(%server_url, "egress probe: unparseable server_url");
        return;
    };
    let Some(centre_host) = base_url
        .host_str()
        .map(|h| h.trim_matches(['[', ']']).to_string())
    else {
        return;
    };
    let Some(centre_port) = base_url.port_or_known_default() else {
        return;
    };

    let uplinks = non_vpn_uplinks_named();
    if uplinks.is_empty() {
        debug!("egress probe: no physical non-VPN uplink available, skipping silently");
        return;
    }

    let pushed = mp::state_path()
        .map(|p| mp::load(&p, &centre_host))
        .unwrap_or_default();
    let (candidates, _) = mp::plan(&pushed, local_entries, None);

    let hostport = tunnel_core::ctl_dns::hostport(&centre_host, centre_port);
    let mut direct_addrs: Option<Vec<SocketAddr>> = None;

    for uplink in &uplinks {
        for cand in &candidates {
            match *cand {
                mp::Candidate::Entry(entry_addr) => {
                    // Obtain FR-134 attestation over the SAME physical-bound uplink so the
                    // gateway attests our physical egress IP, never the VPN IP.
                    let entry_token =
                        match connect_tcp_bound(entry_addr, uplink, PROBE_TIMEOUT).await {
                            Ok(attest_stream) => match crate::mgmt_entry::request_attestation_over(
                                attest_stream,
                                PROBE_TIMEOUT,
                            )
                            .await
                            {
                                Ok(tok) => Some(tok),
                                Err(e) => {
                                    debug!(
                                        uplink = %uplink.name,
                                        %entry_addr,
                                        %e,
                                        "egress probe: entry attestation failed"
                                    );
                                    None
                                }
                            },
                            Err(e) => {
                                debug!(
                                    uplink = %uplink.name,
                                    %entry_addr,
                                    %e,
                                    "egress probe: bound connect to entry failed"
                                );
                                continue;
                            }
                        };
                    let Ok(http_stream) =
                        connect_tcp_bound(entry_addr, uplink, PROBE_TIMEOUT).await
                    else {
                        continue;
                    };
                    if let Some(reply) = post_probe_over_stream(
                        &base_url,
                        token,
                        entry_token.as_deref(),
                        http_stream,
                    )
                    .await
                        && reply.ok
                    {
                        let vpn_now = default_route_vpn();
                        debug!(
                            uplink = %uplink.name,
                            physical_ip = ?reply.physical_public_ip,
                            zone_id = ?reply.zone_id,
                            zone_source = ?reply.zone_source,
                            "egress probe succeeded via management entry"
                        );
                        record_reply(reply, vpn_now);
                        return;
                    }
                }
                mp::Candidate::Direct => {
                    let addrs = match direct_addrs.as_ref() {
                        Some(a) => a,
                        None => {
                            let mut resolved = tunnel_core::ctl_dns::resolve(&hostport).await;
                            // Prefer IPv4 targets first since PhysicalUplink carries an IPv4 source.
                            resolved.sort_by_key(|a| a.is_ipv6());
                            direct_addrs = Some(resolved);
                            direct_addrs.as_ref().expect("set above")
                        }
                    };
                    for &target in addrs {
                        let Ok(http_stream) =
                            connect_tcp_bound(target, uplink, PROBE_TIMEOUT).await
                        else {
                            debug!(
                                uplink = %uplink.name,
                                %target,
                                "egress probe: bound connect failed"
                            );
                            continue;
                        };
                        if let Some(reply) =
                            post_probe_over_stream(&base_url, token, None, http_stream).await
                            && reply.ok
                        {
                            let vpn_now = default_route_vpn();
                            debug!(
                                uplink = %uplink.name,
                                physical_ip = ?reply.physical_public_ip,
                                zone_id = ?reply.zone_id,
                                zone_source = ?reply.zone_source,
                                "egress probe succeeded direct"
                            );
                            record_reply(reply, vpn_now);
                            return;
                        }
                    }
                }
            }
        }
    }
    debug!("egress probe: all physical uplinks/candidates exhausted silently");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn splice_target_preserves_domain_host_header_and_entry_query() {
        let base = reqwest::Url::parse("https://centre.example.test:8443").unwrap();
        let local: SocketAddr = "127.0.0.1:45678".parse().unwrap();
        let (url, domain, host_hdr) =
            build_splice_request_target(&base, local, Some("tok+1/2")).unwrap();
        assert_eq!(domain.as_deref(), Some("centre.example.test"));
        assert_eq!(host_hdr, "centre.example.test:8443");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("centre.example.test"));
        assert_eq!(url.port(), Some(45678));
        assert_eq!(url.path(), "/api/agent/self/egress-probe");
        assert_eq!(url.query(), Some("entry=tok%2B1%2F2"));
    }

    #[test]
    fn splice_target_preserves_base_path_for_direct_and_entry_candidates() {
        let local: SocketAddr = "127.0.0.1:45678".parse().unwrap();

        // Deployment under a reverse-proxy base path (both direct and entry).
        let with_prefix = reqwest::Url::parse("https://centre.example.test/meshharbor").unwrap();
        let (direct_url, direct_domain, direct_host) =
            build_splice_request_target(&with_prefix, local, None).unwrap();
        assert_eq!(direct_domain.as_deref(), Some("centre.example.test"));
        assert_eq!(direct_host, "centre.example.test");
        assert_eq!(direct_url.path(), "/meshharbor/api/agent/self/egress-probe");
        assert_eq!(direct_url.query(), None);

        let (entry_url, entry_domain, entry_host) =
            build_splice_request_target(&with_prefix, local, Some("tok+1/2")).unwrap();
        assert_eq!(entry_domain.as_deref(), Some("centre.example.test"));
        assert_eq!(entry_host, "centre.example.test");
        assert_eq!(entry_url.path(), "/meshharbor/api/agent/self/egress-probe");
        assert_eq!(entry_url.query(), Some("entry=tok%2B1%2F2"));

        // Trailing slash on the base path must not introduce a double slash.
        let trailing = reqwest::Url::parse("https://centre.example.test/meshharbor/").unwrap();
        let (trailing_url, _, _) = build_splice_request_target(&trailing, local, None).unwrap();
        assert_eq!(
            trailing_url.path(),
            "/meshharbor/api/agent/self/egress-probe"
        );
        let (trailing_entry_url, _, _) =
            build_splice_request_target(&trailing, local, Some("att")).unwrap();
        assert_eq!(
            trailing_entry_url.path(),
            "/meshharbor/api/agent/self/egress-probe"
        );
        assert_eq!(trailing_entry_url.query(), Some("entry=att"));

        // Root path (with and without explicit trailing slash).
        for root in [
            "https://centre.example.test",
            "https://centre.example.test/",
        ] {
            let base = reqwest::Url::parse(root).unwrap();
            let (url, _, _) = build_splice_request_target(&base, local, None).unwrap();
            assert_eq!(url.path(), "/api/agent/self/egress-probe", "root={root}");
        }
    }

    #[tokio::test]
    async fn post_probe_over_stream_sends_base_path_on_wire_for_direct_and_entry() {
        for (entry_token, expected_target) in [
            (None, "/meshharbor/api/agent/self/egress-probe"),
            (
                Some("att-xyz"),
                "/meshharbor/api/agent/self/egress-probe?entry=att-xyz",
            ),
        ] {
            let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();

            let srv = tokio::spawn(async move {
                let (mut sock, _) = server.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = r#"{"ok":true,"physical_public_ip":"198.51.100.10"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                let _ = sock.shutdown().await;
                req
            });

            let bound_stream = TcpStream::connect(server_addr).await.unwrap();
            let base_url =
                reqwest::Url::parse("http://centre.example.test:8080/meshharbor/").unwrap();
            let reply =
                post_probe_over_stream(&base_url, "agent-tok-123", entry_token, bound_stream)
                    .await
                    .expect("probe reply");

            let req_text = srv.await.unwrap();
            assert!(
                req_text.starts_with(&format!("POST {expected_target} HTTP/1.1\r\n")),
                "unexpected request line: {req_text}"
            );
            assert!(reply.ok);
        }
    }

    #[tokio::test]
    async fn post_probe_over_stream_sends_bearer_and_parses_reply() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (mut sock, _) = server.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = r#"{"ok":true,"physical_public_ip":"198.51.100.10","current_public_ip":"203.0.113.20","zone_id":"cn","zone_name":"CN","zone_source":"auto_physical"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            let _ = sock.shutdown().await;
            req
        });

        let bound_stream = TcpStream::connect(server_addr).await.unwrap();
        let base_url = reqwest::Url::parse("http://centre.example.test:8080").unwrap();
        let reply =
            post_probe_over_stream(&base_url, "agent-tok-123", Some("att-xyz"), bound_stream)
                .await
                .expect("probe reply");

        let req_text = srv.await.unwrap();
        assert!(
            req_text.starts_with("POST /api/agent/self/egress-probe?entry=att-xyz HTTP/1.1\r\n")
        );
        assert!(
            req_text
                .to_ascii_lowercase()
                .contains("authorization: bearer agent-tok-123")
        );
        assert!(
            req_text
                .to_ascii_lowercase()
                .contains("host: centre.example.test:8080")
        );
        assert!(reply.ok);
        assert_eq!(reply.physical_public_ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(reply.current_public_ip.as_deref(), Some("203.0.113.20"));
        assert_eq!(reply.zone_id.as_deref(), Some("cn"));
        assert_eq!(reply.zone_name.as_deref(), Some("CN"));
        assert_eq!(reply.zone_source.as_deref(), Some("auto_physical"));
    }
}
