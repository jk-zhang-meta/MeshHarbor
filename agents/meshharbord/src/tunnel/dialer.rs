// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! TCP dialer for the agent-side tunnel acceptor.
//!
//! `dial_dst` connects to `(host, port)` with a bounded total timeout
//! and returns the open socket on success. The default 5 s timeout is
//! deliberately tight — corp intranets resolve fast (mDNS / internal
//! DNS), and an operator typing into psql would rather see a clean
//! `RejectKind::DialFailed` than a 30 s tokio default hang.
//!
//! TCP_NODELAY is set immediately on the connected socket (plan
//! §"Performance levers" — Nagle's 40 ms is the difference between
//! snappy and laggy psql). The DC pump that wraps this socket lands
//! in T2.7-9.

use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;

/// Default total time budget for resolution + connect.
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum DialError {
    #[error("dial timed out after {0:?}")]
    Timeout(Duration),
    #[error("resolve or connect failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Connect to `host:port` with `timeout`. Sets `TCP_NODELAY` on the
/// returned socket. Returns `DialError::Timeout` if the deadline
/// fires before connect completes (tokio's default would be
/// effectively unbounded — the OS TCP-SYN retry budget).
pub async fn dial_dst(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, DialError> {
    let addr = format!("{host}:{port}");
    let connect = TcpStream::connect(&addr);
    let stream = match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(DialError::Io(e)),
        Err(_) => return Err(DialError::Timeout(timeout)),
    };
    // TCP_NODELAY — disables Nagle. Without it, psql interactive
    // round-trips see Nagle's 40 ms delay on small writes.
    if let Err(e) = stream.set_nodelay(true) {
        // Non-fatal — log via the caller's tracing context if needed.
        // Returning the stream anyway because tunnel still works
        // (just laggier on small writes).
        tracing::warn!(%addr, %e, "TCP_NODELAY failed; continuing");
    }
    Ok(stream)
}

/// Bind a local UDP socket and `connect()` it to `host:port` for a UDP
/// ASSOCIATE flow. UDP `connect` sends nothing — it fixes the default
/// peer (so `send`/`recv` need no address and ICMP errors surface) and
/// lets the pump treat the socket like a point-to-point pipe to the
/// target. Resolution is bounded by `timeout`; the socket family
/// (v4/v6) follows the resolved target. Returns the connected socket.
pub async fn dial_udp(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<tokio::net::UdpSocket, DialError> {
    let addr = format!("{host}:{port}");
    // Resolve first so we can pick the bind family + fail fast on a bad
    // host (mirrors `dial_dst`'s tight budget for interactive UX).
    let target = match tokio::time::timeout(timeout, tokio::net::lookup_host(&addr)).await {
        Ok(Ok(mut it)) => it.next().ok_or_else(|| {
            DialError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "resolved to no addresses",
            ))
        })?,
        Ok(Err(e)) => return Err(DialError::Io(e)),
        Err(_) => return Err(DialError::Timeout(timeout)),
    };
    let bind: std::net::SocketAddr = if target.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(DialError::Io)?;
    sock.connect(target).await.map_err(DialError::Io)?;
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Localhost on an unbound port should fail to connect quickly
    /// (RST from the OS). Verifies the error path returns `Io` —
    /// not the timeout branch — for the common-case-fast-failure.
    #[tokio::test]
    async fn unbound_port_fails_fast_not_timeout() {
        let result = dial_dst("127.0.0.1", 1, Duration::from_secs(5)).await;
        match result {
            Err(DialError::Io(_)) => { /* expected — connection refused */ }
            Err(DialError::Timeout(_)) => panic!("should fail fast, not time out"),
            Ok(_) => panic!("port 1 unexpectedly bound on this host"),
        }
    }

    /// Routable-but-non-responsive address (TEST-NET-1 reserved
    /// 192.0.2.0/24 per RFC 5737) should time out, not error fast.
    /// Verifies the timeout branch fires before tokio's default.
    #[tokio::test]
    async fn unroutable_address_times_out() {
        // 50 ms timeout — tight so the test doesn't drag. TEST-NET
        // addresses are guaranteed by RFC 5737 to be discarded by
        // routing infrastructure, so we never see a real RST.
        let result = dial_dst("192.0.2.1", 1, Duration::from_millis(50)).await;
        match result {
            Err(DialError::Timeout(d)) => assert_eq!(d, Duration::from_millis(50)),
            Err(DialError::Io(_)) => {
                // Some hosts (Windows with no route to 192.0.2.0/24)
                // return immediate "no route to host" before the
                // timeout fires. Accept either branch — both are
                // failure paths the acceptor must map to `DialFailed`.
            }
            Ok(_) => panic!("192.0.2.1 unexpectedly accepted connection"),
        }
    }
}
