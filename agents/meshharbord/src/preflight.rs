// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Phase 8: pre-flight checks at agent startup.
//!
//! Three quick probes — DNS resolution, TCP reachability, and clock-skew vs
//! the server — that surface the most common deployment blunders with
//! actionable hints **before** the signaling loop starts trying (and
//! exponential-backoff-failing) against a server it can't talk to.
//!
//! Non-blocking: each finding is logged at WARN with a `hint=...` field,
//! never returns an error. The signaling loop runs unconditionally afterward
//! — pre-flight is diagnostics, not gating. 15 s overall budget enforced by
//! running the three probes in parallel via `tokio::join!`, each capped at
//! 5 s individually.

use std::time::Duration;
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Format `err` plus its full `.source()` chain as one colon-joined string.
/// `std::error::Error::Display` only emits the top-level message; the
/// underlying cause is hidden behind `source()` and never surfaced unless
/// the caller walks the chain. reqwest's `error sending request for url`
/// and io's generic "connection refused" both hide what we actually want
/// to see (rustls cert errors, EAI_NONAME, ECONNRESET, etc.), so this
/// helper makes the chain greppable in field logs.
fn chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(cause) = src {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        src = cause.source();
    }
    out
}
/// Tolerated clock offset before we warn. JWT validation typically allows
/// 30–60 s of skew either way; 60 s threshold gives us 1 minute of headroom
/// before the operator's tokens start failing to validate.
const CLOCK_SKEW_THRESHOLD_SECS: i64 = 60;

/// Outcome of a single check. Each variant carries enough context for the
/// log line to be self-explanatory ("clock skew 47 min — sync time").
#[derive(Debug, Clone)]
pub enum Finding {
    DnsFailed {
        host: String,
        reason: String,
    },
    TcpFailed {
        host: String,
        port: u16,
        reason: String,
    },
    /// Local clock differs from server clock by `offset_seconds`.
    /// Positive = local is ahead; negative = local is behind.
    ClockSkew {
        offset_seconds: i64,
    },
    HttpFailed {
        url: String,
        reason: String,
    },
    /// Couldn't parse the supplied `server_url` — unusual, but still
    /// safer to surface than to silently no-op.
    BadServerUrl {
        url: String,
    },
}

#[derive(Debug, Clone)]
pub struct Report {
    pub server_url: String,
    pub host: String,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.findings.is_empty()
    }

    /// Emit one tracing event per finding, with an actionable `hint=`
    /// field. All-clear logs a single info line so the operator can
    /// confirm the checks ran.
    pub fn log(&self) {
        if self.findings.is_empty() {
            tracing::info!(
                host = %self.host,
                "preflight: DNS + TCP + clock-skew checks passed"
            );
            return;
        }
        for f in &self.findings {
            match f {
                Finding::DnsFailed { host, reason } => tracing::warn!(
                    %host,
                    %reason,
                    hint = "check /etc/hosts, the system DNS resolver, or whether VPN is required",
                    "preflight: DNS lookup failed"
                ),
                Finding::TcpFailed { host, port, reason } => tracing::warn!(
                    %host,
                    port,
                    %reason,
                    hint = "check firewall outbound rules, corporate proxy / captive portal",
                    "preflight: TCP connect failed"
                ),
                Finding::ClockSkew { offset_seconds } => {
                    let mins = offset_seconds / 60;
                    tracing::warn!(
                        offset_seconds,
                        offset_minutes = mins,
                        hint = "JWT validation will fail past ±60 s; sync time (w32time / chronyd / ntpd)",
                        "preflight: clock skew vs server"
                    );
                }
                Finding::HttpFailed { url, reason } => tracing::warn!(
                    %url,
                    %reason,
                    hint = "HEAD / probe failed — TLS or routing issue between agent and server",
                    "preflight: HEAD request failed"
                ),
                Finding::BadServerUrl { url } => tracing::warn!(
                    %url,
                    hint = "expected https://host[:port]; re-enroll with --server set correctly",
                    "preflight: server_url is not parseable"
                ),
            }
        }
    }
}

/// Run all three checks in parallel, with per-step timeout. Total elapsed
/// is bounded by the slowest step (≤5 s) plus task scheduling overhead.
pub async fn run_checks(server_url: &str) -> Report {
    let Some((host, port, scheme)) = parse_host_port(server_url) else {
        return Report {
            server_url: server_url.to_string(),
            host: "?".into(),
            findings: vec![Finding::BadServerUrl {
                url: server_url.to_string(),
            }],
        };
    };

    let dns_fut = check_dns(host.clone(), port);
    let tcp_fut = check_tcp(host.clone(), port);
    let clock_fut = check_clock(scheme, host.clone(), port);

    let (dns, tcp, clock) = tokio::join!(dns_fut, tcp_fut, clock_fut);

    let mut findings = Vec::new();
    if let Some(f) = dns {
        findings.push(f);
    }
    if let Some(f) = tcp {
        findings.push(f);
    }
    if let Some(f) = clock {
        findings.push(f);
    }

    Report {
        server_url: server_url.to_string(),
        host,
        findings,
    }
}

/// Parse a `https://host[:port]/...` or `http://host[:port]/...` URL into
/// `(host, port, scheme)`. Returns `None` for anything else (so the caller
/// can surface a `BadServerUrl` finding).
fn parse_host_port(url: &str) -> Option<(String, u16, &'static str)> {
    let (scheme, default_port, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", 443u16, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", 80u16, rest)
    } else {
        return None;
    };
    // Trim path / query off the host part.
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host_port.is_empty() {
        return None;
    }
    if let Some(colon) = host_port.rfind(':') {
        let (host, port_str) = host_port.split_at(colon);
        let port: u16 = port_str[1..].parse().ok()?;
        Some((host.to_string(), port, scheme))
    } else {
        Some((host_port.to_string(), default_port, scheme))
    }
}

async fn check_dns(host: String, port: u16) -> Option<Finding> {
    match timeout(STEP_TIMEOUT, lookup_host(format!("{host}:{port}"))).await {
        Ok(Ok(mut iter)) => {
            if iter.next().is_none() {
                Some(Finding::DnsFailed {
                    host,
                    reason: "no addresses returned".into(),
                })
            } else {
                None
            }
        }
        Ok(Err(e)) => Some(Finding::DnsFailed {
            host,
            reason: chain(&e),
        }),
        Err(_) => Some(Finding::DnsFailed {
            host,
            reason: format!("lookup timed out after {}s", STEP_TIMEOUT.as_secs()),
        }),
    }
}

async fn check_tcp(host: String, port: u16) -> Option<Finding> {
    match timeout(STEP_TIMEOUT, TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(Finding::TcpFailed {
            host,
            port,
            reason: chain(&e),
        }),
        Err(_) => Some(Finding::TcpFailed {
            host,
            port,
            reason: format!("connect timed out after {}s", STEP_TIMEOUT.as_secs()),
        }),
    }
}

async fn check_clock(scheme: &str, host: String, port: u16) -> Option<Finding> {
    let url = if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        format!("{scheme}://{host}/health")
    } else {
        format!("{scheme}://{host}:{port}/health")
    };
    let client = match reqwest::Client::builder().timeout(STEP_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            return Some(Finding::HttpFailed {
                url,
                reason: format!("client build: {}", chain(&e)),
            });
        }
    };
    let resp = match client.head(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Some(Finding::HttpFailed {
                url,
                reason: chain(&e),
            });
        }
    };
    let date_header = resp.headers().get(reqwest::header::DATE)?;
    let s = date_header.to_str().ok()?;
    let server_dt = chrono::DateTime::parse_from_rfc2822(s).ok()?;
    let server_unix = server_dt.timestamp();
    let local_unix = chrono::Utc::now().timestamp();
    let offset = local_unix - server_unix;
    if offset.abs() > CLOCK_SKEW_THRESHOLD_SECS {
        Some(Finding::ClockSkew {
            offset_seconds: offset,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_default_port() {
        assert_eq!(
            parse_host_port("https://roomler.ai"),
            Some(("roomler.ai".into(), 443, "https"))
        );
    }

    #[test]
    fn parse_https_with_path_strips_path() {
        assert_eq!(
            parse_host_port("https://roomler.ai/api/agent/enroll"),
            Some(("roomler.ai".into(), 443, "https"))
        );
    }

    #[test]
    fn parse_http_with_explicit_port() {
        assert_eq!(
            parse_host_port("http://10.0.0.5:3000"),
            Some(("10.0.0.5".into(), 3000, "http"))
        );
    }

    #[test]
    fn parse_https_with_explicit_port_and_query() {
        assert_eq!(
            parse_host_port("https://internal:8443/?token=x"),
            Some(("internal".into(), 8443, "https"))
        );
    }

    #[test]
    fn parse_rejects_bare_host() {
        assert_eq!(parse_host_port("roomler.ai"), None);
    }

    #[test]
    fn parse_rejects_unknown_scheme() {
        assert_eq!(parse_host_port("file:///tmp/x"), None);
    }

    #[test]
    fn parse_rejects_unparseable_port() {
        assert_eq!(parse_host_port("https://host:abc"), None);
    }

    #[tokio::test]
    async fn run_checks_against_invalid_url_yields_bad_url_finding() {
        let r = run_checks("not-a-url").await;
        assert_eq!(r.findings.len(), 1);
        assert!(matches!(&r.findings[0], Finding::BadServerUrl { .. }));
    }

    #[tokio::test]
    async fn dns_check_against_unreachable_host_yields_finding() {
        // A fake-IP DNS proxy (Clash/Mihomo-style, 198.18.0.0/15) or a hijacking
        // resolver answers even RFC 6761 `.invalid` names, so the failure this
        // test needs cannot happen there (measured on a dev host: every run).
        // Probe with a second reserved name first; MESHHARBORD_TEST_REQUIRE_DNS
        // turns the skip into a failure where a clean resolver is expected.
        let probe = format!("preflight-probe-{}.invalid:443", std::process::id());
        if tokio::net::lookup_host(probe).await.is_ok() {
            if std::env::var_os("MESHHARBORD_TEST_REQUIRE_DNS").is_some() {
                panic!(
                    "MESHHARBORD_TEST_REQUIRE_DNS is set and this host's resolver answers .invalid names"
                );
            }
            eprintln!(
                "skipping: this host's resolver answers .invalid names (fake-IP DNS proxy or hijack)"
            );
            return;
        }
        // RFC 2606 reserved test TLD — guaranteed not to resolve.
        let f = check_dns("meshharbor.invalid".into(), 443).await;
        assert!(
            matches!(f, Some(Finding::DnsFailed { .. })),
            "expected DnsFailed, got {f:?}"
        );
    }
}
