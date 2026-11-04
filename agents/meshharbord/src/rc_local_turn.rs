// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Loopback-TURN corp-relay (Phase 2b) — the agent side.
//!
//! When a corp host runs this agent AND its browser is the controller, the
//! browser can't punch a direct WebRTC path (chrome.exe UDP is firewalled /
//! the corp edge drops UDP) so sessions fall back to the far coturn relay and
//! get the relay caps (blurry text). The *agent*, however, traverses the corp
//! edge fine over the overlay. So: the local agent hosts a tiny UDP TURN on its
//! overlay IP, the co-located browser relays through it over **loopback** (never
//! firewalled), and the remote agent reaches the allocated relays over the
//! **overlay** (WFP-permitted). Design: `~/.claude/plans/roomler-loopback-turn-
//! corp-relay.md`; the TURN server itself is [`LocalTurnHost`] (Phase 1).
//!
//! This module is the discovery + lifecycle half:
//!   * a loopback HTTP probe on `127.0.0.1:47989` the browser fetches to learn
//!     its local agent's TURN (`turn_port` + `overlay_ip` + freshly-minted
//!     creds) — answering the Chrome Private-Network-Access (PNA) CORS
//!     preflight so an HTTPS page may read a loopback resource;
//!   * a [`LocalTurnHost`] kept in sync with the overlay's assigned self-IP.
//!
//! Default-ON since rc.220 (the DERP precedent: fallbacks must be armed
//! BEFORE the network that needs them — nobody runs an elevated
//! `set-service-env-var` from inside a UDP-blocked corp VPN). Hosting the
//! TURN + probe is inert infrastructure: nothing uses it until the BROWSER
//! opts in (`localRelayEnabled`, still default-OFF pending the first real
//! UDP-blocked field proof). `ROOMLERD_LOCAL_TURN=0` disables. Compiles
//! in the default build; without an overlay IP the probe answers 503 and no
//! TURN is hosted.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use meshharbor_remote_control::signaling::LocalRelayDescriptor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};
use tunnel_core::localapi::OverlayView;
use tunnel_core::transport::turn_host::LocalTurnHost;

/// Primary loopback discovery port (legacy well-known). MUST match
/// `LOCAL_RELAY_PROBE_PORT` in `ui/src/composables/useRemoteControl.ts`.
pub const PROBE_PORT: u16 = 47989;
/// Fallback band base. `47989+` sits right at the edge of where
/// Hyper-V / WSL2-mirrored / HNS reserve their large port pools (a
/// ~2500-port block around 46000-48500 was found on a WSL-mirrored
/// host — invisible to `netstat` AND `netsh excludedportrange`, so
/// the whole primary band was unbindable). This band lives in the
/// quiet region WELL BELOW that zone, which those stacks don't touch,
/// so the range-walk always has a free port to fall to. MUST match
/// the browser's `LOCAL_RELAY_PROBE_PORTS`.
pub const PROBE_PORT_FALLBACK: u16 = 41989;
/// Ports per band. A host running N agents needs ≥N free ports per
/// band; 5 covers realistic Windows+WSL (+ a stray) co-tenancy.
pub const PROBE_PORT_BAND: u16 = 5;

/// The candidate discovery ports: the primary band first (unchanged
/// behaviour on normal hosts), then the fallback band for hosts whose
/// Hyper-V/WSL/HNS reservations swallow the primary.
fn probe_ports() -> impl Iterator<Item = u16> + Clone {
    (0..PROBE_PORT_BAND)
        .map(|i| PROBE_PORT + i)
        .chain((0..PROBE_PORT_BAND).map(|i| PROBE_PORT_FALLBACK + i))
}

/// TTL of a minted relay credential (handed to the browser + remote agent).
const CRED_TTL: Duration = Duration::from_secs(3600);
/// Max time to read a request head before giving up on a connection.
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Overall per-connection lifetime bound (head + body + write). Covers
/// the v2.2 POST body read whose per-read timeout doesn't cap the total.
const CONN_DEADLINE: Duration = Duration::from_secs(30);
/// Probe-port bind retry (self-heals the MSI-upgrade handover, where
/// the exiting old worker briefly still holds 47989). 15 × 2 s ≈ 30 s
/// of coverage — well past the few-second worker overlap.
const BIND_MAX_ATTEMPTS: u32 = 15;
const BIND_RETRY_DELAY: Duration = Duration::from_secs(2);
/// Cap on the request head we buffer (a browser probe head is ~a few hundred B).
const MAX_HEAD: usize = 16 * 1024;

/// Browser origins allowed to read the descriptor across the public→loopback
/// (Private-Network-Access) boundary. An origin outside this set gets no CORS
/// headers → the browser blocks the read → the probe is a graceful no-op.
const ALLOWED_ORIGINS: &[&str] = &[
    "https://roomler.ai",
    "http://localhost:5000",
    "http://localhost:5173",
];

/// Default-ON (rc.220); `ROOMLERD_LOCAL_TURN=0` (or `false`/`no`/`off`)
/// disables — the DERP-style escape-hatch convention.
pub fn enabled() -> bool {
    !matches!(
        // S2: dual-prefix + config-fallback read (was a direct
        // ROOMLERD_LOCAL_TURN-only env::var).
        tunnel_core::env::node_env("LOCAL_TURN").as_deref(),
        Some("0" | "false" | "no" | "off")
    )
}

/// v2.2 — the loopback CLIPBOARD BRIDGE half (`/rc-clipboard`): lets the
/// roomler.ai page on THIS machine read/write the machine's NATIVE clipboard
/// formats (RTF with embedded images) that no browser API exposes. Default-ON;
/// `ROOMLERD_CLIPBOARD_BRIDGE=0` disables. Only meaningful on builds with
/// the `clipboard` feature — the routes 404 otherwise.
///
/// Trust model (same as the TURN probe): loopback-only bind + strict
/// browser-origin allowlist (CORS/PNA — a foreign page's fetch gets no ACAO
/// header, so the browser blocks the read and preflight-blocks the write) +
/// the fact that any LOCAL process could already read the OS clipboard
/// directly, so no new privilege is exposed to the machine itself.
pub fn bridge_enabled() -> bool {
    cfg!(feature = "clipboard")
        && !matches!(
            tunnel_core::env::node_env("CLIPBOARD_BRIDGE").as_deref(),
            Some("0" | "false" | "no" | "off")
        )
}

/// Spawn the loopback probe server when either half wants it (TURN relay
/// assist and/or the clipboard bridge; each half is route-gated inside).
/// `agent_id` is used as the minted TURN credential's user-id (opaque; the
/// host both mints and validates statelessly).
pub fn spawn(
    overlay_view: watch::Receiver<OverlayView>,
    agent_id: String,
    shutdown: watch::Receiver<bool>,
) {
    if !enabled() && !bridge_enabled() {
        return;
    }
    tokio::spawn(serve(overlay_view, agent_id, shutdown));
}

/// The overlay's currently-assigned self-IP, parsed. `None` until the node has
/// joined a mesh (or in a non-overlay build).
fn overlay_self_ip(view: &watch::Receiver<OverlayView>) -> Option<IpAddr> {
    view.borrow()
        .self_ip
        .as_deref()
        .and_then(|s| s.parse().ok())
}

/// (Re)build `host` to match `want_ip`. Idempotent: unchanged IP ⇒ no-op;
/// a new IP tears down the old host and starts a fresh one bound to `0.0.0.0:0`
/// (so it receives on BOTH loopback and the overlay adapter) with the overlay
/// IP as its relay-candidate address; `None` tears the host down.
async fn reconcile_host(host: &mut Option<LocalTurnHost>, want_ip: Option<IpAddr>, secret: &[u8]) {
    let have = host.as_ref().map(|h| h.relay_ip());
    if want_ip == have {
        return;
    }
    if let Some(old) = host.take() {
        let _ = old.stop().await;
    }
    let Some(ip) = want_ip else {
        info!("loopback-TURN: overlay IP cleared; local TURN host stopped");
        return;
    };
    match LocalTurnHost::start((Ipv4Addr::UNSPECIFIED, 0).into(), ip, secret.to_vec()).await {
        Ok(h) => {
            info!(
                port = h.local_addr().port(),
                relay = %ip,
                "loopback-TURN: local TURN host up on overlay IP"
            );
            *host = Some(h);
        }
        Err(e) => warn!(error = %e, "loopback-TURN: failed to start local TURN host"),
    }
}

/// Main supervisor: serve the loopback probe + keep the TURN host synced to the
/// overlay IP, until shutdown.
async fn serve(
    overlay_view: watch::Receiver<OverlayView>,
    agent_id: String,
    mut shutdown: watch::Receiver<bool>,
) {
    // Bind the FIRST FREE port in the candidate range (rc.232), not a
    // single fixed port. A host can run MORE THAN ONE agent — e.g.
    // DEVBOX's Windows agent + a WSL agent under Win11 mirrored
    // networking, which share the Windows loopback and both want 47989
    // — so a fixed port deadlocks: whoever loses gets "address in use"
    // FOREVER (the earlier bind-retry only covered the transient
    // MSI-upgrade handover, not a persistent co-tenant). Walking the
    // range lets each agent bind a distinct port; the browser probes
    // the whole range and (for the clipboard bridge) gates on the
    // Windows-only capability header, so it naturally skips a WSL
    // agent answering on 47989 and finds the Windows agent on 47990.
    // The outer retry still covers the handover window.
    let listener = {
        let mut bound: Option<TcpListener> = None;
        'retry: for attempt in 1..=BIND_MAX_ATTEMPTS {
            for port in probe_ports() {
                if let Ok(l) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                    if attempt > 1 || port != PROBE_PORT {
                        info!(port, attempt, "loopback probe: bound (range walk)");
                    }
                    bound = Some(l);
                    break 'retry;
                }
            }
            if attempt == BIND_MAX_ATTEMPTS {
                warn!(
                    ports = ?probe_ports().collect::<Vec<_>>(),
                    attempts = attempt,
                    "loopback probe: no free port in the candidate range after retries; disabled"
                );
                break;
            }
            // Whole range busy — wait out the handover, bail on shutdown.
            tokio::select! {
                _ = tokio::time::sleep(BIND_RETRY_DELAY) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
            }
        }
        match bound {
            Some(l) => l,
            None => return,
        }
    };
    let bound_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(PROBE_PORT);
    info!(
        port = bound_port,
        "loopback-TURN: probe on 127.0.0.1 (ROOMLERD_LOCAL_TURN)"
    );

    // Per-run TURN secret (32 random bytes). The host both mints AND validates
    // with it, so it never leaves this process except as an opaque HMAC in the
    // credential handed to the two relay endpoints.
    let secret: Vec<u8> = rand::random::<[u8; 32]>().to_vec();

    let turn_on = enabled();
    let mut overlay_view = overlay_view;
    let mut host: Option<LocalTurnHost> = None;
    if turn_on {
        reconcile_host(&mut host, overlay_self_ip(&overlay_view), &secret).await;
    }

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            changed = overlay_view.changed() => {
                if changed.is_err() {
                    break; // sender dropped — agent is going away
                }
                if turn_on {
                    reconcile_host(&mut host, overlay_self_ip(&overlay_view), &secret).await;
                }
            }
            accept = listener.accept() => {
                let Ok((stream, _peer)) = accept else { continue };
                // Mint fresh creds off the live host and hand the connection an
                // owned descriptor (or None if no overlay yet → 503). No host
                // sharing across tasks.
                let descriptor = host.as_ref().map(|h| {
                    let (username, credential) = h.mint_credentials_now(&agent_id, CRED_TTL);
                    LocalRelayDescriptor {
                        turn_port: h.local_addr().port(),
                        overlay_ip: h.relay_ip().to_string(),
                        username,
                        credential,
                    }
                });
                // Overall per-connection deadline (the per-read timeout
                // alone leaves a dribbling client's lifetime unbounded —
                // it resets on every ≥1-byte read). Bounds a slow-loris
                // even though the port is loopback-only.
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(CONN_DEADLINE, handle_conn(stream, descriptor))
                        .await;
                });
            }
        }
    }

    if let Some(h) = host.take() {
        let _ = h.stop().await;
    }
    info!("loopback-TURN: probe stopped");
}

/// Handle one probe connection: `GET /rc-local-turn` → the descriptor JSON (or
/// 503 with no overlay), `OPTIONS` → the PNA CORS preflight, else 404. Generic
/// over the stream so it's unit-testable over an in-memory duplex.
async fn handle_conn<S>(mut stream: S, descriptor: Option<LocalRelayDescriptor>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((head, leftover)) = read_head(&mut stream).await else {
        return;
    };
    let (verb, path, origin) = parse_request_head(&head);
    let allow = allowed_origin(origin.as_deref());

    let response = match verb.as_str() {
        "OPTIONS" => preflight_response(allow),
        "GET" if path.starts_with("/rc-local-turn") => match &descriptor {
            Some(d) => match serde_json::to_string(d) {
                Ok(body) => json_response(allow, &body),
                Err(_) => status_response(500, "Internal Server Error", allow),
            },
            None => status_response(503, "Service Unavailable", allow),
        },
        // v2.2 — the clipboard bridge. Feature- and env-gated. GET
        // (read) relies on CORS response-blocking for a foreign origin
        // (the body never reaches evil.com); the write path enforces
        // the origin SERVER-SIDE (below) since CORS is client-only.
        "GET" if path.starts_with("/rc-clipboard") => {
            if bridge_enabled() {
                bridge_read_response(allow).await
            } else {
                status_response(404, "Not Found", allow)
            }
        }
        "POST" if path.starts_with("/rc-clipboard") => {
            if !bridge_enabled() {
                status_response(404, "Not Found", allow)
            } else if allow.is_none() {
                // SERVER-SIDE origin enforcement — the write side effect
                // completes before the browser could block the response,
                // and CORS/PNA are client-side. A foreign or absent
                // origin is rejected BEFORE the body is read (no 24 MiB
                // read from a hostile caller) so a `text/plain`
                // simple-request POST from evil.com can't pastejack the
                // local clipboard on a PNA-less browser (Firefox/Safari).
                status_response(403, "Forbidden", None)
            } else if !is_json_content_type(&head) {
                // Require application/json — kills the CORS-safelisted
                // `text/plain` no-preflight bypass even if origin
                // enforcement ever regresses.
                status_response(415, "Unsupported Media Type", allow)
            } else {
                let body = read_body(&mut stream, leftover, content_length(&head)).await;
                bridge_write_response(allow, body).await
            }
        }
        _ => status_response(404, "Not Found", allow),
    };

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// True when the request head declares a JSON body. Tolerant of a
/// `; charset=…` suffix.
fn is_json_content_type(head: &str) -> bool {
    head.lines().any(|l| {
        l.split_once(':').is_some_and(|(name, val)| {
            name.trim().eq_ignore_ascii_case("content-type")
                && val
                    .trim()
                    .to_ascii_lowercase()
                    .starts_with("application/json")
        })
    })
}

/// Read the request head (up to the blank line) with a timeout + size cap.
/// Returns the head text plus any body bytes that arrived in the same reads.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let leftover = buf.split_off(pos + 4);
            return Some((String::from_utf8_lossy(&buf).into_owned(), leftover));
        }
        if buf.len() > MAX_HEAD {
            break;
        }
        let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,        // EOF
            Ok(Ok(n)) => n,            // got bytes
            Ok(Err(_)) => return None, // read error
            Err(_) => return None,     // timeout
        };
        buf.extend_from_slice(&tmp[..n]);
    }
    Some((String::from_utf8_lossy(&buf).into_owned(), Vec::new()))
}

/// v2.2 — cap on a bridge POST body: base64(16 MiB RTF) + JSON overhead.
const MAX_BODY: usize = 24 * 1024 * 1024;

/// The head's Content-Length, when present and sane.
fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|l| {
        let (name, val) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| val.trim().parse::<usize>().ok())
            .flatten()
    })
}

/// Read the remaining POST body (`leftover` already buffered by
/// [`read_head`]) up to Content-Length, bounded by [`MAX_BODY`] + the
/// same read timeout per chunk.
async fn read_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut body: Vec<u8>,
    declared: Option<usize>,
) -> Option<Vec<u8>> {
    let declared = declared?;
    if declared > MAX_BODY {
        return None;
    }
    let mut tmp = [0u8; 16 * 1024];
    while body.len() < declared {
        let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return None,
            Err(_) => return None,
        };
        body.extend_from_slice(&tmp[..n]);
        if body.len() > MAX_BODY {
            return None;
        }
    }
    (body.len() >= declared).then(|| {
        body.truncate(declared);
        body
    })
}

/// Windows-only native-capability marker on the bridge GET response,
/// exposed cross-origin so the browser can tell a native-capable bridge
/// (a `204` = "no RTF on the clipboard right now") from a non-Windows
/// one (a `204` = "never any RTF"). Without it a Linux/macOS viewer of
/// a Windows host would falsely opt into the native lane and the host
/// would stream megabytes of RTF the local bridge can't write.
#[cfg(feature = "clipboard")]
fn bridge_native_headers() -> &'static str {
    if cfg!(windows) {
        "X-Roomler-Clipboard-Native: 1\r\n\
         Access-Control-Expose-Headers: X-Roomler-Clipboard-Native\r\n"
    } else {
        ""
    }
}

/// `GET /rc-clipboard` — the machine's native clipboard as JSON
/// (`NativePayload`: base64 RTF + html + text), 204 when it holds no
/// RTF (the browser's own clipboard API covers the rest). Carries the
/// native-capability header so the probe isn't fooled by a bare 204.
#[cfg(feature = "clipboard")]
async fn bridge_read_response(allow: Option<&str>) -> String {
    let native = bridge_native_headers();
    let Some(cb) = crate::clipboard::Clipboard::shared() else {
        return status_response_ext(503, "Service Unavailable", allow, native);
    };
    match cb.read_native().await {
        Ok(Some(payload)) => match serde_json::to_string(&payload) {
            Ok(body) => json_response_ext(allow, &body, native),
            Err(_) => status_response_ext(500, "Internal Server Error", allow, native),
        },
        Ok(None) => status_response_ext(204, "No Content", allow, native),
        Err(_) => status_response_ext(500, "Internal Server Error", allow, native),
    }
}

#[cfg(not(feature = "clipboard"))]
async fn bridge_read_response(allow: Option<&str>) -> String {
    status_response(404, "Not Found", allow)
}

/// `POST /rc-clipboard` — write the JSON `NativePayload` to the
/// machine's clipboard (RTF + html + text in native formats).
#[cfg(feature = "clipboard")]
async fn bridge_write_response(allow: Option<&str>, body: Option<Vec<u8>>) -> String {
    let Some(body) = body else {
        return status_response(400, "Bad Request", allow);
    };
    let Ok(payload) = serde_json::from_slice::<crate::clipboard::NativePayload>(&body) else {
        return status_response(400, "Bad Request", allow);
    };
    if payload.rtf.is_empty()
        || payload.rtf.len() + payload.html.len() + payload.text.len()
            > crate::clipboard::CLIPBOARD_NATIVE_MAX_BYTES
    {
        return status_response(400, "Bad Request", allow);
    }
    let Some(cb) = crate::clipboard::Clipboard::shared() else {
        return status_response(503, "Service Unavailable", allow);
    };
    match cb.write_native(payload).await {
        Ok(()) => status_response(204, "No Content", allow),
        Err(_) => status_response(500, "Internal Server Error", allow),
    }
}

#[cfg(not(feature = "clipboard"))]
async fn bridge_write_response(allow: Option<&str>, _body: Option<Vec<u8>>) -> String {
    status_response(404, "Not Found", allow)
}

/// Extract `(verb, path, origin)` from a raw request head. Tolerant of garbage
/// (empty verb/path ⇒ the caller answers 404).
fn parse_request_head(head: &str) -> (String, String, Option<String>) {
    let mut lines = head.lines();
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let verb = request.next().unwrap_or("").to_string();
    let path = request.next().unwrap_or("").to_string();
    let origin = head.lines().find_map(|l| {
        let (name, val) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("origin")
            .then(|| val.trim().to_string())
    });
    (verb, path, origin)
}

/// The origin to reflect in `Access-Control-Allow-Origin`, or `None` to emit no
/// CORS headers (an origin outside the allowlist).
fn allowed_origin(origin: Option<&str>) -> Option<&str> {
    origin.filter(|o| ALLOWED_ORIGINS.contains(o))
}

/// CORS + Private-Network-Access headers, emitted only for an allowed origin.
fn cors_headers(allow: Option<&str>) -> String {
    match allow {
        Some(origin) => format!(
            "Access-Control-Allow-Origin: {origin}\r\n\
             Access-Control-Allow-Private-Network: true\r\n\
             Vary: Origin\r\n"
        ),
        None => String::new(),
    }
}

/// Response to the Chrome PNA preflight (`OPTIONS`).
fn preflight_response(allow: Option<&str>) -> String {
    format!(
        "HTTP/1.1 204 No Content\r\n\
         {cors}\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Access-Control-Max-Age: 600\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n",
        cors = cors_headers(allow),
    )
}

/// 200 with a JSON body plus extra response headers (e.g. the bridge's
/// native-capability marker). `extra` must be pre-formatted CRLF header
/// lines or empty.
#[cfg(feature = "clipboard")]
fn json_response_ext(allow: Option<&str>, body: &str, extra: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         {cors}{extra}\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        cors = cors_headers(allow),
        len = body.len(),
    )
}

/// Empty-body status response with extra headers.
#[cfg(feature = "clipboard")]
fn status_response_ext(code: u16, reason: &str, allow: Option<&str>, extra: &str) -> String {
    format!(
        "HTTP/1.1 {code} {reason}\r\n\
         {cors}{extra}\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n",
        cors = cors_headers(allow),
    )
}

/// 200 with the descriptor JSON body.
fn json_response(allow: Option<&str>, body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         {cors}\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        cors = cors_headers(allow),
        len = body.len(),
    )
}

/// Empty-body status response (404 / 503 / 500).
fn status_response(code: u16, reason: &str, allow: Option<&str>) -> String {
    format!(
        "HTTP/1.1 {code} {reason}\r\n\
         {cors}\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n",
        cors = cors_headers(allow),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc() -> LocalRelayDescriptor {
        LocalRelayDescriptor {
            turn_port: 47989,
            overlay_ip: "100.64.0.7".into(),
            username: "1700000600:507f1f77bcf86cd799439012".into(),
            credential: "abcd1234".into(),
        }
    }

    #[test]
    fn allowlist_only_passes_known_origins() {
        assert_eq!(
            allowed_origin(Some("https://roomler.ai")),
            Some("https://roomler.ai")
        );
        assert_eq!(
            allowed_origin(Some("http://localhost:5000")),
            Some("http://localhost:5000")
        );
        assert_eq!(allowed_origin(Some("https://evil.example")), None);
        assert_eq!(allowed_origin(None), None);
    }

    #[test]
    fn parses_verb_path_and_origin() {
        let head = "GET /rc-local-turn HTTP/1.1\r\nHost: 127.0.0.1:47989\r\nOrigin: https://roomler.ai\r\n\r\n";
        let (verb, path, origin) = parse_request_head(head);
        assert_eq!(verb, "GET");
        assert_eq!(path, "/rc-local-turn");
        assert_eq!(origin.as_deref(), Some("https://roomler.ai"));
    }

    #[test]
    fn preflight_carries_pna_header_for_allowed_origin() {
        let r = preflight_response(Some("https://roomler.ai"));
        assert!(r.starts_with("HTTP/1.1 204"));
        assert!(r.contains("Access-Control-Allow-Origin: https://roomler.ai\r\n"));
        assert!(r.contains("Access-Control-Allow-Private-Network: true\r\n"));
        assert!(r.contains("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"));
    }

    #[test]
    fn content_length_parses_case_insensitively_and_rejects_garbage() {
        let head = "POST /rc-clipboard HTTP/1.1\r\ncontent-length: 42\r\n\r\n";
        assert_eq!(content_length(head), Some(42));
        let head = "POST /rc-clipboard HTTP/1.1\r\nContent-Length: nope\r\n\r\n";
        assert_eq!(content_length(head), None);
        assert_eq!(content_length("GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn json_content_type_gate() {
        assert!(is_json_content_type(
            "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
        ));
        // charset suffix + case-insensitive header name.
        assert!(is_json_content_type(
            "POST / HTTP/1.1\r\ncontent-type: application/json; charset=utf-8\r\n\r\n"
        ));
        // The CORS-safelisted simple type an attacker would use to skip
        // preflight must NOT satisfy the gate.
        assert!(!is_json_content_type(
            "POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n"
        ));
        assert!(!is_json_content_type("POST / HTTP/1.1\r\n\r\n"));
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn native_capability_header_is_windows_only() {
        let h = bridge_native_headers();
        #[cfg(windows)]
        {
            assert!(h.contains("X-Roomler-Clipboard-Native: 1"));
            assert!(h.contains("Access-Control-Expose-Headers: X-Roomler-Clipboard-Native"));
        }
        #[cfg(not(windows))]
        assert_eq!(h, "");
    }

    #[cfg(feature = "clipboard")]
    #[test]
    fn status_response_ext_injects_extra_headers() {
        let r = status_response_ext(
            204,
            "No Content",
            Some("https://roomler.ai"),
            "X-Test: 1\r\n",
        );
        assert!(r.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(r.contains("Access-Control-Allow-Origin: https://roomler.ai\r\n"));
        assert!(r.contains("X-Test: 1\r\n"));
        assert!(r.trim_end().ends_with("Connection: close"));
    }

    #[tokio::test]
    async fn read_head_splits_leftover_body_bytes() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let payload = b"POST /rc-clipboard HTTP/1.1\r\nContent-Length: 9\r\n\r\n{\"x\":1}ab";
        tokio::io::AsyncWriteExt::write_all(&mut client, payload)
            .await
            .unwrap();
        drop(client);
        let (head, leftover) = read_head(&mut server).await.unwrap();
        assert!(head.ends_with("\r\n\r\n"));
        assert_eq!(leftover, b"{\"x\":1}ab");
        // read_body completes from the leftover alone.
        let body = read_body(&mut server, leftover, Some(9)).await.unwrap();
        assert_eq!(body, b"{\"x\":1}ab");
    }

    #[tokio::test]
    async fn read_body_rejects_oversized_declarations() {
        let (_client, mut server) = tokio::io::duplex(64);
        assert!(
            read_body(&mut server, Vec::new(), Some(MAX_BODY + 1))
                .await
                .is_none()
        );
        assert!(read_body(&mut server, Vec::new(), None).await.is_none());
    }

    #[test]
    fn preflight_omits_cors_for_unknown_origin() {
        let r = preflight_response(None);
        assert!(r.starts_with("HTTP/1.1 204"));
        assert!(!r.contains("Access-Control-Allow-Origin"));
        assert!(!r.contains("Access-Control-Allow-Private-Network"));
    }

    #[test]
    fn json_response_has_body_and_content_length() {
        let body = serde_json::to_string(&desc()).unwrap();
        let r = json_response(Some("https://roomler.ai"), &body);
        assert!(r.starts_with("HTTP/1.1 200 OK"));
        assert!(r.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(r.contains("Content-Type: application/json"));
        assert!(r.ends_with(&body));
        assert!(r.contains("\"overlay_ip\":\"100.64.0.7\""));
    }

    #[tokio::test]
    async fn handle_conn_get_returns_descriptor_json() {
        let (mut client, server) = tokio::io::duplex(8192);
        let task = tokio::spawn(handle_conn(server, Some(desc())));
        client
            .write_all(b"GET /rc-local-turn HTTP/1.1\r\nOrigin: https://roomler.ai\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        let resp = String::from_utf8_lossy(&out);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
        assert!(resp.contains("Access-Control-Allow-Private-Network: true"));
        assert!(resp.contains("\"turn_port\":47989"));
        assert!(resp.contains("\"overlay_ip\":\"100.64.0.7\""));
    }

    #[tokio::test]
    async fn handle_conn_get_without_host_is_503() {
        let (mut client, server) = tokio::io::duplex(8192);
        let task = tokio::spawn(handle_conn(server, None));
        client
            .write_all(b"GET /rc-local-turn HTTP/1.1\r\nOrigin: https://roomler.ai\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 503"));
    }

    #[tokio::test]
    async fn handle_conn_options_is_pna_preflight() {
        let (mut client, server) = tokio::io::duplex(8192);
        let task = tokio::spawn(handle_conn(server, None));
        client
            .write_all(
                b"OPTIONS /rc-local-turn HTTP/1.1\r\nOrigin: https://roomler.ai\r\n\
                  Access-Control-Request-Private-Network: true\r\n\r\n",
            )
            .await
            .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        let resp = String::from_utf8_lossy(&out);
        assert!(resp.starts_with("HTTP/1.1 204"));
        assert!(resp.contains("Access-Control-Allow-Private-Network: true"));
    }

    #[tokio::test]
    async fn reconcile_starts_and_stops_host_on_overlay_ip() {
        let secret = vec![7u8; 32];
        let mut host: Option<LocalTurnHost> = None;

        // No overlay IP → no host.
        reconcile_host(&mut host, None, &secret).await;
        assert!(host.is_none());

        // Overlay IP assigned → host up on that IP with an ephemeral port.
        let ip: IpAddr = "100.64.0.7".parse().unwrap();
        reconcile_host(&mut host, Some(ip), &secret).await;
        {
            let h = host.as_ref().expect("host started");
            assert_eq!(h.relay_ip(), ip);
            assert_ne!(h.local_addr().port(), 0);
        }

        // Same IP → idempotent (still up, same host).
        let port_before = host.as_ref().unwrap().local_addr().port();
        reconcile_host(&mut host, Some(ip), &secret).await;
        assert_eq!(host.as_ref().unwrap().local_addr().port(), port_before);

        // Overlay IP cleared → host torn down.
        reconcile_host(&mut host, None, &secret).await;
        assert!(host.is_none());
    }

    /// The browser can only reach these ports if the SPA's `Content-Security-
    /// Policy` permits them, and that policy lives in `files/security-headers.conf`,
    /// which `files/nginx-pod.conf` includes (FR-91 moved it there so the blog
    /// lane's server sends the same headers) — a different language, a different
    /// crate, a different deploy artifact. This test is the only thing joining
    /// them, so it also checks the include and the Dockerfile line that installs
    /// the file: a CSP in a file nginx never reads protects nothing.
    ///
    /// It matters because the failure is SILENT. A `fetch` to a CSP-blocked
    /// port does not error visibly: the probe just fails, the viewer falls
    /// back to the far coturn, and nobody notices until somebody measures
    /// relay quality on a corporate network. #242 is the precedent — a CSP
    /// change exercised only against the dashboard broke this exact path in
    /// production.
    ///
    /// The constants here are canonical (`ui/src/composables/useRemoteControl
    /// .ts` mirrors them, locked by its own vitest), so this asserts from the
    /// source of truth outward.
    #[test]
    fn the_deployed_csp_permits_every_port_we_serve_on() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let read = |rel: &str| {
            let p = repo.join(rel);
            std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
        };
        const INSTALLED_AT: &str = "/etc/nginx/snippets/security-headers.conf";
        assert!(
            read("files/nginx-pod.conf")
                .lines()
                .any(|l| l.trim() == format!("include {INSTALLED_AT};")),
            "files/nginx-pod.conf no longer includes {INSTALLED_AT}: the CSP below \
             would not be served at all"
        );
        assert!(
            read("Dockerfile")
                .lines()
                .any(|l| l.trim() == format!("COPY files/security-headers.conf {INSTALLED_AT}")),
            "the Dockerfile no longer installs files/security-headers.conf at {INSTALLED_AT}"
        );
        let conf = read("files/security-headers.conf");

        let csp = conf
            .lines()
            .find(|l| l.contains("add_header Content-Security-Policy"))
            .expect("no Content-Security-Policy in files/security-headers.conf");
        let connect_src = csp
            .split_once("connect-src ")
            .and_then(|(_, rest)| rest.split_once(';'))
            .map(|(v, _)| v)
            .expect("CSP has no connect-src directive");

        for port in probe_ports() {
            for host in ["127.0.0.1", "localhost"] {
                let want = format!("http://{host}:{port}");
                assert!(
                    connect_src.split_whitespace().any(|s| s == want),
                    "files/security-headers.conf connect-src is missing {want}. The loopback \
                     probe to that port would be blocked — silently — and the viewer \
                     would fall back to the far coturn. Change the CSP together with \
                     PROBE_PORT / PROBE_PORT_FALLBACK / PROBE_PORT_BAND here and \
                     LOCAL_RELAY_PROBE_PORTS in the UI.\nconnect-src was: {connect_src}"
                );
            }
        }

        // …and the wildcard must not creep back. Re-adding `127.0.0.1:*` would
        // satisfy every assertion above while handing an XSS on the app's own
        // origin the user's entire loopback again — which is the thing the
        // enumeration exists to prevent, so it has to be asserted separately.
        for wildcard in ["http://127.0.0.1:*", "http://localhost:*"] {
            assert!(
                !connect_src.contains(wildcard),
                "connect-src allows {wildcard} again — the enumeration above exists \
                 to replace exactly that"
            );
        }
    }

    /// FR-52 P4e — the `/connect` page's OPAQUE client is WebAssembly, and a
    /// browser compiles none under a `script-src` without `'wasm-unsafe-eval'`:
    /// drop the keyword and every outsider's login fails before its first
    /// frame, with nothing on the server to say why. And it must stay THAT
    /// keyword: `'unsafe-eval'` would satisfy the WebAssembly compile while
    /// also re-opening JS `eval` to any XSS on the origin.
    ///
    /// The policy lives in `files/security-headers.conf`; that it is the one
    /// served (included by the pod nginx, installed by the Dockerfile) is the
    /// port test's to assert, above.
    #[test]
    fn the_deployed_csp_compiles_webassembly_and_nothing_more() {
        let conf_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../files/security-headers.conf");
        let conf = std::fs::read_to_string(&conf_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", conf_path.display()));
        let csp = conf
            .lines()
            .find(|l| l.contains("add_header Content-Security-Policy"))
            .expect("no Content-Security-Policy in files/security-headers.conf");
        let script_src: Vec<&str> = csp
            .split_once("script-src ")
            .and_then(|(_, rest)| rest.split_once(';'))
            .map(|(v, _)| v.split_whitespace().collect())
            .expect("CSP has no script-src directive");

        assert!(
            script_src.contains(&"'wasm-unsafe-eval'"),
            "script-src lost 'wasm-unsafe-eval' — the /connect page cannot compile its \
             OPAQUE client, so no outsider can log in.\nscript-src was: {script_src:?}"
        );
        assert!(
            !script_src.contains(&"'unsafe-eval'"),
            "script-src allows 'unsafe-eval' — 'wasm-unsafe-eval' is the narrow keyword \
             WebAssembly needs; this one re-opens JS eval.\nscript-src was: {script_src:?}"
        );
    }
}
