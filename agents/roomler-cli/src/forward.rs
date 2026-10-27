// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `meshharbor forward` — open one TCP forward through an enrolled
//! agent. The TeamViewer-shaped flow:
//!
//! 1. WS-connect to `wss://<server>/ws?role=tunnel-client&token=<jwt>`.
//! 2. `rc:tunnel.hello { role: TunnelClient, version, supported_transports }`.
//! 3. `rc:tunnel.open { agent_id, transport: "webrtc-dc-v1" }`.
//!    Wait for `rc:tunnel.opened` → carries `session_id` + `ice_servers`.
//! 4. Build a `TunnelPeer` with those ICE servers. Generate SDP
//!    offer; ship over `rc:sdp.offer { session_id, sdp }`.
//!    Trickle ICE via `rc:ice { session_id, candidate }`.
//! 5. Receive `rc:sdp.answer { session_id, sdp }`; remote-describe.
//!    Wait for the DC pool to fully open.
//! 6. Install `FlowDemux` on each DC.
//! 7. Bind a local TCP listener on `--local`. Per accepted conn:
//!    request a forward, and on Accept pump it over the negotiated
//!    transport.
//!
//! As of P3b-1b the session orchestration lives in
//! [`tunnel_core::driver::run_tunnel_session`], behind the
//! [`tunnel_core::signaling_link`] seam. This module is now the thin CLI:
//! it owns the WebSocket transport (connect, the single outbound-writer
//! task + keepalive, the WS-frame → `ServerMsg` parse), wraps it in
//! [`WsSink`] + [`WsSource`], and drives the reusable driver — plus the
//! auto-reconnect loop + the `--transport auto` WebRTC fallback.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info, warn};
use tunnel_core::driver::{SessionOutcome, SessionParams, Target, run_tunnel_session};
use tunnel_core::signaling_link::{TunnelSignalingSink, TunnelSignalingSource};
use tunnel_core::transport::TRANSPORT_WEBRTC_DC_V1;

use crate::config::{TunnelConfig, derive_ws_url};

/// Re-export so `forward::TransportPref` still resolves for callers
/// (`main.rs`'s clap shim converts into it; `mesh.rs` takes it directly).
/// The type itself now lives in the driver so it's clap-free.
pub use tunnel_core::driver::TransportPref;

/// Buffer depth for the outbound WS channel. Generous — most flow
/// activity is ICE candidate trickle + per-flow Accept replies, both
/// modest. Sized to absorb a burst at session-open without blocking.
const WS_OUT_CHANNEL_DEPTH: usize = 256;

/// How often to send a WebSocket keepalive Ping on the control channel so an
/// idle middlebox (WS proxy / corp full-tunnel VPN) doesn't reap it after
/// ~5 min. Well under any real idle-reap window.
const WS_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(30);

/// Receive-liveness deadline (3 keepalive periods) for the established WS.
/// The server auto-pongs our keepalive Pings, so a healthy link delivers an
/// inbound frame at least every `WS_KEEPALIVE`. Send-success alone proves
/// nothing: a TLS-inspecting corp middlebox (Check Point et al.) terminates
/// TCP locally and keeps ACKing our Pings after its upstream leg has died —
/// field case WINHOST-A 2026-08-02 (agent twin of this loop sat half-open for
/// 45+ min after a server pod roll). `WsSource::recv` treats the deadline as
/// link-gone (`None`), which drives the normal reconnect path.
const WS_RX_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// Auto-reconnect backoff bounds. Start short (a session that ran then dropped
/// usually reconnects instantly) and cap so a persistently-offline agent isn't
/// hammered.
const RECONNECT_BACKOFF_MIN: std::time::Duration = std::time::Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// Read half of the signaling WebSocket. Aliased so [`WsSource`] can name the
/// concrete `SplitStream` it wraps.
type WsReadHalf = futures::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// The CLI's [`TunnelSignalingSink`]: every outbound `ClientMsg` the driver
/// emits is pushed onto the single outbound mpsc a lone writer task drains
/// onto the WS sink (which also emits the keepalive Ping). Funnelling through
/// ONE channel + ONE writer preserves the pre-seam FIFO send ordering — never
/// a shared locked SplitSink.
struct WsSink {
    tx: mpsc::Sender<ClientMsg>,
}

#[async_trait]
impl TunnelSignalingSink for WsSink {
    async fn send(&self, msg: ClientMsg) -> anyhow::Result<()> {
        self.tx
            .send(msg)
            .await
            .map_err(|e| anyhow::anyhow!("outbound WS channel closed: {e}"))
    }
}

/// The CLI's [`TunnelSignalingSource`]: the ONLY place the WS-frame layer
/// lives now. Absorbs Ping/Close/parse so the driver sees a typed `ServerMsg`
/// (lifted from the old `recv_server_msg` + `dispatch_loop`'s frame handling).
/// `None` = the link is gone (Close or a read error).
struct WsSource {
    inner: WsReadHalf,
}

#[async_trait]
impl TunnelSignalingSource for WsSource {
    async fn recv(&mut self) -> Option<ServerMsg> {
        // The timeout IS the receive-liveness check (see `WS_RX_DEADLINE`):
        // a healthy link delivers at least the auto-pongs to our keepalive
        // Pings, so `next()` never legitimately blocks this long. On expiry
        // report link-gone and let the driver reconnect.
        while let Ok(Some(item)) = tokio::time::timeout(WS_RX_DEADLINE, self.inner.next())
            .await
            .map_err(|_| {
                warn!(
                    deadline_s = WS_RX_DEADLINE.as_secs(),
                    "no inbound WS frames within the RX deadline — half-open socket; ending source"
                );
            })
        {
            match item {
                Ok(Message::Text(t)) => match serde_json::from_str::<ServerMsg>(t.as_str()) {
                    Ok(m) => return Some(m),
                    Err(e) => {
                        debug!(%e, text = %t.as_str(), "ignoring non-rc:* / unparseable WS frame");
                        continue;
                    }
                },
                Ok(Message::Close(c)) => {
                    info!(?c, "server closed WS");
                    return None;
                }
                Ok(Message::Ping(d)) => {
                    // tokio-tungstenite auto-pongs; log for diagnostics.
                    debug!(len = d.len(), "ws ping");
                    continue;
                }
                Ok(_) => continue,
                Err(e) => {
                    warn!(%e, "ws read error; ending source");
                    return None;
                }
            }
        }
        None
    }
}

/// `meshharbor forward` — one static local→remote TCP forward.
pub async fn run(
    cfg: TunnelConfig,
    agent_hex: &str,
    local: u16,
    remote: &str,
    transport: TransportPref,
) -> Result<()> {
    let (host, port) = parse_remote(remote)?;
    run_forward(
        cfg,
        agent_hex,
        local,
        Target::Static { host, port },
        transport,
    )
    .await
}

/// `roomler socks5` — the userspace-mode SOCKS5 proxy. Same transport +
/// server policy + agent allowlist as a static forward; the destination is taken
/// from each connection's SOCKS5 CONNECT instead of a fixed `--remote`.
pub async fn run_socks5(
    cfg: TunnelConfig,
    agent_hex: &str,
    local: u16,
    transport: TransportPref,
) -> Result<()> {
    run_forward(cfg, agent_hex, local, Target::Socks5, transport).await
}

/// Shared driver for `forward` (static target) and `socks5` (per-connection
/// target). Runs sessions in an **auto-reconnect loop**: each session serves
/// local TCP connections until its WS control channel drops (idle-reap by a WS
/// proxy / corp VPN, a network blip, a VPN reconnect), then re-establishes with
/// backoff. Ctrl-C kills the process, which ends the loop.
async fn run_forward(
    cfg: TunnelConfig,
    agent_hex: &str,
    local: u16,
    target: Target,
    transport: TransportPref,
) -> Result<()> {
    let agent_id = ObjectId::parse_str(agent_hex)
        .with_context(|| format!("--agent must be a 24-hex ObjectId, got {agent_hex}"))?;

    info!(
        server = %cfg.server_url,
        agent = %agent_id,
        local,
        ?target,
        ?transport,
        "meshharbor forward starting"
    );

    let mut backoff = RECONNECT_BACKOFF_MIN;
    loop {
        match run_one_session(&cfg, agent_id, local, &target, transport).await {
            // A session that established then dropped resets the backoff so the
            // reconnect is near-instant; a repeated setup failure grows it.
            Ok(()) => {
                info!("tunnel session ended; reconnecting");
                backoff = RECONNECT_BACKOFF_MIN;
            }
            Err(e) => {
                warn!(%e, backoff_s = backoff.as_secs(), "tunnel session failed; retrying");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// One session attempt: request the preferred transport (Auto → QUIC →
/// WebRTC-DC fallback) and serve local TCP connections until the control
/// channel drops. Returns `Ok(())` when a session ran and ended (→ reconnect),
/// `Err` on a setup failure (→ backoff + retry).
async fn run_one_session(
    cfg: &TunnelConfig,
    agent_id: ObjectId,
    local: u16,
    target: &Target,
    transport: TransportPref,
) -> Result<()> {
    let outcome = run_session(
        cfg,
        agent_id,
        local,
        target,
        transport.supported_transports(),
        transport.request_transport(),
    )
    .await?;
    if matches!(outcome, SessionOutcome::QuicSetupFailed) {
        if transport == TransportPref::Auto {
            warn!("QUIC transport setup failed; re-opening session forcing webrtc-dc-v1");
            let fallback = run_session(
                cfg,
                agent_id,
                local,
                target,
                vec![TRANSPORT_WEBRTC_DC_V1.to_string()],
                TRANSPORT_WEBRTC_DC_V1,
            )
            .await?;
            if matches!(fallback, SessionOutcome::QuicSetupFailed) {
                bail!("webrtc-dc-v1 fallback unexpectedly reported QUIC-setup-failed");
            }
        } else {
            bail!("QUIC transport setup failed and --transport={transport:?} forbids fallback");
        }
    }
    Ok(())
}

/// Connect a fresh WS, build the [`TunnelSignalingSink`] + [`TunnelSignalingSource`]
/// seam over it, and drive [`run_tunnel_session`]. This is the CLI's transport
/// glue: the driver owns the protocol; this owns the WebSocket.
async fn run_session(
    cfg: &TunnelConfig,
    agent_id: ObjectId,
    local: u16,
    target: &Target,
    supported_transports: Vec<String>,
    request_transport: &str,
) -> Result<SessionOutcome> {
    // ────────────── WS connect ─────────────────────────────────────
    let ws_base = derive_ws_url(&cfg.server_url)?;
    // S6 — `tid` = tenant-affinity hint for the front LB (co-locates
    // this tunnel client with its tenant's agents on one pod; the
    // tunnel-hub is pod-local). Extracted from our own JWT; the server
    // re-validates against the verified claims, and pre-S6 servers
    // ignore the param.
    let tid_param = tenant_id_from_jwt(&cfg.tunnel_client_token)
        .map(|t| format!("&tid={t}"))
        .unwrap_or_default();
    let ws_url = format!(
        "{ws_base}?role=tunnel-client&token={}{tid_param}",
        urlencoding_lite(&cfg.tunnel_client_token)
    );
    info!(%ws_base, "connecting websocket");
    let (ws_stream, _resp) = connect_async(&ws_url)
        .await
        .with_context(|| format!("WS connect to {ws_base}"))?;
    info!("websocket connected");
    let (mut ws_sink, ws_source) = ws_stream.split();

    // Outbound channel — any task pushes ClientMsg here; a single
    // task drains it onto the WS sink.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<ClientMsg>(WS_OUT_CHANNEL_DEPTH);

    let _sender_task = tokio::spawn(async move {
        // Keepalive so an idle middlebox (our nginx/HAProxy WS proxy, or a corp
        // full-tunnel VPN like Check Point) doesn't reap the control channel
        // after ~5 min of silence. Post-setup the data plane rides QUIC/DC and
        // the WS goes quiet, so without this the next SOCKS/forward connection —
        // which needs the WS to carry TcpForwardRequest — fails against a dead
        // socket. A protocol-level Ping needs no server change (axum auto-pongs).
        let mut keepalive = tokio::time::interval(WS_KEEPALIVE);
        keepalive.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                maybe = outbound_rx.recv() => {
                    let Some(msg) = maybe else { break };
                    let json = match serde_json::to_string(&msg) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(%e, "outbound serialise failed");
                            continue;
                        }
                    };
                    if let Err(e) = ws_sink.send(Message::text(json)).await {
                        warn!(%e, "outbound WS send failed; dropping");
                        break;
                    }
                }
                _ = keepalive.tick() => {
                    if let Err(e) = ws_sink.send(Message::Ping(Vec::new().into())).await {
                        warn!(%e, "WS keepalive ping failed; sender exiting");
                        break;
                    }
                }
            }
        }
        debug!("outbound WS task exiting");
    });

    let sink: Arc<dyn TunnelSignalingSink> = Arc::new(WsSink { tx: outbound_tx });
    let source: Box<dyn TunnelSignalingSource> = Box::new(WsSource { inner: ws_source });

    run_tunnel_session(
        sink,
        source,
        local,
        SessionParams {
            agent_id,
            target: target.clone(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            // R4: the standalone CLI is not an overlay node — no DERP
            // identity, no derp tunnel flavor; the classic ladder stands.
            derp: None,
            // #1685: one forward per process and no liveness state to
            // publish — the daemon's route reconciler is the consumer.
            on_listening: None,
            // FR-90 P3-7-3a: a person's own tunnel, never a session's grant.
            net_grant: None,
        },
        supported_transports,
        request_transport,
        // The standalone CLI has one forward per process and doesn't surface a
        // `flows` table — a throwaway aggregate (P3b-3); the daemon owns the
        // real one.
        Arc::new(tunnel_core::forward::SessionThroughput::default()),
    )
    .await
}

/// Parse a `host:port` string. Robust to bracketed IPv6 (`[::1]:80`).
pub(crate) fn parse_remote(s: &str) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6: `[addr]:port`
        let close = rest
            .find(']')
            .with_context(|| format!("--remote with `[` must close with `]:port`: {s}"))?;
        let host = &rest[..close];
        let port_str = rest[close + 1..]
            .strip_prefix(':')
            .with_context(|| format!("missing `:port` after `]`: {s}"))?;
        let port = port_str
            .parse()
            .with_context(|| format!("invalid port {port_str}"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port_str) = s
        .rsplit_once(':')
        .with_context(|| format!("--remote must be host:port, got {s}"))?;
    if host.is_empty() {
        bail!("--remote host must not be empty");
    }
    let port = port_str
        .parse()
        .with_context(|| format!("invalid port {port_str}"))?;
    Ok((host.to_string(), port))
}

/// S6 — best-effort extraction of the `tenant_id` claim from OUR OWN
/// JWT, used only as the LB affinity hint (`tid=`). No signature check:
/// the server re-validates the hint against the VERIFIED claims and
/// rejects a mismatch, so a garbled value can only mis-route, never
/// escalate. Returns `None` on any parse hiccup (param simply omitted;
/// the LB then pins the connection to the legacy pod).
fn tenant_id_from_jwt(token: &str) -> Option<String> {
    use base64::Engine as _;
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    // Only forward a plausible ObjectId hex — anything else would just
    // 403 at the server.
    let t = v.get("tenant_id")?.as_str()?;
    if t.len() == 24 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(t.to_string())
    } else {
        None
    }
}

/// Tiny URL-encoder for the JWT in the query string. We only need
/// to escape characters that appear in JWTs (`.`, `-`, `_` are safe
/// per JWT spec; we just guard against future drift). Avoids pulling
/// the `url` crate just for this.
fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_simple() {
        let (h, p) = parse_remote("db.intranet:5432").unwrap();
        assert_eq!(h, "db.intranet");
        assert_eq!(p, 5432);
    }

    #[test]
    fn parse_remote_ipv4() {
        let (h, p) = parse_remote("10.0.0.5:1521").unwrap();
        assert_eq!(h, "10.0.0.5");
        assert_eq!(p, 1521);
    }

    #[test]
    fn parse_remote_ipv6_bracketed() {
        let (h, p) = parse_remote("[::1]:5432").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 5432);
    }

    #[test]
    fn parse_remote_ipv6_with_zone_id() {
        let (h, p) = parse_remote("[fe80::1%eth0]:22").unwrap();
        assert_eq!(h, "fe80::1%eth0");
        assert_eq!(p, 22);
    }

    #[test]
    fn parse_remote_rejects_missing_port() {
        let err = parse_remote("db.intranet").unwrap_err();
        assert!(err.to_string().contains("host:port"));
    }

    #[test]
    fn parse_remote_rejects_empty_host() {
        let err = parse_remote(":5432").unwrap_err();
        assert!(err.to_string().contains("host must not be empty"));
    }

    #[test]
    fn parse_remote_rejects_invalid_port() {
        assert!(parse_remote("db.intranet:notaport").is_err());
        assert!(parse_remote("db.intranet:99999").is_err()); // u16 overflow
    }

    #[test]
    fn urlencoding_lite_preserves_jwt_chars() {
        // JWT chars are A-Z a-z 0-9 . - _ — none should be encoded.
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.payload.sig-with_under";
        assert_eq!(urlencoding_lite(jwt), jwt);
    }

    #[test]
    fn urlencoding_lite_encodes_space() {
        assert_eq!(urlencoding_lite("a b"), "a%20b");
    }

    fn fake_jwt(payload_json: &str) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.sig",
            b64.encode(r#"{"alg":"HS256"}"#),
            b64.encode(payload_json)
        )
    }

    #[test]
    fn tenant_id_from_jwt_extracts_hex_oid() {
        let jwt = fake_jwt(r#"{"sub":"x","tenant_id":"64b1f0aa12cd34ef56ab78cd"}"#);
        assert_eq!(
            tenant_id_from_jwt(&jwt).as_deref(),
            Some("64b1f0aa12cd34ef56ab78cd")
        );
    }

    #[test]
    fn tenant_id_from_jwt_rejects_non_oid_and_garbage() {
        // Non-hex / wrong length values are dropped (would 403 server-side).
        let jwt = fake_jwt(r#"{"tenant_id":"not-an-object-id"}"#);
        assert_eq!(tenant_id_from_jwt(&jwt), None);
        // Missing claim.
        let jwt2 = fake_jwt(r#"{"sub":"x"}"#);
        assert_eq!(tenant_id_from_jwt(&jwt2), None);
        // Not a JWT at all.
        assert_eq!(tenant_id_from_jwt("hello"), None);
    }
}

/// Adapter for the explicit share endpoint. The existing tunnel driver still
/// owns SDP/ICE/DC/flow pumping; only its one static TCP request becomes a typed
/// embedded-SSH open. No arbitrary destination is ever sent to the share route.
struct SharedSshSink {
    tx: mpsc::Sender<ClientMsg>,
}
#[async_trait]
impl TunnelSignalingSink for SharedSshSink {
    async fn send(&self, msg: ClientMsg) -> anyhow::Result<()> {
        let msg = match msg {
            ClientMsg::TcpForwardRequest {
                session_id,
                flow_id,
                dst_host,
                dst_port,
            } if dst_host == "embedded-ssh" && dst_port == 22 => ClientMsg::SharedSshConnect {
                session_id,
                flow_id,
            },
            other @ (ClientMsg::TunnelHello { .. }
            | ClientMsg::TunnelOpen { .. }
            | ClientMsg::TunnelSdpOffer { .. }
            | ClientMsg::TunnelIce { .. }
            | ClientMsg::TcpHalfClose { .. }
            | ClientMsg::TcpClosed { .. }
            | ClientMsg::TunnelTerminate { .. }) => other,
            _ => anyhow::bail!("shared SSH transport cannot request another service"),
        };
        self.tx
            .send(msg)
            .await
            .context("shared SSH signaling channel closed")
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn run_shared_ssh_transport(
    server: String,
    token: String,
    share: ObjectId,
    public_key: String,
    session_secs: u64,
    agent: ObjectId,
    ready: tunnel_core::driver::ListeningHook,
) -> Result<SessionOutcome> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let ws = derive_ws_url(&server)?;
    let base = ws
        .strip_suffix("/ws")
        .context("server WS URL must end in /ws")?;
    let url = format!(
        "{base}/api/device-shares/{share}/ssh/ws?public_key={}&session_secs={session_secs}",
        urlencoding_lite(&public_key)
    );
    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse()?);
    let (socket, _) =
        tokio::time::timeout(std::time::Duration::from_secs(8), connect_async(request))
            .await
            .context("shared SSH WS connect timeout")?
            .context("shared SSH WS authorization")?;
    let (mut writer, reader) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ClientMsg>(64);
    struct AbortWriter(tokio::task::JoinHandle<()>);
    impl Drop for AbortWriter {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _writer = AbortWriter(tokio::spawn(async move {
        let mut keepalive = tokio::time::interval(WS_KEEPALIVE);
        keepalive.tick().await;
        loop {
            tokio::select! {
                msg=rx.recv()=>{let Some(msg)=msg else {break;};let Ok(text)=serde_json::to_string(&msg) else {break;};if !matches!(tokio::time::timeout(std::time::Duration::from_secs(3),writer.send(Message::Text(text.into()))).await,Ok(Ok(()))){break;}},
                _=keepalive.tick()=>{if !matches!(tokio::time::timeout(std::time::Duration::from_secs(3),writer.send(Message::Ping(Vec::new().into()))).await,Ok(Ok(()))){break;}},
            }
        }
    }));
    run_tunnel_session(
        Arc::new(SharedSshSink { tx }),
        Box::new(WsSource { inner: reader }),
        0,
        SessionParams {
            agent_id: agent,
            target: Target::Static {
                host: "embedded-ssh".into(),
                port: 22,
            },
            client_version: env!("CARGO_PKG_VERSION").into(),
            derp: None,
            on_listening: Some(ready),
            net_grant: None,
        },
        vec![TRANSPORT_WEBRTC_DC_V1.into()],
        TRANSPORT_WEBRTC_DC_V1.into(),
        Arc::new(tunnel_core::forward::SessionThroughput::default()),
    )
    .await
}
#[cfg(test)]
mod shared_ssh_sink_tests {
    use super::*;
    #[tokio::test]
    async fn shared_ssh_driver_sink_maps_only_typed_service_and_refuses_other_destinations() {
        let (tx, mut rx) = mpsc::channel(8);
        let sink = SharedSshSink { tx };
        let sid = ObjectId::new();
        sink.send(ClientMsg::TcpForwardRequest {
            session_id: sid,
            flow_id: 7,
            dst_host: "embedded-ssh".into(),
            dst_port: 22,
        })
        .await
        .unwrap();
        assert!(
            matches!(rx.recv().await.unwrap(),ClientMsg::SharedSshConnect {session_id,flow_id:7} if session_id==sid)
        );
        assert!(
            sink.send(ClientMsg::TcpForwardRequest {
                session_id: sid,
                flow_id: 8,
                dst_host: "127.0.0.1".into(),
                dst_port: 22
            })
            .await
            .is_err()
        );
        assert!(rx.try_recv().is_err());
    }
}
