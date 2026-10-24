// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Agent-side handler for one inbound `ServerMsg::TcpForwardForward`.
//!
//! Splits into two steps so the policy + dial logic stays unit-
//! testable without spinning up a real `AgentTunnelPeer`:
//!
//! 1. [`decide_forward`] applies the agent-local [`AgentForwardAcl`]
//!    then dials dst with a bounded timeout. Returns either the open
//!    `TcpStream` (caller pipes it into the DC) or a typed
//!    `TcpForwardReject` to be shipped over the WS.
//! 2. [`handle_forward_request`] wires the decision into the data
//!    plane: registers the flow on the right `FlowDemux`, replies
//!    `TcpForwardAccept`, spawns `tunnel_core::forward::run_flow`,
//!    and on close cleans the flow + emits `TcpClosed` for audit.

use std::sync::Arc;
use std::time::Duration;

use bson::oid::ObjectId;
use roomler_ai_remote_control::signaling::{ClientMsg, CloseReason, RejectKind};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::acl::{AclDecision, AgentForwardAcl};
use super::dialer::{DialError, dial_dst, dial_udp};
use super::peer::AgentTunnelPeer;
use super::quic_peer::AgentQuicPeer;
use tunnel_core::policy::ProtocolKind;

/// Cap on how long we'll wait for the DC pool to finish opening
/// before bailing on a forward request. The pool usually opens
/// within seconds of `TunnelSdpOffer`; this only fires when a
/// forward arrives suspiciously early or the peer connection
/// stalled.
const POOL_READY_WAIT: Duration = Duration::from_secs(10);

/// `quic-v1` analogue of [`POOL_READY_WAIT`]: how long the agent waits
/// for the client to open the QUIC flow stream after the agent replies
/// `TcpForwardAccept`. The client opens it immediately on receipt of
/// the Accept, so this only fires when the client died in that window
/// or the QUIC connection stalled — bounded so a dialed dst socket
/// can't leak waiting for a stream that never comes.
const FLOW_RENDEZVOUS_WAIT: Duration = Duration::from_secs(10);

/// Policy + dial layer. Pure decision logic, no peer interaction —
/// keeps the unit tests self-contained.
pub async fn decide_forward(
    session_id: ObjectId,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
    acl: &AgentForwardAcl,
    dial_timeout: Duration,
) -> Result<TcpStream, ClientMsg> {
    if let AclDecision::Reject { reason } =
        acl.check(dst_host, dst_port, tunnel_core::policy::ProtocolKind::Tcp)
    {
        info!(
            %session_id, %flow_id, %dst_host, %dst_port, %reason,
            "agent ACL rejected forward"
        );
        return Err(ClientMsg::TcpForwardReject {
            session_id,
            flow_id,
            kind: RejectKind::AclDenied,
            reason: format!("agent: {reason}"),
        });
    }
    match dial_dst(dst_host, dst_port, dial_timeout).await {
        Ok(stream) => {
            debug!(
                %session_id, %flow_id, %dst_host, %dst_port,
                peer = ?stream.peer_addr().ok(),
                "agent dialed dst; preparing flow"
            );
            Ok(stream)
        }
        Err(DialError::Timeout(d)) => {
            warn!(%session_id, %flow_id, %dst_host, %dst_port, ?d, "dial timeout");
            Err(ClientMsg::TcpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::DialFailed,
                reason: format!("dial timed out after {d:?}"),
            })
        }
        Err(DialError::Io(e)) => {
            warn!(%session_id, %flow_id, %dst_host, %dst_port, %e, "dial failed");
            Err(ClientMsg::TcpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::DialFailed,
                reason: format!("dial: {e}"),
            })
        }
    }
}

/// End-to-end driver for one `TcpForwardForward`. Decides, dials,
/// wires the flow into the DC pool, and runs the bidirectional pump
/// to completion. Sends `TcpForwardAccept` / `Reject` and the final
/// `TcpClosed` audit message itself via `outbound`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_forward_request(
    session_id: ObjectId,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
    acl: &AgentForwardAcl,
    dial_timeout: Duration,
    tunnel_peer: &Arc<AgentTunnelPeer>,
    outbound: mpsc::Sender<ClientMsg>,
) {
    let stream =
        match decide_forward(session_id, flow_id, dst_host, dst_port, acl, dial_timeout).await {
            Ok(s) => s,
            Err(reject) => {
                let _ = outbound.send(reject).await;
                return;
            }
        };

    handle_preopened_forward(session_id, flow_id, stream, tunnel_peer, outbound).await;
}
/// Existing DC/flow pump, also used by the typed embedded-SSH socketpair. This
/// function accepts an already-open stream, never a new host/port authority.
pub(crate) async fn handle_preopened_forward(
    session_id: ObjectId,
    flow_id: u32,
    stream: TcpStream,
    tunnel_peer: &Arc<AgentTunnelPeer>,
    outbound: mpsc::Sender<ClientMsg>,
) {
    // Make sure the DC pool is fully open before assigning a channel.
    // Under normal operation the SDP/ICE handshake finishes long
    // before the first flow request, so this resolves immediately.
    if !tunnel_peer.wait_pool_ready(POOL_READY_WAIT).await {
        warn!(%session_id, %flow_id, "DC pool not ready within budget — rejecting");
        let _ = outbound
            .send(ClientMsg::TcpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::AgentError,
                reason: "DC pool not ready on agent".into(),
            })
            .await;
        return;
    }

    let pool_size = tunnel_peer.pool_size().await;
    if pool_size == 0 {
        let _ = outbound
            .send(ClientMsg::TcpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::AgentError,
                reason: "empty DC pool on agent".into(),
            })
            .await;
        return;
    }
    let dc_index = (flow_id % pool_size as u32) as u8;
    let Some(demux) = tunnel_peer.demux(dc_index).await else {
        let _ = outbound
            .send(ClientMsg::TcpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::AgentError,
                reason: format!("demux missing for dc_index={dc_index}"),
            })
            .await;
        return;
    };

    let (from_dc, stats) = demux.register(flow_id).await;
    let dc = demux.dc();

    // Accept the flow + start pumping.
    if let Err(e) = outbound
        .send(ClientMsg::TcpForwardAccept {
            session_id,
            flow_id,
            dc_index,
        })
        .await
    {
        debug!(%session_id, %flow_id, %e, "TcpForwardAccept send failed (channel closed)");
        demux.unregister(flow_id).await;
        return;
    }

    let half_close = tunnel_peer.half_close_sink(outbound.clone());
    // #2129 — hand this flow the peer's cancel handle so a teardown
    // (`AgentTunnelPeer::close`) ends it even if the dst is idle.
    let cancel = tunnel_peer.flow_cancel();
    // Wave 3 — report this end's totals too. The server audits only the
    // ORIGINATOR's close (booking both would double every flow), but an
    // end that CAN count must not put a false zero on the wire.
    let stats_for_audit = Arc::clone(&stats);
    let close_reason =
        tunnel_core::forward::run_flow(stream, dc, flow_id, from_dc, half_close, stats, cancel)
            .await;
    demux.unregister(flow_id).await;
    info!(%session_id, %flow_id, ?close_reason, "agent flow ended");
    let (tcp_read, _dc_send, _dc_recv, tcp_write, _depth) = stats_for_audit.snapshot();
    let _ = outbound
        .send(ClientMsg::TcpClosed {
            session_id,
            flow_id,
            reason: close_reason,
            // Local side here is the DESTINATION service, so `in` is what
            // arrived from the tunnel client and went to the dst.
            bytes_in: tcp_write,
            bytes_out: tcp_read,
        })
        .await;
}

/// `quic-v1` analogue of [`handle_forward_request`]. The QUIC data
/// plane has no DC pool — each flow is a native QUIC bidirectional
/// stream — so the WebRTC ceremony (`wait_pool_ready` / `pool_size` /
/// `demux.register`) collapses to: decide + dial, reply
/// `TcpForwardAccept`, grab the client-opened flow stream from the
/// peer's rendezvous, then drive [`tunnel_core::forward::run_flow_quic`].
///
/// Ordering: we send `TcpForwardAccept` BEFORE awaiting the stream,
/// because the client opens its QUIC stream only after it sees the
/// Accept. [`AgentQuicPeer::take_flow`] is order-independent (it
/// stashes a stream that beats the waiter), so the window between the
/// send and the await can't drop the flow.
#[allow(clippy::too_many_arguments)]
pub async fn handle_forward_request_quic(
    session_id: ObjectId,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
    acl: &AgentForwardAcl,
    dial_timeout: Duration,
    quic_peer: &Arc<AgentQuicPeer>,
    outbound: mpsc::Sender<ClientMsg>,
) {
    let stream =
        match decide_forward(session_id, flow_id, dst_host, dst_port, acl, dial_timeout).await {
            Ok(s) => s,
            Err(reject) => {
                let _ = outbound.send(reject).await;
                return;
            }
        };

    // Accept first — the client opens its QUIC flow stream in
    // response. `dc_index` is meaningless for QUIC (no pool); send 0
    // for wire-compat with the shared `TcpForwardAccept` shape.
    if let Err(e) = outbound
        .send(ClientMsg::TcpForwardAccept {
            session_id,
            flow_id,
            dc_index: 0,
        })
        .await
    {
        debug!(%session_id, %flow_id, %e, "TcpForwardAccept send failed (channel closed)");
        return;
    }

    // Grab the client-opened flow stream from the rendezvous. Times
    // out if the client never opens it (died right after Accept, QUIC
    // path stalled) so the dialed dst socket doesn't leak.
    let (send, recv) = match quic_peer.take_flow(flow_id, FLOW_RENDEZVOUS_WAIT).await {
        Ok(streams) => streams,
        Err(e) => {
            warn!(%session_id, %flow_id, %e, "QUIC flow stream never opened — closing dst");
            let _ = outbound
                .send(ClientMsg::TcpClosed {
                    session_id,
                    flow_id,
                    reason: CloseReason::IoError,
                    // No flow ever ran, so zero is the measured truth here
                    // rather than a stand-in for "unknown".
                    bytes_in: 0,
                    bytes_out: 0,
                })
                .await;
            return;
        }
    };

    let stats = Arc::new(tunnel_core::forward::FlowStats::default());
    let stats_for_audit = Arc::clone(&stats);
    let close_reason =
        tunnel_core::forward::run_flow_quic(stream, send, recv, flow_id, stats).await;
    info!(%session_id, %flow_id, ?close_reason, "agent QUIC flow ended");
    let (tcp_read, _dc_send, _dc_recv, tcp_write, _depth) = stats_for_audit.snapshot();
    let _ = outbound
        .send(ClientMsg::TcpClosed {
            session_id,
            flow_id,
            reason: close_reason,
            bytes_in: tcp_write,
            bytes_out: tcp_read,
        })
        .await;
}

// ────────────────────────────────────────────────────────────────────────────
// UDP ASSOCIATE — agent side (mirror of the TCP handlers above)
// ────────────────────────────────────────────────────────────────────────────

/// UDP analogue of [`decide_forward`]: agent-local ACL (`proto = udp`)
/// then bind + `connect()` a UDP socket to the target. Returns the
/// connected socket or a typed [`ClientMsg::UdpForwardReject`].
pub async fn decide_forward_udp(
    session_id: ObjectId,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
    acl: &AgentForwardAcl,
    dial_timeout: Duration,
) -> Result<tokio::net::UdpSocket, ClientMsg> {
    if let AclDecision::Reject { reason } = acl.check(dst_host, dst_port, ProtocolKind::Udp) {
        info!(
            %session_id, %flow_id, %dst_host, %dst_port, %reason,
            "agent ACL rejected UDP forward"
        );
        return Err(ClientMsg::UdpForwardReject {
            session_id,
            flow_id,
            kind: RejectKind::AclDenied,
            reason: format!("agent: {reason}"),
        });
    }
    match dial_udp(dst_host, dst_port, dial_timeout).await {
        Ok(sock) => {
            debug!(%session_id, %flow_id, %dst_host, %dst_port, "agent bound UDP socket for flow");
            Ok(sock)
        }
        Err(DialError::Timeout(d)) => {
            warn!(%session_id, %flow_id, %dst_host, %dst_port, ?d, "udp resolve timeout");
            Err(ClientMsg::UdpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::DialFailed,
                reason: format!("udp resolve timed out after {d:?}"),
            })
        }
        Err(DialError::Io(e)) => {
            warn!(%session_id, %flow_id, %dst_host, %dst_port, %e, "udp bind/connect failed");
            Err(ClientMsg::UdpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::DialFailed,
                reason: format!("udp: {e}"),
            })
        }
    }
}

/// UDP analogue of [`handle_forward_request`] (WebRTC-DC data plane).
/// Decides + binds the target socket, registers the flow on the DC
/// pool, replies `UdpForwardAccept`, pumps datagrams via
/// [`tunnel_core::forward::run_flow_udp_dc`], then emits `UdpClosed`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_udp_forward_request(
    session_id: ObjectId,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
    acl: &AgentForwardAcl,
    dial_timeout: Duration,
    tunnel_peer: &Arc<AgentTunnelPeer>,
    outbound: mpsc::Sender<ClientMsg>,
) {
    let udp = match decide_forward_udp(session_id, flow_id, dst_host, dst_port, acl, dial_timeout)
        .await
    {
        Ok(s) => s,
        Err(reject) => {
            let _ = outbound.send(reject).await;
            return;
        }
    };

    if !tunnel_peer.wait_pool_ready(POOL_READY_WAIT).await {
        warn!(%session_id, %flow_id, "DC pool not ready within budget — rejecting UDP");
        let _ = outbound
            .send(ClientMsg::UdpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::AgentError,
                reason: "DC pool not ready on agent".into(),
            })
            .await;
        return;
    }
    let pool_size = tunnel_peer.pool_size().await;
    if pool_size == 0 {
        let _ = outbound
            .send(ClientMsg::UdpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::AgentError,
                reason: "empty DC pool on agent".into(),
            })
            .await;
        return;
    }
    let dc_index = (flow_id % pool_size as u32) as u8;
    let Some(demux) = tunnel_peer.demux(dc_index).await else {
        let _ = outbound
            .send(ClientMsg::UdpForwardReject {
                session_id,
                flow_id,
                kind: RejectKind::AgentError,
                reason: format!("demux missing for dc_index={dc_index}"),
            })
            .await;
        return;
    };

    let (from_dc, stats) = demux.register(flow_id).await;
    let dc = demux.dc();

    if let Err(e) = outbound
        .send(ClientMsg::UdpForwardAccept {
            session_id,
            flow_id,
            dc_index,
        })
        .await
    {
        debug!(%session_id, %flow_id, %e, "UdpForwardAccept send failed (channel closed)");
        demux.unregister(flow_id).await;
        return;
    }

    let close_reason = tunnel_core::forward::run_flow_udp_dc(
        udp,
        dc,
        flow_id,
        from_dc,
        tunnel_core::forward::UDP_FLOW_IDLE_TIMEOUT,
        stats,
    )
    .await;
    demux.unregister(flow_id).await;
    info!(%session_id, %flow_id, ?close_reason, "agent UDP flow ended");
    let _ = outbound
        .send(ClientMsg::UdpClosed {
            session_id,
            flow_id,
            reason: close_reason,
        })
        .await;
}

/// UDP analogue of [`handle_forward_request_quic`]. Decides + binds the
/// target socket, replies `UdpForwardAccept` (dc_index 0), rendezvouses
/// the client-opened QUIC flow stream, then pumps datagrams via
/// [`tunnel_core::forward::run_flow_udp_quic`].
#[allow(clippy::too_many_arguments)]
pub async fn handle_udp_forward_request_quic(
    session_id: ObjectId,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
    acl: &AgentForwardAcl,
    dial_timeout: Duration,
    quic_peer: &Arc<AgentQuicPeer>,
    outbound: mpsc::Sender<ClientMsg>,
) {
    let udp = match decide_forward_udp(session_id, flow_id, dst_host, dst_port, acl, dial_timeout)
        .await
    {
        Ok(s) => s,
        Err(reject) => {
            let _ = outbound.send(reject).await;
            return;
        }
    };

    if let Err(e) = outbound
        .send(ClientMsg::UdpForwardAccept {
            session_id,
            flow_id,
            dc_index: 0,
        })
        .await
    {
        debug!(%session_id, %flow_id, %e, "UdpForwardAccept send failed (channel closed)");
        return;
    }

    let (send, recv) = match quic_peer.take_flow(flow_id, FLOW_RENDEZVOUS_WAIT).await {
        Ok(streams) => streams,
        Err(e) => {
            warn!(%session_id, %flow_id, %e, "QUIC UDP flow stream never opened — closing socket");
            let _ = outbound
                .send(ClientMsg::UdpClosed {
                    session_id,
                    flow_id,
                    reason: CloseReason::IoError,
                })
                .await;
            return;
        }
    };

    let stats = Arc::new(tunnel_core::forward::FlowStats::default());
    let close_reason = tunnel_core::forward::run_flow_udp_quic(
        udp,
        send,
        recv,
        flow_id,
        tunnel_core::forward::UDP_FLOW_IDLE_TIMEOUT,
        stats,
    )
    .await;
    info!(%session_id, %flow_id, ?close_reason, "agent QUIC UDP flow ended");
    let _ = outbound
        .send(ClientMsg::UdpClosed {
            session_id,
            flow_id,
            reason: close_reason,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_core::policy::{DestinationRule, HostPattern, PortRange};

    #[tokio::test]
    async fn agent_disabled_rejects_with_acl_denied() {
        let acl = AgentForwardAcl {
            enabled: false,
            allowlist: vec![],
        };
        let reply = decide_forward(
            ObjectId::new(),
            1,
            "127.0.0.1",
            1,
            &acl,
            Duration::from_secs(1),
        )
        .await
        .expect_err("expected reject");
        match reply {
            ClientMsg::TcpForwardReject { kind, .. } => {
                assert_eq!(kind, RejectKind::AclDenied);
            }
            _ => panic!("expected reject, got {reply:?}"),
        }
    }

    #[tokio::test]
    async fn dst_outside_local_allowlist_rejects() {
        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![DestinationRule {
                host_pattern: HostPattern::Exact("db.intranet".into()),
                port_range: PortRange {
                    low: 5432,
                    high: 5432,
                },
                proto: tunnel_core::policy::ProtocolKind::Any,
            }],
        };
        let reply = decide_forward(
            ObjectId::new(),
            1,
            "ssh.intranet",
            22,
            &acl,
            Duration::from_secs(1),
        )
        .await
        .expect_err("expected reject");
        assert!(matches!(
            reply,
            ClientMsg::TcpForwardReject {
                kind: RejectKind::AclDenied,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn dial_failure_returns_dial_failed_kind() {
        // ACL allows, but port 1 on localhost isn't listening →
        // dialer returns Io error → acceptor maps to DialFailed
        // (not AclDenied — the distinction matters for the
        // dashboard's "policy gap" vs "network broken" report).
        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![],
        };
        let reply = decide_forward(
            ObjectId::new(),
            1,
            "127.0.0.1",
            1,
            &acl,
            Duration::from_secs(1),
        )
        .await
        .expect_err("expected reject");
        match reply {
            ClientMsg::TcpForwardReject { kind, .. } => {
                assert_eq!(kind, RejectKind::DialFailed);
            }
            _ => panic!("expected DialFailed reject, got {reply:?}"),
        }
    }

    #[tokio::test]
    async fn successful_dial_returns_open_tcp_stream() {
        // Bind a one-shot local listener so the acceptor has
        // something to connect to.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![],
        };
        let stream = decide_forward(
            ObjectId::new(),
            42,
            "127.0.0.1",
            port,
            &acl,
            Duration::from_secs(2),
        )
        .await
        .expect("expected open TcpStream");
        // Just verify the stream is bound to a peer — the post-decide
        // data-plane (`run_flow`) is exercised by `peer::tests`.
        assert!(stream.peer_addr().is_ok());
    }

    /// End-to-end glue for the QUIC data plane: drive
    /// [`handle_forward_request_quic`] against a real loopback QUIC
    /// pair + a loopback TCP echo dst, and assert the full sequence —
    /// dial dst → reply `TcpForwardAccept` → rendezvous the client-
    /// opened flow stream → pump bytes both ways → emit `TcpClosed`.
    /// Locks the ordering invariant (Accept BEFORE the stream is
    /// opened) that the two-map rendezvous relies on; the WebRTC
    /// `handle_forward_request` has no equivalent test here because its
    /// post-decide path is covered by `peer::tests`.
    #[tokio::test(flavor = "multi_thread")]
    async fn quic_forward_request_accepts_then_pumps_to_dst() {
        use crate::tunnel::quic_peer::AgentQuicPeer;
        use tunnel_core::transport::quic::{self, QuicPeer};

        // dst: a loopback TCP echo server (echoes whatever it reads,
        // then closes when its peer half-closes).
        let dst = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst_port = dst.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = dst.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // Agent QUIC peer + a pinned, token-authed client connection.
        let session_id = ObjectId::new();
        let token = "tok-quic-accept";
        let (reap_tx, _reap_rx) = mpsc::channel(8);
        let agent = Arc::new(
            AgentQuicPeer::setup(
                session_id,
                token.to_string(),
                "127.0.0.1:0".parse().unwrap(),
                reap_tx,
            )
            .unwrap(),
        );
        let addr: std::net::SocketAddr = agent.addrs()[0].parse().unwrap();
        let client =
            QuicPeer::client("127.0.0.1:0".parse().unwrap(), agent.cert_fingerprint()).unwrap();
        let conn = client.connect(addr).await.unwrap();
        quic::client_authenticate(&conn, token).await.unwrap();

        // Outbound channel the acceptor replies on.
        let (tx, mut rx) = mpsc::channel::<ClientMsg>(16);
        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![],
        };
        let flow_id = 9;

        // Drive the acceptor: decide+dial → Accept → take_flow → pump.
        let agent_task = Arc::clone(&agent);
        let handle = tokio::spawn(async move {
            handle_forward_request_quic(
                session_id,
                flow_id,
                "127.0.0.1",
                dst_port,
                &acl,
                Duration::from_secs(2),
                &agent_task,
                tx,
            )
            .await;
        });

        // Client must see Accept FIRST, then opens the flow stream.
        match rx.recv().await.expect("expected a ClientMsg from acceptor") {
            ClientMsg::TcpForwardAccept {
                flow_id: f,
                dc_index,
                ..
            } => {
                assert_eq!(f, flow_id);
                assert_eq!(dc_index, 0, "QUIC has no DC pool; dc_index is 0");
            }
            other => panic!("expected TcpForwardAccept, got {other:?}"),
        }

        let (mut send, mut recv) = quic::open_flow(&conn, flow_id).await.unwrap();
        send.write_all(b"ping over quic acceptor").await.unwrap();
        send.finish().unwrap();
        // dst echoes it back over the same flow.
        let echoed = recv.read_to_end(64 * 1024).await.unwrap();
        assert_eq!(
            &echoed, b"ping over quic acceptor",
            "bytes must round-trip TCP↔QUIC through the acceptor"
        );

        // Flow ended cleanly → acceptor emits TcpClosed for audit.
        match rx.recv().await.expect("expected TcpClosed after flow end") {
            ClientMsg::TcpClosed {
                flow_id: f,
                bytes_in,
                bytes_out,
                ..
            } => {
                assert_eq!(f, flow_id);
                // Wave 3 — this end counts too. Local side here is the
                // DESTINATION, so `in` is what arrived from the client and
                // `out` is what the dst echoed back.
                let n = b"ping over quic acceptor".len() as u64;
                assert_eq!(bytes_in, n, "bytes_in = what reached the dst");
                assert_eq!(bytes_out, n, "bytes_out = what the dst returned");
            }
            other => panic!("expected TcpClosed, got {other:?}"),
        }

        handle.await.unwrap();
        agent.close();
    }
}
