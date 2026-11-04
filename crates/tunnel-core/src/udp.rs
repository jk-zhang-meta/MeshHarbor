// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Client-side SOCKS5 UDP ASSOCIATE relay (RFC 1928 §7).
//!
//! On a UDP ASSOCIATE the client binds a local UDP relay socket, returns
//! its address in the SOCKS reply, and keeps the app's TCP control
//! connection open (the association lives as long as that TCP conn).
//! The app then sends SOCKS-UDP-framed datagrams
//! (`[RSV|FRAG|ATYP|DST|PORT|DATA]`) to the relay socket; each is parsed
//! into `(target, data)` and forwarded over the tunnel as a **UDP flow**
//! — one flow per distinct `(host, port)` the app addresses. Return
//! datagrams from the agent are re-framed with the target as the source
//! address and delivered back to the app.
//!
//! Each flow is gated server-side with `proto = udp` exactly like a TCP
//! CONNECT forward, then pumped over the negotiated transport: the
//! WebRTC DataChannel pool (one `mux`-framed message per datagram) or a
//! per-flow QUIC bidi stream (`[u16 len | datagram]`). No half-close —
//! UDP flows idle-close ([`tunnel_core::forward::UDP_FLOW_IDLE_TIMEOUT`])
//! or die with the association.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result, bail};
use bson::oid::ObjectId;
use meshharbor_remote_control::signaling::{ClientMsg, CloseReason};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::forward::{
    FlowDemux, FlowGauge, MAX_UDP_DATAGRAM, SessionThroughput, UDP_FLOW_IDLE_TIMEOUT,
    deframe_udp_datagram, quic_read_datagram, quic_write_datagram, send_udp_datagram_dc,
};
use crate::signaling_link::TunnelSignalingSink;
use crate::transport::quic::{self, QuicConnection};

use crate::driver::{FLOW_OPEN_TIMEOUT, ForwardReply, ReplyRegistry};

/// The data plane a UDP association's flows ride, mirroring the session's
/// negotiated transport. Cloned per-flow into the spawned pump.
pub enum AssocCarrier {
    /// WebRTC-DC pool — flows multiplex onto the shared DCs by `flow_id`.
    Dc { demuxes: Arc<Vec<FlowDemux>> },
    /// QUIC — each flow is its own bidirectional stream on the session's
    /// connection.
    Quic { conn: Arc<QuicConnection> },
}

/// Outbound datagram-channel capacity per flow. A slow/stuck flow drops
/// beyond this (UDP is lossy — dropping is correct, blocking is not).
const FLOW_OUTBOX_CAP: usize = 256;

/// Per-flow outbound sender: the association's recv loop hands parsed
/// datagrams to the flow's pump via this.
type FlowTx = mpsc::Sender<Vec<u8>>;

/// Drive one SOCKS5 UDP ASSOCIATE association to completion. Binds the
/// relay socket, replies with its address, then relays datagrams until
/// the app's TCP control connection (`tcp`) closes.
pub async fn handle_associate(
    mut tcp: TcpStream,
    session_id: ObjectId,
    carrier: AssocCarrier,
    reply_registry: ReplyRegistry,
    sink: Arc<dyn TunnelSignalingSink>,
    flow_counter: Arc<AtomicU32>,
    // P3b-4: the per-forward throughput aggregate. Each UDP flow's pump
    // mirrors datagram bytes into it (out = app→target, in = target→app) and
    // holds a `FlowGauge` for `active_flows`, so `mh flows` reports UDP
    // the same way it reports TCP CONNECT flows (previously always 0 B).
    session: Arc<SessionThroughput>,
) -> Result<()> {
    let relay = Arc::new(
        UdpSocket::bind(("127.0.0.1", 0))
            .await
            .context("bind udp relay socket")?,
    );
    let relay_addr = relay.local_addr().context("relay local_addr")?;
    crate::socks5::reply_bound(&mut tcp, crate::socks5::REP_SUCCESS, relay_addr).await;
    info!(%session_id, %relay_addr, "socks5 UDP ASSOCIATE relay bound");

    // target (host,port) → the flow's outbound datagram sender.
    let flows: Arc<Mutex<HashMap<(String, u16), FlowTx>>> = Arc::new(Mutex::new(HashMap::new()));
    // The app's source addr, latched on the first datagram — return
    // datagrams go here; datagrams from other sources are dropped.
    let mut app_src: Option<SocketAddr> = None;
    // +512 header slack over the max datagram for the SOCKS UDP prefix.
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM + 512];

    loop {
        tokio::select! {
            // The app's TCP control connection closing ends the whole
            // association (RFC 1928). Reading it also drains anything the
            // app writes (it shouldn't write payload — only close).
            r = drain_control(&mut tcp) => {
                debug!(%session_id, ?r, "socks5 UDP control connection closed; ending association");
                break;
            }
            recvd = relay.recv_from(&mut buf) => {
                let (n, from) = match recvd {
                    Ok(x) => x,
                    Err(e) => { warn!(%session_id, %e, "udp relay recv_from failed"); continue; }
                };
                let src = *app_src.get_or_insert(from);
                if from != src {
                    debug!(%session_id, %from, %src, "udp datagram from unexpected source — dropping");
                    continue;
                }
                let (host, port, off) = match crate::socks5::parse_udp_datagram(&buf[..n]) {
                    Ok(x) => x,
                    Err(e) => { debug!(%session_id, %e, "malformed socks udp datagram — dropping"); continue; }
                };
                let data = buf[off..n].to_vec();
                let tx = get_or_open_flow(
                    &flows,
                    &carrier,
                    session_id,
                    &host,
                    port,
                    src,
                    &relay,
                    &reply_registry,
                    &sink,
                    &flow_counter,
                    &session,
                )
                .await;
                // Lossy hand-off — a full/closed outbox drops the datagram.
                if let Err(e) = tx.try_send(data) {
                    debug!(%session_id, %host, port, %e, "udp flow outbox full/closed — dropping datagram");
                }
            }
        }
    }
    // Dropping `flows` drops every flow's outbound sender → each pump
    // sees its channel close and tears down (closing its QUIC stream /
    // unregistering its demux mailbox).
    Ok(())
}

/// Look up the flow for `(host, port)`; open + spawn its pump if absent.
/// Returns the flow's outbound sender.
#[allow(clippy::too_many_arguments)]
async fn get_or_open_flow(
    flows: &Arc<Mutex<HashMap<(String, u16), FlowTx>>>,
    carrier: &AssocCarrier,
    session_id: ObjectId,
    host: &str,
    port: u16,
    app_src: SocketAddr,
    relay: &Arc<UdpSocket>,
    reply_registry: &ReplyRegistry,
    sink: &Arc<dyn TunnelSignalingSink>,
    flow_counter: &Arc<AtomicU32>,
    session: &Arc<SessionThroughput>,
) -> FlowTx {
    let key = (host.to_string(), port);
    let mut map = flows.lock().await;
    if let Some(tx) = map.get(&key) {
        return tx.clone();
    }
    let flow_id = flow_counter.fetch_add(1, Ordering::Relaxed);
    let (ftx, frx) = mpsc::channel::<Vec<u8>>(FLOW_OUTBOX_CAP);
    map.insert(key.clone(), ftx.clone());

    let flows2 = Arc::clone(flows);
    let relay2 = Arc::clone(relay);
    let registry2 = Arc::clone(reply_registry);
    let outbound2 = sink.clone();
    let host_owned = host.to_string();
    match carrier {
        AssocCarrier::Dc { demuxes } => {
            let demuxes = Arc::clone(demuxes);
            let session = Arc::clone(session);
            tokio::spawn(async move {
                run_flow_dc(
                    session_id, flow_id, host_owned, port, demuxes, relay2, app_src, frx,
                    registry2, outbound2, session,
                )
                .await;
                flows2.lock().await.remove(&key);
            });
        }
        AssocCarrier::Quic { conn } => {
            let conn = Arc::clone(conn);
            let session = Arc::clone(session);
            tokio::spawn(async move {
                run_flow_quic(
                    session_id, flow_id, host_owned, port, conn, relay2, app_src, frx, registry2,
                    outbound2, session,
                )
                .await;
                flows2.lock().await.remove(&key);
            });
        }
    }
    ftx
}

/// Send a `UdpForwardRequest` and await the server's accept/reject
/// (routed into `reply_registry` by the session dispatch loop). Returns
/// the accepted `dc_index` (meaningful for the DC transport; 0 for QUIC).
async fn open_udp_flow(
    session_id: ObjectId,
    flow_id: u32,
    host: &str,
    port: u16,
    reply_registry: &ReplyRegistry,
    sink: &Arc<dyn TunnelSignalingSink>,
) -> Result<u8> {
    let (reply_tx, reply_rx) = oneshot::channel::<ForwardReply>();
    reply_registry.lock().await.insert(flow_id, reply_tx);
    sink.send(ClientMsg::UdpForwardRequest {
        session_id,
        flow_id,
        dst_host: host.to_string(),
        dst_port: port,
    })
    .await
    .context("send UdpForwardRequest")?;
    let reply = match tokio::time::timeout(FLOW_OPEN_TIMEOUT, reply_rx).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => {
            reply_registry.lock().await.remove(&flow_id);
            bail!("udp reply oneshot dropped — dispatcher exited?");
        }
        Err(_) => {
            reply_registry.lock().await.remove(&flow_id);
            bail!("UdpForwardRequest timed out after {FLOW_OPEN_TIMEOUT:?}");
        }
    };
    match reply {
        ForwardReply::Accept { dc_index } => Ok(dc_index),
        ForwardReply::Reject { kind, reason } => bail!("udp forward rejected: {kind:?} {reason}"),
    }
}

/// One UDP flow over the WebRTC-DC pool. Datagrams from the app
/// (`outbound_rx`) are framed + sent on the DC; datagrams off the DC are
/// re-framed with the target as source and delivered to the app.
#[allow(clippy::too_many_arguments)]
async fn run_flow_dc(
    session_id: ObjectId,
    flow_id: u32,
    host: String,
    port: u16,
    demuxes: Arc<Vec<FlowDemux>>,
    relay: Arc<UdpSocket>,
    app_src: SocketAddr,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    reply_registry: ReplyRegistry,
    sink: Arc<dyn TunnelSignalingSink>,
    session: Arc<SessionThroughput>,
) {
    let dc_index =
        match open_udp_flow(session_id, flow_id, &host, port, &reply_registry, &sink).await {
            Ok(i) => i,
            Err(e) => {
                warn!(%session_id, flow_id, %host, port, %e, "udp flow open failed");
                return;
            }
        };
    let Some(demux) = demuxes.get(dc_index as usize).cloned() else {
        warn!(%session_id, flow_id, dc_index, "server returned out-of-range dc_index for udp flow");
        return;
    };
    let (mut from_dc, _stats) = demux.register(flow_id).await;
    let dc = demux.dc();
    debug!(%session_id, flow_id, dc_index, %host, port, "udp flow open (dc)");
    // P3b-4: count this flow in `active_flows` for its pump lifetime, and
    // mirror datagram payload bytes into the session aggregate so `flows`
    // reports UDP throughput. Datagram bytes (not framed) = the true payload.
    let _gauge = FlowGauge::new(session.clone());

    let reason = loop {
        tokio::select! {
            out = outbound_rx.recv() => match out {
                Some(dg) => {
                    if let Err(e) = send_udp_datagram_dc(&dc, flow_id, &dg).await {
                        debug!(%session_id, flow_id, %e, "udp flow DC send failed");
                        break CloseReason::IoError;
                    }
                    session.bytes_out.fetch_add(dg.len() as u64, Ordering::Relaxed);
                }
                None => break CloseReason::ClientShutdown,
            },
            inb = from_dc.recv() => match inb {
                Some(bytes) => {
                    if let Some(dg) = deframe_udp_datagram(&bytes) {
                        session.bytes_in.fetch_add(dg.len() as u64, Ordering::Relaxed);
                        let framed = crate::socks5::encode_udp_datagram(&host, port, dg);
                        if let Err(e) = relay.send_to(&framed, app_src).await {
                            debug!(%session_id, flow_id, %e, "udp flow relay send_to app failed");
                        }
                    }
                }
                None => break CloseReason::Eof,
            },
            _ = tokio::time::sleep(UDP_FLOW_IDLE_TIMEOUT) => break CloseReason::IdleTimeout,
        }
    };

    demux.unregister(flow_id).await;
    debug!(%session_id, flow_id, ?reason, "udp flow ended (dc)");
    let _ = sink
        .send(ClientMsg::UdpClosed {
            session_id,
            flow_id,
            reason,
        })
        .await;
}

/// One UDP flow over a native QUIC bidi stream.
#[allow(clippy::too_many_arguments)]
async fn run_flow_quic(
    session_id: ObjectId,
    flow_id: u32,
    host: String,
    port: u16,
    conn: Arc<QuicConnection>,
    relay: Arc<UdpSocket>,
    app_src: SocketAddr,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    reply_registry: ReplyRegistry,
    sink: Arc<dyn TunnelSignalingSink>,
    session: Arc<SessionThroughput>,
) {
    if let Err(e) = open_udp_flow(session_id, flow_id, &host, port, &reply_registry, &sink).await {
        warn!(%session_id, flow_id, %host, port, %e, "udp flow open failed");
        return;
    }
    let (mut send, mut recv) = match quic::open_flow(&conn, flow_id).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%session_id, flow_id, %e, "udp flow quic open_flow failed");
            return;
        }
    };
    debug!(%session_id, flow_id, %host, port, "udp flow open (quic)");
    // P3b-4: active_flows gauge + per-datagram byte accounting (see run_flow_dc).
    let _gauge = FlowGauge::new(session.clone());

    let reason = loop {
        tokio::select! {
            out = outbound_rx.recv() => match out {
                Some(dg) => {
                    if let Err(e) = quic_write_datagram(&mut send, &dg).await {
                        debug!(%session_id, flow_id, %e, "udp flow quic write failed");
                        break CloseReason::IoError;
                    }
                    session.bytes_out.fetch_add(dg.len() as u64, Ordering::Relaxed);
                }
                None => break CloseReason::ClientShutdown,
            },
            inb = quic_read_datagram(&mut recv) => match inb {
                Ok(Some(dg)) => {
                    session.bytes_in.fetch_add(dg.len() as u64, Ordering::Relaxed);
                    let framed = crate::socks5::encode_udp_datagram(&host, port, &dg);
                    if let Err(e) = relay.send_to(&framed, app_src).await {
                        debug!(%session_id, flow_id, %e, "udp flow relay send_to app failed");
                    }
                }
                Ok(None) => break CloseReason::Eof,
                Err(e) => {
                    debug!(%session_id, flow_id, %e, "udp flow quic read failed");
                    break CloseReason::IoError;
                }
            },
            _ = tokio::time::sleep(UDP_FLOW_IDLE_TIMEOUT) => break CloseReason::IdleTimeout,
        }
    };

    debug!(%session_id, flow_id, ?reason, "udp flow ended (quic)");
    let _ = sink
        .send(ClientMsg::UdpClosed {
            session_id,
            flow_id,
            reason,
        })
        .await;
}

/// Read + discard the SOCKS control connection until EOF/error. RFC 1928
/// says nothing meaningful flows on it after the ASSOCIATE reply; its
/// close is the association's teardown signal.
async fn drain_control(tcp: &mut TcpStream) -> std::io::Result<()> {
    let mut b = [0u8; 256];
    loop {
        match tcp.read(&mut b).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::{FlowStats, run_flow_udp_dc};
    use crate::transport::webrtc_dc::TunnelPeer;
    use std::time::Duration;

    /// Minimal sink: the client UDP pump emits `UdpForwardRequest` (auto-accepted
    /// below) + `UdpClosed`; the test doesn't inspect them.
    struct NoopSink;
    #[async_trait::async_trait]
    impl TunnelSignalingSink for NoopSink {
        async fn send(&self, _msg: ClientMsg) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// P3b-4 regression: the CLIENT-side UDP pump (`run_flow_dc`) carries a
    /// SOCKS5-UDP datagram round-trip over the DC pool AND mirrors the payload
    /// bytes into the `SessionThroughput` aggregate — previously always 0, the
    /// gap that let daemon SOCKS5 UDP look "broken". Also asserts the
    /// `active_flows` gauge is held for the flow's lifetime and released on
    /// teardown. Reuses the in-process DC pair from
    /// `forward::tests::run_flow_udp_dc_echoes_through_pool` (reliable — the ICE
    /// is loopback, not the flaky over-the-network path the E2E suite avoids).
    #[tokio::test(flavor = "multi_thread")]
    async fn client_udp_flow_dc_accounts_session_bytes() {
        // Loopback UDP echo target.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });

        // WebRTC-DC peer pair: offerer = client, answerer = agent.
        let offerer = TunnelPeer::new(vec![]).await.unwrap();
        let answerer = TunnelPeer::new(vec![]).await.unwrap();
        let answerer_pc = answerer.peer_connection();
        offerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&answerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });
        let offerer_pc = offerer.peer_connection();
        answerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&offerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });
        let offer = offerer.create_offer().await.unwrap();
        let answer = answerer.accept_offer(&offer.sdp).await.unwrap();
        offerer.accept_answer(&answer.sdp).await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), offerer.wait_pool_open())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), answerer.wait_pool_open())
            .await
            .unwrap()
            .unwrap();

        let flow_id = 7u32;
        // Agent side: run_flow_udp_dc echoes datagrams to the echo target.
        let agent_demux = FlowDemux::install(answerer.dc(0).unwrap(), None).await;
        let (agent_from_dc, _as) = agent_demux.register(flow_id).await;
        let audp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        audp.connect(echo_addr).await.unwrap();
        let agent_pump = tokio::spawn(run_flow_udp_dc(
            audp,
            answerer.dc(0).unwrap(),
            flow_id,
            agent_from_dc,
            Duration::from_secs(5),
            Arc::new(FlowStats::default()),
        ));

        // Client side: OUR run_flow_dc, driven with a real SessionThroughput.
        let client_demux = FlowDemux::install(offerer.dc(0).unwrap(), None).await;
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app_src = app.local_addr().unwrap();
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(16);
        let reply_registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(NoopSink);
        let session = Arc::new(SessionThroughput::default());

        // Stand in for the server's UdpForwardAccept: the session dispatch loop
        // would route it into `reply_registry` by flow_id; here a task does.
        {
            let reg = Arc::clone(&reply_registry);
            tokio::spawn(async move {
                for _ in 0..300 {
                    if let Some(tx) = reg.lock().await.remove(&flow_id) {
                        let _ = tx.send(ForwardReply::Accept { dc_index: 0 });
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
        }

        let client_pump = tokio::spawn(run_flow_dc(
            ObjectId::new(),
            flow_id,
            "127.0.0.1".to_string(),
            echo_addr.port(),
            Arc::new(vec![client_demux]),
            Arc::clone(&relay),
            app_src,
            out_rx,
            reply_registry,
            sink,
            Arc::clone(&session),
        ));

        // App sends a datagram toward the target (payload only — as
        // `handle_associate` hands the parsed payload to the flow).
        let payload = b"ping-udp-acct";
        out_tx.send(payload.to_vec()).await.unwrap();

        // The pump relays the agent's echo back to the app as a SOCKS-UDP frame.
        let mut rb = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(8), app.recv_from(&mut rb))
            .await
            .expect("no echo delivered to the app within 8s")
            .unwrap();
        let (_h, _p, off) = crate::socks5::parse_udp_datagram(&rb[..n])
            .expect("app received a valid socks-udp datagram");
        assert_eq!(
            &rb[off..n],
            payload,
            "the datagram must round-trip through the CLIENT udp pump"
        );

        // P3b-4: the round-trip must be reflected in the session aggregate.
        let (bytes_in, bytes_out, active) = session.snapshot();
        assert_eq!(
            bytes_out,
            payload.len() as u64,
            "bytes_out counts the datagram sent toward the target"
        );
        assert_eq!(
            bytes_in,
            payload.len() as u64,
            "bytes_in counts the echoed datagram"
        );
        assert_eq!(active, 1, "the live UDP flow holds one active_flows gauge");

        // Aborting the pump drops its FlowGauge → active_flows returns to 0.
        client_pump.abort();
        agent_pump.abort();
        let mut settled = false;
        for _ in 0..100 {
            if session.snapshot().2 == 0 {
                settled = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            settled,
            "active_flows returns to 0 after the flow's pump ends"
        );
        drop(out_tx);
    }
}
