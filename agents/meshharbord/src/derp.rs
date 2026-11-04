// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Agent-side `/derp` WebSocket owner (NAT-traversal Phase D, DERP).
//!
//! When DERP is enabled (`ROOMLERD_OVERLAY_DERP=1`) the agent opens ONE
//! persistent WSS to the server's `/derp` relay, registers its WG pubkey, and
//! bridges it to the node's [`DerpMux`]: outbound carrier frames drain to the
//! socket, inbound frames are demuxed by source pubkey to the right peer's
//! [`DerpConn`](tunnel_core::transport::derp::DerpConn). This is the transport
//! the [`RelayCoordinator`](tunnel_core::overlay::relay_link) uses to carry WG
//! between two BOTH-UDP-blocked peers — both dial OUT over TCP/TLS-443, so no
//! UDP is needed anywhere.
//!
//! The mux + this task are created per overlay connection (in
//! [`crate::overlay::maybe_start`]); the task holds only a `Weak<DerpMux>` and
//! owns the outbound receiver, so when the runtime tears down (its strong
//! `Arc<DerpMux>` + all `DerpConn`s drop) the outbound channel closes and this
//! task exits — no leak across the agent's WS reconnects.

use std::sync::{Arc, Weak};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::relay_probe::DerpTicketSlot;
use tunnel_core::transport::derp::DerpMux;

/// Hard upper bound on a single `/derp` connect attempt (mirrors the control
/// WS's `WS_CONNECT_TIMEOUT`): a hung TLS handshake must not stall the backoff.
const DERP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// FR-18 — ceiling for the `/derp` TCP socket's send buffer. Sized well above
/// the bandwidth-delay product of the paths this carrier actually serves
/// (3 Mbps × 200 ms ≈ 75 KB) so throughput is untouched, and far below the
/// megabytes autotuning would otherwise allow to accumulate as latency.
const DERP_SNDBUF_BYTES: usize = 256 * 1024;

/// Reconnect backoff ceiling. Deliberately LOW: the `/derp` WS is the relay
/// FLOOR — with a force-DERP pin active the pinned pair has no other tier, and
/// (post-#497) its build is withheld for exactly as long as this mux is down.
/// At the old 60 s ceiling a VPN capture pushed attempts to ~90 s spacing
/// (30 s connect timeout + 60 s backoff), so the floor could lag the network's
/// recovery by minutes (field 2026-08-16: multi-minute dark windows on pinned
/// pairs through a Check Point cycle). One TLS dial per 10 s while the path is
/// actually broken is noise; a fast floor restoration is the whole point.
const DERP_BACKOFF_MAX: Duration = Duration::from_secs(10);
/// Keepalive Ping cadence on the established `/derp` WS. An idle DERP socket
/// is legitimately silent (frames only flow while a both-UDP-blocked pair is
/// relaying), so WITHOUT our own pings the RX deadline below would false-fire
/// on healthy idle links. The server auto-pongs, giving a healthy link an
/// inbound frame at least this often.
const DERP_KEEPALIVE: Duration = Duration::from_secs(25);
/// Receive-liveness deadline (3 keepalive periods + margin). Same rationale
/// as `signaling::WS_RX_DEADLINE`: a TLS-inspecting corp middlebox keeps
/// ACKing our pings after its upstream leg died, so send-success proves
/// nothing — reconnect must key on frames RECEIVED.
const DERP_RX_DEADLINE: Duration = Duration::from_secs(80);

/// FR-18 — request the [`DERP_SNDBUF_BYTES`] ceiling on the socket under the
/// (possibly TLS-wrapped) WebSocket. Best-effort by design: an OS may clamp or
/// ignore the request, and a carrier that works with a big buffer must not fail
/// to start because we could not shrink it.
fn cap_send_buffer(
    ws: &tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    relay: &str,
) {
    use socket2::SockRef;
    use tokio_tungstenite::MaybeTlsStream;
    let tcp = match ws.get_ref() {
        MaybeTlsStream::Plain(s) => s,
        MaybeTlsStream::Rustls(s) => s.get_ref().0,
        // `MaybeTlsStream` is `#[non_exhaustive]`; an unknown wrapper just
        // keeps the OS default rather than blocking the connection.
        _ => {
            debug!(%relay, "overlay derp: unrecognised TLS wrapper — send buffer left at the OS default");
            return;
        }
    };
    if let Err(e) = SockRef::from(tcp).set_send_buffer_size(DERP_SNDBUF_BYTES) {
        debug!(%relay, %e, "overlay derp: set_send_buffer_size failed — OS default retained");
    }
}

/// Derive the `/derp` WSS URL from the control `ws_url` (`wss://host/ws`).
fn derp_url_from_ws(ws_url: &str) -> String {
    match ws_url.strip_suffix("/ws") {
        Some(base) => format!("{base}/derp"),
        // An operator override that isn't `/ws`-suffixed: swap the last segment.
        None => match ws_url.rsplit_once('/') {
            Some((base, _)) => format!("{base}/derp"),
            None => format!("{ws_url}/derp"),
        },
    }
}

/// The central `/derp` URL for one dial. S6 — `tid` = tenant-affinity key for
/// the front LB. DERP relays are pod-local, so both mesh peers must land on
/// the SAME pod; hashing every /derp socket by tenant guarantees it. Pre-S6
/// servers ignore the param.
fn central_url(derp_base: &str, token: &str, tenant_id: &str) -> String {
    format!(
        "{derp_base}?token={}&role=agent&tid={}",
        crate::signaling::urlencode(token),
        crate::signaling::urlencode(tenant_id)
    )
}

/// FR-103 — the central URL, built per ATTEMPT from the live token: the WS
/// owner outlives the connection that spawned it, and a URL fixed at spawn
/// would keep dialling with a token renewed since.
///
/// #2512 — and NO URL while the control socket's verdict on that token is
/// "refused" (`TokenSlot::is_refused`): a dial then is a request the server
/// will only 401, and a device whose row was gone re-dialled every 10 s,
/// forever. `run` backs off (≤ `DERP_BACKOFF_MAX`) and asks again, so a new
/// token or the socket's next accepted upgrade brings the carrier back within
/// one step. ⚠️ Never this dialer's own 401: `/derp` answers 401 for ANY
/// lookup error, so a dialer that believed it would drop every device's DERP
/// floor on one database wobble.
fn central_url_per_attempt(
    ws_url: &str,
    token: crate::token_slot::TokenSlot,
    tenant_id: &str,
) -> Box<dyn Fn() -> Option<String> + Send> {
    let (base, tenant_id) = (derp_url_from_ws(ws_url), tenant_id.to_string());
    Box::new(move || {
        if token.is_refused() {
            return None;
        }
        Some(central_url(&base, &token.get(), &tenant_id))
    })
}

/// Spawn the persistent `/derp` WS owner for this overlay connection. `ws_url`
/// is the control WS URL (`cfg.ws_url()`); the enrollment's agent token
/// authenticates exactly like the control WS (`role=agent`). Holds a `Weak` to
/// `mux` and owns `outbound_rx`, so it exits when the runtime tears the mux
/// down.
pub fn spawn(
    ws_url: &str,
    token: crate::token_slot::TokenSlot,
    tenant_id: &str,
    mux: &Arc<DerpMux>,
    outbound_rx: mpsc::Receiver<tunnel_core::transport::derp::OutboundFrame>,
) {
    let reg_frame = mux.registration_frame();
    let weak = Arc::downgrade(mux);
    tokio::spawn(run(
        "central".to_string(),
        central_url_per_attempt(ws_url, token, tenant_id),
        reg_frame,
        weak,
        outbound_rx,
    ));
}

/// Multi-region DERP: like [`spawn`] but for a REGIONAL relay authenticated by
/// an admission ticket. The URL is rebuilt per connect attempt from the ticket
/// slot, so a refreshed ticket takes effect on the next reconnect; while the
/// slot is empty the owner just backs off (ticket still in flight).
pub fn spawn_regional(
    derp_url: &str,
    ticket_slot: DerpTicketSlot,
    tenant_id: &str,
    mux: &Arc<DerpMux>,
    outbound_rx: mpsc::Receiver<tunnel_core::transport::derp::OutboundFrame>,
) {
    let base = derp_url.to_string();
    // Host part only — the ticket query string must never reach a log line.
    let label = derp_url
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .split(['/', '?'])
        .next()
        .unwrap_or(derp_url)
        .to_string();
    let tid = crate::signaling::urlencode(tenant_id);
    let reg_frame = mux.registration_frame();
    let weak = Arc::downgrade(mux);
    tokio::spawn(run(
        label,
        Box::new(move || {
            let ticket = ticket_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|(t, _)| t.clone())?;
            let sep = if base.contains('?') { '&' } else { '?' };
            Some(format!(
                "{base}{sep}ticket={}&tid={tid}",
                crate::signaling::urlencode(&ticket)
            ))
        }),
        reg_frame,
        weak,
        outbound_rx,
    ));
}

async fn run(
    relay: String,
    url_for_attempt: Box<dyn Fn() -> Option<String> + Send>,
    reg_frame: Vec<u8>,
    mux: Weak<DerpMux>,
    mut outbound_rx: mpsc::Receiver<tunnel_core::transport::derp::OutboundFrame>,
) {
    // FR-18 — resolved once: the queue-age bound is a deployment knob, not a
    // per-frame decision, and re-reading the env per frame would be the hot
    // path of the whole carrier.
    let max_queue_age = tunnel_core::transport::derp::queue_max_age();
    // FR-18 — last value reported, so the keepalive log is change-gated
    // rather than a line every 25 s on a carrier that shed nothing.
    let mut last_reported_stale: u64 = 0;
    let mut backoff = Duration::from_secs(1);
    loop {
        // The mux is gone (runtime torn down) ⇒ stop reconnecting.
        if mux.upgrade().is_none() {
            debug!(%relay, "overlay derp: mux dropped; stopping /derp WS owner");
            return;
        }
        // Regional relays: no admission ticket cached yet — back off and
        // retry (the signaling loop fills the slot within seconds). #2512 —
        // the central relay: the server refuses this enrollment's token, as
        // the control socket heard it (`central_url_per_attempt`).
        let Some(url) = url_for_attempt() else {
            debug!(
                %relay,
                "overlay derp: no usable credential (no admission ticket yet, or the server \
                 refuses this enrollment's token); delaying connect"
            );
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(DERP_BACKOFF_MAX);
            continue;
        };
        // #2187 — the relay's address comes from `ctl_dns`, as the control WS's does.
        match tokio::time::timeout(DERP_CONNECT_TIMEOUT, crate::ws_connect::connect(&url)).await {
            Ok(Ok((ws, _))) => {
                backoff = Duration::from_secs(1);
                // FR-18 — bound the KERNEL's send buffer too. Shedding stale
                // frames above is pointless if a frame we did choose to send
                // then sits for seconds in a socket buffer the age check can no
                // longer reach: Windows autotuning happily grows this into the
                // megabytes, which at a 3 Mbps relay is multiple seconds of
                // committed latency. The BDP of these paths is tens of KB
                // (3 Mbps × 200 ms ≈ 75 KB), so this cap costs no throughput.
                cap_send_buffer(&ws, &relay);
                let (mut tx, mut rx) = ws.split();
                // Register our pubkey as the first frame.
                if tx
                    .send(Message::Binary(reg_frame.clone().into()))
                    .await
                    .is_err()
                {
                    warn!(%relay, "overlay derp: registration send failed; reconnecting");
                    if let Some(m) = mux.upgrade() {
                        m.mark_down();
                    }
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                if let Some(m) = mux.upgrade() {
                    m.mark_up();
                } else {
                    return;
                }
                info!(%relay, "overlay derp: /derp WS connected + registered");

                let mut keepalive = tokio::time::interval(DERP_KEEPALIVE);
                keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                keepalive.tick().await; // swallow the immediate first tick
                let mut last_rx = std::time::Instant::now();
                // A5 — resume detection (see signaling.rs RESUME_SKEW_MIN):
                // monotonic timers exclude suspend, so a nap leaves a dead
                // socket trusted for up to another RX-deadline window.
                let mut skew_wall = std::time::SystemTime::now();
                let mut skew_mono = std::time::Instant::now();

                // Pump until either half dies (or the mux is torn down).
                loop {
                    tokio::select! {
                        _ = keepalive.tick() => {
                            let wall_gap = skew_wall.elapsed().unwrap_or_default();
                            let mono_gap = skew_mono.elapsed();
                            skew_wall = std::time::SystemTime::now();
                            skew_mono = std::time::Instant::now();
                            if wall_gap > mono_gap + std::time::Duration::from_secs(120) {
                                warn!(
                                    %relay,
                                    napped_s = (wall_gap - mono_gap).as_secs(),
                                    "overlay derp: suspend/resume detected — cycling the /derp WS"
                                );
                                break;
                            }
                            if last_rx.elapsed() > DERP_RX_DEADLINE {
                                warn!(
                                    %relay,
                                    silent_s = last_rx.elapsed().as_secs(),
                                    "overlay derp: no inbound frames within the RX deadline — half-open /derp WS; reconnecting"
                                );
                                break;
                            }
                            // FR-18 — report the shed count on the keepalive
                            // tick, change-gated so a healthy carrier stays
                            // silent. Without a reader the counter proves
                            // nothing in the field, and "the carrier shed
                            // stale load" has to be distinguishable from "the
                            // carrier stalled" — they look identical from the
                            // pump's side and want opposite responses.
                            if let Some(m) = mux.upgrade() {
                                let shed = m.stale_drops();
                                if shed != last_reported_stale {
                                    info!(
                                        %relay,
                                        dropped_stale = shed,
                                        since_last = shed - last_reported_stale,
                                        "overlay derp: shed stale carrier frames (queue age bound)"
                                    );
                                    last_reported_stale = shed;
                                }
                            }
                            if tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                                warn!(%relay, "overlay derp: keepalive ping failed; reconnecting");
                                break;
                            }
                        }
                        out = outbound_rx.recv() => match out {
                            // A carrier frame to relay: [peer_pubkey||payload].
                            Some((queued_at, frame)) => {
                                // FR-18 — shed stale load. A frame that has
                                // already waited longer than its useful life is
                                // worse than nothing: it occupies the wire the
                                // CURRENT frame needs, and by the time it lands
                                // the receiver has moved on. Dropping here is
                                // also what turns the bounded-but-deep queue
                                // into drop-OLDEST semantics — under overload
                                // the writer discards the stale head quickly and
                                // reaches fresh frames, instead of faithfully
                                // delivering 1.8 s of history.
                                //
                                // WG is loss-tolerant by construction, so this
                                // costs a retransmit at worst; the alternative
                                // costs seconds of latency (measured: a single
                                // frame blocked 10.2 s inside the DC send).
                                if let Some(max_age) = max_queue_age
                                    && queued_at.elapsed() > max_age
                                {
                                    if let Some(m) = mux.upgrade() {
                                        m.note_stale_drop();
                                    }
                                    continue;
                                }
                                if tx.send(Message::Binary(frame.into())).await.is_err() {
                                    break;
                                }
                            }
                            // All senders gone ⇒ the mux + every DerpConn dropped
                            // (runtime torn down): we're done for good.
                            None => {
                                debug!(%relay, "overlay derp: outbound closed; /derp WS owner exiting");
                                return;
                            }
                        },
                        inb = rx.next() => match inb {
                            Some(Ok(Message::Binary(data))) => {
                                last_rx = std::time::Instant::now();
                                match mux.upgrade() {
                                    Some(m) => m.deliver(&data[..]),
                                    None => return,
                                }
                            }
                            // Keep the corp middlebox happy; ignore text.
                            Some(Ok(Message::Ping(p))) => {
                                last_rx = std::time::Instant::now();
                                let _ = tx.send(Message::Pong(p)).await;
                            }
                            // Pong (auto-reply to our keepalive) et al. — any
                            // inbound frame proves the link is alive.
                            Some(Ok(_)) => {
                                last_rx = std::time::Instant::now();
                            }
                            Some(Err(_)) | None => break,
                        },
                    }
                }
                if let Some(m) = mux.upgrade() {
                    m.mark_down();
                }
                warn!(%relay, "overlay derp: /derp WS closed; reconnecting");
            }
            Ok(Err(e)) => warn!(%relay, %e, "overlay derp: /derp connect failed"),
            Err(_) => warn!(%relay, "overlay derp: /derp connect timed out"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(DERP_BACKOFF_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derp_url_swaps_ws_for_derp() {
        assert_eq!(
            derp_url_from_ws("wss://roomler.ai/ws"),
            "wss://roomler.ai/derp"
        );
        assert_eq!(
            derp_url_from_ws("ws://localhost:3000/ws"),
            "ws://localhost:3000/derp"
        );
        // Non-/ws override: swap the last path segment.
        assert_eq!(derp_url_from_ws("wss://host/control"), "wss://host/derp");
    }

    /// FR-103 — a token renewed after the owner was spawned is the one its
    /// next dial carries.
    #[test]
    fn each_dial_carries_the_token_in_use_now() {
        let slot = crate::token_slot::TokenSlot::new("first");
        let url = central_url_per_attempt("wss://host/ws", slot.clone(), "t1");
        assert_eq!(
            url().as_deref(),
            Some("wss://host/derp?token=first&role=agent&tid=t1")
        );
        slot.set("renewed".into());
        assert_eq!(
            url().as_deref(),
            Some("wss://host/derp?token=renewed&role=agent&tid=t1")
        );
    }

    /// #2512 — while the control socket's verdict on the token is "refused",
    /// the central relay is not dialled at all; the socket's next accepted
    /// upgrade, or a renewed token, brings the dial back.
    #[test]
    fn a_refused_token_is_never_dialled() {
        let slot = crate::token_slot::TokenSlot::new("dead");
        let url = central_url_per_attempt("wss://host/ws", slot.clone(), "t1");
        assert!(slot.mark_refused("dead"));
        assert_eq!(url(), None);
        assert!(slot.mark_accepted("dead"));
        assert_eq!(
            url().as_deref(),
            Some("wss://host/derp?token=dead&role=agent&tid=t1")
        );
        assert!(slot.mark_refused("dead"));
        assert_eq!(url(), None);
        assert!(slot.set("renewed".into()));
        assert_eq!(
            url().as_deref(),
            Some("wss://host/derp?token=renewed&role=agent&tid=t1")
        );
    }

    /// A loopback server that answers every upgrade with a plain 401, as
    /// `/derp` does for a gone row and for any lookup error. Returns its
    /// `ws://…/ws` base and a count of the dials it has seen.
    async fn refusing_server() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("ws://{}/ws", listener.local_addr().unwrap());
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = dials.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\
                              Connection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        (base, dials)
    }

    fn dialer(
        base: &str,
        slot: &crate::token_slot::TokenSlot,
        mux: &Arc<DerpMux>,
        outbound_rx: mpsc::Receiver<tunnel_core::transport::derp::OutboundFrame>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(run(
            "central".to_string(),
            central_url_per_attempt(base, slot.clone(), "t1"),
            mux.registration_frame(),
            Arc::downgrade(mux),
            outbound_rx,
        ))
    }

    /// #2512 ⚠️ — the dialer's OWN 401 never parks it. `/derp` answers 401
    /// for ANY lookup error (a Mongo blip included), so a 401 here keeps the
    /// ordinary backoff and the dialer keeps trying: only the control
    /// socket's verdict holds it.
    #[tokio::test]
    async fn a_derp_401_alone_never_parks_the_dialer() {
        let (base, dials) = refusing_server().await;
        let slot = crate::token_slot::TokenSlot::new("live");
        let (mux, outbound_rx) = DerpMux::new([7u8; 32]);
        let task = dialer(&base, &slot, &mux, outbound_rx);
        tokio::time::sleep(Duration::from_millis(3500)).await;
        task.abort();
        let n = dials.load(std::sync::atomic::Ordering::SeqCst);
        // Dials at ~0 s, ~1 s and ~3 s on the 1 s → 2 s backoff.
        assert!(n >= 2, "a 401 must not stop the dialer: {n} dial(s)");
        assert!(!slot.is_refused(), "and it never marks the slot");
    }

    /// #2512 — a refused enrollment's dialer sends nothing, and a renewed
    /// token brings it back on its next step.
    #[tokio::test]
    async fn a_refused_enrollment_dials_nothing_until_its_token_changes() {
        let (base, dials) = refusing_server().await;
        let slot = crate::token_slot::TokenSlot::new("gone");
        assert!(slot.mark_refused("gone"));
        let (mux, outbound_rx) = DerpMux::new([8u8; 32]);
        let task = dialer(&base, &slot, &mux, outbound_rx);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(
            dials.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a refused token is never dialled"
        );
        assert!(slot.set("renewed".into()));
        let deadline = std::time::Instant::now() + Duration::from_secs(12);
        while dials.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "a renewed token is dialled within one backoff step"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        task.abort();
    }
}
