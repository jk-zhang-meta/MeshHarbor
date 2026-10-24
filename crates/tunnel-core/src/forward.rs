// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Bidirectional TCP ↔ DataChannel pump with event-driven
//! backpressure.
//!
//! Pattern lifted from the agent's rc.19 file-DC code. Pause
//! `TcpStream::read` when `dc.buffered_amount > HIGH_WATER_MARK`,
//! resume when it crosses `LOW_WATER_MARK` (via webrtc-rs's
//! `bufferedAmountLowThreshold` event — not poll). Without this a
//! 3 GB MSSQL stream OOMs the agent.
//!
//! Two halves per flow:
//! * **TCP → DC**: read TCP, frame with `flow_id` (4-byte LE prefix
//!   per `crate::mux`), send on the DC, pause when `buffered_amount
//!   > HIGH_WATER_MARK_BYTES`, resume when the
//!   `bufferedAmountLow` event fires (threshold set to
//!   `LOW_WATER_MARK_BYTES`).
//! * **DC → TCP**: messages routed through a [`FlowDemux`] (one per
//!   DC, decodes the `flow_id` prefix and routes to per-flow
//!   `mpsc::Receiver<Bytes>`); receiver feeds bytes to the TCP write
//!   half until EOF or error.
//!
//! Cross-references that MUST stay in sync if these constants move:
//! `crates/api/src/ws/tunnel.rs` (server-side audit) and
//! `crates/remote_control/src/signaling.rs` (`CloseReason` taxonomy).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use roomler_ai_remote_control::signaling::CloseReason;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify, mpsc};
use tracing::{debug, info, trace, warn};
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;

use quinn::{RecvStream, SendStream};

use crate::mux;

/// Threshold above which the pump pauses TCP reads. 4 MiB.
pub const HIGH_WATER_MARK_BYTES: usize = 4 * 1024 * 1024;

/// Threshold at which the pump resumes TCP reads. 1 MiB. Hysteresis
/// matters — too tight = thrash; too loose = latency under burst.
pub const LOW_WATER_MARK_BYTES: usize = 1024 * 1024;

/// Hard ceiling on one framed DC message (4-byte flow_id prefix +
/// payload) — and thus the chunk size for native↔native DC sends. The
/// TCP read budget below subtracts the flow_id prefix so the framed
/// `encode(flow_id, &buf[..n])` never exceeds this.
///
/// This MUST be ≤ 65535, NOT merely ≤ the SCTP max_message_size of
/// 65536. webrtc-data's `DataChannel` read loop reads every inbound
/// message into a fixed `u16::MAX` = 65535-byte buffer
/// (`DATA_CHANNEL_BUFFER_SIZE`). A reassembled SCTP message larger than
/// that buffer makes `read_sctp` return `ErrShortBuffer`, which
/// webrtc-data turns into a *stream close* and the read loop then
/// breaks — so `on_message` stops firing for the life of the DC. The
/// one-byte gap between 65535 and 65536 silently stalled large
/// transfers mid-flight: the first full-size chunk to cross the wire
/// killed the receiver's read loop (sender `dc_send` kept climbing while
/// the receiver's `dc_recv` flatlined), while small/slow transfers that
/// never filled a whole chunk worked fine. Was `64 * 1024` (= 65536).
pub const CHUNK_BYTES: usize = u16::MAX as usize;

// RETIRED-NAME-RECORD(24): a field observation, recorded under the name the
// binary had when it was measured. Rewriting it would misreport history.
/// Per-flow inbound mailbox capacity (in messages, not bytes). When
/// the receiver is slow, the [`FlowDemux::on_message`] handler awaits
/// `send` — cascading backpressure into the DC read loop and (via
/// SCTP) the peer's sender.
///
/// rc.66 bump: 256 → 4096. Field-test 2026-05-27 with TDS bulk read
/// stalled at ~50 KB/s effective throughput while SCTP was happily
/// acknowledging at 1-2 MB/s; arwnd closed monotonically and
/// `roomler-tunnel.exe` was at 0% CPU (so not busy-loop, not lock
/// contention — purely I/O-bound waiting for the local app to
/// drain). With 4096 × ~64 KiB chunks the per-flow buffer ceiling
/// is ~256 MiB; a momentary slow consumer no longer cascades back
/// to the SCTP receive window before the receiver app catches up.
/// Memory cost per flow is tiny — the mpsc only allocates slots as
/// messages arrive, not upfront.
const FLOW_INBOX_CAP: usize = 4096;

/// rc.66: per-flow byte counters surfaced by `run_flow` for
/// instrumentation. Each flow records three cumulative atomics + the
/// current mailbox depth so a periodic logger task can sample at a
/// 2 s cadence and we can see EXACTLY which of the four pump stages
/// is rate-limiting under bulk-stream load.
///
/// Field-test 2026-05-27 with TDS bulk read showed `roomler-tunnel.
/// exe` at 0% CPU while throughput effectively topped out at
/// ~50 KB/s. These counters are the diagnostic we needed: by
/// comparing `tcp_read_bytes` (producer side) against
/// `tcp_write_bytes` (consumer side) and looking at `mailbox_depth`
/// we can localise the slow stage in one log line per flow.
///
/// Atomics are `Relaxed`-only — they're counters, not synchronisation
/// primitives. Cost per chunk is one atomic-add, well below the
/// noise floor of a webrtc-data callback.
#[derive(Debug, Default)]
pub struct FlowStats {
    /// Bytes the local TCP→DC pump has READ from the local TcpStream
    /// (post-Nagle, post-read syscall). On the agent side that's the
    /// corp-network destination; on the tunnel-client side it's the
    /// operator's local app (sqlcmd, psql, …) writing toward the
    /// tunnel.
    pub tcp_read_bytes: AtomicU64,
    /// Bytes the local TCP→DC pump has SENT into the DC after
    /// framing — `tcp_read_bytes + 4 × frame_count` to a rounding
    /// error; tracked separately so any divergence (frames refused
    /// by `dc.send` due to send-buffer pressure, etc.) is visible.
    pub dc_send_bytes: AtomicU64,
    /// Bytes the FlowDemux's `on_message` handler RECEIVED off the DC
    /// for this flow (payload bytes, post-frame-strip), incremented
    /// the instant a message is dispatched — BEFORE it's pushed into
    /// the mailbox.
    ///
    /// rc.78: re-added (it existed in the rc.66 draft, then was
    /// dropped). This is the decisive counter for the tunnel-stall
    /// investigation: compared against the PEER's `dc_send_bytes`, it
    /// localises a freeze to either the wire/SCTP receive path
    /// (peer's `dc_send` climbs but our `dc_recv` flatlines → data
    /// left the sender but never reached our `on_message`) or the
    /// local consumer (`dc_recv` tracks the peer's `dc_send` but
    /// `tcp_write_bytes` lags). On the agent this counts the query
    /// bytes from the client; on the tunnel-client it counts the
    /// result-set bytes from the agent (the SELECT direction).
    pub dc_recv_bytes: AtomicU64,
    /// Bytes the DC→TCP pump has WRITTEN to the local TcpStream
    /// (post-`write_all` on loopback in the tunnel-client case).
    /// This is the bottom of the consumer chain — if it lags
    /// `tcp_read_bytes` on the producer, that's the rate at which
    /// the local app is draining.
    pub tcp_write_bytes: AtomicU64,
    /// Current mailbox depth — snapshot of `from_dc.len()` taken at
    /// each successful `recv()`. If this stays near `FLOW_INBOX_CAP`
    /// the bottleneck is the local TCP write (or the kernel /
    /// application beyond it); if it stays near 0 the bottleneck is
    /// upstream (DC delivery is slow).
    pub mailbox_depth: AtomicU64,
    /// Optional back-pointer to the session-level throughput aggregate
    /// (P3b-3). Set by [`FlowDemux::register`] (WebRTC) / the QUIC
    /// client path when the daemon originates the flow; `None` on the
    /// agent target side + the CLI + every `FlowStats::default()`, so
    /// those carry no aggregate. When present, the pumps mirror each
    /// TCP-side byte add into the session cumulative (`bytes_out` =
    /// local→peer, `bytes_in` = peer→local) so `roomler flows` can
    /// report per-forward throughput. TCP-side (not `dc_send`) so the
    /// count is the true application payload — comparable across
    /// WebRTC (which adds a 4-byte frame prefix) and QUIC.
    pub session: Option<Arc<SessionThroughput>>,
}

impl FlowStats {
    /// `(tcp_read, dc_send, dc_recv, tcp_write, mailbox_depth)` —
    /// relaxed snapshot.
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.tcp_read_bytes.load(Ordering::Relaxed),
            self.dc_send_bytes.load(Ordering::Relaxed),
            self.dc_recv_bytes.load(Ordering::Relaxed),
            self.tcp_write_bytes.load(Ordering::Relaxed),
            self.mailbox_depth.load(Ordering::Relaxed),
        )
    }

    /// Mirror an outbound (local→peer) byte count into the session
    /// aggregate, if this flow is session-tracked. No-op otherwise.
    #[inline]
    fn add_session_out(&self, n: u64) {
        if let Some(s) = &self.session {
            s.bytes_out.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Mirror an inbound (peer→local) byte count into the session
    /// aggregate, if this flow is session-tracked. No-op otherwise.
    #[inline]
    fn add_session_in(&self, n: u64) {
        if let Some(s) = &self.session {
            s.bytes_in.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Session-level throughput aggregate for a daemon-originated tunnel
/// (P3b-3). One per `roomler forward` / `socks5` flow, shared across
/// its per-connection [`FlowStats`] and across WS-reconnect attempts
/// (so `bytes_in`/`bytes_out` are cumulative for the forward's life).
/// Read by the daemon's `flows` LocalAPI verb.
///
/// Named `SessionThroughput` (not `SessionStats`) to avoid colliding
/// with the unrelated video-session `roomler_ai_remote_control::models::
/// SessionStats`.
///
/// `bytes_*` are cumulative (never decremented). `active_flows` is a
/// live GAUGE of currently-pumping connections, maintained by a
/// [`FlowGauge`] RAII guard held for each flow's pump lifetime — so it
/// decrements on normal return AND on a tokio task-abort (`kill_flow`).
/// It is best-effort across a reconnect (a prior session's draining
/// flow can briefly decrement after the next session's
/// [`reset_active_flows`](Self::reset_active_flows)); `saturating_sub`
/// keeps it from underflowing and it self-heals as flows churn.
#[derive(Debug, Default)]
pub struct SessionThroughput {
    /// Cumulative peer→local bytes (the local app RECEIVES).
    pub bytes_in: AtomicU64,
    /// Cumulative local→peer bytes (the local app SENDS).
    pub bytes_out: AtomicU64,
    /// Live count of currently-pumping connections through this flow.
    pub active_flows: AtomicU64,
}

impl SessionThroughput {
    /// `(bytes_in, bytes_out, active_flows)` — relaxed snapshot.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.bytes_in.load(Ordering::Relaxed),
            self.bytes_out.load(Ordering::Relaxed),
            self.active_flows.load(Ordering::Relaxed),
        )
    }

    /// Zero the `active_flows` GAUGE at the start of a session attempt
    /// so a prior session's leaked count (unclean WS teardown) can't
    /// carry over. Does NOT touch the cumulative `bytes_*`.
    pub fn reset_active_flows(&self) {
        self.active_flows.store(0, Ordering::Relaxed);
    }
}

/// RAII guard that holds an `active_flows` increment for one flow's
/// pump lifetime. Increments on construction; saturating-decrements on
/// `Drop` — which tokio runs when the owning task returns normally OR
/// is aborted (`kill_flow`), so the gauge can't leak on either path.
pub(crate) struct FlowGauge(Arc<SessionThroughput>);

impl FlowGauge {
    pub(crate) fn new(session: Arc<SessionThroughput>) -> Self {
        session.active_flows.fetch_add(1, Ordering::Relaxed);
        Self(session)
    }
}

impl Drop for FlowGauge {
    fn drop(&mut self) {
        // AtomicU64 has no saturating fetch_sub; fetch_update with a
        // saturating closure clamps at 0 (a stale cross-attempt drop
        // can otherwise underflow-wrap to u64::MAX).
        let _ = self
            .0
            .active_flows
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

/// In-band half-close sentinel: `[flow_id_le | HALF_CLOSE_MAGIC]`.
/// Non-empty payload because empty-payload (4-byte total) DC
/// messages weren't reliably delivered in the local two-peer
/// fixture — possibly the DCEP empty-binary PPID path interacting
/// badly with our pre-negotiated streams.
///
/// **Why in-band, not wire-level**: SCTP guarantees ordered delivery
/// within a stream, so this byte arrives strictly after every
/// prior data chunk on the same DC. A wire-level half-close
/// (`ClientMsg::TcpHalfClose` over WS) is fired in parallel —
/// useful for audit and bookkeeping — but it can race ahead of or
/// behind in-flight DC chunks and is therefore NOT used to close
/// the mailbox. The mailbox close is exclusively driven by this
/// sentinel inside [`FlowDemux::install`].
pub(crate) const HALF_CLOSE_MAGIC: &[u8] = &[0xFF];

/// Reserved `flow_id` for the idle keepalive frame. Real flows start at
/// 1 (the client's `flow_counter` is `AtomicU32::new(1)` and the agent
/// reuses that id), so 0 never collides with a live flow and serves as a
/// marker that [`FlowDemux::install`] silently drops.
pub const KEEPALIVE_FLOW_ID: u32 = 0;

/// How often each peer sends a keepalive frame over one DC so an idle
/// `webrtc-dc` tunnel's TURN-relay permission / NAT mapping stays warm.
/// webrtc-dc — unlike QUIC, which sets `keep_alive_interval` (8 s) on the
/// endpoint — has no built-in keepalive, so an idle relay path gets
/// reaped: coturn permissions lapse ~5 min and a corp NAT can drop an
/// idle UDP mapping sooner. 20 s comfortably beats both and is negligible
/// on the wire (one 5-byte frame). See [`spawn_dc_keepalive`].
pub const DC_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

// Compile-time invariants. Cross-referenced from the audit log
// dashboard's roll-up — see CLAUDE.md for the constants we lock here.
const _: () = assert!(
    HIGH_WATER_MARK_BYTES >= LOW_WATER_MARK_BYTES * 2,
    "watermark hysteresis must be non-trivial — too close = thrash"
);
// The framed wire message (`CHUNK_BYTES`, which is the framed ceiling
// including the flow_id prefix) must fit webrtc-data's read-loop
// buffer, a fixed `u16::MAX` = 65535 bytes. This is one byte tighter
// than the SCTP max_message_size of 65536 — exceeding it makes the
// receiver's read loop break on `ErrShortBuffer` and never deliver
// another message. See `CHUNK_BYTES` above for the full failure mode.
const _: () = assert!(CHUNK_BYTES <= u16::MAX as usize);
const _: () = assert!(CHUNK_BYTES > mux::FLOW_ID_HEADER_BYTES);

// ────────────────────────────────────────────────────────────────────────────
// Flow demux — one per DC, fans inbound DC messages to per-flow
// mailboxes by decoding the 4-byte `flow_id` prefix.
// ────────────────────────────────────────────────────────────────────────────

/// Per-flow demux entry: the mailbox sender + the flow's shared
/// [`FlowStats`]. The stats live here (not just in `run_flow`) so the
/// demux `on_message` handler — which runs per-DC, fanning out to many
/// flows — can bump `dc_recv_bytes` for the right flow the instant a
/// message is dispatched. Same `Arc<FlowStats>` is handed to
/// `run_flow` so the throughput logger and the receive counter share
/// one set of atomics.
type FlowMap = Arc<
    Mutex<
        HashMap<
            u32,
            (
                mpsc::Sender<Bytes>,
                Arc<FlowStats>,
                Option<(Arc<PendingIngress>, u8)>,
            ),
        >,
    >,
>;

/// Owns one `RTCDataChannel` and routes inbound messages to per-flow
/// `mpsc::Receiver<Bytes>`. Install once per DC right after the pool
/// is open; `register` before sending the first `TcpForwardAccept`
/// for that flow.
#[derive(Clone)]
pub struct FlowDemux {
    dc: Arc<RTCDataChannel>,
    flows: FlowMap,
    pending_slots: Arc<tokio::sync::Semaphore>,
    /// Session throughput aggregate (P3b-3), stamped onto every
    /// registered flow's [`FlowStats`] so the pumps mirror bytes into
    /// it. `None` on the agent target side + tests (no `flows` verb).
    session: Option<Arc<SessionThroughput>>,
}

/// Pending prefixes are bounded independently of the existing active-flow
/// throughput queue: at most 128 pending opens/pool and 256 KiB each. No global
/// unknown-flow cache exists. Byte budget + DC binding share one atomic state,
/// so a racing packet cannot overflow/change DC after Accept validation.
const MAX_PENDING_POOL_FLOWS: usize = 128;
const MAX_PENDING_PREFIX_BYTES: usize = 256 * 1024;
const PREFIX_BYTES_MASK: u64 = (1 << 24) - 1;
const PREFIX_SEEN_MASK: u64 = 0xffff_ffff << 24;
const PREFIX_ACTIVE: u64 = 1 << 63;
const PREFIX_OVERFLOW: u64 = 1 << 62;
#[derive(Default)]
struct PendingIngress {
    state: AtomicU64,
}
impl PendingIngress {
    fn admit(&self, dc_index: u8, len: usize) -> bool {
        if dc_index >= 32 {
            return false;
        }
        let mut old = self.state.load(Ordering::Acquire);
        loop {
            if old & PREFIX_ACTIVE != 0 {
                return ((old >> 56) & 0x3f) as u8 == dc_index;
            }
            if old & PREFIX_OVERFLOW != 0 {
                return false;
            }
            let bytes = (old & PREFIX_BYTES_MASK) as usize;
            let allowed = bytes
                .checked_add(len)
                .is_some_and(|n| n <= MAX_PENDING_PREFIX_BYTES);
            let next = if allowed {
                (old & !PREFIX_BYTES_MASK) | (bytes + len) as u64 | (1 << (24 + dc_index))
            } else {
                old | PREFIX_OVERFLOW
            };
            match self
                .state
                .compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return allowed,
                Err(current) => old = current,
            }
        }
    }
    fn accept(&self, dc_index: u8) -> anyhow::Result<()> {
        anyhow::ensure!(dc_index < 32, "unsupported authoritative DC index");
        let mut old = self.state.load(Ordering::Acquire);
        loop {
            anyhow::ensure!(
                old & PREFIX_OVERFLOW == 0,
                "pending forward prefix exceeded 256 KiB"
            );
            anyhow::ensure!(
                old & PREFIX_ACTIVE == 0,
                "flow registration already activated"
            );
            anyhow::ensure!(
                old & PREFIX_SEEN_MASK & !(1 << (24 + dc_index)) == 0,
                "pending bytes arrived on a non-authoritative DC"
            );
            let next = old | PREFIX_ACTIVE | ((dc_index as u64) << 56);
            match self
                .state
                .compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(current) => old = current,
            }
        }
    }
}

/// Reserve one already-known local flow before its request crosses signalling.
/// All DC aliases share ONE bounded mailbox/stats, not one queue per channel.
/// No payload is released to TCP until the caller receives authoritative Accept.
/// Drop removes only our own aliases, including task-abort/send/reject paths.
pub struct FlowPoolRegistration {
    flow_id: u32,
    demuxes: Arc<Vec<FlowDemux>>,
    from_dc: Option<mpsc::Receiver<Bytes>>,
    stats: Arc<FlowStats>,
    ingress: Arc<PendingIngress>,
    pending: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl FlowPoolRegistration {
    pub async fn reserve(demuxes: Arc<Vec<FlowDemux>>, flow_id: u32) -> anyhow::Result<Self> {
        let first = demuxes
            .first()
            .ok_or_else(|| anyhow::anyhow!("empty DC pool"))?;
        anyhow::ensure!(flow_id != KEEPALIVE_FLOW_ID, "reserved keepalive flow ID");
        anyhow::ensure!(
            demuxes.len() <= 32,
            "DC pool exceeds pending reservation bound"
        );
        let pending = first
            .pending_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("pending DC forward capacity reached"))?;
        let (tx, rx) = mpsc::channel(FLOW_INBOX_CAP);
        let stats = Arc::new(FlowStats {
            session: first.session.clone(),
            ..Default::default()
        });
        // Construct the guard before the first await/insert: cancellation during
        // partial registration still removes every inserted alias by identity.
        let reservation = Self {
            flow_id,
            demuxes,
            from_dc: Some(rx),
            stats,
            ingress: Arc::new(PendingIngress::default()),
            pending: Some(pending),
        };
        for (idx, demux) in reservation.demuxes.iter().enumerate() {
            let mut map = demux.flows.lock().await;
            anyhow::ensure!(
                !map.contains_key(&flow_id),
                "flow already registered in DC pool"
            );
            map.insert(
                flow_id,
                (
                    tx.clone(),
                    reservation.stats.clone(),
                    Some((reservation.ingress.clone(), idx as u8)),
                ),
            );
        }
        // Do NOT retain tx in the guard: in-band half-close must drop the last
        // sender and deliver EOF once the chosen DC unregisters its alias.
        drop(tx);
        Ok(reservation)
    }
    async fn remove_owned(demux: &FlowDemux, flow_id: u32, stats: &Arc<FlowStats>) {
        let mut map = demux.flows.lock().await;
        if map
            .get(&flow_id)
            .is_some_and(|(_, current, _)| Arc::ptr_eq(current, stats))
        {
            map.remove(&flow_id);
        }
    }
    pub async fn activate(
        &mut self,
        dc_index: u8,
    ) -> anyhow::Result<(mpsc::Receiver<Bytes>, Arc<FlowStats>)> {
        anyhow::ensure!(
            (dc_index as usize) < self.demuxes.len(),
            "server returned out-of-range dc_index {dc_index}"
        );
        self.ingress.accept(dc_index)?;
        for (idx, demux) in self.demuxes.iter().enumerate() {
            if idx != dc_index as usize {
                Self::remove_owned(demux, self.flow_id, &self.stats).await;
            }
        }
        let rx = self
            .from_dc
            .take()
            .ok_or_else(|| anyhow::anyhow!("flow registration already activated"))?;
        self.pending.take();
        Ok((rx, self.stats.clone()))
    }
}
impl Drop for FlowPoolRegistration {
    fn drop(&mut self) {
        let demuxes = self.demuxes.clone();
        let stats = self.stats.clone();
        let flow_id = self.flow_id;
        let pending = self.pending.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _pending_until_removed = pending;
                for demux in demuxes.iter() {
                    Self::remove_owned(demux, flow_id, &stats).await;
                }
            });
        }
    }
}

impl FlowDemux {
    /// Wrap a DC and install the routing `on_message` handler. The
    /// handler `await`s on a slow mailbox so backpressure cascades
    /// into the DC reader. Unregistered flow_ids are logged + dropped
    /// (e.g. the peer raced a close). `session` is the daemon's
    /// per-forward throughput aggregate (P3b-3) or `None` (agent side /
    /// tests).
    pub async fn install(dc: Arc<RTCDataChannel>, session: Option<Arc<SessionThroughput>>) -> Self {
        let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
        let flows_for_handler = Arc::clone(&flows);
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let flows = Arc::clone(&flows_for_handler);
            Box::pin(async move {
                let Some((flow_id, payload)) = mux::decode(&msg.data) else {
                    warn!(
                        len = msg.data.len(),
                        "tunnel DC message too short for flow_id prefix"
                    );
                    return;
                };
                // Idle keepalive frame (see `spawn_dc_keepalive`): the
                // reserved flow_id carries no flow data — drop it silently
                // so it isn't logged as an unregistered flow.
                if flow_id == KEEPALIVE_FLOW_ID {
                    trace!("tunnel DC idle keepalive received");
                    return;
                }
                // In-band half-close. SCTP ordering guarantees this
                // byte arrives strictly after every prior chunk on
                // the same flow, so dropping the sender now means
                // `pump_dc_to_tcp` sees None on its next recv()
                // AFTER all data has been drained. Wire-level
                // `TcpHalfClose` is also emitted by the sender's
                // pump (for audit), but only this in-band sentinel
                // closes the mailbox.
                if payload == HALF_CLOSE_MAGIC {
                    trace!(flow_id, "tunnel flow half-close marker received");
                    flows.lock().await.remove(&flow_id);
                    return;
                }
                let entry = {
                    let map = flows.lock().await;
                    map.get(&flow_id).cloned()
                };
                let Some((tx, stats, pending)) = entry else {
                    trace!(
                        flow_id,
                        len = payload.len(),
                        "tunnel DC message for unregistered flow — dropping"
                    );
                    return;
                };
                if let Some((ingress, dc_index)) = pending
                    && !ingress.admit(dc_index, payload.len())
                {
                    return; // bounded/incorrect pending flow is rejected on Accept
                }
                // Count receipt the instant we dispatch — BEFORE the
                // (potentially blocking) mailbox send — so `dc_recv_bytes`
                // reflects what actually arrived off the DC, independent
                // of how fast the local consumer drains. This is the
                // counter that splits "stuck on the wire" from "stuck in
                // the consumer" in the throughput log.
                stats
                    .dc_recv_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                if let Err(e) = tx.send(Bytes::copy_from_slice(payload)).await {
                    debug!(flow_id, %e, "tunnel flow mailbox closed; dropping payload");
                }
            })
        }));
        Self {
            dc,
            flows,
            session,
            pending_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_POOL_FLOWS)),
        }
    }

    /// Open a mailbox for `flow_id`. Returns the receiver (yielding
    /// payload `Bytes` with the flow_id prefix already stripped) plus
    /// the flow's [`FlowStats`] — hand the SAME `Arc<FlowStats>` to
    /// [`run_flow`] so the demux's `dc_recv_bytes` counter and the
    /// pumps' counters share one set of atomics. The mailbox closes
    /// when [`unregister`] fires or the DC drops.
    pub async fn register(&self, flow_id: u32) -> (mpsc::Receiver<Bytes>, Arc<FlowStats>) {
        let (tx, rx) = mpsc::channel(FLOW_INBOX_CAP);
        let stats = Arc::new(FlowStats {
            session: self.session.clone(),
            ..Default::default()
        });
        let mut map = self.flows.lock().await;
        if map
            .insert(flow_id, (tx, Arc::clone(&stats), None))
            .is_some()
        {
            warn!(
                flow_id,
                "tunnel flow re-registered; previous mailbox dropped"
            );
        }
        (rx, stats)
    }

    /// Close the mailbox for `flow_id`. Idempotent.
    pub async fn unregister(&self, flow_id: u32) {
        let mut map = self.flows.lock().await;
        map.remove(&flow_id);
    }

    #[cfg(test)]
    pub(crate) async fn registered_for_test(&self, flow_id: u32) -> bool {
        self.flows.lock().await.contains_key(&flow_id)
    }

    /// Borrow the DC so the caller can hand it to [`run_flow`].
    pub fn dc(&self) -> Arc<RTCDataChannel> {
        Arc::clone(&self.dc)
    }
}

/// Spawn a task that sends a tiny keepalive frame over `dc` every
/// [`DC_KEEPALIVE_INTERVAL`], keeping an idle `webrtc-dc` tunnel's
/// TURN-relay permission / NAT mapping warm. Both peers run this — the
/// client once its DC pool opens, the agent once it installs its demuxes
/// — so traffic flows both ways and neither relay half lapses. The frame
/// rides [`KEEPALIVE_FLOW_ID`], which [`FlowDemux::install`] drops on
/// receipt. QUIC needs no equivalent: quinn's `keep_alive_interval` does
/// this at the transport layer. Fire-and-forget: the task self-terminates
/// when the DC send fails (the pool is torn down at session end).
pub fn spawn_dc_keepalive(dc: Arc<RTCDataChannel>) {
    // Non-empty 1-byte payload → a 5-byte frame. Empty-payload (4-byte)
    // DC messages were unreliably delivered in the local two-peer fixture
    // (see the `HALF_CLOSE_MAGIC` note), so never send a bare prefix.
    let frame = Bytes::from(mux::encode(KEEPALIVE_FLOW_ID, &[0u8]));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(DC_KEEPALIVE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // consume the immediate first tick
        loop {
            tick.tick().await;
            if let Err(e) = dc.send(&frame).await {
                debug!(%e, "tunnel DC keepalive send failed; keepalive task exiting");
                break;
            }
        }
    });
}

// ────────────────────────────────────────────────────────────────────────────
// Bidirectional pump — one task per flow, runs until close.
// ────────────────────────────────────────────────────────────────────────────

/// Callback invoked when [`run_flow`]'s TCP→DC pump observes local
/// EOF (i.e. the local TCP read half closed cleanly). The caller
/// uses this to fire a wire-level [`ClientMsg::TcpHalfClose`] /
/// [`ServerMsg::TcpHalfClose`] for audit + accounting in the
/// server's `tunnel_audit` collection. **The wire message is not
/// load-bearing for the data-plane half-close** — the in-band
/// [`HALF_CLOSE_MAGIC`] sentinel on the DC is what actually closes
/// the peer's mailbox, because SCTP's per-stream ordering
/// guarantees the marker arrives strictly after every prior data
/// chunk.
///
/// Decoupled from the wire because tunnel-core has no dependency on
/// the WebSocket sink. The CLI / agent owns sink-shaped state.
pub type HalfCloseSink = std::sync::Arc<dyn Fn(u32) + Send + Sync>;

/// Session-scoped cancellation for a WebRTC-DC carrier's live flows (#2129).
///
/// A `webrtc-dc-v1` session that ends while a flow is live cannot end that
/// flow through the data plane alone: [`pump_dc_to_tcp`] waits on a mailbox
/// whose only sender lives in the DC's `on_message` closure, which the flow's
/// own `dc: Arc<RTCDataChannel>` keeps alive, and [`pump_tcp_to_dc`] waits on
/// a `read` that an idle app never satisfies. So every teardown path must
/// actively tell its live flows to stop. [`FlowCanceller::cancel`] resolves
/// every [`FlowCancel::cancelled`] handed to [`run_flow`], which then stops
/// both halves and returns — dropping this flow's DC reference so the peer's
/// ICE/DTLS/SCTP sockets are freed once the peer itself is closed.
///
/// A mailbox close alone is NOT enough: it only half-closes (the demux's
/// in-band `HALF_CLOSE_MAGIC` path ends [`pump_dc_to_tcp`] but leaves
/// [`pump_tcp_to_dc`] waiting on an idle `read`), so cancellation drives both
/// halves. Only an explicit [`cancel`](FlowCanceller::cancel) resolves it;
/// dropping the canceller does not, so each teardown triggers it deliberately
/// (the exit does it in `AgentTunnelPeer::close`, the client when its DC
/// carrier drops).
#[derive(Default)]
pub struct FlowCanceller {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl FlowCanceller {
    pub fn new() -> Self {
        Self::default()
    }

    /// A handle for one flow to observe. Cheap; clone one per flow.
    pub fn handle(&self) -> FlowCancel {
        FlowCancel {
            cancelled: Arc::clone(&self.cancelled),
            notify: Arc::clone(&self.notify),
        }
    }

    /// End every live flow of this session. Idempotent.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

/// A flow's handle onto its session's [`FlowCanceller`]. [`run_flow`] selects
/// on [`cancelled`](Self::cancelled) alongside its two pumps.
#[derive(Clone)]
pub struct FlowCancel {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl FlowCancel {
    /// Resolves once this session is cancelled. Latches: a flow that checks
    /// after the cancel still returns at once. The waiter is armed BEFORE the
    /// flag is re-read, so a `cancel` that fires between the read and the
    /// await is not missed (`Notify` stores no permit for `notify_waiters`) —
    /// the same race-free shape as [`crate::driver`]'s `Carrier::drained`.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// Drive a single accepted forward to completion. Returns the
/// terminating [`CloseReason`] which the caller plumbs into the
/// `rc:tunnel.tcp.closed` audit message.
///
/// Implementation: spawns one inner task for TCP→DC (with
/// `bufferedAmountLow`-driven backpressure) and one for DC→TCP.
/// **Both halves are awaited** so half-close semantics survive an
/// echo-style flow that writes 1 MiB then needs to read 1 MiB back
/// from the peer. Outbound EOF triggers `on_local_eof(flow_id)` —
/// the caller relays a wire-level `TcpHalfClose` so the peer's
/// dispatch unregisters the flow on its [`FlowDemux`], which causes
/// THIS side's `pump_dc_to_tcp` to see None on `recv()` and shut
/// down its local TCP write half. (Previously this used an in-band
/// `HALF_CLOSE_MAGIC = [0xFF]` sentinel multiplexed through the DC;
/// T2.10 lifts that into the wire-level message.)
///
/// `cancel` is the session's [`FlowCancel`] (#2129): when the session ends
/// with this flow still live, it resolves and both halves are stopped at
/// once — the normal half-close path can only end one of them, so without
/// this an idle app or target would pin the flow (and, on the exit, the DC's
/// whole ICE/DTLS/SCTP socket set) forever.
pub async fn run_flow(
    tcp: TcpStream,
    dc: Arc<RTCDataChannel>,
    flow_id: u32,
    mut from_dc: mpsc::Receiver<Bytes>,
    on_local_eof: HalfCloseSink,
    stats: Arc<FlowStats>,
    cancel: FlowCancel,
) -> CloseReason {
    // P3b-3: hold an `active_flows` gauge for this flow's pump lifetime
    // (no-op when not session-tracked). Drops on return AND on abort.
    let _gauge = stats.session.clone().map(FlowGauge::new);
    // Set the DC's low-water threshold once. `on_buffered_amount_low`
    // fires whenever the SCTP send queue drops back to or below this
    // value — i.e. when we have room to push more.
    dc.set_buffered_amount_low_threshold(LOW_WATER_MARK_BYTES)
        .await;
    let resume = Arc::new(Notify::new());
    let resume_handler = Arc::clone(&resume);
    dc.on_buffered_amount_low(Box::new(move || {
        let resume = Arc::clone(&resume_handler);
        Box::pin(async move {
            resume.notify_waiters();
        })
    }))
    .await;

    let (read_half, write_half) = tcp.into_split();

    // rc.66/rc.78 instrumentation: per-flow byte counters with a
    // periodic logger that prints {tcp_read, dc_send, dc_recv,
    // tcp_write, mailbox_depth} every 2 s. The `stats` are created by
    // [`FlowDemux::register`] and shared with the demux so `dc_recv`
    // reflects what arrived off the DC. The logger task dies when the
    // flow finishes (both pumps return). Throughput is reported as
    // delta-per-period, so "5 MB/s" means 5 MB moved through that
    // stage in the last 2 s window.
    //
    // rc.78: the `dc_recv_kbps` column is the decisive one for the
    // stall hunt — compare it against the PEER's `dc_send_kbps`:
    //   * peer dc_send climbing, our dc_recv flat  → wire / SCTP
    //     receive-path stall (bytes left the sender, never reached
    //     our on_message)
    //   * dc_recv tracks peer dc_send, tcp_write lags → local
    //     consumer stall (but mailbox_depth would also rise)
    let logger_handle = spawn_flow_logger(flow_id, Arc::clone(&stats));

    // Spawn TCP → DC.
    let dc_for_send = Arc::clone(&dc);
    let resume_for_send = Arc::clone(&resume);
    let on_local_eof_for_send = Arc::clone(&on_local_eof);
    let stats_for_send = Arc::clone(&stats);
    let mut tcp_to_dc = tokio::spawn(async move {
        pump_tcp_to_dc(
            read_half,
            dc_for_send,
            flow_id,
            resume_for_send,
            on_local_eof_for_send,
            stats_for_send,
        )
        .await
    });

    // Spawn DC → TCP.
    let stats_for_recv = Arc::clone(&stats);
    let mut dc_to_tcp = tokio::spawn(async move {
        pump_dc_to_tcp(write_half, &mut from_dc, flow_id, stats_for_recv).await
    });

    // #2129 — race the two pumps against the session's cancellation. The
    // pumps end themselves on EOF / error; cancellation is the path for a
    // session that ends while this flow is live, where neither pump can end
    // on its own (one waits on a mailbox its own DC pins, the other on an
    // idle `read`). On cancel, abort both — dropping each pump's TcpStream
    // half closes the local socket in BOTH directions, so the app/target
    // sees EOF or RST with no CLOSE-WAIT left behind — and return, releasing
    // this flow's DC reference.
    let (r1, r2) = tokio::select! {
        pair = async {
            let r1 = (&mut tcp_to_dc).await.unwrap_or(CloseReason::IoError);
            let r2 = (&mut dc_to_tcp).await.unwrap_or(CloseReason::IoError);
            (r1, r2)
        } => pair,
        _ = cancel.cancelled() => (CloseReason::ServerTerminated, CloseReason::ServerTerminated),
    };
    // Cancelled → stop both halves now; finished → both are already no-ops.
    tcp_to_dc.abort();
    dc_to_tcp.abort();

    // Log the final tallies before the logger task is aborted, so
    // the operator gets a one-shot summary of the flow's lifetime
    // throughput even if the 2 s ticker hadn't fired since the last
    // delta.
    let (read_total, send_total, recv_total, write_total, _mb_depth) = stats.snapshot();
    info!(
        flow_id,
        tcp_read_total = read_total,
        dc_send_total = send_total,
        dc_recv_total = recv_total,
        tcp_write_total = write_total,
        "tunnel flow closed — final throughput totals"
    );
    logger_handle.abort();

    if matches!(r1, CloseReason::ServerTerminated) {
        // #2129 — the session ended out from under a live flow.
        CloseReason::ServerTerminated
    } else if matches!(r1, CloseReason::Eof) && matches!(r2, CloseReason::Eof) {
        CloseReason::Eof
    } else {
        CloseReason::IoError
    }
}

/// Spawn the per-flow 2 s throughput logger shared by [`run_flow`]
/// (WebRTC-DC) and [`run_flow_quic`] (QUIC). Samples [`FlowStats`] every
/// 2 s and logs the `{tcp_read, dc_send, dc_recv, tcp_write}` deltas +
/// totals — the SAME line shape across transports, so the admin-UI log
/// viewer and the stall-diagnosis comparison work identically. Abort the
/// returned handle when the flow ends.
fn spawn_flow_logger(flow_id: u32, stats: Arc<FlowStats>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut prev = stats.snapshot();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Burn the immediate first tick — `interval` fires right away by
        // default, which would log a useless zero-delta on every flow.
        interval.tick().await;
        loop {
            interval.tick().await;
            let cur = stats.snapshot();
            let d_read = cur.0.saturating_sub(prev.0);
            let d_send = cur.1.saturating_sub(prev.1);
            let d_recv = cur.2.saturating_sub(prev.2);
            let d_write = cur.3.saturating_sub(prev.3);
            if d_read != 0 || d_send != 0 || d_recv != 0 || d_write != 0 {
                info!(
                    flow_id,
                    tcp_read_total = cur.0,
                    dc_send_total = cur.1,
                    dc_recv_total = cur.2,
                    tcp_write_total = cur.3,
                    mailbox_depth = cur.4,
                    tcp_read_kbps = d_read / 1024 / 2,
                    dc_send_kbps = d_send / 1024 / 2,
                    dc_recv_kbps = d_recv / 1024 / 2,
                    tcp_write_kbps = d_write / 1024 / 2,
                    "tunnel flow throughput (2s window)"
                );
            }
            prev = cur;
        }
    })
}

/// QUIC variant of [`run_flow`]: drive one accepted forward over a
/// native QUIC bidirectional stream. **None** of the WebRTC-DC
/// machinery applies — no `flow_id` framing (the stream is dedicated to
/// one flow, with a one-time preamble handled by
/// [`crate::transport::quic::open_flow`]/`accept_flow`), no
/// `HALF_CLOSE_MAGIC` (QUIC FIN), no `bufferedAmountLow` watermark dance
/// (quinn's per-stream flow control applies backpressure on
/// `write_all`), and no 65535-byte cap. The same [`FlowStats`] columns
/// are populated (tcp_read/dc_send outbound, dc_recv/tcp_write inbound)
/// so the 2 s logger reads identically across transports. Both halves
/// are awaited so half-close survives a duplex flow.
pub async fn run_flow_quic(
    tcp: TcpStream,
    mut send: SendStream,
    mut recv: RecvStream,
    flow_id: u32,
    stats: Arc<FlowStats>,
) -> CloseReason {
    // P3b-3: hold an `active_flows` gauge for this flow's pump lifetime
    // (no-op when not session-tracked). Drops on return AND on abort.
    let _gauge = stats.session.clone().map(FlowGauge::new);
    let (mut read_half, mut write_half) = tcp.into_split();
    let logger_handle = spawn_flow_logger(flow_id, Arc::clone(&stats));

    // TCP → QUIC send.
    let stats_send = Arc::clone(&stats);
    let tcp_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK_BYTES];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => {
                    // Local read half EOF → clean FIN on the QUIC stream.
                    let _ = send.finish();
                    return CloseReason::Eof;
                }
                Ok(n) => {
                    stats_send
                        .tcp_read_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                    stats_send.add_session_out(n as u64);
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        debug!(flow_id, %e, "quic pump: stream write error");
                        return CloseReason::IoError;
                    }
                    // quinn's write_all returns once the bytes are
                    // accepted into the (flow-controlled) send buffer —
                    // backpressure is implicit, no watermark poll needed.
                    stats_send
                        .dc_send_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    debug!(flow_id, %e, "quic pump: TCP read error");
                    let _ = send.reset(0u32.into());
                    return CloseReason::IoError;
                }
            }
        }
    });

    // QUIC recv → TCP write.
    let stats_recv = Arc::clone(&stats);
    let quic_to_tcp = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK_BYTES];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    stats_recv
                        .dc_recv_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                    if let Err(e) = write_half.write_all(&buf[..n]).await {
                        debug!(flow_id, %e, "quic pump: TCP write error");
                        return CloseReason::IoError;
                    }
                    stats_recv
                        .tcp_write_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                    stats_recv.add_session_in(n as u64);
                }
                Ok(None) => {
                    // Peer finished the stream (FIN) — shut the local
                    // write half so downstream sees EOF.
                    if let Err(e) = write_half.shutdown().await {
                        debug!(flow_id, %e, "quic pump: TCP shutdown after EOF failed");
                    }
                    return CloseReason::Eof;
                }
                Err(e) => {
                    debug!(flow_id, %e, "quic pump: stream read error");
                    return CloseReason::IoError;
                }
            }
        }
    });

    let r1 = tcp_to_quic.await.unwrap_or(CloseReason::IoError);
    let r2 = quic_to_tcp.await.unwrap_or(CloseReason::IoError);

    let (read_total, send_total, recv_total, write_total, _mb) = stats.snapshot();
    info!(
        flow_id,
        tcp_read_total = read_total,
        dc_send_total = send_total,
        dc_recv_total = recv_total,
        tcp_write_total = write_total,
        "tunnel flow closed (quic) — final throughput totals"
    );
    logger_handle.abort();

    if matches!(r1, CloseReason::Eof) && matches!(r2, CloseReason::Eof) {
        CloseReason::Eof
    } else {
        CloseReason::IoError
    }
}

// ────────────────────────────────────────────────────────────────────────────
// UDP ASSOCIATE datagram carriage (SOCKS5 UDP over the tunnel)
// ────────────────────────────────────────────────────────────────────────────

/// Largest UDP datagram carried over a flow. 65535 covers any real
/// UDP payload and is exactly what the 2-byte length prefix can encode.
pub const MAX_UDP_DATAGRAM: usize = u16::MAX as usize;

/// Default idle timeout for a UDP flow. UDP has no EOF, so a flow that
/// sees no traffic in either direction for this long is closed (RFC 1928
/// ties the association to the SOCKS control TCP connection; individual
/// per-target flows idle-close under it). 60 s comfortably outlives a
/// DNS query/response and a typical request/response exchange.
pub const UDP_FLOW_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Frame one datagram for carriage: `[u16 BE len | datagram]`. The
/// length prefix (a) delimits datagrams on a QUIC reliable stream and
/// (b) guarantees a UDP flow's DC payload can never collide with the
/// 1-byte [`HALF_CLOSE_MAGIC`] TCP sentinel (a framed datagram is ≥ 2
/// bytes). Returns `None` if the datagram exceeds [`MAX_UDP_DATAGRAM`]
/// (dropped, matching UDP's lossy semantics).
pub fn frame_udp_datagram(dg: &[u8]) -> Option<Vec<u8>> {
    if dg.len() > MAX_UDP_DATAGRAM {
        return None;
    }
    let mut out = Vec::with_capacity(2 + dg.len());
    out.extend_from_slice(&(dg.len() as u16).to_be_bytes());
    out.extend_from_slice(dg);
    Some(out)
}

/// Strip the 2-byte length prefix from a DC-carried UDP frame (one DC
/// message = one framed datagram). Returns the datagram bytes, or `None`
/// on a short / malformed frame.
pub fn deframe_udp_datagram(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    buf.get(2..2 + len)
}

/// Read one length-prefixed datagram off a QUIC recv stream. Returns
/// `Ok(None)` on a clean stream FIN at a datagram boundary (the peer
/// closed the flow). A FIN mid-frame is an error.
pub async fn quic_read_datagram(recv: &mut RecvStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut lenb = [0u8; 2];
    match recv.read_exact(&mut lenb).await {
        Ok(()) => {}
        // FinishedEarly(0) == clean FIN exactly at a datagram boundary.
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(std::io::Error::other(e)),
    }
    let len = u16::from_be_bytes(lenb) as usize;
    let mut dg = vec![0u8; len];
    recv.read_exact(&mut dg)
        .await
        .map_err(std::io::Error::other)?;
    Ok(Some(dg))
}

/// Write one length-prefixed datagram to a QUIC send stream. Oversized
/// datagrams are dropped (UDP semantics) rather than erroring the flow.
pub async fn quic_write_datagram(send: &mut SendStream, dg: &[u8]) -> std::io::Result<()> {
    let Some(framed) = frame_udp_datagram(dg) else {
        return Ok(());
    };
    send.write_all(&framed).await.map_err(std::io::Error::other)
}

/// Frame + send one UDP datagram on a DataChannel for `flow_id`
/// (`mux::encode(flow_id, [u16 len | datagram])`). Convenience so a
/// caller (the tunnel-client UDP relay) needn't depend on `bytes` /
/// webrtc directly. Oversized datagrams are dropped.
pub async fn send_udp_datagram_dc(
    dc: &RTCDataChannel,
    flow_id: u32,
    dg: &[u8],
) -> std::io::Result<()> {
    let Some(framed) = frame_udp_datagram(dg) else {
        return Ok(());
    };
    dc.send(&Bytes::from(mux::encode(flow_id, &framed)))
        .await
        .map(|_| ())
        .map_err(std::io::Error::other)
}

/// Agent-side UDP flow pump over the WebRTC DataChannel pool. `udp` is a
/// socket the caller has already `connect()`ed to the flow's target, so
/// `send`/`recv` are unambiguous. Datagrams from the carrier
/// (`from_dc`, each mailbox `Bytes` = one `[u16 len | datagram]` frame)
/// are sent to the target; datagrams from the target are framed and
/// pushed onto the DC as `mux::encode(flow_id, [u16 len | datagram])`.
///
/// A single idle timer covers both directions and resets on any
/// activity — a one-directional stream (media in, nothing back) keeps
/// the flow alive. Returns [`CloseReason::IdleTimeout`] when both
/// directions are silent for `idle_timeout`, [`CloseReason::Eof`] when
/// the client closes the flow (mailbox drop), or [`CloseReason::IoError`]
/// on a transport error.
pub async fn run_flow_udp_dc(
    udp: tokio::net::UdpSocket,
    dc: Arc<RTCDataChannel>,
    flow_id: u32,
    mut from_dc: mpsc::Receiver<Bytes>,
    idle_timeout: std::time::Duration,
    stats: Arc<FlowStats>,
) -> CloseReason {
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            // carrier → target
            m = from_dc.recv() => match m {
                Some(framed) => {
                    if let Some(dg) = deframe_udp_datagram(&framed) {
                        stats.dc_recv_bytes.fetch_add(dg.len() as u64, Ordering::Relaxed);
                        match udp.send(dg).await {
                            Ok(_) => { stats.tcp_write_bytes.fetch_add(dg.len() as u64, Ordering::Relaxed); }
                            Err(e) => debug!(flow_id, %e, "udp pump: send to target failed"),
                        }
                    } else {
                        warn!(flow_id, len = framed.len(), "udp pump: malformed carrier frame");
                    }
                }
                None => return CloseReason::Eof,
            },
            // target → carrier
            r = udp.recv(&mut buf) => match r {
                Ok(n) => {
                    stats.tcp_read_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(framed) = frame_udp_datagram(&buf[..n]) {
                        if let Err(e) = dc.send(&Bytes::from(mux::encode(flow_id, &framed))).await {
                            debug!(flow_id, %e, "udp pump: DC send failed");
                            return CloseReason::IoError;
                        }
                        stats.dc_send_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    debug!(flow_id, %e, "udp pump: recv from target failed");
                    return CloseReason::IoError;
                }
            },
            _ = tokio::time::sleep(idle_timeout) => return CloseReason::IdleTimeout,
        }
    }
}

/// Agent-side UDP flow pump over a native QUIC bidirectional stream. The
/// `udp` socket is `connect()`ed to the target; the stream carries
/// `[u16 len | datagram]` frames (via [`quic_read_datagram`] /
/// [`quic_write_datagram`]). Idle + close semantics match
/// [`run_flow_udp_dc`]; a clean stream FIN from the client closes the
/// flow.
pub async fn run_flow_udp_quic(
    udp: tokio::net::UdpSocket,
    mut send: SendStream,
    mut recv: RecvStream,
    flow_id: u32,
    idle_timeout: std::time::Duration,
    stats: Arc<FlowStats>,
) -> CloseReason {
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    loop {
        tokio::select! {
            r = quic_read_datagram(&mut recv) => match r {
                Ok(Some(dg)) => {
                    stats.dc_recv_bytes.fetch_add(dg.len() as u64, Ordering::Relaxed);
                    match udp.send(&dg).await {
                        Ok(_) => { stats.tcp_write_bytes.fetch_add(dg.len() as u64, Ordering::Relaxed); }
                        Err(e) => debug!(flow_id, %e, "udp pump: send to target failed"),
                    }
                }
                Ok(None) => return CloseReason::Eof,
                Err(e) => {
                    debug!(flow_id, %e, "udp pump: quic read failed");
                    return CloseReason::IoError;
                }
            },
            r = udp.recv(&mut buf) => match r {
                Ok(n) => {
                    stats.tcp_read_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    if let Err(e) = quic_write_datagram(&mut send, &buf[..n]).await {
                        debug!(flow_id, %e, "udp pump: quic write failed");
                        return CloseReason::IoError;
                    }
                    stats.dc_send_bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    debug!(flow_id, %e, "udp pump: recv from target failed");
                    return CloseReason::IoError;
                }
            },
            _ = tokio::time::sleep(idle_timeout) => return CloseReason::IdleTimeout,
        }
    }
}

async fn pump_tcp_to_dc(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    dc: Arc<RTCDataChannel>,
    flow_id: u32,
    resume: Arc<Notify>,
    on_local_eof: HalfCloseSink,
    stats: Arc<FlowStats>,
) -> CloseReason {
    let mut buf = vec![0u8; CHUNK_BYTES - mux::FLOW_ID_HEADER_BYTES];
    loop {
        // Backpressure gate. Check current buffered_amount; if
        // above HIGH, wait on the notifier (which fires when SCTP
        // drains to LOW).
        //
        // rc.78 instrumentation: promote the pause/resume tracing from
        // trace! to info! and count how long / how many wakeups a
        // single pause spans. This is the OTHER half of the stall
        // diagnostic: if the log shows "pump paused buffered=4.x MiB"
        // followed by repeated "still paused" heartbeats and NO
        // "resumed" line, the `bufferedAmountLow` event has stopped
        // firing (a known webrtc-rs footgun) and the sender is wedged
        // — distinct from a receive-side stall (which shows as the
        // peer's dc_recv flatlining while THIS side never even fills
        // its send buffer). Only the FIRST entry into the paused state
        // logs at info; subsequent re-checks within the same pause use
        // a heartbeat every ~2 s so a long pause is visible without
        // spamming.
        let mut paused_wakeups: u64 = 0;
        loop {
            let buffered = dc.buffered_amount().await;
            if buffered <= HIGH_WATER_MARK_BYTES {
                if paused_wakeups > 0 {
                    info!(
                        flow_id,
                        buffered,
                        wakeups = paused_wakeups,
                        "tunnel pump resumed — buffered drained below HIGH_WATER"
                    );
                }
                break;
            }
            // Log the first pause at info; thereafter a heartbeat every
            // ~8 wakeups (≈2 s at the 250 ms re-check cadence) so a
            // wedged sender is loud but a healthy transient pause is one
            // line.
            if paused_wakeups == 0 {
                info!(
                    flow_id,
                    buffered,
                    high_water = HIGH_WATER_MARK_BYTES,
                    "tunnel pump paused — buffered above HIGH_WATER, awaiting bufferedAmountLow"
                );
            } else if paused_wakeups.is_multiple_of(8) {
                info!(
                    flow_id,
                    buffered,
                    wakeups = paused_wakeups,
                    "tunnel pump STILL paused — bufferedAmountLow has not fired \
                     (possible sender wedge)"
                );
            }
            paused_wakeups += 1;
            // Race a small timeout so we don't deadlock if the
            // low-water event somehow never fires (defensive — the
            // event SHOULD fire reliably).
            tokio::select! {
                _ = resume.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                    // Fall through and re-check buffered_amount.
                }
            }
        }

        let n = match read_half.read(&mut buf).await {
            Ok(0) => {
                // Local TCP read half hit EOF. Send the in-band
                // sentinel on the DC so the peer's FlowDemux closes
                // the mailbox AFTER it has drained every prior
                // chunk (SCTP per-stream ordering). Then notify the
                // caller so it can emit a wire-level
                // `rc:tunnel.tcp.half_close` for audit.
                let marker = mux::encode(flow_id, HALF_CLOSE_MAGIC);
                if let Err(e) = dc.send(&Bytes::from(marker)).await {
                    debug!(flow_id, %e, "tunnel pump half-close marker send failed");
                }
                (on_local_eof)(flow_id);
                return CloseReason::Eof;
            }
            Ok(n) => n,
            Err(e) => {
                debug!(flow_id, %e, "tunnel pump TCP read error");
                let marker = mux::encode(flow_id, HALF_CLOSE_MAGIC);
                let _ = dc.send(&Bytes::from(marker)).await;
                (on_local_eof)(flow_id);
                return CloseReason::IoError;
            }
        };
        stats.tcp_read_bytes.fetch_add(n as u64, Ordering::Relaxed);
        stats.add_session_out(n as u64);

        let framed = mux::encode(flow_id, &buf[..n]);
        let framed_len = framed.len();
        if let Err(e) = dc.send(&Bytes::from(framed)).await {
            debug!(flow_id, %e, "tunnel pump DC send error");
            return CloseReason::IoError;
        }
        stats
            .dc_send_bytes
            .fetch_add(framed_len as u64, Ordering::Relaxed);
    }
}

async fn pump_dc_to_tcp(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    from_dc: &mut mpsc::Receiver<Bytes>,
    flow_id: u32,
    stats: Arc<FlowStats>,
) -> CloseReason {
    loop {
        let chunk = match from_dc.recv().await {
            Some(c) => c,
            None => {
                // Mailbox closed (FlowDemux saw the peer's
                // half-close marker). Shutdown the local TCP write
                // half so downstream sees FIN. Failure to shutdown
                // (e.g. peer already RST'd) is non-fatal.
                if let Err(e) = write_half.shutdown().await {
                    debug!(flow_id, %e, "tunnel pump TCP shutdown after EOF failed");
                }
                return CloseReason::Eof;
            }
        };
        // Snapshot the post-recv mailbox depth so the periodic
        // logger can see "we keep draining but the mailbox stays
        // full → upstream is the bottleneck" vs "mailbox is empty
        // → downstream is the bottleneck."
        stats
            .mailbox_depth
            .store(from_dc.len() as u64, Ordering::Relaxed);
        let chunk_len = chunk.len();
        if let Err(e) = write_half.write_all(&chunk).await {
            debug!(flow_id, %e, "tunnel pump TCP write error");
            return CloseReason::IoError;
        }
        stats
            .tcp_write_bytes
            .fetch_add(chunk_len as u64, Ordering::Relaxed);
        stats.add_session_in(chunk_len as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::webrtc_dc::TunnelPeer;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn preaccept_prefix_budget_and_authoritative_dc_are_fail_closed() {
        let prefix = PendingIngress::default();
        assert!(prefix.admit(1, MAX_PENDING_PREFIX_BYTES));
        assert!(!prefix.admit(1, 1));
        assert!(
            prefix.accept(1).is_err(),
            "overflow must not release a truncated prefix"
        );
        let wrong = PendingIngress::default();
        assert!(wrong.admit(0, 3));
        assert!(
            wrong.accept(1).is_err(),
            "wrong-channel data cannot be relabeled by Accept"
        );
        let valid = PendingIngress::default();
        assert!(valid.admit(1, 3));
        valid.accept(1).unwrap();
        assert!(
            valid.admit(1, usize::MAX),
            "active flows retain normal throughput queue"
        );
        assert!(!valid.admit(0, 1));
        assert!(valid.accept(1).is_err());
    }

    async fn preaccept_pool() -> (TunnelPeer, Arc<Vec<FlowDemux>>) {
        let peer = TunnelPeer::new(vec![]).await.unwrap();
        let mut demuxes = Vec::new();
        for idx in 0..peer.pool_size() {
            demuxes.push(FlowDemux::install(peer.dc(idx).unwrap(), None).await);
        }
        (peer, Arc::new(demuxes))
    }

    async fn preaccept_removed(pool: &Arc<Vec<FlowDemux>>, flow: u32) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut found = false;
                for d in pool.iter() {
                    found |= d.flows.lock().await.contains_key(&flow);
                }
                if !found {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("RAII must remove every alias");
    }

    #[tokio::test]
    async fn preaccept_pool_shares_one_queue_stats_and_preserves_half_close() {
        let (peer, pool) = preaccept_pool().await;
        let mut guard = FlowPoolRegistration::reserve(pool.clone(), 1)
            .await
            .unwrap();
        let first = pool[0].flows.lock().await.get(&1).unwrap().clone();
        for demux in pool.iter() {
            let entry = demux.flows.lock().await.get(&1).unwrap().clone();
            assert!(
                entry.0.same_channel(&first.0),
                "no pool-size buffer multiplier"
            );
            assert!(Arc::ptr_eq(&entry.1, &first.1));
        }
        let (sender, stats, pending) = pool[1].flows.lock().await.get(&1).unwrap().clone();
        assert!(pending.unwrap().0.admit(1, 6));
        sender.send(Bytes::from_static(b"banner")).await.unwrap();
        drop((sender, first));
        let (mut rx, activated_stats) = guard.activate(1).await.unwrap();
        assert!(Arc::ptr_eq(&stats, &activated_stats));
        for (idx, demux) in pool.iter().enumerate() {
            assert_eq!(demux.flows.lock().await.contains_key(&1), idx == 1);
        }
        assert_eq!(rx.recv().await.unwrap().as_ref(), b"banner");
        // Same removal the ordered in-band half-close performs; the guard
        // must not keep a hidden sender alive after the authoritative alias.
        pool[1].unregister(1).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .is_none()
        );
        drop(guard);
        preaccept_removed(&pool, 1).await;
        peer.close().await;
    }

    #[tokio::test]
    async fn preaccept_capacity_is_bounded_and_drop_releases_owned_slots_only() {
        let (peer, pool) = preaccept_pool().await;
        let mut guards = Vec::new();
        for id in 1..=MAX_PENDING_POOL_FLOWS as u32 {
            guards.push(
                FlowPoolRegistration::reserve(pool.clone(), id)
                    .await
                    .unwrap(),
            );
        }
        assert!(
            FlowPoolRegistration::reserve(pool.clone(), 999)
                .await
                .is_err()
        );
        drop(guards.pop());
        preaccept_removed(&pool, MAX_PENDING_POOL_FLOWS as u32).await;
        let replacement = FlowPoolRegistration::reserve(pool.clone(), 999)
            .await
            .unwrap();
        drop(replacement);
        drop(guards);
        preaccept_removed(&pool, 1).await;
        preaccept_removed(&pool, 999).await;
        let old = FlowPoolRegistration::reserve(pool.clone(), 777)
            .await
            .unwrap();
        let (mut fresh_rx, fresh_stats) = pool[0].register(777).await;
        drop(old);
        preaccept_removed(&Arc::new(pool.iter().skip(1).cloned().collect()), 777).await;
        let fresh = pool[0].flows.lock().await.get(&777).unwrap().clone();
        assert!(
            Arc::ptr_eq(&fresh_stats, &fresh.1),
            "late cleanup cannot delete a replacement"
        );
        fresh.0.send(Bytes::from_static(b"fresh")).await.unwrap();
        assert_eq!(fresh_rx.recv().await.unwrap().as_ref(), b"fresh");
        pool[0].unregister(777).await;
        peer.close().await;
    }

    #[tokio::test]
    async fn preaccept_abort_during_partial_reserve_removes_inserted_aliases() {
        let (peer, pool) = preaccept_pool().await;
        let blocked = pool[1].flows.lock().await;
        let task = tokio::spawn(FlowPoolRegistration::reserve(pool.clone(), 1));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !pool[0].flows.lock().await.contains_key(&1) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(matches!(task.await, Err(e) if e.is_cancelled()));
        drop(blocked);
        preaccept_removed(&pool, 1).await;
        assert_eq!(
            pool[0].pending_slots.available_permits(),
            MAX_PENDING_POOL_FLOWS
        );
        peer.close().await;
    }

    /// P3b-3: a session-tracked `FlowStats` mirrors TCP-side byte adds into the
    /// shared `SessionThroughput` (`bytes_out` = local→peer, `bytes_in` =
    /// peer→local); an untracked one (`session: None`) is a silent no-op.
    #[test]
    fn session_throughput_mirrors_tcp_side_bytes() {
        let session = Arc::new(SessionThroughput::default());
        let tracked = FlowStats {
            session: Some(session.clone()),
            ..Default::default()
        };
        tracked.add_session_out(100);
        tracked.add_session_out(23);
        tracked.add_session_in(40);
        assert_eq!(
            session.snapshot(),
            (40, 123, 0),
            "(bytes_in, bytes_out, active)"
        );

        // No aggregate → no-op, no panic.
        let untracked = FlowStats::default();
        untracked.add_session_out(999);
        untracked.add_session_in(999);
    }

    /// The `active_flows` gauge saturates at 0 — a stale cross-attempt
    /// `FlowGauge::drop` can decrement more than were incremented, and an
    /// `AtomicU64` `fetch_sub` would wrap to `u64::MAX`. The `fetch_update`
    /// saturating decrement must clamp instead.
    #[test]
    fn active_flows_gauge_never_underflows() {
        let session = Arc::new(SessionThroughput::default());
        // Two live flows, then three drops (one stale) → clamps at 0, not wrap.
        let g1 = FlowGauge::new(session.clone());
        let g2 = FlowGauge::new(session.clone());
        assert_eq!(session.active_flows.load(Ordering::Relaxed), 2);
        drop(g1);
        drop(g2);
        assert_eq!(session.active_flows.load(Ordering::Relaxed), 0);
        // An extra (stale) decrement clamps rather than wrapping to u64::MAX.
        let _ = session
            .active_flows
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
        assert_eq!(session.active_flows.load(Ordering::Relaxed), 0);
    }

    /// `reset_active_flows` zeroes the gauge without touching cumulative bytes.
    #[test]
    fn reset_active_flows_leaves_bytes_untouched() {
        let s = SessionThroughput::default();
        s.bytes_in.fetch_add(500, Ordering::Relaxed);
        s.bytes_out.fetch_add(700, Ordering::Relaxed);
        s.active_flows.fetch_add(3, Ordering::Relaxed);
        s.reset_active_flows();
        assert_eq!(s.snapshot(), (500, 700, 0));
    }

    /// Stress the [`FlowDemux`] with sustained traffic + the in-band
    /// half-close marker: send 256 KiB in 4-KiB framed chunks via
    /// direct `dc.send` (mimicking what `pump_tcp_to_dc` would do),
    /// then send the [`HALF_CLOSE_MAGIC`] sentinel. Verifies (a)
    /// framing roundtrips at scale, (b) bytes arrive in order, (c)
    /// the in-band marker closes the mailbox AFTER all buffered
    /// chunks have been routed — i.e. zero bytes are lost. SCTP
    /// per-stream ordering is what makes the in-band approach
    /// correct; a wire-level half-close would race ahead of /
    /// behind in-flight DC chunks and lose bytes.
    #[tokio::test(flavor = "multi_thread")]
    async fn demux_handles_256k_burst_then_in_band_half_close() {
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

        let off_dc = offerer.dc(0).unwrap();
        let ans_dc = answerer.dc(0).unwrap();
        let ans_demux = FlowDemux::install(ans_dc.clone(), None).await;
        let (mut from_dc_answerer, _stats) = ans_demux.register(1).await;

        // Manual send loop — same framing as `pump_tcp_to_dc` but
        // bypasses the TCP read half so the test scope stays focused
        // on demux + marker behaviour.
        let payload: Vec<u8> = (0..(1 << 18)).map(|i| (i & 0xFF) as u8).collect();
        let payload_for_sender = payload.clone();
        let off_dc_for_sender = Arc::clone(&off_dc);
        tokio::spawn(async move {
            for chunk in payload_for_sender.chunks(4 * 1024) {
                let framed = mux::encode(1, chunk);
                off_dc_for_sender
                    .send(&Bytes::from(framed))
                    .await
                    .expect("dc.send failed");
            }
            // In-band half-close marker — SCTP ordering puts this
            // strictly after every chunk above on the same flow.
            let marker = mux::encode(1, HALF_CLOSE_MAGIC);
            off_dc_for_sender
                .send(&Bytes::from(marker))
                .await
                .expect("marker send failed");
        });

        let received = tokio::time::timeout(Duration::from_secs(30), async {
            let mut out = Vec::with_capacity(payload.len());
            while let Some(chunk) = from_dc_answerer.recv().await {
                out.extend_from_slice(&chunk);
            }
            out
        })
        .await
        .expect("demux did not deliver 256 KiB within 30s");

        assert_eq!(received.len(), payload.len(), "received length mismatch");
        assert_eq!(received, payload, "received payload mismatch");
    }

    /// #2129 — a WebRTC-DC flow whose session ends mid-stream ends on BOTH
    /// ends, even when the app and the target are idle. A live, idle TCP pair
    /// sits on each side of a real flow; cancelling the session must make both
    /// `run_flow` tasks return AND both local TCP endpoints see EOF/RST within
    /// ~2 s — not hang forever on a mailbox that can never close
    /// (`pump_dc_to_tcp`) or a `read` that never completes (`pump_tcp_to_dc`).
    /// Run under a timeout so a regression fails red instead of hanging.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_live_flow_ends_on_both_ends_when_its_session_is_cancelled() {
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

        // A live, idle TCP pair on EACH end: `app` ↔ the client's local side,
        // `target` ↔ the exit's dst side. The test holds `app`/`target`, so
        // when `run_flow` drops its half the held end sees EOF/RST.
        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let mut app = tokio::net::TcpStream::connect(client_addr).await.unwrap();
        let (client_tcp, _) = client_listener.accept().await.unwrap();

        let exit_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit_listener.local_addr().unwrap();
        let mut target = tokio::net::TcpStream::connect(exit_addr).await.unwrap();
        let (exit_tcp, _) = exit_listener.accept().await.unwrap();

        let flow_id = 1;
        let client_demux = FlowDemux::install(offerer.dc(0).unwrap(), None).await;
        let (client_from_dc, client_stats) = client_demux.register(flow_id).await;
        let exit_demux = FlowDemux::install(answerer.dc(0).unwrap(), None).await;
        let (exit_from_dc, exit_stats) = exit_demux.register(flow_id).await;

        // One canceller per side — as the client carrier and the exit peer
        // each own one.
        let client_cancel = FlowCanceller::new();
        let exit_cancel = FlowCanceller::new();
        let noop: HalfCloseSink = Arc::new(|_fid: u32| {});

        let mut client_flow = tokio::spawn(run_flow(
            client_tcp,
            offerer.dc(0).unwrap(),
            flow_id,
            client_from_dc,
            noop.clone(),
            client_stats,
            client_cancel.handle(),
        ));
        let mut exit_flow = tokio::spawn(run_flow(
            exit_tcp,
            answerer.dc(0).unwrap(),
            flow_id,
            exit_from_dc,
            noop,
            exit_stats,
            exit_cancel.handle(),
        ));

        // Idle: neither flow ends on its own.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !client_flow.is_finished(),
            "client flow must not end while idle"
        );
        assert!(
            !exit_flow.is_finished(),
            "exit flow must not end while idle"
        );

        // End the session on both ends through the new mechanism.
        client_cancel.cancel();
        exit_cancel.cancel();

        let (c_reason, e_reason, app_eof, tgt_eof) =
            tokio::time::timeout(Duration::from_secs(2), async {
                let c = (&mut client_flow).await.unwrap();
                let e = (&mut exit_flow).await.unwrap();
                let mut b = [0u8; 1];
                let app_eof = matches!(app.read(&mut b).await, Ok(0) | Err(_));
                let tgt_eof = matches!(target.read(&mut b).await, Ok(0) | Err(_));
                (c, e, app_eof, tgt_eof)
            })
            .await
            .expect("both flows must end within 2 s of cancellation");

        assert!(
            matches!(c_reason, CloseReason::ServerTerminated),
            "client flow reports the session teardown, got {c_reason:?}"
        );
        assert!(
            matches!(e_reason, CloseReason::ServerTerminated),
            "exit flow reports the session teardown, got {e_reason:?}"
        );
        assert!(
            app_eof,
            "the app must see EOF/RST on the client's local socket"
        );
        assert!(
            tgt_eof,
            "the target must see EOF/RST on the exit's dst socket"
        );
    }

    /// Most basic FlowDemux smoke: install, register a flow_id,
    /// have the peer side send one framed message via dc.send(),
    /// expect it to land in the mailbox. Verifies the demux on_message
    /// hookup before the pump test (which depends on this working).
    #[tokio::test(flavor = "multi_thread")]
    async fn demux_routes_one_message_to_registered_flow() {
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

        let off_dc = offerer.dc(0).unwrap();
        let ans_dc = answerer.dc(0).unwrap();
        let ans_demux = FlowDemux::install(ans_dc, None).await;
        let (mut from_dc, _stats) = ans_demux.register(42).await;

        let framed = mux::encode(42, b"hello world");
        off_dc.send(&Bytes::from(framed)).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), from_dc.recv())
            .await
            .expect("demux did not deliver within 5s");
        assert_eq!(received.as_deref(), Some(b"hello world".as_ref()));
    }

    /// Regression lock for the one-byte framing overflow that silently
    /// stalled large transfers: the sender's `dc_send` kept climbing
    /// while the receiver's `dc_recv` flatlined the moment the first
    /// full-size chunk crossed the wire. webrtc-data reads every inbound
    /// message into a fixed `u16::MAX` = 65535-byte buffer; a 65536-byte
    /// message returned `ErrShortBuffer`, which closed the stream and
    /// broke the read loop so `on_message` never fired again. A single
    /// MAX-size framed message (`CHUNK_BYTES` on the wire) must arrive
    /// intact AND leave the DC alive for a follow-up — every other test
    /// here uses tiny messages or 4 KiB sub-chunks, so none caught it.
    #[tokio::test(flavor = "multi_thread")]
    async fn max_size_framed_message_survives_receiver_read_loop() {
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

        let off_dc = offerer.dc(0).unwrap();
        let ans_dc = answerer.dc(0).unwrap();
        let ans_demux = FlowDemux::install(ans_dc, None).await;
        let (mut from_dc, _stats) = ans_demux.register(7).await;

        // Largest legal payload: framed length == CHUNK_BYTES == exactly
        // the receiver's 65535-byte read buffer.
        let payload = vec![0xABu8; CHUNK_BYTES - mux::FLOW_ID_HEADER_BYTES];
        let framed = mux::encode(7, &payload);
        assert_eq!(
            framed.len(),
            CHUNK_BYTES,
            "framed message must be the max size"
        );
        off_dc.send(&Bytes::from(framed)).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), from_dc.recv())
            .await
            .expect("receiver read loop died on a max-size message (the overflow regression)")
            .expect("flow mailbox closed unexpectedly");
        assert_eq!(
            received.len(),
            payload.len(),
            "max-size payload length mismatch"
        );
        assert_eq!(received, payload, "max-size payload corrupted");

        // The DC must still be alive: a follow-up message must arrive.
        // Pre-fix the read loop had already broken — on_message was dead.
        off_dc
            .send(&Bytes::from(mux::encode(7, b"still alive")))
            .await
            .unwrap();
        let received2 = tokio::time::timeout(Duration::from_secs(5), from_dc.recv())
            .await
            .expect("receiver read loop did not survive past the max-size message");
        assert_eq!(received2.as_deref(), Some(b"still alive".as_ref()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unregistered_flow_id_drops_messages_silently() {
        let peer = TunnelPeer::new(vec![]).await.unwrap();
        let dc = peer.dc(0).unwrap();
        let _demux = FlowDemux::install(dc, None).await;
        // No register; flow_id 99 mailbox doesn't exist. No
        // assertion needed — if the handler panicked on unknown
        // flow ids, the test would fail by causing the runtime to
        // tear down. As-is this just exercises the trace! path.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // ─── UDP ASSOCIATE datagram carriage ─────────────────────────────

    #[test]
    fn udp_datagram_framing_roundtrip() {
        for dg in [&b""[..], b"x", b"hello world", &vec![0xABu8; 4096]] {
            let framed = frame_udp_datagram(dg).unwrap();
            assert_eq!(framed.len(), dg.len() + 2, "2-byte length prefix");
            assert_eq!(deframe_udp_datagram(&framed), Some(dg));
        }
    }

    #[test]
    fn udp_framing_never_collides_with_half_close_magic() {
        // A single-byte 0xFF datagram frames to [0x00,0x01,0xFF] — never
        // equal to the 1-byte TCP HALF_CLOSE_MAGIC, so a UDP flow's DC
        // payload can't trip the demux half-close path.
        let framed = frame_udp_datagram(&[0xFF]).unwrap();
        assert_ne!(framed.as_slice(), HALF_CLOSE_MAGIC);
        assert!(framed.len() >= 2);
    }

    #[test]
    fn deframe_rejects_short_and_truncated() {
        assert_eq!(deframe_udp_datagram(&[]), None);
        assert_eq!(deframe_udp_datagram(&[0x00]), None); // < 2 bytes
        // Declares len=5 but only 2 payload bytes present → None.
        assert_eq!(deframe_udp_datagram(&[0x00, 0x05, 1, 2]), None);
        // Exact fit: len=2, 2 bytes.
        assert_eq!(
            deframe_udp_datagram(&[0x00, 0x02, 9, 9]),
            Some(&[9u8, 9][..])
        );
    }

    #[test]
    fn oversized_datagram_is_dropped_by_framer() {
        let too_big = vec![0u8; MAX_UDP_DATAGRAM + 1];
        assert!(frame_udp_datagram(&too_big).is_none());
    }

    #[test]
    fn keepalive_frame_uses_reserved_flow_id() {
        // The idle keepalive (spawn_dc_keepalive) rides flow_id 0 — reserved
        // because real flows start at 1 — as a 5-byte frame the demux drops.
        let frame = mux::encode(KEEPALIVE_FLOW_ID, &[0u8]);
        let (flow_id, payload) = mux::decode(&frame).expect("keepalive frame decodes");
        assert_eq!(flow_id, KEEPALIVE_FLOW_ID);
        assert_eq!(
            KEEPALIVE_FLOW_ID, 0,
            "reserved id must not collide with live flows (which start at 1)"
        );
        // Distinct from the half-close sentinel so the demux's check order
        // (keepalive first, then half-close) is unambiguous.
        assert_ne!(payload, HALF_CLOSE_MAGIC);
        assert_eq!(
            frame.len(),
            5,
            "4-byte prefix + 1-byte pad; never a bare prefix"
        );
    }

    /// Agent-side UDP pump over a real DC pool: a datagram sent by the
    /// "client" DC lands at the pump, is delivered to a loopback UDP
    /// echo target, and the echo is framed back onto the DC. Exercises
    /// [`run_flow_udp_dc`] end-to-end incl. the `mux` + framing layers.
    #[tokio::test(flavor = "multi_thread")]
    async fn run_flow_udp_dc_echoes_through_pool() {
        // Loopback UDP echo server.
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });

        // WebRTC-DC peer pair with ICE wired.
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

        let flow_id = 3;
        // Client (offerer) receives the agent's echoes via a demux on
        // its own DC; agent (answerer) receives client datagrams via a
        // demux on its DC — the socket the pump owns.
        let client_demux = FlowDemux::install(offerer.dc(0).unwrap(), None).await;
        let (mut client_from_dc, _cs) = client_demux.register(flow_id).await;
        let agent_demux = FlowDemux::install(answerer.dc(0).unwrap(), None).await;
        let (agent_from_dc, _as) = agent_demux.register(flow_id).await;

        // Agent pump: a UDP socket connected to the echo target.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(echo_addr).await.unwrap();
        let agent_dc = answerer.dc(0).unwrap();
        let pump = tokio::spawn(run_flow_udp_dc(
            udp,
            agent_dc,
            flow_id,
            agent_from_dc,
            Duration::from_secs(3),
            Arc::new(FlowStats::default()),
        ));

        // Client sends a datagram over its DC toward the agent.
        let client_dc = offerer.dc(0).unwrap();
        send_udp_datagram_dc(&client_dc, flow_id, b"ping-udp")
            .await
            .unwrap();

        // The echo comes back framed onto the client's DC.
        let echoed = tokio::time::timeout(Duration::from_secs(5), client_from_dc.recv())
            .await
            .expect("no echo within 5s")
            .expect("client mailbox closed");
        assert_eq!(
            deframe_udp_datagram(&echoed),
            Some(&b"ping-udp"[..]),
            "echoed datagram must round-trip through the UDP pump"
        );
        pump.abort();
    }
}
