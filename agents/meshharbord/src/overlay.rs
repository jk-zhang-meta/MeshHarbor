// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Agent-side overlay-network glue (Phase 3b).
//!
//! Bridges the agent's WS signaling loop to the shared
//! [`OverlayRuntime`](tunnel_core::overlay::runtime::OverlayRuntime): on
//! connect it spawns the runtime (relay mode) and returns the channel its
//! `ServerMsg::Overlay*` events flow into; the WS read loop forwards those
//! via [`intercept`].
//!
//! Two overlay surfaces, picked at runtime:
//! * **`overlay-l3`** — a real OS TUN (`SystemTun`). The agent runs privileged
//!   (service), so the device + routes come up directly. The default when no
//!   netstack port is set.
//! * **`overlay-netstack`** — a userspace smoltcp stack + a loopback SOCKS5
//!   front, the OS-free twin: on a locked-down host (full-tunnel VPN) the mesh
//!   is reachable with NO OS routing. Opt in with the env var
//!   `MESHHARBORD_OVERLAY_NETSTACK_SOCKS=<port>`.
//!
//! Default-OFF regardless: `overlay_enabled` config **and** a build carrying
//! the relevant feature are both required to join the mesh.

use std::sync::Arc;

use meshharbor_remote_control::signaling;
use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use tunnel_core::env::node_env;
use tunnel_core::localapi;
use tunnel_core::localapi::OverlayView;
use tunnel_core::overlay::WgKeypair;
use tunnel_core::overlay::runtime::{
    DerpMuxFactory, OverlayEvent, OverlayRuntime, RegionalDerpFactory, TunFactory,
};
#[cfg(feature = "overlay-l3")]
use tunnel_core::overlay::tun::SystemTun;
use tunnel_core::overlay::tun::TunIo;

use crate::config::AgentConfig;

/// Overlay MTU. 1280 (the IPv6 minimum) is safe under WireGuard + coturn
/// overhead on any path.
const OVERLAY_MTU: u16 = 1280;

/// rc.307 (B) — everything a spawned runtime's behavior was derived from.
/// A reconnect with an EQUAL fingerprint re-attaches the persistent runtime
/// (carriers survive); any difference spawns a fresh one (the old dies when
/// its last event-sender clone drops). Live-read env flags (MBB, DERP, tier
/// gates, …) are deliberately NOT here — `make_join` re-reads them on every
/// re-join, so they don't need a rebuild.
#[derive(Clone, PartialEq)]
struct RuntimeFingerprint {
    wg_public_key: String,
    netstack_port: Option<u16>,
    advertised_routes: Vec<String>,
    exit_node: Option<String>,
    tenant_id: String,
    server_url: String,
    /// The local LAN interface IP set (sorted). The config-derived fields
    /// above are process-immutable (config changes restart the daemon), so
    /// this is the ONE input that actually changes at runtime: after a
    /// network move the persistent runtime's per-interface sockets are bound
    /// to dead addresses and its punch socket STUNs from a corpse — a
    /// changed set forces the full rebuild a move needs. IP set only (not
    /// ifindexes): Windows renumbers ifindexes on adapter events without the
    /// addresses changing, and the sockets are bound to addresses.
    lan_ips: Vec<String>,
}

impl RuntimeFingerprint {
    /// R4 — do the fields that REQUIRE a runtime respawn all match?
    /// `lan_ips` is deliberately excluded: it is the one runtime-variable
    /// input, and a changed set is handled by an IN-PLACE direct-plane
    /// rebuild (`OverlayEvent::RebuildDirect`) instead of the old
    /// spawn-a-second-runtime path — which never told the first runtime,
    /// left both holding direct sockets, and made the new one walk the
    /// stable-port band, forfeiting the very 5-tuple stability rc.307/308
    /// exist to provide.
    fn same_shape(&self, other: &Self) -> bool {
        self.wg_public_key == other.wg_public_key
            && self.netstack_port == other.netstack_port
            && self.advertised_routes == other.advertised_routes
            && self.exit_node == other.exit_node
            && self.tenant_id == other.tenant_id
            && self.server_url == other.server_url
    }
}

const MAX_RELIABLE_EVENTS: usize = 64;

enum QueuedOverlayEvent {
    Reliable {
        evt: OverlayEvent,
        enqueued_at: std::time::Instant,
    },
    Droppable(OverlayEvent),
}

struct OverlayEventQueueState {
    buf: std::collections::VecDeque<QueuedOverlayEvent>,
    droppable: usize,
    reliable: usize,
    closed: bool,
}

struct OverlayEventQueue {
    state: std::sync::Mutex<OverlayEventQueueState>,
    notify: tokio::sync::Notify,
    senders: std::sync::atomic::AtomicUsize,
    droppable_cap: usize,
}

/// Non-blocking, bounded FIFO sender feeding [`OverlayRuntime`] via a dedicated
/// pump task so `signaling`'s `select!` loop never awaits runtime queue
/// capacity (breaking the circular wait against `ControlTx::send`) while still
/// guaranteeing reliable delivery of `JoinRefused`, `Netmap`, `ControlDetached`,
/// `Reattach`, and `RebuildDirect`.
pub struct OverlayEventTx {
    inner: Arc<OverlayEventQueue>,
    runtime_weak: mpsc::WeakSender<OverlayEvent>,
}

impl Clone for OverlayEventTx {
    fn clone(&self) -> Self {
        self.inner
            .senders
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
            runtime_weak: self.runtime_weak.clone(),
        }
    }
}

impl Drop for OverlayEventTx {
    fn drop(&mut self) {
        if self
            .inner
            .senders
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.inner.notify.notify_waiters();
        }
    }
}

#[derive(Clone)]
pub struct WeakOverlayEventTx {
    inner: std::sync::Weak<OverlayEventQueue>,
    runtime_weak: mpsc::WeakSender<OverlayEvent>,
}

impl WeakOverlayEventTx {
    pub fn upgrade(&self) -> Option<OverlayEventTx> {
        let inner = self.inner.upgrade()?;
        inner
            .senders
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |n| (n > 0).then_some(n + 1),
            )
            .ok()?;
        Some(OverlayEventTx {
            inner,
            runtime_weak: self.runtime_weak.clone(),
        })
    }
}

pub fn overlay_event_channel(droppable_cap: usize) -> (OverlayEventTx, mpsc::Receiver<OverlayEvent>) {
    let (runtime_tx, runtime_rx) = mpsc::channel::<OverlayEvent>(1);
    let runtime_weak = runtime_tx.downgrade();
    let inner = Arc::new(OverlayEventQueue {
        state: std::sync::Mutex::new(OverlayEventQueueState {
            buf: std::collections::VecDeque::with_capacity(droppable_cap.min(64)),
            droppable: 0,
            reliable: 0,
            closed: false,
        }),
        notify: tokio::sync::Notify::new(),
        senders: std::sync::atomic::AtomicUsize::new(1),
        droppable_cap,
    });
    let queue_for_task = Arc::clone(&inner);
    tokio::spawn(async move {
        loop {
            let notified = queue_for_task.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let next = {
                let mut st = queue_for_task.state.lock().unwrap_or_else(|e| e.into_inner());
                match st.buf.pop_front() {
                    Some(QueuedOverlayEvent::Reliable { evt, .. }) => {
                        st.reliable = st.reliable.saturating_sub(1);
                        Some(evt)
                    }
                    Some(QueuedOverlayEvent::Droppable(evt)) => {
                        st.droppable = st.droppable.saturating_sub(1);
                        Some(evt)
                    }
                    None => None,
                }
            };
            if let Some(evt) = next {
                if runtime_tx.send(evt).await.is_err() {
                    let mut st = queue_for_task.state.lock().unwrap_or_else(|e| e.into_inner());
                    st.closed = true;
                    st.buf.clear();
                    st.droppable = 0;
                    st.reliable = 0;
                    break;
                }
                continue;
            }
            if queue_for_task
                .senders
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
            {
                let empty = queue_for_task
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .buf
                    .is_empty();
                if empty {
                    break;
                }
                continue;
            }
            tokio::select! {
                () = runtime_tx.closed() => {
                    let mut st = queue_for_task.state.lock().unwrap_or_else(|e| e.into_inner());
                    st.closed = true;
                    st.buf.clear();
                    st.droppable = 0;
                    st.reliable = 0;
                    break;
                }
                () = notified => {}
            }
        }
    });
    (
        OverlayEventTx {
            inner,
            runtime_weak,
        },
        runtime_rx,
    )
}

impl OverlayEventTx {
    pub fn is_closed(&self) -> bool {
        self.runtime_weak.upgrade().is_none_or(|tx| tx.is_closed())
    }

    pub async fn closed(&self) {
        if let Some(tx) = self.runtime_weak.upgrade() {
            tx.closed().await;
        }
    }

    pub fn downgrade(&self) -> WeakOverlayEventTx {
        WeakOverlayEventTx {
            inner: Arc::downgrade(&self.inner),
            runtime_weak: self.runtime_weak.clone(),
        }
    }

    pub fn try_send(&self, evt: OverlayEvent) -> Result<(), OverlayEvent> {
        if self.is_closed() {
            return Err(evt);
        }
        {
            let mut st = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.closed || st.droppable >= self.inner.droppable_cap {
                return Err(evt);
            }
            st.buf.push_back(QueuedOverlayEvent::Droppable(evt));
            st.droppable += 1;
        }
        self.inner.notify.notify_one();
        Ok(())
    }

    pub fn send_reliable(&self, evt: OverlayEvent) -> Result<(), OverlayEvent> {
        if self.is_closed() {
            return Err(evt);
        }
        let now = std::time::Instant::now();
        {
            let mut st = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.closed {
                return Err(evt);
            }
            let tail_start_of = |buf: &std::collections::VecDeque<QueuedOverlayEvent>| -> usize {
                buf.iter()
                    .rposition(|q| {
                        matches!(
                            q,
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::Netmap { .. },
                                ..
                            }
                        )
                    })
                    .map(|idx| idx + 1)
                    .unwrap_or(0)
            };
            let ensure_detached_in_segment = |st: &mut OverlayEventQueueState,
                                              seg_start: usize,
                                              seg_end: usize,
                                              at: std::time::Instant| {
                for q in st.buf.range_mut(seg_start..seg_end) {
                    if let QueuedOverlayEvent::Reliable {
                        evt,
                        enqueued_at,
                    } = q
                    {
                        match evt {
                            OverlayEvent::ControlDetached => {
                                let earliest = (*enqueued_at).min(at);
                                *evt = OverlayEvent::ControlDetachedAt(earliest);
                                *enqueued_at = earliest;
                                return;
                            }
                            OverlayEvent::ControlDetachedAt(prev) => {
                                if at < *prev {
                                    *prev = at;
                                }
                                if at < *enqueued_at {
                                    *enqueued_at = at;
                                }
                                return;
                            }
                            _ => {}
                        }
                    }
                }
                st.buf.insert(
                    seg_start,
                    QueuedOverlayEvent::Reliable {
                        evt: OverlayEvent::ControlDetachedAt(at),
                        enqueued_at: at,
                    },
                );
                st.reliable += 1;
            };
            let ensure_tail_detached_at =
                |st: &mut OverlayEventQueueState, at: std::time::Instant| {
                    let tail_start = tail_start_of(&st.buf);
                    let tail_end = st.buf.len();
                    ensure_detached_in_segment(st, tail_start, tail_end, at);
                };

            let evt_to_push: Option<OverlayEvent> = match evt {
                OverlayEvent::RebuildDirect => {
                    if let Some(pos) = st.buf.iter().position(|q| {
                        matches!(
                            q,
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::RebuildDirect,
                                ..
                            }
                        )
                    }) {
                        st.buf.remove(pos);
                        st.reliable = st.reliable.saturating_sub(1);
                    }
                    Some(OverlayEvent::RebuildDirect)
                }
                OverlayEvent::ControlDetached | OverlayEvent::ControlDetachedAt(_) => {
                    let mut earliest = match evt {
                        OverlayEvent::ControlDetachedAt(at) => at,
                        _ => now,
                    };
                    let tail_start = tail_start_of(&st.buf);
                    let mut idx = tail_start;
                    while idx < st.buf.len() {
                        let remove_refused = match &st.buf[idx] {
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::JoinRefused { .. },
                                enqueued_at,
                            } => Some(*enqueued_at),
                            _ => None,
                        };
                        if let Some(refused_at) = remove_refused {
                            earliest = earliest.min(refused_at);
                            st.buf.remove(idx);
                            st.reliable = st.reliable.saturating_sub(1);
                        } else {
                            idx += 1;
                        }
                    }
                    ensure_tail_detached_at(&mut st, earliest);
                    None
                }
                OverlayEvent::Reattach { outbound } => {
                    // 1. Supersede `Reattach` / `JoinRefused` in the post-`Netmap` tail
                    //    while preserving the earliest detach/refusal deadline in that tail.
                    let mut earliest = now;
                    let tail_start = tail_start_of(&st.buf);
                    let mut idx = tail_start;
                    while idx < st.buf.len() {
                        let remove_superseded = match &st.buf[idx] {
                            QueuedOverlayEvent::Reliable {
                                evt:
                                    OverlayEvent::Reattach { .. } | OverlayEvent::JoinRefused { .. },
                                enqueued_at,
                            } => Some(*enqueued_at),
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::ControlDetachedAt(at),
                                ..
                            } => {
                                earliest = earliest.min(*at);
                                None
                            }
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::ControlDetached,
                                enqueued_at,
                            } => {
                                earliest = earliest.min(*enqueued_at);
                                None
                            }
                            _ => None,
                        };
                        if let Some(ts) = remove_superseded {
                            earliest = earliest.min(ts);
                            st.buf.remove(idx);
                            st.reliable = st.reliable.saturating_sub(1);
                        } else {
                            idx += 1;
                        }
                    }
                    ensure_tail_detached_at(&mut st, earliest);
                    // 2. Also remove any older `Reattach` from an earlier segment before
                    //    `tail_start` (folding its timestamp into that segment's detach)
                    //    so at most ONE live `Reattach` ever exists in `st.buf`.
                    while let Some(pos) = st.buf.iter().position(|q| {
                        matches!(
                            q,
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::Reattach { .. },
                                ..
                            }
                        )
                    }) {
                        let ts = match st.buf.remove(pos) {
                            Some(QueuedOverlayEvent::Reliable { enqueued_at, .. }) => enqueued_at,
                            _ => now,
                        };
                        st.reliable = st.reliable.saturating_sub(1);
                        let seg_start = st
                            .buf
                            .range(..pos)
                            .rposition(|q| {
                                matches!(
                                    q,
                                    QueuedOverlayEvent::Reliable {
                                        evt: OverlayEvent::Netmap { .. },
                                        ..
                                    }
                                )
                            })
                            .map(|i| i + 1)
                            .unwrap_or(0);
                        let seg_end = st
                            .buf
                            .range(pos..)
                            .position(|q| {
                                matches!(
                                    q,
                                    QueuedOverlayEvent::Reliable {
                                        evt: OverlayEvent::Netmap { .. },
                                        ..
                                    }
                                )
                            })
                            .map(|off| pos + off)
                            .unwrap_or(st.buf.len());
                        ensure_detached_in_segment(&mut st, seg_start, seg_end, ts);
                    }
                    Some(OverlayEvent::Reattach { outbound })
                }
                OverlayEvent::JoinRefused { retryable } => {
                    let tail_start = tail_start_of(&st.buf);
                    let mut removed_earliest: Option<std::time::Instant> = None;
                    let mut idx = tail_start;
                    while idx < st.buf.len() {
                        let old_ts = match &st.buf[idx] {
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::JoinRefused { .. },
                                enqueued_at,
                            } => Some(*enqueued_at),
                            _ => None,
                        };
                        if let Some(ts) = old_ts {
                            removed_earliest =
                                Some(removed_earliest.map_or(ts, |prev| prev.min(ts)));
                            st.buf.remove(idx);
                            st.reliable = st.reliable.saturating_sub(1);
                        } else {
                            idx += 1;
                        }
                    }
                    if let Some(ts) = removed_earliest {
                        ensure_tail_detached_at(&mut st, ts);
                    }
                    Some(OverlayEvent::JoinRefused { retryable })
                }
                OverlayEvent::Netmap {
                    self_ip,
                    network,
                    peers,
                    org_relay_discovery,
                    path_trial_v1,
                } => {
                    let first_netmap_pos = st.buf.iter().position(|q| {
                        matches!(
                            q,
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::Netmap { .. },
                                ..
                            }
                        )
                    });
                    // Once at least one `Netmap` sits at `first_netmap_pos`, the runtime is
                    // guaranteed to have entered its main loop for every subsequent event in
                    // `st.buf[first_netmap_pos..]`, so both `Netmap`s and `NetmapDelta`s at or
                    // after `first_netmap_pos` raise `applied_auth_revision`.
                    let max_queued_rev = first_netmap_pos
                        .map(|fpos| {
                            st.buf
                                .range(fpos..)
                                .enumerate()
                                .filter_map(|(off, q)| match q {
                                    QueuedOverlayEvent::Reliable {
                                        evt: OverlayEvent::Netmap { network, .. },
                                        ..
                                    } => Some(network.auth_revision),
                                    QueuedOverlayEvent::Droppable(OverlayEvent::NetmapDelta {
                                        auth_revision,
                                        ..
                                    }) if off > 0 => Some(*auth_revision),
                                    _ => None,
                                })
                                .max()
                                .unwrap_or(0)
                        })
                        .unwrap_or(0);
                    if network.auth_revision > 0 && network.auth_revision < max_queued_rev {
                        // Guaranteed rejected by `accept_netmap_version` because an
                        // earlier queued `Netmap` or post-`Netmap` `NetmapDelta` already
                        // raised `applied_auth_revision` above `network.auth_revision`.
                        // Never let a stale snapshot advance `tail_start`, evict an
                        // authoritative earlier `Netmap`, or erase a detach deadline!
                        let tail_start = tail_start_of(&st.buf);
                        let tail_detached = st.buf.range(tail_start..).any(|q| {
                            matches!(
                                q,
                                QueuedOverlayEvent::Reliable {
                                    evt: OverlayEvent::ControlDetached
                                        | OverlayEvent::ControlDetachedAt(_),
                                    ..
                                }
                            )
                        });
                        let tail_has_reattach_or_refused = st.buf.range(tail_start..).any(|q| {
                            matches!(
                                q,
                                QueuedOverlayEvent::Reliable {
                                    evt: OverlayEvent::Reattach { .. }
                                        | OverlayEvent::JoinRefused { .. },
                                    ..
                                }
                            )
                        });
                        if tail_detached && !tail_has_reattach_or_refused {
                            Some(OverlayEvent::JoinRefused { retryable: true })
                        } else {
                            None
                        }
                    } else {
                        if network.auth_revision == 0 {
                            // An unversioned `Netmap` (`auth_revision == 0`) is unconditionally
                            // accepted by `accept_netmap_version` and unconditionally clears
                            // `control_detached_at` and `post_join_retry`, without lowering
                            // `applied_auth_revision`. Drop all earlier detaches/refusals, and
                            // drop earlier `auth_revision == 0` snapshots except when one is the
                            // very first `Netmap` and a `NetmapDelta` follows it (needed to exit
                            // the pre-first-netmap loop before that delta runs).
                            let mut idx = 0;
                            while idx < st.buf.len() {
                                let drop_it = match &st.buf[idx] {
                                    QueuedOverlayEvent::Reliable {
                                        evt:
                                            OverlayEvent::ControlDetached
                                            | OverlayEvent::ControlDetachedAt(_)
                                            | OverlayEvent::JoinRefused { .. },
                                        ..
                                    } => true,
                                    QueuedOverlayEvent::Reliable {
                                        evt: OverlayEvent::Netmap { network: n, .. },
                                        ..
                                    } if n.auth_revision == 0 => {
                                        let is_first_netmap = !st.buf.range(..idx).any(|q| {
                                            matches!(
                                                q,
                                                QueuedOverlayEvent::Reliable {
                                                    evt: OverlayEvent::Netmap { .. },
                                                    ..
                                                }
                                            )
                                        });
                                        let has_later_delta = st.buf.range(idx + 1..).any(|q| {
                                            matches!(
                                                q,
                                                QueuedOverlayEvent::Droppable(
                                                    OverlayEvent::NetmapDelta { .. }
                                                )
                                            )
                                        });
                                        !(is_first_netmap && has_later_delta)
                                    }
                                    _ => false,
                                };
                                if drop_it {
                                    st.buf.remove(idx);
                                    st.reliable = st.reliable.saturating_sub(1);
                                } else {
                                    idx += 1;
                                }
                            }
                        }
                        Some(OverlayEvent::Netmap {
                            self_ip,
                            network,
                            peers,
                            org_relay_discovery,
                            path_trial_v1,
                        })
                    }
                }
                other => Some(other),
            };

            let incoming_pos_netmap_rev = match &evt_to_push {
                Some(OverlayEvent::Netmap { network, .. }) if network.auth_revision > 0 => {
                    Some(network.auth_revision)
                }
                _ => None,
            };
            let target_cap = if evt_to_push.is_some() {
                MAX_RELIABLE_EVENTS.saturating_sub(1)
            } else {
                MAX_RELIABLE_EVENTS
            };
            while st.reliable > target_cap {
                let last_netmap_pos = st.buf.iter().rposition(|q| {
                    matches!(
                        q,
                        QueuedOverlayEvent::Reliable {
                            evt: OverlayEvent::Netmap { .. },
                            ..
                        }
                    )
                });
                // 1. Drop superseded `JoinRefused` before `last_netmap_pos` (NEVER drop `Reattach`!),
                //    folding its timestamp into a `ControlDetachedAt` in the same segment.
                if let Some(bound) = last_netmap_pos
                    && let Some(pos) = st.buf.range(..bound).position(|q| {
                        matches!(
                            q,
                            QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::JoinRefused { .. },
                                ..
                            }
                        )
                    })
                {
                    let ts = match st.buf.remove(pos) {
                        Some(QueuedOverlayEvent::Reliable { enqueued_at, .. }) => enqueued_at,
                        _ => now,
                    };
                    st.reliable = st.reliable.saturating_sub(1);
                    let seg_start = st
                        .buf
                        .range(..pos)
                        .rposition(|q| {
                            matches!(
                                q,
                                QueuedOverlayEvent::Reliable {
                                    evt: OverlayEvent::Netmap { .. },
                                    ..
                                }
                            )
                        })
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    let seg_end = st
                        .buf
                        .range(pos..)
                        .position(|q| {
                            matches!(
                                q,
                                QueuedOverlayEvent::Reliable {
                                    evt: OverlayEvent::Netmap { .. },
                                    ..
                                }
                            )
                        })
                        .map(|off| pos + off)
                        .unwrap_or(st.buf.len());
                    let before_rel = st.reliable;
                    ensure_detached_in_segment(&mut st, seg_start, seg_end, ts);
                    if st.reliable < before_rel + 1 {
                        continue;
                    }
                }
                // 2. Coalesce multiple `ControlDetached*` ONLY within the SAME segment
                //    (never across an intervening `Netmap`!).
                let mut merged_same_seg = false;
                let mut seg_start = 0usize;
                while seg_start < st.buf.len() {
                    let seg_end = st
                        .buf
                        .range(seg_start..)
                        .position(|q| {
                            matches!(
                                q,
                                QueuedOverlayEvent::Reliable {
                                    evt: OverlayEvent::Netmap { .. },
                                    ..
                                }
                            )
                        })
                        .map(|off| seg_start + off)
                        .unwrap_or(st.buf.len());
                    let detached_positions: Vec<usize> = st
                        .buf
                        .range(seg_start..seg_end)
                        .enumerate()
                        .filter_map(|(off, q)| {
                            matches!(
                                q,
                                QueuedOverlayEvent::Reliable {
                                    evt: OverlayEvent::ControlDetached
                                        | OverlayEvent::ControlDetachedAt(_),
                                    ..
                                }
                            )
                            .then_some(seg_start + off)
                        })
                        .collect();
                    if detached_positions.len() >= 2 {
                        let first = detached_positions[0];
                        let second = detached_positions[1];
                        let second_ts = match st.buf.remove(second) {
                            Some(QueuedOverlayEvent::Reliable {
                                evt: OverlayEvent::ControlDetachedAt(t),
                                ..
                            }) => t,
                            Some(QueuedOverlayEvent::Reliable { enqueued_at, .. }) => enqueued_at,
                            _ => now,
                        };
                        st.reliable = st.reliable.saturating_sub(1);
                        if let Some(QueuedOverlayEvent::Reliable {
                            evt,
                            enqueued_at,
                        }) = st.buf.get_mut(first)
                        {
                            let merged = match evt {
                                OverlayEvent::ControlDetachedAt(t) => (*t).min(second_ts),
                                _ => (*enqueued_at).min(second_ts),
                            };
                            *evt = OverlayEvent::ControlDetachedAt(merged);
                            *enqueued_at = merged;
                        }
                        merged_same_seg = true;
                        break;
                    }
                    seg_start = seg_end.saturating_add(1);
                }
                if merged_same_seg {
                    continue;
                }
                // 3. Evict an older positive-revision `Netmap(r1)` that is dominated by a
                //    later `Netmap(r2)` (`r2 >= r1 > 0` AND `r2 >= max_intervening_delta_rev`).
                //    Accounting for intervening `NetmapDelta` revisions ensures a later
                //    snapshot that will be rejected after a higher-revision delta can never
                //    evict the earlier full snapshot!
                let max_delta_between =
                    |buf: &std::collections::VecDeque<QueuedOverlayEvent>,
                     start: usize,
                     end: usize|
                     -> u64 {
                        buf.range(start..end)
                            .filter_map(|q| match q {
                                QueuedOverlayEvent::Droppable(OverlayEvent::NetmapDelta {
                                    auth_revision,
                                    ..
                                }) => Some(*auth_revision),
                                _ => None,
                            })
                            .max()
                            .unwrap_or(0)
                    };
                let netmap_entries: Vec<(usize, u64)> = st
                    .buf
                    .iter()
                    .enumerate()
                    .filter_map(|(i, q)| match q {
                        QueuedOverlayEvent::Reliable {
                            evt: OverlayEvent::Netmap { network, .. },
                            ..
                        } => Some((i, network.auth_revision)),
                        _ => None,
                    })
                    .collect();
                let buf_len = st.buf.len();
                let dominated_pos = netmap_entries.iter().enumerate().find_map(|(k, &(pos, rev))| {
                    if rev == 0 {
                        return None;
                    }
                    let dominated_in_buf = netmap_entries[k + 1..].iter().any(
                        |&(later_pos, later_rev)| {
                            later_rev >= rev
                                && later_rev >= max_delta_between(&st.buf, pos + 1, later_pos)
                        },
                    );
                    let dominated_by_incoming = incoming_pos_netmap_rev.is_some_and(|in_rev| {
                        in_rev >= rev && in_rev >= max_delta_between(&st.buf, pos + 1, buf_len)
                    });
                    (dominated_in_buf || dominated_by_incoming).then_some(pos)
                });
                if let Some(evict_pos) = dominated_pos {
                    st.buf.remove(evict_pos);
                    st.reliable = st.reliable.saturating_sub(1);
                    continue;
                }
                break;
            }
            if let Some(push_evt) = evt_to_push {
                st.buf.push_back(QueuedOverlayEvent::Reliable {
                    evt: push_evt,
                    enqueued_at: now,
                });
                st.reliable += 1;
            }
        }
        self.inner.notify.notify_one();
        Ok(())
    }
}

struct RuntimeSlot {
    fingerprint: RuntimeFingerprint,
    evt_tx: OverlayEventTx,
}

/// rc.307 (B) — the process-lifetime runtime slots. The overlay runtime used
/// to be scoped to ONE control-WS session (every server deploy / pod roll /
/// receive-liveness cycle tore down all carriers and rebuilt from empty —
/// which relay-locks a corp-VPN'd host whose firewall only grandfathers
/// established UDP flows). Now the first session spawns the runtime and
/// every later session RE-ATTACHES it (`OverlayEvent::Reattach`): the
/// runtime swaps its outbound sender, re-joins, and reconciles the reply
/// netmap against live state. The data plane (TUN, WG peers, carriers)
/// keeps flowing through the whole control-plane outage.
///
/// Multi-org P2c — keyed by TENANT: each org supervisor owns its own
/// persistent runtime, so org B's fresh spawn can never evict org A's
/// re-attach entry (a single slot would ping-pong and both orgs would
/// rebuild-from-empty on every reconnect — exactly the churn rc.307 killed).
static RUNTIME_SLOTS: std::sync::Mutex<std::collections::BTreeMap<String, RuntimeSlot>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// R4 — the per-tenant CENTRAL DERP mux, exposed to the tunnel plane for the
/// `quic-derp-v1` flavor. `Weak` so a mux that died with its runtime reads
/// as absent instead of leaking; the stored hex is the node's own pubkey
/// (the mux registered with it — one identity per tenant enrollment).
static DERP_TUNNEL_MUXES: std::sync::Mutex<
    std::collections::BTreeMap<
        String,
        (
            std::sync::Weak<tunnel_core::transport::derp::DerpMux>,
            String,
        ),
    >,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// R4 — the PRIMARY enrollment's tenant id, set once at daemon start. The
/// tunnel plane's derp flavor is primary-org-scoped (declared routes are;
/// the reconciler parks non-primary routes), and the flow supervisor has no
/// per-org context — this is its bridge to the right mux.
pub static PRIMARY_TENANT_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn register_derp_tunnel_mux(tenant: &str, mux: &Arc<tunnel_core::transport::derp::DerpMux>) {
    DERP_TUNNEL_MUXES.lock().unwrap().insert(
        tenant.to_string(),
        (
            Arc::downgrade(mux),
            tunnel_core::transport::derp::pubkey_hex(&mux.self_pubkey()),
        ),
    );
}

/// R4 — the PRIMARY org's live DERP mux + identity as a tunnel handle, or
/// `None` when the overlay/derp is down or not yet started (callers fall
/// back to the classic transport ladder).
pub(crate) fn primary_derp_tunnel_handle() -> Option<tunnel_core::transport::derp::DerpTunnelHandle>
{
    derp_tunnel_handle(PRIMARY_TENANT_ID.get()?)
}

/// R4 — a specific tenant's live DERP mux + identity as a tunnel handle.
pub(crate) fn derp_tunnel_handle(
    tenant: &str,
) -> Option<tunnel_core::transport::derp::DerpTunnelHandle> {
    let slots = DERP_TUNNEL_MUXES.lock().unwrap();
    let (weak, hex) = slots.get(tenant)?;
    let mux = weak.upgrade()?;
    Some(tunnel_core::transport::derp::DerpTunnelHandle {
        mux,
        self_pubkey_hex: hex.clone(),
    })
}

/// Multi-org v2 — the ONE process-wide shared carrier plane every org's
/// engine attaches to when `overlay_shared_carrier` is on (one stable
/// direct-socket set for the whole daemon; receiver-index demux). Created on
/// first use, process-lifetime — the plane must outlive
/// any single org's session churn.
static SHARED_PLANE: std::sync::Mutex<
    Option<std::sync::Arc<tunnel_core::overlay::carrier_plane::CarrierPlane>>,
> = std::sync::Mutex::new(None);

/// The plane when the flag is on (`OVERLAY_SHARED_CARRIER` / config
/// `overlay_shared_carrier`, built-in default ON since rc.339 — explicit
/// `false` is the kill switch), else `None` — the runtime then binds
/// per-runtime sockets exactly as before.
fn shared_carrier_plane()
-> Option<std::sync::Arc<tunnel_core::overlay::carrier_plane::CarrierPlane>> {
    if !tunnel_core::env::flag("OVERLAY_SHARED_CARRIER", true) {
        return None;
    }
    let mut g = SHARED_PLANE.lock().unwrap_or_else(|e| e.into_inner());
    Some(
        g.get_or_insert_with(tunnel_core::overlay::carrier_plane::CarrierPlane::new)
            .clone(),
    )
}

/// If overlay is enabled, spawn the node runtime (relay mode) and return
/// the channel its control events arrive on. `None` when overlay is
/// disabled or the node has no persisted WG key (generated at startup in
/// `main`, so a missing one here means a misconfiguration).
pub async fn maybe_start(
    cfg: &AgentConfig,
    // FR-103 — this enrollment's LIVE token. The DERP dialer below outlives
    // the connection that built it (the runtime persists across reconnects),
    // so it reads this per dial rather than keeping a copy.
    token: crate::token_slot::TokenSlot,
    outbound: mpsc::Sender<ClientMsg>,
    peer_view: watch::Sender<OverlayView>,
    derp_ticket_slot: crate::relay_probe::DerpTicketSlot,
    // A2 — the session-services bundle the SSH server is built with. Threaded
    // explicitly (signaling::run already holds the broker) instead of the old
    // `consent::set_shared` process global.
    services: crate::ssh::SessionServices,
) -> Option<OverlayEventTx> {
    if !cfg.overlay_enabled {
        // Drop THIS org's persistent-runtime slot entry: once the sessions'
        // event-sender clones are gone too, its channel closes and it tears
        // down cleanly. Other orgs' runtimes are untouched.
        RUNTIME_SLOTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&cfg.tenant_id);
        crate::overlay_supervision::clear_org_state(&cfg.tenant_id);
        return None;
    }
    let Some(keypair) = cfg
        .overlay_wg_secret_key
        .as_deref()
        .and_then(WgKeypair::from_secret_base64)
    else {
        warn!("overlay enabled but no/invalid WG key persisted; not joining the mesh");
        return None;
    };

    // rc.307 (B) — re-attach the persistent runtime when nothing that shaped
    // it changed. Take the sender clone OUTSIDE the lock before awaiting.
    let fingerprint = RuntimeFingerprint {
        wg_public_key: keypair.public_base64(),
        netstack_port: netstack_socks_port(cfg)
            .or_else(|| crate::overlay_supervision::effective_socks5_port(&cfg.tenant_id)),
        advertised_routes: cfg.effective_overlay_advertised_routes(),
        exit_node: cfg.overlay_exit_node.clone(),
        tenant_id: cfg.tenant_id.clone(),
        server_url: cfg.server_url.clone(),
        lan_ips: {
            let mut ips: Vec<String> = tunnel_core::overlay::direct::gather_lan_interfaces()
                .into_iter()
                .map(|(ip, _)| ip.to_string())
                .collect();
            ips.sort();
            ips
        },
    };
    let existing = {
        let slots = RUNTIME_SLOTS.lock().unwrap_or_else(|e| e.into_inner());
        slots
            .get(&cfg.tenant_id)
            .filter(|s| s.fingerprint.same_shape(&fingerprint))
            .map(|s| {
                (
                    s.evt_tx.clone(),
                    s.fingerprint.lan_ips == fingerprint.lan_ips,
                )
            })
    };
    if let Some((evt_tx, lan_ips_same)) = existing {
        match evt_tx.send_reliable(OverlayEvent::Reattach {
            outbound: outbound.clone(),
        }) {
            Ok(()) => {
                if lan_ips_same {
                    info!("overlay: re-attached the persistent node runtime (carriers intact)");
                } else {
                    info!(
                        "overlay: re-attached the persistent runtime; LAN addresses changed — requesting a direct-plane rebuild"
                    );
                    let _ = evt_tx.send_reliable(OverlayEvent::RebuildDirect);
                    if let Some(s) = RUNTIME_SLOTS
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get_mut(&cfg.tenant_id)
                    {
                        s.fingerprint = fingerprint.clone();
                    }
                }
                return Some(evt_tx);
            }
            Err(_) => {
                RUNTIME_SLOTS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&cfg.tenant_id);
                info!("overlay: previous node runtime exited; starting fresh");
            }
        }
    }

    let shape_key = crate::overlay_supervision::shape_key_for_config(cfg);
    if !crate::overlay_supervision::can_attempt_start(
        &cfg.tenant_id,
        &shape_key,
        std::time::Instant::now(),
    ) {
        warn!(
            org = %cfg.tenant_id,
            mode = %crate::overlay_supervision::effective_overlay_mode(&cfg.tenant_id, "tun"),
            "overlay: start suppressed by bounded failure backoff; not sending rc:overlay.join"
        );
        return None;
    }

    let (evt_tx, evt_rx) = overlay_event_channel(64);

    // Pick the overlay surface: the userspace netstack (+ loopback SOCKS front)
    // when `MESHHARBORD_OVERLAY_NETSTACK_SOCKS` names a port or when OS TUN
    // lacks privilege on Windows (F1 fallback), else the OS TUN.
    let base_os_tun = if cfg.overlay_multi_org && !cfg.derived_netstack {
        if !cfg.derived_org && netstack_socks_port(cfg).is_some() {
            warn!(
                "overlay: OVERLAY_NETSTACK_SOCKS is set but overlay_multi_org is on — \
                 the primary's netstack yields to that flag; using its own OS TUN instead"
            );
        }
        per_org_systun_factory(cfg.tenant_id.clone(), !cfg.derived_org)
    } else {
        systun_tun_factory()
    };
    let (tun_factory, effective_socks_port) = build_tun_factory_with_fallback(
        cfg,
        peer_view.subscribe(),
        crate::overlay_supervision::is_windows_platform(),
        crate::overlay_supervision::process_can_create_os_tun(),
        base_os_tun,
        Arc::new(std::time::Instant::now),
    )?;
    // MeshHarbor SSH — when this node opts in, splice a port-intercept shim over
    // whichever device we just chose, so `<overlay ip>:<ssh_port>` terminates in
    // the daemon. Deliberately applied AFTER the mode selection: it decorates
    // the OS-TUN, per-org and netstack factories identically, so SSH behaves the
    // same on a server, a multi-org host and a locked-down corp laptop.
    // No-op (and byte-for-byte the old path) unless `ssh_enabled` is on.
    let tun_factory = crate::ssh::maybe_intercept(tun_factory, cfg, services);
    // P5 exit-node client — resolve the coordination server's IPs NOW, while the
    // uplink is still clean (before any split-default is installed), so exit
    // routing can exempt them. Only when this node opts into an exit node.
    let exit_server_ips = if cfg.overlay_exit_node.is_some() {
        resolve_server_ips(&cfg.server_url).await
    } else {
        Vec::new()
    };

    // Phase D (DERP) — when enabled, provide a factory that opens the persistent
    // `/derp` WS. The runtime calls it lazily when THIS node is UDP-blocked
    // (its srflx gather found nothing) — and, Phase A (overlay v3), also
    // unconditionally when `overlay_derp_floor` is on (the always-on floor:
    // every floor-capable node stays registered so pairs can be floored at
    // birth). When called, it builds the demux, opens the WS (both peers dial
    // OUT over TCP/TLS-443), and returns the mux. Default-ON since rc.203.
    let derp_factory: Option<DerpMuxFactory> = if tunnel_core::overlay::direct::derp_enabled() {
        let ws_url = cfg.ws_url();
        let tenant = cfg.tenant_id.clone();
        let pubkey = keypair.public.to_bytes();
        Some(Box::new(move || {
            let (mux, outbound_rx) = tunnel_core::transport::derp::DerpMux::new(pubkey);
            crate::derp::spawn(&ws_url, token.clone(), &tenant, &mux, outbound_rx);
            // R4 — expose this tenant's central mux to the tunnel plane
            // (the quic-derp-v1 flavor multiplexes over it).
            register_derp_tunnel_mux(&tenant, &mux);
            info!("overlay derp: /derp carrier opened (UDP-blocked tier, or the always-on floor)");
            mux
        }))
    } else {
        None
    };

    // Multi-region DERP — the per-URL regional relay opener the force-DERP
    // handler consults when a push carries a `derp_url`. Reads the admission
    // ticket cached by the signaling loop; no ticket yet ⇒ `None` (the
    // coordinator degrades to the central mux; the WS owner spawned on a
    // later successful open reads the slot per attempt anyway).
    let regional_derp_factory: Option<RegionalDerpFactory> =
        if tunnel_core::overlay::direct::derp_enabled() {
            let tenant = cfg.tenant_id.clone();
            let pubkey = keypair.public.to_bytes();
            let slot = derp_ticket_slot.clone();
            Some(Box::new(move |url: &str| {
                let has_ticket = slot.lock().unwrap_or_else(|e| e.into_inner()).is_some();
                if !has_ticket {
                    warn!(%url, "overlay derp: regional relay pushed but no admission ticket yet");
                    return None;
                }
                let (mux, outbound_rx) = tunnel_core::transport::derp::DerpMux::new(pubkey);
                crate::derp::spawn_regional(url, slot.clone(), &tenant, &mux, outbound_rx);
                info!(%url, "overlay derp: regional /derp carrier opened");
                Some(mux)
            }))
        } else {
            None
        };

    let rt = OverlayRuntime::new_relay(keypair, outbound, tun_factory, OVERLAY_MTU)
        // FR-40 — the epoch persisted next to the key, bumped per rotation;
        // sent as `key_epoch` on the join.
        .with_key_epoch(cfg.overlay_wg_key_epoch)
        // Phase 1 — advertise this node's subnet routes (admin-gated server-side).
        // P5 — plus `0.0.0.0/0` when this node is configured as an exit node.
        .with_advertised_routes(cfg.effective_overlay_advertised_routes())
        // P5 — route THIS node's default egress through a chosen exit peer (with
        // carrier-endpoint exemptions), when `overlay_exit_node` is set.
        .with_exit_node(cfg.overlay_exit_node.clone(), exit_server_ips)
        // FR-97 P0c-3 / F1 — the netstack front, when that is the device chosen
        // above (either explicitly configured or auto-fallback on Windows): an
        // exit then carries only what the front dials, and the host's DNS is
        // left alone.
        .with_netstack_socks(effective_socks_port)
        // T12 — this device's own srflx STUN servers, when it set them.
        .with_srflx_stun_urls(cfg.overlay_stun_urls.clone())
        // Phase D — LAZY `/derp`: the runtime opens the WS via this factory only
        // if the node is itself UDP-blocked (else no idle WS).
        .with_derp_mux_factory(derp_factory)
        // Multi-region DERP — per-URL regional relay opener (ticket-gated).
        .with_regional_derp_factory(regional_derp_factory)
        // Multi-org v2 — every org's engine shares ONE process-wide socket
        // set (receiver-index demux) instead of racing the port band.
        .with_carrier_plane(shared_carrier_plane())
        // Unification P1 — publish the live mesh view for the LocalAPI so
        // `mh status` / `peers` see per-device connection types.
        .with_peer_view(peer_view)
        .with_org_primary(!cfg.derived_org)
        .with_relay_listener_readiness(crate::relay_server::readiness());
    // FIELD: endpoints are advertised lazily — the relay coordinator
    // trickles each relayed address post-allocation — so join carries none.
    tokio::spawn(rt.run(evt_rx, Vec::new()));
    info!("overlay: node runtime started (relay mode)");
    // rc.307 (B) — remember it for the next session's re-attach, under THIS
    // org's key. Replacing a fingerprint-mismatched entry drops the old
    // runtime's last stored sender clone; it tears down once the old
    // session's clones are gone too.
    RUNTIME_SLOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            cfg.tenant_id.clone(),
            RuntimeSlot {
                fingerprint,
                evt_tx: evt_tx.clone(),
            },
        );
    Some(evt_tx)
}

/// Resolve the coordination server's host (from `server_url`) to its current
/// IPs. Exit-node routing exempts these from the split-default, and they MUST be
/// resolved BEFORE any `0.0.0.0/1` is installed — once the default is captured,
/// DNS to a remote resolver may itself be swallowed. Best-effort + timeout-bound:
/// an empty result just means the runtime's exemption gate withholds default
/// routing (fail-safe — never a wedge). meshharbor.itachi.fans sits behind nginx/HAProxy and
/// may be multi-A, so every returned address is exempted.
async fn resolve_server_ips(server_url: &str) -> Vec<std::net::IpAddr> {
    use std::collections::HashSet;
    use std::net::IpAddr;

    // Host out of `scheme://host[:port][/path]` (server_url is never a v6 literal).
    let authority = server_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_url)
        .split('/')
        .next()
        .unwrap_or("");
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority)
        .trim();
    if host.is_empty() {
        return Vec::new();
    }
    // #2187 — through `ctl_dns`: the control WS resolves the server the same
    // way, so the exemption pins and the connection agree on the addresses, and
    // a name resolved before never waits on a dead resolver. A first lookup is
    // bounded at `ctl_dns::FIRST_LOOKUP_BOUND` (5 s, as before).
    let ips: Vec<IpAddr> =
        tunnel_core::ctl_dns::resolve(&tunnel_core::ctl_dns::hostport(host, 443))
            .await
            .into_iter()
            .map(|s| s.ip())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
    if ips.is_empty() {
        warn!(%host, "overlay exit-node: coordination-server DNS resolve failed; exit routing withholds until exemptions are known");
        return ips;
    }
    info!(
        %host,
        count = ips.len(),
        "overlay exit-node: resolved coordination-server IPs for carrier exemption"
    );
    ips
}

/// This org's loopback SOCKS5 port for **netstack mode**. `None` (the
/// default) selects OS-TUN mode; a zero value is treated as unset.
///
/// The PRIMARY reads `MESHHARBORD_OVERLAY_NETSTACK_SOCKS`, exactly as
/// before. A SECONDARY gets whatever its `[[orgs]]` entry declares and
/// deliberately does NOT fall back to the env key: the port is one TCP
/// listener, so inheriting it would put two orgs on one front — the very
/// thing the per-org split exists to prevent.
fn netstack_socks_port(cfg: &AgentConfig) -> Option<u16> {
    cfg.netstack_socks_port
        .or_else(|| {
            // Only a primary config reaches the env: `for_org` always sets
            // the field explicitly (to the org's value, or None).
            (!cfg.derived_org)
                .then(|| node_env("OVERLAY_NETSTACK_SOCKS"))
                .flatten()
                .and_then(|v| v.trim().parse::<u16>().ok())
        })
        .filter(|p| *p != 0)
}

/// rc.280 — process-lifetime TUN cache. The runtime builds its device per WS
/// SESSION (first netmap) and drops it when `run()` returns, which used to
/// REMOVE the Wintun adapter on every reconnect (wintun's close-of-created
/// removes) and re-create it seconds later — the ifIndex/NLA churn multiplier
/// on top of the per-create random GUID (fixed in rc.279), and the source of
/// the rc.209 "device installation mutex" race between a dying session's
/// release and the next session's create. Caching the `Arc` here keeps the
/// device alive across sessions: a reconnect with the same `(ip, netmask,
/// mtu)` reuses it (metric pin, derived v6, WFP guard, Private profile all
/// still in place); a changed tuple (re-IP / re-enroll) drops the old device
/// first, then builds fresh. The static itself is never dropped, so even a
/// clean process exit leaves the adapter installed — the next process opens
/// it by name or re-forms the same identity via the rc.279 stable GUID.
#[cfg(feature = "overlay-l3")]
#[allow(clippy::type_complexity)]
static SYSTUN_CACHE: std::sync::Mutex<
    Option<(
        (std::net::Ipv4Addr, std::net::Ipv4Addr, u16),
        Arc<SystemTun>,
    )>,
> = std::sync::Mutex::new(None);

/// OS-TUN factory (`overlay-l3`). The agent is privileged, so the device +
/// routes come up directly in `SystemTun::up`. Kill-switch for the cache:
/// `overlay_tun_persist` / `MESHHARBORD_OVERLAY_TUN_PERSIST`, default ON —
/// `0` restores the per-session create/remove cycle.
#[cfg(feature = "overlay-l3")]
fn systun_tun_factory() -> Option<TunFactory> {
    Some(Box::new(|ip, nm, mtu| {
        if !tunnel_core::env::flag("OVERLAY_TUN_PERSIST", true) {
            return SystemTun::up(ip, nm, mtu).map(|t| Arc::new(t) as Arc<dyn TunIo>);
        }
        let mut cache = SYSTUN_CACHE.lock().unwrap();
        if let Some((params, dev)) = cache.as_ref()
            && *params == (ip, nm, mtu)
            && dev.is_alive()
        {
            info!("overlay: reusing the process-lifetime TUN device (reconnect)");
            return Ok(dev.clone() as Arc<dyn TunIo>);
        }
        // Param change (re-IP) or dead device: release the old one BEFORE the
        // new create so the adapter's device-install lock frees up (the
        // rc.209 mutex retry inside `up` covers the release latency).
        *cache = None;
        let dev = Arc::new(SystemTun::up(ip, nm, mtu)?);
        *cache = Some(((ip, nm, mtu), dev.clone()));
        Ok(dev as Arc<dyn TunIo>)
    }))
}
#[cfg(not(feature = "overlay-l3"))]
fn systun_tun_factory() -> Option<TunFactory> {
    warn!(
        "overlay: OS-TUN mode requested but this build lacks `overlay-l3` \
         (set MESHHARBORD_OVERLAY_NETSTACK_SOCKS for netstack mode); not joining"
    );
    None
}

/// Multi-org — release everything process-wide an org held: its per-org TUN
/// device claim, and the netstack surface if it owned that.
///
/// Called when an org's supervised loop ENDS for good (disabled, removed,
/// terminal error) — until now the address stayed up until the daemon
/// restarted (docs/multi-org.md §12). Harmless but untidy, and on a
/// long-lived multi-org host the litter accumulates.
///
/// No-op for anything the org never claimed (single-org daemons never
/// register), so it is safe to call unconditionally on teardown.
pub fn release_org(org_key: &str) {
    release_per_org_tun(org_key);
    release_netstack(org_key);
    crate::overlay_supervision::clear_org_state(org_key);
}

/// F1 — build the overlay `TunFactory` for `cfg`, automatically falling back to
/// userspace `netstack` (with an ephemeral loopback SOCKS5 port on `127.0.0.1`)
/// on Windows when OS TUN creation lacks administrator privilege, and tracking
/// bounded-interval failure backoff for non-privilege overlay errors.
fn build_tun_factory_with_fallback(
    cfg: &AgentConfig,
    view_rx: watch::Receiver<OverlayView>,
    is_windows: bool,
    os_tun_permitted: bool,
    base_os_tun: Option<TunFactory>,
    now_fn: Arc<dyn Fn() -> std::time::Instant + Send + Sync>,
) -> Option<(TunFactory, Option<u16>)> {
    let shape_key = crate::overlay_supervision::shape_key_for_config(cfg);

    // 1. Explicitly configured netstack mode (`netstack_socks_port` or env).
    if (!cfg.overlay_multi_org || cfg.derived_netstack)
        && let Some(port) = netstack_socks_port(cfg)
    {
        let f = netstack_tun_factory(port, view_rx, &cfg.tenant_id)?;
        crate::overlay_supervision::record_overlay_running(
            &cfg.tenant_id,
            &shape_key,
            "netstack",
            Some(port),
            false,
        );
        let org = cfg.tenant_id.clone();
        let shape = shape_key.clone();
        let wrapped: TunFactory = Box::new(move |ip, nm, mtu| {
            let dev = f(ip, nm, mtu)?;
            crate::overlay_supervision::record_overlay_running(
                &org,
                &shape,
                "netstack",
                Some(port),
                false,
            );
            Ok(dev)
        });
        return Some((wrapped, Some(port)));
    }

    // 2. F1 Windows fallback: when on Windows and OS TUN is not permitted
    // (non-elevated Medium IL process) or a prior attempt in this process
    // latched netstack fallback for this org, build the runtime in netstack
    // mode up front (`effective_socks_port = Some(port)`) so `OverlayRuntime`
    // withdraws route offers and disables host-wide DNS steering (FR-97 P0c-3).
    if is_windows
        && (!os_tun_permitted
            || crate::overlay_supervision::has_latched_netstack_fallback(&cfg.tenant_id))
    {
        #[cfg(feature = "overlay-netstack")]
        {
            let (f, port) =
                allocate_fallback_netstack_tun_factory(view_rx, &cfg.tenant_id, &shape_key)?;
            info!(
                org = %cfg.tenant_id,
                socks_port = port,
                "overlay: OS TUN unavailable without administrator privilege; automatically using userspace netstack (127.0.0.1 SOCKS5)"
            );
            return Some((f, Some(port)));
        }
        #[cfg(not(feature = "overlay-netstack"))]
        {
            let _ = &view_rx;
            crate::overlay_supervision::record_overlay_failure(
                &cfg.tenant_id,
                &shape_key,
                "OS TUN requires administrator privileges and overlay-netstack is not compiled in"
                    .to_string(),
                (now_fn)(),
            );
            return None;
        }
    }

    // 3. OS TUN mode is permitted: wrap `base_os_tun` so a reactive Windows
    // privilege failure (e.g. `WintunCreateAdapter failed`) latches netstack
    // fallback and returns `Err` so `OverlayRuntime` exits and immediately
    // rebuilds via Branch 2 with `netstack_socks = Some(port)`. Non-Windows or
    // non-privilege failures record bounded-interval backoff.
    let os_tun = base_os_tun?;
    let org = cfg.tenant_id.clone();
    let shape = shape_key.clone();

    let wrapped: TunFactory = Box::new(move |ip, nm, mtu| match os_tun(ip, nm, mtu) {
        Ok(dev) => {
            crate::overlay_supervision::record_overlay_running(&org, &shape, "tun", None, false);
            Ok(dev)
        }
        Err(e) => {
            #[cfg(feature = "overlay-netstack")]
            if crate::overlay_supervision::is_tun_privilege_error_on(&e, is_windows) {
                crate::overlay_supervision::latch_netstack_fallback(&org, &shape);
                warn!(
                    org = %org,
                    error = %e,
                    "overlay: OS TUN creation failed due to insufficient privilege on Windows; latching userspace netstack fallback for immediate runtime rebuild"
                );
                return Err(e);
            }

            let now = (now_fn)();
            #[cfg(feature = "overlay-netstack")]
            if crate::overlay_supervision::is_generic_wintun_create_error_on(&e, is_windows) {
                if crate::overlay_supervision::record_wintun_create_failure(
                    &org,
                    &shape,
                    e.to_string(),
                    now,
                ) {
                    warn!(
                        org = %org,
                        error = %e,
                        strikes = crate::overlay_supervision::WINTUN_FALLBACK_STRIKE_LIMIT,
                        "overlay: WintunCreateAdapter failed 3 consecutive times on Windows; latching userspace netstack fallback for immediate runtime rebuild"
                    );
                } else {
                    warn!(
                        org = %org,
                        error = %e,
                        mode = %crate::overlay_supervision::effective_overlay_mode(&org, "tun"),
                        "overlay: WintunCreateAdapter failed; recorded bounded failure backoff and will retry OS TUN"
                    );
                }
                return Err(e);
            }

            crate::overlay_supervision::record_overlay_failure(&org, &shape, e.to_string(), now);
            warn!(
                org = %org,
                error = %e,
                mode = %crate::overlay_supervision::effective_overlay_mode(&org, "tun"),
                "overlay: TUN creation failed; recorded bounded failure backoff"
            );
            Err(e)
        }
    });

    Some((wrapped, None))
}

/// F1 — allocate (or reuse) an ephemeral loopback SOCKS5 port on `127.0.0.1`
/// for `org_key`, start the SOCKS5 front task, record `"netstack"` mode in
/// `overlay_supervision`, and return the userspace `TunFactory` + port.
#[cfg(feature = "overlay-netstack")]
fn allocate_fallback_netstack_tun_factory(
    view_rx: watch::Receiver<OverlayView>,
    org_key: &str,
    shape_key: &str,
) -> Option<(TunFactory, u16)> {
    use std::net::Ipv4Addr;
    use tunnel_core::overlay::netstack::Netstack;
    use tunnel_core::overlay::netstack_socks::serve_socks5;

    let handle_tx = ns_handle_tx(org_key);

    // Reuse an already-bound fallback port for this org if present.
    let existing_port = crate::overlay_supervision::effective_socks5_port(org_key).filter(|p| {
        let ports = SOCKS_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        ports
            .as_ref()
            .and_then(|m| m.get(p))
            .is_some_and(|owner| owner == org_key)
    });

    let socks_port = if let Some(port) = existing_port {
        port
    } else {
        let std_listener = match std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
            Ok(l) => l,
            Err(e) => {
                warn!(org = %org_key, error = %e, "overlay netstack fallback: failed to bind ephemeral loopback SOCKS5 port");
                return None;
            }
        };
        let _ = std_listener.set_nonblocking(true);
        let port = match std_listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => {
                warn!(org = %org_key, error = %e, "overlay netstack fallback: failed to query local_addr");
                return None;
            }
        };
        let _ = claim_socks_port(org_key, port);
        {
            let mut bound = SOCKS_BOUND.lock().unwrap_or_else(|e| e.into_inner());
            bound.get_or_insert_with(Default::default).insert(port);
        }
        if let Ok(rt_handle) = tokio::runtime::Handle::try_current() {
            let handle_rx = handle_tx.subscribe();
            let org = org_key.to_string();
            rt_handle.spawn(async move {
                match tokio::net::TcpListener::from_std(std_listener) {
                    Ok(l) => {
                        info!(
                            port, %org,
                            "overlay netstack: auto-fallback SOCKS5 front on 127.0.0.1"
                        );
                        serve_socks5(handle_rx, view_rx, l).await;
                    }
                    Err(e) => {
                        warn!(port, %org, error = %e, "overlay netstack: auto-fallback SOCKS5 from_std failed");
                    }
                }
            });
        }
        port
    };

    crate::overlay_supervision::record_overlay_running(
        org_key,
        shape_key,
        "netstack",
        Some(socks_port),
        true,
    );

    let org = org_key.to_string();
    let shape = shape_key.to_string();
    let factory: TunFactory = Box::new(move |ip, nm, mtu| {
        let ns = Netstack::start(ip, netmask_to_prefix(nm), mtu);
        let _ = handle_tx.send(Some(ns.handle.clone()));
        crate::overlay_supervision::record_overlay_running(
            &org,
            &shape,
            "netstack",
            Some(socks_port),
            true,
        );
        info!(%ip, socks_port, %org, "overlay netstack: userspace stack up (OS-free fallback)");
        Ok(ns.tun as Arc<dyn TunIo>)
    });
    Some((factory, socks_port))
}

/// B3 — notify this org's persistent `OverlayRuntime` that the control-WS
/// session disconnected (or failed to establish/authenticate), starting the
/// bounded offline continuity lease timer (`offline_continuity_max_age`).
pub fn note_control_detached(tenant_id: &str) {
    let evt_tx = RUNTIME_SLOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(tenant_id)
        .map(|s| s.evt_tx.clone());
    if let Some(tx) = evt_tx {
        let _ = tx.send_reliable(OverlayEvent::ControlDetached);
    }
}

/// Hand this org's loopback SOCKS port back when its loop ends, so an org
/// configured onto the same port can take it on its next reconnect instead
/// of withholding forever.
#[cfg(feature = "overlay-netstack")]
fn release_netstack(org_key: &str) {
    let mut ports = SOCKS_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ports) = ports.as_mut() {
        let freed: Vec<u16> = ports
            .iter()
            .filter(|(_, o)| o.as_str() == org_key)
            .map(|(p, _)| *p)
            .collect();
        for p in freed {
            ports.remove(&p);
            info!(org = %org_key, port = p,
                "overlay netstack: released the org's loopback SOCKS port");
        }
    }
}
#[cfg(not(feature = "overlay-netstack"))]
fn release_netstack(_org_key: &str) {}

/// Multi-org v2 — per-org TUN devices, keyed by tenant. Same process-lifetime
/// reuse contract as [`SYSTUN_CACHE`] (incl. the `overlay_tun_persist` kill
/// switch), one entry per org. Dropping an entry releases the process's
/// device handle; the ADAPTER persists by design (stable per-org GUID —
/// explicit org removal owns real deletion, never a loop end, so an ESET-y
/// host never sees device churn on reconnects).
#[cfg(feature = "overlay-l3")]
#[allow(clippy::type_complexity)]
static ORG_TUN_CACHE: std::sync::Mutex<
    Option<
        std::collections::BTreeMap<
            String,
            (
                (std::net::Ipv4Addr, std::net::Ipv4Addr, u16),
                Arc<SystemTun>,
            ),
        >,
    >,
> = std::sync::Mutex::new(None);

/// Multi-org v2 — a per-org adapter name that FITS the OS limit. Linux caps
/// interface names at `IFNAMSIZ-1` = 15 usable chars, and the base `IF_NAME`
/// differs per platform (`meshharbor` on Windows = 7, `meshharbor0` on Linux = 8),
/// so the naive `meshharbor0-<7hex>` (16) overflows on Linux and the kernel
/// rejects it — the secondary org's TUN never comes up. The tenant suffix is
/// truncated to whatever fits after `<IF_NAME>-`: Windows keeps 7 hex
/// (`meshharbor-6a712a5`), Linux keeps 6 (`meshharbor0-6a712a`). Deterministic per
/// (machine, org) — the suffix is a stable tenant-id prefix, and the FULL
/// tenant still drives the distinct per-org GUID, so a 6-hex-prefix clash
/// (negligible for a machine's handful of orgs) can't alias two devices.
#[cfg(any(feature = "overlay-l3", test))]
fn per_org_ifname(if_name: &str, org_key: &str) -> String {
    const MAX_IFNAME: usize = 15; // IFNAMSIZ - 1 (Linux); Windows aliases allow more
    let max_suffix = MAX_IFNAME.saturating_sub(if_name.len() + 1);
    let short = &org_key[..org_key.len().min(max_suffix)];
    format!("{if_name}-{short}")
}

/// Multi-org v2 — the per-org twin of [`systun_tun_factory`]: this org gets
/// its OWN adapter with its own name, stable per-org GUID, and a derived-ULA
/// on-link NARROWED to its block (`96 + v4_plen`), so N adapters hold
/// nested-or-disjoint v6 prefixes and longest-prefix picks the right one.
///
/// Naming: the primary KEEPS the legacy `IF_NAME` (`meshharbor` / `meshharbor0`) +
/// GUID (no adapter churn on the mode flip); a secondary is
/// [`per_org_ifname`] (length-clamped for Linux IFNAMSIZ) with a stable
/// per-org GUID. The primary's on-link is narrowed too: its whole-/96 would
/// otherwise cover every sibling's embedded ULA range.
#[cfg(feature = "overlay-l3")]
fn per_org_systun_factory(org_key: String, is_primary: bool) -> Option<TunFactory> {
    use tunnel_core::overlay::tun::{IF_NAME, TunOptions, org_tun_guid};
    Some(Box::new(move |ip, nm, mtu| {
        let plen = u32::from(nm).count_ones() as u8;
        let mut opts = TunOptions::legacy(ip, nm, mtu);
        opts.v6_onlink_plen = 96 + plen;
        if !is_primary {
            opts.name = per_org_ifname(IF_NAME, &org_key);
            opts.guid = org_tun_guid(&org_key);
        }
        if !tunnel_core::env::flag("OVERLAY_TUN_PERSIST", true) {
            return SystemTun::up_with(opts).map(|t| Arc::new(t) as Arc<dyn TunIo>);
        }
        let mut cache = ORG_TUN_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let map = cache.get_or_insert_with(Default::default);
        if let Some((params, dev)) = map.get(&org_key)
            && *params == (ip, nm, mtu)
            && dev.is_alive()
        {
            info!(org = %org_key, "overlay: reusing this org's process-lifetime TUN device (reconnect)");
            return Ok(dev.clone() as Arc<dyn TunIo>);
        }
        // Param change (re-IP) or dead device: release the old handle BEFORE
        // the new create (frees the adapter's device-install lock; the
        // rc.209 retry inside `up_with` covers the release latency).
        map.remove(&org_key);
        let dev = Arc::new(SystemTun::up_with(opts)?);
        map.insert(org_key.clone(), ((ip, nm, mtu), dev.clone()));
        info!(org = %org_key, primary = is_primary, "overlay: per-org TUN device up");
        Ok(dev as Arc<dyn TunIo>)
    }))
}
#[cfg(not(feature = "overlay-l3"))]
fn per_org_systun_factory(_org_key: String, _is_primary: bool) -> Option<TunFactory> {
    warn!("overlay: a per-org adapter requires an `overlay-l3` build; not joining");
    None
}

/// Drop an org's per-org device HANDLE when its loop ends for good. The
/// adapter itself persists (stable GUID re-binds it next start); explicit
/// org removal owns real deletion.
#[cfg(feature = "overlay-l3")]
fn release_per_org_tun(org_key: &str) {
    let mut cache = ORG_TUN_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = cache.as_mut()
        && map.remove(org_key).is_some()
    {
        info!(org = %org_key, "overlay: released the org's per-org TUN handle (adapter persists)");
    }
}
#[cfg(not(feature = "overlay-l3"))]
fn release_per_org_tun(_org_key: &str) {}

/// Multi-org — one netstack handle channel PER ORG.
///
/// This used to be a single `OnceLock` channel, and that was the bug: the
/// SOCKS front and the `mh ping` backend both read it, so a second org
/// publishing its stack did not join the mesh twice — it REPLACED the first
/// org's stack underneath a front that kept answering on the same port, and
/// a caller dialing for org A was silently routed by org B.
///
/// Keyed by org (the tenant id), so each org's front and pinger read their
/// OWN stack. Created on first use per org and reused across that org's
/// reconnects, which is what keeps the front alive between sessions.
#[cfg(feature = "overlay-netstack")]
#[allow(clippy::type_complexity)]
static NS_HANDLES: std::sync::Mutex<
    Option<
        std::collections::BTreeMap<
            String,
            watch::Sender<Option<tunnel_core::overlay::netstack::NetstackHandle>>,
        >,
    >,
> = std::sync::Mutex::new(None);

#[cfg(feature = "overlay-netstack")]
fn ns_handle_tx(
    org_key: &str,
) -> watch::Sender<Option<tunnel_core::overlay::netstack::NetstackHandle>> {
    let mut map = NS_HANDLES.lock().unwrap_or_else(|e| e.into_inner());
    map.get_or_insert_with(Default::default)
        .entry(org_key.to_string())
        .or_insert_with(|| watch::channel(None).0)
        .clone()
}

/// RDP over the mesh — `org_key`'s netstack handle (`None` until the userspace
/// stack is up; replaced whenever it is rebuilt).
#[cfg(feature = "overlay-netstack")]
pub(crate) fn netstack_handle_rx(
    org_key: &str,
) -> watch::Receiver<Option<tunnel_core::overlay::netstack::NetstackHandle>> {
    ns_handle_tx(org_key).subscribe()
}

/// Which org holds each loopback SOCKS port.
///
/// The per-org split removes the shared-stack hazard but not this one: a
/// port is a single TCP listener, so two orgs configured onto the same one
/// still genuinely conflict. First org in binds it; a second withholds its
/// overlay with an actionable message rather than taking a front that
/// answers for someone else. Released when its owner's loop ends.
#[cfg(feature = "overlay-netstack")]
static SOCKS_PORTS: std::sync::Mutex<Option<std::collections::BTreeMap<u16, String>>> =
    std::sync::Mutex::new(None);

/// Claim `port` for `org_key`. `false` ⇒ another org already holds it.
/// Re-claiming by the owner is a no-op, which is what every reconnect does.
#[cfg(feature = "overlay-netstack")]
fn claim_socks_port(org_key: &str, port: u16) -> bool {
    let mut map = SOCKS_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let map = map.get_or_insert_with(Default::default);
    match map.get(&port) {
        Some(cur) => cur == org_key,
        None => {
            map.insert(port, org_key.to_string());
            true
        }
    }
}

/// Netstack factory (`overlay-netstack`): each (re)connect builds a fresh
/// userspace stack for THIS org and publishes its handle to that org's
/// channel, so its loopback SOCKS front (bound once per port) outlives
/// reconnects without rebinding.
///
/// `None` when another org already holds `socks_port` — see
/// [`claim_socks_port`].
#[cfg(feature = "overlay-netstack")]
fn netstack_tun_factory(
    socks_port: u16,
    view_rx: watch::Receiver<OverlayView>,
    org_key: &str,
) -> Option<TunFactory> {
    use std::net::Ipv4Addr;
    use tunnel_core::overlay::netstack::Netstack;
    use tunnel_core::overlay::netstack_socks::serve_socks5;

    if !claim_socks_port(org_key, socks_port) {
        warn!(
            org = %org_key, port = socks_port,
            "overlay netstack: another organization already serves this loopback SOCKS \
             port. This org joins no mesh until it gets its own — set \
             `netstack_socks_port` on its [[orgs]] entry, or give both orgs an OS \
             TUN of their own with `overlay_multi_org`."
        );
        return None;
    }

    let handle_tx = ns_handle_tx(org_key);

    // Bind this org's front exactly once — a repeat call for the same port
    // is a reconnect, and the running front is already subscribed to the
    // org's channel.
    let bind_needed = {
        let mut bound = SOCKS_BOUND.lock().unwrap_or_else(|e| e.into_inner());
        bound
            .get_or_insert_with(Default::default)
            .insert(socks_port)
    };
    if bind_needed {
        let handle_rx = handle_tx.subscribe();
        let org = org_key.to_string();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, socks_port)).await {
                Ok(l) => {
                    info!(
                        port = socks_port, %org,
                        "overlay netstack: SOCKS5 front on 127.0.0.1"
                    );
                    serve_socks5(handle_rx, view_rx, l).await;
                }
                Err(e) => {
                    warn!(port = socks_port, %org, error = %e,
                        "overlay netstack: SOCKS bind failed")
                }
            }
        });
    }

    let org = org_key.to_string();
    Some(Box::new(move |ip, nm, mtu| {
        let ns = Netstack::start(ip, netmask_to_prefix(nm), mtu);
        let _ = handle_tx.send(Some(ns.handle.clone()));
        info!(%ip, socks_port, %org, "overlay netstack: userspace stack up (OS-free)");
        Ok(ns.tun as Arc<dyn TunIo>)
    }))
}

/// Ports whose SOCKS front task is already running.
#[cfg(feature = "overlay-netstack")]
static SOCKS_BOUND: std::sync::Mutex<Option<std::collections::BTreeSet<u16>>> =
    std::sync::Mutex::new(None);

/// The netstack ICMP backend for the `mh ping` LocalAPI verb, watching the
/// shared handle channel. Supports both explicit netstack mode and F1
/// privilege fallback to netstack; delegates to `OsPinger` when running in
/// OS-TUN mode.
#[cfg(feature = "overlay-netstack")]
pub fn netstack_pinger(
    cfg: &AgentConfig,
) -> Option<Arc<dyn crate::localapi_state::NetstackPinger>> {
    use std::net::IpAddr;
    use std::time::Duration;
    use tunnel_core::overlay::netstack::NetstackHandle;

    let explicit_netstack = netstack_socks_port(cfg).is_some();
    if !explicit_netstack && !cfg.overlay_enabled {
        return None;
    }

    struct NsPinger {
        tenant_id: String,
        explicit_netstack: bool,
        handle: watch::Receiver<Option<NetstackHandle>>,
    }
    #[async_trait::async_trait]
    impl crate::localapi_state::NetstackPinger for NsPinger {
        async fn ping(&self, dst: IpAddr, timeout: Duration) -> Result<Duration, String> {
            let maybe_handle = self.handle.borrow().clone();
            if let Some(handle) = maybe_handle {
                return handle.ping(dst, timeout).await.map_err(|e| e.to_string());
            }
            if self.explicit_netstack
                || !crate::overlay_supervision::process_can_create_os_tun()
                || crate::overlay_supervision::effective_socks5_port(&self.tenant_id).is_some()
            {
                return Err("netstack not up yet (mesh not joined)".to_string());
            }
            crate::localapi_state::OsPinger.ping(dst, timeout).await
        }
    }

    Some(Arc::new(NsPinger {
        tenant_id: cfg.tenant_id.clone(),
        explicit_netstack,
        handle: ns_handle_tx(&cfg.tenant_id).subscribe(),
    }))
}

/// MeshHarbor #20 FWD-02 — how a managed forward dials a destination behind
/// the overlay on a netstack node: this org's own stack, or the host's routes
/// when the org is running in OS-TUN mode (checked dynamically per dial so a
/// reactive Windows fallback switches existing forwarders to netstack).
#[cfg(feature = "overlay-netstack")]
pub fn managed_forward_dialer(
    cfg: &AgentConfig,
) -> Option<Arc<dyn crate::managed_forward::OverlayDial>> {
    use tunnel_core::overlay::netstack::NetstackHandle;

    let explicit_netstack = netstack_socks_port(cfg).is_some();
    if !explicit_netstack && !cfg.overlay_enabled {
        return None;
    }

    struct NsDial {
        tenant_id: String,
        explicit_netstack: bool,
        handle: watch::Receiver<Option<NetstackHandle>>,
    }
    impl NsDial {
        fn should_use_netstack(&self) -> bool {
            self.explicit_netstack
                || !crate::overlay_supervision::process_can_create_os_tun()
                || crate::overlay_supervision::is_org_in_netstack_mode(&self.tenant_id)
                || self.handle.borrow().is_some()
        }
    }
    #[async_trait::async_trait]
    impl crate::managed_forward::OverlayDial for NsDial {
        async fn tcp(
            &self,
            dst: std::net::SocketAddr,
        ) -> std::io::Result<Box<dyn crate::managed_forward::Io>> {
            if !self.should_use_netstack() {
                return Ok(Box::new(tokio::net::TcpStream::connect(dst).await?));
            }
            let handle =
                self.handle.borrow().clone().ok_or_else(|| {
                    std::io::Error::other("netstack not up yet (mesh not joined)")
                })?;
            Ok(Box::new(handle.connect(dst).await?))
        }
        async fn udp(
            &self,
            dst: std::net::SocketAddr,
        ) -> std::io::Result<Box<dyn crate::managed_forward::UdpSession>> {
            if !self.should_use_netstack() {
                return crate::managed_forward::kernel_udp(dst).await;
            }
            let handle =
                self.handle.borrow().clone().ok_or_else(|| {
                    std::io::Error::other("netstack not up yet (mesh not joined)")
                })?;
            let sock = handle.udp_bind().await?;
            Ok(Box::new(NsUdp {
                tx: sock.sender(),
                rx: tokio::sync::Mutex::new(sock),
                dst,
            }))
        }
    }

    /// A client's UDP session on the netstack: its own socket, talking to
    /// `dst` only (a datagram from anyone else is dropped).
    struct NsUdp {
        tx: tunnel_core::overlay::netstack::NsUdpSender,
        rx: tokio::sync::Mutex<tunnel_core::overlay::netstack::NsUdpSocket>,
        dst: std::net::SocketAddr,
    }
    #[async_trait::async_trait]
    impl crate::managed_forward::UdpSession for NsUdp {
        async fn send(&self, data: &[u8]) -> std::io::Result<()> {
            self.tx.send_to(data, self.dst).await
        }
        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut rx = self.rx.lock().await;
            loop {
                let (data, from) = rx.recv_from().await?;
                if from == self.dst {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok(n);
                }
            }
        }
    }

    Some(Arc::new(NsDial {
        tenant_id: cfg.tenant_id.clone(),
        explicit_netstack,
        handle: ns_handle_tx(&cfg.tenant_id).subscribe(),
    }))
}

#[cfg(not(feature = "overlay-netstack"))]
pub fn managed_forward_dialer(
    _cfg: &AgentConfig,
) -> Option<Arc<dyn crate::managed_forward::OverlayDial>> {
    None
}

/// FR-90 P3-8-2b — the netstack dialer for this daemon's own SSH client
/// ([`crate::ssh_client`]), watching the primary's handle channel, where
/// agent sessions run. Dynamically delegates to [`crate::ssh_client::OsDialer`]
/// when the org is in OS-TUN mode and switches to `netstack` when configured
/// or after F1 privilege fallback.
#[cfg(all(feature = "ssh-server", feature = "overlay-netstack"))]
pub fn netstack_dialer(cfg: &AgentConfig) -> Option<Arc<dyn crate::ssh_client::OverlayDialer>> {
    use tunnel_core::overlay::netstack::NetstackHandle;

    let explicit_netstack = netstack_socks_port(cfg).is_some();
    if !explicit_netstack && !cfg.overlay_enabled {
        return None;
    }

    struct NsDialer {
        tenant_id: String,
        explicit_netstack: bool,
        handle: watch::Receiver<Option<NetstackHandle>>,
    }
    impl NsDialer {
        fn should_use_netstack(&self) -> bool {
            self.explicit_netstack
                || !crate::overlay_supervision::process_can_create_os_tun()
                || crate::overlay_supervision::is_org_in_netstack_mode(&self.tenant_id)
                || self.handle.borrow().is_some()
        }
    }
    #[async_trait::async_trait]
    impl crate::ssh_client::OverlayDialer for NsDialer {
        async fn dial(
            &self,
            address: &str,
            port: u16,
        ) -> Result<Box<dyn crate::ssh_client::Stream>, String> {
            if !self.should_use_netstack() {
                return crate::ssh_client::OsDialer.dial(address, port).await;
            }
            let ip: std::net::IpAddr = address
                .parse()
                .map_err(|_| format!("{address} is not an overlay address"))?;
            let handle = self
                .handle
                .borrow()
                .clone()
                .ok_or_else(|| "netstack not up yet (mesh not joined)".to_string())?;
            let stream = handle
                .connect(std::net::SocketAddr::new(ip, port))
                .await
                .map_err(|e| format!("{address}:{port}: {e}"))?;
            Ok(Box::new(stream))
        }
    }

    Some(Arc::new(NsDialer {
        tenant_id: cfg.tenant_id.clone(),
        explicit_netstack,
        handle: ns_handle_tx(&cfg.tenant_id).subscribe(),
    }))
}

#[cfg(all(feature = "ssh-server", not(feature = "overlay-netstack")))]
pub fn netstack_dialer(_cfg: &AgentConfig) -> Option<Arc<dyn crate::ssh_client::OverlayDialer>> {
    None
}
#[cfg(not(feature = "overlay-netstack"))]
fn netstack_tun_factory(
    _socks_port: u16,
    _view_rx: watch::Receiver<OverlayView>,
    _org_key: &str,
) -> Option<TunFactory> {
    warn!(
        "overlay: netstack mode requested (MESHHARBORD_OVERLAY_NETSTACK_SOCKS set) \
         but this build lacks `overlay-netstack`; not joining"
    );
    None
}

/// IPv4 netmask → prefix length (count of leading one-bits).
#[cfg(feature = "overlay-netstack")]
pub(crate) fn netmask_to_prefix(nm: std::net::Ipv4Addr) -> u8 {
    u32::from(nm).count_ones() as u8
}

/// Forward an `rc:overlay.*` `ServerMsg` to the runtime. Returns the
/// message untouched if it isn't an overlay message, so the caller's
/// normal dispatch handles everything else.
pub fn intercept(
    evt_tx: &OverlayEventTx,
    msg: ServerMsg,
    is_primary: bool,
    local_agent_id: &str,
    local_tenant_id: &str,
) -> Option<ServerMsg> {
    if let ServerMsg::OverlaySelfName {
        agent_id,
        tenant_id,
        node_id,
        revision,
        name,
    } = msg
    {
        if agent_id == local_agent_id && tenant_id == local_tenant_id {
            if evt_tx
                .try_send(OverlayEvent::SelfName {
                    node_id,
                    revision,
                    name,
                })
                .is_err()
            {
                warn!("overlay self DNS metadata queue unavailable; awaiting next reconciliation");
            }
        } else {
            warn!("overlay self DNS metadata ignored: enrollment scope mismatch");
        }
        return None;
    }
    match classify_intercept(msg, is_primary, local_agent_id, |bridge| {
        crate::relay_server::install_bridge_from_wire(bridge)
    }) {
        InterceptOutcome::MustDeliver(evt) => {
            if evt_tx.send_reliable(evt).is_err() {
                warn!("overlay: event channel closed; dropping authoritative join/netmap event");
            }
            None
        }
        InterceptOutcome::Forward(evt) => {
            if evt_tx.try_send(evt).is_err() {
                warn!("overlay: event channel full/closed; dropping a netmap update");
            }
            None
        }
        InterceptOutcome::Consumed => None,
        InterceptOutcome::PassThrough(other) => Some(other),
    }
}

enum InterceptOutcome {
    MustDeliver(OverlayEvent),
    Forward(OverlayEvent),
    Consumed,
    PassThrough(ServerMsg),
}

fn classify_intercept(
    msg: ServerMsg,
    is_primary: bool,
    local_agent_id: &str,
    install: impl FnOnce(meshharbor_remote_control::signaling::RelayBridgeWire),
) -> InterceptOutcome {
    let evt = match msg {
        ServerMsg::OverlayNetmap {
            self_ip,
            network,
            peers,
            org_relay_discovery,
            path_trial_v1,
            ..
        } => {
            return InterceptOutcome::MustDeliver(OverlayEvent::Netmap {
                self_ip,
                network,
                peers,
                org_relay_discovery,
                path_trial_v1,
            });
        }
        ServerMsg::OverlayNetmapDelta {
            epoch,
            auth_revision,
            upserts,
            removes,
        } => OverlayEvent::NetmapDelta {
            epoch,
            auth_revision,
            upserts,
            removes,
        },
        // FR-47 — the server could not complete our join and said why.
        //
        // When `reason.is_retryable()` (`StoreUnavailable`, e.g. concurrent
        // authority / access-projection contention on a fleet-wide reconnect),
        // reliably forward `JoinRefused { retryable: true }` so the persistent
        // runtime schedules a jittered re-join on the still-open control WS
        // instead of stranding detached forever; terminal refusals
        // (`retryable: false`, such as `AddressSpaceExhausted` or
        // `KeyUnauthorized`) cancel pending retries and start continuity clocks.
        ServerMsg::OverlayJoinRefused { reason, detail } => {
            if reason.is_retryable() {
                tracing::warn!(
                    ?reason,
                    %detail,
                    retryable = true,
                    "overlay: join transiently refused by server — runtime will back off and retry"
                );
            } else {
                tracing::error!(
                    ?reason,
                    %detail,
                    retryable = false,
                    "overlay: the server REFUSED our join — this node has no overlay \
                     address and will not appear in the mesh"
                );
            }
            record_join_refusal(reason, &detail);
            return InterceptOutcome::MustDeliver(OverlayEvent::JoinRefused {
                retryable: reason.is_retryable(),
            });
        }
        // T12 — a host with the TURN tier switched off never dials a coturn
        // worker. A pair grant stops here, before any allocation exists.
        ServerMsg::OverlayRelayGrant { .. }
            if !tunnel_core::overlay::direct::turn_relay_enabled() =>
        {
            static NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !NOTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::info!(
                    "overlay: TURN relay tier is off on this host (overlay_turn_relay = false) — \
                     relay grants are ignored and no coturn worker is dialled"
                );
            }
            return InterceptOutcome::Consumed;
        }
        // The warm grant also carries the netcheck measurement, which waits
        // for it: forward it WITHOUT credentials, so the measurement completes
        // with the relay band honestly unmeasured and nothing is allocated.
        ServerMsg::OverlayWarmRelayGrant { .. }
            if !tunnel_core::overlay::direct::turn_relay_enabled() =>
        {
            OverlayEvent::WarmRelayGrant {
                ice_servers: Vec::new(),
            }
        }
        ServerMsg::OverlayRelayGrant {
            ice_servers,
            peer_node_id,
            pair_key,
        } => OverlayEvent::RelayGrant {
            peer_node_id,
            ice_servers,
            pair_key,
        },
        // C4 stage 1 — pair-less creds for the standing warm allocation
        // (the reply to the runtime's own warm_relay_request).
        ServerMsg::OverlayWarmRelayGrant { ice_servers } => {
            OverlayEvent::WarmRelayGrant { ice_servers }
        }
        // P7 — server-pushed per-pair DERP escalation (corp TURN churn).
        ServerMsg::OverlayForceDerp {
            peer_node_id,
            ttl_ms,
            derp_url,
        } => OverlayEvent::ForceDerp {
            peer_node_id,
            ttl_ms,
            derp_url,
        },
        // FR-19 P4b — org-relay frames. PRIMARY org only: serving and use are
        // host-global, and a secondary org's WS must not be able to install a
        // session onto the device owner's listener — the `rc:agent.update`
        // trust line. The server refuses these for a secondary-org node
        // already; this is the device's own half of that rule.
        ServerMsg::OverlayPathTrialReturnPrepare { .. }
        | ServerMsg::OverlayPathTrialReturnCommit { .. }
        | ServerMsg::OverlayPathTrialReturnFinalize { .. }
        | ServerMsg::OverlayPathTrialReturnAbort { .. }
        | ServerMsg::OverlayPathTrialStart { .. }
        | ServerMsg::OverlayPathTrialCommit { .. }
        | ServerMsg::OverlayPathTrialFinalize { .. }
        | ServerMsg::OverlayPathTrialAbort { .. }
        | ServerMsg::OverlayOrgRelayCandidates { .. }
        | ServerMsg::OverlayRelaySession { .. }
        | ServerMsg::OverlayRelayBridgeServe { .. }
        | ServerMsg::OverlayRelayBridgeRevoke { .. }
        | ServerMsg::OverlayRelayServe { .. }
        | ServerMsg::OverlayRelayRevoke { .. }
            if !is_primary =>
        {
            warn!("overlay: org-relay frame on a secondary org's WS; dropped");
            return InterceptOutcome::Consumed;
        }
        trial @ (ServerMsg::OverlayPathTrialReturnPrepare { .. }
        | ServerMsg::OverlayPathTrialReturnCommit { .. }
        | ServerMsg::OverlayPathTrialReturnFinalize { .. }
        | ServerMsg::OverlayPathTrialReturnAbort { .. }
        | ServerMsg::OverlayPathTrialStart { .. }
        | ServerMsg::OverlayPathTrialCommit { .. }
        | ServerMsg::OverlayPathTrialFinalize { .. }
        | ServerMsg::OverlayPathTrialAbort { .. }) => OverlayEvent::PathTrial(trial),
        ServerMsg::OverlayOrgRelayCandidates {
            peer_node_id,
            request_id,
            candidates,
            ttl_secs,
            next_cursor,
            scan,
        } => OverlayEvent::OrgRelayCandidates {
            peer_node_id,
            request_id,
            candidates,
            ttl_secs,
            next_cursor,
            scan,
        },
        ServerMsg::OverlayRelaySession {
            vni,
            generation,
            peer_node_id,
            relay_node_id,
            relay_endpoints,
            bind_secret,
            bind_secs,
            max_lifetime_secs,
        } => OverlayEvent::OrgRelaySession {
            vni,
            generation,
            peer_node_id,
            relay_node_id,
            relay_endpoints,
            bind_secret,
            bind_secs,
            max_lifetime_secs,
        },
        // The RELAY's copy: install into this node's relay server, if it is
        // serving. Never reaches the member runtime.
        ServerMsg::OverlayRelayBridgeServe { bridge } => {
            if bridge_source_is_local(&bridge, local_agent_id) {
                install(bridge);
            } else {
                warn!("overlay: bridge grant source does not match local agent; dropped");
            }
            return InterceptOutcome::Consumed;
        }
        ServerMsg::OverlayRelayBridgeRevoke {
            trial_id,
            generation,
        } => {
            crate::relay_server::revoke_bridge_from_wire(trial_id, generation);
            return InterceptOutcome::Consumed;
        }
        ServerMsg::OverlayRelayServe {
            vni,
            generation,
            members,
            bind_secs,
            idle_secs,
            max_lifetime_secs,
        } => {
            crate::relay_server::install_from_wire(
                vni,
                generation,
                &members,
                bind_secs,
                idle_secs,
                max_lifetime_secs,
            );
            return InterceptOutcome::Consumed;
        }
        ServerMsg::OverlayRelayRevoke { vni, scope } => {
            // A node can serve one VNI while using the same VNI on a different
            // relay. A scoped revoke belongs to exactly one of these roles.
            if scope.peer_node_id.is_none() {
                crate::relay_server::revoke_from_wire(vni, scope.generation);
                return InterceptOutcome::Consumed;
            }
            OverlayEvent::OrgRelayRevoke { vni, scope }
        }
        other => return InterceptOutcome::PassThrough(other),
    };
    InterceptOutcome::Forward(evt)
}

/// The derived-port layout is split across two crates (agent-core computes,
/// tunnel-core binds) with NO direct dependency — this lock keeps the two
/// halves arithmetically consistent, or the sibling de-confliction silently
/// re-collides.
#[cfg(test)]
mod derived_port_layout_lock {
    #[tokio::test]
    async fn self_dns_metadata_is_bound_to_enrollment_and_secondary_is_supported() {
        let (tx, mut rx) = super::overlay_event_channel(4);
        let msg = |agent: &str, tenant: &str| {
            meshharbor_remote_control::signaling::ServerMsg::OverlaySelfName {
                agent_id: agent.into(),
                tenant_id: tenant.into(),
                node_id: bson::oid::ObjectId::new(),
                revision: "1".into(),
                name: "alias-label".into(),
            }
        };
        for (agent, tenant) in [("other", "org"), ("agent", "other")] {
            assert!(super::intercept(&tx, msg(agent, tenant), false, "agent", "org").is_none());
            tokio::task::yield_now().await;
            assert!(rx.try_recv().is_err());
        }
        assert!(super::intercept(&tx, msg("agent", "org"), false, "agent", "org").is_none());
        assert!(
            matches!(rx.recv().await, Some(tunnel_core::overlay::runtime::OverlayEvent::SelfName { name, .. }) if name == "alias-label")
        );
    }

    #[test]
    fn agent_core_layout_matches_tunnel_core() {
        use meshharbor_node_core::config as c;
        use tunnel_core::overlay::direct as d;
        assert_eq!(c::DERIVED_PORT_BASE, u32::from(d::DEFAULT_DIRECT_PORT));
        assert_eq!(c::DERIVED_PORT_STRIDE, u32::from(d::DIRECT_PORT_BAND));
        // Every derived slot's WALK band must end before the public-dial
        // offset begins, and the highest base must clear the global cap.
        assert!(
            c::DERIVED_PORT_SLOTS * c::DERIVED_PORT_STRIDE <= u32::from(d::PUBLIC_DIAL_PORT_OFFSET),
            "a derived direct band would overlap another slot's public band"
        );
        // The band-2 jump must clear the WHOLE primary layout (direct
        // region + public region), or band-2 direct binds would land
        // inside primary public bands.
        assert!(
            u32::from(d::SECOND_BAND_OFFSET)
                >= u32::from(d::PUBLIC_DIAL_PORT_OFFSET)
                    + c::DERIVED_PORT_SLOTS * c::DERIVED_PORT_STRIDE,
            "band 2 would overlap the primary public region"
        );
        let max_base = c::DERIVED_PORT_BASE + (c::DERIVED_PORT_SLOTS - 1) * c::DERIVED_PORT_STRIDE;
        assert!(max_base <= u32::from(d::MAX_DIRECT_PORT_BASE));
    }
}

#[cfg(test)]
mod ifname_tests {
    use super::per_org_ifname;

    /// The per-org adapter name must never exceed Linux's 15-char IFNAMSIZ
    /// limit — the bug the fleet-host-2 canary caught: `meshharbor0-<7hex>` = 16.
    #[test]
    fn per_org_ifname_fits_ifnamsiz_on_every_platform() {
        let tenant = "6a712a572ceed780ac1ccbce";
        // Linux base "meshharbor0" (11): 15 - 12 = 3-hex suffix → 15 total.
        let linux = per_org_ifname("meshharbor0", tenant);
        assert_eq!(linux, "meshharbor0-6a7");
        assert!(linux.len() <= 15, "linux name too long: {linux}");
        // Windows base "meshharbor" (10): 15 - 11 = 4-hex suffix → 15 total.
        let win = per_org_ifname("meshharbor", tenant);
        assert_eq!(win, "meshharbor-6a71");
        assert!(win.len() <= 15, "windows name too long: {win}");
        // A short org key never overflows and keeps its full suffix.
        assert_eq!(per_org_ifname("meshharbor0", "abc"), "meshharbor0-abc");
        // Distinct tenants that share a 3-hex prefix would clash on NAME —
        // acceptable (the full-tenant GUID still differs), and real fleet
        // tenants (grox 69a1…, jovanov 6a71…) don't even share the first char.
        assert_ne!(
            per_org_ifname("meshharbor0", "69a1dbbad2000f26adc875ce"),
            per_org_ifname("meshharbor0", "6a712a572ceed780ac1ccbce")
        );
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::RuntimeFingerprint;

    fn base() -> RuntimeFingerprint {
        RuntimeFingerprint {
            wg_public_key: "pk".into(),
            netstack_port: None,
            advertised_routes: vec!["10.0.0.0/24".into()],
            exit_node: None,
            tenant_id: "t1".into(),
            server_url: "https://meshharbor.itachi.fans".into(),
            lan_ips: vec!["192.168.68.5".into()],
        }
    }

    /// R4 — the respawn/rebuild split: a lan_ips-only difference is
    /// same-shape (⇒ reattach + in-place plane rebuild, never a second
    /// runtime), while any process-immutable field difference is not
    /// (⇒ the old fresh-spawn path).
    #[test]
    fn lan_ips_change_is_same_shape_immutable_fields_are_not() {
        let a = base();
        let mut roamed = base();
        roamed.lan_ips = vec!["10.20.30.40".into()];
        assert!(a.same_shape(&roamed), "a roam must not respawn the runtime");
        assert!(a != roamed, "but it is still a fingerprint difference");

        for mutate in [
            |f: &mut RuntimeFingerprint| f.wg_public_key = "other".into(),
            |f: &mut RuntimeFingerprint| f.netstack_port = Some(1080),
            |f: &mut RuntimeFingerprint| f.advertised_routes = vec![],
            |f: &mut RuntimeFingerprint| f.exit_node = Some("exit".into()),
            |f: &mut RuntimeFingerprint| f.tenant_id = "t2".into(),
            |f: &mut RuntimeFingerprint| f.server_url = "https://other".into(),
        ] {
            let mut m = base();
            mutate(&mut m);
            assert!(
                !a.same_shape(&m),
                "an immutable-field change must force a respawn"
            );
        }
    }
}

#[cfg(all(test, feature = "overlay-netstack"))]
mod netstack_claim_tests {
    use super::{claim_socks_port, ns_handle_tx, release_netstack};

    /// Each org gets its OWN netstack handle channel.
    ///
    /// This was one shared channel, and that was the bug: a second org
    /// publishing its stack did not join twice, it REPLACED the first org's
    /// under a SOCKS front that kept answering on the same port, so a caller
    /// dialing for org A was routed by org B.
    #[test]
    fn every_org_reads_its_own_stack() {
        let a = ns_handle_tx("org-a");
        let b = ns_handle_tx("org-b");
        assert!(
            !a.same_channel(&b),
            "two orgs must never share a stack handle"
        );
        assert!(
            a.same_channel(&ns_handle_tx("org-a")),
            "an org's channel survives its reconnects — the front stays subscribed"
        );
    }

    /// A loopback SOCKS port is one TCP listener, so it still has exactly
    /// one owner even though the stacks are now separate.
    #[test]
    fn a_socks_port_still_has_exactly_one_owner() {
        // Serialized in ONE test on purpose: the claim map is process-global,
        // so separate #[test] fns would race each other. Ports are unique to
        // this test for the same reason.
        assert!(claim_socks_port("org-a", 41080), "first org in binds it");
        assert!(
            claim_socks_port("org-a", 41080),
            "re-claim by the owner is a no-op — every reconnect does this"
        );
        assert!(
            !claim_socks_port("org-b", 41080),
            "a second org on the same port is refused, not served"
        );

        // Different ports are the whole point: both orgs get a mesh.
        assert!(
            claim_socks_port("org-b", 41081),
            "its own port is always available"
        );

        // Releasing frees only the leaver's ports.
        release_netstack("org-b");
        assert!(
            !claim_socks_port("org-c", 41080),
            "org-a still holds its own"
        );
        assert!(claim_socks_port("org-c", 41081), "org-b's is free again");

        release_netstack("org-a");
        release_netstack("org-c");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// FR-47 — the last join the server refused
// ───────────────────────────────────────────────────────────────────────────

/// The most recent [`ServerMsg::OverlayJoinRefused`], for `mh status`.
///
/// A process-global rather than runtime state, and deliberately so: a refusal
/// means the overlay runtime never came up, so there is no runtime to hold it.
/// Same shape as the netcheck and netstate slots the status assembly already
/// reads for HOST-level facts.
static LAST_JOIN_REFUSAL: std::sync::Mutex<Option<localapi::JoinRefusalStatus>> =
    std::sync::Mutex::new(None);

/// Record a refusal. Last-writer-wins: the newest reason is the actionable one.
pub fn record_join_refusal(reason: signaling::OverlayJoinRefusal, detail: &str) {
    let status = localapi::JoinRefusalStatus {
        reason: serde_json::to_value(reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            // A tag that will not serialise is not worth losing the whole
            // report over — the detail string still carries the specifics.
            .unwrap_or_else(|| "unknown".to_string()),
        detail: detail.to_string(),
        at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        retryable: reason.is_retryable(),
    };
    if let Ok(mut slot) = LAST_JOIN_REFUSAL.lock() {
        *slot = Some(status);
    }
}

// The authenticated primary enrollment's identity is independent of the
// grant. Reject malformed local identities and a grant for any other relay.
fn bridge_source_is_local(
    bridge: &meshharbor_remote_control::signaling::RelayBridgeWire,
    local_agent_id: &str,
) -> bool {
    bson::oid::ObjectId::parse_str(local_agent_id)
        .is_ok_and(|local| local == bridge.source_agent_id)
}

/// The last refusal, if this daemon has seen one.
pub fn last_join_refusal() -> Option<localapi::JoinRefusalStatus> {
    LAST_JOIN_REFUSAL.lock().ok().and_then(|s| s.clone())
}

pub use crate::overlay_supervision::{
    effective_overlay_mode, effective_socks5_port, should_respawn_after_exit,
    should_respawn_after_exit_at,
};

#[cfg(all(test, feature = "overlay-netstack"))]
fn build_tun_factory_for_test(
    cfg: &AgentConfig,
    view_rx: watch::Receiver<OverlayView>,
    is_windows: bool,
    os_tun_permitted: bool,
    os_tun_up: TunFactory,
    now_fn: Arc<dyn Fn() -> std::time::Instant + Send + Sync>,
) -> Option<(TunFactory, Option<u16>)> {
    build_tun_factory_with_fallback(
        cfg,
        view_rx,
        is_windows,
        os_tun_permitted,
        Some(os_tun_up),
        now_fn,
    )
}

#[cfg(all(test, feature = "overlay-netstack"))]
mod overlay_fallback_tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    fn sample_cfg(tenant_id: &str) -> AgentConfig {
        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = tenant_id.to_string();
        cfg.overlay_enabled = true;
        cfg.netstack_socks_port = None;
        cfg.overlay_wg_secret_key = Some(WgKeypair::generate().secret_base64());
        cfg
    }

    #[tokio::test]
    async fn reactive_privilege_fallback_exits_and_rebuilds_runtime_as_netstack_withdrawing_routes_and_switching_dialers()
     {
        let mut cfg = sample_cfg("tenant-win-fallback-rebuild");
        cfg.overlay_advertised_routes = vec!["10.88.0.0/24".to_string()];
        cfg.overlay_exit_node = Some("exit-node-1".to_string());

        // Construct managed_forward_dialer and ssh_client::dialer_for BEFORE
        // any reactive fallback happens (as connect_once / DaemonSsh do).
        let fwd_dialer_before = managed_forward_dialer(&cfg);
        #[cfg(feature = "ssh-server")]
        let ssh_dialer = crate::ssh_client::dialer_for(&cfg);

        let (view_tx, view_rx) = watch::channel(OverlayView::default());
        let os_tun_calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = os_tun_calls.clone();
        let make_os_tun = move || -> TunFactory {
            let c = calls_clone.clone();
            Box::new(move |_, _, _| {
                c.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Access is denied. (os error 5)",
                ))
            })
        };

        let t0 = Instant::now();
        // Attempt 1 (is_windows = true, os_tun_permitted = true): starts as OS TUN (initial_port == None).
        let (factory1, initial_port1) = build_tun_factory_for_test(
            &cfg,
            view_rx.clone(),
            true,
            true,
            make_os_tun(),
            Arc::new(Instant::now),
        )
        .expect("factory1 built");
        assert_eq!(initial_port1, None);

        // First netmap arrives: Wintun fails due to privilege. Must latch fallback
        // and return Err so the first runtime exits and is immediately rebuilt as
        // a true netstack runtime (with netstack_socks = Some(port)).
        let res1 = factory1(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(255, 192, 0, 0),
            OVERLAY_MTU,
        );
        assert!(
            res1.is_err(),
            "reactive privilege failure must return Err so runtime rebuilds with netstack_socks = Some(port)"
        );
        assert_eq!(os_tun_calls.load(Ordering::SeqCst), 1);
        assert!(crate::overlay_supervision::has_latched_netstack_fallback(
            &cfg.tenant_id
        ));
        assert!(
            crate::overlay_supervision::should_poll_start_at(&cfg, Some(true), t0),
            "reactive fallback restart must not incur failure backoff"
        );

        // Attempt 2 (immediate rebuild via Branch 2): must return Some(port) up front!
        let (factory2, initial_port2) = build_tun_factory_for_test(
            &cfg,
            view_rx.clone(),
            true,
            true,
            make_os_tun(),
            Arc::new(Instant::now),
        )
        .expect("factory2 built");
        let socks_port =
            initial_port2.expect("rebuild after latched fallback must provide Some(port)");
        assert!(socks_port > 0);
        assert_eq!(effective_overlay_mode(&cfg.tenant_id, "tun"), "netstack");
        assert_eq!(effective_socks5_port(&cfg.tenant_id), Some(socks_port));

        // Spawn OverlayRuntime with the rebuilt factory2 + Some(socks_port) and verify:
        // 1) advertised_routes in rc:overlay.join are withdrawn (empty),
        // 2) OverlayView reports overlay_socks5_port = Some(socks_port), route_offer_withheld = Some,
        //    and exit_node.socks5_port = Some(socks_port) (so dns_steer_allowed is false).
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<ClientMsg>(16);
        let (evt_tx, evt_rx) = mpsc::channel::<OverlayEvent>(16);
        let kp =
            WgKeypair::from_secret_base64(cfg.overlay_wg_secret_key.as_deref().unwrap()).unwrap();
        let rt = OverlayRuntime::new_relay(kp, outbound_tx, factory2, OVERLAY_MTU)
            .with_advertised_routes(cfg.effective_overlay_advertised_routes())
            .with_exit_node(cfg.overlay_exit_node.clone(), Vec::new())
            .with_netstack_socks(Some(socks_port))
            .with_peer_view(view_tx);
        let rt_handle = tokio::spawn(rt.run(evt_rx, Vec::new()));

        let join_msg = tokio::time::timeout(Duration::from_secs(5), outbound_rx.recv())
            .await
            .expect("join timeout")
            .expect("join msg");
        match join_msg {
            ClientMsg::OverlayJoin {
                advertised_routes, ..
            } => {
                assert!(
                    advertised_routes.is_empty(),
                    "rebuilt netstack runtime must withdraw advertised routes, got: {advertised_routes:?}"
                );
            }
            other => panic!("expected OverlayJoin, got {other:?}"),
        }

        let net_info: meshharbor_remote_control::signaling::OverlayNetworkInfo =
            serde_json::from_value(serde_json::json!({
                "cidr": "100.64.0.0/10",
                "mtu": OVERLAY_MTU,
                "magic_domain": "mesh.local"
            }))
            .unwrap();
        evt_tx
            .send(OverlayEvent::Netmap {
                self_ip: "100.64.0.2".to_string(),
                network: net_info,
                peers: Vec::new(),
                org_relay_discovery: false,
                path_trial_v1: false,
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let v = view_rx.borrow().clone();
                if v.self_ip.as_deref() == Some("100.64.0.2") {
                    assert_eq!(v.overlay_socks5_port, Some(socks_port));
                    assert!(
                        v.route_offer_withheld.is_some(),
                        "route_offer_withheld must be populated on netstack fallback"
                    );
                    let exit = v.exit_node.expect("exit_node status present");
                    assert_eq!(
                        exit.socks5_port,
                        Some(socks_port),
                        "exit_node status must carry socks5_port so dns_steer_allowed is false"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("OverlayView published");

        assert_eq!(
            os_tun_calls.load(Ordering::SeqCst),
            1,
            "rebuilt runtime must not call os_tun again"
        );

        // Verify both pre-created dialers (managed_forward_dialer and ssh_client::dialer_for)
        // now route through the userspace netstack (100.64.0.2) rather than OS sockets:
        let fwd_dialer = fwd_dialer_before
            .expect("managed_forward_dialer must be available for overlay-enabled org");
        // Drop the runtime so the netstack handle channel can be cleared, then verify
        // both dialers hit the netstack path ("netstack not up yet (mesh not joined)")
        // when the netstack handle is cleared while fallback remains latched.
        drop(evt_tx);
        let _ = rt_handle.await;
        let _ = ns_handle_tx(&cfg.tenant_id).send(None);

        let fwd_err = fwd_dialer
            .tcp(SocketAddr::from(([100, 64, 0, 99], 22)))
            .await
            .err()
            .expect("netstack dial with cleared handle must fail fast via netstack");
        assert!(
            fwd_err.to_string().contains("netstack"),
            "managed_forward_dialer must use netstack after fallback, got: {fwd_err}"
        );

        #[cfg(feature = "ssh-server")]
        {
            let ssh_err = ssh_dialer
                .dial("100.64.0.99", 22)
                .await
                .err()
                .expect("ssh dialer with cleared handle must fail fast via netstack");
            assert!(
                ssh_err.contains("netstack"),
                "ssh_client::dialer_for must use netstack after fallback, got: {ssh_err}"
            );
        }

        release_org(&cfg.tenant_id);
    }

    #[tokio::test]
    async fn unprivileged_windows_proactively_selects_netstack_without_calling_wintun() {
        let cfg = sample_cfg("tenant-win-fallback-proactive");
        let (_view_tx, view_rx) = watch::channel(OverlayView::default());
        let os_tun_calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = os_tun_calls.clone();
        let os_tun: TunFactory = Box::new(move |_, _, _| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other(
                "WintunCreateAdapter should never be called",
            ))
        });

        let (factory, initial_port) = build_tun_factory_for_test(
            &cfg,
            view_rx,
            true,
            false, // non-elevated Windows process (Medium IL)
            os_tun,
            Arc::new(Instant::now),
        )
        .expect("factory built");

        let port =
            initial_port.expect("proactive fallback must allocate loopback SOCKS5 port up front");
        assert!(port > 0);
        let tun = factory(
            Ipv4Addr::new(100, 64, 0, 3),
            Ipv4Addr::new(255, 192, 0, 0),
            OVERLAY_MTU,
        )
        .expect("netstack starts cleanly");
        assert_eq!(tun.os_name(), None);
        assert_eq!(
            os_tun_calls.load(Ordering::SeqCst),
            0,
            "proactive non-elevated path must not invoke WintunCreateAdapter at all"
        );
        assert_eq!(effective_overlay_mode(&cfg.tenant_id, "tun"), "netstack");
        assert_eq!(effective_socks5_port(&cfg.tenant_id), Some(port));

        release_org(&cfg.tenant_id);
    }

    #[tokio::test]
    async fn non_windows_tun_permission_error_does_not_fall_back_to_netstack_in_factory() {
        let cfg = sample_cfg("tenant-non-win-no-fallback");
        let (_view_tx, view_rx) = watch::channel(OverlayView::default());
        let os_tun: TunFactory = Box::new(|_, _, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Operation not permitted (utun/tun)",
            ))
        });

        let (factory, initial_port) = build_tun_factory_for_test(
            &cfg,
            view_rx,
            false, // non-Windows (Linux / macOS)
            true,
            os_tun,
            Arc::new(Instant::now),
        )
        .expect("factory built");
        assert_eq!(initial_port, None);

        let res = factory(
            Ipv4Addr::new(100, 64, 0, 5),
            Ipv4Addr::new(255, 192, 0, 0),
            OVERLAY_MTU,
        );
        assert!(
            res.is_err(),
            "non-Windows permission error must return Err and not fall back to netstack"
        );
        assert!(
            !crate::overlay_supervision::has_latched_netstack_fallback(&cfg.tenant_id),
            "non-Windows must not latch netstack fallback"
        );
        assert_eq!(effective_socks5_port(&cfg.tenant_id), None);
        assert!(effective_overlay_mode(&cfg.tenant_id, "tun").starts_with("error ("));

        release_org(&cfg.tenant_id);
    }

    #[tokio::test]
    async fn non_privilege_overlay_failure_uses_capped_backoff_and_never_halts_permanently() {
        let cfg = sample_cfg("tenant-overlay-backoff");
        let t0 = Instant::now();
        let clock = Arc::new(std::sync::Mutex::new(t0));
        let clock_for_factory = clock.clone();

        let make_failing_factory = || {
            let (_view_tx, view_rx) = watch::channel(OverlayView::default());
            let clock_clone = clock_for_factory.clone();
            let os_tun: TunFactory =
                Box::new(|_, _, _| Err(std::io::Error::other("fatal driver hardware fault")));
            build_tun_factory_for_test(
                &cfg,
                view_rx,
                true,
                true,
                os_tun,
                Arc::new(move || *clock_clone.lock().unwrap()),
            )
            .expect("factory built")
            .0
        };

        let mut cur = t0;
        for (idx, &delay_secs) in [30u64, 60, 120, 300, 600, 600].iter().enumerate() {
            *clock.lock().unwrap() = cur;
            let f = make_failing_factory();
            assert!(
                f(
                    Ipv4Addr::new(100, 64, 0, 4),
                    Ipv4Addr::new(255, 192, 0, 0),
                    OVERLAY_MTU
                )
                .is_err()
            );
            assert!(
                !should_respawn_after_exit_at(&cfg, cur + Duration::from_secs(25)),
                "25s keepalive tick must be suppressed during {delay_secs}s backoff (attempt {})",
                idx + 1
            );
            assert!(
                !should_respawn_after_exit_at(&cfg, cur + Duration::from_secs(delay_secs - 1)),
                "must stay in backoff just before {delay_secs}s"
            );
            assert!(
                should_respawn_after_exit_at(&cfg, cur + Duration::from_secs(delay_secs)),
                "must allow retry after {delay_secs}s backoff (attempt {})",
                idx + 1
            );
            let mode = effective_overlay_mode(&cfg.tenant_id, "tun");
            assert!(
                mode.starts_with("error")
                    && mode.contains(&format!("attempt {}", idx + 1))
                    && mode.contains("fatal driver hardware fault")
                    && !mode.contains("halted"),
                "status mode must report attempt count and reason without halting, got: {mode}"
            );
            cur += Duration::from_secs(delay_secs);
        }

        release_org(&cfg.tenant_id);
    }

    #[tokio::test]
    async fn generic_wintun_create_adapter_failure_retries_os_tun_before_latching_on_third_consecutive_failure()
     {
        let cfg = sample_cfg("tenant-win-generic-wintun-3strikes");
        let (_view_tx, view_rx) = watch::channel(OverlayView::default());
        let os_tun_calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = os_tun_calls.clone();
        let make_wintun_failing = move || -> TunFactory {
            let c = calls_clone.clone();
            Box::new(move |_, _, _| {
                c.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::other(
                    "Failed to create adapter: WintunCreateAdapter failed: \"No inner logs\"",
                ))
            })
        };

        let mut now = Instant::now();
        let clock = Arc::new(std::sync::Mutex::new(now));

        // Attempt 1: generic WintunCreateAdapter failure must NOT latch fallback; must enter 30s backoff.
        let c1 = clock.clone();
        let (f1, p1) = build_tun_factory_for_test(
            &cfg,
            view_rx.clone(),
            true,
            true,
            make_wintun_failing(),
            Arc::new(move || *c1.lock().unwrap()),
        )
        .expect("f1 built");
        assert_eq!(p1, None);
        assert!(
            f1(
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::new(255, 192, 0, 0),
                OVERLAY_MTU
            )
            .is_err()
        );
        assert_eq!(os_tun_calls.load(Ordering::SeqCst), 1);
        assert!(
            !crate::overlay_supervision::has_latched_netstack_fallback(&cfg.tenant_id),
            "1st generic WintunCreateAdapter failure must NOT latch netstack fallback"
        );
        assert!(
            effective_overlay_mode(&cfg.tenant_id, "tun").contains("attempt 1"),
            "1st generic failure must report attempt 1 backoff"
        );
        assert!(!should_respawn_after_exit_at(
            &cfg,
            now + Duration::from_secs(29)
        ));
        now += Duration::from_secs(30);
        *clock.lock().unwrap() = now;
        assert!(should_respawn_after_exit_at(&cfg, now));

        // Attempt 2: still builds OS TUN factory (initial_port == None) and tries Wintun again;
        // 2nd consecutive generic WintunCreateAdapter failure still does NOT latch fallback (60s backoff).
        let c2 = clock.clone();
        let (f2, p2) = build_tun_factory_for_test(
            &cfg,
            view_rx.clone(),
            true,
            true,
            make_wintun_failing(),
            Arc::new(move || *c2.lock().unwrap()),
        )
        .expect("f2 built");
        assert_eq!(
            p2, None,
            "2nd attempt after 1st generic failure must still try OS TUN"
        );
        assert!(
            f2(
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::new(255, 192, 0, 0),
                OVERLAY_MTU
            )
            .is_err()
        );
        assert_eq!(os_tun_calls.load(Ordering::SeqCst), 2);
        assert!(
            !crate::overlay_supervision::has_latched_netstack_fallback(&cfg.tenant_id),
            "2nd generic WintunCreateAdapter failure must NOT latch netstack fallback"
        );
        assert!(
            effective_overlay_mode(&cfg.tenant_id, "tun").contains("attempt 2"),
            "2nd generic failure must report attempt 2 backoff"
        );
        now += Duration::from_secs(60);
        *clock.lock().unwrap() = now;
        assert!(should_respawn_after_exit_at(&cfg, now));

        // Attempt 3: 3rd consecutive generic WintunCreateAdapter failure latches netstack fallback!
        let c3 = clock.clone();
        let (f3, p3) = build_tun_factory_for_test(
            &cfg,
            view_rx.clone(),
            true,
            true,
            make_wintun_failing(),
            Arc::new(move || *c3.lock().unwrap()),
        )
        .expect("f3 built");
        assert_eq!(p3, None);
        assert!(
            f3(
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::new(255, 192, 0, 0),
                OVERLAY_MTU
            )
            .is_err()
        );
        assert_eq!(os_tun_calls.load(Ordering::SeqCst), 3);
        assert!(
            crate::overlay_supervision::has_latched_netstack_fallback(&cfg.tenant_id),
            "3rd consecutive generic WintunCreateAdapter failure on Windows must latch netstack fallback"
        );
        assert!(
            crate::overlay_supervision::should_poll_start_at(&cfg, Some(true), now),
            "latched fallback after 3 strikes must trigger immediate rebuild without waiting for backoff"
        );

        // Rebuild after 3rd failure now selects netstack up front (`Some(port)`) without calling os_tun a 4th time.
        let c4 = clock.clone();
        let (f4, p4) = build_tun_factory_for_test(
            &cfg,
            view_rx,
            true,
            true,
            make_wintun_failing(),
            Arc::new(move || *c4.lock().unwrap()),
        )
        .expect("f4 built");
        let port = p4.expect("latched fallback after 3rd strike must allocate SOCKS5 port");
        assert!(port > 0);
        let tun = f4(
            Ipv4Addr::new(100, 64, 0, 10),
            Ipv4Addr::new(255, 192, 0, 0),
            OVERLAY_MTU,
        )
        .expect("netstack starts");
        assert_eq!(tun.os_name(), None);
        assert_eq!(os_tun_calls.load(Ordering::SeqCst), 3);
        assert_eq!(effective_overlay_mode(&cfg.tenant_id, "tun"), "netstack");

        release_org(&cfg.tenant_id);
    }
}

#[cfg(test)]
mod org_relay_discovery_dispatch_tests {
    use super::*;
    #[tokio::test]
    async fn scoped_revoke_routes_only_to_its_recipient_role() {
        use meshharbor_remote_control::signaling::RelayRevokeScopeWire;
        let (tx, mut rx) = overlay_event_channel(4);
        let scope = RelayRevokeScopeWire {
            relay_node_id: bson::oid::ObjectId::new(),
            generation: 7,
            peer_node_id: None,
        };
        assert!(
            intercept(
                &tx,
                ServerMsg::OverlayRelayRevoke {
                    vni: 1,
                    scope: scope.clone(),
                },
                true,
                "",
                ""
            )
            .is_none()
        );
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "serving revoke must not reach member runtime"
        );

        let member_scope = RelayRevokeScopeWire {
            peer_node_id: Some(bson::oid::ObjectId::new()),
            ..scope
        };
        assert!(
            intercept(
                &tx,
                ServerMsg::OverlayRelayRevoke {
                    vni: 1,
                    scope: member_scope.clone(),
                },
                true,
                "",
                ""
            )
            .is_none()
        );
        assert!(matches!(rx.recv().await, Some(OverlayEvent::OrgRelayRevoke {
            vni: 1, scope: got,
        }) if got == member_scope));
    }

    #[test]
    fn bridge_dispatch_checks_primary_enrollment_and_local_source() {
        let local = bson::oid::ObjectId::new();
        let make = || ServerMsg::OverlayRelayBridgeServe {
            bridge: meshharbor_remote_control::signaling::RelayBridgeWire {
                trial_id: bson::oid::ObjectId::new(),
                generation: 1,
                source_agent_id: local,
                target_agent_id: bson::oid::ObjectId::new(),
                local_vni: 1,
                local_generation: 1,
                local_bind_secret: String::new(),
                remote_endpoint: String::new(),
                remote_vni: 2,
                remote_generation: 1,
                remote_bind_secret: String::new(),
                max_lifetime_secs: 1,
            },
        };
        for (primary, identity, expected) in [
            (true, local.to_hex(), true),
            (false, local.to_hex(), false),
            (true, bson::oid::ObjectId::new().to_hex(), false),
            (true, String::new(), false),
            (true, "not-an-object-id".into(), false),
        ] {
            let installed = std::cell::Cell::new(false);
            assert!(matches!(
                classify_intercept(make(), primary, &identity, |_| {
                    installed.set(true);
                }),
                InterceptOutcome::Consumed
            ));
            assert_eq!(installed.get(), expected);
        }
    }
    #[tokio::test]
    async fn org_relay_discovery_old_netmap_capability_is_forwarded_as_false() {
        let (tx, mut rx) = overlay_event_channel(2);
        let msg: ServerMsg = serde_json::from_value(serde_json::json!({
            "t":"rc:overlay.netmap", "self_ip":"100.64.0.1",
            "network":{"cidr":"100.64.0.0/10","mtu":1280}, "peers":[]
        }))
        .unwrap();
        assert!(intercept(&tx, msg, true, "", "").is_none());
        assert!(matches!(
            rx.recv().await,
            Some(OverlayEvent::Netmap {
                org_relay_discovery: false,
                ..
            })
        ));
    }
    #[tokio::test]
    async fn org_relay_discovery_signaling_candidates_reach_runtime_only_on_primary_org() {
        let (tx, mut rx) = overlay_event_channel(4);
        let peer_node_id = bson::oid::ObjectId::new();
        let msg = || ServerMsg::OverlayOrgRelayCandidates {
            peer_node_id,
            request_id: 17,
            candidates: vec![],
            ttl_secs: 0,
            next_cursor: None,
            scan: None,
        };
        assert!(intercept(&tx, msg(), false, "", "").is_none());
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err());
        assert!(intercept(&tx, msg(), true, "", "").is_none());
        assert!(
            matches!(rx.recv().await, Some(OverlayEvent::OrgRelayCandidates {
            peer_node_id: id, request_id: 17, ttl_secs: 0, candidates, ..
        }) if id == peer_node_id && candidates.is_empty())
        );
        assert!(rx.try_recv().is_err()); // no serving/session/TURN action
    }

    #[tokio::test]
    async fn join_refused_and_netmap_deliver_without_deadlocking_full_bidirectional_queues() {
        // Reproduce the exact bidirectional burst:
        // - runtime -> signaling outbound channel (`capacity = 1`) is FULL (`outbound_tx.send` parked),
        // - signaling -> runtime droppable queue (`droppable_cap = 2`) is overflowed while
        //   `OverlayJoinRefused` and `OverlayNetmap` arrive on the signaling task BEFORE it
        //   drains `outbound_rx`.
        let (evt_tx, mut evt_rx) = overlay_event_channel(2);
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<u32>(1);
        outbound_tx.try_send(1).unwrap();

        let runtime_task = tokio::spawn(async move {
            // Runtime is blocked waiting for signaling to drain `outbound_rx` before reading `evt_rx`.
            outbound_tx.send(2).await.unwrap();
            let mut got = Vec::new();
            while let Some(e) = evt_rx.recv().await {
                got.push(e);
            }
            got
        });
        tokio::task::yield_now().await;

        // Signaling processes a burst synchronously (never awaiting runtime capacity):
        for i in 0..8u64 {
            let delta = ServerMsg::OverlayNetmapDelta {
                epoch: i,
                auth_revision: 1,
                upserts: vec![],
                removes: vec![],
            };
            assert!(intercept(&evt_tx, delta, true, "", "").is_none());
        }
        let transient = ServerMsg::OverlayJoinRefused {
            reason: signaling::OverlayJoinRefusal::StoreUnavailable,
            detail: "authority changed before join netmap; retry".into(),
        };
        assert!(intercept(&evt_tx, transient, true, "", "").is_none());
        let netmap: ServerMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:overlay.netmap",
            "self_ip": "100.64.0.1",
            "network": { "cidr": "100.64.0.0/10", "mtu": 1280, "auth_revision": 2 },
            "peers": []
        }))
        .unwrap();
        assert!(intercept(&evt_tx, netmap, true, "", "").is_none());
        let terminal = ServerMsg::OverlayJoinRefused {
            reason: signaling::OverlayJoinRefusal::AddressSpaceExhausted,
            detail: "no free IPv4 in pool".into(),
        };
        assert!(intercept(&evt_tx, terminal, true, "", "").is_none());

        // Signaling remains completely unblocked and immediately drains `outbound_rx`!
        assert_eq!(outbound_rx.recv().await, Some(1));
        assert_eq!(outbound_rx.recv().await, Some(2));
        drop(evt_tx);

        let delivered = tokio::time::timeout(std::time::Duration::from_secs(2), runtime_task)
            .await
            .expect("must not deadlock when both queues fill")
            .unwrap();

        // Reliable events (`JoinRefused(true)` -> `Netmap` -> `JoinRefused(false)`) arrive in exact FIFO order!
        let reliable: Vec<&str> = delivered
            .iter()
            .filter_map(|e| match e {
                OverlayEvent::JoinRefused { retryable: true } => Some("refused_retry"),
                OverlayEvent::Netmap { .. } => Some("netmap"),
                OverlayEvent::JoinRefused { retryable: false } => Some("refused_terminal"),
                _ => None,
            })
            .collect();
        assert_eq!(reliable, vec!["refused_retry", "netmap", "refused_terminal"]);

        // Also verify `RebuildDirect` and original detach deadline survive 65+ detach/reattach pairs
        // while the pump is genuinely backlogged in `st.buf`!
        let (evt_tx2, mut evt_rx2) = overlay_event_channel(2);
        // Occupy `mpsc(1)` + the pump's in-flight `send().await` so all subsequent
        // reliable events coalesce directly inside `st.buf`.
        for i in 0..2 {
            evt_tx2
                .try_send(OverlayEvent::SelfName {
                    node_id: bson::oid::ObjectId::new(),
                    revision: i.to_string(),
                    name: format!("stall-{i}"),
                })
                .unwrap();
        }
        tokio::task::yield_now().await;
        evt_tx2.send_reliable(OverlayEvent::RebuildDirect).unwrap();
        evt_tx2.send_reliable(OverlayEvent::ControlDetached).unwrap();
        let t_after_first_detach = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        for _ in 0..65 {
            evt_tx2.send_reliable(OverlayEvent::ControlDetached).unwrap();
            let (out_tx, _out_rx) = mpsc::channel(1);
            evt_tx2
                .send_reliable(OverlayEvent::Reattach { outbound: out_tx })
                .unwrap();
        }
        drop(evt_tx2);
        let mut saw_rebuild = false;
        let mut detached_timestamps = Vec::new();
        let mut saw_reattach = false;
        while let Some(e) = evt_rx2.recv().await {
            match e {
                OverlayEvent::RebuildDirect => saw_rebuild = true,
                OverlayEvent::ControlDetachedAt(at) => detached_timestamps.push(at),
                OverlayEvent::Reattach { .. } => saw_reattach = true,
                _ => {}
            }
        }
        assert!(saw_rebuild, "RebuildDirect must never be evicted across detach/reattach bursts");
        assert_eq!(
            detached_timestamps.len(),
            1,
            "coalesced detach/reattach burst in st.buf must emit a single ControlDetachedAt"
        );
        assert!(
            detached_timestamps[0] <= t_after_first_detach,
            "coalesced ControlDetachedAt must preserve the original detach deadline"
        );
        assert!(saw_reattach, "latest Reattach must be delivered");
    }

    #[tokio::test]
    async fn overflow_preserves_live_reattach_and_detach_deadlines_across_stale_and_random_netmaps() {
        let make_netmap = |rev: u64, tag: &str| -> ServerMsg {
            serde_json::from_value(serde_json::json!({
                "t": "rc:overlay.netmap",
                "self_ip": "100.64.0.1",
                "network": {
                    "cidr": "100.64.0.0/10",
                    "mtu": 1280,
                    "auth_revision": rev,
                    "self_name": tag
                },
                "peers": []
            }))
            .unwrap()
        };

        // 1. Reproduce Round 5 #1: `Detached, Reattach(new_sender), Netmap × 70` while stalled.
        //    `Reattach(new_sender)` must NEVER be discarded by netmap overflow!
        let (tx1, mut rx1) = overlay_event_channel(2);
        for i in 0..2 {
            tx1.try_send(OverlayEvent::SelfName {
                node_id: bson::oid::ObjectId::new(),
                revision: i.to_string(),
                name: format!("stall-{i}"),
            })
            .unwrap();
        }
        tokio::task::yield_now().await;
        tx1.send_reliable(OverlayEvent::ControlDetached).unwrap();
        let (live_out_tx, mut live_out_rx) = mpsc::channel(4);
        tx1.send_reliable(OverlayEvent::Reattach {
            outbound: live_out_tx,
        })
        .unwrap();
        for rev in 1..=70u64 {
            assert!(intercept(&tx1, make_netmap(rev, &format!("n-{rev}")), true, "", "").is_none());
        }
        assert!(
            tx1.inner.state.lock().unwrap().reliable <= MAX_RELIABLE_EVENTS,
            "reliable count must stay bounded <= MAX_RELIABLE_EVENTS"
        );
        drop(tx1);
        let mut reattach_count = 0usize;
        let mut max_delivered_rev = 0u64;
        while let Some(evt) = rx1.recv().await {
            match evt {
                OverlayEvent::Reattach { outbound } => {
                    reattach_count += 1;
                    outbound
                        .send(signaling::ClientMsg::OverlayEndpoints { candidates: vec![] })
                        .await
                        .expect("live sender must match live_out_rx");
                }
                OverlayEvent::Netmap { network, .. } => {
                    max_delivered_rev = max_delivered_rev.max(network.auth_revision);
                }
                _ => {}
            }
        }
        assert_eq!(reattach_count, 1, "sole live Reattach must survive netmap overflow");
        assert!(live_out_rx.recv().await.is_some(), "delivered Reattach must carry live_out_tx");
        assert_eq!(max_delivered_rev, 70);

        // 2. Reproduce Round 5 #2: `D(t0), Reattach0, N(rev100), D(t1), Reattach1, N(rev99) × 70`.
        //    Both `D(t0)` (if rev100 is rejected) and `D(t1)` (when rev100 is accepted) AND `Reattach1`
        //    must survive!
        let (tx2, mut rx2) = overlay_event_channel(2);
        for i in 0..2 {
            tx2.try_send(OverlayEvent::SelfName {
                node_id: bson::oid::ObjectId::new(),
                revision: i.to_string(),
                name: format!("stall2-{i}"),
            })
            .unwrap();
        }
        tokio::task::yield_now().await;
        let base = std::time::Instant::now() - std::time::Duration::from_secs(10);
        let t0 = base;
        let t1 = base + std::time::Duration::from_millis(50);
        tx2.send_reliable(OverlayEvent::ControlDetachedAt(t0)).unwrap();
        let (dead_tx, _dead_rx) = mpsc::channel(1);
        tx2.send_reliable(OverlayEvent::Reattach { outbound: dead_tx })
            .unwrap();
        assert!(intercept(&tx2, make_netmap(100, "rev100"), true, "", "").is_none());
        tx2.send_reliable(OverlayEvent::ControlDetachedAt(t1)).unwrap();
        let (live2_tx, mut live2_rx) = mpsc::channel(4);
        tx2.send_reliable(OverlayEvent::Reattach { outbound: live2_tx })
            .unwrap();
        for _ in 0..70 {
            assert!(intercept(&tx2, make_netmap(99, "stale99"), true, "", "").is_none());
        }
        assert!(tx2.inner.state.lock().unwrap().reliable <= MAX_RELIABLE_EVENTS);
        drop(tx2);

        let mut events2 = Vec::new();
        while let Some(e) = rx2.recv().await {
            events2.push(e);
        }

        let sim = |initial_rev: u64, evts: &[OverlayEvent]| -> (u64, Option<std::time::Instant>, usize) {
            let mut epoch = 0u64;
            let mut rev = initial_rev;
            let mut detached: Option<std::time::Instant> = None;
            let mut reattachs = 0usize;
            for e in evts {
                match e {
                    OverlayEvent::ControlDetachedAt(at) => {
                        detached = Some(detached.map_or(*at, |p| p.min(*at)));
                    }
                    OverlayEvent::Reattach { .. } => {
                        reattachs += 1;
                    }
                    OverlayEvent::Netmap { network, .. } => {
                        if tunnel_core::overlay::runtime::accept_netmap_version(
                            &mut epoch,
                            &mut rev,
                            0,
                            network.auth_revision,
                        ) {
                            epoch = 0;
                            detached = None;
                        }
                    }
                    _ => {}
                }
            }
            (rev, detached, reattachs)
        };
        // When `rev100` is accepted (`initial_rev = 1`), `D(t1)` MUST survive after `rev100`!
        let (r_acc, d_acc, re_acc) = sim(1, &events2);
        assert_eq!(r_acc, 100);
        assert_eq!(d_acc, Some(t1), "post-rev100 detach deadline t1 must survive stale rev99 flood");
        assert_eq!(re_acc, 1);
        // When `rev100` is also stale (`initial_rev = 105`), `D(t0)` MUST survive!
        let (r_rej, d_rej, re_rej) = sim(105, &events2);
        assert_eq!(r_rej, 105);
        assert_eq!(d_rej, Some(t0), "pre-rev100 detach deadline t0 must survive if rev100 is rejected");
        assert_eq!(re_rej, 1);
        // Verify the delivered Reattach is `live2_tx`, not `dead_tx`!
        for e in &events2 {
            if let OverlayEvent::Reattach { outbound } = e {
                outbound
                    .send(signaling::ClientMsg::OverlayEndpoints { candidates: vec![] })
                    .await
                    .unwrap();
            }
        }
        assert!(live2_rx.recv().await.is_some());

        // 2b. Reproduce Round 6 P1 #1: initial rev=99 with installed peer A, then
        //     `D(t0), Reattach(live), N100(empty), Delta101(upsert B), N100(empty) × 70`.
        //     `N100(empty)` MUST survive before `Delta101(upsert B)` so peer A is removed,
        //     peer B is installed, `rev == 101`, and `control_detached_at` is cleared (`None`)!
        let peer_a = bson::oid::ObjectId::new();
        let peer_b = bson::oid::ObjectId::new();
        let make_peer = |id: bson::oid::ObjectId| -> signaling::NetmapPeer {
            serde_json::from_value(serde_json::json!({
                "node_id": id.to_hex(),
                "name": format!("peer-{id}"),
                "wg_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "overlay_ip": "100.64.0.2",
                "reachable": true
            }))
            .unwrap()
        };
        let (tx3, mut rx3) = overlay_event_channel(64);
        for i in 0..2 {
            tx3.try_send(OverlayEvent::SelfName {
                node_id: bson::oid::ObjectId::new(),
                revision: i.to_string(),
                name: format!("stall3-{i}"),
            })
            .unwrap();
        }
        tokio::task::yield_now().await;
        tx3.send_reliable(OverlayEvent::ControlDetachedAt(t0)).unwrap();
        let (live3_tx, _live3_rx) = mpsc::channel(4);
        tx3.send_reliable(OverlayEvent::Reattach { outbound: live3_tx })
            .unwrap();
        assert!(intercept(&tx3, make_netmap(100, "n100-first"), true, "", "").is_none());
        let delta101 = ServerMsg::OverlayNetmapDelta {
            epoch: 1,
            auth_revision: 101,
            upserts: vec![make_peer(peer_b)],
            removes: vec![],
        };
        assert!(intercept(&tx3, delta101, true, "", "").is_none());
        for _ in 0..70 {
            assert!(intercept(&tx3, make_netmap(100, "n100-stale"), true, "", "").is_none());
        }
        assert!(tx3.inner.state.lock().unwrap().reliable <= MAX_RELIABLE_EVENTS);
        drop(tx3);

        let mut cur_ep = 0u64;
        let mut cur_rev = 99u64;
        let mut cur_det: Option<std::time::Instant> = None;
        let mut cur_peers: std::collections::BTreeSet<bson::oid::ObjectId> =
            [peer_a].into_iter().collect();
        let mut peer_vers: std::collections::HashMap<bson::oid::ObjectId, (u64, u64)> =
            [(peer_a, (99, 0))].into_iter().collect();
        while let Some(e) = rx3.recv().await {
            match e {
                OverlayEvent::ControlDetachedAt(at) => {
                    cur_det = Some(cur_det.map_or(at, |p| p.min(at)));
                }
                OverlayEvent::Netmap { network, peers, .. } => {
                    if tunnel_core::overlay::runtime::accept_netmap_version(
                        &mut cur_ep,
                        &mut cur_rev,
                        0,
                        network.auth_revision,
                    ) {
                        cur_ep = 0;
                        cur_det = None;
                        cur_peers = peers.iter().map(|p| p.node_id).collect();
                        peer_vers = peers
                            .iter()
                            .map(|p| (p.node_id, (cur_rev, 0)))
                            .collect();
                    }
                }
                OverlayEvent::NetmapDelta {
                    epoch,
                    auth_revision,
                    mut upserts,
                    mut removes,
                } => {
                    if tunnel_core::overlay::runtime::filter_netmap_delta_by_peer(
                        &mut cur_ep,
                        &mut cur_rev,
                        &mut peer_vers,
                        epoch,
                        auth_revision,
                        &mut upserts,
                        &mut removes,
                    ) {
                        for r in removes {
                            cur_peers.remove(&r);
                        }
                        for u in upserts {
                            cur_peers.insert(u.node_id);
                        }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(cur_rev, 101);
        assert_eq!(cur_det, None, "accepted N100 before Delta101 must clear detach deadline");
        assert_eq!(
            cur_peers,
            [peer_b].into_iter().collect(),
            "revoked peer A must be evicted by N100 and peer B installed by Delta101"
        );

        // 3. Deterministic 250-sequence equivalence oracle over 120-step mixed workloads
        //    INCLUDING `NetmapDelta` peer upserts/removals across BOTH pre-first-netmap
        //    and main-loop runtime states!
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for case_idx in 0..250usize {
            let (tx, mut rx) = overlay_event_channel(128);
            for i in 0..2 {
                tx.try_send(OverlayEvent::SelfName {
                    node_id: bson::oid::ObjectId::new(),
                    revision: i.to_string(),
                    name: format!("s-{i}"),
                })
                .unwrap();
            }
            tokio::task::yield_now().await;

            #[derive(Clone)]
            enum SpecEvt {
                Rebuild,
                Detach(std::time::Instant),
                Reattach(usize),
                Refused(std::time::Instant),
                Netmap(u64, Vec<bson::oid::ObjectId>),
                Delta {
                    epoch: u64,
                    rev: u64,
                    upsert: Option<bson::oid::ObjectId>,
                    remove: Option<bson::oid::ObjectId>,
                },
            }
            let pool = [
                peer_a,
                peer_b,
                bson::oid::ObjectId::new(),
                bson::oid::ObjectId::new(),
            ];
            let mut ref_log = Vec::new();
            let mut reattach_rxs = Vec::new();
            for step in 0..120usize {
                let ts = base + std::time::Duration::from_millis((step as u64 + 1) * 10);
                match next_u64() % 6 {
                    0 => {
                        ref_log.push(SpecEvt::Rebuild);
                        tx.send_reliable(OverlayEvent::RebuildDirect).unwrap();
                    }
                    1 => {
                        ref_log.push(SpecEvt::Detach(ts));
                        tx.send_reliable(OverlayEvent::ControlDetachedAt(ts)).unwrap();
                    }
                    2 => {
                        let id = reattach_rxs.len() + 1;
                        let (otx, orx) = mpsc::channel(4);
                        reattach_rxs.push((id, orx));
                        ref_log.push(SpecEvt::Detach(ts));
                        ref_log.push(SpecEvt::Reattach(id));
                        tx.send_reliable(OverlayEvent::ControlDetachedAt(ts)).unwrap();
                        tx.send_reliable(OverlayEvent::Reattach { outbound: otx }).unwrap();
                    }
                    3 => {
                        let retryable = (next_u64() & 1) == 0;
                        ref_log.push(SpecEvt::Detach(ts));
                        ref_log.push(SpecEvt::Refused(ts));
                        tx.send_reliable(OverlayEvent::ControlDetachedAt(ts)).unwrap();
                        tx.send_reliable(OverlayEvent::JoinRefused { retryable }).unwrap();
                    }
                    4 => {
                        let rev = next_u64() % 13;
                        let epoch = (step as u64) + 1;
                        let pid = pool[(next_u64() as usize) % pool.len()];
                        let is_upsert = (next_u64() & 1) == 0;
                        let (upsert, remove) = if is_upsert {
                            (Some(pid), None)
                        } else {
                            (None, Some(pid))
                        };
                        ref_log.push(SpecEvt::Delta {
                            epoch,
                            rev,
                            upsert,
                            remove,
                        });
                        let dmsg = ServerMsg::OverlayNetmapDelta {
                            epoch,
                            auth_revision: rev,
                            upserts: upsert.into_iter().map(&make_peer).collect(),
                            removes: remove.into_iter().collect(),
                        };
                        assert!(intercept(&tx, dmsg, true, "", "").is_none());
                    }
                    _ => {
                        let rev = next_u64() % 13;
                        let mask = next_u64() & 0b1111;
                        let ids: Vec<bson::oid::ObjectId> = pool
                            .iter()
                            .enumerate()
                            .filter_map(|(i, p)| (((mask >> i) & 1) == 1).then_some(*p))
                            .collect();
                        let nmsg: ServerMsg = serde_json::from_value(serde_json::json!({
                            "t": "rc:overlay.netmap",
                            "self_ip": "100.64.0.1",
                            "network": { "cidr": "100.64.0.0/10", "mtu": 1280, "auth_revision": rev },
                            "peers": ids.iter().map(|p| make_peer(*p)).collect::<Vec<_>>()
                        }))
                        .unwrap();
                        ref_log.push(SpecEvt::Netmap(rev, ids));
                        assert!(intercept(&tx, nmsg, true, "", "").is_none());
                    }
                }
                assert!(
                    tx.inner.state.lock().unwrap().reliable <= MAX_RELIABLE_EVENTS,
                    "case {case_idx} step {step} exceeded MAX_RELIABLE_EVENTS"
                );
            }
            drop(tx);
            let mut actual = Vec::new();
            while let Some(e) = rx.recv().await {
                if let OverlayEvent::Reattach { outbound } = &e {
                    let _ = outbound.try_send(signaling::ClientMsg::OverlayEndpoints {
                        candidates: vec![],
                    });
                }
                actual.push(e);
            }
            let actual_reattach_id = reattach_rxs
                .iter_mut()
                .filter_map(|(id, orx)| orx.try_recv().ok().map(|_| *id))
                .last();
            let expected_reattach_id = ref_log.iter().rev().find_map(|s| match s {
                SpecEvt::Reattach(id) => Some(*id),
                _ => None,
            });
            assert_eq!(
                actual_reattach_id, expected_reattach_id,
                "case {case_idx}: latest Reattach sender mismatch"
            );

            // Check BOTH pre-first-netmap mode (`None`) AND main-loop mode (`Some(init_rev)`)!
            for mode in [None, Some(0u64), Some(1), Some(4), Some(8), Some(11), Some(15)] {
                let mut ref_in_main = mode.is_some();
                let mut ref_ep = 0u64;
                let mut ref_rev = mode.unwrap_or(0);
                let mut ref_det: Option<std::time::Instant> = None;
                let mut ref_rebuild = false;
                let mut ref_peers: std::collections::BTreeSet<bson::oid::ObjectId> =
                    if ref_in_main {
                        [peer_a].into_iter().collect()
                    } else {
                        Default::default()
                    };
                let mut ref_vers: std::collections::HashMap<bson::oid::ObjectId, (u64, u64)> =
                    if ref_in_main {
                        [(peer_a, (ref_rev, 0))].into_iter().collect()
                    } else {
                        Default::default()
                    };
                for s in &ref_log {
                    match s {
                        SpecEvt::Rebuild => {
                            if ref_in_main {
                                ref_rebuild = true;
                            }
                        }
                        SpecEvt::Detach(t) | SpecEvt::Refused(t) => {
                            if ref_in_main {
                                ref_det = Some(ref_det.map_or(*t, |p| p.min(*t)));
                            }
                        }
                        SpecEvt::Reattach(_) => {}
                        SpecEvt::Netmap(r, ids) => {
                            if !ref_in_main {
                                ref_in_main = true;
                                ref_ep = 0;
                                ref_rev = *r;
                                ref_det = None;
                                ref_peers = ids.iter().copied().collect();
                                ref_vers = ids.iter().map(|p| (*p, (ref_rev, 0))).collect();
                            } else if tunnel_core::overlay::runtime::accept_netmap_version(
                                &mut ref_ep, &mut ref_rev, 0, *r,
                            ) {
                                ref_ep = 0;
                                ref_det = None;
                                ref_peers = ids.iter().copied().collect();
                                ref_vers = ids.iter().map(|p| (*p, (ref_rev, 0))).collect();
                            }
                        }
                        SpecEvt::Delta {
                            epoch,
                            rev,
                            upsert,
                            remove,
                        } => {
                            if ref_in_main {
                                let mut ups: Vec<signaling::NetmapPeer> =
                                    upsert.iter().map(|p| make_peer(*p)).collect();
                                let mut rems: Vec<bson::oid::ObjectId> =
                                    remove.iter().copied().collect();
                                if tunnel_core::overlay::runtime::filter_netmap_delta_by_peer(
                                    &mut ref_ep,
                                    &mut ref_rev,
                                    &mut ref_vers,
                                    *epoch,
                                    *rev,
                                    &mut ups,
                                    &mut rems,
                                ) {
                                    for r in rems {
                                        ref_peers.remove(&r);
                                    }
                                    for u in ups {
                                        ref_peers.insert(u.node_id);
                                    }
                                }
                            }
                        }
                    }
                }

                let mut act_in_main = mode.is_some();
                let mut act_ep = 0u64;
                let mut act_rev = mode.unwrap_or(0);
                let mut act_det: Option<std::time::Instant> = None;
                let mut act_rebuild = false;
                let mut act_peers: std::collections::BTreeSet<bson::oid::ObjectId> =
                    if act_in_main {
                        [peer_a].into_iter().collect()
                    } else {
                        Default::default()
                    };
                let mut act_vers: std::collections::HashMap<bson::oid::ObjectId, (u64, u64)> =
                    if act_in_main {
                        [(peer_a, (act_rev, 0))].into_iter().collect()
                    } else {
                        Default::default()
                    };
                for e in &actual {
                    match e {
                        OverlayEvent::RebuildDirect => {
                            if act_in_main {
                                act_rebuild = true;
                            }
                        }
                        OverlayEvent::ControlDetachedAt(t) => {
                            if act_in_main {
                                act_det = Some(act_det.map_or(*t, |p| p.min(*t)));
                            }
                        }
                        OverlayEvent::Netmap { network, peers, .. } => {
                            if !act_in_main {
                                act_in_main = true;
                                act_ep = 0;
                                act_rev = network.auth_revision;
                                act_det = None;
                                act_peers = peers.iter().map(|p| p.node_id).collect();
                                act_vers = peers.iter().map(|p| (p.node_id, (act_rev, 0))).collect();
                            } else if tunnel_core::overlay::runtime::accept_netmap_version(
                                &mut act_ep,
                                &mut act_rev,
                                0,
                                network.auth_revision,
                            ) {
                                act_ep = 0;
                                act_det = None;
                                act_peers = peers.iter().map(|p| p.node_id).collect();
                                act_vers = peers.iter().map(|p| (p.node_id, (act_rev, 0))).collect();
                            }
                        }
                        OverlayEvent::NetmapDelta {
                            epoch,
                            auth_revision,
                            upserts,
                            removes,
                        } => {
                            if act_in_main {
                                let mut ups = upserts.clone();
                                let mut rems = removes.clone();
                                if tunnel_core::overlay::runtime::filter_netmap_delta_by_peer(
                                    &mut act_ep,
                                    &mut act_rev,
                                    &mut act_vers,
                                    *epoch,
                                    *auth_revision,
                                    &mut ups,
                                    &mut rems,
                                ) {
                                    for r in rems {
                                        act_peers.remove(&r);
                                    }
                                    for u in ups {
                                        act_peers.insert(u.node_id);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                assert_eq!(act_in_main, ref_in_main, "case {case_idx} mode {mode:?} in_main");
                assert_eq!(act_rebuild, ref_rebuild, "case {case_idx} mode {mode:?} rebuild");
                assert_eq!(act_rev, ref_rev, "case {case_idx} mode {mode:?} rev");
                assert_eq!(act_det, ref_det, "case {case_idx} mode {mode:?} detach deadline");
                assert_eq!(act_peers, ref_peers, "case {case_idx} mode {mode:?} peers");
            }
        }
    }
}
