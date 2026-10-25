// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Multi-org v2 — the process-wide shared direct-carrier plane.
//!
//! Today every org runtime binds its own direct sockets off the SAME
//! process-global stable port ([`direct::direct_port`]), deconflicted only by
//! the blind band walk — so which org holds the base is a spawn-order race
//! that re-runs on every restart and rebuild, churning the NAT mappings of
//! every org that loses it (field: winhost-a's second org re-punching after
//! each restart). The plane replaces that with ONE socket set for the whole
//! process: every attached engine (one per org) sends and receives on the
//! same stable `ip:port`, and inbound datagrams are demultiplexed by the
//! WireGuard **receiver index** instead of by source address.
//!
//! Why the index and not the source: with N orgs sharing one socket pair on
//! BOTH hosts, two independent sessions (org A's and org B's) arrive from the
//! SAME remote `ip:port` — a source-keyed table cannot tell them apart (the
//! `wg.rs` `DemuxRoutes` insert is last-write-wins). The receiver index can:
//! boringtun derives each session's on-wire index from the `index` passed to
//! `Tunn::new` (`local_index = index << 8`; rekeys walk only the low 8 bits),
//! so `receiver_idx >> 8` is a stable per-session key — provided indices are
//! unique across ALL engines, which is exactly what [`PlaneHandle::alloc_index`]
//! provides.
//!
//! Handshake INITIATIONS carry no receiver index (the peer doesn't know our
//! session yet), so they route the way WireGuard itself routes them — by
//! static key: the plane tries [`wg::authenticate_init_with`] against each
//! attached engine (N ≤ a handful, and only on handshakes). An init from a
//! source the authenticated engine already has a session with is processed on
//! that session's `Tunn` (the rekey path); anything else is forwarded to that
//! engine's [`DirectInbound`] channel exactly as the per-device demux did —
//! same rate limit, same runtime-side accept path.
//!
//! One plane per process, owned by the embedder (the agent holds it in a
//! static beside the TUN cache). Engines attach with [`CarrierPlane::attach`];
//! the returned [`PlaneHandle`] is the engine's capability to allocate
//! indices and register routes, and detaches on drop. Gated by
//! `OVERLAY_SHARED_CARRIER` at the embedder — nothing in this module reads
//! the flag.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use boringtun::noise::{Packet, Tunn};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::direct;
use super::disco::DiscoInbound;
#[cfg(target_os = "linux")]
use super::wg::decap_inbound;
use super::wg::{
    Carrier, DirectInbound, Ingress, UNKNOWN_INIT_MAX_SOURCES, UNKNOWN_INIT_MIN_INTERVAL, WgSender,
    authenticate_init_with, is_wg_shaped, process_inbound,
};
use crate::transport::stun::StunInbound;

/// Receiver-index space: boringtun shifts the `Tunn::new` index left by 8, so
/// the index must fit 24 bits for the on-wire receiver index to round-trip.
const INDEX_SPACE: u32 = 1 << 24;

/// One engine (org) attached to the plane. The secret/public pair is what
/// handshake-initiation trial-authentication runs against; `direct_events`
/// receives the engine's unknown-source inits; `tun_tx` is where its peers'
/// decrypted inbound lands.
pub struct EngineHooks {
    pub secret: StaticSecret,
    pub public: PublicKey,
    /// C1 (disco) — the engine.s send-side peer mirror, so the plane can ask
    /// "is this sender one of YOUR installed peers?" before spending a DH.
    pub send: WgSender,
    /// C2 (disco) — where this engine.s PONGs are delivered. Per-engine, not
    /// per-plane: N org engines share one plane, so a single plane-wide sink
    /// would be taken by whichever engine asked first and leave every other
    /// engine blind — every path it measures reading 100 % loss. Field
    /// 2026-08-12: one engine reported 8 % on the same buildhost endpoint the
    /// other reported 100 % on. Routed exactly like `direct_events`.
    pub disco_events: mpsc::Sender<DiscoInbound>,
    pub direct_events: mpsc::Sender<DirectInbound>,
    pub tun_tx: mpsc::Sender<Vec<u8>>,
}

struct EngineEntry {
    id: u64,
    secret: StaticSecret,
    public: PublicKey,
    /// Precomputed `Blake2s256(LABEL_MAC1 || public)` — the ~1 µs mac1
    /// pre-filter that decides WHICH engine (if any) is worth an X25519
    /// during initiation trial-authentication. Router state, not a secret.
    mac1_key: [u8; 32],
    send: WgSender,
    disco_events: mpsc::Sender<DiscoInbound>,
    direct_events: mpsc::Sender<DirectInbound>,
    tun_tx: mpsc::Sender<Vec<u8>>,
}

/// One registered session route: the demux target for `receiver_idx >> 8`.
struct PlaneRoute {
    engine: u64,
    tunn: Arc<tokio::sync::Mutex<Tunn>>,
    ingress: Ingress,
    tun_tx: mpsc::Sender<Vec<u8>>,
    /// The peer endpoint this session sends to. Inbound is accepted from this
    /// source; A3 roaming updates it in place on an AUTHENTICATED inbound from
    /// a new source (kill switch `OVERLAY_ROAM`, else the strict no-roam
    /// stance holds and behavior matches the source-keyed demux).
    expected_src: SocketAddr,
    /// A3 — the peer's direct carrier, to repoint its outbound dst in place
    /// on a roam (the send pump's `SendPeer` mirror shares the same `Arc`).
    /// Weak so a dropped peer's carrier isn't pinned by the route table.
    carrier: std::sync::Weak<Carrier>,
    /// A3 — last adoption instant for this session (roam rate limit).
    last_roam: Option<Instant>,
    /// Diagnostic — last session-trace emission (throttle; see
    /// `OVERLAY_SESSION_TRACE`).
    last_trace: Option<Instant>,
}

/// The plane's bound socket set (the process-wide twin of one runtime's
/// direct-socket half of `DirectCtx`).
pub struct PlaneView {
    /// One socket per usable LAN interface, bound to `(iface_ip, stable_port)`.
    pub socks: Vec<(Ipv4Addr, Arc<UdpSocket>)>,
    /// The wildcard public/srflx dialer at `stable_port + 32`, when either
    /// public-direct or srflx is enabled.
    pub public_sock: Option<Arc<UdpSocket>>,
    /// The advertised `ip:port` per LAN socket.
    pub endpoints: Vec<String>,
    pub my_ips: Vec<Ipv4Addr>,
}

struct PlaneBinds {
    socks: Vec<(Ipv4Addr, Arc<UdpSocket>)>,
    public_sock: Option<Arc<UdpSocket>>,
    endpoints: Vec<String>,
    my_ips: Vec<Ipv4Addr>,
    tasks: Vec<JoinHandle<()>>,
    /// PR-B1 — per-socket receive liveness, in lockstep with the recv loops
    /// (`socks` order first, then the public dialer). Snapshotted into
    /// `NodeStatus.direct_socks` so a reader-less socket is visible.
    stats: Vec<Arc<direct::SockStat>>,
}

impl Drop for PlaneBinds {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

struct PlaneState {
    engines: Vec<EngineEntry>,
    routes: HashMap<u32, PlaneRoute>,
    /// Reverse view for handshake-initiation routing: an init from a source
    /// an engine already has a session with is the REKEY path and processes
    /// on that session's `Tunn`. Keyed by `(engine, src)` — the same remote
    /// `ip:port` legitimately appears once per org.
    by_src: HashMap<(u64, SocketAddr), u32>,
    /// Throttle for the unregistered-receiver-index WARN (see
    /// [`CarrierPlane::route_by_index`]). Plane-wide, not per index: the
    /// point is to surface the CONDITION, and a junk flood must not become a
    /// log flood.
    last_unknown_idx_log: Option<Instant>,
    /// Throttle for the initiation-authenticated-to-no-engine WARN (the
    /// type-1 twin of `last_unknown_idx_log`). Before this WARN existed, a
    /// sibling org's init eaten by the wrong engine died as a DEBUG-only
    /// decap error — the dual-org direct lockout ran silent for weeks.
    last_foreign_init_log: Option<Instant>,
    binds: Option<PlaneBinds>,
    next_engine_id: u64,
    /// Demux-routed STUN Binding responses (the plane twin of the device's
    /// channel — the srflx keepalive's query rides plane sockets whose
    /// `recv_from` the plane owns).
    stun_tx: mpsc::Sender<StunInbound>,
    stun_rx: Option<mpsc::Receiver<StunInbound>>,
    /// The shared srflx state every attached runtime mirrors onto its own
    /// control WS (see [`SrflxShared`]).
    srflx_watch: tokio::sync::watch::Sender<SrflxShared>,
    /// The plane keepalive task, once armed (aborted + re-armed by the
    /// rebuild — the plane itself is process-lifetime).
    keepalive: Option<JoinHandle<()>>,
    /// P1-d — the runtimes subscribed to rebuild steps ([`PlaneEvent`]).
    subscribers: Vec<mpsc::Sender<PlaneEvent>>,
    /// P1-d — rebuild-in-flight latch + cooldown stamp (the plane twin of
    /// the per-runtime `pending_rebuild`/`last_rebuild` pair).
    rebuilding: bool,
    last_rebuild: Option<Instant>,
}

/// The shared direct-carrier plane. See the module docs.
pub struct CarrierPlane {
    state: Mutex<PlaneState>,
    /// Session-index allocator, unique across every attached engine for the
    /// process lifetime (monotonic, wrapped into 24 bits, 0 skipped). At one
    /// install per second it takes ~194 days to wrap, and a wrapped index
    /// collides only with a session that has been dead for exactly that long.
    index_alloc: AtomicU32,
    /// Serializes [`ensure_srflx`](Self::ensure_srflx): the first caller
    /// gathers while later callers wait, then read the cached result.
    srflx_gate: tokio::sync::Mutex<bool>,
    /// PR-B1 — serializes [`ensure_bound`](Self::ensure_bound) ACROSS its
    /// awaits. The bind loop can take seconds (3×300 ms base retries per
    /// socket), and two orgs attaching concurrently both used to pass the
    /// empty-view fast-path, both bind, and the second `st.binds` assignment
    /// dropped the first set — whose sockets the first runtime's `DirectCtx`
    /// already held: bound, reader-less, still advertised. Field 2026-08-10:
    /// buildhost/fleet-host-1 relay-locked, the advertised socket's Recv-Q pegged at
    /// rmem, the winner walked the band to :43649. First caller binds; every
    /// later caller waits here and reuses the same view.
    bind_gate: tokio::sync::Mutex<()>,
    /// Times the bind section actually ran (must stay ≤1 between rebuilds —
    /// locked by `ensure_bound_binds_once_under_concurrent_attach`).
    binds_performed: AtomicU32,
    /// W5 — pokes the plane srflx task: SEEKING re-gathers immediately,
    /// ESTABLISHED re-queries the mapping immediately. Fired by the
    /// runtimes' interface-event arm (a VPN connect can change NAT reality
    /// without changing the LAN-IP set, so the net-change rebuild never
    /// fires for it). tokio Notify coalesces storms into one permit.
    regather: tokio::sync::Notify,
    /// Auth-first type-1 routing (kill switch `OVERLAY_INIT_AUTH_FIRST`,
    /// default ON; read once at construction — config keys freeze at daemon
    /// start anyway). ON: with more than one engine attached, an inbound
    /// handshake initiation is routed by trial-authentication, never by the
    /// source-keyed shortcut — two orgs sharing one remote `ip:port` is the
    /// NORMAL multi-org state, and the shortcut deterministically fed the
    /// second org's inits to whichever org held a session at that source
    /// first (field 2026-08-14: every dual-org pair direct on exactly one
    /// org, the other locked on relay until a restart swapped the winner).
    /// OFF restores the legacy shortcut.
    init_auth_first: AtomicBool,
    /// F0 — test-only fault: while set, every datagram this plane's sockets
    /// receive is dropped before demux (and before any rx accounting), so the
    /// direct path is dark in both directions while sends still leave and
    /// `/derp` keeps working (`runtime::failover_bench`).
    #[cfg(test)]
    pub(crate) blackhole: AtomicBool,
    /// F0 — test-only: bind only these of the gathered LAN addresses, so two
    /// planes in one netns model two machines with disjoint addresses (a
    /// peer endpoint on one of OUR addresses is never a LAN candidate,
    /// `direct::pick_same_subnet_endpoint`).
    #[cfg(test)]
    pub(crate) lan_only: Mutex<Option<Vec<Ipv4Addr>>>,
}

impl CarrierPlane {
    pub fn new() -> Arc<Self> {
        let (stun_tx, stun_rx) = mpsc::channel(16);
        let (srflx_watch, _) = tokio::sync::watch::channel(SrflxShared::default());
        Arc::new(Self {
            state: Mutex::new(PlaneState {
                engines: Vec::new(),
                routes: HashMap::new(),
                by_src: HashMap::new(),
                last_unknown_idx_log: None,
                last_foreign_init_log: None,
                binds: None,
                next_engine_id: 1,
                stun_tx,
                stun_rx: Some(stun_rx),
                srflx_watch,
                keepalive: None,
                subscribers: Vec::new(),
                rebuilding: false,
                last_rebuild: None,
            }),
            index_alloc: AtomicU32::new(0),
            srflx_gate: tokio::sync::Mutex::new(false),
            bind_gate: tokio::sync::Mutex::new(()),
            binds_performed: AtomicU32::new(0),
            regather: tokio::sync::Notify::new(),
            init_auth_first: AtomicBool::new(direct::init_auth_first_enabled()),
            #[cfg(test)]
            blackhole: AtomicBool::new(false),
            #[cfg(test)]
            lan_only: Mutex::new(None),
        })
    }

    /// W5 — poke the plane srflx task (see the `regather` field). Sync and
    /// cheap; callable from any select arm.
    pub fn notify_regather(&self) {
        self.regather.notify_one();
    }

    /// Test seam: flip the auth-first routing switch (production reads the
    /// `OVERLAY_INIT_AUTH_FIRST` flag once at construction).
    #[cfg(test)]
    pub(crate) fn set_init_auth_first(&self, on: bool) {
        self.init_auth_first.store(on, Ordering::Relaxed);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PlaneState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Attach an engine. The handle is the engine's capability to allocate
    /// indices and register routes; dropping it detaches the engine and
    /// purges every route it registered.
    pub fn attach(self: &Arc<Self>, hooks: EngineHooks) -> PlaneHandle {
        let mut st = self.lock();
        let id = st.next_engine_id;
        st.next_engine_id += 1;
        st.engines.push(EngineEntry {
            id,
            mac1_key: super::wg::mac1_key_for(&hooks.public),
            secret: hooks.secret,
            public: hooks.public,
            send: hooks.send,
            disco_events: hooks.disco_events,
            direct_events: hooks.direct_events,
            tun_tx: hooks.tun_tx,
        });
        info!(
            engine = id,
            engines = st.engines.len(),
            "carrier plane: engine attached"
        );
        PlaneHandle {
            plane: self.clone(),
            id,
        }
    }

    /// Bind the plane's socket set once (idempotent): one socket per usable
    /// LAN interface at the stable direct port, plus the wildcard
    /// public/srflx dialer on its offset band — the exact binds one runtime's
    /// `setup_direct` performs today, moved to process scope so the band is
    /// walked once instead of raced per org. `None` when no LAN interface is
    /// usable (the caller stays relay-only, as today).
    pub async fn ensure_bound(self: &Arc<Self>) -> Option<PlaneView> {
        // PR-B1 — hold the gate across the WHOLE bind (see `bind_gate`): the
        // first caller binds, every later caller parks here and reuses its
        // view. Without this, concurrent org attaches raced the empty-view
        // check and the loser's sockets leaked bound-but-reader-less.
        let _gate = self.bind_gate.lock().await;
        if let Some(v) = self.view() {
            return Some(v);
        }
        let ifaces = direct::gather_lan_interfaces();
        #[cfg(test)]
        let ifaces: Vec<_> = match self.lan_only.lock().unwrap().as_ref() {
            Some(keep) => ifaces.into_iter().filter(|(ip, _)| keep.contains(ip)).collect(),
            None => ifaces,
        };
        let my_ips: Vec<Ipv4Addr> = ifaces.iter().map(|(ip, _)| *ip).collect();
        if my_ips.is_empty() {
            info!("carrier plane: no usable LAN interface; direct path off (relay only)");
            return None;
        }
        let stable_port = direct::direct_port();
        let mut socks: Vec<(Ipv4Addr, Arc<UdpSocket>)> = Vec::new();
        let mut endpoints: Vec<String> = Vec::new();
        for (ip, ifindex) in &ifaces {
            let Some(s) = direct::bind_direct_socket(*ip, stable_port, "lan").await else {
                continue;
            };
            if let Some(idx) = ifindex {
                direct::force_egress_interface(&s, *idx);
            }
            match s.local_addr() {
                Ok(local) => {
                    endpoints.push(format!("{ip}:{}", local.port()));
                    socks.push((*ip, Arc::new(s)));
                }
                Err(e) => warn!(%ip, %e, "carrier plane: socket local_addr failed; skipping"),
            }
        }
        if socks.is_empty() {
            info!("carrier plane: no bindable LAN interface; direct path off (relay only)");
            return None;
        }
        let public_sock = if direct::public_direct_enabled() || direct::srflx_enabled() {
            let public_port = if stable_port != 0 {
                stable_port + direct::PUBLIC_DIAL_PORT_OFFSET
            } else {
                0
            };
            match direct::bind_direct_socket(Ipv4Addr::UNSPECIFIED, public_port, "public-dial")
                .await
            {
                Some(s) => {
                    if let Some(ix) = direct::vpn_bypass_ifindex() {
                        direct::force_egress_interface(&s, ix);
                    }
                    Some(Arc::new(s))
                }
                None => {
                    warn!("carrier plane: public-dial socket bind failed; public/srflx tiers off");
                    None
                }
            }
        } else {
            None
        };
        info!(
            endpoints = ?endpoints,
            public_dial = public_sock.is_some(),
            "carrier plane: direct sockets bound ONCE for every attached engine"
        );
        self.binds_performed.fetch_add(1, Ordering::Relaxed);
        let mut tasks = Vec::new();
        let mut stats: Vec<Arc<direct::SockStat>> = Vec::new();
        for ((_, s), ep) in socks.iter().zip(&endpoints) {
            let stat = direct::SockStat::new(ep.clone());
            tasks.push(self.adopt_socket_with(s.clone(), Some(stat.clone())));
            stats.push(stat);
        }
        if let Some(p) = &public_sock {
            let local = p
                .local_addr()
                .map(|a| format!("{a} (public-dial)"))
                .unwrap_or_else(|_| "public-dial".into());
            let stat = direct::SockStat::new(local);
            tasks.push(self.adopt_socket_with(p.clone(), Some(stat.clone())));
            stats.push(stat);
        }
        let mut st = self.lock();
        if st.binds.is_some() {
            // Tripwire — structurally unreachable under `bind_gate`; if it
            // ever fires the race guard regressed. Keep the EXISTING set (its
            // sockets are already advertised/held) and discard ours cleanly:
            // aborting our tasks drops the loops, and our socket Arcs die
            // with the locals below, closing the fds.
            warn!(
                "carrier plane: bind completed against an already-bound plane — keeping the \
                 existing set (tripwire: ensure_bound race guard failed?)"
            );
            for t in &tasks {
                t.abort();
            }
            drop(st);
            return self.view();
        }
        st.binds = Some(PlaneBinds {
            socks,
            public_sock,
            endpoints,
            my_ips,
            tasks,
            stats,
        });
        drop(st);
        self.view()
    }

    /// PR-B1 — per-socket receive liveness for `NodeStatus.direct_socks`:
    /// one row per bound plane socket. A row whose `rx_pkts` is frozen while
    /// its endpoint is advertised is the wedge signature.
    pub fn socket_stats(&self) -> Vec<crate::localapi::DirectSockStatus> {
        let st = self.lock();
        st.binds
            .as_ref()
            .map(|b| b.stats.iter().map(|s| s.status()).collect())
            .unwrap_or_default()
    }

    /// The current bound view, if [`ensure_bound`](Self::ensure_bound) ran.
    pub fn view(&self) -> Option<PlaneView> {
        let st = self.lock();
        st.binds.as_ref().map(|b| PlaneView {
            socks: b.socks.clone(),
            public_sock: b.public_sock.clone(),
            endpoints: b.endpoints.clone(),
            my_ips: b.my_ips.clone(),
        })
    }

    /// Test seam: spawn the plane's recv loop on a caller-provided (loopback)
    /// socket, no liveness stat. Production sockets go through `ensure_bound`,
    /// which wires a [`direct::SockStat`] per socket.
    #[cfg(test)]
    pub(crate) fn adopt_socket(self: &Arc<Self>, sock: Arc<UdpSocket>) -> JoinHandle<()> {
        self.adopt_socket_with(sock, None)
    }

    /// The plane recv loop, with a PR-B1 liveness stat the loop bumps per
    /// read datagram (`None` for test loops).
    fn adopt_socket_with(
        self: &Arc<Self>,
        sock: Arc<UdpSocket>,
        stat: Option<Arc<direct::SockStat>>,
    ) -> JoinHandle<()> {
        let plane = self.clone();
        tokio::spawn(async move {
            let local = sock.local_addr().map(|a| a.to_string()).unwrap_or_default();
            let mut buf = vec![0u8; super::wg::WG_BUF];
            // Per-source rate limit for forwarded unknown-source initiations —
            // loop-local, like the per-device demux's, but counting per window:
            // N attached orgs may each legitimately init from ONE remote
            // `ip:port` (shared far-end socket), and boringtun's ~5 s
            // retransmit keeps them phase-locked — a 1-per-src limiter starves
            // one org indefinitely.
            let mut recent_unknown: HashMap<SocketAddr, (Instant, u32)> = HashMap::new();
            // Throttle for the STUN-channel-full WARN (a dropped Binding
            // response starves the srflx keepalive, whose watchdog then
            // rebuilds the whole plane — that must not be invisible).
            let mut last_stun_drop_log: Option<Instant> = None;
            // Linux: up to RECV_BATCH messages per syscall, GRO-joined runs
            // split back into datagrams (`udp_batch`). A socket that refuses
            // the setup keeps the one-datagram reads below.
            #[cfg(target_os = "linux")]
            let mut batch = super::udp_batch::BatchRecv::new(&sock)
                .inspect_err(|e| debug!(%e, %local, "carrier plane: batched receive unavailable"))
                .ok();
            loop {
                #[cfg(target_os = "linux")]
                {
                    if let Some(b) = batch.as_mut() {
                        let msgs = match b.recv(&sock).await {
                            Ok(n) => n,
                            Err(e) => {
                                warn!(%e, %local, "carrier plane: recv ended; loop exiting");
                                break;
                            }
                        };
                        for i in 0..msgs {
                            let (src, datagrams) = b.datagrams(i);
                            plane
                                .on_datagrams(
                                    &sock,
                                    &local,
                                    stat.as_deref(),
                                    src,
                                    datagrams,
                                    &mut recent_unknown,
                                    &mut last_stun_drop_log,
                                )
                                .await;
                        }
                        continue;
                    }
                }
                // #2220 — read on past the errors about an EARLIER datagram:
                // Windows reports a peer's ICMP port-unreachable as 10054 on
                // the next receive, and ending here on it left this socket
                // bound, advertised and unread until a watchdog rebuilt the
                // whole plane (107 s in the field).
                let (n, src) = match super::udp_recv::recv_from(&sock, &mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        // PR-B1 tripwire — a dead recv loop leaves the socket
                        // bound + advertised but reader-less; that's a WARN,
                        // not a DEBUG nobody sees.
                        warn!(%e, %local, "carrier plane: recv ended; loop exiting");
                        break;
                    }
                };
                plane
                    .on_datagram(
                        &sock,
                        &local,
                        stat.as_deref(),
                        src,
                        &mut buf,
                        n,
                        &mut recent_unknown,
                        &mut last_stun_drop_log,
                    )
                    .await;
            }
        })
    }

    /// One message of a batched read: the datagrams GRO joined from `src`
    /// (Linux). A run of WG data datagrams for one session is decrypted under
    /// ONE route lookup and ONE `Tunn` lock, and its packets reach the TUN
    /// channel back to back once the lock is released, so the inbound writer
    /// coalesces the run (`tun_offload`) instead of a packet or two at a time.
    /// Anything else, and a session's first datagram from a new source (a
    /// roam candidate), takes the per-datagram path, in arrival order.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    async fn on_datagrams(
        self: &Arc<Self>,
        sock: &Arc<UdpSocket>,
        local: &str,
        stat: Option<&direct::SockStat>,
        src: SocketAddr,
        datagrams: std::slice::ChunksMut<'_, u8>,
        recent_unknown: &mut HashMap<SocketAddr, (Instant, u32)>,
        last_stun_drop_log: &mut Option<Instant>,
    ) {
        #[cfg(test)]
        if self.blackhole.load(Ordering::Relaxed) {
            return;
        }
        let mut run: Option<InboundRun> = None;
        for dg in datagrams {
            let n = dg.len();
            let idx = match Tunn::parse_incoming_packet(dg) {
                Ok(Packet::PacketData(p)) => Some(p.receiver_idx >> 8),
                _ => None,
            };
            let Some(idx) = idx else {
                if let Some(r) = run.take() {
                    r.deliver().await;
                }
                self.on_datagram(sock, local, stat, src, dg, n, recent_unknown, last_stun_drop_log)
                    .await;
                continue;
            };
            if let Some(s) = stat {
                s.bump();
            }
            if run.as_ref().is_none_or(|r| r.idx != idx) {
                if let Some(r) = run.take() {
                    r.deliver().await;
                }
                let Routed::Session { tunn, ingress, tun_tx } = self.route_by_index(idx, src) else {
                    self.handle_datagram(sock, src, dg, n, Some(&mut *recent_unknown)).await;
                    continue;
                };
                run = Some(InboundRun {
                    idx,
                    tunn: tunn.lock_owned().await,
                    ingress,
                    tun_tx,
                    reply: Carrier::direct(sock.clone(), src),
                    packets: Vec::new(),
                });
            }
            let r = run.as_mut().expect("a run is open");
            if let (_, Some(p)) = decap_inbound(&mut r.tunn, n, dg, &r.reply, &r.ingress) {
                r.packets.push(p);
            }
        }
        if let Some(r) = run.take() {
            r.deliver().await;
        }
    }

    /// One datagram read by a plane recv loop: liveness, disco, STUN, then WG.
    #[allow(clippy::too_many_arguments)]
    async fn on_datagram(
        self: &Arc<Self>,
        sock: &Arc<UdpSocket>,
        local: &str,
        stat: Option<&direct::SockStat>,
        src: SocketAddr,
        buf: &mut [u8],
        n: usize,
        recent_unknown: &mut HashMap<SocketAddr, (Instant, u32)>,
        last_stun_drop_log: &mut Option<Instant>,
    ) {
        #[cfg(test)]
        if self.blackhole.load(Ordering::Relaxed) {
            return;
        }
        if let Some(s) = stat {
            s.bump();
        }
        // C1 — disco: the out-of-tunnel carrier echo, answered
        // unconditionally. Shape-disjoint from WG and STUN by
        // construction (see `overlay::disco`), so it can never steal a
        // live datagram. On the plane the sender may belong to ANY
        // attached engine, so each is tried in turn (N ≤ a handful,
        // and only after the cheap shape + known-peer filters).
        if super::disco::is_disco_shaped(&buf[..n]) {
            // Pongs are routed to the owning engine inside; a ping
            // yields the bytes to echo back.
            if let Some(pong) = self.disco_handle(&buf[..n], src)
                && super::direct::disco_respond_enabled()
            {
                let s = sock.clone();
                tokio::spawn(async move {
                    let _ = s.send_to(&pong, src).await;
                });
                crate::evidence::DISCO_ANSWERED.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        if crate::transport::stun::has_stun_cookie(&buf[..n]) && !is_wg_shaped(&buf[..n]) {
            // Only a STUN datagram needs the channel: taking the plane lock
            // for it on every WG data packet was pure per-packet overhead.
            let stun_tx = { self.lock().stun_tx.clone() };
            if stun_tx
                .try_send(StunInbound {
                    src,
                    packet: buf[..n].to_vec(),
                })
                .is_err()
                && last_stun_drop_log
                    .is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(10))
            {
                *last_stun_drop_log = Some(Instant::now());
                warn!(
                    %src, %local,
                    "carrier plane: STUN response dropped (channel full) — a starved \
                     srflx keepalive ends in a watchdog plane rebuild"
                );
            }
            return;
        }
        self.handle_datagram(sock, src, buf, n, Some(recent_unknown)).await;
    }

    /// Take the receiver for plane-routed STUN Binding responses. `None`
    /// after the first take (one srflx keepalive per plane).
    pub fn take_stun_events(&self) -> Option<mpsc::Receiver<StunInbound>> {
        self.lock().stun_rx.take()
    }

    /// Route + process ONE WG datagram. Shared by the recv loops and
    /// [`PlaneHandle::feed`] (the accept path re-feeding the very init that
    /// triggered a [`DirectInbound`], which carries no rate-limit state).
    async fn handle_datagram(
        self: &Arc<Self>,
        sock: &Arc<UdpSocket>,
        src: SocketAddr,
        buf: &mut [u8],
        n: usize,
        mut recent_unknown: Option<&mut HashMap<SocketAddr, (Instant, u32)>>,
    ) {
        let routed = match Tunn::parse_incoming_packet(&buf[..n]) {
            // Sessionful message types carry OUR receiver index — the exact
            // demux key, unique across engines by construction.
            Ok(Packet::HandshakeResponse(p)) => self.route_by_index(p.receiver_idx >> 8, src),
            Ok(Packet::PacketCookieReply(p)) => self.route_by_index(p.receiver_idx >> 8, src),
            Ok(Packet::PacketData(p)) => self.route_by_index(p.receiver_idx >> 8, src),
            // An initiation carries no receiver index; route it by static key
            // the way WireGuard does. The source-keyed shortcut below is safe
            // ONLY when one engine is attached: with N orgs on one socket,
            // BOTH ends' orgs collapse onto the same remote `ip:port`, so "one
            // engine has a session with this source" routinely means "the
            // OTHER org's engine" — and an init delivered to the wrong Tunn
            // dies as a debug-only decap error. Field 2026-08-14: that made
            // dual-org direct a mutual-exclusion ratchet (whichever org lost
            // its session could never re-handshake: its inits were eaten,
            // so it never answered, so it never re-registered — absorbing).
            Ok(Packet::HandshakeInit(_)) => {
                let (candidates, engines_len) = {
                    let st = self.lock();
                    let c: Vec<u64> = st
                        .engines
                        .iter()
                        .map(|e| e.id)
                        .filter(|id| st.by_src.contains_key(&(*id, src)))
                        .collect();
                    (c, st.engines.len())
                };
                let auth_first = engines_len > 1 && self.init_auth_first.load(Ordering::Relaxed);
                match candidates.as_slice() {
                    // Single-org plane (or the kill switch is off): an init
                    // from a source the engine has a session with is that
                    // session's rekey — no crypto needed, org-unambiguous.
                    [only] if !auth_first => self.route_session_of(*only, src),
                    // Multi-org: authenticate to find the owner (the init is
                    // sealed to exactly one engine's static) — candidates
                    // first, so the common case (a genuine rekey) pays one
                    // DH. Zero-known sources are rate-limited FIRST so a junk
                    // flood never burns a DH per engine; the window admits
                    // one init per ATTACHED ENGINE per source, because N
                    // orgs legitimately init from one shared far-end socket.
                    _ => {
                        if candidates.is_empty()
                            && let Some(recent) = recent_unknown.take()
                            && !unknown_init_fresh(recent, src, engines_len.max(1) as u32)
                        {
                            Routed::Drop
                        } else {
                            match self.authenticate_against_engines(&buf[..n], &candidates) {
                                Some(engine) => match self.route_session_of(engine, src) {
                                    Routed::Drop => {
                                        let ev = {
                                            let st = self.lock();
                                            st.engines
                                                .iter()
                                                .find(|e| e.id == engine)
                                                .map(|e| e.direct_events.clone())
                                        };
                                        match ev {
                                            Some(tx) => Routed::ForwardInit(tx),
                                            None => Routed::Drop,
                                        }
                                    }
                                    hit => hit,
                                },
                                None => {
                                    // Sealed to NO attached engine — foreign
                                    // or forged. This was a silent drop (or
                                    // worse, a wrong-Tunn decap error at
                                    // DEBUG); surface the condition, hard
                                    // throttled like the unregistered-index
                                    // WARN.
                                    let now = Instant::now();
                                    let mut st = self.lock();
                                    if st.last_foreign_init_log.is_none_or(|t| {
                                        now.duration_since(t) >= std::time::Duration::from_secs(10)
                                    }) {
                                        st.last_foreign_init_log = Some(now);
                                        warn!(
                                            %src,
                                            engines = st.engines.len(),
                                            "carrier plane: handshake initiation authenticated \
                                             to NO attached engine — dropped (foreign key, or \
                                             an org this host has not joined)"
                                        );
                                    }
                                    Routed::Drop
                                }
                            }
                        }
                    }
                }
            }
            _ => Routed::Drop,
        };

        match routed {
            Routed::Session {
                tunn,
                ingress,
                tun_tx,
            } => {
                let reply = Carrier::direct(sock.clone(), src);
                let mut t = tunn.lock().await;
                process_inbound(&mut t, n, buf, &reply, &tun_tx, &ingress).await;
            }
            Routed::SessionRoam {
                tunn,
                ingress,
                tun_tx,
                idx,
                new_src,
            } => {
                // A3 — reply to the OBSERVED source, process, and commit the
                // roam ONLY on cryptographic success (process_inbound → true).
                let reply = Carrier::direct(sock.clone(), new_src);
                let authenticated = {
                    let mut t = tunn.lock().await;
                    process_inbound(&mut t, n, buf, &reply, &tun_tx, &ingress).await
                };
                if authenticated {
                    self.commit_roam(idx, new_src);
                }
            }
            Routed::ForwardInit(tx) => {
                if tx
                    .try_send(DirectInbound {
                        src,
                        sock: sock.clone(),
                        packet: buf[..n].to_vec(),
                    })
                    .is_err()
                {
                    // Depth-16 channel full — the peer retries in ~5 s;
                    // count it so a churn storm's slow re-establish is
                    // attributable (LOG-every-silent-drop).
                    crate::evidence::DIRECT_INBOUND_DROPS.fetch_add(1, Ordering::Relaxed);
                    debug!(%src, "carrier plane: accept channel full — initiation dropped");
                }
            }
            Routed::Drop => {}
        }

        // Local helper wants a name — defined after use for readability.
        // Admits up to `per_src` initiations per source per window: one per
        // attached engine, because two orgs' inits from the SAME remote
        // `ip:port` retransmit phase-locked (~5 s apart on both) and a
        // 1-per-window limiter starved one org indefinitely.
        fn unknown_init_fresh(
            recent: &mut HashMap<SocketAddr, (Instant, u32)>,
            src: SocketAddr,
            per_src: u32,
        ) -> bool {
            if recent.len() >= UNKNOWN_INIT_MAX_SOURCES {
                recent.retain(|_, (t, _)| t.elapsed() < UNKNOWN_INIT_MIN_INTERVAL);
            }
            match recent.get_mut(&src) {
                Some((t, count)) if t.elapsed() < UNKNOWN_INIT_MIN_INTERVAL => {
                    if *count < per_src {
                        *count += 1;
                        true
                    } else {
                        false
                    }
                }
                Some(entry) => {
                    *entry = (Instant::now(), 1);
                    true
                }
                None => {
                    if recent.len() < UNKNOWN_INIT_MAX_SOURCES {
                        recent.insert(src, (Instant::now(), 1));
                        true
                    } else {
                        false
                    }
                }
            }
        }
    }

    fn route_by_index(&self, idx: u32, src: SocketAddr) -> Routed {
        let mut st = self.lock();
        // Diagnostic — per-session inbound trace (src vs expected vs verdict),
        // throttled 2 s/session. Shows whether a session receives direct
        // inbound at all and from which source (the uni-directional-carrier
        // diagnosis: same-port = filtering, new-port-no-roam = roam gap,
        // no-trace = relay-only inbound).
        if direct::session_trace_enabled()
            && let Some(r) = st.routes.get_mut(&idx)
        {
            let now = Instant::now();
            if r.last_trace
                .is_none_or(|t| now.duration_since(t) >= std::time::Duration::from_secs(2))
            {
                r.last_trace = Some(now);
                let verdict = if r.expected_src == src {
                    "match"
                } else if direct::roam_enabled() {
                    "roam"
                } else {
                    "drop"
                };
                info!(
                    idx, engine = r.engine, %src, expected = %r.expected_src, verdict,
                    "carrier plane: session-trace (inbound)"
                );
            }
        }
        match st.routes.get(&idx) {
            Some(r) if r.expected_src == src => Routed::Session {
                tunn: r.tunn.clone(),
                ingress: r.ingress.clone(),
                tun_tx: r.tun_tx.clone(),
            },
            // A3 — a known session (by receiver index) from a NEW source:
            // route it to the session's Tunn as a ROAM CANDIDATE. Adoption
            // commits only if the payload authenticates (handle_datagram
            // calls `commit_roam` on success), so a forged index can spend
            // one decap but never move an endpoint. Rate-limited per session.
            Some(r)
                if direct::roam_enabled()
                    && r.last_roam
                        .is_none_or(|t| t.elapsed() >= direct::ROAM_MIN_INTERVAL) =>
            {
                Routed::SessionRoam {
                    tunn: r.tunn.clone(),
                    ingress: r.ingress.clone(),
                    tun_tx: r.tun_tx.clone(),
                    idx,
                    new_src: src,
                }
            }
            Some(r) => {
                // Roam off (or rate-limited): the strict no-roam stance — a
                // known session from an unexpected source is dropped.
                debug!(
                    idx,
                    %src,
                    expected = %r.expected_src,
                    "carrier plane: session datagram from unexpected source; dropped"
                );
                Routed::Drop
            }
            None => {
                // An authenticated-looking session datagram for an index no
                // engine registered. This was a bare `Drop` with NO log, and
                // that silence is what made the 2026-08-12 winhost-a outage take
                // a day: packets arrived on the carrier socket, nothing
                // reached any TUN, and every layer above reported health.
                //
                // Throttled hard — a junk flood must not become a log flood.
                let now = Instant::now();
                if st
                    .last_unknown_idx_log
                    .is_none_or(|t| now.duration_since(t) >= std::time::Duration::from_secs(10))
                {
                    st.last_unknown_idx_log = Some(now);
                    let registered = st.routes.len();
                    warn!(
                        idx,
                        %src,
                        registered,
                        "carrier plane: session datagram for an UNREGISTERED receiver index — \
                         dropped pre-decrypt. A peer installed on a relay carrier whose far end \
                         dials us directly looks exactly like this."
                    );
                }
                Routed::Drop
            }
        }
    }

    /// A3 — commit an authenticated roam: repoint the session's `expected_src`,
    /// rekey the `(engine, src)` reverse map, and repoint the peer's carrier
    /// dst in place. No-op if the route vanished or a concurrent roam already
    /// moved it (idempotent).
    fn commit_roam(&self, idx: u32, new_src: SocketAddr) {
        let mut st = self.lock();
        let Some(r) = st.routes.get(&idx) else {
            return;
        };
        let old_src = r.expected_src;
        let engine = r.engine;
        if old_src == new_src {
            // Heal-only: a same-`(engine, src)` REPLACEMENT registration that
            // later unregistered leaves a live route with NO reverse entry —
            // its rekey inits then Drop out of `route_session_of` forever
            // (the ForwardInit livelock precondition). Re-asserting the entry
            // is idempotent when it is already present.
            st.by_src.insert((engine, new_src), idx);
            return;
        }
        if let Some(c) = r.carrier.upgrade() {
            c.set_direct_dst(new_src);
        }
        let r = st.routes.get_mut(&idx).expect("checked above");
        r.expected_src = new_src;
        r.last_roam = Some(Instant::now());
        if st.by_src.get(&(engine, old_src)) == Some(&idx) {
            st.by_src.remove(&(engine, old_src));
        }
        st.by_src.insert((engine, new_src), idx);
        crate::evidence::ROAM_ADOPTIONS.fetch_add(1, Ordering::Relaxed);
        info!(
            idx, %old_src, %new_src,
            "carrier plane: peer endpoint ROAMED — authenticated inbound from a new source \
             adopted (outbound repointed)"
        );
    }

    fn route_session_of(&self, engine: u64, src: SocketAddr) -> Routed {
        let st = self.lock();
        match st
            .by_src
            .get(&(engine, src))
            .and_then(|idx| st.routes.get(idx))
        {
            Some(r) => Routed::Session {
                tunn: r.tunn.clone(),
                ingress: r.ingress.clone(),
                tun_tx: r.tun_tx.clone(),
            },
            None => Routed::Drop,
        }
    }

    /// C1 — answer a disco ping on behalf of whichever attached engine knows
    /// the sender. Engines are snapshotted out of the lock so the X25519 runs
    /// unlocked, exactly like [`authenticate_against_engines`].
    ///
    /// "Knows the sender" here is: the engine has a live session route whose
    /// peer is that key. The plane indexes routes by session index, not by
    /// peer key, so this asks each engine's own send-mirror via the hook
    /// captured at attach.
    /// Classify a disco datagram against every attached engine, and hand a
    /// PONG to the OWNING engine.s sink (not a plane-wide one — see
    /// `EngineHooks::disco_events`). Returns the pong bytes to send when the
    /// datagram was a ping.
    fn disco_handle(&self, pkt: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
        let sender = super::disco::claimed_sender(pkt)?;
        let engines: Vec<(
            StaticSecret,
            PublicKey,
            WgSender,
            mpsc::Sender<DiscoInbound>,
        )> = {
            let st = self.lock();
            st.engines
                .iter()
                .map(|e| {
                    (
                        e.secret.clone(),
                        e.public,
                        e.send.clone(),
                        e.disco_events.clone(),
                    )
                })
                .collect()
        };
        for (secret, public, send, sink) in engines {
            match super::disco::classify(pkt, src, &secret, &public, |pk| {
                *pk == sender && send.has_peer(pk)
            }) {
                super::disco::Verdict::Ignore => continue,
                super::disco::Verdict::Answer(pong) => return Some(pong),
                // The engine that authenticated it is the engine that probed
                // it: deliver there and nowhere else.
                super::disco::Verdict::Pong(p) => {
                    if sink.try_send(p).is_err() {
                        // A dropped verified pong reads as LOSS in the
                        // owner's per-path table — count it so a bad loss
                        // number can be re-framed as backpressure.
                        crate::evidence::DISCO_PONG_DROPS.fetch_add(1, Ordering::Relaxed);
                    }
                    return None;
                }
            }
        }
        None
    }

    /// Try each attached engine's static against a handshake initiation.
    /// Engines are snapshotted out of the lock — the crypto runs unlocked.
    /// `preferred` engines (the ones with a `by_src` session at the packet's
    /// source) are tried first: a genuine rekey then costs one DH.
    ///
    /// The mac1 pre-filter runs first (per engine, ~1 µs keyed Blake2s):
    /// an initiation is mac1-keyed to exactly one responder static, so a
    /// spoofed/foreign packet — including one from a source that holds a
    /// live `by_src` entry and therefore bypasses the unknown-source
    /// limiter — is rejected without ever reaching an X25519.
    fn authenticate_against_engines(&self, init: &[u8], preferred: &[u64]) -> Option<u64> {
        let mut engines: Vec<(u64, StaticSecret, PublicKey, [u8; 32])> = {
            let st = self.lock();
            st.engines
                .iter()
                .map(|e| (e.id, e.secret.clone(), e.public, e.mac1_key))
                .collect()
        };
        engines.sort_by_key(|(id, _, _, _)| !preferred.contains(id));
        engines
            .into_iter()
            .filter(|(_, _, _, mac1_key)| super::wg::init_mac1_matches(mac1_key, init))
            .find(|(_, secret, public, _)| authenticate_init_with(secret, public, init).is_some())
            .map(|(id, _, _, _)| id)
    }
}

/// One routed datagram's disposition. `Session` = process on the session's
/// `Tunn`; `ForwardInit` = hand an authenticated unknown-source initiation
/// to the owning engine's accept path; `Drop` = not ours / not permitted.
enum Routed {
    Session {
        tunn: Arc<tokio::sync::Mutex<Tunn>>,
        ingress: Ingress,
        tun_tx: mpsc::Sender<Vec<u8>>,
    },
    /// A3 — a known session (by receiver index) from a NEW source: process on
    /// its Tunn, then `commit_roam(idx, new_src)` iff it authenticated.
    SessionRoam {
        tunn: Arc<tokio::sync::Mutex<Tunn>>,
        ingress: Ingress,
        tun_tx: mpsc::Sender<Vec<u8>>,
        idx: u32,
        new_src: SocketAddr,
    },
    ForwardInit(mpsc::Sender<DirectInbound>),
    Drop,
}

/// A run of one session's data datagrams being decrypted by
/// [`CarrierPlane::on_datagrams`]: the session held, its packets collected.
#[cfg(target_os = "linux")]
struct InboundRun {
    idx: u32,
    tunn: tokio::sync::OwnedMutexGuard<Tunn>,
    ingress: Ingress,
    tun_tx: mpsc::Sender<Vec<u8>>,
    reply: Arc<Carrier>,
    packets: Vec<Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl InboundRun {
    /// Release the session, then hand its packets to the TUN channel back to
    /// back, in order.
    async fn deliver(self) {
        let Self { tunn, tun_tx, packets, .. } = self;
        drop(tunn);
        for p in packets {
            if tun_tx.send(p).await.is_err() {
                break;
            }
        }
    }
}

/// An attached engine's capability: allocate plane-unique session indices and
/// register/unregister the session routes they key. Dropping the handle
/// detaches the engine and purges its routes — the engine (a `WgDevice`)
/// owns exactly one.
pub struct PlaneHandle {
    plane: Arc<CarrierPlane>,
    id: u64,
}

impl PlaneHandle {
    /// A process-unique 24-bit session index for `Tunn::new`. Monotonic;
    /// never handed out twice within a wrap of the 24-bit space.
    pub(crate) fn alloc_index(&self) -> u32 {
        1 + self.plane.index_alloc.fetch_add(1, Ordering::Relaxed) % (INDEX_SPACE - 1)
    }

    /// Register the session route for an index handed out by
    /// [`alloc_index`](Self::alloc_index). Replaces nothing by construction —
    /// an occupied slot is a bug and is logged loudly instead of silently
    /// clobbered (the source-keyed table's failure mode). Decrypted inbound
    /// for the session lands on the engine's `tun_tx` from its attach hooks.
    pub(crate) fn register_route(
        &self,
        idx: u32,
        tunn: Arc<tokio::sync::Mutex<Tunn>>,
        ingress: Ingress,
        expected_src: SocketAddr,
        carrier: std::sync::Weak<Carrier>,
    ) {
        let mut st = self.plane.lock();
        let Some(tun_tx) = st
            .engines
            .iter()
            .find(|e| e.id == self.id)
            .map(|e| e.tun_tx.clone())
        else {
            warn!(
                idx,
                engine = self.id,
                "carrier plane: register on a detached engine (bug)"
            );
            return;
        };
        // Visibility, not a guard: a same-peer re-install to the same dst
        // legitimately overwrites (the old route unregisters right after and
        // leaves the new entry alone), but a DIFFERENT session losing its
        // reverse entry here is the §2(b) orphan — its rekey inits stop
        // resolving until `commit_roam`'s heal path re-asserts it.
        if let Some(old) = st.by_src.insert((self.id, expected_src), idx)
            && old != idx
        {
            debug!(
                engine = self.id, %expected_src, old, new = idx,
                "carrier plane: by_src reverse entry overwritten by a new session"
            );
        }
        if st
            .routes
            .insert(
                idx,
                PlaneRoute {
                    engine: self.id,
                    tunn,
                    ingress,
                    tun_tx,
                    expected_src,
                    carrier,
                    last_roam: None,
                    last_trace: None,
                },
            )
            .is_some()
        {
            warn!(
                idx,
                engine = self.id,
                "carrier plane: index slot was already occupied (bug)"
            );
        }
    }

    /// Drop a session route. The `(engine, src)` reverse entry is removed
    /// only if it still points at THIS index — a replacement session for the
    /// same source (re-install to the same peer) registered after us must
    /// keep its own reverse entry.
    pub(crate) fn unregister_route(&self, idx: u32) {
        let mut st = self.plane.lock();
        if let Some(r) = st.routes.remove(&idx) {
            let key = (self.id, r.expected_src);
            if st.by_src.get(&key) == Some(&idx) {
                st.by_src.remove(&key);
            }
        }
    }

    /// Re-assert (or roam) a live session's source mapping from an
    /// AUTHENTICATED inbound init: same `src` heals a missing/clobbered
    /// `by_src` reverse entry (the ForwardInit livelock breaker — without it,
    /// an init whose session lost its reverse entry cycles
    /// auth → Drop → ForwardInit → feed → auth forever); a NEW `src` commits
    /// a full roam (expected_src + reverse map + carrier dst). Callers must
    /// have authenticated the packet — this moves routing state.
    pub(crate) fn reassert_src(&self, idx: u32, src: SocketAddr) {
        self.plane.commit_roam(idx, src);
    }

    /// Process ONE datagram as if it had arrived on a plane socket — the
    /// plane twin of `WgDevice::feed_direct` (the accept path answers the
    /// very initiation that triggered its [`DirectInbound`] immediately
    /// instead of waiting for the ~5 s retransmit).
    pub(crate) async fn feed(&self, src: SocketAddr, sock: Arc<UdpSocket>, packet: &[u8]) {
        let mut buf = packet.to_vec();
        let n = buf.len();
        self.plane
            .handle_datagram(&sock, src, &mut buf, n, None)
            .await;
    }
}

impl Drop for PlaneHandle {
    fn drop(&mut self) {
        let mut st = self.plane.lock();
        st.engines.retain(|e| e.id != self.id);
        let dead: Vec<u32> = st
            .routes
            .iter()
            .filter(|(_, r)| r.engine == self.id)
            .map(|(idx, _)| *idx)
            .collect();
        for idx in &dead {
            if let Some(r) = st.routes.remove(idx) {
                let key = (self.id, r.expected_src);
                if st.by_src.get(&key) == Some(idx) {
                    st.by_src.remove(&key);
                }
            }
        }
        if !dead.is_empty() || !st.engines.is_empty() {
            debug!(
                engine = self.id,
                purged = dead.len(),
                remaining_engines = st.engines.len(),
                "carrier plane: engine detached"
            );
        }
    }
}

/// Multi-org v2 — the plane's shared srflx state: ONE gather + NAT probe +
/// keepalive for the whole process, broadcast to every attached runtime via
/// [`CarrierPlane::subscribe_srflx`] (each runtime advertises on its OWN
/// control WS, after its OWN join — the server-side join-clears-srflx
/// ordering holds per org). `generation` bumps on every change so a
/// forwarder can tell a fresh value from the initial empty state.
#[derive(Clone, Default)]
pub struct SrflxShared {
    pub stun_server: Option<SocketAddr>,
    /// Advertised candidates; `[0]` is the punch candidate.
    pub candidates: Vec<String>,
    /// The punch pair — the advertised candidate and the plane socket that
    /// owns its NAT mapping (peers' srflx are dialed FROM this socket).
    pub punch: Option<(String, Arc<UdpSocket>)>,
    pub my_nat: Option<String>,
    /// R2 — the advertised mapping came from the wildcard PUBLIC-DIAL socket
    /// (full-tunnel VPN egress rescue): every LAN-bound vantage was dead and
    /// the captured default route answered. Punches ride the tunnel path.
    pub via_public_dial: bool,
    /// What the LocalAPI shows when the tier is off/empty this run.
    pub error: Option<String>,
    /// §6 item 5 — the gateway port mapping on the punch socket's port
    /// ([`super::portmap::PortMapper::describe`]). While one is held, the
    /// PUBLISHED value carries its external address at `candidates[0]` and
    /// `my_nat = "cone"`; the srflx task's own state never does.
    pub portmap: Option<String>,
    pub generation: u64,
}

impl SrflxShared {
    /// What the watch publishes: `self` (the STUN-only state the srflx task
    /// keeps) with the held mapping, if any, merged in.
    fn published(&self, pm: Option<&super::portmap::PortMapper>) -> SrflxShared {
        SrflxShared {
            candidates: super::portmap::advert(&self.candidates, pm),
            my_nat: super::portmap::advert_nat(self.my_nat.clone(), pm),
            portmap: pm.and_then(super::portmap::PortMapper::describe),
            ..self.clone()
        }
    }
}

impl CarrierPlane {
    /// Subscribe to the shared srflx state (see [`SrflxShared`]).
    pub fn subscribe_srflx(&self) -> tokio::sync::watch::Receiver<SrflxShared> {
        self.lock().srflx_watch.subscribe()
    }

    /// ONE srflx gather + NAT probe for the whole process. The first caller
    /// performs it — via the plane's STUN sink, because the plane's recv
    /// loops own the sockets and raw-socket STUN would be stolen by them —
    /// and every later caller gets the cached result. Also arms the plane
    /// keepalive, which holds the mapping open and re-publishes on change.
    /// P1-d re-gathers per rebuild epoch; until then the result is
    /// process-lifetime, like the plane's binds.
    ///
    /// `portmap_key` keys the gateway mapping's PCP nonce
    /// ([`super::portmap::nonce_for`]); the first caller's key wins, like the
    /// gather itself.
    pub async fn ensure_srflx(
        self: &Arc<Self>,
        stun_urls: &[String],
        portmap_key: &[u8],
    ) -> SrflxShared {
        let mut done = self.srflx_gate.lock().await;
        if *done {
            return self.lock().srflx_watch.borrow().clone();
        }
        let mut sink = self.lock().stun_rx.take();
        let Some(rx) = sink.as_mut() else {
            // The srflx task already owns the sink (it lives for the plane
            // epoch). Return the CURRENT state without publishing anything:
            // the old error-publish here clobbered a good watch value with
            // "sink already taken" (the W5 review's landmine).
            return self.lock().srflx_watch.borrow().clone();
        };
        let shared = self.gather_via_sink(stun_urls, rx, false).await;
        // send_replace, NOT send: the plane keeps no persistent receiver
        // (the channel's initial one is dropped at construction), and
        // `send` DROPS the value when there are zero receivers — which is
        // exactly the case here, because ensure_srflx runs BEFORE any
        // runtime's forwarder subscribes. That silently left the watch empty,
        // so every forwarder read `[]` and never advertised, and the losing
        // org of the gather-gate race went relay-locked (field 2026-08-10:
        // random org per host stuck at srflx=[]). send_replace stores the
        // value unconditionally, so late subscribers see the candidate.
        self.lock().srflx_watch.send_replace(shared.clone());
        if let Some(rx) = sink {
            self.spawn_srflx_task(rx, stun_urls.to_vec(), &shared, portmap_key.to_vec());
        }
        *done = true;
        shared
    }

    /// The gather pass — the plane twin of the runtime's
    /// `gather_and_advertise_srflx` core, minus the advertising (each
    /// runtime does its own) and driven through the STUN sink.
    ///
    /// `quiet` — demote the per-vantage progress lines and the all-empty
    /// WARN to debug. The SEEKING task re-walks every backoff tick (and on
    /// every interface-event poke), so at full verbosity a UDP-blocked host
    /// wrote the same 4 lines per walk forever — field 2026-08-14: 40k srflx
    /// lines in one day's log on winhost-a. The task keeps its own low-rate
    /// heartbeat instead.
    async fn gather_via_sink(
        &self,
        stun_urls: &[String],
        rx: &mut mpsc::Receiver<StunInbound>,
        quiet: bool,
    ) -> SrflxShared {
        let mut out = SrflxShared {
            generation: 1,
            ..Default::default()
        };
        if !direct::srflx_gather_active() || stun_urls.is_empty() {
            return out;
        }
        let Some(v) = self.view() else {
            return out;
        };
        if v.socks.is_empty() {
            return out;
        }
        // W5(a) — walk the topologically-spread vantage list AT GATHER TIME.
        // The old single-`resolve_stun_server` pick used the FIRST resolved
        // address for every socket, so one corp path that drops UDP to that
        // /16 read as "srflx NONE" even when the other vantages were fine
        // (field 2026-08-14: winhost-a's error named 94.130.141.74 while
        // 5.9.157.x would have answered).
        let mut targets = direct::resolve_stun_targets(stun_urls, &v.my_ips).await;
        if targets.is_empty()
            && let Some(s) = direct::resolve_stun_server(stun_urls, &v.my_ips).await
        {
            targets.push(s);
        }
        if targets.is_empty() {
            warn!(
                urls = ?stun_urls,
                "carrier plane: no resolvable STUN server — srflx tier OFF for every org this run"
            );
            out.error = Some(format!("no resolvable STUN server among {stun_urls:?}"));
            return out;
        }
        let mut pairs: Vec<(String, Arc<UdpSocket>)> = Vec::new();
        let mut tried = 0usize;
        for server in targets.iter().take(3).copied() {
            tried += 1;
            out.stun_server = Some(server);
            pairs = tokio::time::timeout(super::runtime::SRFLX_GATHER_BUDGET, async {
                let mut pairs: Vec<(String, Arc<UdpSocket>)> = Vec::new();
                for (_ip, sock) in &v.socks {
                    match crate::transport::stun::srflx_query_via_sink(
                        sock,
                        rx,
                        server,
                        super::runtime::SRFLX_ATTEMPT_TIMEOUT,
                    )
                    .await
                    {
                        Ok(SocketAddr::V4(s)) if direct::is_public_v4(*s.ip()) => {
                            let ep = SocketAddr::V4(s).to_string();
                            if !pairs.iter().any(|(e, _)| e == &ep) {
                                pairs.push((ep, sock.clone()));
                            }
                        }
                        Ok(other) => {
                            debug!(%other, "carrier plane: srflx candidate not public — skipping")
                        }
                        Err(e) => {
                            debug!(%e, "carrier plane: srflx query failed on a socket — skipping")
                        }
                    }
                }
                pairs
            })
            .await
            .unwrap_or_default();
            // R2 — full-tunnel rescue: every LAN-bound sock came up empty for
            // this vantage. The UNSPECIFIED public dialer egresses via the
            // captured default route (the tunnel), which on AnyConnect-class
            // hosts is the ONLY path that passes UDP (field corplap-3
            // 2026-08-15: physical NICs filtered both directions, tunnel UDP
            // fine — srflx sat at NONE because nothing ever asked the one
            // socket that could answer). Outside the per-server budget above
            // so a multi-dead-sock host still reaches it; bounded by the
            // query's own retry ceiling. Healthy hosts never get here.
            if pairs.is_empty()
                && direct::vpn_vantage_enabled()
                && let Some(p) = v.public_sock.as_ref()
            {
                match crate::transport::stun::srflx_query_via_sink(
                    p,
                    rx,
                    server,
                    super::runtime::SRFLX_ATTEMPT_TIMEOUT,
                )
                .await
                {
                    Ok(SocketAddr::V4(s)) if direct::is_public_v4(*s.ip()) => {
                        info!(
                            mapped = %s,
                            %server,
                            "carrier plane: srflx RESCUED via the public-dial socket — every \
                             LAN vantage was dead but the default-route (VPN) path answers"
                        );
                        out.via_public_dial = true;
                        pairs.push((SocketAddr::V4(s).to_string(), p.clone()));
                    }
                    Ok(other) => {
                        debug!(%other, "carrier plane: public-dial srflx not public — skipping")
                    }
                    Err(e) => {
                        debug!(%e, "carrier plane: public-dial srflx query failed")
                    }
                }
            }
            if !pairs.is_empty() {
                break;
            }
            let remaining = targets.len().saturating_sub(tried).min(2);
            if quiet {
                debug!(
                    %server,
                    remaining,
                    "carrier plane: srflx gather empty from this vantage — trying the next"
                );
            } else {
                info!(
                    %server,
                    remaining,
                    "carrier plane: srflx gather empty from this vantage — trying the next"
                );
            }
        }
        if pairs.is_empty() {
            // WARN for the same reason the per-runtime pass warns: an empty
            // srflx tier once died fleet-wide at debug! visibility. (Quiet
            // repeat walks demote it — the FIRST verdict already warned.)
            if quiet {
                debug!(
                    vantages = tried,
                    sockets = v.socks.len(),
                    "carrier plane: srflx gather yielded NO public candidate — every org's peers \
                     will read this node as UDP-blocked (pairs fall to the relay/DERP tier)"
                );
            } else {
                warn!(
                    vantages = tried,
                    sockets = v.socks.len(),
                    "carrier plane: srflx gather yielded NO public candidate — every org's peers \
                     will read this node as UDP-blocked (pairs fall to the relay/DERP tier)"
                );
            }
            out.error = Some(format!(
                "STUN yielded no public candidate ({} vantage(s), {} socket(s) probed{})",
                tried,
                v.socks.len(),
                if direct::vpn_vantage_enabled() && v.public_sock.is_some() {
                    " + public-dial fallback"
                } else {
                    ""
                }
            ));
            return out;
        }
        // A1 — up to three topologically-spread vantages; ANY pairwise
        // mapping mismatch classifies symmetric (one dead vantage tolerated).
        // Shared classifier with the per-runtime `probe_nat_type` twin.
        // (The list was already resolved above — reuse it.)
        // Typing evidence — keep the raw (vantage ⇒ mapping) pairs for the
        // gather line below. Field 2026-08-15: all three cluster nodes
        // (public-IP, no NAT) flipped cone→symmetric at the rc.379 boot and
        // a fresh-socket manual probe minutes later showed identity mappings
        // from every vantage — the verdict alone was uninvestigable because
        // the mappings that produced it were never logged. Cost: one short
        // Vec per gather (gathers are rare: boot/rebuild/regather).
        let mut typing: Vec<String> = Vec::new();
        // W5(b) — typing must never consult a vantage that IS this host
        // (kernel-hairpin mappings fake "symmetric" on NAT-less cluster
        // nodes). The GATHER above keeps the full list — only the CLASSIFIER
        // input is filtered.
        let typing_targets = direct::exclude_self_vantages(&targets);
        let my_nat = if typing_targets.len() >= 2 {
            let punch_sock = pairs[0].1.clone();
            let mut mappings: Vec<SocketAddr> = Vec::with_capacity(typing_targets.len());
            for t in &typing_targets {
                match crate::transport::stun::srflx_query_via_sink(
                    &punch_sock,
                    rx,
                    *t,
                    super::runtime::SRFLX_ATTEMPT_TIMEOUT,
                )
                .await
                {
                    Ok(m) => {
                        typing.push(format!("{t}=>{m}"));
                        mappings.push(m);
                    }
                    Err(_) => typing.push(format!("{t}=>FAIL")),
                }
            }
            direct::classify_nat_mappings(&mappings).map(str::to_string)
        } else {
            None
        };
        out.candidates = pairs.iter().map(|(e, _)| e.clone()).collect();
        out.punch = pairs.into_iter().next();
        out.my_nat = my_nat;
        info!(
            candidates = ?out.candidates,
            my_nat = ?out.my_nat,
            typing = ?typing,
            server = ?out.stun_server,
            "carrier plane: srflx gathered ONCE for every attached org"
        );
        out
    }

    /// W5 — the persistent plane srflx task: owns the STUN sink for the
    /// plane epoch, in two states.
    ///
    /// **SEEKING** (no punch yet — the gather found nothing): periodically
    /// re-run the FULL multi-vantage gather with backoff (keepalive-secs
    /// floor 20 s, ×3 per miss, 300 s cap), plus an immediate pass when
    /// [`notify_regather`](CarrierPlane::notify_regather) pokes (interface
    /// events — a VPN connect changes NAT reality without changing the LAN
    /// set). Before W5 a NONE gather returned the sink and NOTHING ever
    /// re-queried: `srflx NONE` was sticky for the daemon lifetime, which
    /// also made the node the universal relay ANCHOR (`set_udp_relay_ok`
    /// false forever). The B4 watchdog is INERT here BY CONSTRUCTION —
    /// there is no advertised mapping to defend, and on a genuinely
    /// UDP-blocked host it would force an authoritative plane rebuild
    /// every few cycles forever.
    ///
    /// **ESTABLISHED** (punch exists): the pre-W5 keepalive verbatim —
    /// re-query the pinned server on the punch socket each interval,
    /// publish a changed mapping on the watch (every runtime's forwarder
    /// re-advertises on its own WS; the runtimes' srflx-watch arm refreshes
    /// their carriers' view), re-resolve the server after repeated
    /// failures, B4 watchdog ARMED. A regather poke here runs the query
    /// immediately instead of waiting out the tick.
    fn spawn_srflx_task(
        self: &Arc<Self>,
        rx: mpsc::Receiver<StunInbound>,
        stun_urls: Vec<String>,
        seed: &SrflxShared,
        portmap_key: Vec<u8>,
    ) {
        let secs = direct::srflx_keepalive_secs();
        if !direct::srflx_enabled() || secs == 0 {
            self.lock().stun_rx = Some(rx);
            return;
        }
        if seed.punch.is_none() && !direct::srflx_seek_enabled() {
            // Kill switch: restore the pre-W5 sticky-NONE behaviour.
            self.lock().stun_rx = Some(rx);
            return;
        }
        let plane = self.clone();
        let my_ips: Vec<Ipv4Addr> = self.view().map(|v| v.my_ips).unwrap_or_default();
        let mut state = seed.clone();
        let handle = tokio::spawn(async move {
            let mut rx = rx;
            // ---- SEEKING ----
            if state.punch.is_none() {
                let mut delay = std::time::Duration::from_secs(secs.max(20));
                const SEEK_CAP: std::time::Duration = std::time::Duration::from_secs(300);
                let mut last_walk: Option<std::time::Instant> = None;
                let mut walks: u64 = 0;
                loop {
                    let poked = tokio::select! {
                        _ = tokio::time::sleep(delay) => false,
                        _ = plane.regather.notified() => {
                            debug!("carrier plane: srflx re-gather poked (interface event) while SEEKING");
                            true
                        }
                    };
                    // W6 — pokes bypass the backoff BY DESIGN (a VPN drop
                    // must re-gather fast), but a churny event source must
                    // not turn that into a continuous STUN loop: field
                    // 2026-08-14, winhost-a under Check Point emitted an
                    // interface event every ~6 s, so SEEKING walked all 3
                    // vantages back-to-back for 15 minutes (~140 walks)
                    // until the source quieted. Timer-driven walks never
                    // wait — their spacing IS the backoff.
                    if poked {
                        let wait = poke_floor_wait(last_walk.map(|t| t.elapsed()));
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                    }
                    let fresh = plane.gather_via_sink(&stun_urls, &mut rx, walks > 0).await;
                    last_walk = Some(std::time::Instant::now());
                    walks += 1;
                    if fresh.punch.is_some() {
                        state = SrflxShared {
                            generation: state.generation + 1,
                            ..fresh
                        };
                        plane.lock().srflx_watch.send_replace(state.clone());
                        info!(
                            candidates = ?state.candidates,
                            my_nat = ?state.my_nat,
                            walks,
                            "carrier plane: srflx RECOVERED after NONE — every org re-advertises \
                             and re-pairs"
                        );
                        break; // → ESTABLISHED below
                    }
                    delay = (delay * 3).min(SEEK_CAP);
                    // Low-rate heartbeat (walk 1, 11, 21, …) — the per-walk
                    // detail is at debug since the quiet-gather demotion.
                    if walks % 10 == 1 {
                        info!(
                            walks,
                            next_secs = delay.as_secs(),
                            "carrier plane: srflx still NONE — seeking continues \
                             (per-walk detail at debug)"
                        );
                    } else {
                        debug!(
                            next_secs = delay.as_secs(),
                            "carrier plane: srflx still NONE — backing off"
                        );
                    }
                }
            }
            // ---- ESTABLISHED ----
            let (Some(mut server), Some((_, punch))) = (state.stun_server, state.punch.clone())
            else {
                // A gather success always sets both; defensive only.
                warn!("carrier plane: srflx task seeded without server/punch — exiting");
                return;
            };
            let mut failures = 0u32;
            // B4 — a SEPARATE consecutive-failure counter for the watchdog:
            // `failures` resets every RERESOLVE_AFTER cycles (the STUN-server
            // re-resolve), so it can't measure a sustained outage. This one
            // resets ONLY on a successful query.
            let mut watchdog_fails = 0u32;
            // PR-B1 tripwire — one WARN per outage (not per cycle): repeated
            // keepalive failure is the "advertised mapping may be dead"
            // signal, most notably a reader-less punch socket queueing the
            // reply forever (the 2026-08-10 wedge). DEBUG-only left it
            // invisible.
            let mut warned = false;
            const RERESOLVE_AFTER: u32 = 3;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The interval's immediate first tick — the gather just ran.
            tick.tick().await;
            // §6 item 5 — ask the gateway to map the punch port. Here, not in
            // the gather: the STUN advert is already out, so a silent gateway
            // (most cloud hosts; ≤ 2 × `portmap::WAIT`) delays nothing, and a
            // grant re-publishes with the mapping first.
            let mut pm =
                super::portmap::PortMapper::start(&punch, &state.candidates, &portmap_key).await;
            if pm.is_some() {
                state.generation += 1;
                plane.lock().srflx_watch.send_replace(state.published(pm.as_ref()));
            }
            // W6 — poke-storm floor (see SEEKING): a poked query here is only
            // an ACCELERATION of the ≤`secs` tick, so under an interface-event
            // storm a too-soon poke is skipped outright — the regular
            // keepalive re-queries within the interval anyway, and the tick
            // cadence itself must NEVER be floored (Check Point grandfathering
            // depends on the ≤25 s keepalive holding the session entry).
            let mut last_query: Option<std::time::Instant> = None;
            loop {
                let poked = tokio::select! {
                    _ = tick.tick() => false,
                    _ = plane.regather.notified() => {
                        debug!("carrier plane: srflx keepalive poked (interface event) — querying now");
                        true
                    }
                };
                if poked && !poke_floor_wait(last_query.map(|t| t.elapsed())).is_zero() {
                    continue;
                }
                last_query = Some(std::time::Instant::now());
                let mut publish = false;
                match crate::transport::stun::srflx_query_via_sink(
                    &punch,
                    &mut rx,
                    server,
                    super::runtime::SRFLX_ATTEMPT_TIMEOUT,
                )
                .await
                {
                    Ok(cur) => {
                        failures = 0;
                        watchdog_fails = 0;
                        if warned {
                            warned = false;
                            state.error = None;
                            publish = true;
                            info!("carrier plane: srflx keepalive recovered");
                        }
                        let ep = cur.to_string();
                        if state.candidates.first() != Some(&ep) {
                            if state.candidates.is_empty() {
                                state.candidates.push(ep.clone());
                            } else {
                                state.candidates[0] = ep.clone();
                            }
                            publish = true;
                            // The gateway's external address may have moved too.
                            if let Some(p) = pm.as_mut() {
                                p.recheck();
                            }
                            info!(
                                new_srflx = %ep,
                                "carrier plane: srflx mapping changed — every org re-advertises"
                            );
                        }
                    }
                    Err(e) => {
                        failures += 1;
                        watchdog_fails += 1;
                        // B4 — sustained failure ⇒ the punch socket is dead
                        // (reader-less / wedged); re-resolving the server
                        // won't help. Self-heal via a debounced plane rebuild
                        // (re-binds fresh sockets + re-arms this keepalive).
                        if direct::plane_watchdog_enabled()
                            && watchdog_fails >= direct::PLANE_WATCHDOG_FAILS
                        {
                            warn!(
                                watchdog_fails,
                                "carrier plane: srflx keepalive dead for {} cycles — watchdog \
                                 forcing a plane rebuild (punch socket wedged?)",
                                watchdog_fails
                            );
                            watchdog_fails = 0;
                            plane.request_rebuild("srflx-keepalive-watchdog", true);
                        }
                        if failures >= RERESOLVE_AFTER && !warned {
                            warned = true;
                            warn!(
                                %e, failures,
                                "carrier plane: srflx keepalive failing repeatedly — the \
                                 advertised mapping may be DEAD (reader-less socket / filtered \
                                 path?); peers punching it will fail"
                            );
                            state.error =
                                Some(format!("srflx keepalive failing ({failures} consecutive)"));
                            publish = true;
                        } else {
                            debug!(
                                %e, failures,
                                "carrier plane: srflx keepalive query failed — retaining last advert"
                            );
                        }
                        if failures >= RERESOLVE_AFTER {
                            if let Some(fresh) =
                                direct::resolve_stun_server(&stun_urls, &my_ips).await
                            {
                                server = fresh;
                            }
                            failures = 0;
                        }
                    }
                }
                // Refresh the gateway mapping when due (half its lifetime),
                // or ask again after a loss.
                if let Some(p) = pm.as_mut()
                    && p.poll(&state.candidates).await
                {
                    publish = true;
                }
                if publish {
                    state.generation += 1;
                    plane.lock().srflx_watch.send_replace(state.published(pm.as_ref()));
                }
            }
        });
        self.lock().keepalive = Some(handle);
    }
}

/// Multi-org v2 P1-d — one step of the plane-wide direct-socket rebuild,
/// delivered to every subscribed runtime.
pub enum PlaneEvent {
    /// Release every socket-pinning Arc (direct carriers, probes, the
    /// runtime's `DirectCtx` view), then ack — the plane re-binds only when
    /// every engine has released (or the 3 s straggler timeout fires; the
    /// band walk absorbs a lingering port).
    Teardown { ack: mpsc::Sender<()> },
    /// The plane re-bound its socket set: re-join from the new endpoints,
    /// re-gather (the plane's srflx cache was reset), re-install.
    Ready,
}

impl CarrierPlane {
    /// P1-d — subscribe a runtime to the plane's rebuild steps. One
    /// subscription per attached runtime; a dropped receiver is pruned on
    /// the next rebuild.
    pub fn subscribe_events(&self) -> mpsc::Receiver<PlaneEvent> {
        let (tx, rx) = mpsc::channel(4);
        self.lock().subscribers.push(tx);
        rx
    }

    /// P1-d — request a plane-wide rebuild. Debounced: an in-flight rebuild
    /// swallows the request, and a non-authoritative one (net-change storms)
    /// also respects [`REBUILD_COOLDOWN`](super::runtime::REBUILD_COOLDOWN);
    /// authoritative triggers (resume, the embedder's fingerprint push)
    /// bypass the cooldown, matching the per-runtime R3 semantics. Sync —
    /// the executor runs on its own task, so any select arm can call this.
    pub fn request_rebuild(self: &Arc<Self>, reason: &'static str, authoritative: bool) {
        {
            let mut st = self.lock();
            if st.rebuilding {
                return;
            }
            if !authoritative
                && let Some(t) = st.last_rebuild
                && t.elapsed() < super::runtime::REBUILD_COOLDOWN
            {
                return;
            }
            st.rebuilding = true;
        }
        let plane = self.clone();
        tokio::spawn(async move { plane.run_rebuild(reason).await });
    }

    /// The rebuild executor: Teardown to every runtime → await acks (3 s
    /// straggler timeout — a wedged org must not block the plane) → drop the
    /// binds (recv loops + socket Arcs) → fresh STUN sink + srflx cache
    /// reset → re-bind → Ready to every runtime. Ordering is load-bearing
    /// exactly as in the per-runtime R3 it replaces: the ports only free
    /// once every carrier/probe/view Arc is gone.
    async fn run_rebuild(self: Arc<Self>, reason: &'static str) {
        warn!(
            reason,
            "carrier plane: rebuilding the shared socket set for every org"
        );
        let subs: Vec<mpsc::Sender<PlaneEvent>> = {
            let mut st = self.lock();
            st.subscribers.retain(|s| !s.is_closed());
            st.subscribers.clone()
        };
        let (ack_tx, mut ack_rx) = mpsc::channel::<()>(subs.len().max(1));
        let mut expected = 0usize;
        for s in &subs {
            if s.try_send(PlaneEvent::Teardown {
                ack: ack_tx.clone(),
            })
            .is_ok()
            {
                expected += 1;
            }
        }
        drop(ack_tx);
        let acked = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut n = 0usize;
            while n < expected && ack_rx.recv().await.is_some() {
                n += 1;
            }
            n
        })
        .await
        .unwrap_or(0);
        if acked < expected {
            warn!(
                acked,
                expected,
                "carrier plane: teardown ack timeout — re-binding anyway (band walk absorbs \
                 a straggler's lingering port)"
            );
        }
        let had_binds = {
            let mut st = self.lock();
            if let Some(h) = st.keepalive.take() {
                h.abort();
            }
            // Fresh STUN sink: retired recv loops keep the dead sender; the
            // loops adopted below clone the new one — the same discipline as
            // the device-side `replace_stun_events`.
            let (tx, rx) = mpsc::channel(16);
            st.stun_tx = tx;
            st.stun_rx = Some(rx);
            // Dropping the binds aborts the recv loops and releases the
            // plane's own socket Arcs.
            st.binds.take().is_some()
        };
        // The srflx result was measured through sockets that no longer
        // exist — the next `ensure_srflx` re-gathers on the new binds.
        *self.srflx_gate.lock().await = false;
        if had_binds && self.ensure_bound().await.is_none() {
            warn!("carrier plane: re-bind found no usable LAN interface — direct path off");
        }
        {
            let mut st = self.lock();
            st.rebuilding = false;
            st.last_rebuild = Some(Instant::now());
            for s in &st.subscribers {
                // A dropped Ready means that org NEVER re-establishes after
                // this plane-wide rebuild — Teardown has an ack + straggler
                // timeout, but Ready was fire-and-forget-and-silent. WARN,
                // don't upgrade to a retry loop here: the subscriber channel
                // going unserviced is a runtime-loop failure the org's own
                // watchdogs surface; the missing piece was the breadcrumb.
                if s.try_send(PlaneEvent::Ready).is_err() {
                    warn!(
                        "carrier plane: PlaneEvent::Ready DROPPED (subscriber channel \
                         full/closed) — that org will not re-establish after this rebuild"
                    );
                }
            }
        }
    }
}

/// W6 — minimum spacing between POKED srflx walks/queries. Interface-event
/// pokes bypass the SEEKING backoff by design, so a churny event source
/// (field 2026-08-14: Check Point on winhost-a emitted one every ~6 s) would
/// otherwise drive back-to-back multi-vantage STUN walks indefinitely.
const SEEK_POKE_FLOOR: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a POKED walk must still wait to honour [`SEEK_POKE_FLOOR`].
/// `None` (no walk yet) waits nothing — the first poke is always immediate.
fn poke_floor_wait(since_last_walk: Option<std::time::Duration>) -> std::time::Duration {
    match since_last_walk {
        Some(s) => SEEK_POKE_FLOOR.saturating_sub(s),
        None => std::time::Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    //! Multi-org v2 proof: N engines share ONE socket pair and the plane
    //! demuxes their sessions correctly even when both hosts' orgs collapse
    //! onto the SAME remote `ip:port` — the exact collision the source-keyed
    //! demux cannot express (its insert is last-write-wins).

    use super::*;
    use crate::overlay::WgKeypair;
    use crate::overlay::wg::{DirectInbound, WgDevice, test_genuine_init};
    use std::time::Duration;
    use tokio::sync::mpsc::Receiver;
    use tokio::time::timeout;

    /// W6 — a poke storm cannot walk faster than the floor: only the FIRST
    /// poke is immediate; later ones wait out the remainder, and a poke
    /// after a long quiet gap (the VPN-drop recovery case) waits nothing.
    #[test]
    fn a_poke_storm_cannot_walk_faster_than_the_floor() {
        assert_eq!(poke_floor_wait(None), Duration::ZERO);
        assert_eq!(
            poke_floor_wait(Some(Duration::from_secs(6))),
            Duration::from_secs(24),
            "6 s after a walk, a poked re-walk still owes 24 s"
        );
        assert_eq!(
            poke_floor_wait(Some(Duration::from_secs(31))),
            Duration::ZERO,
            "past the floor a poke walks immediately"
        );
    }

    /// R2 — full-tunnel rescue: when every LAN-bound vantage is dead but the
    /// wildcard public-dial socket (which the OS routes via the captured
    /// default = the VPN tunnel) can reach STUN, the gather promotes ITS
    /// mapping instead of reporting NONE, and attributes it. Field
    /// corplap-3 2026-08-15: AnyConnect filtered the physical NICs both
    /// directions while the CORP3 tunnel passed UDP fine — srflx sat at NONE
    /// purely because the gather never asked the one socket that could
    /// answer. The fake STUN server here ignores the "LAN" sock (the
    /// filtered NIC) and answers only the public dialer, with a fabricated
    /// PUBLIC mapping (the real reply would carry a loopback address, which
    /// the gather rightly refuses to advertise).
    #[tokio::test]
    async fn gather_rescues_srflx_via_the_public_dial_socket() {
        let plane = CarrierPlane::new();
        let lan = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let public = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let public_port = public.local_addr().unwrap().port();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, from)) = server.recv_from(&mut buf).await else {
                    break;
                };
                if from.port() != public_port || n < 20 {
                    continue; // the "LAN" vantage stays dead
                }
                let txn: [u8; 12] = buf[8..20].try_into().unwrap();
                let magic = 0x2112A442u32.to_be_bytes();
                let ip = Ipv4Addr::new(203, 0, 113, 7).octets();
                let mut resp = Vec::with_capacity(32);
                resp.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
                resp.extend_from_slice(&12u16.to_be_bytes());
                resp.extend_from_slice(&magic);
                resp.extend_from_slice(&txn);
                resp.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
                resp.extend_from_slice(&8u16.to_be_bytes());
                resp.push(0);
                resp.push(1); // family: IPv4
                resp.extend_from_slice(&(4242u16 ^ 0x2112).to_be_bytes());
                resp.extend_from_slice(&[
                    ip[0] ^ magic[0],
                    ip[1] ^ magic[1],
                    ip[2] ^ magic[2],
                    ip[3] ^ magic[3],
                ]);
                let _ = server.send_to(&resp, from).await;
            }
        });
        let t_lan = plane.adopt_socket(lan.clone());
        let t_pub = plane.adopt_socket(public.clone());
        {
            let mut st = plane.lock();
            st.binds = Some(PlaneBinds {
                socks: vec![(Ipv4Addr::new(127, 0, 0, 1), lan)],
                public_sock: Some(public.clone()),
                endpoints: vec!["127.0.0.1:0".into()],
                my_ips: Vec::new(),
                tasks: vec![t_lan, t_pub],
                stats: Vec::new(),
            });
        }
        let mut rx = plane.take_stun_events().unwrap();
        let shared = plane
            .gather_via_sink(&[format!("stun:{server_addr}")], &mut rx, false)
            .await;
        assert!(shared.via_public_dial, "the rescue must be attributed");
        assert_eq!(shared.candidates, vec!["203.0.113.7:4242".to_string()]);
        let (_, punch) = shared.punch.expect("punch pair");
        assert_eq!(
            punch.local_addr().unwrap().port(),
            public_port,
            "the punch must ride the public-dial socket"
        );
    }

    /// A peer installed on a RELAY carrier must still be reachable by
    /// receiver index on the plane.
    ///
    /// Only `add_direct_peer` used to register a plane route, so a
    /// relay-installed session had a live index the plane did not know. When
    /// the far end held a DIRECT carrier and dialled the shared socket,
    /// `route_by_index` returned `None` and the datagram was dropped
    /// pre-decrypt — silently. Carriers are negotiated per side, so that
    /// asymmetry is routine.
    ///
    /// Field 2026-08-12 (winhost-a, dual-org): the org whose peers sat on relay
    /// was unreachable inbound from EVERY peer, its socket rx climbing while
    /// its TUN rx stayed at idle; a restart only changed WHICH org lost.
    #[tokio::test]
    async fn add_peer_registers_a_plane_route_so_relay_sessions_are_reachable() {
        let plane = CarrierPlane::new();
        let (tx_e, _rx_e) = mpsc::channel(8);
        let (tx_t, _rx_t) = mpsc::channel(8);
        let kp = WgKeypair::generate();
        let peer = WgKeypair::generate();

        let mut dev = WgDevice::new(kp.secret.clone()).0;
        dev.set_plane(plane.attach(EngineHooks {
            secret: kp.secret.clone(),
            public: kp.public,
            send: dev.sender(),
            disco_events: mpsc::channel(1).0,
            direct_events: tx_e,
            tun_tx: tx_t,
        }));

        // Install via `add_peer` — the generic path relay carriers take.
        // Carrier KIND is irrelevant to the invariant: what matters is that
        // this entry point registers an index route at all.
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let carrier = Carrier::direct(sock, "127.0.0.1:9".parse().unwrap());
        dev.add_peer(
            *peer.public.as_bytes(),
            Ipv4Addr::new(100, 65, 4, 28),
            carrier,
            false,
        );

        // The session must be in the plane's index table, or authenticated
        // direct inbound for it has nowhere to go.
        let st = plane.lock();
        assert_eq!(
            st.routes.len(),
            1,
            "a relay-installed session must register a plane route"
        );
    }

    /// Minimal well-formed IPv4 packet (version nibble + total length + dst),
    /// the same shape the wg two-device tests use.
    fn synthetic_ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2] = (total >> 8) as u8;
        p[3] = (total & 0xff) as u8;
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..].copy_from_slice(payload);
        p
    }

    /// One plane-attached engine: device + its decrypted-inbound receiver.
    async fn engine(plane: &Arc<CarrierPlane>, kp: &WgKeypair) -> (WgDevice, Receiver<Vec<u8>>) {
        let (mut dev, tun_rx) = WgDevice::new(kp.secret.clone());
        let handle = plane.attach(dev.plane_hooks());
        dev.set_plane(handle);
        (dev, tun_rx)
    }

    /// Send `payload` from `dev` until it lands on `rx` (the handshake races
    /// the first sends — boringtun queues + initiates), then return it.
    async fn pump_until_delivered(
        dev: &WgDevice,
        rx: &mut Receiver<Vec<u8>>,
        pkt: &[u8],
    ) -> Vec<u8> {
        for _ in 0..100 {
            dev.send_ip_packet(pkt).await;
            if let Ok(Some(got)) = timeout(Duration::from_millis(50), rx.recv()).await {
                return got;
            }
        }
        panic!("packet never delivered through the plane");
    }

    /// THE core proof: two orgs per host, ONE socket per host, all four
    /// sessions ride the same `ip:port` pair. Receiver-index demux keeps
    /// both directions of both org pairs apart; the source-keyed table
    /// structurally could not (same key for both).
    #[tokio::test(flavor = "multi_thread")]
    async fn two_orgs_share_one_socket_pair_and_demux_by_index() {
        let (a1_kp, a2_kp) = (WgKeypair::generate(), WgKeypair::generate());
        let (b1_kp, b2_kp) = (WgKeypair::generate(), WgKeypair::generate());

        let plane_a = CarrierPlane::new();
        let plane_b = CarrierPlane::new();
        let sock_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (addr_a, addr_b) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        plane_a.adopt_socket(sock_a.clone());
        plane_b.adopt_socket(sock_b.clone());

        let (mut a1, _a1_rx) = engine(&plane_a, &a1_kp).await;
        let (mut a2, _a2_rx) = engine(&plane_a, &a2_kp).await;
        let (mut b1, mut b1_rx) = engine(&plane_b, &b1_kp).await;
        let (mut b2, mut b2_rx) = engine(&plane_b, &b2_kp).await;

        let (ip_a1, ip_b1) = (Ipv4Addr::new(100, 65, 4, 1), Ipv4Addr::new(100, 65, 4, 2));
        let (ip_a2, ip_b2) = (Ipv4Addr::new(100, 65, 8, 1), Ipv4Addr::new(100, 65, 8, 2));

        // Org 1 pair and org 2 pair — SAME socket pair, four sessions. The
        // RESPONDER side registers first: an `initiate` install fires its
        // handshake immediately, and boringtun retransmits a lost init only
        // after its ~5 s rekey timeout (in production the accept path
        // re-feeds it; this test has no runtime).
        b1.add_direct_peer(
            sock_b.clone(),
            a1_kp.public.to_bytes(),
            ip_a1,
            addr_a,
            false,
        )
        .await;
        b2.add_direct_peer(
            sock_b.clone(),
            a2_kp.public.to_bytes(),
            ip_a2,
            addr_a,
            false,
        )
        .await;
        a1.add_direct_peer(sock_a.clone(), b1_kp.public.to_bytes(), ip_b1, addr_b, true)
            .await;
        a2.add_direct_peer(sock_a.clone(), b2_kp.public.to_bytes(), ip_b2, addr_b, true)
            .await;

        let got1 =
            pump_until_delivered(&a1, &mut b1_rx, &synthetic_ipv4(ip_a1, ip_b1, b"org-one")).await;
        assert_eq!(&got1[20..], b"org-one");
        let got2 =
            pump_until_delivered(&a2, &mut b2_rx, &synthetic_ipv4(ip_a2, ip_b2, b"org-two")).await;
        assert_eq!(&got2[20..], b"org-two");

        // Cross-isolation: org 1's channel never saw org 2's packet.
        assert!(
            timeout(Duration::from_millis(100), b1_rx.recv())
                .await
                .is_err(),
            "org 1's engine received a packet that belongs to org 2"
        );
    }

    /// A3 — the plane roam decision + commit seam: a sessionful datagram from
    /// a NEW source (same receiver index) routes as a roam candidate; commit
    /// moves `expected_src`, rekeys `by_src`, bumps the counter, and is
    /// rate-limited; the original source still routes as a plain session.
    #[tokio::test(flavor = "multi_thread")]
    async fn plane_roam_adopts_by_index_gated_and_rate_limited() {
        let my_kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let plane = CarrierPlane::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        plane.adopt_socket(sock.clone());
        let (mut dev, _rx) = engine(&plane, &my_kp).await;

        let old_src: SocketAddr = "203.0.113.9:41000".parse().unwrap();
        let ip = Ipv4Addr::new(100, 65, 4, 9);
        // First registration in a fresh plane → session index 1.
        dev.add_direct_peer(sock.clone(), peer_kp.public.to_bytes(), ip, old_src, false)
            .await;
        let idx = 1u32;

        // Same source → plain session (no roam).
        assert!(matches!(
            plane.route_by_index(idx, old_src),
            Routed::Session { .. }
        ));
        // New source (roam ON by default) → roam candidate naming the new src.
        let new_src: SocketAddr = "198.51.100.5:52000".parse().unwrap();
        match plane.route_by_index(idx, new_src) {
            Routed::SessionRoam { new_src: n, .. } => assert_eq!(n, new_src),
            _ => panic!("expected a roam candidate for a known index from a new source"),
        }

        // Commit the roam (as handle_datagram does after authentication).
        let before = crate::evidence::ROAM_ADOPTIONS.load(Ordering::Relaxed);
        plane.commit_roam(idx, new_src);
        assert!(crate::evidence::ROAM_ADOPTIONS.load(Ordering::Relaxed) > before);
        // The new source is now the session's expected source…
        assert!(matches!(
            plane.route_by_index(idx, new_src),
            Routed::Session { .. }
        ));
        // …and immediately re-roaming to a THIRD source is rate-limited (drop).
        let third: SocketAddr = "198.51.100.6:53000".parse().unwrap();
        assert!(matches!(plane.route_by_index(idx, third), Routed::Drop));
    }

    /// An initiation from an unknown source is trial-authenticated against
    /// each engine's static and forwarded ONLY to the owner; a forged init
    /// (sealed to nobody here) reaches no engine at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_init_forwards_to_the_owning_engine_only() {
        let (a1_kp, a2_kp) = (WgKeypair::generate(), WgKeypair::generate());
        let plane = CarrierPlane::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        plane.adopt_socket(sock);

        let (mut a1, _rx1) = engine(&plane, &a1_kp).await;
        let (mut a2, _rx2) = engine(&plane, &a2_kp).await;
        let mut a1_events = a1.take_direct_events().unwrap();
        let mut a2_events = a2.take_direct_events().unwrap();

        let dialer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = WgKeypair::generate();

        // Sealed to a2's static: lands on a2's accept channel, not a1's.
        let init = test_genuine_init(&stranger.secret, a2_kp.public.to_bytes());
        dialer.send_to(&init, addr).await.unwrap();
        let ev: DirectInbound = timeout(Duration::from_secs(2), a2_events.recv())
            .await
            .expect("owner engine never got the init")
            .unwrap();
        assert_eq!(ev.packet, init);
        assert!(
            timeout(Duration::from_millis(150), a1_events.recv())
                .await
                .is_err(),
            "non-owner engine received a foreign init"
        );

        // Sealed to an unrelated third key: nobody accepts it.
        let nobody = WgKeypair::generate();
        let forged = test_genuine_init(&stranger.secret, nobody.public.to_bytes());
        dialer.send_to(&forged, addr).await.unwrap();
        assert!(
            timeout(Duration::from_millis(200), a2_events.recv())
                .await
                .is_err(),
            "an init sealed to no attached engine was forwarded"
        );
    }

    /// THE dual-org lockout repro (field 2026-08-14): org 2 holds a direct
    /// session at the shared remote `ip:port`; org 1 (on relay there — no
    /// `by_src` entry) punches with an init sealed to org 1's static, from
    /// that same source. The source-keyed shortcut delivered it into org 2's
    /// `Tunn`, where it died as a debug-only decap error — so org 1 never
    /// answered, never registered, and could never leave relay. Auth-first
    /// routing must land it on org 1's accept channel.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_org_on_relay_can_punch_while_a_sibling_holds_direct_at_the_same_src() {
        let (e1_kp, e2_kp) = (WgKeypair::generate(), WgKeypair::generate());
        let plane = CarrierPlane::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        plane.adopt_socket(sock.clone());

        let (mut e1, _rx1) = engine(&plane, &e1_kp).await;
        let (mut e2, _rx2) = engine(&plane, &e2_kp).await;
        let mut e1_events = e1.take_direct_events().unwrap();

        // ONE far-end socket both orgs share — the normal multi-org state.
        let dialer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = dialer.local_addr().unwrap();

        // Org 2 is the "winner": a direct session registered at `far`.
        let peer2 = WgKeypair::generate();
        e2.add_direct_peer(
            sock.clone(),
            peer2.public.to_bytes(),
            Ipv4Addr::new(100, 65, 8, 2),
            far,
            false,
        )
        .await;

        // Org 1's far end punches from the SAME source.
        let far1 = WgKeypair::generate();
        let init = test_genuine_init(&far1.secret, e1_kp.public.to_bytes());
        dialer.send_to(&init, addr).await.unwrap();

        let ev: DirectInbound = timeout(Duration::from_secs(2), e1_events.recv())
            .await
            .expect("org 1's init was eaten by org 2's session (the dual-org lockout)")
            .unwrap();
        assert_eq!(ev.packet, init);
        assert_eq!(ev.src, far);
    }

    /// The kill switch (`OVERLAY_INIT_AUTH_FIRST` off) restores the legacy
    /// source-keyed shortcut on a multi-org plane — org 1's init from org 2's
    /// claimed source is eaten again. Locks that the switch actually
    /// switches.
    #[tokio::test(flavor = "multi_thread")]
    async fn kill_switch_restores_the_legacy_source_shortcut() {
        let (e1_kp, e2_kp) = (WgKeypair::generate(), WgKeypair::generate());
        let plane = CarrierPlane::new();
        plane.set_init_auth_first(false);
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        plane.adopt_socket(sock.clone());

        let (mut e1, _rx1) = engine(&plane, &e1_kp).await;
        let (mut e2, _rx2) = engine(&plane, &e2_kp).await;
        let mut e1_events = e1.take_direct_events().unwrap();

        let dialer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = dialer.local_addr().unwrap();
        let peer2 = WgKeypair::generate();
        e2.add_direct_peer(
            sock.clone(),
            peer2.public.to_bytes(),
            Ipv4Addr::new(100, 65, 8, 2),
            far,
            false,
        )
        .await;

        let far1 = WgKeypair::generate();
        let init = test_genuine_init(&far1.secret, e1_kp.public.to_bytes());
        dialer.send_to(&init, addr).await.unwrap();
        assert!(
            timeout(Duration::from_millis(200), e1_events.recv())
                .await
                .is_err(),
            "with the kill switch off the legacy shortcut must apply (init eaten)"
        );
    }

    /// A SINGLE-engine plane keeps the no-crypto shortcut: a genuine rekey
    /// init from the session's source is processed on the session `Tunn`
    /// (observable: the handshake RESPONSE comes back), and nothing is
    /// forwarded to the accept channel.
    #[tokio::test(flavor = "multi_thread")]
    async fn single_engine_plane_keeps_the_sourcekeyed_shortcut() {
        let e1_kp = WgKeypair::generate();
        let plane = CarrierPlane::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        plane.adopt_socket(sock.clone());

        let (mut e1, _rx1) = engine(&plane, &e1_kp).await;
        let mut e1_events = e1.take_direct_events().unwrap();

        let dialer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let far = dialer.local_addr().unwrap();
        let peer_x = WgKeypair::generate();
        e1.add_direct_peer(
            sock.clone(),
            peer_x.public.to_bytes(),
            Ipv4Addr::new(100, 65, 4, 7),
            far,
            false,
        )
        .await;

        // A genuine rekey: sealed BY the installed peer TO this engine, from
        // the session's registered source.
        let init = test_genuine_init(&peer_x.secret, e1_kp.public.to_bytes());
        dialer.send_to(&init, addr).await.unwrap();
        let mut rbuf = [0u8; 256];
        let (rn, rsrc) = timeout(Duration::from_secs(2), dialer.recv_from(&mut rbuf))
            .await
            .expect("no handshake response — the rekey shortcut regressed")
            .unwrap();
        assert_eq!(rsrc, addr);
        assert!(rn >= 4 && rbuf[0] == 2, "expected a handshake RESPONSE");
        assert!(
            timeout(Duration::from_millis(150), e1_events.recv())
                .await
                .is_err(),
            "a session rekey must not take the ForwardInit accept path"
        );
    }

    /// Org fairness in the unknown-source limiter: two orgs' far ends share
    /// one remote socket, and both punch within one window. The old
    /// 1-per-src-per-2s limiter dropped the second org's init every window
    /// (both retransmit ~5 s, phase-locked — it starved indefinitely).
    #[tokio::test(flavor = "multi_thread")]
    async fn two_orgs_inits_from_one_source_both_pass_the_limiter() {
        let (e1_kp, e2_kp) = (WgKeypair::generate(), WgKeypair::generate());
        let plane = CarrierPlane::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        plane.adopt_socket(sock);

        let (mut e1, _rx1) = engine(&plane, &e1_kp).await;
        let (mut e2, _rx2) = engine(&plane, &e2_kp).await;
        let mut e1_events = e1.take_direct_events().unwrap();
        let mut e2_events = e2.take_direct_events().unwrap();

        let dialer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (far1, far2) = (WgKeypair::generate(), WgKeypair::generate());
        let i1 = test_genuine_init(&far1.secret, e1_kp.public.to_bytes());
        let i2 = test_genuine_init(&far2.secret, e2_kp.public.to_bytes());
        dialer.send_to(&i1, addr).await.unwrap();
        dialer.send_to(&i2, addr).await.unwrap();

        let got1: DirectInbound = timeout(Duration::from_secs(2), e1_events.recv())
            .await
            .expect("org 1's init never arrived")
            .unwrap();
        assert_eq!(got1.packet, i1);
        let got2: DirectInbound = timeout(Duration::from_secs(2), e2_events.recv())
            .await
            .expect("org 2's init was starved by the per-source limiter")
            .unwrap();
        assert_eq!(got2.packet, i2);
    }

    /// The ForwardInit livelock breaker's plane half: a live route whose
    /// `(engine, src)` reverse entry was clobbered away (same-source
    /// replacement registered then unregistered) no longer resolves — until
    /// `reassert_plane_src` heals the entry in place.
    #[tokio::test(flavor = "multi_thread")]
    async fn reassert_src_heals_a_clobbered_reverse_entry() {
        let e_kp = WgKeypair::generate();
        let plane = CarrierPlane::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        plane.adopt_socket(sock.clone());
        let (mut dev, _rx) = engine(&plane, &e_kp).await;

        let shared: SocketAddr = "203.0.113.7:43648".parse().unwrap();
        let (peer_a, peer_b) = (WgKeypair::generate(), WgKeypair::generate());
        dev.add_direct_peer(
            sock.clone(),
            peer_a.public.to_bytes(),
            Ipv4Addr::new(100, 65, 4, 3),
            shared,
            false,
        )
        .await;
        // A second session at the SAME (engine, src) clobbers A's reverse
        // entry; removing it then deletes the entry outright (§2(b) orphan).
        dev.add_direct_peer(
            sock.clone(),
            peer_b.public.to_bytes(),
            Ipv4Addr::new(100, 65, 4, 4),
            shared,
            false,
        )
        .await;
        dev.remove_peer(&peer_b.public.to_bytes()).await;

        assert!(
            matches!(plane.route_session_of(1, shared), Routed::Drop),
            "precondition: the surviving route must be orphaned from by_src"
        );
        dev.reassert_plane_src(&peer_a.public.to_bytes(), shared);
        assert!(
            matches!(plane.route_session_of(1, shared), Routed::Session { .. }),
            "reassert_plane_src must heal the reverse entry for the live session"
        );
    }

    /// W5 — when the persistent srflx task owns the STUN sink,
    /// `ensure_srflx` must return the CURRENT watch value untouched. The
    /// pre-W5 code published an error ("sink already taken") over whatever
    /// the watch held — clobbering a good candidate that a later subscriber
    /// (or the LocalAPI) would then read as NONE.
    #[tokio::test]
    async fn ensure_srflx_returns_cache_untouched_when_the_sink_is_owned() {
        let plane = CarrierPlane::new();
        // Simulate the task owning the sink.
        let _sink = plane.lock().stun_rx.take();
        // A good shared value is already published.
        let good = SrflxShared {
            candidates: vec!["37.63.112.129:43649".into()],
            my_nat: Some("cone".into()),
            generation: 7,
            ..Default::default()
        };
        plane.lock().srflx_watch.send_replace(good.clone());

        let got = plane
            .ensure_srflx(&["stun:example.invalid:3478".into()], b"test-key")
            .await;
        assert_eq!(got.candidates, good.candidates);
        assert_eq!(got.generation, 7);
        assert!(got.error.is_none(), "must not clobber with a sink error");
        let watched = plane.lock().srflx_watch.borrow().clone();
        assert_eq!(
            watched.candidates, good.candidates,
            "the watch value must survive the call"
        );
    }

    /// P1-a lock: indices are unique across handles for the process life —
    /// they key the cross-engine demux, so a duplicate would alias sessions.
    #[tokio::test]
    async fn alloc_index_is_unique_across_engines() {
        let plane = CarrierPlane::new();
        let (tx_e, _rx_e) = mpsc::channel(1);
        let (tx_t, _rx_t) = mpsc::channel(1);
        let kp1 = WgKeypair::generate();
        let h1 = plane.attach(EngineHooks {
            secret: kp1.secret.clone(),
            public: kp1.public,
            send: crate::overlay::wg::WgSender::new(),
            disco_events: mpsc::channel(1).0,
            direct_events: tx_e.clone(),
            tun_tx: tx_t.clone(),
        });
        let kp2 = WgKeypair::generate();
        let h2 = plane.attach(EngineHooks {
            secret: kp2.secret.clone(),
            public: kp2.public,
            send: crate::overlay::wg::WgSender::new(),
            disco_events: mpsc::channel(1).0,
            direct_events: tx_e,
            tun_tx: tx_t,
        });
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            for h in [&h1, &h2] {
                let idx = h.alloc_index();
                assert!(idx > 0 && idx < INDEX_SPACE);
                assert!(seen.insert(idx), "index handed out twice: {idx}");
            }
        }
    }

    /// The srflx-watch send must persist the value even with ZERO receivers —
    /// the real ordering is: ensure_srflx gathers and publishes BEFORE any
    /// runtime's forwarder subscribes. Plain `watch::Sender::send` DROPS the
    /// value when there are no receivers (the plane keeps none), which left
    /// every forwarder reading `[]` and relay-locked the gather-gate loser
    /// (field 2026-08-10). `send_replace` stores unconditionally.
    /// §6 item 5 — what the watch publishes carries a held gateway mapping
    /// first, as `cone`, with its description for the LocalAPI; the srflx
    /// task's own state stays STUN-only (its `[0]` is the punch mapping the
    /// keepalive compares against).
    #[tokio::test]
    async fn a_held_gateway_mapping_is_published_first_and_the_state_stays_stun_only() {
        let external = std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 41641);
        let gw = super::super::portmap::fake_pcp_gateway(external).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let state = SrflxShared {
            candidates: vec!["203.0.113.7:1111".into()],
            my_nat: Some("symmetric".into()),
            ..Default::default()
        };
        let pm = super::super::portmap::Source::At(gw, b"node-secret".to_vec())
            .start(&sock, &state.candidates)
            .await
            .expect("mapped");
        let p = state.published(Some(&pm));
        assert_eq!(
            p.candidates,
            vec![external.to_string(), "203.0.113.7:1111".to_string()]
        );
        assert_eq!(p.my_nat.as_deref(), Some("cone"));
        assert_eq!(p.portmap.as_deref(), Some("pcp 203.0.113.7:41641"));
        assert_eq!(state.candidates, vec!["203.0.113.7:1111".to_string()], "state untouched");
        let none = state.published(None);
        assert_eq!(none.candidates, state.candidates);
        assert_eq!((none.my_nat, none.portmap), (state.my_nat.clone(), None));
    }

    #[tokio::test]
    async fn srflx_watch_persists_value_sent_before_any_subscriber() {
        let plane = CarrierPlane::new();
        let shared = SrflxShared {
            candidates: vec!["1.2.3.4:43648".to_string()],
            my_nat: Some("cone".to_string()),
            generation: 1,
            ..Default::default()
        };
        // Publish BEFORE any forwarder subscribes (the exact production order).
        plane.lock().srflx_watch.send_replace(shared);
        // A late subscriber (the forwarder) MUST see the candidate, not `[]`.
        let rx = plane.subscribe_srflx();
        assert_eq!(rx.borrow().candidates, vec!["1.2.3.4:43648".to_string()]);
        assert_eq!(rx.borrow().my_nat.as_deref(), Some("cone"));
    }

    /// P1-d protocol lock: a rebuild delivers Teardown to every subscriber,
    /// waits for their acks, then delivers Ready; a second request while one
    /// is in flight is swallowed, a non-authoritative one inside the
    /// cooldown is swallowed, and an authoritative one is not. The no-ack
    /// straggler path re-binds after the timeout (paused time). Runs on an
    /// UNBOUND plane — protocol only; the bind half is the runtime's own
    /// rebuild coverage.
    #[tokio::test(start_paused = true)]
    async fn rebuild_delivers_teardown_then_ready_to_every_subscriber() {
        let plane = CarrierPlane::new();
        let mut r1 = plane.subscribe_events();
        let mut r2 = plane.subscribe_events();

        plane.request_rebuild("test", true);
        plane.request_rebuild("test-dup", true); // swallowed: in flight

        let a1 = match r1.recv().await {
            Some(PlaneEvent::Teardown { ack }) => ack,
            _ => panic!("subscriber 1 expected Teardown"),
        };
        let a2 = match r2.recv().await {
            Some(PlaneEvent::Teardown { ack }) => ack,
            _ => panic!("subscriber 2 expected Teardown"),
        };
        a1.send(()).await.unwrap();
        a2.send(()).await.unwrap();
        assert!(matches!(r1.recv().await, Some(PlaneEvent::Ready)));
        assert!(matches!(r2.recv().await, Some(PlaneEvent::Ready)));

        // Cooldown (real-time clock): a net-change right after is swallowed…
        plane.request_rebuild("net-change", false);
        // …an authoritative resume is not. Nobody acks this round — the 3 s
        // straggler timeout (paused tokio time auto-advances) re-binds and
        // Ready still arrives.
        plane.request_rebuild("resume", true);
        assert!(matches!(r1.recv().await, Some(PlaneEvent::Teardown { .. })));
        assert!(matches!(r2.recv().await, Some(PlaneEvent::Teardown { .. })));
        assert!(matches!(r1.recv().await, Some(PlaneEvent::Ready)));
        assert!(matches!(r2.recv().await, Some(PlaneEvent::Ready)));
    }

    /// PR-B1 — the ensure_bound race lock: two orgs attaching concurrently
    /// must produce exactly ONE bind pass and the SAME socket set. Field
    /// 2026-08-10: without the gate, both passed the empty-view check, both
    /// bound, and the loser's sockets stayed bound + advertised with no
    /// reader (Recv-Q pegged at rmem) — buildhost/fleet-host-1 relay-locked fleet-wide.
    /// Binds REAL host ports (band-walking if a local daemon holds the base);
    /// on a host with no usable LAN interface both callers get `None`, and
    /// the ≤1 assertion still locks the invariant.
    #[tokio::test]
    async fn ensure_bound_binds_once_under_concurrent_attach() {
        let plane = CarrierPlane::new();
        let (a, b) = tokio::join!(plane.ensure_bound(), plane.ensure_bound());
        assert!(
            plane.binds_performed.load(Ordering::Relaxed) <= 1,
            "concurrent ensure_bound calls ran the bind section more than once"
        );
        match (a, b) {
            (Some(a), Some(b)) => {
                assert_eq!(a.endpoints, b.endpoints);
                assert!(
                    Arc::ptr_eq(&a.socks[0].1, &b.socks[0].1),
                    "both callers must share the SAME bound sockets, not parallel sets"
                );
            }
            (None, None) => {} // no usable LAN interface (CI container)
            _ => panic!("one caller bound while the other didn't"),
        }
    }

    /// #2220 — the field case, on loopback. The plane's socket sends to ports
    /// nothing listens on, and Windows reports each ICMP port-unreachable as
    /// `WSAECONNRESET` on the NEXT receive. The loop used to END on the first,
    /// leaving the socket bound, advertised and unread (107 s in the field,
    /// until a watchdog rebuilt the whole plane). It must read what arrives
    /// after them. Linux never reports the ICMP on an unconnected socket, so
    /// this passes there either way; Windows is where it discriminates.
    #[tokio::test]
    async fn port_unreachables_do_not_end_the_plane_loop() {
        let plane = CarrierPlane::new();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = sock.local_addr().unwrap();
        let task = plane.adopt_socket(sock.clone());
        let mut stun = plane.take_stun_events().unwrap();
        for _ in 0..3 {
            let gone = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let closed = gone.local_addr().unwrap();
            drop(gone);
            sock.send_to(b"to nobody", closed).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        let ext = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ping = crate::transport::stun::encode_binding_request([4u8; 12]);
        ext.send_to(&ping, local).await.unwrap();
        let got = timeout(Duration::from_secs(5), stun.recv())
            .await
            .expect("the plane loop must still read after the port-unreachables")
            .expect("sink open");
        assert_eq!(got.packet, ping.to_vec());
        assert!(!task.is_finished(), "the plane loop must still be running");
        task.abort();
    }

    /// A GSO burst arrives as ONE GRO-joined message and is decrypted as one
    /// run (`on_datagrams`): every packet delivered, intact and in order.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_gso_burst_is_delivered_whole_and_in_order() {
        let (kp_a, kp_b) = (WgKeypair::generate(), WgKeypair::generate());
        let (plane_a, plane_b) = (CarrierPlane::new(), CarrierPlane::new());
        let sock_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (addr_a, addr_b) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        plane_a.adopt_socket(sock_a.clone());
        plane_b.adopt_socket(sock_b.clone());
        let (mut a, _ra) = engine(&plane_a, &kp_a).await;
        let (mut b, mut rb) = engine(&plane_b, &kp_b).await;
        let (ip_a, ip_b) = (Ipv4Addr::new(100, 65, 9, 1), Ipv4Addr::new(100, 65, 9, 2));
        b.add_direct_peer(sock_b.clone(), kp_a.public.to_bytes(), ip_a, addr_a, false).await;
        a.add_direct_peer(sock_a.clone(), kp_b.public.to_bytes(), ip_b, addr_b, true).await;
        pump_until_delivered(&a, &mut rb, &synthetic_ipv4(ip_a, ip_b, b"warm")).await;
        while timeout(Duration::from_millis(200), rb.recv()).await.is_ok() {}

        let burst: Vec<Vec<u8>> = (0u16..48)
            .map(|i| synthetic_ipv4(ip_a, ip_b, &[&i.to_be_bytes()[..], &[0x5a; 1000]].concat()))
            .collect();
        a.send_ip_batch(&burst).await;
        for (i, want) in burst.iter().enumerate() {
            let got = timeout(Duration::from_secs(2), rb.recv()).await.expect("delivered").unwrap();
            assert_eq!(&got, want, "packet {i} lost, reordered or altered");
        }
    }

    /// Process CPU seconds (user + system) from `/proc/self/stat`; benches only.
    fn process_cpu_secs() -> f64 {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
        let tail = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
        let f: Vec<&str> = tail.split_whitespace().collect();
        let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
        (ticks(11) + ticks(12)) / 100.0
    }

    /// Production-shaped data-plane throughput (not a correctness test;
    /// `--ignored`): both ends receive through a carrier plane recv loop and
    /// send through `send_ip_packet`'s routing path, over real UDP. Env:
    /// MH_BENCH_PACKETS (200000), MH_BENCH_SIZE (1280), MH_BENCH_A / _B bind
    /// addresses (127.0.0.1), MH_BENCH_BATCH (1 = one packet per call).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn bench_plane_direct_throughput() {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let n: usize = env("MH_BENCH_PACKETS", "200000").parse().unwrap();
        let size: usize = env("MH_BENCH_SIZE", "1280").parse().unwrap();
        let batch: usize = env("MH_BENCH_BATCH", "1").parse().unwrap();
        let (bind_a, bind_b) = (env("MH_BENCH_A", "127.0.0.1"), env("MH_BENCH_B", "127.0.0.1"));
        let (kp_a, kp_b) = (WgKeypair::generate(), WgKeypair::generate());
        let (plane_a, plane_b) = (CarrierPlane::new(), CarrierPlane::new());
        let sock_a = Arc::new(tokio::net::UdpSocket::bind(format!("{bind_a}:0")).await.unwrap());
        let sock_b = Arc::new(tokio::net::UdpSocket::bind(format!("{bind_b}:0")).await.unwrap());
        for s in [&sock_a, &sock_b] {
            super::super::sockbuf::tune_carrier(s, "bench");
        }
        let (addr_a, addr_b) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        plane_a.adopt_socket(sock_a.clone());
        plane_b.adopt_socket(sock_b.clone());
        let (mut a, _ra) = engine(&plane_a, &kp_a).await;
        let (mut b, mut rb) = engine(&plane_b, &kp_b).await;
        let (ip_a, ip_b) = (Ipv4Addr::new(100, 65, 9, 1), Ipv4Addr::new(100, 65, 9, 2));
        b.add_direct_peer(sock_b.clone(), kp_a.public.to_bytes(), ip_a, addr_a, false).await;
        a.add_direct_peer(sock_a.clone(), kp_b.public.to_bytes(), ip_b, addr_b, true).await;
        let pkt = synthetic_ipv4(ip_a, ip_b, &vec![0x5a; size.saturating_sub(20)]);
        pump_until_delivered(&a, &mut rb, &pkt).await;
        while timeout(Duration::from_millis(200), rb.recv()).await.is_ok() {}

        let counter = tokio::spawn(async move {
            let (mut got, mut bytes, mut last) = (0usize, 0usize, std::time::Instant::now());
            while let Ok(Some(p)) = timeout(Duration::from_secs(2), rb.recv()).await {
                got += 1;
                bytes += p.len();
                last = std::time::Instant::now();
            }
            (got, bytes, last)
        });
        let chunk: Vec<Vec<u8>> = vec![pkt.clone(); batch.max(1)];
        let (cpu0, t0) = (process_cpu_secs(), std::time::Instant::now());
        let mut left = n;
        while left > 0 {
            let k = left.min(batch.max(1));
            if batch <= 1 {
                a.send_ip_packet(&pkt).await;
            } else {
                a.send_ip_batch(&chunk[..k]).await;
            }
            left -= k;
        }
        let send_secs = t0.elapsed().as_secs_f64();
        let (got, bytes, last) = counter.await.unwrap();
        let secs = last.duration_since(t0).as_secs_f64().max(1e-9);
        let cpu = process_cpu_secs() - cpu0;
        println!(
            "BENCH plane-direct size={size} batch={batch} sent={n} delivered={got} loss={:.2}% \
             send_pps={:.0} delivered_pps={:.0} delivered_mbps={:.1} wall={secs:.2}s cpu={cpu:.2}s cpu_per_gbit={:.2}s",
            100.0 * (n - got.min(n)) as f64 / n as f64,
            n as f64 / send_secs,
            got as f64 / secs,
            bytes as f64 * 8.0 / secs / 1e6,
            cpu / (bytes as f64 * 8.0 / 1e9).max(1e-9),
        );
        drop((a, b));
    }
}
