//! Hard-NAT punching: the birthday spray (`OVERLAY_BIRTHDAY`, default OFF).
//!
//! A srflx punch needs each end to send to the port the OTHER end's NAT
//! mapped for this pair. Behind an endpoint-dependent ("symmetric") NAT that
//! port is not the one STUN saw: every new destination gets a fresh, unknown
//! port. So a pair of one symmetric end (a mobile CGNAT) and one cone end with
//! port-restricted filtering (most home routers) cannot punch today, and rides
//! a relay for good.
//!
//! The spray finds that port by the birthday paradox, as Tailscale describes
//! it ("How NAT traversal works"):
//!
//! - the HARD end (symmetric) opens [`HARD_SOCKETS`] fresh sockets and sends
//!   a disco ping from each to the easy end's srflx, so its NAT holds that
//!   many mappings toward the easy end;
//! - the EASY end (cone) sends [`EASY_PROBES`] disco pings from its punch
//!   socket to the hard end's public IP on probed ports. Each one also opens
//!   its own filter for that port.
//!
//! A probe that lands on one of the hard end's mappings is answered (the
//! pong goes back through the same mapping, which the easy end's filter now
//! admits), and the easy end has the port. 256 mappings and 1024 probes over
//! ~64 K ports hit with p ≈ 1 − e^(−256·1024/64512) ≈ 98 %. From there it is
//! an ordinary make-before-break srflx probe: the WG init goes to that port,
//! the hard end's plane forwards it as an inbound dial on the socket it
//! arrived on, and the relay is held until the handshake latches.
//!
//! No signalling: both ends derive the attempt from the netmap (the two NAT
//! types) and the wall clock. Attempts start at the top of a [`SLOT`] whose
//! phase is a hash of the pair, so the two ends start within their clock skew
//! of each other. A failed attempt backs off by attempting only on slots whose
//! index is a multiple of 2^failures: the end that failed more often attempts
//! on a subset of the other's slots, so the two always meet even when their
//! failure counts differ (one restarted, say). Both-symmetric pairs are not
//! sprayed: that needs ~65 K probes per side.
//!
//! The hard end's sockets are released when the attempt ends, except one a
//! carrier or upgrade probe now uses, which is kept until nothing uses it.
//!
//! Recovered WIP, not a field-validated carrier: the retained lab attempts
//! found no authenticated pong or direct promotion. The port-overlap model
//! below assumes stable, compatible NAT tuples and is not a success oracle.
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};

use boringtun::x25519::PublicKey;
use tokio::task::JoinHandle;

use super::*;
use crate::overlay::disco;

/// The wall-clock period attempts are aligned to.
const SLOT: u64 = 120;
/// How late into its slot an attempt may still start (the runtime tick is
/// 500 ms; a busy loop can be late).
const START_GRACE: u64 = 5;
/// How long an attempt runs, from the top of its slot.
const WINDOW: Duration = Duration::from_secs(30);
/// Sockets (so NAT mappings) the hard end opens.
const HARD_SOCKETS: usize = 256;
/// Fewer sockets than this (descriptor pressure) and the hard end does not try.
const HARD_MIN_SOCKETS: usize = 32;
/// One full active batch plus at most one batch worth of retained/retiring
/// sockets, shared across all peers. A live carrier is never evicted for room.
const MAX_OWNED_SOCKETS: usize = 2 * HARD_SOCKETS;
/// The hard end pings from every socket at these offsets into the slot:
/// once to create the mappings, then to keep them open.
const HARD_PING_AT: [u64; 3] = [0, 10, 20];
/// Probes the easy end sends.
const EASY_PROBES: usize = 1024;
/// Of those, the ports just above each port the hard end's NAT is known to
/// have mapped (its srflx), for NATs that allocate in sequence.
const EASY_NEAR_HINT: u16 = 64;
/// The easy end starts after the hard end's mappings exist, and spreads its
/// probes over [`EASY_SPREAD`] (~68 packets/s).
const EASY_START: Duration = Duration::from_secs(3);
const EASY_SPREAD: Duration = Duration::from_secs(15);
/// Attempts each end runs at once. The hard end's 256 descriptors are the
/// scarce part (a socket leak once ate a host's ephemeral range and its DNS).
const MAX_HARD_ACTIVE: usize = 1;
const MAX_EASY_ACTIVE: usize = 4;
/// The backoff stops growing here: one attempt per 2^6 slots (~2 h).
const MAX_BACKOFF_EXP: u32 = 6;

/// `OVERLAY_BIRTHDAY=1|true|yes|on` turns the spray on. Default OFF.
pub(super) fn enabled() -> bool {
    crate::env::flag("OVERLAY_BIRTHDAY", false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// We are behind the symmetric NAT: open many mappings.
    Hard,
    /// We are behind the cone NAT: probe for one of the peer's mappings.
    Easy,
}

/// Which side of a spray we are, from the two probed NAT types. `None` for
/// any pair a spray cannot help (cone↔cone punches already; both-symmetric is
/// out of reach) and for an unknown type on either side. Pure.
pub(super) fn role(mine: Option<&str>, peer: Option<&str>) -> Option<Role> {
    match (mine, peer) {
        (Some("symmetric"), Some("cone")) => Some(Role::Hard),
        (Some("cone"), Some("symmetric")) => Some(Role::Easy),
        _ => None,
    }
}

/// The pair's slot phase in seconds, equal on both ends (order-free). Pure.
pub(super) fn pair_phase(a: &[u8; 32], b: &[u8; 32]) -> u64 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    // FNV-1a: stable across builds and platforms, which a std hasher is not.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in lo.iter().chain(hi.iter()) {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h % SLOT
}

/// The slot `unix` falls in for this pair, and how far into it. Pure.
pub(super) fn slot_of(unix: u64, phase: u64) -> (u64, u64) {
    let t = unix.saturating_sub(phase);
    (t / SLOT, t % SLOT)
}

/// Does a pair that failed `failures` times in a row attempt in slot `index`?
/// Power-of-two spacing, so the slots of a higher count are a subset of the
/// slots of a lower one. Pure.
pub(super) fn attempts_in(index: u64, failures: u32) -> bool {
    index.is_multiple_of(1u64 << failures.min(MAX_BACKOFF_EXP))
}

/// The ports the easy end probes, in order: the ports just above each known
/// mapping first, then distinct random ones. Never below 1024, never twice.
pub(super) fn probe_ports(hints: &[u16], n: usize, rng: &mut impl rand::Rng) -> Vec<u16> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(n);
    for h in hints {
        for d in 1..=EASY_NEAR_HINT {
            if out.len() >= n {
                return out;
            }
            if let Some(p) = h.checked_add(d)
                && p >= 1024
                && seen.insert(p)
            {
                out.push(p);
            }
        }
    }
    while out.len() < n.min(65535 - 1024) {
        let p = rng.random_range(1024..=65535u16);
        if seen.insert(p) {
            out.push(p);
        }
    }
    out
}

/// The first public IPv4 endpoint of a list. Pure.
fn first_public_v4(list: &[String]) -> Option<SocketAddrV4> {
    list.iter()
        .find_map(|e| match e.trim().parse::<SocketAddr>() {
            Ok(SocketAddr::V4(v4)) if direct::is_public_v4(*v4.ip()) => Some(v4),
            _ => None,
        })
}

/// One hard-end socket and its receive loop.
struct Spray {
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    rx: Option<JoinHandle<()>>,
}

struct Attempt {
    role: Role,
    peer_pub: [u8; 32],
    overlay_ip: Ipv4Addr,
    /// Opaque incarnation: a rebuilt plane cannot reuse this Arc identity.
    punch: std::sync::Weak<UdpSocket>,
    my_srflx: String,
    /// Exact easy-side probe created by this attempt, never a later replacement.
    probe: Option<(Instant, SocketAddr, Option<SocketAddr>)>,
    /// What the probes go to: the peer's public IP (easy) or srflx (hard).
    target: SocketAddrV4,
    nonce: [u8; 8],
    ends: Instant,
    /// The sender task (pings or probes).
    task: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    sprays: Vec<Spray>,
    /// Where an answer came from.
    hit: Option<SocketAddr>,
    probing: bool,
}

impl Attempt {
    fn owns_probe(&self, p: &UpgradeProbe) -> bool {
        p.pubkey == self.peer_pub
            && p.overlay_ip == self.overlay_ip
            && match self.probe {
                Some(stamp) => stamp == (p.since, p.dst, p.local),
                None => p
                    .local
                    .is_some_and(|local| self.sprays.iter().any(|s| s.local == local)),
            }
    }
}

#[derive(Default)]
struct PeerState {
    failures: u32,
    last_slot: Option<u64>,
}

#[derive(Default)]
pub(super) struct Engine {
    peers: HashMap<ObjectId, PeerState>,
    active: HashMap<ObjectId, Attempt>,
    /// Hard-end sockets that outlived their attempt because a carrier uses them.
    kept: Vec<Spray>,
    /// Aborting a Tokio task is asynchronous. Count its socket until the
    /// last real owner drops it; dropping our Arc alone does not free an FD.
    retiring: Vec<std::sync::Weak<UdpSocket>>,
}

impl Engine {
    fn owned_sockets(&self) -> usize {
        self.kept.len()
            + self.active.values().map(|a| a.sprays.len()).sum::<usize>()
            + self
                .retiring
                .iter()
                .filter(|s| s.strong_count() > 0)
                .count()
    }

    fn release(&mut self, rt: &OverlayRuntime, wg: &mut WgDevice, s: Spray) {
        let weak = Arc::downgrade(&s.sock);
        release(rt, wg, s);
        if weak.strong_count() > 0 {
            self.retiring.push(weak);
        }
    }

    fn open_hard_sprays(
        &mut self,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        bind: impl FnMut() -> std::io::Result<Arc<UdpSocket>>,
    ) -> Vec<Spray> {
        let room = MAX_OWNED_SOCKETS.saturating_sub(self.owned_sockets());
        if room < HARD_MIN_SOCKETS {
            return Vec::new();
        }
        let sprays = open_sprays(rt, wg, room.min(HARD_SOCKETS), bind);
        if sprays.len() < HARD_MIN_SOCKETS {
            warn!(
                opened = sprays.len(),
                "overlay: birthday spray — too few sockets opened; not attempting"
            );
            for s in sprays {
                self.release(rt, wg, s);
            }
            Vec::new()
        } else {
            sprays
        }
    }

    /// Recheck before drive, inbound adoption and every promotion sweep. Only
    /// identity and direct eligibility matter; display/relay metadata may churn.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn reconcile(
        &mut self,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        by_node: &HashMap<ObjectId, Installed>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        direct_ctx: Option<&DirectCtx>,
    ) {
        let now = Instant::now();
        let invalid: Vec<_> = self
            .active
            .iter()
            .filter_map(|(node, a)| {
                let current = direct_ctx
                    .and_then(|ctx| {
                        let (advert, sock) = ctx.punch.as_ref()?;
                        let cfg = current_peers.get(node).and_then(peer_config_from_netmap)?;
                        let inst = by_node.get(node)?;
                        Some(
                            a.punch.ptr_eq(&Arc::downgrade(sock))
                                && a.my_srflx == *advert
                                && a.peer_pub == cfg.public_key
                                && a.overlay_ip == cfg.overlay_ip
                                && inst.pubkey == a.peer_pub
                                && inst.overlay_ip == a.overlay_ip
                                && role(ctx.my_nat.as_deref(), cfg.srflx_nat.as_deref())
                                    == Some(a.role)
                                && cfg.srflx_endpoints.iter().any(|s| {
                                    s.trim().parse::<SocketAddrV4>().ok() == Some(a.target)
                                })
                                && !cfg.backbone_only,
                        )
                    })
                    .unwrap_or(false);
                let blocked = rt
                    .path_trial_managed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(node)
                    || rt
                        .shadow(|s| s.mon.forced_derp_active(node, now))
                        .unwrap_or(false);
                (!current || blocked || !direct::srflx_enabled()).then_some(*node)
            })
            .collect();
        for node in invalid {
            self.cancel(node, rt, wg, by_node, upgrade_probes).await;
        }
        self.release_unused(rt, wg, by_node, upgrade_probes);
        self.retiring.retain(|s| s.strong_count() > 0);
    }

    async fn cancel(
        &mut self,
        node: ObjectId,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        by_node: &HashMap<ObjectId, Installed>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
    ) {
        let Some(a) = self.active.remove(&node) else {
            return;
        };
        a.stop.store(true, Ordering::Relaxed);
        a.task.abort();
        let owns_probe = upgrade_probes.get(&node).is_some_and(|p| a.owns_probe(p));
        if owns_probe {
            upgrade_probes.remove(&node);
            rt.shadow(|s| s.mon.on_probe_aborted(&node));
            wg.drop_direct_probe(&a.peer_pub).await;
        }
        let in_use = locals_in_use(by_node, upgrade_probes);
        for s in a.sprays {
            if in_use.contains(&s.local) {
                self.kept.push(s);
            } else {
                self.release(rt, wg, s);
            }
        }
    }

    /// Called only as part of direct-plane teardown (before the legacy rebuild
    /// executor, or after the shared plane's carrier teardown). Cancellation is requested here;
    /// runtime budget keeps counting any still-running owner via Weak.
    pub(super) async fn reset(&mut self, rt: &OverlayRuntime, wg: &mut WgDevice) {
        let nodes: Vec<_> = self.active.keys().copied().collect();
        for node in nodes {
            self.cancel(node, rt, wg, &HashMap::new(), &mut HashMap::new())
                .await;
        }
        for s in std::mem::take(&mut self.kept) {
            self.release(rt, wg, s);
        }
    }

    /// A verified pong. The easy end learns the port from it; the hard end
    /// learns that a probe got through.
    pub(super) fn on_pong(&mut self, p: &disco::DiscoInbound) {
        for (node, a) in self.active.iter_mut() {
            if a.hit.is_some() || a.peer_pub != p.sender || a.nonce != p.nonce {
                continue;
            }
            if p.src.ip() != IpAddr::V4(*a.target.ip()) {
                continue;
            }
            a.hit = Some(p.src);
            // The port is found: no more probes. The hard end keeps pinging,
            // which keeps the mapping open until the handshake.
            if a.role == Role::Easy {
                a.stop.store(true, Ordering::Relaxed);
            }
            info!(peer = %node, role = ?a.role, src = %p.src,
                "overlay: birthday spray — the peer answered through its NAT");
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn tick(
        &mut self,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        by_node: &HashMap<ObjectId, Installed>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        direct_ctx: Option<&DirectCtx>,
    ) {
        let now = Instant::now();
        self.reconcile(rt, wg, current_peers, by_node, upgrade_probes, direct_ctx)
            .await;
        self.drive(
            rt,
            wg,
            current_peers,
            by_node,
            upgrade_probes,
            direct_ctx,
            now,
        )
        .await;
        self.finish_due(rt, wg, by_node, upgrade_probes, Instant::now())
            .await;
        self.release_unused(rt, wg, by_node, upgrade_probes);
        if enabled() {
            self.start_due(rt, wg, current_peers, by_node, direct_ctx, now);
        }
    }

    /// Easy end: dial the port a probe found, make-before-break.
    #[allow(clippy::too_many_arguments)]
    async fn drive(
        &mut self,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        by_node: &HashMap<ObjectId, Installed>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        direct_ctx: Option<&DirectCtx>,
        now: Instant,
    ) {
        let Some(ctx) = direct_ctx else { return };
        for (node, a) in self.active.iter_mut() {
            // A delayed pong may not start a new probe beyond the spray window.
            if now >= a.ends || Instant::now() >= a.ends {
                continue;
            }
            let Some(dst) = a.hit else { continue };
            if a.role != Role::Easy || a.probing {
                continue;
            }
            a.probing = true;
            let Some(cfg) = current_peers.get(node).and_then(peer_config_from_netmap) else {
                continue;
            };
            if by_node.get(node).is_none_or(|i| i.is_direct) {
                continue;
            }
            let Some(sock) = ctx.srflx_sock(dst) else {
                continue;
            };
            // Whatever probe is in flight dials a port that is not this one
            // (the peer's srflx is wrong for us by definition): this one is
            // answered, so it goes first.
            if let Some(old) = upgrade_probes.get(node) {
                if old.dst == dst {
                    continue;
                }
                upgrade_probes.remove(node);
                rt.shadow(|s| s.mon.on_probe_aborted(node));
                wg.drop_direct_probe(&cfg.public_key).await;
            }
            let now = Instant::now();
            if now >= a.ends {
                continue;
            }
            info!(peer = %node, %dst, "overlay: birthday spray — probing the found port (relay held)");
            rt.start_upgrade_probe(
                wg,
                upgrade_probes,
                *node,
                &cfg,
                sock,
                dst,
                DirectTier::Srflx,
                now,
            )
            .await;
            a.probe = upgrade_probes.get(node).map(|p| (p.since, p.dst, p.local));
        }
    }

    /// End attempts whose window closed or whose peer is direct now, and
    /// book the outcome.
    async fn finish_due(
        &mut self,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        by_node: &HashMap<ObjectId, Installed>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        now: Instant,
    ) {
        let done: Vec<ObjectId> = self
            .active
            .iter()
            .filter(|(node, a)| now >= a.ends || by_node.get(*node).is_none_or(|i| i.is_direct))
            .map(|(node, _)| *node)
            .collect();
        let in_use = locals_in_use(by_node, upgrade_probes);
        for node in done {
            let Some(mut a) = self.active.remove(&node) else {
                continue;
            };
            a.stop.store(true, Ordering::Relaxed);
            a.task.abort();
            let direct = by_node.get(&node).is_some_and(|i| i.is_direct);
            // A probe still converging on the found port is not a failure yet;
            // its own deadline books the tier, and the next slot retries.
            let owned = upgrade_probes.get(&node).is_some_and(|p| a.owns_probe(p));
            let pending = !direct
                && upgrade_probes.get(&node).is_some_and(|p| {
                    a.owns_probe(p)
                        && p.since < a.ends
                        && probe_tick(
                            wg.probe_handshake_done(&p.pubkey) == Some(true),
                            now.saturating_duration_since(p.since),
                            p.tier,
                            p.initiated,
                        ) != ProbeVerdict::Expire
                });
            if pending {
                // Keep the captured identity/policy guard until this exact
                // probe's own deadline or completion, but stop the spray and
                // retire all sockets no current carrier/probe needs.
                let p = &upgrade_probes[&node];
                a.probe = Some((p.since, p.dst, p.local));
                let (keep, drop): (Vec<_>, Vec<_>) = a
                    .sprays
                    .into_iter()
                    .partition(|s| in_use.contains(&s.local));
                a.sprays = keep;
                for s in drop {
                    self.release(rt, wg, s);
                }
                self.active.insert(node, a);
                continue;
            }
            if owned && !direct {
                upgrade_probes.remove(&node);
                rt.shadow(|s| s.mon.on_probe_aborted(&node));
                wg.drop_direct_probe(&a.peer_pub).await;
            }
            let st = self.peers.entry(node).or_default();
            if direct {
                st.failures = 0;
            } else {
                st.failures = st.failures.saturating_add(1);
            }
            info!(peer = %node, role = ?a.role, hit = ?a.hit, direct, failures = st.failures,
                "overlay: birthday spray ended");
            for s in a.sprays {
                if in_use.contains(&s.local) {
                    self.kept.push(s);
                } else {
                    self.release(rt, wg, s);
                }
            }
        }
    }

    fn release_unused(
        &mut self,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        by_node: &HashMap<ObjectId, Installed>,
        upgrade_probes: &HashMap<ObjectId, UpgradeProbe>,
    ) {
        if self.kept.is_empty() {
            return;
        }
        let in_use = locals_in_use(by_node, upgrade_probes);
        let (keep, drop): (Vec<_>, Vec<_>) = std::mem::take(&mut self.kept)
            .into_iter()
            .partition(|s| in_use.contains(&s.local));
        self.kept = keep;
        for s in drop {
            debug!(local = %s.local, "overlay: birthday spray socket no longer carries a peer — released");
            self.release(rt, wg, s);
        }
    }

    fn start_due(
        &mut self,
        rt: &OverlayRuntime,
        wg: &mut WgDevice,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        by_node: &HashMap<ObjectId, Installed>,
        direct_ctx: Option<&DirectCtx>,
        now: Instant,
    ) {
        let Some(ctx) = direct_ctx else { return };
        let Some((my_srflx, punch)) = ctx.punch.as_ref() else {
            return;
        };
        let Some(role_mine) = ctx.my_nat.as_deref() else {
            return;
        };
        if !direct::srflx_enabled() {
            return;
        }
        let my_ip = my_srflx.parse::<SocketAddr>().ok().map(|a| a.ip());
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let me = *rt.keypair.public.as_bytes();
        for (node, np) in current_peers {
            if self.active.contains_key(node) {
                continue;
            }
            let Some(cfg) = peer_config_from_netmap(np) else {
                continue;
            };
            let Some(role) = role(Some(role_mine), cfg.srflx_nat.as_deref()) else {
                continue;
            };
            let Some(inst) = by_node.get(node) else {
                continue;
            };
            if inst.is_direct || cfg.backbone_only {
                continue;
            }
            let (slot, into) = slot_of(unix, pair_phase(&me, &cfg.public_key));
            if into >= START_GRACE {
                continue;
            }
            let st = self.peers.entry(*node).or_default();
            if st.last_slot == Some(slot) || !attempts_in(slot, st.failures) {
                continue;
            }
            let Some(target) = first_public_v4(&cfg.srflx_endpoints) else {
                continue;
            };
            // Behind one NAT: that is a hairpin, not a spray.
            if my_ip == Some(IpAddr::V4(*target.ip())) {
                continue;
            }
            if rt
                .path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(node)
                || rt
                    .shadow(|s| s.mon.forced_derp_active(node, now))
                    .unwrap_or(false)
            {
                continue;
            }
            let busy = self.active.values().filter(|a| a.role == role).count();
            let cap = match role {
                Role::Hard => MAX_HARD_ACTIVE,
                Role::Easy => MAX_EASY_ACTIVE,
            };
            if busy >= cap {
                continue;
            }
            st.last_slot = Some(slot);
            let failures = st.failures;
            // Offsets below are from the top of the slot, which may be a
            // few seconds ago.
            let top = now.checked_sub(Duration::from_secs(into)).unwrap_or(now);
            let nonce = rand::random::<[u8; 8]>();
            let shared = disco::shared_secret(&rt.keypair.secret, &PublicKey::from(cfg.public_key));
            let frame = disco::build(disco::KIND_PING, nonce, &me, None, &shared);
            let stop = Arc::new(AtomicBool::new(false));
            let (task, sprays, n) = match role {
                Role::Hard => {
                    let ip = punch
                        .local_addr()
                        .map(|a| a.ip())
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                    let sprays = self.open_hard_sprays(rt, wg, || bind_spray(ip));
                    if sprays.is_empty() {
                        continue;
                    }
                    let socks: Vec<Arc<UdpSocket>> =
                        sprays.iter().map(|s| s.sock.clone()).collect();
                    let n = socks.len();
                    let task = tokio::spawn(hard_pings(socks, SocketAddr::V4(target), frame, top));
                    (task, sprays, n)
                }
                Role::Easy => {
                    let hints: Vec<u16> = cfg
                        .srflx_endpoints
                        .iter()
                        .filter_map(|e| e.trim().parse::<SocketAddrV4>().ok())
                        .filter(|e| e.ip() == target.ip())
                        .map(|e| e.port())
                        .collect();
                    let ports = probe_ports(&hints, EASY_PROBES, &mut rand::rng());
                    let n = ports.len();
                    let task = tokio::spawn(easy_probes(
                        punch.clone(),
                        *target.ip(),
                        ports,
                        frame,
                        top,
                        stop.clone(),
                    ));
                    (task, Vec::new(), n)
                }
            };
            info!(peer = %node, ?role, %target, packets_or_sockets = n, slot, failures,
                "overlay: birthday spray started (symmetric↔cone pair on a relay)");
            self.active.insert(
                *node,
                Attempt {
                    role,
                    peer_pub: cfg.public_key,
                    overlay_ip: cfg.overlay_ip,
                    punch: Arc::downgrade(punch),
                    my_srflx: my_srflx.clone(),
                    probe: None,
                    target,
                    nonce,
                    ends: top + WINDOW,
                    task,
                    stop,
                    sprays,
                    hit: None,
                    probing: false,
                },
            );
        }
        // Forget peers that left the netmap.
        self.peers.retain(|n, _| current_peers.contains_key(n));
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // The receive loops are spawned tasks: they outlive the engine unless
        // aborted, and each holds its socket open.
        for a in self.active.values() {
            a.task.abort();
            for s in &a.sprays {
                if let Some(rx) = &s.rx {
                    rx.abort();
                }
            }
        }
        for s in &self.kept {
            if let Some(rx) = &s.rx {
                rx.abort();
            }
        }
    }
}

/// The local addresses carriers and upgrade probes send from.
fn locals_in_use(
    by_node: &HashMap<ObjectId, Installed>,
    upgrade_probes: &HashMap<ObjectId, UpgradeProbe>,
) -> HashSet<SocketAddr> {
    by_node
        .values()
        .filter_map(|i| i.carrier_local)
        .chain(upgrade_probes.values().filter_map(|p| p.local))
        .collect()
}

/// Open the hard end's sockets on the punch socket's address (so they leave
/// by the same interface), each with a receive loop that answers disco and
/// forwards a WG init as an inbound dial. Stops at the first bind failure.
fn bind_spray(ip: IpAddr) -> std::io::Result<Arc<UdpSocket>> {
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0))
        .and_then(|s| s.set_nonblocking(true).map(|_| s))
        .and_then(UdpSocket::from_std)
        .map(Arc::new)
}

fn open_sprays(
    rt: &OverlayRuntime,
    wg: &mut WgDevice,
    limit: usize,
    mut bind: impl FnMut() -> std::io::Result<Arc<UdpSocket>>,
) -> Vec<Spray> {
    let mut out = Vec::with_capacity(HARD_SOCKETS);
    for _ in 0..limit {
        let sock = match bind() {
            Ok(s) => s,
            Err(e) => {
                debug!(%e, opened = out.len(), "overlay: birthday spray — socket bind failed");
                break;
            }
        };
        let Ok(local) = sock.local_addr() else {
            continue;
        };
        rt.spray_locals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(local);
        let rx = wg.adopt_spray_socket(sock.clone());
        out.push(Spray { sock, local, rx });
    }
    out
}

fn release(rt: &OverlayRuntime, wg: &mut WgDevice, s: Spray) {
    rt.spray_locals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&s.local);
    wg.release_spray_socket(s.local, s.rx);
}

impl OverlayRuntime {
    /// Is `local` one of the birthday spray's open sockets?
    pub(super) fn is_spray_local(&self, local: SocketAddr) -> bool {
        self.spray_locals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&local)
    }
}

async fn hard_pings(socks: Vec<Arc<UdpSocket>>, dst: SocketAddr, frame: Vec<u8>, top: Instant) {
    for at in HARD_PING_AT {
        tokio::time::sleep_until((top + Duration::from_secs(at)).into()).await;
        for (i, s) in socks.iter().enumerate() {
            let _ = s.send_to(&frame, dst).await;
            if i % 32 == 31 {
                tokio::task::yield_now().await;
            }
        }
    }
}

async fn easy_probes(
    sock: Arc<UdpSocket>,
    ip: Ipv4Addr,
    ports: Vec<u16>,
    frame: Vec<u8>,
    top: Instant,
    stop: Arc<AtomicBool>,
) {
    const BATCH: usize = 16;
    let start = top + EASY_START;
    let batches = ports.len().div_ceil(BATCH).max(1) as u32;
    let gap = EASY_SPREAD / batches;
    for (b, chunk) in ports.chunks(BATCH).enumerate() {
        tokio::time::sleep_until((start + gap * b as u32).into()).await;
        if stop.load(Ordering::Relaxed) {
            return;
        }
        for port in chunk {
            let _ = sock.send_to(&frame, SocketAddr::from((ip, *port))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn shared_plane_known_source_adopts_spray_and_keeps_real_bidirectional_data() {
        use super::super::tests::{MockTun, synthetic_ipv4};
        use crate::overlay::carrier_plane::CarrierPlane;
        let our = WgKeypair::generate();
        let remote_key = WgKeypair::generate();
        let our_pk = our.public.to_bytes();
        let pk = remote_key.public.to_bytes();
        let (out, _out_rx) = mpsc::channel(4);
        let rt =
            OverlayRuntime::new_relay(our.clone(), out, Box::new(|_, _, _| unreachable!()), 1280);
        let (mut wg, mut ours_rx) = WgDevice::new(our.secret);
        let plane = CarrierPlane::new();
        wg.set_plane(plane.attach(wg.plane_hooks()));
        let main = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let main_rx = plane.adopt_socket(main.clone());
        let spray = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = spray.local_addr().unwrap();
        let spray_rx = wg.adopt_spray_socket(spray.clone());
        rt.spray_locals.lock().unwrap().insert(local);
        let far = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let src = far.local_addr().unwrap();
        let np = super::super::tests::peer(&remote_key, "100.64.0.7");
        let node = np.node_id;
        let ip = "100.64.0.7".parse().unwrap();
        let self_ip = "100.64.0.1".parse().unwrap();
        let mut installed = HashMap::from([(
            node,
            Installed::base(pk, ip, DirectTier::Relay, Instant::now()),
        )]);
        let current = HashMap::from([(node, np)]);
        wg.start_direct_probe(main.clone(), pk, ip, src, false)
            .await;
        let old_identity = wg.direct_probe_identity(&pk).unwrap();
        let mut probes = HashMap::from([(
            node,
            UpgradeProbe {
                pubkey: pk,
                overlay_ip: ip,
                dst: src,
                tier: DirectTier::Lan,
                since: Instant::now(),
                initiated: true,
                local: main.local_addr().ok(),
            },
        )]);
        let mut inbound = wg.take_direct_events().unwrap();
        let mut forged = crate::overlay::wg::test_genuine_init(&remote_key.secret, our_pk);
        forged[40] ^= 1;
        far.send_to(&forged, local).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), inbound.recv())
                .await
                .is_err()
        );
        assert_eq!(probes[&node].local, main.local_addr().ok());
        assert_eq!(
            wg.direct_probe_identity(&pk),
            Some(old_identity),
            "forged INIT cannot replace the actual probe"
        );

        // Let the original main-socket Tunn accept a real INIT first, so its
        // handshake replay timestamp is populated before any socket change.
        let older = crate::overlay::wg::test_genuine_init(&remote_key.secret, our_pk);
        tokio::time::sleep(Duration::from_millis(2)).await;
        let accepted = crate::overlay::wg::test_genuine_init(&remote_key.secret, our_pk);
        far.send_to(&accepted, main.local_addr().unwrap()).await.unwrap();
        let mut wire = vec![0u8; 2048];
        let (n, reply_from) = tokio::time::timeout(Duration::from_secs(2), far.recv_from(&mut wire))
            .await.unwrap().unwrap();
        assert_eq!(reply_from, main.local_addr().unwrap());
        assert_eq!((n, &wire[..4]), (92, &[2, 0, 0, 0][..]));

        let (tun, _, _) = MockTun::new();
        let tun: Arc<dyn TunIo> = tun;
        let mut relay = None;
        let (tx, _rx) = mpsc::channel(4);
        let mut bq = RelayBuildQueue { in_flight: HashMap::new(), epoch: 0, tx };
        for stale in [&accepted, &older] {
            far.send_to(stale, local).await.unwrap();
            if let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(150), inbound.recv()).await {
                rt.handle_direct_inbound(
                    &mut wg, &mut installed, &mut relay, &tun, &current, &mut probes, &mut bq, event,
                ).await;
            }
            assert_eq!(wg.direct_probe_identity(&pk), Some(old_identity),
                "an accepted or older INIT must not replace/move the pending probe");
            assert_eq!(probes[&node].local, main.local_addr().ok());
            assert!(tokio::time::timeout(Duration::from_millis(100), far.recv_from(&mut wire)).await.is_err(),
                "a replayed INIT must not receive a new handshake response");
        }

        // The remote has no competing recv loop: every genuine WG packet is
        // read here to assert its actual send socket before feeding its Tunn.
        let (mut remote, mut remote_rx) = WgDevice::new(remote_key.secret.clone());
        let remote_plane = CarrierPlane::new();
        remote.set_plane(remote_plane.attach(remote.plane_hooks()));
        remote
            .add_direct_peer(far.clone(), our_pk, self_ip, local, false)
            .await;
        assert!(remote.poke_handshake(&our_pk));
        let event = tokio::time::timeout(Duration::from_secs(2), inbound.recv())
            .await
            .expect("known-src INIT on spray must reach authenticated adoption, not main probe")
            .unwrap();
        assert_eq!(event.src, src);
        assert!(Arc::ptr_eq(&event.sock, &spray));
        rt.handle_direct_inbound(
            &mut wg,
            &mut installed,
            &mut relay,
            &tun,
            &current,
            &mut probes,
            &mut bq,
            event,
        )
        .await;
        assert_eq!(probes[&node].local, Some(local));
        let adopted_identity = wg.direct_probe_identity(&pk).unwrap();
        assert_eq!(
            adopted_identity.0, old_identity.0,
            "in-place adoption must preserve the probe session index and replay state"
        );
        assert_eq!((adopted_identity.1, adopted_identity.2), (local, src));
        let mut buf = vec![0u8; 2048];
        let (n, actual) = tokio::time::timeout(Duration::from_secs(2), far.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual, local, "authenticated response must leave the spray");
        remote.feed_direct(actual, far.clone(), &buf[..n]).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while wg.probe_handshake_done(&pk) != Some(true) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("real bidirectional WireGuard handshake must latch");
        rt.sweep_upgrade_probes(
            &mut wg,
            &mut installed,
            &mut relay,
            &tun,
            &mut probes,
            &mut bq,
        )
        .await;
        assert!(installed[&node].is_direct);
        assert!(installed[&node].hs_done);
        assert_eq!(installed[&node].carrier_local, Some(local));
        assert_eq!(
            wg.direct_peer_identity(&pk),
            Some(adopted_identity),
            "promoted direct peer keeps the adopted session identity"
        );

        // Note (a) + Note (d) regression checks on the promoted direct incumbent:
        // 1) Replay accepted/older INITs from the known source onto a second live
        //    spray socket (both without and with a residual shadow probe).
        // 2) Replay accepted/older INITs from a brand-new unknown source address
        //    onto both the active socket and the second live spray socket.
        // In all cases, the installed direct session identity must remain
        // unchanged and no handshake response may be emitted.
        let spray2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local2 = spray2.local_addr().unwrap();
        let spray2_rx = wg.adopt_spray_socket(spray2.clone());
        rt.spray_locals.lock().unwrap().insert(local2);
        let attacker = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        for stale in [&accepted, &older] {
            // (a.1) Direct incumbent + replay from known src onto another live spray socket.
            far.send_to(stale, local2).await.unwrap();
            if let Ok(Some(ev)) =
                tokio::time::timeout(Duration::from_millis(120), inbound.recv()).await
            {
                rt.handle_direct_inbound(
                    &mut wg,
                    &mut installed,
                    &mut relay,
                    &tun,
                    &current,
                    &mut probes,
                    &mut bq,
                    ev,
                )
                .await;
            }
            assert_eq!(
                wg.direct_peer_identity(&pk),
                Some(adopted_identity),
                "direct incumbent identity must not change on spray replay"
            );
            assert_eq!(installed[&node].carrier_local, Some(local));
            assert_eq!(installed[&node].carrier_dst, Some(src));
            assert!(
                tokio::time::timeout(Duration::from_millis(80), far.recv_from(&mut wire))
                    .await
                    .is_err(),
                "spray replay against direct incumbent must not emit a handshake response"
            );

            // (a.2a) Direct incumbent WITH a same-source residual shadow probe
            // (clobbering by_src[(engine, src)] to probing=true on `main`) +
            // replay onto spray2: CarrierPlane forwards to handle_direct_inbound,
            // which must drop the residual probe and heal by_src without manual cleanup.
            wg.start_direct_probe(main.clone(), pk, ip, src, false)
                .await;
            probes.insert(
                node,
                UpgradeProbe {
                    pubkey: pk,
                    overlay_ip: ip,
                    dst: src,
                    tier: DirectTier::Lan,
                    since: Instant::now(),
                    initiated: false,
                    local: main.local_addr().ok(),
                },
            );
            far.send_to(stale, local2).await.unwrap();
            let ev_a2a = tokio::time::timeout(Duration::from_secs(1), inbound.recv())
                .await
                .expect("same-source residual probe on main must forward spray2 INIT to runtime")
                .unwrap();
            rt.handle_direct_inbound(
                &mut wg,
                &mut installed,
                &mut relay,
                &tun,
                &current,
                &mut probes,
                &mut bq,
                ev_a2a,
            )
            .await;
            assert!(
                !probes.contains_key(&node) && !wg.has_direct_probe(&pk),
                "handle_direct_inbound must drop same-source residual probe beside direct incumbent"
            );
            assert_eq!(
                wg.direct_peer_identity(&pk),
                Some(adopted_identity),
                "same-source residual probe beside direct incumbent must not replace direct session"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(80), far.recv_from(&mut wire))
                    .await
                    .is_err(),
                "replay with same-source residual probe must not emit a handshake response"
            );

            // (a.2b) Direct incumbent WITH a different-source residual shadow probe
            // + replay from that source onto spray2: handle_direct_inbound must
            // drop the residual probe, heal the installed peer's reverse entry,
            // and reject the replayed INIT against the installed Tunn.
            let attacker_src = attacker.local_addr().unwrap();
            wg.start_direct_probe(main.clone(), pk, ip, attacker_src, false)
                .await;
            probes.insert(
                node,
                UpgradeProbe {
                    pubkey: pk,
                    overlay_ip: ip,
                    dst: attacker_src,
                    tier: DirectTier::Lan,
                    since: Instant::now(),
                    initiated: false,
                    local: main.local_addr().ok(),
                },
            );
            attacker.send_to(stale, local2).await.unwrap();
            let ev_a2b = tokio::time::timeout(Duration::from_secs(1), inbound.recv())
                .await
                .expect("different-source residual probe on main must forward spray2 INIT to runtime")
                .unwrap();
            rt.handle_direct_inbound(
                &mut wg,
                &mut installed,
                &mut relay,
                &tun,
                &current,
                &mut probes,
                &mut bq,
                ev_a2b,
            )
            .await;
            assert!(
                !probes.contains_key(&node) && !wg.has_direct_probe(&pk),
                "handle_direct_inbound must drop different-source residual probe beside direct incumbent"
            );
            assert_eq!(
                wg.direct_peer_identity(&pk),
                Some(adopted_identity),
                "different-source residual probe beside direct incumbent must not replace direct session"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(80), attacker.recv_from(&mut wire))
                    .await
                    .is_err(),
                "replay with different-source residual probe must not emit a handshake response"
            );

            // (d) Intercepted INIT replayed from an unknown source address.
            attacker.send_to(stale, local).await.unwrap();
            if let Ok(Some(ev)) =
                tokio::time::timeout(Duration::from_millis(150), inbound.recv()).await
            {
                rt.handle_direct_inbound(
                    &mut wg,
                    &mut installed,
                    &mut relay,
                    &tun,
                    &current,
                    &mut probes,
                    &mut bq,
                    ev,
                )
                .await;
            }
            assert_eq!(
                wg.direct_peer_identity(&pk),
                Some(adopted_identity),
                "unknown-source replayed INIT must not tear down or repoint the direct session"
            );
            assert_eq!(installed[&node].carrier_local, Some(local));
            assert_eq!(installed[&node].carrier_dst, Some(src));
            assert!(
                tokio::time::timeout(Duration::from_millis(80), attacker.recv_from(&mut wire))
                    .await
                    .is_err(),
                "unknown-source replayed INIT must not receive a handshake response"
            );
        }
        rt.spray_locals.lock().unwrap().remove(&local2);
        wg.release_spray_socket(local2, spray2_rx);

        let mut a = attempt(Role::Hard);
        a.peer_pub = pk;
        a.overlay_ip = ip;
        a.sprays.push(Spray {
            sock: spray,
            local,
            rx: spray_rx,
        });
        let mut engine = Engine::default();
        engine.active.insert(node, a);
        engine
            .finish_due(
                &rt,
                &mut wg,
                &installed,
                &mut probes,
                Instant::now() + WINDOW,
            )
            .await;
        assert!(engine.active.is_empty());
        assert_eq!(engine.kept.len(), 1);
        assert!(
            !engine.kept[0].rx.as_ref().unwrap().is_finished(),
            "actual spray receiver survives birthday end"
        );

        let mut payload = vec![0u8; 1024];
        rand::rng().fill(&mut payload[..]);
        let packet = synthetic_ipv4(self_ip, ip, &payload);
        assert!(wg.send_ip_packet(&packet).await);
        let got = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    p = remote_rx.recv() => break p.unwrap(),
                    p = far.recv_from(&mut buf) => {
                        let (n, actual) = p.unwrap();
                        assert_eq!(actual, local, "promoted data/timer must use the authenticated socket");
                        remote.feed_direct(actual, far.clone(), &buf[..n]).await;
                    }
                }
            }
        }).await.unwrap();
        assert_eq!(got, packet);
        payload.reverse();
        let back = synthetic_ipv4(ip, self_ip, &payload);
        assert!(remote.send_ip_packet(&back).await);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), ours_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            back
        );
        // Genuine roam from a new source socket with a strictly newer TAI64N
        // INIT repoints the direct peer in-place without changing its session
        // index.
        tokio::time::sleep(Duration::from_millis(2)).await;
        let roamed_far = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let roamed_src = roamed_far.local_addr().unwrap();
        let fresh_roam_init = crate::overlay::wg::test_genuine_init(&remote_key.secret, our_pk);
        roamed_far.send_to(&fresh_roam_init, local).await.unwrap();
        let roam_ev = tokio::time::timeout(Duration::from_secs(2), inbound.recv())
            .await
            .expect("fresh unknown-source INIT must reach handle_direct_inbound")
            .unwrap();
        assert_eq!(roam_ev.src, roamed_src);
        rt.handle_direct_inbound(
            &mut wg,
            &mut installed,
            &mut relay,
            &tun,
            &current,
            &mut probes,
            &mut bq,
            roam_ev,
        )
        .await;
        let roamed_identity = wg.direct_peer_identity(&pk).unwrap();
        assert_eq!(
            roamed_identity.0, adopted_identity.0,
            "genuine unknown-source roam INIT must preserve the installed session index"
        );
        assert_eq!((roamed_identity.1, roamed_identity.2), (local, roamed_src));
        assert_eq!(installed[&node].carrier_dst, Some(roamed_src));
        let (rn, rfrom) = tokio::time::timeout(Duration::from_secs(2), roamed_far.recv_from(&mut wire))
            .await
            .expect("fresh unknown-source INIT must receive a handshake response")
            .unwrap();
        assert_eq!(rfrom, local);
        assert_eq!((rn, &wire[..4]), (92, &[2, 0, 0, 0][..]));

        // Retire exactly this peer and the retained birthday receive task.
        wg.remove_peer(&pk).await;
        remote.remove_peer(&our_pk).await;
        installed.clear();
        engine.reset(&rt, &mut wg).await;
        main_rx.abort();
    }

    #[test]
    fn only_a_symmetric_cone_pair_sprays() {
        assert_eq!(role(Some("symmetric"), Some("cone")), Some(Role::Hard));
        assert_eq!(role(Some("cone"), Some("symmetric")), Some(Role::Easy));
        assert_eq!(role(Some("cone"), Some("cone")), None);
        assert_eq!(role(Some("symmetric"), Some("symmetric")), None);
        assert_eq!(role(None, Some("symmetric")), None);
        assert_eq!(role(Some("symmetric"), None), None);
    }

    #[test]
    fn both_ends_compute_the_same_phase() {
        let a = [7u8; 32];
        let mut b = [7u8; 32];
        b[31] = 9;
        assert_eq!(pair_phase(&a, &b), pair_phase(&b, &a));
        assert!(pair_phase(&a, &b) < SLOT);
    }

    #[test]
    fn slots_start_at_the_phase() {
        assert_eq!(slot_of(1000 * SLOT + 17, 17), (1000, 0));
        assert_eq!(slot_of(1000 * SLOT + 20, 17), (1000, 3));
        assert_eq!(slot_of(1000 * SLOT + 16, 17), (999, SLOT - 1));
        assert_eq!(slot_of(3, 17), (0, 0));
    }

    #[test]
    fn a_more_failed_end_attempts_on_a_subset_of_the_others_slots() {
        for hi in 0..=MAX_BACKOFF_EXP + 2 {
            for lo in 0..=hi {
                for slot in 0..512u64 {
                    if attempts_in(slot, hi) {
                        assert!(
                            attempts_in(slot, lo),
                            "slot {slot}: {hi} attempts, {lo} does not"
                        );
                    }
                }
            }
        }
        assert!((0..8).all(|s| attempts_in(s, 0)));
        assert_eq!((0..64).filter(|s| attempts_in(*s, 3)).count(), 8);
        assert_eq!(
            (0..1024).filter(|s| attempts_in(*s, 50)).count(),
            1024 >> MAX_BACKOFF_EXP,
            "the backoff is capped"
        );
    }

    #[test]
    fn probe_ports_lead_with_the_neighbours_of_known_mappings() {
        let mut rng = rand::rng();
        let ports = probe_ports(&[40000, 65500], EASY_PROBES, &mut rng);
        assert_eq!(ports.len(), EASY_PROBES);
        assert_eq!(&ports[..3], &[40001, 40002, 40003]);
        assert_eq!(ports[EASY_NEAR_HINT as usize - 1], 40000 + EASY_NEAR_HINT);
        // 65500 + 1..=35 fit; the rest of that run would overflow.
        assert_eq!(ports[EASY_NEAR_HINT as usize], 65501);
        assert_eq!(ports[EASY_NEAR_HINT as usize + 34], 65535);
        let distinct: HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(distinct.len(), ports.len(), "no port twice");
        assert!(ports.iter().all(|p| *p >= 1024));
        // Low hints never yield a privileged port.
        let low = probe_ports(&[1000], 70, &mut rng);
        assert!(low.iter().all(|p| *p >= 1024));
        assert_eq!(low.len(), 70);
    }

    #[test]
    fn independent_random_port_model_has_the_expected_overlap() {
        // Synthetic port overlap only: this does not model NAT tuples,
        // filtering, authentication, WireGuard or application delivery.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xb17d);
        let trials = 400;
        let mut hits = 0;
        for _ in 0..trials {
            let mapped: HashSet<u16> = (0..HARD_SOCKETS)
                .map(|_| rng.random_range(1024..=65535u16))
                .collect();
            let ports = probe_ports(&[], EASY_PROBES, &mut rng);
            if ports.iter().any(|p| mapped.contains(p)) {
                hits += 1;
            }
        }
        assert!(hits * 100 >= trials * 95, "{hits}/{trials}");
    }

    fn attempt(role: Role) -> Attempt {
        Attempt {
            role,
            peer_pub: [7; 32],
            overlay_ip: "100.64.0.7".parse().unwrap(),
            punch: std::sync::Weak::new(),
            my_srflx: String::new(),
            probe: None,
            target: "45.77.1.2:45210".parse().unwrap(),
            nonce: [9; 8],
            ends: Instant::now() + WINDOW,
            task: tokio::spawn(std::future::pending()),
            stop: Arc::new(AtomicBool::new(false)),
            sprays: Vec::new(),
            hit: None,
            probing: false,
        }
    }

    #[tokio::test]
    async fn pong_must_match_peer_nonce_and_target_ip_and_only_first_hit_wins() {
        let node = ObjectId::new();
        let mut engine = Engine::default();
        engine.active.insert(node, attempt(Role::Easy));
        let pong = disco::DiscoInbound {
            sender: [7; 32],
            nonce: [9; 8],
            src: "45.77.1.2:61000".parse().unwrap(),
            at: Instant::now(),
        };
        for wrong in [
            disco::DiscoInbound {
                sender: [8; 32],
                ..pong.clone()
            },
            disco::DiscoInbound {
                nonce: [8; 8],
                ..pong.clone()
            },
            disco::DiscoInbound {
                src: "45.77.2.2:61000".parse().unwrap(),
                ..pong.clone()
            },
        ] {
            engine.on_pong(&wrong);
            assert!(engine.active[&node].hit.is_none());
            assert!(!engine.active[&node].stop.load(Ordering::Relaxed));
        }
        engine.on_pong(&pong);
        assert_eq!(engine.active[&node].hit, Some(pong.src));
        assert!(engine.active[&node].stop.load(Ordering::Relaxed));
        engine.on_pong(&disco::DiscoInbound {
            src: "45.77.1.2:62000".parse().unwrap(),
            ..pong
        });
        assert_eq!(engine.active[&node].hit.unwrap().port(), 61000);
    }

    #[tokio::test]
    async fn hard_hit_keeps_mapping_sender_running_until_attempt_finishes() {
        let node = ObjectId::new();
        let mut engine = Engine::default();
        engine.active.insert(node, attempt(Role::Hard));
        engine.on_pong(&disco::DiscoInbound {
            sender: [7; 32],
            nonce: [9; 8],
            src: "45.77.1.2:45210".parse().unwrap(),
            at: Instant::now(),
        });
        assert!(engine.active[&node].hit.is_some());
        assert!(!engine.active[&node].stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn changed_peer_key_cancels_pending_hit_before_drive() {
        let mut f = LifecycleFixture::new().await;
        f.current.get_mut(&f.node).unwrap().wg_public_key = WgKeypair::generate().public_base64();
        f.engine
            .tick(
                &f.rt,
                &mut f.wg,
                &f.current,
                &f.installed,
                &mut f.probes,
                Some(&f.ctx),
            )
            .await;
        f.assert_cancelled().await;
    }

    struct LifecycleFixture {
        rt: OverlayRuntime,
        wg: WgDevice,
        ctx: DirectCtx,
        current: HashMap<ObjectId, NetmapPeer>,
        installed: HashMap<ObjectId, Installed>,
        probes: HashMap<ObjectId, UpgradeProbe>,
        engine: Engine,
        node: ObjectId,
        sender: tokio::task::AbortHandle,
        socket: std::sync::Weak<UdpSocket>,
    }

    impl LifecycleFixture {
        async fn new() -> Self {
            let kp = WgKeypair::generate();
            let (out, _out_rx) = mpsc::channel(4);
            let rt = OverlayRuntime::new_relay(
                kp.clone(),
                out,
                Box::new(|_, _, _| unreachable!()),
                1280,
            );
            let (wg, _tun_rx) = WgDevice::new(kp.secret);
            let peer = WgKeypair::generate();
            let mut np = super::super::tests::peer(&peer, "100.64.0.7");
            np.srflx_nat = Some("cone".into());
            np.srflx_endpoints = vec!["45.77.1.2:45210".into()];
            let node = np.node_id;
            let punch = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let ctx = DirectCtx {
                socks: vec![],
                my_ips: vec![],
                endpoints: vec![],
                public_sock: None,
                punch: Some(("45.77.2.2:40000".into(), punch.clone())),
                my_nat: Some("symmetric".into()),
                v6: None,
                my_v6: vec![],
            };
            let mut inst = Installed::base(
                peer.public.to_bytes(),
                "100.64.0.7".parse().unwrap(),
                DirectTier::Srflx,
                Instant::now(),
            );
            inst.is_direct = false;
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let socket = Arc::downgrade(&sock);
            let local = sock.local_addr().unwrap();
            rt.spray_locals.lock().unwrap().insert(local);
            let rx_sock = sock.clone();
            let rx = tokio::spawn(async move {
                let mut buf = [0; 1];
                let _ = rx_sock.recv_from(&mut buf).await;
            });
            let mut a = attempt(Role::Hard);
            a.task.abort();
            let tx_sock = sock.clone();
            a.task = tokio::spawn(async move {
                let _held = tx_sock;
                std::future::pending::<()>().await;
            });
            let sender = a.task.abort_handle();
            a.peer_pub = peer.public.to_bytes();
            a.punch = Arc::downgrade(&punch);
            a.my_srflx = ctx.punch.as_ref().unwrap().0.clone();
            a.hit = Some("45.77.1.2:61000".parse().unwrap());
            a.sprays.push(Spray {
                sock,
                local,
                rx: Some(rx),
            });
            let mut engine = Engine::default();
            engine.active.insert(node, a);
            Self {
                rt,
                wg,
                ctx,
                current: HashMap::from([(node, np)]),
                installed: HashMap::from([(node, inst)]),
                probes: HashMap::new(),
                engine,
                node,
                sender,
                socket,
            }
        }

        async fn reconcile(&mut self) {
            self.engine
                .reconcile(
                    &self.rt,
                    &mut self.wg,
                    &self.current,
                    &self.installed,
                    &mut self.probes,
                    Some(&self.ctx),
                )
                .await;
        }

        async fn assert_cancelled(&self) {
            assert!(
                self.engine.active.is_empty(),
                "stale attempt must not reach drive/promotion"
            );
            assert!(self.rt.spray_locals.lock().unwrap().is_empty());
            tokio::time::timeout(Duration::from_secs(1), async {
                while !self.sender.is_finished() || self.socket.strong_count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cancelled sender/receiver must release their actual socket");
        }
    }

    #[tokio::test]
    async fn key_policy_remove_and_plane_replacement_cancel_real_owned_tasks() {
        for change in [
            "key", "force", "trial", "remove", "plane", "overlay", "backbone", "target",
        ] {
            let mut f = LifecycleFixture::new().await;
            match change {
                "key" => {
                    f.current.get_mut(&f.node).unwrap().wg_public_key =
                        WgKeypair::generate().public_base64()
                }
                "force" => {
                    f.rt.shadow(|s| {
                        s.mon
                            .on_forced_derp(&f.node, Duration::from_secs(60), Instant::now())
                    });
                }
                "trial" => {
                    f.rt.path_trial_managed.lock().unwrap().insert(f.node);
                }
                "remove" => {
                    f.current.remove(&f.node);
                }
                "plane" => {
                    f.ctx.punch.as_mut().unwrap().1 =
                        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
                }
                "overlay" => f.current.get_mut(&f.node).unwrap().overlay_ip = "100.64.0.8".into(),
                "backbone" => f.current.get_mut(&f.node).unwrap().backbone_only = true,
                "target" => {
                    f.current.get_mut(&f.node).unwrap().srflx_endpoints =
                        vec!["45.77.1.3:45210".into()]
                }
                _ => unreachable!(),
            }
            f.reconcile().await;
            f.assert_cancelled().await;
        }
    }

    #[tokio::test]
    async fn cancelled_spray_probe_cannot_promote_but_unrelated_probe_survives() {
        for owned in [false, true] {
            let mut f = LifecycleFixture::new().await;
            let sock = if owned {
                f.engine.active[&f.node].sprays[0].sock.clone()
            } else {
                Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
            };
            let pk = f.installed[&f.node].pubkey;
            let ip = f.installed[&f.node].overlay_ip;
            let dst = "127.0.0.1:9".parse().unwrap();
            if owned {
                // This fixture is a device-mode demux, not a plane receiver.
                f.engine.active.get_mut(&f.node).unwrap().sprays[0]
                    .rx
                    .take()
                    .unwrap()
                    .abort();
            }
            f.wg.ensure_direct_demux(sock.clone());
            f.wg.start_direct_probe(sock.clone(), pk, ip, dst, false)
                .await;
            f.probes.insert(
                f.node,
                UpgradeProbe {
                    pubkey: pk,
                    overlay_ip: ip,
                    dst,
                    tier: DirectTier::Srflx,
                    since: Instant::now(),
                    initiated: false,
                    local: sock.local_addr().ok(),
                },
            );
            drop(sock);
            f.rt.path_trial_managed.lock().unwrap().insert(f.node);
            f.reconcile().await;
            assert_eq!(f.probes.contains_key(&f.node), !owned);
            assert_eq!(f.wg.has_direct_probe(&pk), !owned);
            f.assert_cancelled().await;
            if !owned {
                f.wg.drop_direct_probe(&pk).await;
            }
        }
    }

    #[tokio::test]
    async fn unrelated_netmap_fields_preserve_attempt_and_carrier_socket() {
        let mut f = LifecycleFixture::new().await;
        let p = f.current.get_mut(&f.node).unwrap();
        p.name = "renamed".into();
        p.endpoints = vec!["127.0.0.1:9999".into()];
        p.supports_derp = true;
        f.reconcile().await;
        assert!(f.engine.active.contains_key(&f.node));
        assert!(!f.sender.is_finished());
        // Once promoted, cancellation still keeps the socket the carrier uses.
        let local = f.engine.active[&f.node].sprays[0].local;
        f.installed.get_mut(&f.node).unwrap().carrier_local = Some(local);
        f.installed.get_mut(&f.node).unwrap().is_direct = true;
        f.current.remove(&f.node);
        f.reconcile().await;
        assert_eq!(f.engine.kept.len(), 1);
        assert!(f.socket.strong_count() > 0);
        f.installed.clear();
        f.reconcile().await;
        f.assert_cancelled().await;
    }

    #[tokio::test]
    async fn expired_window_keeps_owned_pending_probe_until_real_handshake_completes() {
        let mut f = LifecycleFixture::new().await;
        let remote_key = WgKeypair::generate();
        let remote_pk = remote_key.public.to_bytes();
        f.current.get_mut(&f.node).unwrap().wg_public_key = remote_key.public_base64();
        f.installed.get_mut(&f.node).unwrap().pubkey = remote_pk;
        f.engine.active.get_mut(&f.node).unwrap().peer_pub = remote_pk;
        let local = f.engine.active[&f.node].sprays[0].sock.clone();
        f.engine.active.get_mut(&f.node).unwrap().sprays[0]
            .rx
            .take()
            .unwrap()
            .abort();
        f.wg.ensure_direct_demux(local.clone());
        let far = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = far.local_addr().unwrap();
        let since = Instant::now() - Duration::from_secs(2);
        f.wg.start_direct_probe(
            local.clone(),
            remote_pk,
            f.installed[&f.node].overlay_ip,
            dst,
            false,
        )
        .await;
        f.probes.insert(
            f.node,
            UpgradeProbe {
                pubkey: remote_pk,
                overlay_ip: f.installed[&f.node].overlay_ip,
                dst,
                tier: DirectTier::Srflx,
                since,
                initiated: false,
                local: local.local_addr().ok(),
            },
        );
        let a = f.engine.active.get_mut(&f.node).unwrap();
        a.ends = since + Duration::from_secs(1);
        a.probe = Some((since, dst, local.local_addr().ok()));
        let local_addr = local.local_addr().unwrap();
        drop(local);
        f.engine
            .tick(
                &f.rt,
                &mut f.wg,
                &f.current,
                &f.installed,
                &mut f.probes,
                Some(&f.ctx),
            )
            .await;
        assert!(
            f.wg.has_direct_probe(&remote_pk),
            "attempt deadline must not cancel a live owned probe"
        );
        assert!(
            f.engine.active.contains_key(&f.node),
            "retain identity guard while the probe converges"
        );
        assert_eq!(f.engine.peers.get(&f.node).map_or(0, |p| p.failures), 0);
        let local_pk = f.rt.keypair.public.to_bytes();
        let (mut remote, _remote_rx) = WgDevice::new(remote_key.secret.clone());
        remote.ensure_direct_demux(far.clone());
        remote
            .add_direct_peer(
                far,
                local_pk,
                "100.64.0.1".parse().unwrap(),
                local_addr,
                false,
            )
            .await;
        assert!(remote.poke_handshake(&local_pk));
        tokio::time::timeout(Duration::from_secs(2), async {
            while f.wg.probe_handshake_done(&remote_pk) != Some(true) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("preserved probe must complete a real WireGuard exchange");
        assert!(f.wg.promote_direct_probe(&remote_pk));
        f.probes.remove(&f.node);
        let carrier = f.installed.get_mut(&f.node).unwrap();
        carrier.is_direct = true;
        carrier.carrier_local = Some(local_addr);
        f.engine
            .tick(
                &f.rt,
                &mut f.wg,
                &f.current,
                &f.installed,
                &mut f.probes,
                Some(&f.ctx),
            )
            .await;
        assert!(f.engine.active.is_empty());
        assert_eq!(
            f.engine.kept.len(),
            1,
            "the actual promoted carrier keeps its socket"
        );
        f.wg.remove_peer(&remote_pk).await;
        f.installed.clear();
        f.reconcile().await;
        f.assert_cancelled().await;
        remote.remove_peer(&local_pk).await;
    }

    #[tokio::test]
    async fn retained_pending_probe_still_revokes_on_policy_or_its_own_deadline() {
        for expire in [false, true] {
            let mut f = LifecycleFixture::new().await;
            let pk = f.installed[&f.node].pubkey;
            let sock = f.engine.active[&f.node].sprays[0].sock.clone();
            f.engine.active.get_mut(&f.node).unwrap().sprays[0]
                .rx
                .take()
                .unwrap()
                .abort();
            f.wg.ensure_direct_demux(sock.clone());
            let dst = "127.0.0.1:9".parse().unwrap();
            let since = Instant::now() - Duration::from_secs(if expire { 21 } else { 2 });
            f.wg.start_direct_probe(
                sock.clone(),
                pk,
                f.installed[&f.node].overlay_ip,
                dst,
                false,
            )
            .await;
            f.probes.insert(
                f.node,
                UpgradeProbe {
                    pubkey: pk,
                    overlay_ip: f.installed[&f.node].overlay_ip,
                    dst,
                    tier: DirectTier::Srflx,
                    since,
                    initiated: false,
                    local: sock.local_addr().ok(),
                },
            );
            let a = f.engine.active.get_mut(&f.node).unwrap();
            a.ends = since + Duration::from_secs(1);
            a.probe = Some((since, dst, sock.local_addr().ok()));
            drop(sock);
            f.engine
                .tick(
                    &f.rt,
                    &mut f.wg,
                    &f.current,
                    &f.installed,
                    &mut f.probes,
                    Some(&f.ctx),
                )
                .await;
            if !expire {
                assert!(f.wg.has_direct_probe(&pk));
                f.rt.shadow(|s| {
                    s.mon
                        .on_forced_derp(&f.node, Duration::from_secs(60), Instant::now())
                });
                f.engine
                    .tick(
                        &f.rt,
                        &mut f.wg,
                        &f.current,
                        &f.installed,
                        &mut f.probes,
                        Some(&f.ctx),
                    )
                    .await;
            }
            assert!(!f.wg.has_direct_probe(&pk));
            assert!(f.probes.is_empty());
            assert!(
                !f.installed[&f.node].is_direct,
                "failed/revoked probe must preserve the incumbent"
            );
            f.assert_cancelled().await;
        }
    }

    #[tokio::test]
    async fn late_hit_after_window_cannot_start_a_fresh_probe() {
        let mut f = LifecycleFixture::new().await;
        f.ctx.my_nat = Some("cone".into());
        f.current.get_mut(&f.node).unwrap().srflx_nat = Some("symmetric".into());
        let a = f.engine.active.get_mut(&f.node).unwrap();
        a.role = Role::Easy;
        a.ends = Instant::now() - Duration::from_secs(1);
        a.hit = Some("127.0.0.1:9".parse().unwrap());
        let stale_tick = a.ends - Duration::from_secs(1);
        f.engine
            .drive(
                &f.rt,
                &mut f.wg,
                &f.current,
                &f.installed,
                &mut f.probes,
                Some(&f.ctx),
                stale_tick,
            )
            .await;
        assert!(
            f.probes.is_empty(),
            "a stale tick timestamp cannot extend the window"
        );
        f.engine
            .tick(
                &f.rt,
                &mut f.wg,
                &f.current,
                &f.installed,
                &mut f.probes,
                Some(&f.ctx),
            )
            .await;
        assert!(f.probes.is_empty());
        assert_eq!(f.wg.probe_count(), 0);
        f.assert_cancelled().await;
    }

    #[tokio::test]
    async fn retained_budget_skips_without_binding_or_evicting_live_sockets() {
        let mut f = LifecycleFixture::new().await;
        f.engine.reset(&f.rt, &mut f.wg).await;
        f.assert_cancelled().await;
        for _ in 0..MAX_OWNED_SOCKETS {
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            f.engine.kept.push(Spray {
                local: sock.local_addr().unwrap(),
                sock,
                rx: None,
            });
        }
        let survivor = Arc::downgrade(&f.engine.kept[0].sock);
        let v = f.engine.open_hard_sprays(&f.rt, &mut f.wg, || {
            panic!("budget exhausted: must not bind")
        });
        assert!(v.is_empty());
        assert!(
            survivor.upgrade().is_some(),
            "existing carrier resources cannot be evicted"
        );
        f.engine
            .kept
            .truncate(MAX_OWNED_SOCKETS - HARD_MIN_SOCKETS + 1);
        assert!(
            f.engine
                .open_hard_sprays(&f.rt, &mut f.wg, || panic!(
                    "less than minimum: must not bind"
                ))
                .is_empty()
        );
        f.engine.kept.truncate(MAX_OWNED_SOCKETS - HARD_MIN_SOCKETS);
        let sprays = f.engine.open_hard_sprays(&f.rt, &mut f.wg, || {
            bind_spray(IpAddr::V4(Ipv4Addr::LOCALHOST))
        });
        assert_eq!(
            sprays.len(),
            HARD_MIN_SOCKETS,
            "allocation is clamped to the remaining budget"
        );
        let mut a = attempt(Role::Hard);
        a.sprays = sprays;
        f.engine.active.insert(f.node, a);
        assert_eq!(f.engine.owned_sockets(), MAX_OWNED_SOCKETS);
        assert!(
            f.engine
                .open_hard_sprays(&f.rt, &mut f.wg, || panic!(
                    "retained plus active exhausts budget"
                ))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn partial_bind_failure_releases_every_allocated_socket_and_receive_task() {
        let mut f = LifecycleFixture::new().await;
        f.engine.reset(&f.rt, &mut f.wg).await;
        f.assert_cancelled().await;
        let mut weak = Vec::new();
        let sprays = f.engine.open_hard_sprays(&f.rt, &mut f.wg, || {
            if weak.len() == 3 {
                return Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory));
            }
            let sock = bind_spray(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
            weak.push(Arc::downgrade(&sock));
            Ok(sock)
        });
        assert!(sprays.is_empty(), "below minimum: no partial attempt");
        assert!(f.rt.spray_locals.lock().unwrap().is_empty());
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.iter().any(|s| s.strong_count() > 0) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("partial receive tasks must actually release their FDs");
        assert_eq!(f.engine.owned_sockets(), 0);
    }

    #[tokio::test]
    async fn repeated_cancellation_counts_pending_socket_owners_until_they_exit() {
        for _ in 0..16 {
            let mut f = LifecycleFixture::new().await;
            f.engine.reset(&f.rt, &mut f.wg).await;
            assert_eq!(
                f.engine.owned_sockets(),
                usize::from(f.socket.strong_count() > 0)
            );
            f.assert_cancelled().await;
            assert_eq!(f.engine.owned_sockets(), 0);
        }
    }

    #[tokio::test]
    async fn dropping_engine_aborts_its_sender_and_active_and_kept_receivers() {
        let mut engine = Engine::default();
        let mut active = attempt(Role::Hard);
        let sender = active.task.abort_handle();
        let mut receivers = Vec::new();
        let mut sockets = Vec::new();
        for kept in [false, true] {
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            sockets.push(Arc::downgrade(&sock));
            let rx_sock = sock.clone();
            let rx = tokio::spawn(async move {
                let _held = rx_sock;
                std::future::pending::<()>().await;
            });
            receivers.push(rx.abort_handle());
            let spray = Spray {
                local: sock.local_addr().unwrap(),
                sock,
                rx: Some(rx),
            };
            if kept {
                engine.kept.push(spray);
            } else {
                active.sprays.push(spray);
            }
        }
        engine.active.insert(ObjectId::new(), active);
        drop(engine);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !sender.is_finished() || receivers.iter().any(|r| !r.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all owned tasks must observe cancellation");
        assert!(
            sockets.iter().all(|s| s.upgrade().is_none()),
            "no receive-task socket retained"
        );
    }

    #[test]
    fn only_a_public_v4_srflx_is_a_target() {
        let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            first_public_v4(&l(&["10.0.0.2:5", "[2001:db8::1]:5", " 45.77.1.2:6000 "])),
            Some("45.77.1.2:6000".parse().unwrap())
        );
        assert_eq!(first_public_v4(&l(&["192.168.1.2:5", "junk"])), None);
    }
}
