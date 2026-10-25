// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Overlay node runtime (Phase 3b).
//!
//! Drives one node's membership in the overlay mesh: announces itself
//! (`rc:overlay.join`), applies the server's netmap (install / drop a
//! WireGuard peer per entry), brings up the TUN, and pumps packets
//! between the TUN and the [`WgDevice`](super::wg::WgDevice).
//!
//! The runtime **owns** the `WgDevice` and runs a single `select!` loop of
//! pure CONTROL work (netmap installs, carrier health sweeps, relay
//! coordination, route guard). The DATA PLANE is fully off-loop (P1/S6):
//! outbound rides the persistent TUN reader task → mpsc → the dedicated
//! outbound pump (a [`WgSender`](super::wg::WgSender) clone — the shared
//! send half of the device, single-writer/multi-reader); inbound rides the
//! per-peer recv tasks / shared demux → mpsc → the inbound writer task.
//! No control handler can therefore ever delay a packet; `warn_if_slow`
//! remains as the tripwire against re-coupling.
//!
//! Carrier construction (direct UDP vs coturn relay) is delegated to a
//! [`LinkFactory`] so this orchestration is testable with loopback
//! carriers + a mock TUN, and so the corp-NAT relay path can be added
//! without reworking the runtime.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use bson::oid::ObjectId;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use super::WgKeypair;
use super::direct;
use super::dns;
use super::hosts as dns_hosts;
use super::netmap::{PeerConfig, peer_config_from_netmap};
use super::relay_link::{ReadyLink, RelayCoordinator, RelayKind};
use super::tun::TunIo;
use super::wg::{
    Carrier, QUIC_BUILD_TIMEOUT, QUIC_UPGRADE_DEADLINE, QUIC_UPGRADE_RETRY_GAP, WG_OVERHEAD,
    WgDevice, overlay_quic_enabled,
};
use crate::localapi::{
    ConnectionType, DnsStatus, ExitNodeStatus, OverlayView, PathProbe, PeerCarrierDebug, PeerInfo,
    PeerWhy, TierWhy,
};
use crate::transport::derp::DerpMux;
use roomler_ai_remote_control::signaling::{ClientMsg, IceServer, NetmapPeer, OverlayNetworkInfo};

// rc.284 — the god-file split. The establishment half, the inbound-adopt
// handler, and the route-ownership/exit-routing half live in CHILD modules of
// `runtime` (not siblings), so the moved code keeps private-field access to
// [`OverlayRuntime`]/[`Installed`] and its `use super::*` inherits this import
// block unchanged — a pure move, no behavior change.
mod establish;
mod inbound;
mod path_trial;
#[cfg(feature = "path-trial-test-support")]
#[doc(hidden)]
pub use path_trial::test_support::{
    Harness as PathTrialTestHarness, Snapshot as PathTrialTestSnapshot,
};
mod route_guard;
#[cfg(test)]
mod failover_bench;

use establish::*;
// §6 item 5 — the carrier plane binds and advertises the IPv6 socket the same way.
pub(in crate::overlay) use establish::{bind_v6_direct, refresh_v6_adverts, v6_adverts};
// Path-compat re-export: `tun.rs` purge names these as
// `crate::overlay::runtime::SPLIT_DEFAULT_V4`/`_V6`.
use route_guard::*;
pub(crate) use route_guard::{SPLIT_DEFAULT_V4, SPLIT_DEFAULT_V6};

// P2 — `DirectTier`, the lifecycle deadlines/constants, and the carrier/probe
// transition fns live in the sibling `lifecycle` module (one place for every
// rule that can kill a carrier). Glob-imported so this module — and its test
// module's `use super::*` — reads them unchanged.
use super::lifecycle::*;
// P3 PR-A — the PathMonitor (measured path selection) runs in SHADOW next to
// the legacy cooldown machinery below: fed the same evidence, asked the same
// questions, compared, never obeyed. See `PathShadow`.
use super::path;

/// P3 PR-A — the shadow harness around [`path::PathMonitor`]: the monitor +
/// the divergence bookkeeping the 48 h soak gate reads. Owned by
/// [`OverlayRuntime`] behind a `std::sync::Mutex` so the sweep/install
/// surfaces (whose signatures are frozen by the timer-parity tests) can feed
/// it through `&self`; every access goes through [`OverlayRuntime::shadow`],
/// which locks, runs a SYNC closure, and drops the guard — the guard can
/// never be held across an await by construction.
struct PathShadow {
    mode: path::PathMonMode,
    /// B2 — score-driven demotion engagement (off | shadow | on;
    /// default ON since the clean rc.296 shadow soak).
    demote: path::DemoteMode,
    /// B3 — mid-tier upward probing (`OVERLAY_UPWARD_PROBE`, default
    /// on): srflx/public incumbents probe an eligible higher tier every
    /// ≥120 s via the same MBB machinery.
    upward: bool,
    mon: path::PathMonitor,
    stats: path::ShadowStats,
    /// Per-peer divergence-warn rate limit (1/min/peer).
    last_div_log: HashMap<ObjectId, Instant>,
    /// B2 — per-peer shadow-demote log rate limit (1/min/peer; the
    /// deficit is sustained by definition, so unthrottled it would fire
    /// every evaluation tick).
    last_demote_log: HashMap<ObjectId, Instant>,
    /// Last 10-minute summary emission.
    last_summary: Instant,
    /// Harmful-class ledger: (peer, tier) the monitor refused while legacy
    /// proceeded. If legacy then PROVES the tier (probe latch / healthy rx)
    /// within [`SHADOW_HARM_WINDOW`], the refusal was harmful — the
    /// acceptance gate requires zero of these.
    refused: HashMap<(ObjectId, DirectTier), Instant>,
}

/// A monitor refusal contradicted by a legacy establishment within this
/// window counts as the HARMFUL divergence class.
const SHADOW_HARM_WINDOW: Duration = Duration::from_secs(60);
/// Shadow summary cadence.
const SHADOW_SUMMARY_EVERY: Duration = Duration::from_secs(600);

/// B1 — RTT→Q ingestion gate (config `overlay_rtt_q`, env
/// `ROOMLERD_OVERLAY_RTT_Q`). Default ON; a kill switch only —
/// samples are Q-plane-only either way, never eligibility.
fn rtt_q_enabled() -> bool {
    crate::env::flag("OVERLAY_RTT_Q", true)
}

impl PathShadow {
    fn new() -> Self {
        let mode = path::PathMonMode::parse(crate::env::node_env("OVERLAY_PATHMON").as_deref());
        if mode != path::PathMonMode::On {
            // PR-E — the legacy selection machinery is deleted; there is no
            // shadow/off SELECTION to revert to any more. One startup warn so
            // an operator holding the old env understands what it now does.
            warn!(
                mode = mode.as_str(),
                "overlay pathmon: legacy selection removed (PR-E) — this mode now affects telemetry only; selection is always the monitor (rollback = deploy a pre-PR-E release)"
            );
        }
        let demote = path::DemoteMode::parse(crate::env::node_env("OVERLAY_DEMOTE").as_deref());
        let upward = crate::env::flag("OVERLAY_UPWARD_PROBE", true);
        // §6.3 F3 kill switch: `OVERLAY_FAST_RETURN=0` restores the pre-F3
        // return-to-direct pacing after a poke conviction.
        let fast_return = crate::env::flag("OVERLAY_FAST_RETURN", true);
        info!(
            demote = demote.as_str(),
            upward,
            fast_return,
            "overlay pathmon: voluntary moves armed (B2 demotion; B3 mid-tier upward probing)"
        );
        Self {
            mode,
            demote,
            upward,
            mon: path::PathMonitor::with_fast_return(fast_return)
                .with_fast_return_lan(crate::env::flag("OVERLAY_FAST_RETURN_LAN", true))
                .with_fast_return_extend(crate::env::flag("OVERLAY_FAST_RETURN_EXTEND", true)),
            stats: path::ShadowStats::default(),
            last_div_log: HashMap::new(),
            last_demote_log: HashMap::new(),
            last_summary: Instant::now(),
            refused: HashMap::new(),
        }
    }

    /// B2 shadow — count a would-be demotion (its own `by_class` lane,
    /// `voluntary_demote:N/0`) + a rate-limited log carrying the verdict.
    fn note_shadow_demote(&mut self, peer: &ObjectId, action: path::PathAction, now: Instant) {
        let class = self
            .stats
            .by_class
            .entry("voluntary_demote")
            .or_insert((0, 0));
        class.0 += 1;
        if self
            .last_demote_log
            .get(peer)
            .is_none_or(|&t| now.duration_since(t) >= Duration::from_secs(60))
        {
            self.last_demote_log.insert(*peer, now);
            info!(
                peer = %peer, ?action,
                "overlay pathmon[demote-shadow]: sustained score deficit — would demote (not acting; rate-limited 1/min/peer)"
            );
        }
    }

    /// The tier a comparable action commits to, if any.
    fn action_tier(a: path::PathAction) -> Option<DirectTier> {
        match a {
            path::PathAction::Install(t) | path::PathAction::Probe(t) => Some(t),
            path::PathAction::Keep | path::PathAction::Relay => None,
        }
    }

    /// Record one legacy-vs-monitor comparison. `None` = "refuse / no
    /// decision" (the inbound gate's shape). Divergences are counted (per
    /// trigger class too — P3 PR-B: a reupgrade-tick divergence is a
    /// SCHEDULING disagreement, a netmap/delta one a selection disagreement,
    /// so the soak reads them separately), fed to the harmful ledger, and
    /// warn-logged at most once per minute per peer.
    fn compare(
        &mut self,
        surface: &'static str,
        trigger: &'static str,
        peer: &ObjectId,
        legacy: Option<path::PathAction>,
        monitor: Option<path::PathAction>,
        now: Instant,
    ) {
        self.stats.decisions += 1;
        let class = self.stats.by_class.entry(trigger).or_insert((0, 0));
        class.0 += 1;
        let diverged = match (legacy, monitor) {
            (Some(l), Some(m)) => path::classify(l, m) == path::DivergenceClass::Diverged,
            (l, m) => l != m,
        };
        if !diverged {
            return;
        }
        self.stats.diverged += 1;
        class.1 += 1;
        // Harmful ledger: legacy commits to a tier the monitor currently
        // holds ineligible (whatever the monitor proposed instead).
        if let Some(t) = legacy.and_then(Self::action_tier)
            && monitor.and_then(Self::action_tier) != Some(t)
            && !self.mon.eligible(peer, t, now)
        {
            self.refused.insert((*peer, t), now);
        }
        if self
            .last_div_log
            .get(peer)
            .is_none_or(|&t| now.duration_since(t) >= Duration::from_secs(60))
        {
            self.last_div_log.insert(*peer, now);
            info!(
                %surface, peer = %peer, ?legacy, ?monitor,
                "overlay pathmon[shadow]: decision divergence (legacy authoritative; rate-limited 1/min/peer)"
            );
        }
    }

    /// Legacy PROVED a tier for this peer (probe latched / direct carrier
    /// genuinely receiving) — grade any recent refusal as harmful.
    fn establishment(&mut self, peer: &ObjectId, tier: DirectTier, now: Instant) {
        if let Some(at) = self.refused.remove(&(*peer, tier))
            && now.duration_since(at) <= SHADOW_HARM_WINDOW
        {
            self.stats.harmful += 1;
            warn!(
                peer = %peer, ?tier,
                "overlay pathmon[shadow]: HARMFUL divergence — monitor refused a tier legacy then proved within 60 s"
            );
        }
    }

    /// Model-bug tripwire: right after the monitor booked a failure on a
    /// tier, that tier must be ineligible (the penalty math guarantees it).
    fn assert_ineligible(&mut self, peer: &ObjectId, tier: DirectTier, now: Instant) {
        if self.mon.eligible(peer, tier, now) {
            self.stats.post_death_eligible += 1;
            warn!(
                peer = %peer, ?tier,
                "overlay pathmon[shadow]: MODEL BUG — tier still eligible immediately after its failure booked"
            );
        }
    }

    /// The 10-minute rolling summary (driven from the 5 s health sweep).
    fn maybe_summary(&mut self, now: Instant) {
        // PR-E — `off` silences telemetry only (the monitor still selects).
        if self.mode == path::PathMonMode::Off {
            return;
        }
        if now.duration_since(self.last_summary) < SHADOW_SUMMARY_EVERY {
            return;
        }
        self.last_summary = now;
        // Expire stale refusals so the ledger can't grow unbounded.
        self.refused
            .retain(|_, &mut at| now.duration_since(at) <= SHADOW_HARM_WINDOW);
        info!(
            mode = self.mode.as_str(),
            demote = self.demote.as_str(),
            decisions = self.stats.decisions,
            diverged = self.stats.diverged,
            harmful = self.stats.harmful,
            post_death_eligible = self.stats.post_death_eligible,
            d10_redials = self.stats.d10_redials,
            rtt_samples = self.stats.rtt_samples,
            classes = %self.stats.classes_line(),
            "overlay pathmon: 10-min summary (soak gate: steady <0.1% diverged, harmful = 0)"
        );
    }
}

/// #26 — WHY a sweep is arming forced revalidation pokes, which is also what
/// decides the conviction window of the pokes it arms. The two net-change
/// causes are deliberately NOT one flag: their rate limits differ by 40x (one
/// Major per 120 s vs one addr/iface wave per 3 s) and so does what they imply
/// about the carriers being judged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ForcedPoke {
    /// No forced arming this sweep — only the silence / stale-proof / re-init
    /// pressure triggers.
    No,
    /// An addr/iface signal that did NOT rise to a netstate Major: a virtual
    /// adapter appearing (Docker, WSL, Hyper-V, a VPN client's TAP), a lease
    /// renewal, an interface renumber. Worth revalidating — that is why this
    /// path exists — but NOT worth the tight window. These fire up to once per
    /// `netstate::ROUTE_WAVE_MIN_INTERVAL` (3 s) against carriers that are
    /// usually perfectly healthy, and a one-round-trip verdict would demote
    /// every direct pair on the box each time an adapter blinked. Judged on the
    /// tier deadline, exactly as before #26 — an answered poke costs one
    /// handshake round and nothing else, which is the property that makes
    /// arming here harmless in the first place.
    AddrIface,
    /// A material netstate **MAJOR** — the default route moved or addresses
    /// vanished. That is the VPN-transition signature, it is the class the
    /// measured 9-and-34-dropped-ping holes belong to, and `netstate` publishes
    /// at most one per `MAJOR_PUBLISH_COOLDOWN` (120 s). Judged on
    /// [`lifecycle::MAJOR_POKE_DEADLINE`].
    Major,
}

/// Stage 2 / #26 — an in-flight active-revalidation poke: WHEN it was armed
/// and WHICH class it is. The class rides the poke rather than the carrier on
/// purpose — it decides the conviction window
/// ([`lifecycle::MAJOR_POKE_DEADLINE`] vs the tier's handshake deadline),
/// so it must be impossible for it to outlive the poke it describes. Held
/// inside the `Option` for exactly that reason: clearing the poke clears the
/// class, structurally. A parallel `bool` on `Installed` would have worked
/// too, and would have had two places to keep in sync — which is precisely
/// the shape of the rc.411/412/415/416 floor wedges, where `floored`,
/// `dialing` and `derping` each outlived the thing they described and starved
/// a peer of its carrier for hours.
#[derive(Clone, Copy, Debug)]
struct PokeArm {
    at: Instant,
    from_major: bool,
    from_business: bool,
}

/// A separate sampling baseline keeps the cheap business scout from changing
/// the health sweep's five-second one-way counters or consuming its liveness.
#[derive(Clone, Copy)]
struct BusinessTrafficSample {
    installed_at: Instant,
    traffic: (u64, u64),
    /// §6.3 F1 — the arm instant of the business proof this carrier already
    /// re-sent an initiation for (at most one re-send per proof).
    retapped: Option<Instant>,
}

/// An installed peer carrier + the bookkeeping the direct→relay fallback
/// (rc.136/137) needs.
#[derive(Clone)]
struct Installed {
    pubkey: [u8; 32],
    overlay_ip: Ipv4Addr,
    /// `true` if reached over the direct LAN socket, `false` over the relay.
    is_direct: bool,
    /// When this carrier was installed — for the warm-up grace period.
    since: Instant,
    /// Last `(tx, rx)` snapshot from the previous sweep (rc.137 lock-free
    /// health). Only meaningful for direct carriers.
    last_traffic: (u64, u64),
    /// Consecutive sweeps where we sent but received nothing (tx grew, rx
    /// flat). A few in a row ⇒ the direct carrier is one-way / dead.
    bad_sweeps: u32,
    /// Stage 2 — the active-revalidation poke (a forced WG rekey) the sweep
    /// last armed for this carrier; `None` = none pending. Cleared when the
    /// poke is answered (an initiator-role handshake completed at-or-after it
    /// — `WgDevice::peer_initiator_hs_answered`); an unanswered poke past its
    /// window is a `DeathReason::RekeyUnanswered`.
    poke: Option<PokeArm>,
    /// rc.275 honesty — the health sweep's verdict that this carrier is
    /// SILENTLY ONE-WAY: installed past the warm-up grace with either no
    /// completed WG handshake ever (the pre-handshake zombie whose tx/rx
    /// counters stay flat — winhost-a behind its corp VPN: every tier
    /// "installed", zero handshakes, `roomler peers` said `direct`/`relay`
    /// while 100% of pings died) or the rc.137 one-way strike counter
    /// accumulating. Surfaced through the LocalAPI peer view so the CLI can
    /// render `stalled` instead of a healthy-looking tier label. Verdict
    /// only — every kill/refresh decision stays in `lifecycle::carrier_tick`.
    stalled: bool,
    /// P4 — inbound packets from this peer refused by the ingress ACL
    /// (`PeerStats::rx_denied`), snapshotted by the health sweep. Monotonic.
    /// Surfaced through the LocalAPI so a `warn`-mode fleet can be READ
    /// (`roomler peers --json`) instead of grepped: the warning line is
    /// throttled to one per peer per minute, which is deliberately useless for
    /// measuring volume — and volume is exactly what decides whether `enforce`
    /// is safe to flip.
    rx_denied: u64,
    /// #22 — authenticated handshake INITIATIONS from the peer accumulated
    /// within the current [`Self::reinit_window_from`] window. A healthy
    /// peer re-initiates ~every 2 min; sustained ~5 s-cadence re-inits
    /// against an established session mean the peer cannot hear our
    /// responses (our outbound is one-way) — the sweep converts that
    /// pressure into an immediate revalidation poke instead of waiting for
    /// the slow proof-age trigger (the 08-18 zombie-leg wedge sat unheard
    /// for ~30 min on exactly this signal).
    reinit_recent: u32,
    /// Window anchor for [`Self::reinit_recent`]; reset every
    /// `REINIT_WINDOW`.
    reinit_window_from: Instant,
    /// The `Rpf(NoRoute)` subset of [`Self::rx_denied`] — sources NO installed
    /// peer owns, whose replies this node cannot route back (the multi-org
    /// wrong-source signature). Snapshotted beside it.
    rx_denied_noroute: u64,
    /// Stats PR-5 — the prober's last RTT measurement for this peer (the
    /// B1 `RttSample` events previously fed only the path-monitor Q).
    /// Published through [`build_overlay_view`] so `roomler peers` and the
    /// agent's heartbeat telemetry get a real `rtt_ms` instead of the
    /// historical hardcoded `None`.
    last_rtt_ms: Option<u32>,
    /// Monotonic instant we last HEARD from this peer — a real "last seen"
    /// (P3b-3). Seeded to `since` at install; advanced by `sweep_carrier_health`
    /// whenever the keepalive-inclusive `rx_any` liveness counter climbed since
    /// the previous sweep (rc.206 — NOT the IP-data `rx`, which stays flat on an
    /// idle-but-alive link whose only inbound is keepalives). Converted to an
    /// absolute epoch-ms `last_seen_ms` in `build_overlay_view`. Sweep cadence
    /// (`FALLBACK_TICK`, ~5 s) sets the granularity — fine for a human
    /// "Ns/Nm ago" column, and passive keepalives now keep it fresh for live
    /// peers (which is also what the rx-staleness watchdog relies on).
    last_rx_at: Instant,
    /// rc.187 — for a RELAY carrier: our own coturn-relayed address (the worker
    /// we allocated on) and the peer's relayed address we dial. `None` for a
    /// direct carrier. Surfaced in the LocalAPI `peers` view so an operator can
    /// see — without a debug-log hunt — which coturn worker each end pinned and
    /// whether a relay pair is same-worker (IPs equal) or cross-worker.
    relay_local: Option<std::net::SocketAddr>,
    relay_dst: Option<std::net::SocketAddr>,
    /// Phase A/C — for an OFF-LINK direct carrier (public-NIC dial OR srflx
    /// punch), the peer's public `ip:port` we dial (or accepted an inbound dial
    /// from). `None` for a same-LAN direct carrier or a relay carrier. It is a
    /// MANDATORY exit-node exemption — an off-link public dst is a real internet
    /// address reached via the default route, NOT on-link like a same-LAN peer,
    /// so the split-default `/1`s would capture the very path to the exit and
    /// self-wedge unless its IP is pinned via the original gateway (see
    /// [`exit_exemption_set`]). Which tier (`Public` vs `Srflx`) it is comes
    /// from [`tier`](Self::tier), not this field (both set it).
    public_direct_dst: Option<std::net::SocketAddr>,
    /// Phase C — which carrier tier this is. Drives the health sweep's tier-split
    /// cooldown (CC1) and the off-link handshake deadline. `Relay` for a coturn
    /// carrier, `Lan`/`Public`/`Srflx` for the three direct tiers.
    tier: DirectTier,
    /// rc.276 diagnostics — did WE initiate this carrier's flow (outbound dial /
    /// our own allocation), or was it adopted from an authenticated INBOUND
    /// dial (accept re-point / accepted-probe promote)? The winhost-a corp-VPN
    /// case turns on exactly this split: outbound-initiated flows are policy-
    /// dropped while inbound-accepted ones pass — and pre-rc.276 the
    /// `initiate` bit was discarded at install, so the peers view couldn't
    /// distinguish them.
    initiated: bool,
    /// rc.276 diagnostics — the sweep's latest `peer_handshake_done` read
    /// (set-once WG session latch, either role). Stamped each tick next to
    /// `stalled`; `false` until the first sweep after install.
    hs_done: bool,
    /// rc.276 diagnostics — the carrier socket's LOCAL address (for a relay
    /// carrier: the allocation's relayed address). Which socket each
    /// direction rides is the exact question the winhost-a field captures need
    /// answered.
    carrier_local: Option<std::net::SocketAddr>,
    /// rc.276 diagnostics — the carrier's send destination (direct: the dial
    /// dst or the accepted peer's observed src; relay: the peer's relayed
    /// address).
    carrier_dst: Option<std::net::SocketAddr>,
    /// Which relay flavour this carrier is; `None` for direct carriers.
    ///
    /// Started life (rc.276) as a `&'static str` label purely for the peers
    /// view. It is now also LOAD-BEARING: the DERP regrade
    /// ([`RelayCoordinator::derp_regrade_due`]) branches on it, so it is typed —
    /// a carrier decision must not hang off a debug string that a stray edit to
    /// the display label could silently change.
    relay_kind: Option<crate::overlay::relay_link::RelayKind>,
    /// The DERP incumbent remains active until this authorized ORG link
    /// proves an initiator-role WG handshake on its own private session.
    org_upgrade: Option<(ReadyLink, Instant)>,
    org_recovery_until: Option<Instant>,
    org_recovery_notified_until: Option<Instant>,
    org_recovery_needs_query: bool,
}

impl Installed {
    /// rc.279 — every field's inert default in ONE place. Install sites
    /// override only what they actually decide (`..Installed::base(…)`
    /// struct-update), so a new diagnostics field lands HERE instead of in
    /// every literal (adding `stalled`, then `initiated`, each swept ~20
    /// literals in this file and broke E0063 twice in a single session).
    /// `is_direct` is derived (`tier != Relay`) — every site agreed on that
    /// mapping, including the two that computed `tier` FROM `is_direct`.
    fn base(pubkey: [u8; 32], overlay_ip: Ipv4Addr, tier: DirectTier, now: Instant) -> Self {
        Installed {
            pubkey,
            overlay_ip,
            is_direct: !matches!(tier, DirectTier::Relay),
            since: now,
            last_traffic: (0, 0),
            bad_sweeps: 0,
            poke: None,
            stalled: false,
            initiated: false,
            hs_done: false,
            carrier_local: None,
            carrier_dst: None,
            relay_kind: None,
            org_upgrade: None,
            org_recovery_until: None,
            org_recovery_notified_until: None,
            org_recovery_needs_query: false,
            last_rtt_ms: None,
            last_rx_at: now,
            relay_local: None,
            relay_dst: None,
            public_direct_dst: None,
            rx_denied: 0,
            rx_denied_noroute: 0,
            reinit_recent: 0,
            reinit_window_from: now,
            tier,
        }
    }
}

/// Phase C (D8) — re-run the direct-upgrade evaluation every Nth fallback tick
/// (6 × [`FALLBACK_TICK`] ≈ 30 s). A lapsed suppression penalty otherwise only
/// matters when the next netmap happens to arrive, so a quiet mesh would never
/// re-attempt direct after a fallback; this drives that retry (and Phase C
/// punch convergence at large install skew) without a netmap.
const REUPGRADE_EVERY_N_TICKS: u32 = 6;
/// rc.139 — a dead RELAY carrier (one-way, same `tx>rx` signal) is usually a
/// STALE coturn port: the peer re-allocated (restart/churn → new port) and we
/// kept dialing the old one. Refresh it (re-request → fresh allocation, re-dial
/// the peer's CURRENT address) — but not more than once per this window, so two
/// ends each refreshing don't ping-pong faster than they can converge.
const RELAY_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
/// How often the carrier-health sweep runs. Cheap (lock-free atomic reads), so
/// a tighter cadence is fine and makes detection quicker.
const FALLBACK_TICK: Duration = Duration::from_secs(5);
/// F2 — how often each direct peer hears our `STANDBY_HELLO`.
const STANDBY_HELLO_EVERY: Duration = Duration::from_secs(20);
/// F2 — a proof unanswered this long starts standby copies: longer than a
/// healthy path's RTT, so a healthy one-way stream's proofs never copy.
const STANDBY_ARM_AFTER: Duration = Duration::from_millis(200);
/// F2 — while a proof is pending, the tees are re-decided this often.
const STANDBY_WATCH_TICK: Duration = Duration::from_millis(100);
/// F4 — while an upgrade probe is in flight, its latch is checked this often.
/// The responder end promotes the moment the initiator's first direct packet
/// arrives; until the initiator promotes too, its stream still rides `/derp`
/// in the relay carrier's session, which the responder has just replaced, so
/// that direction is dark for the initiator's promote lag (F0-WAN: 0–1 s, the
/// scout tick's phase).
const PROBE_WATCH_TICK: Duration = Duration::from_millis(100);
const BUSINESS_SCOUT_TICK: Duration = Duration::from_secs(1);

// This is a bounded authorization query, never a session/cache authorization.
// Discovery hints are invalidated by ordinary D0 deltas and quality cooldowns,
// so they cannot gate recovery from actual carrier loss. The server re-runs
// current policy before issuing any session or secret. Keep DERP installed.
async fn request_org_fallbacks(
    enabled: bool,
    installed: &HashMap<ObjectId, Installed>,
    peers: &HashMap<ObjectId, NetmapPeer>,
    relay: &mut Option<RelayCoordinator>,
    now: Instant,
) -> Vec<ObjectId> {
    if !enabled {
        return Vec::new();
    }
    let Some(relay) = relay.as_mut() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for (id, current) in installed {
        if current.is_direct || current.relay_kind != Some(RelayKind::Derp)
            || current.org_recovery_until.is_some_and(|until| now < until) {
            continue;
        }
        let Some(metadata) = peers.get(id).filter(|p| p.supports_org_relay) else {
            continue;
        };
        let Some(peer) = peer_config_from_netmap(metadata) else {
            continue;
        };
        if peer.public_key != current.pubkey
            || peer.overlay_ip != current.overlay_ip
        {
            continue;
        }
        candidates.push(*id);
    }
    relay.request_org_fallback_batch(candidates, now).await
}

fn reconcile_org_recovery(
    wg: &mut WgDevice, by_node: &mut HashMap<ObjectId, Installed>,
    relay: &mut Option<RelayCoordinator>, org_q: &mut OrgBindQueue,
    alloc_q: &mut RelayAllocQueue, relay_bq: &mut RelayBuildQueue,
) {
    for (nid, e) in by_node.iter_mut() {
        if let Some(until) = wg.org_recovery_until(&e.pubkey)
            && e.org_recovery_notified_until.is_none_or(|old| until > old)
        {
            e.org_recovery_until = Some(until); e.org_recovery_notified_until = Some(until);
            e.org_recovery_needs_query = true;
            e.org_upgrade = None; wg.cancel_org_upgrade(&e.pubkey);
            org_q.invalidate(nid); alloc_q.invalidate(nid); relay_bq.invalidate(nid);
            if let Some(r) = relay.as_mut() { r.org_bind_failed(nid); }
        }
    }
}
fn finish_org_recovery_queries(
    sent: Vec<ObjectId>, wg: &WgDevice, by_node: &mut HashMap<ObjectId, Installed>,
) {
    for nid in sent {
        if let Some(e) = by_node.get_mut(&nid) && wg.finish_org_recovery_query(&e.pubkey) {
            e.org_recovery_needs_query = false;
            e.org_recovery_until = None; e.org_recovery_notified_until = None;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn request_reconciled_org_fallbacks(
    enabled: bool, wg: &mut WgDevice, installed: &mut HashMap<ObjectId, Installed>,
    peers: &HashMap<ObjectId, NetmapPeer>, relay: &mut Option<RelayCoordinator>,
    org_q: &mut OrgBindQueue, alloc_q: &mut RelayAllocQueue, relay_bq: &mut RelayBuildQueue,
    now: Instant,
) -> Vec<ObjectId> {
    // A delayed main loop can resume on this tick before its scout. Discharge
    // old work first, even when the local recovery backoff already expired.
    reconcile_org_recovery(wg, installed, relay, org_q, alloc_q, relay_bq);
    let sent = request_org_fallbacks(enabled, installed, peers, relay, now).await;
    finish_org_recovery_queries(sent.clone(), wg, installed);
    sent
}

/// §6.3 F1 kill switch: `OVERLAY_BUSINESS_POKE_FAST=0` restores the pre-F1
/// business proof (one initiation, 6 s window). Read once.
fn business_poke_fast() -> bool {
    static FAST: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FAST.get_or_init(|| crate::env::flag("OVERLAY_BUSINESS_POKE_FAST", true))
}

fn business_poke_window() -> Duration {
    if business_poke_fast() {
        crate::overlay::lifecycle::BUSINESS_POKE_DEADLINE
    } else {
        crate::overlay::lifecycle::BUSINESS_POKE_LEGACY_DEADLINE
    }
}

fn business_poke_recheck(by_node: &HashMap<ObjectId, Installed>, now: Instant) -> Option<Duration> {
    let deadline = by_node.values().filter_map(|e| e.poke)
        .filter(|p| p.from_business && !p.from_major)
        .map(|p| p.at + business_poke_window()
            + Duration::from_millis(250)).min()?;
    let wait = deadline.saturating_duration_since(now).max(Duration::from_millis(100));
    (wait < FALLBACK_TICK).then_some(wait)
}

/// FR-97 P3i — how often the host firewall is asked again what it lets a mesh
/// peer reach on the adapter. Zones and rules change by hand and rarely; the
/// sweep's view publish (every [`FALLBACK_TICK`]) carries a new answer out.
const HOST_FIREWALL_REPROBE: Duration = Duration::from_secs(600);
/// #26 — after a netstate MAJOR arms the forced revalidation pokes, pull the
/// next fallback tick forward to just past
/// [`lifecycle::MAJOR_POKE_DEADLINE`] instead of letting it land wherever
/// the 5 s grid happens to be. Without this the tight window buys much less
/// than it looks: the deadline is only ever EVALUATED on a tick, so a 2 s rule
/// judged on a 5 s grid convicts somewhere in 2–7 s (mean ~4.5) purely on the
/// phase of a timer started when the runtime did.
///
/// The margin over the deadline is deliberate and must stay comfortably above
/// timer jitter: the conviction predicate is a strict `>`, so a tick landing a
/// hair early doesn't just miss — it costs a whole `FALLBACK_TICK`. Locked
/// against both bounds by `major_recheck_lands_inside_the_grid`.
///
/// Reusing the fallback interval (rather than adding a select arm) is the
/// point: conviction alone changes nothing a peer can feel, and the SAME tick
/// body is what rebuilds — `install_peers` runs right behind the sweep inside
/// the post-Major `fast_reupgrade_until` window, and the DERP floor it builds
/// is synchronous over an already-open mux. One pulled-forward tick therefore
/// convicts, re-floors and republishes in a single pass.
const MAJOR_RECHECK_AFTER: Duration = Duration::from_millis(2_250);
/// #27 — minimum spacing between demote-follows for the SAME peer. Comfortably
/// above one carrier build + handshake, so a successful follow is never
/// re-triggered by frames already in flight, and short enough that a follow
/// declined for a transient reason (mux mid-reconnect) retries promptly rather
/// than waiting out the ordinary walk.
const DERP_FOLLOW_COOLDOWN: Duration = Duration::from_secs(5);

/// #34 — how long a freshly PROMOTED direct carrier is immune to the
/// demote-follow. The peer still has its own probe → latch → cutover to
/// finish (measured 4.2-7.4 s on a healthy LAN) and is legitimately still on
/// the relay until then; without this, our own promotion is torn down by the
/// peer's in-flight relay frames in the same second, and each round books a
/// strike that escalates the hold-down toward 15 minutes.
pub(crate) const PROMOTE_FOLLOW_GRACE: Duration = Duration::from_secs(15);
/// #28 — how soon after the `/derp` WS returns to pull the establish walk in.
/// Short but not zero: the WS is registered by the time `mark_up` fires, and a
/// small delay lets a burst of reconnects (central + regional muxes coming back
/// together) coalesce into ONE walk instead of one apiece.
const DERP_RECOVERY_RECHECK: Duration = Duration::from_millis(300);
/// #28 — how long to keep walking every tick after a `/derp` recovery. Long
/// enough to cover a second flap (the field case reconnected twice inside 2 s)
/// without becoming a standing cost: outside this window the walk returns to
/// its ~30 s cadence.
const DERP_RECOVERY_WALK_WINDOW: Duration = Duration::from_secs(15);
/// P8 — resume-from-suspend detection threshold: across one sweep interval,
/// wall-clock advancing this much MORE than the monotonic clock means the host
/// slept in between (monotonic clocks exclude suspend on Windows and Linux —
/// QPC and CLOCK_MONOTONIC both stop). Well above any NTP step correction.
const RESUME_SKEW_THRESHOLD: Duration = Duration::from_secs(120);

/// P8 — did the host suspend between two sweep samples? Pure (tested with
/// synthetic deltas). On resume every installed carrier is dead (NAT
/// mappings/firewall pinholes expired, peers tore their ends down while we
/// slept) and every cooldown is stale evidence — the caller drops both and
/// re-coordinates from scratch, exactly like a fresh session but without
/// losing the WS or the TUN.
fn resumed_from_suspend(mono_elapsed: Duration, wall_elapsed: Duration) -> bool {
    wall_elapsed > mono_elapsed + RESUME_SKEW_THRESHOLD
}
/// P1 (S6) — outbound TUN→pump queue depth. Sized for a full burst of
/// in-flight packets between the reader and the pump; the reader-side
/// backpressure warn fires if the pump ever lets it fill.
const OUTBOUND_QUEUE_PKTS: usize = 512;
/// Most packets the outbound pump hands the sender per call (one GSO send
/// carries at most 64 segments on Linux).
const OUTBOUND_BURST_PKTS: usize = 64;
/// Most decrypted packets the inbound writer hands the TUN per call: a Linux
/// offload device coalesces each TCP run among them into one super-packet
/// write. wireguard-go's batch size.
const INBOUND_BURST_PKTS: usize = 128;

/// rc.211 (re-scoped by P1/S6) — slow-handler watchdog threshold. Since P1 the
/// data plane runs entirely off-loop (reader → outbound pump → carriers), so a
/// slow select! arm can no longer delay packets — a trip here now means
/// CONTROL-PLANE convergence is late (carrier repair, netmap install,
/// inbound-init answering — the last still latency-relevant at the ~5 s WG
/// init retransmit). The same threshold guards the pump's per-packet send
/// (`pump:send_ip_packet`) and the reader-side backpressure twin, where a trip
/// IS a data-plane incident (a wedged carrier send). Permanent telemetry: this
/// is the tripwire that catches anyone re-coupling work onto the pump or
/// fattening a control arm.
const LOOP_STALL_WARN_MS: u128 = 250;

/// rc.211 — log a named slow handler / slow send (see [`LOOP_STALL_WARN_MS`]).
fn warn_if_slow(stage: &'static str, t0: Instant) {
    let ms = t0.elapsed().as_millis();
    if ms > LOOP_STALL_WARN_MS {
        warn!(
            stage,
            ms,
            "overlay: handler ran long (control-plane latency; data plane unaffected unless stage is pump:*)"
        );
    }
}

/// P1 (S6) test hook — when non-zero, the Netmap arm sleeps this long at its
/// top (async — the arm is genuinely busy on the loop for the duration).
/// Lets `control_stall_does_not_delay_outbound` prove a fat control arm can
/// no longer delay outbound packets. Zero (inert) outside tests.
#[cfg(test)]
static TEST_NETMAP_STALL_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// rc.211 — a finished OFF-LOOP QUIC-over-TURN carrier build (see
/// [`RelayBuildQueue`]). `quic: None` = the QUIC handshake failed/timed out →
/// the commit installs the link's already-built raw relay carrier (today's
/// fallback semantics, unchanged — just no longer blocking the loop).
struct BuiltRelay {
    epoch: u64,
    link: ReadyLink,
    quic: Option<Arc<Carrier>>,
}

/// P2 (rc.211 + rc.218 merged) — epoch-token ABA bookkeeping for OFF-LOOP work,
/// generic over the completion payload. One instance per off-loop pipeline:
///
/// * `in_flight` maps node → the epoch stamped at spawn; a completion commits
///   ONLY if its epoch is still current, so any invalidating event (peer
///   removed, direct carrier installed / `coord.forget`) simply removes the
///   entry and the stale completion is dropped on arrival — immune to the
///   forget→re-request ABA a plain "is in flight" set would have.
/// * Call sites that would start duplicate work consult `in_flight` first
///   (see the per-alias docs below for each pipeline's specifics).
struct EpochQueue<T> {
    in_flight: HashMap<ObjectId, u64>,
    epoch: u64,
    tx: mpsc::Sender<T>,
}

impl<T> EpochQueue<T> {
    /// Stamp new in-flight work for `node` (supersedes any prior stamp).
    fn stamp(&mut self, node: ObjectId) -> u64 {
        self.epoch += 1;
        self.in_flight.insert(node, self.epoch);
        self.epoch
    }
    /// Invalidate any in-flight work for `node` — its completion will be
    /// dropped on arrival.
    fn invalidate(&mut self, node: &ObjectId) {
        self.in_flight.remove(node);
    }
    /// `true` iff `(node, epoch)` is still the CURRENT work for its peer;
    /// clears the entry either way (the completion consumes the slot).
    fn take_if_current(&mut self, node: &ObjectId, epoch: u64) -> bool {
        if self.in_flight.get(node) == Some(&epoch) {
            self.in_flight.remove(node);
            true
        } else {
            false
        }
    }
}

/// rc.211 — OFF-LOOP relay carrier builds. The QUIC-over-TURN rendezvous
/// (`Carrier::quic_relay`, capped at [`QUIC_BUILD_TIMEOUT`] = 8 s) used to run
/// INLINE on the steady-state select! loop — the field-proven head-of-line
/// stall behind the 1–2 s overlay RTT plateaus (the S1 watchdog named it five
/// times at 8.06 s in one 150 s run). `install_ready` spawns the build and the
/// completion is committed by a dedicated select! arm. `install_peers`' relay-
/// coordination branch checks `in_flight` so it never spawns a DUPLICATE
/// coordination for a peer whose carrier is mid-build (post-`try_build` the
/// coordinator no longer tracks the peer, so `!is_tracking` alone would
/// re-request during the 8 s window).
type RelayBuildQueue = EpochQueue<BuiltRelay>;

/// rc.218 — a finished OFF-LOOP relay ALLOCATE (see [`RelayAllocQueue`]).
/// `conn: None` = every TURN candidate failed/timed out → the commit arm
/// `forget`s the peer so the next netmap/sweep tick re-requests cleanly
/// (replacing the old park-in-`pending`-forever, which left a peer whose one
/// allocate failed PERMANENTLY blocked — nothing ever cleared `pending`).
struct AllocDone {
    epoch: u64,
    node_id: ObjectId,
    conn: Option<Arc<dyn crate::transport::relay::RelayConn>>,
}

/// rc.218 — OFF-LOOP relay allocates. rc.211 moved the QUIC-over-TURN build
/// off-loop and flagged `on_grant`'s inline DNS + TURN allocate (UDP 5 s →
/// TURNS/TCP 6 s caps per candidate) as "next in line if it ever fires in the
/// field" — it did: winhost-a's rc.213–216 logs still show `stalled the data
/// plane` from exactly this await on its hostile corp path. The `RelayGrant`
/// arm stashes the creds (`grant_accept`, sync), spawns
/// [`RelayCoordinator::allocate_for_pair`], and a dedicated select! arm
/// commits the result (`commit_alloc`, µs). Same epoch-token ABA guard, with
/// NO per-site invalidation plumbing except the P7 force-DERP conversion
/// (`invalidate` — a stale `AllocDone` landing after the pair re-cycled into
/// `pending` would otherwise commit a TURN link inside the forced window; the
/// orphan coturn allocation idles out at the server's TTL): LAST GRANT WINS
/// (every grant re-stamps, superseding any in-flight allocate), a stale
/// completion drops on epoch mismatch, and `commit_alloc` requiring the peer
/// still in `pending` drops the forgotten-not-re-requested case. While an
/// allocate is in flight the peer stays in `pending`, so `is_tracking` keeps
/// deduping re-requests exactly as before.
type RelayAllocQueue = EpochQueue<AllocDone>;

/// FR-19 P4b — a finished OFF-LOOP org-relay bind (see [`OrgBindQueue`]).
/// `conn: None` = no endpoint challenged → the commit arm drops the session
/// so the pair takes the TURN/DERP path on its next request.
struct OrgBindDone {
    epoch: u64,
    generation: u64,
    peer_public_key: [u8; 32],
    peer_overlay_ip: Ipv4Addr,
    node_id: ObjectId,
    relay_node_id: ObjectId,
    conn: Option<Arc<crate::overlay::orgrelay::client::OrgRelayConn>>,
    outcomes: Vec<crate::overlay::orgrelay::client::EndpointOutcome>,
}

/// FR-19 P4b — OFF-LOOP org-relay binds: the `RelayAllocQueue` discipline
/// applied to the bind handshake, because a network round trip per endpoint
/// must never run on the data-plane loop. Same epoch-token ABA guard — a
/// stale completion drops on epoch mismatch, and `commit_org_bind` requiring
/// the SAME session (by VNI) drops a bind that a re-mint superseded mid-flight.
type OrgBindQueue = EpochQueue<OrgBindDone>;

/// A queued relay request is not authority to demote a recovered direct path.
/// There is no direct-vs-relay quality grant in this protocol slice.
fn org_bind_needed(tracking: bool, installed: Option<&Installed>) -> bool {
    !installed.is_some_and(|p| p.is_direct) && (tracking || installed.is_some())
}

/// Accept a true replacement without losing the pre-replacement tracking
/// reason. A duplicate mint must preserve the current bind epoch and carrier.
fn accept_org_bind_session(
    peer: ObjectId,
    session: super::orgrelay::member::OrgSession,
    relay: &mut RelayCoordinator,
    queue: &mut OrgBindQueue,
    alloc_queue: &mut RelayAllocQueue,
    peers: &HashMap<ObjectId, NetmapPeer>,
    installed: &HashMap<ObjectId, Installed>,
) -> bool {
    if relay.org_relay_pinned(&peer) || installed.get(&peer).is_some_and(|e| {
        e.org_recovery_until.is_some_and(|until| Instant::now() < until) || e.org_recovery_needs_query
    }) { return false; }
    let needed = org_bind_needed(relay.is_tracking(&peer), installed.get(&peer));
    if !relay.org_session_accept(peer, session) {
        return false;
    }
    queue.invalidate(&peer);
    if needed && let Some(pc) = peers.get(&peer).and_then(peer_config_from_netmap) {
        alloc_queue.invalidate(&peer);
        relay.forget(&peer);
        relay.org_request_bind(peer, pc);
    }
    true
}

fn cancel_org_upgrade_candidate(
    peer: &ObjectId, wg: &mut WgDevice, installed: &mut HashMap<ObjectId, Installed>,
) {
    if let Some(e) = installed.get_mut(peer) {
        wg.cancel_org_upgrade(&e.pubkey);
        wg.cancel_derp_follow(&e.pubkey);
        e.org_upgrade = None;
    }
}

fn org_peer_identity(peer: &NetmapPeer) -> Option<([u8; 32], Ipv4Addr)> {
    peer_config_from_netmap(peer).map(|p| (p.public_key, p.overlay_ip))
}

/// Invalidate even a carrier-less peer's pending bind on remove/rekey/re-IP.
/// Called before netmap reconciliation; epoch invalidation prevents remove /
/// re-add ABA even when the returning row has the same public key and address.
fn invalidate_org_bind_identity(
    peer: &ObjectId,
    queue: &mut OrgBindQueue,
    relay: &mut Option<RelayCoordinator>,
) {
    queue.invalidate(peer);
    if let Some(r) = relay.as_mut() {
        r.org_bind_failed(peer);
    }
}

/// The actual org completion convergence point. Re-check live membership,
/// captured identity and direct priority AFTER the async bind, not just when
/// it starts. Rejected current work releases its session/tracking; stale work
/// must not touch a newer session. A rejected relay carrier is marked closed before its completion is dropped.
fn commit_current_org_bind(
    done: OrgBindDone,
    queue: &mut OrgBindQueue,
    peers: &HashMap<ObjectId, NetmapPeer>,
    installed: &HashMap<ObjectId, Installed>,
    relay: &mut RelayCoordinator,
) -> Option<ReadyLink> {
    if !queue.take_if_current(&done.node_id, done.epoch) {
        if let Some(conn) = done.conn {
            conn.close();
        }
        return None;
    }
    let identity_matches = peers.get(&done.node_id).and_then(org_peer_identity)
        == Some((done.peer_public_key, done.peer_overlay_ip));
    if relay.org_relay_pinned(&done.node_id) || !identity_matches || installed.get(&done.node_id).is_some_and(|p| p.is_direct
        || p.org_recovery_until.is_some_and(|until| Instant::now() < until) || p.org_recovery_needs_query) {
        if let Some(conn) = done.conn {
            conn.close();
        }
        relay.org_bind_failed(&done.node_id);
        debug!(peer = %done.node_id, "overlay: refusing org bind commit (peer changed/removed or direct recovered)");
        return None;
    }
    match done.conn {
        Some(conn) => relay.commit_org_bind(done.node_id, done.generation, conn),
        None => {
            relay.org_bind_failed(&done.node_id);
            None
        }
    }
}

/// Run one org-relay bind off-loop and hand the result to the commit arm.
/// The socket is fresh per session: the relay binds a member by its observed
/// source, so every session needs its own.
fn spawn_org_bind(
    job: crate::overlay::orgrelay::member::OrgBindJob,
    relay_label: String,
    epoch: u64,
    tx: mpsc::Sender<OrgBindDone>,
) {
    use crate::overlay::orgrelay::client::{OrgRelayConn, bind_any};
    tokio::spawn(async move {
        let (conn, outcomes) = match bind_any(
            &job.endpoints,
            job.vni,
            job.generation,
            &job.secret,
            job.per_endpoint,
        )
        .await
        {
            Ok((sock, relay, outcomes)) => (
                Some(Arc::new(OrgRelayConn::new(
                    Arc::new(sock),
                    relay,
                    job.vni,
                    relay_label,
                ))),
                outcomes,
            ),
            Err((e, outcomes)) => {
                debug!(peer = %job.node_id, vni = job.vni, %e,
                    "overlay relay: org-relay bind failed on every endpoint");
                (None, outcomes)
            }
        };
        let _ = tx
            .send(OrgBindDone {
                epoch,
                generation: job.generation,
                peer_public_key: job.peer_public_key,
                peer_overlay_ip: job.peer_overlay_ip,
                node_id: job.node_id,
                relay_node_id: job.relay_node_id,
                conn,
                outcomes,
            })
            .await;
    });
}
/// Phase B — per-socket STUN attempt timeout when gathering srflx candidates at
/// startup. `srflx_query` retries a few times, so worst-case per socket is a
/// small multiple of this; the whole gather is additionally bounded by
/// [`SRFLX_GATHER_BUDGET`] so an unreachable STUN server can't stall the join.
pub(crate) const SRFLX_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(700);
/// Phase B — overall wall-clock cap on the startup srflx gather across all
/// sockets. The common case (coturn reachable) resolves on the first attempt
/// per socket in tens of ms; this only bounds the pathological all-unreachable
/// case so the runtime never blocks the netmap→install path for long.
pub(crate) const SRFLX_GATHER_BUDGET: Duration = Duration::from_secs(4);

/// Overlay control events the runtime consumes, fed in from the node's
/// signaling loop (the `ServerMsg::Overlay*` handlers forward these).
#[derive(Debug, Clone)]
pub enum OverlayEvent {
    /// Full snapshot — carries the node's own `self_ip`, so the first one
    /// triggers TUN bring-up.
    Netmap {
        self_ip: String,
        network: OverlayNetworkInfo,
        peers: Vec<NetmapPeer>,
        org_relay_discovery: bool,
        path_trial_v1: bool,
    },
    PathTrial(roomler_ai_remote_control::signaling::ServerMsg),
    /// Incremental update.
    NetmapDelta {
        upserts: Vec<NetmapPeer>,
        removes: Vec<ObjectId>,
    },
    /// rc.307 (B) — a fresh control-WS session re-binding a PERSISTENT
    /// runtime: swap the outbound sender, re-send the join (the server
    /// replies with a full netmap the authoritative reconcile arm applies),
    /// re-advertise srflx. Carriers, TUN, WG state all stay up — a server
    /// deploy / pod roll no longer tears the data plane down (the corp-VPN
    /// relay-lock trigger, 2026-08-05).
    Reattach {
        outbound: mpsc::Sender<ClientMsg>,
    },
    /// Coturn creds for a relay leg to `peer_node_id` (relay mode only).
    /// `pair_key` is the server's symmetric `sorted(a,b)` key — both ends
    /// receive an identical value and use it to pick the same coturn worker.
    RelayGrant {
        peer_node_id: ObjectId,
        ice_servers: Vec<IceServer>,
        pair_key: String,
    },
    /// C4 stage 1 — pair-less coturn creds for the standing WARM
    /// allocation (the reply to our own `rc:overlay.warm_relay_request`;
    /// relay mode only, gated by `overlay_warm_relay`).
    WarmRelayGrant {
        ice_servers: Vec<IceServer>,
    },
    /// P7 — server-pushed per-pair DERP escalation: the server observed
    /// sustained TURN churn for this pair and tells BOTH ends to pin it onto
    /// the DERP carrier for `ttl_ms`. Pushed (never grant-borne) because the
    /// single-relay DIALER never sends a relay_request and so never sees a
    /// grant.
    ForceDerp {
        peer_node_id: ObjectId,
        ttl_ms: u64,
        /// Multi-region DERP: the regional relay both ends must dial (server-
        /// computed, identical on both). `None` = the central `/derp`.
        derp_url: Option<String>,
    },
    /// B1 — one overlay ICMP RTT measurement from the agent's 15 s prober
    /// (OsPinger/NsPinger, measured over the ACTIVE carrier). Fed to the
    /// PathMonitor's Q for the peer's incumbent tier; never affects
    /// eligibility. Gated by `OVERLAY_RTT_Q` (default on).
    RttSample {
        node_id: ObjectId,
        rtt_ms: u32,
    },
    /// FR-19 P4b — the server minted an org-relay session for us and
    /// `peer_node_id` (`rc:overlay.relay_session`).
    OrgRelaySession {
        vni: u32,
        generation: u64,
        peer_node_id: ObjectId,
        relay_node_id: ObjectId,
        relay_endpoints: Vec<String>,
        bind_secret: String,
        bind_secs: u32,
        max_lifetime_secs: u32,
    },
    /// FR-19 P4b — the server tore a session down (`rc:overlay.relay_revoke`:
    /// org mode off, an ACL edit, the relay's approval cleared, a party gone).
    OrgRelayRevoke {
        vni: u32,
    },
    /// Discovery metadata only: never grants or installs an org-relay session.
    OrgRelayCandidates {
        peer_node_id: ObjectId,
        request_id: u64,
        candidates: Vec<roomler_ai_remote_control::signaling::OrgRelayCandidateWire>,
        next_cursor: Option<roomler_ai_remote_control::signaling::OrgRelayDiscoveryCursorWire>,
        ttl_secs: u32,
    },
    /// R3/R4 — the embedder observed a LAN-address-set change on a
    /// control-WS reconnect (the `RuntimeFingerprint` lan_ips mismatch that
    /// used to spawn a WHOLE NEW runtime beside this one — which was never
    /// told, so both held direct sockets and the new one walked the
    /// stable-port band). The runtime now rebuilds its direct plane in
    /// place instead. Also useful for tests and future embedder triggers.
    RebuildDirect,
}

/// Builds the WG carrier for a peer. Production wires a direct UDP socket
/// or a coturn relay; tests inject pre-wired loopback carriers. Returning
/// `None` skips the peer (it is retried on the next netmap that lists it).
#[async_trait]
pub trait LinkFactory: Send + Sync {
    async fn build_carrier(&self, peer: &PeerConfig) -> Option<Arc<Carrier>>;
}

/// Await one coalesced listener transition. Closed/absent publishers never spin.
async fn relay_listener_changed(rx: &mut Option<watch::Receiver<Option<u16>>>) -> bool {
    match rx.as_mut() {
        Some(receiver) => match receiver.changed().await {
            Ok(()) => true,
            Err(_) => {
                *rx = None;
                false
            }
        },
        None => std::future::pending().await,
    }
}

/// Creates the TUN once the node's overlay IP is known. Production
/// returns `SystemTun`; tests return a mock. Boxed so the runtime stays
/// device-agnostic. Args: `(self_ip, netmask, mtu)`.
pub type TunFactory =
    Box<dyn Fn(Ipv4Addr, Ipv4Addr, u16) -> std::io::Result<Arc<dyn TunIo>> + Send + Sync>;

/// IPv4 netmask for a CIDR prefix length (e.g. `10` → `255.192.0.0`).
fn netmask_for_prefix(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    Ipv4Addr::from(!0u32 << (32 - u32::from(prefix.min(32))))
}

/// Prefix length out of a `"a.b.c.d/n"` CIDR string.
fn prefix_of_cidr(cidr: &str) -> Option<u8> {
    cidr.split_once('/')
        .and_then(|(_, p)| p.trim().parse().ok())
}

/// Phase 2 MagicDNS — rebuild the resolver's `name → overlay-IP` map from the
/// current netmap peers PLUS this node itself. Called after each netmap
/// change. The self entry matters because the netmap's peer list excludes
/// self: without it, `<own-name>.<domain>` was NXDOMAIN from the node's own
/// resolver (W2 field find, 2026-08-14 — the NameMap doc claimed
/// self-inclusion that never existed). `self_name` comes from the server's
/// `OverlayNetworkInfo.self_name` (`None` from a pre-W2 server ⇒ peers-only,
/// the old behaviour).
async fn sync_name_map(
    names: &dns::NameMap,
    peers: &HashMap<ObjectId, NetmapPeer>,
    self_name: Option<&str>,
    self_v4: Ipv4Addr,
) {
    let mut map = names.write().await;
    map.clear();
    for p in peers.values() {
        if p.name.is_empty() {
            continue;
        }
        if let Ok(ip) = p.overlay_ip.parse::<Ipv4Addr>() {
            map.insert(p.name.clone(), ip);
        }
    }
    if let Some(me) = self_name.filter(|s| !s.is_empty()) {
        map.insert(me.to_string(), self_v4);
    }
}

/// Phase C (D5) — the srflx keepalive / re-gather task. Every `interval`
/// (jittered) it re-runs a STUN Binding on the PUNCH socket (through the demux
/// STUN sink) to (a) hold the NAT mapping open on an idle link — WG keepalives
/// only cover ACTIVE sessions — and (b) detect a CHANGED public mapping and
/// re-advertise it, so a peer that joins later dials the live srflx, not a dead
/// one.
///
/// The STUN target is PINNED (A4): re-resolved only after several consecutive
/// failures, so a multi-worker DNS rotation can't masquerade as a mapping change
/// and fan a network-wide re-trickle every tick. On failure the last-known
/// advert is RETAINED (a transient STUN outage must not strip a working srflx).
/// Re-trickles ONLY when the punch mapping (`[0]`) actually changes. Ends when
/// the control channel closes (runtime gone).
#[allow(clippy::too_many_arguments)]
async fn run_srflx_keepalive(
    punch_sock: Arc<UdpSocket>,
    mut stun_rx: mpsc::Receiver<crate::transport::stun::StunInbound>,
    mut stun_server: SocketAddr,
    stun_urls: Vec<String>,
    own_ips: Vec<Ipv4Addr>,
    mut advertised: Vec<String>,
    nat: Option<String>,
    outbound: ControlTx,
    interval: Duration,
    // rc.307 (B) — bumped by the runtime's Reattach arm. The re-join's
    // server-side rehydrate WIPES srflx_endpoints, and only THIS task owns
    // the evolving advert (the runtime's copy is a startup snapshot), so the
    // restore must come from here.
    mut reattach_rx: tokio::sync::watch::Receiver<u64>,
    // §6 item 5 — where the gateway port mapping comes from.
    portmap: super::portmap::Source,
    // §6 item 5 — the IPv6 direct socket, whose advert tracks the host's
    // current global addresses (`refresh_v6_adverts`).
    v6: Option<Arc<UdpSocket>>,
) {
    const RERESOLVE_AFTER: u32 = 3;
    let mut failures: u32 = 0;
    // PR-B1 tripwire — one WARN per outage (not per cycle): repeated
    // keepalive failure means the advertised mapping may be dead (reader-less
    // socket / filtered path); DEBUG-only left it invisible.
    let mut warned = false;
    // rc.307 (B) — a pending (re-)advertise: set when the mapping changed or
    // a reattach fired, cleared by a successful send. A send failure now
    // means DETACHED (the runtime outlives sessions), never "runtime gone" —
    // so no `break`: keep the advert dirty and retry every tick until a
    // fresh session carries it. (Pre-B this task broke on send failure AND
    // committed `advertised[0]` before sending — a mapping change during an
    // outage was lost forever.)
    let mut resend_pending = false;
    // §6 item 5 — map the punch port on the gateway. Here, not in the
    // gather: the STUN advert is already out, so a silent gateway (most
    // cloud hosts; ≤ 2 × `portmap::WAIT`) delays nothing, and a grant
    // re-advertises with the mapping first.
    let mut pm = portmap.start(&punch_sock, &advertised).await;
    if pm.is_some() {
        resend_pending = true;
    }
    loop {
        // At the TOP, so a mapping granted before the first tick goes out
        // now, not one interval later; otherwise the same as sending right
        // after the previous iteration's select.
        if resend_pending {
            resend_pending = outbound
                .send(ClientMsg::OverlaySrflx {
                    // `advertised` stays STUN-only (`[0]` is the punch
                    // mapping compared below); the gateway mapping goes first.
                    candidates: super::portmap::advert(&advertised, pm.as_ref()),
                    // Re-send our NAT type with every advert so the server
                    // never clears it.
                    nat: super::portmap::advert_nat(nat.clone(), pm.as_ref()),
                    udp_dialer_ok: Some(crate::overlay::dialer::advertised_dialer_ok()),
                })
                .await
                .is_err();
            if resend_pending {
                debug!("overlay: srflx advert send failed (detached) — retrying next tick");
            }
        }
        // Small jitter (≤25% of the interval) so a fleet doesn't STUN in
        // lockstep; scaled to the interval so short test intervals stay quick.
        let jitter =
            Duration::from_millis(rand::random::<u64>() % (interval.as_millis() as u64 / 4 + 1));
        tokio::select! {
            _ = tokio::time::sleep(interval + jitter) => {
                match crate::transport::stun::srflx_query_via_sink(
                    &punch_sock,
                    &mut stun_rx,
                    stun_server,
                    SRFLX_ATTEMPT_TIMEOUT,
                )
                .await
                {
                    Ok(mapped) => {
                        failures = 0;
                        if warned {
                            warned = false;
                            info!("overlay: srflx keepalive recovered");
                        }
                        let ep = mapped.to_string();
                        if advertised.first().map(String::as_str) != Some(ep.as_str()) {
                            // Mapping changed → update the punch candidate `[0]`
                            // (keeping any other multi-homed candidates).
                            if advertised.is_empty() {
                                advertised.push(ep.clone());
                            } else {
                                advertised[0] = ep.clone();
                            }
                            info!(new_srflx = %ep, "overlay: srflx mapping changed — re-advertising (Phase C keepalive)");
                            resend_pending = true;
                            // The gateway's external address may have moved too.
                            if let Some(p) = pm.as_mut() {
                                p.recheck();
                            }
                        }
                    }
                    Err(e) => {
                        failures += 1;
                        if failures >= RERESOLVE_AFTER && !warned {
                            warned = true;
                            warn!(
                                %e, failures,
                                "overlay: srflx keepalive failing repeatedly — the advertised \
                                 mapping may be DEAD (reader-less socket / filtered path?); \
                                 peers punching it will fail"
                            );
                        } else {
                            debug!(%e, failures, "overlay: srflx keepalive query failed — retaining last advert");
                        }
                        if failures >= RERESOLVE_AFTER {
                            if let Some(fresh) =
                                direct::resolve_stun_server(&stun_urls, &own_ips).await
                            {
                                stun_server = fresh;
                            }
                            failures = 0;
                        }
                    }
                }
                // Refresh the gateway mapping when due (half its lifetime),
                // or ask again after a loss.
                if let Some(p) = pm.as_mut()
                    && p.poll(&advertised).await
                {
                    resend_pending = true;
                }
                if refresh_v6_adverts(&mut advertised, v6.as_ref()) {
                    info!(?advertised, "overlay: IPv6 address set changed — re-advertising");
                    resend_pending = true;
                }
            }
            changed = reattach_rx.changed() => {
                if changed.is_err() {
                    // The runtime dropped its sender = it exited; end with it,
                    // handing the gateway its port back.
                    if let Some(p) = pm.as_mut() {
                        p.release().await;
                    }
                    break;
                }
                if !advertised.is_empty() {
                    debug!("overlay: reattach — restoring the current srflx advert");
                    resend_pending = true;
                }
            }
        }
    }
}

/// R3 — spawn (or re-spawn, after a direct-plane rebuild) the srflx
/// keepalive task. Extracted from `run()`'s startup so the rebuild executor
/// can rebuild it against the NEW plane: the task captures its punch socket,
/// advert and NAT class by value, so a plane swap must replace the whole
/// task, not mutate it. `None` when any precondition is missing (no punch
/// socket / no STUN server / keepalive disabled / nothing advertised) —
/// exactly the startup semantics.
#[allow(clippy::too_many_arguments)]
fn spawn_srflx_keepalive(
    direct_ctx: &Option<DirectCtx>,
    stun_server: Option<SocketAddr>,
    stun_rx: Option<mpsc::Receiver<crate::transport::stun::StunInbound>>,
    stun_urls: &[String],
    advertised: &[String],
    my_nat: &Option<String>,
    outbound: ControlTx,
    reattach_rx: tokio::sync::watch::Receiver<u64>,
    portmap_key: Vec<u8>,
) -> Option<tokio::task::JoinHandle<()>> {
    let secs = direct::srflx_keepalive_secs();
    match (
        direct_ctx.as_ref().and_then(|c| c.punch.clone()),
        stun_server,
        stun_rx,
    ) {
        (Some((_, punch_sock)), Some(stun_server), Some(stun_rx))
            if direct::srflx_enabled() && secs > 0 && !advertised.is_empty() =>
        {
            Some(tokio::spawn(run_srflx_keepalive(
                punch_sock,
                stun_rx,
                stun_server,
                stun_urls.to_vec(),
                direct_ctx
                    .as_ref()
                    .map(|c| c.socks.iter().map(|(ip, _)| *ip).collect())
                    .unwrap_or_default(),
                advertised.to_vec(),
                my_nat.clone(),
                outbound,
                Duration::from_secs(secs),
                reattach_rx,
                super::portmap::Source::DefaultGateway(portmap_key),
                direct_ctx.as_ref().and_then(|c| c.v6.clone()),
            )))
        }
        // NEVER return None silently. An org with no re-advert task keeps
        // whatever endpoint its one-shot join advert published — and the
        // server WIPES `srflx_endpoints` on every (re-)join, so if that
        // one-shot raced the socket bind, the org is pinned to a stale or
        // empty endpoint FOREVER. Every peer then dials a dead NAT mapping,
        // including peers on the same LAN, while the host's own outbound
        // works perfectly — so it presents as "that org is black-holed" with
        // nothing in the log to explain it.
        //
        // Field 2026-08-12 (winhost-a, dual-org): grox reachable, jovanov 100 %
        // loss from EVERY peer; fleet-host-2 aimed at :62349 while the host had
        // rebound to :59669. Restarting only swapped which org was stale.
        // Diagnosis cost hours precisely because this arm said nothing.
        (punch, stun, rx) => {
            warn!(
                has_punch_sock = punch.is_some(),
                has_stun_server = stun.is_some(),
                has_stun_sink = rx.is_some(),
                srflx_enabled = direct::srflx_enabled(),
                keepalive_secs = secs,
                advertised = advertised.len(),
                "overlay: NO srflx re-advert task for this org — its endpoint \
                 can never be refreshed after a NAT rebind; peers will keep \
                 dialing the last advertised mapping"
            );
            None
        }
    }
}

/// Multi-org v2 — the plane-mode replacement for [`spawn_srflx_keepalive`]:
/// the ONE keepalive lives on the [`CarrierPlane`] (its sockets, its STUN
/// sink); this task only mirrors its watch onto THIS runtime's control WS —
/// re-advertising on a mapping change, and restoring the current advert on a
/// reattach (the same two duties the per-runtime keepalive's select had).
/// Ends when the watch (plane) or the reattach sender (runtime) goes away.
fn spawn_plane_srflx_forwarder(
    mut srflx_rx: watch::Receiver<super::carrier_plane::SrflxShared>,
    outbound: ControlTx,
    mut reattach_rx: tokio::sync::watch::Receiver<u64>,
    label: Ipv4Addr,
) -> Option<tokio::task::JoinHandle<()>> {
    // Re-assert the shared srflx on a TIMER as well as on every change/
    // reattach. In plane mode the srflx gather is decoupled from each org's
    // WS: the server WIPES `srflx_endpoints` on every (re-)join, and a
    // forwarder that only fires on `changed()` misses the current value if it
    // subscribed AFTER the shared gather set it — so a re-join's one-shot
    // re-advert is the only thing keeping the mesh populated, and if it races
    // the join that org goes relay-locked (field 2026-08-10: winhost-a's GROX
    // mesh had `srflx=[]` while JOVANOV had the candidate — same plane socket,
    // one org simply lost its advert). The idempotent periodic re-advert makes
    // every org converge; the interval's immediate first tick also covers the
    // subscribe-after-set startup gap. Cadence tracks the NAT keepalive.
    let secs = super::direct::srflx_keepalive_secs().clamp(15, 60);
    Some(tokio::spawn(async move {
        info!(self_v4 = %label, secs, "overlay: plane srflx forwarder started");
        let mut tick = tokio::time::interval(Duration::from_secs(secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // DIAG (rc.337): a stuck one-org srflx=[] in the field — log the
            // trigger + candidate count + send result so we can see whether
            // THIS org's forwarder ticks/sends, and which watch closes it.
            let trigger = tokio::select! {
                c = srflx_rx.changed() => if c.is_ok() { "change" } else { "srflx-watch-closed" },
                c = reattach_rx.changed() => if c.is_ok() { "reattach" } else { "reattach-watch-closed" },
                _ = tick.tick() => "tick",
            };
            if trigger.ends_with("closed") {
                warn!(self_v4 = %label, trigger, "overlay: plane srflx forwarder EXITING");
                break;
            }
            let s = srflx_rx.borrow().clone();
            let n = s.candidates.len();
            if s.candidates.is_empty() {
                debug!(self_v4 = %label, trigger, "overlay: plane srflx forwarder — watch empty, nothing to advertise");
                continue;
            }
            let sent = outbound
                .send(ClientMsg::OverlaySrflx {
                    candidates: s.candidates,
                    nat: s.my_nat,
                    // Read at SEND time so a mid-life latch flip rides the
                    // next periodic re-advert without any extra plumbing.
                    udp_dialer_ok: Some(crate::overlay::dialer::advertised_dialer_ok()),
                })
                .await;
            debug!(self_v4 = %label, trigger, candidates = n, ok = sent.is_ok(),
                "overlay: plane srflx re-advertised");
        }
    }))
}

/// R3 — minimum spacing between direct-plane rebuilds (the net-change
/// trigger respects it; resume and the embedder's fingerprint push bypass
/// it — those are authoritative). A rebuild is cheap but not free (~900 ms
/// worst-case port re-bind + a full re-establish wave), and interface
/// events arrive in storms.
pub(crate) const REBUILD_COOLDOWN: Duration = Duration::from_secs(30);

/// How the runtime obtains a carrier for each peer.
enum CarrierMode {
    /// Direct/test: a stateless [`LinkFactory`] builds the carrier
    /// immediately (loopback in tests).
    Direct(Arc<dyn LinkFactory>),
    /// Production: coturn relay coordination ([`RelayCoordinator`]) —
    /// field-pending.
    Relay,
}

/// rc.307 (B) — swappable control-plane sender. The overlay runtime OUTLIVES
/// a control-WS session now (`OverlayEvent::Reattach` re-binds it to each
/// fresh session), so every long-lived holder of the outbound `ClientMsg`
/// sender — the runtime itself, the [`RelayCoordinator`], the srflx
/// keepalive task — goes through this handle and picks up the swap without
/// being restarted. Send discipline: clone the CURRENT sender under the read
/// lock, await OUTSIDE it (never hold a std lock across an await). While
/// detached (the old session died, no reattach yet) sends fail exactly like
/// the old dead-channel sends did — every caller already tolerates that.
#[derive(Clone)]
pub struct ControlTx(Arc<std::sync::RwLock<mpsc::Sender<ClientMsg>>>);

impl From<mpsc::Sender<ClientMsg>> for ControlTx {
    fn from(tx: mpsc::Sender<ClientMsg>) -> Self {
        Self::new(tx)
    }
}

impl ControlTx {
    pub fn new(tx: mpsc::Sender<ClientMsg>) -> Self {
        Self(Arc::new(std::sync::RwLock::new(tx)))
    }
    /// Re-bind to a fresh session's outbound sender.
    pub fn swap(&self, tx: mpsc::Sender<ClientMsg>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = tx;
    }
    fn current(&self) -> mpsc::Sender<ClientMsg> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub async fn send(
        &self,
        msg: ClientMsg,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ClientMsg>> {
        self.current().send(msg).await
    }
}

/// One node's overlay runtime. Construct with [`OverlayRuntime::new`] (or
/// [`new_relay`](OverlayRuntime::new_relay)), then
/// `tokio::spawn(rt.run(events, endpoints))`.
pub struct OverlayRuntime {
    keypair: WgKeypair,
    outbound: ControlTx,
    mode: CarrierMode,
    tun_factory: TunFactory,
    mtu: u16,
    /// FR-40 — the key epoch this node presents on its join (bumped by the
    /// agent on every rotation, persisted next to the key). `0` = never
    /// rotated. See [`Self::with_key_epoch`].
    key_epoch: u32,
    /// FR-19 P4b — see [`Self::with_org_primary`].
    org_primary: bool,
    path_trial_managed: std::sync::Mutex<HashSet<ObjectId>>,
    /// Actual daemon listener lifetime; never inferred from environment.
    relay_listener_readiness: Option<watch::Receiver<Option<u16>>>,
    /// Phase 1 — subnet CIDRs this node advertises as a router (from config).
    /// Sent in the join; the server gates them behind admin approval.
    advertised_routes: Vec<String>,
    /// FR-97 P0b — why this node offers no routes although it was configured
    /// to: the host cannot forward or NAT for the overlay ([`super::nat::gate_offer`],
    /// run at the top of [`Self::run`], before the first join). Sent in the
    /// join and published for `roomler status`. `None` = offering as
    /// configured.
    route_offer_withheld: Option<String>,
    /// Unification P1 — where to publish this node's live overlay view (self
    /// IP + peers with connection type) for the daemon's LocalAPI. `None` in
    /// test / direct mode (nothing reads it there).
    peer_view: Option<watch::Sender<OverlayView>>,
    /// P5 exit-node CLIENT opt-in — the mesh peer (its [`NetmapPeer::name`] or
    /// node-id hex) this node routes ALL its internet egress through. `None` =
    /// today's behaviour (no default routing). Only takes effect once the named
    /// peer is present, reachable, has a live carrier, AND is an admin-approved
    /// exit node (its netmap `routes` carry `0.0.0.0/0`). See
    /// [`OverlayRuntime::reconcile_exit_routing`].
    exit_node: Option<String>,
    /// P5 exit-node — carrier-critical endpoint IPs that MUST stay on the
    /// physical uplink (exempted from the split-default) for the mesh to survive
    /// exit routing: the coordination server's resolved A-records, provided by
    /// the agent (which knows `server_url`) BEFORE any `/1` is installed, so DNS
    /// still worked when they were resolved. Coturn worker IPs are added
    /// dynamically from live relay carriers. Empty unless `exit_node` is set.
    exit_server_ips: Vec<IpAddr>,
    /// FR-97 P0c-3 — the netstack SOCKS5 front's port, when the agent built
    /// this runtime over the userspace netstack. Copied onto the exit state:
    /// such a node's exit carries only what that front dials, and it never
    /// steers the host's DNS. Set via
    /// [`with_netstack_socks`](Self::with_netstack_socks).
    netstack_socks: Option<u16>,
    /// Phase D (DERP) — a factory that OPENS this node's `/derp` WS + returns
    /// its demux, called LAZILY by [`run`](Self::run) only when the node is
    /// itself UDP-blocked (its srflx gather found nothing). A UDP-capable node
    /// can never be in a both-UDP-blocked pair, so it never needs DERP — this
    /// way it doesn't hold an idle `/derp` WS. `None` (no factory / not called)
    /// ⇒ no DERP; the coordinator falls through to both-allocate. Set via
    /// [`with_derp_mux_factory`](Self::with_derp_mux_factory).
    derp_mux_factory: Option<DerpMuxFactory>,
    /// Multi-region DERP — per-URL regional mux opener (agent-provided, like
    /// [`derp_mux_factory`](Self::derp_mux_factory)); consulted by the
    /// force-DERP handler when a push carries a `derp_url`.
    regional_derp_factory: Option<RegionalDerpFactory>,
    /// P3 PR-A — the shadow [`path::PathMonitor`] + divergence bookkeeping.
    /// Behind a Mutex (not a field of the loop) because the feed sites are
    /// `&self` methods whose signatures are frozen by the timer-parity tests;
    /// accessed ONLY through [`Self::shadow`] (sync closure — the guard
    /// cannot cross an await). Uncontended: the overlay loop is the only
    /// caller.
    path_shadow: std::sync::Mutex<PathShadow>,
    /// S2 — the MagicDNS bring-up outcome, set once by [`run`](Self::run)
    /// after the resolver/OS-steer attempt and grafted onto every
    /// published [`OverlayView`]. `None` when MagicDNS is off.
    dns_status: Option<DnsStatus>,
    /// NAT-traversal — the srflx (STUN) gather outcome, set by [`run`](Self::run)
    /// on every gather and grafted onto every published [`OverlayView`], exactly
    /// like [`dns_status`](Self::dns_status). `None` before the first gather.
    ///
    /// Exists so an empty srflx tier is VISIBLE: it failed fleet-wide and
    /// silently on 2026-08-06 because both failure paths only logged at
    /// `debug!`.
    srflx_status: Option<crate::localapi::SrflxStatus>,
    /// FR-97 P3i — what the host's firewall lets a mesh peer reach on this
    /// runtime's adapter. Written by the probe task [`run`](Self::run) starts
    /// once the adapter exists (at once, then every ten minutes), read into
    /// every published view; shared because that task is not the run loop.
    host_firewall: Arc<std::sync::Mutex<Option<crate::localapi::HostFirewallStatus>>>,
    /// C4 stage 1 — the warm allocation's state, published into
    /// [`OverlayView::warm_relay`](crate::localapi::OverlayView) on every
    /// view publish. `None` while the feature is off.
    warm_relay_status: Option<crate::localapi::WarmRelayStatus>,
    /// Multi-org v2 — the process-wide shared carrier plane, when this
    /// runtime rides it (see [`with_carrier_plane`](Self::with_carrier_plane)).
    carrier_plane: Option<Arc<super::carrier_plane::CarrierPlane>>,
    /// C2 — disco rounds completed, for the periodic summary cadence.
    disco_rounds: std::sync::atomic::AtomicU64,
    /// A — the prober's latest table, republished by `disco_round` so
    /// `publish_view` (which has no access to the run loop's prober) can
    /// attach it to the peer view. Measurement only: nothing in the selector
    /// reads this.
    disco_paths: std::sync::Mutex<Vec<super::disco::PathSample>>,
}

/// Opens the node's `/derp` WS (the agent owns `server_url` + the token +
/// `tokio_tungstenite`) and returns the connected [`DerpMux`]. Boxed +
/// agent-provided so `tunnel-core` stays WebSocket-free; [`OverlayRuntime::run`]
/// calls it AT MOST ONCE, and only for a UDP-blocked node (lazy `/derp`).
///
/// `Send + Sync`: the `run` future keeps `&self` alive across awaits and is
/// spawned onto the multi-thread runtime, so `OverlayRuntime` (and thus this
/// factory) must be `Sync`. The agent's closure captures only `Sync` values
/// (`String` server-url/token + the 32-byte pubkey), so it satisfies both.
pub type DerpMuxFactory = Box<dyn FnOnce() -> Arc<DerpMux> + Send + Sync>;

/// Multi-region DERP: opens a `/derp` WS to a REGIONAL relay (`derp_url`) and
/// returns its demux, or `None` when the connection can't be attempted yet
/// (e.g. no admission ticket cached) — the caller then degrades to the central
/// mux. Called per distinct URL (results are cached in the coordinator), so
/// unlike [`DerpMuxFactory`] this is a reusable `Fn`.
pub type RegionalDerpFactory = Box<dyn Fn(&str) -> Option<Arc<DerpMux>> + Send + Sync>;

/// Map the runtime's live carrier bookkeeping into the LocalAPI [`OverlayView`]
/// — the daemon-internal shape the `roomler status` / `peers` verbs read. Pure
/// (no I/O / no `self`) so the [`ConnectionType`] classification is unit-tested
/// directly. `current_peers` (the netmap) is authoritative for membership;
/// `by_node` tells us HOW we currently reach each one:
/// - installed **direct** carrier → [`ConnectionType::Direct`]
/// - installed **relay** carrier → [`ConnectionType::Relay`]
/// - known + server-reachable but no carrier yet (relay pending, cooling down)
///   → [`ConnectionType::Blocked`]
/// - not server-reachable → [`ConnectionType::Offline`]
///
/// `Tunnel` is never produced here — that's the userspace-tunnel fallback the
/// daemon labels once the tunnel-client folds in (P3). `rtt_ms` is the prober's
/// last `RttSample` for the peer's installed carrier (stats PR-5 — previously
/// hardcoded `None`; the daemon may still overlay its own ICMP measurement in
/// the LocalAPI merge); `last_seen_ms` is the
/// absolute epoch-ms of the peer's last inbound packet (P3b-3), `None` for a peer
/// with no installed carrier.
///
/// `now` + `epoch_now_ms` are the monotonic + wall-clock references captured by
/// the caller ([`publish_view`]); passed in (not read here) so this stays a pure
/// function the tests can drive with a fixed clock.
fn build_overlay_view(
    self_ip: &str,
    by_node: &HashMap<ObjectId, Installed>,
    current_peers: &HashMap<ObjectId, NetmapPeer>,
    probing: &HashMap<ObjectId, UpgradeProbe>,
    now: Instant,
    epoch_now_ms: u64,
    // Transport half of the relay label, keyed by peer pubkey. The KIND lives
    // on `Installed`; only the carrier knows udp-vs-tcp and which PoP served
    // the allocation, and this fn has no carrier access. Empty in tests.
    relay_transport: &HashMap<[u8; 32], (crate::transport::relay::RelayTransport, Option<String>)>,
) -> OverlayView {
    let mut peers: Vec<PeerInfo> = current_peers
        .values()
        .map(|np| {
            let inst = by_node.get(&np.node_id);
            let connection = match inst {
                Some(inst) if inst.is_direct => ConnectionType::Direct,
                Some(_) => ConnectionType::Relay,
                None if np.reachable => ConnectionType::Blocked,
                None => ConnectionType::Offline,
            };
            // Absolute epoch-ms of the last inbound packet (what the CLI's
            // `fmt_last_seen` expects). Only a peer with an installed carrier
            // has an `last_rx_at`; Blocked/Offline stay `None`.
            let last_seen_ms = inst.map(|inst| {
                let age_ms = now.saturating_duration_since(inst.last_rx_at).as_millis() as u64;
                epoch_now_ms.saturating_sub(age_ms)
            });
            PeerInfo {
                node_id: np.node_id.to_hex(),
                name: np.name.clone(),
                // Multi-org — the runtime is org-agnostic (it has no tenant
                // identity); the DAEMON stamps this when it merges the
                // per-org views, since only it knows which view is which org.
                org: String::new(),
                overlay_ip: (!np.overlay_ip.is_empty()).then(|| np.overlay_ip.clone()),
                overlay_ip6: derived_v6_of(&np.overlay_ip),
                online: np.reachable,
                connection,
                // P8-cosmetics — a relay-carried peer with an MBB probe in
                // flight renders as `upgrading` in the CLI, so a snapshot
                // taken mid-transition reads as what it is.
                upgrading: connection == ConnectionType::Relay && probing.contains_key(&np.node_id),
                // rc.275 honesty — the sweep's silently-one-way verdict.
                stalled: inst.is_some_and(|i| i.stalled),
                rtt_ms: inst.and_then(|i| i.last_rtt_ms),
                last_seen_ms,
                // P3b-3 — carry the backing agent id (hex) so the daemon can join
                // this peer to a tunnel flow and label it `Tunnel`.
                agent_id: np.agent_id.map(|a| a.to_hex()),
                // rc.187 — relay endpoints (relay carriers only) so `peers --json`
                // shows each end's coturn worker; same IP on both = same-worker.
                relay_local: inst.and_then(|i| i.relay_local).map(|a| a.to_string()),
                relay_dst: inst.and_then(|i| i.relay_dst).map(|a| a.to_string()),
                // Promote the relay label out of the JSON-only `debug` block:
                // the human table showed a bare `relay` for both a coturn hop
                // and a DERP one, so a dead PoP was invisible there.
                relay_kind: inst
                    .and_then(|i| i.relay_kind)
                    .map(|k| k.as_str().to_string()),
                relay_transport: inst
                    .and_then(|i| relay_transport.get(&i.pubkey))
                    .map(|(t, _)| t.as_str().to_string()),
                relay_server: inst
                    .and_then(|i| relay_transport.get(&i.pubkey))
                    .and_then(|(_, s)| s.clone()),
                // rc.276 diagnostics — the carrier forensic snapshot (JSON-only).
                debug: inst.map(|i| PeerCarrierDebug {
                    tier: match i.tier {
                        DirectTier::Lan => "lan",
                        DirectTier::Public => "public",
                        DirectTier::Srflx => "srflx",
                        DirectTier::Relay => "relay",
                    }
                    .to_string(),
                    initiated: i.initiated,
                    hs_done: i.hs_done,
                    local: i.carrier_local.map(|a| a.to_string()),
                    dst: i.carrier_dst.map(|a| a.to_string()),
                    tx: i.last_traffic.0,
                    rx: i.last_traffic.1,
                    last_rx_age_s: now.saturating_duration_since(i.last_rx_at).as_secs(),
                    relay_kind: i.relay_kind.map(|k| k.as_str().to_string()),
                    rx_denied: i.rx_denied,
                    rx_denied_noroute: i.rx_denied_noroute,
                }),
                // F — grafted on by `publish_view`, which holds the monitor;
                // the pure builder cannot see the selector state.
                why: None,
                probes: Vec::new(),
            }
        })
        .collect();
    // Stable order so a LocalAPI reader doesn't see the list jitter between
    // otherwise-identical reads (HashMap iteration order is nondeterministic).
    peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    OverlayView {
        path_trials: None,
        self_ip: (!self_ip.is_empty()).then(|| self_ip.to_string()),
        self_ip6: derived_v6_of(self_ip),
        peers,
        // Set by `publish_view` from the runtime's exit-routing state (S4)
        // and DNS bring-up state (S2).
        exit_node: None,
        route_offer_withheld: None,
        host_firewall: None,
        dns: None,
        srflx: None,
        warm_relay: None,
        direct_socks: Vec::new(),
        // Set by `publish_view` from the process-global evidence counters.
        derp_inbound_drops: None,
    }
}

/// The *derived* overlay IPv6 for an overlay-v4 string ([`derive_overlay_v6`]
/// as display text), or `None` for an empty/unparseable one. The runtime is the
/// single place the daemon-facing view learns v6 addresses — the daemon and its
/// clients (CLI / tray) render them without needing the `overlay` feature.
fn derived_v6_of(overlay_ip: &str) -> Option<String> {
    overlay_ip
        .parse::<Ipv4Addr>()
        .ok()
        .map(|v4| super::router::derive_overlay_v6(v4).to_string())
}

impl OverlayRuntime {
    /// FR-40 — the key epoch to present on the join. The agent persists it
    /// next to the key and bumps it on every rotation; the server stores it
    /// on the node row alongside the public key.
    pub fn with_key_epoch(mut self, key_epoch: u32) -> Self {
        self.key_epoch = key_epoch;
        self
    }
}

impl OverlayRuntime {
    /// Direct/test runtime: carriers come from `links`.
    pub fn new(
        keypair: WgKeypair,
        outbound: mpsc::Sender<ClientMsg>,
        links: Arc<dyn LinkFactory>,
        tun_factory: TunFactory,
        mtu: u16,
    ) -> Self {
        Self {
            keypair,
            outbound: ControlTx::new(outbound),
            mode: CarrierMode::Direct(links),
            tun_factory,
            mtu,
            key_epoch: 0,
            advertised_routes: Vec::new(),
            route_offer_withheld: None,
            peer_view: None,
            org_primary: false,
            path_trial_managed: std::sync::Mutex::new(HashSet::new()),
            relay_listener_readiness: None,
            exit_node: None,
            exit_server_ips: Vec::new(),
            netstack_socks: None,
            derp_mux_factory: None,
            regional_derp_factory: None,
            path_shadow: std::sync::Mutex::new(PathShadow::new()),
            dns_status: None,
            srflx_status: None,
            host_firewall: Default::default(),
            warm_relay_status: None,
            carrier_plane: None,
            disco_rounds: std::sync::atomic::AtomicU64::new(0),
            disco_paths: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Production runtime: carriers come from the coturn relay
    /// coordination (field-pending).
    pub fn new_relay(
        keypair: WgKeypair,
        outbound: mpsc::Sender<ClientMsg>,
        tun_factory: TunFactory,
        mtu: u16,
    ) -> Self {
        Self {
            keypair,
            outbound: ControlTx::new(outbound),
            mode: CarrierMode::Relay,
            tun_factory,
            mtu,
            key_epoch: 0,
            advertised_routes: Vec::new(),
            route_offer_withheld: None,
            peer_view: None,
            org_primary: false,
            path_trial_managed: std::sync::Mutex::new(HashSet::new()),
            relay_listener_readiness: None,
            exit_node: None,
            exit_server_ips: Vec::new(),
            netstack_socks: None,
            derp_mux_factory: None,
            regional_derp_factory: None,
            path_shadow: std::sync::Mutex::new(PathShadow::new()),
            dns_status: None,
            srflx_status: None,
            host_firewall: Default::default(),
            warm_relay_status: None,
            carrier_plane: None,
            disco_rounds: std::sync::atomic::AtomicU64::new(0),
            disco_paths: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// P3 PR-A (re-scoped by PR-E) — run a SYNC closure against the path
    /// monitor. Always runs: the monitor IS the selector now, so `off` can no
    /// longer skip the feed (it only silences telemetry inside PathShadow's
    /// own methods). The lock/drop pair lives entirely inside this call, so
    /// no caller can hold the guard across an await; the closure being
    /// `FnOnce(&mut PathShadow) -> R` (not async) makes that structural.
    /// Returns `Option` purely for call-site compatibility — always `Some`.
    fn shadow<R>(&self, f: impl FnOnce(&mut PathShadow) -> R) -> Option<R> {
        let mut s = self.path_shadow.lock().unwrap_or_else(|p| p.into_inner());
        Some(f(&mut s))
    }

    /// Phase 1 — set the subnet routes this node advertises as a router.
    pub fn with_advertised_routes(mut self, routes: Vec<String>) -> Self {
        self.advertised_routes = routes;
        self
    }

    /// Phase D (DERP) — attach a factory that opens the node's `/derp` WS. The
    /// runtime calls it LAZILY, only when this node is itself UDP-blocked, so a
    /// UDP-capable node never opens an idle `/derp` WS. The factory (agent-side,
    /// owning `server_url`/token/`tokio_tungstenite`) creates the [`DerpMux`],
    /// opens the WS, and returns the mux for the relay coordinator to vend
    /// `DerpConn` carriers. `None` (the default) leaves DERP inert.
    pub fn with_derp_mux_factory(mut self, factory: Option<DerpMuxFactory>) -> Self {
        self.derp_mux_factory = factory;
        self
    }

    /// Multi-region DERP — install the per-URL regional relay opener.
    pub fn with_regional_derp_factory(mut self, factory: Option<RegionalDerpFactory>) -> Self {
        self.regional_derp_factory = factory;
        self
    }

    /// Multi-org v2 — attach this runtime to the process-wide
    /// [`CarrierPlane`](super::carrier_plane::CarrierPlane). Its `WgDevice`
    /// then registers sessions on the plane (receiver-index demux on the
    /// shared socket set), `setup_direct` consumes the plane's bound view
    /// instead of binding its own, and the srflx gather/keepalive are the
    /// plane's shared ones. `None` (the default) keeps every existing path.
    pub fn with_carrier_plane(
        mut self,
        plane: Option<Arc<super::carrier_plane::CarrierPlane>>,
    ) -> Self {
        self.carrier_plane = plane;
        self
    }

    /// P5 exit-node CLIENT opt-in — route this node's default internet egress
    /// through `exit_node` (a peer's [`NetmapPeer::name`] or node-id hex).
    /// `server_ips` are the coordination server's already-resolved IPs (the agent
    /// resolves `server_url` before the mesh forms — while the uplink is still
    /// clean — so they can be exempted from the split-default). Both `None` /
    /// empty (test / non-exit nodes) leaves exit routing entirely inert.
    pub fn with_exit_node(mut self, exit_node: Option<String>, server_ips: Vec<IpAddr>) -> Self {
        self.exit_node = exit_node;
        self.exit_server_ips = server_ips;
        self
    }

    /// FR-97 P0c-3 — this runtime runs over the userspace netstack, whose
    /// SOCKS5 front listens on `127.0.0.1:<port>`. A netstack node installs no
    /// OS routes, so an exit then carries only what the front dials:
    /// `roomler status` says so, never claims IPv6 through it, and the host's
    /// DNS is left alone. `None` (an OS TUN, tests) changes nothing.
    pub fn with_netstack_socks(mut self, port: Option<u16>) -> Self {
        self.netstack_socks = port;
        self
    }

    /// Unification P1 — publish this node's live overlay view (self IP + peers
    /// with connection type) on `tx` so the daemon's LocalAPI can answer
    /// `roomler status` / `peers`. The runtime republishes on join and after
    /// every netmap / carrier-state change. Unset (test / direct mode) → the
    /// runtime publishes nothing.
    pub fn with_peer_view(mut self, tx: watch::Sender<OverlayView>) -> Self {
        self.peer_view = Some(tx);
        self
    }

    /// FR-19 P4b — whether this runtime serves the device's PRIMARY org.
    /// Carried on the join as `org_primary`: the server refuses every
    /// org-relay decision for a node that does not say `true`, and the agent
    /// drops relay frames on a secondary org's WS, so a secondary runtime is
    /// never handed a session.
    pub fn with_org_primary(mut self, primary: bool) -> Self {
        self.org_primary = primary;
        self
    }

    /// Inject the daemon's actually bound relay listener. Unset means this
    /// runtime is a client, even if a configuration flag requests serving.
    pub fn with_relay_listener_readiness(
        mut self,
        readiness: watch::Receiver<Option<u16>>,
    ) -> Self {
        self.relay_listener_readiness = Some(readiness);
        self
    }

    fn ready_relay_port(&self) -> Option<u16> {
        let rx = self.relay_listener_readiness.as_ref()?;
        // A dead publisher is not readiness; a watch retains its last value.
        rx.has_changed().ok()?;
        (*rx.borrow()).filter(|port| *port != 0)
    }

    /// Rebuild + publish the [`OverlayView`] if a LocalAPI receiver is wired.
    /// Cheap (a few-element Vec + a `watch` replace); called at each point the
    /// netmap or a carrier changes. The `watch` keeps only the latest value, so
    /// coalescing bursts is automatic.
    /// C2 — one disco round: absorb any pongs that arrived since the last
    /// tick, then send one fresh ping per installed DIRECT carrier over the
    /// exact socket+dst that carrier uses.
    ///
    /// Strictly measurement. It never demotes, penalises or re-ranks — the
    /// table it fills is read only by the LocalAPI and the summary log. That
    /// separation is deliberate: rc.346 coupled measurement to demotion in
    /// one release and took healthy carriers down with it.
    async fn disco_round(
        &self,
        prober: &mut super::disco::Prober,
        path_trials: &mut path_trial::Engine,
        rx: &mut Option<mpsc::Receiver<super::disco::DiscoInbound>>,
        wg: &WgDevice,
        by_node: &HashMap<ObjectId, Installed>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        direct_ctx: Option<&super::runtime::establish::DirectCtx>,
    ) {
        if !crate::overlay::direct::disco_probe_enabled() {
            return;
        }
        // Absorb replies first so this round's verdicts reflect the last one.
        if let Some(rx) = rx.as_mut() {
            while let Ok(p) = rx.try_recv() {
                path_trials.active_pong(&p);
                prober.on_pong(&p);
            }
        }
        // Everything probed this round, per peer — the keep-set for pruning
        // below. A peer contributes either its live carrier path or its
        // candidate set, never both, but collecting them uniformly means the
        // prune cannot depend on which branch ran.
        let mut probed: HashMap<[u8; 32], Vec<std::net::SocketAddr>> = HashMap::new();
        for e in by_node.values() {
            let (nonce, frame) =
                prober.next_ping(&e.pubkey, &self.keypair.secret, &self.keypair.public);
            let sent_at = Instant::now();
            if let Some(dst) = wg.sender().send_disco_raw(&e.pubkey, &frame).await {
                prober.sent_at(e.pubkey, dst, nonce, sent_at);
                probed.entry(e.pubkey).or_default().push(dst);
            }
        }
        // A2 — probe the CANDIDATE paths of peers parked on a relay.
        //
        // Until now the loop above was the whole prober, and it walks only
        // carriers that are ALREADY direct. So the one question an operator
        // actually asks — "this pair is on relay; would the LAN path work?" —
        // was the one question disco could not answer, and answering it took a
        // tcpdump on one host and log archaeology on the other (2026-08-26,
        // neo16 ↔ MacBook, same Wi-Fi).
        //
        // This is measurement, NOT a dial: a disco ping is a stateless echo
        // the peer answers to the packet's OBSERVED SOURCE, so it neither
        // creates a carrier nor disturbs the relay one in use, and unlike a
        // WireGuard handshake its reply cannot be routed to a stale endpoint.
        // Nothing reads the result to make a decision — that is still C3/C6.
        for (nid, np) in current_peers {
            let Some(inst) = by_node.get(nid) else {
                continue;
            };
            if inst.is_direct {
                continue; // covered above, over the path it actually uses
            }
            let Some(cfg) = super::netmap::peer_config_from_netmap(np) else {
                continue;
            };
            // Rotation 0 on purpose: the prober measures the PRIMARY candidate
            // of each tier. Rotating here would sample a different endpoint
            // every round and never accumulate a loss window on any of them,
            // which is the opposite of what a loss window is for.
            let cands = super::runtime::establish::resolve_direct_candidates(
                direct_ctx,
                &cfg,
                Default::default(),
            );
            let Some(ctx) = direct_ctx else { continue };
            // The LAN candidate carries the local interface IP to egress from,
            // which is why it is shaped differently from the other two.
            let lan = match cands.lan {
                Some((local_ip, dst)) => {
                    super::runtime::establish::lan_egress_socket(ctx, local_ip, dst)
                        .await
                        .map(|s| (dst, s))
                }
                None => None,
            };
            for pair in [
                lan,
                cands.public.zip(ctx.public_sock.clone()),
                cands.srflx.and_then(|d| ctx.srflx_sock(d).map(|s| (d, s))),
            ] {
                let Some((dst, sock)) = pair else { continue };
                let (nonce, frame) =
                    prober.next_ping(&cfg.public_key, &self.keypair.secret, &self.keypair.public);
                let sent_at = Instant::now();
                if sock.send_to(&frame, dst).await.is_ok() {
                    prober.sent_at(cfg.public_key, dst, nonce, sent_at);
                    probed.entry(cfg.public_key).or_default().push(dst);
                }
            }
        }
        // Anything we are no longer probing for a peer is stale (the carrier
        // moved, or a candidate went away) — see `retain_paths`.
        for (pk, dsts) in &probed {
            prober.retain_paths(pk, dsts);
        }
        // C2.s only observable: a periodic digest. Every 60 rounds ≈ 5 min
        // at the 5 s tick, so it is legible in a live journal without
        // drowning it.
        self.disco_rounds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self
            .disco_rounds
            .load(std::sync::atomic::Ordering::Relaxed)
            .is_multiple_of(60)
            && let Some(s) = prober.summary(|pk| {
                by_node
                    .values()
                    .find(|e| &e.pubkey == pk)
                    .map(|e| e.overlay_ip)
            })
        {
            info!("overlay disco: {s}");
        }

        // A — republish the table so `publish_view` can attach it to the peer
        // view. Done every round (cheap: a few entries), so a reader never
        // sees a table older than one tick.
        if let Ok(mut g) = self.disco_paths.lock() {
            *g = prober.paths();
        }
        // Forget peers that left, so the table can't grow without bound.
        let live: std::collections::HashSet<[u8; 32]> =
            by_node.values().map(|e| e.pubkey).collect();
        for s in prober.paths() {
            if !live.contains(&s.peer) {
                prober.forget(&s.peer);
            }
        }
    }

    fn publish_view(
        &self,
        self_ip: &str,
        by_node: &HashMap<ObjectId, Installed>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        probing: &HashMap<ObjectId, UpgradeProbe>,
        exit_status: Option<ExitNodeStatus>,
        wg: &WgDevice,
        path_trials: &path_trial::Engine,
        path_trial_supported: bool,
    ) {
        if let Some(tx) = &self.peer_view {
            // Capture both clocks together so `last_seen_ms` (absolute epoch-ms)
            // is derived from the same instant the monotonic ages are measured
            // against. `UNIX_EPOCH` is monotonic-safe here (a backwards wall
            // clock only makes a last_seen look slightly newer).
            let now = Instant::now();
            let epoch_now_ms = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            // Carrier-side half of the relay label; the view builder is pure
            // over peers and has no `wg` access of its own.
            let relay_transport: HashMap<
                [u8; 32],
                (crate::transport::relay::RelayTransport, Option<String>),
            > = by_node
                .values()
                .filter(|i| !i.is_direct)
                .filter_map(|i| {
                    wg.sender()
                        .relay_transport_info(&i.pubkey)
                        .map(|info| (i.pubkey, info))
                })
                .collect();
            let mut view = build_overlay_view(
                self_ip,
                by_node,
                current_peers,
                probing,
                now,
                epoch_now_ms,
                &relay_transport,
            );
            // A — attach the disco measurements, keyed peer-pubkey → view row.
            // Deliberately alongside `why`: the interesting case is the two
            // DISAGREEING (a path the prober says is clean that the selector
            // will not use), and that is unreadable if they live apart.
            {
                let table = self
                    .disco_paths
                    .lock()
                    .map(|g| g.clone())
                    .unwrap_or_default();
                if !table.is_empty() {
                    let pk_of: HashMap<String, [u8; 32]> = view
                        .peers
                        .iter()
                        .filter_map(|p| {
                            ObjectId::parse_str(&p.node_id)
                                .ok()
                                .and_then(|n| by_node.get(&n))
                                .map(|i| (p.node_id.clone(), i.pubkey))
                        })
                        .collect();
                    for p in &mut view.peers {
                        let Some(pk) = pk_of.get(&p.node_id) else {
                            continue;
                        };
                        p.probes = table
                            .iter()
                            .filter(|s| &s.peer == pk)
                            .map(|s| PathProbe {
                                dst: s.dst.to_string(),
                                loss: s.loss,
                                rtt_ms: s.rtt_ms,
                                rtt_p95_ms: s.rtt_p95_ms,
                                rtt_max_ms: s.rtt_max_ms,
                            })
                            .collect();
                    }
                }
            }
            // F — attach the path decision. `build_overlay_view` is pure over
            // peers and holds no monitor, so like `exit_node`/`dns` this is
            // grafted on here. Done for EVERY peer on every publish, not on
            // demand: an incident capture is a `peers --json` taken while the
            // fault is live, and the explanation is worth far more inside that
            // snapshot than in a command someone had to know to run at the
            // time. `explain` is a pure read of already-computed state.
            self.shadow(|s| {
                for p in &mut view.peers {
                    let Ok(nid) = ObjectId::parse_str(&p.node_id) else {
                        continue;
                    };
                    let e = s.mon.explain(&nid, now);
                    p.why = Some(PeerWhy {
                        tiers: e
                            .tiers
                            .iter()
                            .map(|t| TierWhy {
                                tier: path::tier_label(t.tier).to_string(),
                                eligible: t.eligible,
                                blocked_by: t.blocked_by.map(|b| b.as_str().to_string()),
                                available: t.available,
                                base: t.base,
                                q: t.q,
                                penalty: t.penalty,
                                score: t.score,
                                fails: t.fails,
                            })
                            .collect(),
                        relayed_instead_s: e.relayed_instead_s,
                        relayed_instead_strikes: e.relayed_instead_strikes,
                        forced_derp_s: e.forced_derp_s,
                        probing: e.probing.map(|t| path::tier_label(t).to_string()),
                    });
                }
            });
            // S4 — the exit-node routing status the runtime holds (the view
            // builder is pure over peers, so this is grafted on after).
            view.path_trials = path_trials.observation(
                current_peers,
                by_node,
                self.org_primary && path_trial::enabled() && path_trial_supported,
            );
            view.exit_node = exit_status;
            // FR-97 P0b — why this node offers no routes it was configured to.
            view.route_offer_withheld = self.route_offer_withheld.clone();
            // S2 — ditto for the DNS bring-up outcome.
            view.dns = self.dns_status.clone();
            // NAT-traversal — ditto for the srflx gather outcome. An empty
            // candidate list here is the "why is everything on relay?" signal.
            view.srflx = self.srflx_status.clone();
            // C4 stage 1 — ditto for the warm allocation state.
            view.warm_relay = self.warm_relay_status.clone();
            // PR-B1 — per-socket receive liveness: a bound socket whose
            // rx_pkts is frozen while its endpoint is advertised is the
            // 2026-08-10 wedge signature (reader-less, Recv-Q pegged).
            view.direct_socks = if let Some(p) = &self.carrier_plane {
                p.socket_stats()
            } else {
                wg.direct_sock_stats()
            };
            // FR-97 P3i — the host firewall's word on the adapter, as last probed.
            view.host_firewall = self
                .host_firewall
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            // #32 — the `/derp` inbound-drop counters, so an operator can ask
            // "is a peer relaying to us that we have not followed?" instead of
            // inferring it from an absence of log lines. Process-global (see
            // `evidence`), so no coordinator access is needed here.
            view.derp_inbound_drops = Some((
                crate::evidence::DERP_INBOUND_UNROUTED.load(std::sync::atomic::Ordering::Relaxed),
                crate::evidence::DERP_INBOUND_BACKPRESSURE
                    .load(std::sync::atomic::Ordering::Relaxed),
            ));
            // send_replace never fails (unlike send) even if the receiver is
            // transiently absent, and keeps the value for the next borrow.
            tx.send_replace(view);
        }
    }

    /// Run until the event channel closes (WS disconnect). Sends
    /// Build the `rc:overlay.join` for this node. Called at start AND on
    /// every rc.307 `Reattach` re-join — capability flags are re-read from
    /// the env each time, so a config change bridged via env lands on the
    /// next reconnect without a runtime rebuild.
    fn make_join(&self, endpoints: Vec<String>) -> ClientMsg {
        ClientMsg::OverlayJoin {
            network_hint: None,
            wg_public_key: self.keypair.public_base64(),
            key_epoch: self.key_epoch,
            supported: vec!["wireguard-v1".to_string()],
            mtu: self.mtu,
            endpoints,
            // rc.142 — advertise the QUIC-over-TURN capability so the server
            // only tells a peer to attempt QUIC when BOTH ends support it.
            supports_quic: overlay_quic_enabled(),
            // Phase D — advertise the single-relay capability (our OVERLAY_RELAY_SINGLE
            // flag) so the server only lets a peer pick single-relay when BOTH ends
            // opted in; a mixed pair stays on the both-allocate relay.
            // rc.276 — forced-TLS vetoes single-relay: the raw-UDP DIALER
            // role is the exact flow shape the affected hosts can't send,
            // and advertising the veto keeps both ends' strategy symmetric.
            supports_relay_single: crate::overlay::direct::relay_single_enabled()
                && !crate::overlay::direct::relay_tls_forced(),
            // Phase D (DERP) — advertise the DERP capability (our OVERLAY_DERP
            // flag) so a both-UDP-blocked pair only picks DERP when BOTH ends
            // opted in. Default-OFF until field-proven.
            supports_derp: crate::overlay::direct::derp_enabled(),
            // P7 — this build honors the server's per-pair `OverlayForceDerp`
            // escalation push. Same local flag as `supports_derp` (a node with
            // DERP disabled can't be force-pinned onto it).
            supports_forced_derp: crate::overlay::direct::derp_enabled(),
            // U2 — advertise that we accept a server-computed relay-tier
            // verdict. Default-OFF (env/config `OVERLAY_SERVER_RELAY_STRATEGY`)
            // until field-proven; the server only stamps a verdict when BOTH
            // ends advertise this.
            supports_server_relay_strategy: crate::overlay::direct::server_relay_strategy_enabled(),
            supports_derp_floor: crate::overlay::direct::derp_floor_enabled(),
            // Data-probe — this build's engine answers the overlay-native
            // echo inline (wired in `process_inbound`), so advertise it.
            supports_overlay_echo: true,
            // FR-19 P4b — advertised only with `overlay_org_relay` on: the
            // server pushes `relay_session` frames only to a node that says it
            // can act on them, and a session on a build that cannot is a black
            // hole. `org_primary` gates every relay decision server-side
            // (absent = refused), and `relay_port` is what the mint pairs with
            // this node's public addresses when it serves.
            supports_org_relay: super::direct::org_relay_enabled(),
            // Parsing capability only; does not enable org relay or path trials.
            supports_org_relay_multi_candidate: true,
            supports_org_relay_discovery_cursor: true,
            // FR-47 — unconditionally true: understanding a refusal is not a
            // feature to roll out behind a flag, it is the difference between
            // "the server told us why" and waiting forever on a netmap that
            // is never coming.
            supports_join_refusal: true,
            org_primary: Some(self.org_primary),
            supports_path_trial_v1: path_trial::enabled() && self.org_primary,
            supports_path_backbone_v1: path_trial::enabled()
                && self.org_primary
                && self.mtu <= roomler_ai_remote_control::models::peer_relay_limits::BACKBONE_MAX_OVERLAY_MTU
                && super::orgrelay::backbone::path_enabled(),
            relay_backbone_ready: self.org_primary
                && self.ready_relay_port().is_some()
                && super::orgrelay::backbone::configured_local_policy().is_some(),
            relay_port: self.ready_relay_port(),
            // Phase 1 — subnet routes we offer (admin must approve server-side).
            advertised_routes: self.advertised_routes.clone(),
            // FR-97 P0b — and, when we withheld them, why.
            route_offer_withheld: self.route_offer_withheld.clone(),
        }
    }

    /// `OverlayJoin`, waits for the first full netmap (which yields the
    /// node's overlay IP), brings up the TUN + inbound writer, then
    /// steady-state pumps TUN traffic and applies netmap deltas.
    pub async fn run(mut self, mut events: mpsc::Receiver<OverlayEvent>, endpoints: Vec<String>) {
        // FR-97 P0b — offer `/0` and subnet routes only if this host can
        // forward and NAT for the overlay, decided BEFORE the first join: every
        // join below sends `advertised_routes`, and `nat::enable` (after the
        // first netmap) and the ingress scope read the same list. A host that
        // cannot serve offers nothing, so no admin can approve a black hole.
        // FR-97 P0c-3 — and never from a netstack node, which forwards nothing.
        let offer = super::nat::gate_offer(
            std::mem::take(&mut self.advertised_routes),
            self.netstack_socks.is_some(),
        )
        .await;
        if let Some(why) = &offer.withheld {
            warn!(reason = %why,
                "overlay: route offer WITHHELD (no /0, no subnet route advertised): this host cannot forward or NAT for its peers");
        }
        self.advertised_routes = offer.routes;
        self.route_offer_withheld = offer.withheld;

        // rc.131 — direct LAN path: bind a shared UDP socket + discover our
        // LAN endpoint so a same-subnet peer dials us directly and skips the
        // relay. Off in Direct mode (the test/helper path) and when disabled.
        // `mut` — the srflx gather (below, after the first netmap) records the
        // punch socket into it (Phase C).
        let mut direct_ctx = self.setup_direct().await;
        // R3 — the non-plane half of the advertised set (agent-config
        // extras), kept so a rebuild can recompose `advertised` from the NEW
        // plane instead of replaying the startup snapshot.
        let base_endpoints = endpoints.clone();
        let mut advertised = endpoints;
        if let Some(ctx) = &direct_ctx {
            advertised.extend(ctx.endpoints.iter().cloned());
        }

        // Listener readiness is independent of the control WS lifetime. Keep
        // one coalescing watch subscription; no polling task or per-event queue.
        let mut listener_changes = self.relay_listener_readiness.clone();

        if self
            .outbound
            .send(self.make_join(advertised.clone()))
            .await
            .is_err()
        {
            // rc.307 (B): the spawning session died within ms. Don't die with
            // it — the runtime is persistent now; the next session's Reattach
            // re-joins. (If the process is exiting, the event channel closes
            // and the wait below returns.)
            warn!("overlay: control channel closed before join; awaiting reattach");
        } else {
            info!("overlay: rc:overlay.join sent");
        }

        // Phase 1 — wait for the first full netmap (it carries self_ip).
        let (self_ip, network, first_peers, mut server_org_discovery, mut server_path_trial_v1) = loop {
            let event = tokio::select! {
                changed = relay_listener_changed(&mut listener_changes) => {
                    if changed {
                        let _ = self.outbound.send(self.make_join(advertised.clone())).await;
                    }
                    continue;
                }
                event = events.recv() => event,
            };
            match event {
                Some(OverlayEvent::Netmap {
                    self_ip,
                    network,
                    peers,
                    org_relay_discovery,
                    path_trial_v1,
                }) => break (self_ip, network, peers, org_relay_discovery, path_trial_v1),
                // rc.307 (B) — the session died before the first netmap:
                // re-bind + re-join on the fresh one, keep waiting.
                Some(OverlayEvent::Reattach { outbound }) => {
                    self.outbound.swap(outbound);
                    if self
                        .outbound
                        .send(self.make_join(advertised.clone()))
                        .await
                        .is_err()
                    {
                        warn!("overlay: reattach join failed (session died immediately)");
                    } else {
                        info!("overlay: rc:overlay.join re-sent (reattach before first netmap)");
                    }
                    continue;
                }
                Some(OverlayEvent::NetmapDelta { .. }) => continue, // pre-netmap; ignore
                Some(OverlayEvent::RelayGrant { .. }) => continue,  // pre-netmap; ignore
                Some(OverlayEvent::WarmRelayGrant { .. }) => continue, // pre-netmap; ignore
                Some(OverlayEvent::ForceDerp { .. }) => continue,   // pre-netmap; ignore
                Some(OverlayEvent::RttSample { .. }) => continue,   // pre-netmap; ignore
                Some(OverlayEvent::PathTrial(_)) => continue,
                Some(OverlayEvent::OrgRelaySession { .. }) => continue, // pre-netmap; ignore
                Some(OverlayEvent::OrgRelayRevoke { .. }) => continue,  // pre-netmap; ignore
                Some(OverlayEvent::OrgRelayCandidates { .. }) => continue, // no membership yet
                Some(OverlayEvent::RebuildDirect) => continue,          // pre-netmap; no plane yet
                None => return,
            }
        };

        let mut server_org_fallback = network.org_relay_fallback_v1;

        let Ok(self_v4) = self_ip.parse::<Ipv4Addr>() else {
            warn!(%self_ip, "overlay: server sent a non-IPv4 self_ip; aborting runtime");
            return;
        };
        let netmask = netmask_for_prefix(prefix_of_cidr(&network.cidr).unwrap_or(10));

        let (mut wg, tun_rx) = WgDevice::new(self.keypair.secret.clone());
        // Multi-org v2 — attach the device to the shared carrier plane BEFORE
        // any peer installs: sessions then register on the plane's
        // receiver-index demux instead of the device's source-keyed one. The
        // events subscription is P1-d's rebuild protocol (Teardown/Ready).
        let mut plane_events = self.carrier_plane.as_ref().map(|plane| {
            wg.set_plane(plane.attach(wg.plane_hooks()));
            plane.subscribe_events()
        });
        let tun: Arc<dyn TunIo> = match (self.tun_factory)(self_v4, netmask, self.mtu) {
            Ok(t) => t,
            Err(e) => {
                warn!(%e, %self_v4, "overlay: TUN bring-up failed; aborting runtime");
                return;
            }
        };
        info!(%self_v4, mtu = self.mtu, "overlay: TUN up");

        // FR-97 P3i — what the host's firewall lets a mesh peer reach on this
        // adapter: probed now and every ten minutes, off the run loop, into the
        // slot every published view reads. It dies with the runtime. A device
        // with no OS surface (netstack, mocks) has no adapter to govern.
        // `ROOMLERD_HOST_FW_PROBE=0` switches it off.
        let probe_host_firewall = crate::env::flag("HOST_FW_PROBE", true);
        let _host_firewall_probe = tun.os_name().filter(|_| probe_host_firewall).map(|ifname| {
            let slot = self.host_firewall.clone();
            crate::driver::AbortOnDrop::new(tokio::spawn(async move {
                let mut every = tokio::time::interval(HOST_FIREWALL_REPROBE);
                loop {
                    every.tick().await;
                    let status = super::hostfw::probe(&ifname).await;
                    *slot.lock().unwrap_or_else(|e| e.into_inner()) = status;
                }
            }))
        });

        // Phase 1 — if this node advertises subnet routes, turn on IP forwarding
        // + NAT so overlay peers can reach the LANs it fronts. Held for the
        // runtime's lifetime; its `Drop` reverts on WS disconnect / shutdown.
        // Multi-org v2 — the rules are scoped to THIS device's OS name; a
        // device with no OS surface (mock, netstack) falls back to the
        // historical per-platform singleton name, exactly as before.
        let nat_if = tun.os_name();
        // FR-47 P5e — NAT every block of the org, not just the one this node
        // is addressed in: a peer in another block is equally overlay-sourced,
        // and masquerading only our own would let its packets out un-NATed.
        //
        // `cidrs` is empty from a pre-P5d server, and then this is exactly the
        // single `network.cidr` it always was. It is also a one-element list
        // for every org that has not grown — so the commands issued are
        // byte-identical on every deployment that exists today.
        let nat_cidrs: Vec<String> = if network.cidrs.is_empty() {
            vec![network.cidr.clone()]
        } else {
            network.cidrs.clone()
        };
        // #1882 — the same blocks are what reaches this process THROUGH the
        // mesh; remote desktop's ICE reads them to keep a session off the
        // overlay when the device asks it to.
        crate::overlay_footprint::note_v4_nets(&nat_cidrs);
        let _subnet_router = super::nat::enable(
            nat_if.as_deref().unwrap_or(super::tun::IF_NAME),
            &nat_cidrs,
            &self.advertised_routes,
        )
        .await;

        // P4 — publish the ingress destination scope from the SAME list that
        // just provisioned forwarding, so the filter and the forwarding it
        // guards can never disagree. Set before any peer is installed.
        wg.set_local_scope(Some(self_v4), &self.advertised_routes);

        // Inbound writer: decrypted packets → TUN. Independent of the
        // device, so it's a plain spawned task. It hands the device what is
        // already queued, never waiting for more, so a Linux offload device
        // can coalesce TCP runs (`tun_offload`) at no added latency.
        let writer_tun = tun.clone();
        let inbound = tokio::spawn(async move {
            let mut rx = tun_rx;
            let mut burst: Vec<Vec<u8>> = Vec::with_capacity(INBOUND_BURST_PKTS);
            while let Some(pkt) = rx.recv().await {
                burst.push(pkt);
                while burst.len() < INBOUND_BURST_PKTS
                    && let Ok(p) = rx.try_recv()
                {
                    burst.push(p);
                }
                if let Err(e) = writer_tun.write_packets(&mut burst).await {
                    debug!(%e, "overlay: TUN write failed; inbound writer exiting");
                    break;
                }
            }
        });

        // node_id → installed carrier (pubkey/IP/kind/install-time).
        let mut by_node: HashMap<ObjectId, Installed> = HashMap::new();
        // rc.139 — peers whose stale relay was just refreshed (anti-ping-pong).
        let mut relay_refresh_cooldown: HashMap<ObjectId, Instant> = HashMap::new();
        // C2 — the disco prober + its pong sink (plane-fed). Inert unless
        // `overlay_disco_probe` is on; the sink is `None` when this runtime
        // has no plane (the device demux feeds its own path in C2b).
        let mut disco = super::disco::Prober::new();
        let mut disco_rx = wg.take_disco_events();
        // rc.208 — in-flight make-before-break upgrade probes (node → metadata).
        // The shadow carriers live in `WgDevice::probes`; this tracks tier +
        // deadline for `sweep_upgrade_probes`. Empty unless the feature is on.
        let mut upgrade_probes: HashMap<ObjectId, UpgradeProbe> = HashMap::new();

        // NAT-traversal Phase B/C — gather our server-reflexive (srflx)
        // candidates and advertise them, so a peer behind a DIFFERENT NAT can
        // dial us at the public mapping our own STUN query opens, AND record the
        // PUNCH SOCKET (the interface socket that owns our first candidate) so we
        // dial a peer's srflx from it (Phase C hole-punch). This MUST run BEFORE
        // the eager demux below starts reading these sockets: the STUN reply
        // rides the same socket the overlay traffic will use (that's the point —
        // the NAT mapping has to match), so a demux recv loop would otherwise
        // steal the response. Best-effort + time-bounded, so a slow/unreachable
        // STUN server just leaves srflx unset this run. WG keepalives hold the
        // mapping for active sessions; Phase C's in-band keepalive (demux-routed
        // STUN, chunk 2) refreshes an idle mapping + re-trickles on change.
        // Captured for the Phase C keepalive task (chunk 2): the pinned STUN
        // server it re-queries, the candidates it started from (so it only
        // re-trickles on a CHANGE), and our probed NAT type (re-sent on each
        // re-trickle so the server never clears it). Empty/None ⇒ no keepalive.
        // Phase D note preserved: the gather also runs when single-relay is on
        // (even with srflx-direct off) — a single-relay DIALER advertises no
        // relay, so the ANCHOR permits its inbound by the IP it learns from
        // our srflx. R1 — the whole pass lives in
        // `gather_and_advertise_srflx` now (establish.rs), callable again by
        // the direct-plane rebuild; these three locals keep their original
        // roles (keepalive seed + reattach restore).
        let gathered = self
            .gather_and_advertise_srflx(&mut direct_ctx, &network.stun_urls)
            .await;
        let mut srflx_stun_server: Option<SocketAddr> = gathered.stun_server;
        let mut srflx_advertised: Vec<String> = gathered.advertised;
        let mut srflx_my_nat: Option<String> = gathered.my_nat;

        // Phase A/B — receiver for AUTHENTICATED inbound direct handshakes (a
        // NAT'd client dialing our public endpoint, or a known peer that roamed
        // to a new ephemeral port — the field-observed stale-port race). Wired
        // when EITHER public-dial tier is on (public-direct or srflx; CC8
        // flag-gate); the demux loops for our own sockets are started EAGERLY
        // here so an inbound INIT is read even before any peer is installed (an
        // exit with no other direct peers would otherwise never spawn a recv
        // loop for its public socket).
        let mut direct_events = if direct_ctx.is_some()
            && (direct::public_direct_enabled() || direct::srflx_enabled())
        {
            if let Some(ctx) = &direct_ctx {
                for (_ip, s) in &ctx.socks {
                    wg.ensure_direct_demux(s.clone());
                }
                if let Some(ps) = &ctx.public_sock {
                    wg.ensure_direct_demux(ps.clone());
                }
                if let Some(s6) = &ctx.v6 {
                    wg.ensure_direct_demux(s6.clone());
                }
            }
            wg.take_direct_events()
        } else {
            None
        };

        // Phase C (D5) — spawn the srflx keepalive/re-gather task. It re-queries
        // the PINNED STUN server on the punch socket every interval (via the
        // demux STUN sink wired just above) to hold an idle NAT mapping open and
        // re-advertise a changed one. Only when: srflx tier on, a punch socket +
        // STUN server resolved, an advert exists, and the interval isn't 0 (off).
        // rc.307 (B) — Reattach signal to the keepalive: bumped on every
        // re-join so the task (the sole owner of the EVOLVING advert)
        // restores it on the fresh session. Dropped when run() returns,
        // which ends the task.
        let (srflx_reattach_tx, srflx_reattach_rx) = tokio::sync::watch::channel(0u64);
        // Which re-advert path THIS org took, and whether it got one at all.
        // `overlay_shared_carrier=true` is supposed to mean "plane", but
        // winhost-a had it set and produced no plane log lines whatsoever —
        // there was no way to tell a plane-mode host from a legacy one, or a
        // spawned forwarder from a silently-skipped one, without this.
        // W5 — this runtime's OWN receiver on the plane's shared srflx watch,
        // consumed by a select arm below: the forwarder re-ADVERTISES on the
        // WS, but four runtime-local copies also go stale on a shared-state
        // change (DirectCtx.punch/my_nat, the relay coordinator's
        // udp_relay_ok, the srflx_* locals, the LocalAPI status) — before
        // this, `set_udp_relay_ok`'s only caller was the rebuild path, so a
        // NONE→SOME recovery left the node frozen as universal relay anchor.
        let mut plane_srflx_rx = self.carrier_plane.as_ref().map(|p| p.subscribe_srflx());
        let mut srflx_keepalive = if let Some(plane) = &self.carrier_plane {
            info!(
                self_v4 = %self_v4,
                "overlay: srflx re-advert via the carrier PLANE forwarder"
            );
            // Multi-org v2 — the plane owns the ONE keepalive (its sockets,
            // its STUN sink); this runtime only forwards mapping changes and
            // reattach restores onto ITS control WS.
            spawn_plane_srflx_forwarder(
                plane.subscribe_srflx(),
                self.outbound.clone(),
                srflx_reattach_rx,
                self_v4,
            )
        } else {
            info!(
                self_v4 = %self_v4,
                "overlay: srflx re-advert via the LEGACY per-org keepalive (no carrier plane)"
            );
            spawn_srflx_keepalive(
                &direct_ctx,
                srflx_stun_server,
                wg.take_stun_events(),
                &network.stun_urls,
                &srflx_advertised,
                &srflx_my_nat,
                self.outbound.clone(),
                srflx_reattach_rx,
                self.keypair.secret.to_bytes().to_vec(),
            )
        };
        if srflx_keepalive.is_none() {
            warn!(
                self_v4 = %self_v4,
                "overlay: this org has NO srflx re-advert task at all — a NAT \
                 rebind will strand every peer on a dead mapping until restart"
            );
        }
        // R3 — direct-plane rebuild scheduling: triggers (an addr/iface
        // event whose LAN-IP set actually changed, a resume-from-suspend, or
        // the embedder's fingerprint push) set the flag; ONE executor at the
        // top of the fallback tick runs the ordered sequence. `last_rebuild`
        // paces the net-change trigger; resume + embedder pushes clear it
        // (authoritative). `last_netcheck` debounces the gather behind
        // interface-event storms.
        let mut pending_rebuild: Option<&'static str> = None;
        let mut last_rebuild: Option<Instant> = None;
        let mut last_netcheck: Option<Instant> = None;

        // Latest netmap view (node_id → peer), so the fallback sweep can drive
        // the relay path for a downgraded peer without waiting for a netmap.
        let mut current_peers: HashMap<ObjectId, NetmapPeer> =
            first_peers.iter().map(|p| (p.node_id, p.clone())).collect();

        // Phase 2 MagicDNS — if the tenant set a domain, run a local split-DNS
        // resolver bound to our overlay IP:53, point the OS at it for that
        // domain, and keep the resolver's name→IP map synced with the netmap.
        // `None` when MagicDNS is off. `_dns_os_guard` reverts the OS DNS config
        // on runtime exit (WS disconnect / shutdown).
        // P5/Phase2 DNS. Compute the upstream once — the resolver's forward target
        // AND (when MagicDNS is off) the exit-DNS catch-all target. `dns_magic` is
        // the normalised suffix, `None` when MagicDNS is off.
        let dns_upstream = network
            .nameservers
            .iter()
            .find_map(|s| dns::parse_upstream(s))
            .unwrap_or_else(|| SocketAddr::from(([1, 1, 1, 1], 53)));
        let dns_magic: Option<String> = network
            .magic_domain
            .as_deref()
            .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty());
        let mut _dns_os_guard: Option<dns::DnsOsGuard> = None;
        // P5 S4b — did the local resolver actually bind :53? Only meaningful when
        // MagicDNS is on (else exit-DNS steers the public upstream directly). Gates
        // the "." steer so we never point the OS at a dead resolver (→ a total DNS
        // blackhole). Known before the first reconcile (awaited here), so there's
        // no late-bind race to chase.
        let mut dns_bound = false;
        // Owned so the teardown can stop it; see the ⚠️ at the spawn below.
        let mut dns_task: Option<tokio::task::JoinHandle<()>> = None;
        // FR-72 P2 — watched for the WHOLE session, not read once: the resolver
        // retries a failed bind, so it can come up long after the initial wait.
        let mut dns_bound_rx: Option<tokio::sync::watch::Receiver<bool>> = None;
        // FR-72 P6 — the last rung: where the OS DNS path is MEASURED not to
        // reach our resolver (a corporate DNS-enforcement layer refusing the
        // host's own queries), put the names in the hosts file instead.
        let mut dns_ladder: Option<dns_hosts::Ladder> = None;
        let dns_names: Option<dns::NameMap> = if let Some(magic_domain) = dns_magic.clone() {
            let names: dns::NameMap = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
            sync_name_map(
                &names,
                &current_peers,
                network.self_name.as_deref(),
                self_v4,
            )
            .await;
            // FR-72 P2 — a `watch`, not a `oneshot`: the resolver now retries a
            // failed bind, so "bound" can arrive AFTER the wait below gives up,
            // and the loop re-reads this to steer the OS late (see the tick arm).
            let (bound_tx, mut bound_rx) = tokio::sync::watch::channel(false);
            dns_bound_rx = Some(bound_rx.clone());
            // ⚠️ KEEP THIS HANDLE. `dns::run` serves until its socket errors, so
            // a spawned-and-forgotten resolver outlives the runtime that made
            // it and keeps `<self overlay ip>:53` bound. The runtime is scoped
            // to ONE WS session, so every reconnect spawned another one and the
            // new one lost the bind to its own predecessor — field-measured on
            // a corp laptop, two starts 14 s apart in one daemon lifetime:
            //
            //   INFO magicdns: resolver up            bind=100.65.4.30:53
            //   WARN magicdns: bind failed; resolver off  … AddressAlreadyInUse
            //
            // The survivor still answered, from the DEAD session's name map, so
            // every MagicDNS name NXDOMAIN'd while `roomler status` reported
            // whichever runtime's flag it happened to read — `active` or
            // `resolver DOWN` on the same host hours apart. It reads as a
            // third-party `:53` squatter and is not one: we were colliding with
            // ourselves. Aborted in the teardown below, beside every other task.
            dns_task = Some(tokio::spawn(dns::run(
                dns::DnsConfig {
                    bind: SocketAddr::new(self_v4.into(), 53),
                    magic_domain: magic_domain.clone(),
                    upstream: dns_upstream,
                    names: names.clone(),
                    // AAAA (derived overlay v6) default-on; ROOMLERD_DNS_AAAA=0
                    // reverts to A-only without a rebuild — the mixed-fleet escape
                    // hatch (an old peer's OS doesn't own its derived v6, so v6 to
                    // it blackholes; happy-eyeballs apps fall back, sequential apps
                    // may hang on it).
                    answer_aaaa: crate::env::node_env("DNS_AAAA").as_deref() != Some("0"),
                },
                bound_tx,
            )));
            // The bind is a local UDP bind — microseconds; bound the wait so a hung
            // reactor can't stall the join. Timeout / send-error → not-bound.
            dns_bound = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if *bound_rx.borrow_and_update() {
                        return true;
                    }
                    // Sender gone ⇒ the resolver task is dead; not bound.
                    if bound_rx.changed().await.is_err() {
                        return false;
                    }
                }
            })
            .await
            .unwrap_or(false);
            // Point the OS resolver at us for `<magic_domain>` (reverted on Drop).
            //
            // Multi-org P2a: gated on `dns_bound` — steering the OS at a
            // resolver that never bound (`:53` taken, netstack-style modes
            // where the self-IP isn't an OS address, bind race) blackholes
            // the magic domain HOST-WIDE (Windows NRPT is registry-global).
            // The exit-DNS "." steer already had exactly this gate; the
            // magic-domain steer predates it. Un-steered ⇒ names simply
            // don't resolve via the OS (SOCKS DOMAIN resolution still
            // works), surfaced below as `os_steer_active=false`.
            if dns_bound {
                _dns_os_guard =
                    Some(dns::configure_os(self_v4, &magic_domain, tun.os_name().as_deref()).await);
            } else {
                tracing::warn!(
                    %magic_domain,
                    "overlay dns: resolver did not bind :53 — NOT steering the OS \
                     (would blackhole the magic domain); names resolve via SOCKS only"
                );
            }
            // FR-72 P6. Constructed even when the switch is off, because the
            // constructor is also the BOOT RECONCILER: a block left by a
            // previous process must be cleared whether or not we will write one.
            dns_ladder = Some(dns_hosts::Ladder::new(
                magic_domain.clone(),
                crate::env::node_env("MAGICDNS_HOSTS").as_deref() == Some("1"),
            ));
            Some(names)
        } else {
            None
        };
        // S2 — record the DNS bring-up outcome for the LocalAPI view
        // (`roomler status` / the desktop's DNS section). `answer_aaaa`
        // recomputes the same expression the resolver was configured with.
        self.dns_status = dns_magic.clone().map(|magic_domain| DnsStatus {
            magic_domain,
            resolver_bound: dns_bound,
            os_steer_active: _dns_os_guard.as_ref().is_some_and(|g| g.active()),
            upstream: dns_upstream.to_string(),
            answer_aaaa: crate::env::node_env("DNS_AAAA").as_deref() != Some("0"),
            os_steer_bypassed: _dns_os_guard
                .as_ref()
                .and_then(|g| g.bypassed().map(str::to_string)),
        });

        // Independent of TURN coordination and the installed P2P/DERP carrier.
        let mut path_trials = path_trial::Engine::new();
        let _path_trial_view_guard = path_trial::ObservationViewGuard::new(
            self.peer_view.clone(),
            path_trials.observation_runtime_id(),
        );
        let mut path_trial_tick = tokio::time::interval(Duration::from_millis(500));
        path_trial_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut org_discovery = super::orgrelay::discovery::Discovery::default();
        let mut org_discovery_tick = tokio::time::interval(Duration::from_secs(11));
        org_discovery_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut fallback = tokio::time::interval(FALLBACK_TICK);
        let mut business_scout = tokio::time::interval(BUSINESS_SCOUT_TICK);
        business_scout.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut business_samples = HashMap::new();
        let mut standby_peers: HashMap<[u8; 32], Option<Instant>> = HashMap::new();
        let mut standby_watch = tokio::time::interval(STANDBY_WATCH_TICK);
        standby_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let probe_watch_on =
            super::direct::fast_probe_promote_enabled() && super::direct::probe_watch_enabled();
        let mut probe_watch = tokio::time::interval(PROBE_WATCH_TICK);
        probe_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // netstate PR-2 — subscribe to the process-wide network monitor
        // (typed deltas replace the P4 string feed; ONE OS registration per
        // process, see `netstate`). `None` (either kill-switch off /
        // platform-unavailable) = tick-only, the pre-P4 behaviour exactly.
        // Immaterial deltas still arrive (an erased peer /32 is
        // snapshot-invisible), so the route-guard erase contract holds; the
        // MAJOR fast lane below is what turns a VPN transition from
        // flag-parking into an inline forced sweep.
        let mut net_watch = if super::netstate::route_events_enabled() {
            super::netstate::handle().map(|h| h.subscribe())
        } else {
            debug!("overlay: net-change consumer disabled (OVERLAY_ROUTE_EVENTS=0)");
            None
        };
        let mut last_route_wave: Option<Instant> = None;
        // #1282 — set by the event arm's trailing edge, consumed by the tick it
        // pulled forward, so a wave an EVENT caused is not read as the blind
        // tick's (`evidence::ROUTE_WAVES_PULLED`).
        let mut tick_pulled = false;
        // netstate PR-2 — after a MAJOR change's inline forced sweep, walk
        // install_peers on EVERY fallback tick inside this window (instead of
        // the ~30 s reupgrade cadence) so re-selection lands right behind the
        // poke verdicts' handshake deadlines (~12-30 s), not half a minute
        // later.
        let mut fast_reupgrade_until: Option<Instant> = None;
        // Net-change poke acceleration — one-shot flag set by the addr/iface
        // route-event arm, consumed by the next fallback sweep: every
        // established DIRECT carrier gets a forced revalidation poke, so a
        // captured-route casualty (corp-VPN connect) dies at its handshake
        // deadline (~seconds) instead of waiting out `POKE_SILENCE_AFTER` +
        // the passive rx-stale race (~90 s observed, winhost-a 2026-08-15).
        let mut netchange_poke_due = false;
        // rc.146 — re-assert per-peer /32 routes so a full-tunnel VPN can't
        // keep its competing capture routes installed. First tick fires
        // immediately; skip it (routes are freshly installed by
        // `install_peers` below). P4 demotion: with a live subscription the
        // tick is a 30 s belt-and-braces heartbeat (events + their
        // trailing-edge pull do the real catching); without one — or if the
        // watch dies mid-session (the event arm's `None` leg) — it is the
        // 2 s war cadence.
        let route_cadence = route_guard_cadence(
            net_watch.is_some(),
            crate::env::node_env("OVERLAY_ROUTE_TICK_SECS"),
        );
        let mut route_guard = tokio::time::interval(route_cadence);
        route_guard.tick().await;
        info!(
            events = net_watch.is_some(),
            tick_secs = route_cadence.as_secs(),
            "overlay: route guard armed"
        );
        // Phase D — LAZY `/derp`: open the WS (via the agent-provided factory)
        // Historically ONLY for a relay-mode node that is itself UDP-blocked —
        // its srflx gather found nothing (`srflx_advertised.is_empty()`), the
        // exact condition under which the DERP strategy arm can pick it. The
        // factory is `FnOnce`, so `take()` it; a reconnect re-runs `run` and
        // re-decides from the fresh gather.
        //
        // Phase A1 (overlay v3) — with `overlay_derp_floor` on, the mux opens
        // UNCONDITIONALLY in relay mode: the floor contract is "every
        // floor-capable node is registered on `/derp` at all times", so a pair
        // can be floored at birth without predicting the peer's mux state
        // (the rc.393 deadlock class). One idle WSS per org; the server's
        // 30 s keepalive (#509) carries it.
        //
        // P7 — the factory is RETAINED (moved into a local, not consumed at
        // startup unless needed): a UDP-capable node can now be force-pinned
        // onto DERP mid-run by the server's `OverlayForceDerp` push, and the
        // handler invokes the factory at-most-once THEN — see the ForceDerp
        // arm.
        let mut derp_factory = self.derp_mux_factory.take();
        // Multi-region DERP — reusable per-URL opener for regional relays.
        let regional_derp_factory = self.regional_derp_factory.take();
        let derp_mux = if matches!(self.mode, CarrierMode::Relay)
            && (srflx_advertised.is_empty() || super::direct::derp_floor_enabled())
        {
            derp_factory.take().map(|f| f())
        } else {
            None
        };
        let mut relay = match self.mode {
            // Pass our LAN endpoints so the relay-endpoint trickle re-includes
            // them (the server replaces, so they'd otherwise be clobbered —
            // rc.135). Empty when the direct path is off.
            CarrierMode::Relay => {
                let mut r = RelayCoordinator::new(
                    self.outbound.clone(),
                    self.keypair.public.to_bytes(),
                    // Phase D — we can be the raw-UDP single-relay DIALER only if our
                    // own srflx gather succeeded (proof raw UDP to coturn works). A
                    // UDP-blocked host gathered none ⇒ it can only be the ANCHOR
                    // (TURNS/TCP allocation). The peer's equivalent is read off the
                    // netmap's `srflx_endpoints`, so the role choice is symmetric.
                    !srflx_advertised.is_empty(),
                    direct_ctx
                        .as_ref()
                        .map(|c| c.endpoints.clone())
                        .unwrap_or_default(),
                    derp_mux,
                );
                // W6 phase-2 — the full coturn worker IP set (uncapped
                // A-record resolve of the STUN hosts): the single-relay
                // dialer positively identifies the anchor's relayed address
                // with it; a NAT-less anchor's host addresses are public too,
                // and dialing one was the rx=0 QUIC rendezvous bug. One
                // resolve at startup; empty (DNS failure) = legacy pick.
                r.set_coturn_ips(direct::resolve_stun_worker_ips(&network.stun_urls).await);
                Some(r)
            }
            CarrierMode::Direct(_) => None,
        };
        // #27 — the demote-follow signal. ONE channel for every mux the
        // coordinator holds now or acquires later (central + regional); it
        // installs the sender as each arrives.
        let (mux_ev_tx, mut mux_ev_rx) = mpsc::channel::<crate::transport::derp::MuxEvent>(
            crate::transport::derp::DerpMux::EVENT_SINK_DEPTH,
        );
        if let Some(r) = relay.as_mut() {
            r.set_event_sink(mux_ev_tx);
        }
        // #27 — per-peer floor on how often a demote-follow may fire. The
        // signal is level-triggered (a demoted peer keeps relaying until we
        // converge), so without this a peer whose DERP build keeps failing
        // would re-follow on every inbound frame.
        let mut derp_follow_cooldown: HashMap<ObjectId, Instant> = HashMap::new();
        // C4 stage 1 — the warm-allocation manager's loop-side state
        // (measurement-only; see `warm_relay` module + docs/overlay-warm-relay.md).
        let warm_enabled =
            super::direct::warm_relay_enabled() && matches!(self.mode, CarrierMode::Relay);
        let mut warm = super::warm_relay::WarmRelay::default();
        let (warm_tx, mut warm_rx) = mpsc::channel::<super::warm_relay::WarmMsg>(4);
        let mut warm_tick = tokio::time::interval(std::time::Duration::from_secs(30));
        warm_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        if warm_enabled {
            info!("overlay warm relay: enabled — will establish once srflx proves UDP egress");
        }
        // Phase B (netcheck) — the measurement cadence. Rides the warm-grant
        // creds flow (`OverlayWarmRelayRequest` → `WarmRelayGrant`) with NO
        // new wire message: when a measurement is due, the tick requests
        // creds with `netcheck_pending` set, and the grant arm spawns the
        // dedicated probe allocation alongside (never instead of) the warm
        // machinery. A netstate Major invalidates the vector and pulls the
        // next measurement close.
        let netcheck_enabled =
            super::direct::netcheck_enabled() && matches!(self.mode, CarrierMode::Relay);
        let mut netcheck_next = Instant::now() + super::netcheck::NETCHECK_STARTUP_DELAY;
        let mut netcheck_pending = false;
        // The measurement clock — deliberately NOT the warm tick (see the
        // netcheck select arm): 15 s granularity against the minutes-scale
        // `netcheck_next` schedule.
        let mut netcheck_tick = tokio::time::interval(std::time::Duration::from_secs(15));
        netcheck_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // rc.211 — off-loop relay carrier builds (see `RelayBuildQueue`).
        // Created before the FIRST install so the startup batch can spawn too.
        let (built_tx, mut built_rx) = mpsc::channel::<BuiltRelay>(16);
        let mut relay_bq = RelayBuildQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx: built_tx,
        };
        // rc.218 — off-loop relay ALLOCATES (see `RelayAllocQueue`).
        // FR-19 P4b — off-loop org-relay binds, the same shape as the TURN
        // allocate queue right below.
        let (org_tx, mut org_rx) = mpsc::channel::<OrgBindDone>(16);
        let mut org_q = OrgBindQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx: org_tx,
        };
        let (alloc_tx, mut alloc_rx) = mpsc::channel::<AllocDone>(16);
        let mut alloc_q = RelayAllocQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx: alloc_tx,
        };
        self.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &first_peers,
            direct_ctx.as_ref(),
            &mut upgrade_probes,
            &mut relay_bq,
            "initial",
        )
        .await;
        // P5 exit-node — default-route capture state, reconciled after every
        // carrier change. Inert unless this node has `exit_node` configured.
        // P5 S4b — DNS-steering context for this run (immutable): whether MagicDNS
        // is on (→ steer "." at the LOCAL resolver `self_v4`, which forwards to the
        // network upstream via the exit; else steer "." at the public upstream
        // DIRECTLY), the catch-all target, and whether the local resolver bound.
        let dns_target = if dns_magic.is_some() {
            self_v4
        } else {
            match dns_upstream.ip() {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => Ipv4Addr::new(1, 1, 1, 1),
            }
        };
        let mut exit_state = ExitRoutingState {
            dns_magic_domain: dns_magic,
            dns_target: Some(dns_target),
            dns_bound,
            socks5_port: self.netstack_socks,
            ..Default::default()
        };
        self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state)
            .await;

        // Unification P1 — first LocalAPI view, so `roomler status` right after
        // join isn't empty until the first sweep (carries the exit-node status).
        self.publish_view(
            &self_ip,
            &by_node,
            &current_peers,
            &upgrade_probes,
            exit_node_status(self.exit_node.as_deref(), &exit_state),
            &wg,
            &path_trials,
            server_path_trial_v1,
        );

        // Phase C (D8) — re-upgrade tick counter (see `REUPGRADE_EVERY_N_TICKS`).
        let mut reupgrade_ticks: u32 = 0;

        // rc.206 — serializes the DETACHED route-guard re-assert (see the
        // `route_guard.tick()` arm): an owned `try_lock` drops any tick whose
        // predecessor batch is still running, so a slow Windows `netsh` sweep
        // never stacks concurrent delete-then-add mutations on the same prefix.
        let route_reassert_lock = Arc::new(tokio::sync::Mutex::new(()));

        // P8 — resume-from-suspend detector state (see `resumed_from_suspend`):
        // one (monotonic, wall) sample per sweep tick.
        let mut resume_probe = (Instant::now(), SystemTime::now());

        // rc.213 — dedicated outbound TUN reader (the Windows 1–2 s batching
        // fix). `tokio::select!` DROPS every losing arm's future each
        // iteration; a dropped `tun.read_packet()` future on Windows leaves its
        // blocking-pool thread parked in `WaitForMultipleObjects(INFINITE)` on
        // wintun's read event as a ZOMBIE waiter. The event releases ONE waiter
        // per edge, so an accumulated zombie usually swallows it and the live
        // read future starves — outbound packets then only left the ring when a
        // periodic arm (route guard 2 s / fallback 5 s) woke the loop and a
        // FRESH read future's `try_receive` drained the backlog. Field-proven
        // on devbox: buildhost-side tcpdump showed every overlay packet arriving in
        // bursts on exactly the union of those two timer grids (sub-ms aligned;
        // RTT sequence {2,2,1,1,2,2} s ⇒ the measured ~1.65 s averages) while
        // the raw wire RTT was 43 ms — and the rc.211 handler watchdog stayed
        // silent throughout, because the delay was future-PENDING time, which
        // no handler timer sees. A PERSISTENT reader task is never cancelled,
        // so exactly one event waiter exists and every edge lands on it; the
        // loop consumes via an mpsc arm, whose `recv()` is cancel-safe by
        // contract. Linux never suffered (level-triggered epoll on the tun fd,
        // no blocking-pool waiters) and shares the structure harmlessly.
        let (tun_pkt_tx, tun_pkt_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE_PKTS);
        let reader_tun = tun.clone();
        let tun_reader = tokio::spawn(async move {
            // One device read can carry many packets: every segment of a TSO
            // super-packet on a Linux offload device (`tun_offload`).
            let mut pkts: Vec<Vec<u8>> = Vec::new();
            loop {
                match reader_tun.read_packets(&mut pkts).await {
                    Ok(()) => {
                        // Reader-side twin of `warn_if_slow`: a slow send here
                        // means the channel is FULL — since P1 the consumer is
                        // the dedicated outbound PUMP, so a full queue indicts
                        // the send path itself (a wedged carrier send), not
                        // the control loop. Complements the pump's per-packet
                        // timer, which can't see future-PENDING time.
                        let t0 = Instant::now();
                        for pkt in pkts.drain(..) {
                            if tun_pkt_tx.send(pkt).await.is_err() {
                                return; // outbound pump gone
                            }
                        }
                        let ms = t0.elapsed().as_millis();
                        if ms > LOOP_STALL_WARN_MS {
                            warn!(
                                ms,
                                "overlay: outbound pump backpressured the TUN reader (send queue full — carrier send path wedged?)"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(%e, "overlay: TUN read ended; reader exiting");
                        break;
                    }
                }
            }
        });

        // P1 (S6) — the dedicated OUTBOUND PUMP: TUN packets → encapsulate →
        // carrier, in its own task via the shared [`WgSender`], so NO control
        // work on the select! loop can ever delay an outbound packet again
        // (the structural close of the rc.206→rc.218 inline-await arc; the
        // loop below is pure control plane). Pump death is FATAL, never
        // respawned: it only exits when the TUN reader died (`recv()` →
        // `None` — the same condition the pre-P1 loop arm broke on) or on a
        // panic in the send path (respawning would just re-panic on the next
        // packet); either way the loop breaks and the agent's WS lifecycle
        // rebuilds the whole runtime.
        let sender = wg.sender();
        let mut outbound_pump = tokio::spawn(async move {
            let mut rx = tun_pkt_rx;
            let mut burst: Vec<Vec<u8>> = Vec::with_capacity(OUTBOUND_BURST_PKTS);
            while let Some(pkt) = rx.recv().await {
                // Take what is ALREADY queued, never waiting for more: a lone
                // packet leaves exactly as before, while a burst shares one
                // routing pass, one Tunn lock per peer and (Linux, direct)
                // GSO sends — FR-110's batched-I/O lever.
                burst.push(pkt);
                while burst.len() < OUTBOUND_BURST_PKTS
                    && let Ok(p) = rx.try_recv()
                {
                    burst.push(p);
                }
                let t0 = Instant::now();
                let _ = sender.send_ip_batch(&burst).await;
                // >250 ms here is now PURE send-path latency (a wedged
                // carrier send), un-polluted by loop scheduling.
                warn_if_slow("pump:send_ip_batch", t0);
                burst.clear();
            }
            debug!("overlay: TUN reader ended; outbound pump exiting");
        });

        // Phase 2 — steady state. Control plane ONLY (P1): the data plane
        // runs reader → pump → carriers / demux → inbound writer, entirely
        // off-loop.
        loop {
            tokio::select! {
                changed = relay_listener_changed(&mut listener_changes) => {
                    if changed {
                        // Reannounce through the SAME authenticated socket.
                        // No Reattach: keep WG/direct paths and discovery state.
                        if self.outbound.send(self.make_join(advertised.clone())).await.is_err() {
                            warn!("overlay: listener readiness rejoin send failed; normal reattach will retry");
                        }
                    }
                }
                // P1 (S6) — the pump ending is the session-fatal signal the
                // TUN-reader `None` used to be.
                _ = &mut outbound_pump => {
                    debug!("overlay: outbound pump ended; runtime exiting");
                    break;
                },
                // Only lock-free traffic reads and a bounded fresh proof:
                // carrier verdicts, retries and the heavier work stay on the
                // original fallback cadence.
                _ = standby_watch.tick(), if !standby_peers.is_empty()
                    && by_node.values().any(|e| e.poke.is_some()) =>
                {
                    if super::direct::standby_copies_enabled()
                        && let Some(mux) = relay.as_ref().and_then(|r| r.derp_mux_handle())
                    {
                        self.arm_standby_tees(&wg, &by_node, &mux);
                    }
                }
                // F4 — promote a latched probe within one watch tick instead of
                // on the next 1 s scout tick (see `PROBE_WATCH_TICK`). A lock-free
                // latch read per probe; the promote is the scout arm's own.
                _ = probe_watch.tick(), if probe_watch_on && !upgrade_probes.is_empty() => {
                    let latched = upgrade_probes
                        .values()
                        .any(|p| wg.probe_handshake_done(&p.pubkey) == Some(true));
                    if latched {
                        self.sweep_upgrade_probes(
                            &mut wg, &mut by_node, &mut relay, &tun,
                            &mut upgrade_probes, &mut relay_bq,
                        ).await;
                        self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                        self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                    }
                }
                _ = business_scout.tick() => {
                    self.scout_business_traffic(&mut wg, &mut by_node, &mut business_samples);
                    // F1 — a proof armed here is convicted at its own deadline, not
                    // at whichever fallback tick comes next: only the fallback arm
                    // re-armed the recheck, so the verdict landed up to 5 s late
                    // (F0: the stall sat at 5.0 s, phase-locked to the tick).
                    if business_poke_fast()
                        && let Some(wait) = business_poke_recheck(&by_node, Instant::now())
                    {
                        fallback.reset_after(wait);
                    }
                    reconcile_org_recovery(&mut wg, &mut by_node, &mut relay, &mut org_q, &mut alloc_q, &mut relay_bq);
                    let followed = self.sweep_authenticated_derp_follow(&mut wg, &mut by_node, &mut relay, &current_peers);
                    let promoted = self.sweep_org_upgrades(&mut wg, &mut by_node, &mut relay, &current_peers);
                    // A latched make-before-break probe is promoted here, on the
                    // 1 s tick, rather than up to 5 s later on the fallback sweep;
                    // the exit-route reconcile below covers its new carrier.
                    let latched = super::direct::fast_probe_promote_enabled()
                        && upgrade_probes
                            .values()
                            .any(|p| wg.probe_handshake_done(&p.pubkey) == Some(true));
                    if latched {
                        self.sweep_upgrade_probes(
                            &mut wg, &mut by_node, &mut relay, &tun,
                            &mut upgrade_probes, &mut relay_bq,
                        ).await;
                    }
                    if super::direct::standby_copies_enabled()
                        && let Some(mux) = relay.as_ref().and_then(|r| r.derp_mux_handle())
                    {
                        self.sweep_standby(&mut wg, &by_node, &mux, &mut standby_peers).await;
                    }
                    if followed || promoted || latched {
                        self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                        self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                    }
                },
                // rc.211 — commit a finished OFF-LOOP relay carrier build (the
                // spawned QUIC-over-TURN rendezvous — see `RelayBuildQueue`).
                // The install half is µs. A STALE completion (peer removed /
                // went direct / superseded mid-build) is dropped; the next
                // netmap/sweep tick re-coordinates cleanly.
                built = built_rx.recv() => {
                    if let Some(built) = built {
                        let t_arm = Instant::now();
                        if relay_bq.take_if_current(&built.link.node_id, built.epoch) && current_peers.contains_key(&built.link.node_id) && !self.path_trial_managed.lock().unwrap_or_else(|e|e.into_inner()).contains(&built.link.node_id) {
                            let BuiltRelay { link, quic, .. } = built;
                            self.install_built(&mut wg, &mut by_node, &tun, link, quic).await;
                            // Same tail as a synchronous relay install: a new
                            // coturn worker may need an exit exemption, and the
                            // LocalAPI view must reflect the new carrier.
                            self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                            self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                        } else {
                            debug!(peer = %built.link.node_id, "overlay: dropping stale off-loop carrier build (peer removed/superseded mid-build)");
                        }
                        warn_if_slow("arm:relay_build_commit", t_arm);
                    }
                },
                // #27 — DEMOTE-FOLLOW. A `/derp` frame arrived that no local
                // conn could route, which means that peer has demoted to DERP
                // and we are still on a carrier it has abandoned. Follow it.
                //
                // This closes the one gap that made a VPN transition a
                // multi-minute outage rather than a blip: the hole is
                // `max(both ends)`, and the end whose network did NOT change
                // has no fast lane at all — it waits out `POKE_SILENCE_AFTER`
                // (floored by the ~25 s WG keepalive) plus its tier deadline.
                // Measured 2026-08-24: 67 s, with BOTH directions dark for the
                // whole window (our replies rode the abandoned path).
                //
                // The signal is trustworthy because the relay STAMPS the source
                // pubkey from the sender's authenticated registration — it is
                // not sender-chosen (`api::ws::derp::forward_frame`) — so it
                // can only name a node registered in this network whose ACL
                // permits reaching us. The worst a misbehaving member can do is
                // hold a pair on the relay it is already entitled to use, and
                // make-before-break re-upgrades it anyway.
                Some(ev) = mux_ev_rx.recv() => {
                    let t_arm = Instant::now();
                    match ev {
                        crate::transport::derp::MuxEvent::Unrouted(pk) => {
                            let installed = self.demote_follow(
                                pk, &mut wg, &mut by_node, &mut relay, &tun,
                                &current_peers, &mut relay_bq, &mut derp_follow_cooldown,
                            ).await;
                            if installed {
                                // Same tail as any other carrier flip: the relay
                                // set may need a new exit exemption, and the
                                // LocalAPI view must show the carrier the peer
                                // is actually on.
                                self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                                self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                            }
                        }
                        // #28 — the `/derp` WS is back. EVERY DERP build
                        // attempted during the outage was withheld (a carrier
                        // born over a dead WS convicts one-way and rebuilds
                        // forever), so those peers are carrier-less RIGHT NOW
                        // and the establish walk is what re-floors them.
                        //
                        // Open a short fast-walk window and pull the fallback
                        // tick into it — the same two levers the netstate-Major
                        // lane uses, for the same reason: without the window
                        // `install_peers` only runs every 6th tick (~30 s), and
                        // without the pull-forward the window's first walk
                        // waits out the 5 s grid. Field 2026-08-24: the WS
                        // returned in 1.5 s and the floor still took 5 s more.
                        crate::transport::derp::MuxEvent::Recovered => {
                            info!(
                                "overlay derp: /derp WS recovered — walking now to rebuild the carriers withheld during the outage"
                            );
                            fast_reupgrade_until =
                                Some(Instant::now() + DERP_RECOVERY_WALK_WINDOW);
                            fallback.reset_after(DERP_RECOVERY_RECHECK);
                        }
                    }
                    warn_if_slow("arm:derp_mux_event", t_arm);
                },
                // rc.218 — commit a finished OFF-LOOP relay ALLOCATE (the
                // spawned DNS + TURN allocate — see `RelayAllocQueue`). Success
                // advertises + tries to build (µs, on-loop by design: the
                // `OverlayEndpoints` trickle reads coordinator state); failure
                // FORGETS the peer so the next netmap/sweep tick re-requests —
                // the old inline path parked a failed peer in `pending`
                // forever, with nothing to ever retry it.
                done = alloc_rx.recv() => {
                    if let Some(done) = done {
                        let t_arm = Instant::now();
                        if alloc_q.take_if_current(&done.node_id, done.epoch) {
                            if let Some(r) = relay.as_mut() {
                                match done.conn {
                                    Some(conn) => {
                                        let link = r.commit_alloc(done.node_id, conn).await;
                                        if let Some(link) = link {
                                            let t0 = Instant::now();
                                            self.install_ready(&mut wg, &mut by_node, &tun, link, &mut relay_bq).await;
                                            warn_if_slow("install_ready(spawn-or-sync)", t0);
                                            // Same tail as the old inline grant path: a
                                            // newly-installed relay carrier adds a coturn
                                            // worker to exempt, and the LocalAPI view must
                                            // reflect the new carrier.
                                            self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                                            self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                                        }
                                    }
                                    None => {
                                        warn!(peer = %done.node_id, "overlay relay: off-loop allocate failed — dropping coordination (re-requested next tick)");
                                        r.forget(&done.node_id);
                                    }
                                }
                            }
                        } else {
                            debug!(peer = %done.node_id, "overlay: dropping stale off-loop allocate (peer superseded mid-allocate)");
                        }
                        warn_if_slow("arm:relay_alloc_commit", t_arm);
                    }
                },
                // FR-19 P4b — an off-loop org-relay bind finished: report what
                // was measured, then commit the carrier (µs) or drop the session.
                done = org_rx.recv() => {
                    if let Some(done) = done {
                        let t_arm = Instant::now();
                        // Every endpoint tried is reported — the server ranks
                        // relays for the NEXT mint on these, and accepts them
                        // only about (relay, endpoint) pairs it minted for us.
                        for o in &done.outcomes {
                            let _ = self
                                .outbound
                                .send(ClientMsg::OverlayRelayProbe {
                                    relay_node_id: done.relay_node_id,
                                    endpoint: o.endpoint.to_string(),
                                    reachable: o.reachable,
                                    rtt_ms: o.rtt.map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
                                })
                                .await;
                        }
                        if let Some(r) = relay.as_mut() {
                            if let Some(link) = commit_current_org_bind(
                                done, &mut org_q, &current_peers, &by_node, r,
                            ) {
                                let t0 = Instant::now();
                                self.install_ready(&mut wg, &mut by_node, &tun, link, &mut relay_bq).await;
                                warn_if_slow("install_ready(org-relay)", t0);
                                self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                                self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                            }
                        } else if let Some(conn) = done.conn {
                            conn.close();
                        }
                        warn_if_slow("arm:org_bind_commit", t_arm);
                    }
                },
                // rc.136 — direct→relay fallback sweep. A DIRECT carrier whose
                // handshake never completes (or dies mid-session) means the LAN
                // path only LOOKED viable (same subnet) but isn't actually
                // reachable — a corp full-tunnel VPN that hijacks routing, Wi-Fi
                // AP/client isolation, an asymmetric firewall. Tear it down and
                // switch the peer to relay (with a cooldown so the next netmap
                // doesn't immediately re-upgrade it to direct).
                _ = fallback.tick() => {
                    let t_arm = Instant::now();
                    // FR-72 P2 — the resolver retries its bind, so it may come up
                    // after the bring-up wait already concluded "not bound" and
                    // WITHHELD the OS steer. Without this the retry is pointless:
                    // a bound resolver nobody is steered at answers nothing, which
                    // is exactly the state a corp laptop sat in for hours.
                    //
                    // ⚠️ One-way on purpose. This installs the steer when the bind
                    // finally lands; it never REVOKES it, because the guard's Drop
                    // already reverts on teardown and a flap must not repeatedly
                    // rewrite the host-global NRPT.
                    // FR-72 P6 — pick the resolution rung by measurement. Cheap
                    // (one `getaddrinfo` a minute) and it climbs back to DNS on
                    // its own, so a host that is only briefly enforced does not
                    // keep hosts entries.
                    if let (Some(l), Some(names)) = (dns_ladder.as_mut(), dns_names.as_ref()) {
                        l.tick(names, crate::env::node_env("DNS_AAAA").as_deref() != Some("0"))
                            .await;
                    }
                    if _dns_os_guard.is_none()
                        && let Some(rx) = dns_bound_rx.as_mut()
                        && *rx.borrow_and_update()
                        && let Some(magic_domain) = exit_state.dns_magic_domain.clone()
                    {
                        info!(%magic_domain, "magicdns: resolver bound late — steering the OS now");
                        _dns_os_guard = Some(
                            dns::configure_os(self_v4, &magic_domain, tun.os_name().as_deref()).await,
                        );
                        // The exit-DNS "." steer is gated on the same fact.
                        exit_state.dns_bound = true;
                        self.dns_status = Some(DnsStatus {
                            magic_domain: magic_domain.clone(),
                            resolver_bound: true,
                            os_steer_active: _dns_os_guard.as_ref().is_some_and(|g| g.active()),
                            upstream: dns_upstream.to_string(),
                            answer_aaaa: crate::env::node_env("DNS_AAAA").as_deref() != Some("0"),
                            os_steer_bypassed: _dns_os_guard
                                .as_ref()
                                .and_then(|g| g.bypassed().map(str::to_string)),
                        });
                    }
                    // FR-19 P4b — expire org-relay sessions past their lifetime
                    // and spawn the binds `request` decided on since the last
                    // pass (a bind is a network round trip: never on-loop).
                    if let Some(r) = relay.as_mut() {
                        for p in r.reap_org_sessions(Instant::now()) {
                            org_q.invalidate(&p);
                            cancel_org_upgrade_candidate(&p, &mut wg, &mut by_node);
                            debug!(peer = %p, "overlay relay: org-relay session expired (absolute lifetime)");
                        }
                        for job in r.take_org_jobs() {
                            let label = current_peers.get(&job.relay_node_id).map(|p| p.name.clone()).unwrap_or_else(|| job.relay_node_id.to_hex());
                            let epoch = org_q.stamp(job.node_id);
                            spawn_org_bind(job, label, epoch, org_q.tx.clone());
                        }
                    }
                    // P8 — resume-from-suspend: wall-vs-monotonic skew across
                    // the tick means the host slept. Every installed carrier is
                    // dead (NAT/pinhole state expired; peers tore their ends
                    // down while we slept) and every cooldown is stale
                    // evidence — drop both and re-coordinate NOW instead of
                    // letting the sweeps discover the corpses one deadline at
                    // a time (field 2026-07-25: a hibernate wake-up left the
                    // mesh relay-wedged for hours).
                    let (prev_mono, prev_wall) = resume_probe;
                    let wall_elapsed = SystemTime::now()
                        .duration_since(prev_wall)
                        .unwrap_or_default();
                    let mono_elapsed = prev_mono.elapsed();
                    resume_probe = (Instant::now(), SystemTime::now());
                    if resumed_from_suspend(mono_elapsed, wall_elapsed) {
                        warn!(
                            slept_s = wall_elapsed.as_secs(),
                            "overlay: resume from suspend — dropping all carriers + path penalties for fresh re-coordination"
                        );
                        let nids: Vec<ObjectId> = by_node.keys().copied().collect();
                        for nid in nids {
                            // Through the shared teardown: this used to leave
                            // `upgrade_probes` populated, so a later
                            // `promote_direct_probe` could re-upsert a STALE
                            // probe.overlay_ip and hijack a recycled address.
                            self.remove_peer_state(
                                nid, &mut wg, &mut by_node, &tun, &mut relay,
                                &mut relay_bq, Some(&mut alloc_q), &mut upgrade_probes,
                                PeerRoute::Drop,
                            ).await;
                        }
                        relay_refresh_cooldown.clear();
                        // P3 PR-A — same clean slate in the monitor (probe
                        // bookkeeping survives, like `upgrade_probes` does).
                        self.shadow(|s| s.mon.on_resume());
                        // R3 — a laptop resumes on a DIFFERENT network more
                        // often than the same one, and the old sockets are
                        // pinned (IP_UNICAST_IF) to pre-sleep interfaces —
                        // rebuild the whole direct plane rather than reusing
                        // the sockets verbatim (the pre-R3 behavior). The
                        // executor below rebinds + re-joins + re-gathers +
                        // installs; authoritative, so the cooldown clears.
                        if let Some(plane) = &self.carrier_plane {
                            // Multi-org v2 — the plane owns the sockets, so
                            // the rebuild is plane-wide (every org tears
                            // down, ONE re-bind, every org re-establishes).
                            plane.request_rebuild("resume", true);
                        } else {
                            pending_rebuild = Some("resume");
                            last_rebuild = None;
                        }
                    }
                    // R3 — the ONE direct-plane rebuild executor: triggers
                    // only set `pending_rebuild`; this runs the ordered
                    // sequence (teardown → retire → rebind → demux → join →
                    // gather → coordinator swap → keepalive respawn →
                    // re-establish). Ordering is load-bearing throughout —
                    // see `rebuild_direct_plane_sockets` and the join/gather
                    // contract on `gather_and_advertise_srflx`.
                    if let Some(reason) = pending_rebuild {
                        let rebuild_due =
                            last_rebuild.is_none_or(|t| t.elapsed() >= REBUILD_COOLDOWN);
                        if rebuild_due {
                            pending_rebuild = None;
                            last_rebuild = Some(Instant::now());
                            let t0 = Instant::now();
                            warn!(reason, "overlay: rebuilding the direct plane");
                            // The keepalive owns a punch-socket Arc by value —
                            // down first so the old ports can actually free.
                            if let Some(h) = srflx_keepalive.take() {
                                h.abort();
                            }
                            let stun_rx = self
                                .rebuild_direct_plane_sockets(
                                    &mut wg, &mut by_node, &mut upgrade_probes, &mut relay,
                                    &mut relay_bq, &mut alloc_q, &tun, &mut direct_ctx,
                                )
                                .await;
                            // Fresh join FROM THE NEW PLANE (the server's
                            // re-join updates lan_endpoints AND clears srflx
                            // — which is why the gather comes after).
                            advertised = base_endpoints.clone();
                            if let Some(ctx) = direct_ctx.as_ref() {
                                advertised.extend(ctx.endpoints.iter().cloned());
                            }
                            if self
                                .outbound
                                .send(self.make_join(advertised.clone()))
                                .await
                                .is_err()
                            {
                                warn!("overlay: rebuild join failed (detached); reattach will re-join");
                            }
                            let gathered = self
                                .gather_and_advertise_srflx(&mut direct_ctx, &network.stun_urls)
                                .await;
                            srflx_stun_server = gathered.stun_server;
                            srflx_advertised = gathered.advertised;
                            srflx_my_nat = gathered.my_nat;
                            if let Some(r) = relay.as_mut() {
                                r.set_lan_endpoints(
                                    direct_ctx
                                        .as_ref()
                                        .map(|c| c.endpoints.clone())
                                        .unwrap_or_default(),
                                );
                                r.set_udp_relay_ok(!srflx_advertised.is_empty());
                            }
                            srflx_keepalive = if let Some(plane) = &self.carrier_plane {
                                spawn_plane_srflx_forwarder(
                                    plane.subscribe_srflx(),
                                    self.outbound.clone(),
                                    srflx_reattach_tx.subscribe(),
                                    self_v4,
                                )
                            } else {
                                spawn_srflx_keepalive(
                                    &direct_ctx,
                                    srflx_stun_server,
                                    stun_rx,
                                    &network.stun_urls,
                                    &srflx_advertised,
                                    &srflx_my_nat,
                                    self.outbound.clone(),
                                    srflx_reattach_tx.subscribe(),
                                    self.keypair.secret.to_bytes().to_vec(),
                                )
                            };
                            let peers_now: Vec<NetmapPeer> =
                                current_peers.values().cloned().collect();
                            self.install_peers(
                                &mut wg, &mut by_node, &mut relay, &tun, &peers_now,
                                direct_ctx.as_ref(), &mut upgrade_probes, &mut relay_bq,
                                "rebuild",
                            ).await;
                            self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                            self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                            warn_if_slow("rebuild_direct_plane", t0);
                        }
                    }
                    let t0 = Instant::now();
                    // #26 — the parked flag is the ADDR/IFACE cause; a Major
                    // never reaches here (its lane consumes the flag inline).
                    // The distinction decides the conviction window, so it is
                    // a type, not a bool: see `ForcedPoke`.
                    let carrier_lost = self.sweep_and_repair_carriers(
                        &mut wg, &mut by_node, &mut relay, &tun,
                        &mut relay_refresh_cooldown, &current_peers,
                        if std::mem::take(&mut netchange_poke_due) {
                            ForcedPoke::AddrIface
                        } else {
                            ForcedPoke::No
                        },
                        direct_ctx.as_ref(), &mut upgrade_probes, &mut relay_bq,
                    ).await;
                    warn_if_slow("sweep_and_repair_carriers", t0);
                    if let Some(wait) = business_poke_recheck(&by_node, Instant::now()) {
                        fallback.reset_after(wait);
                    }
                    // C2 — disco round: one out-of-tunnel echo per direct
                    // carrier over the path it actually uses, then absorb the
                    // replies. MEASUREMENT ONLY — nothing below reads the
                    // table to make a routing decision (that is C3/C6, behind
                    // their own flags). Default OFF.
                    self.disco_round(&mut disco, &mut path_trials, &mut disco_rx, &wg, &by_node, &current_peers, direct_ctx.as_ref()).await;
                    // rc.208 — make-before-break: promote any upgrade probe whose
                    // handshake latched (cut over to direct, drop the relay) and
                    // expire any that missed its deadline (keep the relay). Inert
                    // when the feature is off / no probes are in flight.
                    let t0 = Instant::now();
                    self.sweep_upgrade_probes(
                        &mut wg, &mut by_node, &mut relay, &tun,
                        &mut upgrade_probes, &mut relay_bq,
                    ).await;
                    warn_if_slow("sweep_upgrade_probes", t0);
                    request_reconciled_org_fallbacks(
                        self.org_primary && super::direct::org_relay_enabled() && server_org_discovery && server_org_fallback,
                        &mut wg, &mut by_node, &current_peers, &mut relay,
                        &mut org_q, &mut alloc_q, &mut relay_bq, Instant::now(),
                    ).await;
                    // D8 — periodic direct re-upgrade (~every 6th tick ≈ 30 s).
                    // A lapsed cooldown only takes effect on the next netmap
                    // otherwise; a quiet mesh would never re-attempt direct after
                    // a fallback. Re-run the tier evaluation over the current
                    // netmap — install_peers no-ops on already-direct peers and
                    // won't re-request a relay it's already tracking, so this only
                    // (a) retries a direct tier whose cooldown lapsed and (b)
                    // drives Phase C punch convergence at large install skew.
                    reupgrade_ticks = reupgrade_ticks.wrapping_add(1);
                    // netstate PR-2 — inside the post-Major fast window, walk
                    // EVERY tick so re-selection lands right behind the forced
                    // sweep's handshake verdicts instead of at the 30 s cadence.
                    let fast_walk = fast_reupgrade_until.is_some_and(|t| Instant::now() < t);
                    if fast_reupgrade_until.is_some() && !fast_walk {
                        fast_reupgrade_until = None;
                    }
                    // §6.3 F3 — a peer convicted by an active proof is in its
                    // fast-return lane: walk every tick so the next direct
                    // attempt follows each short in-lane penalty at once.
                    let fast_walk = fast_walk
                        || self
                            .shadow(|s| s.mon.fast_return_active(Instant::now()))
                            .unwrap_or(false);
                    // A loss already walked every peer in this same pass.
                    if !carrier_lost && (fast_walk || reupgrade_ticks.is_multiple_of(REUPGRADE_EVERY_N_TICKS)) {
                        let peers: Vec<NetmapPeer> = current_peers.values().cloned().collect();
                        let t0 = Instant::now();
                        self.install_peers(
                            &mut wg, &mut by_node, &mut relay, &tun,
                            &peers, direct_ctx.as_ref(), &mut upgrade_probes,
                            &mut relay_bq, if fast_walk { "net-change-walk" } else { "reupgrade" },
                        ).await;
                        warn_if_slow("install_peers(reupgrade)", t0);
                    }
                    // A carrier flip may have changed the coturn worker set or
                    // the exit peer's reachability — re-reconcile exit routing
                    // FIRST, so the refreshed view carries the new exit status.
                    let t0 = Instant::now();
                    self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state)
                        .await;
                    warn_if_slow("reconcile_exit_routing(sweep)", t0);
                    // A direct→relay fallback (or relay refresh) changed how we
                    // reach a peer (and maybe the exit status) — refresh the view.
                    self.publish_view(
                        &self_ip,
                        &by_node,
                        &current_peers,
                        &upgrade_probes,
                        exit_node_status(self.exit_node.as_deref(), &exit_state),
                        &wg, &path_trials, server_path_trial_v1);
                    warn_if_slow("arm:fallback_sweep", t_arm);
                },
                // rc.146 — re-assert every installed peer's /32 on the overlay
                // NIC (evict any competing route a full-tunnel VPN re-added, then
                // re-add ours at low metric). Unconditional: a captured route
                // keeps our packets off the WG device, so the carrier's traffic
                // counters can't detect it — only a periodic re-assert can.
                _ = route_guard.tick() => {
                    // A tick wave counts as a wave for the event arm's rate
                    // limiter / trailing edge (P4 demotion — both arms share
                    // one wave clock).
                    last_route_wave = Some(Instant::now());
                    let pulled = std::mem::take(&mut tick_pulled);
                    // rc.206 — DETACH the per-peer /32 re-assert (the head-of-line
                    // bulk on Windows: N peers × `route`/`netsh` delete-then-add,
                    // ~0.3–2 s each) off the select! loop. Awaiting it INLINE
                    // stalled the outbound TUN-packet arm above (select! doesn't
                    // re-poll a sibling arm while the chosen handler awaits), so
                    // outbound packets piled unread in the wintun ring → ~1.8 s
                    // Windows RTT (lossless, just delayed) vs Linux's ~40 ms (one
                    // fast `ip route replace`). The owned `try_lock` drops a tick
                    // whose predecessor is still running (a slow batch must never
                    // stack concurrent delete-then-add on the same prefix) and
                    // releases on task end/panic. Worst case a since-removed peer
                    // leaves a harmless dangling /32 to a dead overlay IP (traffic
                    // there drops anyway; `store=active` clears on reboot).
                    if let Ok(guard) = route_reassert_lock.clone().try_lock_owned() {
                        let tun2 = tun.clone();
                        // rc.285 — the wave runs the DECLARATIVE defended set
                        // (every peer /32, then our own /32 + v6 twins —
                        // composed in one place, `route_guard::defended_routes`).
                        let set = defended_routes(&by_node, self_v4);
                        // #1282 — attribute the wave to the TICK arm.
                        crate::evidence::ROUTE_WAVES_TICK
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if pulled {
                            crate::evidence::ROUTE_WAVES_PULLED
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        tokio::spawn(async move {
                            let _guard = guard;
                            run_defense_wave(tun2, set).await;
                        });
                    }
                    // P5 — the exit split-default /1 re-assert stays INLINE (NOT
                    // detached): a background task with a stale `split` snapshot
                    // could re-install a /1 that `teardown_exit_routing` (running
                    // on THIS loop) had just purged, black-holing the host's whole
                    // egress with no exit carrier to forward it — and the
                    // edge-triggered teardown would never heal it (self-wedge).
                    // Inline keeps it mutually exclusive with teardown. It's ≤4
                    // route calls and fires only on exit-node clients
                    // (`split_default_installed` is false everywhere else →
                    // skipped), so it isn't the latency bulk. Mirrors the per-peer
                    // /32 war (A7): a competing full-tunnel VPN default can't
                    // reclaim egress.
                    if exit_state.split_default_installed {
                        let t0 = Instant::now();
                        for cidr in SPLIT_DEFAULT_V4.iter().chain(SPLIT_DEFAULT_V6.iter()) {
                            tun.add_cidr_route(cidr).await.ok();
                        }
                        warn_if_slow("arm:route_guard(exit /1)", t0);
                    }
                },
                // P4 — OS route-table change → re-assert NOW (same body as the
                // tick above: detached /32 wave + inline exit /1). Rate-
                // limited to one wave per ROUTE_WAVE_MIN_INTERVAL because our
                // own re-asserts feed the subscription back; an event inside
                // the quiet window pulls the next tick to the due boundary
                // (trailing edge), so a quiet-window erase is repaired within
                // ROUTE_WAVE_MIN_INTERVAL — the demoted 30 s heartbeat never
                // carries it. Inert (`pending`) when the subscription is
                // off/unavailable.
                net_evt = async {
                    match net_watch.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match net_evt {
                        Ok(delta) => {
                            // R3 — an ADDRESS/INTERFACE-classed burst (N4) is
                            // the roam signal: gate on the ONLY thing that
                            // justifies a plane rebuild — the sorted LAN IP
                            // SET actually changed (IPs, never ifindexes,
                            // which Windows renumbers without addresses
                            // changing). Route-only bursts never trigger: a
                            // filter-only VPN changes no addresses, and the
                            // Major fast lane below owns that class.
                            if delta.saw_addr_signal || delta.saw_iface_signal {
                                let check_due = last_netcheck.is_none_or(|t| {
                                    t.elapsed() >= super::netstate::ROUTE_WAVE_MIN_INTERVAL
                                });
                                if check_due && pending_rebuild.is_none() {
                                    last_netcheck = Some(Instant::now());
                                    // W5(c) — poke the plane srflx task
                                    // UNCONDITIONALLY: a corp-VPN connect
                                    // changes NAT reality without touching the
                                    // LAN-IP set (the VPN adapter is
                                    // deny-listed from the gather). Notify
                                    // coalesces; SEEKING re-gathers now,
                                    // ESTABLISHED re-verifies the mapping.
                                    if let Some(plane) = &self.carrier_plane {
                                        plane.notify_regather();
                                    }
                                    if direct::netchange_poke_enabled() {
                                        netchange_poke_due = true;
                                    }
                                    let mut now_ips = direct::gather_lan_ips();
                                    now_ips.sort_unstable();
                                    let mut plane_ips: Vec<Ipv4Addr> = direct_ctx
                                        .as_ref()
                                        .map(|c| c.my_ips.clone())
                                        .unwrap_or_default();
                                    plane_ips.sort_unstable();
                                    if now_ips != plane_ips {
                                        info!(
                                            ?now_ips, ?plane_ips,
                                            "overlay: LAN address set changed — scheduling a direct-plane rebuild"
                                        );
                                        if let Some(plane) = &self.carrier_plane {
                                            plane.request_rebuild("net-change", false);
                                        } else {
                                            pending_rebuild = Some("net-change");
                                        }
                                    }
                                }
                            }
                            // netstate PR-2 — the MAJOR fast lane: the network
                            // materially moved (default route changed identity
                            // or addresses vanished). Don't park flags for the
                            // next 5 s tick — the E1 lab measured that parking
                            // as pure loss on a 28-50 s conn-side outage:
                            //   1. stale path evidence dies now (the old
                            //      network's scores/penalties/stickies mean
                            //      nothing on the new one),
                            //   2. every established carrier gets its forced
                            //      revalidation NOW (casualties die at their
                            //      handshake deadlines, ~12-30 s),
                            //   3. re-selection walks EVERY tick for the next
                            //      25 s so the verdicts are acted on as they
                            //      land, not at the ~30 s reupgrade cadence.
                            if delta.material
                                && delta.severity == super::netstate::Severity::Major
                                && direct::netchange_poke_enabled()
                            {
                                // Dialer honesty — a new network is a new
                                // egress policy: drop the not-dialer-capable
                                // latch and re-earn it (worst case one more
                                // failed dialer cycle). The sweep below syncs
                                // the coordinator mirror; the periodic srflx
                                // advert re-publishes the reset verdict.
                                super::dialer::reset_on_network_change();
                                // Phase B — the capability vector describes a
                                // network that no longer exists; invalidate
                                // and re-measure once the transition settles.
                                super::netcheck::invalidate_on_network_change();
                                netcheck_next = Instant::now() + Duration::from_secs(60);
                                if let Some(coord) = relay.as_mut() {
                                    coord.set_udp_dialer_ok(super::dialer::udp_dialer_ok());
                                    // B3 — the invalidate above just emptied
                                    // the slot; mirror the absence so roles
                                    // fall back to presence rules until the
                                    // re-measure lands.
                                    coord.set_relay_band_udp(
                                        super::netcheck::current_fresh()
                                            .and_then(|v| v.relay_band_udp),
                                    );
                                }
                                self.shadow(|s| s.mon.on_network_changed());
                                netchange_poke_due = false; // consumed inline
                                let t0 = Instant::now();
                                self.sweep_carrier_health(
                                    &mut wg, &mut by_node, &mut relay, &tun,
                                    &mut relay_refresh_cooldown, &current_peers,
                                    ForcedPoke::Major,
                                ).await;
                                warn_if_slow("sweep_carrier_health(net-change)", t0);
                                fast_reupgrade_until =
                                    Some(Instant::now() + Duration::from_secs(25));
                                // #26 — the sweep above only ARMED the pokes;
                                // the verdict lands on the next tick. Pull it
                                // to the deadline so the pokes are judged when
                                // they expire rather than at the next grid
                                // point, and the same tick re-floors the
                                // casualties (the fast_reupgrade window just
                                // opened makes `install_peers` run behind the
                                // sweep). Phase-shifting the fallback grid is
                                // harmless: every tick body is idempotent and
                                // the D8 re-upgrade counter is a modulo.
                                fallback.reset_after(MAJOR_RECHECK_AFTER);
                            }
                            // The route wave rides EVERY delta — including
                            // immaterial ones (an erased peer /32 is
                            // snapshot-invisible; that wake-up is the whole
                            // P4 erase contract).
                            let due = last_route_wave
                                .is_none_or(|t| t.elapsed() >= super::netstate::ROUTE_WAVE_MIN_INTERVAL);
                            if due {
                                last_route_wave = Some(Instant::now());
                                let summary_short: String = delta.summary.chars().take(120).collect();
                                info!(
                                    material = delta.material, first = %summary_short,
                                    "overlay: network change — re-asserting peer routes now (netstate event-driven; heartbeat tick is the backstop)"
                                );
                                if let Ok(guard) = route_reassert_lock.clone().try_lock_owned() {
                                    let tun2 = tun.clone();
                                    // rc.285 — the same declarative set as the
                                    // tick arm. A VPN connect is exactly the
                                    // route storm that re-adds the hijacking
                                    // /32 for our own address; evict it NOW
                                    // rather than waiting for the 2 s tick.
                                    let set = defended_routes(&by_node, self_v4);
                                    // #1282 — attribute the wave to the EVENT arm.
                                    crate::evidence::ROUTE_WAVES_EVENT
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    tokio::spawn(async move {
                                        let _guard = guard;
                                        run_defense_wave(tun2, set).await;
                                    });
                                }
                                // P5 exit /1 — INLINE for the same teardown-
                                // mutual-exclusion reason as the tick arm.
                                if exit_state.split_default_installed {
                                    let t0 = Instant::now();
                                    for cidr in SPLIT_DEFAULT_V4.iter().chain(SPLIT_DEFAULT_V6.iter()) {
                                        tun.add_cidr_route(cidr).await.ok();
                                    }
                                    warn_if_slow("arm:net_events(exit /1)", t0);
                                }
                                // The heartbeat counts from the last wave.
                                route_guard.reset();
                                tick_pulled = false;
                            } else {
                                // Trailing edge: pull the next tick to the due
                                // boundary so an erase inside the quiet window
                                // waits ≤ ROUTE_WAVE_MIN_INTERVAL, not a full
                                // heartbeat.
                                tick_pulled = true;
                                let elapsed = last_route_wave
                                    .map(|t| t.elapsed())
                                    .unwrap_or_default();
                                route_guard.reset_after(
                                    super::netstate::ROUTE_WAVE_MIN_INTERVAL
                                        .saturating_sub(elapsed),
                                );
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                            // Only possible if THIS loop stalled behind 16+
                            // deltas. State was never lost (the snapshot has
                            // it) — reconcile conservatively: regather, arm
                            // the poke, and let the wave/tick machinery catch
                            // up on the next delta or heartbeat.
                            warn!(missed, "overlay: net-change deltas lagged — reconciling from snapshot");
                            if let Some(plane) = &self.carrier_plane {
                                plane.notify_regather();
                            }
                            if direct::netchange_poke_enabled() {
                                netchange_poke_due = true;
                            }
                            fast_reupgrade_until =
                                Some(Instant::now() + Duration::from_secs(25));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            // The monitor stopped (backend died). The 30 s
                            // heartbeat must not stay the only guard: restore
                            // the 2 s war cadence; the fresh interval fires
                            // immediately → one prompt catch-up wave.
                            warn!(
                                "overlay: netstate feed ended — restoring the 2 s route-guard tick"
                            );
                            net_watch = None;
                            route_guard = tokio::time::interval(ROUTE_GUARD_TICK);
                        }
                    }
                },
                // W5 — the plane's shared srflx state changed (mapping moved,
                // keepalive outage flagged, or a SEEKING re-gather RECOVERED
                // a candidate after NONE). Refresh the four runtime-local
                // copies a watch-publish alone never reached; the pairing
                // itself follows from the regrade tick + the monitor's
                // reupgrade sweep reading the refreshed state — no forced
                // re-install here.
                changed = async {
                    match plane_srflx_rx.as_mut() {
                        Some(r) => r.changed().await.is_ok(),
                        None => std::future::pending::<bool>().await,
                    }
                } => {
                    if changed {
                        let s = plane_srflx_rx
                            .as_ref()
                            .map(|r| r.borrow().clone())
                            .unwrap_or_default();
                        if let Some(ctx) = direct_ctx.as_mut() {
                            ctx.punch = s.punch.clone();
                            ctx.my_nat = s.my_nat.clone();
                        }
                        srflx_advertised = s.candidates.clone();
                        srflx_my_nat = s.my_nat.clone();
                        // (srflx_stun_server deliberately NOT refreshed: in
                        // plane mode that local only ever feeds the LEGACY
                        // keepalive spawn, which never runs here; the rebuild
                        // arm re-derives it from its own fresh gather.)
                        if let Some(r) = relay.as_mut() {
                            r.set_udp_relay_ok(!s.candidates.is_empty());
                        }
                        self.srflx_status = Some(crate::localapi::SrflxStatus {
                            candidates: s.candidates.clone(),
                            stun_server: s.stun_server.map(|x| x.to_string()),
                            nat: s.my_nat.clone(),
                            via_public_dial: s.via_public_dial,
                            error: s.error.clone(),
                            portmap: s.portmap.clone(),
                        });
                        info!(
                            candidates = ?s.candidates,
                            generation = s.generation,
                            udp_relay_ok = !s.candidates.is_empty(),
                            "overlay: shared srflx state refreshed from the plane watch"
                        );
                    } else {
                        // Watch closed (plane gone in tests) — stop polling.
                        plane_srflx_rx = None;
                    }
                },
                // C4 stage 1 — warm-allocation cadence: request creds when
                // UDP provably works (srflx non-empty) and nothing is live;
                // probe liveness (a 1-byte permission assert, spawned
                // off-loop) while one is. The probe succeeding while srflx
                // is NONE is THE measurement: the flow is grandfathered.
                _ = path_trial_tick.tick() => {
                    if let Some(rx) = disco_rx.as_mut() { while let Ok(p) = rx.try_recv() {
                        path_trials.active_pong(&p); disco.on_pong(&p);
                    }}
                    path_trials.tick(&self, &mut wg, &current_peers, &mut by_node, &mut org_discovery, server_path_trial_v1).await;
                    path_trial::publish_observation_view(&self.peer_view,&path_trials,&current_peers,&by_node,
                        self.org_primary && path_trial::enabled() && server_path_trial_v1);
                },
                _ = org_discovery_tick.tick() => {
                    org_discovery.request(
                        self.org_primary && super::direct::org_relay_enabled(),
                        server_org_discovery, &current_peers, &self.outbound, Instant::now(),
                    ).await;
                },
                _ = warm_tick.tick(), if warm_enabled => {
                    let now = Instant::now();
                    // C4 stage 2 — request whenever nothing is live: the
                    // stage-1 srflx gate ("only when UDP provably works")
                    // kept strict-corp hosts permanently warm-less, and
                    // those are exactly the hosts the standing leg exists
                    // for. The FLAVOR decision at grant time consumes the
                    // srflx evidence instead (empty ⇒ TLS leg).
                    if warm.request_due(now) {
                        warm.note_requested(now);
                        if self.outbound.send(ClientMsg::OverlayWarmRelayRequest {}).await.is_ok() {
                            debug!(
                                udp_dead = srflx_advertised.is_empty(),
                                "overlay warm relay: creds requested"
                            );
                        }
                    }
                    if warm.probe_due(now)
                        && let Some((conn, dst)) = warm.probe_parts()
                    {
                        warm.note_probe_started();
                        let tx = warm_tx.clone();
                        tokio::spawn(async move {
                            let (_ms, ok) =
                                super::wg::assert_relay_permission(&conn, dst, "warm-probe").await;
                            let msg = if ok {
                                super::warm_relay::WarmMsg::ProbeOk
                            } else {
                                super::warm_relay::WarmMsg::ProbeFailed(
                                    "permission assert through the allocation failed".into(),
                                )
                            };
                            let _ = tx.send(msg).await;
                        });
                    }
                    self.warm_relay_status = Some(warm.status(now));
                },
                // Phase B (netcheck) — its OWN cadence arm. B1 parked this
                // logic inside the warm tick, but `warm_enabled` requires the
                // default-OFF `OVERLAY_WARM_RELAY` flag — so every host
                // without the warm leg (the whole direct-carrier fleet) never
                // measured, its peers saw no vector, and the B3 measured
                // branch silently stayed legacy for every pair touching such
                // a host. The request still rides the warm-grant creds wire
                // (`OverlayWarmRelayRequest` → `WarmRelayGrant`, whose arm
                // spawns the probe when `netcheck_pending` rides it) — only
                // the CLOCK is independent now.
                _ = netcheck_tick.tick(), if netcheck_enabled => {
                    let now = Instant::now();
                    // B3 — a dialer-role conviction is a DETECTOR: it
                    // requests an immediate re-measure instead of (only)
                    // flipping roles through the latch.
                    if super::dialer::take_probe_request() && !netcheck_pending {
                        info!("netcheck: dialer-role conviction — immediate re-measure scheduled");
                        netcheck_next = now;
                    }
                    if !netcheck_pending && now >= netcheck_next {
                        netcheck_pending = true;
                        netcheck_next = now + super::netcheck::NETCHECK_INTERVAL;
                        if self
                            .outbound
                            .send(ClientMsg::OverlayWarmRelayRequest {})
                            .await
                            .is_ok()
                        {
                            debug!("netcheck: measurement due — creds requested");
                        }
                    }
                    // B3 — keep the coordinator's measured-verdict mirror in
                    // step with the slot (the publish runs off-loop;
                    // freshness expiry must also read as a change).
                    if let Some(coord) = relay.as_mut() {
                        coord.set_relay_band_udp(
                            super::netcheck::current_fresh().and_then(|v| v.relay_band_udp),
                        );
                    }
                },
                Some(wm) = warm_rx.recv() => {
                    let now = Instant::now();
                    let probe_ok = matches!(wm, super::warm_relay::WarmMsg::ProbeOk);
                    // PR-B — grab the leg's conn before `apply` consumes the
                    // message; the coordinator's fast-commit slot mirrors it.
                    let established_conn = match &wm {
                        super::warm_relay::WarmMsg::Established { conn, .. } => Some(conn.clone()),
                        _ => None,
                    };
                    match warm.apply(wm, now) {
                        super::warm_relay::WarmTransition::Established => {
                            let s = warm.status(now);
                            info!(
                                relayed = s.relayed.as_deref().unwrap_or("?"),
                                flavor = s.flavor.as_deref().unwrap_or("?"),
                                cred_expiry_in_s = s.cred_expiry_in_s.unwrap_or(-1),
                                "overlay warm relay: ESTABLISHED — standing allocation live"
                            );
                            // PR-B — arm the anchor fast-commit: the next
                            // single-relay-anchor pair (typically the one a
                            // VPN capture just killed) commits this leg
                            // instead of running the request round-trips.
                            if let Some(r) = relay.as_mut() {
                                r.set_warm_leg(established_conn);
                            }
                        }
                        super::warm_relay::WarmTransition::EstablishFailed => {
                            warn!(
                                detail = warm.status(now).detail.as_deref().unwrap_or("?"),
                                "overlay warm relay: establish failed; retrying on the spacing"
                            );
                        }
                        super::warm_relay::WarmTransition::Lost => {
                            warn!(
                                detail = warm.status(now).detail.as_deref().unwrap_or("?"),
                                "overlay warm relay: LOST — will re-establish when UDP egress returns"
                            );
                            // PR-B — a dead leg must never fast-commit; the
                            // committed pair's own carrier dies on its own
                            // terms (health sweep) and re-requests normally.
                            if let Some(r) = relay.as_mut() {
                                r.set_warm_leg(None);
                            }
                        }
                        super::warm_relay::WarmTransition::ProbeMissed => {
                            info!(
                                detail = warm.status(now).detail.as_deref().unwrap_or("?"),
                                "overlay warm relay: probe missed once — tolerating (2-strike rule)"
                            );
                        }
                        super::warm_relay::WarmTransition::ProbeOk => {}
                    }
                    if probe_ok && srflx_advertised.is_empty() && !warm.grandfather_logged {
                        warm.grandfather_logged = true;
                        info!(
                            "overlay warm relay: srflx is NONE but the warm allocation still \
                             answers — the flow is GRANDFATHERED across the network transition"
                        );
                    }
                    self.warm_relay_status = Some(warm.status(now));
                },
                // Multi-org v2 P1-d — the plane's rebuild steps. Teardown:
                // release every socket-pinning Arc (direct carriers, probes,
                // our DirectCtx view) and ack, so the plane can actually
                // re-bind. Ready: the plane re-bound — run the R3 tail
                // (join → gather → coordinator → install) via the ONE
                // executor, authoritative. `pending()` when not attached.
                pev = async {
                    match plane_events.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<super::carrier_plane::PlaneEvent>>().await,
                    }
                } => {
                    match pev {
                        Some(super::carrier_plane::PlaneEvent::Teardown { ack }) => {
                            let t_arm = Instant::now();
                            self.teardown_direct_carriers(
                                &mut wg, &mut by_node, &mut upgrade_probes,
                                &mut relay, &mut relay_bq, &mut alloc_q, &tun,
                            ).await;
                            // Our view of the old sockets goes too — holding
                            // it would keep the ports alive past the ack.
                            direct_ctx = None;
                            self.shadow(|s| s.mon.on_local_rebuild());
                            let _ = ack.send(()).await;
                            warn_if_slow("arm:plane_teardown", t_arm);
                        }
                        Some(super::carrier_plane::PlaneEvent::Ready) => {
                            pending_rebuild = Some("plane-rebind");
                            last_rebuild = None;
                        }
                        None => {
                            // The plane is gone (test teardown) — stop polling.
                            plane_events = None;
                        }
                    }
                },
                // Phase A — an authenticated inbound direct handshake initiation
                // forwarded by a demux loop (a NAT'd client dialing our public
                // endpoint, or a peer roaming to a new port). `pending()` when
                // the public-direct tier is off, so this branch is inert on the
                // fleet default.
                maybe_init = async {
                    match direct_events.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<crate::overlay::wg::DirectInbound>>().await,
                    }
                } => {
                    if let Some(inb) = maybe_init {
                        let t_arm = Instant::now();
                        self.handle_direct_inbound(
                            &mut wg, &mut by_node, &mut relay, &tun,
                            &current_peers, &mut upgrade_probes,
                            &mut relay_bq, inb,
                        ).await;
                        self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                        self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                        warn_if_slow("arm:direct_inbound", t_arm);
                    }
                },
                evt = events.recv() => match evt {
                    // rc.307 (B) — a fresh control-WS session re-binding this
                    // persistent runtime: swap the sender, re-join (the server
                    // replies with a full netmap → the authoritative reconcile
                    // arm below), re-advertise srflx (the server's copy may not
                    // survive the re-join, and the keepalive only re-trickles
                    // on a CHANGE). Carriers/TUN/WG stay untouched — that is
                    // the point.
                    Some(OverlayEvent::Reattach { outbound }) => {
                        let t_arm = Instant::now();
                        path_trials.reset_observation(crate::localapi::PathTrialResetReason::Reattach);
                        path_trial::clear_observation_view(&self.peer_view,path_trials.observation_runtime_id());
                        server_path_trial_v1 = false;
                        server_org_discovery = false; // await explicit support on the NEW full netmap
                        server_org_fallback = false;
                        org_discovery.invalidate(); // old WS replies cannot refresh metadata
                        self.outbound.swap(outbound);
                        // Join-send failure = the new session died within ms.
                        // NEVER exit here (a rapid double-flap must not kill
                        // the persistent runtime) — stay detached; the next
                        // Reattach retries.
                        if self
                            .outbound
                            .send(self.make_join(advertised.clone()))
                            .await
                            .is_err()
                        {
                            warn!("overlay: reattach join failed; awaiting the next session");
                        } else {
                            info!("overlay: control-WS reattached — re-joined with carriers intact");
                        }
                        // srflx restore: the re-join's server-side rehydrate
                        // WIPED srflx_endpoints. The keepalive task owns the
                        // EVOLVING advert — signal it; only when it doesn't
                        // exist fall back to the startup snapshot.
                        if srflx_keepalive.is_some() {
                            srflx_reattach_tx.send_modify(|n| *n += 1);
                        } else if !srflx_advertised.is_empty() {
                            let _ = self
                                .outbound
                                .send(ClientMsg::OverlaySrflx {
                                    candidates: srflx_advertised.clone(),
                                    nat: srflx_my_nat.clone(),
                                    udp_dialer_ok: Some(super::dialer::advertised_dialer_ok()),
                                })
                                .await;
                        }
                        if let Some(r) = relay.as_mut() {
                            // A grant lost in flight (WS died between request
                            // and grant) would park its pair FOREVER now that
                            // the coordinator outlives sessions — `is_tracking`
                            // dedupes every later request. Forget ungranted
                            // pendings; the next netmap/sweep re-requests.
                            let dropped = r.forget_ungranted_pending();
                            if dropped > 0 {
                                info!(dropped, "overlay: reattach — re-requesting relays whose grant was lost in flight");
                            }
                            // The rehydrate also replaced our endpoints with
                            // the join's LAN-only list, wiping every LIVE
                            // relayed address (surviving allocations don't
                            // re-allocate, so nothing would re-trickle them).
                            // Restore the full union; per-connection FIFO
                            // guarantees it lands AFTER the join's rehydrate.
                            let _ = self
                                .outbound
                                .send(ClientMsg::OverlayEndpoints {
                                    candidates: r.all_endpoints(),
                                })
                                .await;
                        }
                        // NB: peers see our endpoints wiped-then-restored and
                        // clear their path-monitor evidence for us twice
                        // (`direct_endpoints_changed`) — harmless, converges.
                        warn_if_slow("arm:reattach", t_arm);
                    }
                    // Re-sync: a full netmap is the reconcile point — today it
                    // arrives on every rc.307 re-join (reattach), and the arm
                    // below applies it AUTHORITATIVELY against live state.
                    Some(OverlayEvent::Netmap { self_ip: new_self_ip, network: new_network, peers, org_relay_discovery, path_trial_v1 }) => {
                        let t_arm = Instant::now();
                        // A re-join can only reconcile onto the SAME identity.
                        // A different self_ip (re-enroll / tenant renumber) or
                        // network shape (cidr → netmask/NAT guard, magic
                        // domain → DNS resolver — both baked from the FIRST
                        // netmap) needs the full rebuild this persistent
                        // runtime deliberately avoids — exit; the agent-side
                        // slot spawns a fresh runtime on the next session
                        // (its Reattach send fails).
                        if new_self_ip != self_ip
                            || new_network.cidr != network.cidr
                            || new_network.magic_domain != network.magic_domain
                        {
                            warn!(old = %self_ip, new = %new_self_ip,
                                "overlay: re-join returned a different identity/network — exiting for a clean rebuild");
                            break;
                        }
                        #[cfg(test)]
                        {
                            let stall = TEST_NETMAP_STALL_MS.load(std::sync::atomic::Ordering::Relaxed);
                            if stall > 0 {
                                tokio::time::sleep(Duration::from_millis(stall)).await;
                            }
                        }
                        path_trials.reset_observation(crate::localapi::PathTrialResetReason::FullNetmap);
                        path_trial::clear_observation_view(&self.peer_view,path_trials.observation_runtime_id());
                        server_path_trial_v1 = path_trial_v1;
                        server_org_discovery = org_relay_discovery;
                        server_org_fallback = new_network.org_relay_fallback_v1;
                        org_discovery.invalidate(); // authoritative membership / key / ACL reconciliation
                        let old_peers = std::mem::take(&mut current_peers);
                        current_peers = peers.iter().map(|p| (p.node_id, p.clone())).collect();
                        for (nid, old) in &old_peers {
                            if current_peers.get(nid).and_then(org_peer_identity)
                                != org_peer_identity(old)
                            {
                                invalidate_org_bind_identity(nid, &mut org_q, &mut relay);
                            }
                        }
                        // P4 — refresh per-source ingress rules from the netmap
                        // the server just shaped for us.
                        wg.sync_peer_ingress(&current_peers);
                        // rc.225 — a peer whose direct endpoints changed gets a
                        // clean slate: its old strike counts were measured
                        // against dial conditions that no longer exist.
                        for p in &peers {
                            if let Some(old) = old_peers.get(&p.node_id)
                                && direct_endpoints_changed(old, p)
                            {
                                // P3 PR-A — same clean slate in the monitor
                                // (penalties, strikes AND quality — F1).
                                self.shadow(|s| s.mon.on_endpoint_change(&p.node_id));
                                debug!(peer = %p.node_id, "overlay: peer's direct endpoints changed — cleared its path-monitor evidence");
                            }
                        }
                        // The full netmap is AUTHORITATIVE: anything we still
                        // hold that it does not list is gone — released, or
                        // ACL'd out.
                        //
                        // LIVE since rc.307 (B): the runtime persists across
                        // control-WS sessions, and every `Reattach` re-join is
                        // answered with a full netmap that lands HERE — this
                        // arm is the reconcile that replaces the old
                        // rebuild-from-empty ("a peer vanished while we were
                        // away" is now covered by the prune below; endpoint
                        // changes by `direct_endpoints_changed` + upsert).
                        // (Kept verbatim from its #278 "defensive" era, whose
                        // comment predicted exactly this use: "a re-join that
                        // keeps the connection".)
                        //
                        // MEMBERSHIP, not presence: P9 ghost rows are still
                        // LISTED (with `reachable = false`), so they are not
                        // pruned — an offline peer keeps its carrier and comes
                        // back without a rebuild. Only a peer the server dropped
                        // from the netmap entirely — released, or ACL'd out — is
                        // torn down here.
                        //
                        // Collect first: the diff holds borrows of `by_node`,
                        // `upgrade_probes` and `current_peers` that must end
                        // before the loop takes them mutably.
                        let mut vanished: Vec<ObjectId> = by_node
                            .keys()
                            .chain(upgrade_probes.keys())
                            .filter(|id| !current_peers.contains_key(id))
                            .copied()
                            .collect();
                        vanished.sort_unstable();
                        vanished.dedup();
                        if !vanished.is_empty() {
                            info!(pruned = vanished.len(), listed = current_peers.len(),
                                "overlay: full netmap prune");
                        }
                        // Prune BEFORE install_peers so a stale peer and the new
                        // owner of its address are never both installed.
                        for nid in vanished {
                            self.evict_peer(
                                nid, &mut wg, &mut by_node, &tun, &mut relay, &mut relay_bq,
                                &mut alloc_q, &mut upgrade_probes, &mut current_peers,
                                &mut relay_refresh_cooldown,
                            ).await;
                        }
                        if let Some(names) = &dns_names { sync_name_map(names, &current_peers, network.self_name.as_deref(), self_v4).await; }
                        let t0 = Instant::now();
                        self.install_peers(&mut wg, &mut by_node, &mut relay, &tun, &peers, direct_ctx.as_ref(), &mut upgrade_probes, &mut relay_bq, "netmap").await;
                        warn_if_slow("install_peers(netmap)", t0);
                        self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                        self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                        warn_if_slow("arm:netmap", t_arm);
                    }
                    Some(OverlayEvent::NetmapDelta { upserts, removes }) => {
                        path_trials.reset_observation(crate::localapi::PathTrialResetReason::NetmapDelta);
                        path_trial::clear_observation_view(&self.peer_view,path_trials.observation_runtime_id());
                        let t_arm = Instant::now();
                        // Multi-org P2a — REMOVES FIRST. The tenant-block
                        // renumber (P2b) re-IPs a node as a `remove(id) +
                        // upsert(id, new_ip)` pair in ONE delta; with the old
                        // upserts-first order the freshly-upserted peer was
                        // immediately evicted by its own remove — the pair
                        // netted to "peer gone". Removes-first makes the pair
                        // a genuine re-IP primitive (evict old → clean
                        // install new); disjoint-id deltas are order-blind.
                        for node_id in removes.iter().copied() {
                            invalidate_org_bind_identity(&node_id, &mut org_q, &mut relay);
                            self.evict_peer(
                                node_id, &mut wg, &mut by_node, &tun, &mut relay, &mut relay_bq,
                                &mut alloc_q, &mut upgrade_probes, &mut current_peers,
                                &mut relay_refresh_cooldown,
                            ).await;
                        }
                        for p in &upserts {
                            if current_peers.get(&p.node_id).is_some_and(|old|
                                org_peer_identity(old) != org_peer_identity(p))
                            {
                                invalidate_org_bind_identity(&p.node_id, &mut org_q, &mut relay);
                            }
                            // rc.225 — endpoint change ⇒ clean cooldown slate
                            // (see the Netmap arm / `direct_endpoints_changed`).
                            if let Some(old) = current_peers.insert(p.node_id, p.clone())
                                && direct_endpoints_changed(&old, p)
                            {
                                // P3 PR-A — same clean slate in the monitor
                                // (penalties, strikes AND quality — F1).
                                self.shadow(|s| s.mon.on_endpoint_change(&p.node_id));
                                debug!(peer = %p.node_id, "overlay: peer's direct endpoints changed — cleared its path-monitor evidence");
                            }
                        }
                        org_discovery.reconcile_delta(&current_peers, &removes);
                        // P4 — a delta can change a peer's grant without any
                        // install/removal, so the table is resynced here too.
                        wg.sync_peer_ingress(&current_peers);
                        let t0 = Instant::now();
                        self.install_peers(&mut wg, &mut by_node, &mut relay, &tun, &upserts, direct_ctx.as_ref(), &mut upgrade_probes, &mut relay_bq, "delta").await;
                        warn_if_slow("install_peers(delta)", t0);
                        if let Some(names) = &dns_names { sync_name_map(names, &current_peers, network.self_name.as_deref(), self_v4).await; }
                        self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                        self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                        warn_if_slow("arm:netmap_delta", t_arm);
                    }
                    Some(OverlayEvent::RelayGrant { peer_node_id, ice_servers, pair_key }) => {
                        let t_arm = Instant::now();
                        if let Some(r) = relay.as_mut() {
                            // rc.218 — the DNS + TURN allocate no longer runs
                            // inline (it stalled the data plane for seconds on a
                            // hostile corp path — see `RelayAllocQueue`). Stash
                            // the creds sync, spawn the allocate, and let the
                            // `alloc_rx` arm commit the result. LAST GRANT WINS:
                            // re-stamping supersedes any in-flight allocate for
                            // this peer (its completion drops on epoch mismatch),
                            // and `grant_accept` requiring a `pending` slot drops
                            // grants for peers already torn down.
                            if let Some((ice, pair_key)) = r.grant_accept(peer_node_id, ice_servers, pair_key) {
                                let epoch = alloc_q.stamp(peer_node_id);
                                let tx = alloc_q.tx.clone();
                                tokio::spawn(async move {
                                    let conn = RelayCoordinator::allocate_for_pair(&ice, &pair_key).await;
                                    let _ = tx.send(AllocDone { epoch, node_id: peer_node_id, conn }).await;
                                });
                            }
                        }
                        warn_if_slow("arm:relay_grant", t_arm);
                    }
                    // C4 stage 1 — warm-allocation creds arrived: allocate
                    // over TURN/UDP off-loop (UDP-or-nothing — a TCP "warm"
                    // allocation would just be today's TURNS fallback), and
                    // let the warm_rx arm commit the outcome.
                    Some(OverlayEvent::WarmRelayGrant { ice_servers }) => {
                        // Phase B — a due netcheck rode this grant: spawn the
                        // DEDICATED probe allocation (never the warm leg —
                        // its relayed address is dialed by real peers) and
                        // publish the measured vector. Runs alongside the
                        // warm machinery below; allocation failure publishes
                        // an honest partial (relay_band unmeasured).
                        if netcheck_pending {
                            netcheck_pending = false;
                            let stun_udp = !srflx_advertised.is_empty();
                            let nat = srflx_my_nat.clone();
                            let derp_ws_ok = relay
                                .as_ref()
                                .map(|r| r.derp_ws_alive())
                                .unwrap_or(false);
                            let own_ips: Vec<std::net::IpAddr> = srflx_advertised
                                .iter()
                                .filter_map(|e| e.parse::<SocketAddr>().ok())
                                .map(|a| a.ip())
                                .collect();
                            let creds = super::relay_link::turn_creds(&ice_servers);
                            let advert_tx = self.outbound.clone();
                            tokio::spawn(async move {
                                let alloc = match (&creds, stun_udp) {
                                    (Some((urls, user, cred)), true) => {
                                        let udp = super::warm_relay::udp_turn_urls(urls);
                                        match crate::transport::relay::allocate_relay_from_ice_tiered(
                                            &udp, user, cred, false,
                                        )
                                        .await
                                        {
                                            Ok(c) => {
                                                let conn: std::sync::Arc<
                                                    dyn crate::transport::relay::RelayConn,
                                                > = std::sync::Arc::new(c);
                                                conn.local_addr().ok().map(|r| (conn, r))
                                            }
                                            Err(e) => {
                                                debug!(%e, "netcheck: probe allocation failed — relay_band unmeasured");
                                                None
                                            }
                                        }
                                    }
                                    _ => None,
                                };
                                super::netcheck::run_measurement(
                                    stun_udp, nat, derp_ws_ok, alloc, own_ips,
                                )
                                .await;
                                // B2 — advertise the fresh vector; the server
                                // stamps receipt time and surfaces it behind
                                // the freshness gate.
                                if let Some((v, _age)) = super::netcheck::current() {
                                    let _ = advert_tx
                                        .send(ClientMsg::OverlayNetcheck {
                                            caps: roomler_ai_remote_control::signaling::CapVectorWire {
                                                stun_udp: v.stun_udp,
                                                relay_band_udp: v.relay_band_udp,
                                                derp_ws_ok: v.derp_ws_ok,
                                            },
                                        })
                                        .await;
                                }
                            });
                        }
                        if warm_enabled && !warm.is_live() {
                            match super::relay_link::turn_creds(&ice_servers) {
                                Some((urls, user, cred)) => {
                                    // C4 stage 2 — flavor ladder: UDP while it can work
                                    // (the grandfather-measurable leg), TURNS/TCP:443 when
                                    // fresh UDP is provably dead right now (srflx empty —
                                    // the strict-corp case the standing leg exists for).
                                    let flavor = warm.next_flavor(srflx_advertised.is_empty());
                                    let alloc_urls = match flavor {
                                        super::warm_relay::WarmFlavor::Udp => {
                                            super::warm_relay::udp_turn_urls(&urls)
                                        }
                                        // The tiered allocator's `tls_only` walks the
                                        // `turns:` urls itself — hand it the full grant.
                                        super::warm_relay::WarmFlavor::Tls => urls.clone(),
                                    };
                                    let tls_only = flavor == super::warm_relay::WarmFlavor::Tls;
                                    if alloc_urls.is_empty() {
                                        warn!(?flavor, "overlay warm relay: grant carried no usable turn urls; skipping");
                                    } else {
                                        let expiry = super::warm_relay::ephemeral_cred_expiry_s(&user);
                                        let tx = warm_tx.clone();
                                        tokio::spawn(async move {
                                            let msg = match crate::transport::relay::allocate_relay_from_ice_tiered(
                                                &alloc_urls, &user, &cred, tls_only,
                                            )
                                            .await
                                            {
                                                Ok(c) => {
                                                    let conn: std::sync::Arc<dyn crate::transport::relay::RelayConn> =
                                                        std::sync::Arc::new(c);
                                                    match conn.local_addr() {
                                                        Ok(relayed) => super::warm_relay::WarmMsg::Established {
                                                            conn,
                                                            relayed,
                                                            cred_expiry_epoch_s: expiry,
                                                            flavor,
                                                        },
                                                        Err(e) => super::warm_relay::WarmMsg::EstablishFailed {
                                                            flavor,
                                                            error: format!("relayed addr unreadable: {e}"),
                                                        },
                                                    }
                                                }
                                                Err(e) => super::warm_relay::WarmMsg::EstablishFailed {
                                                    flavor,
                                                    error: e.to_string(),
                                                },
                                            };
                                            let _ = tx.send(msg).await;
                                        });
                                    }
                                }
                                None => warn!("overlay warm relay: grant carried no turn creds; skipping"),
                            }
                        }
                    }
                    // FR-19 P4b — the server minted an org-relay session for a pair.
                    Some(OverlayEvent::PathTrial(msg)) => {
                        path_trials.control(msg, &self, &mut wg, &current_peers, &mut by_node, server_path_trial_v1).await;
                        let managed: Vec<_> = self.path_trial_managed.lock().unwrap_or_else(|e|e.into_inner()).iter().copied().collect();
                        for node in managed {
                            org_q.invalidate(&node); alloc_q.invalidate(&node); relay_bq.invalidate(&node);
                            if let Some(probe)=upgrade_probes.remove(&node) { wg.drop_direct_probe(&probe.pubkey).await; self.shadow(|s|s.mon.on_probe_aborted(&node)); }
                            if let Some(r)=relay.as_mut() { r.forget(&node); }
                        }
                        self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                    }
                    Some(OverlayEvent::OrgRelaySession { vni, generation, peer_node_id, relay_node_id, relay_endpoints, bind_secret, bind_secs, max_lifetime_secs }) => {
                        let t_arm = Instant::now();
                        if self.path_trial_managed.lock().unwrap_or_else(|e|e.into_inner()).contains(&peer_node_id) { continue; }
                        if by_node.get(&peer_node_id).is_some_and(|e| wg.org_recovery_held(&e.pubkey)) {
                            org_q.invalidate(&peer_node_id); alloc_q.invalidate(&peer_node_id); relay_bq.invalidate(&peer_node_id);
                            if let Some(r) = relay.as_mut() { r.org_bind_failed(&peer_node_id); }
                            continue;
                        }
                        if let Some(r) = relay.as_mut() {
                            match crate::overlay::orgrelay::member::OrgSession::from_wire(vni, generation, relay_node_id, &relay_endpoints, &bind_secret, bind_secs, max_lifetime_secs) {
                                Some(session) => {
                                    if accept_org_bind_session(
                                        peer_node_id, session, r, &mut org_q,
                                        &mut alloc_q, &current_peers, &by_node,
                                    ) {
                                        cancel_org_upgrade_candidate(&peer_node_id, &mut wg, &mut by_node);
                                    }
                                    for job in r.take_org_jobs() {
                                        let label = current_peers.get(&job.relay_node_id).map(|p| p.name.clone()).unwrap_or_else(|| job.relay_node_id.to_hex());
                                        let epoch = org_q.stamp(job.node_id);
                                        spawn_org_bind(job, label, epoch, org_q.tx.clone());
                                    }
                                }
                                None => warn!(peer = %peer_node_id, vni,
                                    "overlay relay: malformed org-relay session (secret or endpoints); ignored"),
                            }
                        }
                        warn_if_slow("arm:org_relay_session", t_arm);
                    }
                    Some(OverlayEvent::OrgRelayCandidates { peer_node_id, request_id, candidates, ttl_secs, next_cursor }) => {
                        if self.org_primary && super::direct::org_relay_enabled() && server_org_discovery {
                            let count = org_discovery.receive_page(&current_peers, peer_node_id, request_id, candidates, ttl_secs, next_cursor, Instant::now());
                            debug!(target: "tunnel_core::overlay::runtime::org_discovery_metadata", peer = %peer_node_id, candidates = count, "overlay: org-relay discovery metadata received (not a session or path decision)");
                        } else {
                            org_discovery.invalidate();
                        }
                    }
                    Some(OverlayEvent::OrgRelayRevoke { vni }) => {
                        org_discovery.invalidate(); // no stale hints survive any relay revocation
                        if let Some(r) = relay.as_mut()
                            && let Some(peer) = r.org_session_revoke(vni)
                        {
                            org_q.invalidate(&peer);
                            cancel_org_upgrade_candidate(&peer, &mut wg, &mut by_node);
                            info!(%peer, vni, "overlay relay: org-relay session revoked by the server — the sweep re-coordinates the pair");
                        }
                    }
                    Some(OverlayEvent::ForceDerp { peer_node_id, ttl_ms, derp_url }) => {
                        let t_arm = Instant::now();
                        // P3 PR-A — annotate the pinned window in the monitor
                        // (relay-Q resets; direct decisions unaffected — the
                        // pin stays a server-side OVERRIDE, never scored).
                        self.shadow(|s| s.mon.on_forced_derp(&peer_node_id, Duration::from_millis(ttl_ms), Instant::now()));
                        if let Some(r) = relay.as_mut() {
                            // P7 — a UDP-capable node skipped the startup
                            // `/derp` open; lazily invoke the retained factory
                            // (at-most-once) before pinning.
                            if !r.has_derp_mux()
                                && let Some(f) = derp_factory.take()
                            {
                                r.set_derp_mux(f());
                            }
                            // Multi-region DERP — a push carrying a regional
                            // url: open (once per URL) via the reusable
                            // factory. An unopenable region (no ticket yet /
                            // factory absent) degrades to the central mux
                            // inside force_derp.
                            if let Some(url) = derp_url.as_deref()
                                && !r.has_regional_mux(url)
                                && let Some(f) = regional_derp_factory.as_ref()
                                && let Some(mux) = f(url)
                            {
                                r.set_regional_mux(url, mux);
                            }
                            // Supersede any in-flight off-loop ALLOCATE — a
                            // stale AllocDone must not resurrect a TURN link
                            // inside the forced window.
                            alloc_q.invalidate(&peer_node_id);
                            let mut link = r.force_derp(peer_node_id, Duration::from_millis(ttl_ms), derp_url.as_deref());
                            if r.org_relay_pinned(&peer_node_id) { org_q.invalidate(&peer_node_id); }
                            // rc.222 — stamp-only + an INSTALLED TURN relay for
                            // the pair: tear it down NOW and rebuild under the
                            // pin. The server just certified the pair's TURN
                            // broken, and a half-dead (one-way) relay keeps rx
                            // alive, so the liveness sweep would never cycle it
                            // (the field-observed ZOMBIE wedge). Direct
                            // carriers are left alone — the escalation is about
                            // the TURN tier.
                            if link.is_none()
                                && by_node.get(&peer_node_id).is_some_and(|e| !e.is_direct)
                                && let Some(e) = by_node.remove(&peer_node_id)
                            {
                                wg.remove_peer(&e.pubkey).await;
                                del_peer_route_if_unowned(&tun, &by_node, e.overlay_ip).await;
                                r.forget(&peer_node_id);
                                if let Some(cfg) = current_peers
                                    .get(&peer_node_id)
                                    .and_then(peer_config_from_netmap)
                                {
                                    r.request(peer_node_id, cfg.clone()).await;
                                    link = r.maybe_complete(peer_node_id, &cfg);
                                }
                            }
                            if let Some(link) = link {
                                let t0 = Instant::now();
                                self.install_ready(&mut wg, &mut by_node, &tun, link, &mut relay_bq).await;
                                warn_if_slow("install_ready(spawn-or-sync)", t0);
                                self.reconcile_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state).await;
                                self.publish_view(&self_ip, &by_node, &current_peers, &upgrade_probes, exit_node_status(self.exit_node.as_deref(), &exit_state), &wg, &path_trials, server_path_trial_v1);
                            }
                        }
                        warn_if_slow("arm:force_derp", t_arm);
                    }
                    // B1 — one prober RTT measurement: Q-credit the peer's
                    // INCUMBENT tier (the ping rode the installed carrier).
                    // Uninstalled peer ⇒ drop (no carrier attribution).
                    Some(OverlayEvent::RttSample { node_id, rtt_ms }) => {
                        // Stats PR-5: remember the measurement for the
                        // LocalAPI / heartbeat views regardless of the
                        // Q-credit flag — `rtt_ms` was hardcoded None there.
                        if let Some(e) = by_node.get_mut(&node_id) {
                            e.last_rtt_ms = Some(rtt_ms);
                        }
                        if rtt_q_enabled()
                            && let Some(tier) = by_node.get(&node_id).map(|e| e.tier)
                        {
                            self.shadow(|s| {
                                s.stats.rtt_samples += 1;
                                s.mon.on_rtt_sample(&node_id, tier, rtt_ms);
                            });
                        }
                    }
                    Some(OverlayEvent::RebuildDirect) => {
                        // R4 — the embedder saw the LAN-IP fingerprint change
                        // on a WS reconnect. Authoritative: bypass the
                        // cooldown; the tick executor runs the sequence.
                        info!("overlay: embedder requested a direct-plane rebuild (fingerprint change)");
                        if let Some(plane) = &self.carrier_plane {
                            plane.request_rebuild("ws-fingerprint", true);
                        } else {
                            pending_rebuild = Some("ws-fingerprint");
                            last_rebuild = None;
                        }
                    }
                    None => break,
                },
            }
        }

        // P5 — revert exit-node default routing on a clean exit (WS disconnect /
        // shutdown). An UNCLEAN exit self-heals too (the OS default was never
        // deleted); S3.5 adds the process::exit + boot-reconciler paths (A2).
        self.teardown_exit_routing(&mut wg, &tun, &by_node, &current_peers, &mut exit_state)
            .await;

        inbound.abort();
        // rc.213 — stop the dedicated outbound TUN reader; aborting drops its
        // in-flight `read_packet()` future, and the TUN `Arc` it holds drops
        // with the task, so session teardown isn't kept alive by the reader.
        tun_reader.abort();
        // P1 (S6) — and the outbound pump (it would end on its own once the
        // reader's channel closes, but an abort makes teardown prompt).
        outbound_pump.abort();
        // Phase C — stop the srflx keepalive task (if any) on runtime exit.
        if let Some(h) = srflx_keepalive {
            h.abort();
        }
        // FR-72 — and the MagicDNS resolver, which owns `<self overlay ip>:53`.
        // Without this it survives its own runtime and the NEXT session's
        // resolver cannot bind, so MagicDNS dies on the first WS reconnect and
        // stays dead until the process restarts. The socket is released when the
        // task drops, so the successor binds cleanly.
        // FR-72 P6 — give the hosts file back before anything else in the DNS
        // teardown. A block that outlives the daemon points names at addresses
        // nothing is serving, and overlay addresses are RECYCLED, so a stale
        // line is not merely dead — it can route to a different machine.
        if let Some(mut l) = dns_ladder.take() {
            l.shutdown();
        }
        if let Some(h) = dns_task {
            h.abort();
            // ⚠️ `abort()` only REQUESTS cancellation — the socket is released
            // when the task is next polled and dropped, which is NOT guaranteed
            // to have happened before the next session's resolver binds. Await
            // it (bounded, so a wedged task can't stall a reconnect) so the
            // successor cannot lose the race to its own aborted predecessor.
            let _ = tokio::time::timeout(Duration::from_secs(1), h).await;
        }
    }
}

#[cfg(test)]
mod tests {
    //! Phase 3b proof: two `OverlayRuntime`s, driven only by injected
    //! `rc:overlay.netmap` events + a loopback `LinkFactory`, bring up
    //! their WG peers and round-trip an IP packet between their mock
    //! TUNs — exercising join → netmap → add_peer → bridge end to end
    //! with no real device and no server.

    use super::*;
    use std::io;

    /// W2 — the resolver's name map must include the node ITSELF (the
    /// netmap's peer list excludes self, so before this fix
    /// `<own-name>.<domain>` was NXDOMAIN from the node's own resolver;
    /// the NameMap doc claimed a self-inclusion that never existed). A
    /// pre-W2 server sends no `self_name` ⇒ peers-only, the old shape.
    #[tokio::test]
    async fn sync_name_map_includes_self_when_the_server_names_us() {
        let names: dns::NameMap = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let me = Ipv4Addr::new(100, 65, 4, 2);
        sync_name_map(&names, &HashMap::new(), Some("devbox"), me).await;
        assert_eq!(
            names.read().await.get("devbox"),
            Some(&me),
            "own name must resolve to own overlay IP"
        );
        sync_name_map(&names, &HashMap::new(), None, me).await;
        assert!(
            names.read().await.is_empty(),
            "pre-W2 server (no self_name) keeps the peers-only shape"
        );
        sync_name_map(&names, &HashMap::new(), Some(""), me).await;
        assert!(names.read().await.is_empty(), "empty name never inserted");
    }
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;

    /// rc.307 — the stable-port bind helper: prefers the base, WALKS THE BAND
    /// when the base is swallowed (the Hyper-V/WSL reservation case that ate
    /// the original default), and `0` means plain ephemeral.
    #[tokio::test]
    async fn bind_direct_socket_prefers_base_then_walks_the_band() {
        use std::net::Ipv4Addr;
        // 0 → plain ephemeral bind.
        let scratch = establish::bind_direct_socket(Ipv4Addr::LOCALHOST, 0, "test")
            .await
            .expect("ephemeral bind");
        assert_ne!(scratch.local_addr().unwrap().port(), 0);
        drop(scratch);

        // Find a base whose whole band is free, then occupy the base only.
        let mut base = 43648u16;
        let mut held: Vec<UdpSocket> = Vec::new();
        loop {
            held.clear();
            let mut all_free = true;
            for p in direct::direct_port_candidates(base) {
                match UdpSocket::bind((Ipv4Addr::LOCALHOST, p)).await {
                    Ok(s) => held.push(s),
                    Err(_) => {
                        all_free = false;
                        break;
                    }
                }
            }
            if all_free {
                break;
            }
            base = base
                .checked_add(direct::DIRECT_PORT_BAND)
                .expect("a free band");
            held.clear();
        }
        held.clear(); // release the whole band

        // Base free → bound exactly (the stability property).
        let on_base = establish::bind_direct_socket(Ipv4Addr::LOCALHOST, base, "test")
            .await
            .expect("base bind");
        assert_eq!(on_base.local_addr().unwrap().port(), base);

        // Base occupied → the NEXT band member, never ephemeral.
        let walked = establish::bind_direct_socket(Ipv4Addr::LOCALHOST, base, "test")
            .await
            .expect("band walk bind");
        let wp = walked.local_addr().unwrap().port();
        assert_ne!(wp, base, "base is taken");
        assert!(
            direct::direct_port_candidates(base).any(|c| c == wp),
            "must stay INSIDE the band (got {wp}), not fall to ephemeral"
        );
    }

    /// rc.211 — a fresh off-loop build queue for tests. The receiver is
    /// dropped: these tests exercise direct/LAN paths that never spawn a
    /// QUIC build, and a send into a closed channel is simply ignored.
    fn test_relay_bq() -> RelayBuildQueue {
        let (tx, _rx) = mpsc::channel(4);
        RelayBuildQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx,
        }
    }

    /// rc.211 (P2: generic `EpochQueue`) — the off-loop queue's staleness
    /// guards. (a) A completion commits only while its epoch is current;
    /// (b) `invalidate` (peer removed / went direct) drops the in-flight work
    /// on arrival; (c) re-`stamp` for the same peer supersedes — the ABA case
    /// a plain "is in flight" set would get wrong (old completion must NOT
    /// commit, new one must). Exercised through the `RelayBuildQueue` alias;
    /// `RelayAllocQueue` is the same generic (its extra semantics — last
    /// grant wins, no per-site invalidation — are call-site policy, not
    /// queue mechanics).
    #[tokio::test]
    async fn relay_build_queue_epoch_guards() {
        let mut bq = test_relay_bq();
        let n = ObjectId::from_bytes([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // (a) current epoch commits, and the slot is consumed.
        let e1 = bq.stamp(n);
        assert!(bq.in_flight.contains_key(&n));
        assert!(bq.take_if_current(&n, e1));
        assert!(!bq.in_flight.contains_key(&n), "commit consumes the slot");
        assert!(
            !bq.take_if_current(&n, e1),
            "a second arrival of the same build is stale"
        );

        // (b) invalidate → the completion is dropped on arrival.
        let e2 = bq.stamp(n);
        bq.invalidate(&n);
        assert!(!bq.take_if_current(&n, e2));

        // (c) ABA: re-stamp supersedes — the OLD build must not commit, the
        // NEW one must.
        let e3 = bq.stamp(n);
        let e4 = bq.stamp(n);
        assert!(!bq.take_if_current(&n, e3), "superseded build is stale");
        assert!(bq.take_if_current(&n, e4), "current build commits");
    }

    /// rc.218 — the ALLOCATE queue rides the same generic: last grant wins
    /// (re-stamp supersedes), commits consume the slot, stale completions
    /// drop.
    #[tokio::test]
    async fn relay_alloc_queue_epoch_guards() {
        let (tx, _rx) = mpsc::channel::<AllocDone>(4);
        let mut q = RelayAllocQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx,
        };
        let n = ObjectId::from_bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // (a) current epoch commits, and the slot is consumed.
        let e1 = q.stamp(n);
        assert!(q.take_if_current(&n, e1));
        assert!(!q.in_flight.contains_key(&n), "commit consumes the slot");
        assert!(
            !q.take_if_current(&n, e1),
            "a second arrival of the same allocate is stale"
        );

        // (b) last grant wins: the superseded allocate must not commit, the
        // newest must.
        let e2 = q.stamp(n);
        let e3 = q.stamp(n);
        assert!(!q.take_if_current(&n, e2), "superseded allocate stale");
        assert!(q.take_if_current(&n, e3), "current allocate commits");
    }

    /// P3 PR-E (was PR-C's ON-leg; the legacy control leg is gone with the
    /// legacy) — a FRESH peer with a probe already in flight rides relay
    /// instead of racing a destructive direct install over the probe (the
    /// soak-#1 Class-A fix, now the only behaviour).
    #[tokio::test(flavor = "multi_thread")]
    async fn fresh_peer_with_probe_in_flight_rides_relay_not_installing() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let tun: Arc<dyn TunIo> = tun_mock;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let my_ip: Ipv4Addr = "10.1.2.9".parse().unwrap();
        let ctx = DirectCtx {
            socks: vec![(my_ip, sock)],
            my_ips: vec![my_ip],
            endpoints: vec![],
            public_sock: None,
            punch: None,
            my_nat: None,
            v6: None,
            my_v6: vec![],
        };
        let mut relay: Option<RelayCoordinator> = None;
        let mut by_node = HashMap::new();
        let mut upgrade_probes = HashMap::new();
        let mut lan_peer = peer(&peer_kp, "100.64.0.7");
        lan_peer.lan_endpoints = vec!["10.1.2.3:1000".into()];

        // The Class-A shape: a probe survives its peer's carrier death.
        let probe_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.start_direct_probe(
            probe_sock,
            peer_kp.public.to_bytes(),
            "100.64.0.7".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
            false,
        )
        .await;
        rt.path_shadow.lock().unwrap().mon.on_probe_started(
            &lan_peer.node_id,
            DirectTier::Srflx,
            Instant::now(),
        );

        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&lan_peer),
            Some(&ctx),
            &mut upgrade_probes,
            &mut test_relay_bq(),
            "test",
        )
        .await;
        assert!(
            !by_node.contains_key(&lan_peer.node_id),
            "no fresh install while a probe is in flight (rides relay)"
        );
    }

    /// P3 PR-E — a monitor-penalized tier is not probed by the upgrade arm
    /// (the eligibility plane is the ONE suppression system now).
    /// Birth probe — a fresh LAN peer whose first carrier is the DERP floor
    /// starts its LAN upgrade probe in the SAME walk, instead of riding the
    /// floor until the next re-upgrade walk (F0 measured ~30 s per LAN pair).
    /// Make-before-break: the floor stays the installed carrier until the
    /// probe latches.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_floored_lan_peer_probes_lan_at_birth() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx.clone(), tf, 1280);
        let mux = DerpMux::new(kp.public.to_bytes()).0;
        let mut relay = Some(RelayCoordinator::new(
            out_tx,
            kp.public.to_bytes(),
            true,
            vec![],
            Some(mux),
        ));
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let tun: Arc<dyn TunIo> = tun_mock;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let my_ip: Ipv4Addr = "10.1.2.9".parse().unwrap();
        let ctx = DirectCtx {
            socks: vec![(my_ip, sock)],
            my_ips: vec![my_ip],
            endpoints: vec![],
            public_sock: None,
            punch: None,
            my_nat: None,
            v6: None,
            my_v6: vec![],
        };
        let mut lan_peer = peer(&peer_kp, "100.64.0.7");
        lan_peer.lan_endpoints = vec!["10.1.2.3:1000".into()];
        lan_peer.supports_derp = true;
        lan_peer.supports_derp_floor = true;
        let mut by_node = HashMap::new();
        let mut upgrade_probes = HashMap::new();

        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&lan_peer),
            Some(&ctx),
            &mut upgrade_probes,
            &mut test_relay_bq(),
            "test",
        )
        .await;
        let e = by_node
            .get(&lan_peer.node_id)
            .expect("the floor is installed at birth");
        assert_eq!(
            e.relay_kind,
            Some(RelayKind::Derp),
            "the floor carries until the probe latches"
        );
        let probe = upgrade_probes
            .get(&lan_peer.node_id)
            .expect("the LAN probe starts in the same walk");
        assert_eq!(probe.tier, DirectTier::Lan);
        assert!(wg.has_direct_probe(&peer_kp.public.to_bytes()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn upgrade_arm_respects_monitor_penalty() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let tun: Arc<dyn TunIo> = tun_mock;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let my_ip: Ipv4Addr = "10.1.2.9".parse().unwrap();
        let ctx = DirectCtx {
            socks: vec![(my_ip, sock)],
            my_ips: vec![my_ip],
            endpoints: vec![],
            public_sock: None,
            punch: None,
            my_nat: None,
            v6: None,
            my_v6: vec![],
        };
        let mut relay: Option<RelayCoordinator> = None;
        let mut by_node = HashMap::new();
        let mut upgrade_probes = HashMap::new();
        let mut lan_peer = peer(&peer_kp, "100.64.0.7");
        lan_peer.lan_endpoints = vec!["10.1.2.3:1000".into()];
        by_node.insert(
            lan_peer.node_id,
            Installed {
                is_direct: false,
                ..Installed::base(
                    peer_kp.public.to_bytes(),
                    "100.64.0.7".parse().unwrap(),
                    DirectTier::Relay,
                    Instant::now(),
                )
            },
        );
        rt.path_shadow.lock().unwrap().mon.on_death(
            &lan_peer.node_id,
            DirectTier::Lan,
            DeathReason::HandshakeDeadline,
            true,
            Instant::now(),
        );

        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&lan_peer),
            Some(&ctx),
            &mut upgrade_probes,
            &mut test_relay_bq(),
            "test",
        )
        .await;
        assert!(
            !upgrade_probes.contains_key(&lan_peer.node_id),
            "no upgrade probe against a monitor-penalized tier"
        );
        // The suppression lapses (H_ORDINARY) — locked by path.rs's parity
        // curves; here we just confirm the monitor still holds the strike.
        assert_eq!(
            rt.path_shadow
                .lock()
                .unwrap()
                .mon
                .strikes(&lan_peer.node_id, DirectTier::Lan),
            1
        );
    }

    /// #26 — the post-Major re-check has to land in the narrow band between
    /// "past the conviction window" and "before the tick it replaces", and
    /// BOTH bounds are load-bearing:
    ///
    /// * at or below `MAJOR_POKE_DEADLINE` the pulled-forward tick judges
    ///   a poke that has not expired yet, the strict `>` fails, and the real
    ///   verdict slips to the NEXT tick — i.e. the acceleration silently buys
    ///   nothing while looking like it works;
    /// * at or above `FALLBACK_TICK` it is not an acceleration at all, just a
    ///   phase shift of the ordinary grid.
    ///
    /// The margin also has to be big enough to swallow timer jitter, since
    /// undershooting costs a whole `FALLBACK_TICK` rather than a millisecond.
    #[test]
    fn major_recheck_lands_inside_the_grid() {
        assert!(
            MAJOR_RECHECK_AFTER > crate::overlay::lifecycle::MAJOR_POKE_DEADLINE,
            "the re-check must land AFTER the conviction window, or it judges an unexpired poke"
        );
        assert!(
            MAJOR_RECHECK_AFTER < FALLBACK_TICK,
            "a re-check at/after the ordinary cadence is not an acceleration"
        );
        assert!(
            MAJOR_RECHECK_AFTER - crate::overlay::lifecycle::MAJOR_POKE_DEADLINE
                >= Duration::from_millis(100),
            "leave real margin over timer jitter — undershooting costs a whole FALLBACK_TICK"
        );
    }

    /// #28 — the `/derp`-recovery levers must land where they can act. The
    /// pull-forward is only an acceleration below the ordinary cadence, and the
    /// walk window must outlast it or the tick it pulls in lands after the
    /// window has already closed — which would leave `install_peers` back on
    /// its ~30 s cadence and buy nothing at all.
    #[test]
    fn derp_recovery_levers_land_where_they_can_act() {
        assert!(
            DERP_RECOVERY_RECHECK < FALLBACK_TICK,
            "a recheck at/after the ordinary cadence is not an acceleration"
        );
        assert!(
            DERP_RECOVERY_WALK_WINDOW > DERP_RECOVERY_RECHECK,
            "the pulled-forward tick must land INSIDE the fast-walk window"
        );
        assert!(
            DERP_RECOVERY_WALK_WINDOW >= FALLBACK_TICK * 2,
            "cover a second flap — the field case reconnected twice inside 2 s"
        );
    }

    /// P8 — the resume detector: fires only when wall-clock outran the
    /// monotonic clock by more than the threshold (suspend), not on NTP-step
    /// noise or ordinary ticks.
    #[test]
    fn resume_detector_fires_on_suspend_skew_only() {
        let tick = Duration::from_secs(5);
        assert!(!resumed_from_suspend(tick, tick), "ordinary tick");
        assert!(
            !resumed_from_suspend(tick, tick + Duration::from_secs(60)),
            "NTP step below threshold"
        );
        assert!(
            resumed_from_suspend(tick, tick + Duration::from_secs(3600)),
            "an hour of sleep must fire"
        );
        assert!(
            !resumed_from_suspend(Duration::from_secs(3600), Duration::from_secs(3600)),
            "long but consistent gap (loop stalled, no sleep) must not fire"
        );
    }

    /// rc.225 (re-scoped by PR-E) — the endpoint-change PREDICATE reacts to
    /// the LAN/srflx buckets but NOT the churny relay-advert bucket (the
    /// wipe itself is `PathMonitor::on_endpoint_change`, locked by path.rs's
    /// `endpoint_change_resets_penalties_strikes_and_q`).
    #[test]
    fn endpoint_change_predicate_tracks_direct_buckets_only() {
        let a = ObjectId::from_bytes([1; 12]);
        let mk = |lan: &[&str], srflx: &[&str], relay: &[&str]| NetmapPeer {
            node_id: a,
            overlay_ip: "100.64.0.9".into(),
            name: "t".into(),
            wg_public_key: String::new(),
            endpoints: relay.iter().map(|s| s.to_string()).collect(),
            lan_endpoints: lan.iter().map(|s| s.to_string()).collect(),
            srflx_endpoints: srflx.iter().map(|s| s.to_string()).collect(),
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            caps: None,
            supports_overlay_echo: false,
            supports_org_relay: false,
            relay_strategy: None,
            routes: vec![],
            agent_id: None,
            ingress_rules: None,
        };
        let base = mk(
            &["192.168.68.126:51573"],
            &["37.63.112.129:58770"],
            &["94.130.141.74:1"],
        );
        assert!(
            !direct_endpoints_changed(&base, &base.clone()),
            "identical ⇒ no reset"
        );
        assert!(
            direct_endpoints_changed(
                &base,
                &mk(
                    &["192.168.68.126:60001"],
                    &["37.63.112.129:58770"],
                    &["94.130.141.74:1"]
                )
            ),
            "LAN port change (daemon restart) ⇒ reset"
        );
        assert!(
            direct_endpoints_changed(
                &base,
                &mk(
                    &["192.168.68.126:51573"],
                    &["37.63.112.129:60002"],
                    &["94.130.141.74:1"]
                )
            ),
            "srflx change (roam / NAT rebind) ⇒ reset"
        );
        assert!(
            !direct_endpoints_changed(
                &base,
                &mk(
                    &["192.168.68.126:51573"],
                    &["37.63.112.129:58770"],
                    &["5.9.157.226:9"]
                )
            ),
            "relay-advert churn must NOT reset (it changes on every re-allocation)"
        );
        // The deadlines are ordered srflx/LAN (tight) < public (loose) <
        // relay (loosest — needs BOTH ends' allocations, and the peer's grant
        // cycle can lag). rc.204 — LAN gained a deadline: a false same-subnet
        // match must demote, not zombie forever. rc.223 — RELAY gained one
        // too: a never-handshaked relay was invisible to every other detector
        // (pre-handshake traffic advances neither tx nor rx) and wedged the
        // pair for good — while also starving the P7 churn counter.
        assert!(SRFLX_HANDSHAKE_DEADLINE < PUBLIC_HANDSHAKE_DEADLINE);
        assert!(LAN_HANDSHAKE_DEADLINE < PUBLIC_HANDSHAKE_DEADLINE);
        assert!(PUBLIC_HANDSHAKE_DEADLINE < RELAY_HANDSHAKE_DEADLINE);
        assert!(
            LAN_HANDSHAKE_DEADLINE > DIRECT_GRACE,
            "a blown LAN deadline must land past the warm-up grace"
        );
        assert!(
            RELAY_HANDSHAKE_DEADLINE > DIRECT_GRACE,
            "a blown relay deadline must land past the warm-up grace"
        );
        assert_eq!(DirectTier::Lan.handshake_deadline(), LAN_HANDSHAKE_DEADLINE);
        assert_eq!(
            DirectTier::Relay.handshake_deadline(),
            RELAY_HANDSHAKE_DEADLINE
        );
        // PR-E — the escalation thresholds live in the monitor now; keep the
        // cross-tier relationships the deleted legacy tests guarded (const
        // blocks: these are compile-time invariants, which is the point).
        const {
            assert!(path::MAX_FAILURES_SRFLX > path::MAX_FAILURES_LAN_PUBLIC);
        }
        assert!(path::H_ESCALATED.as_secs() > path::H_ORDINARY.as_secs() * 5);
    }

    /// Phase C (D7 + CC1) — the health sweep tears down a zombie srflx punch (a
    /// Srflx-tier carrier that never completed its WG handshake) once past the
    /// srflx deadline, and books the failure ONLY on the srflx cooldown tier —
    /// never poisoning the proven LAN or public-direct tiers.
    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_tears_down_zombie_srflx_and_cools_only_srflx_tier() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        // A direct peer dialing a DEAD destination → the handshake never
        // completes → `peer_handshake_done` stays false (the zombie condition).
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 2);
        wg.add_direct_peer(
            sock.clone(),
            peer_kp.public.to_bytes(),
            overlay_ip,
            dead,
            true,
        )
        .await;
        assert_eq!(
            wg.peer_handshake_done(&peer_kp.public.to_bytes()),
            Some(false),
            "precondition: the punch never handshook"
        );

        let nid = ObjectId::from_bytes([5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                // Installed past the srflx handshake deadline (and the grace).
                since: Instant::now()
                    .checked_sub(Duration::from_secs(SRFLX_HANDSHAKE_DEADLINE.as_secs() + 3))
                    .unwrap(),
                public_direct_dst: Some(dead),
                ..Installed::base(
                    peer_kp.public.to_bytes(),
                    overlay_ip,
                    DirectTier::Srflx,
                    Instant::now(),
                )
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;

        assert!(
            !by_node.contains_key(&nid),
            "the zombie srflx carrier is torn down"
        );
        // PR-E — the failure bookkeeping is the monitor's suppression plane.
        let now = Instant::now();
        let s = rt.path_shadow.lock().unwrap();
        assert!(
            !s.mon.eligible(&nid, DirectTier::Srflx, now),
            "the srflx suppression penalty is booked"
        );
        assert_eq!(
            s.mon.strikes(&nid, DirectTier::Srflx),
            1,
            "one srflx strike"
        );
        assert!(
            s.mon.eligible(&nid, DirectTier::Lan, now) && s.mon.strikes(&nid, DirectTier::Lan) == 0,
            "CC1: the LAN tier is NOT poisoned"
        );
        assert!(
            s.mon.eligible(&nid, DirectTier::Public, now)
                && s.mon.strikes(&nid, DirectTier::Public) == 0,
            "CC1: the public-direct tier is NOT poisoned"
        );
    }

    /// rc.204 — the health sweep tears down a zombie LAN carrier (a Lan-tier
    /// carrier that never completed its WG handshake) once past the LAN
    /// deadline, and books the failure ONLY on the LAN cooldown tier. Before
    /// rc.204 the LAN tier had no handshake deadline: pre-handshake tx/rx stay
    /// flat, so the rx-flat heuristic never fired and a false same-subnet match
    /// was a PERMANENT zombie with no relay fallback (field-observed
    /// 2026-07-21: every LAN pair wedged in `HANDSHAKE(REKEY_TIMEOUT)`).
    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_tears_down_zombie_lan_and_cools_only_lan_tier() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        // A LAN carrier dialing a DEAD destination → the handshake never
        // completes → `peer_handshake_done` stays false (the zombie condition).
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 3);
        wg.add_direct_peer(
            sock.clone(),
            peer_kp.public.to_bytes(),
            overlay_ip,
            dead,
            true,
        )
        .await;
        assert_eq!(
            wg.peer_handshake_done(&peer_kp.public.to_bytes()),
            Some(false),
            "precondition: the LAN carrier never handshook"
        );

        let nid = ObjectId::from_bytes([6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                // Installed past the LAN handshake deadline (and the grace).
                since: Instant::now()
                    .checked_sub(Duration::from_secs(LAN_HANDSHAKE_DEADLINE.as_secs() + 3))
                    .unwrap(),
                ..Installed::base(
                    peer_kp.public.to_bytes(),
                    overlay_ip,
                    DirectTier::Lan,
                    Instant::now(),
                )
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;

        assert!(
            !by_node.contains_key(&nid),
            "the zombie LAN carrier is torn down"
        );
        // PR-E — the failure bookkeeping is the monitor's suppression plane.
        let now = Instant::now();
        let s = rt.path_shadow.lock().unwrap();
        assert!(
            !s.mon.eligible(&nid, DirectTier::Lan, now),
            "the LAN suppression penalty is booked"
        );
        assert_eq!(s.mon.strikes(&nid, DirectTier::Lan), 1, "one LAN strike");
        assert!(
            s.mon.eligible(&nid, DirectTier::Srflx, now)
                && s.mon.strikes(&nid, DirectTier::Srflx) == 0,
            "CC1: the srflx tier is NOT poisoned"
        );
        assert!(
            s.mon.eligible(&nid, DirectTier::Public, now)
                && s.mon.strikes(&nid, DirectTier::Public) == 0,
            "CC1: the public-direct tier is NOT poisoned"
        );
    }

    /// Net-change acceleration — `force_poke` arms a revalidation poke on an
    /// established direct carrier with FRESH rx (none of the passive gates
    /// met), and without the flag the same sweep arms nothing. This is the
    /// contract that collapses the winhost-a CP-connect failover from ~90 s
    /// (waiting out `POKE_SILENCE_AFTER` + the rx-stale race) to ~one
    /// handshake deadline: the OS route event is the suspicion, the poke is
    /// the honest proof either way.
    #[tokio::test(flavor = "multi_thread")]
    async fn netchange_force_poke_arms_without_silence() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 5);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock.clone(), pk, overlay_ip, dead, true)
            .await;
        wg.test_latch_handshake_done(&pk);

        let nid = ObjectId::from_bytes([8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                // Past the warm-up grace but heard from JUST NOW, and young
                // enough that the stale-proof trigger (POKE_PROOF_AFTER,
                // 120 s — since_proof falls back to install age when we never
                // initiated) is nowhere near: NO passive trigger can fire.
                since: Instant::now().checked_sub(Duration::from_secs(30)).unwrap(),
                last_rx_at: Instant::now(),
                ..Installed::base(pk, overlay_ip, DirectTier::Lan, Instant::now())
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        // Control: no net-change flag → the fresh carrier is left alone.
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;
        assert!(
            by_node.get(&nid).is_some_and(|e| e.poke.is_none()),
            "fresh carrier is not poked without the net-change flag"
        );

        // Net-change flag → the same fresh carrier gets a forced poke armed
        // (and survives the sweep — arming never kills).
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::Major,
        )
        .await;
        assert!(
            by_node
                .get(&nid)
                .is_some_and(|e| e.poke.is_some_and(|p| p.from_major)),
            "a Major forces a revalidation poke despite fresh rx, STAMPED \
             `from_major` (the stamp is what buys the tight conviction window)"
        );

        // #26 — the CHATTY cause arms the same poke but must NOT stamp it: an
        // addr/iface signal fires up to once per 3 s (a Docker/WSL adapter
        // blinking, a lease renewal) against carriers that are usually
        // healthy, so judging it on one round trip would demote every direct
        // pair on the box. Only the ≤1-per-120 s Major earns that.
        by_node.get_mut(&nid).unwrap().poke = None;
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::AddrIface,
        )
        .await;
        let p = by_node
            .get(&nid)
            .and_then(|e| e.poke)
            .expect("an addr/iface signal still arms the forced poke (pre-#26 behaviour)");
        assert!(
            !p.from_major,
            "an addr/iface signal must NOT inherit the Major conviction window"
        );
    }

    /// A minimal netmap peer for the demote-follow tests: derp-capable and
    /// reachable, with no endpoints (the follow resolves by pubkey, not by
    /// candidate). Shared so the two tests cannot drift apart on the fields
    /// that gate the path under test.
    fn test_netmap_peer(nid: ObjectId, overlay_ip: Ipv4Addr, kp: &WgKeypair) -> NetmapPeer {
        NetmapPeer {
            node_id: nid,
            overlay_ip: overlay_ip.to_string(),
            name: "pc".into(),
            wg_public_key: kp.public_base64(),
            supports_derp: true,
            supports_derp_floor: true,
            reachable: true,
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            supports_quic: false,
            supports_relay_single: false,
            supports_forced_derp: false,
            caps: None,
            supports_overlay_echo: false,
            supports_org_relay: false,
            relay_strategy: None,
            routes: vec![],
            agent_id: None,
            ingress_rules: None,
        }
    }

    /// #34 — a carrier we JUST promoted must survive the peer catching up.
    ///
    /// The peer has its own probe → latch → cutover to finish (4.2-7.4 s
    /// measured on a healthy LAN) and is legitimately still sending over the
    /// relay until then. Without a grace those in-flight frames read as "the
    /// peer relays instead" and tear down the promotion we just made — caught
    /// live 2026-08-26, promote and follow in the SAME SECOND, on a pair whose
    /// peer had itself INITIATED the direct handshake:
    ///
    ///   22:59:01  accepted inbound direct handshake as a PROBE
    ///   22:59:06  direct carrier PROMOTED (relay held throughout)
    ///   22:59:06  peer is relaying to us over /derp — following it (demote-follow)
    ///
    /// Each such round also books a strike, and #31 escalates the hold-down
    /// 3→6→12→15 min, so a pair pins itself to a relay for a quarter of an
    /// hour by the act of converging. Six laptops on one table sat on relay
    /// because of it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_just_promoted_carrier_is_not_torn_down_by_the_peer_catching_up() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let pk = peer_kp.public.to_bytes();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx.clone(), tf, 1280);
        let mux = DerpMux::new(kp.public.to_bytes()).0;
        let mut relay = Some(RelayCoordinator::new(
            out_tx,
            kp.public.to_bytes(),
            true,
            vec![],
            Some(mux),
        ));
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 65, 4, 34);
        wg.add_direct_peer(sock.clone(), pk, overlay_ip, dst, true)
            .await;
        let nid = ObjectId::from_bytes([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();
        current_peers.insert(nid, test_netmap_peer(nid, overlay_ip, &peer_kp));
        let tun: Arc<dyn TunIo> = tun_mock;
        let mut bq = test_relay_bq();
        let mut cooldown: HashMap<ObjectId, Instant> = HashMap::new();

        // Promoted one second ago — the peer is still cutting over.
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed::base(
                pk,
                overlay_ip,
                DirectTier::Lan,
                Instant::now() - Duration::from_secs(1),
            ),
        );
        assert!(
            !rt.demote_follow(
                pk,
                &mut wg,
                &mut by_node,
                &mut relay,
                &tun,
                &current_peers,
                &mut bq,
                &mut cooldown,
            )
            .await,
            "a carrier promoted 1 s ago must NOT be torn down by the peer's \
             in-flight relay frames"
        );
        assert!(
            by_node[&nid].is_direct,
            "and it must still be the direct carrier afterwards"
        );
        assert!(
            cooldown.is_empty(),
            "no strike, no cooldown — nothing disagreed"
        );

        // Past the grace, the same signal IS a real disagreement and is followed.
        by_node.insert(
            nid,
            Installed::base(
                pk,
                overlay_ip,
                DirectTier::Lan,
                Instant::now() - PROMOTE_FOLLOW_GRACE - Duration::from_secs(1),
            ),
        );
        assert!(
            rt.demote_follow(
                pk,
                &mut wg,
                &mut by_node,
                &mut relay,
                &tun,
                &current_peers,
                &mut bq,
                &mut cooldown,
            )
            .await,
            "past the grace, a peer still relaying to us is a genuine disagreement"
        );
    }

    /// #27 — the demote-follow, end to end. A peer we hold on a DIRECT carrier
    /// that is relaying to us over `/derp` flips onto DERP immediately, instead
    /// of waiting for our own passive detectors — which, on the end whose
    /// network did NOT change, means no netstate Major, so `POKE_SILENCE_AFTER`
    /// (floored by the ~25 s WG keepalive) plus a tier deadline. Field
    /// 2026-08-24: **67 s**, with BOTH directions dark for all of it.
    ///
    /// The three bounds are asserted with it: an unknown pubkey is ignored, a
    /// peer already ON derp is a no-op, and the per-peer cooldown holds.
    #[tokio::test(flavor = "multi_thread")]
    async fn demote_follow_flips_a_direct_carrier_onto_derp() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let pk = peer_kp.public.to_bytes();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx.clone(), tf, 1280);

        // A coordinator with a LIVE /derp mux — the follow builds over it.
        let mux = DerpMux::new(kp.public.to_bytes()).0;
        let mut relay = Some(RelayCoordinator::new(
            out_tx,
            kp.public.to_bytes(),
            true,
            vec![],
            Some(mux),
        ));

        // The peer, on a DIRECT (LAN) carrier that looks perfectly healthy.
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 65, 4, 28);
        wg.add_direct_peer(sock.clone(), pk, overlay_ip, dst, true)
            .await;
        let nid = ObjectId::from_bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            // #34 — AGED past `PROMOTE_FOLLOW_GRACE`: this test is about a peer that
            // genuinely disagrees, not one still cutting over. The grace case is
            // covered by `a_just_promoted_carrier_is_not_torn_down_by_the_peer_catching_up`.
            Installed::base(
                pk,
                overlay_ip,
                DirectTier::Lan,
                Instant::now() - PROMOTE_FOLLOW_GRACE - Duration::from_secs(1),
            ),
        );

        let mut current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();
        current_peers.insert(
            nid,
            NetmapPeer {
                node_id: nid,
                overlay_ip: overlay_ip.to_string(),
                name: "pc".into(),
                wg_public_key: peer_kp.public_base64(),
                supports_derp: true,
                supports_derp_floor: true,
                reachable: true,
                endpoints: vec![],
                lan_endpoints: vec![],
                srflx_endpoints: vec![],
                srflx_nat: None,
                udp_dialer_ok: None,
                relay_home: None,
                warm_relay_endpoint: None,
                supports_quic: false,
                supports_relay_single: false,
                supports_forced_derp: false,
                caps: None,
                supports_overlay_echo: false,
                supports_org_relay: false,
                relay_strategy: None,
                routes: vec![],
                agent_id: None,
                ingress_rules: None,
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut bq = test_relay_bq();
        let mut cooldown: HashMap<ObjectId, Instant> = HashMap::new();

        // A pubkey nobody in the netmap owns must be ignored outright — the
        // first bound on a signal that arrives from the network.
        assert!(
            !rt.demote_follow(
                [0xAB; 32],
                &mut wg,
                &mut by_node,
                &mut relay,
                &tun,
                &current_peers,
                &mut bq,
                &mut cooldown,
            )
            .await,
            "an unknown pubkey must never move a carrier"
        );
        assert!(cooldown.is_empty(), "and must not even arm the cooldown");

        // The real signal: the peer is relaying to us. Follow it.
        assert!(
            rt.demote_follow(
                pk,
                &mut wg,
                &mut by_node,
                &mut relay,
                &tun,
                &current_peers,
                &mut bq,
                &mut cooldown,
            )
            .await,
            "a known peer relaying to us must flip our carrier"
        );
        let e = by_node.get(&nid).expect("still installed");
        assert_eq!(
            e.relay_kind,
            Some(crate::overlay::relay_link::RelayKind::Derp),
            "the carrier must now be DERP — the path the peer is actually using"
        );
        assert_eq!(e.tier, DirectTier::Relay);

        // #29 — the follow must SUPPRESS the tier it left, or make-before-break
        // re-promotes it on its next probe and the pair flaps on MBB's cadence
        // (field: every 60 s for hours). Decaying, so direct returns by itself.
        assert!(
            rt.path_shadow
                .lock()
                .unwrap()
                .mon
                .strikes(&nid, DirectTier::Lan)
                >= 1,
            "following a peer onto DERP must suppress the direct tier we left"
        );

        // Repeat notices are ordinary (frames in flight when we flipped) and
        // must be inert, not a rebuild loop.
        assert!(
            !rt.demote_follow(
                pk,
                &mut wg,
                &mut by_node,
                &mut relay,
                &tun,
                &current_peers,
                &mut bq,
                &mut cooldown,
            )
            .await,
            "a peer already ON derp is a no-op"
        );

        // And the cooldown holds even if the carrier is somehow not derp.
        by_node.get_mut(&nid).unwrap().relay_kind = None;
        assert!(
            !rt.demote_follow(
                pk,
                &mut wg,
                &mut by_node,
                &mut relay,
                &tun,
                &current_peers,
                &mut bq,
                &mut cooldown,
            )
            .await,
            "the per-peer cooldown must bound how often a follow can fire"
        );
    }

    /// #26 — a net-change RE-ARMS a poke that is already in flight, and the
    /// re-arm both restamps the clock and marks the poke net-change-class.
    ///
    /// This is the second half of the VPN-transition hole: the pre-#26 arming
    /// sat behind `last_poke_at.is_none()`, so a poke armed by the silence or
    /// proof trigger seconds before a VPN connect kept its establish-sized
    /// tier deadline (12-30 s) and blackholed that pair for the whole window
    /// while its neighbours failed over in ~2 s. Re-arming is also what makes
    /// the tight window honest: it judges an initiation sent NOW, not one
    /// whose last boringtun re-send may already be ~5 s old.
    #[tokio::test(flavor = "multi_thread")]
    async fn major_rearms_a_poke_already_in_flight() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 6);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock.clone(), pk, overlay_ip, dead, true)
            .await;
        wg.test_latch_handshake_done(&pk);

        let nid = ObjectId::from_bytes([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // An ORDINARY poke armed 5 s ago (as the silence trigger would), on a
        // Public-tier carrier whose deadline is 30 s — so nothing convicts it
        // yet, and pre-#26 nothing would re-arm it either.
        let armed_at = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                since: Instant::now().checked_sub(Duration::from_secs(30)).unwrap(),
                last_rx_at: Instant::now(),
                poke: Some(PokeArm {
                    at: armed_at,
                    from_major: false,
                    from_business: false,
                }),
                ..Installed::base(pk, overlay_ip, DirectTier::Public, Instant::now())
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::Major,
        )
        .await;

        let p = by_node
            .get(&nid)
            .expect("carrier survives the arming sweep")
            .poke
            .expect("the poke is still armed");
        assert!(
            p.from_major,
            "a net-change must PROMOTE an in-flight poke to the tight window"
        );
        assert!(
            p.at > armed_at,
            "the re-arm must restamp the clock — judging a 2 s window against a \
             5 s-old initiation would convict on stale evidence"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_business_poke_before_silence_and_through_tcp_backoff() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let ip = Ipv4Addr::new(100, 64, 0, 4);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock, pk, ip, dead, true).await;
        wg.test_latch_handshake_done(&pk);
        let nid = ObjectId::from_bytes([74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(nid, Installed {
            since: Instant::now().checked_sub(Duration::from_secs(20)).unwrap(),
            last_rx_at: Instant::now(),
            ..Installed::base(pk, ip, DirectTier::Srflx, Instant::now())
        });
        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay = None;
        let mut refresh = HashMap::new();
        let peers = HashMap::new();
        // A healthy idle carrier must not gain a new revalidation trigger.
        assert!(!rt.sweep_carrier_health(&mut wg, &mut by_node, &mut relay, &tun,
            &mut refresh, &peers, ForcedPoke::No).await,
            "healthy idle peers do not request an immediate repair walk");
        assert!(by_node[&nid].poke.is_none());
        // A periodic/pressure proof may already be in flight when business
        // becomes one-way. Upgrade it against a fresh initiation, rather than
        // leaving the business flow behind its old establishment-sized wait.
        let earlier = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm {
            at: earlier, from_major: false, from_business: false,
        });
        wg.test_set_ip_traffic(&pk, 1, 0);
        rt.sweep_carrier_health(&mut wg, &mut by_node, &mut relay, &tun,
            &mut refresh, &peers, ForcedPoke::No).await;
        assert!(by_node[&nid].poke.is_some(),
            "unanswered business traffic must start round-trip validation immediately");
        assert_eq!(by_node[&nid].bad_sweeps, 1);
        assert!(by_node[&nid].poke.unwrap().from_business,
            "business suspicion must select the established-path proof window");
        let armed = by_node[&nid].poke.unwrap().at;
        assert!(armed > earlier, "a shorter window needs a fresh initiation");
        wg.test_set_ip_traffic(&pk, 2, 0);
        rt.sweep_carrier_health(&mut wg, &mut by_node, &mut relay, &tun,
            &mut refresh, &peers, ForcedPoke::No).await;
        assert_eq!(by_node[&nid].poke.unwrap().at, armed,
            "repeated suspicion must not keep moving the proof deadline");
        let major_at = Instant::now();
        by_node.get_mut(&nid).unwrap().bad_sweeps = 0;
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm {
            at: major_at, from_major: true, from_business: false,
        });
        wg.test_set_ip_traffic(&pk, 3, 0);
        rt.sweep_carrier_health(&mut wg, &mut by_node, &mut relay, &tun,
            &mut refresh, &peers, ForcedPoke::No).await;
        assert!(by_node[&nid].poke.unwrap().from_major,
            "business suspicion must not replace the more urgent Major proof");
        assert_eq!(by_node[&nid].poke.unwrap().at, major_at);

        // TCP backs off and submits no further packet. Its idle interval must
        // not cancel the independent handshake proof or restart its deadline.
        let at = Instant::now().checked_sub(crate::overlay::lifecycle::BUSINESS_POKE_DEADLINE
            + Duration::from_secs(1)).unwrap();
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm { at, from_major: false, from_business: true });
        assert!(rt.sweep_carrier_health(&mut wg, &mut by_node, &mut relay, &tun,
            &mut refresh, &peers, ForcedPoke::No).await,
            "a real removal requests repair immediately");
        assert!(!by_node.contains_key(&nid));
        assert_eq!(rt.path_shadow.lock().unwrap().mon.strikes(&nid, DirectTier::Srflx), 0,
            "an active proof failure must retain the existing no-strike policy");
    }


    #[tokio::test]
    async fn business_scout_resends_one_initiation_for_an_unanswered_business_proof() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock.clone(), pk, ip, dead, true).await;
        wg.test_latch_handshake_done(&pk);
        let nid = ObjectId::from_bytes([77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(nid, Installed {
            since: Instant::now() - Duration::from_secs(20),
            last_rx_at: Instant::now(),
            ..Installed::base(pk, ip, DirectTier::Srflx, Instant::now())
        });
        let mut samples = HashMap::new();
        wg.test_set_ip_traffic(&pk, 10, 10);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);

        // A business proof armed before the re-send point, still unanswered.
        let at = Instant::now() - crate::overlay::lifecycle::BUSINESS_POKE_RETAP_AFTER;
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm { at, from_major: false, from_business: true });
        wg.test_set_ip_traffic(&pk, 20, 10);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert_eq!(samples[&nid].retapped, Some(at), "one fresh initiation for the unanswered proof");
        assert_eq!(by_node[&nid].poke.unwrap().at, at, "the re-send keeps the proof's window");

        // A Major proof is never re-sent by the scout.
        let major = Instant::now() - Duration::from_secs(1);
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm { at: major, from_major: true, from_business: false });
        wg.test_set_ip_traffic(&pk, 30, 10);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert_eq!(samples[&nid].retapped, Some(at));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn business_scout_detects_loss_inside_a_mixed_health_bucket() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let ip = Ipv4Addr::new(100, 64, 0, 6);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock.clone(), pk, ip, dead, true).await;
        wg.test_latch_handshake_done(&pk);
        let nid = ObjectId::from_bytes([76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(nid, Installed {
            since: Instant::now() - Duration::from_secs(20),
            last_rx_at: Instant::now(),
            ..Installed::base(pk, ip, DirectTier::Srflx, Instant::now())
        });
        let mut samples = HashMap::new();
        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay = None;
        let mut refresh = HashMap::new();
        let peers = HashMap::new();

        // The scout first sees healthy traffic. A fault then loses one packet,
        // but the full five-second bucket still contains pre-fault receives.
        wg.test_set_ip_traffic(&pk, 10, 10);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert!(by_node[&nid].poke.is_none());
        wg.test_set_ip_traffic(&pk, 11, 10);
        rt.sweep_carrier_health(&mut wg, &mut by_node, &mut relay, &tun,
            &mut refresh, &peers, ForcedPoke::No).await;
        assert_eq!(by_node[&nid].bad_sweeps, 0);
        assert!(by_node[&nid].poke.is_none(), "the mixed health bucket masks this loss");
        wg.test_bump_rx_any(&pk);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        let armed = by_node[&nid].poke.expect("the one-second scout must start proof before the next health sweep");
        assert!(armed.from_business && !armed.from_major);
        assert_eq!(by_node[&nid].bad_sweeps, 0);
        assert_eq!(by_node[&nid].last_traffic, (11, 10));
        assert_eq!(wg.peer_take_rx_any(&pk), 1, "the scout must not drain sweep liveness");
        assert_eq!(rt.path_shadow.lock().unwrap().mon.strikes(&nid, DirectTier::Srflx), 0);

        // Repeated sends or TCP idle backoff must not move an existing deadline.
        wg.test_set_ip_traffic(&pk, 12, 10);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert_eq!(by_node[&nid].poke.unwrap().at, armed.at);
        tokio::time::sleep(Duration::from_millis(2)).await;
        wg.test_stamp_initiator_hs(&pk);
        assert!(wg.peer_initiator_hs_answered(&pk, armed.at));
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert_eq!(by_node[&nid].poke.unwrap().at, armed.at,
            "only the normal sweep settles an answered proof");
        wg.test_set_ip_traffic(&pk, 12, 11);
        rt.sweep_carrier_health(&mut wg, &mut by_node, &mut relay, &tun,
            &mut refresh, &peers, ForcedPoke::No).await;
        assert!(by_node[&nid].poke.is_none(), "an answered healthy path survives and settles");
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert!(by_node[&nid].poke.is_none());

        let major = Instant::now();
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm {
            at: major, from_major: true, from_business: false,
        });
        wg.test_set_ip_traffic(&pk, 13, 11);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert_eq!(by_node[&nid].poke.unwrap().at, major);
        assert!(by_node[&nid].poke.unwrap().from_major);
        let normal = major - Duration::from_secs(1);
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm {
            at: normal, from_major: false, from_business: false,
        });
        wg.test_set_ip_traffic(&pk, 14, 11);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert!(by_node[&nid].poke.unwrap().from_business);
        assert!(by_node[&nid].poke.unwrap().at > normal);

        // New installations and installing/relay carriers cannot inherit an
        // older carrier's sample or use this established-direct fast path.
        by_node.get_mut(&nid).unwrap().poke = None;
        by_node.get_mut(&nid).unwrap().since = Instant::now() - Duration::from_secs(21);
        wg.test_set_ip_traffic(&pk, 15, 11);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert!(by_node[&nid].poke.is_none());
        wg.remove_peer(&pk).await;
        wg.add_direct_peer(sock, pk, ip, dead, false).await;
        wg.test_set_ip_traffic(&pk, 1, 0);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert!(by_node[&nid].poke.is_none());
        assert!(!samples.contains_key(&nid));
        by_node.get_mut(&nid).unwrap().is_direct = false;
        wg.test_latch_handshake_done(&pk);
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert!(by_node[&nid].poke.is_none());
        assert!(!samples.contains_key(&nid));
    }


    #[tokio::test(flavor = "multi_thread")]
    async fn business_scout_observes_a_failed_carrier_send_without_inflating_tx() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        // An IPv4-only carrier socket cannot send to an IPv6 destination.
        // This exercises a real send error without changing a host firewall.
        let impossible: SocketAddr = "[::1]:9".parse().unwrap();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock, pk, ip, impossible, false).await;
        wg.test_latch_handshake_done(&pk);
        let nid = ObjectId::from_bytes([77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(nid, Installed {
            since: Instant::now() - Duration::from_secs(20),
            last_rx_at: Instant::now(),
            ..Installed::base(pk, ip, DirectTier::Srflx, Instant::now())
        });
        let mut samples = HashMap::new();
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        let packet = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0,
            100, 64, 0, 1, 100, 64, 0, 7];
        assert!(!wg.sender().send_to_peer(&pk, &packet).await,
            "the carrier send must actually fail");
        assert_eq!(wg.peer_traffic(&pk), Some((0, 0)),
            "a failed send must not become successful API traffic");
        assert_eq!(wg.peer_business_traffic(&pk), Some((1, 0)),
            "failed business sends still require path validation");
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        let proof = by_node[&nid].poke.expect("failed local business send arms proof");
        assert!(proof.from_business && !proof.from_major);
        assert_eq!(by_node[&nid].bad_sweeps, 0);
        assert_eq!(by_node[&nid].last_traffic, (0, 0));
        assert!(wg.poke_handshake(&pk));
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(wg.peer_business_traffic(&pk), Some((1, 0)),
            "a standalone handshake must not count as business traffic");
        rt.scout_business_traffic(&mut wg, &mut by_node, &mut samples);
        assert_eq!(by_node[&nid].poke.unwrap().at, proof.at);
    }


    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_repair_builds_floor_immediately_only_after_a_real_removal() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let new_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(32);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx.clone(), tf, 1280);
        let mux = DerpMux::new(kp.public.to_bytes()).0;
        let mut relay = Some(RelayCoordinator::new(out_tx, kp.public.to_bytes(),
            true, vec![], Some(mux)));
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let ip = Ipv4Addr::new(100, 64, 0, 8);
        let new_ip = Ipv4Addr::new(100, 64, 0, 9);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock, pk, ip, "127.0.0.1:9".parse().unwrap(), true).await;
        wg.test_latch_handshake_done(&pk);
        let nid = ObjectId::from_bytes([78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let new_nid = ObjectId::from_bytes([79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(nid, Installed {
            since: Instant::now() - Duration::from_secs(20),
            last_rx_at: Instant::now(),
            ..Installed::base(pk, ip, DirectTier::Srflx, Instant::now())
        });
        let mut current_peers = HashMap::new();
        current_peers.insert(nid, test_netmap_peer(nid, ip, &peer_kp));
        // This eligible but uninstalled sentinel exposes any extra walk on
        // a healthy pass: a walk would floor it immediately too.
        current_peers.insert(new_nid, test_netmap_peer(new_nid, new_ip, &new_kp));
        let tun: Arc<dyn TunIo> = tun_mock;
        let mut refresh = HashMap::new();
        let mut probes = HashMap::new();
        let mut bq = test_relay_bq();
        assert!(!rt.sweep_and_repair_carriers(&mut wg, &mut by_node, &mut relay,
            &tun, &mut refresh, &current_peers, ForcedPoke::No, None,
            &mut probes, &mut bq).await);
        assert!(by_node[&nid].is_direct);
        assert!(!by_node.contains_key(&new_nid), "healthy sweep must not walk or retry peers");

        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm {
            at: Instant::now() - crate::overlay::lifecycle::BUSINESS_POKE_DEADLINE
                - Duration::from_secs(1),
            from_major: false, from_business: true,
        });
        assert!(rt.sweep_and_repair_carriers(&mut wg, &mut by_node, &mut relay,
            &tun, &mut refresh, &current_peers, ForcedPoke::No, None,
            &mut probes, &mut bq).await);
        let repaired = by_node.get(&nid).expect("a dead carrier must be re-floored in this pass");
        assert!(!repaired.is_direct);
        assert_eq!(repaired.relay_kind, Some(RelayKind::Derp));
        assert_eq!(wg.test_route(&ip), Some(pk));
        assert!(by_node.contains_key(&new_nid), "the existing establish walk repairs all peers");
    }

    #[test]
    fn business_poke_recheck_reaches_deadline_without_a_busy_loop() {
        let now = Instant::now();
        let nid = ObjectId::from_bytes([75, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut peers = HashMap::new();
        peers.insert(nid, Installed {
            poke: Some(PokeArm { at: now, from_major: false, from_business: true }),
            ..Installed::base([0; 32], Ipv4Addr::new(100, 64, 0, 5), DirectTier::Srflx, now)
        });
        // §6.3 F1 — the 2 s business window closes before the next 5 s sweep,
        // so the recheck is scheduled from the moment the proof is armed.
        let due = crate::overlay::lifecycle::BUSINESS_POKE_DEADLINE + Duration::from_millis(250);
        assert_eq!(business_poke_recheck(&peers, now), Some(due));
        assert_eq!(business_poke_recheck(&peers, now + Duration::from_secs(1)),
            Some(due - Duration::from_secs(1)));
        assert_eq!(business_poke_recheck(&peers, now + Duration::from_secs(7)),
            Some(Duration::from_millis(100)));
        // Further away than the regular sweep: no extra wake-up.
        assert!(business_poke_recheck(&peers, now - Duration::from_secs(4)).is_none());
        peers.get_mut(&nid).unwrap().poke.as_mut().unwrap().from_business = false;
        assert!(business_poke_recheck(&peers, now + Duration::from_secs(5)).is_none());
        peers.get_mut(&nid).unwrap().poke = None;
        assert!(business_poke_recheck(&peers, now + Duration::from_secs(5)).is_none());
    }

    /// Stage 2 — the sweep's poke wiring end-to-end: a silent ESTABLISHED
    /// carrier gets a revalidation poke armed (and survives the arming
    /// sweep); unanswered past the tier's handshake-deadline window it dies
    /// `RekeyUnanswered` with NO strike and the tier still ELIGIBLE (the
    /// no-penalty contract `PathMonitor::on_death` promises); an answered
    /// poke (the initiator-handshake stamp advancing) clears instead and the
    /// carrier lives on.
    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_poke_arms_reaps_unanswered_and_clears_answered() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 4);
        let pk = peer_kp.public.to_bytes();
        wg.add_direct_peer(sock.clone(), pk, overlay_ip, dead, true)
            .await;
        // ESTABLISHED phase (the poke is Established-only).
        wg.test_latch_handshake_done(&pk);

        let nid = ObjectId::from_bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                // Old enough for the grace; silent past POKE_SILENCE_AFTER
                // but inside the 60 s rx-stale deadline.
                since: Instant::now()
                    .checked_sub(Duration::from_secs(120))
                    .unwrap(),
                last_rx_at: Instant::now()
                    .checked_sub(POKE_SILENCE_AFTER + Duration::from_secs(2))
                    .unwrap(),
                ..Installed::base(pk, overlay_ip, DirectTier::Lan, Instant::now())
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        // Sweep 1 — arms the poke, kills nothing.
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;
        assert!(
            by_node.get(&nid).is_some_and(|e| e.poke.is_some()),
            "silent carrier survives the arming sweep with a poke pending"
        );

        // Back-date the poke past the LAN window (12 s): the next sweep must
        // reap it — RekeyUnanswered, and the no-penalty contract holds.
        by_node.get_mut(&nid).unwrap().poke = Some(PokeArm {
            at: Instant::now()
                .checked_sub(LAN_HANDSHAKE_DEADLINE + Duration::from_secs(1))
                .unwrap(),
            from_major: false,
            from_business: false,
        });
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;
        assert!(
            !by_node.contains_key(&nid),
            "the unanswered carrier is torn down"
        );
        {
            let now = Instant::now();
            let s = rt.path_shadow.lock().unwrap();
            assert_eq!(
                s.mon.strikes(&nid, DirectTier::Lan),
                0,
                "RekeyUnanswered books NO strike"
            );
            assert!(
                s.mon.eligible(&nid, DirectTier::Lan, now),
                "the LAN tier stays immediately eligible"
            );
        }

        // Answered variant: reinstall the carrier, arm a poke older than the
        // window, then stamp an initiator-handshake AFTER it — the sweep must
        // clear the poke and keep the carrier.
        wg.add_direct_peer(sock.clone(), pk, overlay_ip, dead, true)
            .await;
        wg.test_latch_handshake_done(&pk);
        by_node.insert(
            nid,
            Installed {
                since: Instant::now().checked_sub(Duration::from_secs(60)).unwrap(),
                poke: Some(PokeArm {
                    at: Instant::now()
                        .checked_sub(LAN_HANDSHAKE_DEADLINE + Duration::from_secs(1))
                        .unwrap(),
                    from_major: false,
                    from_business: false,
                }),
                ..Installed::base(pk, overlay_ip, DirectTier::Lan, Instant::now())
            },
        );
        wg.test_stamp_initiator_hs(&pk);
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;
        assert!(
            by_node.get(&nid).is_some_and(|e| e.poke.is_none()),
            "an answered poke clears and the carrier survives"
        );
    }

    /// A `TunIo` that records every peer-route add/remove, so the tests can
    /// assert what actually reached the OS routing table. `MockTun` takes the
    /// no-op default `add_peer_route`/`del_peer_route`, which makes route calls
    /// unobservable.
    struct RouteRecordingTun {
        routes: std::sync::Mutex<Vec<(&'static str, Ipv4Addr)>>,
    }
    impl RouteRecordingTun {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                routes: std::sync::Mutex::new(Vec::new()),
            })
        }
        fn calls(&self) -> Vec<(&'static str, Ipv4Addr)> {
            self.routes.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl TunIo for RouteRecordingTun {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            // Never yields — the prune tests drive the helpers directly.
            std::future::pending().await
        }
        async fn write_packet(&self, _packet: &[u8]) -> io::Result<()> {
            Ok(())
        }
        async fn add_peer_route(&self, ip: Ipv4Addr) -> io::Result<()> {
            self.routes.lock().unwrap().push(("add", ip));
            Ok(())
        }
        async fn del_peer_route(&self, ip: Ipv4Addr) {
            self.routes.lock().unwrap().push(("del", ip));
        }
        async fn defend_self_route(&self, ip: Ipv4Addr) {
            self.routes.lock().unwrap().push(("defend", ip));
        }
        async fn defend_block_floor(&self) {
            // Change B — recorded with the unspecified address (the step has
            // no single IP; its CIDR math is unit-tested in `tun.rs`).
            self.routes
                .lock()
                .unwrap()
                .push(("floor", Ipv4Addr::UNSPECIFIED));
        }
        async fn verify_peer_path_ownership(&self, peers: &[Ipv4Addr]) {
            // v3 (#23) — recorded per peer, so the wave test can assert the
            // ownership check runs LAST and receives exactly the asserted peer set.
            let mut g = self.routes.lock().unwrap();
            for ip in peers {
                g.push(("verify", *ip));
            }
        }
    }

    /// rc.278 — the route-guard re-assert must cover our OWN overlay `/32`, not
    /// just peers'. A full-tunnel VPN (Check Point) installs a metric-1 `/32`
    /// for our own address that out-ranks Windows' metric-256 on-link route, so
    /// every packet addressed to us — including the REPLY to everything we
    /// initiate — is forwarded into the corp tunnel instead of delivered
    /// locally (field: winhost-a, 100 % IPv4 loss both ways while its WireGuard
    /// carriers were healthy and IPv6 worked). rc.285 — the test now drives the
    /// REAL wave (`defended_routes` → `run_defense_wave`, the exact code both
    /// select-loop arms spawn) instead of a hand-mirrored copy of the arms.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_reassert_covers_self_and_peers() {
        let tun = RouteRecordingTun::new();
        let self_v4 = Ipv4Addr::new(100, 64, 0, 28);
        let peers = [Ipv4Addr::new(100, 64, 0, 2), Ipv4Addr::new(100, 64, 0, 4)];
        let mut by_node = HashMap::new();
        for (i, ip) in peers.iter().enumerate() {
            by_node.insert(ObjectId::new(), installed_at([i as u8 + 1; 32], *ip));
        }

        let t: Arc<dyn TunIo> = tun.clone();
        run_defense_wave(t, defended_routes(&by_node, self_v4)).await;

        let got = tun.calls();
        // v3 (#23) — peers asserted, self defended, floor, then the ownership check
        // step once per peer.
        assert_eq!(got.len(), peers.len() * 2 + 2);
        let verified: HashSet<Ipv4Addr> = got[peers.len() + 2..]
            .iter()
            .map(|(op, ip)| {
                assert_eq!(
                    *op, "verify",
                    "everything after the floor is the ownership check"
                );
                *ip
            })
            .collect();
        assert_eq!(
            verified,
            peers.iter().copied().collect::<HashSet<_>>(),
            "the ownership check receives exactly the asserted peer set, after the floor"
        );
        assert_eq!(
            got.get(peers.len() + 1),
            Some(&("floor", Ipv4Addr::UNSPECIFIED)),
            "the block-floor maintenance runs after peers + self (Change B)"
        );
        assert_eq!(
            got.get(peers.len()),
            Some(&("defend", self_v4)),
            "our own address defended after every peer re-assert"
        );
        let added: HashSet<Ipv4Addr> = got
            .iter()
            .filter(|(op, _)| *op == "add")
            .map(|(_, ip)| *ip)
            .collect();
        assert_eq!(
            added,
            peers.iter().copied().collect::<HashSet<_>>(),
            "every installed peer re-asserted exactly once"
        );
        assert!(
            !got.iter().any(|(op, ip)| *op == "add" && *ip == self_v4),
            "our own address must be EVICTION-only — never re-added via the TUN \
             (the on-link route already serves local delivery; adding a /32 to \
             ourselves risks a forwarding loop)"
        );
    }

    /// rc.285 — the defended-set composition is declarative: every installed
    /// peer exactly once, then self, then (Change B) the block-floor step
    /// LAST, and nothing else. (The P5 exit `/1`s are deliberately ABSENT —
    /// their re-assert is inline-only for the teardown mutual-exclusion; see
    /// [`Defend`].)
    #[test]
    fn defended_set_lists_every_peer_once_and_self_last() {
        let self_v4 = Ipv4Addr::new(100, 64, 0, 28);
        let ips = [
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 4),
            Ipv4Addr::new(100, 64, 0, 9),
        ];
        let mut by_node = HashMap::new();
        for (i, ip) in ips.iter().enumerate() {
            by_node.insert(ObjectId::new(), installed_at([i as u8 + 1; 32], *ip));
        }

        let set = defended_routes(&by_node, self_v4);
        assert_eq!(set.len(), ips.len() + 2);
        assert_eq!(set.last(), Some(&Defend::BlockFloor));
        assert_eq!(
            set.get(set.len() - 2),
            Some(&Defend::EvictSelf(self_v4)),
            "self defended after every peer, before the floor step"
        );
        let asserted: HashSet<Ipv4Addr> = set
            .iter()
            .filter_map(|d| match d {
                Defend::AssertPeer(ip) => Some(*ip),
                Defend::EvictSelf(_) | Defend::BlockFloor => None,
            })
            .collect();
        assert_eq!(asserted, ips.iter().copied().collect::<HashSet<_>>());

        // An empty mesh still defends our own address + the floor.
        assert_eq!(
            defended_routes(&HashMap::new(), self_v4),
            vec![Defend::EvictSelf(self_v4), Defend::BlockFloor]
        );
    }

    /// The off-loop ALLOCATE queue's test twin (see `test_relay_bq`).
    fn test_alloc_q() -> RelayAllocQueue {
        let (tx, _rx) = mpsc::channel(4);
        RelayAllocQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx,
        }
    }

    /// Build an `Installed` for a peer whose carrier details don't matter.
    fn installed_at(pubkey: [u8; 32], overlay_ip: Ipv4Addr) -> Installed {
        Installed::base(pubkey, overlay_ip, DirectTier::Lan, Instant::now())
    }

    /// The full netmap is authoritative: a peer it no longer lists loses its WG
    /// identity, its crypto-route and its OS `/32`. Before the prune, only a
    /// delta `removes` could evict — so a peer that vanished while this client
    /// was disconnected stayed installed (and kept accepting inbound) forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn full_netmap_prune_tears_down_a_vanished_peer() {
        let kp = WgKeypair::generate();
        let gone_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let tun_rec = RouteRecordingTun::new();
        let tf: TunFactory = {
            let m = tun_rec.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let gone_pk = gone_kp.public.to_bytes();
        wg.add_direct_peer(sock.clone(), gone_pk, IP_A, dead, true)
            .await;

        let nid = ObjectId::from_bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::from([(nid, installed_at(gone_pk, IP_A))]);
        let tun: Arc<dyn TunIo> = tun_rec.clone();
        let mut relay: Option<RelayCoordinator> = None;
        let mut relay_bq = test_relay_bq();
        let mut alloc_q = test_alloc_q();
        let mut upgrade_probes: HashMap<ObjectId, UpgradeProbe> = HashMap::new();
        // The peer is NOT in the incoming netmap — i.e. it vanished.
        let mut current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();

        rt.evict_peer(
            nid,
            &mut wg,
            &mut by_node,
            &tun,
            &mut relay,
            &mut relay_bq,
            &mut alloc_q,
            &mut upgrade_probes,
            &mut current_peers,
            &mut relay_refresh,
        )
        .await;

        assert!(!by_node.contains_key(&nid), "the carrier is gone");
        assert!(
            wg.peer_handshake_done(&gone_pk).is_none(),
            "the WG peer (and its inbound acceptance) is gone"
        );
        assert_eq!(
            tun_rec.calls(),
            vec![("del", IP_A)],
            "the OS /32 is dropped — nobody else claims it"
        );
    }

    /// …but a vanished peer whose address was RECYCLED to a live node must not
    /// take that node's OS route with it. This is the blackhole the release
    /// feature would otherwise introduce.
    #[tokio::test(flavor = "multi_thread")]
    async fn prune_keeps_the_os_route_of_a_recycled_overlay_ip() {
        let kp = WgKeypair::generate();
        let stale_kp = WgKeypair::generate();
        let live_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let tun_rec = RouteRecordingTun::new();
        let tf: TunFactory = {
            let m = tun_rec.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let stale_pk = stale_kp.public.to_bytes();
        let live_pk = live_kp.public.to_bytes();
        // Both hold IP_A: the server released it from `stale` and handed it to
        // `live`, and only now do we get around to reaping `stale`.
        wg.add_direct_peer(sock.clone(), stale_pk, IP_A, dead, true)
            .await;
        wg.add_direct_peer(sock.clone(), live_pk, IP_A, dead, true)
            .await;

        let stale_nid = ObjectId::from_bytes([8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let live_nid = ObjectId::from_bytes([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::from([
            (stale_nid, installed_at(stale_pk, IP_A)),
            (live_nid, installed_at(live_pk, IP_A)),
        ]);
        let tun: Arc<dyn TunIo> = tun_rec.clone();
        let mut relay: Option<RelayCoordinator> = None;
        let mut relay_bq = test_relay_bq();
        let mut alloc_q = test_alloc_q();
        let mut upgrade_probes: HashMap<ObjectId, UpgradeProbe> = HashMap::new();
        let mut current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();

        rt.evict_peer(
            stale_nid,
            &mut wg,
            &mut by_node,
            &tun,
            &mut relay,
            &mut relay_bq,
            &mut alloc_q,
            &mut upgrade_probes,
            &mut current_peers,
            &mut relay_refresh,
        )
        .await;

        assert!(by_node.contains_key(&live_nid), "the live peer survives");
        assert!(
            tun_rec.calls().is_empty(),
            "the OS /32 is KEPT — the address now belongs to the live peer, got {:?}",
            tun_rec.calls()
        );
        assert!(
            wg.peer_handshake_done(&live_pk).is_some(),
            "the live peer's WG identity is untouched"
        );
        assert!(
            wg.peer_handshake_done(&stale_pk).is_none(),
            "…and the stale one is gone"
        );
        // The crypto-route still resolves IP_A, and to the LIVE peer.
        assert_eq!(wg.test_route(&IP_A), Some(live_pk));
    }

    /// rc.208 make-before-break test scaffold: a peer currently on RELAY with a
    /// shadow direct PROBE in flight for `dst`. Returns the runtime, the wg
    /// device (probe already started), the `by_node` (relay), and the
    /// `upgrade_probes` metadata — the caller drives `sweep_upgrade_probes`.
    async fn mbb_fixture(
        tier: DirectTier,
        probe_since: Instant,
    ) -> (
        OverlayRuntime,
        WgDevice,
        Arc<dyn TunIo>,
        HashMap<ObjectId, Installed>,
        HashMap<ObjectId, UpgradeProbe>,
        ObjectId,
        [u8; 32],
    ) {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 7);
        let pk = peer_kp.public.to_bytes();
        wg.start_direct_probe(sock, pk, overlay_ip, dead, true)
            .await;

        let nid = ObjectId::from_bytes([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut by_node = HashMap::new();
        // The peer routes over RELAY while the probe runs (make-before-break).
        by_node.insert(
            nid,
            Installed::base(pk, overlay_ip, DirectTier::Relay, Instant::now()),
        );
        let mut upgrade_probes = HashMap::new();
        upgrade_probes.insert(
            nid,
            UpgradeProbe {
                pubkey: pk,
                overlay_ip,
                dst: dead,
                tier,
                since: probe_since,
                initiated: true,
                local: None,
            },
        );
        (rt, wg, tun_mock, by_node, upgrade_probes, nid, pk)
    }

    /// Make-before-break — a probe whose handshake LATCHES (direct proven both
    /// ways) is promoted: `by_node` retags to the direct tier, the shadow probe
    /// leaves the probe map, and the tier's accumulated strikes clear. The relay
    /// was held the entire time (no stall).
    #[tokio::test(flavor = "multi_thread")]
    async fn mbb_promotes_probe_on_handshake_latch() {
        let (rt, mut wg, tun, mut by_node, mut upgrade_probes, nid, pk) =
            mbb_fixture(DirectTier::Srflx, Instant::now()).await;
        assert_eq!(wg.probe_count(), 1);
        // The direct handshake completed (peer's response reached us).
        wg.test_latch_probe_handshake_done(&pk);

        // Stale strikes in the monitor — the latch must clear them (CC1).
        rt.path_shadow.lock().unwrap().mon.on_death(
            &nid,
            DirectTier::Srflx,
            DeathReason::HandshakeDeadline,
            true,
            Instant::now() - Duration::from_secs(3600),
        );
        let mut relay: Option<RelayCoordinator> = None;

        rt.sweep_upgrade_probes(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut upgrade_probes,
            &mut test_relay_bq(),
        )
        .await;

        assert!(upgrade_probes.is_empty(), "the probe settled");
        assert_eq!(wg.probe_count(), 0, "promoted out of the shadow map");
        let inst = by_node.get(&nid).expect("still tracked");
        assert!(inst.is_direct, "cut over to a DIRECT carrier");
        assert_eq!(inst.tier, DirectTier::Srflx);
        assert_eq!(
            inst.public_direct_dst.map(|d| d.to_string()),
            Some("127.0.0.1:9".into()),
            "off-link tier records its exit-exemption dst"
        );
        assert_eq!(
            rt.path_shadow
                .lock()
                .unwrap()
                .mon
                .strikes(&nid, DirectTier::Srflx),
            0,
            "success clears the tier's strikes"
        );
    }

    /// P3 PR-B — the probe's REAL latch latency is measured from the PROBE
    /// START (the runtime's `since`), not the process epoch, and reads `None`
    /// while unlatched. Locks the `handshake_at` plumbing the PathMonitor's
    /// latch Q credit consumes (pre-PR-B the sweep's 5 s tick quantization
    /// made any number worse than none).
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_latency_measures_from_probe_start() {
        let (_rt, wg, _tun, _by_node, _probes, _nid, pk) =
            mbb_fixture(DirectTier::Srflx, Instant::now()).await;
        // De-flake (2026-08-24): `probe_handshake_latency_ms` measures `since`
        // against the process-wide `wg_epoch()`, with a `saturating_duration_since`.
        // A `since` older than that epoch clamps to 0, and the assert then reads
        // "milliseconds since the WG epoch" instead of the probe latency — so the
        // test failed whenever it happened to run inside the first 200 ms of the
        // process, i.e. ALWAYS in isolation (`--lib -- probe_latency…`, where this
        // test is what initializes the epoch) and intermittently in the full suite
        // depending on scheduling. Age the epoch past the back-date first; the
        // fixture above has already touched it.
        tokio::time::sleep(Duration::from_millis(250)).await;
        let since = Instant::now() - Duration::from_millis(200);
        assert_eq!(
            wg.probe_handshake_latency_ms(&pk, since),
            None,
            "unlatched probe has no latency"
        );
        wg.test_latch_probe_handshake_done(&pk);
        let ms = wg.probe_handshake_latency_ms(&pk, since).expect("latched");
        // PR-C — floor at 170, not 200: Windows quantizes Instant deltas to
        // the ~15.6 ms timer resolution, so the 200 ms back-date can measure
        // as low as ~185 (field-flaked on pristine master 2026-07-28).
        assert!(
            (170..10_000).contains(&ms),
            "latency runs from probe start (the back-dated since sets a ~200 ms floor, \
             minus Windows timer quantization), got {ms}"
        );
    }

    /// Make-before-break — a probe that never latches within the tier deadline is
    /// dropped and the RELAY is left untouched (the whole point: no stall on a
    /// peer that can only relay). The failure books ONE strike on the probed
    /// tier (CC1), so a persistently-unreachable tier still escalates.
    #[tokio::test(flavor = "multi_thread")]
    async fn mbb_expires_probe_and_keeps_relay_past_deadline() {
        let stale = Instant::now()
            .checked_sub(Duration::from_secs(SRFLX_HANDSHAKE_DEADLINE.as_secs() + 3))
            .unwrap();
        let (rt, mut wg, tun, mut by_node, mut upgrade_probes, nid, _pk) =
            mbb_fixture(DirectTier::Srflx, stale).await;
        assert_eq!(wg.probe_count(), 1);
        // NOT latched — the direct path never handshook.

        let mut relay: Option<RelayCoordinator> = None;

        rt.sweep_upgrade_probes(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut upgrade_probes,
            &mut test_relay_bq(),
        )
        .await;

        assert!(upgrade_probes.is_empty(), "the probe settled");
        assert_eq!(wg.probe_count(), 0, "the failed probe was dropped");
        let inst = by_node.get(&nid).expect("relay carrier kept");
        assert!(!inst.is_direct, "the RELAY carrier is untouched (no stall)");
        assert_eq!(inst.tier, DirectTier::Relay);
        let s = rt.path_shadow.lock().unwrap();
        assert_eq!(
            s.mon.strikes(&nid, DirectTier::Srflx),
            1,
            "one srflx strike booked"
        );
        assert!(
            !s.mon.eligible(&nid, DirectTier::Srflx, Instant::now()),
            "the srflx suppression penalty is set"
        );
    }

    /// Make-before-break — while a probe is in flight (not yet latched, within
    /// the deadline) the sweep is a no-op: the probe stays, and the peer keeps
    /// routing over its relay carrier.
    #[tokio::test(flavor = "multi_thread")]
    async fn mbb_holds_relay_while_probe_in_flight() {
        let (rt, mut wg, tun, mut by_node, mut upgrade_probes, nid, _pk) =
            mbb_fixture(DirectTier::Srflx, Instant::now()).await;
        let mut relay: Option<RelayCoordinator> = None;

        rt.sweep_upgrade_probes(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut upgrade_probes,
            &mut test_relay_bq(),
        )
        .await;

        assert_eq!(upgrade_probes.len(), 1, "still probing");
        assert_eq!(wg.probe_count(), 1, "the probe is still in flight");
        assert!(
            !by_node.get(&nid).unwrap().is_direct,
            "the relay is still the routing carrier"
        );
        assert_eq!(
            rt.path_shadow
                .lock()
                .unwrap()
                .mon
                .strikes(&nid, DirectTier::Srflx),
            0,
            "no strike while the probe is still pending"
        );
    }

    /// rc.208 make-before-break INBOUND — an authenticated direct init arriving
    /// while the peer is on RELAY is accepted as a SHADOW PROBE (relay held), not
    /// a destructive re-point. With the feature OFF (the default) the same init
    /// tears the relay down and installs direct immediately.
    #[tokio::test(flavor = "multi_thread")]
    async fn mbb_inbound_accepts_init_as_probe_and_holds_relay() {
        let our = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(our.clone(), out_tx, tf, 1280);
        let tun: Arc<dyn TunIo> = tun_mock;

        // A private (LAN) source → tier Lan, no cooldown gating.
        let src: SocketAddr = "192.168.50.9:41000".parse().unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let np = peer(&peer_kp, "100.64.0.7");
        let nid = np.node_id;
        let mut current_peers = HashMap::new();
        current_peers.insert(nid, np);
        let relay_installed = || {
            Installed::base(
                peer_kp.public.to_bytes(),
                Ipv4Addr::new(100, 64, 0, 7),
                DirectTier::Relay,
                Instant::now(),
            )
        };
        let mut relay: Option<RelayCoordinator> = None;

        // Serialize env mutation (the CI overlay-l3 suite runs --test-threads=1).
        let key = "ROOMLERD_OVERLAY_MBB";
        let restore = std::env::var(key).ok();

        // ── MBB ON: accept as a probe, hold the relay ──
        unsafe { std::env::set_var(key, "1") };
        let (mut wg, _rx) = WgDevice::new(our.secret.clone());
        let mut by_node = HashMap::from([(nid, relay_installed())]);
        let mut probes = HashMap::new();
        let inb = crate::overlay::wg::DirectInbound {
            src,
            sock: sock.clone(),
            packet: crate::overlay::wg::test_genuine_init(&peer_kp.secret, our.public.to_bytes()),
        };
        rt.handle_direct_inbound(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &current_peers,
            &mut probes,
            &mut test_relay_bq(),
            inb,
        )
        .await;
        assert_eq!(
            wg.probe_count(),
            1,
            "inbound init accepted as a shadow probe"
        );
        assert!(probes.contains_key(&nid), "the probe is recorded");
        let inst = by_node.get(&nid).expect("still tracked");
        assert!(!inst.is_direct, "the RELAY carrier is HELD, not destroyed");
        assert_eq!(inst.tier, DirectTier::Relay);

        // ── MBB OFF: the same init destructively re-points to direct ──
        unsafe { std::env::set_var(key, "0") };
        let (mut wg2, _rx2) = WgDevice::new(our.secret.clone());
        let mut by_node2 = HashMap::from([(nid, relay_installed())]);
        let mut probes2 = HashMap::new();
        let inb2 = crate::overlay::wg::DirectInbound {
            src,
            sock: sock.clone(),
            packet: crate::overlay::wg::test_genuine_init(&peer_kp.secret, our.public.to_bytes()),
        };
        rt.handle_direct_inbound(
            &mut wg2,
            &mut by_node2,
            &mut relay,
            &tun,
            &current_peers,
            &mut probes2,
            &mut test_relay_bq(),
            inb2,
        )
        .await;
        assert_eq!(wg2.probe_count(), 0, "MBB off → no probe");
        assert!(probes2.is_empty());
        assert!(
            by_node2.get(&nid).expect("tracked").is_direct,
            "MBB off → destructive re-point to a DIRECT carrier (pre-rc.208)"
        );

        match restore {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        };
    }

    /// rc.206 — the silent-zombie backstop. An ESTABLISHED direct carrier whose
    /// inbound packets stop (peer roamed / NAT rebind / path died mid-session)
    /// goes tx-flat AND rx-flat once boringtun gives up re-handshaking, so the
    /// `tx>last_tx && rx==last_rx` heuristic reads it as benign idle and
    /// `punch_dead` can't fire (the handshake already latched). Pre-rc.206 it
    /// lived forever — field-observed as an 8-hour "direct" carrier at 100 %
    /// loss with a frozen last-seen. The absolute `last_rx_at` staleness deadline
    /// tears it down and re-requests via relay.
    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_tears_down_established_carrier_gone_silent() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 2);
        wg.add_direct_peer(
            sock.clone(),
            peer_kp.public.to_bytes(),
            overlay_ip,
            dst,
            true,
        )
        .await;
        // Latch the handshake so this is an ESTABLISHED carrier: `punch_dead`
        // (which fires only PRE-handshake) can't be the reason it's reaped —
        // isolating the rx-staleness trigger.
        wg.test_latch_handshake_done(&peer_kp.public.to_bytes());
        assert_eq!(
            wg.peer_handshake_done(&peer_kp.public.to_bytes()),
            Some(true),
            "precondition: the carrier is established"
        );
        // Pin `last_traffic` to the current snapshot so the tx/rx-delta heuristic
        // takes its else-branch (no strike accrues) — only rx-staleness can be
        // the trigger for this teardown.
        let snap = wg.peer_traffic(&peer_kp.public.to_bytes()).unwrap();

        let nid = ObjectId::from_bytes([6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Installed (and last received) well past the rx-stale deadline — hence
        // also past DIRECT_GRACE.
        let stale = Instant::now()
            .checked_sub(RELAY_RX_STALE_DEADLINE + Duration::from_secs(5))
            .unwrap();
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                last_traffic: snap,
                public_direct_dst: Some(dst),
                ..Installed::base(
                    peer_kp.public.to_bytes(),
                    overlay_ip,
                    DirectTier::Srflx,
                    stale,
                )
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;

        assert!(
            !by_node.contains_key(&nid),
            "the silent established carrier is torn down via rx-staleness"
        );
        assert!(
            !rt.path_shadow
                .lock()
                .unwrap()
                .mon
                .eligible(&nid, DirectTier::Srflx, Instant::now()),
            "the failure books on the carrier's own tier → relay fallback"
        );
    }

    /// rc.206 — the rx-staleness backstop must NOT reap a HEALTHY but IDLE
    /// carrier. A live peer's only inbound on a quiet link is WG persistent-
    /// keepalives, which advance the keepalive-inclusive `rx_any` counter but
    /// NOT the IP-data `rx`. This locks that the sweep refreshes a stale
    /// `last_rx_at` from a keepalive (drained via `peer_take_rx_any`) so the
    /// carrier survives — the false premise the reviewer caught, now a real test
    /// (the earlier version injected a fresh `last_rx_at` keepalives never move).
    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_keeps_established_idle_carrier_heard_via_keepalive() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 2);
        wg.add_direct_peer(
            sock.clone(),
            peer_kp.public.to_bytes(),
            overlay_ip,
            dst,
            true,
        )
        .await;
        wg.test_latch_handshake_done(&peer_kp.public.to_bytes());
        // Simulate a persistent-keepalive landing THIS interval: `rx_any` bumps
        // but the IP-data `rx` does NOT (a keepalive decapsulates to Done). The
        // sweep must read that as "heard" and refresh an otherwise-stale
        // `last_rx_at` — the exact case the pre-rc.206 `rx`-only signal missed.
        wg.test_bump_rx_any(&peer_kp.public.to_bytes());
        let snap = wg.peer_traffic(&peer_kp.public.to_bytes()).unwrap();

        let nid = ObjectId::from_bytes([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // `last_rx_at` last advanced > 90 s ago (looks silent) — but the keepalive
        // above proves the carrier is alive, so the sweep must NOT reap it.
        let old = Instant::now()
            .checked_sub(RELAY_RX_STALE_DEADLINE + Duration::from_secs(5))
            .unwrap();
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                last_traffic: snap,
                public_direct_dst: Some(dst),
                ..Installed::base(
                    peer_kp.public.to_bytes(),
                    overlay_ip,
                    DirectTier::Srflx,
                    old,
                )
            },
        );

        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;

        assert!(
            by_node.contains_key(&nid),
            "an idle carrier heard from via keepalive must survive the sweep"
        );
        assert!(
            by_node.get(&nid).unwrap().last_rx_at > old,
            "the sweep refreshed last_rx_at from the keepalive (rx_any), not rx"
        );
        {
            let s = rt.path_shadow.lock().unwrap();
            assert!(
                s.mon.eligible(&nid, DirectTier::Srflx, Instant::now())
                    && s.mon.strikes(&nid, DirectTier::Srflx) == 0,
                "no failure is booked for a healthy carrier"
            );
        }
    }

    /// #22 — re-init PRESSURE forces an immediate revalidation poke: a peer
    /// hammering handshake initiations at the ~5 s failure cadence against
    /// our ESTABLISHED session can't hear our responses, and rx-silence can
    /// never catch it (the re-inits themselves keep `last_rx_at` fresh — the
    /// 08-18 zombie-leg wedge sat 30 min on exactly that). Below the
    /// threshold nothing arms; at it, the poke arms at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn reinit_pressure_forces_an_immediate_revalidation_poke() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);

        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.ensure_direct_demux(sock.clone());
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 3);
        wg.add_direct_peer(
            sock.clone(),
            peer_kp.public.to_bytes(),
            overlay_ip,
            dst,
            true,
        )
        .await;
        wg.test_latch_handshake_done(&peer_kp.public.to_bytes());
        let snap = wg.peer_traffic(&peer_kp.public.to_bytes()).unwrap();
        let nid = ObjectId::from_bytes([8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let now = Instant::now();
        let mut by_node = HashMap::new();
        by_node.insert(
            nid,
            Installed {
                last_traffic: snap,
                public_direct_dst: Some(dst),
                ..Installed::base(
                    peer_kp.public.to_bytes(),
                    overlay_ip,
                    DirectTier::Srflx,
                    now,
                )
            },
        );
        let tun: Arc<dyn TunIo> = tun_mock;
        let mut relay_refresh: HashMap<ObjectId, Instant> = HashMap::new();
        let mut relay: Option<RelayCoordinator> = None;
        let current_peers: HashMap<ObjectId, NetmapPeer> = HashMap::new();

        // Below the threshold: a couple of inits (an ordinary rekey + a
        // stray retry) must NOT arm a poke on a fresh, healthy carrier.
        wg.test_bump_reinits(&peer_kp.public.to_bytes(), 2);
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;
        assert!(
            by_node.get(&nid).unwrap().poke.is_none(),
            "ordinary rekey cadence must not trigger the pressure poke"
        );

        // Sustained pressure: the retry storm crosses the threshold (the
        // window already holds 2) — the poke arms THIS sweep.
        wg.test_bump_reinits(&peer_kp.public.to_bytes(), 4);
        rt.sweep_carrier_health(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            &mut relay_refresh,
            &current_peers,
            ForcedPoke::No,
        )
        .await;
        assert!(
            by_node.get(&nid).unwrap().poke.is_some(),
            "re-init pressure must force an immediate revalidation poke"
        );
    }

    /// bind-to-interface-by-route (Phase 1): with the gate OFF, `lan_egress_socket`
    /// returns the same-subnet socket unchanged (byte-identical to pre-change).
    /// With the gate ON and a loopback ctx, the connect()-trick resolves the
    /// loopback source, `classify_egress` says `Use`, and the matching socket is
    /// returned — exercising the OS-routed selection path end to end.
    #[tokio::test(flavor = "multi_thread")]
    async fn lan_egress_socket_gate_off_then_on_selects_socket() {
        let n = "ROOMLERD_OVERLAY_BIND_BY_ROUTE";
        let a = "ROOMLERD_OVERLAY_BIND_BY_ROUTE";
        let (rn, ra) = (std::env::var(n).ok(), std::env::var(a).ok());
        let lo = Ipv4Addr::LOCALHOST;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let want = sock.local_addr().unwrap();
        let ctx = DirectCtx {
            socks: vec![(lo, sock)],
            my_ips: vec![lo],
            endpoints: vec![],
            public_sock: None,
            punch: None,
            my_nat: None,
            v6: None,
            my_v6: vec![],
        };
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // Gate OFF → the same-subnet socket, no route query.
        unsafe {
            std::env::remove_var(n);
            std::env::remove_var(a);
        }
        let off = lan_egress_socket(&ctx, lo, dst).await.expect("same-subnet");
        assert_eq!(
            off.local_addr().unwrap(),
            want,
            "gate off → same-subnet pick"
        );

        // Gate ON → connect-trick to a loopback dst sources from 127.0.0.1,
        // which is in our socket set → Use(127.0.0.1) → the same socket.
        unsafe { std::env::set_var(n, "1") };
        let on = lan_egress_socket(&ctx, lo, dst)
            .await
            .expect("os-routed socket");
        assert_eq!(on.local_addr().unwrap(), want, "gate on → OS-routed socket");

        unsafe {
            match rn {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
            match ra {
                Some(v) => std::env::set_var(a, v),
                None => std::env::remove_var(a),
            }
        }
    }

    /// rc.204 — the same-subnet LAN tier must scan ONLY the provenance-pure
    /// `lan_endpoints` bucket. The `endpoints` union also carries the peer's
    /// trickled coturn-RELAYED addresses, and on this fleet the coturn workers
    /// ride the hosts' own public IPs — pre-rc.204 a fleet host same-/24
    /// matched a peer's *relay allocation* and "LAN"-dialed coturn forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn lan_tier_scans_only_the_pure_lan_endpoint_bucket() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let tun: Arc<dyn TunIo> = tun_mock;

        // Our side: one "interface" at 10.1.2.9 (the socket itself is bound to
        // loopback — nothing needs to actually flow in this test).
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let my_ip: Ipv4Addr = "10.1.2.9".parse().unwrap();
        let ctx = DirectCtx {
            socks: vec![(my_ip, sock)],
            my_ips: vec![my_ip],
            endpoints: vec!["10.1.2.9:41000".into()],
            public_sock: None,
            punch: None,
            my_nat: None,
            v6: None,
            my_v6: vec![],
        };
        let mut relay: Option<RelayCoordinator> = None;
        let mut by_node = HashMap::new();

        // A same-/24 address present ONLY in the `endpoints` union (the shape
        // of a trickled relay allocation) must NOT produce a LAN carrier.
        let mut tainted = peer(&peer_kp, "100.64.0.7");
        tainted.endpoints = vec!["10.1.2.3:1000".into()];
        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&tainted),
            Some(&ctx),
            &mut HashMap::new(),
            &mut test_relay_bq(),
            "test",
        )
        .await;
        assert!(
            by_node.is_empty(),
            "an endpoints-union (relay-tainted) address must not become a LAN carrier"
        );

        // The SAME address in the pure `lan_endpoints` bucket → LAN carrier.
        let mut lan_peer = peer(&peer_kp, "100.64.0.7");
        lan_peer.node_id = tainted.node_id;
        lan_peer.lan_endpoints = vec!["10.1.2.3:1000".into()];
        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&lan_peer),
            Some(&ctx),
            &mut HashMap::new(),
            &mut test_relay_bq(),
            "test",
        )
        .await;
        let inst = by_node
            .get(&lan_peer.node_id)
            .expect("the pure-bucket LAN candidate installs a LAN carrier");
        assert_eq!(inst.tier, DirectTier::Lan);
        assert!(inst.is_direct);
    }

    /// P9 — a FRESH peer with a same-/24 candidate must NOT install the
    /// unproven LAN carrier destructively when a fallback tier exists: a
    /// false-subnet match (vendor-default /24s collide across sites) otherwise
    /// burns the whole LAN handshake deadline with NO carrier at all, on every
    /// retry (field 2026-07-28). The LAN candidate becomes a shadow PROBE and
    /// the working carrier comes from the fallback walk (here: srflx) in the
    /// SAME pass. The airgap case (nothing else dialable, `relay = None`) in
    /// `lan_tier_scans_only_the_pure_lan_endpoint_bucket` keeps the
    /// destructive install.
    #[tokio::test(flavor = "multi_thread")]
    async fn fresh_lan_probes_first_when_fallback_exists() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let tun: Arc<dyn TunIo> = tun_mock;

        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let punch_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let my_ip: Ipv4Addr = "10.1.2.9".parse().unwrap();
        let ctx = DirectCtx {
            socks: vec![(my_ip, sock)],
            my_ips: vec![my_ip],
            endpoints: vec!["10.1.2.9:41000".into()],
            public_sock: None,
            punch: Some(("93.184.216.90:5555".into(), punch_sock)),
            my_nat: None,
            v6: None,
            my_v6: vec![],
        };
        let mut relay: Option<RelayCoordinator> = None;
        let mut by_node = HashMap::new();
        let mut upgrade_probes = HashMap::new();

        // Same-/24 LAN candidate (possibly a false match) + a srflx fallback.
        let mut p = peer(&peer_kp, "100.64.0.7");
        p.lan_endpoints = vec!["10.1.2.3:1000".into()];
        p.srflx_endpoints = vec!["93.184.216.34:4444".into()];
        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&p),
            Some(&ctx),
            &mut upgrade_probes,
            &mut test_relay_bq(),
            "test",
        )
        .await;

        let probe = upgrade_probes
            .get(&p.node_id)
            .expect("the LAN candidate is a shadow probe, not the carrier");
        assert_eq!(probe.tier, DirectTier::Lan);
        assert_eq!(probe.dst.to_string(), "10.1.2.3:1000");
        assert_eq!(wg.probe_count(), 1, "one shadow probe in flight");
        let inst = by_node
            .get(&p.node_id)
            .expect("the working carrier comes from the fallback walk");
        assert_eq!(
            inst.tier,
            DirectTier::Srflx,
            "srflx fallback carries while the LAN probe runs"
        );
        assert!(inst.is_direct);

        // A second pass with the probe in flight must not duplicate it.
        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&p),
            Some(&ctx),
            &mut upgrade_probes,
            &mut test_relay_bq(),
            "test",
        )
        .await;
        assert_eq!(wg.probe_count(), 1, "no duplicate probe on re-entry");
    }

    /// P9 — a peer the server marked `reachable = false` (ghost enrollment /
    /// stale heartbeat / clean leave) is never dialed: no carrier install, no
    /// shadow probe, no relay request — even with perfectly dialable
    /// candidates on the row.
    #[tokio::test(flavor = "multi_thread")]
    async fn unreachable_peer_is_never_dialed() {
        let kp = WgKeypair::generate();
        let peer_kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let (tun_mock, _inj, _del) = MockTun::new();
        let tf: TunFactory = {
            let m = tun_mock.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let tun: Arc<dyn TunIo> = tun_mock;

        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let my_ip: Ipv4Addr = "10.1.2.9".parse().unwrap();
        let ctx = DirectCtx {
            socks: vec![(my_ip, sock)],
            my_ips: vec![my_ip],
            endpoints: vec!["10.1.2.9:41000".into()],
            public_sock: None,
            punch: None,
            my_nat: None,
            v6: None,
            my_v6: vec![],
        };
        let mut relay: Option<RelayCoordinator> = None;
        let mut by_node = HashMap::new();
        let mut upgrade_probes = HashMap::new();

        let mut p = peer(&peer_kp, "100.64.0.9");
        p.lan_endpoints = vec!["10.1.2.3:1000".into()];
        p.reachable = false;
        rt.install_peers(
            &mut wg,
            &mut by_node,
            &mut relay,
            &tun,
            std::slice::from_ref(&p),
            Some(&ctx),
            &mut upgrade_probes,
            &mut test_relay_bq(),
            "test",
        )
        .await;

        assert!(by_node.is_empty(), "no carrier for an unreachable peer");
        assert!(upgrade_probes.is_empty(), "no shadow probe either");
        assert_eq!(wg.probe_count(), 0);
    }

    /// Minimal STUN Binding Success carrying an XOR-MAPPED-ADDRESS (IPv4), so a
    /// keepalive test needs no real STUN server (RFC 5389 §15.2).
    fn stun_success(txn: [u8; 12], ip: [u8; 4], port: u16) -> Vec<u8> {
        const COOKIE: u32 = 0x2112_A442;
        let cookie = COOKIE.to_be_bytes();
        let xport = port ^ ((COOKIE >> 16) as u16);
        let mut r = Vec::new();
        r.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
        r.extend_from_slice(&12u16.to_be_bytes()); // one 12-byte attribute
        r.extend_from_slice(&cookie);
        r.extend_from_slice(&txn);
        r.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        r.extend_from_slice(&8u16.to_be_bytes());
        r.push(0);
        r.push(0x01); // family IPv4
        r.extend_from_slice(&xport.to_be_bytes());
        r.extend_from_slice(&[
            ip[0] ^ cookie[0],
            ip[1] ^ cookie[1],
            ip[2] ^ cookie[2],
            ip[3] ^ cookie[3],
        ]);
        r
    }

    /// Phase C (D5) — the srflx keepalive re-advertises EXACTLY when the punch
    /// mapping changes, and never on a query returning the same mapping. A demux
    /// emulator feeds STUN replies into the sink as the real demux loop would.
    #[tokio::test(flavor = "multi_thread")]
    async fn srflx_keepalive_retrickles_only_on_mapping_change() {
        let punch = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let (sink_tx, sink_rx) = mpsc::channel::<crate::transport::stun::StunInbound>(16);

        // Reply to the FIRST query with the initial advert (no change), and to
        // every later query with a CHANGED mapping.
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let mut seen = 0u32;
            loop {
                let Ok((_n, _from)) = server.recv_from(&mut buf).await else {
                    break;
                };
                let txn: [u8; 12] = buf[8..20].try_into().unwrap();
                let port = if seen == 0 { 1111 } else { 2222 };
                seen += 1;
                let _ = sink_tx
                    .send(crate::transport::stun::StunInbound {
                        src: server_addr,
                        packet: stun_success(txn, [203, 0, 113, 7], port),
                    })
                    .await;
            }
        });

        let (out_tx, mut out_rx) = mpsc::channel::<ClientMsg>(16);
        let advertised = vec!["203.0.113.7:1111".to_string()];
        let (_reattach_tx, reattach_rx) = tokio::sync::watch::channel(0u64);
        let task = tokio::spawn(run_srflx_keepalive(
            punch,
            sink_rx,
            server_addr,
            vec![],
            vec![], // own_ips (co-located-worker exclusion — none in this test)
            advertised,
            Some("cone".into()),
            out_tx.into(),
            Duration::from_millis(60),
            reattach_rx,
            crate::overlay::portmap::Source::Off,
            None,
        ));

        // First tick: mapping == advert → NO trickle. Second tick: changed to
        // :2222 → exactly one trickle with the new punch candidate at [0].
        let msg = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .expect("expected a re-trickle")
            .expect("channel closed");
        match msg {
            ClientMsg::OverlaySrflx {
                candidates, nat, ..
            } => {
                assert_eq!(candidates, vec!["203.0.113.7:2222".to_string()]);
                // The NAT type rides every re-trickle (mapping changed, class
                // didn't) so the server never clears it.
                assert_eq!(nat.as_deref(), Some("cone"));
            }
            other => panic!("expected OverlaySrflx, got {other:?}"),
        }
        // No further trickle while the mapping stays :2222.
        assert!(
            tokio::time::timeout(Duration::from_millis(400), out_rx.recv())
                .await
                .is_err(),
            "must not re-trickle when the mapping is unchanged"
        );
        task.abort();
    }

    /// §6 item 5 — a gateway that grants a mapping makes the keepalive
    /// re-advertise with that mapping FIRST and the NAT as `cone` (a
    /// symmetric peer can reach a mapped port), keeping the STUN candidate
    /// after it; the runtime's exit ends the task (which releases it).
    #[tokio::test(flavor = "multi_thread")]
    async fn srflx_keepalive_advertises_a_gateway_mapping_first() {
        let punch = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (_sink_tx, sink_rx) = mpsc::channel::<crate::transport::stun::StunInbound>(1);
        let (out_tx, mut out_rx) = mpsc::channel::<ClientMsg>(4);
        let (reattach_tx, reattach_rx) = tokio::sync::watch::channel(0u64);
        let external = std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 41641);
        let gw = crate::overlay::portmap::fake_pcp_gateway(external).await;
        let task = tokio::spawn(run_srflx_keepalive(
            punch,
            sink_rx,
            "127.0.0.1:9".parse().unwrap(),
            vec![],
            vec![],
            vec!["203.0.113.7:1111".to_string()],
            Some("symmetric".into()),
            out_tx.into(),
            Duration::from_secs(60),
            reattach_rx,
            crate::overlay::portmap::Source::At(gw, b"node-secret".to_vec()),
            None,
        ));
        let msg = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .expect("expected an advert with the mapping")
            .expect("channel closed");
        match msg {
            ClientMsg::OverlaySrflx { candidates, nat, .. } => {
                assert_eq!(
                    candidates,
                    vec![external.to_string(), "203.0.113.7:1111".to_string()]
                );
                assert_eq!(nat.as_deref(), Some("cone"));
            }
            other => panic!("expected OverlaySrflx, got {other:?}"),
        }
        drop(reattach_tx);
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("the runtime's exit ends the keepalive")
            .unwrap();
    }

    /// Phase C (D5) — a STUN outage must NOT strip a working advert: with no
    /// reply arriving, the keepalive retains the last-known srflx (no trickle).
    #[tokio::test(flavor = "multi_thread")]
    async fn srflx_keepalive_retains_advert_on_outage() {
        let punch = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // Hold the sender so the channel stays open; never feed it (outage).
        let (_sink_tx, sink_rx) = mpsc::channel::<crate::transport::stun::StunInbound>(1);
        let (out_tx, mut out_rx) = mpsc::channel::<ClientMsg>(4);
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (_reattach_tx, reattach_rx) = tokio::sync::watch::channel(0u64);
        let task = tokio::spawn(run_srflx_keepalive(
            punch,
            sink_rx,
            dead,
            vec![],
            vec![], // own_ips
            vec!["203.0.113.7:1111".to_string()],
            Some("cone".into()),
            out_tx.into(),
            Duration::from_millis(30),
            reattach_rx,
            crate::overlay::portmap::Source::Off,
            None,
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(500), out_rx.recv())
                .await
                .is_err(),
            "a STUN outage must not produce a re-trickle"
        );
        task.abort();
    }

    /// rc.307 (B) — the keepalive OUTLIVES control-WS sessions: a send
    /// failure while detached must NOT kill the task or lose a mapping
    /// change, and a reattach signal must restore the task's CURRENT
    /// (evolving) advert on the fresh session — the re-join's server-side
    /// rehydrate wiped it.
    #[tokio::test(flavor = "multi_thread")]
    async fn srflx_keepalive_survives_detach_and_restores_on_reattach() {
        let punch = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let (sink_tx, sink_rx) = mpsc::channel::<crate::transport::stun::StunInbound>(16);
        // Every query maps to :2222 — a CHANGE from the initial :1111 advert.
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((_n, _from)) = server.recv_from(&mut buf).await else {
                    break;
                };
                let txn: [u8; 12] = buf[8..20].try_into().unwrap();
                let _ = sink_tx
                    .send(crate::transport::stun::StunInbound {
                        src: server_addr,
                        packet: stun_success(txn, [203, 0, 113, 7], 2222),
                    })
                    .await;
            }
        });

        // Detached from the start: the receiver is dropped immediately.
        let (dead_tx, dead_rx) = mpsc::channel::<ClientMsg>(4);
        drop(dead_rx);
        let ctl = ControlTx::new(dead_tx);
        let (reattach_tx, reattach_rx) = tokio::sync::watch::channel(0u64);
        let task = tokio::spawn(run_srflx_keepalive(
            punch,
            sink_rx,
            server_addr,
            vec![],
            vec![],
            vec!["203.0.113.7:1111".to_string()],
            Some("cone".into()),
            ctl.clone(),
            Duration::from_millis(40),
            reattach_rx,
            crate::overlay::portmap::Source::Off,
            None,
        ));

        // Give it a few ticks: the mapping change lands, its send fails
        // (detached), and — the pre-B bug — the task must NOT exit.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !task.is_finished(),
            "detached send failure must not kill the keepalive"
        );

        // Reattach: swap in a live session and signal. The task must push its
        // CURRENT advert (:2222 — the evolved one, not the startup snapshot).
        let (live_tx, mut live_rx) = mpsc::channel::<ClientMsg>(4);
        ctl.swap(live_tx);
        reattach_tx.send_modify(|n| *n += 1);
        let msg = tokio::time::timeout(Duration::from_secs(3), live_rx.recv())
            .await
            .expect("expected the advert restore after reattach")
            .expect("channel closed");
        match msg {
            ClientMsg::OverlaySrflx {
                candidates, nat, ..
            } => {
                assert_eq!(candidates, vec!["203.0.113.7:2222".to_string()]);
                assert_eq!(nat.as_deref(), Some("cone"));
            }
            other => panic!("expected OverlaySrflx, got {other:?}"),
        }
        task.abort();
    }

    #[test]
    fn overlay_view_classifies_connection_types_and_sorts() {
        // Locks the LocalAPI connection-type mapping (the Tailscale-style
        // per-device "how am I reaching it" column): installed-direct → Direct,
        // installed-relay → Relay, reachable-but-no-carrier → Blocked,
        // not-reachable → Offline. And the peer list is node_id-sorted so a
        // LocalAPI reader doesn't see it jitter.
        fn oid(b: u8) -> ObjectId {
            ObjectId::from_bytes([b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        }
        fn np(id: ObjectId, name: &str, ip: &str, reachable: bool) -> NetmapPeer {
            NetmapPeer {
                node_id: id,
                overlay_ip: ip.into(),
                name: name.into(),
                wg_public_key: String::new(),
                endpoints: vec![],
                lan_endpoints: vec![],
                srflx_endpoints: vec![],
                srflx_nat: None,
                udp_dialer_ok: None,
                relay_home: None,
                warm_relay_endpoint: None,
                reachable,
                supports_quic: false,
                supports_relay_single: false,
                supports_derp: false,
                supports_forced_derp: false,
                supports_derp_floor: false,
                caps: None,
                supports_overlay_echo: false,
                supports_org_relay: false,
                relay_strategy: None,
                routes: vec![],
                agent_id: None,
                ingress_rules: None,
            }
        }
        fn installed(
            is_direct: bool,
            ip: Ipv4Addr,
            last_rx_at: Instant,
            relay: Option<(std::net::SocketAddr, std::net::SocketAddr)>,
        ) -> Installed {
            Installed {
                last_rx_at,
                relay_local: relay.map(|(l, _)| l),
                relay_dst: relay.map(|(_, d)| d),
                ..Installed::base(
                    [0u8; 32],
                    ip,
                    if is_direct {
                        DirectTier::Lan
                    } else {
                        DirectTier::Relay
                    },
                    Instant::now(),
                )
            }
        }

        // Fixed clock basis so the epoch-ms conversion is deterministic. Both
        // the peers' `last_rx_at` and the view's `now` derive from this `now`.
        let now = Instant::now();
        let epoch_now_ms: u64 = 1_000_000_000_000;
        let (d, r, b, o) = (oid(0x01), oid(0x02), oid(0x03), oid(0x04));
        let mut by_node = HashMap::new();
        // Direct peer last received a packet 10 s ago; relay peer just now.
        by_node.insert(
            d,
            installed(
                true,
                Ipv4Addr::new(100, 64, 0, 1),
                now.checked_sub(std::time::Duration::from_secs(10)).unwrap(),
                None,
            ),
        );
        by_node.insert(
            r,
            installed(
                false,
                Ipv4Addr::new(100, 64, 0, 2),
                now,
                Some((
                    "94.130.141.74:10850".parse().unwrap(),
                    "5.9.157.226:12728".parse().unwrap(),
                )),
            ),
        );

        let mut current = HashMap::new();
        current.insert(d, np(d, "direct-peer", "100.64.0.1", true));
        current.insert(r, np(r, "relay-peer", "100.64.0.2", true));
        current.insert(b, np(b, "pending-peer", "100.64.0.3", true)); // no carrier
        current.insert(o, np(o, "offline-peer", "100.64.0.4", false));

        // P8-cosmetics — an in-flight MBB probe marks the RELAY peer (and only
        // it) as `upgrading`; a probe entry for the DIRECT peer is ignored
        // (the marker is a relay-tier transition signal).
        let mut probes: HashMap<ObjectId, UpgradeProbe> = HashMap::new();
        let dummy_probe = || UpgradeProbe {
            pubkey: [0u8; 32],
            overlay_ip: Ipv4Addr::new(100, 64, 0, 2),
            dst: "192.168.68.1:51820".parse().unwrap(),
            tier: DirectTier::Lan,
            since: now,
            initiated: true,
            local: None,
        };
        probes.insert(r, dummy_probe());
        probes.insert(d, dummy_probe());

        let view = build_overlay_view(
            "100.64.0.9",
            &by_node,
            &current,
            &probes,
            now,
            epoch_now_ms,
            &Default::default(),
        );
        assert_eq!(view.self_ip.as_deref(), Some("100.64.0.9"));
        assert_eq!(view.peers.len(), 4);
        assert!(
            view.peers[1].upgrading,
            "relay peer with a probe ⇒ upgrading"
        );
        assert!(
            !view.peers[0].upgrading,
            "direct peer never shows upgrading"
        );
        assert!(!view.peers[2].upgrading && !view.peers[3].upgrading);
        // Sorted by node_id hex → 01,02,03,04.
        assert_eq!(view.peers[0].connection, ConnectionType::Direct);
        assert_eq!(view.peers[0].name, "direct-peer");
        assert_eq!(view.peers[0].overlay_ip.as_deref(), Some("100.64.0.1"));
        assert!(view.peers[0].online);
        assert_eq!(view.peers[1].connection, ConnectionType::Relay);
        assert_eq!(view.peers[2].connection, ConnectionType::Blocked);
        assert!(
            view.peers[2].online,
            "blocked peer is still server-reachable"
        );
        assert_eq!(view.peers[3].connection, ConnectionType::Offline);
        assert!(!view.peers[3].online);
        // RTT isn't tracked by the runtime (the daemon's prober fills it).
        assert!(view.peers[0].rtt_ms.is_none());
        // last_seen_ms is absolute epoch-ms of the last inbound packet: the
        // direct peer 10 s ago, the relay peer ~now; carrier-less peers None.
        assert_eq!(view.peers[0].last_seen_ms, Some(epoch_now_ms - 10_000));
        assert_eq!(view.peers[1].last_seen_ms, Some(epoch_now_ms));
        assert!(view.peers[2].last_seen_ms.is_none());
        assert!(view.peers[3].last_seen_ms.is_none());
        // rc.187 — relay endpoints surface only for the relay peer (local=buildhost,
        // dst=fleet-host-2 ⇒ the cross-worker signal an operator reads from `peers`);
        // direct + carrier-less peers carry none.
        assert_eq!(
            view.peers[1].relay_local.as_deref(),
            Some("94.130.141.74:10850")
        );
        assert_eq!(
            view.peers[1].relay_dst.as_deref(),
            Some("5.9.157.226:12728")
        );
        assert!(view.peers[0].relay_local.is_none() && view.peers[0].relay_dst.is_none());
        assert!(view.peers[2].relay_dst.is_none());
        assert!(view.peers[3].relay_dst.is_none());
        // rc.276 — the carrier debug snapshot: present for installed peers
        // (tier + rx-age mapped through), absent for carrier-less ones.
        let d0 = view.peers[0].debug.as_ref().expect("direct peer has debug");
        assert_eq!(d0.tier, "lan");
        assert_eq!(d0.last_rx_age_s, 10);
        assert!(!d0.initiated && !d0.hs_done, "fixture defaults map through");
        assert!(d0.relay_kind.is_none());
        let d1 = view.peers[1].debug.as_ref().expect("relay peer has debug");
        assert_eq!(d1.tier, "relay");
        assert_eq!(d1.last_rx_age_s, 0);
        assert!(view.peers[2].debug.is_none() && view.peers[3].debug.is_none());
    }

    pub(super) struct MockTun {
        inject: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        delivered: mpsc::UnboundedSender<Vec<u8>>,
    }
    impl MockTun {
        pub(super) fn new() -> (
            Arc<Self>,
            mpsc::UnboundedSender<Vec<u8>>,
            mpsc::UnboundedReceiver<Vec<u8>>,
        ) {
            let (i_tx, i_rx) = mpsc::unbounded_channel();
            let (d_tx, d_rx) = mpsc::unbounded_channel();
            (
                Arc::new(Self {
                    inject: Mutex::new(i_rx),
                    delivered: d_tx,
                }),
                i_tx,
                d_rx,
            )
        }
    }
    #[async_trait]
    impl TunIo for MockTun {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            self.inject
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::other("mock inject closed"))
        }
        async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.delivered
                .send(packet.to_vec())
                .map_err(|_| io::Error::other("mock delivered closed"))
        }
    }

    /// A factory that always hands back a fixed loopback carrier (one
    /// peer per node in the test).
    struct LoopbackLinks {
        sock: Arc<UdpSocket>,
        dst: SocketAddr,
    }
    #[async_trait]
    impl LinkFactory for LoopbackLinks {
        async fn build_carrier(&self, _peer: &PeerConfig) -> Option<Arc<Carrier>> {
            Some(Carrier::direct(self.sock.clone(), self.dst))
        }
    }

    pub(super) fn synthetic_ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
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

    pub(super) fn net() -> OverlayNetworkInfo {
        OverlayNetworkInfo {
            org_relay_fallback_v1: false,
            cidr: "100.64.0.0/10".into(),
            cidrs: vec![],
            mtu: 1280,
            magic_domain: None,
            nameservers: vec![],
            self_name: None,
            stun_urls: vec![],
        }
    }
    pub(super) fn peer(kp: &WgKeypair, ip: &str) -> NetmapPeer {
        NetmapPeer {
            node_id: ObjectId::new(),
            overlay_ip: ip.into(),
            name: String::new(),
            wg_public_key: kp.public_base64(),
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            caps: None,
            supports_overlay_echo: false,
            supports_org_relay: false,
            relay_strategy: None,
            routes: vec![],
            agent_id: None,
            ingress_rules: None,
        }
    }

    const IP_A: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const IP_B: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_installs_peer_from_netmap_and_round_trips() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();

        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (out_a, mut out_a_rx) = mpsc::channel::<ClientMsg>(16);
        let (out_b, mut out_b_rx) = mpsc::channel::<ClientMsg>(16);
        let (evt_a, evt_a_rx) = mpsc::channel::<OverlayEvent>(16);
        let (evt_b, evt_b_rx) = mpsc::channel::<OverlayEvent>(16);

        let (mock_a, inject_a, _del_a) = MockTun::new();
        let (mock_b, _inj_b, mut del_b) = MockTun::new();
        let tf_a: TunFactory = {
            let m = mock_a.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let tf_b: TunFactory = {
            let m = mock_b.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };

        let rt_a = OverlayRuntime::new(
            a.clone(),
            out_a,
            Arc::new(LoopbackLinks {
                sock: sock_a,
                dst: addr_b,
            }),
            tf_a,
            1280,
        );
        let rt_b = OverlayRuntime::new(
            b.clone(),
            out_b,
            Arc::new(LoopbackLinks {
                sock: sock_b,
                dst: addr_a,
            }),
            tf_b,
            1280,
        );
        tokio::spawn(rt_a.run(evt_a_rx, vec![]));
        tokio::spawn(rt_b.run(evt_b_rx, vec![]));

        // Both runtimes announce themselves first.
        assert!(matches!(
            out_a_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));
        assert!(matches!(
            out_b_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));

        // Server pushes each its netmap (the other node as the one peer).
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.1".into(),
                network: net(),
                peers: vec![peer(&b, "100.64.0.2")],
            })
            .await
            .unwrap();
        evt_b
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.2".into(),
                network: net(),
                peers: vec![peer(&a, "100.64.0.1")],
            })
            .await
            .unwrap();

        // App on A sends to B's overlay IP; assert it arrives on B's TUN.
        // Re-inject (best-effort send drops until the WG session is up).
        let pkt = synthetic_ipv4(IP_A, IP_B, b"runtime-loopback");
        for _ in 0..100 {
            let _ = inject_a.send(pkt.clone());
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(150), del_b.recv()).await
            {
                assert_eq!(got, pkt, "packet must traverse the overlay runtime intact");
                return;
            }
        }
        panic!("packet did not traverse the runtime in time");
    }

    /// rc.307 (B) — the reattach flow end to end: a runtime whose control-WS
    /// died gets a `Reattach` from the next session, re-JOINS on the new
    /// sender, reconciles the re-join's full netmap against LIVE state
    /// (`install_peers` leaves the installed carrier alone), and the data
    /// plane keeps working across the whole exchange. Then the authoritative
    /// prune: a re-join netmap that no longer lists the peer tears it down.
    #[tokio::test(flavor = "multi_thread")]
    async fn reattach_rejoins_reconciles_and_then_prunes() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();

        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (out_a, mut out_a_rx) = mpsc::channel::<ClientMsg>(16);
        let (out_b, mut out_b_rx) = mpsc::channel::<ClientMsg>(16);
        let (evt_a, evt_a_rx) = mpsc::channel::<OverlayEvent>(16);
        let (evt_b, evt_b_rx) = mpsc::channel::<OverlayEvent>(16);

        let (mock_a, inject_a, _del_a) = MockTun::new();
        let (mock_b, _inj_b, mut del_b) = MockTun::new();
        let tf_a: TunFactory = {
            let m = mock_a.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let tf_b: TunFactory = {
            let m = mock_b.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };

        let rt_a = OverlayRuntime::new(
            a.clone(),
            out_a,
            Arc::new(LoopbackLinks {
                sock: sock_a,
                dst: addr_b,
            }),
            tf_a,
            1280,
        );
        let rt_b = OverlayRuntime::new(
            b.clone(),
            out_b,
            Arc::new(LoopbackLinks {
                sock: sock_b,
                dst: addr_a,
            }),
            tf_b,
            1280,
        );
        tokio::spawn(rt_a.run(evt_a_rx, vec![]));
        tokio::spawn(rt_b.run(evt_b_rx, vec![]));
        assert!(matches!(
            out_a_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));
        assert!(matches!(
            out_b_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));

        let peer_b = peer(&b, "100.64.0.2");
        let peer_a = peer(&a, "100.64.0.1");
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.1".into(),
                network: net(),
                peers: vec![peer_b.clone()],
            })
            .await
            .unwrap();
        evt_b
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.2".into(),
                network: net(),
                peers: vec![peer_a.clone()],
            })
            .await
            .unwrap();

        // Bring the pair up.
        let pkt = synthetic_ipv4(IP_A, IP_B, b"pre-reattach");
        let mut up = false;
        for _ in 0..100 {
            let _ = inject_a.send(pkt.clone());
            if tokio::time::timeout(Duration::from_millis(150), del_b.recv())
                .await
                .ok()
                .flatten()
                .is_some()
            {
                up = true;
                break;
            }
        }
        assert!(up, "pair did not come up");

        // The session dies (old outbound receiver dropped) and a NEW session
        // reattaches. The runtime must re-join on the NEW sender…
        drop(out_a_rx);
        let (out_a2, mut out_a2_rx) = mpsc::channel::<ClientMsg>(16);
        evt_a
            .send(OverlayEvent::Reattach { outbound: out_a2 })
            .await
            .unwrap();
        let rejoin = tokio::time::timeout(Duration::from_secs(3), out_a2_rx.recv())
            .await
            .expect("expected the re-join on the fresh session")
            .expect("new session channel closed");
        assert!(
            matches!(rejoin, ClientMsg::OverlayJoin { .. }),
            "first message after reattach must be the re-join, got {rejoin:?}"
        );

        // …and the re-join's full netmap (same peer) reconciles WITHOUT
        // touching the carrier: traffic keeps flowing.
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.1".into(),
                network: net(),
                peers: vec![peer_b.clone()],
            })
            .await
            .unwrap();
        let pkt2 = synthetic_ipv4(IP_A, IP_B, b"post-reattach");
        let mut alive = false;
        for _ in 0..100 {
            let _ = inject_a.send(pkt2.clone());
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(150), del_b.recv()).await
                && got == pkt2
            {
                alive = true;
                break;
            }
        }
        assert!(alive, "carrier must survive reattach + reconcile");

        // Authoritative prune: a re-join netmap WITHOUT the peer tears it
        // down — injected packets stop arriving.
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.1".into(),
                network: net(),
                peers: vec![],
            })
            .await
            .unwrap();
        // Let the prune land, then drain anything already in flight.
        tokio::time::sleep(Duration::from_millis(200)).await;
        while tokio::time::timeout(Duration::from_millis(100), del_b.recv())
            .await
            .ok()
            .flatten()
            .is_some()
        {}
        for _ in 0..5 {
            let _ = inject_a.send(pkt2.clone());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(400), del_b.recv())
                .await
                .ok()
                .flatten()
                .is_none(),
            "pruned peer must stop receiving traffic"
        );
    }

    /// rc.307 (B) — a re-join that comes back with a DIFFERENT identity
    /// (re-enroll / tenant renumber while detached) cannot be reconciled in
    /// place: the runtime exits so the agent-side slot spawns a fresh one.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejoin_with_different_self_ip_exits_runtime() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_b: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (out_a, mut out_a_rx) = mpsc::channel::<ClientMsg>(16);
        let (evt_a, evt_a_rx) = mpsc::channel::<OverlayEvent>(16);
        let (mock_a, _inj_a, _del_a) = MockTun::new();
        let tf_a: TunFactory = {
            let m = mock_a.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt_a = OverlayRuntime::new(
            a.clone(),
            out_a,
            Arc::new(LoopbackLinks {
                sock: sock_a,
                dst: addr_b,
            }),
            tf_a,
            1280,
        );
        let handle = tokio::spawn(rt_a.run(evt_a_rx, vec![]));
        assert!(matches!(
            out_a_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.1".into(),
                network: net(),
                peers: vec![peer(&b, "100.64.0.2")],
            })
            .await
            .unwrap();
        // Give it a beat to enter the steady-state loop, then re-join with a
        // different identity.
        tokio::time::sleep(Duration::from_millis(100)).await;
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.9".into(),
                network: net(),
                peers: vec![],
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("runtime must exit on a self_ip change")
            .expect("runtime task panicked");
    }

    /// P1 (S6) — the permanent RE-COUPLING TRIPWIRE. A fat control arm (a
    /// 2 s Netmap handler, via [`TEST_NETMAP_STALL_MS`]) must not delay
    /// outbound packets: the data plane runs on the dedicated pump, off the
    /// select! loop. Pre-P1 this fails by construction — the outbound arm
    /// shared the loop, so every packet injected during the stall queued for
    /// its full duration (one >2 s inter-arrival gap at the receiver);
    /// post-P1 the MAX GAP stays bounded. (A delivered-count assertion can't
    /// discriminate: the mpsc buffers the burst either way — the gap is the
    /// signal.)
    #[tokio::test(flavor = "multi_thread")]
    async fn control_stall_does_not_delay_outbound() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();

        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (out_a, mut out_a_rx) = mpsc::channel::<ClientMsg>(16);
        let (out_b, mut out_b_rx) = mpsc::channel::<ClientMsg>(16);
        let (evt_a, evt_a_rx) = mpsc::channel::<OverlayEvent>(16);
        let (evt_b, evt_b_rx) = mpsc::channel::<OverlayEvent>(16);

        let (mock_a, inject_a, _del_a) = MockTun::new();
        let (mock_b, _inj_b, mut del_b) = MockTun::new();
        let tf_a: TunFactory = {
            let m = mock_a.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let tf_b: TunFactory = {
            let m = mock_b.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };

        let rt_a = OverlayRuntime::new(
            a.clone(),
            out_a,
            Arc::new(LoopbackLinks {
                sock: sock_a,
                dst: addr_b,
            }),
            tf_a,
            1280,
        );
        let rt_b = OverlayRuntime::new(
            b.clone(),
            out_b,
            Arc::new(LoopbackLinks {
                sock: sock_b,
                dst: addr_a,
            }),
            tf_b,
            1280,
        );
        tokio::spawn(rt_a.run(evt_a_rx, vec![]));
        tokio::spawn(rt_b.run(evt_b_rx, vec![]));
        assert!(matches!(
            out_a_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));
        assert!(matches!(
            out_b_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));

        let netmap_a = OverlayEvent::Netmap {
            org_relay_discovery: false,
            path_trial_v1: false,
            self_ip: "100.64.0.1".into(),
            network: net(),
            peers: vec![peer(&b, "100.64.0.2")],
        };
        evt_a.send(netmap_a).await.unwrap();
        evt_b
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.2".into(),
                network: net(),
                peers: vec![peer(&a, "100.64.0.1")],
            })
            .await
            .unwrap();

        // Establish the session (first round-trip), then drain any handshake-
        // era straggler deliveries so the measurement starts clean.
        let pkt = synthetic_ipv4(IP_A, IP_B, b"stall-probe");
        let mut established = false;
        for _ in 0..100 {
            let _ = inject_a.send(pkt.clone());
            if tokio::time::timeout(Duration::from_millis(150), del_b.recv())
                .await
                .ok()
                .flatten()
                .is_some()
            {
                established = true;
                break;
            }
        }
        assert!(established, "session did not establish in time");
        while tokio::time::timeout(Duration::from_millis(300), del_b.recv())
            .await
            .ok()
            .flatten()
            .is_some()
        {}

        // Arm the 2 s stall and hand A a DUPLICATE netmap (same peer ⇒ the
        // already-installed carrier is kept — the arm just sits busy).
        TEST_NETMAP_STALL_MS.store(2000, std::sync::atomic::Ordering::Relaxed);
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.1".into(),
                network: net(),
                peers: vec![peer(&b, "100.64.0.2")],
            })
            .await
            .unwrap();
        // Let the loop pick the netmap arm up before measuring.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Collect delivery instants at B while injecting 40 packets at 50 ms
        // across the stall window.
        let collector = tokio::spawn(async move {
            let mut arrivals: Vec<Instant> = Vec::new();
            while arrivals.len() < 40 {
                match tokio::time::timeout(Duration::from_secs(1), del_b.recv()).await {
                    Ok(Some(_)) => arrivals.push(Instant::now()),
                    _ => break,
                }
            }
            arrivals
        });
        for _ in 0..40 {
            let _ = inject_a.send(pkt.clone());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let arrivals = collector.await.unwrap();
        TEST_NETMAP_STALL_MS.store(0, std::sync::atomic::Ordering::Relaxed);

        assert!(
            arrivals.len() >= 35,
            "expected ≥35/40 deliveries over an established loopback session, got {}",
            arrivals.len()
        );
        let max_gap = arrivals
            .windows(2)
            .map(|w| w[1].duration_since(w[0]))
            .max()
            .unwrap_or_default();
        assert!(
            max_gap < Duration::from_millis(500),
            "outbound delayed by a control-arm stall: max inter-arrival gap {max_gap:?} \
             (pre-P1 the 2 s Netmap stall produces a >2 s gap here)"
        );
    }

    /// P1 (S6) — pump death is session-fatal, never respawned: when the TUN
    /// dies (inject sender dropped ⇒ `read_packet` errors ⇒ reader exits ⇒
    /// the pump's channel closes ⇒ the pump ends), the runtime loop must
    /// exit — same disposition the pre-P1 outbound arm had on reader death.
    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_exits_when_outbound_pump_dies() {
        let a = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = sock_a.local_addr().unwrap();

        let (out_a, mut out_a_rx) = mpsc::channel::<ClientMsg>(16);
        let (evt_a, evt_a_rx) = mpsc::channel::<OverlayEvent>(16);
        let (mock_a, inject_a, _del_a) = MockTun::new();
        let tf_a: TunFactory = {
            let m = mock_a.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let rt_a = OverlayRuntime::new(
            a.clone(),
            out_a,
            Arc::new(LoopbackLinks { sock: sock_a, dst }),
            tf_a,
            1280,
        );
        let run = tokio::spawn(rt_a.run(evt_a_rx, vec![]));
        assert!(matches!(
            out_a_rx.recv().await,
            Some(ClientMsg::OverlayJoin { .. })
        ));
        // Reach steady state (TUN up, reader + pump spawned).
        evt_a
            .send(OverlayEvent::Netmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                self_ip: "100.64.0.1".into(),
                network: net(),
                peers: vec![],
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Kill the TUN: reader errors out → pump ends → loop breaks.
        drop(inject_a);
        tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .expect("runtime must exit once the outbound pump dies")
            .unwrap();
    }

    // ---- P5 exit-node pure helpers ----

    fn exit_oid(b: u8) -> ObjectId {
        ObjectId::from_bytes([b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    fn exit_np(id: ObjectId, name: &str, routes: Vec<String>) -> NetmapPeer {
        NetmapPeer {
            node_id: id,
            overlay_ip: "100.64.0.1".into(),
            name: name.into(),
            wg_public_key: String::new(),
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            caps: None,
            supports_overlay_echo: false,
            supports_org_relay: false,
            relay_strategy: None,
            routes,
            agent_id: None,
            ingress_rules: None,
        }
    }

    #[test]
    fn resolve_exit_peer_matches_name_or_hex() {
        let a = exit_oid(0x0a);
        let b = exit_oid(0x0b);
        let mut peers = HashMap::new();
        peers.insert(a, exit_np(a, "fleet-host-1", vec![]));
        peers.insert(b, exit_np(b, "fleet-host-2", vec![]));
        // By name.
        assert_eq!(resolve_exit_peer("fleet-host-1", &peers), Some(a));
        assert_eq!(resolve_exit_peer("fleet-host-2", &peers), Some(b));
        // By node-id hex.
        assert_eq!(resolve_exit_peer(&a.to_hex(), &peers), Some(a));
        // Surrounding whitespace is tolerated.
        assert_eq!(resolve_exit_peer("  fleet-host-1  ", &peers), Some(a));
        // Unknown selector → None (reconcile defers rather than blackholing).
        assert_eq!(resolve_exit_peer("buildhost", &peers), None);
    }

    /// Names are recycled between machines now, so a NAME selector that starts
    /// resolving elsewhere must not silently move this host's whole egress. A
    /// hex selector can't drift and a first resolution isn't drift.
    #[test]
    fn exit_selector_drifted_only_fires_for_a_name_that_moved() {
        let a = exit_oid(0x31);
        let b = exit_oid(0x32);
        assert!(
            !exit_selector_drifted(None, "fleet-host-1", a),
            "first resolution is not drift"
        );
        assert!(
            !exit_selector_drifted(Some(a), "fleet-host-1", a),
            "same machine is not drift"
        );
        assert!(
            exit_selector_drifted(Some(a), "fleet-host-1", b),
            "the name moved to another machine"
        );
        assert!(
            !exit_selector_drifted(Some(a), &b.to_hex(), b),
            "a hex selector is unambiguous — never drift"
        );
    }

    #[test]
    fn peer_is_approved_exit_detects_default_route() {
        // An admin-approved exit node carries 0.0.0.0/0 in its netmap routes.
        assert!(peer_is_approved_exit(&exit_np(
            exit_oid(1),
            "x",
            vec!["0.0.0.0/0".into()]
        )));
        // Exit node that is ALSO a subnet router.
        assert!(peer_is_approved_exit(&exit_np(
            exit_oid(1),
            "x",
            vec!["192.168.1.0/24".into(), "0.0.0.0/0".into()]
        )));
        // A plain subnet router is NOT an exit node.
        assert!(!peer_is_approved_exit(&exit_np(
            exit_oid(1),
            "x",
            vec!["192.168.1.0/24".into()]
        )));
        assert!(!peer_is_approved_exit(&exit_np(exit_oid(1), "x", vec![])));
    }

    #[test]
    fn exit_exemption_set_unions_server_and_relay_workers() {
        fn inst(is_direct: bool, relay: Option<(SocketAddr, SocketAddr)>) -> Installed {
            Installed {
                relay_local: relay.map(|(l, _)| l),
                relay_dst: relay.map(|(_, d)| d),
                ..Installed::base(
                    [0u8; 32],
                    Ipv4Addr::new(100, 64, 0, 1),
                    if is_direct {
                        DirectTier::Lan
                    } else {
                        DirectTier::Relay
                    },
                    Instant::now(),
                )
            }
        }
        // Server A + AAAA (S3b — the v6 AAAA rides the set too; reconcile
        // partitions by family, and the v6 exemption keeps the WS-over-v6 direct).
        let server: Vec<IpAddr> = vec![
            "94.130.141.98".parse().unwrap(),
            "94.130.141.99".parse().unwrap(),
            "2a01:4f8:c17:b8f::2".parse().unwrap(),
        ];
        let mut by_node = HashMap::new();
        // A relay carrier → BOTH its coturn worker IPs are exempted.
        by_node.insert(
            exit_oid(1),
            inst(
                false,
                Some((
                    "94.130.141.74:10850".parse().unwrap(),
                    "5.9.157.226:12728".parse().unwrap(),
                )),
            ),
        );
        // A direct carrier → contributes NO exemption (same-subnet / on-link).
        by_node.insert(exit_oid(2), inst(true, None));

        let set = exit_exemption_set(&server, &by_node);
        assert!(set.contains(&"94.130.141.98".parse::<IpAddr>().unwrap()));
        assert!(set.contains(&"94.130.141.99".parse::<IpAddr>().unwrap()));
        assert!(set.contains(&"2a01:4f8:c17:b8f::2".parse::<IpAddr>().unwrap())); // AAAA
        assert!(set.contains(&"94.130.141.74".parse::<IpAddr>().unwrap())); // relay_local
        assert!(set.contains(&"5.9.157.226".parse::<IpAddr>().unwrap())); // relay_dst
        // Exactly the 3 server (2×A + 1×AAAA) + 2 relay IPs; direct added nothing.
        assert_eq!(set.len(), 5);
    }

    /// Phase A never-self-wedge: a PUBLIC-DIRECT carrier's peer IP MUST be
    /// exempted (it's a real internet dst reached via the default route, unlike
    /// an on-link LAN peer), or the split-default `/1`s would swallow the path
    /// to the very exit that carries egress.
    #[test]
    fn exit_exemption_set_includes_public_direct_dst() {
        let pd: std::net::SocketAddr = "5.9.157.226:41234".parse().unwrap();
        let mut by_node = HashMap::new();
        by_node.insert(
            exit_oid(9),
            Installed {
                public_direct_dst: Some(pd),
                ..Installed::base(
                    [1u8; 32],
                    Ipv4Addr::new(100, 64, 0, 9),
                    DirectTier::Public,
                    Instant::now(),
                )
            },
        );
        let set = exit_exemption_set(&[], &by_node);
        assert!(
            set.contains(&pd.ip()),
            "a public-direct peer IP must be exempted from the split-default"
        );
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn exit_peer_allowed_ips_preserves_real_subnets_and_appends_split_default() {
        let kp = WgKeypair::generate();
        let exit = NetmapPeer {
            node_id: exit_oid(7),
            overlay_ip: "100.64.0.7".into(),
            name: "fleet-host-1".into(),
            wg_public_key: kp.public_base64(),
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            caps: None,
            supports_overlay_echo: false,
            supports_org_relay: false,
            relay_strategy: None,
            routes: vec!["192.168.5.0/24".into(), "0.0.0.0/0".into()],
            agent_id: None,
            ingress_rules: None,
        };
        let strs: Vec<String> = exit_peer_allowed_ips(&exit)
            .iter()
            .map(|c| c.to_string())
            .collect();
        // Real subnet preserved; both /1 halves appended; the bare /0 dropped.
        assert!(strs.contains(&"192.168.5.0/24".to_string()));
        assert!(strs.contains(&"0.0.0.0/1".to_string()));
        assert!(strs.contains(&"128.0.0.0/1".to_string()));
        assert!(!strs.contains(&"0.0.0.0/0".to_string()));
        assert_eq!(strs.len(), 3);
    }

    /// FR-97 — the field black-hole, in the crypto-router: the exit
    /// reconcile sets the split-default as the exit peer's allowed-IPs once,
    /// then a re-install of that peer runs the generic `install_subnets`,
    /// which REPLACES them with its real subnets. The reconcile must see the
    /// `/1`s gone (and re-assert them), or every v4 packet the OS routes into
    /// the TUN finds no peer while the state still says "installed".
    #[test]
    fn a_reinstall_that_drops_the_exit_split_default_is_seen() {
        use crate::overlay::router::{Cidr, Router};
        let exit = [7u8; 32];
        let real = vec![Cidr::parse("192.168.5.0/24").unwrap()];
        let mut allowed = real.clone();
        allowed.extend(SPLIT_DEFAULT_V4.iter().map(|c| Cidr::parse(c).unwrap()));
        let mut r = Router::new();
        r.set_subnets(exit, &allowed);
        assert!(!split_default_missing(&r.subnets_of(&exit)));
        // The generic peer install: its real subnets, the /0 filtered out.
        r.set_subnets(exit, &real);
        assert!(
            split_default_missing(&r.subnets_of(&exit)),
            "a re-install that replaced the allowed-IPs must read as missing"
        );
        // Half of it is no better than none.
        r.set_subnets(exit, &[allowed[0], allowed[1]]);
        assert!(split_default_missing(&r.subnets_of(&exit)));
        // Re-asserted: whole again; another peer's routes never count.
        r.set_subnets(exit, &allowed);
        assert!(!split_default_missing(&r.subnets_of(&exit)));
        assert!(split_default_missing(&r.subnets_of(&[8u8; 32])));
    }

    #[test]
    fn exit_readiness_reports_distinct_split_tunnel_reasons() {
        let id = exit_oid(0x21);
        let no_carriers: HashMap<ObjectId, Installed> = HashMap::new();

        // Not in the mesh at all.
        let empty: HashMap<ObjectId, NetmapPeer> = HashMap::new();
        assert_eq!(
            exit_readiness("fleet-host-1", &empty, &no_carriers).unwrap_err(),
            "exit node not visible in the mesh yet"
        );

        // Present, but not an admin-approved exit node (no /0 in its routes).
        let mut subnet_only = HashMap::new();
        subnet_only.insert(
            id,
            exit_np(id, "fleet-host-1", vec!["192.168.1.0/24".into()]),
        );
        assert_eq!(
            exit_readiness("fleet-host-1", &subnet_only, &no_carriers).unwrap_err(),
            "not an admin-approved exit node (no 0.0.0.0/0 approved)"
        );

        // Approved, but no live carrier yet.
        let mut approved = HashMap::new();
        approved.insert(id, exit_np(id, "fleet-host-1", vec!["0.0.0.0/0".into()]));
        assert_eq!(
            exit_readiness("fleet-host-1", &approved, &no_carriers).unwrap_err(),
            "exit node has no live carrier yet"
        );

        // Approved + carriered → ready, yields the peer's pubkey.
        let mut carriered = HashMap::new();
        carriered.insert(
            id,
            Installed::base(
                [7u8; 32],
                Ipv4Addr::new(100, 64, 0, 1),
                DirectTier::Lan,
                Instant::now(),
            ),
        );
        let (rid, _np, pk) = exit_readiness("fleet-host-1", &approved, &carriered).unwrap();
        assert_eq!(rid, id);
        assert_eq!(pk, [7u8; 32]);
    }

    #[test]
    fn exit_node_status_reflects_active_and_withheld() {
        let mut st = ExitRoutingState::default();
        // Not configured (no selector) → no status at all.
        assert!(exit_node_status(None, &st).is_none());
        // Configured + withheld surfaces the reason.
        st.withheld_reason = Some("exit node has no live carrier yet".into());
        let w = exit_node_status(Some("fleet-host-1"), &st).unwrap();
        assert_eq!(w.selector, "fleet-host-1");
        assert!(!w.active);
        assert_eq!(
            w.withheld_reason.as_deref(),
            Some("exit node has no live carrier yet")
        );
        // Withheld → v6 is never "on".
        assert!(!w.v6_active);
        // Active but v6 undecided/fail-closed → active, v6 off.
        st.split_default_installed = true;
        let a = exit_node_status(Some("fleet-host-1"), &st).unwrap();
        assert!(a.active);
        assert!(a.withheld_reason.is_none());
        assert!(!a.v6_active);
        // Active AND v6 enabled → both on.
        st.v6_active = Some(true);
        let a6 = exit_node_status(Some("fleet-host-1"), &st).unwrap();
        assert!(a6.active && a6.v6_active);
        // Active but v6 fail-closed → v4 on, v6 off.
        st.v6_active = Some(false);
        assert!(
            !exit_node_status(Some("fleet-host-1"), &st)
                .unwrap()
                .v6_active
        );
        // S4b — DNS steered surfaces only while active.
        st.dns_steered = true;
        let d = exit_node_status(Some("fleet-host-1"), &st).unwrap();
        assert!(d.active && d.dns_steered);
        // Not active → dns_steered is never reported true (masked like v6).
        st.split_default_installed = false;
        assert!(
            !exit_node_status(Some("fleet-host-1"), &st)
                .unwrap()
                .dns_steered
        );
    }

    /// FR-97 P0c-3 — measured 2026-10-17 on a netstack exit client: its SOCKS5
    /// front carried IPv4 literals through the exit (a SYN from its overlay
    /// address on the exit's TUN, one new MASQUERADE flow) and refused IPv6
    /// destinations, while `roomler status` said "active, v6 on" for the whole
    /// host. The status now carries the front, never IPv6 through it.
    #[test]
    fn a_netstack_exit_reports_its_socks_front_and_never_v6() {
        let mut st = ExitRoutingState {
            split_default_installed: true,
            v6_active: Some(true),
            ..Default::default()
        };
        let os_tun = exit_node_status(Some("exit"), &st).unwrap();
        assert!(os_tun.active && os_tun.v6_active);
        assert_eq!(os_tun.socks5_port, None);
        st.socks5_port = Some(1080);
        let ns = exit_node_status(Some("exit"), &st).unwrap();
        assert!(ns.active, "the front's IPv4 dials do ride the exit");
        assert!(
            !ns.v6_active,
            "the front refuses every non-overlay IPv6 destination"
        );
        assert_eq!(ns.socks5_port, Some(1080));
    }

    /// FR-97 P0c-3 — the DNS steer is host-wide on Windows (an NRPT catch-all)
    /// and macOS (a resolver entry). From a netstack node, whose OS routes
    /// nothing through the exit, it would only move every app to the public
    /// upstream over the uplink, and cut a managed laptop off from its own
    /// names. Locked here so the gate cannot drift from the reconcile.
    #[test]
    fn a_netstack_node_never_steers_the_hosts_dns() {
        let mut st = ExitRoutingState {
            split_default_installed: true,
            dns_target: Some(Ipv4Addr::new(1, 1, 1, 1)),
            ..Default::default()
        };
        assert!(
            dns_steer_allowed(&st),
            "MagicDNS off, an OS TUN: the steer runs"
        );
        st.socks5_port = Some(1080);
        assert!(!dns_steer_allowed(&st));
        // The pre-existing gates still hold for an OS TUN.
        st.socks5_port = None;
        st.dns_magic_domain = Some("org.example".into());
        assert!(
            !dns_steer_allowed(&st),
            "MagicDNS on needs a live local resolver"
        );
        st.dns_bound = true;
        assert!(dns_steer_allowed(&st));
        st.dns_steered = true;
        assert!(!dns_steer_allowed(&st), "once is enough");
        st.dns_steered = false;
        st.split_default_installed = false;
        assert!(!dns_steer_allowed(&st), "never without the split-default");
    }

    // ---- FR-97 P1a — pins that stop holding, and the cause they report ----

    #[test]
    fn a_pin_failure_is_news_once_per_cause() {
        let mut st = ExitRoutingState::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(note_exemption_failure(&mut st, ip, "no IPv4 default route"));
        assert!(
            !note_exemption_failure(&mut st, ip, "no IPv4 default route"),
            "the same cause again is not news: the gate retries every few seconds"
        );
        assert!(
            note_exemption_failure(&mut st, ip, "route refused the pin"),
            "a new cause is"
        );
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        assert!(
            note_exemption_failure(&mut st, other, "route refused the pin"),
            "and it is per endpoint"
        );
        // It pinned, which clears it, so failing again later is news again.
        st.exemption_failures.remove(&ip);
        assert!(note_exemption_failure(&mut st, ip, "route refused the pin"));
    }

    #[test]
    fn the_withheld_reason_names_the_lowest_missing_v4_cause() {
        let mut st = ExitRoutingState::default();
        let a: IpAddr = "198.51.100.9".parse().unwrap();
        let b: IpAddr = "203.0.113.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        let want: HashSet<IpAddr> = [a, b, v6].into_iter().collect();
        st.exemption_failures.insert(a, "cause a".into());
        st.exemption_failures.insert(b, "cause b".into());
        st.exemption_failures.insert(v6, "cause v6".into());
        assert_eq!(
            exemption_withheld_reason(&want, &st),
            "carrier-endpoint exemption for 198.51.100.9 unavailable: cause a"
        );
        // Once that one pins, the next is named. v6 never decides the v4 gate.
        st.exemptions.insert(a);
        assert_eq!(
            exemption_withheld_reason(&want, &st),
            "carrier-endpoint exemption for 203.0.113.7 unavailable: cause b"
        );
        st.exemption_failures.clear();
        assert_eq!(
            exemption_withheld_reason(&want, &st),
            "carrier-endpoint exemption for 203.0.113.7 unavailable",
            "no recorded cause still names the endpoint"
        );
    }

    #[test]
    fn the_pin_recheck_is_bounded() {
        let t0 = Instant::now();
        assert!(exemption_recheck_due(None, t0), "never checked: due");
        assert!(!exemption_recheck_due(Some(t0), t0));
        assert!(!exemption_recheck_due(
            Some(t0),
            t0 + EXEMPTION_RECHECK_EVERY - Duration::from_millis(1)
        ));
        assert!(exemption_recheck_due(
            Some(t0),
            t0 + EXEMPTION_RECHECK_EVERY
        ));
    }

    /// A device for the exit gate: pins succeed or fail on demand, the device
    /// names the pins it scripts as stale, and every route call is recorded.
    struct ExemptionTun {
        pin_ok: std::sync::atomic::AtomicBool,
        stale: std::sync::Mutex<Vec<IpAddr>>,
        calls: std::sync::Mutex<Vec<String>>,
    }
    impl ExemptionTun {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                pin_ok: std::sync::atomic::AtomicBool::new(true),
                stale: std::sync::Mutex::new(Vec::new()),
                calls: std::sync::Mutex::new(Vec::new()),
            })
        }
        fn log(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }
        fn take_calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }
    #[async_trait]
    impl TunIo for ExemptionTun {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
        async fn write_packet(&self, _packet: &[u8]) -> io::Result<()> {
            Ok(())
        }
        async fn add_cidr_route(&self, cidr: &str) -> io::Result<()> {
            self.log(format!("add {cidr}"));
            Ok(())
        }
        async fn del_cidr_route(&self, cidr: &str) {
            self.log(format!("del {cidr}"));
        }
        async fn add_host_exemption(&self, ip: IpAddr) -> io::Result<()> {
            self.log(format!("pin {ip}"));
            if self.pin_ok.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(())
            } else {
                Err(io::Error::other(
                    "no IPv4 default route through a gateway to pin it on",
                ))
            }
        }
        async fn del_host_exemption(&self, ip: IpAddr) {
            self.log(format!("unpin {ip}"));
        }
        async fn stale_host_exemptions(&self, pinned: &[IpAddr]) -> Vec<IpAddr> {
            self.log(format!("recheck {}", pinned.len()));
            std::mem::take(&mut *self.stale.lock().unwrap())
        }
    }

    /// FR-97 — the field black-hole, end to end. The reconcile installs the
    /// exit; then the exit peer is re-installed the way a carrier rebuild or
    /// a netmap update does it (the generic `install_subnets`, which logs
    /// "dropped advertised default route(s)" and REPLACES the peer's
    /// allowed-IPs). The next reconcile must put the split-default back into
    /// the crypto-router: it did not, and every v4 packet the OS routed into
    /// the TUN found no peer until a restart (tart Mac exit clients, twice).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reinstalled_exit_peer_gets_its_split_default_back() {
        use crate::overlay::router::Cidr;
        let kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let tun = ExemptionTun::new();
        let tf: TunFactory = {
            let m = tun.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let id = exit_oid(0x32);
        let server: IpAddr = "203.0.113.7".parse().unwrap();
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280)
            .with_exit_node(Some(id.to_hex()), vec![server]);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let dev: Arc<dyn TunIo> = tun.clone();
        let pk = [7u8; 32];
        let mut peers = HashMap::new();
        peers.insert(id, exit_np(id, "exit-a", vec!["0.0.0.0/0".into()]));
        let mut by_node = HashMap::new();
        by_node.insert(
            id,
            Installed::base(
                pk,
                Ipv4Addr::new(100, 64, 0, 1),
                DirectTier::Lan,
                Instant::now(),
            ),
        );
        let mut st = ExitRoutingState::default();

        rt.reconcile_exit_routing(&mut wg, &dev, &by_node, &peers, &mut st)
            .await;
        assert!(st.split_default_installed);
        assert!(!split_default_missing(&wg.peer_subnets(&pk)), "installed");

        // The re-install, as the runtime runs it for this peer.
        rt.install_subnets(&mut wg, &dev, id, pk, &[Cidr::parse("0.0.0.0/0").unwrap()])
            .await;
        assert!(
            split_default_missing(&wg.peer_subnets(&pk)),
            "the field state: the re-install replaced the allowed-IPs"
        );
        assert!(st.split_default_installed, "…while the state still says in");

        rt.reconcile_exit_routing(&mut wg, &dev, &by_node, &peers, &mut st)
            .await;
        assert!(
            !split_default_missing(&wg.peer_subnets(&pk)),
            "the next reconcile must put the split-default back: {:?}",
            wg.peer_subnets(&pk)
        );
        assert!(st.split_default_installed);
    }

    /// FR-97 P1a — the uplink moves under an active exit (Wi-Fi ↔ Ethernet).
    /// A pin that stops holding is re-pinned through the new uplink with the
    /// `/1`s left in place; one that cannot be re-pinned is DELETED before it
    /// is forgotten, and the exit is withheld with the device's own cause. A
    /// forgotten host route on a dead next hop black-holes the endpoint it
    /// was pinned for, and no later teardown would ever remove it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pin_that_stops_holding_is_repinned_or_removed_never_forgotten() {
        let kp = WgKeypair::generate();
        let (out_tx, _out_rx) = mpsc::channel::<ClientMsg>(16);
        let tun = ExemptionTun::new();
        let tf: TunFactory = {
            let m = tun.clone();
            Box::new(move |_, _, _| Ok(m.clone() as Arc<dyn TunIo>))
        };
        let id = exit_oid(0x31);
        let server: IpAddr = "203.0.113.7".parse().unwrap();
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280)
            .with_exit_node(Some(id.to_hex()), vec![server]);
        let (mut wg, _tun_rx) = WgDevice::new(kp.secret.clone());
        let dev: Arc<dyn TunIo> = tun.clone();
        let mut peers = HashMap::new();
        peers.insert(id, exit_np(id, "exit-a", vec!["0.0.0.0/0".into()]));
        let mut by_node = HashMap::new();
        by_node.insert(
            id,
            Installed::base(
                [7u8; 32],
                Ipv4Addr::new(100, 64, 0, 1),
                DirectTier::Lan,
                Instant::now(),
            ),
        );
        let mut st = ExitRoutingState::default();

        rt.reconcile_exit_routing(&mut wg, &dev, &by_node, &peers, &mut st)
            .await;
        assert!(st.split_default_installed && st.exemptions.contains(&server));
        assert_eq!(
            tun.take_calls().first().map(String::as_str),
            Some("pin 203.0.113.7"),
            "pinned BEFORE the /1s"
        );

        // The uplink moved and the new one takes the pin: re-pinned in place,
        // nothing torn down.
        *tun.stale.lock().unwrap() = vec![server];
        rt.reconcile_exit_routing(&mut wg, &dev, &by_node, &peers, &mut st)
            .await;
        assert_eq!(tun.take_calls(), ["recheck 1", "pin 203.0.113.7"]);
        assert!(st.split_default_installed && st.exemptions.contains(&server));

        // A carrier event right after does not re-check again.
        rt.reconcile_exit_routing(&mut wg, &dev, &by_node, &peers, &mut st)
            .await;
        assert!(tun.take_calls().is_empty(), "the re-check is bounded");

        // It moves again, and this time the pin cannot follow.
        st.exemptions_checked_at = None;
        tun.pin_ok.store(false, std::sync::atomic::Ordering::SeqCst);
        *tun.stale.lock().unwrap() = vec![server];
        rt.reconcile_exit_routing(&mut wg, &dev, &by_node, &peers, &mut st)
            .await;
        let calls = tun.take_calls();
        let unpin = calls
            .iter()
            .position(|c| c == "unpin 203.0.113.7")
            .unwrap_or_else(|| panic!("a pin that cannot follow is deleted: {calls:?}"));
        assert!(
            calls[..unpin].iter().any(|c| c == "pin 203.0.113.7"),
            "after the re-pin was tried: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == "del 0.0.0.0/1"),
            "and the /1s come out: {calls:?}"
        );
        assert!(!st.split_default_installed);
        assert!(st.exemptions.is_empty());
        assert_eq!(
            st.withheld_reason.as_deref(),
            Some(
                "carrier-endpoint exemption for 203.0.113.7 unavailable: \
                 no IPv4 default route through a gateway to pin it on"
            ),
            "the status names the device's cause"
        );
    }

    #[test]
    fn org_relay_join_advertises_multi_candidate_parser_capability() {
        let (out, _) = mpsc::channel(1);
        let tf: TunFactory = Box::new(|_, _, _| panic!("join test must not create TUN"));
        let rt = OverlayRuntime::new_relay(WgKeypair::generate(), out, tf, 1280);
        assert!(matches!(
            rt.make_join(vec![]),
            ClientMsg::OverlayJoin {
                supports_org_relay_multi_candidate: true,
                ..
            }
        ));
    }

    #[test]
    fn relay_listener_readiness_controls_join_and_rejoin_port() {
        let (out, _) = mpsc::channel(1);
        let tf: TunFactory = Box::new(|_, _, _| panic!("join test must not create TUN"));
        let rt = OverlayRuntime::new_relay(WgKeypair::generate(), out, tf, 1280);
        let port = |msg| match msg {
            ClientMsg::OverlayJoin { relay_port, .. } => relay_port,
            _ => panic!("expected join"),
        };
        assert_eq!(port(rt.make_join(vec![])), None);
        let (tx, rx) = watch::channel(None);
        let rt = rt.with_relay_listener_readiness(rx);
        assert_eq!(port(rt.make_join(vec![])), None);
        tx.send_replace(Some(43210));
        assert_eq!(port(rt.make_join(vec![])), Some(43210));
        tx.send_replace(None);
        assert_eq!(port(rt.make_join(vec![])), None);
        tx.send_replace(Some(43210));
        drop(tx);
        assert_eq!(
            port(rt.make_join(vec![])),
            None,
            "closed publisher is not a live listener"
        );
    }

    /// Controlled completion at the SAME convergence function used by org_rx:
    /// a bind starts, then direct recovers, then the old completion arrives.
    /// No WAN or global environment is used.
    #[tokio::test]
    async fn org_bind_completion_never_replaces_recovered_direct() {
        let kp = WgKeypair::generate();
        let nid = ObjectId::new();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let peers = HashMap::from([(nid, test_netmap_peer(nid, ip, &kp))]);
        let (tx, _rx) = mpsc::channel(8);
        let mut relay = RelayCoordinator::new(tx, [0; 32], true, vec![], None);
        let (done, mut q, conn) = pending_org_test_bind(&mut relay, nid, &peers[&nid], 7, 1).await;
        let (mut wg, _wg_rx) = WgDevice::new(WgKeypair::generate().secret);
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        wg.add_peer(
            kp.public.to_bytes(),
            ip,
            Carrier::direct(sock, "127.0.0.1:9".parse().unwrap()),
            false,
        );
        wg.test_latch_handshake_done(&kp.public.to_bytes());
        let direct = Installed::base(kp.public.to_bytes(), ip, DirectTier::Lan, Instant::now());
        let by_node = HashMap::from([(nid, direct)]);
        assert!(
            !org_bind_needed(true, by_node.get(&nid)),
            "stale tracking cannot demote direct"
        );
        assert!(commit_current_org_bind(done, &mut q, &peers, &by_node, &mut relay).is_none());
        assert!(by_node[&nid].is_direct);
        assert_eq!(by_node[&nid].pubkey, kp.public.to_bytes());
        assert_eq!(wg.peer_count(), 1);
        assert_eq!(
            wg.peer_handshake_done(&kp.public.to_bytes()),
            Some(true),
            "the installed direct WG session survives the late completion"
        );
        wg.remove_peer(&kp.public.to_bytes()).await;
        assert!(!conn.is_alive(), "unused bound relay socket is closed");
        assert!(!relay.is_tracking(&nid), "no stuck in-flight bookkeeping");
    }

    pub(super) async fn pending_org_test_bind(
        relay: &mut RelayCoordinator,
        nid: ObjectId,
        peer: &NetmapPeer,
        vni: u32,
        generation: u64,
    ) -> (
        OrgBindDone,
        OrgBindQueue,
        Arc<super::super::orgrelay::client::OrgRelayConn>,
    ) {
        use super::super::orgrelay::{bind::BindSecret, client::OrgRelayConn, member::OrgSession};
        let pc = peer_config_from_netmap(peer).unwrap();
        relay.org_session_accept(
            nid,
            OrgSession {
                vni,
                generation,
                relay_node_id: ObjectId::new(),
                endpoints: vec!["127.0.0.1:9".parse().unwrap()],
                secret: BindSecret::from_bytes([7; 32]),
                bind_budget: Duration::from_secs(3),
                expires_at: Instant::now() + Duration::from_secs(60),
                conn: None,
            },
        );
        relay.org_request_bind(nid, pc);
        let job = relay.take_org_jobs().pop().unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let mut q = OrgBindQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx,
        };
        let epoch = q.stamp(nid);
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let conn = Arc::new(OrgRelayConn::new(
            sock,
            job.endpoints[0],
            vni,
            "fixture".into(),
        ));
        let done = OrgBindDone {
            epoch,
            generation,
            peer_public_key: job.peer_public_key,
            peer_overlay_ip: job.peer_overlay_ip,
            node_id: nid,
            relay_node_id: job.relay_node_id,
            conn: Some(conn.clone()),
            outcomes: vec![],
        };
        (done, q, conn)
    }

    #[tokio::test]
    async fn org_bind_completion_drops_removed_rekeyed_and_readded_peers() {
        let kp = WgKeypair::generate();
        let nid = ObjectId::new();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let peer = test_netmap_peer(nid, ip, &kp);
        for case in ["removed", "rekeyed", "remove-readd"] {
            let (tx, _rx) = mpsc::channel(8);
            let mut relay = Some(RelayCoordinator::new(tx, [0; 32], true, vec![], None));
            let (done, mut q, conn) =
                pending_org_test_bind(relay.as_mut().unwrap(), nid, &peer, 7, 1).await;
            let mut peers = HashMap::from([(nid, peer.clone())]);
            if case == "removed" {
                peers.remove(&nid);
            }
            if case == "rekeyed" {
                peers.insert(nid, test_netmap_peer(nid, ip, &WgKeypair::generate()));
            }
            if case == "remove-readd" {
                invalidate_org_bind_identity(&nid, &mut q, &mut relay);
            }
            assert!(
                commit_current_org_bind(
                    done,
                    &mut q,
                    &peers,
                    &HashMap::new(),
                    relay.as_mut().unwrap()
                )
                .is_none(),
                "{case}"
            );
            assert!(!conn.is_alive(), "{case}");
        }
    }

    #[tokio::test]
    async fn org_fallback_force_pin_wins_over_controlled_udp_completion_and_late_session() {
        use base64::Engine as _;
        let kp = WgKeypair::generate();
        let nid = ObjectId::new();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let peers = HashMap::from([(nid, test_netmap_peer(nid, ip, &kp))]);
        let (tx, _rx) = mpsc::channel(8);
        let mux = DerpMux::new([0; 32]).0;
        let mut relay = RelayCoordinator::new(tx, [0; 32], true, vec![], Some(mux));
        let (done, mut q, conn) = pending_org_test_bind(&mut relay, nid, &peers[&nid], 17, 7).await;
        let _ = relay.force_derp(nid, Duration::from_secs(60), None);
        assert!(relay.org_relay_pinned(&nid));
        assert!(
            commit_current_org_bind(done, &mut q, &peers, &HashMap::new(), &mut relay).is_none()
        );
        assert!(
            !conn.is_alive(),
            "completed old UDP bind must be closed inside pin"
        );
        let secret = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
        let late = super::super::orgrelay::member::OrgSession::from_wire(
            18,
            8,
            ObjectId::new(),
            &["8.8.8.8:47865".into()],
            &secret,
            10,
            60,
        )
        .unwrap();
        let (alloc_tx, _alloc_rx) = mpsc::channel(1);
        let mut alloc = RelayAllocQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx: alloc_tx,
        };
        accept_org_bind_session(
            nid,
            late,
            &mut relay,
            &mut q,
            &mut alloc,
            &peers,
            &HashMap::new(),
        );
        assert!(
            relay.take_org_jobs().is_empty(),
            "late session may not start another bind while pinned"
        );
    }

    #[tokio::test]
    async fn org_bind_completion_preserves_fallback_and_rejects_old_generation() {
        let kp = WgKeypair::generate();
        let nid = ObjectId::new();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let peers = HashMap::from([(nid, test_netmap_peer(nid, ip, &kp))]);
        let (tx, _rx) = mpsc::channel(8);
        let mut relay = RelayCoordinator::new(tx, [0; 32], true, vec![], None);
        let (mut done, mut q, conn) =
            pending_org_test_bind(&mut relay, nid, &peers[&nid], 7, 2).await;
        done.generation = 1;
        assert!(
            commit_current_org_bind(done, &mut q, &peers, &HashMap::new(), &mut relay).is_none()
        );
        assert!(
            !conn.is_alive(),
            "same VNI with stale session generation is refused"
        );
        let (done, mut q, conn) = pending_org_test_bind(&mut relay, nid, &peers[&nid], 8, 3).await;
        let link = commit_current_org_bind(done, &mut q, &peers, &HashMap::new(), &mut relay)
            .expect("no direct: current relay remains valid fallback");
        assert_eq!(link.relay_kind, RelayKind::Org);
        assert_eq!(link.public_key, kp.public.to_bytes());
        assert!(conn.is_alive());
        assert!(org_bind_needed(true, None));
    }

    #[tokio::test]
    async fn org_bind_duplicate_session_preserves_inflight_epoch_and_bound_carrier() {
        use super::super::orgrelay::{bind::BindSecret, member::OrgSession};
        let kp = WgKeypair::generate();
        let nid = ObjectId::new();
        let peers = HashMap::from([(
            nid,
            test_netmap_peer(nid, Ipv4Addr::new(100, 64, 0, 7), &kp),
        )]);
        let (tx, _rx) = mpsc::channel(8);
        let mut relay = RelayCoordinator::new(tx, [0; 32], true, vec![], None);
        let (done, mut q, conn) = pending_org_test_bind(&mut relay, nid, &peers[&nid], 7, 1).await;
        let duplicate = OrgSession {
            vni: 7,
            generation: 1,
            relay_node_id: done.relay_node_id,
            endpoints: vec!["127.0.0.1:9".parse().unwrap()],
            secret: BindSecret::from_bytes([7; 32]),
            bind_budget: Duration::from_secs(3),
            expires_at: Instant::now() + Duration::from_secs(60),
            conn: None,
        };
        let (tx, _rx) = mpsc::channel(8);
        let mut alloc = RelayAllocQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx,
        };
        let epoch = done.epoch;
        accept_org_bind_session(
            nid,
            duplicate.clone(),
            &mut relay,
            &mut q,
            &mut alloc,
            &peers,
            &HashMap::new(),
        );
        assert_eq!(q.in_flight.get(&nid), Some(&epoch));
        assert!(
            relay.is_tracking(&nid),
            "duplicate does not lose the only pending bind"
        );
        assert!(
            relay.take_org_jobs().is_empty(),
            "duplicate does not restart a bind"
        );
        assert!(
            commit_current_org_bind(done, &mut q, &peers, &HashMap::new(), &mut relay).is_some()
        );
        accept_org_bind_session(
            nid,
            duplicate,
            &mut relay,
            &mut q,
            &mut alloc,
            &peers,
            &HashMap::new(),
        );
        assert!(
            conn.is_alive(),
            "duplicate after commit must not close the bound carrier"
        );
        assert!(relay.take_org_jobs().is_empty());
    }

    #[tokio::test]
    async fn org_bind_replacement_reschedules_and_old_failure_cannot_drop_it() {
        use super::super::orgrelay::{bind::BindSecret, member::OrgSession};
        let kp = WgKeypair::generate();
        let nid = ObjectId::new();
        let peers = HashMap::from([(
            nid,
            test_netmap_peer(nid, Ipv4Addr::new(100, 64, 0, 7), &kp),
        )]);
        let (tx, _rx) = mpsc::channel(8);
        let mut relay = RelayCoordinator::new(tx, [0; 32], true, vec![], None);
        let (mut done, mut q, conn) =
            pending_org_test_bind(&mut relay, nid, &peers[&nid], 7, 1).await;
        let replacement = OrgSession {
            vni: 7,
            generation: 2,
            relay_node_id: done.relay_node_id,
            endpoints: vec!["127.0.0.1:9".parse().unwrap()],
            secret: BindSecret::from_bytes([8; 32]),
            bind_budget: Duration::from_secs(3),
            expires_at: Instant::now() + Duration::from_secs(60),
            conn: None,
        };
        let (tx, _rx) = mpsc::channel(8);
        let mut alloc = RelayAllocQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx,
        };
        accept_org_bind_session(
            nid,
            replacement,
            &mut relay,
            &mut q,
            &mut alloc,
            &peers,
            &HashMap::new(),
        );
        let job = relay
            .take_org_jobs()
            .pop()
            .expect("pre-replacement tracking starts the replacement bind");
        assert_eq!(job.generation, 2);
        let replacement_epoch = q.stamp(nid);
        conn.close();
        done.conn = None; // the old asynchronous bind failed, after replacement
        assert!(
            commit_current_org_bind(done, &mut q, &peers, &HashMap::new(), &mut relay).is_none()
        );
        assert!(
            relay.is_tracking(&nid),
            "stale failure must not drop newer session/bind"
        );
        assert_eq!(q.in_flight.get(&nid), Some(&replacement_epoch));
    }

    #[tokio::test]
    async fn listener_watch_reannounces_actual_port_over_existing_control_sender() {
        let (out, mut messages) = mpsc::channel(4);
        let tf: TunFactory =
            Box::new(|_, _, _| panic!("listener control test must not create TUN"));
        let (tx, rx) = watch::channel(Some(3478));
        let rt = OverlayRuntime::new_relay(WgKeypair::generate(), out, tf, 1280)
            .with_relay_listener_readiness(rx);
        let mut changes = rt.relay_listener_readiness.clone();
        tx.send_replace(None);
        assert!(relay_listener_changed(&mut changes).await);
        rt.outbound
            .send(rt.make_join(vec!["203.0.113.1:41641".into()]))
            .await
            .unwrap();
        assert!(matches!(
            messages.recv().await,
            Some(ClientMsg::OverlayJoin {
                relay_port: None,
                ..
            })
        ));
        tx.send_replace(Some(3479));
        assert!(relay_listener_changed(&mut changes).await);
        rt.outbound.send(rt.make_join(vec![])).await.unwrap();
        assert!(matches!(
            messages.recv().await,
            Some(ClientMsg::OverlayJoin {
                relay_port: Some(3479),
                ..
            })
        ));
        drop(tx);
        assert!(!relay_listener_changed(&mut changes).await);
        assert!(changes.is_none());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                relay_listener_changed(&mut changes)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn listener_watch_running_runtime_withdraws_without_reattach_or_netmap() {
        let (out, mut messages) = mpsc::channel(4);
        let (events, event_rx) = mpsc::channel(4);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let links = Arc::new(LoopbackLinks {
            dst: socket.local_addr().unwrap(),
            sock: socket,
        });
        let tf: TunFactory = Box::new(|_, _, _| panic!("no netmap means no TUN creation"));
        let (tx, rx) = watch::channel(Some(3478));
        let rt = OverlayRuntime::new(WgKeypair::generate(), out, links, tf, 1280)
            .with_relay_listener_readiness(rx);
        let task = tokio::spawn(rt.run(event_rx, vec![]));
        let first = tokio::time::timeout(Duration::from_secs(1), messages.recv())
            .await
            .unwrap();
        assert!(matches!(
            first,
            Some(ClientMsg::OverlayJoin {
                relay_port: Some(3478),
                ..
            })
        ));
        tx.send_replace(None);
        let withdrawn = tokio::time::timeout(Duration::from_secs(1), messages.recv())
            .await
            .unwrap();
        assert!(matches!(
            withdrawn,
            Some(ClientMsg::OverlayJoin {
                relay_port: None,
                ..
            })
        ));
        assert!(
            !task.is_finished(),
            "same runtime stayed attached; no Reattach event was sent"
        );
        drop(events);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[cfg(test)]
mod org_fallback_tests {
    use super::*;
    use roomler_ai_remote_control::signaling::OrgRelayCandidateWire;

    async fn fixture() -> (
        ObjectId,
        HashMap<ObjectId, Installed>,
        HashMap<ObjectId, NetmapPeer>,
        super::super::orgrelay::discovery::Discovery,
        Option<RelayCoordinator>,
        mpsc::Receiver<ClientMsg>,
        Instant,
    ) {
        let key = WgKeypair::generate();
        let id = ObjectId::new();
        let now = Instant::now();
        let peer:NetmapPeer=serde_json::from_value(serde_json::json!({
            "node_id":id.to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":key.public_base64(),
            "reachable":true,"supports_org_relay":true,"supports_derp":true,"supports_derp_floor":true
        })).unwrap();
        let peers = HashMap::from([(id, peer)]);
        let cfg = peer_config_from_netmap(&peers[&id]).unwrap();
        let (tx, rx) = mpsc::channel(8);
        let mux = DerpMux::new([0; 32]).0;
        let mut relay = RelayCoordinator::new(tx, [0; 32], false, vec![], Some(mux));
        relay.set_org_relay(true);
        assert!(relay.build_floor(id, &cfg).is_some());
        let installed = HashMap::from([(
            id,
            Installed {
                is_direct: false,
                relay_kind: Some(RelayKind::Derp),
                ..Installed::base(cfg.public_key, cfg.overlay_ip, DirectTier::Relay, now)
            },
        )]);
        let mut discovery = super::super::orgrelay::discovery::Discovery::default();
        let (metadata_tx, mut metadata_rx) = mpsc::channel(4);
        discovery
            .request(true, true, &peers, &ControlTx::new(metadata_tx), now)
            .await;
        let ClientMsg::OverlayOrgRelayDiscover { request_id, .. } = metadata_rx.try_recv().unwrap()
        else {
            panic!("expected actual queued discovery request")
        };
        assert_eq!(
            discovery.receive_page(
                &peers,
                id,
                request_id,
                vec![OrgRelayCandidateWire {
                    relay_node_id: ObjectId::new(),
                    exit_relay_node_id: None,
                    endpoints: vec!["8.8.8.8:47865".into()]
                }],
                30,
                None,
                now
            ),
            1
        );
        (id, installed, peers, discovery, Some(relay), rx, now)
    }

    #[tokio::test]
    async fn org_fallback_runtime_fresh_hint_bootstraps_derp_without_replacing_it() {
        let (id, installed, peers, discovery, mut relay, mut rx, now) = fixture().await;
        let since = installed[&id].since;
        request_org_fallbacks(true, &installed, &peers, &mut relay, now).await;
        assert!(
            matches!(rx.try_recv(),Ok(ClientMsg::OverlayOrgRelayFallbackRequest{peer_node_id,..})if peer_node_id==id),
            "a fresh metadata hint must reach the real server-mint control channel from DERP"
        );
        assert_eq!(installed[&id].since, since);
        assert_eq!(installed[&id].relay_kind, Some(RelayKind::Derp));
        assert!(relay.as_ref().unwrap().is_floored(&id));
        assert!(
            relay
                .as_mut()
                .unwrap()
                .grant_accept(id, vec![], "unrelated-turn".into())
                .is_none()
        );
    }

    #[tokio::test]
    async fn org_fallback_runtime_requires_enabled_current_identity_capability_and_derp() {
        for gate in 0..8 {
            let (id, mut installed, mut peers, mut discovery, mut relay, mut rx, now) =
                fixture().await;
            let mut enabled = true;
            let mut at = now;
            match gate {
                0 => enabled = false,
                1 => installed.get_mut(&id).unwrap().is_direct = true,
                2 => peers.get_mut(&id).unwrap().supports_org_relay = false,
                3 => peers.get_mut(&id).unwrap().reachable = false,
                4 => {
                    peers.get_mut(&id).unwrap().wg_public_key =
                        WgKeypair::generate().public_base64()
                }
                5 => installed.get_mut(&id).unwrap().relay_kind = Some(RelayKind::Turn),
                6 => peers.get_mut(&id).unwrap().overlay_ip = "100.64.0.99".into(),
                7 => { peers.remove(&id); },
                _ => unreachable!(),
            }
            request_org_fallbacks(enabled, &installed, &peers, &mut relay, at).await;
            assert!(rx.try_recv().is_err(), "unsafe request at gate {gate}");
        }
    }
    #[tokio::test]
    async fn org_fallback_runtime_quality_cooldown_does_not_block_real_carrier_loss() {
        let (id, installed, peers, mut discovery, mut relay, mut rx, now) = fixture().await;
        let candidate = discovery.candidate_for(&peers, id, now).unwrap();
        let identity = (peers[&id].wg_public_key.clone(), peers[&id].overlay_ip.clone());
        discovery.note_failure(&peers, id, &identity, &candidate, now);
        assert!(discovery.candidate_for(&peers, id, now).is_none(),
            "normal quality trials must retain their existing failure cooldown");
        request_org_fallbacks(true, &installed, &peers, &mut relay, now).await;
        assert!(matches!(rx.try_recv(), Ok(ClientMsg::OverlayOrgRelayFallbackRequest { peer_node_id, .. }) if peer_node_id == id),
            "fresh current metadata must allow the server-authorized fallback query during DERP, independently of quality trial cooldown");
        assert!(relay.as_ref().unwrap().is_floored(&id));
    }

    #[tokio::test]
    async fn org_fallback_runtime_unrelated_delta_cannot_delay_authoritative_query() {
        let (id, installed, peers, mut discovery, mut relay, mut rx, now) = fixture().await;
        discovery.reconcile_delta(&peers, &[]);
        assert!(discovery.candidate_for(&peers, id, now).is_none(),
            "discovery authorization hints must remain invalidated on every delta");
        request_org_fallbacks(true, &installed, &peers, &mut relay, now).await;
        assert!(matches!(rx.try_recv(), Ok(ClientMsg::OverlayOrgRelayFallbackRequest { peer_node_id, .. }) if peer_node_id == id),
            "current peer and DERP carrier must reach authoritative server authorization after an unrelated D0 delta");
    }

    #[tokio::test]
    async fn org_fallback_runtime_expired_discovery_does_not_reuse_session_or_block_query() {
        let (id, installed, peers, discovery, mut relay, mut rx, now) = fixture().await;
        let at = now + Duration::from_secs(31);
        assert!(discovery.candidate_for(&peers, id, at).is_none());
        request_org_fallbacks(true, &installed, &peers, &mut relay, at).await;
        assert!(matches!(rx.try_recv(), Ok(ClientMsg::OverlayOrgRelayFallbackRequest { peer_node_id, .. }) if peer_node_id == id));
        assert!(relay.as_ref().unwrap().is_floored(&id));
    }

}

#[cfg(test)]
mod org_upgrade_tests {
    use super::*;
    fn test_relay_bq() -> RelayBuildQueue {
        let (tx, _rx) = mpsc::channel(4);
        RelayBuildQueue {
            in_flight: HashMap::new(),
            epoch: 0,
            tx,
        }
    }

    fn test_netmap_peer(nid: ObjectId, overlay_ip: Ipv4Addr, kp: &WgKeypair) -> NetmapPeer {
        NetmapPeer {
            node_id: nid,
            overlay_ip: overlay_ip.to_string(),
            name: "pc".into(),
            wg_public_key: kp.public_base64(),
            supports_derp: true,
            supports_derp_floor: true,
            reachable: true,
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            supports_quic: false,
            supports_relay_single: false,
            supports_forced_derp: false,
            caps: None,
            supports_overlay_echo: false,
            supports_org_relay: false,
            relay_strategy: None,
            routes: vec![],
            agent_id: None,
            ingress_rules: None,
        }
    }


    use crate::transport::relay::UdpRelayConn;
    use base64::Engine;
    use crate::overlay::disco::derp_follow as proofwire;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[derive(Default)]
    struct FollowTap {
        frames: std::sync::Mutex<Vec<Vec<u8>>>, held: std::sync::Mutex<Vec<Vec<u8>>>,
        hold_init: AtomicBool, hold_proof: AtomicBool,
    }
    impl FollowTap {
        fn forward(&self, bytes: &[u8]) -> bool {
            let mut seen=self.frames.lock().unwrap();
            if seen.len()==1024 {seen.remove(0);}
            seen.push(bytes.to_vec());drop(seen);
            let body=&bytes[32..];
            let hold = body.len()==148 && body[0]==1 && self.hold_init.swap(false,Ordering::Relaxed)
                || proofwire::shaped(body) && body[8]==proofwire::Kind::Proof as u8 && self.hold_proof.swap(false,Ordering::Relaxed);
            if hold {self.held.lock().unwrap().push(bytes.to_vec());}
            !hold
        }
        fn count(&self, kind:proofwire::Kind)->usize {
            self.frames.lock().unwrap().iter().filter(|f|proofwire::shaped(&f[32..])&&f[40]==kind as u8).count()
        }
    }
    struct FollowUdp { socket:UdpSocket, drop_ack:Arc<AtomicBool> }
    #[async_trait]
    impl crate::transport::relay::RelayConn for FollowUdp {
        async fn send_to(&self, bytes:&[u8], target:SocketAddr)->std::io::Result<usize> {
            if proofwire::shaped(bytes) && bytes[8]==proofwire::Kind::HelloAck as u8 && self.drop_ack.load(Ordering::Relaxed) {
                return Ok(bytes.len()); // fixture drops only capability ACK on the actual carrier
            }
            self.socket.send_to(bytes,target).await
        }
        async fn recv_from(&self,bytes:&mut[u8])->std::io::Result<(usize,SocketAddr)> {self.socket.recv_from(bytes).await}
        fn local_addr(&self)->std::io::Result<SocketAddr> {self.socket.local_addr()}
    }

    struct CandidateTun;
    #[async_trait]
    impl TunIo for CandidateTun {
        async fn read_packet(&self)->std::io::Result<Vec<u8>> { std::future::pending().await }
        async fn write_packet(&self,_:&[u8])->std::io::Result<()> { Ok(()) }
    }

    struct End {
        rt: OverlayRuntime, wg: WgDevice,
        received: mpsc::Receiver<Vec<u8>>, installed: HashMap<ObjectId, Installed>,
        peers: HashMap<ObjectId, NetmapPeer>, relay: Option<RelayCoordinator>,
        tun: Arc<dyn TunIo>, bq: RelayBuildQueue,
        mux: Arc<DerpMux>, events: mpsc::Receiver<crate::transport::derp::MuxEvent>,
        id: ObjectId, pk: [u8;32], ip: Ipv4Addr,
        control: mpsc::Receiver<ClientMsg>, tap: Arc<FollowTap>, drop_org_ack: Arc<AtomicBool>,
    }
    async fn pair() -> (End, End, Vec<tokio::task::JoinHandle<()>>) {
        let a = WgKeypair::generate(); let b = WgKeypair::generate();
        let aip = Ipv4Addr::new(100,65,4,2); let bip = Ipv4Addr::new(100,65,4,3);
        let aid = ObjectId::new(); let bid = ObjectId::new();
        let (am, mut ar) = DerpMux::new(a.public.to_bytes());
        let (bm, mut br) = DerpMux::new(b.public.to_bytes());
        async fn end(key: WgKeypair, peer: &WgKeypair, id: ObjectId,
            ip: Ipv4Addr, mux: Arc<DerpMux>) -> End {
            let (tx, control) = mpsc::channel(16);
            let mock = Arc::new(CandidateTun);
            let tf: TunFactory = { let m=mock.clone(); Box::new(move |_,_,_| Ok(m.clone() as Arc<dyn TunIo>)) };
            let rt = OverlayRuntime::new_relay(key.clone(), tx.clone(), tf, 1280);
            let (mut wg, received) = WgDevice::new(key.secret.clone());
            let peers=HashMap::from([(id,test_netmap_peer(id,ip,peer))]);
            let cfg=peer_config_from_netmap(&peers[&id]).unwrap();
            let mut r=RelayCoordinator::new(tx,key.public.to_bytes(),false,vec![],Some(mux.clone()));
            let floor=r.build_floor(id,&cfg).unwrap();
            let tun:Arc<dyn TunIo>=mock;
            let mut installed=HashMap::new(); let mut bq=test_relay_bq();
            let (et,events)=mpsc::channel(32); mux.set_event_sink(et);
            rt.install_ready(&mut wg,&mut installed,&tun,floor,&mut bq).await;
            End {rt,wg,received,installed,peers,relay:Some(r),tun,bq,mux,events,id,pk:peer.public.to_bytes(),ip,
                control,tap:Arc::new(FollowTap::default()),drop_org_ack:Arc::new(AtomicBool::new(false))}
        }
        let ea=end(a.clone(),&b,bid,bip,am.clone()).await;
        let eb=end(b.clone(),&a,aid,aip,bm.clone()).await;
        let ap=a.public.to_bytes();let bp=b.public.to_bytes();
        let tap_ab=ea.tap.clone();let tap_ba=eb.tap.clone();
        let bridge_ab=tokio::spawn(async move {while let Some((_,mut f))=ar.recv().await {
            f[..32].copy_from_slice(&ap);if tap_ab.forward(&f){bm.deliver(&f);}
        }});
        let bridge_ba=tokio::spawn(async move {while let Some((_,mut f))=br.recv().await {
            f[..32].copy_from_slice(&bp);if tap_ba.forward(&f){am.deliver(&f);}
        }});
        let deadline=Instant::now()+Duration::from_secs(5);
        while !(ea.wg.peer_handshake_done(&ea.pk)==Some(true) && eb.wg.peer_handshake_done(&eb.pk)==Some(true)) {
            assert!(Instant::now()<deadline,"real DERP WG handshake");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (ea,eb,vec![bridge_ab,bridge_ba])
    }
    async fn links(a:&End,b:&End)->(ReadyLink,ReadyLink) {
        let sa=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sb=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aa=sa.local_addr().unwrap();let ba=sb.local_addr().unwrap();
        let ca:Arc<dyn crate::transport::relay::RelayConn>=Arc::new(FollowUdp{socket:sa,drop_ack:a.drop_org_ack.clone()});
        let cb:Arc<dyn crate::transport::relay::RelayConn>=Arc::new(FollowUdp{socket:sb,drop_ack:b.drop_org_ack.clone()});
        let make=|e:&End,c:Arc<dyn crate::transport::relay::RelayConn>,dst| ReadyLink {
            node_id:e.id,public_key:e.pk,overlay_ip:e.ip,carrier:Carrier::relay(c.clone(),dst),
            relay_parts:Some((c,dst)),extra_permission_targets:vec![],supports_quic:false,
            single_relay:None,relay_kind:RelayKind::Org,subnets:vec![],
        };
        (make(a,ca,ba),make(b,cb,aa))
    }
    async fn stage(e:&mut End,l:ReadyLink) {
        e.rt.install_ready(&mut e.wg,&mut e.installed,&e.tun,l,&mut e.bq).await;
    }
    fn settle(e:&mut End)->bool {
        e.rt.sweep_org_upgrades(&mut e.wg,&mut e.installed,&mut e.relay,&e.peers)
    }
    fn packet(src:Ipv4Addr,dst:Ipv4Addr,label:u8)->Vec<u8> {
        let mut p=vec![0u8;21];p[0]=0x45;p[2..4].copy_from_slice(&21u16.to_be_bytes());
        p[8]=64;p[9]=17;p[12..16].copy_from_slice(&src.octets());p[16..20].copy_from_slice(&dst.octets());p[20]=label;p
    }
    async fn payload(a:&End,b:&mut End,label:u8) {
        let p=packet(b.ip,a.ip,label);
        assert!(a.wg.send_ip_packet(&p).await);
        let got=tokio::time::timeout(Duration::from_secs(2),b.received.recv()).await.unwrap().unwrap();
        assert_eq!(got,p,"real WG payload must survive on current sender");
    }
    async fn promoted(a:&mut End,b:&mut End) {
        let deadline=Instant::now()+Duration::from_secs(8);
        loop {
            settle(a);settle(b);
            if a.installed[&a.id].relay_kind==Some(RelayKind::Org)
                && b.installed[&b.id].relay_kind==Some(RelayKind::Org) {break;}
            assert!(Instant::now()<deadline,"both own INIT responses must promote");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    #[tokio::test]
    async fn org_upgrade_failed_candidate_keeps_real_derp_payload_and_cannot_borrow_floor_proof() {
        let (mut a,mut b,tasks)=pair().await;let (la,_lb)=links(&a,&b).await;
        stage(&mut a,la).await;
        assert_eq!(a.installed[&a.id].relay_kind,Some(RelayKind::Derp),"unproven candidate cannot replace DERP");
        payload(&a,&mut b,1).await;payload(&b,&mut a,2).await;
        assert!(!settle(&mut a),"floor handshake/data are not candidate proof");
        assert_eq!(a.installed[&a.id].relay_kind,Some(RelayKind::Derp));
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn org_upgrade_simultaneous_real_handshakes_and_delayed_floor_frames() {
        let (mut a,mut b,tasks)=pair().await;let (la,lb)=links(&a,&b).await;
        stage(&mut a,la).await;stage(&mut b,lb).await;
        let deadline=Instant::now()+Duration::from_secs(8);
        while !(a.wg.org_upgrade_ready(&a.pk) && b.wg.org_upgrade_ready(&b.pk)) {
            assert!(Instant::now()<deadline,"real initiator-role proof on both candidates");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(settle(&mut a));
        assert_eq!(b.installed[&b.id].relay_kind,Some(RelayKind::Derp));
        let before=a.wg.peer_traffic(&a.pk).unwrap();
        // B is genuinely still sending old-session encrypted business over
        // DERP while A's sender has already cut over to ORG.
        payload(&b,&mut a,3).await;
        assert!(a.events.try_recv().is_err(),"valid delayed floor data must not emit demote-follow");
        assert_eq!(a.wg.peer_traffic(&a.pk).unwrap(),before,"valid floor data cannot credit ORG counters");
        payload(&a,&mut b,4).await;
        assert!(settle(&mut b));
        payload(&a,&mut b,5).await;payload(&b,&mut a,6).await;
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn org_upgrade_one_end_early_recovers_its_own_initiator_proof() {
        let (mut a,mut b,tasks)=pair().await;let (la,lb)=links(&a,&b).await;
        stage(&mut a,la).await;
        let mut discarded = [0u8; 2048];
        loop {
            let n=tokio::time::timeout(Duration::from_secs(1),lb.relay_parts.as_ref().unwrap().0.recv_from(&mut discarded)).await.unwrap().unwrap().0;
            if n>=148 && discarded[0]==1 { break; }
            assert_eq!(&discarded[..n],b"\x00","only the real permission bootstrap precedes INIT");
        }
        stage(&mut b,lb).await;promoted(&mut a,&mut b).await;
        payload(&a,&mut b,5).await;payload(&b,&mut a,6).await;
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn org_upgrade_remove_fences_late_real_candidate_completion() {
        let (mut a,mut b,tasks)=pair().await;let (la,lb)=links(&a,&b).await;
        stage(&mut a,la).await;a.wg.remove_peer(&a.pk).await;
        stage(&mut b,lb).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!settle(&mut a),"removed incumbent cannot be resurrected");
        assert_eq!(a.wg.peer_handshake_done(&a.pk),None);
        for t in tasks {t.abort();}
    }

    #[tokio::test]
    async fn org_upgrade_identical_completion_does_not_rearm_and_expiry_keeps_floor() {
        let (mut a,mut b,tasks)=pair().await;let (la,_lb)=links(&a,&b).await;
        stage(&mut a,la.clone()).await;
        let since=a.installed[&a.id].org_upgrade.as_ref().unwrap().1;
        stage(&mut a,la).await;
        assert_eq!(a.installed[&a.id].org_upgrade.as_ref().unwrap().1,since);
        a.installed.get_mut(&a.id).unwrap().org_upgrade.as_mut().unwrap().1=
            Instant::now()-DirectTier::Relay.handshake_deadline()-Duration::from_secs(1);
        assert!(!settle(&mut a));
        assert!(a.installed[&a.id].org_upgrade.is_none());
        payload(&a,&mut b,7).await;payload(&b,&mut a,8).await;
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn org_upgrade_force_pin_replacement_cancels_late_real_handshake() {
        let (mut a,mut b,tasks)=pair().await;let (la,lb)=links(&a,&b).await;
        stage(&mut a,la).await;
        let id=a.id;
        let mut r=a.relay.take().unwrap();
        let mut floor=r.force_derp(id,Duration::from_secs(60),None);
        if floor.is_none() {
            // Same stamp-only fallback used by the real ForceDerp arm.
            floor=r.follow_peer_to_derp(id,peer_config_from_netmap(&a.peers[&id]).unwrap());
        }
        a.relay=Some(r);
        stage(&mut a,floor.unwrap()).await;
        stage(&mut b,lb).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!settle(&mut a));
        assert!(a.installed[&id].org_upgrade.is_none());
        assert_eq!(a.installed[&id].relay_kind,Some(RelayKind::Derp));
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn org_upgrade_revoke_cancels_pending_candidate_without_weakening_floor() {
        let (mut a,mut b,tasks)=pair().await;let (la,lb)=links(&a,&b).await;
        let session=super::super::orgrelay::member::OrgSession::from_wire(
            77,1,ObjectId::new(),&["8.8.8.8:47865".into()],&base64::engine::general_purpose::STANDARD.encode([11u8;32]),10,60).unwrap();
        assert!(a.relay.as_mut().unwrap().org_session_accept(a.id,session));
        stage(&mut a,la).await;
        let id=a.relay.as_mut().unwrap().org_session_revoke(77).unwrap();
        cancel_org_upgrade_candidate(&id,&mut a.wg,&mut a.installed);
        stage(&mut b,lb).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!settle(&mut a));
        assert!(a.installed[&id].org_upgrade.is_none());
        payload(&a,&mut b,9).await;payload(&b,&mut a,10).await;
        for t in tasks {t.abort();}
    }
    fn fresh_poll(e:&mut End)->bool {
        e.rt.sweep_authenticated_derp_follow(&mut e.wg,&mut e.installed,&mut e.relay,&e.peers)
    }
    async fn cap_ready(a:&mut End,b:&mut End) {
        let until=Instant::now()+Duration::from_secs(9);
        while !a.wg.test_follow_capable(&a.pk)||!b.wg.test_follow_capable(&b.pk) {
            fresh_poll(a);fresh_poll(b);
            assert!(Instant::now()<until,"fresh ORG-owner capability exchange");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn as_org(a:&mut End,b:&mut End) {
        let (la,lb)=links(a,b).await;stage(a,la).await;stage(b,lb).await;
        promoted(a,b).await;cap_ready(a,b).await;
    }
    async fn fallback(e:&mut End) {
        let link=e.relay.as_mut().unwrap().follow_peer_to_derp(e.id,peer_config_from_netmap(&e.peers[&e.id]).unwrap()).unwrap();
        stage(e,link).await;
        assert!(e.wg.poke_handshake(&e.pk),"new actual DERP owner emits a real INIT");
    }
    async fn held(tap:&FollowTap)->Vec<u8> {
        let until=Instant::now()+Duration::from_secs(2);
        loop {
            if let Some(p)=tap.held.lock().unwrap().pop(){return p;}
            assert!(Instant::now()<until,"expected real withheld wire packet");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    #[tokio::test]
    async fn fresh_follow_real_new_derp_init_restores_same_floor_and_recovers_after_org_loss() {
        let (mut a,mut b,tasks)=pair().await;as_org(&mut a,&mut b).await;
        payload(&a,&mut b,20).await;payload(&b,&mut a,21).await;
        fallback(&mut b).await; // destroys B's real ORG UDP socket/owner
        let until=Instant::now()+Duration::from_secs(3);
        while a.installed[&a.id].relay_kind!=Some(RelayKind::Derp) {
            fresh_poll(&mut a);
            assert!(Instant::now()<until,"authenticated owner proof must follow without health timeout");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(a.wg.org_recovery_held(&a.pk));assert!(b.wg.org_recovery_held(&b.pk));
        assert!(a.installed[&a.id].org_recovery_needs_query);
        payload(&a,&mut b,22).await;payload(&b,&mut a,23).await;
        // A second copy of a consumed actual proof cannot change the sender.
        let proof=b.tap.frames.lock().unwrap().iter().find(|f|proofwire::shaped(&f[32..])&&f[40]==proofwire::Kind::Proof as u8).unwrap().clone();
        a.mux.deliver(&proof);assert!(!fresh_poll(&mut a));
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn fresh_follow_unseen_old_init_while_peer_org_and_old_data_do_not_demote() {
        let (mut a,mut b,tasks)=pair().await;
        b.tap.hold_init.store(true,Ordering::Relaxed);
        assert!(b.wg.poke_handshake(&b.pk));
        let old=held(&b.tap).await; // a valid, previously unseen floor INIT
        as_org(&mut a,&mut b).await;
        let old_org=a.wg.peer_traffic(&a.pk).unwrap();
        a.mux.deliver(&old);
        let until=Instant::now()+Duration::from_millis(400);
        while Instant::now()<until {fresh_poll(&mut a);fresh_poll(&mut b);tokio::time::sleep(Duration::from_millis(10)).await;}
        assert!(a.tap.count(proofwire::Kind::Challenge)>0,"old unseen INIT really passed Tunn and initiated a fresh challenge");
        assert_eq!(b.tap.count(proofwire::Kind::Proof),0,"retained floor cannot attest while ORG owner is active");
        assert_eq!(a.installed[&a.id].relay_kind,Some(RelayKind::Org));
        assert_eq!(a.wg.peer_traffic(&a.pk).unwrap(),old_org,"old floor does not credit ORG");
        // Replay the same authentic INIT, and delayed genuine old ciphertext.
        a.mux.deliver(&old);
        if let Some(data)=b.tap.frames.lock().unwrap().iter().find(|f|f.len()>36&&f[32..36]==[4,0,0,0]).cloned(){a.mux.deliver(&data);}
        fresh_poll(&mut a);
        assert_eq!(a.installed[&a.id].relay_kind,Some(RelayKind::Org));
        payload(&a,&mut b,24).await;payload(&b,&mut a,25).await;
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn fresh_follow_missing_hello_ack_never_sends_derp_challenge_and_later_recovers_capability() {
        let (mut a,mut b,tasks)=pair().await;
        b.drop_org_ack.store(true,Ordering::Relaxed);
        let (la,lb)=links(&a,&b).await;stage(&mut a,la).await;stage(&mut b,lb).await;promoted(&mut a,&mut b).await;
        let until=Instant::now()+Duration::from_millis(3_300);
        while Instant::now()<until {fresh_poll(&mut a);fresh_poll(&mut b);tokio::time::sleep(Duration::from_millis(10)).await;}
        assert!(!a.wg.test_follow_capable(&a.pk));
        assert_eq!(a.tap.count(proofwire::Kind::Challenge),0,"no new frame goes to DERP before explicit capability ACK");
        payload(&a,&mut b,26).await;payload(&b,&mut a,27).await;
        b.drop_org_ack.store(false,Ordering::Relaxed);cap_ready(&mut a,&mut b).await;
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn fresh_follow_late_valid_proof_cannot_revive_after_revoke_pin_remove_rekey_or_reip() {
        for case in 0..5 {
            let (mut a,mut b,tasks)=pair().await;as_org(&mut a,&mut b).await;
            b.tap.hold_proof.store(true,Ordering::Relaxed);fallback(&mut b).await;
            let until=Instant::now()+Duration::from_secs(2);
            while b.tap.held.lock().unwrap().is_empty(){fresh_poll(&mut a);assert!(Instant::now()<until);tokio::time::sleep(Duration::from_millis(10)).await;}
            let proof=held(&b.tap).await;
            let previous_key=a.pk;
            match case {
                0 => {
                    let session=super::super::orgrelay::member::OrgSession::from_wire(77,1,ObjectId::new(),&["8.8.8.8:47865".into()],&base64::engine::general_purpose::STANDARD.encode([17u8;32]),10,60).unwrap();
                    a.relay.as_mut().unwrap().org_session_accept(a.id,session);
                    let peer=a.relay.as_mut().unwrap().org_session_revoke(77).unwrap();
                    cancel_org_upgrade_candidate(&peer,&mut a.wg,&mut a.installed);
                },
                1 => {
                    let r=a.relay.as_mut().unwrap();
                    let floor=r.force_derp(a.id,Duration::from_secs(60),None)
                        .or_else(||r.follow_peer_to_derp(a.id,peer_config_from_netmap(&a.peers[&a.id]).unwrap())).unwrap();
                    assert!(r.org_relay_pinned(&a.id));stage(&mut a,floor).await;
                },
                2 => {a.wg.remove_peer(&a.pk).await;a.installed.remove(&a.id);a.peers.remove(&a.id);},
                _ => {
                    a.wg.remove_peer(&a.pk).await;a.installed.remove(&a.id);
                    let mut peer=a.peers[&a.id].clone();
                    if case==3 {
                        let replacement=WgKeypair::generate();
                        peer.wg_public_key=replacement.public_base64();a.pk=replacement.public.to_bytes();
                    } else {
                        a.ip=Ipv4Addr::new(100,65,4,99);peer.overlay_ip=a.ip.to_string();
                    }
                    a.peers.insert(a.id,peer);
                    let floor=a.relay.as_mut().unwrap().follow_peer_to_derp(a.id,peer_config_from_netmap(&a.peers[&a.id]).unwrap()).unwrap();
                    stage(&mut a,floor).await;
                },
            }
            a.mux.deliver(&proof);tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(!fresh_poll(&mut a),"old nonce/owner must not mutate replacement state");
            if case==0 {assert_eq!(a.installed[&a.id].relay_kind,Some(RelayKind::Org));}
            if case==1 {assert_eq!(a.installed[&a.id].relay_kind,Some(RelayKind::Derp));}
            if case==2 {assert_eq!(a.wg.peer_count(),0);}
            if case>=3 {
                assert_eq!(a.wg.peer_count(),1);
                assert_eq!(a.installed[&a.id].pubkey,a.pk);
                assert_eq!(a.installed[&a.id].overlay_ip,a.ip);
                assert_eq!(a.installed[&a.id].relay_kind,Some(RelayKind::Derp));
                if case==3 {assert_eq!(a.wg.peer_handshake_done(&previous_key),None);}
                if case==4 {assert!(!a.wg.org_recovery_held(&a.pk),"different IP never inherits another identity's hold");}
            }
            for t in tasks {t.abort();}
        }
    }
    #[tokio::test]
    async fn fresh_follow_hold_rejects_late_session_and_expiry_requires_successful_fresh_request() {
        let (mut a,mut b,tasks)=pair().await;as_org(&mut a,&mut b).await;
        let (old_done,mut q,old_conn)=super::tests::pending_org_test_bind(a.relay.as_mut().unwrap(),a.id,&a.peers[&a.id],88,1).await;
        let (at,_ar)=mpsc::channel(4);let mut alloc=RelayAllocQueue {in_flight:HashMap::new(),epoch:0,tx:at};
        let alloc_epoch=alloc.stamp(a.id);let mut old_bq=test_relay_bq();let build_epoch=old_bq.stamp(a.id);
        assert!(old_conn.is_alive());
        fallback(&mut b).await;
        let until=Instant::now()+Duration::from_secs(3);
        while !fresh_poll(&mut a) {assert!(Instant::now()<until);tokio::time::sleep(Duration::from_millis(10)).await;}
        assert!(q.in_flight.contains_key(&a.id),"simulate fallback tick running before its first recovery scout");
        let now=Instant::now();
        a.relay.as_mut().unwrap().set_org_relay(true);
        for p in a.peers.values_mut(){p.supports_org_relay=true;}
        assert!(request_org_fallbacks(true,&a.installed,&a.peers,&mut a.relay,now).await.is_empty());
        let secret=base64::engine::general_purpose::STANDARD.encode([13u8;32]);
        let session=||super::super::orgrelay::member::OrgSession::from_wire(99,1,ObjectId::new(),&["8.8.8.8:47865".into()],&secret,10,60).unwrap();
        assert!(!accept_org_bind_session(a.id,session(),a.relay.as_mut().unwrap(),&mut q,&mut alloc,&a.peers,&a.installed));
        // Isolate expiry-boundary testing from packet authentication: only the
        // monotonic hold clock is advanced, no WG/proof counter is fabricated.
        a.wg.test_expire_recovery_hold(&a.pk);
        a.installed.get_mut(&a.id).unwrap().org_recovery_until=Some(Instant::now()-Duration::from_millis(1));
        assert!(!accept_org_bind_session(a.id,session(),a.relay.as_mut().unwrap(),&mut q,&mut alloc,&a.peers,&a.installed),"expiry alone cannot revive a lease");
        for p in a.peers.values_mut(){p.supports_org_relay=true;}
        let sent=request_reconciled_org_fallbacks(true,&mut a.wg,&mut a.installed,&a.peers,&mut a.relay,&mut q,&mut alloc,&mut old_bq,Instant::now()).await;
        assert!(!q.in_flight.contains_key(&a.id));
        assert!(!alloc.take_if_current(&a.id,alloc_epoch));assert!(!old_bq.take_if_current(&a.id,build_epoch));
        assert!(old_conn.is_alive(),"off-loop completion closes at its rejected commit, not queue invalidation");
        assert_eq!(sent,vec![a.id]);
        assert!(matches!(a.control.try_recv().unwrap(),ClientMsg::OverlayOrgRelayFallbackRequest {..}));
        assert!(a.wg.org_recovery_until(&a.pk).is_none(),"successful fresh query consumes the expired marker");
        assert!(accept_org_bind_session(a.id,session(),a.relay.as_mut().unwrap(),&mut q,&mut alloc,&a.peers,&a.installed),"fresh request permits a new bind, not an old pending completion");
        assert!(commit_current_org_bind(old_done,&mut q,&a.peers,&a.installed,a.relay.as_mut().unwrap()).is_none(),"pre-fence completion cannot overwrite fresh admission after expiry");
        assert!(!old_conn.is_alive(),"rejected late completion releases its actual UDP conn");
        reconcile_org_recovery(&mut a.wg,&mut a.installed,&mut a.relay,&mut q,&mut alloc,&mut old_bq);
        assert!(!a.installed[&a.id].org_recovery_needs_query,"expired marker cannot reappear after successful fresh request");
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn fresh_follow_proof_attestation_blocks_an_already_wg_ready_org_candidate() {
        let (mut a,mut b,tasks)=pair().await;
        let (la,lb)=links(&a,&b).await;let retained_org=lb.clone();
        stage(&mut a,la).await;stage(&mut b,lb).await;promoted(&mut a,&mut b).await;cap_ready(&mut a,&mut b).await;
        fallback(&mut b).await;
        stage(&mut b,retained_org).await;
        let until=Instant::now()+Duration::from_secs(3);
        while !b.wg.org_upgrade_ready(&b.pk) {
            assert!(Instant::now()<until,"candidate must possess genuine WG proof before fence");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(b.installed[&b.id].relay_kind,Some(RelayKind::Derp));
        while !b.wg.org_recovery_held(&b.pk) {
            fresh_poll(&mut a);assert!(Instant::now()<until);tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!settle(&mut b),"proof attestation and promotion serialize through the same sender owner");
        assert_eq!(b.installed[&b.id].relay_kind,Some(RelayKind::Derp));
        assert!(b.installed[&b.id].org_upgrade.is_none());
        while a.installed[&a.id].relay_kind!=Some(RelayKind::Derp) {
            fresh_poll(&mut a);assert!(Instant::now()<until);tokio::time::sleep(Duration::from_millis(10)).await;
        }
        payload(&a,&mut b,28).await;payload(&b,&mut a,29).await;
        for t in tasks {t.abort();}
    }
    #[tokio::test]
    async fn fresh_follow_closed_or_full_control_queue_cannot_clear_admission_fence() {
        for full in [false,true] {
            let (mut a,mut b,tasks)=pair().await;as_org(&mut a,&mut b).await;fallback(&mut b).await;
            let until=Instant::now()+Duration::from_secs(3);
            while !fresh_poll(&mut a) {assert!(Instant::now()<until);tokio::time::sleep(Duration::from_millis(10)).await;}
            a.wg.test_expire_recovery_hold(&a.pk);
            a.installed.get_mut(&a.id).unwrap().org_recovery_until=Some(Instant::now()-Duration::from_millis(1));
            a.relay.as_mut().unwrap().set_org_relay(true);
            for p in a.peers.values_mut(){p.supports_org_relay=true;}
            if full {
                for i in 0..16 {a.rt.outbound.send(ClientMsg::OverlayOrgRelayFallbackRequest{peer_node_id:ObjectId::new(),request_id:i}).await.unwrap();}
            } else {a.control.close();}
            let sent=request_org_fallbacks(true,&a.installed,&a.peers,&mut a.relay,Instant::now()).await;
            assert!(sent.is_empty(),"only a true successful enqueue qualifies");
            finish_org_recovery_queries(sent,&a.wg,&mut a.installed);
            assert!(a.installed[&a.id].org_recovery_needs_query);
            for t in tasks {t.abort();}
        }
    }
}
