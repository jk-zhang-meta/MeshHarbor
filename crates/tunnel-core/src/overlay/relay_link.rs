// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Coturn-relay carrier coordination for the overlay runtime (Phase 3b).
//!
//! **Deterministic worker (rc.127).** The relay-to-relay leg must hairpin on
//! ONE coturn worker: cross-worker relay traffic drops under buildhost's
//! dual-public-IP SNAT (the issue the QUIC tunnel fixed in rc.112). rc.125
//! pinned the *responder* onto the *initiator's* worker by reading the
//! initiator's advertised relayed address — but that read is racy: on
//! (re)start the initiator's current relay hasn't propagated yet, so the
//! responder pinned to a **stale** worker and never re-pinned, leaving the
//! pair split and the WireGuard handshake timing out forever (field bring-up
//! 2026-06-10: a restart merely *swapped* which side read stale).
//!
//! rc.127 removes the dependence on the peer's endpoint entirely: **both ends
//! pick the same coturn worker deterministically from the shared `pair_key`**
//! — a stable hash over the *resolved* coturn worker IPs. Same `pair_key`
//! (the server sends an identical `sorted(a,b)` to both) + same DNS record →
//! same sorted IP list → same index → same worker, with zero dependence on
//! propagation timing. No race, no latch; the hairpin is guaranteed.
//!
//! Per-peer flow (symmetric on both sides):
//! 1. peer appears → [`request`](RelayCoordinator::request) sends
//!    `rc:overlay.relay_request`.
//! 2. `rc:overlay.relay_grant` (coturn creds + `pair_key`) →
//!    [`grant_accept`](RelayCoordinator::grant_accept) stashes the creds and
//!    hands the runtime an alloc job; the runtime SPAWNS
//!    [`allocate_for_pair`] (DNS + TURN allocate — seconds on a hostile corp
//!    path, so never inline on the steady loop — rc.218) and commits the
//!    result back on-loop via
//!    [`commit_alloc`](RelayCoordinator::commit_alloc): advertise our relayed
//!    address, move to `allocated`, try to build.
//! 3. the peer's relayed address arrives in a netmap delta →
//!    [`maybe_complete`](RelayCoordinator::maybe_complete): build the
//!    `Carrier::relay` dialing it.

use std::collections::HashMap;
use std::collections::HashSet;

use super::orgrelay::{
    client::OrgRelayConn,
    member::{OrgBindJob, OrgSession, per_endpoint_budget},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::netmap::PeerConfig;
use super::wg::Carrier;
use crate::transport::derp::{DerpMux, MuxEvent};
use crate::transport::relay::RelayConn;
use roomler_ai_remote_control::signaling::{ClientMsg, IceServer, RelayStrategyWire};
use roomler_ai_remote_control::worker_pick::pick_worker_fnv1a;

/// Minimum spacing between break-before-make regrades OFF an established DERP
/// link for the same peer (see [`RelayCoordinator::derp_regrade_due`]).
///
/// Sized against the failure mode, not the happy path: if the rebuilt TURN tier
/// turns out not to carry the pair, the peer is dark until the next attempt —
/// and the server's own force-DERP escalation (P7), which pins the pair back to
/// DERP on sustained churn, needs room to observe that churn and act. Ten
/// minutes leaves the steady state cheap (one disturbance, then quiet) while
/// keeping a genuinely-stuck pair recoverable without an agent restart.
const DERP_REGRADE_COOLDOWN: Duration = Duration::from_secs(600);

/// How soon after a regrade a server force-DERP pin still counts as the server
/// OVERRULING that regrade (see [`RelayCoordinator::note_regrade_overruled`]).
///
/// Field-measured: every overruled regrade on DEVBOX drew its pin 2m45s–4m14s
/// later — the churn has to happen before the server can see it. Ten minutes
/// covers that with margin without swallowing an unrelated later escalation.
const REGRADE_OVERRULE_WINDOW: Duration = Duration::from_secs(600);

/// Backoff after consecutive OVERRULED regrades for the same peer, indexed by
/// strike count.
///
/// Without this the flat [`DERP_REGRADE_COOLDOWN`] is useless against the P7
/// pin, because the pin (1800 s) always outlives it: the pin expires, the
/// regrade re-fires seconds later, TURN churns again, the server re-pins —
/// a permanent ~30-minute cycle on pairs that were previously STABLE on DERP.
/// Observed on DEVBOX 2026-08-07: devbox-wsl's pin lapsed at 09:32:01 and the
/// regrade re-fired at 09:32:16, 15 s later.
///
/// Historically the first rung therefore had to exceed the pin TTL (40 min).
/// Since [`REGRADE_EVIDENCE_CEILING`] landed, IT is what keeps the pin-lapse
/// cycle dead — a struck peer with unchanged evidence waits the ceiling, not
/// the rung — so the rungs only pace post-ceiling retries and evidence-driven
/// ones, and Phase C shrank them accordingly (see [`REGRADE_BACKOFF`]).
/// A regrade that is NOT overruled never books a strike, so capable pairs are
/// unaffected.
/// How long a previously-overruled peer stays gated on NEW EVIDENCE before the
/// backoff timer alone is allowed to release it again.
///
/// This is the difference between repeats trending to zero and merely being
/// rarer. Without it the ladder still fires a doomed retry on schedule; with it
/// a pair whose situation has not changed simply never retries, because
/// "the timer elapsed" is not a reason to believe TURN will work this time.
/// The ceiling exists only to cover changes we cannot observe from here
/// (the far side's firewall, a coturn fix).
///
/// Phase C — shrunk from 24 h to 2 h: a no-evidence retry now costs a brief
/// break-before-make blip cushioned by the permanent DERP floor (A2), not a
/// carrier outage, and the netcheck vector (B3) turns most formerly-invisible
/// far-side changes into observable evidence anyway (a measured flip bypasses
/// this gate entirely). Worst case for a genuinely TURN-less pair: one
/// floor-cushioned probe every 2 h instead of one a day.
const REGRADE_EVIDENCE_CEILING: Duration = Duration::from_secs(7_200);

/// Phase A1 — how long the central `/derp` WS must be continuously DOWN
/// before relay-request evidence reports `derp_mux_failed`. Above the
/// reconnect backoff ceiling (10 s) with margin, so an ordinary blip never
/// clears a server force-DERP pin; a genuine sustained outage (corp
/// middlebox eating wss:/derp while TURNS works) reports within a minute.
const DERP_WS_DOWN_EVIDENCE: Duration = Duration::from_secs(60);

/// Unresponsive-peer re-request ladder: consecutive relay deaths 1-2 keep
/// today's immediate re-request (ordinary transients — coturn blip, worker
/// roll — must stay snappy); from the 3rd the peer has been dark for ≥ two
/// full relay-handshake deadlines and each further attempt is deferred,
/// doubling from 60 s to the 5-min cap. Steady-state against a sleeping
/// peer: ~12 allocations/h instead of ~60 — below the server's TURN-churn
/// escalation, so no force-DERP pin forms to slow the peer's eventual wake.
pub(crate) fn relay_death_backoff(streak: u32) -> Option<Duration> {
    if streak < 3 {
        return None;
    }
    let base = Duration::from_secs(60);
    let cap = Duration::from_secs(300);
    Some(cap.min(base * 2u32.saturating_pow(streak - 3)))
}

/// Phase C (overlay v3) — shrunk from `[40 min, 2 h, 8 h, 24 h]`: with the
/// DERP floor permanent (A2) a failed regrade rebuild falls back onto the
/// floor within one cycle instead of leaving the pair carrier-less, and with
/// the measured capability vector (B3) driving the strategy, a host that
/// provably can't dial never becomes the would-be dialer in the first place —
/// the blind-retry-into-a-wall class the 40-min first rung guarded is gone
/// structurally. The pin-lapse re-churn cycle (rc.314) stays dead via
/// [`REGRADE_EVIDENCE_CEILING`]: a struck peer with UNCHANGED evidence waits
/// the ceiling, not the rung, and a netcheck re-measure is what changes
/// evidence now.
const REGRADE_BACKOFF: [Duration; 4] = [
    Duration::from_secs(120),   // 2 min
    Duration::from_secs(600),   // 10 min
    Duration::from_secs(1_800), // 30 min
    Duration::from_secs(7_200), // 2 h
];

/// Which relay carrier a [`ReadyLink`] rides. `install_ready` gates the
/// QUIC-over-relay upgrade on `Turn`: a `Derp` link is RAW WG over the
/// pubkey-addressed `/derp` WS relay — v1 never rides QUIC-over-DERP (QUIC over
/// a reliable TCP/WS is double-reliable, HOL-on-HOL). The pubkey pinning makes
/// the raw carrier correct (the recv-source discard can never be wrong).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayKind {
    /// A coturn TURN allocation (single-relay or both-allocate).
    Turn,
    /// The DERP `/derp` WS relay (both-UDP-blocked pair).
    Derp,
    /// FR-19 — a tenant-owned org relay (`orgrelay`), reached over UDP.
    Org,
}

impl RelayKind {
    /// The stable LocalAPI label (`roomler peers --json` → `relay_kind`).
    /// Wire-visible: keep these strings as-is.
    pub fn as_str(self) -> &'static str {
        match self {
            RelayKind::Turn => "turn",
            RelayKind::Derp => "derp",
            RelayKind::Org => "org",
        }
    }
}

/// The relay carrier tier chosen for a peer at the relay tier. A 3-way split so
/// the both-UDP-blocked `(false,false)` case (→ [`RelayStrategy::Derp`]) is
/// distinct from "peer doesn't support single-relay" (→
/// [`RelayStrategy::BothAllocate`]) — the old `Option<bool>` conflated them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayStrategy {
    /// v1 single-relay: `true` = ANCHOR (allocate), `false` = DIALER (raw-dial).
    SingleRelay(bool),
    /// DERP: both UDP-blocked, both advertise it, our flag on + WS present.
    Derp,
    /// The both-allocate fall-through (two coturn allocations).
    BothAllocate,
    /// FR-19 P4b — the server minted an org-relay session for this pair and
    /// it is live: bind at the tenant relay. No alloc, no creds.
    OrgRelay,
}

/// A peer link whose carrier is ready to install.
///
/// `Clone` (W6 phase 3): the raw-first QUIC upgrade installs the raw
/// carrier immediately and hands a clone to the background rendezvous —
/// every field is a handle/value (`Arc`s share the same conn/carrier).
#[derive(Clone)]
pub struct ReadyLink {
    pub node_id: ObjectId,
    pub public_key: [u8; 32],
    pub overlay_ip: std::net::Ipv4Addr,
    pub carrier: Arc<Carrier>,
    /// The raw TURN allocation + peer relayed `dst` behind `carrier` (relay
    /// carriers only; `None` for direct/test). Lets the runtime optionally
    /// upgrade the carrier to QUIC-over-TURN in `install_ready`, falling back
    /// to the already-built raw `carrier` on failure.
    pub relay_parts: Option<(Arc<dyn RelayConn>, SocketAddr)>,
    /// W6 phase-2 — ADDITIONAL public srflx addresses of the peer, beyond
    /// `relay_parts.1`, that the ANCHOR must open coturn permissions for.
    /// Permissions are IP-scoped; the anchor's `\x00` bootstrap used to
    /// target only the FIRST advertised srflx, so a multi-homed dialer
    /// (buildhost: 94.130.141.74 + .98 — one plane sock per local IP, several
    /// srflx adverts) whose fresh raw dial socket egressed from another of
    /// its addresses was silently dropped at coturn (field 2026-08-15:
    /// QUIC rendezvous rx=0 on both sides, raw fallback fine). Distinct
    /// IPs only, primary excluded; empty for non-anchor links.
    pub extra_permission_targets: Vec<SocketAddr>,
    /// rc.142 — the peer advertised QUIC-over-TURN support. `install_ready`
    /// only attempts the QUIC upgrade when this is set (both ends must agree).
    pub supports_quic: bool,
    /// Phase D — this link's v1 single-relay role: `None` = not single-relay
    /// (both-allocate / direct), `Some(true)` = ANCHOR, `Some(false)` = DIALER.
    ///
    /// `install_ready` uses it for TWO things. (1) Force the QUIC-over-relay
    /// upgrade REGARDLESS of the `OVERLAY_QUIC` opt-in: a raw `Carrier::Relay`
    /// discards the recv source, so an anchor can't reply to a symmetric
    /// dialer's coturn-observed port — only the QUIC server consumes the
    /// observed path (plan BLOCKER 1). (2) Pick the QUIC role: the ANCHOR must
    /// be the QUIC SERVER — its allocation is the rendezvous, and only the
    /// server-on-the-allocation replies to observed sources. With UDP-aware
    /// anchor selection the anchor may hold the LARGER pubkey, so the old
    /// pubkey-based `am_server` would invert the roles: the anchor would
    /// QUIC-connect toward the dialer's advertised srflx (dropped — that
    /// socket's NAT filter never opened toward `R`) while the dialer serves on
    /// a socket nobody dials. Both ends compute this role from the same
    /// symmetric inputs, so they can't disagree.
    pub single_relay: Option<bool>,
    /// Phase D — which relay carrier this link rides. `Turn` (default) allows the
    /// QUIC-over-relay upgrade; `Derp` forces raw WG over the `/derp` WS relay
    /// and gates QUIC OFF (A2). Direct/test links are `Turn` (QUIC is separately
    /// gated off for them by `relay_parts.is_none()`).
    pub relay_kind: RelayKind,
    /// Phase 1 — approved subnet routes this peer is a router for; `install_ready`
    /// registers them in the router + installs OS routes.
    pub subnets: Vec<super::router::Cidr>,
}

/// A peer we're coordinating a relay link to, before our allocation exists.
struct PendingPeer {
    peer: PeerConfig,
    /// coturn creds from `relay_grant` (`None` until granted).
    ice: Option<Vec<IceServer>>,
    /// symmetric per-pair key from `relay_grant` — drives the deterministic
    /// worker pick so both ends land on the same coturn worker (`None` until
    /// granted).
    pair_key: Option<String>,
}

/// A relay allocation made for one peer, awaiting that peer's relayed
/// address before the carrier can be built.
struct Allocated {
    conn: Arc<dyn RelayConn>,
    peer: PeerConfig,
}

/// Drives the relay handshake for every peer the node wants to reach.
const ORG_FALLBACK_GAP: Duration = Duration::from_secs(60);
const ORG_FALLBACK_RETENTION: Duration = Duration::from_secs(120);
const ORG_FALLBACK_MAX_PEERS: usize = 64;

pub struct RelayCoordinator {
    /// rc.307 (B) — swappable: the runtime outlives control-WS sessions and
    /// re-binds this on every `Reattach`, so relay re-requests after a
    /// reconnect ride the fresh session without rebuilding the coordinator.
    outbound: crate::overlay::runtime::ControlTx,
    /// rc.307 (B) — detached-mode log damper: `true` after the first failed
    /// control send, cleared by the first success (post-reattach).
    warned_detached: bool,
    // Explicit ORG-only bootstrap requests never occupy legacy TURN pending.
    org_fallback_last: HashMap<ObjectId, Instant>,
    org_fallback_serial: u64,
    org_fallback_cursor: Option<ObjectId>,
    /// Requested (and maybe granted), not yet allocated.
    pending: HashMap<ObjectId, PendingPeer>,
    /// Allocated + advertised; awaiting the peer's relayed address.
    allocated: HashMap<ObjectId, Allocated>,
    /// Our relayed address **per peer** (peer node_id → the relay we
    /// allocated for that link). Keyed so a re-allocation *replaces* and
    /// [`forget`](Self::forget) *prunes* the entry — a flat append-only list
    /// let a relay torn down in an earlier churn cycle linger in the
    /// advertised set, and the peer (which dials `endpoints[0]`) then sent
    /// WireGuard to a dead allocation forever (the rc.125→126 field failure).
    /// Each `endpoints` trickle carries every *current* value.
    advertised: HashMap<ObjectId, String>,
    /// rc.135 — this node's DIRECT LAN endpoints (from `setup_direct`). The
    /// server REPLACES a node's stored endpoints on each `rc:overlay.endpoints`
    /// trickle, so the trickle MUST re-include the LAN endpoints or they're
    /// clobbered — which is exactly what stripped `.2`/`.3`'s `192.168.68.x`
    /// from the netmap and forced peers onto relay (field 2026-06-27). Every
    /// trickle now carries `lan ∪ current relays`.
    lan_endpoints: Vec<String>,
    /// Phase D — this node's WG public key, the tie-break for the single-relay
    /// role when BOTH ends are UDP-capable (smaller pubkey = ANCHOR). Pure
    /// function of the two pubkeys ⇒ both ends agree with no coordination
    /// message. See [`single_relay_role`](Self::single_relay_role).
    my_public_key: [u8; 32],
    /// Phase D — our end of the single-relay opt-in, captured once from
    /// [`relay_single_enabled`](super::direct::relay_single_enabled). A link
    /// goes single-relay only when this AND the peer's advertised support are
    /// both set (a mixed pair must stay on both-allocate, never deadlock).
    single_relay: bool,
    /// Phase D — can THIS node reach coturn over raw UDP (so it can be the
    /// single-relay DIALER, which raw-UDP-dials the anchor's `R`)? Derived from
    /// whether our own srflx gather succeeded (`!srflx_advertised.is_empty()`):
    /// a successful UDP STUN round-trip to a coturn worker is proof that raw UDP
    /// to coturn works. A UDP-blocked host (corp / TLS-inspecting net) gathers
    /// no srflx and sets this `false` — it can still be the ANCHOR (allocates
    /// over the TURNS/TCP Tier-3 fallback), just never the raw-UDP dialer. The
    /// PEER's equivalent is read symmetrically off the netmap as
    /// `!peer.srflx_endpoints.is_empty()`, so both ends compute the same role.
    my_udp_relay_ok: bool,
    /// Dialer honesty — mirror of [`super::dialer::udp_dialer_ok`], synced by
    /// the runtime at sweep time (kept as a field so the role logic stays
    /// static-free and unit-testable). `false` = this HOST proved its raw
    /// dials toward relay-band ports never land (corp egress whitelists
    /// STUN:3478 but drops the relay band) — it can still ANCHOR, exactly
    /// like a udp-blocked host, and the role split treats it as such against
    /// honesty-capable peers.
    my_udp_dialer_ok: bool,
    /// B3 — our own MEASURED relay-band verdict (netcheck `relay_band_udp`),
    /// synced by the runtime at sweep time like the latch mirror above, and
    /// already freshness-gated at the sync site (`None` = no fresh vector).
    /// When BOTH this and the peer's netmap-carried bit are present, the
    /// measured pair supersedes the srflx/latch inference in the role split.
    my_relay_band_udp: Option<bool>,
    /// Phase D — v1 single-relay DIALER links awaiting the anchor's advertised
    /// relay `R`. We hold NO allocation for these (the anchor owns the sole
    /// relay); each becomes a raw [`UdpRelayConn`](crate::transport::relay::UdpRelayConn)
    /// carrier the moment the anchor's `R` lands in the netmap. Keyed like
    /// `pending`/`allocated` so [`forget`](Self::forget) prunes it and
    /// [`is_tracking`](Self::is_tracking) sees it.
    dialing: HashMap<ObjectId, PeerConfig>,
    /// W6 phase-2 — the coturn worker IP set (full A-record resolve of the
    /// STUN hosts, fed once by the runtime after the first netmap). The
    /// single-relay dialer uses it to positively identify the anchor's
    /// relayed address `R`; empty = resolution unavailable → legacy pick.
    coturn_ips: Vec<IpAddr>,
    /// Phase D (DERP) — both-UDP-blocked links awaiting their symmetric DERP
    /// carrier. We hold NO coturn allocation and make NO server round-trip (both
    /// ends dial the `/derp` WS); each becomes a [`DerpConn`] carrier built off
    /// [`derp_mux`](Self::derp_mux) the moment the peer is tracked. Keyed like
    /// `dialing` so `forget`/`is_tracking` see it.
    derping: HashMap<ObjectId, PeerConfig>,
    /// Phase A2 (overlay v3) — peers whose INSTALLED carrier is the DERP
    /// FLOOR: built at birth (both ends `supports_derp_floor`, mux alive)
    /// while the better-tier coordination runs in parallel. Deliberately
    /// OUTSIDE the role maps and [`is_tracking`](Self::is_tracking): the
    /// floor is not a strategy outcome, so `maybe_complete`'s strategy-flip
    /// recompute never touches it, and the caller's `!is_tracking` path
    /// still fires the parallel TURN `request`. Cleared when any
    /// coordinator-built link supersedes the floor (`try_build*` hooks) or
    /// the peer is forgotten.
    floored: HashMap<ObjectId, PeerConfig>,
    /// rc.413 (#25) — per-peer throttle for the floor-withheld report:
    /// `(last_logged, reason_code)`. See `note_floor_withheld`.
    floor_withheld_log: HashMap<ObjectId, (Instant, u8)>,
    /// Phase D — our end of the DERP opt-in ([`derp_enabled`](super::direct::derp_enabled),
    /// default-OFF). A link goes DERP only when this is set, the peer advertises
    /// `supports_derp`, both ends are UDP-blocked, AND `derp_mux` is present.
    derp: bool,
    /// Phase A2 — our `overlay_derp_floor` opt-in
    /// ([`derp_floor_enabled`](super::direct::derp_floor_enabled),
    /// default-OFF), read once at construction like its siblings so the
    /// role/floor logic stays env-free and unit-testable.
    derp_floor: bool,
    /// Phase D — this node's single `/derp` WS demux, if the DERP tier is on and
    /// the WS is up. `try_build_derp` vends a per-peer [`DerpConn`] from it.
    /// `None` disables DERP (falls through to both-allocate).
    derp_mux: Option<Arc<DerpMux>>,
    /// Phase D — the relay STRATEGY each TRACKED link was established with
    /// ([`relay_strategy`](Self::relay_strategy)'s value at request time).
    /// `maybe_complete` recomputes it from every fresh netmap and, if it changed,
    /// `forget`s the link so the caller re-establishes with the correct strategy.
    /// It can change because it depends on the peer's `srflx_endpoints`, which
    /// arrive on a LATER `rc:overlay.srflx` trickle than the join: during that
    /// window a UDP-capable peer briefly looks UDP-blocked, so both ends can pick
    /// "dialer" (single-relay) or "DERP" and deadlock. The strategy is otherwise
    /// frozen once tracked (`request` early-returns on `is_tracking`), so without
    /// this recompute the pair would never heal.
    roles: HashMap<ObjectId, RelayStrategy>,
    /// P7 — per-peer force-DERP pins from the server's `OverlayForceDerp`
    /// escalation push (sustained TURN churn on the pair). While a pin is
    /// unexpired, [`relay_strategy`](Self::relay_strategy) returns
    /// [`RelayStrategy::Derp`] for the peer FIRST — before the UDP-capability
    /// split — so `maybe_complete`'s strategy-flip recompute can't thrash the
    /// pinned pair back to a TURN tier on the next srflx trickle. Expiry is
    /// lazy (checked on read); after it, the normal strategy resumes on the
    /// next establishment cycle.
    forced_derp_until: HashMap<ObjectId, Instant>,
    /// FR-19 P4b — org-relay sessions the server minted for this node, by
    /// PEER. A live entry makes `relay_strategy` answer `OrgRelay` for that
    /// peer regardless of the netmap stamp: both ends were pushed the same
    /// session, so the decision is symmetric without the wire, and the stamp
    /// (which only changes on the next netmap event) cannot lag behind it.
    org_sessions: HashMap<ObjectId, OrgSession>,
    /// The peer config captured when the org bind was requested — what the
    /// `ReadyLink` is built from at commit time (refreshed by `maybe_complete`).
    org_peers: HashMap<ObjectId, PeerConfig>,
    /// Peers whose org bind the runtime is running off-loop; `is_tracking`
    /// dedups on it exactly as on `pending`.
    org_binding: HashSet<ObjectId>,
    /// Binds `request` decided on but the runtime has not spawned yet —
    /// drained by `take_org_jobs` on the runtime's next pass.
    org_jobs: Vec<OrgBindJob>,
    /// `overlay_org_relay` — the client half of FR-19, default ON (MeshHarbor).
    org_relay: bool,
    /// Multi-region DERP — lazily-opened muxes for REGIONAL relays, keyed by
    /// their `derp_url`. A pair force-pinned with a `derp_url` builds its
    /// [`DerpConn`] off that region's mux; everything else keeps the central
    /// [`derp_mux`](Self::derp_mux).
    regional_muxes: HashMap<String, Arc<DerpMux>>,
    /// #27 — the runtime's sink for "a peer is relaying to us over DERP that we
    /// hold no conn for". Held here so every mux that arrives later gets it.
    event_sink: Option<mpsc::Sender<MuxEvent>>,
    /// Multi-region DERP — the regional URL a force-pinned peer must use
    /// (server-pushed, identical on both ends). Entry present ONLY when the
    /// matching regional mux exists; pruned alongside `forced_derp_until`.
    forced_urls: HashMap<ObjectId, String>,
    /// Earliest instant a peer may be re-graded off DERP again — booked by
    /// [`derp_regrade_due`](Self::derp_regrade_due) each time it says yes.
    /// The regrade is break-before-make, so a pair whose strategy oscillates
    /// (srflx appearing and lapsing) must not be able to tear its carrier
    /// down every netmap tick.
    derp_regrade_at: HashMap<ObjectId, Instant>,
    /// When the last regrade FIRED for a peer, so a subsequent force-DERP pin
    /// can be attributed to it ([`note_regrade_overruled`](Self::note_regrade_overruled)).
    derp_regrade_last: HashMap<ObjectId, Instant>,
    /// Consecutive regrades for a peer that the server overruled with a pin.
    /// Indexes [`REGRADE_BACKOFF`]; cleared once a regrade survives.
    derp_regrade_strikes: HashMap<ObjectId, usize>,
    /// [`strategy_fingerprint`] of the inputs at the peer's last regrade — the
    /// evidence gate. A peer the server already overruled does not get to try
    /// again just because a timer elapsed; something about the pair has to have
    /// actually CHANGED first.
    derp_regrade_inputs: HashMap<ObjectId, u64>,
    /// When the peer's last regrade fired. Unlike `derp_regrade_last` this is
    /// never consumed, so it can enforce the absolute minimum spacing even when
    /// fresh evidence waives the backoff.
    derp_regrade_fired_at: HashMap<ObjectId, Instant>,
    /// U1 — one-shot context for the NEXT [`request`](Self::request) per
    /// peer: which relay flavour is being replaced + why it died. Stamped by
    /// the health sweep's teardown just before its re-request; consumed on
    /// send so a later fresh establishment doesn't replay stale evidence.
    refresh_ctx: HashMap<ObjectId, (Option<RelayKind>, &'static str)>,
    /// Unresponsive-peer re-request backoff — consecutive relay-carrier
    /// deaths for a peer with NO intervening completed handshake, plus the
    /// instant our OWN next `request` for it is allowed. Field 2026-08-15:
    /// buildhost ground a fresh allocation + 89 s QUIC rendezvous window against
    /// SLEEPING winhost-a (zombie server registration) every ~45-90 s all
    /// evening — the reap→re-request loop has no memory, and the resulting
    /// TURN churn kept re-triggering the server's 30-min force-DERP pins,
    /// which then delayed direct upgrades after the peer WOKE. Deferral is
    /// safe for wake latency: relay pairing is server-coordinated two-sided,
    /// so the waking peer's own request installs the pair regardless of our
    /// hold (grants bypass `request`). Streak cleared by the sweep when a
    /// relay carrier for the peer completes a handshake. Entries for peers
    /// that never return leak ~32 bytes each — bounded by fleet size.
    death_streaks: HashMap<ObjectId, (u32, Instant)>,
    /// U1 — STICKY: a `/derp` mux open was ATTEMPTED and failed (the
    /// [`force_derp`](Self::force_derp) veto fired with no mux to bind).
    /// Reported on every relay request so the server stops choosing/holding
    /// forced-DERP for this node's pairs — the silent-veto dark window
    /// (client ignores the pin, server refuses TURN grants for the pin's
    /// TTL). Cleared the moment any mux registers successfully.
    derp_mux_failed: bool,
    /// U2 — our own `OVERLAY_SERVER_RELAY_STRATEGY` opt-in, read once at
    /// construction (like `derp`/`single_relay`). When on, and the server
    /// stamped a per-edge verdict (`PeerConfig::relay_strategy`, which it
    /// only does when the PEER is also flagged), `relay_strategy()` returns
    /// that verdict verbatim instead of deriving locally.
    server_strategy: bool,
    /// C4 stage 2 (PR-B) — the STANDING warm TURN allocation, mirrored here
    /// by the runtime's warm arm ([`set_warm_leg`](Self::set_warm_leg)) while
    /// the leg is live. A single-relay ANCHOR [`request`](Self::request)
    /// commits it instantly — no request/grant/allocate round-trips — which is
    /// the whole point of keeping the leg warm: the pair fails over in the
    /// time it takes the peer to dial, not the time three round-trips take
    /// through a possibly-captured control WS.
    warm_leg: Option<Arc<dyn RelayConn>>,
    /// C4 stage 2 (PR-B) — which pair currently OWNS the warm leg. SINGLE-PAIR
    /// by design: a [`Carrier::relay`] spawns a reader that `recv_from`s the
    /// conn, so two pairs sharing one allocation would steal each other's
    /// datagrams (per-peer readers decap against their own Tunn — no demux).
    /// Cleared by [`forget`](Self::forget) (the leg, if still alive, is free
    /// for the next commit) and by `set_warm_leg(None)` (the leg died).
    /// Sharing one allocation across pairs needs a DERP-style inbound demux —
    /// that's PR-C, not this.
    warm_committed: Option<ObjectId>,
}

/// Hash of everything `relay_strategy` reads about a pair, other than the
/// server's force-DERP pin (which it checks first and which expires on its own).
///
/// Comparing this across attempts is what turns the retry from "a timer elapsed"
/// into "something changed". Only meaningful within one process lifetime —
/// `DefaultHasher` is not stable across runs — which is all the coordinator's
/// in-memory maps live for anyway.
fn strategy_fingerprint(
    my_udp_relay_ok: bool,
    my_udp_dialer_ok: bool,
    my_relay_band_udp: Option<bool>,
    peer: &PeerConfig,
) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    my_udp_relay_ok.hash(&mut h);
    // Dialer honesty — both halves are strategy inputs, so a latch flip (or
    // a peer's honest re-advert) must read as "something changed" and
    // re-establish the pair on the corrected roles.
    my_udp_dialer_ok.hash(&mut h);
    peer.udp_dialer_ok.hash(&mut h);
    // B3 — the measured pair likewise: a fresh vector landing (either
    // side), changing, or expiring must re-establish on the new roles.
    my_relay_band_udp.hash(&mut h);
    peer.relay_band_udp.hash(&mut h);
    peer.supports_relay_single.hash(&mut h);
    peer.supports_derp.hash(&mut h);
    // Order-independent: the netmap does not promise a stable ordering, and a
    // reshuffle of the same set is NOT new evidence.
    let mut eps: Vec<&String> = peer.srflx_endpoints.iter().collect();
    eps.sort();
    eps.hash(&mut h);
    h.finish()
}

impl RelayCoordinator {
    pub fn new(
        // rc.307 (B): `impl Into<ControlTx>` keeps the ~14 test call sites
        // (bare mpsc senders) source-compatible; PRODUCTION passes the
        // runtime's shared `ControlTx` CLONE so a `Reattach` swap propagates
        // here — a coordinator wrapping its own private sender would never
        // see it.
        outbound: impl Into<crate::overlay::runtime::ControlTx>,
        my_public_key: [u8; 32],
        my_udp_relay_ok: bool,
        lan_endpoints: Vec<String>,
        derp_mux: Option<Arc<DerpMux>>,
    ) -> Self {
        // Dialer honesty — arm the process-wide start-grace clock (idempotent;
        // every org runtime constructs a coordinator at startup).
        super::dialer::touch_start();
        Self {
            outbound: outbound.into(),
            warned_detached: false,
            org_fallback_last: HashMap::new(),
            org_fallback_serial: 0,
            org_fallback_cursor: None,
            pending: HashMap::new(),
            allocated: HashMap::new(),
            advertised: HashMap::new(),
            lan_endpoints,
            coturn_ips: Vec::new(),
            my_public_key,
            // rc.276 — forced-TLS vetoes single-relay locally too (paired
            // with the join-time `supports_relay_single` veto so both ends'
            // strategy matrices stay symmetric).
            single_relay: super::direct::relay_single_enabled()
                && !super::direct::relay_tls_forced(),
            my_udp_relay_ok,
            my_udp_dialer_ok: super::dialer::udp_dialer_ok(),
            // B3 — deliberately NOT read from the netcheck slot here: the
            // runtime tick syncs it within one cycle, the slot is empty at
            // process start (45 s startup delay) anyway, and a construction-
            // time read would couple every unit test to process-wide state.
            my_relay_band_udp: None,
            dialing: HashMap::new(),
            derping: HashMap::new(),
            floored: HashMap::new(),
            floor_withheld_log: HashMap::new(),
            derp: super::direct::derp_enabled(),
            derp_floor: super::direct::derp_floor_enabled(),
            derp_mux,
            roles: HashMap::new(),
            forced_derp_until: HashMap::new(),
            org_sessions: HashMap::new(),
            org_peers: HashMap::new(),
            org_binding: HashSet::new(),
            org_jobs: Vec::new(),
            org_relay: super::direct::org_relay_enabled(),
            regional_muxes: HashMap::new(),
            event_sink: None,
            forced_urls: HashMap::new(),
            derp_regrade_at: HashMap::new(),
            derp_regrade_last: HashMap::new(),
            derp_regrade_strikes: HashMap::new(),
            derp_regrade_inputs: HashMap::new(),
            derp_regrade_fired_at: HashMap::new(),
            refresh_ctx: HashMap::new(),
            death_streaks: HashMap::new(),
            derp_mux_failed: false,
            server_strategy: super::direct::server_relay_strategy_enabled(),
            warm_leg: None,
            warm_committed: None,
        }
    }

    /// C4 stage 2 (PR-B) — mirror the warm leg's lifecycle from the runtime's
    /// warm arm: `Some(conn)` on ESTABLISHED, `None` on LOST. Losing the leg
    /// also releases the single-pair commit — the committed pair's carrier
    /// holds its own `Arc` clone and dies on its own terms (health sweep),
    /// but a DEAD leg must never be fast-committed to the next pair.
    pub fn set_warm_leg(&mut self, conn: Option<Arc<dyn RelayConn>>) {
        if conn.is_none() {
            self.warm_committed = None;
        }
        self.warm_leg = conn;
    }

    /// R2 — replace the LAN endpoints after a direct-plane rebuild. These
    /// were constructor-only (relay grant handling advertises
    /// `all_endpoints()` = these + the allocation), so every trickle after a
    /// roam re-advertised the DEAD plane's addresses.
    pub fn set_lan_endpoints(&mut self, endpoints: Vec<String>) {
        self.lan_endpoints = endpoints;
    }

    /// R2 — update our own UDP-relay capability after a srflx re-gather.
    /// Constructor-only until now, which FROZE half of
    /// [`strategy_fingerprint`] for the runtime's life — the #355 latent
    /// limitation: the exact incident the DERP regrade was built for (a
    /// fleet-wide srflx outage recovering) was undetectable from our own
    /// side; only the peer's srflx reappearing or a process restart could
    /// unfreeze a pinned pair. A live value makes our half of the evidence
    /// real.
    pub fn set_udp_relay_ok(&mut self, ok: bool) {
        if self.my_udp_relay_ok != ok {
            info!(
                was = self.my_udp_relay_ok,
                now = ok,
                "overlay relay: own UDP-relay capability changed (srflx re-gather)"
            );
        }
        self.my_udp_relay_ok = ok;
    }

    /// Dialer honesty — sync the host-wide latch ([`super::dialer`]) into
    /// this org's role inputs. Called by the runtime at sweep time; kept a
    /// plain setter so role tests drive it directly without the static.
    pub fn set_udp_dialer_ok(&mut self, ok: bool) {
        if self.my_udp_dialer_ok != ok {
            info!(
                was = self.my_udp_dialer_ok,
                now = ok,
                "overlay relay: own dialer capability changed — relay roles recompute on the next cycle"
            );
        }
        self.my_udp_dialer_ok = ok;
    }

    /// B3 — sync our own measured relay-band verdict (freshness-gated at
    /// the call site: `None` = no fresh netcheck vector). Same runtime
    /// sweep-time discipline as [`set_udp_dialer_ok`](Self::set_udp_dialer_ok).
    pub fn set_relay_band_udp(&mut self, measured: Option<bool>) {
        if self.my_relay_band_udp != measured {
            info!(
                was = ?self.my_relay_band_udp,
                now = ?measured,
                "overlay relay: own measured relay-band verdict changed — relay roles recompute on the next cycle"
            );
        }
        self.my_relay_band_udp = measured;
    }

    /// Whether the tracked strategy for `node_id` was single-relay with US
    /// as the raw-UDP DIALER — the role whose failure is dialer-honesty
    /// evidence (an anchor-role death says nothing about our egress).
    pub fn was_dialer_for(&self, node_id: &ObjectId) -> bool {
        matches!(
            self.roles.get(node_id),
            Some(RelayStrategy::SingleRelay(false))
        )
    }

    /// U1 — stamp the one-shot evidence for `node_id`'s NEXT relay request:
    /// the dead carrier's flavour + the `DeathReason` short string. Called by
    /// the health sweep's teardown right before its re-request.
    pub fn note_refresh_context(
        &mut self,
        node_id: ObjectId,
        kind: Option<RelayKind>,
        reason: &'static str,
    ) {
        self.refresh_ctx.insert(node_id, (kind, reason));
        // Unresponsive-peer backoff — every RELAY death without an
        // intervening completed handshake escalates the streak; from the
        // 3rd, our OWN next `request` is deferred (see `death_streaks`).
        //
        // RELAY deaths only (`kind.is_some()`): the first cut booked EVERY
        // death, and a direct-tier failure loop (a srflx punch dying at its
        // 12 s deadline every ~65 s walk) then re-armed the 300 s hold
        // faster than it could expire — the relay re-request starved
        // FOREVER while the pair sat carrier-less (field 2026-08-17,
        // rc.398 post-roll: corplap/winhost-a pairs wedged fleet-wide once the
        // storm-era force-DERP pins expired and stopped masking it). A
        // direct-tier death says nothing about grinding allocations —
        // #496's whole point — so it must not feed this streak.
        if kind.is_none() {
            return;
        }
        let now = Instant::now();
        let entry = self.death_streaks.entry(node_id).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        if let Some(hold) = relay_death_backoff(entry.0) {
            entry.1 = now + hold;
            info!(
                peer = %node_id, streak = entry.0, hold_s = hold.as_secs(),
                "overlay relay: peer unresponsive across consecutive relay deaths — deferring our re-request (their own request still pairs us instantly)"
            );
        }
    }

    /// Unresponsive-peer backoff — a relay carrier for `node_id` completed a
    /// handshake: the peer is provably alive, forget the death streak.
    pub fn clear_death_streak(&mut self, node_id: &ObjectId) {
        self.death_streaks.remove(node_id);
    }

    /// #22 — a peer we can HEAR is not asleep, so the defer's premise is
    /// void: `relay_death_backoff` exists to stop hammering allocations at a
    /// SLEEPING peer, but the 08-18 devbox↔winhost-a wedge showed the other
    /// face — one end's replacement legs kept dying (rebirthing floor) while
    /// it deferred "because their own request still pairs us instantly", and
    /// the peer, whose OWN leg round-tripped fine, never had a reason to
    /// re-request. The deferring end could hear the peer the whole time.
    /// Called by the health sweep whenever the peer was heard this sweep:
    /// an active hold expires immediately (the streak COUNT survives for
    /// telemetry and re-books on the next death — against a still-audible
    /// peer it is voided again, restoring the pre-defer request cadence,
    /// which is exactly right: only silence earns the defer).
    pub fn note_peer_audible(&mut self, node_id: &ObjectId) {
        let now = Instant::now();
        if let Some((streak, until)) = self.death_streaks.get_mut(node_id)
            && relay_death_backoff(*streak).is_some()
            && *until > now
        {
            info!(
                peer = %node_id, streak = *streak,
                "overlay relay: deferred peer is AUDIBLE — voiding the hold (a heard peer is not asleep; its own leg may be healthy and it will never re-request)"
            );
            *until = now;
        }
    }

    /// P7 — does this coordinator hold a live `/derp` mux? The runtime checks
    /// before a force-DERP conversion and lazily opens one when absent.
    pub fn has_derp_mux(&self) -> bool {
        self.derp_mux.is_some()
    }

    /// F2 — the node-level `/derp` mux that standby copies ride, if any.
    pub fn derp_mux_handle(&self) -> Option<Arc<DerpMux>> {
        self.derp_mux.clone()
    }

    /// P7 — hand the coordinator a lazily-opened `/derp` mux (a UDP-capable
    /// node skips the startup open and only needs one when the server
    /// force-pins a pair onto DERP). First mux wins; a second call is a no-op
    /// (per-peer `DerpConn`s vend from the original).
    pub fn set_derp_mux(&mut self, mux: Arc<DerpMux>) {
        if self.derp_mux.is_none() {
            self.derp_mux = Some(mux);
        }
        if let Some(m) = self.derp_mux.as_ref() {
            Self::arm_event_sink(&self.event_sink, m);
        }
        // U1 — a mux registered: the sticky open-failure evidence is stale.
        self.derp_mux_failed = false;
    }

    /// Phase A1 — the DERP-failure evidence that rides every relay request
    /// (`OverlayRelayRequest.derp_mux_failed`). Two producers:
    /// * the sticky open-failure latch (`derp_mux_failed` — a force-derp push
    ///   arrived with NO mux Arc; pre-floor this was the only signal), and
    /// * a SUSTAINED central-WS outage (`down_for() >= DERP_WS_DOWN_EVIDENCE`)
    ///   — with the permanent floor mux the Arc always exists, so Arc absence
    ///   alone would never fire again and the server's U1 silent-veto healer
    ///   would go blind for the WSS-down-while-control-WS-works class
    ///   (winhost-a, Check Point). The hysteresis keeps a reconnect blip from
    ///   clearing force-DERP pins.
    fn derp_evidence_failed(&self) -> bool {
        self.derp_mux_failed
            || self
                .derp_mux
                .as_ref()
                .and_then(|m| m.down_for())
                .is_some_and(|d| d >= DERP_WS_DOWN_EVIDENCE)
    }

    /// Multi-region DERP — is a mux for this regional `derp_url` already open?
    pub fn has_regional_mux(&self, url: &str) -> bool {
        self.regional_muxes.contains_key(url)
    }

    /// Multi-region DERP — register a lazily-opened regional mux. First mux
    /// per URL wins (per-peer `DerpConn`s vend from the original).
    pub fn set_regional_mux(&mut self, url: &str, mux: Arc<DerpMux>) {
        let m = self.regional_muxes.entry(url.to_string()).or_insert(mux);
        Self::arm_event_sink(&self.event_sink, m);
    }

    /// #27/#28 — install the runtime's [`MuxEvent`] sink, and back-fill it onto
    /// every mux already held. Idempotent; a rebuild re-points cleanly.
    ///
    /// The coordinator owns this rather than the runtime reaching in, because
    /// muxes arrive through two doors at unpredictable times ([`set_derp_mux`]
    /// for the central one, [`set_regional_mux`] per region) and a mux that
    /// never got the sink is a mux whose black-hole stays silent — exactly the
    /// failure this whole path exists to close.
    ///
    /// [`set_derp_mux`]: Self::set_derp_mux
    /// [`set_regional_mux`]: Self::set_regional_mux
    pub fn set_event_sink(&mut self, tx: mpsc::Sender<MuxEvent>) {
        self.event_sink = Some(tx);
        if let Some(m) = self.derp_mux.as_ref() {
            Self::arm_event_sink(&self.event_sink, m);
        }
        for m in self.regional_muxes.values() {
            Self::arm_event_sink(&self.event_sink, m);
        }
    }

    fn arm_event_sink(sink: &Option<mpsc::Sender<MuxEvent>>, mux: &Arc<DerpMux>) {
        if let Some(tx) = sink {
            mux.set_event_sink(tx.clone());
        }
    }

    /// The DERP mux serving `node_id`: its force-pinned REGIONAL mux when one
    /// exists, else the central `/derp` mux. Region failure degrades to
    /// central (worse RTT, still connected) — never to no-DERP.
    fn mux_for(&self, node_id: &ObjectId) -> Option<&Arc<DerpMux>> {
        self.forced_urls
            .get(node_id)
            .and_then(|u| self.regional_muxes.get(u))
            .or(self.derp_mux.as_ref())
    }

    /// P7 — is `node_id` currently force-pinned to DERP (unexpired pin)?
    fn forced_derp_active(&self, node_id: &ObjectId) -> bool {
        self.forced_derp_until
            .get(node_id)
            .is_some_and(|until| Instant::now() < *until)
    }

    /// P7 — apply a server `OverlayForceDerp` push: pin the pair to DERP for
    /// `ttl` and reconcile whatever coordination slot the peer occupies into
    /// `derping`. Returns a [`ReadyLink`] when the DERP carrier is buildable
    /// right now; a peer with NO slot (untracked, or currently INSTALLED on a
    /// churning TURN carrier) is stamp-only — the pin flips the strategy on
    /// its next (re)establishment cycle, which the health sweep drives within
    /// ~15 s for a dead carrier.
    ///
    /// The caller must ensure a `/derp` mux exists first ([`has_derp_mux`] /
    /// [`set_derp_mux`]); without one the pin is refused (a pinned peer with
    /// no mux would park in `derping` unreachable until expiry).
    pub fn force_derp(
        &mut self,
        node_id: ObjectId,
        ttl: Duration,
        derp_url: Option<&str>,
    ) -> Option<ReadyLink> {
        // Multi-region DERP: bind the peer to the pushed regional relay when
        // its mux was opened (the runtime opens it via the regional factory
        // BEFORE calling here); an un-openable region or `None` degrades to
        // the central mux — worse RTT, still connected.
        match derp_url {
            Some(u) if self.regional_muxes.contains_key(u) => {
                self.forced_urls.insert(node_id, u.to_string());
            }
            // Degrading to central is only safe when the PEER degrades too —
            // if it honors the regional URL the two ends register on
            // DIFFERENT relays and the pair one-ways. Loud, so a split pin
            // is attributable from either end's log.
            Some(u) => {
                warn!(
                    peer = %node_id, url = %u,
                    "overlay relay: force-derp pin names a regional relay we have no mux for — degrading to central (pair may one-way if the peer honors it)"
                );
                self.forced_urls.remove(&node_id);
            }
            None => {
                self.forced_urls.remove(&node_id);
            }
        }
        if self.mux_for(&node_id).is_none() {
            // U1 — latch the veto as sticky evidence: every later relay
            // request reports `derp_mux_failed`, so the server stops
            // choosing/holding forced-DERP for this node's pairs instead of
            // refusing TURN grants at a client that cannot comply (the
            // silent-veto dark window).
            self.derp_mux_failed = true;
            warn!(peer = %node_id, "overlay relay: force-derp push but no /derp mux — ignoring (reporting derp_mux_failed on future requests)");
            return None;
        }
        // Lazy hygiene: drop expired pins so the map tracks only live ones
        // (URL pins go with them — a re-pin re-supplies its URL).
        self.forced_derp_until
            .retain(|_, until| Instant::now() < *until);
        self.forced_derp_until.insert(node_id, Instant::now() + ttl);
        self.drop_org_session(&node_id); // a later bind must not defeat this pin
        let live = &self.forced_derp_until;
        self.forced_urls.retain(|n, _| live.contains_key(n));
        info!(
            peer = %node_id, ttl_s = ttl.as_secs(),
            relay = %self
                .forced_urls
                .get(&node_id)
                .map(String::as_str)
                .unwrap_or("central"),
            "overlay relay: pair force-pinned to DERP (server escalation — TURN churn)"
        );
        // If this pin lands right after WE moved the pair off DERP, the churn
        // it is reacting to is ours — back off before trying that again.
        self.note_regrade_overruled(&node_id, Instant::now());
        let peer_cfg = if let Some(pp) = self.pending.remove(&node_id) {
            Some(pp.peer)
        } else if let Some(p) = self.dialing.remove(&node_id) {
            Some(p)
        } else if let Some(a) = self.allocated.remove(&node_id) {
            // Dropping the allocation releases the churning TURN client (its
            // `Drop` closes the allocation); the advertised relay address dies
            // with it, so prune it from the trickle set too.
            self.advertised.remove(&node_id);
            Some(a.peer)
        } else {
            None
        };
        match peer_cfg {
            Some(peer) => {
                self.roles.insert(node_id, RelayStrategy::Derp);
                self.derping.insert(node_id, peer);
            }
            None if self.derping.contains_key(&node_id) => {
                self.roles.insert(node_id, RelayStrategy::Derp);
            }
            None => return None, // stamp-only: pin governs the next cycle
        }
        self.try_build_derp(&node_id)
    }

    /// #27 — FOLLOW a peer that is already relaying to us over DERP.
    ///
    /// The trigger is an inbound `/derp` frame we could not route (see
    /// `DerpMux::deliver`): a peer only relays once it has DEMOTED, so such a
    /// frame means our side is still on a carrier the peer has abandoned.
    /// Measured 2026-08-24: without this the far end sat on a dead direct
    /// carrier for **67 s** — it had no netstate Major of its own, so it waited
    /// out `POKE_SILENCE_AFTER` (floored by the ~25 s WG keepalive) plus its
    /// tier deadline — and the pair was 100 % dark in BOTH directions for the
    /// whole time, since our replies went out the abandoned path.
    ///
    /// Deliberately NOT [`force_derp`](Self::force_derp), whose semantics are a
    /// server escalation: that one pins a TTL and overrides `roles`, which
    /// would outlive the transient condition and keep the pair on DERP after
    /// the network settled. This only reconciles the peer's slot into `derping`
    /// and builds — the relay STRATEGY is left alone, and the direct re-upgrade
    /// (make-before-break) is untouched, so a pair that can go direct again
    /// still does.
    ///
    /// `None` (no carrier built) when the peer can't speak DERP, when no mux
    /// serves it, or when that mux's WS is currently down — the ordinary walk
    /// picks it up once the mux is back.
    pub fn follow_peer_to_derp(
        &mut self,
        node_id: ObjectId,
        peer: PeerConfig,
    ) -> Option<ReadyLink> {
        if !peer.supports_derp {
            return None;
        }
        // Decide BEFORE mutating: a follow that is going to be withheld must
        // leave the coordinator exactly as it found it. Seeding `derping` and
        // then failing would park an INSTALLED peer in a tracking slot, which
        // is the rc.412 starvation shape (`request` early-returns on
        // `is_tracking`) — survivable today only because `build_floor` decides
        // alone since rc.416, and not worth re-creating.
        if !self.mux_for(&node_id).is_some_and(|m| m.is_alive()) {
            return None;
        }
        // Same slot reconciliation as `force_derp` — a peer mid-coordination
        // must not keep a TURN slot that would race the DERP build. Dropping
        // `allocated` releases the TURN client (its `Drop` closes the
        // allocation), so its advertised address must go with it.
        let slot = if let Some(pp) = self.pending.remove(&node_id) {
            Some(pp.peer)
        } else if let Some(p) = self.dialing.remove(&node_id) {
            Some(p)
        } else if let Some(a) = self.allocated.remove(&node_id) {
            self.advertised.remove(&node_id);
            Some(a.peer)
        } else {
            None
        };
        match slot {
            Some(p) => {
                self.derping.insert(node_id, p);
            }
            // Already coordinating a DERP link — the build below is the same
            // carrier, delivered now rather than when the trickle arrives.
            None if self.derping.contains_key(&node_id) => {}
            // The ordinary case this exists for: the peer holds NO relay slot
            // because we have it on a DIRECT carrier that looks healthy from
            // here. Seed the slot from the netmap.
            None => {
                self.derping.insert(node_id, peer);
            }
        }
        self.try_build_derp(&node_id)
    }

    /// v1 single-relay role for this peer, or `None` for the both-allocate path:
    /// single-relay is off on our side, the peer didn't advertise support, or
    /// neither end can be the raw-UDP dialer.
    ///
    /// `Some(true)` = ANCHOR (allocate the one relay — over UDP, or the TURNS/TCP
    /// Tier-3 fallback if we're UDP-blocked — advertise `R`, QUIC-serve);
    /// `Some(false)` = DIALER (no allocation, raw-UDP-dial the anchor's `R`,
    /// QUIC-connect).
    ///
    /// **The DIALER must be UDP-capable** (its raw socket sends straight to
    /// coturn), while the ANCHOR only needs an allocation, which coturn grants
    /// over TURNS/TCP too. So the role is chosen by UDP capability first, pubkey
    /// only as a tie-break — this is what lets a UDP-blocked corp host (e.g. one
    /// behind a TLS-inspecting VPN) reach a UDP-capable peer: the corp host
    /// anchors over TCP:443, the peer raw-dials, and coturn bridges the two legs.
    /// Both ends read the same `(udp_ok_a, udp_ok_b)` — our own from the srflx
    /// gather, the peer's from `srflx_endpoints` in the netmap — so the decision
    /// is symmetric with no extra wire:
    /// * we UDP-OK, peer UDP-blocked → peer anchors, WE dial → `Some(false)`
    /// * we UDP-blocked, peer UDP-OK → WE anchor → `Some(true)`
    /// * both UDP-OK → smaller pubkey anchors (deterministic tie-break)
    /// * both UDP-blocked → no raw-UDP dialer exists → `None` (single-relay can't
    ///   carry this pair; it falls through to both-allocate today, DERP later)
    fn single_relay_role(&self, node_id: &ObjectId, peer: &PeerConfig) -> Option<bool> {
        match self.relay_strategy(node_id, peer) {
            RelayStrategy::SingleRelay(anchor) => Some(anchor),
            _ => None,
        }
    }

    /// The relay carrier tier for this peer: single-relay (with anchor/dialer
    /// role), DERP, or the both-allocate fall-through.
    ///
    /// Single-relay wins when both ends advertise it AND ≥1 side is UDP-capable
    /// (a raw-UDP dialer must exist). If neither side is UDP-capable — the
    /// `(false, false)` arm — single-relay CAN'T carry the pair (two anchors, no
    /// dialer), and we fall to **DERP** when both ends advertise `supports_derp`,
    /// our `OVERLAY_DERP` flag is on, and our `/derp` WS (`derp_mux`) is up.
    /// Everything else is both-allocate. Both ends read the same symmetric inputs
    /// (our UDP-capability from the srflx gather, the peer's from its
    /// `srflx_endpoints`), so they always agree on the tier.
    fn relay_strategy(&self, node_id: &ObjectId, peer: &PeerConfig) -> RelayStrategy {
        // P7 — a server force-DERP pin wins over every capability-derived
        // tier while unexpired (checked FIRST so the strategy-flip recompute
        // in `maybe_complete` can't thrash a pinned pair back onto the
        // broken TURN tier). Still gated on the peer's `supports_derp` and a
        // live mux — the server only escalates when both ends advertised
        // support, so these normally hold; they keep a stale pin harmless.
        if self.forced_derp_active(node_id) && self.mux_for(node_id).is_some() && peer.supports_derp
        {
            return RelayStrategy::Derp;
        }
        // FR-19 P4b — a live org-relay session for this pair is the answer,
        // ahead of the server's netmap stamp: both ends hold the same session,
        // so this is symmetric without the wire, and the stamp only changes on
        // the next netmap event. Gated on the local flag so a build with
        // `overlay_org_relay` off ignores any session it is pushed (it never
        // advertised `supports_org_relay`, so it is pushed none — belt and
        // braces against a server bug, never a black hole).
        if self.org_relay
            && self
                .org_sessions
                .get(node_id)
                .is_some_and(|s| s.is_live(Instant::now()))
        {
            return RelayStrategy::OrgRelay;
        }
        // U2 — a server-computed verdict is authoritative, taken verbatim.
        // Checked AFTER the local force-DERP pin (a live `OverlayForceDerp`
        // push the server may still send during a mixed transition wins over
        // a possibly-stale netmap verdict; once the pin is set the server's
        // own verdict is `Derp` anyway, so they agree outside the skew
        // window). Gated on BOTH our own opt-in AND the presence of a stamp —
        // and the server only stamps when the PEER is also flagged, so the
        // both-ends requirement holds without us re-checking the peer's cap.
        if self.server_strategy
            && let Some(w) = peer.relay_strategy
        {
            match w {
                RelayStrategyWire::SingleRelayAnchor => return RelayStrategy::SingleRelay(true),
                RelayStrategyWire::SingleRelayDialer => return RelayStrategy::SingleRelay(false),
                RelayStrategyWire::Derp => return RelayStrategy::Derp,
                RelayStrategyWire::BothAllocate => return RelayStrategy::BothAllocate,
                // FR-19 — an org-relay verdict. This build cannot ride one yet
                // (the client carrier is P4), so it is treated exactly as an
                // ABSENT verdict: fall through to the local derivation below.
                // The server only stamps this for a peer whose join advertised
                // `supports_org_relay`, which this build never does, so the arm
                // is reachable only through a server bug — and the right answer
                // to a server bug is the pre-FR-19 behaviour, never a panic and
                // never a black hole.
                RelayStrategyWire::OrgRelay => {}
            }
        }
        // B3 — MEASURED capability supersedes every derived input, but only
        // when BOTH ends carry a fresh relay-band bit: ours from the local
        // netcheck slot (freshness-gated at the runtime sync), the peer's
        // from the netmap (freshness-gated by the server). One-sided
        // measurement keeps the legacy rules — the same both-ends symmetry
        // discipline as the honesty latch below, so a mixed pair can never
        // split roles. The measured bit is the probe over the EXACT
        // single-relay dial path, strictly stronger than any srflx/latch
        // inference — no srflx ANDing on this branch by design (a dialer
        // needs no srflx to dial; srflx was only ever the proxy).
        let (my_udp_ok, peer_udp_ok) =
            if let (Some(mine), Some(theirs)) = (self.my_relay_band_udp, peer.relay_band_udp) {
                (mine, theirs)
            } else {
                // Dialer honesty (legacy inputs) — a srflx candidate only proves
                // UDP to a WELL-KNOWN port; the DIALER role needs raw UDP to the
                // coturn relay band. Fold the honest verdicts in, gated on the
                // PEER carrying the field at all (`None` = pre-honesty peer ⇒
                // BOTH ends keep the srflx-only inputs — field presence is the
                // capability signal).
                let honest = peer.udp_dialer_ok.is_some();
                (
                    self.my_udp_relay_ok && (self.my_udp_dialer_ok || !honest),
                    !peer.srflx_endpoints.is_empty() && peer.udp_dialer_ok.unwrap_or(true),
                )
            };
        if self.single_relay && peer.supports_relay_single {
            match (my_udp_ok, peer_udp_ok) {
                (true, false) => return RelayStrategy::SingleRelay(false), // peer blocked → it anchors, we dial
                (false, true) => return RelayStrategy::SingleRelay(true), // we're blocked → we anchor
                (true, true) => {
                    return RelayStrategy::SingleRelay(self.my_public_key < peer.public_key);
                } // tie-break
                (false, false) => {} // neither can raw-UDP-dial → try DERP below
            }
        }
        // DERP — the ONLY tier that serves a both-UDP-blocked pair. Keyed on
        // the RAW srflx signals, NOT the honesty-adjusted ones: the lazy
        // `/derp` mux opens only when a node's own srflx gather is empty, so
        // "srflx-empty on both ends" is the exact condition under which both
        // ends hold muxes and compute Derp symmetrically. Routing a LATCHED
        // (srflx-present) host here split strategies in the rc.393 storm —
        // the latched end has no mux ⇒ it fell to BothAllocate while its
        // mux-holding peer parked in `derping` ⇒ deadlocked "blocked" pairs.
        // A latched host doesn't need DERP anyway: both-allocate rides its
        // client→:3478 socket, which is precisely what still works on such
        // egresses.
        if self.derp
            && self.mux_for(node_id).is_some()
            && peer.supports_derp
            && !self.my_udp_relay_ok
            && peer.srflx_endpoints.is_empty()
        {
            return RelayStrategy::Derp;
        }
        RelayStrategy::BothAllocate
    }

    /// An **established** DERP link whose strategy inputs have since changed:
    /// the pair should be re-established on a better relay tier.
    ///
    /// `maybe_complete`'s flip-recompute only runs while `is_tracking`, and
    /// `try_build_derp` drops the peer from `derping` the moment the link is
    /// BUILT — so a DERP carrier established while both ends looked UDP-blocked
    /// was frozen there for the life of the link. That is exactly what the
    /// fleet hit on 2026-08-06: coturn had been answering STUN with `TTL=1`, so
    /// every node gathered an empty `srflx_endpoints` and every pair read as
    /// both-UDP-blocked ⇒ DERP. Once the TTL fix restored srflx, pairs with a
    /// public reflexive address on BOTH ends stayed on DERP indefinitely,
    /// because nothing re-asked the question after the link was up.
    ///
    /// `roles` survives the build (only `forget` clears it), so it still holds
    /// the strategy the link was established with — that is the comparison
    /// point. A force-DERP pin keeps this false for free: `relay_strategy`
    /// checks the pin FIRST and keeps returning `Derp`.
    ///
    /// ⚠️ The regrade is **break-before-make** (same as the P7 force-DERP
    /// teardown/rebuild it mirrors): the caller drops a WORKING carrier to
    /// rebuild it on the new tier. Hence the cooldown, and hence the caller's
    /// requirement that no direct probe be in flight — a pair that oscillates
    /// must cost at most one disturbance per [`DERP_REGRADE_COOLDOWN`].
    pub fn derp_regrade_due(
        &mut self,
        node_id: &ObjectId,
        peer: &PeerConfig,
        now: Instant,
    ) -> bool {
        // Established ON Derp, and not mid-establishment (the tracked window
        // belongs to `maybe_complete`'s recompute, which heals it in place).
        if self.roles.get(node_id) != Some(&RelayStrategy::Derp) || self.is_tracking(node_id) {
            return false;
        }
        if matches!(self.relay_strategy(node_id, peer), RelayStrategy::Derp) {
            return false;
        }
        // Evidence gate. `relay_strategy` already says a better tier exists —
        // but it said that last time too, and the server overruled us. Retrying
        // on a timer alone is a guess: if nothing about the pair has changed,
        // the attempt can only fail again and cost the carrier a second
        // disturbance. So a peer with strikes must show NEW EVIDENCE.
        let fp = strategy_fingerprint(
            self.my_udp_relay_ok,
            self.my_udp_dialer_ok,
            self.my_relay_band_udp,
            peer,
        );
        let evidence_changed = self
            .derp_regrade_inputs
            .get(node_id)
            .is_some_and(|&prev| prev != fp);
        let since_fired = self
            .derp_regrade_fired_at
            .get(node_id)
            .map(|&t| now.saturating_duration_since(t));
        // Absolute floor — fresh evidence must never let a flapping srflx
        // churn the carrier faster than the base cooldown.
        if since_fired.is_some_and(|d| d < DERP_REGRADE_COOLDOWN) {
            return false;
        }
        if self.derp_regrade_strikes.contains_key(node_id)
            && !evidence_changed
            && since_fired.is_some_and(|d| d < REGRADE_EVIDENCE_CEILING)
        {
            return false;
        }
        // The backoff timer still governs, but NEW EVIDENCE supersedes it: a
        // pair whose srflx just appeared should not sit out yesterday's 24 h
        // penalty for a failure that no longer describes it.
        if !evidence_changed && self.derp_regrade_at.get(node_id).is_some_and(|&t| now < t) {
            return false;
        }
        // `derp_regrade_last` means "a regrade is awaiting judgement": an
        // overrule CONSUMES it (guilty), so an entry still here once the
        // attribution window has passed was acquitted — that regrade held, and
        // the peer starts fresh. Otherwise a pair that recovers (its network
        // changed) would stay stuck on yesterday's backoff forever.
        //
        // Judging on age ALONE would be wrong: after a strike the next attempt
        // is deliberately far in the future, so every overruled regrade would
        // also look "old" by the time we asked again and would silently reset
        // its own strike — the backoff could never escalate past 1.
        if self
            .derp_regrade_last
            .remove(node_id)
            .is_some_and(|t| now.saturating_duration_since(t) > REGRADE_OVERRULE_WINDOW)
        {
            self.derp_regrade_strikes.remove(node_id);
        }
        let wait = match self.derp_regrade_strikes.get(node_id) {
            Some(&s) => REGRADE_BACKOFF[s.min(REGRADE_BACKOFF.len() - 1)],
            None => DERP_REGRADE_COOLDOWN,
        };
        self.derp_regrade_at.insert(*node_id, now + wait);
        self.derp_regrade_last.insert(*node_id, now);
        self.derp_regrade_inputs.insert(*node_id, fp);
        self.derp_regrade_fired_at.insert(*node_id, now);
        true
    }

    /// The server force-pinned a pair to DERP right after we re-graded it off
    /// DERP — i.e. the tier we moved it to churned, and the server's P7
    /// escalation overruled us. Book a strike so the next attempt for this peer
    /// waits [`REGRADE_BACKOFF`] rather than the flat cooldown.
    ///
    /// Without this the two mechanisms fight forever: the pin (1800 s) outlives
    /// the 600 s cooldown, so the instant it lapses the regrade re-fires,
    /// re-churns, and is re-pinned — a ~30-minute cycle that makes a pair which
    /// was STABLE on DERP permanently unstable. Field-observed on DEVBOX
    /// (devbox-wsl, regal, corplap-3) within an hour of the rc.314 rollout.
    ///
    /// Called from [`force_derp`](Self::force_derp), which is the only place a
    /// pin is applied; a pin for a peer we did NOT just regrade is left alone.
    fn note_regrade_overruled(&mut self, node_id: &ObjectId, now: Instant) {
        if self
            .derp_regrade_last
            .get(node_id)
            .is_none_or(|&t| now.saturating_duration_since(t) > REGRADE_OVERRULE_WINDOW)
        {
            return;
        }
        // Consume the pending judgement — this regrade is convicted, so it
        // must not later be mistaken for one that held (see `derp_regrade_due`).
        self.derp_regrade_last.remove(node_id);
        let strikes = self.derp_regrade_strikes.entry(*node_id).or_insert(0);
        let idx = (*strikes).min(REGRADE_BACKOFF.len() - 1);
        let wait = REGRADE_BACKOFF[idx];
        *strikes = strikes.saturating_add(1);
        let strikes = *strikes;
        self.derp_regrade_at.insert(*node_id, now + wait);
        info!(
            peer = %node_id, strikes, backoff_s = wait.as_secs(),
            "overlay relay: server overruled our DERP regrade — backing off before retrying this pair"
        );
    }

    /// rc.307 (B) — the control-WS died between a relay REQUEST and its
    /// GRANT: the grant is gone forever, and `is_tracking` (pending counts)
    /// would dedupe every later request for the pair — a permanent park now
    /// that the coordinator OUTLIVES sessions. Called from the runtime's
    /// `Reattach` arm; the next netmap/sweep re-requests cleanly. Entries
    /// WITH creds are left alone — those have an (in-flight or complete)
    /// allocation the alloc-queue epoch guard already owns.
    pub fn forget_ungranted_pending(&mut self) -> usize {
        let stale: Vec<ObjectId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.ice.is_none())
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            self.pending.remove(id);
        }
        stale.len()
    }

    /// LAN endpoints ∪ every current relay address — the full candidate set the
    /// server should store (it replaces on each trickle, so LAN must be here).
    pub(crate) fn all_endpoints(&self) -> Vec<String> {
        let mut eps = self.lan_endpoints.clone();
        eps.extend(self.advertised.values().cloned());
        eps
    }

    /// Already coordinating a link to this peer (pending, allocated, or a
    /// single-relay dialer awaiting the anchor's `R`)?
    pub fn is_tracking(&self, node_id: &ObjectId) -> bool {
        self.pending.contains_key(node_id)
            || self.allocated.contains_key(node_id)
            || self.dialing.contains_key(node_id)
            || self.derping.contains_key(node_id)
            || self.org_binding.contains(node_id)
    }

    /// Query only the ORG mint path, gated by fresh metadata in the runtime.
    /// Neither the installed DERP carrier nor legacy TURN pending is changed.
    pub(crate) async fn request_org_fallback(&mut self, peer: ObjectId, now: Instant) -> bool {
        if !self.org_relay
            || self.forced_derp_active(&peer)
            || self.pending.contains_key(&peer)
            || self.org_binding.contains(&peer)
            || self
                .death_streaks
                .get(&peer)
                .is_some_and(|(streak, until)| {
                    relay_death_backoff(*streak).is_some() && now < *until
                })
        {
            return false;
        }
        self.org_fallback_last
            .retain(|_, at| now.saturating_duration_since(*at) < ORG_FALLBACK_RETENTION);
        if self
            .org_fallback_last
            .get(&peer)
            .is_some_and(|at| now.saturating_duration_since(*at) < ORG_FALLBACK_GAP)
        {
            return false;
        }
        if !self.org_fallback_last.contains_key(&peer)
            && self.org_fallback_last.len() >= ORG_FALLBACK_MAX_PEERS
        {
            // Never evict a live cooldown. A cooled oldest entry can safely
            // yield to a previously unseen peer without a 120s starvation gap.
            let oldest = self
                .org_fallback_last
                .iter()
                .filter(|(_, at)| now.saturating_duration_since(**at) >= ORG_FALLBACK_GAP)
                .min_by_key(|(id, at)| (**at, **id))
                .map(|(id, _)| *id);
            let Some(oldest) = oldest else {
                return false;
            };
            self.org_fallback_last.remove(&oldest);
        }
        let Some(request_id) = self.org_fallback_serial.checked_add(1) else {
            return false;
        };
        self.org_fallback_serial = request_id;
        self.org_fallback_last.insert(peer, now);
        let sent = matches!(
            tokio::time::timeout(
                Duration::from_millis(10),
                self.outbound
                    .send(ClientMsg::OverlayOrgRelayFallbackRequest {
                        peer_node_id: peer,
                        request_id
                    })
            )
            .await,
            Ok(Ok(()))
        );
        if sent {
            self.org_fallback_cursor = Some(peer);
            // A live lease can outlast its failed carrier. A real server reply
            // may rebind the same immutable lease without extending its TTL.
            self.drop_org_session(&peer);
            info!(peer=%peer,request_id,"overlay relay: ORG-only fallback requested while retaining DERP");
        }
        sent
    }

    /// Continue after the last queued peer so a bounded cooldown table does
    /// not let a stable traversal refresh the same first 64 peers forever.
    pub(crate) async fn request_org_fallback_batch(
        &mut self,
        mut peers: Vec<ObjectId>,
        now: Instant,
    ) -> Vec<ObjectId> {
        let cursor = self.org_fallback_cursor;
        peers.sort_unstable_by_key(|id| (cursor.is_some_and(|last| *id <= last), *id));
        peers.dedup();
        let mut sent = Vec::new();
        for peer in peers {
            if self.request_org_fallback(peer, now).await { sent.push(peer); }
        }
        sent
    }

    pub(crate) fn org_relay_pinned(&self, peer: &ObjectId) -> bool {
        self.forced_derp_active(peer)
    }

    /// Kick off a relay link. The strategy decides the mechanics:
    ///
    /// - **single-relay DIALER** (larger-pubkey / UDP-capable-vs-blocked-peer):
    ///   allocates NOTHING, needs no creds — just tracked; `maybe_complete`
    ///   builds its raw carrier once the anchor advertises `R`.
    /// - **DERP** (both UDP-blocked): allocates NOTHING and makes NO server
    ///   round-trip — both ends dial the `/derp` WS; tracked, then built
    ///   symmetrically off `derp_mux`.
    /// - **single-relay ANCHOR / both-allocate**: asks the server for coturn
    ///   creds + the `pair_key`.
    pub async fn request(&mut self, node_id: ObjectId, peer: PeerConfig) {
        if self.is_tracking(&node_id) {
            return;
        }
        // Unresponsive-peer backoff — held peers are skipped (the refresh
        // evidence stays stashed for the eventual real request). Only OUR
        // initiations defer; a server-pushed grant for a peer-initiated pair
        // never passes through here, so a waking peer pairs immediately.
        if let Some((streak, until)) = self.death_streaks.get(&node_id)
            && relay_death_backoff(*streak).is_some()
            && *until > Instant::now()
        {
            debug!(
                peer = %node_id, streak,
                "overlay relay: re-request held (unresponsive-peer backoff)"
            );
            return;
        }
        // U1 — consume the one-shot refresh evidence UNCONDITIONALLY (the
        // no-wire strategies below send nothing, and stale evidence must not
        // linger to be replayed by a later, unrelated request).
        let refresh = self.refresh_ctx.remove(&node_id);
        // Compute the strategy ONCE and remember it, so `maybe_complete` can
        // detect a later flip (the peer's srflx propagating) and re-establish —
        // see `roles`.
        let strat = self.relay_strategy(&node_id, &peer);
        match strat {
            RelayStrategy::SingleRelay(false) => {
                debug!(peer = %node_id, "overlay relay: single-relay dialer — awaiting anchor R (no alloc, no creds)");
                self.roles.insert(node_id, strat);
                self.dialing.insert(node_id, peer);
                return;
            }
            RelayStrategy::Derp => {
                debug!(peer = %node_id, "overlay relay: DERP link (both UDP-blocked) — no alloc, no creds");
                self.roles.insert(node_id, strat);
                self.derping.insert(node_id, peer);
                return;
            }
            RelayStrategy::OrgRelay => {
                debug!(peer = %node_id,
                    "overlay relay: org-relay session minted — binding at the tenant relay (no alloc, no creds)");
                self.org_request_bind(node_id, peer);
                return;
            }
            RelayStrategy::SingleRelay(true) | RelayStrategy::BothAllocate => {}
        }
        // U1 — attach the refresh evidence + the sticky mux-failure flag.
        let (current_kind, reason) = match refresh {
            Some((kind, reason)) => (
                kind.map(|k| {
                    match k {
                        RelayKind::Turn => "turn",
                        RelayKind::Derp => "derp",
                        RelayKind::Org => "org",
                    }
                    .to_string()
                }),
                Some(reason.to_string()),
            ),
            None => (None, None),
        };
        // C4 stage 2 (PR-B) — single-relay ANCHOR with a live warm leg: commit
        // the standing allocation NOW instead of the request→grant→allocate
        // round-trips (each of which can take seconds — or forever, when this
        // host's control WS is what a VPN capture just killed). Anchor-only:
        // the anchor's `try_build` dials the peer's srflx, so the leg's worker
        // never has to match a pair-key pin (both-allocate's `try_build`
        // requires the peer's allocation on OUR worker, and the warm leg is
        // deliberately un-pinned — fast-committing it there would withhold
        // forever). Single-pair gate per the `warm_committed` field doc.
        if strat == RelayStrategy::SingleRelay(true)
            && self.warm_committed.is_none()
            && let Some(conn) = self.warm_leg.clone()
        {
            // PR-B2 (field 2026-08-16, winhost-b↔corplap) — the server must still
            // SEE this establishment: P7's force-DERP escalation counts relay
            // requests, and a fast path that skips the wire made a churning
            // pair (dialer whose corp egress drops raw UDP to ephemeral relay
            // ports — it can never reach ANY anchor R) invisible, so it
            // looped on the broken tier forever instead of being pinned to
            // DERP. Fire-and-forget: the commit below never waits on the
            // grant, which arrives for a peer that never enters `pending`
            // and is dropped by `grant_accept` harmlessly. A failed send
            // (detached WS — the VPN-capture case) changes nothing: the leg
            // works without the server.
            let _ = self
                .outbound
                .send(ClientMsg::OverlayRelayRequest {
                    peer_node_id: node_id,
                    current_kind,
                    reason,
                    derp_mux_failed: self.derp_evidence_failed(),
                })
                .await;
            self.roles.insert(node_id, strat);
            if let Ok(own) = conn.local_addr() {
                info!(peer = %node_id, %own,
                      "overlay relay: warm leg committed as the anchor allocation (no round-trips)");
                self.advertised.insert(node_id, own.to_string());
                let _ = self
                    .outbound
                    .send(ClientMsg::OverlayEndpoints {
                        candidates: self.all_endpoints(),
                    })
                    .await;
            }
            // Straight into `allocated` — NOT via `commit_alloc`, whose
            // `try_build` would hand the ReadyLink back to US; every call
            // site follows `request` with `maybe_complete`, which builds
            // from `allocated` and installs it.
            self.allocated.insert(node_id, Allocated { conn, peer });
            self.warm_committed = Some(node_id);
            return;
        }
        if self
            .outbound
            .send(ClientMsg::OverlayRelayRequest {
                peer_node_id: node_id,
                current_kind,
                reason,
                derp_mux_failed: self.derp_evidence_failed(),
            })
            .await
            .is_err()
        {
            // rc.307 (B): while DETACHED (session died, reattach pending)
            // the 5 s sweep hits this for every relay peer every tick — log
            // the transition once, not thousands of lines per outage.
            if !self.warned_detached {
                self.warned_detached = true;
                warn!(peer = %node_id, "overlay relay: control channel closed; requests paused until reattach");
            }
            return;
        }
        self.warned_detached = false;
        self.roles.insert(node_id, strat);
        self.pending.insert(
            node_id,
            PendingPeer {
                peer,
                ice: None,
                pair_key: None,
            },
        );
        debug!(peer = %node_id, "overlay relay: requested coturn creds");
    }

    /// Got coturn creds + `pair_key` — the SYNC half of the old `on_grant`
    /// (rc.218). Stash them into the pending slot and return the inputs the
    /// runtime needs to run [`allocate_for_pair`] OFF-LOOP (the DNS + TURN
    /// allocate takes seconds on a hostile corp path — winhost-a's rc.213-216
    /// logs still showed `stalled the data plane` from exactly this await).
    /// `None` for a grant we never requested (or already tore down). The peer
    /// STAYS in `pending` while the spawned allocate runs, so `is_tracking`
    /// keeps deduping re-requests; [`commit_alloc`] (success) or a
    /// [`forget`](Self::forget) on failure resolves it.
    pub fn grant_accept(
        &mut self,
        node_id: ObjectId,
        ice_servers: Vec<IceServer>,
        pair_key: String,
    ) -> Option<(Vec<IceServer>, String)> {
        let pp = self.pending.get_mut(&node_id)?;
        pp.ice = Some(ice_servers.clone());
        pp.pair_key = Some(pair_key.clone());
        Some((ice_servers, pair_key))
    }

    /// Commit a finished off-loop allocate (rc.218): advertise our relayed
    /// address (the `OverlayEndpoints` trickle reads coordinator state, so this
    /// half MUST run on-loop), move the peer to `allocated`, and try to build.
    /// `None` (dropping the allocation — it idles out at coturn's TTL) when the
    /// peer left `pending` mid-allocate: a strategy flip or teardown raced the
    /// spawned task; the runtime's epoch guard already drops the
    /// forget→re-request ABA case before this is called.
    pub async fn commit_alloc(
        &mut self,
        node_id: ObjectId,
        conn: Arc<dyn RelayConn>,
    ) -> Option<ReadyLink> {
        let peer = self.pending.get(&node_id)?.peer.clone();
        if let Ok(own) = conn.local_addr() {
            info!(peer = %node_id, %own, "overlay relay: allocated");
            // Per-peer (not append-only) so this replaces any prior relay we
            // allocated for the same peer across a churn cycle — see the
            // `advertised` field doc. A peer reads `endpoints[0]`, so a stale
            // relay must never outlive its allocation here.
            self.advertised.insert(node_id, own.to_string());
            let _ = self
                .outbound
                .send(ClientMsg::OverlayEndpoints {
                    candidates: self.all_endpoints(),
                })
                .await;
        }
        self.pending.remove(&node_id);
        self.allocated.insert(node_id, Allocated { conn, peer });
        self.try_build(&node_id)
    }

    /// A fresh netmap view arrived. Refresh the peer config; if we've already
    /// allocated, the peer's relayed address may now be known — build.
    pub fn maybe_complete(&mut self, node_id: ObjectId, peer: &PeerConfig) -> Option<ReadyLink> {
        // Phase D — the single-relay role can FLIP after we commit: the peer's
        // `srflx_endpoints` (its UDP-capable signal) arrive on a later trickle
        // than its join, so during that window a UDP-capable peer looks
        // UDP-blocked and both ends can pick "dialer" → deadlock. If the fresh
        // role differs from the one we tracked, drop the link; the caller's
        // `!is_tracking` path then re-`request`s it with the correct role.
        if self.is_tracking(&node_id) {
            let fresh = self.relay_strategy(&node_id, peer);
            if self.roles.get(&node_id) != Some(&fresh) {
                debug!(peer = %node_id, ?fresh, "overlay relay: strategy changed (srflx settled) — re-establishing");
                self.forget(&node_id);
                return None;
            }
        }
        // Phase D (DERP) — both-UDP-blocked link: build the symmetric DERP
        // carrier off our `/derp` WS. No allocation, no server round-trip.
        if let Some(slot) = self.derping.get_mut(&node_id) {
            *slot = peer.clone();
            return self.try_build_derp(&node_id);
        }
        // Phase D — a single-relay DIALER holds no allocation: build the raw
        // carrier to the anchor's `R` the moment it appears in the netmap.
        if let Some(slot) = self.dialing.get_mut(&node_id) {
            *slot = peer.clone();
            return self.try_build_dialer(&node_id);
        }
        // FR-19 P4b — keep the config the org link will be built from fresh.
        if let Some(p) = self.org_peers.get_mut(&node_id) {
            *p = peer.clone();
        }
        if let Some(a) = self.allocated.get_mut(&node_id) {
            a.peer = peer.clone();
            return self.try_build(&node_id);
        }
        if let Some(pp) = self.pending.get_mut(&node_id) {
            pp.peer = peer.clone();
        }
        None
    }

    /// The spawnable allocate phase (rc.218): deterministic same-worker pick
    /// (both ends derive the identical worker from the shared `pair_key`, with
    /// NO dependence on the peer's racy advertised endpoint) + the TURN
    /// allocate. Needs nothing from the coordinator — only the grant's creds —
    /// so the runtime runs it in a `tokio::spawn` and the steady loop never
    /// waits on DNS or coturn (UDP 5 s → TURNS/TCP 6 s caps per candidate on a
    /// hostile corp path).
    pub(crate) async fn allocate_for_pair(
        ice: &[IceServer],
        pair_key: &str,
    ) -> Option<Arc<dyn RelayConn>> {
        // Deterministic same-worker pick: both ends derive the identical
        // worker from the shared pair_key.
        let pin = pick_worker(pair_key, ice).await;
        let conn = Self::allocate_pinned(ice, pin).await;
        if conn.is_some() {
            debug!(
                pinned = pin.is_some(),
                "overlay relay: off-loop allocate finished"
            );
        }
        conn
    }

    /// Allocate a coturn relay. With `pin = Some(ip)` that worker is tried
    /// first (UDP, then TURNS/TCP for UDP-blocked corp hosts), so the
    /// relay-to-relay path becomes an intra-worker hairpin.
    ///
    /// Associated (no `&self`, rc.218) so the spawned [`allocate_for_pair`]
    /// can run it without touching coordinator state.
    async fn allocate_pinned(ice: &[IceServer], pin: Option<IpAddr>) -> Option<Arc<dyn RelayConn>> {
        let (urls, user, cred) = turn_creds(ice)?;
        // rc.276 (B-probe) — `OVERLAY_RELAY_TLS=1` forces every allocation
        // onto the TURNS/TCP tier (the WebRTC-proven corp transport). The
        // UDP worker-pin prepend is skipped too (it's a Tier-2 URL; the
        // TURNS tier stays worker-pinned via the server's `&pin=`).
        let tls_only = super::direct::relay_tls_forced();
        let urls = match pin {
            Some(ip) if !tls_only => {
                let h = if ip.is_ipv6() {
                    format!("[{ip}]")
                } else {
                    ip.to_string()
                };
                // UDP tier only: pin the worker for the Tier-2 intra-worker
                // hairpin. Do NOT prepend a `turns:{ip}` URL — TLS to an IP
                // literal fails coturn's DNS-cert verification (NotValidForName).
                // The TURNS tier is pinned via the server's `&pin=` on its
                // hostname URL (rc.140), which dials this same worker while
                // keeping the SNI valid. The pin dials the grant's own UDP
                // port, not a hardcoded 3478 — regional PoPs may differ.
                let udp_port = roomler_ai_remote_control::turn_url::first_udp_port(
                    ice.iter().flat_map(|s| s.urls.iter()).map(String::as_str),
                );
                let mut pinned = vec![format!("turn:{h}:{udp_port}?transport=udp")];
                pinned.extend(urls);
                pinned
            }
            _ => urls,
        };
        match crate::transport::relay::allocate_relay_from_ice_tiered(&urls, &user, &cred, tls_only)
            .await
        {
            Ok(c) => Some(Arc::new(c) as Arc<dyn RelayConn>),
            Err(e) => {
                warn!(%e, pinned = pin.is_some(), tls_only, "overlay relay: allocate failed");
                None
            }
        }
    }

    /// Build the carrier once we have an allocation AND the peer's RELAYED
    /// address. On success the link leaves `allocated`.
    ///
    /// rc.138 — dial the peer's endpoint on the SAME coturn worker we
    /// allocated on (the deterministic pin lands both ends on one worker, so
    /// its IP == our relay's local IP), falling back to any other PUBLIC
    /// endpoint. NEVER a private/LAN address: rc.135's netmap unions
    /// `[LAN…, relay]`, and the old "first parseable endpoint" grabbed the
    /// peer's LAN address — which a coturn relay can't reach (and is dead
    /// under Wi-Fi AP isolation / a VPN), so the relay carried nothing
    /// (field: relay-only 100 % loss; VPN fallback leaked to the gateway).
    /// `None` until the peer advertises a relay/public address (retry next
    /// netmap) — we must not dial its LAN address as the "relay".
    fn try_build(&mut self, node_id: &ObjectId) -> Option<ReadyLink> {
        let a = self.allocated.get(node_id)?;
        let single_anchor = self.single_relay_role(node_id, &a.peer) == Some(true);
        let dst: SocketAddr = if single_anchor {
            // Phase D ANCHOR: we hold the ONE allocation; the DIALER runs none
            // and advertises no relay, so dial its public IP — taken from its
            // srflx bucket (Phase C) — purely for the IP-only `\x00` permission
            // `install_ready` opens. The port may be "wrong" under a symmetric
            // NAT: harmless, since the permit is IP-only and `quic_relay`'s
            // server `accept()`s the dialer's REAL connection. WITHHOLD (retry
            // next netmap) until the dialer advertises a srflx — single-relay's
            // anchor therefore depends on Phase C srflx being on for the dialer.
            a.peer
                .srflx_endpoints
                .iter()
                .filter_map(|e| e.parse().ok())
                .find(|s: &SocketAddr| !is_lan_addr(s.ip()))?
        } else {
            // Both-allocate: dial the peer's relayed addr on OUR worker — and
            // ONLY that. WITHHOLD (retry next netmap) until it appears.
            //
            // The old "else any public endpoint" fallback predates the rc.127
            // deterministic worker pin and could grab the peer's HOST public
            // IP as the "relay" dst. Field 2026-07-24: a web-deploy rejoin
            // wiped the peer's relay advert (rehydrate resets `endpoints` to
            // the join's LAN candidates), the fallback dialed the peer's host
            // address as if it were coturn, and the result was an outbound-
            // blackhole ZOMBIE carrier — its rx stayed alive on the peer's
            // healthy inbound leg, so the liveness sweep never cycled it and
            // the pair wedged permanently (which also starved the P7 churn
            // counter of the re-requests it feeds on). Both ends pin to one
            // worker from the shared `pair_key`, so the peer's true relay
            // MUST be on our worker; anything else in `endpoints` is a host
            // address, never a relay. NEVER LAN (see the fn doc).
            let our_worker_ip = a.conn.local_addr().ok().map(|s| s.ip());
            a.peer
                .endpoints
                .iter()
                .filter_map(|e| e.parse().ok())
                .find(|s: &SocketAddr| Some(s.ip()) == our_worker_ip)?
        };
        let extra_permission_targets = if single_anchor {
            extra_srflx_permission_targets(&a.peer.srflx_endpoints, dst.ip())
        } else {
            Vec::new()
        };
        let carrier = Carrier::relay(a.conn.clone(), dst);
        let link = ReadyLink {
            node_id: *node_id,
            public_key: a.peer.public_key,
            overlay_ip: a.peer.overlay_ip,
            carrier,
            relay_parts: Some((a.conn.clone(), dst)),
            extra_permission_targets,
            supports_quic: a.peer.supports_quic,
            single_relay: single_anchor.then_some(true),
            relay_kind: RelayKind::Turn,
            subnets: a.peer.subnets.clone(),
        };
        self.allocated.remove(node_id);
        // A2 — a TURN link supersedes the birth floor (install_ready replaces
        // the carrier; this clears the bookkeeping with it).
        self.floored.remove(node_id);
        info!(peer = %node_id, %dst, single_relay = single_anchor,
              extra_perms = link.extra_permission_targets.len(),
              "overlay relay: link ready");
        Some(link)
    }

    /// W6 phase-2 — feed the coturn worker IP set (runtime resolves it once
    /// after the first netmap; see `resolve_stun_worker_ips`).
    pub fn set_coturn_ips(&mut self, ips: Vec<IpAddr>) {
        self.coturn_ips = ips;
    }

    /// Phase D DIALER build: we hold NO allocation. Bind a fresh raw socket,
    /// wrap it as a [`UdpRelayConn`](crate::transport::relay::UdpRelayConn), and
    /// dial the anchor's advertised relay `R` — positively identified as a
    /// public endpoint ON A COTURN WORKER (see
    /// [`pick_anchor_relay_endpoint`]). `install_ready` then sends the `\x00`
    /// that opens our NAT toward `R` and QUIC-connects (`am_server = false`
    /// by pubkey). `None` until the anchor advertises `R` (retry next netmap).
    fn try_build_dialer(&mut self, node_id: &ObjectId) -> Option<ReadyLink> {
        let peer = self.dialing.get(node_id)?;
        // Rotation index over an ambiguous multi-R advert = the #496 relay
        // death streak: each failed cycle walks to the next candidate; a
        // completed handshake clears the streak and pins the working R.
        let rotate = self
            .death_streaks
            .get(node_id)
            .map(|(s, _)| *s as usize)
            .unwrap_or(0);
        let r: SocketAddr = pick_anchor_relay_endpoint(
            &peer.endpoints,
            peer.warm_relay_endpoint.as_deref(),
            &self.coturn_ips,
            node_id,
            rotate,
        )?;
        // Fresh raw socket, NO TURN allocation. Bind via std (sync) then adopt
        // into the tokio reactor without awaiting, so this stays on the sync
        // build path (`maybe_complete` is not async).
        let std_sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        std_sock.set_nonblocking(true).ok()?;
        let sock = tokio::net::UdpSocket::from_std(std_sock).ok()?;
        // VPN-bypass: pin the single-relay dialer's egress to the physical
        // uplink so coturn is reached via the real NIC, not a captured VPN.
        if let Some(ix) = crate::overlay::direct::vpn_bypass_ifindex() {
            crate::overlay::direct::force_egress_interface(&sock, ix);
        }
        let conn: Arc<dyn RelayConn> = Arc::new(crate::transport::relay::UdpRelayConn(sock));
        // W6 phase-2 — say which SOURCE the OS picked for the dial: the
        // anchor's coturn permission is IP-scoped to OUR ADVERTISED srflx,
        // and a multi-homed host can route toward R from another of its
        // addresses — coturn then drops the whole dial silently. A
        // throwaway connect() does source selection without sending.
        let src_ip = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .ok()
            .and_then(|p| {
                p.connect(r).ok()?;
                p.local_addr().ok()
            })
            .map(|a| a.ip());
        let carrier = Carrier::relay(conn.clone(), r);
        let link = ReadyLink {
            node_id: *node_id,
            public_key: peer.public_key,
            overlay_ip: peer.overlay_ip,
            carrier,
            relay_parts: Some((conn, r)),
            extra_permission_targets: Vec::new(),
            supports_quic: peer.supports_quic,
            single_relay: Some(false),
            relay_kind: RelayKind::Turn,
            subnets: peer.subnets.clone(),
        };
        self.dialing.remove(node_id);
        // A2 — a dialer link supersedes the birth floor.
        self.floored.remove(node_id);
        info!(peer = %node_id, %r, ?src_ip,
              "overlay relay: single-relay dialer link ready (raw → anchor R)");
        Some(link)
    }

    /// Phase D (DERP) build: we hold NO allocation. Vend a per-peer
    /// [`DerpConn`](crate::transport::derp::DerpConn) off our `/derp` WS demux
    /// and wrap it as a RAW [`Carrier::relay`] — no QUIC (`relay_kind: Derp`
    /// gates it off), no anchor/dialer asymmetry (`single_relay: None`). The
    /// carrier is symmetric: both ends dial out to the relay, and the WG
    /// handshake single-initiator (smaller pubkey) is applied by `install_ready`.
    /// `None` if the DERP WS isn't up (no `derp_mux`).
    fn try_build_derp(&mut self, node_id: &ObjectId) -> Option<ReadyLink> {
        let peer = self.derping.get(node_id)?.clone();
        let mux = self.mux_for(node_id)?;
        // Field 2026-08-15/16 (winhost-a under a Check Point capture): the mux
        // Arc EXISTS while its `/derp` WS is down and slowly reconnecting
        // through the throttled TLS path — and a carrier built over it is born
        // dead, convicts as "one-way" on the next sweep, and rebuilds every
        // ~60 s for as long as the WS stays down (with force-DERP pins active,
        // that loop was the multi-minute blackhole). WITHHOLD instead: the
        // pair stays tracked in `derping`, and the install_peers walk (netmap
        // + the 30 s reupgrade tick) builds it the moment the mux is back.
        if !mux.is_alive() {
            debug!(peer = %node_id,
                   "overlay relay: DERP mux down (reconnecting) — withholding the DERP link");
            return None;
        }
        let derp_conn = mux.conn_for(peer.public_key);
        // A stable synthetic peer addr (the DERP carrier is pubkey-addressed and
        // discards this `dst`; it exists only so the carrier has a consistent
        // remote — and, for a future QUIC-over-DERP path, a valid one).
        let dst = derp_conn.synth_peer();
        let conn: Arc<dyn RelayConn> = Arc::new(derp_conn);
        let carrier = Carrier::relay(conn.clone(), dst);
        let link = ReadyLink {
            node_id: *node_id,
            public_key: peer.public_key,
            overlay_ip: peer.overlay_ip,
            carrier,
            relay_parts: Some((conn, dst)),
            extra_permission_targets: Vec::new(),
            supports_quic: false, // DERP raw v1: never QUIC-over-DERP (A2)
            single_relay: None,   // symmetric — no anchor/dialer role
            relay_kind: RelayKind::Derp,
            subnets: peer.subnets.clone(),
        };
        self.derping.remove(node_id);
        // A strategy-owned DERP link supersedes any floor bookkeeping.
        self.floored.remove(node_id);
        info!(peer = %node_id, "overlay relay: DERP link ready (raw WG over /derp)");
        Some(link)
    }

    // ─── FR-19 P4b — org-relay sessions, the member's side ─────────────────

    /// The server minted (or re-pushed) an org-relay session for `peer`.
    /// Replaces any prior session for that peer — a re-mint after a revoke
    /// carries a new VNI, and a re-push of the SAME session (the server's
    /// idempotent re-request path) is harmless to overwrite. A previous
    /// carrier is closed so the runtime rebuilds onto the new session.
    pub fn org_session_accept(&mut self, peer: ObjectId, session: OrgSession) -> bool {
        // A replay of one immutable minted session is not a replacement.
        // Keep its original lifetime, in-flight bind and already-bound carrier.
        if self.org_sessions.get(&peer).is_some_and(|old| {
            old.vni == session.vni
                && old.generation == session.generation
                && old.relay_node_id == session.relay_node_id
                && old.endpoints == session.endpoints
                && old.is_live(Instant::now())
        }) {
            return false;
        }
        if let Some(old) = self.org_sessions.insert(peer, session)
            && let Some(conn) = old.conn
        {
            conn.close();
        }
        self.org_binding.remove(&peer);
        self.org_jobs.retain(|j| j.node_id != peer);
        true
    }

    /// `rc:overlay.relay_revoke` — drop the session with this VNI, closing its
    /// carrier so the dead latch fires and the sweep re-coordinates the pair
    /// onto TURN/DERP (the strategy no longer answers `OrgRelay`). Returns
    /// the peer it belonged to.
    pub fn org_session_revoke(&mut self, vni: u32) -> Option<ObjectId> {
        let peer = *self.org_sessions.iter().find(|(_, s)| s.vni == vni)?.0;
        self.drop_org_session(&peer);
        Some(peer)
    }

    /// The off-loop bind for `peer` failed on every endpoint: the session is
    /// unusable from here. Drop it and forget the pair, so the next request
    /// takes the TURN/DERP path; the server re-mints on a later
    /// `relay_request` if it still wants to.
    pub fn org_bind_failed(&mut self, peer: &ObjectId) {
        self.drop_org_session(peer);
    }

    /// Expire sessions past their absolute lifetime (the member's own clock,
    /// from receipt), closing their carriers. Returns the peers affected.
    pub fn reap_org_sessions(&mut self, now: Instant) -> Vec<ObjectId> {
        let dead: Vec<ObjectId> = self
            .org_sessions
            .iter()
            .filter(|(_, s)| !s.is_live(now))
            .map(|(p, _)| *p)
            .collect();
        for p in &dead {
            self.drop_org_session(p);
        }
        dead
    }

    fn drop_org_session(&mut self, peer: &ObjectId) {
        if let Some(s) = self.org_sessions.remove(peer)
            && let Some(conn) = s.conn
        {
            conn.close();
        }
        self.org_binding.remove(peer);
        self.org_peers.remove(peer);
        self.org_jobs.retain(|j| j.node_id != *peer);
        if self.roles.get(peer) == Some(&RelayStrategy::OrgRelay) {
            self.forget(peer);
        }
    }

    /// Test hook — the production value comes from `OVERLAY_ORG_RELAY`.
    #[cfg(test)]
    pub(crate) fn set_org_relay(&mut self, on: bool) {
        self.org_relay = on;
    }

    /// Binds decided by `request` that the runtime has not spawned yet.
    pub fn take_org_jobs(&mut self) -> Vec<OrgBindJob> {
        std::mem::take(&mut self.org_jobs)
    }

    /// Queue the bind for `peer` — idempotent while one is in flight or a
    /// carrier is already bound on the current session.
    pub fn org_request_bind(&mut self, peer: ObjectId, peer_cfg: PeerConfig) {
        let Some(s) = self.org_sessions.get(&peer) else {
            return;
        };
        if self.org_binding.contains(&peer) || s.conn.is_some() {
            return;
        }
        let job = OrgBindJob {
            peer_public_key: peer_cfg.public_key,
            peer_overlay_ip: peer_cfg.overlay_ip,
            node_id: peer,
            relay_node_id: s.relay_node_id,
            vni: s.vni,
            generation: s.generation,
            endpoints: s.endpoints.clone(),
            secret: s.secret.clone(),
            per_endpoint: per_endpoint_budget(s.bind_budget, s.endpoints.len()),
        };
        self.org_binding.insert(peer);
        self.org_peers.insert(peer, peer_cfg);
        self.roles.insert(peer, RelayStrategy::OrgRelay);
        self.org_jobs.push(job);
    }

    /// Commit a finished off-loop bind (on-loop, µs): wrap the bound conn as a
    /// RAW relay carrier — symmetric, no anchor/dialer role, no QUIC — and
    /// hand it to `install_ready`. `None` if the session was revoked or
    /// superseded while the bind ran (the conn is then closed here).
    pub fn commit_org_bind(
        &mut self,
        peer: ObjectId,
        generation: u64,
        conn: Arc<OrgRelayConn>,
    ) -> Option<ReadyLink> {
        self.org_binding.remove(&peer);
        let Some(s) = self.org_sessions.get_mut(&peer) else {
            conn.close();
            return None;
        };
        if s.vni != conn.vni() || s.generation != generation || !s.is_live(Instant::now()) {
            conn.close();
            return None;
        }
        let Some(peer_cfg) = self.org_peers.get(&peer).cloned() else {
            conn.close();
            return None;
        };
        s.conn = Some(conn.clone());
        let dst = conn.synth_peer();
        let conn_dyn: Arc<dyn RelayConn> = conn;
        let carrier = Carrier::relay(conn_dyn.clone(), dst);
        self.roles.insert(peer, RelayStrategy::OrgRelay);
        info!(peer = %peer, vni = s.vni, relay = %s.relay_node_id,
            "overlay relay: org-relay link ready (raw WG through a tenant relay)");
        Some(ReadyLink {
            node_id: peer,
            public_key: peer_cfg.public_key,
            overlay_ip: peer_cfg.overlay_ip,
            carrier,
            relay_parts: Some((conn_dyn, dst)),
            extra_permission_targets: Vec::new(),
            supports_quic: false,
            single_relay: None,
            relay_kind: RelayKind::Org,
            subnets: peer_cfg.subnets.clone(),
        })
    }

    /// Phase A2 (overlay v3) — build the DERP FLOOR for a fresh pair: an
    /// immediately-installable derp carrier so "reachable but carrier-less"
    /// can't exist wherever wss:/derp works, while the better-tier
    /// coordination runs in parallel and replaces it MBB-ishly via the
    /// normal `install_ready` path.
    ///
    /// Gates, all required: our `overlay_derp_floor` flag; our DERP opt-in;
    /// the PEER advertising BOTH `supports_derp` and `supports_derp_floor`
    /// (a pre-floor peer whose srflx gather succeeded holds no mux and never
    /// registers — a floor toward it would blackhole); a central mux that is
    /// present AND `is_alive()` (the #497 born-dead rule). A withheld floor
    /// returns `None` and the caller falls through to the existing fresh
    /// ladder unchanged — TURNS:443 and wss:/derp are different transports
    /// and corp middleboxes split them, so pair formation must never couple
    /// to `/derp` health.
    pub fn build_floor(&mut self, node_id: ObjectId, peer: &PeerConfig) -> Option<ReadyLink> {
        // rc.413 (#25) — every withhold reason is REPORTED, throttled to one
        // line per peer per reason-change (or per 5 min).
        //
        // This branch was a single `debug!` covering only the WS-down case,
        // which made the whole class invisible at INFO: a peer that stays
        // "blocked" for hours produced NO log explaining why its floor never
        // appeared, so three separate diagnosis rounds had to infer it from
        // peers-table shapes. A carrier-less peer is precisely the state the
        // floor exists to prevent, so the refusal is operator-relevant by
        // definition — see the field wedges on winhost-a / winhost-b / corplap under
        // corp VPN, 2026-08-19.
        let reason = if !self.derp_floor {
            Some("the overlay_derp_floor flag is off on THIS node")
        } else if !self.derp {
            Some("DERP is not enabled on THIS node")
        } else if !peer.supports_derp {
            Some("the PEER does not advertise supports_derp (pre-DERP build?)")
        } else if !peer.supports_derp_floor {
            Some(
                "the PEER does not advertise supports_derp_floor (build predates the floor — it holds no mux, so a floor toward it would blackhole)",
            )
        } else {
            None
        };
        if let Some(reason) = reason {
            self.note_floor_withheld(node_id, 1, reason);
            return None;
        }
        let Some(mux) = self.mux_for(&node_id) else {
            self.note_floor_withheld(
                node_id,
                2,
                "no /derp mux exists for this peer (neither a pinned regional mux nor the central one)",
            );
            return None;
        };
        if !mux.is_alive() {
            // Which mux: a server-pinned REGIONAL relay, or the central one?
            // The distinction matters — a corp VPN can reach one and not the
            // other, and a dead regional mux silently starves every peer
            // pinned to it while central-mux peers stay healthy.
            let pinned = self.forced_urls.get(&node_id).cloned();
            let which = pinned.unwrap_or_else(|| "central".to_string());
            self.note_floor_withheld(
                node_id,
                3,
                &format!("its /derp mux is DOWN (relay={which}); the fresh ladder proceeds"),
            );
            return None;
        }
        let derp_conn = mux.conn_for(peer.public_key);
        let dst = derp_conn.synth_peer();
        let conn: Arc<dyn RelayConn> = Arc::new(derp_conn);
        let carrier = Carrier::relay(conn.clone(), dst);
        let link = ReadyLink {
            node_id,
            public_key: peer.public_key,
            overlay_ip: peer.overlay_ip,
            carrier,
            relay_parts: Some((conn, dst)),
            extra_permission_targets: Vec::new(),
            supports_quic: false,
            single_relay: None,
            relay_kind: RelayKind::Derp,
            subnets: peer.subnets.clone(),
        };
        // rc.416 (#25) — the floor IS this peer's DERP link (same mux, same
        // `conn_for`), so any pending DERP coordination is now satisfied.
        // Leaving the `derping` entry would let `maybe_complete` later build a
        // second, identical link over the same mux for no benefit.
        self.derping.remove(&node_id);
        self.floored.insert(node_id, peer.clone());
        info!(peer = %node_id, "overlay relay: DERP floor installed at birth (better tiers coordinate in parallel)");
        Some(link)
    }

    /// rc.413 (#25) — report a floor refusal, at most one line per peer per
    /// (changed) reason or per 5 minutes. The establish walk re-runs on every
    /// netmap delta and sweep, so an unthrottled line would be a flood; but a
    /// SILENT refusal is worse — it is exactly the "blocked with no
    /// explanation" state that cost three diagnosis rounds. WARN, because a
    /// carrier-less peer is a user-visible outage of that leg.
    fn note_floor_withheld(&mut self, node_id: ObjectId, code: u8, reason: &str) {
        const QUIET: Duration = Duration::from_secs(300);
        let now = Instant::now();
        let fresh = match self.floor_withheld_log.get(&node_id) {
            Some((at, c)) => *c != code || now.duration_since(*at) >= QUIET,
            None => true,
        };
        if fresh {
            self.floor_withheld_log.insert(node_id, (now, code));
            warn!(
                peer = %node_id,
                "overlay relay: DERP floor WITHHELD — {reason}. This peer has no carrier \
                 until a better tier completes, so it shows as `blocked`"
            );
        }
    }

    /// rc.411 (#24) — the peer lost its carrier, so the floor bookkeeping is
    /// stale: drop it so a fresh floor can be built again.
    ///
    /// `floored` means "the birth floor IS this peer's installed carrier".
    /// It is cleared when a TURN or DERP link supersedes the floor, and by
    /// [`Self::forget`] — but `forget` runs only for RELAY deaths (a direct
    /// death must not wipe allocation/role state). So a peer that was
    /// floored, upgraded to a direct tier, then LOST that direct carrier
    /// kept a stale entry forever, and the establish walk's
    /// `!coord.is_floored()` gate suppressed its floor rebuild permanently.
    /// With no srflx and no dialer role — a corp VPN connecting — the
    /// fallback ladder can't build either, so the pair sat "blocked"
    /// indefinitely: exactly the state the floor exists to make impossible
    /// (field: winhost-a's secondary org, 2026-08-19, four peers wedged from
    /// the moment its VPN came up and killed their direct carriers).
    ///
    /// Returns whether anything was cleared (for the caller's log).
    pub fn clear_floor(&mut self, node_id: &ObjectId) -> bool {
        self.floored.remove(node_id).is_some()
    }

    /// Phase A2 — is this peer's installed carrier the birth floor?
    /// rc.412 (#24) — is a DERP link already coming for this peer through the
    /// strategy path (`request` put it in `derping`; `maybe_complete` builds
    /// it)? The floor would be the SAME carrier over the same mux, so
    /// flooring a derping peer is pure duplication — the one tracking state
    /// that must still suppress the floor.
    ///
    /// Every OTHER tracking state must NOT: a carrier-less peer waiting on a
    /// better tier is exactly what the floor is for. In particular
    /// `SingleRelay(false)` — we are the dialer awaiting the anchor's `R` —
    /// only does `dialing.insert(...)` and returns, with no allocation, no
    /// wire message and nothing that can time out, so `is_tracking` stays
    /// true forever if the anchor never advertises. Gating the floor on
    /// `!is_tracking` therefore starved precisely those pairs (field:
    /// winhost-a's secondary org under corp VPN, 2026-08-19).
    pub fn is_derping(&self, node_id: &ObjectId) -> bool {
        self.derping.contains_key(node_id)
    }

    pub fn is_floored(&self, node_id: &ObjectId) -> bool {
        self.floored.contains_key(node_id)
    }

    /// Phase B (netcheck) — is the central `/derp` WS present AND alive
    /// right now? The capability vector's `derp_ws_ok` bit.
    pub fn derp_ws_alive(&self) -> bool {
        self.derp_mux
            .as_ref()
            .map(|m| m.is_alive())
            .unwrap_or(false)
    }

    /// Phase A2 — would the pair's computed strategy be DERP anyway? The
    /// floor block skips the parallel TURN `request` for such pairs — the
    /// floor IS their carrier, and a request would double-build it.
    pub fn strategy_is_derp(&self, node_id: &ObjectId, peer: &PeerConfig) -> bool {
        matches!(self.relay_strategy(node_id, peer), RelayStrategy::Derp)
    }

    /// Drop all state for a peer (it left the netmap), including the relay
    /// we advertised for it — so when the peer's WG carrier is torn down
    /// (`wg.remove_peer`) and the underlying allocation closes, we stop
    /// advertising that now-dead address. Without this the next
    /// `OverlayEndpoints` trickle still carries the stale relay and a
    /// re-joining peer dials it (the rc.125 accumulation bug).
    pub fn forget(&mut self, node_id: &ObjectId) {
        self.pending.remove(node_id);
        self.allocated.remove(node_id);
        self.advertised.remove(node_id);
        self.dialing.remove(node_id);
        self.derping.remove(node_id);
        self.floored.remove(node_id);
        self.roles.remove(node_id);
        self.org_binding.remove(node_id);
        self.org_jobs.retain(|j| j.node_id != *node_id);
        // C4 stage 2 (PR-B) — release the single-pair warm commit. If the leg
        // itself is still alive (its probes decide that, not this pair's
        // fate), the very next `request` for this — or any — anchor pair
        // fast-commits it again: exactly the instant re-establishment the
        // standing leg exists for. A leg that actually died goes LOST on the
        // probe path and `set_warm_leg(None)` closes the fast path.
        if self.warm_committed == Some(*node_id) {
            self.warm_committed = None;
        }
    }
}

/// rc.138 — is `ip` a private/LAN (non-relay) address? Used to keep
/// `try_build` from dialing a peer's LAN endpoint as its "relay". Covers RFC
/// 1918, link-local, loopback, and the overlay/CGNAT `100.64.0.0/10` — so the
/// coturn-relayed public addresses (94.130.141.74, 5.9.157.x) are the only
/// ones that pass through.
fn is_lan_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_loopback()
                || v4.is_unspecified()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT / overlay
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Pull `(urls, username, credential)` out of the first ICE server that
/// carries REST-API short-lived TURN creds (the coturn entry).
pub(crate) fn turn_creds(ice_servers: &[IceServer]) -> Option<(Vec<String>, String, String)> {
    ice_servers.iter().find_map(|s| {
        let user = s.username.clone()?;
        let cred = s.credential.clone()?;
        Some((s.urls.clone(), user, cred))
    })
}

/// Host + port of the first `turn:`/`turns:` ICE url (e.g.
/// `("coturn.roomler.ai", 3478)`). Skips `stun:` entries; the port defaults to
/// 3478 when the url carries none.
fn turn_host_port(ice: &[IceServer]) -> Option<(String, u16)> {
    ice.iter().flat_map(|s| s.urls.iter()).find_map(|u| {
        if !u.starts_with("turn:") && !u.starts_with("turns:") {
            return None;
        }
        roomler_ai_remote_control::turn_url::host_port(u)
    })
}

/// Resolve the coturn host from the ICE creds and pick ONE worker IP
/// deterministically from `pair_key`, so both peers of the pair independently
/// choose the same worker (intra-worker relay hairpin — no cross-worker
/// SNAT). The pick itself is `remote_control::worker_pick` — the ONE
/// implementation the api broker and TURN creds also use (invariant I6).
/// `None` (→ no pin → round-robin) when there's no TURN url or DNS
/// resolution fails, which degrades to the pre-rc.125 behaviour rather than
/// failing the allocation.
async fn pick_worker(pair_key: &str, ice: &[IceServer]) -> Option<IpAddr> {
    let (host, port) = turn_host_port(ice)?;
    // #2187 — through `ctl_dns`, so a dead exit DNS never stalls a relay pick
    // for a coturn host that resolved before.
    let ips: Vec<IpAddr> = crate::ctl_dns::resolve(&crate::ctl_dns::hostport(&host, port))
        .await
        .into_iter()
        .map(|s| s.ip())
        .collect();
    if ips.is_empty() {
        warn!(%host, "overlay relay: coturn DNS resolve failed; not pinning a worker");
        return None;
    }
    let pick = pick_worker_fnv1a(pair_key, ips);
    if let Some(ip) = pick {
        debug!(%host, worker = %ip, "overlay relay: deterministic worker picked");
    }
    pick
}

/// W6 phase-2 VERDICT fix — positively identify the anchor's relayed
/// address `R` among its advertised endpoints. The old pick ("first
/// public, non-LAN entry") assumed the LAN + srflx buckets kept
/// `endpoints` down to `[LAN…, R]` — but a NAT-less anchor's (cluster
/// hosts) "LAN" candidates ARE public host addresses, so the dialer
/// QUIC-connected at the anchor's PLANE socket where no QUIC server
/// listens. Field 2026-08-15, rc.365 perm-instrumentation: every failing
/// dial showed `dst=<host-ip>:43648` (the peer's DIRECT sock, not a
/// coturn allocation) with `perm=0ms rx=0` on both sides; the raw
/// fallback only "worked" because raw WG at a host's direct sock is
/// still valid WG — an accidental direct path wearing a relay label.
///
/// With the coturn worker IPs known, `R` must be ON one. An EMPTY
/// `coturn_ips` (resolution unavailable) falls back to the legacy pick —
/// better a possibly-wrong dial than no relay tier at all.
///
/// C4 stage 2 (PR-B) — `warm` is the anchor's STANDING warm-leg address from
/// the netmap (heartbeat-refreshed, pair-less). When the per-pair advert
/// hasn't landed — or never will, because the anchor's control WS is what
/// just died — the dialer dials the warm leg instead of withholding. Held to
/// the SAME coturn-worker validation as the advert (a coturn-co-located
/// host's own address must not pass as a "relay"), and only trusted when the
/// worker set is actually known: with `coturn_ips` unresolved the warm claim
/// is unverifiable, and the legacy first-public pick has already returned.
/// `rotate` — the pick index over the coturn-matching entries, fed from the
/// #496 per-peer relay-death streak. An anchor serving SEVERAL single-relay
/// pairs advertises ALL its pair allocations in ONE flat `endpoints` list
/// (nothing on the wire says which R belongs to which pair), so a fixed
/// "first coturn match" sent EVERY dialer to the SAME R: the one pair owning
/// it worked, every other dialer hit an allocation holding no permission for
/// it — silently dropped by coturn, one-way, convicted, rebuilt to the same
/// wrong R forever. Field 2026-08-17 ~00:45Z: winhost-a (anchor on VPN)
/// advertised two pair-Rs; fleet-host-1 AND fleet-host-2 both dialed the same one and
/// both looped one-way at ~50 s/cycle — the persistent `blocked` set.
/// Rotating by the death streak makes each failing dialer walk the
/// candidates; the correct R completes a handshake, which CLEARS the streak
/// (#496's contract), pinning the pick there. Streak 0 (healthy / first
/// attempt) keeps today's first-match behaviour.
fn pick_anchor_relay_endpoint(
    endpoints: &[String],
    warm: Option<&str>,
    coturn_ips: &[IpAddr],
    node_id: &ObjectId,
    rotate: usize,
) -> Option<SocketAddr> {
    let parsed: Vec<SocketAddr> = endpoints
        .iter()
        .filter_map(|e| e.parse().ok())
        .filter(|s: &SocketAddr| !is_lan_addr(s.ip()))
        .collect();
    if coturn_ips.is_empty() {
        return parsed.first().copied();
    }
    let matches: Vec<SocketAddr> = parsed
        .iter()
        .filter(|s| coturn_ips.contains(&s.ip()))
        .copied()
        .collect();
    if !matches.is_empty() {
        let idx = rotate % matches.len();
        if matches.len() > 1 {
            info!(
                peer = %node_id, r = %matches[idx], idx, of = matches.len(), rotate,
                "overlay relay: dialer — anchor advertises MULTIPLE relay allocations \
                 (flat list, pair-ownership unknown); picking by death-streak rotation"
            );
        }
        return Some(matches[idx]);
    }
    if let Some(w) = warm
        .and_then(|w| w.parse::<SocketAddr>().ok())
        .filter(|s| coturn_ips.contains(&s.ip()))
    {
        info!(peer = %node_id, warm = %w,
              "overlay relay: dialer — per-pair relay advert absent; dialing the anchor's warm leg");
        return Some(w);
    }
    if !parsed.is_empty() {
        // The anchor's relay advert is missing (rejoin wiped it) or stale —
        // WITHHOLD rather than dial its host address as if it were coturn.
        debug!(
            peer = %node_id,
            rejected = ?parsed,
            "overlay relay: dialer — peer advertises public endpoints but none on a \
             known coturn worker; withholding until its relay advert lands"
        );
    }
    None
}

/// W6 phase-2 — the dialer's OTHER public srflx addresses (distinct IPs,
/// `primary` excluded, LAN skipped, capped at 3) the anchor must ALSO open
/// coturn permissions for. Permissions are IP-scoped, so one entry per IP
/// suffices; a multi-homed dialer advertises one srflx per plane sock and
/// its raw dial socket picks a source by route — any advertised IP may be
/// the one that shows up at coturn.
fn extra_srflx_permission_targets(srflx: &[String], primary: IpAddr) -> Vec<SocketAddr> {
    let mut seen = vec![primary];
    let mut out = Vec::new();
    for s in srflx.iter().filter_map(|e| e.parse::<SocketAddr>().ok()) {
        if is_lan_addr(s.ip()) || seen.contains(&s.ip()) {
            continue;
        }
        seen.push(s.ip());
        out.push(s);
        if out.len() == 3 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ─── FR-19 P4b — org-relay sessions, the member's side ─────────────────

    fn org_session(vni: u32, secs: u64) -> OrgSession {
        OrgSession {
            vni,
            generation: 1,
            relay_node_id: ObjectId::new(),
            endpoints: vec!["8.8.8.8:3478".parse().unwrap()],
            secret: crate::overlay::orgrelay::bind::BindSecret::from_bytes([1; 32]),
            bind_budget: Duration::from_secs(30),
            expires_at: Instant::now() + Duration::from_secs(secs),
            conn: None,
        }
    }

    /// A live session decides the strategy only with the flag on; `request`
    /// then queues an off-loop bind instead of asking for creds, and a revoke
    /// by VNI drops both the decision and the tracking.
    #[tokio::test]
    async fn a_live_org_session_decides_the_strategy_only_with_the_flag_on() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut coord = RelayCoordinator::new(tx, [0u8; 32], true, vec![], None);
        // Explicitly off: the build default is on (MeshHarbor), and a host's
        // `false` must still win over any pushed session.
        coord.set_org_relay(false);
        let node = ObjectId::new();
        let peer = base_peer();
        coord.org_session_accept(node, org_session(7, 60));
        assert_ne!(
            coord.relay_strategy(&node, &peer),
            RelayStrategy::OrgRelay,
            "flag off ⇒ a pushed session is ignored"
        );
        coord.set_org_relay(true);
        assert_eq!(coord.relay_strategy(&node, &peer), RelayStrategy::OrgRelay);

        coord.request(node, peer.clone()).await;
        assert!(
            coord.is_tracking(&node),
            "an org bind in flight is tracking"
        );
        let jobs = coord.take_org_jobs();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].vni, 7);
        assert_eq!(jobs[0].node_id, node);
        assert!(coord.take_org_jobs().is_empty(), "drained once");
        coord.request(node, peer.clone()).await;
        assert!(
            coord.take_org_jobs().is_empty(),
            "a second request while binding queues nothing"
        );

        assert_eq!(coord.org_session_revoke(7), Some(node));
        assert_ne!(coord.relay_strategy(&node, &peer), RelayStrategy::OrgRelay);
        assert!(!coord.is_tracking(&node), "revoke clears the tracking too");
        assert_eq!(coord.org_session_revoke(7), None, "already gone");
    }

    /// Expiry reaps on the member's own clock; a bind that completes for a
    /// session that was replaced meanwhile is refused and its conn closed; the
    /// current session commits an `Org` link, and revoking it closes the
    /// carrier so the dead latch fires.
    #[tokio::test]
    async fn expired_sessions_are_reaped_and_a_stale_bind_is_refused() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut coord = RelayCoordinator::new(tx, [0u8; 32], true, vec![], None);
        coord.set_org_relay(true);
        let node = ObjectId::new();

        coord.org_session_accept(node, org_session(9, 0));
        assert_ne!(
            coord.relay_strategy(&node, &base_peer()),
            RelayStrategy::OrgRelay,
            "an expired session decides nothing"
        );
        assert_eq!(coord.reap_org_sessions(Instant::now()), vec![node]);

        coord.org_session_accept(node, org_session(11, 60));
        coord.org_request_bind(node, base_peer());
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let stale = Arc::new(OrgRelayConn::new(sock.clone(), relay, 10, "r".into()));
        assert!(
            coord.commit_org_bind(node, 1, stale.clone()).is_none(),
            "a bind for another VNI never commits"
        );
        assert!(!stale.is_alive(), "a refused conn is closed");

        let fresh = Arc::new(OrgRelayConn::new(sock, relay, 11, "r".into()));
        let link = coord
            .commit_org_bind(node, 1, fresh.clone())
            .expect("the current session commits");
        assert_eq!(link.relay_kind, RelayKind::Org);
        assert!(
            link.single_relay.is_none(),
            "symmetric — no anchor/dialer role"
        );
        assert!(!link.supports_quic, "raw WG only");
        assert!(!coord.is_tracking(&node), "bound ⇒ no longer coordinating");
        assert!(fresh.is_alive());

        coord.org_session_revoke(11);
        assert!(
            !fresh.is_alive(),
            "revoking a bound session closes its carrier"
        );
    }

    /// W6 phase-2 — the anchor permits every DISTINCT public srflx IP the
    /// dialer advertises, beyond the primary: same-IP re-adverts collapse,
    /// LAN entries and garbage are skipped, and the list is capped.
    #[test]
    fn extra_permission_targets_are_distinct_public_ips_beyond_the_primary() {
        let srflx = vec![
            "94.130.141.98:43648".to_string(),  // primary's IP — excluded
            "94.130.141.98:51000".to_string(),  // same IP, other port — collapsed
            "94.130.141.74:43648".to_string(),  // the multi-homed second IP
            "192.168.68.106:43648".to_string(), // LAN — skipped
            "not-an-addr".to_string(),          // garbage — skipped
            "62.210.194.66:43648".to_string(),
        ];
        let primary: IpAddr = "94.130.141.98".parse().unwrap();
        let got = extra_srflx_permission_targets(&srflx, primary);
        assert_eq!(
            got,
            vec![
                "94.130.141.74:43648".parse::<SocketAddr>().unwrap(),
                "62.210.194.66:43648".parse::<SocketAddr>().unwrap(),
            ]
        );

        // Cap at 3 distinct extras.
        let many: Vec<String> = (1..=6).map(|i| format!("203.0.113.{i}:1000")).collect();
        assert_eq!(
            extra_srflx_permission_targets(&many, "198.51.100.1".parse().unwrap()).len(),
            3
        );
    }

    /// W6 phase-2 VERDICT lock — the dialer must dial the anchor's COTURN
    /// endpoint, never its public HOST address: a NAT-less anchor (cluster
    /// host) advertises its own public direct sock among `endpoints`, and
    /// dialing that was the rx=0 QUIC rendezvous bug (perm fine, nobody
    /// listening). Missing relay advert ⇒ WITHHOLD, not guess; unresolved
    /// worker set ⇒ legacy first-public pick.
    #[test]
    fn dialer_picks_r_on_a_coturn_worker_never_the_anchors_host_address() {
        let nid = ObjectId::new();
        let coturn: Vec<IpAddr> = vec![
            "5.9.157.221".parse().unwrap(),
            "94.130.141.74".parse().unwrap(),
        ];
        // The field shape: host public address FIRST, real R after.
        let eps = vec![
            "192.168.68.1:43648".to_string(),  // LAN — skipped
            "94.130.141.98:43648".to_string(), // the anchor's HOST addr — NOT R
            "5.9.157.221:11885".to_string(),   // the coturn allocation — R
        ];
        assert_eq!(
            pick_anchor_relay_endpoint(&eps, None, &coturn, &nid, 0),
            Some("5.9.157.221:11885".parse().unwrap())
        );

        // No entry on a worker ⇒ withhold (retry next netmap).
        let hostonly = vec!["94.130.141.98:43648".to_string()];
        assert_eq!(
            pick_anchor_relay_endpoint(&hostonly, None, &coturn, &nid, 0),
            None
        );

        // Worker set unresolved ⇒ legacy first-public pick (never brick the
        // relay tier on a DNS failure).
        assert_eq!(
            pick_anchor_relay_endpoint(&hostonly, None, &[], &nid, 0),
            Some("94.130.141.98:43648".parse().unwrap())
        );
    }

    /// C4 stage 2 (PR-B) — the dialer falls back to the anchor's heartbeat-
    /// advertised WARM leg when the per-pair advert is absent, under the same
    /// coturn-worker validation: a warm claim off a worker (a coturn-
    /// co-located host's own address, a spoof, a stale row) is rejected, the
    /// per-pair advert still wins when present, and an unresolved worker set
    /// never consults the warm claim at all (unverifiable).
    #[test]
    fn dialer_falls_back_to_the_warm_leg_only_when_validated() {
        let nid = ObjectId::new();
        let coturn: Vec<IpAddr> = vec![
            "5.9.157.221".parse().unwrap(),
            "94.130.141.74".parse().unwrap(),
        ];
        let hostonly = vec!["94.130.141.98:43648".to_string()];

        // Advert absent + warm on a worker ⇒ dial the warm leg.
        assert_eq!(
            pick_anchor_relay_endpoint(&hostonly, Some("5.9.157.221:11764"), &coturn, &nid, 0),
            Some("5.9.157.221:11764".parse().unwrap())
        );
        // Warm NOT on a worker (co-located host / spoof) ⇒ withhold.
        assert_eq!(
            pick_anchor_relay_endpoint(&hostonly, Some("94.130.141.98:12000"), &coturn, &nid, 0),
            None
        );
        // Garbage warm ⇒ withhold.
        assert_eq!(
            pick_anchor_relay_endpoint(&hostonly, Some("not-an-addr"), &coturn, &nid, 0),
            None
        );
        // Per-pair advert present ⇒ it wins over the warm claim.
        let with_advert = vec![
            "94.130.141.98:43648".to_string(),
            "94.130.141.74:11223".to_string(),
        ];
        assert_eq!(
            pick_anchor_relay_endpoint(&with_advert, Some("5.9.157.221:11764"), &coturn, &nid, 0),
            Some("94.130.141.74:11223".parse().unwrap())
        );
        // Worker set unresolved ⇒ legacy pick, warm never consulted.
        assert_eq!(
            pick_anchor_relay_endpoint(&hostonly, Some("5.9.157.221:11764"), &[], &nid, 0),
            Some("94.130.141.98:43648".parse().unwrap())
        );
    }

    /// Multi-R ambiguity — an anchor serving several single-relay pairs
    /// advertises ALL its pair allocations in one flat list, and nothing on
    /// the wire says which R belongs to which pair. A fixed first-match sent
    /// every dialer to the same R (field 2026-08-17: fleet-host-1 AND fleet-host-2 both
    /// one-way-looping on winhost-a's first R at ~50 s/cycle — the persistent
    /// `blocked` set). The death-streak rotation walks the candidates; the
    /// working R clears the streak (#496) and the pick pins there.
    #[test]
    fn dialer_rotates_across_multiple_advertised_relays_by_death_streak() {
        let nid = ObjectId::new();
        let coturn: Vec<IpAddr> = vec![
            "5.9.157.221".parse().unwrap(),
            "94.130.141.74".parse().unwrap(),
            "5.9.157.226".parse().unwrap(),
        ];
        // The live winhost-a shape: LAN + two pair-Rs on different workers.
        let eps = vec![
            "192.168.68.106:43650".to_string(), // LAN — skipped
            "94.130.141.74:11259".to_string(),  // pair-R #1
            "5.9.157.226:10821".to_string(),    // pair-R #2
        ];
        let r1: SocketAddr = "94.130.141.74:11259".parse().unwrap();
        let r2: SocketAddr = "5.9.157.226:10821".parse().unwrap();
        // Streak 0 (first attempt / healthy) = today's first-match.
        assert_eq!(
            pick_anchor_relay_endpoint(&eps, None, &coturn, &nid, 0),
            Some(r1)
        );
        // Each relay death rotates to the next candidate…
        assert_eq!(
            pick_anchor_relay_endpoint(&eps, None, &coturn, &nid, 1),
            Some(r2)
        );
        // …and wraps.
        assert_eq!(
            pick_anchor_relay_endpoint(&eps, None, &coturn, &nid, 2),
            Some(r1)
        );
        // A single candidate is immune to rotation (any streak).
        let one = vec!["5.9.157.221:11885".to_string()];
        assert_eq!(
            pick_anchor_relay_endpoint(&one, None, &coturn, &nid, 7),
            Some("5.9.157.221:11885".parse().unwrap())
        );
    }

    fn ice(url: &str) -> IceServer {
        IceServer {
            urls: vec![url.into()],
            username: Some("u".into()),
            credential: Some("c".into()),
        }
    }

    /// A minimal peer for the coordinator tests — override the fields a test
    /// cares about with `..base_peer()`.
    /// P7 — a fixed node id for strategy-signature calls (the forced-DERP pin
    /// is keyed by node id; these tests exercise the capability-derived path,
    /// so any id without a pin works).
    fn test_nid() -> ObjectId {
        ObjectId::from_bytes([0x42; 12])
    }

    fn base_peer() -> PeerConfig {
        PeerConfig {
            public_key: [1u8; 32],
            overlay_ip: Ipv4Addr::new(100, 64, 0, 9),
            name: String::new(),
            subnets: vec![],
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_band_udp: None,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            supports_overlay_echo: false,
            relay_strategy: None,
            relay_home: None,
            warm_relay_endpoint: None,
        }
    }

    #[test]
    fn turn_creds_picks_the_authed_entry() {
        let servers = vec![
            IceServer {
                urls: vec!["stun:stun.example:3478".into()],
                username: None,
                credential: None,
            },
            ice("turn:coturn.example:3478?transport=udp"),
        ];
        let (urls, u, c) = turn_creds(&servers).expect("authed entry");
        assert_eq!(urls, vec!["turn:coturn.example:3478?transport=udp"]);
        assert_eq!((u.as_str(), c.as_str()), ("u", "c"));
        assert!(turn_creds(&[]).is_none());
    }

    #[test]
    fn turn_host_port_strips_scheme_and_query_keeps_port() {
        let servers = vec![
            IceServer {
                urls: vec!["stun:stun.l.google.com:19302".into()],
                username: None,
                credential: None,
            },
            ice("turn:coturn.roomler.ai:3478?transport=udp"),
        ];
        assert_eq!(
            turn_host_port(&servers),
            Some(("coturn.roomler.ai".into(), 3478))
        );
        assert_eq!(
            turn_host_port(&[ice("turns:coturn.roomler.ai:443?transport=tcp")]),
            Some(("coturn.roomler.ai".into(), 443))
        );
        // A portless url resolves on the default TURN port.
        assert_eq!(
            turn_host_port(&[ice("turn:pop.example.com")]),
            Some(("pop.example.com".into(), 3478))
        );
        // stun-only / empty → no host
        assert_eq!(
            turn_host_port(&[IceServer {
                urls: vec!["stun:stun.example:3478".into()],
                username: None,
                credential: None,
            }]),
            None
        );
    }

    /// worker-pick golden vector (invariant I6): this end and the api broker
    /// hash the same `pair_key` over independently-resolved worker sets, so
    /// the pick is byte-pinned here to the exact value the shared
    /// `remote_control::worker_pick` suite pins — any drift between the two
    /// call paths fails one of the golden tests.
    #[test]
    fn deterministic_worker_pick_agrees_with_golden_vector() {
        let a = "5.9.157.221".parse().unwrap();
        let b = "5.9.157.226".parse().unwrap();
        let c: IpAddr = "94.130.141.74".parse().unwrap();
        let key = "507f1f77bcf86cd799439011:507f1f77bcf86cd799439012";
        // FNV-1a(key) = 0xad37_bde0_cdd9_5470; % 3 = 2 → third sorted IPv4.
        assert_eq!(pick_worker_fnv1a(key, vec![a, b, c]), Some(c));
        assert_eq!(pick_worker_fnv1a(key, vec![c, b, a, b]), Some(c)); // shuffled + dup
        // ipv6 filtered; empty → None (→ unpinned fallback upstream)
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(pick_worker_fnv1a(key, vec![v6, a]), Some(a));
        assert_eq!(pick_worker_fnv1a(key, vec![v6]), None);
    }

    #[tokio::test]
    async fn request_is_idempotent_and_sends_one_relay_request() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut coord = RelayCoordinator::new(tx, [0u8; 32], true, vec![], None);
        let node = ObjectId::new();
        let peer = base_peer();
        coord.request(node, peer.clone()).await;
        coord.request(node, peer).await; // de-duped
        assert!(coord.is_tracking(&node));
        assert!(matches!(
            rx.recv().await,
            Some(ClientMsg::OverlayRelayRequest { peer_node_id, .. }) if peer_node_id == node
        ));
        assert!(rx.try_recv().is_err()); // only one request sent
    }

    /// Unresponsive-peer backoff ladder: deaths 1-2 re-request immediately
    /// (transients stay snappy), the 3rd defers 60 s, doubling to the 5-min
    /// cap — the buildhost-vs-sleeping-winhost-a grind (one allocation + QUIC
    /// window every ~45-90 s for HOURS, feeding the server's force-DERP
    /// pins) becomes ~12 attempts/h.
    #[test]
    fn relay_death_backoff_ladder() {
        assert_eq!(relay_death_backoff(0), None);
        assert_eq!(relay_death_backoff(1), None);
        assert_eq!(relay_death_backoff(2), None);
        assert_eq!(relay_death_backoff(3), Some(Duration::from_secs(60)));
        assert_eq!(relay_death_backoff(4), Some(Duration::from_secs(120)));
        assert_eq!(relay_death_backoff(5), Some(Duration::from_secs(240)));
        assert_eq!(
            relay_death_backoff(6),
            Some(Duration::from_secs(300)),
            "cap"
        );
        assert_eq!(
            relay_death_backoff(60),
            Some(Duration::from_secs(300)),
            "cap holds"
        );
    }

    /// Unresponsive-peer backoff behaviour: three consecutive death notes
    /// hold our own `request` (peer stays untracked, nothing on the wire);
    /// `clear_death_streak` (the sweep's completed-handshake signal) restores
    /// immediate re-requests. Grants never pass through `request`, so the
    /// held state cannot strand a peer-initiated pairing.
    #[tokio::test]
    async fn request_backs_off_after_consecutive_relay_deaths_and_clears() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut coord = RelayCoordinator::new(tx, [0u8; 32], true, vec![], None);
        let node = ObjectId::new();
        // rc.398 regression lock: DIRECT-tier deaths (kind=None) must NOT
        // feed the streak — a dead srflx punch looping its 12 s deadline
        // re-armed the 300 s hold faster than expiry and starved the relay
        // re-request forever (the post-roll carrier-less wedge).
        for _ in 0..5 {
            coord.note_refresh_context(node, None, "handshake-deadline");
        }
        coord.request(node, base_peer()).await;
        assert!(
            coord.is_tracking(&node),
            "direct-tier deaths never defer the relay request"
        );
        coord.forget(&node);
        assert!(rx.try_recv().is_ok(), "the request went out");

        // RELAY deaths (kind=Some) book as before: 3rd holds.
        for _ in 0..3 {
            coord.note_refresh_context(node, Some(RelayKind::Turn), "handshake-deadline");
        }
        coord.request(node, base_peer()).await;
        assert!(
            !coord.is_tracking(&node),
            "3rd relay-death re-request is held"
        );
        assert!(rx.try_recv().is_err(), "nothing sent while held");

        coord.clear_death_streak(&node);
        coord.request(node, base_peer()).await;
        assert!(coord.is_tracking(&node), "cleared streak requests again");
        assert!(matches!(
            rx.recv().await,
            Some(ClientMsg::OverlayRelayRequest { peer_node_id, .. }) if peer_node_id == node
        ));
    }

    /// #22 (mutual-defer wedge, 08-18) — a peer we can HEAR must not stay
    /// deferred: the sweep's `note_peer_audible` voids an active hold, so
    /// the deferring end re-requests instead of waiting forever for a peer
    /// whose own leg is healthy (and who therefore never re-requests). A
    /// SILENT peer's hold is untouched — the defer's real target.
    #[tokio::test]
    async fn audible_peer_voids_the_relay_death_defer() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut coord = RelayCoordinator::new(tx, [0u8; 32], true, vec![], None);
        let node = ObjectId::new();
        for _ in 0..3 {
            coord.note_refresh_context(node, Some(RelayKind::Turn), "handshake-deadline");
        }
        coord.request(node, base_peer()).await;
        assert!(!coord.is_tracking(&node), "3rd relay-death re-request held");
        assert!(rx.try_recv().is_err(), "nothing sent while held");

        // The sweep heard the peer this tick — the "asleep" premise is void.
        coord.note_peer_audible(&node);
        coord.request(node, base_peer()).await;
        assert!(
            coord.is_tracking(&node),
            "an audible peer's hold is voided — the request goes out"
        );
        assert!(matches!(
            rx.recv().await,
            Some(ClientMsg::OverlayRelayRequest { peer_node_id, .. }) if peer_node_id == node
        ));
        // The streak itself survives (telemetry + re-books on the next
        // death); only the HOLD was voided.
        assert!(coord.death_streaks.contains_key(&node));
    }

    /// C4 stage 2 (PR-B) — a fixed-address stand-in for the warm leg's
    /// [`RelayConn`]; `local_addr` is the allocation's relayed address.
    struct WarmTestConn;
    #[async_trait::async_trait]
    impl RelayConn for WarmTestConn {
        async fn send_to(&self, buf: &[u8], _dst: SocketAddr) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("5.9.157.221:12795".parse().unwrap())
        }
    }

    /// C4 stage 2 (PR-B) — a live warm leg makes the single-relay ANCHOR
    /// request commit instantly: no `OverlayRelayRequest` round-trip, the
    /// leg's relayed address advertised as this pair's relay, and
    /// `maybe_complete` builds the anchor link off it. SINGLE-PAIR: a second
    /// anchor pair while the leg is committed takes today's request path;
    /// `forget` releases the commit (still-live leg re-commits for the next
    /// pair — the standing failover this exists for); a LOST leg closes the
    /// fast path entirely.
    #[tokio::test]
    async fn warm_leg_fast_commits_the_single_relay_anchor() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // We are UDP-BLOCKED (the strict-corp anchor case), single-relay on.
        let mut coord = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], None);
        coord.single_relay = true;
        coord.set_warm_leg(Some(Arc::new(WarmTestConn)));
        let node = ObjectId::new();
        // Peer: UDP-capable + single-relay ⇒ we ANCHOR.
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        coord.request(node, peer.clone()).await;
        assert!(coord.is_tracking(&node));
        // PR-B2 — the wire still carries the request (P7's churn counter
        // feeds on it), but purely as a NOTIFY: the commit never waits on a
        // grant, and a late grant hits a peer that never entered `pending`.
        assert!(matches!(
            rx.try_recv(),
            Ok(ClientMsg::OverlayRelayRequest { peer_node_id, .. }) if peer_node_id == node
        ));
        let Ok(ClientMsg::OverlayEndpoints { candidates }) = rx.try_recv() else {
            panic!("expected the endpoints trickle carrying the warm leg");
        };
        assert!(candidates.contains(&"5.9.157.221:12795".to_string()));
        assert!(rx.try_recv().is_err());
        assert!(
            coord.grant_accept(node, vec![], "pk".into()).is_none(),
            "a late grant for a fast-committed peer is dropped harmlessly"
        );
        // The no-round-trip proof: the link builds with NO grant ever accepted.
        let link = coord
            .maybe_complete(node, &peer)
            .expect("anchor link ready");
        assert_eq!(link.single_relay, Some(true));
        assert_eq!(link.relay_kind, RelayKind::Turn);
        assert_eq!(
            link.relay_parts.as_ref().unwrap().1,
            "203.0.113.9:40000".parse().unwrap(),
            "anchor dials the dialer's srflx for the IP-only permit"
        );

        // SINGLE-PAIR: a second anchor pair goes down today's request path.
        let node2 = ObjectId::new();
        coord.request(node2, peer.clone()).await;
        assert!(matches!(
            rx.recv().await,
            Some(ClientMsg::OverlayRelayRequest { peer_node_id, .. }) if peer_node_id == node2
        ));

        // `forget` releases the commit — the still-live leg re-commits.
        coord.forget(&node);
        let node3 = ObjectId::new();
        coord.request(node3, peer.clone()).await;
        assert!(coord.is_tracking(&node3));
        assert!(
            matches!(
                rx.try_recv(),
                Ok(ClientMsg::OverlayRelayRequest { peer_node_id, .. }) if peer_node_id == node3
            ),
            "each re-commit notifies the server (P7 churn visibility)"
        );
        assert!(
            matches!(rx.try_recv(), Ok(ClientMsg::OverlayEndpoints { .. })),
            "fast re-commit trickles the leg again"
        );
        assert!(rx.try_recv().is_err());
        assert!(
            coord.maybe_complete(node3, &peer).is_some(),
            "re-commit builds without any grant"
        );

        // A LOST leg closes the fast path.
        coord.forget(&node3);
        coord.set_warm_leg(None);
        let node4 = ObjectId::new();
        coord.request(node4, peer).await;
        assert!(matches!(
            rx.recv().await,
            Some(ClientMsg::OverlayRelayRequest { peer_node_id, .. }) if peer_node_id == node4
        ));
    }

    #[test]
    fn forget_prunes_the_advertised_relay() {
        // rc.126 regression lock: a churn-removed peer must drop the relay
        // we advertised for it, or the next `OverlayEndpoints` trickle keeps
        // carrying a now-dead allocation and the peer dials it forever.
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut coord =
            RelayCoordinator::new(tx, [0u8; 32], true, vec!["192.168.68.5:51820".into()], None);
        let node = ObjectId::new();
        coord.advertised.insert(node, "94.130.141.74:11085".into());
        coord.pending.insert(
            node,
            PendingPeer {
                peer: PeerConfig {
                    public_key: [2u8; 32],
                    ..base_peer()
                },
                ice: None,
                pair_key: None,
            },
        );
        assert!(coord.is_tracking(&node));
        coord.forget(&node);
        assert!(!coord.is_tracking(&node));
        assert!(
            coord.advertised.is_empty(),
            "forget must prune the advertised relay so a re-joining peer can't dial a dead allocation"
        );
        // rc.135 — the LAN endpoint is ALWAYS in the trickle's candidate set
        // (the server replaces, so the LAN endpoint must survive each trickle);
        // forgetting a relay drops only that relay, never the LAN endpoint.
        assert_eq!(
            coord.all_endpoints(),
            vec!["192.168.68.5:51820".to_string()],
            "LAN endpoint must persist; only the relay is pruned"
        );
    }

    #[test]
    fn is_lan_addr_keeps_only_relay_publics() {
        let lan = |s: &str| is_lan_addr(s.parse().unwrap());
        // LAN / private / overlay → true (must NOT be dialed as a relay).
        assert!(lan("192.168.0.241")); // Wi-Fi
        assert!(lan("172.31.176.1")); // WSL / vEthernet
        assert!(lan("172.26.0.1"));
        assert!(lan("10.16.6.34")); // corp
        assert!(lan("169.254.1.2")); // link-local
        assert!(lan("100.64.0.2")); // overlay/CGNAT
        // coturn-relayed publics → false (these ARE the relay address).
        assert!(!lan("94.130.141.74")); // buildhost
        assert!(!lan("5.9.157.221")); // hetzner coturn
        assert!(!lan("5.9.157.226"));
    }

    #[test]
    fn relay_dst_picks_worker_then_public_never_lan() {
        // The selection logic from `try_build`, isolated: given the peer's
        // unioned endpoints (LAN first, rc.135) and our coturn worker IP, dial
        // the peer's relay on our worker — never the LAN address.
        let our_worker: std::net::IpAddr = "94.130.141.74".parse().unwrap();
        let endpoints = [
            "192.168.0.241:64392".to_string(), // peer LAN (first) — must skip
            "172.26.0.1:64392".to_string(),    // peer virtual — must skip
            "94.130.141.74:11947".to_string(), // peer relay on OUR worker — pick
            "5.9.157.221:10000".to_string(),   // peer relay on another worker
        ];
        let parsed: Vec<SocketAddr> = endpoints.iter().filter_map(|e| e.parse().ok()).collect();
        let dst = parsed
            .iter()
            .find(|s| s.ip() == our_worker)
            .or_else(|| parsed.iter().find(|s| !is_lan_addr(s.ip())))
            .copied()
            .unwrap();
        assert_eq!(dst, "94.130.141.74:11947".parse::<SocketAddr>().unwrap());

        // No relay on our worker → fall back to ANY public, still never LAN.
        let only_other = [
            "192.168.0.241:64392".to_string(),
            "5.9.157.221:10000".to_string(),
        ];
        let parsed: Vec<SocketAddr> = only_other.iter().filter_map(|e| e.parse().ok()).collect();
        let dst = parsed
            .iter()
            .find(|s| s.ip() == our_worker)
            .or_else(|| parsed.iter().find(|s| !is_lan_addr(s.ip())))
            .copied()
            .unwrap();
        assert_eq!(dst, "5.9.157.221:10000".parse::<SocketAddr>().unwrap());

        // Only LAN advertised → None (don't dial LAN as relay; wait for relay).
        let only_lan = ["192.168.0.241:64392".to_string()];
        let parsed: Vec<SocketAddr> = only_lan.iter().filter_map(|e| e.parse().ok()).collect();
        let dst = parsed
            .iter()
            .find(|s| s.ip() == our_worker)
            .or_else(|| parsed.iter().find(|s| !is_lan_addr(s.ip())))
            .copied();
        assert!(dst.is_none());
    }

    #[test]
    fn all_endpoints_unions_lan_and_relays() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut coord =
            RelayCoordinator::new(tx, [0u8; 32], true, vec!["192.168.68.5:51820".into()], None);
        coord
            .advertised
            .insert(ObjectId::new(), "94.130.141.74:11085".into());
        let eps = coord.all_endpoints();
        assert!(
            eps.contains(&"192.168.68.5:51820".to_string()),
            "LAN included"
        );
        assert!(
            eps.contains(&"94.130.141.74:11085".to_string()),
            "relay included"
        );
    }

    // ───────────────── Phase D — v1 single-relay role split ─────────────────

    #[test]
    fn single_relay_role_by_udp_capability_then_pubkey() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let small = [0x00u8; 32];
        let large = [0xFFu8; 32];
        // `sup` = peer advertises single-relay; `udp` = peer is UDP-capable
        // (has a srflx endpoint — the raw-UDP-dialer signal).
        let peer = |pk: [u8; 32], sup: bool, udp: bool| PeerConfig {
            public_key: pk,
            supports_relay_single: sup,
            srflx_endpoints: if udp {
                vec!["203.0.113.9:40000".into()]
            } else {
                vec![]
            },
            ..base_peer()
        };
        // Helper: a coordinator with the flag forced on and a given UDP status.
        let coord = |pk: [u8; 32], udp_ok: bool| {
            let mut c = RelayCoordinator::new(tx.clone(), pk, udp_ok, vec![], None);
            c.single_relay = true;
            c
        };

        // Flag off → both-allocate regardless (gate defaults ON, so force off).
        let mut off = RelayCoordinator::new(tx.clone(), small, true, vec![], None);
        off.single_relay = false;
        assert_eq!(
            off.single_relay_role(&test_nid(), &peer(large, true, true)),
            None
        );

        // Peer doesn't advertise → both-allocate (no anchor/dialer split).
        assert_eq!(
            coord(small, true).single_relay_role(&test_nid(), &peer(large, false, true)),
            None,
            "peer flag off ⇒ both-allocate"
        );

        // Both UDP-capable → smaller pubkey anchors (deterministic tie-break).
        assert_eq!(
            coord(small, true).single_relay_role(&test_nid(), &peer(large, true, true)),
            Some(true),
            "both UDP-OK, smaller pubkey ⇒ ANCHOR"
        );
        assert_eq!(
            coord(large, true).single_relay_role(&test_nid(), &peer(small, true, true)),
            Some(false),
            "both UDP-OK, larger pubkey ⇒ DIALER"
        );

        // UDP-capability OVERRIDES pubkey: the UDP-blocked side always anchors,
        // even when its pubkey is the LARGER one (would be dialer under the old
        // rule) — this is the WINHOST-A corp-host path.
        assert_eq!(
            coord(large, false).single_relay_role(&test_nid(), &peer(small, true, true)),
            Some(true),
            "we're UDP-blocked (larger pubkey) ⇒ we still ANCHOR"
        );
        assert_eq!(
            coord(small, true).single_relay_role(&test_nid(), &peer(large, true, false)),
            Some(false),
            "peer is UDP-blocked (larger pubkey) ⇒ peer anchors, WE dial"
        );

        // Both UDP-blocked → no raw-UDP dialer exists → not single-relay.
        assert_eq!(
            coord(small, false).single_relay_role(&test_nid(), &peer(large, true, false)),
            None,
            "both UDP-blocked ⇒ single-relay can't carry (→ both-allocate/DERP)"
        );

        // Symmetry: the two ends of a mixed (UDP-OK ↔ UDP-blocked) pair compute
        // mirror roles (exactly one anchor), regardless of pubkey order.
        let a_ok_dialer =
            coord(large, true).single_relay_role(&test_nid(), &peer(small, true, false));
        let b_blocked_anchor =
            coord(small, false).single_relay_role(&test_nid(), &peer(large, true, true));
        assert_eq!(a_ok_dialer, Some(false));
        assert_eq!(b_blocked_anchor, Some(true));
    }

    /// Dialer honesty (field 2026-08-16, CORPLAP-3): a srflx candidate only
    /// proves UDP to a well-known port — a host whose raw dials toward the
    /// coturn relay band never land must ANCHOR, and the verdict only applies
    /// when the peer carries the honesty field at all (mixed-version pairs
    /// must keep legacy inputs on BOTH ends, or roles split).
    #[tokio::test]
    async fn dialer_honesty_flips_roles_only_against_honesty_capable_peers() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let (small, large) = ([0x01u8; 32], [0xFFu8; 32]);
        let honest_peer = |pk: [u8; 32], dialer_ok: Option<bool>| PeerConfig {
            public_key: pk,
            supports_relay_single: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            udp_dialer_ok: dialer_ok,
            ..base_peer()
        };
        let coord = |pk: [u8; 32]| {
            let mut c = RelayCoordinator::new(tx.clone(), pk, true, vec![], None);
            c.single_relay = true;
            c
        };

        // Baseline: larger pubkey + both udp-ok ⇒ WE dial (legacy tie-break),
        // whether the peer is honesty-capable or not.
        assert_eq!(
            coord(large).single_relay_role(&test_nid(), &honest_peer(small, Some(true))),
            Some(false)
        );

        // The corplap fix: we latched not-dialer-capable ⇒ we ANCHOR against an
        // honesty-capable peer, pubkey order be damned.
        let mut latched = coord(large);
        latched.set_udp_dialer_ok(false);
        assert_eq!(
            latched.single_relay_role(&test_nid(), &honest_peer(small, Some(true))),
            Some(true),
            "latched host must anchor against an honesty-capable peer"
        );

        // Mixed-version safety: same latch, but the peer predates the field
        // (`None`) ⇒ BOTH ends must keep the legacy inputs ⇒ we still dial.
        assert_eq!(
            latched.single_relay_role(&test_nid(), &honest_peer(small, None)),
            Some(false),
            "against a pre-honesty peer the latch must NOT apply (role-split hazard)"
        );

        // The mirror: the PEER declared not-dialer-capable ⇒ it anchors, we
        // dial — even though its srflx bucket is non-empty.
        assert_eq!(
            coord(small).single_relay_role(&test_nid(), &honest_peer(large, Some(false))),
            Some(false),
            "we dial toward a peer that can't dial"
        );
        assert_eq!(
            coord(large).single_relay_role(&test_nid(), &honest_peer(small, Some(false))),
            Some(false),
            "pubkey order must not matter: the capable side always dials"
        );

        // Both latched ⇒ no raw-UDP dialer exists ⇒ not single-relay
        // (falls through to DERP/both-allocate).
        let mut both = coord(small);
        both.set_udp_dialer_ok(false);
        assert_eq!(
            both.single_relay_role(&test_nid(), &honest_peer(large, Some(false))),
            None
        );

        // The latch is strategy-input material: flipping it must change the
        // fingerprint so tracked pairs re-establish on the corrected roles.
        let p = honest_peer(small, Some(true));
        assert_ne!(
            strategy_fingerprint(true, true, None, &p),
            strategy_fingerprint(true, false, None, &p)
        );
        assert_ne!(
            strategy_fingerprint(true, true, None, &p),
            strategy_fingerprint(true, true, None, &honest_peer(small, Some(false)))
        );
        // B3 — the measured pair is likewise strategy-input material, on
        // both the own-side and the peer-side halves.
        assert_ne!(
            strategy_fingerprint(true, true, None, &p),
            strategy_fingerprint(true, true, Some(false), &p)
        );
        let mut measured_peer = p.clone();
        measured_peer.relay_band_udp = Some(false);
        assert_ne!(
            strategy_fingerprint(true, true, None, &p),
            strategy_fingerprint(true, true, None, &measured_peer)
        );
    }

    /// B3 — the MEASURED relay-band pair supersedes every derived input
    /// (srflx presence AND the honesty latch), but only when BOTH ends
    /// carry a fresh bit; one-sided measurement keeps the legacy rules so
    /// a mixed pair can never split roles.
    #[tokio::test]
    async fn measured_relay_band_supersedes_latch_and_srflx_when_both_ends_carry_it() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let (small, large) = ([0x01u8; 32], [0xFFu8; 32]);
        let peer = |pk: [u8; 32], dialer_ok: Option<bool>, band: Option<bool>| PeerConfig {
            public_key: pk,
            supports_relay_single: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            udp_dialer_ok: dialer_ok,
            relay_band_udp: band,
            ..base_peer()
        };
        let coord = |pk: [u8; 32], band: Option<bool>| {
            let mut c = RelayCoordinator::new(tx.clone(), pk, true, vec![], None);
            c.single_relay = true;
            c.set_relay_band_udp(band);
            c
        };

        // The corplap case, measured: srflx PRESENT + latch clear, but the probe
        // proved the relay band is dropped ⇒ we ANCHOR (peer measured-capable
        // dials), pubkey order be damned.
        assert_eq!(
            coord(small, Some(false))
                .single_relay_role(&test_nid(), &peer(large, None, Some(true))),
            Some(true),
            "measured relay-band-blocked host must anchor despite srflx presence"
        );
        // Mirror: the PEER measured blocked ⇒ we dial.
        assert_eq!(
            coord(large, Some(true))
                .single_relay_role(&test_nid(), &peer(small, None, Some(false))),
            Some(false),
            "measured-capable side dials toward a measured-blocked peer"
        );
        // Measurement outranks a (possibly false) latch: latched host whose
        // fresh probe says the band works dials again immediately — no
        // LATCH_TTL wait.
        let mut c = coord(large, Some(true));
        c.set_udp_dialer_ok(false);
        assert_eq!(
            c.single_relay_role(&test_nid(), &peer(small, Some(true), Some(true))),
            Some(false),
            "a fresh measured-capable verdict overrides the latch (larger pubkey ⇒ dialer)"
        );
        // One-sided measurement ⇒ legacy rules verbatim (here: the latch
        // applies against an honesty-capable peer ⇒ we anchor).
        let mut one_sided = coord(large, Some(true));
        one_sided.set_udp_dialer_ok(false);
        assert_eq!(
            one_sided.single_relay_role(&test_nid(), &peer(small, Some(true), None)),
            Some(true),
            "peer without a fresh vector ⇒ measured branch must NOT engage"
        );
        // Both measured blocked ⇒ no raw-UDP dialer ⇒ not single-relay.
        assert_eq!(
            coord(small, Some(false))
                .single_relay_role(&test_nid(), &peer(large, None, Some(false))),
            None
        );
        // Both measured capable ⇒ deterministic pubkey tie-break survives.
        assert_eq!(
            coord(small, Some(true)).single_relay_role(&test_nid(), &peer(large, None, Some(true))),
            Some(true),
            "smaller pubkey anchors on the measured both-capable tie-break"
        );
    }

    #[tokio::test]
    async fn single_relay_dialer_tracks_without_request_and_builds_raw_to_anchor_r() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // We are UDP-capable and our pubkey is LARGER; the peer is also
        // UDP-capable (has a srflx endpoint), so the tie-break makes US the
        // DIALER (Some(false)).
        let mut coord = RelayCoordinator::new(tx, [0xFFu8; 32], true, vec![], None);
        coord.single_relay = true; // same-module: force the opt-in on for the test
        let node = ObjectId::new();
        let anchor_r = "94.130.141.74:11085"; // the anchor's advertised relay R
        let peer = PeerConfig {
            public_key: [0x00u8; 32], // smaller than ours ⇒ the peer is the anchor
            // The anchor's endpoints = LAN ∪ R; the sole PUBLIC one is R.
            endpoints: vec!["192.168.1.5:51820".into(), anchor_r.into()],
            // Peer is UDP-capable (has srflx) so this is the both-UDP-OK
            // tie-break case, not the UDP-blocked-peer override.
            srflx_endpoints: vec!["198.51.100.7:41000".into()],
            supports_quic: true,
            supports_relay_single: true,
            ..base_peer()
        };
        // request() must NOT hit the wire for a dialer (it allocates nothing and
        // asks for no creds — the anchor owns the relay).
        coord.request(node, peer.clone()).await;
        assert!(coord.is_tracking(&node), "dialer link is tracked");
        assert!(
            rx.try_recv().is_err(),
            "a single-relay dialer sends NO OverlayRelayRequest"
        );
        // maybe_complete builds a raw carrier dialing the anchor's R (never LAN).
        let link = coord
            .maybe_complete(node, &peer)
            .expect("dialer link ready once R is known");
        assert_eq!(link.public_key, [0x00u8; 32]);
        assert!(
            link.supports_quic,
            "supports_quic carries through so install_ready runs the QUIC upgrade"
        );
        assert_eq!(
            link.single_relay,
            Some(false),
            "the link carries the DIALER role: install_ready FORCES the QUIC \
             carrier AND makes us the QUIC CLIENT (the anchor serves on its \
             allocation — only the server-side consumes observed sources)"
        );
        let (_conn, dst) = link.relay_parts.expect("relay parts present");
        assert_eq!(
            dst,
            anchor_r.parse().unwrap(),
            "dialer dials the anchor's R, not its LAN endpoint"
        );
        assert!(
            !coord.is_tracking(&node),
            "a built link leaves the dialing set"
        );
    }

    #[tokio::test]
    async fn single_relay_role_flip_on_late_srflx_re_establishes() {
        // Regression: the role depends on the peer's srflx, which arrives on a
        // LATER trickle than the join. During that window a UDP-capable peer
        // looks UDP-blocked, so we (UDP-OK) pick "dialer" for it. When its srflx
        // finally lands the role flips; `maybe_complete` must FORGET the
        // stale-role link so the caller re-establishes — else the pair can
        // deadlock (both sides picked "dialer") forever.
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // We are UDP-OK with the SMALLER pubkey.
        let mut coord = RelayCoordinator::new(tx, [0x00u8; 32], true, vec![], None);
        coord.single_relay = true;
        let node = ObjectId::new();
        // Peer: larger pubkey, advertises single-relay, NO srflx yet → looks
        // UDP-blocked → we compute ourselves the DIALER.
        let blocked = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            srflx_endpoints: vec![],
            ..base_peer()
        };
        coord.request(node, blocked.clone()).await;
        assert!(coord.is_tracking(&node), "tracked as dialer");
        assert!(
            rx.try_recv().is_err(),
            "a dialer sends no coturn-creds request"
        );

        // The peer's srflx propagates → it's UDP-capable → the role flips to
        // ANCHOR (both UDP-OK, our pubkey smaller). maybe_complete must forget.
        let unblocked = PeerConfig {
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..blocked.clone()
        };
        assert!(coord.maybe_complete(node, &unblocked).is_none());
        assert!(
            !coord.is_tracking(&node),
            "the stale-role link is forgotten so the caller re-establishes"
        );

        // Re-request with the settled peer establishes us as the ANCHOR (asks
        // the server for creds → pending, no longer a dialer).
        coord.request(node, unblocked).await;
        assert!(coord.is_tracking(&node));
        assert!(
            matches!(rx.try_recv(), Ok(ClientMsg::OverlayRelayRequest { .. })),
            "re-established as anchor ⇒ sends a coturn-creds request"
        );
    }

    // ───────────────────── Phase D — DERP tier selection ─────────────────────

    /// An ESTABLISHED DERP link is re-graded once srflx settles — the gap that
    /// left the whole fleet on DERP after the coturn TTL fix restored srflx
    /// (2026-08-06). `maybe_complete`'s flip-recompute only fires while the peer
    /// is still tracked, and `try_build_derp` untracks it at build time.
    #[test]
    fn established_derp_regrades_once_srflx_settles() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let blocked = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec![],
            ..base_peer()
        };
        // Same peer, now advertising a public reflexive address.
        let udp_ok = PeerConfig {
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..blocked.clone()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        let t0 = Instant::now();

        // Nothing established yet ⇒ nothing to regrade.
        assert!(!c.derp_regrade_due(&nid, &udp_ok, t0));

        // Establish on DERP, then BUILD it — the build untracks the peer
        // (`derping` cleared) while `roles` keeps the established strategy.
        c.roles.insert(nid, RelayStrategy::Derp);
        c.derping.insert(nid, blocked.clone());
        assert!(c.try_build_derp(&nid).is_some());
        assert!(!c.is_tracking(&nid), "build must untrack the peer");

        // Peer still UDP-blocked ⇒ DERP is still right ⇒ no churn.
        assert!(!c.derp_regrade_due(&nid, &blocked, t0));
        // srflx arrived ⇒ single-relay now beats DERP ⇒ regrade.
        assert!(c.derp_regrade_due(&nid, &udp_ok, t0));
        // …but only once per cooldown, so an oscillating pair can't tear its
        // carrier down every netmap tick.
        assert!(!c.derp_regrade_due(&nid, &udp_ok, t0));
        assert!(!c.derp_regrade_due(
            &nid,
            &udp_ok,
            t0 + DERP_REGRADE_COOLDOWN - Duration::from_secs(1)
        ));
        // Allowed again once the cooldown has fully elapsed.
        assert!(c.derp_regrade_due(&nid, &udp_ok, t0 + DERP_REGRADE_COOLDOWN));
    }

    /// The regrade↔pin churn loop measured on DEVBOX on 2026-08-07: the P7 pin
    /// (1800 s) outlives the flat 600 s cooldown, so the moment it lapsed the
    /// regrade re-fired (15 s later, in the field), re-churned TURN, and was
    /// re-pinned — forever, on pairs that had been STABLE on DERP.
    /// A pin that lands right after our own regrade must book a strike.
    #[test]
    fn overruled_regrade_backs_off_past_the_pin() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let udp_ok = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        c.roles.insert(nid, RelayStrategy::Derp);

        let t0 = Instant::now();
        assert!(c.derp_regrade_due(&nid, &udp_ok, t0), "first regrade fires");

        // ~3 min later the server pins the pair — that is our churn.
        c.note_regrade_overruled(&nid, t0 + Duration::from_secs(180));
        assert_eq!(c.derp_regrade_strikes.get(&nid), Some(&1));

        // The pin lapses at +1800 s. Pre-fix the regrade re-fired here.
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(
            !c.derp_regrade_due(&nid, &udp_ok, t0 + Duration::from_secs(1_815)),
            "must NOT re-fire the moment the 30-min pin lapses"
        );
        // Well past the pin the TIMER is satisfied — but the evidence gate
        // holds an overruled peer until something about the pair actually
        // changes, so this test threads fresh evidence to exercise the
        // ladder. `overruled_peer_does_not_retry_on_the_timer_alone` covers
        // the unchanged case.
        let moved = PeerConfig {
            srflx_endpoints: vec!["198.51.100.1:41000".into()],
            ..udp_ok.clone()
        };
        assert!(c.derp_regrade_due(&nid, &moved, t0 + Duration::from_secs(180 + 2_400)));

        // A second overrule escalates the ladder a rung and the evidence
        // ceiling re-arms. Same `moved` config as the last fire, so the
        // evidence gate is neutral and the gating alone is under test.
        let t2 = t0 + Duration::from_secs(180 + 2_400);
        c.note_regrade_overruled(&nid, t2 + Duration::from_secs(180));
        assert_eq!(c.derp_regrade_strikes.get(&nid), Some(&2));
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(!c.derp_regrade_due(&nid, &moved, t2 + Duration::from_secs(2_400)));
    }

    /// A regrade the server never overruled counts as having HELD: the peer's
    /// strikes reset, so a pair whose network later recovers is not stuck on
    /// yesterday's top-rung backoff forever.
    #[test]
    fn surviving_regrade_clears_the_backoff() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let udp_ok = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        c.roles.insert(nid, RelayStrategy::Derp);
        let t0 = Instant::now();

        // Each attempt carries fresh evidence (a new srflx mapping) so the
        // evidence gate lets the ladder run; this test is about STRIKES.
        let ep = |p: u16| PeerConfig {
            srflx_endpoints: vec![format!("198.51.100.1:{p}")],
            ..udp_ok.clone()
        };

        // Two overruled regrades put the peer deep into the backoff.
        assert!(c.derp_regrade_due(&nid, &ep(1), t0));
        c.note_regrade_overruled(&nid, t0 + Duration::from_secs(120));
        c.roles.insert(nid, RelayStrategy::Derp);
        let t1 = t0 + Duration::from_secs(3_000);
        assert!(c.derp_regrade_due(&nid, &ep(2), t1));
        c.note_regrade_overruled(&nid, t1 + Duration::from_secs(120));
        assert_eq!(c.derp_regrade_strikes.get(&nid), Some(&2));

        // The next regrade is NOT overruled — it survives the window.
        c.roles.insert(nid, RelayStrategy::Derp);
        let t2 = t1 + Duration::from_secs(7_500);
        assert!(c.derp_regrade_due(&nid, &ep(3), t2));
        // Asking again well after the window judges that regrade as held.
        c.roles.insert(nid, RelayStrategy::Derp);
        let t3 = t2 + Duration::from_secs(30_000);
        assert!(c.derp_regrade_due(&nid, &ep(4), t3));
        assert!(
            !c.derp_regrade_strikes.contains_key(&nid),
            "a regrade that held must clear the backoff"
        );
    }

    /// The evidence gate — what takes repeats from "rarer" to zero. Once the
    /// server has overruled a peer, the backoff timer expiring is NOT on its
    /// own a reason to try again: if nothing about the pair changed, the retry
    /// can only fail and churn the carrier a second time.
    #[test]
    fn overruled_peer_does_not_retry_on_the_timer_alone() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        c.roles.insert(nid, RelayStrategy::Derp);
        let t0 = Instant::now();

        assert!(c.derp_regrade_due(&nid, &peer, t0));
        c.note_regrade_overruled(&nid, t0 + Duration::from_secs(120));

        // Backoff elapsed, inputs IDENTICAL ⇒ still refused. Pre-fix this
        // fired and produced the repeat.
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(!c.derp_regrade_due(&nid, &peer, t0 + Duration::from_secs(3_000)));
        // …and stays refused for the whole evidence ceiling, not just one
        // backoff window.
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(!c.derp_regrade_due(&nid, &peer, t0 + Duration::from_secs(7_000)));
        // Phase C — past the ceiling the exile is BOUNDED: one floor-cushioned
        // probe is permitted even with unchanged evidence (covers far-side
        // changes the vector cannot observe).
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(c.derp_regrade_due(&nid, &peer, t0 + Duration::from_secs(8_000)));
    }

    /// Phase C — the measured vector is first-class regrade evidence: a
    /// struck peer whose `relay_band_udp` bit flips (a netcheck re-measure
    /// landed on either end) bypasses the evidence ceiling immediately,
    /// while the same peer with an unchanged vector stays gated. This is
    /// the loop the latch demotion promised: conviction → re-probe →
    /// measured flip → selection recomputes, no timer guessing.
    #[test]
    fn measured_vector_flip_unlocks_a_struck_regrade() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        c.roles.insert(nid, RelayStrategy::Derp);
        let t0 = Instant::now();
        assert!(c.derp_regrade_due(&nid, &peer, t0));
        c.note_regrade_overruled(&nid, t0 + Duration::from_secs(120));

        // Unchanged inputs inside the ceiling ⇒ gated (the baseline).
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(!c.derp_regrade_due(&nid, &peer, t0 + Duration::from_secs(3_000)));

        // The peer's measured relay-band bit lands (netcheck advert reached
        // the netmap) ⇒ NEW EVIDENCE ⇒ the gate opens at once.
        let measured = PeerConfig {
            relay_band_udp: Some(true),
            ..peer.clone()
        };
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(
            c.derp_regrade_due(&nid, &measured, t0 + Duration::from_secs(3_100)),
            "a measured-vector flip must supersede the evidence ceiling"
        );

        // Our OWN measured bit flipping is evidence too.
        c.note_regrade_overruled(&nid, t0 + Duration::from_secs(3_200));
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(!c.derp_regrade_due(&nid, &measured, t0 + Duration::from_secs(6_000)));
        c.set_relay_band_udp(Some(true));
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(
            c.derp_regrade_due(&nid, &measured, t0 + Duration::from_secs(6_100)),
            "our own measured flip is regrade evidence as well"
        );
    }

    /// …but the gate must not WEDGE a pair: real new evidence (the peer's srflx
    /// changed) supersedes the backoff instead of waiting it out.
    #[test]
    fn new_evidence_supersedes_the_backoff() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        c.roles.insert(nid, RelayStrategy::Derp);
        let t0 = Instant::now();
        assert!(c.derp_regrade_due(&nid, &peer, t0));
        c.note_regrade_overruled(&nid, t0 + Duration::from_secs(120));

        // The peer re-NATs to a different mapping — that IS new information.
        let moved = PeerConfig {
            srflx_endpoints: vec!["198.51.100.7:51000".into()],
            ..peer.clone()
        };
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(
            c.derp_regrade_due(&nid, &moved, t0 + Duration::from_secs(900)),
            "changed inputs must not sit out a backoff earned by a stale failure"
        );

        // A mere REORDER of the same endpoints is not evidence.
        let reordered = PeerConfig {
            srflx_endpoints: vec!["198.51.100.7:51000".into()],
            ..moved.clone()
        };
        c.note_regrade_overruled(&nid, t0 + Duration::from_secs(1_000));
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(!c.derp_regrade_due(&nid, &reordered, t0 + Duration::from_secs(4_000)));
    }

    /// Fresh evidence still cannot beat the absolute floor — a flapping srflx
    /// must not be able to churn the carrier every netmap tick.
    #[test]
    fn evidence_cannot_beat_the_minimum_spacing() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let a = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        let b = PeerConfig {
            srflx_endpoints: vec!["203.0.113.9:40001".into()],
            ..a.clone()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        c.roles.insert(nid, RelayStrategy::Derp);
        let t0 = Instant::now();
        assert!(c.derp_regrade_due(&nid, &a, t0));
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(!c.derp_regrade_due(&nid, &b, t0 + Duration::from_secs(30)));
        c.roles.insert(nid, RelayStrategy::Derp);
        assert!(c.derp_regrade_due(&nid, &b, t0 + DERP_REGRADE_COOLDOWN));
    }

    /// A pin for a peer we did NOT just regrade is somebody else's escalation —
    /// it must not book a strike against us.
    #[test]
    fn unrelated_pin_books_no_strike() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        // Never regraded at all.
        c.note_regrade_overruled(&nid, Instant::now());
        assert!(!c.derp_regrade_strikes.contains_key(&nid));
        // Regraded, but far outside the attribution window.
        let t0 = Instant::now();
        c.derp_regrade_last.insert(nid, t0);
        c.note_regrade_overruled(&nid, t0 + REGRADE_OVERRULE_WINDOW + Duration::from_secs(1));
        assert!(!c.derp_regrade_strikes.contains_key(&nid));
    }

    /// A server force-DERP pin (P7) outranks the regrade: `relay_strategy`
    /// checks the pin first, so a pinned pair keeps answering `Derp` and is
    /// never torn off the tier the server just escalated it onto.
    #[test]
    fn forced_derp_pin_suppresses_the_regrade() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        let nid = test_nid();
        let udp_ok = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        c.single_relay = true;
        c.derp = true;
        c.roles.insert(nid, RelayStrategy::Derp);
        // Pinned by the server ⇒ suppressed even though srflx says otherwise.
        c.force_derp(nid, Duration::from_secs(300), None);
        assert!(!c.derp_regrade_due(&nid, &udp_ok, Instant::now()));
    }

    #[test]
    fn relay_strategy_falls_to_derp_only_when_both_udp_blocked() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([9u8; 32]).0;
        // A coordinator with single-relay + DERP forced to a given state.
        let mk = |derp_on: bool, my_udp_ok: bool, m: Option<Arc<DerpMux>>| {
            let mut c = RelayCoordinator::new(tx.clone(), [0x00u8; 32], my_udp_ok, vec![], m);
            c.single_relay = true;
            c.derp = derp_on;
            c
        };
        let peer = |derp: bool, udp: bool| PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: derp,
            srflx_endpoints: if udp {
                vec!["203.0.113.9:40000".into()]
            } else {
                vec![]
            },
            ..base_peer()
        };
        // Both UDP-blocked + both advertise DERP + flag on + WS present ⇒ DERP.
        assert_eq!(
            mk(true, false, Some(mux.clone())).relay_strategy(&test_nid(), &peer(true, false)),
            RelayStrategy::Derp
        );
        // DERP flag off ⇒ both-allocate (single-relay can't: both UDP-blocked).
        assert_eq!(
            mk(false, false, Some(mux.clone())).relay_strategy(&test_nid(), &peer(true, false)),
            RelayStrategy::BothAllocate
        );
        // No `/derp` WS present ⇒ both-allocate.
        assert_eq!(
            mk(true, false, None).relay_strategy(&test_nid(), &peer(true, false)),
            RelayStrategy::BothAllocate
        );
        // Peer doesn't advertise DERP ⇒ both-allocate.
        assert_eq!(
            mk(true, false, Some(mux.clone())).relay_strategy(&test_nid(), &peer(false, false)),
            RelayStrategy::BothAllocate
        );
        // A UDP-capable side exists ⇒ single-relay wins over DERP (we're blocked,
        // the peer is UDP-OK ⇒ we anchor). DERP is strictly the both-blocked tier.
        assert_eq!(
            mk(true, false, Some(mux)).relay_strategy(&test_nid(), &peer(true, true)),
            RelayStrategy::SingleRelay(true)
        );
    }

    /// Field 2026-08-15/16 — a DERP link must never be built over a mux whose
    /// WS is down (the Arc exists while it reconnects through a throttled corp
    /// TLS path): the carrier would be born dead and churn the pair every
    /// sweep for as long as the reconnect takes — with force-DERP pins active
    /// that loop was a multi-minute blackhole. WITHHOLD while down (pair stays
    /// tracked); build the moment it's back.
    #[tokio::test]
    async fn derp_build_withholds_while_the_mux_is_down() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([0x00u8; 32]).0;
        let mut coord = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux.clone()));
        coord.single_relay = true;
        coord.derp = true;
        let node = ObjectId::new();
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec![],
            ..base_peer()
        };
        mux.mark_down();
        coord.request(node, peer.clone()).await;
        assert!(coord.is_tracking(&node), "pair is tracked while withheld");
        assert!(
            coord.maybe_complete(node, &peer).is_none(),
            "no carrier over a down mux"
        );
        assert!(coord.is_tracking(&node), "withheld, not forgotten");
        mux.mark_up();
        let link = coord
            .maybe_complete(node, &peer)
            .expect("builds the moment the mux is back");
        assert_eq!(link.relay_kind, RelayKind::Derp);
    }

    /// Phase A2 — the floor lifecycle: installs at birth for a both-capable
    /// pair on a live mux; withheld when the mux is down or the peer lacks
    /// the capability (caller falls through); superseded by a TURN build;
    /// OUTSIDE `is_tracking` so the strategy machinery never touches it;
    /// rebuildable after death+forget.
    #[tokio::test]
    async fn floor_installs_withholds_supersedes_and_survives_strategy_paths() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([0x00u8; 32]).0;
        let mut coord = RelayCoordinator::new(tx, [0x00u8; 32], true, vec![], Some(mux.clone()));
        coord.single_relay = true;
        coord.derp = true;
        coord.derp_floor = true;
        let node = ObjectId::new();
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            supports_derp_floor: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };

        // (2) withheld while the mux WS is down — the caller's ladder runs.
        mux.mark_down();
        assert!(coord.build_floor(node, &peer).is_none());
        assert!(!coord.is_floored(&node));
        mux.mark_up();

        // (3) a peer without the floor capability never floors.
        let pre_floor = PeerConfig {
            supports_derp_floor: false,
            ..peer.clone()
        };
        assert!(coord.build_floor(node, &pre_floor).is_none());

        // (1) both-capable + live mux ⇒ immediate derp link, tracked as
        // floored but NOT as strategy state.
        let link = coord.build_floor(node, &peer).expect("floor installs");
        assert_eq!(link.relay_kind, RelayKind::Derp);
        assert_eq!(link.single_relay, None, "the floor is symmetric");
        assert!(coord.is_floored(&node));
        assert!(
            !coord.is_tracking(&node),
            "floored ≠ tracking — the parallel TURN request path stays open"
        );

        // (5) a strategy recompute (srflx trickle) for an untracked node is
        // a no-op — the floor survives maybe_complete untouched.
        assert!(coord.maybe_complete(node, &peer).is_none());
        assert!(coord.is_floored(&node));

        // This pair is single-relay (both udp-ok) — the floor block would
        // fire the parallel request.
        assert!(!coord.strategy_is_derp(&node, &peer));

        // (4) the parallel TURN coordination completing supersedes the
        // floor: the warm fast-commit (we anchor — smaller pubkey, both
        // udp-ok) puts the pair in `allocated`, and try_build yields TURN.
        coord.set_warm_leg(Some(Arc::new(WarmTestConn)));
        coord.request(node, peer.clone()).await;
        if let Some(turn) = coord.maybe_complete(node, &peer) {
            assert_eq!(turn.relay_kind, RelayKind::Turn);
            assert!(
                !coord.is_floored(&node),
                "a TURN link must clear the floor bookkeeping"
            );
        } else {
            // No warm-commit shape in this fixture — supersede via the
            // explicit hook instead.
            coord.forget(&node);
            assert!(!coord.is_floored(&node));
        }

        // (6) after death+forget the floor rebuilds without a round-trip.
        coord.forget(&node);
        assert!(coord.build_floor(node, &peer).is_some());
        assert!(coord.is_floored(&node));

        // (7) #24 — a DIRECT death must also free the floor. `forget` runs
        // only for relay deaths (a direct death must not wipe allocation /
        // role state), so `clear_floor` is what the direct path calls. Without
        // it the stale entry made `!is_floored()` false forever and the
        // establish walk never rebuilt the floor — the peer then depended
        // entirely on a ladder that a corp VPN (no srflx, no dialer role) can
        // not complete, and sat "blocked" indefinitely.
        assert!(coord.is_floored(&node), "floored before the direct upgrade");
        assert!(coord.clear_floor(&node), "the direct death frees the floor");
        assert!(!coord.is_floored(&node));
        assert!(
            coord.build_floor(node, &peer).is_some(),
            "the floor MUST rebuild after a direct carrier dies — this is the \
             regression that wedged winhost-a's secondary org on 2026-08-19"
        );
        assert!(coord.is_floored(&node));
        // Idempotent: clearing twice is harmless (the death path is allowed
        // to run for peers that were never floored).
        assert!(coord.clear_floor(&node));
        assert!(!coord.clear_floor(&node));

        // (8) #24 — the establish walk gates the floor on `is_derping`, NOT
        // `is_tracking`. A peer tracked as a single-relay DIALER is
        // carrier-less and waiting on an anchor advert that may never come
        // (`request` inserts into `dialing` and returns — no allocation, no
        // wire message, no timeout), so it MUST still be floorable. Only a
        // DERPING peer is excluded, because its link is the same carrier
        // over the same mux.
        coord.forget(&node);
        coord.dialing.insert(node, peer.clone());
        assert!(coord.is_tracking(&node), "dialing counts as tracking");
        assert!(
            !coord.is_derping(&node),
            "a single-relay dialer is NOT derping — it must remain floorable, \
             or it starves whenever the anchor never advertises R"
        );
        coord.dialing.remove(&node);
        coord.derping.insert(node, peer.clone());
        assert!(
            coord.is_derping(&node),
            "a derping peer IS excluded — the floor would duplicate its link"
        );
        coord.derping.remove(&node);
    }

    /// #27/#28 — the coordinator must arm the runtime's event sink on muxes
    /// that arrive AFTER the sink does, and on regional muxes, not just the one
    /// it was constructed with. A mux that never got the sink is a mux whose
    /// black hole stays silent and whose recovery never wakes the walk — the
    /// exact failures this seam exists to close, and easy to half-wire because
    /// muxes enter through three different doors.
    #[tokio::test]
    async fn the_event_sink_reaches_muxes_that_arrive_later() {
        let (ctl, _ctl_rx) = mpsc::channel::<ClientMsg>(8);
        let (tx, mut rx) = mpsc::channel(DerpMux::EVENT_SINK_DEPTH);
        // Constructed with NO mux at all — the lazy-open shape.
        let mut coord = RelayCoordinator::new(ctl, [0u8; 32], true, vec![], None);
        coord.set_event_sink(tx);

        // Door 1: the central mux, registered later.
        let central = DerpMux::new([9u8; 32]).0;
        coord.set_derp_mux(Arc::clone(&central));
        let mut frame = [0xAAu8; 32].to_vec();
        frame.push(1);
        central.deliver(&frame);
        assert_eq!(
            rx.try_recv().ok(),
            Some(MuxEvent::Unrouted([0xAA; 32])),
            "a central mux registered after the sink must still report"
        );
        central.mark_down();
        central.mark_up();
        assert_eq!(rx.try_recv().ok(), Some(MuxEvent::Recovered));

        // Door 2: a regional mux.
        let regional = DerpMux::new([8u8; 32]).0;
        coord.set_regional_mux("wss://derp.example/derp", Arc::clone(&regional));
        let mut frame = [0xBBu8; 32].to_vec();
        frame.push(1);
        regional.deliver(&frame);
        assert_eq!(
            rx.try_recv().ok(),
            Some(MuxEvent::Unrouted([0xBB; 32])),
            "a regional mux must report on the SAME channel as the central one"
        );
    }

    /// #27 — `follow_peer_to_derp` builds for a peer holding NO relay slot (the
    /// ordinary case: we have it on a direct carrier that looks fine from
    /// here), and refuses on each of its three preconditions. It must NOT
    /// behave like `force_derp`: no TTL pin, no `roles` override, so the pair's
    /// relay strategy — and therefore its ability to re-coordinate normally
    /// once the network settles — is untouched.
    #[tokio::test]
    async fn follow_peer_to_derp_builds_without_pinning_the_pair() {
        let (tx, _rx) = mpsc::channel::<ClientMsg>(8);
        let node = ObjectId::new();
        let peer = PeerConfig {
            supports_derp: true,
            supports_derp_floor: true,
            ..base_peer()
        };

        // No mux at all ⇒ declined (a build would have nothing to ride).
        let mut bare = RelayCoordinator::new(tx.clone(), [0u8; 32], true, vec![], None);
        assert!(bare.follow_peer_to_derp(node, peer.clone()).is_none());

        let mux = DerpMux::new([9u8; 32]).0;
        let mut coord = RelayCoordinator::new(tx, [0u8; 32], true, vec![], Some(Arc::clone(&mux)));

        // A peer that cannot speak DERP ⇒ declined before anything is touched.
        let no_derp = PeerConfig {
            supports_derp: false,
            ..peer.clone()
        };
        assert!(coord.follow_peer_to_derp(node, no_derp).is_none());
        assert!(
            !coord.strategy_is_derp(&node, &peer),
            "a declined follow must not have flipped any strategy"
        );

        // The real case: no relay slot (we hold it on direct) ⇒ builds.
        let link = coord
            .follow_peer_to_derp(node, peer.clone())
            .expect("a peer relaying to us is followable");
        assert_eq!(link.relay_kind, RelayKind::Derp);
        assert_eq!(link.node_id, node);
        assert!(
            !coord.forced_derp_active(&node),
            "follow must NOT pin the pair like a server force-derp escalation \
             — the pin would outlive the transient condition that caused it"
        );

        // Mux mid-reconnect ⇒ withheld, not a carrier born dead — and the
        // decision happens BEFORE any mutation, so a withheld follow leaves no
        // tracking slot behind on a peer that is still installed elsewhere.
        mux.mark_down();
        let other = ObjectId::new();
        assert!(
            coord.follow_peer_to_derp(other, peer.clone()).is_none(),
            "a DERP carrier built over a down WS is born dead — withhold instead"
        );
        assert!(
            !coord.is_tracking(&other),
            "a withheld follow must not park the peer in a tracking slot"
        );
    }

    #[tokio::test]
    async fn derp_link_tracks_without_request_and_builds_symmetric_carrier() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([0x00u8; 32]).0;
        // We are UDP-BLOCKED; DERP on + WS present.
        let mut coord = RelayCoordinator::new(tx, [0x00u8; 32], false, vec![], Some(mux));
        coord.single_relay = true;
        coord.derp = true;
        let node = ObjectId::new();
        // Peer: UDP-blocked (no srflx), advertises single-relay + DERP.
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec![],
            ..base_peer()
        };
        // A DERP link makes NO server round-trip (both ends dial the `/derp` WS).
        coord.request(node, peer.clone()).await;
        assert!(coord.is_tracking(&node), "DERP link is tracked");
        assert!(
            rx.try_recv().is_err(),
            "a DERP link sends NO OverlayRelayRequest"
        );
        // maybe_complete builds the symmetric DERP carrier immediately.
        let link = coord.maybe_complete(node, &peer).expect("DERP link ready");
        assert_eq!(link.public_key, [0xFFu8; 32]);
        assert_eq!(link.relay_kind, RelayKind::Derp);
        assert_eq!(
            link.single_relay, None,
            "DERP is symmetric — no anchor/dialer role"
        );
        assert!(!link.supports_quic, "DERP raw v1 never rides QUIC (A2)");
        assert!(link.relay_parts.is_some(), "DERP carrier has relay parts");
        assert!(
            !coord.is_tracking(&node),
            "a built link leaves the derping set"
        );
    }

    #[test]
    fn single_relay_anchor_dst_uses_dialer_srflx_or_withholds() {
        // The anchor's dst-selection from `try_build`, isolated: it dials the
        // DIALER's public srflx IP (for the IP-only permit), never LAN, and
        // WITHHOLDS (None) when the dialer has advertised no srflx yet.
        let pick = |srflx: &[&str]| -> Option<SocketAddr> {
            srflx
                .iter()
                .filter_map(|e| e.parse().ok())
                .find(|s: &SocketAddr| !is_lan_addr(s.ip()))
        };
        assert_eq!(
            pick(&["203.0.113.9:40000"]),
            Some("203.0.113.9:40000".parse().unwrap()),
            "public srflx ⇒ permit that IP"
        );
        assert_eq!(
            pick(&["192.168.1.9:40000", "203.0.113.9:41000"]),
            Some("203.0.113.9:41000".parse().unwrap()),
            "skip LAN, take the public srflx"
        );
        assert!(
            pick(&["192.168.1.9:40000"]).is_none(),
            "only LAN ⇒ withhold"
        );
        assert!(pick(&[]).is_none(), "no srflx advertised ⇒ withhold");
    }

    /// P7 — the forced pin beats every capability-derived tier while
    /// unexpired (so `maybe_complete`'s strategy recompute can't thrash a
    /// pinned pair), and lapses back to the normal strategy on expiry.
    #[tokio::test]
    async fn forced_derp_pin_beats_single_relay_and_expires() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let mux = DerpMux::new([0x00u8; 32]).0;
        // BOTH ends UDP-capable ⇒ the natural strategy is SingleRelay.
        let mut coord = RelayCoordinator::new(tx, [0x00u8; 32], true, vec![], Some(mux));
        coord.single_relay = true;
        coord.derp = true;
        let node = ObjectId::new();
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };
        assert_eq!(
            coord.relay_strategy(&node, &peer),
            RelayStrategy::SingleRelay(true),
            "natural tier before the pin"
        );
        assert!(
            coord
                .force_derp(node, Duration::from_secs(60), None)
                .is_none()
        );
        assert_eq!(
            coord.relay_strategy(&node, &peer),
            RelayStrategy::Derp,
            "pin wins over SingleRelay"
        );
        // Another peer is unaffected.
        assert_eq!(
            coord.relay_strategy(&ObjectId::new(), &peer),
            RelayStrategy::SingleRelay(true)
        );
        // Expiry: back-date the pin ⇒ the natural strategy resumes.
        coord
            .forced_derp_until
            .insert(node, Instant::now() - Duration::from_secs(1));
        assert_eq!(
            coord.relay_strategy(&node, &peer),
            RelayStrategy::SingleRelay(true),
            "expired pin lapses to the natural tier"
        );
    }

    /// P7 — `force_derp` reconciles every coordination slot into `derping`
    /// (and builds when possible), is stamp-only for an untracked peer, and
    /// refuses without a mux.
    #[tokio::test]
    async fn force_derp_reconciles_slots() {
        let mk = || {
            let (tx2, _rx2) = tokio::sync::mpsc::channel::<ClientMsg>(8);
            let mux = DerpMux::new([0x00u8; 32]).0;
            let mut c = RelayCoordinator::new(tx2, [0x00u8; 32], true, vec![], Some(mux));
            c.single_relay = true;
            c.derp = true;
            c
        };
        let peer = PeerConfig {
            public_key: [0xFFu8; 32],
            supports_relay_single: true,
            supports_derp: true,
            srflx_endpoints: vec!["203.0.113.9:40000".into()],
            ..base_peer()
        };

        // pending → derping, and the DERP link builds immediately.
        let mut c = mk();
        let n = ObjectId::new();
        c.pending.insert(
            n,
            PendingPeer {
                peer: peer.clone(),
                ice: None,
                pair_key: None,
            },
        );
        let link = c
            .force_derp(n, Duration::from_secs(60), None)
            .expect("built");
        assert_eq!(link.relay_kind, RelayKind::Derp);
        assert!(c.pending.is_empty() && c.derping.is_empty());

        // dialing → derping.
        let mut c = mk();
        c.dialing.insert(n, peer.clone());
        let link = c
            .force_derp(n, Duration::from_secs(60), None)
            .expect("built");
        assert_eq!(link.relay_kind, RelayKind::Derp);
        assert!(c.dialing.is_empty());

        // allocated → derping; the dead relay leaves the advertised set.
        let mut c = mk();
        let sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        sock.set_nonblocking(true).unwrap();
        let conn: Arc<dyn RelayConn> = Arc::new(crate::transport::relay::UdpRelayConn(
            tokio::net::UdpSocket::from_std(sock).unwrap(),
        ));
        c.advertised.insert(n, "203.0.113.1:3478".into());
        c.allocated.insert(
            n,
            Allocated {
                conn,
                peer: peer.clone(),
            },
        );
        let link = c
            .force_derp(n, Duration::from_secs(60), None)
            .expect("built");
        assert_eq!(link.relay_kind, RelayKind::Derp);
        assert!(
            !c.advertised.contains_key(&n),
            "dead relay pruned from the trickle set"
        );

        // Untracked peer ⇒ stamp-only (pin governs the next cycle).
        let mut c = mk();
        assert!(c.force_derp(n, Duration::from_secs(60), None).is_none());
        assert!(c.forced_derp_active(&n), "pin stamped");

        // No mux ⇒ refused, no pin.
        let (tx3, _rx3) = tokio::sync::mpsc::channel::<ClientMsg>(8);
        let mut bare = RelayCoordinator::new(tx3, [0x00u8; 32], true, vec![], None);
        assert!(bare.force_derp(n, Duration::from_secs(60), None).is_none());
        assert!(!bare.forced_derp_active(&n), "no mux ⇒ no pin");
    }

    /// rc.222 — the both-allocate dst is SAME-WORKER ONLY. A peer whose
    /// endpoints carry no address on our allocation's worker (e.g. its relay
    /// advert was wiped by a rejoin, leaving only host/public addresses)
    /// WITHHOLDS — never dials a host IP as the "relay" (the field-proven
    /// zombie-carrier wedge: an outbound-blackhole dst whose rx stays alive
    /// on the peer's healthy inbound leg, so the sweep never cycles it).
    #[tokio::test]
    async fn try_build_withholds_without_same_worker_relay() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<ClientMsg>(8);
        let mut c = RelayCoordinator::new(tx, [0x00u8; 32], true, vec![], None);
        let n = ObjectId::new();
        let mk_conn = || -> (Arc<dyn RelayConn>, SocketAddr) {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_nonblocking(true).unwrap();
            let local = sock.local_addr().unwrap();
            (
                Arc::new(crate::transport::relay::UdpRelayConn(
                    tokio::net::UdpSocket::from_std(sock).unwrap(),
                )),
                local,
            )
        };

        // Peer advertises ONLY a public host address (no relay on our worker)
        // ⇒ WITHHOLD: no link, the allocation stays parked for the next netmap.
        let (conn, _local) = mk_conn();
        c.allocated.insert(
            n,
            Allocated {
                conn,
                peer: PeerConfig {
                    public_key: [0xFFu8; 32],
                    endpoints: vec!["203.0.113.7:33969".into()],
                    ..base_peer()
                },
            },
        );
        assert!(
            c.try_build(&n).is_none(),
            "host/public endpoint must never become the relay dst"
        );
        assert!(c.allocated.contains_key(&n), "still parked for retry");

        // Peer's relayed address on OUR worker (same IP as our allocation's
        // local socket) ⇒ build.
        let (conn2, local2) = mk_conn();
        let dst = format!("{}:45555", local2.ip());
        c.allocated.insert(
            n,
            Allocated {
                conn: conn2,
                peer: PeerConfig {
                    public_key: [0xFFu8; 32],
                    endpoints: vec!["203.0.113.7:33969".into(), dst.clone()],
                    ..base_peer()
                },
            },
        );
        let link = c.try_build(&n).expect("same-worker relay dst builds");
        assert_eq!(link.relay_parts.unwrap().1, dst.parse().unwrap());
    }
    #[tokio::test]
    async fn org_fallback_explicit_query_preserves_floor_and_ignores_unrelated_turn_grant() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (mux, mut frames) = DerpMux::new([0; 32]);
        let mut c = RelayCoordinator::new(tx, [0; 32], false, vec![], Some(mux));
        c.set_org_relay(true);
        c.derp = true;
        c.derp_floor = true;
        let node = ObjectId::new();
        let peer = PeerConfig {
            supports_derp: true,
            supports_derp_floor: true,
            supports_relay_single: false,
            srflx_endpoints: vec![],
            ..base_peer()
        };
        let floor = c.build_floor(node, &peer).unwrap();
        let (conn, dst) = floor.relay_parts.unwrap();
        let now = Instant::now();
        assert!(
            c.request_org_fallback(node, now).await,
            "fresh authorized metadata must have a server mint entrypoint even on DERP"
        );
        let ClientMsg::OverlayOrgRelayFallbackRequest {
            peer_node_id,
            request_id,
        } = rx.try_recv().unwrap()
        else {
            panic!("expected the typed ORG-only fallback request")
        };
        assert_eq!(peer_node_id, node);
        assert_eq!(request_id, 1);
        assert!(!c.is_tracking(&node));
        assert!(c.is_floored(&node));
        assert!(
            c.grant_accept(node, vec![], "unused-turn-reply".into())
                .is_none(),
            "an unrelated legacy TURN reply must not create a new allocation"
        );
        assert_eq!(conn.send_to(b"floor-still-live", dst).await.unwrap(), 16);
        assert!(
            frames.try_recv().is_ok(),
            "the same DERP connection still emits datagrams"
        );
        assert!(
            !c.request_org_fallback(node, now + Duration::from_secs(59))
                .await
        );
        assert!(rx.try_recv().is_err());
        assert!(c.request_org_fallback(node, now + ORG_FALLBACK_GAP).await);
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn org_fallback_respects_off_pin_pending_bind_and_death_backoff() {
        for gate in 0..5 {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            let mux = DerpMux::new([0; 32]).0;
            let mut c = RelayCoordinator::new(tx, [0; 32], false, vec![], Some(mux));
            c.set_org_relay(true);
            let node = ObjectId::new();
            let now = Instant::now();
            match gate {
                0 => c.set_org_relay(false),
                1 => {
                    c.forced_derp_until
                        .insert(node, now + Duration::from_secs(120));
                }
                2 => {
                    c.pending.insert(
                        node,
                        PendingPeer {
                            peer: base_peer(),
                            ice: None,
                            pair_key: None,
                        },
                    );
                }
                3 => {
                    c.org_binding.insert(node);
                }
                4 => {
                    c.death_streaks
                        .insert(node, (3, now + Duration::from_secs(60)));
                }
                _ => unreachable!(),
            }
            assert!(
                !c.request_org_fallback(node, now).await,
                "ignored gate {gate}"
            );
            assert!(rx.try_recv().is_err());
            assert!(c.org_fallback_last.is_empty());
        }
    }

    #[tokio::test]
    async fn org_fallback_queue_pressure_and_peer_state_are_bounded() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.send(ClientMsg::OverlayWarmRelayRequest {})
            .await
            .unwrap();
        let mut c = RelayCoordinator::new(tx, [0; 32], false, vec![], None);
        c.set_org_relay(true);
        let node = ObjectId::new();
        let now = Instant::now();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), c.request_org_fallback(node, now))
                .await
                .is_ok()
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(ClientMsg::OverlayWarmRelayRequest {})
        ));
        assert!(
            !c.request_org_fallback(node, now + Duration::from_secs(1))
                .await,
            "failed queue sends consume the same cooldown"
        );
        assert!(rx.try_recv().is_err());
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(128);
        let mut c2 = RelayCoordinator::new(tx2, [0; 32], false, vec![], None);
        c2.set_org_relay(true);
        for _ in 0..ORG_FALLBACK_MAX_PEERS {
            assert!(c2.request_org_fallback(ObjectId::new(), now).await);
        }
        assert_eq!(c2.org_fallback_last.len(), ORG_FALLBACK_MAX_PEERS);
        assert!(!c2.request_org_fallback(ObjectId::new(), now).await);
        while rx2.try_recv().is_ok() {}
        assert!(
            c2.request_org_fallback(ObjectId::new(), now + ORG_FALLBACK_GAP)
                .await
        );
        assert_eq!(c2.org_fallback_last.len(), ORG_FALLBACK_MAX_PEERS);
        assert!(
            c2.request_org_fallback(ObjectId::new(), now + ORG_FALLBACK_RETENTION * 2)
                .await
        );
        assert_eq!(c2.org_fallback_last.len(), 1);
    }
    #[tokio::test]
    async fn org_fallback_live_lease_on_derp_can_be_requeried_without_fake_session() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut c = RelayCoordinator::new(tx, [0; 32], false, vec![], None);
        c.set_org_relay(true);
        let node = ObjectId::new();
        c.org_session_accept(node, org_session(9, 60));
        assert!(c.org_sessions[&node].is_live(Instant::now()));
        assert!(c.request_org_fallback(node, Instant::now()).await);
        assert!(
            matches!(rx.try_recv(),Ok(ClientMsg::OverlayOrgRelayFallbackRequest{peer_node_id,..})if peer_node_id==node)
        );
        assert!(
            !c.org_sessions.contains_key(&node),
            "old failed carrier lease must not suppress its restoration reply"
        );
    }
    #[tokio::test]
    async fn org_fallback_fixed_peer_order_rotates_without_breaking_cooldowns() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let mut c = RelayCoordinator::new(tx, [0; 32], false, vec![], None);
        c.set_org_relay(true);
        let peers: Vec<_> = (1..=200u32)
            .map(|n| {
                let mut bytes = [0u8; 12];
                bytes[8..].copy_from_slice(&n.to_be_bytes());
                ObjectId::from_bytes(bytes)
            })
            .collect();
        let now = Instant::now();
        let mut sent_at = HashMap::new();
        let mut serial = 0;
        for round in 0..4 {
            let at = now + ORG_FALLBACK_GAP * round;
            c.request_org_fallback_batch(peers.clone(), at).await;
            let mut count = 0;
            while let Ok(message) = rx.try_recv() {
                let ClientMsg::OverlayOrgRelayFallbackRequest { peer_node_id, request_id } = message else {
                    panic!("unexpected legacy request");
                };
                assert_eq!(request_id, serial + 1);
                serial = request_id;
                if let Some(previous) = sent_at.insert(peer_node_id, at) {
                    assert!(at.duration_since(previous) >= ORG_FALLBACK_GAP);
                }
                count += 1;
            }
            assert!(count <= ORG_FALLBACK_MAX_PEERS);
            assert!(c.org_fallback_last.len() <= ORG_FALLBACK_MAX_PEERS);
        }
        assert_eq!(sent_at.len(), peers.len(), "fixed-order peers must all get a turn");
    }

}
