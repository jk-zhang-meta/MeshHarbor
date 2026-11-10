// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Overlay evidence counters — process-global, always compiled (increment
//! sites may live behind features/cfgs; a build without them reports honest
//! zeros). Cumulative since daemon start — consumers DIFF two readings,
//! never judge absolutes (the summary-counter rule).
//!
//! (The multi-org v2 retirement counters — mux-NAT rewrites/restores +
//! SkipAsSource flips — served their purpose: fleet-wide zeros over the
//! ≥7-day soak licensed the W7c deletion of the whole compensation layer,
//! and the counters left with it.)

use std::sync::atomic::AtomicU64;

/// PR-B1 tripwire — direct-socket binds that could NOT take the stable base
/// port and walked the band. On a host with a configured stable port this is
/// either an external squatter (Hyper-V/WSL reservation) or — the 2026-08-10
/// wedge — a second in-process binder colliding with the first's leaked
/// sockets. Nonzero on a quiet host is a bug signal, not noise.
pub static DIRECT_BIND_WALKS: AtomicU64 = AtomicU64::new(0);

/// #27/#32 — inbound `/derp` frames the mux could not hand to a consumer.
///
/// `UNROUTED`: no route for the source pubkey — a peer is relaying to us while
/// we hold it on a different carrier. That IS the demote-follow.s input, so on
/// a healthy mesh it ticks briefly around a transition and then stops; climbing
/// steadily means follows are not converging the pair.
///
/// `BACKPRESSURE`: a LIVE consumer whose inbound queue is full — it stopped
/// draining. A different fault, deliberately counted apart.
///
/// Process-global rather than per-mux because a node holds several (central +
/// one per relay region) and the question an operator asks is about the NODE.
/// They were per-mux and readable NOWHERE for a day, which is exactly why a
/// real 2026-08-25 transition could not be diagnosed.
pub static DERP_INBOUND_UNROUTED: AtomicU64 = AtomicU64::new(0);
pub static DERP_INBOUND_BACKPRESSURE: AtomicU64 = AtomicU64::new(0);

/// A3 — peer endpoints ADOPTED via WG-style roaming: an authenticated inbound
/// from a source other than the peer's registered endpoint repointed the
/// carrier. Expected to tick a few times as a symmetric-NAT peer's real
/// mapping is learned, then settle; a steadily climbing count means endpoint
/// thrash (a roam war or a spoof-probe storm) — worth a look, not silent.
pub static ROAM_ADOPTIONS: AtomicU64 = AtomicU64::new(0);

/// C1 (disco) — out-of-tunnel carrier echoes this node ANSWERED. The
/// responder-only stage has no other observable: a node that answers is a
/// node the future prober can measure, so this counter IS the C1 field gate
/// (every node nonzero before any prober ships).
pub static DISCO_ANSWERED: AtomicU64 = AtomicU64::new(0);

/// C2 (disco) — verified PONGs dropped because the owning engine's sink was
/// full. Every drop reads as LOSS in that engine's per-path table upstream
/// (the exact silent seam the 2026-08-12 half-protocol incident hid in), so
/// a nonzero here re-frames a bad loss number as backpressure, not path
/// quality.
pub static DISCO_PONG_DROPS: AtomicU64 = AtomicU64::new(0);

/// Authenticated/limiter-passed handshake initiations dropped because the
/// engine's accept channel (`direct_events`, depth 16) was full. Each drop
/// costs the initiating peer a ~5 s retransmit; a burst here during a
/// churn storm explains "slow re-establish" without blaming the network.
pub static DIRECT_INBOUND_DROPS: AtomicU64 = AtomicU64::new(0);

/// FR-68 — competing routes this node DELETED from the FIB.
///
/// #1237 ran for weeks and #1246 fixed it with nothing to measure either by:
/// an eviction has only ever been a WARN, and that WARN is throttled to
/// **1/min/prefix**, so counting log lines under-reports the true rate by up
/// to 40×. On a settled host this should be flat. Climbing steadily means a
/// route war — we delete, the competitor re-adds, neither side holds the FIB
/// (measured against AnyConnect: 25,197 → 33,294 in one day).
pub static ROUTE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// FR-68 — rows we declined to evict **because they belong to a sibling
/// meshharbor adapter** (another org's per-org TUN in this process, or a
/// co-tenant daemon's, matched by adapter alias).
///
/// ⚠️ This is deliberately NOT "sibling evictions". After #1246 a sibling row
/// is SPARED, so a sibling eviction is unreachable by construction — a counter
/// for it would read zero whether the fix works or has been reverted, and
/// would prove nothing either way. What is observable is the sparing itself:
/// on a multi-org host this climbs while [`ROUTE_EVICTIONS`] stays flat, and
/// with `OVERLAY_SIBLING_EXEMPT=0` that inverts. The pair is the assertion;
/// neither half means much alone.
pub static ROUTE_SIBLING_SPARES: AtomicU64 = AtomicU64::new(0);

/// FR-68 — route-defense waves run. The wave re-asserts every peer route, so
/// it is the unit of work a route war multiplies: each eviction is a FIB
/// change, which feeds our own route-change subscription, which arms the next
/// wave (rate-limited to 1 per 3 s). Waves/min far above the 30 s heartbeat
/// cadence means the guard is driving itself.
pub static ROUTE_WAVES: AtomicU64 = AtomicU64::new(0);

/// #1328 — times this node STOOD DOWN from defending a prefix after repeated
/// futile re-assertions (the generalised auto-yield).
///
/// Nonzero means a route war was detected and bounded. Zero on a healthy host.
/// ⚠️ Read it with [`ROUTE_EVICTIONS`]: yields climbing while evictions go flat
/// is the fix working; BOTH climbing means the backoff is being out-paced and
/// the cooldown is too short for that competitor.
pub static ROUTE_YIELDS: AtomicU64 = AtomicU64::new(0);

/// #1282 — which ARM armed a route-defense wave.
///
/// [`ROUTE_WAVES`] measured the rate and could not explain it: an idle host
/// runs 20/min average, bursting to ~40, against an intended 30 s heartbeat
/// (~2/min), and there is no log line for it at all. The two arms have
/// completely different meanings and completely different fixes — the blind
/// 2 s TICK means no live route-change subscription, while the EVENT arm at
/// its 3 s floor means something is generating change notifications
/// continuously (plausibly the guard's own re-assertions feeding back).
///
/// ⚠️ These are counted at the two CALL SITES, not inside `run_defense_wave`,
/// so `ROUTE_WAVES - (TICK + EVENT)` stays non-zero for any third caller
/// rather than silently mis-attributing it. A discrepancy is a finding.
pub static ROUTE_WAVES_TICK: AtomicU64 = AtomicU64::new(0);
pub static ROUTE_WAVES_EVENT: AtomicU64 = AtomicU64::new(0);

/// #1282 — TICK-arm waves that an EVENT pulled forward.
///
/// An event inside the 3 s quiet window does not run a wave. It resets the
/// tick to the window's end, and the tick runs and counts the wave. So a guard
/// whose own route writes keep re-arming it reads as `tick` ≫ `event`, which
/// is exactly what #1282 first misread as "no live subscription". The real
/// causes, found in #1856, were a delete-then-add per wave on macOS (every
/// peer /32) and on Windows (the block floors).
/// `pulled ≈ tick` is a self-feeding guard; on a healthy host `tick − pulled`
/// is the heartbeat (or the 2 s blind tick when there is no subscription) and
/// `pulled` stays near 0.
pub static ROUTE_WAVES_PULLED: AtomicU64 = AtomicU64::new(0);

/// FR-68 — carrier revalidations forced by a network change ("forced rekey
/// poke"). Each one re-keys every peer and can demote a healthy direct
/// carrier, so this is the counter that turns "the mesh feels unstable" into
/// a number. ~100/min was the #1237 signature on a two-org host.
pub static FORCED_REVALIDATIONS: AtomicU64 = AtomicU64::new(0);
