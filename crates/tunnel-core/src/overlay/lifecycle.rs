// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P2 — the ONE carrier lifecycle (consolidation invariant I2).
//!
//! Every liveness rule that can kill an overlay carrier lives here as a pure,
//! clock-free transition: *a carrier must HANDSHAKE within its tier deadline,
//! then keep being HEARD within the staleness bound, else it dies with a typed
//! [`DeathReason`]*. Before P2 these rules were four ad-hoc booleans accreted
//! across incidents (`hard_dead` rc.181, `punch_dead` Phase C/rc.204/rc.223,
//! `rx_stale` rc.206, one-way `bad_sweeps` rc.137) scattered through
//! `sweep_carrier_health`; the sweep now gathers inputs, calls
//! [`carrier_tick`], and dispatches the verdict — the rules themselves are
//! testable without tokio, sockets, or time.
//!
//! ## The lifecycle, derived — never stored
//!
//! A carrier's phase is DERIVED from the monotonic handshake latch
//! (`PeerStats::handshake` — boringtun exposes no rekey callback, so "never
//! handshaked" is inferred from `time_since_last_handshake().is_none()` + a
//! deadline, exactly as before):
//!
//! * [`CarrierPhase::Installing`] — handshake not latched. The only death is
//!   [`DeathReason::HandshakeDeadline`] (per-tier: LAN/srflx 12 s, public
//!   30 s, relay 45 s) — plus [`DeathReason::HardDead`] for a relay whose
//!   send hard-errored.
//! * [`CarrierPhase::Established`] — handshake latched (set-once). The deaths
//!   are [`DeathReason::RxStale`] (nothing heard — keepalives included — for
//!   the tier's [`DirectTier::rx_stale_deadline`]: direct 60 s, relay 90 s) and
//!   [`DeathReason::OneWay`] (tx advancing, rx flat, 3 sweeps).
//!
//! `Installing × RxStale` and `Established × HandshakeDeadline` are
//! structurally unreachable — the phase split makes the old comment-level
//! claims ("this can never fire again once the handshake latches") a matter
//! of construction.
//!
//! Storing the phase would duplicate the latch's truth (and break the tests
//! that literal-construct `Installed`); deriving it keeps `Installed`
//! field-for-field identical to pre-P2.
//!
//! ## Counter mechanics (corrected, was mis-stated pre-P2)
//!
//! Pre-handshake, `tx` is NOT strictly flat: boringtun's `encapsulate` with no
//! session queues the data packet and emits the handshake INITIATION as
//! `WriteToNetwork`, which the send path counts (+1 per rekey attempt, ~90 s
//! apart; timer-task retransmits ride `update_timers` and do NOT count). The
//! one-way detector still cannot fire pre-handshake because an isolated
//! single-sweep tx blip resets on the next sweep — locked by
//! `single_sweep_tx_blip_does_not_accumulate_bad_sweeps`.
//!
//! ## Dispositions (the sweep's half, unchanged by P2)
//!
//! | Trigger | Disposition |
//! |---|---|
//! | sweep death (any [`DeathReason`]) | teardown → tier cooldown/strike (direct) or refresh-cooldown (relay) → immediate re-request |
//! | probe expiry ([`ProbeVerdict::Expire`]) | drop probe, KEEP relay, book tier strike |
//! | netmap removal | park (peer left the mesh) |
//! | resume-from-suspend | mass drop + full re-coordinate |
//!
//! ## Boundary: the forced-DERP TTL pin is NOT lifecycle
//!
//! `RelayCoordinator::forced_derp_until` stays in `relay_link.rs`. It is
//! next-establishment *strategy* (which relay sub-tier the next (re)build
//! picks), server-pushed and TTL'd — its whole purpose is to OUTLIVE the
//! carriers it steers (the health sweep tears a carrier down; the pin shapes
//! the rebuild). Attaching it to a per-carrier lifecycle whose instance dies
//! with the carrier would be wrong by construction.

use std::time::Duration;

/// Which carrier tier an installed peer is on. Direct tiers differ in cooldown
/// bookkeeping (CC1 — a failure on one tier must never poison another) and
/// each tier carries a WG-handshake completion deadline (a carrier that never
/// establishes is torn down; direct tiers fall back to relay, the relay tier
/// re-coordinates).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum DirectTier {
    /// Same-subnet LAN direct (rc.131-135) — on-link. rc.204: gets a TIGHT
    /// handshake deadline too — pre-handshake tx/rx stay (near-)flat, so
    /// without a deadline a false LAN match (stale endpoint, AP isolation,
    /// VPN-captured reply path) was a PERMANENT zombie with no relay fallback.
    Lan,
    /// Direct-to-public NIC (Phase A) — off-link; public cooldown + a loose
    /// handshake deadline (the accept side may lag).
    Public,
    /// srflx hole-punch (Phase C) — off-link; srflx cooldown + a tight
    /// handshake deadline (a cross-NAT punch works in a couple of INIT cycles
    /// or won't at all).
    Srflx,
    /// coturn relay carrier — not a direct tier; governed by the hard-dead /
    /// one-way / rx-stale relay signals PLUS (rc.223) its own handshake
    /// deadline.
    Relay,
}

impl DirectTier {
    /// True for the direct tiers (everything but [`Relay`](Self::Relay)) — the
    /// carriers whose failure bookkeeping is keyed by tier.
    pub(crate) fn is_direct(self) -> bool {
        !matches!(self, DirectTier::Relay)
    }

    /// Phase C — the WG-handshake completion deadline past which a
    /// never-established carrier on this tier is torn down (direct tiers →
    /// relay fallback; relay tier → re-coordinate).
    pub(crate) fn handshake_deadline(self) -> Duration {
        match self {
            DirectTier::Srflx => SRFLX_HANDSHAKE_DEADLINE,
            DirectTier::Public => PUBLIC_HANDSHAKE_DEADLINE,
            // rc.204 — LAN gets a deadline too (see the variant doc): on-link
            // handshakes complete in milliseconds or not at all.
            DirectTier::Lan => LAN_HANDSHAKE_DEADLINE,
            // rc.223 — the RELAY tier gets one as well. A relay carrier that
            // never completes its handshake evaded EVERY detector (field
            // 2026-07-24, devbox on a UDP-hostile network): `punch_dead` was
            // direct-only, `rx_stale` requires a latched handshake,
            // `hard_dead` needs a send error (sends into a TURNS/TCP
            // allocation "succeed"), and the pre-handshake one-way counter
            // resets between rekey attempts (an init tx-blip is isolated, ~one
            // per 90 s), so `bad_sweeps` never accumulates — an IMMORTAL
            // zombie that also starved the P7 churn counter (no teardown → no
            // re-request → no forced-DERP escalation). Generous deadline: the
            // handshake needs BOTH ends' allocations installed, and the
            // peer's own grant cycle can lag ours by tens of seconds.
            DirectTier::Relay => RELAY_HANDSHAKE_DEADLINE,
        }
    }

    /// rc.206's absolute rx-staleness backstop, per tier.
    ///
    /// Split out of the former single global because the two cases are sized
    /// against different things. Both must clear the ~25 s persistent
    /// keepalive (`wg::KEEPALIVE_SECS`) with room for losses, but:
    ///
    /// * a **direct** carrier dies the instant its path is filtered — a
    ///   full-tunnel VPN connecting drops every off-tunnel datagram at once
    ///   (field 2026-08-08, winhost-a/Check Point: `ping` went from a steady
    ///   75 ms to total loss, and the mesh stayed dark for MINUTES waiting out
    ///   this deadline). 60 s still tolerates two consecutive lost keepalives,
    ///   and a false trip only forces a rebuild that re-establishes if the
    ///   path really recovered;
    /// * a **relay** carrier's liveness depends on a third party (coturn /
    ///   the DERP WS) whose own reconnects can legitimately straddle a
    ///   keepalive or two, so it keeps the original, more forgiving 90 s.
    ///
    /// This is the cheap half of the recovery work — it needs no new state, no
    /// probe, and no platform code. The active liveness poke that takes this
    /// below ~30 s is a separate change.
    pub(crate) fn rx_stale_deadline(self) -> Duration {
        if self.is_direct() {
            DIRECT_RX_STALE_DEADLINE
        } else {
            RELAY_RX_STALE_DEADLINE
        }
    }
}

/// Grace after install before the fallback can fire — lets the bilateral
/// handshake + first packets flow before we judge the carrier.
pub(crate) const DIRECT_GRACE: Duration = Duration::from_secs(8);
/// Consecutive bad sweeps (sent, received nothing) before falling back. At the
/// 5 s tick that's ~15 s of one-way traffic — long enough to ignore a blip,
/// short enough that a VPN/AP-isolation break doesn't stay dark for long.
pub(crate) const BAD_SWEEPS_TO_FALLBACK: u32 = 3;
/// rc.206 — the "silent zombie" backstop. An *established* carrier that stops
/// RECEIVING is dead even when it also stopped SENDING: a healthy peer emits a
/// WireGuard persistent-keepalive every ~25 s (`wg::KEEPALIVE_SECS`), so no
/// inbound packet for this long means the underlying path died AND boringtun
/// gave up re-handshaking (it stops emitting anything once a rekey attempt
/// expires ~90 s). With no tx either, the `tx>last_tx && rx==last_rx`
/// heuristic reads that as "just idle — no judgment" and never tears the
/// carrier down — observed in the field as an 8-hour "direct" carrier stuck at
/// 100 % loss with a frozen last-seen. This absolute rx-staleness deadline
/// catches it regardless of tx. A false trip only forces a (cheap) rebuild,
/// which re-establishes if the path actually recovered.
///
/// Sized per tier by [`DirectTier::rx_stale_deadline`] — read that for why the
/// two differ.
///
/// 60 s ≈ 2 missed keepalives. Chosen over the original 90 s because a direct
/// carrier's path can be revoked instantly (a full-tunnel VPN connecting), and
/// the old value was the whole reason the mesh stayed dark for minutes after
/// one.
pub(crate) const DIRECT_RX_STALE_DEADLINE: Duration = Duration::from_secs(60);
/// 90 s ≈ 3–4 missed keepalives — the original value, kept for the relay tier
/// (see [`DirectTier::rx_stale_deadline`]).
pub(crate) const RELAY_RX_STALE_DEADLINE: Duration = Duration::from_secs(90);
/// Phase C — the WG-handshake completion deadline for a srflx punch carrier:
/// past it with no session, the punch failed → tear down to relay. Tight —
/// bilateral INIT retransmit is ~5 s, so ~2 cycles + jitter + RTT covers a
/// genuine cross-NAT punch; longer just delays the relay fallback for a pair
/// that can't punch (e.g. one side symmetric).
pub(crate) const SRFLX_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(12);
/// Phase C — the handshake deadline for a public-direct (Phase A) carrier.
/// Looser than srflx: the accept side (a NAT'd client dialling a public exit)
/// can lag, and public-NIC reachability rarely fails outright, so we don't
/// rush it to relay. Still finite so a truly dead public dst can't zombie
/// forever (closes the same latent Phase A gap the srflx work exposed).
pub(crate) const PUBLIC_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
/// rc.223 — RELAY handshake deadline (see `handshake_deadline`'s Relay arm:
/// the never-handshaked relay was an immortal zombie invisible to every other
/// detector). Generous: the handshake needs both ends' allocations up, and
/// the peer's grant/allocate cycle can lag ours; a teardown just
/// re-coordinates (rate-limited by `RELAY_REFRESH_COOLDOWN`), and each
/// re-request feeds the P7 churn counter toward the forced-DERP escalation —
/// exactly the intended cascade on a network where TURN can't carry data.
pub(crate) const RELAY_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(45);
/// rc.204 — LAN handshake deadline. On-link, so a genuine same-subnet
/// handshake completes in milliseconds; one that hasn't completed by this
/// window is a false LAN match (stale/foreign endpoint, Wi-Fi AP isolation, a
/// VPN-captured reply path). Pre-rc.204 the LAN tier had NO deadline, and a
/// never-handshaken carrier's counters stay (near-)flat, so the rx-flat
/// heuristic never fired either — the pair was a permanent zombie with no
/// relay fallback (field-observed 2026-07-21: every LAN pair wedged in
/// `HANDSHAKE(REKEY_TIMEOUT)` while boringtun gave up after ~90 s). As tight
/// as srflx: it either establishes near-instantly or never will.
pub(crate) const LAN_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(12);
/// Stage 2 (active revalidation) — poke an ESTABLISHED carrier with a forced
/// WG rekey once it has been silent this long. Must clear the ~25 s persistent
/// keepalive (`wg::KEEPALIVE_SECS`) or every idle keepalive gap would poke;
/// 30 s = one keepalive interval + loss/jitter margin. The poke converts
/// "suspiciously quiet" into proof either way ~`handshake_deadline` later —
/// vs. waiting out the full `rx_stale_deadline` (60/90 s) doing nothing.
pub(crate) const POKE_SILENCE_AFTER: Duration = Duration::from_secs(30);
/// Stage 2 — ALSO poke when no INITIATOR-role handshake has completed within
/// this window (counting from install). This is the detector for the carrier
/// class the rx-anchored rules are structurally blind to (field 2026-08-08,
/// winhost-a→devbox): our tx dead while the peer's own traffic keeps arriving —
/// `rx_any` advances (so rx-staleness never fires) and `rx` trickles (so the
/// one-way counter resets), yet 100 % of our sends are lost. Only a completed
/// handshake WE initiated proves the round trip. ≈ WireGuard's own
/// REKEY_AFTER_TIME (120 s), so an active carrier usually refreshes the proof
/// organically and the poke only fires for idle or responder-role carriers —
/// one 2-packet handshake per peer per ~2 min at worst.
pub(crate) const POKE_PROOF_AFTER: Duration = Duration::from_secs(120);
/// #26 — the conviction window for a poke armed BY a netstate **Major** (a VPN
/// connect / default-route move), instead of the tier's handshake deadline.
///
/// Those deadlines (12 s LAN/Srflx, 30 s Public, 45 s Relay) answer a
/// different question: *"can a carrier ESTABLISH over this path?"* — a NAT
/// punch, a TURN allocation and two ends' grants all have to converge, so they
/// are generous by design. Re-validating an ALREADY-ESTABLISHED carrier is a
/// far easier question — a live path answers a forced rekey in ONE round trip
/// (single-digit ms on a LAN, ~200 ms across the internet) — and paying the
/// establish-sized deadline for it IS the VPN-transition hole: field
/// 2026-08-24 measured 9 dropped pings on a LAN/Srflx pair and **34** on a
/// public pair, both matching their tier deadline almost exactly.
///
/// ⚠️ The trade this makes, stated plainly: boringtun re-sends an in-flight
/// initiation about every 5 s, so a 12 s window judges 2–3 attempts while this
/// one judges **one**. A single dropped initiation therefore convicts. That is
/// the right side of an asymmetric bet — a *false* conviction demotes the pair
/// to the relay floor, which carries traffic at a worse RTT and re-upgrades
/// itself within a sweep or two (`RekeyUnanswered` deliberately books NO
/// PathMonitor strike or penalty, so the tier stays eligible), whereas a *late*
/// conviction is 100 % packet loss for its whole duration. Degrade beats
/// blackhole. It is also bounded: only ESTABLISHED **direct** carriers are
/// armed on a net-change, and `netstate` publishes at most one material Major
/// per `MAJOR_PUBLISH_COOLDOWN` (120 s), so this cannot become a churn engine.
pub(crate) const MAJOR_POKE_DEADLINE: Duration = Duration::from_secs(2);
/// §6.3 F1 — the conviction window for a poke armed by unanswered BUSINESS
/// traffic on an established direct carrier. The business scout re-sends one
/// fresh initiation after [`BUSINESS_POKE_RETAP_AFTER`], so this window judges
/// TWO attempts about a second apart, and a false conviction needs both lost.
/// The trade is the [`MAJOR_POKE_DEADLINE`] one: a false conviction costs a
/// detour over the DERP floor (`RekeyUnanswered` books no penalty), a late one
/// blackholes the pair for the whole window. It was 6 s (one initiation plus
/// boringtun's ~5 s re-send), which is most of the measured 8.75 s stall.
pub(crate) const BUSINESS_POKE_DEADLINE: Duration = Duration::from_secs(2);
/// The pre-F1 window, restored by `OVERLAY_BUSINESS_POKE_FAST=0` (the scout
/// then skips the re-send too).
pub(crate) const BUSINESS_POKE_LEGACY_DEADLINE: Duration = Duration::from_secs(6);
/// F1 — how long a business poke may stay unanswered before the scout sends
/// its single extra initiation. Below the 1 s scout tick, so tick jitter
/// cannot push the re-send past the window.
pub(crate) const BUSINESS_POKE_RETAP_AFTER: Duration = Duration::from_millis(800);

/// Why a carrier died. Precedence when several signals co-trip (mirrors the
/// pre-P2 log selection, which keyed off `(hard_dead, rx_stale)` in this
/// order): `HardDead` > `RxStale` > `HandshakeDeadline` > `OneWay`. The
/// dispatch half maps a reason to the SAME log line the old booleans chose —
/// on the direct side `HandshakeDeadline` and `OneWay` share the
/// "didn't establish" string, on the relay side they share "one-way", exactly
/// as before.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DeathReason {
    /// rc.181 — the carrier's send hard-errored (TURNS/TCP reset, lost
    /// QUIC-over-TURN connection). Relay-only in practice (a direct send
    /// failure is a dropped datagram, not a dead session); skips the warm-up
    /// grace.
    HardDead,
    /// rc.206 — established, then nothing heard (keepalives included) within
    /// [`DirectTier::rx_stale_deadline`].
    RxStale,
    /// Phase C / rc.204 / rc.223 — never handshaked within the tier's
    /// [`DirectTier::handshake_deadline`].
    HandshakeDeadline,
    /// rc.137 — tx advancing while rx stayed flat for
    /// [`BAD_SWEEPS_TO_FALLBACK`] consecutive sweeps.
    OneWay,
    /// Stage 2 — an active-revalidation poke (forced WG rekey,
    /// `format_handshake_initiation(force_resend: true)`) went unanswered for
    /// the tier's [`DirectTier::handshake_deadline`]. boringtun auto-retries an
    /// in-flight initiation every ~5 s, so even the tightest window (12 s) is
    /// 2–3 attempts — this is proof-grade, not a single lost packet. Books NO
    /// PathMonitor strike/penalty/Q-slam (see `PathMonitor::on_death`): the
    /// rebuild it triggers supplies fresh evidence itself, so a transient blip
    /// recovers with zero penalty and can't feed the forced-DERP escalation.
    RekeyUnanswered,
}

impl DeathReason {
    /// U1 — the wire/diagnostic short string (rides
    /// `OverlayRelayRequest.reason` so the server's escalation logs say WHY a
    /// relay carrier is being replaced, not just that it was).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DeathReason::HardDead => "hard-dead",
            DeathReason::RxStale => "rx-stale",
            DeathReason::HandshakeDeadline => "handshake-deadline",
            DeathReason::OneWay => "one-way",
            DeathReason::RekeyUnanswered => "rekey-unanswered",
        }
    }
}

/// The lifecycle phase, DERIVED from the monotonic handshake latch — never
/// stored (see the module doc).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CarrierPhase {
    /// Handshake not latched; must latch within `deadline` or die
    /// [`DeathReason::HandshakeDeadline`].
    Installing { deadline: Duration },
    /// Handshake latched (set-once); governed by rx-staleness and the one-way
    /// counter.
    Established,
}

impl CarrierPhase {
    /// Derive the phase for a carrier on `tier` with the given latch state.
    pub(crate) fn of(handshake_done: bool, tier: DirectTier) -> Self {
        if handshake_done {
            CarrierPhase::Established
        } else {
            CarrierPhase::Installing {
                deadline: tier.handshake_deadline(),
            }
        }
    }
}

/// Stage 2 — the sweep's view of a pending active-revalidation poke, built
/// from `Installed.last_poke_at` + the lock-free initiator-handshake stamp
/// (`WgDevice::peer_initiator_hs_answered`). `answered` means an
/// INITIATOR-role handshake completed at-or-after the poke — the only signal
/// that proves OUR outbound works. (Responder-role handshakes prove nothing
/// here: a peer whose tx works while ours is dead hammers initiations at us
/// and each one we answer re-establishes a session — an rx- or
/// either-role-anchored predicate would read permanently alive. Field
/// 2026-08-08.)
#[derive(Clone, Copy, Debug)]
pub(crate) struct PokeState {
    pub(crate) since_poke: Duration,
    pub(crate) answered: bool,
    /// #26 — this poke was armed by a netstate **Major** specifically, so it
    /// convicts on [`MAJOR_POKE_DEADLINE`] rather than the tier's
    /// establish-sized handshake deadline. ⚠️ Not merely "armed by a
    /// net-change": the chattier addr/iface cause arms the same poke with this
    /// `false`, deliberately (`runtime::ForcedPoke`). Carried on the POKE, not
    /// on the carrier — the class belongs to the question being asked, and a
    /// re-arm is what re-decides it.
    pub(crate) from_major: bool,
    /// Proof for an established direct path with unanswered application data.
    pub(crate) from_business: bool,
}

/// Everything [`carrier_tick`] needs about one installed carrier, gathered by
/// the sweep from the lock-free `PeerStats` reads + `Installed` bookkeeping.
/// All durations are relative to the sweep's single `now` so the transition
/// is clock-free.
pub(crate) struct HealthInputs {
    pub(crate) tier: DirectTier,
    /// §6.3 F1 — the business-poke window the runtime chose
    /// ([`BUSINESS_POKE_DEADLINE`], or the legacy one under its kill switch).
    /// An input, so this module stays env-free.
    pub(crate) business_poke_window: Duration,
    /// `Installed.is_direct` (drives the strike-clear + relay holdoff rules).
    pub(crate) is_direct: bool,
    /// `WgDevice::peer_carrier_dead` — the rc.181 send-error latch.
    pub(crate) hard_dead: bool,
    /// `WgDevice::peer_handshake_done` — the monotonic latch the phase derives
    /// from.
    pub(crate) handshake_done: bool,
    /// `Installed.since.elapsed()` — age of this carrier.
    pub(crate) since_install: Duration,
    /// `now - Installed.last_rx_at` — how long since we last HEARD the peer
    /// (keepalive-inclusive; the sweep advances `last_rx_at` from `rx_any`
    /// BEFORE building these inputs).
    pub(crate) since_last_rx: Duration,
    /// This sweep's `(tx, rx)` snapshot.
    pub(crate) traffic: (u64, u64),
    /// The previous sweep's `(tx, rx)` snapshot.
    pub(crate) last_traffic: (u64, u64),
    /// The one-way strike counter carried in `Installed.bad_sweeps`.
    pub(crate) bad_sweeps: u32,
    /// A relay refresh happened within `RELAY_REFRESH_COOLDOWN` — the
    /// anti-ping-pong holdoff. The tick applies it only to relay carriers.
    pub(crate) relay_refresh_held: bool,
    /// Stage 2 — the pending active-revalidation poke, if one is armed.
    pub(crate) poke: Option<PokeState>,
}

/// [`carrier_tick`]'s result: the updated one-way counter (store back into
/// `Installed.bad_sweeps`), whether the carrier's OWN tier strikes should
/// clear (direct + genuinely receiving — CC1: never cross-tier), and the
/// death verdict, if any.
pub(crate) struct HealthVerdict {
    pub(crate) bad_sweeps: u32,
    pub(crate) clear_tier_strikes: bool,
    pub(crate) death: Option<DeathReason>,
}

/// The ONE carrier-health transition (pre-P2: four ad-hoc booleans inline in
/// `sweep_carrier_health`). Pure and clock-free — parity contract with the
/// pre-P2 order, including the three subtleties:
///
/// * the warm-up grace early-return skips the counter update entirely (a
///   hard-dead relay conclusively skips the grace);
/// * the relay refresh-holdoff defers the death verdict but the updated
///   counter still returns (the pre-P2 `continue` sat after the counter
///   write);
/// * the strike-clear fires only for a direct carrier whose rx genuinely
///   advanced (not merely idle).
pub(crate) fn carrier_tick(i: &HealthInputs) -> HealthVerdict {
    // Phase-split detection: HandshakeDeadline is Installing-only; RxStale and
    // RekeyUnanswered are Established-only — structurally disjoint (see the
    // module doc). A poke can only be armed on an established carrier (the
    // sweep gates on the handshake latch), but the phase gate here keeps the
    // pure transition robust to a caller that armed one anyway.
    let (punch_dead, rx_stale, rekey_unanswered) = match CarrierPhase::of(i.handshake_done, i.tier)
    {
        CarrierPhase::Installing { deadline } => (i.since_install > deadline, false, false),
        CarrierPhase::Established => (
            false,
            i.since_install >= DIRECT_GRACE && i.since_last_rx > i.tier.rx_stale_deadline(),
            // Stage 2 — the poke's window is the tier's handshake deadline:
            // it is literally the same physical question ("can a handshake
            // complete over this path?"), so the deadline table stays the
            // single source of truth.
            //
            // #26 — EXCEPT for a poke armed by a netstate MAJOR, which asks
            // the easier question "is this ESTABLISHED carrier still alive?"
            // and convicts on `MAJOR_POKE_DEADLINE` instead. Both windows are
            // chosen here so the deadline policy stays in one place.
            i.poke.as_ref().is_some_and(|p| {
                let window = if p.from_major {
                    MAJOR_POKE_DEADLINE
                } else if p.from_business && i.is_direct {
                    i.business_poke_window
                } else {
                    i.tier.handshake_deadline()
                };
                !p.answered && p.since_poke > window
            }),
        ),
    };

    // Warm-up grace: let the handshake + first packets flow — no counter
    // update, no judgment. (A blown handshake deadline is > grace by
    // construction, so it never lands in the grace window; a hard-dead relay
    // conclusively skips it.)
    if !i.hard_dead && i.since_install < DIRECT_GRACE {
        return HealthVerdict {
            bad_sweeps: i.bad_sweeps,
            clear_tier_strikes: false,
            death: None,
        };
    }

    // One-way counter: sent this interval but received nothing back ⇒
    // suspect; anything else resets (idle = no judgment). A direct carrier
    // that's genuinely RECEIVING clears its tier's strikes (CC1).
    let (tx, rx) = i.traffic;
    let (last_tx, last_rx) = i.last_traffic;
    let (bad_sweeps, clear_tier_strikes) = if tx > last_tx && rx == last_rx {
        (i.bad_sweeps + 1, false)
    } else {
        (0, i.is_direct && rx > last_rx)
    };

    let tripped = bad_sweeps >= BAD_SWEEPS_TO_FALLBACK
        || i.hard_dead
        || punch_dead
        || rx_stale
        || rekey_unanswered;
    let death = if !tripped {
        None
    } else if !i.is_direct && i.relay_refresh_held {
        // Anti-ping-pong: we just refreshed this relay — hold the verdict
        // (the counter above still stores).
        None
    } else if i.hard_dead {
        Some(DeathReason::HardDead)
    } else if rekey_unanswered {
        // Above RxStale: an unanswered poke is ACTIVE proof (2–3 initiation
        // attempts lost), stronger evidence than passive silence — and it
        // normally fires first anyway (poke windows close before the
        // rx-stale deadlines).
        Some(DeathReason::RekeyUnanswered)
    } else if rx_stale {
        Some(DeathReason::RxStale)
    } else if punch_dead {
        Some(DeathReason::HandshakeDeadline)
    } else {
        Some(DeathReason::OneWay)
    };
    HealthVerdict {
        bad_sweeps,
        clear_tier_strikes,
        death,
    }
}

/// Stage 2 — should the sweep arm an active-revalidation poke for this
/// carrier right now? Pure and clock-free, like [`carrier_tick`]. Established
/// carriers only (`handshake_done`), one poke at a time (`poke_pending`), on
/// either trigger:
///
/// * **silence** — nothing heard for [`POKE_SILENCE_AFTER`] (> the ~25 s
///   keepalive cadence, so a healthy idle gap never pokes). Converts the
///   VPN-filter / path-died class into a verdict ~`handshake_deadline` later
///   instead of waiting out the full rx-stale deadline;
/// * **stale proof** — no INITIATOR-role handshake within
///   [`POKE_PROOF_AFTER`] (`since_proof` = min(time since install, time since
///   the last initiator handshake)). The only detector for a carrier whose tx
///   is dead while the peer's own traffic keeps our rx counters moving.
///
/// The sweep arms the poke only for carriers the same tick left alive.
pub(crate) fn should_poke(
    handshake_done: bool,
    poke_pending: bool,
    since_last_rx: Duration,
    since_proof: Duration,
) -> bool {
    handshake_done
        && !poke_pending
        && (since_last_rx > POKE_SILENCE_AFTER || since_proof > POKE_PROOF_AFTER)
}

/// Net-change acceleration — should a FORCED revalidation poke arm for this
/// carrier right now, given an OS route/iface event just fired? Same
/// contract as [`should_poke`] minus the silence/proof waits: the event IS
/// the suspicion. Field 2026-08-15 winhost-a: a Check Point connect killed
/// every UDP flow within seconds (REKEY_TIMEOUT at +1 s), but the first
/// pair failover took ~92 s — the poke sat behind `POKE_SILENCE_AFTER`
/// (30 s) plus the passive rx-stale race. Arming on the event collapses
/// detection to ~poke deadline + one sweep tick, and stays honest: an
/// answered poke clears with zero side effects, so a benign event (Wi-Fi
/// roam, VPN disconnect) costs one handshake round per pair, nothing more.
/// Established carriers only — an Installing carrier already has the
/// handshake-deadline reaper.
///
/// #26 — it deliberately does NOT take `poke_pending`: a net-change **re-arms**
/// over a poke that is already in flight. It used to skip those carriers, which
/// left a hole exactly one poke-window wide — a poke armed by the silence or
/// proof trigger seconds before a VPN connect kept its establish-sized tier
/// deadline (12–30 s) and blackholed the pair for that whole window. Re-arming
/// is also the honest way to apply [`MAJOR_POKE_DEADLINE`]: the tight
/// window judges a FRESH initiation sent now, not one whose last boringtun
/// re-send may already be ~5 s old.
pub(crate) fn should_poke_on_netchange(handshake_done: bool) -> bool {
    handshake_done
}

/// A make-before-break shadow probe's verdict (pre-P2: the two branch
/// conditions inline in `sweep_upgrade_probes`). A probe has a disjoint input
/// set from an installed carrier (no stats, no hard-dead, no rx-staleness —
/// it never routes) and disjoint dispositions (Promote = cut over; Expire =
/// park + strike), which is why this is a separate tiny fn and NOT a merged
/// phase of [`carrier_tick`] — merging would manufacture unreachable states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ProbeVerdict {
    /// Handshake latched — the direct path is proven bidirectional; cut over.
    Promote,
    /// Deadline blown with no latch — direct unreachable; drop the probe,
    /// keep the relay, book the tier strike.
    Expire,
    /// Still within the deadline — leave it in flight.
    Wait,
}

/// #35 — the deadline for a probe we ACCEPTED rather than initiated.
///
/// The tier deadlines are sized for an INITIATED probe, which must get an
/// initiation out through whatever NAT is in the way and wait for the reply.
/// An accepted probe has already had the peer's initiation delivered — it
/// needs one response and the peer's follow-up, not a traversal.
///
/// Measured over one day on the reference host, successful probes:
///
/// | kind | n | mean | max |
/// |---|---|---|---|
/// | accepted | 38 | 4115 ms | **4921 ms** |
/// | initiated | 34 | 5035 ms | 12398 ms |
///
/// So 8 s is ~1.6× the observed accepted maximum while cutting the slot hold
/// roughly in half. It matters because the probe slot is ONE PER PEER: an
/// accepted probe on a tier the peer chose blocks us from probing a tier we
/// would rather have, for as long as it runs. Erring short is cheap — the
/// peer retransmits its initiation every ~5 s (WG's rekey timeout) and we
/// accept again — whereas erring long starves the better tier.
pub(crate) const ACCEPTED_PROBE_DEADLINE: Duration = Duration::from_secs(8);

/// The probe transition: latch ⇒ promote, past the deadline ⇒ expire, else
/// wait. `initiated` selects the deadline — see [`ACCEPTED_PROBE_DEADLINE`].
pub(crate) fn probe_tick(
    handshake_done: bool,
    since: Duration,
    tier: DirectTier,
    initiated: bool,
) -> ProbeVerdict {
    let deadline = if initiated {
        tier.handshake_deadline()
    } else {
        // `min` so a tier whose own deadline is already shorter keeps it —
        // this may only ever SHORTEN the wait, never extend one.
        ACCEPTED_PROBE_DEADLINE.min(tier.handshake_deadline())
    };
    if handshake_done {
        ProbeVerdict::Promote
    } else if since > deadline {
        ProbeVerdict::Expire
    } else {
        ProbeVerdict::Wait
    }
}

/// rc.275 honesty — is this installed carrier SILENTLY ONE-WAY right now?
/// Display verdict only (stored in `Installed.stalled`, surfaced as `stalled`
/// in the LocalAPI peer view) — it kills nothing; every reap decision stays
/// in [`carrier_tick`].
///
/// Two evidence sources, matching the two ways a one-way carrier hides:
/// * **no completed WG handshake ever** — the pre-handshake zombie. Its
///   `tx`/`rx` counters stay flat (handshake packets touch neither), so the
///   rx-flat heuristic can't see it; only the handshake latch can. Field:
///   winhost-a behind its corp VPN — every tier "installed", `roomler peers`
///   said `direct`/`relay` with fresh LAST SEEN (inbound worked!) while 100 %
///   of its own pings died for hours. This fn is what makes that visible.
/// * **the rc.137 one-way strike counter** (`bad_sweeps`) — an established
///   session that sends but no longer receives.
///
/// The warm-up grace mirrors [`carrier_tick`]'s: no judgment while the
/// handshake + first packets are still expected to be in flight.
pub(crate) fn carrier_stalled(
    since_install: Duration,
    handshake_done: bool,
    bad_sweeps: u32,
) -> bool {
    since_install >= DIRECT_GRACE && (!handshake_done || bad_sweeps >= 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rc.275 honesty — the stalled display verdict: pre-handshake zombies and
    /// one-way strike accumulation read as stalled once past the grace; a
    /// healthy or still-warming carrier never does.
    #[test]
    fn carrier_stalled_matrix() {
        let grace = DIRECT_GRACE;
        let young = grace / 2;
        let old = grace * 3;
        // Warm-up: never stalled, whatever the evidence.
        assert!(!carrier_stalled(young, false, 0));
        assert!(!carrier_stalled(young, false, 9));
        // The winhost-a shape: installed for ages, handshake never completed.
        assert!(carrier_stalled(old, false, 0));
        // Established + healthy: not stalled.
        assert!(!carrier_stalled(old, true, 0));
        assert!(!carrier_stalled(old, true, 1), "one strike is a blip");
        // Established but one-way strikes accumulating: stalled.
        assert!(carrier_stalled(old, true, 2));
        // Boundary: judgment starts exactly at the grace edge.
        assert!(carrier_stalled(grace, false, 0));
        assert!(!carrier_stalled(grace - Duration::from_millis(1), false, 0));
    }

    /// Baseline healthy-established inputs; tests override the field under
    /// test.
    fn established() -> HealthInputs {
        HealthInputs {
            business_poke_window: BUSINESS_POKE_DEADLINE,
            tier: DirectTier::Lan,
            is_direct: true,
            hard_dead: false,
            handshake_done: true,
            since_install: Duration::from_secs(60),
            since_last_rx: Duration::from_secs(1),
            traffic: (10, 10),
            last_traffic: (10, 10),
            bad_sweeps: 0,
            relay_refresh_held: false,
            poke: None,
        }
    }

    #[test]
    fn grace_suppresses_all_but_hard_dead() {
        // Inside the 8 s grace: a one-way pattern AND a blown-deadline-shaped
        // input yield NO death and an UNTOUCHED counter (the pre-P2 `continue`
        // skipped the counter update).
        let i = HealthInputs {
            handshake_done: false,
            since_install: Duration::from_secs(7),
            traffic: (5, 0),
            last_traffic: (1, 0),
            bad_sweeps: 2,
            ..established()
        };
        let v = carrier_tick(&i);
        assert!(v.death.is_none());
        assert_eq!(v.bad_sweeps, 2, "grace must not touch the counter");
        assert!(!v.clear_tier_strikes);

        // hard_dead skips the grace entirely (rc.181 fast path).
        let i = HealthInputs {
            tier: DirectTier::Relay,
            is_direct: false,
            hard_dead: true,
            since_install: Duration::from_secs(1),
            ..established()
        };
        assert_eq!(carrier_tick(&i).death, Some(DeathReason::HardDead));
    }

    /// #35 — an ACCEPTED probe gets a shorter deadline than an initiated one,
    /// because it needs one response rather than a NAT traversal.
    ///
    /// This matters for a reason that is not about the probe itself: the probe
    /// slot is ONE PER PEER, so an accepted probe on whatever tier the PEER
    /// chose blocks us from probing a tier we would rather have, for as long
    /// as it runs. Measured over a day, successful accepted probes latched in
    /// ≤ 4921 ms (n=38) while initiated ones reached 12398 ms (n=34) — the
    /// tier deadlines are sized for the latter.
    #[test]
    fn an_accepted_probe_expires_sooner_than_an_initiated_one() {
        let tier = DirectTier::Srflx;
        let tier_deadline = tier.handshake_deadline();
        assert!(
            ACCEPTED_PROBE_DEADLINE < tier_deadline,
            "the whole point is that it is shorter"
        );
        // Past the observed accepted maximum (4.9 s) but inside the tier's:
        // initiated waits, accepted gives up.
        let t = ACCEPTED_PROBE_DEADLINE + Duration::from_secs(1);
        assert_eq!(probe_tick(false, t, tier, true), ProbeVerdict::Wait);
        assert_eq!(probe_tick(false, t, tier, false), ProbeVerdict::Expire);

        // Comfortably inside both — nobody gives up on a probe that is still
        // within the measured latch range.
        let early = Duration::from_millis(4_921);
        assert_eq!(probe_tick(false, early, tier, true), ProbeVerdict::Wait);
        assert_eq!(
            probe_tick(false, early, tier, false),
            ProbeVerdict::Wait,
            "the slowest accepted probe ever measured must still be waited for"
        );

        // A latch always promotes, whoever initiated and however late.
        assert_eq!(
            probe_tick(true, tier_deadline * 2, tier, false),
            ProbeVerdict::Promote
        );

        // It may only ever SHORTEN: a tier whose own deadline is already
        // under the cap keeps its own.
        for t in [DirectTier::Lan, DirectTier::Public, DirectTier::Srflx] {
            let effective = ACCEPTED_PROBE_DEADLINE.min(t.handshake_deadline());
            assert!(
                effective <= t.handshake_deadline(),
                "{t:?}: an accepted probe must never wait LONGER than an initiated one"
            );
        }
    }
    #[test]
    fn handshake_deadline_fires_only_pre_handshake_per_tier() {
        for (tier, deadline_s) in [
            (DirectTier::Lan, 12u64),
            (DirectTier::Srflx, 12),
            (DirectTier::Public, 30),
            (DirectTier::Relay, 45),
        ] {
            // One second short of the deadline: Wait.
            let i = HealthInputs {
                tier,
                is_direct: tier.is_direct(),
                handshake_done: false,
                since_install: Duration::from_secs(deadline_s - 1),
                ..established()
            };
            assert!(
                carrier_tick(&i).death.is_none(),
                "{tier:?} must survive 1 s short of its deadline"
            );
            // One second past: HandshakeDeadline.
            let i = HealthInputs {
                since_install: Duration::from_secs(deadline_s + 1),
                ..i
            };
            assert_eq!(
                carrier_tick(&i).death,
                Some(DeathReason::HandshakeDeadline),
                "{tier:?} must die 1 s past its deadline"
            );
            // Latched handshake: the deadline can NEVER fire (Established
            // phase has no HandshakeDeadline arm — structural).
            let i = HealthInputs {
                handshake_done: true,
                since_last_rx: Duration::from_secs(1),
                ..i
            };
            assert!(carrier_tick(&i).death.is_none());
        }
    }

    #[test]
    fn rx_stale_requires_handshake_grace_and_deadline() {
        // Just under the tier's deadline: survives. Just over: dies RxStale.
        // Expressed RELATIVE to the deadline so the boundary can't silently
        // re-hardcode when a tier's value is retuned.
        for (tier, is_direct) in [
            (DirectTier::Lan, true),
            (DirectTier::Srflx, true),
            (DirectTier::Relay, false),
        ] {
            let d = tier.rx_stale_deadline();
            let at = |since_last_rx: Duration| HealthInputs {
                tier,
                is_direct,
                since_last_rx,
                ..established()
            };
            assert!(
                carrier_tick(&at(d - Duration::from_secs(1)))
                    .death
                    .is_none(),
                "{tier:?} must survive just inside its deadline"
            );
            assert_eq!(
                carrier_tick(&at(d + Duration::from_secs(1))).death,
                Some(DeathReason::RxStale),
                "{tier:?} must die just past it"
            );
            // And the tiers really are on different deadlines: a direct
            // carrier is already dead where the relay one is still alive.
            if is_direct {
                assert!(
                    carrier_tick(&at(RELAY_RX_STALE_DEADLINE - Duration::from_secs(1)))
                        .death
                        .is_some(),
                    "{tier:?} must NOT be waiting out the relay deadline"
                );
            }
        }
        // Heard this sweep: survives regardless of anything else.
        let i = HealthInputs {
            since_last_rx: Duration::ZERO,
            ..established()
        };
        assert!(carrier_tick(&i).death.is_none());
        // Pre-handshake, rx-staleness NEVER fires (Installing phase).
        let i = HealthInputs {
            handshake_done: false,
            since_install: Duration::from_secs(9),
            since_last_rx: Duration::from_secs(120),
            ..established()
        };
        assert!(carrier_tick(&i).death.is_none());
    }

    #[test]
    fn one_way_counts_resets_and_clears_strikes() {
        // tx advanced, rx flat → strike 1, 2, then death on the 3rd.
        let mut i = HealthInputs {
            traffic: (11, 10),
            last_traffic: (10, 10),
            ..established()
        };
        let v = carrier_tick(&i);
        assert_eq!((v.bad_sweeps, v.death), (1, None));
        i.bad_sweeps = 1;
        let v = carrier_tick(&i);
        assert_eq!((v.bad_sweeps, v.death), (2, None));
        i.bad_sweeps = 2;
        let v = carrier_tick(&i);
        assert_eq!(v.bad_sweeps, 3);
        assert_eq!(v.death, Some(DeathReason::OneWay));

        // rx advancing resets the counter AND clears the tier strikes for a
        // direct carrier…
        let i = HealthInputs {
            traffic: (12, 11),
            last_traffic: (11, 10),
            bad_sweeps: 2,
            ..established()
        };
        let v = carrier_tick(&i);
        assert_eq!(v.bad_sweeps, 0);
        assert!(v.clear_tier_strikes);
        // …but NOT for a relay (strike maps are direct-tier bookkeeping)…
        let i = HealthInputs {
            tier: DirectTier::Relay,
            is_direct: false,
            traffic: (12, 11),
            last_traffic: (11, 10),
            ..established()
        };
        assert!(!carrier_tick(&i).clear_tier_strikes);
        // …and idle (nothing sent) resets the counter without claiming the
        // carrier is proven-receiving.
        let i = HealthInputs {
            bad_sweeps: 2,
            ..established()
        };
        let v = carrier_tick(&i);
        assert_eq!(v.bad_sweeps, 0);
        assert!(!v.clear_tier_strikes);
    }

    /// F3 (adversarial-review finding) — pre-handshake `tx` DOES tick once per
    /// rekey attempt (boringtun emits the INIT via `encapsulate`). An isolated
    /// blip books one strike and resets on the next (flat) sweep, so the
    /// one-way detector still cannot fire pre-handshake — the deadline is the
    /// only Installing-phase death.
    #[test]
    fn single_sweep_tx_blip_does_not_accumulate_bad_sweeps() {
        let base = HealthInputs {
            handshake_done: false,
            since_install: Duration::from_secs(9), // past grace, pre-deadline
            ..established()
        };
        // Sweep 1: the init tx-blip → strike 1.
        let v = carrier_tick(&HealthInputs {
            traffic: (1, 0),
            last_traffic: (0, 0),
            ..base
        });
        assert_eq!((v.bad_sweeps, v.death), (1, None));
        // Sweeps 2..: tx flat until the next rekey attempt (~90 s away — the
        // carrier hits its handshake deadline long before) → counter resets.
        let v = carrier_tick(&HealthInputs {
            traffic: (1, 0),
            last_traffic: (1, 0),
            bad_sweeps: 1,
            ..base
        });
        assert_eq!((v.bad_sweeps, v.death), (0, None));
    }

    #[test]
    fn death_reason_precedence() {
        // hard_dead + rx_stale co-trip (relay: send error AND silent) →
        // HardDead wins (the pre-P2 relay log checked hard_dead first).
        let i = HealthInputs {
            tier: DirectTier::Relay,
            is_direct: false,
            hard_dead: true,
            since_last_rx: Duration::from_secs(120),
            ..established()
        };
        assert_eq!(carrier_tick(&i).death, Some(DeathReason::HardDead));
        // rx_stale + one-way co-trip → RxStale wins (distinct "went silent"
        // log, as pre-P2).
        let i = HealthInputs {
            since_last_rx: Duration::from_secs(120),
            traffic: (13, 10),
            last_traffic: (12, 10),
            bad_sweeps: 2,
            ..established()
        };
        assert_eq!(carrier_tick(&i).death, Some(DeathReason::RxStale));
        // rx_stale × handshake-deadline is impossible by phase construction:
        // Installing has no RxStale arm, Established no HandshakeDeadline arm.
        assert!(matches!(
            CarrierPhase::of(false, DirectTier::Lan),
            CarrierPhase::Installing { .. }
        ));
        assert!(matches!(
            CarrierPhase::of(true, DirectTier::Lan),
            CarrierPhase::Established
        ));
    }

    #[test]
    fn relay_refresh_holdoff_defers_death_but_counter_advances() {
        // A relay one-way past the threshold, inside the refresh holdoff:
        // NO death, but the counter still stores (pre-P2 the `continue` sat
        // after the counter update).
        let i = HealthInputs {
            tier: DirectTier::Relay,
            is_direct: false,
            traffic: (13, 10),
            last_traffic: (12, 10),
            bad_sweeps: 2,
            relay_refresh_held: true,
            ..established()
        };
        let v = carrier_tick(&i);
        assert!(v.death.is_none());
        assert_eq!(v.bad_sweeps, 3, "holdoff must not lose the strike");
        // The holdoff is relay-only: a DIRECT carrier with the flag set (the
        // sweep never sets it for direct, but the rule is the tick's) dies.
        let i = HealthInputs {
            relay_refresh_held: true,
            traffic: (13, 10),
            last_traffic: (12, 10),
            bad_sweeps: 2,
            ..established()
        };
        assert_eq!(carrier_tick(&i).death, Some(DeathReason::OneWay));
    }

    #[test]
    fn probe_tick_promote_expire_wait_boundaries() {
        for (tier, deadline_s) in [
            (DirectTier::Lan, 12u64),
            (DirectTier::Srflx, 12),
            (DirectTier::Public, 30),
        ] {
            assert_eq!(
                probe_tick(true, Duration::ZERO, tier, true),
                ProbeVerdict::Promote,
                "latch promotes immediately"
            );
            assert_eq!(
                probe_tick(false, Duration::from_secs(deadline_s - 1), tier, true),
                ProbeVerdict::Wait
            );
            assert_eq!(
                probe_tick(false, Duration::from_secs(deadline_s + 1), tier, true),
                ProbeVerdict::Expire
            );
            // A latch exactly at/past the deadline still promotes — the latch
            // check runs first (pre-P2 branch order).
            assert_eq!(
                probe_tick(true, Duration::from_secs(deadline_s + 5), tier, true),
                ProbeVerdict::Promote
            );
        }
    }

    #[test]
    fn deadline_ordering_invariants() {
        // The cross-tier deadline relationships the pre-P2 test suite pinned:
        // srflx/LAN tight, public looser, relay loosest; all past the grace.
        assert!(SRFLX_HANDSHAKE_DEADLINE < PUBLIC_HANDSHAKE_DEADLINE);
        assert!(LAN_HANDSHAKE_DEADLINE < PUBLIC_HANDSHAKE_DEADLINE);
        assert!(PUBLIC_HANDSHAKE_DEADLINE < RELAY_HANDSHAKE_DEADLINE);
        assert!(LAN_HANDSHAKE_DEADLINE > DIRECT_GRACE);
        assert!(RELAY_HANDSHAKE_DEADLINE > DIRECT_GRACE);

        // Per-tier rx-staleness: direct is tighter (its path can be revoked
        // instantly by a VPN), relay keeps the forgiving bound because its
        // liveness depends on a third party that may reconnect.
        assert!(DIRECT_RX_STALE_DEADLINE < RELAY_RX_STALE_DEADLINE);
        for t in [DirectTier::Lan, DirectTier::Public, DirectTier::Srflx] {
            assert_eq!(t.rx_stale_deadline(), DIRECT_RX_STALE_DEADLINE);
        }
        assert_eq!(
            DirectTier::Relay.rx_stale_deadline(),
            RELAY_RX_STALE_DEADLINE
        );
    }

    /// The floor under BOTH rx-stale deadlines: a healthy but idle carrier is
    /// legitimately silent for a full persistent-keepalive period
    /// (`wg::KEEPALIVE_SECS` = 25 s), and the two ends are unsynchronised. Any
    /// deadline at or below ~2 keepalives would reap working carriers — the
    /// exact trap that makes a naive "no rx in 10 s ⇒ dead" rule unusable.
    #[test]
    fn rx_stale_deadlines_clear_two_keepalive_periods() {
        const KEEPALIVE: Duration = Duration::from_secs(25); // wg::KEEPALIVE_SECS
        for d in [DIRECT_RX_STALE_DEADLINE, RELAY_RX_STALE_DEADLINE] {
            assert!(
                d > KEEPALIVE * 2,
                "{d:?} must survive two consecutive lost keepalives"
            );
        }
    }

    /// An idle-but-healthy DIRECT carrier must survive right up to the new,
    /// tighter deadline — the regression lock for shortening it.
    #[test]
    fn idle_direct_carrier_survives_until_its_deadline() {
        let quiet = |since_last_rx: Duration| HealthInputs {
            since_last_rx,
            ..established()
        };
        // One missed keepalive: alive.
        assert!(
            carrier_tick(&quiet(Duration::from_secs(30)))
                .death
                .is_none()
        );
        // Just inside the deadline: still alive.
        assert!(
            carrier_tick(&quiet(DIRECT_RX_STALE_DEADLINE - Duration::from_secs(1)))
                .death
                .is_none()
        );
        // Past it: dead, and for the rx-stale reason specifically.
        assert_eq!(
            carrier_tick(&quiet(DIRECT_RX_STALE_DEADLINE + Duration::from_secs(1))).death,
            Some(DeathReason::RxStale)
        );
    }

    /// Stage 2 REGRESSION LOCK (write-first, per the plan): an idle
    /// established carrier with NO poke armed must never die early, and the
    /// arming rule must not fire inside a healthy keepalive gap. Persistent
    /// keepalives arrive every ~25 s on an unsynchronised cadence, so
    /// `since_last_rx` on a healthy idle carrier is roughly uniform over
    /// [0, 25 s) — a poke threshold at or below that cadence would poke (and
    /// with any poke-path bug, kill) most idle carriers on every sweep.
    #[test]
    fn healthy_idle_carrier_neither_dies_nor_pokes() {
        let fresh_proof = Duration::from_secs(5);
        let idle = Duration::from_secs(24);
        assert!(
            carrier_tick(&HealthInputs {
                since_last_rx: idle,
                ..established()
            })
            .death
            .is_none()
        );
        assert!(!should_poke(true, false, idle, fresh_proof));
        // At exactly the keepalive cadence: still no poke.
        assert!(!should_poke(
            true,
            false,
            Duration::from_secs(25),
            fresh_proof
        ));
    }

    /// Stage 2 — net-change forced pokes arm on any ESTABLISHED carrier; a
    /// pre-handshake one is left to the handshake-deadline reaper. The
    /// silence/proof waits are deliberately absent — the OS event is the
    /// suspicion (winhost-a 2026-08-15: 92 s failover waiting out the gates).
    /// #26 — and a poke already in flight no longer suppresses: the
    /// net-change RE-ARMS, which is what lets the tight window judge a fresh
    /// initiation (the parameter is gone, so no caller can reintroduce the
    /// skip by passing `true`).
    #[test]
    fn should_poke_on_netchange_matrix() {
        assert!(should_poke_on_netchange(true));
        assert!(!should_poke_on_netchange(false), "pre-handshake");
    }

    #[test]
    fn business_poke_has_an_established_path_window_and_requires_failed_proof() {
        for tier in [DirectTier::Lan, DirectTier::Public, DirectTier::Srflx] {
            let input = |age, answered, business| HealthInputs {
                tier,
                poke: Some(PokeState { since_poke: age, answered,
                    from_major: false, from_business: business }),
                ..established()
            };
            assert!(carrier_tick(&input(BUSINESS_POKE_DEADLINE, false, true)).death.is_none());
            assert_eq!(carrier_tick(&input(BUSINESS_POKE_DEADLINE + Duration::from_millis(1),
                false, true)).death, Some(DeathReason::RekeyUnanswered));
            assert!(carrier_tick(&input(BUSINESS_POKE_DEADLINE + Duration::from_secs(1),
                true, true)).death.is_none(), "an answered proof preserves the healthy carrier");
            assert!(carrier_tick(&input(BUSINESS_POKE_DEADLINE + Duration::from_secs(1),
                false, false)).death.is_none(), "periodic pokes retain the original tier deadline");
        }
    }

    #[test]
    fn business_poke_window_is_an_input_and_the_kill_switch_restores_six_seconds() {
        let input = |age| HealthInputs {
            business_poke_window: BUSINESS_POKE_LEGACY_DEADLINE,
            poke: Some(PokeState { since_poke: age, answered: false,
                from_major: false, from_business: true }),
            ..established()
        };
        assert!(carrier_tick(&input(BUSINESS_POKE_DEADLINE + Duration::from_secs(1))).death.is_none());
        assert_eq!(carrier_tick(&input(BUSINESS_POKE_LEGACY_DEADLINE + Duration::from_millis(1))).death,
            Some(DeathReason::RekeyUnanswered));
        assert!(BUSINESS_POKE_RETAP_AFTER < BUSINESS_POKE_DEADLINE / 2,
            "the re-send must leave the second initiation most of the window");
    }

    #[test]
    fn should_poke_matrix() {
        let s = Duration::from_secs;
        // Silence trigger: strictly past POKE_SILENCE_AFTER.
        assert!(!should_poke(true, false, POKE_SILENCE_AFTER, s(5)));
        assert!(should_poke(true, false, POKE_SILENCE_AFTER + s(1), s(5)));
        // Stale-proof trigger: strictly past POKE_PROOF_AFTER.
        assert!(!should_poke(true, false, s(1), POKE_PROOF_AFTER));
        assert!(should_poke(true, false, s(1), POKE_PROOF_AFTER + s(1)));
        // One poke at a time; Installing carriers never poke.
        assert!(!should_poke(true, true, s(999), s(999)));
        assert!(!should_poke(false, false, s(999), s(999)));
    }

    /// Stage 2 — the verdict: an unanswered poke kills at the tier's
    /// handshake-deadline window; an answered one never does; the window
    /// respects the phase gate and the relay refresh holdoff.
    #[test]
    fn rekey_unanswered_verdict_per_tier() {
        for (tier, is_direct) in [
            (DirectTier::Lan, true),
            (DirectTier::Srflx, true),
            (DirectTier::Public, true),
            (DirectTier::Relay, false),
        ] {
            let w = tier.handshake_deadline();
            let poked = |since_poke: Duration, answered: bool| HealthInputs {
                tier,
                is_direct,
                poke: Some(PokeState {
                    since_poke,
                    answered,
                    from_major: false,
                    from_business: false,
                }),
                ..established()
            };
            // Window still open: wait.
            assert!(
                carrier_tick(&poked(w - Duration::from_secs(1), false))
                    .death
                    .is_none(),
                "{tier:?} must survive inside its poke window"
            );
            // Window closed, unanswered: dead, for the poke reason.
            assert_eq!(
                carrier_tick(&poked(w + Duration::from_secs(1), false)).death,
                Some(DeathReason::RekeyUnanswered),
                "{tier:?} must die once the poke window closes unanswered"
            );
            // Answered: alive no matter how old the poke is.
            assert!(
                carrier_tick(&poked(w * 3, true)).death.is_none(),
                "{tier:?} answered poke must never kill"
            );
        }
        // Phase gate: a poke on a never-handshaked carrier yields the
        // Installing-phase verdict (HandshakeDeadline), not RekeyUnanswered.
        let i = HealthInputs {
            handshake_done: false,
            since_install: Duration::from_secs(60),
            poke: Some(PokeState {
                since_poke: Duration::from_secs(60),
                answered: false,
                from_major: false,
                from_business: false,
            }),
            ..established()
        };
        assert_eq!(carrier_tick(&i).death, Some(DeathReason::HandshakeDeadline));
        // Relay refresh holdoff defers the poke verdict like every other.
        let i = HealthInputs {
            tier: DirectTier::Relay,
            is_direct: false,
            relay_refresh_held: true,
            poke: Some(PokeState {
                since_poke: Duration::from_secs(60),
                answered: false,
                from_major: false,
                from_business: false,
            }),
            ..established()
        };
        assert!(carrier_tick(&i).death.is_none());
    }

    /// #26 — the net-change window. A poke armed BY a netstate Major convicts
    /// at [`MAJOR_POKE_DEADLINE`] on EVERY tier, including the two whose
    /// establish-sized deadlines (Public 30 s, Relay 45 s) measured as the
    /// 34-dropped-ping hole; an ordinary poke on the same carrier still waits
    /// out its tier. The two properties that keep it honest are asserted with
    /// it: an ANSWERED net-change poke never convicts however old it is, and
    /// the tight window is Established-only (a never-handshaked carrier still
    /// yields the Installing-phase verdict, not a 2 s one).
    #[test]
    fn major_poke_convicts_on_its_own_window_not_the_tier_deadline() {
        let s = Duration::from_secs;
        for (tier, is_direct) in [
            (DirectTier::Lan, true),
            (DirectTier::Srflx, true),
            (DirectTier::Public, true),
            (DirectTier::Relay, false),
        ] {
            let poked = |since_poke: Duration, answered: bool, from_major: bool| HealthInputs {
                tier,
                is_direct,
                poke: Some(PokeState {
                    since_poke,
                    answered,
                    from_major,
                    from_business: false,
                }),
                ..established()
            };
            // Inside the tight window: alive.
            assert!(
                carrier_tick(&poked(MAJOR_POKE_DEADLINE, false, true))
                    .death
                    .is_none(),
                "{tier:?} must survive inside the net-change window"
            );
            // Just past it: dead — WITHOUT waiting for the tier deadline,
            // which is 6-22x longer on every tier here.
            assert_eq!(
                carrier_tick(&poked(MAJOR_POKE_DEADLINE + s(1), false, true)).death,
                Some(DeathReason::RekeyUnanswered),
                "{tier:?} net-change poke must convict at its own window"
            );
            // The SAME age on an ordinary poke is still well inside every
            // tier's deadline — the two classes must not collapse into one.
            assert!(
                carrier_tick(&poked(MAJOR_POKE_DEADLINE + s(1), false, false))
                    .death
                    .is_none(),
                "{tier:?} ordinary poke must still wait out its tier deadline"
            );
            // Answered: alive, at any age. This is the whole reason a
            // one-round-trip window is safe on a benign net-change.
            assert!(
                carrier_tick(&poked(tier.handshake_deadline() * 3, true, true))
                    .death
                    .is_none(),
                "{tier:?} answered net-change poke must never kill"
            );
        }
        // Phase gate: Established-only, exactly like the ordinary poke.
        let i = HealthInputs {
            handshake_done: false,
            since_install: s(60),
            poke: Some(PokeState {
                since_poke: s(60),
                answered: false,
                from_major: true,
                from_business: false,
            }),
            ..established()
        };
        assert_eq!(carrier_tick(&i).death, Some(DeathReason::HandshakeDeadline));
    }

    /// #26 — the window has to stay tighter than every tier deadline, or the
    /// net-change class silently becomes a no-op (and, on a hypothetical tier
    /// below it, a REGRESSION that convicts later than before).
    #[test]
    fn major_poke_window_is_tighter_than_every_tier_deadline() {
        for tier in [
            DirectTier::Lan,
            DirectTier::Srflx,
            DirectTier::Public,
            DirectTier::Relay,
        ] {
            assert!(
                MAJOR_POKE_DEADLINE < tier.handshake_deadline(),
                "{tier:?}: net-change window must be tighter than the tier deadline"
            );
        }
        // And tighter than the passive triggers it front-runs, or a carrier
        // could be convicted by a net-change poke it was never even eligible
        // to be armed for.
        assert!(MAJOR_POKE_DEADLINE < POKE_SILENCE_AFTER);
        assert!(MAJOR_POKE_DEADLINE < POKE_PROOF_AFTER);
    }

    /// Stage 2 — precedence: HardDead outranks the poke verdict; the poke
    /// verdict outranks RxStale (active proof beats passive silence).
    #[test]
    fn rekey_unanswered_precedence() {
        let base = HealthInputs {
            tier: DirectTier::Relay,
            is_direct: false,
            // 61 s silence: past DIRECT deadlines but inside the relay's 90 s,
            // and past the relay's own 45 s poke window.
            since_last_rx: Duration::from_secs(61),
            poke: Some(PokeState {
                since_poke: Duration::from_secs(46),
                answered: false,
                from_major: false,
                from_business: false,
            }),
            ..established()
        };
        assert_eq!(
            carrier_tick(&HealthInputs {
                hard_dead: true,
                ..base
            })
            .death,
            Some(DeathReason::HardDead)
        );
        // Both rx-stale and poke-expired co-trip (direct tier, 61 s > 60 s
        // rx-stale, poke window long closed): the poke reason wins.
        let i = HealthInputs {
            tier: DirectTier::Lan,
            is_direct: true,
            since_last_rx: Duration::from_secs(61),
            poke: Some(PokeState {
                since_poke: Duration::from_secs(31),
                answered: false,
                from_major: false,
                from_business: false,
            }),
            ..established()
        };
        assert_eq!(carrier_tick(&i).death, Some(DeathReason::RekeyUnanswered));
    }
}
