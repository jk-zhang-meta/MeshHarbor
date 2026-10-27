// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P3 — PathMonitor: measured path selection (consolidation invariant I3).
//!
//! One probe-and-score model for *which carrier tier to run a peer on*. It
//! REPLACED the reactive cooldown/deny/strike machinery accreted across
//! rc.136→rc.225 (`DirectCooldowns`, `direct_retry_cooldown`, the sticky
//! denies) through a staged rollout — PR-A shadow compare, PR-B instrument
//! fidelity, PR-C consumed decisions, PR-D default-on, and PR-E deleted the
//! legacy machinery outright after three green soaks (48 h shadow parity,
//! 48 h fleet shadow + ON pilot, ~42 h fleet-wide ON). Since PR-E this
//! module IS path selection; the `PathShadow` harness in `runtime.rs` is
//! telemetry.
//!
//! ## The two-plane design (adversarial-critique findings F1+F2)
//!
//! The original single-score draft (`S = B + Q − P` deciding everything) was
//! BROKEN: quality drift stretched the cooldown-parity windows to `[0, ∞)` —
//! a healthy incumbent's heard-credit pumped its Q while a non-incumbent tier
//! had no Q-recovery event, so one failed probe could lock a tier out
//! permanently (and in the +Q direction, escalated denies collapsed toward
//! zero, reintroducing the relay↔direct flap the deny exists to stop). The
//! fix separates ELIGIBILITY from RANKING:
//!
//! * **Eligibility plane (parity-exact, lockout-impossible).** A direct tier
//!   is probe-eligible iff `B_tier − P_tier ≥ B_RELAY` — priors + decaying
//!   penalty ONLY, no Q term. A failure books `P = W` with
//!   `W = 2 × (B_tier − B_RELAY)`, decaying exponentially with half-life `H`;
//!   the tier re-crosses the threshold (`P ≤ W/2`) after EXACTLY `H`. With
//!   `H` chosen per failure from the legacy escalation table (60 s ordinary ≡
//!   `DIRECT_COOLDOWN`; 900 s at the same strike thresholds ≡ the 15 min
//!   denies) the suppression windows reproduce today's `until > now` gates
//!   bit-for-bit — and because P always decays to zero, every tier retries
//!   eventually: **lockout is impossible by construction** (the legacy
//!   guarantee the single-score draft lost).
//! * **Ranking plane (Q, advisory).** `S = B + Q − P` ranks among
//!   ALREADY-eligible tiers — which to probe first when several are eligible.
//!   Q is an EWMA clamped to ±100, fed by real observations (probe latch,
//!   heard-this-sweep, one-way strikes, deaths, authenticated inbound inits).
//!   Q can never make an ineligible tier eligible nor an eligible tier
//!   ineligible — locked by `no_q_state_can_delay_or_advance_eligibility`.
//!
//! The field-load-bearing **fixed 60 s LAN retry spacing** (P8: bilateral
//! punch alignment after the 2026-07-25 hibernate incident depends on BOTH
//! ends retrying on the same fixed cadence) is therefore penalty-only — and
//! additionally pinned scoreless in the scheduler: a LAN probe is never
//! proposed within [`LAN_PROBE_SPACING`] of the previous LAN attempt, no
//! matter what any score says (F2, locked by
//! `lan_spacing_pinned_under_q_extremes`).
//!
//! ## What the monitor does NOT decide
//!
//! * **Carrier death** — that's the P2 lifecycle ([`super::lifecycle`]). The
//!   monitor CONSUMES deaths as evidence ([`PathMonitor::on_death`]).
//! * **The relay sub-tier** (anchor / dialer / both-allocate / DERP) — stays
//!   capability-symmetric in `RelayCoordinator`. In particular the server's
//!   forced-DERP push STAYS AN OVERRIDE: DERP is receivable only if the far
//!   end opened its mux, which UDP-capable nodes do only on the server push,
//!   so a unilateral score-driven flip would be a permanent split. The
//!   monitor consumes the push as an event ([`PathMonitor::on_forced_derp`]:
//!   annotate the pinned window, reset relay-Q for a fresh evidence window)
//!   and its direct-tier decisions are UNAFFECTED by an active pin (locked by
//!   `forced_derp_pin_invariants`).
//! * **Score-driven voluntary switches** — disabled at the flip (upgrades
//!   require a latched probe exactly as today; demotes only on a
//!   [`DeathReason`]). The [`Hysteresis`] rate-limit (≥30 s between voluntary
//!   switches) ships now as the guard the post-flip demotion work must go
//!   through, wired to nothing in shadow mode.
//!
//! ## Purity
//!
//! No sockets, no async, no clock reads — every method takes `now`. The
//! numeric constants deliberately mirror the legacy ones still living in
//! `runtime.rs` (`DIRECT_COOLDOWN` et al.); a cross-check test there pins the
//! two sets equal until PR-E deletes the legacy side.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bson::oid::ObjectId;

use super::lifecycle::{DeathReason, DirectTier};

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

/// `ROOMLERD_OVERLAY_PATHMON` — how far the monitor is engaged.
/// Parsed by [`PathMonMode::parse`]; the env READ lives with the caller
/// (`runtime.rs`) so this module stays env-free.
/// PR-E — the legacy selection machinery is DELETED: the monitor is the one
/// and only path selector, unconditionally. This enum now gates TELEMETRY
/// only (the 10-min summaries + divergence-style execution logs); it is kept
/// so `ROOMLERD_OVERLAY_PATHMON=shadow|off` set on a pre-PR-E host keeps
/// parsing — the runtime warns once at startup that those values no longer
/// change selection (rollback to legacy = deploy a pre-PR-E rc).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PathMonMode {
    /// Telemetry off (summaries and comparison logs suppressed). Selection
    /// is still the monitor — there is nothing else.
    Off,
    /// Vestigial (pre-PR-E: legacy authoritative). Telemetry on; selection
    /// is the monitor.
    Shadow,
    /// The default: telemetry on, monitor authoritative.
    On,
}

impl PathMonMode {
    /// PR-D — `off|0|false` → Off, `shadow` → Shadow (the per-host revert
    /// rail), anything else (incl. unset, `on`, `1`, `true`) → **On**: the
    /// monitor is authoritative by default after two green 48 h soaks
    /// (soak #1 shadow-parity on rc.246; soak #2 fleet shadow + devbox
    /// ON-pilot on rc.271/272 — harmful 0, steady 0–0.05 % throughout,
    /// incl. a fleet-wide server-churn incident absorbed mid-soak).
    pub(crate) fn parse(v: Option<&str>) -> Self {
        match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("off") | Some("0") | Some("false") => PathMonMode::Off,
            Some("shadow") => PathMonMode::Shadow,
            _ => PathMonMode::On,
        }
    }

    /// Lowercase name for logs (the 10-min summary prints it — pre-PR-D the
    /// summary said `[shadow]` unconditionally, which lied on the ON pilot).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PathMonMode::Off => "off",
            PathMonMode::Shadow => "shadow",
            PathMonMode::On => "on",
        }
    }
}

/// B2 — score-driven demotion engagement (`overlay_demote` config /
/// `ROOMLERD_OVERLAY_DEMOTE`): `off` | `shadow` (compute + count
/// would-be demotions, never act — the rc.296 first-ship default) |
/// `on` (voluntary demotions execute as MBB probes — the default since
/// B3/rc.303: the ~43 h fleet shadow read was spotless, ZERO would-be
/// demotions across 10 agents incl. the corp laptops' full VPN workday,
/// diverged=0 harmful=0 throughout — no wrong calls to grade).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DemoteMode {
    Off,
    Shadow,
    On,
}

impl DemoteMode {
    pub(crate) fn parse(v: Option<&str>) -> Self {
        match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("off") | Some("0") | Some("false") => DemoteMode::Off,
            // The per-host revert rail (counted, never acted on).
            Some("shadow") => DemoteMode::Shadow,
            // Unset / "on" / anything else → authoritative.
            _ => DemoteMode::On,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DemoteMode::Off => "off",
            DemoteMode::Shadow => "shadow",
            DemoteMode::On => "on",
        }
    }
}

// ---------------------------------------------------------------------------
// Constants — the model's numbers
// ---------------------------------------------------------------------------

/// Base priors. Cold start (Q = 0, P = 0) makes `S = B`, which reproduces the
/// legacy tier precedence LAN > public-direct > srflx > relay bit-for-bit
/// (locked by `cold_start_ordering_matches_legacy_precedence`).
pub(crate) const B_LAN: f64 = 400.0;
pub(crate) const B_PUBLIC: f64 = 330.0;
pub(crate) const B_SRFLX: f64 = 260.0;
pub(crate) const B_RELAY: f64 = 200.0;

/// Ordinary suppression half-life ≡ the legacy `DIRECT_COOLDOWN` (60 s).
pub(crate) const H_ORDINARY: Duration = Duration::from_secs(60);
/// Escalated suppression half-life ≡ the legacy `DIRECT_DENY_COOLDOWN` /
/// `SRFLX_DENY_COOLDOWN` (both 15 min since rc.225). Reached by carrier
/// deaths, and by probe expiries only without make-before-break.
pub(crate) const H_ESCALATED: Duration = Duration::from_secs(15 * 60);
/// #30 — how long a peer that is RELAYING to us holds every direct tier
/// ineligible (see [`PathMonitor::on_peer_relayed_instead`]). Must comfortably
/// exceed the make-before-break probe cadence — measured at ~70-80 s in the
/// field — or the promote↔follow flap simply resumes at that cadence. Three
/// minutes covers two to three probe cycles; every follow re-arms it, and once
/// the peer stops relaying it lapses and the very next probe promotes, so the
/// worst case for a peer that came back is one window on the relay.
pub(crate) const RELAYED_INSTEAD_HOLDOFF: Duration = Duration::from_secs(3 * 60);
/// #31 — a follow arriving within this long of the previous one is the SAME
/// disagreement continuing, so the holdoff escalates (3 → 6 → 12 → capped at
/// [`H_ESCALATED`]); quiet for longer and the ladder resets to the base.
/// Deliberately longer than the capped holdoff, or an escalated pair would
/// forget between its own retries and never climb past the first rung.
pub(crate) const RELAYED_INSTEAD_MEMORY: Duration = Duration::from_secs(30 * 60);
/// Strike thresholds ≡ legacy `DIRECT_MAX_FAILURES` / `SRFLX_MAX_FAILURES`.
/// The LAN tier under make-before-break never escalates (P8 — fixed 60 s
/// spacing on both ends guarantees bilateral punch alignment; see
/// `direct_retry_cooldown`).
pub(crate) const MAX_FAILURES_LAN_PUBLIC: u32 = 2;
pub(crate) const MAX_FAILURES_SRFLX: u32 = 3;

/// F2 — the scoreless LAN probe-spacing pin: never propose a LAN attempt
/// within this of the previous one, independent of every score and penalty.
pub(crate) const LAN_PROBE_SPACING: Duration = Duration::from_secs(60);
/// Global in-flight probe cap (structural bound; the per-peer bound is one —
/// `WgDevice::probes` is keyed by pubkey and the monitor mirrors it).
pub(crate) const PROBE_CAP: usize = 16;
/// Voluntary (score-driven) switches must be at least this far apart per
/// peer — the flap guard [`Hysteresis::voluntary_allowed`] enforces. Live
/// since B2 (score-driven demotion).
pub(crate) const SWITCH_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// B2 — a strictly-eligible alternative must out-score a live direct
/// incumbent by this margin, sustained for [`DEMOTE_HOLD`], before a
/// voluntary demotion fires. 60 ≈ "the incumbent's Q is deeply negative
/// while the alternative's is solidly positive" — transient dips and
/// probe jitter never clear it.
pub(crate) const DEMOTE_MARGIN: f64 = 60.0;
pub(crate) const DEMOTE_HOLD: Duration = Duration::from_secs(15);
/// B2 — "slammed-bad" Q floor for the (advisory) direct→relay demotion
/// class: within one heard-credit of the −100 slam.
const DEMOTE_RELAY_Q_FLOOR: f64 = -99.0;
/// B3 — mid-tier upward probes (srflx/public incumbent → an eligible
/// HIGHER tier) fire at most this often per peer. Deliberately slower
/// than the 60 s LAN spacing: the incumbent is healthy, so the probe is
/// pure opportunity cost; a failed one books the normal tier penalty
/// which paces retries further.
pub(crate) const UPWARD_PROBE_SPACING: Duration = Duration::from_secs(120);
/// §6.3 F3 — after an active-proof conviction ([`DeathReason::RekeyUnanswered`],
/// business or Major poke) the peer sits in a fast-return lane for this long:
/// the runtime walks every fallback tick instead of every ~30 s, and a
/// srflx/public failure inside the lane books [`FAST_RETURN_HALF_LIFE`] with
/// no strike. A probe is then almost always in flight during the outage, and
/// its ~5 s initiation re-send sees the recovery — return ≈ ≤5 s + RTT +
/// one promote tick, instead of 60 s penalties climbing to 15 min.
pub(crate) const FAST_RETURN_WINDOW: Duration = Duration::from_secs(60);
/// F3 — the suppression half-life of a srflx/public failure inside the
/// fast-return lane (eligibility re-crosses after exactly one half-life).
/// LAN joins the lane's rule since F3b (below); `OVERLAY_FAST_RETURN_LAN=0`
/// keeps it on the P8 fixed spacing.
pub(crate) const FAST_RETURN_HALF_LIFE: Duration = Duration::from_secs(4);
/// F3b — the LAN probe-spacing pin inside an open fast-return lane (P8's
/// [`LAN_PROBE_SPACING`] outside it). F0 measured a LAN pair's return gated
/// by the 60 s pin alone (20–60 s after the heal). P8's point is bilateral:
/// each side's INIT opens its own stateful-firewall hole for the other's. One
/// side probing more often can only land inside the other's open window more
/// often, so a mixed fleet keeps its alignment, and the lane bounds the extra
/// probes to [`FAST_RETURN_WINDOW`].
pub(crate) const FAST_RETURN_LAN_SPACING: Duration = Duration::from_secs(5);
/// F3c — an in-lane failure is the outage still holding, so it EXTENDS the
/// lane by [`FAST_RETURN_WINDOW`], up to this long after the conviction that
/// opened it; the ordinary ladder applies after. Each extension doubles the
/// in-lane penalty half-life and LAN spacing (capped at
/// [`FAST_RETURN_BACKOFF_CAP`]), so a long outage is probed with backoff
/// instead of lapsing into the ladder at 60 s (F0, 90 s outage: back on direct
/// 40 s after the heal; srflx would climb to the 15 min escalation).
pub(crate) const FAST_RETURN_MAX: Duration = Duration::from_secs(300);
/// F3c — the backoff ceiling inside the lane: a probe cycle of about one
/// handshake deadline + 20 s, so a heal is seen within ~25 s however long the
/// outage ran (a 60 s ceiling left 50–60 s gaps in a 150 s outage, F0).
pub(crate) const FAST_RETURN_BACKOFF_CAP: Duration = Duration::from_secs(20);

/// `base` doubled once per in-lane failure so far (F3c), capped at `cap`.
fn lane_backoff(base: Duration, fails: u32, cap: Duration) -> Duration {
    base.saturating_mul(1u32 << fails.min(8)).min(cap)
}

/// The LAN probe-spacing pin for `p` at `now` (F3b/F3c): inside an open
/// fast-return lane unless `lan_off`, [`FAST_RETURN_LAN_SPACING`] doubled per
/// in-lane failure; else P8's [`LAN_PROBE_SPACING`].
fn lan_spacing(p: &PeerPath, lan_off: bool, now: Instant) -> Duration {
    if !lan_off && p.fast_return_until.is_some_and(|until| until > now) {
        lane_backoff(FAST_RETURN_LAN_SPACING, p.fast_return_fails, FAST_RETURN_BACKOFF_CAP)
    } else {
        LAN_PROBE_SPACING
    }
}

/// Q clamp: quality lives in [−Q_CLAMP, +Q_CLAMP].
const Q_CLAMP: f64 = 100.0;
/// Probe latched: sample `+100 − min(50, latency_ms/40)`, α 0.4. Latency
/// `None` (PR-A — the latch is 5 s-quantized until PR-B's `handshake_at`
/// timestamp) deducts nothing rather than inventing a number.
const Q_LATCH_ALPHA: f64 = 0.4;
const Q_LATCH_LATENCY_DIVISOR: f64 = 40.0;
const Q_LATCH_MAX_DEDUCTION: f64 = 50.0;
/// Heard-this-sweep (keepalive-inclusive rx advanced): slow +100 drift.
const Q_HEARD_SAMPLE: f64 = 100.0;
const Q_HEARD_ALPHA: f64 = 0.05;
/// A one-way strike stored this sweep: fast negative drift.
const Q_BAD_SWEEP_SAMPLE: f64 = -60.0;
const Q_BAD_SWEEP_ALPHA: f64 = 0.2;
/// Authenticated inbound WG init on a tier: strong positive evidence (the
/// path traversed BOTH NATs a moment ago).
const Q_INBOUND_SAMPLE: f64 = 80.0;
const Q_INBOUND_ALPHA: f64 = 0.4;
/// A death slams Q to the floor (not an EWMA step — the carrier is gone).
const Q_DEATH_SLAM: f64 = -100.0;
/// B1 — an overlay ICMP RTT sample measured over the ACTIVE carrier (the
/// agent's 15 s prober): a gentle EWMA complementing latch/heard. Sample
/// `100 − rtt_ms/10` grades ~0 ms ≈ +100, 1 s = neutral 0, ≥2 s = −100
/// (clamped). A ping TIMEOUT books NOTHING — loss is the death path's
/// business (an ICMP-hostile network must not debit a healthy tier).
const Q_RTT_ALPHA: f64 = 0.1;
const Q_RTT_DIVISOR: f64 = 10.0;

/// Eligibility float guard: `powf` at exactly one half-life is not guaranteed
/// bit-exact, and legacy `until > now` counts the boundary instant as
/// not-cooling — the epsilon keeps the boundary on the eligible side.
const ELIGIBILITY_EPS: f64 = 1e-9;

fn base(tier: DirectTier) -> f64 {
    match tier {
        DirectTier::Lan => B_LAN,
        DirectTier::Public => B_PUBLIC,
        DirectTier::Srflx => B_SRFLX,
        DirectTier::Relay => B_RELAY,
    }
}

/// Penalty weight `W = 2 × (B_tier − B_RELAY)`: eligibility (`B − P ≥
/// B_RELAY` ⇔ `P ≤ W/2`) is re-crossed after exactly one half-life.
fn weight(tier: DirectTier) -> f64 {
    2.0 * (base(tier) - B_RELAY)
}

/// The suppression half-life for a failure — the legacy
/// `direct_retry_cooldown` escalation table, verbatim: srflx sticks at 3
/// strikes, LAN/public at 2, EXCEPT the LAN tier under make-before-break,
/// which never escalates (a LAN retry is a zero-disruption shadow probe and
/// the fixed spacing is what keeps bilateral punches aligned — P8).
fn suppression_half_life(tier: DirectTier, fails: u32, mbb: bool) -> Duration {
    let max = match tier {
        DirectTier::Srflx => MAX_FAILURES_SRFLX,
        DirectTier::Lan if mbb => return H_ORDINARY,
        _ => MAX_FAILURES_LAN_PUBLIC,
    };
    if fails >= max {
        H_ESCALATED
    } else {
        H_ORDINARY
    }
}

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

/// Clamped EWMA — the ranking plane's accumulator.
#[derive(Clone, Copy, Default, Debug)]
struct Ewma(f64);

impl Ewma {
    fn feed(&mut self, sample: f64, alpha: f64) {
        self.0 = (self.0 + alpha * (sample - self.0)).clamp(-Q_CLAMP, Q_CLAMP);
    }
    fn slam(&mut self, v: f64) {
        self.0 = v.clamp(-Q_CLAMP, Q_CLAMP);
    }
    fn get(self) -> f64 {
        self.0
    }
}

/// One booked suppression: full weight at `at`, halving every `half_life`.
#[derive(Clone, Copy, Debug)]
struct Penalty {
    w: f64,
    half_life: Duration,
    at: Instant,
}

impl Penalty {
    fn value(&self, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.w * 0.5_f64.powf(elapsed / self.half_life.as_secs_f64())
    }
}

/// Per-(peer, direct-tier) state: quality, active suppression, strike count.
#[derive(Default)]
struct TierState {
    q: Ewma,
    penalty: Option<Penalty>,
    fails: u32,
    /// B2 — since when (as the INCUMBENT tier) a margin-sized score
    /// deficit against an eligible alternative has been continuously
    /// observed; cleared the moment the deficit breaks. The demotion
    /// fires only after [`DEMOTE_HOLD`] sustained.
    below_since: Option<Instant>,
}

/// Per-peer monitor state.
#[derive(Default)]
struct PeerPath {
    /// Indexed [Lan, Public, Srflx] — see [`tier_idx`].
    tiers: [TierState; 3],
    /// Relay-tier quality (telemetry + forced-DERP evidence window; the relay
    /// tier's ELIGIBILITY is structural — it is the floor).
    relay_q: Ewma,
    /// In-flight upgrade probe (mirror of `upgrade_probes` / the WgDevice
    /// probe slot — one per peer, structural).
    probe: Option<(DirectTier, Instant)>,
    /// F2 — when the last LAN attempt (probe start or install) began.
    last_lan_attempt: Option<Instant>,
    /// B3 — when the last mid-tier UPWARD probe attempt was booked
    /// (candidate returned, whether or not the probe then resolved an
    /// endpoint) — paces upward probing to [`UPWARD_PROBE_SPACING`].
    last_upward_attempt: Option<Instant>,
    /// P7 — the server's forced-DERP pin window, as an annotation. Direct
    /// decisions ignore it entirely (see the module doc).
    forced_derp_until: Option<Instant>,
    /// #30 — the peer is demonstrably relaying to us instead of using a direct
    /// tier (the demote-follow, #27). Direct tiers are INELIGIBLE until this
    /// passes. Unlike a penalty this is a hard window, because the penalty
    /// plane cannot express it: `suppression_half_life` pins LAN-under-MBB to
    /// `H_ORDINARY` by the P8 never-strand rule, and the make-before-break
    /// probe cadence (~70-80 s measured) is close enough to that half-life that
    /// the tier is eligible again by the next probe — which is exactly the flap
    /// #29 tried and failed to stop.
    relayed_instead_until: Option<Instant>,
    /// #31 — consecutive demote-follows, and when the last one was. A pair
    /// where the two ends persistently disagree (our probe latches, the peer
    /// relays anyway) would otherwise retry at exactly the fixed holdoff
    /// forever; these escalate the window instead. Reset by
    /// [`RELAYED_INSTEAD_MEMORY`] of quiet, so a one-off transition never
    /// leaves a peer on a long window.
    relayed_instead_strikes: u32,
    relayed_instead_at: Option<Instant>,
    /// Voluntary-switch hysteresis bookkeeping (disabled-at-flip machinery).
    hysteresis: Hysteresis,
    /// FR-33 P2 — the peer's LAN candidate lies inside a prefix that THIS
    /// host's own routing table hands to another interface (a corporate VPN
    /// client's split-prefix capture, `netstate::LanCapture`). A LAN dial
    /// cannot work while it holds: the OS routes our packets into the tunnel
    /// (Check Point) and the client's filters drop the peer's (AnyConnect,
    /// measured with pktmon 2026-09-03). Like #30 this is a FACT, not a
    /// quality judgement — it gates eligibility outright and books no
    /// penalty, so the tier is back the moment the capture clears. Refreshed
    /// on every `install_peers` walk by the runtime, the only party holding
    /// both the candidate and the snapshot ([`PathMonitor::on_lan_capture`]).
    lan_captured: bool,
    /// #2089 — which direct tiers had a dialable candidate at the last
    /// [`PathMonitor::decide`]. Display only: `decide` takes availability
    /// fresh on every call, and this copy exists so [`PathMonitor::explain`]
    /// can tell a tier that is merely unpenalised (eligible) from one that is
    /// actually on the ballot. `None` until the first decision.
    avail: Option<TierAvailability>,
    /// F3 — the fast-return lane armed by a `RekeyUnanswered` death; cleared
    /// by a latched probe (direct is back) or when it lapses.
    fast_return_until: Option<Instant>,
    /// F3c — when the open lane was armed (caps its extension at
    /// [`FAST_RETURN_MAX`]) and how many in-lane failures it has absorbed
    /// (the backoff exponent). Untouched when the extension is switched off.
    fast_return_since: Option<Instant>,
    fast_return_fails: u32,
}

fn tier_idx(tier: DirectTier) -> Option<usize> {
    match tier {
        DirectTier::Lan => Some(0),
        DirectTier::Public => Some(1),
        DirectTier::Srflx => Some(2),
        DirectTier::Relay => None,
    }
}

/// Direct tiers in legacy precedence order — the ranking tie-break, so a
/// cold-start ranking (all S equal to B) IS the legacy order.
const DIRECT_TIERS: [DirectTier; 3] = [DirectTier::Lan, DirectTier::Public, DirectTier::Srflx];

// ---------------------------------------------------------------------------
// Decision inputs / outputs
// ---------------------------------------------------------------------------

/// Which direct tiers currently HAVE a dialable candidate for this peer —
/// the runtime's endpoint/flag/hairpin checks, WITHOUT the cooldown gates
/// (cooling is the monitor's own penalty plane). Availability is eligibility
/// input, never score: a tier with no endpoint simply isn't on the ballot.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct TierAvailability {
    pub(crate) lan: bool,
    pub(crate) public: bool,
    pub(crate) srflx: bool,
}

impl TierAvailability {
    fn has(&self, tier: DirectTier) -> bool {
        match tier {
            DirectTier::Lan => self.lan,
            DirectTier::Public => self.public,
            DirectTier::Srflx => self.srflx,
            DirectTier::Relay => true,
        }
    }
}

/// What the peer currently runs on, from the runtime's `by_node` view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Incumbent {
    /// No installed carrier (fresh peer / just torn down).
    None,
    /// Installed direct carrier on this tier.
    Direct(DirectTier),
    /// Installed relay carrier.
    Relay,
}

/// A path decision — the monitor's, or the legacy machinery's recorded one
/// (`LegacyChoice` instrumentation). Compared by [`classify`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PathAction {
    /// No change (incumbent kept / nothing worth doing).
    Keep,
    /// Install this direct tier now (fresh peer, or the destructive
    /// break-before-make upgrade when MBB is env-off, or an inbound
    /// re-point).
    Install(DirectTier),
    /// Start a make-before-break shadow probe toward this tier.
    Probe(DirectTier),
    /// Coordinate / fall back to the relay tier.
    Relay,
}

/// The result of a probe, as fed back by the runtime's promote/expire sweep.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum ProbeOutcome {
    /// Handshake latched — the tier is proven bidirectional. `latency_ms` is
    /// the observed latch latency (PR-B; `None` until then — no deduction).
    Latched { latency_ms: Option<f64> },
    /// Deadline blown. Books the tier failure. NO Q event — the penalty
    /// already encodes the failure; double-booking it into Q was part of the
    /// original design's lockout math (F1).
    Expired,
}

// ---------------------------------------------------------------------------
// Hysteresis (disabled-at-flip voluntary-switch guard)
// ---------------------------------------------------------------------------

/// Rate-limit for SCORE-DRIVEN voluntary switches (≥ [`SWITCH_MIN_INTERVAL`]
/// apart per peer). Deliberately consulted by NOTHING in shadow mode and by
/// nothing legacy-parity at the flip (upgrades stay probe-gated, demotes stay
/// death-gated — both exempt): this exists so the post-flip "demote a
/// degraded-but-live carrier" work has its flap-guard ready-made, with the
/// bound locked by `voluntary_switch_hysteresis_bound` from day one.
#[derive(Default)]
pub(crate) struct Hysteresis {
    last_switch: Option<Instant>,
}

impl Hysteresis {
    /// Record ANY switch (install / promote / death-fallback), voluntary or
    /// not — the spacing is measured from the last actual change.
    pub(crate) fn record_switch(&mut self, now: Instant) {
        self.last_switch = Some(now);
    }
    /// May a VOLUNTARY switch fire now? Live since B2 (score-driven
    /// demotion consumes it); the bound is locked by
    /// `voluntary_switch_hysteresis_bound`.
    pub(crate) fn voluntary_allowed(&self, now: Instant) -> bool {
        self.last_switch
            .is_none_or(|t| now.saturating_duration_since(t) >= SWITCH_MIN_INTERVAL)
    }
}

// ---------------------------------------------------------------------------
// The monitor
// ---------------------------------------------------------------------------

/// The path monitor: per-peer two-plane state + the decision function.
/// Owned by the overlay loop; single-threaded; pure of I/O and clocks.
#[derive(Default)]
pub(crate) struct PathMonitor {
    peers: HashMap<ObjectId, PeerPath>,
    /// Global in-flight probe count (bounds [`decide`]'s Probe proposals).
    probes_in_flight: usize,
    /// F3 kill switch, set once by the runtime from
    /// `OVERLAY_FAST_RETURN=0`: no lane is ever armed (pre-F3 behaviour).
    fast_return_off: bool,
    /// F3b kill switch (`OVERLAY_FAST_RETURN_LAN=0`): LAN keeps the P8 fixed
    /// spacing and ordinary penalties even inside the lane.
    fast_return_lan_off: bool,
    /// F3c kill switch (`OVERLAY_FAST_RETURN_EXTEND=0`): the lane lapses
    /// [`FAST_RETURN_WINDOW`] after the conviction, with no backoff.
    fast_return_extend_off: bool,
}

impl PathMonitor {
    /// A monitor with the F3 fast-return lane on or off (`Default` = on).
    pub(crate) fn with_fast_return(enabled: bool) -> Self {
        Self {
            fast_return_off: !enabled,
            ..Self::default()
        }
    }

    /// F3b on or off: whether LAN joins the fast-return lane (`Default` = on).
    pub(crate) fn with_fast_return_lan(mut self, enabled: bool) -> Self {
        self.fast_return_lan_off = !enabled;
        self
    }

    /// F3c on or off: whether in-lane failures extend the lane with backoff.
    pub(crate) fn with_fast_return_extend(mut self, enabled: bool) -> Self {
        self.fast_return_extend_off = !enabled;
        self
    }

    // -- evidence events -----------------------------------------------------

    /// A direct-tier attempt FAILED (carrier death on that tier, or a probe
    /// expiry): book the strike + the suppression penalty. `mbb` is the
    /// make-before-break env state at failure time (the legacy escalation
    /// table reads it at the same moment). `shadow`: the failure is a probe
    /// that never latched, so under make-before-break nothing was disrupted.
    fn book_failure(
        &mut self,
        peer: &ObjectId,
        tier: DirectTier,
        mbb: bool,
        shadow: bool,
        now: Instant,
    ) {
        let Some(idx) = tier_idx(tier) else { return };
        let lane_tier = matches!(tier, DirectTier::Public | DirectTier::Srflx)
            || (tier == DirectTier::Lan && !self.fast_return_lan_off);
        let extend = !self.fast_return_extend_off;
        let p = self.peers.entry(*peer).or_default();
        let fast_lane = lane_tier && p.fast_return_until.is_some_and(|until| until > now);
        if fast_lane {
            // F3 — inside the lane a failed re-attempt is the outage still
            // holding, not new evidence against the tier: short penalty, no
            // strike, so the ladder never escalates on one outage.
            let half_life =
                lane_backoff(FAST_RETURN_HALF_LIFE, p.fast_return_fails, FAST_RETURN_BACKOFF_CAP);
            // F3c — and it keeps the lane open, backing off, up to the cap.
            if extend && let Some(since) = p.fast_return_since {
                p.fast_return_fails = p.fast_return_fails.saturating_add(1);
                p.fast_return_until = Some((now + FAST_RETURN_WINDOW).min(since + FAST_RETURN_MAX));
            }
            p.tiers[idx].penalty = Some(Penalty {
                w: weight(tier),
                half_life,
                at: now,
            });
            return;
        }
        let t = &mut p.tiers[idx];
        t.fails += 1;
        // A shadow probe cost nothing (the relay carried throughout), so it
        // never climbs the ladder: a healed path is retried about once a
        // minute however long the outage ran. Its strike still rotates the
        // dial candidate.
        let half_life = if shadow && mbb {
            H_ORDINARY
        } else {
            suppression_half_life(tier, t.fails, mbb)
        };
        t.penalty = Some(Penalty {
            w: weight(tier),
            half_life,
            at: now,
        });
    }

    /// P2 seam — a carrier on `tier` died with `reason`. Direct tiers book
    /// the strike+penalty (≡ the legacy sweep's cooldown bookkeeping); every
    /// tier's Q is slammed.
    ///
    /// Stage 2 exception — [`DeathReason::RekeyUnanswered`] books NO strike,
    /// NO penalty and NO Q-slam, only the switch-pacing record. The poke death
    /// is proof the OLD carrier stopped working, not evidence about what a
    /// FRESH attempt on that tier would do (its trigger class — VPN filters,
    /// NAT rebinds, roams — is transient as often as not), and the rebuild it
    /// causes supplies real evidence on its own: a re-attempt that fails books
    /// `HandshakeDeadline` through this same seam ~12 s later, while a
    /// transient recovers with zero penalty. Booking here instead would let a
    /// blip start the suppression ladder and feed the server's forced-DERP
    /// churn escalation — the exact false-positive cost the staged plan was
    /// rebuilt around.
    pub(crate) fn on_death(
        &mut self,
        peer: &ObjectId,
        tier: DirectTier,
        reason: DeathReason,
        mbb: bool,
        now: Instant,
    ) {
        // Both active-proof deaths book NO penalty: the relay they fall back
        // to is the reliable path, and a transient blip should re-attempt
        // direct via make-before-break with zero suppression.
        if matches!(reason, DeathReason::RekeyUnanswered) {
            let fast_return_off = self.fast_return_off;
            let p = self.peers.entry(*peer).or_default();
            p.hysteresis.record_switch(now);
            if tier.is_direct() && !fast_return_off {
                p.fast_return_until = Some(now + FAST_RETURN_WINDOW);
                p.fast_return_since = Some(now);
                p.fast_return_fails = 0;
            }
            return;
        }
        if tier.is_direct() {
            self.book_failure(peer, tier, mbb, false, now);
        }
        let p = self.peers.entry(*peer).or_default();
        match tier_idx(tier) {
            Some(idx) => p.tiers[idx].q.slam(Q_DEATH_SLAM),
            None => p.relay_q.slam(Q_DEATH_SLAM),
        }
        p.hysteresis.record_switch(now);
    }

    /// #29 — the peer is demonstrably NOT using the direct tier we hold it on:
    /// it is relaying to us over `/derp` (see the demote-follow, #27), which a
    /// peer only does once it has moved. Suppress that tier exactly as a
    /// failure does — a DECAYING penalty, so direct is retried on its own once
    /// the condition lapses (a corp VPN going away, or the server's force-DERP
    /// pin on the peer's side expiring).
    ///
    /// Without this the two mechanisms fight: make-before-break promotes the
    /// direct tier the moment its probe latches, the peer keeps relaying, the
    /// follow drags us back, and the pair flaps on MBB's cadence. Field
    /// 2026-08-25: exactly that, every 60 s for hours, starting the minute the
    /// demote-follow shipped — a probe can prove a path CARRIES, and still say
    /// nothing about whether the peer intends to USE it.
    ///
    /// Deliberately NOT [`on_death`](Self::on_death): nothing died and the tier
    /// did not misbehave, so there is no Q slam — this is a selection fact, not
    /// a quality one. It re-books on every follow, so a peer that stays away
    /// keeps the tier suppressed while one that returns lets it decay back.
    pub(crate) fn on_peer_relayed_instead(
        &mut self,
        peer: &ObjectId,
        tier: DirectTier,
        mbb: bool,
        now: Instant,
    ) {
        if tier.is_direct() {
            self.book_failure(peer, tier, mbb, false, now);
        }
        let p = self.peers.entry(*peer).or_default();
        // #30 — a hard window on top of the penalty. The penalty ALONE does not
        // hold: LAN-under-MBB is pinned to `H_ORDINARY` (60 s) by the P8
        // never-strand rule, and MBB re-probes every ~70-80 s, so the tier is
        // eligible again before the next probe and the pair keeps flapping
        // (field 2026-08-25, measured for 20 min after #29 shipped believing it
        // had fixed exactly this).
        //
        // #31 — and the window ESCALATES while the disagreement persists. A
        // fixed holdoff only moves the flap to its own boundary: the field
        // showed a pair retrying at exactly 3 min (12:22:30 / 12:25:45 /
        // 12:29:00) once #30 shipped. Each follow inside `RELAYED_INSTEAD_MEMORY`
        // doubles, capped at `H_ESCALATED`; a quiet gap resets to the base, so a
        // one-off transition never leaves a peer on a long window.
        let consecutive = match p.relayed_instead_at {
            Some(prev) if now.saturating_duration_since(prev) <= RELAYED_INSTEAD_MEMORY => {
                p.relayed_instead_strikes.saturating_add(1)
            }
            _ => 1,
        };
        p.relayed_instead_strikes = consecutive;
        p.relayed_instead_at = Some(now);
        let holdoff = (RELAYED_INSTEAD_HOLDOFF * 2u32.saturating_pow(consecutive - 1))
            .min(H_ESCALATED)
            .max(RELAYED_INSTEAD_HOLDOFF);
        p.relayed_instead_until = Some(now + holdoff);
        p.hysteresis.record_switch(now);
    }

    /// The sweep advanced the peer's keepalive-inclusive last-heard marker.
    pub(crate) fn on_heard(&mut self, peer: &ObjectId, tier: DirectTier) {
        let p = self.peers.entry(*peer).or_default();
        match tier_idx(tier) {
            Some(idx) => p.tiers[idx].q.feed(Q_HEARD_SAMPLE, Q_HEARD_ALPHA),
            None => p.relay_q.feed(Q_HEARD_SAMPLE, Q_HEARD_ALPHA),
        }
    }

    /// B1 — an RTT sample from the agent's overlay pinger, credited to
    /// the INCUMBENT tier only (the ping rode the active carrier).
    /// Q-plane only: never touches penalties, strikes, spacing or
    /// hysteresis — locked by the eligibility-invariance tests.
    pub(crate) fn on_rtt_sample(&mut self, peer: &ObjectId, tier: DirectTier, rtt_ms: u32) {
        let sample = (Q_CLAMP - f64::from(rtt_ms) / Q_RTT_DIVISOR).clamp(-Q_CLAMP, Q_CLAMP);
        let p = self.peers.entry(*peer).or_default();
        match tier_idx(tier) {
            Some(idx) => p.tiers[idx].q.feed(sample, Q_RTT_ALPHA),
            None => p.relay_q.feed(sample, Q_RTT_ALPHA),
        }
    }

    /// The sweep stored a one-way strike (tx advanced, rx flat).
    pub(crate) fn on_bad_sweep(&mut self, peer: &ObjectId, tier: DirectTier) {
        let p = self.peers.entry(*peer).or_default();
        match tier_idx(tier) {
            Some(idx) => p.tiers[idx].q.feed(Q_BAD_SWEEP_SAMPLE, Q_BAD_SWEEP_ALPHA),
            None => p.relay_q.feed(Q_BAD_SWEEP_SAMPLE, Q_BAD_SWEEP_ALPHA),
        }
    }

    /// The P2 tick cleared the tier's strikes (direct carrier genuinely
    /// receiving) — mirror of the legacy `clear_tier_strikes` disposition
    /// (CC1: the carrier's OWN tier only, never cross-tier).
    pub(crate) fn on_healthy_rx(&mut self, peer: &ObjectId, tier: DirectTier) {
        if let (Some(p), Some(idx)) = (self.peers.get_mut(peer), tier_idx(tier)) {
            p.tiers[idx].fails = 0;
        }
    }

    /// A direct carrier was INSTALLED on `tier` (fresh install, destructive
    /// upgrade, inbound re-point) or the relay carrier was installed
    /// (`tier == Relay`). Records switch time + the LAN attempt marker.
    pub(crate) fn on_installed(&mut self, peer: &ObjectId, tier: DirectTier, now: Instant) {
        let p = self.peers.entry(*peer).or_default();
        if tier == DirectTier::Lan {
            p.last_lan_attempt = Some(now);
        }
        p.hysteresis.record_switch(now);
    }

    /// A make-before-break probe STARTED toward `tier`.
    pub(crate) fn on_probe_started(&mut self, peer: &ObjectId, tier: DirectTier, now: Instant) {
        let p = self.peers.entry(*peer).or_default();
        if p.probe.is_none() {
            self.probes_in_flight += 1;
        }
        p.probe = Some((tier, now));
        if tier == DirectTier::Lan {
            p.last_lan_attempt = Some(now);
        }
    }

    /// A probe settled. Latched: Q credit + tier strikes clear (≡ the legacy
    /// promote's `*_fails.remove`) + switch recorded (the promote IS the
    /// switch). Expired: the tier failure books (strike + penalty; under
    /// make-before-break never past the ordinary half-life), and — F1 — NO
    /// Q event.
    pub(crate) fn on_probe_result(
        &mut self,
        peer: &ObjectId,
        tier: DirectTier,
        outcome: ProbeOutcome,
        mbb: bool,
        now: Instant,
    ) {
        if let Some(p) = self.peers.get_mut(peer)
            && p.probe.take().is_some()
        {
            self.probes_in_flight = self.probes_in_flight.saturating_sub(1);
        }
        match outcome {
            ProbeOutcome::Latched { latency_ms } => {
                let deduction = latency_ms
                    .map(|ms| (ms / Q_LATCH_LATENCY_DIVISOR).min(Q_LATCH_MAX_DEDUCTION))
                    .unwrap_or(0.0);
                let p = self.peers.entry(*peer).or_default();
                if let Some(idx) = tier_idx(tier) {
                    p.tiers[idx].q.feed(Q_CLAMP - deduction, Q_LATCH_ALPHA);
                    p.tiers[idx].fails = 0;
                }
                p.hysteresis.record_switch(now);
                // F3 — direct is back; the lane has done its job.
                p.fast_return_until = None;
            }
            ProbeOutcome::Expired => {
                self.book_failure(peer, tier, mbb, true, now);
            }
        }
    }

    /// A probe was ABORTED without a verdict (peer re-pointed by an inbound
    /// init / feature toggled off): free the slot, book nothing.
    pub(crate) fn on_probe_aborted(&mut self, peer: &ObjectId) {
        if let Some(p) = self.peers.get_mut(peer)
            && p.probe.take().is_some()
        {
            self.probes_in_flight = self.probes_in_flight.saturating_sub(1);
        }
    }

    /// rc.225 ≡ `DirectCooldowns::reset_peer` — the peer's advertised direct
    /// endpoints CHANGED: everything measured against the old endpoints is
    /// stale evidence. Clears penalties, strikes AND quality (F1 — new
    /// endpoints get a fresh Q, completing the rc.225 semantics) for the
    /// direct tiers. Relay-Q is untouched (relay reachability didn't change).
    pub(crate) fn on_endpoint_change(&mut self, peer: &ObjectId) {
        if let Some(p) = self.peers.get_mut(peer) {
            for t in &mut p.tiers {
                t.penalty = None;
                t.fails = 0;
                t.q = Ewma::default();
            }
        }
    }

    /// R2 — OUR direct plane was rebuilt (roam / interface change): every
    /// direct-tier measurement was made through sockets that no longer
    /// exist, so clear direct penalties, strikes AND Q for every peer —
    /// [`on_endpoint_change`](Self::on_endpoint_change) semantics, applied
    /// locally. Deliberately NOT [`on_resume`](Self::on_resume): `relay_q`
    /// is KEPT (relay carriers ride the coordinator/WS and survive a plane
    /// rebuild — that evidence is still good) and `last_lan_attempt` is
    /// KEPT (so `LAN_PROBE_SPACING` still paces the post-rebuild re-probe
    /// herd instead of amplifying it).
    pub(crate) fn on_local_rebuild(&mut self) {
        for p in self.peers.values_mut() {
            for t in &mut p.tiers {
                t.penalty = None;
                t.fails = 0;
                t.q = Ewma::default();
            }
        }
    }

    /// P8 ≡ the resume-from-suspend `cooldowns = default()`: every score and
    /// suppression is stale evidence after a sleep. Probe bookkeeping is KEPT
    /// — the legacy resume path leaves `upgrade_probes` in flight too (they
    /// settle via their own promote/expire sweep).
    pub(crate) fn on_resume(&mut self) {
        for p in self.peers.values_mut() {
            for t in &mut p.tiers {
                *t = TierState::default();
            }
            p.relay_q = Ewma::default();
            p.last_lan_attempt = None;
        }
    }

    /// netstate PR-2 — a MAJOR network change (default route moved /
    /// addresses vanished): every score, penalty, and sticky suppression was
    /// earned on the OLD network and is stale evidence on the new one — the
    /// same disposition as resume-from-suspend, because it is the same event
    /// from the path's point of view (the world moved while we watched).
    /// Probe bookkeeping KEPT (in-flight probes settle via their own sweep).
    pub(crate) fn on_network_changed(&mut self) {
        self.on_resume();
    }

    /// The peer left the netmap.
    pub(crate) fn on_peer_removed(&mut self, peer: &ObjectId) {
        if let Some(p) = self.peers.remove(peer)
            && p.probe.is_some()
        {
            self.probes_in_flight = self.probes_in_flight.saturating_sub(1);
        }
    }

    /// P7 — the server pinned this pair to DERP for `ttl`. Annotation only:
    /// direct-tier decisions are unaffected (the pin is about the relay
    /// SUB-tier). Relay-Q resets — evidence gathered under the broken TURN
    /// sub-tier says nothing about the DERP window.
    pub(crate) fn on_forced_derp(&mut self, peer: &ObjectId, ttl: Duration, now: Instant) {
        let p = self.peers.entry(*peer).or_default();
        p.forced_derp_until = Some(now + ttl);
        p.relay_q = Ewma::default();
    }

    /// FR-33 P2 — the runtime's verdict on whether THIS host can reach the
    /// peer's LAN candidate at all: `true` while the candidate sits in a
    /// prefix the host's own route lookup hands to another interface. A hard
    /// eligibility gate on the LAN tier only (public/srflx ride other sockets
    /// and are unaffected); no penalty, no Q event — nothing about the path
    /// was measured, the OS was asked where the packet would go. Cleared the
    /// same way (`false`) on the first walk after the capture lifts;
    /// `on_peer_removed` drops it with the rest of the peer's state.
    pub(crate) fn on_lan_capture(&mut self, peer: &ObjectId, captured: bool) {
        match self.peers.get_mut(peer) {
            Some(p) => p.lan_captured = captured,
            // Don't materialise state for a peer that is NOT captured: a
            // fresh peer's "no state" already means "no gates".
            None if captured => self.peers.entry(*peer).or_default().lan_captured = true,
            None => {}
        }
    }

    /// PR-E — the current strike count on a direct tier. The sweep's sticky-
    /// pin log line keys off this now that the legacy fail maps are gone.
    /// F3 — is any peer inside its fast-return lane? The runtime then walks
    /// `install_peers` every fallback tick instead of every ~30 s.
    pub(crate) fn fast_return_active(&self, now: Instant) -> bool {
        self.peers
            .values()
            .any(|p| p.fast_return_until.is_some_and(|until| until > now))
    }

    pub(crate) fn strikes(&self, peer: &ObjectId, tier: DirectTier) -> u32 {
        tier_idx(tier)
            .and_then(|idx| self.peers.get(peer).map(|p| p.tiers[idx].fails))
            .unwrap_or(0)
    }

    /// PR-E — is `tier` in its escalated (sticky) suppression regime for this
    /// peer? Mirrors [`suppression_half_life`]'s table, including the P8
    /// LAN-under-MBB never-sticky rule.
    pub(crate) fn is_sticky(&self, peer: &ObjectId, tier: DirectTier, mbb: bool) -> bool {
        let max = match tier {
            DirectTier::Srflx => MAX_FAILURES_SRFLX,
            DirectTier::Lan if mbb => return false,
            _ => MAX_FAILURES_LAN_PUBLIC,
        };
        self.strikes(peer, tier) >= max
    }

    /// Is the server's forced-DERP pin active for this peer? Consumed by the
    /// PR-B scheduler comparison (never-select-against-a-pin); until then the
    /// pin-invariant tests are its only caller (the allow tracks that).
    #[allow(dead_code)]
    pub(crate) fn forced_derp_active(&self, peer: &ObjectId, now: Instant) -> bool {
        self.peers
            .get(peer)
            .and_then(|p| p.forced_derp_until)
            .is_some_and(|until| until > now)
    }

    // -- the decision --------------------------------------------------------

    /// Eligibility-plane query: may `tier` be attempted for this peer now?
    /// Priors + penalty ONLY — no Q term (the invariant the two-plane split
    /// exists for). The relay tier is always eligible (it is the floor).
    pub(crate) fn eligible(&self, peer: &ObjectId, tier: DirectTier, now: Instant) -> bool {
        let Some(idx) = tier_idx(tier) else {
            return true;
        };
        let p = match self.peers.get(peer) {
            Some(p) => p,
            None => return true, // fresh peer: no penalties anywhere
        };
        // #30 — the peer is relaying to us instead of using ANY direct tier.
        // That is not a quality judgement about a path, it is a fact about
        // where the peer is, so it gates eligibility outright rather than
        // through the penalty plane (which cannot hold long enough — see
        // `on_peer_relayed_instead`).
        if p.relayed_instead_until.is_some_and(|until| now < until) {
            return false;
        }
        // FR-33 P2 — this host's route to the peer's LAN candidate leaves
        // through another interface (a VPN split-prefix capture): a fact
        // about THIS host, gating the LAN tier outright — `on_lan_capture`.
        if tier == DirectTier::Lan && p.lan_captured {
            return false;
        }
        let penalty = p.tiers[idx]
            .penalty
            .map(|pen| pen.value(now))
            .unwrap_or(0.0);
        base(tier) - penalty >= B_RELAY - ELIGIBILITY_EPS
    }

    /// Ranking-plane score `S = B + Q − P` — meaningful ONLY among eligible
    /// tiers (never consulted for eligibility).
    pub(crate) fn score(&self, peer: &ObjectId, tier: DirectTier, now: Instant) -> f64 {
        let p = self.peers.get(peer);
        let (q, penalty) = match tier_idx(tier) {
            Some(idx) => p
                .map(|p| {
                    (
                        p.tiers[idx].q.get(),
                        p.tiers[idx]
                            .penalty
                            .map(|pen| pen.value(now))
                            .unwrap_or(0.0),
                    )
                })
                .unwrap_or((0.0, 0.0)),
            None => (p.map(|p| p.relay_q.get()).unwrap_or(0.0), 0.0),
        };
        base(tier) + q - penalty
    }

    // -- explaining the decision ---------------------------------------------

    /// Why this peer sits on the tier it sits on, as data (F / `roomler why`).
    ///
    /// Every field here is already consulted by [`Self::eligible`] and
    /// [`Self::score`]; the point is that NONE of it was readable from
    /// outside. Answering "why is this pair on relay and not LAN?" in the
    /// field on 2026-08-26 took a `tcpdump` on one host plus log archaeology
    /// on the other, and the decisive record — the demote-follow — is keyed by
    /// node id with no overlay IP in the line, so an earlier grep by IP
    /// concluded "0 follows" for a pair that was following continuously. A
    /// wrong answer from a plausible-looking search is worse than no answer,
    /// and the fix is to publish the decision rather than to grep harder for
    /// its side effects.
    ///
    /// Pure read: no state is touched, so this is safe to call on every view
    /// publish.
    pub(crate) fn explain(&self, peer: &ObjectId, now: Instant) -> PathExplain {
        let p = self.peers.get(peer);
        let remaining = |until: Option<Instant>| {
            until
                .filter(|&u| u > now)
                .map(|u| u.saturating_duration_since(now).as_secs())
        };
        let relayed_instead_s = remaining(p.and_then(|p| p.relayed_instead_until));
        let tiers = DIRECT_TIERS
            .iter()
            .chain(std::iter::once(&DirectTier::Relay))
            .map(|&tier| {
                let penalty = tier_idx(tier)
                    .and_then(|i| p.and_then(|p| p.tiers[i].penalty))
                    .map(|pen| pen.value(now))
                    .unwrap_or(0.0);
                let eligible = self.eligible(peer, tier, now);
                // The reason is resolved in the SAME order `eligible` tests,
                // so the text can never disagree with the verdict it explains.
                let blocked_by = if eligible {
                    None
                } else if relayed_instead_s.is_some() {
                    Some(BlockedBy::PeerRelaysInstead)
                } else if tier == DirectTier::Lan && p.is_some_and(|p| p.lan_captured) {
                    Some(BlockedBy::LanCaptured)
                } else {
                    Some(BlockedBy::Penalty)
                };
                TierExplain {
                    tier,
                    eligible,
                    blocked_by,
                    available: p.and_then(|p| p.avail).map(|a| a.has(tier)),
                    base: base(tier),
                    q: tier_idx(tier)
                        .and_then(|i| p.map(|p| p.tiers[i].q.get()))
                        .unwrap_or_else(|| p.map(|p| p.relay_q.get()).unwrap_or(0.0)),
                    penalty,
                    score: self.score(peer, tier, now),
                    fails: tier_idx(tier)
                        .and_then(|i| p.map(|p| p.tiers[i].fails))
                        .unwrap_or(0),
                }
            })
            .collect();
        PathExplain {
            tiers,
            relayed_instead_s,
            relayed_instead_strikes: p.map(|p| p.relayed_instead_strikes).unwrap_or(0),
            forced_derp_s: remaining(p.and_then(|p| p.forced_derp_until)),
            probing: p.and_then(|p| p.probe).map(|(t, _)| t),
        }
    }

    /// The path decision for one peer, given what the runtime currently sees:
    /// the incumbent carrier, which direct tiers have a dialable candidate,
    /// and the make-before-break env state. Shadow-compared against the
    /// legacy `install_peers` branch outcomes 1:1:
    ///
    /// * already direct → `Keep` (upg' between direct tiers is post-flip work);
    /// * a probe in flight (this peer, or the global cap) → `Keep`;
    /// * relay incumbent + an eligible direct tier → `Probe` (MBB) /
    ///   `Install` (destructive mode);
    /// * fresh peer + LAN best under MBB → `Probe(Lan)` (P9 — a same-/24
    ///   candidate is only a HINT: vendor-default subnets false-match across
    ///   sites, so the unproven LAN dial must not preempt the working-carrier
    ///   walk; the executor probes LAN and installs the next-best tier / relay
    ///   in the same pass; cap-full → `Relay`);
    /// * fresh peer otherwise → `Install` best eligible direct tier, else `Relay`;
    /// * relay incumbent + nothing eligible → `Keep`.
    ///
    /// "Best" = highest `S` among eligible+available, tie-broken by legacy
    /// precedence; the F2 LAN spacing pin filters LAN scorelessly.
    pub(crate) fn decide(
        &mut self,
        peer: &ObjectId,
        incumbent: Incumbent,
        avail: TierAvailability,
        mbb: bool,
        now: Instant,
        demote_on: bool,
    ) -> PathAction {
        // #2089 — kept for `explain` only; nothing below reads it back. A
        // default entry reads the same zeros as an absent one, so creating it
        // changes no decision.
        self.peers.entry(*peer).or_default().avail = Some(avail);
        if let Incumbent::Direct(cur) = incumbent {
            // B2 — a live direct incumbent is kept UNLESS a sustained
            // margin-sized score deficit demotes it (voluntary MBB probe,
            // hysteresis-bound; never a blind Install). `demote_on` is
            // false in off/shadow modes — shadow counts via a separate
            // `demote_candidate` call at the surface.
            if demote_on && let Some(action) = self.demote_candidate(peer, cur, avail, now) {
                return action;
            }
            return PathAction::Keep;
        }
        let state = self.peers.get(peer);
        if state.is_some_and(|p| p.probe.is_some()) {
            // One probe per peer, structural. An installed incumbent keeps
            // carrying traffic while the probe runs; a FRESH peer (no
            // carrier at all) must not sit carrierless waiting on it —
            // PR-C: ride relay for the working carrier (P9's carrier-first
            // principle) and let the probe promote over it when it latches.
            // Soak #1 Class A caught legacy racing a fresh direct install
            // over a dangling probe here (a sweep death leaves
            // `upgrade_probes` intact and the fresh walk ignored it, so a
            // late promote could clobber the fresh carrier).
            return match incumbent {
                Incumbent::None => PathAction::Relay,
                _ => PathAction::Keep,
            };
        }

        let lan_spaced_out = state.is_some_and(|p| {
            p.last_lan_attempt.is_some_and(|t| {
                now.saturating_duration_since(t) < lan_spacing(p, self.fast_return_lan_off, now)
            })
        });

        let mut best: Option<(DirectTier, f64)> = None;
        for tier in DIRECT_TIERS {
            if !avail.has(tier) || !self.eligible(peer, tier, now) {
                continue;
            }
            // F2 — the LAN spacing pin is scoreless and unconditional.
            if tier == DirectTier::Lan && lan_spaced_out {
                continue;
            }
            let s = self.score(peer, tier, now);
            // Strictly-greater keeps the DIRECT_TIERS iteration order as the
            // tie-break — cold start (all S = B) IS the legacy precedence.
            if best.is_none_or(|(_, bs)| s > bs) {
                best = Some((tier, s));
            }
        }

        match (incumbent, best) {
            (Incumbent::Relay, Some((tier, _))) => {
                if mbb {
                    if self.probes_in_flight >= PROBE_CAP {
                        return PathAction::Keep;
                    }
                    PathAction::Probe(tier)
                } else {
                    PathAction::Install(tier)
                }
            }
            (Incumbent::Relay, None) => PathAction::Keep,
            // P9 — fresh-LAN is probe-first under MBB: a same-/24 candidate is
            // only a HINT (192.168.68.0/24 Deco, 192.168.1.0/24 … false-match
            // across sites; field 2026-07-28: fresh installs burned the 12 s
            // LAN deadline with NO carrier, repeatedly, against corp peers
            // advertising another city's 192.168.68.x). Probe the LAN, take
            // the next-best tier / relay for the working carrier meanwhile.
            // Cap-full → Relay: the carrier comes first, the probe can wait
            // for the relay→direct upgrade arm once a slot frees.
            (Incumbent::None, Some((DirectTier::Lan, _))) if mbb => {
                if self.probes_in_flight >= PROBE_CAP {
                    return PathAction::Relay;
                }
                PathAction::Probe(DirectTier::Lan)
            }
            (Incumbent::None, Some((tier, _))) => PathAction::Install(tier),
            (Incumbent::None, None) => PathAction::Relay,
            (Incumbent::Direct(_), _) => unreachable!("handled above"),
        }
    }

    /// B2 — the voluntary-demotion candidate for a LIVE direct incumbent,
    /// if the sustained-margin conditions hold. Called from `decide` in
    /// `on` mode and from the surface's shadow counter — exactly one
    /// caller per evaluation tick, since it owns the `below_since`
    /// tracking. Returns:
    /// - `Probe(better_tier)` — the MBB machinery executes it (the
    ///   incumbent carries traffic until the probe latches);
    /// - `Relay` — the ADVISORY direct→relay class (nothing else
    ///   eligible + incumbent Q slammed; execution deliberately
    ///   deferred — counted and logged only, even in `on` mode).
    pub(crate) fn demote_candidate(
        &mut self,
        peer: &ObjectId,
        cur: DirectTier,
        avail: TierAvailability,
        now: Instant,
    ) -> Option<PathAction> {
        let cur_idx = tier_idx(cur)?;
        let cur_score = self.score(peer, cur, now);
        let probes_full = self.probes_in_flight >= PROBE_CAP;
        let p = self.peers.entry(*peer).or_default();

        // Never against a forced-DERP pin, and never while a probe for
        // this peer is already in flight (freeze the hold — don't clear).
        if p.forced_derp_until.is_some_and(|until| until > now) {
            p.tiers[cur_idx].below_since = None;
            return None;
        }
        if p.probe.is_some() {
            return None;
        }

        let lan_spaced_out = p.last_lan_attempt.is_some_and(|t| {
            now.saturating_duration_since(t) < lan_spacing(p, self.fast_return_lan_off, now)
        });
        let voluntary_ok = p.hysteresis.voluntary_allowed(now);
        let cur_q = p.tiers[cur_idx].q.get();

        // DEGRADED-but-live means degraded: a non-negative incumbent Q
        // never demotes, whatever the score gap — tier BASE differences
        // alone (e.g. LAN − Public = 70) exceed the margin, and probing
        // a HIGHER tier from a healthy incumbent is B3's upward-probing
        // job (own spacing), not a demotion.
        if cur_q >= 0.0 {
            p.tiers[cur_idx].below_since = None;
            return None;
        }

        // Best strictly-eligible alternative (the F2 LAN spacing pin and
        // the probe cap apply to demotion targets exactly as to upgrades).
        let mut best: Option<(DirectTier, f64)> = None;
        for tier in DIRECT_TIERS {
            if tier == cur || !avail.has(tier) {
                continue;
            }
            if tier == DirectTier::Lan && lan_spaced_out {
                continue;
            }
            if !self.eligible(peer, tier, now) {
                continue;
            }
            let s = self.score(peer, tier, now);
            if best.is_none_or(|(_, bs)| s > bs) {
                best = Some((tier, s));
            }
        }

        let p = self.peers.entry(*peer).or_default();
        let deficit_holds = match best {
            Some((_, alt_score)) => alt_score - cur_score >= DEMOTE_MARGIN,
            // Direct→relay (advisory) class: nothing else eligible AND the
            // incumbent's Q is slammed to the floor.
            None => cur_q <= DEMOTE_RELAY_Q_FLOOR,
        };
        if !deficit_holds {
            p.tiers[cur_idx].below_since = None;
            return None;
        }
        let since = *p.tiers[cur_idx].below_since.get_or_insert(now);
        if now.saturating_duration_since(since) < DEMOTE_HOLD || !voluntary_ok {
            return None;
        }
        match best {
            Some((alt, _)) => {
                if probes_full {
                    return None;
                }
                Some(PathAction::Probe(alt))
            }
            None => Some(PathAction::Relay),
        }
    }

    /// B3 — the mid-tier upward-probe candidate for an established
    /// srflx/public incumbent: the highest-precedence STRICTLY-HIGHER
    /// tier that is available + eligible (the F2 LAN spacing applies to
    /// a LAN target on top — both gates), at most once per
    /// [`UPWARD_PROBE_SPACING`] per peer. Booking happens at candidate
    /// time — an unresolvable endpoint still spends the slot, so a
    /// structurally dead target can't be hammered. A failed probe books
    /// the tier's normal penalty (its own pacing); NO Q event on expiry
    /// (F1). Executed as the same MBB probe (incumbent held until latch).
    pub(crate) fn upward_candidate(
        &mut self,
        peer: &ObjectId,
        cur: DirectTier,
        avail: TierAvailability,
        now: Instant,
    ) -> Option<DirectTier> {
        let cur_idx = tier_idx(cur)?;
        if cur_idx == 0 {
            return None; // LAN incumbent — nothing higher.
        }
        if self.probes_in_flight >= PROBE_CAP {
            return None;
        }
        let p = self.peers.entry(*peer).or_default();
        if p.probe.is_some() {
            return None;
        }
        if p.last_upward_attempt
            .is_some_and(|t| now.saturating_duration_since(t) < UPWARD_PROBE_SPACING)
        {
            return None;
        }
        let lan_spaced_out = p.last_lan_attempt.is_some_and(|t| {
            now.saturating_duration_since(t) < lan_spacing(p, self.fast_return_lan_off, now)
        });

        // First higher-precedence tier passing ALL gates (a penalized top
        // tier falls through to the next one — eligibility needs `&self`,
        // hence the re-borrow dance around `p`).
        let target = DIRECT_TIERS[..cur_idx]
            .iter()
            .copied()
            .filter(|&tier| avail.has(tier) && !(tier == DirectTier::Lan && lan_spaced_out))
            .find(|&tier| self.eligible(peer, tier, now))?;
        let p = self.peers.entry(*peer).or_default();
        p.last_upward_attempt = Some(now);
        Some(target)
    }

    /// The inbound-init decision (≡ `handle_direct_inbound`'s accept/refuse):
    /// feed the evidence (authenticated init = strong positive; a srflx init
    /// is D9 — proof the pair CAN punch right now, so it clears the srflx
    /// suppression outright), then accept iff the tier is eligible.
    /// `None` = refuse (≡ the legacy cooldown gate). The action mirrors the
    /// legacy branch: already-probing → `Keep` (answer only), relay incumbent
    /// under MBB → `Probe`, else `Install` (re-point).
    pub(crate) fn inbound_init(
        &mut self,
        peer: &ObjectId,
        tier: DirectTier,
        incumbent: Incumbent,
        mbb: bool,
        now: Instant,
    ) -> Option<PathAction> {
        let p = self.peers.entry(*peer).or_default();
        if let Some(idx) = tier_idx(tier) {
            p.tiers[idx].q.feed(Q_INBOUND_SAMPLE, Q_INBOUND_ALPHA);
            if tier == DirectTier::Srflx {
                // D9 — the init traversed both NATs; the suppression was
                // measured against conditions that just changed.
                p.tiers[idx].penalty = None;
                p.tiers[idx].fails = 0;
            }
        }
        // #33 — the suppression planes must gate what WE PROMOTE, never
        // whether we ANSWER the peer.
        //
        // This verdict is authoritative for inbound: `None` means the caller
        // returns WITHOUT answering the peer's handshake initiation. So while
        // a tier is suppressed — by the #30 demote-follow window, or by the
        // penalty that `on_peer_relayed_instead` books alongside it — the node
        // goes DEAF on that tier, and two ends that have both followed cannot
        // hear each other for a window that escalates to 15 minutes. Measured
        // 2026-08-26 on neo16 ↔ a MacBook one metre away: 3370 probe failures
        // with `saw_inbound=false` against 3 with `true`, WireGuard initiations
        // visible in tcpdump flowing BOTH ways with zero responses — while
        // disco, whose responder has no such gate, measured that same LAN path
        // at 8 % loss. The path was never the problem.
        //
        // Answering is FREE in the non-destructive case: under
        // make-before-break an init for a relay-carried peer is accepted as a
        // SHADOW probe with its own `Tunn`, and the relay stands unless that
        // probe LATCHES. So the latch is the real gate, and it is untouched —
        // nothing moves traffic on the strength of this. The init is also
        // live evidence that the tier carries peer→us right now, which is the
        // same reasoning D9 already applies to srflx just above.
        //
        // `eligible` still governs every outbound decision, so the hold-down
        // keeps its whole purpose: we do not PROMOTE into a flap.
        let free_to_answer =
            mbb && incumbent == Incumbent::Relay && super::direct::answer_while_followed();
        if !free_to_answer && !self.eligible(peer, tier, now) {
            return None;
        }
        if self.peers.get(peer).is_some_and(|p| p.probe.is_some()) {
            return Some(PathAction::Keep);
        }
        if mbb && incumbent == Incumbent::Relay {
            Some(PathAction::Probe(tier))
        } else {
            Some(PathAction::Install(tier))
        }
    }
}

// ---------------------------------------------------------------------------
// Divergence classification (the shadow harness's pure half)
// ---------------------------------------------------------------------------

/// Shadow-comparison outcome for one decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DivergenceClass {
    /// Monitor and legacy chose the same action.
    Match,
    /// They differ — the soak gate counts these (steady < 0.1 %,
    /// transition < 2 %; see the P3 acceptance gate).
    Diverged,
}

/// Strict comparison — PR-A deliberately classifies nothing as "benign":
/// timing-window forgiveness enters with PR-B's scheduler comparison, where
/// it can be justified per-class instead of blurring the signal here.
pub(crate) fn classify(legacy: PathAction, monitor: PathAction) -> DivergenceClass {
    if legacy == monitor {
        DivergenceClass::Match
    } else {
        DivergenceClass::Diverged
    }
}

/// Why a direct tier is not currently allowed for a peer. Mirrors the order
/// [`PathMonitor::eligible`] tests its gates, so the label and the verdict
/// cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockedBy {
    /// #30 — the peer is demonstrably relaying to us instead of using ANY
    /// direct tier, so every direct tier is held down until the window
    /// passes. This is a fact about the PEER, not a quality judgement about
    /// the path, which is why it reads differently from a penalty.
    PeerRelaysInstead,
    /// FR-33 P2 — THIS host's own routing hands the peer's LAN prefix to
    /// another interface (a corporate VPN client's split-prefix capture), so
    /// a LAN dial cannot work whatever the path's history says. A fact about
    /// this host, not the path: `roomler status` names the capturing
    /// adapter, and the fix lives in the VPN profile.
    LanCaptured,
    /// The tier's own penalty has pushed `base − penalty` below the relay
    /// floor: this path misbehaved recently and is decaying back.
    Penalty,
}

impl BlockedBy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            BlockedBy::PeerRelaysInstead => "peer-relays-instead",
            BlockedBy::LanCaptured => "lan-captured",
            BlockedBy::Penalty => "penalty",
        }
    }
}

/// One tier's side of [`PathExplain`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct TierExplain {
    pub(crate) tier: DirectTier,
    pub(crate) eligible: bool,
    pub(crate) blocked_by: Option<BlockedBy>,
    /// #2089 — did the tier have a dialable candidate at the last decision?
    /// `decide` only considers a tier that is available AND eligible, and an
    /// untried tier carries no penalty, so `eligible` alone reads "yes" for a
    /// tier there is nothing to dial on. `None` before the first decision;
    /// the relay tier is always available once known.
    pub(crate) available: Option<bool>,
    pub(crate) base: f64,
    pub(crate) q: f64,
    pub(crate) penalty: f64,
    pub(crate) score: f64,
    pub(crate) fails: u32,
}

/// A readable account of one peer's path decision — see
/// [`PathMonitor::explain`].
#[derive(Debug, Clone)]
pub(crate) struct PathExplain {
    /// LAN, Public, Srflx, Relay — in that order, so a renderer can print the
    /// ladder top-down without sorting.
    pub(crate) tiers: Vec<TierExplain>,
    /// Seconds left on the #30 demote-follow window, if it is open.
    pub(crate) relayed_instead_s: Option<u64>,
    /// Consecutive demote-follows inside `RELAYED_INSTEAD_MEMORY`. This is the
    /// rung of the escalation ladder, and a climbing value is the signature of
    /// a pair whose two ends persistently disagree.
    pub(crate) relayed_instead_strikes: u32,
    /// Seconds left on the server's forced-DERP pin, if any.
    pub(crate) forced_derp_s: Option<u64>,
    /// A probe is in flight for this peer, on this tier.
    pub(crate) probing: Option<DirectTier>,
}

/// Rolling shadow counters, surfaced in the 10-minute summary log.
#[derive(Default, Debug)]
pub(crate) struct ShadowStats {
    /// Compared decisions (install_peers surfaces + inbound).
    pub(crate) decisions: u64,
    /// Strict mismatches.
    pub(crate) diverged: u64,
    /// HARMFUL class: the monitor refused a tier that legacy then proved
    /// (probe latched / carrier turned healthy) within 60 s. The acceptance
    /// gate requires ZERO of these.
    pub(crate) harmful: u64,
    /// Model-bug tripwire: a tier the monitor still called eligible
    /// immediately after its own death/expiry penalty booked (must be 0 —
    /// the penalty math guarantees ineligibility right after booking).
    pub(crate) post_death_eligible: u64,
    /// B1 — RTT samples applied to an installed peer's incumbent tier
    /// (instrumentation health: a flat 0 with the flag on means the
    /// prober→runtime plumbing is broken).
    pub(crate) rtt_samples: u64,
    /// PR-C (soak #1 finding) — D10 re-dials, counted but NOT compared: a
    /// zombie-srflx re-dial refreshes the DIAL TARGET of the current tier
    /// (Srflx→Srflx), so it is not a tier-selection event and comparing it
    /// against `decide()` was a PR-A over-inclusion (50+/host/45 h of false
    /// "divergence" in soak #1). The re-dial stays execution-layer
    /// permanently — even a post-PR-E authoritative monitor doesn't own
    /// dial-target freshness.
    pub(crate) d10_redials: u64,
    /// P3 PR-B — `(decisions, diverged)` per trigger class
    /// (netmap / delta / reupgrade / resume / initial / inbound): the
    /// scheduler comparison as its own divergence class. A reupgrade-tick
    /// divergence means the monitor would have SCHEDULED differently; a
    /// netmap/delta one that it would have SELECTED differently — the soak
    /// gate reads them separately.
    pub(crate) by_class: HashMap<&'static str, (u64, u64)>,
}

impl ShadowStats {
    /// Compact, sorted `class:decisions/diverged` rendering for the 10-min
    /// summary log line.
    pub(crate) fn classes_line(&self) -> String {
        let mut cls: Vec<String> = self
            .by_class
            .iter()
            .map(|(k, (d, v))| format!("{k}:{d}/{v}"))
            .collect();
        cls.sort();
        cls.join(",")
    }
}

/// Stable wire spelling for a tier. Kept next to the tiers themselves so a
/// renamed variant cannot silently change a diagnostic's vocabulary.
pub(crate) fn tier_label(t: DirectTier) -> &'static str {
    match t {
        DirectTier::Lan => "lan",
        DirectTier::Public => "public",
        DirectTier::Srflx => "srflx",
        DirectTier::Relay => "relay",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(n: u8) -> ObjectId {
        let mut b = [0u8; 12];
        b[11] = n;
        ObjectId::from_bytes(b)
    }

    fn all_avail() -> TierAvailability {
        TierAvailability {
            lan: true,
            public: true,
            srflx: true,
        }
    }

    /// Drive `n` heard events into a tier's Q.
    fn pump_heard(m: &mut PathMonitor, peer: &ObjectId, tier: DirectTier, n: usize) {
        for _ in 0..n {
            m.on_heard(peer, tier);
        }
    }

    /// PR-D — unset (and anything unrecognized) defaults to ON; `shadow` is
    /// the explicit per-host revert; `off` still kills the monitor.
    #[test]
    fn mode_parse_defaults_to_on() {
        assert_eq!(PathMonMode::parse(None), PathMonMode::On);
        assert_eq!(PathMonMode::parse(Some("on")), PathMonMode::On);
        assert_eq!(PathMonMode::parse(Some("1")), PathMonMode::On);
        assert_eq!(PathMonMode::parse(Some("bogus")), PathMonMode::On);
        assert_eq!(PathMonMode::parse(Some("shadow")), PathMonMode::Shadow);
        assert_eq!(PathMonMode::parse(Some("SHADOW")), PathMonMode::Shadow);
        assert_eq!(PathMonMode::parse(Some("off")), PathMonMode::Off);
        assert_eq!(PathMonMode::parse(Some("0")), PathMonMode::Off);
        assert_eq!(PathMonMode::On.as_str(), "on");
        assert_eq!(PathMonMode::Shadow.as_str(), "shadow");
    }

    #[test]
    fn ewma_clamps_and_converges() {
        let mut e = Ewma::default();
        e.feed(100.0, 0.4);
        assert!((e.get() - 40.0).abs() < 1e-9);
        for _ in 0..200 {
            e.feed(100.0, 0.4);
        }
        assert!(e.get() <= 100.0 && e.get() > 99.9, "converges under clamp");
        e.slam(-250.0);
        assert_eq!(e.get(), -100.0, "slam clamps");
    }

    /// The eligibility plane reproduces the legacy 60 s window exactly:
    /// suppressed at 59 s, eligible at 61 s (the boundary instant itself is
    /// eligible, like legacy's `until > now`).
    #[test]
    fn eligibility_parity_ordinary_window_59_61() {
        for tier in DIRECT_TIERS {
            let mut m = PathMonitor::default();
            let a = oid(1);
            let t0 = Instant::now();
            m.on_death(&a, tier, DeathReason::HandshakeDeadline, true, t0);
            assert!(
                !m.eligible(&a, tier, t0 + Duration::from_secs(59)),
                "{tier:?} must still be suppressed at 59 s"
            );
            assert!(
                m.eligible(&a, tier, t0 + Duration::from_secs(61)),
                "{tier:?} must be eligible again at 61 s"
            );
            // Other tiers were never poisoned (CC1).
            for other in DIRECT_TIERS {
                if other != tier {
                    assert!(m.eligible(&a, other, t0 + Duration::from_secs(1)));
                }
            }
        }
    }

    /// Stage 2 — a [`DeathReason::RekeyUnanswered`] death books NOTHING: no
    /// strike, no suppression penalty, no Q movement, on direct AND relay
    /// tiers. The tier must stay immediately eligible (the rebuild's own
    /// failure is what books evidence), and the Q plane must be untouched so
    /// a transient poke death can't nudge tier selection or feed the
    /// forced-DERP churn ladder.
    #[test]
    fn rekey_unanswered_death_books_nothing() {
        for tier in DIRECT_TIERS {
            let mut m = PathMonitor::default();
            let a = oid(1);
            let t0 = Instant::now();
            m.on_death(&a, tier, DeathReason::RekeyUnanswered, true, t0);
            assert!(
                m.eligible(&a, tier, t0 + Duration::from_secs(1)),
                "{tier:?} must stay immediately eligible after a poke death"
            );
            assert_eq!(m.strikes(&a, tier), 0, "{tier:?} must book no strike");
            let p = m.peers.get(&a).expect("switch pacing recorded the peer");
            let idx = tier_idx(tier).unwrap();
            assert_eq!(
                p.tiers[idx].q.get(),
                0.0,
                "{tier:?} Q must be untouched (no death slam)"
            );
            assert!(p.tiers[idx].penalty.is_none(), "{tier:?} no penalty");
        }
        // Relay flavour: relay_q untouched too.
        let mut m = PathMonitor::default();
        let a = oid(2);
        m.on_death(
            &a,
            DirectTier::Relay,
            DeathReason::RekeyUnanswered,
            true,
            Instant::now(),
        );
        assert_eq!(m.peers.get(&a).unwrap().relay_q.get(), 0.0);
        // Contrast lock: the SAME death with any other reason still books.
        let mut m = PathMonitor::default();
        let t0 = Instant::now();
        m.on_death(&a, DirectTier::Lan, DeathReason::RxStale, true, t0);
        assert_eq!(m.strikes(&a, DirectTier::Lan), 1);
        assert!(!m.eligible(&a, DirectTier::Lan, t0 + Duration::from_secs(1)));
    }

    /// F3c — an outage that outlasts [`FAST_RETURN_WINDOW`] keeps the lane open
    /// with backoff instead of lapsing into the ordinary ladder: each in-lane
    /// failure extends the lane (to [`FAST_RETURN_MAX`] after the conviction)
    /// and doubles the short penalty and the LAN spacing; no strike is booked.
    #[test]
    fn a_long_outage_keeps_the_lane_open_with_backoff() {
        let a = oid(1);
        for tier in [DirectTier::Lan, DirectTier::Srflx] {
            let mut m = PathMonitor::default();
            let t0 = Instant::now();
            m.on_death(&a, tier, DeathReason::RekeyUnanswered, true, t0);
            let mut t = t0;
            for k in 0..6u32 {
                t += Duration::from_secs(20);
                m.on_probe_started(&a, tier, t - Duration::from_secs(12));
                m.on_probe_result(&a, tier, ProbeOutcome::Expired, true, t);
                let hl = lane_backoff(FAST_RETURN_HALF_LIFE, k, FAST_RETURN_BACKOFF_CAP);
                assert!(m.fast_return_active(t), "{tier:?}: open after {} failures", k + 1);
                assert!(!m.eligible(&a, tier, t + hl / 2), "{tier:?}: backing off ({k})");
                assert!(m.eligible(&a, tier, t + hl + Duration::from_millis(1)), "{tier:?} ({k})");
                if tier == DirectTier::Lan {
                    let want = lane_backoff(FAST_RETURN_LAN_SPACING, k + 1, FAST_RETURN_BACKOFF_CAP);
                    assert_eq!(lan_spacing(&m.peers[&a], false, t), want);
                }
            }
            assert!(m.fast_return_active(t0 + FAST_RETURN_WINDOW + Duration::from_secs(30)));
            assert_eq!(m.strikes(&a, tier), 0, "{tier:?}: no strike inside the lane");
            // The extension is capped: failures past FAST_RETURN_MAX no longer
            // hold the lane open, and the ordinary ladder takes over.
            while t < t0 + FAST_RETURN_MAX {
                t += Duration::from_secs(20);
                m.on_probe_started(&a, tier, t - Duration::from_secs(12));
                m.on_probe_result(&a, tier, ProbeOutcome::Expired, true, t);
            }
            assert!(!m.fast_return_active(t0 + FAST_RETURN_MAX + Duration::from_secs(1)));
        }
        // The kill switch: the lane lapses at FAST_RETURN_WINDOW, no backoff.
        let mut m = PathMonitor::default().with_fast_return_extend(false);
        let t0 = Instant::now();
        m.on_death(&a, DirectTier::Srflx, DeathReason::RekeyUnanswered, true, t0);
        let t1 = t0 + Duration::from_secs(20);
        m.on_probe_started(&a, DirectTier::Srflx, t0);
        m.on_probe_result(&a, DirectTier::Srflx, ProbeOutcome::Expired, true, t1);
        assert!(!m.fast_return_active(t0 + FAST_RETURN_WINDOW + Duration::from_secs(1)));
    }

    /// §6.3 F3 — a poke conviction opens the fast-return lane. Inside it a
    /// srflx/public failure (a probe expiry, or the fresh attempt's own
    /// handshake deadline) books a `FAST_RETURN_HALF_LIFE` penalty and NO
    /// strike, so the outage never climbs the 60 s → 15 min ladder; a latch
    /// closes the lane; once it lapses the ordinary ladder applies again.
    #[test]
    fn poke_conviction_opens_fast_return_lane() {
        let a = oid(1);
        let past_short = FAST_RETURN_HALF_LIFE + Duration::from_millis(1);
        for tier in [DirectTier::Srflx, DirectTier::Public] {
            let mut m = PathMonitor::default().with_fast_return_extend(false);
            let t0 = Instant::now();
            m.on_death(&a, tier, DeathReason::RekeyUnanswered, true, t0);
            assert!(m.fast_return_active(t0), "{tier:?} conviction arms the lane");

            let t1 = t0 + Duration::from_secs(12);
            m.on_probe_started(&a, tier, t0);
            m.on_probe_result(&a, tier, ProbeOutcome::Expired, true, t1);
            assert!(!m.eligible(&a, tier, t1 + Duration::from_secs(1)));
            assert!(
                m.eligible(&a, tier, t1 + past_short),
                "{tier:?} in-lane expiry must lapse after the short half-life"
            );
            let t2 = t1 + Duration::from_secs(16);
            m.on_death(&a, tier, DeathReason::HandshakeDeadline, true, t2);
            assert!(m.eligible(&a, tier, t2 + past_short));
            assert_eq!(m.strikes(&a, tier), 0, "{tier:?} in-lane failures book no strike");
            assert!(!m.is_sticky(&a, tier, true));

            let t3 = t0 + FAST_RETURN_WINDOW + Duration::from_secs(1);
            assert!(!m.fast_return_active(t3), "{tier:?} lane lapses");
            m.on_probe_started(&a, tier, t3);
            m.on_probe_result(&a, tier, ProbeOutcome::Expired, true, t3);
            assert_eq!(m.strikes(&a, tier), 1, "{tier:?} ordinary ladder after the lane");
            assert!(!m.eligible(&a, tier, t3 + Duration::from_secs(30)));
        }

        // A latched probe closes the lane: a later failure books normally.
        let mut m = PathMonitor::default().with_fast_return_extend(false);
        let t0 = Instant::now();
        m.on_death(&a, DirectTier::Srflx, DeathReason::RekeyUnanswered, true, t0);
        m.on_probe_started(&a, DirectTier::Srflx, t0);
        m.on_probe_result(
            &a,
            DirectTier::Srflx,
            ProbeOutcome::Latched { latency_ms: None },
            true,
            t0 + Duration::from_secs(3),
        );
        assert!(!m.fast_return_active(t0 + Duration::from_secs(3)));
        let t1 = t0 + Duration::from_secs(10);
        m.on_death(&a, DirectTier::Srflx, DeathReason::RxStale, true, t1);
        assert_eq!(m.strikes(&a, DirectTier::Srflx), 1);
        assert!(!m.eligible(&a, DirectTier::Srflx, t1 + past_short));

        // F3b — LAN joins the lane: an in-lane expiry lapses after the short
        // half-life with no strike, and the spacing pin drops to 5 s; once
        // the lane lapses, P8's 60 s pin is back.
        let mut m = PathMonitor::default().with_fast_return_extend(false);
        let t0 = Instant::now();
        m.on_death(&a, DirectTier::Lan, DeathReason::RekeyUnanswered, true, t0);
        let t1 = t0 + Duration::from_secs(12);
        m.on_probe_started(&a, DirectTier::Lan, t0);
        m.on_probe_result(&a, DirectTier::Lan, ProbeOutcome::Expired, true, t1);
        assert!(m.eligible(&a, DirectTier::Lan, t1 + past_short));
        assert_eq!(m.strikes(&a, DirectTier::Lan), 0);
        let p = &m.peers[&a];
        assert_eq!(lan_spacing(p, false, t1), FAST_RETURN_LAN_SPACING);
        assert_eq!(lan_spacing(p, true, t1), LAN_PROBE_SPACING, "the F3b kill switch");
        let lapsed = t0 + FAST_RETURN_WINDOW + Duration::from_secs(1);
        assert_eq!(lan_spacing(p, false, lapsed), LAN_PROBE_SPACING);

        // `OVERLAY_FAST_RETURN_LAN=0`: LAN keeps the P8 fixed spacing even
        // inside the lane (the pre-F3b behaviour).
        let mut m = PathMonitor::default().with_fast_return_extend(false).with_fast_return_lan(false);
        let t0 = Instant::now();
        m.on_death(&a, DirectTier::Lan, DeathReason::RekeyUnanswered, true, t0);
        let t1 = t0 + Duration::from_secs(12);
        m.on_probe_started(&a, DirectTier::Lan, t0);
        m.on_probe_result(&a, DirectTier::Lan, ProbeOutcome::Expired, true, t1);
        assert!(!m.eligible(&a, DirectTier::Lan, t1 + past_short));
        assert!(m.eligible(&a, DirectTier::Lan, t1 + H_ORDINARY + Duration::from_secs(1)));

        // A relay-carrier conviction does not arm it, nor does the kill switch.
        let mut m = PathMonitor::default().with_fast_return_extend(false);
        m.on_death(&a, DirectTier::Relay, DeathReason::RekeyUnanswered, true, t0);
        assert!(!m.fast_return_active(t0));
        let mut m = PathMonitor::with_fast_return(false);
        m.on_death(&a, DirectTier::Srflx, DeathReason::RekeyUnanswered, true, t0);
        assert!(!m.fast_return_active(t0));
        m.on_probe_started(&a, DirectTier::Srflx, t0);
        m.on_probe_result(&a, DirectTier::Srflx, ProbeOutcome::Expired, true, t0);
        assert_eq!(m.strikes(&a, DirectTier::Srflx), 1);
        assert!(!m.eligible(&a, DirectTier::Srflx, t0 + past_short));
    }

    /// A make-before-break probe that never latched cost the pair nothing:
    /// the relay carried every packet. So however long an outage outlasts
    /// the fast-return lane, its expiries keep the ordinary half-life and
    /// the tier is retried about once a minute (strikes still count, for
    /// candidate rotation). Field 2026-10-27 (rf-84f661a5a7e3): a 10 min
    /// direct block escalated srflx to 15 min on both ends, so the healed
    /// direct path was not retried for ~12 min. A carrier that DIED still
    /// climbs the ladder, as does any expiry without make-before-break.
    #[test]
    fn a_shadow_probe_expiry_never_escalates() {
        let a = oid(1);
        let after_ordinary = H_ORDINARY + Duration::from_secs(1);
        for tier in [DirectTier::Srflx, DirectTier::Public] {
            let mut m = PathMonitor::default();
            let mut t = Instant::now();
            for n in 1..=6 {
                m.on_probe_started(&a, tier, t);
                t += Duration::from_secs(15);
                m.on_probe_result(&a, tier, ProbeOutcome::Expired, true, t);
                assert_eq!(m.strikes(&a, tier), n, "{tier:?} strikes still count");
                assert!(!m.eligible(&a, tier, t + Duration::from_secs(30)));
                assert!(
                    m.eligible(&a, tier, t + after_ordinary),
                    "{tier:?} expiry #{n} must keep the ordinary half-life"
                );
                t += after_ordinary;
            }

            let mut m = PathMonitor::default();
            let mut t = Instant::now();
            for _ in 0..3 {
                m.on_death(&a, tier, DeathReason::HandshakeDeadline, true, t);
                t += after_ordinary;
            }
            assert!(
                !m.eligible(&a, tier, t + after_ordinary),
                "{tier:?} deaths still escalate"
            );

            let mut m = PathMonitor::default();
            let mut t = Instant::now();
            for _ in 0..3 {
                m.on_probe_started(&a, tier, t);
                m.on_probe_result(&a, tier, ProbeOutcome::Expired, false, t);
                t += after_ordinary;
            }
            assert!(
                !m.eligible(&a, tier, t + after_ordinary),
                "{tier:?} legacy ladder without MBB"
            );
        }
    }

    /// F — `explain` must never contradict the selector it describes. The
    /// failure mode this guards is a diagnostic that says "eligible: no,
    /// because penalty" while the real gate was the demote-follow window: an
    /// operator would then go tuning path quality for a problem that lives at
    /// the far end. So the reason is resolved in the same order `eligible`
    /// tests its gates, and this asserts they agree in both states.
    #[test]
    fn explain_agrees_with_eligible_and_names_the_gate_that_actually_refused() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();

        // Clean slate: everything eligible, nothing blamed.
        let e = m.explain(&a, t0);
        assert_eq!(e.tiers.len(), 4, "lan/public/srflx/relay, in ladder order");
        for t in &e.tiers {
            assert!(t.eligible, "{:?} should start eligible", t.tier);
            assert!(t.blocked_by.is_none());
            assert_eq!(t.eligible, m.eligible(&a, t.tier, t0));
        }
        assert!(e.relayed_instead_s.is_none());

        // The peer relays to us instead: EVERY direct tier is held down, and
        // the reason must be the peer, not the path.
        m.on_peer_relayed_instead(&a, DirectTier::Lan, true, t0);
        let t1 = t0 + Duration::from_secs(1);
        let e = m.explain(&a, t1);
        assert!(e.relayed_instead_s.is_some(), "window must be open");
        assert_eq!(e.relayed_instead_strikes, 1);
        for t in e.tiers.iter().filter(|t| t.tier.is_direct()) {
            assert!(!t.eligible);
            assert_eq!(
                t.blocked_by.map(|b| b.as_str()),
                Some("peer-relays-instead"),
                "{:?} was refused by the demote-follow window, not by its own penalty",
                t.tier
            );
        }
        // The relay floor is never held down — it is what we fall back TO.
        let relay = e
            .tiers
            .iter()
            .find(|t| t.tier == DirectTier::Relay)
            .unwrap();
        assert!(relay.eligible);
        assert!(relay.blocked_by.is_none());

        // Every row still agrees with the selector, which is the invariant.
        for t in &e.tiers {
            assert_eq!(t.eligible, m.eligible(&a, t.tier, t1));
            assert_eq!(t.score, m.score(&a, t.tier, t1));
        }
    }

    /// A tier suppressed by its OWN failures must be blamed on the penalty,
    /// not on the peer — the other half of the same confusion.
    #[test]
    fn explain_blames_the_penalty_when_no_peer_window_is_open() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        m.on_death(&a, DirectTier::Lan, DeathReason::RxStale, true, t0);
        let t1 = t0 + Duration::from_secs(1);
        let e = m.explain(&a, t1);
        let lan = e.tiers.iter().find(|t| t.tier == DirectTier::Lan).unwrap();
        assert!(!lan.eligible, "a fresh death suppresses the tier");
        assert_eq!(lan.blocked_by.map(|b| b.as_str()), Some("penalty"));
        assert!(
            lan.penalty > 0.0,
            "the penalty must be reported, not just named"
        );
        assert!(e.relayed_instead_s.is_none(), "no peer window is open here");
    }

    /// #2089 — a tier with nothing to dial is UNAVAILABLE, and `explain` says
    /// so. Before, it read only "eligible" (an untried tier has no penalty)
    /// with the best score, while `decide` never considered it: a NATed
    /// CORPLAP-3 showed `public yes 330` on a pair sitting on relay.
    #[test]
    fn explain_reports_a_tier_with_no_candidate_as_unavailable() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        assert!(
            m.explain(&a, t0)
                .tiers
                .iter()
                .all(|t| t.available.is_none()),
            "before any decision the monitor does not know, and says so"
        );

        let behind_nat = TierAvailability {
            lan: false,
            public: false,
            srflx: true,
        };
        let action = m.decide(&a, Incumbent::Relay, behind_nat, true, t0, false);
        let e = m.explain(&a, t0);
        let get = |tier| *e.tiers.iter().find(|t| t.tier == tier).unwrap();
        let public = get(DirectTier::Public);
        assert!(
            public.eligible,
            "untried, so unpenalised: the misleading half"
        );
        assert_eq!(public.available, Some(false), "and nothing to dial");
        assert_eq!(get(DirectTier::Lan).available, Some(false));
        assert_eq!(get(DirectTier::Srflx).available, Some(true));
        assert_eq!(get(DirectTier::Relay).available, Some(true));
        // The selector agrees with the new column: it never proposes public.
        assert_ne!(action, PathAction::Probe(DirectTier::Public));
        assert_ne!(action, PathAction::Install(DirectTier::Public));
    }

    /// FR-33 P2 — a LAN capture on THIS host refuses the LAN tier outright,
    /// `explain` names it (never "penalty" — an operator would go tuning
    /// path quality for a problem that lives in a VPN profile), the other
    /// tiers are untouched, nothing is booked against the path, no selector
    /// proposes the tier, and it is back the instant the capture clears.
    #[test]
    fn lan_capture_refuses_only_the_lan_tier_and_explain_names_it() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();

        m.on_lan_capture(&a, true);
        assert!(!m.eligible(&a, DirectTier::Lan, t0));
        for tier in [DirectTier::Public, DirectTier::Srflx, DirectTier::Relay] {
            assert!(m.eligible(&a, tier, t0), "{tier:?} is not a LAN matter");
        }
        let e = m.explain(&a, t0);
        let lan = e.tiers.iter().find(|t| t.tier == DirectTier::Lan).unwrap();
        assert!(!lan.eligible);
        assert_eq!(lan.blocked_by.map(|b| b.as_str()), Some("lan-captured"));
        assert_eq!(lan.penalty, 0.0, "a capture is a fact, not a strike");
        assert_eq!(lan.fails, 0);
        for t in e.tiers.iter().filter(|t| t.tier != DirectTier::Lan) {
            assert!(t.eligible, "{:?} untouched", t.tier);
            assert!(t.blocked_by.is_none());
        }
        for t in &e.tiers {
            assert_eq!(
                t.eligible,
                m.eligible(&a, t.tier, t0),
                "explain agrees with the selector"
            );
        }

        // No selector proposes the captured tier: a relay incumbent with
        // every candidate present climbs to PUBLIC, not LAN ...
        assert_eq!(
            m.decide(&a, Incumbent::Relay, all_avail(), true, t0, false),
            PathAction::Probe(DirectTier::Public)
        );
        // ... and the mid-tier upward prober skips it the same way.
        let mut up = PathMonitor::default();
        up.on_lan_capture(&a, true);
        assert_eq!(
            up.upward_candidate(&a, DirectTier::Srflx, all_avail(), t0),
            Some(DirectTier::Public)
        );

        // Cleared: eligible again with nothing to decay, and the ladder
        // resumes at the top.
        m.on_lan_capture(&a, false);
        assert!(m.eligible(&a, DirectTier::Lan, t0));
        let e = m.explain(&a, t0);
        let lan = e.tiers.iter().find(|t| t.tier == DirectTier::Lan).unwrap();
        assert!(lan.eligible && lan.blocked_by.is_none());
        assert_eq!(
            m.decide(&a, Incumbent::Relay, all_avail(), true, t0, false),
            PathAction::Probe(DirectTier::Lan)
        );

        // Clearing a peer the monitor never met materialises no state.
        let b = oid(2);
        m.on_lan_capture(&b, false);
        assert!(!m.peers.contains_key(&b));
    }

    /// FR-33 P2 — the host fact and the peer fact compose in the order
    /// `eligible` tests them: an open demote-follow window is named ahead of
    /// a capture, exactly as it refuses ahead of it.
    #[test]
    fn lan_capture_yields_to_the_peer_window_in_explain() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        m.on_lan_capture(&a, true);
        m.on_peer_relayed_instead(&a, DirectTier::Lan, true, t0);
        let t1 = t0 + Duration::from_secs(1);
        let e = m.explain(&a, t1);
        let lan = e.tiers.iter().find(|t| t.tier == DirectTier::Lan).unwrap();
        assert!(!lan.eligible);
        assert_eq!(
            lan.blocked_by.map(|b| b.as_str()),
            Some("peer-relays-instead")
        );
        assert_eq!(lan.eligible, m.eligible(&a, DirectTier::Lan, t1));
    }
    /// #29 — a peer relaying to us instead of using the direct tier we hold it
    /// on suppresses that tier (a decaying penalty, so it comes back), but
    /// books NO Q slam: nothing died and the tier did not misbehave — it is
    /// simply not where the peer is. That distinction is the whole reason this
    /// is not `on_death`, and a Q slam here would poison the ranking of a path
    /// that may be perfectly good.
    #[test]
    fn relayed_instead_suppresses_the_tier_without_slamming_its_quality() {
        for tier in DIRECT_TIERS {
            let mut m = PathMonitor::default();
            let a = oid(1);
            let t0 = Instant::now();
            m.on_peer_relayed_instead(&a, tier, true, t0);

            let idx = tier_idx(tier).unwrap();
            let p = m.peers.get(&a).expect("the peer is tracked");
            assert!(
                p.tiers[idx].penalty.is_some(),
                "{tier:?} must be suppressed, or make-before-break re-promotes \
                 it on its next probe and the pair flaps"
            );
            assert_eq!(m.strikes(&a, tier), 1, "{tier:?} books the strike");
            assert_eq!(
                p.tiers[idx].q.get(),
                0.0,
                "{tier:?} quality is UNTOUCHED — the path may be fine; the peer \
                 is just not on it"
            );
            // #30 — the property #29's test MISSED, and the field then found
            // in 20 minutes: a booked strike is not the same as an ineligible
            // tier. `suppression_half_life` pins LAN-under-MBB to H_ORDINARY
            // (60 s) by the P8 never-strand rule, and MBB re-probes every
            // ~70-80 s — so the penalty alone is eligible again by the next
            // probe and the promote↔follow flap just continues. Assert the
            // thing that actually stops it.
            assert!(
                !m.eligible(&a, tier, t0 + Duration::from_secs(90)),
                "{tier:?} must still be INELIGIBLE past one MBB probe cycle — a \
                 strike alone does not stop make-before-break re-promoting"
            );
            // Bounded, not sticky: once the peer stops relaying the window
            // lapses and the next probe promotes normally.
            assert!(
                m.eligible(
                    &a,
                    tier,
                    t0 + RELAYED_INSTEAD_HOLDOFF + Duration::from_secs(1)
                ),
                "{tier:?} must recover — nothing may be stranded on the relay"
            );

            // #31 — a PERSISTENT disagreement must ESCALATE, or the flap simply
            // moves to the holdoff boundary: the field showed a pair retrying
            // at exactly 3 min (12:22:30 / 12:25:45 / 12:29:00) on rc.465.
            //
            // Asserted on the WINDOW rather than through `eligible`, because
            // eligibility also carries the penalty plane — and after a few
            // strikes Public/Srflx are legitimately suppressed by THAT (their
            // `suppression_half_life` escalates past `MAX_FAILURES`), which
            // would mask whether the ladder itself did anything. Isolate the
            // mechanism under test.
            let window = |m: &PathMonitor, p: &ObjectId, at: Instant| {
                m.peers[p].relayed_instead_until.unwrap() - at
            };
            let t1 = t0 + RELAYED_INSTEAD_HOLDOFF + Duration::from_secs(1);
            m.on_peer_relayed_instead(&a, tier, true, t1);
            assert!(
                window(&m, &a, t1) > RELAYED_INSTEAD_HOLDOFF,
                "{tier:?} a second follow must hold LONGER than the base window"
            );
            // …and it must CAP: a pair may never be stranded on the relay.
            let mut t = t1;
            for _ in 0..12 {
                t += Duration::from_secs(60);
                m.on_peer_relayed_instead(&a, tier, true, t);
            }
            assert_eq!(
                window(&m, &a, t),
                H_ESCALATED,
                "{tier:?} the ladder must cap at H_ESCALATED"
            );
            // A gap longer than the memory resets to the base rung, so a
            // one-off transition never inherits an escalated window.
            let fresh = t + RELAYED_INSTEAD_MEMORY + Duration::from_secs(1);
            m.on_peer_relayed_instead(&a, tier, true, fresh);
            assert_eq!(
                window(&m, &a, fresh),
                RELAYED_INSTEAD_HOLDOFF,
                "{tier:?} the ladder must RESET after a quiet period — a one-off \
                 transition must not inherit an escalated window"
            );
        }
        // The relay tier is not a direct tier: nothing to suppress, and no
        // panic from the tier-index lookup.
        let mut m = PathMonitor::default();
        let b = oid(2);
        m.on_peer_relayed_instead(&b, DirectTier::Relay, true, Instant::now());
        assert_eq!(m.strikes(&b, DirectTier::Relay), 0);
    }

    /// R2 — `on_local_rebuild` clears every peer's DIRECT-tier evidence
    /// (penalties, strikes, Q) but KEEPS `relay_q` (relay carriers survive a
    /// plane rebuild) and KEEPS `last_lan_attempt` (LAN_PROBE_SPACING must
    /// still pace the post-rebuild herd) — the two properties that
    /// disqualify `on_resume` here.
    #[test]
    fn local_rebuild_clears_direct_evidence_keeps_relay_and_lan_pacing() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        // Book direct evidence + relay evidence + a LAN attempt marker.
        m.on_death(
            &a,
            DirectTier::Lan,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        m.on_heard(&a, DirectTier::Relay);
        m.on_installed(&a, DirectTier::Lan, t0);
        let relay_q_before = m.peers.get(&a).unwrap().relay_q.get();
        assert!(relay_q_before > 0.0, "precondition: relay q credited");
        assert!(!m.eligible(&a, DirectTier::Lan, t0 + Duration::from_secs(1)));

        m.on_local_rebuild();

        let p = m.peers.get(&a).unwrap();
        assert!(
            m.eligible(&a, DirectTier::Lan, t0 + Duration::from_secs(1)),
            "direct suppression cleared"
        );
        assert_eq!(m.strikes(&a, DirectTier::Lan), 0, "direct strikes cleared");
        assert_eq!(
            p.relay_q.get(),
            relay_q_before,
            "relay evidence survives the rebuild"
        );
        assert!(
            p.last_lan_attempt.is_some(),
            "LAN probe pacing survives the rebuild"
        );
    }

    /// The escalated window (2 strikes LAN/public, 3 srflx) reproduces the
    /// legacy 15 min deny: suppressed at 14:59, eligible at 15:01 — and the
    /// LAN tier under make-before-break NEVER escalates (P8).
    #[test]
    fn eligibility_parity_escalated_window_899_901() {
        // Public: second failure escalates.
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        m.on_death(
            &a,
            DirectTier::Public,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        let t1 = t0 + Duration::from_secs(120);
        m.on_death(
            &a,
            DirectTier::Public,
            DeathReason::HandshakeDeadline,
            true,
            t1,
        );
        assert!(!m.eligible(&a, DirectTier::Public, t1 + Duration::from_secs(899)));
        assert!(m.eligible(&a, DirectTier::Public, t1 + Duration::from_secs(901)));

        // Srflx: third failure escalates (the second does not).
        let mut m = PathMonitor::default();
        m.on_death(
            &a,
            DirectTier::Srflx,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        m.on_death(
            &a,
            DirectTier::Srflx,
            DeathReason::HandshakeDeadline,
            true,
            t1,
        );
        assert!(
            m.eligible(&a, DirectTier::Srflx, t1 + Duration::from_secs(61)),
            "srflx strike 2 stays on the ordinary window"
        );
        let t2 = t1 + Duration::from_secs(120);
        m.on_death(
            &a,
            DirectTier::Srflx,
            DeathReason::HandshakeDeadline,
            true,
            t2,
        );
        assert!(!m.eligible(&a, DirectTier::Srflx, t2 + Duration::from_secs(899)));
        assert!(m.eligible(&a, DirectTier::Srflx, t2 + Duration::from_secs(901)));

        // LAN under MBB: strike 5 still gets the ordinary 60 s window.
        let mut m = PathMonitor::default();
        let mut t = t0;
        for _ in 0..5 {
            m.on_death(&a, DirectTier::Lan, DeathReason::HandshakeDeadline, true, t);
            t += Duration::from_secs(120);
        }
        let last = t - Duration::from_secs(120);
        assert!(m.eligible(&a, DirectTier::Lan, last + Duration::from_secs(61)));
        // LAN with MBB env-OFF: second failure escalates like public.
        let mut m = PathMonitor::default();
        m.on_death(
            &a,
            DirectTier::Lan,
            DeathReason::HandshakeDeadline,
            false,
            t0,
        );
        m.on_death(
            &a,
            DirectTier::Lan,
            DeathReason::HandshakeDeadline,
            false,
            t1,
        );
        assert!(!m.eligible(&a, DirectTier::Lan, t1 + Duration::from_secs(899)));
        assert!(m.eligible(&a, DirectTier::Lan, t1 + Duration::from_secs(901)));
    }

    /// F1's core invariant: NO Q state — however adversarial — can move an
    /// eligibility boundary in either direction. Two monitors book the same
    /// failure; one is then Q-hammered (max positive on the failed tier, max
    /// negative on the others); the eligibility timings must be identical.
    #[test]
    fn no_q_state_can_delay_or_advance_eligibility() {
        let a = oid(1);
        let t0 = Instant::now();
        let mut quiet = PathMonitor::default();
        let mut noisy = PathMonitor::default();
        for m in [&mut quiet, &mut noisy] {
            m.on_death(
                &a,
                DirectTier::Public,
                DeathReason::HandshakeDeadline,
                true,
                t0,
            );
        }
        // Pump the failed tier's Q to the ceiling (+heard, +inbound on a LAN
        // init so no srflx D9-clear touches penalties) and the others to the
        // floor.
        pump_heard(&mut noisy, &a, DirectTier::Public, 500);
        for _ in 0..500 {
            noisy.on_bad_sweep(&a, DirectTier::Lan);
            noisy.on_bad_sweep(&a, DirectTier::Srflx);
            // B1 — RTT extremes are Q-plane too: a perfect RTT on the
            // failed tier and a terrible one on the healthy tiers must
            // not move any eligibility boundary either.
            noisy.on_rtt_sample(&a, DirectTier::Public, 0);
            noisy.on_rtt_sample(&a, DirectTier::Lan, 5_000);
            noisy.on_rtt_sample(&a, DirectTier::Srflx, 5_000);
        }
        for probe_t in [59u64, 61, 899, 901] {
            let t = t0 + Duration::from_secs(probe_t);
            assert_eq!(
                quiet.eligible(&a, DirectTier::Public, t),
                noisy.eligible(&a, DirectTier::Public, t),
                "Q must not move the Public boundary at {probe_t} s"
            );
        }
        // And negative Q on never-failed tiers cannot make them ineligible.
        assert!(noisy.eligible(&a, DirectTier::Lan, t0 + Duration::from_secs(1)));
        assert!(noisy.eligible(&a, DirectTier::Srflx, t0 + Duration::from_secs(1)));
    }

    /// Cold start reproduces the legacy precedence walk exactly.
    #[test]
    fn cold_start_ordering_matches_legacy_precedence() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let now = Instant::now();
        // P9 — LAN-best on a FRESH peer probes first under MBB (the same-/24
        // candidate is unproven); the destructive walk survives with MBB off.
        assert_eq!(
            m.decide(&a, Incumbent::None, all_avail(), true, now, false),
            PathAction::Probe(DirectTier::Lan)
        );
        assert_eq!(
            m.decide(&a, Incumbent::None, all_avail(), false, now, false),
            PathAction::Install(DirectTier::Lan)
        );
        let no_lan = TierAvailability {
            lan: false,
            ..all_avail()
        };
        assert_eq!(
            m.decide(&a, Incumbent::None, no_lan, true, now, false),
            PathAction::Install(DirectTier::Public)
        );
        let srflx_only = TierAvailability {
            lan: false,
            public: false,
            srflx: true,
        };
        assert_eq!(
            m.decide(&a, Incumbent::None, srflx_only, true, now, false),
            PathAction::Install(DirectTier::Srflx)
        );
        assert_eq!(
            m.decide(
                &a,
                Incumbent::None,
                TierAvailability::default(),
                true,
                now,
                false
            ),
            PathAction::Relay
        );
        // Relay incumbent: MBB probes, destructive mode installs, nothing
        // available keeps.
        assert_eq!(
            m.decide(&a, Incumbent::Relay, all_avail(), true, now, false),
            PathAction::Probe(DirectTier::Lan)
        );
        assert_eq!(
            m.decide(&a, Incumbent::Relay, all_avail(), false, now, false),
            PathAction::Install(DirectTier::Lan)
        );
        assert_eq!(
            m.decide(
                &a,
                Incumbent::Relay,
                TierAvailability::default(),
                true,
                now,
                false
            ),
            PathAction::Keep
        );
        // Already direct: always Keep (cross-direct upgrades are post-flip).
        assert_eq!(
            m.decide(
                &a,
                Incumbent::Direct(DirectTier::Srflx),
                all_avail(),
                true,
                now,
                false
            ),
            PathAction::Keep
        );
    }

    /// Q ranks among ELIGIBLE tiers: after LAN's penalty lapses its slammed Q
    /// keeps it ranked below a heard-up srflx — but never OFF the ballot.
    #[test]
    fn ranking_prefers_higher_q_among_eligible() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        m.on_death(
            &a,
            DirectTier::Lan,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        pump_heard(&mut m, &a, DirectTier::Srflx, 14); // Q ≈ +51
        let t = t0 + Duration::from_secs(120); // LAN penalty ≈ 100, eligible again
        assert!(m.eligible(&a, DirectTier::Lan, t));
        let s_lan = m.score(&a, DirectTier::Lan, t);
        let s_srflx = m.score(&a, DirectTier::Srflx, t);
        assert!(
            s_srflx > s_lan,
            "srflx ({s_srflx:.1}) must outrank slammed+penalized LAN ({s_lan:.1})"
        );
        let avail = TierAvailability {
            lan: true,
            public: false,
            srflx: true,
        };
        assert_eq!(
            m.decide(&a, Incumbent::Relay, avail, true, t, false),
            PathAction::Probe(DirectTier::Srflx)
        );
    }

    /// One probe per peer + the global cap serialize Probe proposals.
    #[test]
    fn probe_serialization_one_per_peer_and_global_cap() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let now = Instant::now();
        m.on_probe_started(&a, DirectTier::Srflx, now);
        assert_eq!(
            m.decide(&a, Incumbent::Relay, all_avail(), true, now, false),
            PathAction::Keep,
            "an in-flight probe blocks new proposals for the peer"
        );
        m.on_probe_result(
            &a,
            DirectTier::Srflx,
            ProbeOutcome::Latched {
                latency_ms: Some(40.0),
            },
            true,
            now,
        );
        assert_eq!(m.probes_in_flight, 0, "latch frees the slot");

        // Fill the global cap with other peers.
        for n in 0..PROBE_CAP {
            m.on_probe_started(&oid(100 + n as u8), DirectTier::Lan, now);
        }
        let fresh = oid(2);
        assert_eq!(
            m.decide(&fresh, Incumbent::Relay, all_avail(), true, now, false),
            PathAction::Keep,
            "global cap blocks new Probe proposals"
        );
        // P9 — a fresh-LAN peer under MBB is probe-first, so the cap applies
        // to it too: cap-full falls back to Relay (carrier first), never to a
        // destructive unproven-LAN install.
        assert_eq!(
            m.decide(&fresh, Incumbent::None, all_avail(), true, now, false),
            PathAction::Relay
        );
        m.on_peer_removed(&oid(100));
        assert_eq!(
            m.decide(&fresh, Incumbent::Relay, all_avail(), true, now, false),
            PathAction::Probe(DirectTier::Lan),
            "freeing one slot unblocks"
        );
    }

    /// P9 — a fresh peer whose best tier is LAN probes first under MBB (the
    /// same-/24 candidate is unproven — vendor-default subnets false-match
    /// across sites); destructive mode (MBB env-off) and non-LAN best tiers
    /// keep the legacy fresh `Install`.
    #[test]
    fn fresh_lan_probes_first_under_mbb() {
        let mut m = PathMonitor::default();
        let a = oid(7);
        let now = Instant::now();
        assert_eq!(
            m.decide(&a, Incumbent::None, all_avail(), true, now, false),
            PathAction::Probe(DirectTier::Lan),
            "fresh + LAN best + MBB → shadow probe, not a destructive install"
        );
        assert_eq!(
            m.decide(&a, Incumbent::None, all_avail(), false, now, false),
            PathAction::Install(DirectTier::Lan),
            "MBB env-off keeps the destructive fresh install"
        );
        let no_lan = TierAvailability {
            lan: false,
            public: true,
            srflx: true,
        };
        assert_eq!(
            m.decide(&a, Incumbent::None, no_lan, true, now, false),
            PathAction::Install(DirectTier::Public),
            "non-LAN best tiers keep the fresh Install"
        );
    }

    /// What ACTUALLY paces a LAN retry after a FAILED make-before-break probe.
    ///
    /// `LAN_PROBE_SPACING` (60 s from the attempt) reads like the governing
    /// constant, and the module doc points at it — but a failed probe also
    /// books a penalty, and eligibility only returns after one `H_ORDINARY`
    /// (60 s) half-life measured from the FAILURE. Since the failure lands one
    /// handshake deadline after the attempt, the half-life always finishes
    /// LATER than the spacing pin: the pin never binds, and the effective
    /// cadence is `deadline + H_ORDINARY`, not 60 s.
    ///
    /// Field 2026-08-13: winhost-a's LAN probes retried every ~90 s, not 60 s,
    /// and reconciling that by hand from timestamps took longer than the
    /// incident it was buried in. This pins the real relationship so a future
    /// reader does not re-derive it — and so any cadence tuning has to state
    /// which of the two constants it is actually moving.
    #[test]
    fn failed_lan_probe_is_paced_by_the_penalty_half_life_not_the_spacing_pin() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        let deadline = crate::overlay::lifecycle::LAN_HANDSHAKE_DEADLINE;

        m.on_probe_started(&a, DirectTier::Lan, t0);
        // The probe misses its handshake deadline — a real failure, which
        // books a penalty (unlike `on_probe_aborted`, which books none).
        m.on_probe_result(
            &a,
            DirectTier::Lan,
            ProbeOutcome::Expired,
            true,
            t0 + deadline,
        );

        // The spacing pin alone would allow a retry here…
        let at_spacing = t0 + LAN_PROBE_SPACING + Duration::from_secs(1);
        assert!(
            !m.eligible(&a, DirectTier::Lan, at_spacing),
            "spacing pin is NOT the binding constraint — the penalty still suppresses LAN"
        );

        // …but eligibility only returns one half-life after the FAILURE.
        let after_half_life = t0 + deadline + H_ORDINARY + Duration::from_secs(1);
        assert!(
            m.eligible(&a, DirectTier::Lan, after_half_life),
            "one H_ORDINARY past the failure, LAN must be eligible again"
        );

        // The effective gap therefore exceeds the documented spacing by about
        // one handshake deadline — this is the ~90 s seen in the field.
        assert!(
            after_half_life.saturating_duration_since(t0) > LAN_PROBE_SPACING,
            "effective cadence must be understood as deadline + H_ORDINARY"
        );
    }

    /// F2 — the LAN spacing pin holds under adversarial Q and with no
    /// penalty on the books (probe aborted without failure). Contrast with
    /// `failed_lan_probe_is_paced_by_the_penalty_half_life_not_the_spacing_pin`
    /// above: with a penalty booked, the pin is no longer what binds.
    #[test]
    fn lan_spacing_pinned_under_q_extremes() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        m.on_probe_started(&a, DirectTier::Lan, t0);
        m.on_probe_aborted(&a); // freed WITHOUT a failure — no penalty booked
        assert!(m.eligible(&a, DirectTier::Lan, t0 + Duration::from_secs(1)));
        // Q-hammer LAN to the ceiling (heard + B1 perfect-RTT samples).
        pump_heard(&mut m, &a, DirectTier::Lan, 500);
        for _ in 0..500 {
            m.on_rtt_sample(&a, DirectTier::Lan, 0);
        }
        let lan_only = TierAvailability {
            lan: true,
            public: false,
            srflx: true,
        };
        // 30 s after the attempt: LAN is eligible + top-Q, yet the pin
        // filters it — the next eligible tier is proposed instead.
        assert_eq!(
            m.decide(
                &a,
                Incumbent::Relay,
                lan_only,
                true,
                t0 + Duration::from_secs(30),
                false
            ),
            PathAction::Probe(DirectTier::Srflx),
            "LAN must be spaced out at 30 s regardless of Q"
        );
        // 61 s after: the pin releases.
        assert_eq!(
            m.decide(
                &a,
                Incumbent::Relay,
                lan_only,
                true,
                t0 + Duration::from_secs(61),
                false
            ),
            PathAction::Probe(DirectTier::Lan)
        );
    }

    /// B1 — the RTT sample curve: fast RTTs drift Q up, slow ones drift it
    /// down, extremes clamp, and the relay tier feeds `relay_q`.
    #[test]
    fn rtt_sample_curve_feeds_incumbent_q_only() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let now = Instant::now();

        // 10 ms samples drift the tier's Q toward +99 (100 − 10/10).
        for _ in 0..200 {
            m.on_rtt_sample(&a, DirectTier::Public, 10);
        }
        let fast = m.score(&a, DirectTier::Public, now) - B_PUBLIC;
        assert!(
            (98.0..=100.0).contains(&fast),
            "fast RTT Q ≈ +99, got {fast}"
        );

        // 2 s samples drift toward the −100 clamp.
        for _ in 0..400 {
            m.on_rtt_sample(&a, DirectTier::Public, 2_000);
        }
        let slow = m.score(&a, DirectTier::Public, now) - B_PUBLIC;
        assert!(slow <= -95.0, "slow RTT Q near clamp, got {slow}");

        // Only the sampled tier moved; a relay sample lands on relay_q.
        assert_eq!(m.score(&a, DirectTier::Lan, now), B_LAN);
        for _ in 0..200 {
            m.on_rtt_sample(&a, DirectTier::Relay, 10);
        }
        assert!(m.score(&a, DirectTier::Relay, now) > B_RELAY + 90.0);

        // One gentle sample moves Q by exactly alpha × delta.
        let mut fresh = PathMonitor::default();
        fresh.on_rtt_sample(&a, DirectTier::Srflx, 500);
        let one = fresh.score(&a, DirectTier::Srflx, now) - B_SRFLX;
        assert!((one - 5.0).abs() < 1e-9, "α·(100−500/10−0) = 5, got {one}");
    }

    /// B2 — drive a tier's Q toward a target via repeated RTT samples
    /// (`q → 100 − rtt/10` as the EWMA converges).
    fn pump_rtt(m: &mut PathMonitor, peer: &ObjectId, tier: DirectTier, rtt_ms: u32, n: usize) {
        for _ in 0..n {
            m.on_rtt_sample(peer, tier, rtt_ms);
        }
    }

    /// B2 — the demotion window: degraded-incumbent gate, margin gate,
    /// the 15 s hold (14/16 s boundaries), and the mode plumbing
    /// (`demote_on = false` keeps forever).
    #[test]
    fn demotion_fires_on_sustained_margin_against_degraded_incumbent_only() {
        let a = oid(1);
        let t0 = Instant::now();
        let inc = Incumbent::Direct(DirectTier::Public);
        let avail = TierAvailability {
            lan: false,
            public: true,
            srflx: true,
        };

        // Healthy incumbent (Q = 0 cold start): base gap Srflx−Public is
        // negative anyway, but even a ceiling-Q alternative must NOT
        // demote a non-negative incumbent.
        let mut m = PathMonitor::default();
        pump_rtt(&mut m, &a, DirectTier::Srflx, 0, 400); // srflx Q → +99
        assert_eq!(m.decide(&a, inc, avail, true, t0, true), PathAction::Keep);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + DEMOTE_HOLD * 4, true),
            PathAction::Keep,
            "a healthy incumbent never demotes"
        );

        // Degraded incumbent, deficit BELOW the margin: no demotion.
        // Public q→−60 (score 270) vs srflx q→+31 (score 291): gap 21.
        let mut m = PathMonitor::default();
        pump_rtt(&mut m, &a, DirectTier::Public, 1_600, 400);
        pump_rtt(&mut m, &a, DirectTier::Srflx, 690, 400);
        assert_eq!(m.decide(&a, inc, avail, true, t0, true), PathAction::Keep);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + DEMOTE_HOLD * 4, true),
            PathAction::Keep,
            "sub-margin deficit never demotes"
        );

        // Degraded incumbent, deficit ABOVE the margin (gap ≈ 89): the
        // hold arms on first sight, refuses at 14 s, fires at 16 s.
        let mut m = PathMonitor::default();
        pump_rtt(&mut m, &a, DirectTier::Public, 1_600, 400);
        pump_rtt(&mut m, &a, DirectTier::Srflx, 0, 400);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0, false),
            PathAction::Keep,
            "demote_on=false (off/shadow) keeps forever"
        );
        assert_eq!(m.decide(&a, inc, avail, true, t0, true), PathAction::Keep);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + Duration::from_secs(14), true),
            PathAction::Keep,
            "inside the 15 s hold"
        );
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + Duration::from_secs(16), true),
            PathAction::Probe(DirectTier::Srflx),
            "sustained deficit past the hold → voluntary MBB probe"
        );

        // A deficit that BREAKS mid-hold disarms: the next sight re-arms
        // from scratch.
        let mut m = PathMonitor::default();
        pump_rtt(&mut m, &a, DirectTier::Public, 1_600, 400);
        pump_rtt(&mut m, &a, DirectTier::Srflx, 0, 400);
        assert_eq!(m.decide(&a, inc, avail, true, t0, true), PathAction::Keep);
        // Alternative collapses (bad RTTs) → deficit gone → cleared.
        pump_rtt(&mut m, &a, DirectTier::Srflx, 2_000, 400);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + Duration::from_secs(16), true),
            PathAction::Keep
        );
        // Alternative recovers; the hold restarts at the NEW first sight.
        pump_rtt(&mut m, &a, DirectTier::Srflx, 0, 800);
        let t1 = t0 + Duration::from_secs(20);
        assert_eq!(m.decide(&a, inc, avail, true, t1, true), PathAction::Keep);
        assert_eq!(
            m.decide(&a, inc, avail, true, t1 + Duration::from_secs(14), true),
            PathAction::Keep,
            "hold re-armed, not carried over"
        );
        assert_eq!(
            m.decide(&a, inc, avail, true, t1 + Duration::from_secs(16), true),
            PathAction::Probe(DirectTier::Srflx)
        );
    }

    /// B2 — the flap guards: voluntary switches respect the 30 s
    /// hysteresis; a forced-DERP pin vetoes; the probe cap holds; and
    /// the no-alternative + slammed-Q case yields the ADVISORY Relay.
    #[test]
    fn demotion_respects_hysteresis_pin_cap_and_relay_advisory() {
        let a = oid(1);
        let t0 = Instant::now();
        let inc = Incumbent::Direct(DirectTier::Public);
        let avail = TierAvailability {
            lan: false,
            public: true,
            srflx: true,
        };

        // Hysteresis: an install at t0 blocks the voluntary fire until
        // t0+30 even though the hold (15 s) is long satisfied.
        let mut m = PathMonitor::default();
        pump_rtt(&mut m, &a, DirectTier::Public, 1_600, 400);
        pump_rtt(&mut m, &a, DirectTier::Srflx, 0, 400);
        m.on_installed(&a, DirectTier::Public, t0);
        assert_eq!(m.decide(&a, inc, avail, true, t0, true), PathAction::Keep);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + Duration::from_secs(29), true),
            PathAction::Keep,
            "hysteresis holds voluntary switches for 30 s"
        );
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + Duration::from_secs(31), true),
            PathAction::Probe(DirectTier::Srflx)
        );

        // Forced-DERP pin vetoes demotion outright.
        let mut m = PathMonitor::default();
        pump_rtt(&mut m, &a, DirectTier::Public, 1_600, 400);
        pump_rtt(&mut m, &a, DirectTier::Srflx, 0, 400);
        m.on_forced_derp(&a, Duration::from_secs(300), t0);
        assert_eq!(m.decide(&a, inc, avail, true, t0, true), PathAction::Keep);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + Duration::from_secs(60), true),
            PathAction::Keep,
            "no voluntary demotion under a forced-DERP pin"
        );

        // Probe cap: cap-full suppresses the fire (Keep, not a blind
        // Install).
        let mut m = PathMonitor::default();
        pump_rtt(&mut m, &a, DirectTier::Public, 1_600, 400);
        pump_rtt(&mut m, &a, DirectTier::Srflx, 0, 400);
        for i in 0..(PROBE_CAP as u8) {
            m.on_probe_started(&oid(100 + i), DirectTier::Srflx, t0);
        }
        assert_eq!(m.decide(&a, inc, avail, true, t0, true), PathAction::Keep);
        assert_eq!(
            m.decide(&a, inc, avail, true, t0 + Duration::from_secs(16), true),
            PathAction::Keep,
            "probe cap suppresses voluntary demotion"
        );

        // No eligible alternative + slammed incumbent Q → the ADVISORY
        // Relay verdict (counted/logged; execution stays with the death
        // path).
        let mut m = PathMonitor::default();
        let only_public = TierAvailability {
            lan: false,
            public: true,
            srflx: false,
        };
        pump_rtt(&mut m, &a, DirectTier::Public, 60_000, 600); // q → −100 clamp
        assert_eq!(
            m.decide(&a, inc, only_public, true, t0, true),
            PathAction::Keep
        );
        assert_eq!(
            m.decide(
                &a,
                inc,
                only_public,
                true,
                t0 + Duration::from_secs(16),
                true
            ),
            PathAction::Relay,
            "slammed incumbent with no alternative → advisory relay demote"
        );
    }

    /// B3 — upward probing: precedence-ordered target pick, the 120 s
    /// spacing (booked at candidate time), the LAN-spacing composition,
    /// eligibility fall-through, and the structural gates.
    #[test]
    fn upward_probe_spacing_targets_and_gates() {
        let a = oid(1);
        let t0 = Instant::now();

        // Srflx incumbent, all higher tiers clean: LAN preferred; the
        // spacing books at candidate time (119 s → held, 121 s → fires).
        let mut m = PathMonitor::default();
        assert_eq!(
            m.upward_candidate(&a, DirectTier::Srflx, all_avail(), t0),
            Some(DirectTier::Lan)
        );
        assert_eq!(
            m.upward_candidate(
                &a,
                DirectTier::Srflx,
                all_avail(),
                t0 + Duration::from_secs(119)
            ),
            None
        );
        assert_eq!(
            m.upward_candidate(
                &a,
                DirectTier::Srflx,
                all_avail(),
                t0 + Duration::from_secs(121)
            ),
            Some(DirectTier::Lan)
        );

        // F2 composition: a fresh LAN attempt pins the LAN target out —
        // Public is picked instead (both spacings apply).
        let mut m = PathMonitor::default();
        m.on_installed(&a, DirectTier::Lan, t0);
        assert_eq!(
            m.upward_candidate(
                &a,
                DirectTier::Srflx,
                all_avail(),
                t0 + Duration::from_secs(1)
            ),
            Some(DirectTier::Public)
        );

        // Eligibility fall-through: a penalized LAN is skipped, not a
        // dead end — Public fires. (F1: the failed-probe penalty is the
        // only pacing a failed upward target needs.)
        let mut m = PathMonitor::default();
        m.on_death(
            &a,
            DirectTier::Lan,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        assert_eq!(
            m.upward_candidate(
                &a,
                DirectTier::Srflx,
                all_avail(),
                t0 + Duration::from_secs(1)
            ),
            Some(DirectTier::Public)
        );

        // Public incumbent: only LAN is higher — unavailable ⇒ None.
        // LAN incumbent: nothing higher, ever.
        let mut m = PathMonitor::default();
        let no_lan = TierAvailability {
            lan: false,
            public: true,
            srflx: true,
        };
        assert_eq!(m.upward_candidate(&a, DirectTier::Public, no_lan, t0), None);
        assert_eq!(
            m.upward_candidate(&a, DirectTier::Lan, all_avail(), t0),
            None
        );

        // Cap-full suppresses WITHOUT booking the spacing — the next
        // free slot fires immediately.
        let mut m = PathMonitor::default();
        for i in 0..(PROBE_CAP as u8) {
            m.on_probe_started(&oid(100 + i), DirectTier::Srflx, t0);
        }
        assert_eq!(
            m.upward_candidate(&a, DirectTier::Srflx, all_avail(), t0),
            None
        );
        m.on_probe_aborted(&oid(100));
        assert_eq!(
            m.upward_candidate(&a, DirectTier::Srflx, all_avail(), t0),
            Some(DirectTier::Lan)
        );
    }

    /// B2 flip — since the clean rc.296 soak the demote default is
    /// authoritative; `shadow` stays the per-host revert rail.
    #[test]
    fn demote_mode_default_is_on() {
        assert_eq!(DemoteMode::parse(None), DemoteMode::On);
        assert_eq!(DemoteMode::parse(Some("on")), DemoteMode::On);
        assert_eq!(DemoteMode::parse(Some("shadow")), DemoteMode::Shadow);
        assert_eq!(DemoteMode::parse(Some("off")), DemoteMode::Off);
        assert_eq!(DemoteMode::parse(Some("0")), DemoteMode::Off);
    }

    /// The forced-DERP pin is an annotation: direct decisions identical with
    /// and without it; relay-Q resets; the pin expires by TTL.
    #[test]
    fn forced_derp_pin_invariants() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let now = Instant::now();
        pump_heard(&mut m, &a, DirectTier::Relay, 20);
        assert!(m.score(&a, DirectTier::Relay, now) > B_RELAY);
        let before = m.decide(&a, Incumbent::Relay, all_avail(), true, now, false);
        m.on_forced_derp(&a, Duration::from_secs(1800), now);
        assert!(m.forced_derp_active(&a, now));
        assert_eq!(
            m.decide(&a, Incumbent::Relay, all_avail(), true, now, false),
            before,
            "the pin must not touch direct-tier decisions"
        );
        for tier in DIRECT_TIERS {
            assert!(
                m.eligible(&a, tier, now),
                "pin never blocks direct eligibility"
            );
        }
        assert_eq!(
            m.score(&a, DirectTier::Relay, now),
            B_RELAY,
            "relay-Q resets for a fresh evidence window"
        );
        assert!(!m.forced_derp_active(&a, now + Duration::from_secs(1801)));
    }

    /// #33 — the demote-follow hold-down must not make a node DEAF.
    ///
    /// This is the mutual-deafness deadlock, in miniature. `inbound_init`'s
    /// verdict is authoritative for inbound: `None` means the caller returns
    /// WITHOUT answering the peer's handshake initiation. So while the #30
    /// window is open, a node refuses to answer — and when both ends have
    /// followed, neither can hear the other for a window that escalates to 15
    /// minutes. Field 2026-08-26, neo16 ↔ a MacBook on the same Wi-Fi: 3370
    /// probe failures with `saw_inbound=false` against 3 with `true`, while
    /// disco measured that same LAN path at 8 % loss.
    ///
    /// Accepting is non-destructive under make-before-break (it becomes a
    /// shadow probe; the relay stands), so the window keeps its purpose — no
    /// promotion into a flap — without costing the pair its hearing.
    #[test]
    fn a_followed_peer_is_still_answered_when_accepting_costs_nothing() {
        let key = "ROOMLERD_OVERLAY_ANSWER_WHILE_FOLLOWED";
        let restore = std::env::var(key).ok();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);

        // A peer we just demote-followed: the window is open.
        let mut m = PathMonitor::default();
        let a = oid(1);
        m.on_peer_relayed_instead(&a, DirectTier::Lan, true, t0);
        assert!(!m.eligible(&a, DirectTier::Lan, t1), "window must be open");

        // OFF — today's behaviour: refuse, i.e. do not answer. This is the
        // deadlock, asserted so the fix cannot be mistaken for a no-op.
        unsafe { std::env::set_var(key, "0") };
        assert_eq!(
            m.inbound_init(&a, DirectTier::Lan, Incumbent::Relay, true, t1),
            None,
            "with the flag off the node stays deaf — the behaviour being fixed"
        );

        // ON — answer it, as a PROBE (never a destructive install: the relay
        // must survive, which is what makes answering free).
        unsafe { std::env::set_var(key, "1") };
        let mut m = PathMonitor::default();
        m.on_peer_relayed_instead(&a, DirectTier::Lan, true, t0);
        assert_eq!(
            m.inbound_init(&a, DirectTier::Lan, Incumbent::Relay, true, t1),
            Some(PathAction::Probe(DirectTier::Lan)),
            "a followed peer must still be ANSWERED, as a non-destructive probe"
        );

        // The window still gates PROMOTION — the whole point of #30 survives.
        assert!(
            !m.eligible(&a, DirectTier::Lan, t1),
            "the hold-down must still refuse anything that MOVES traffic"
        );

        // And the exemption is only for the non-destructive case: with no
        // relay to protect, accepting would be a destructive re-point, so the
        // window must still refuse.
        let mut m = PathMonitor::default();
        m.on_peer_relayed_instead(&a, DirectTier::Lan, true, t0);
        assert_eq!(
            m.inbound_init(&a, DirectTier::Lan, Incumbent::None, true, t1),
            None,
            "no relay to protect ⇒ accepting is destructive ⇒ still refused"
        );

        // A tier suppressed by its OWN failures is ALSO answered, because the
        // reasoning is the same: answering does not move traffic, and the
        // peer's authenticated init is live evidence the tier carries peer→us
        // right now, which is fresher than the penalty that suppressed it.
        // ⚠️ This is the part of #33 that is NOT free — the accept occupies
        // the peer's single probe slot for up to the handshake deadline, so a
        // peer initiating on a genuinely bad tier can delay a probe of a
        // better one. Weigh that in the soak: the alternative measured in the
        // field is indefinite mutual deafness, which is strictly worse, but
        // the slot cost is real and is why this ships default-OFF.
        let mut m = PathMonitor::default();
        m.on_death(&a, DirectTier::Lan, DeathReason::RxStale, true, t0);
        assert!(!m.eligible(&a, DirectTier::Lan, t1), "still suppressed");
        assert_eq!(
            m.inbound_init(&a, DirectTier::Lan, Incumbent::Relay, true, t1),
            Some(PathAction::Probe(DirectTier::Lan)),
            "answering is free of TRAFFIC consequences, so a suppressed tier is \
             still answered — the latch, not this verdict, decides what carries"
        );

        match restore {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }
    /// D9 — an inbound srflx init clears the srflx suppression outright (even
    /// a sticky one) and accepts; LAN/public inits still honour their
    /// suppression window exactly like the legacy cooldown gate.
    #[test]
    fn inbound_init_d9_clears_srflx_and_respects_cooldowns() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        // Srflx: escalate to sticky (3 strikes), then an inbound init lands.
        for i in 0..3u64 {
            m.on_death(
                &a,
                DirectTier::Srflx,
                DeathReason::HandshakeDeadline,
                true,
                t0 + Duration::from_secs(i),
            );
        }
        let t = t0 + Duration::from_secs(10);
        assert!(!m.eligible(&a, DirectTier::Srflx, t));
        assert_eq!(
            m.inbound_init(&a, DirectTier::Srflx, Incumbent::Relay, true, t),
            Some(PathAction::Probe(DirectTier::Srflx)),
            "a srflx init overrides the suppression (D9)"
        );
        assert!(m.eligible(&a, DirectTier::Srflx, t), "and clears it");

        // LAN: #33 generalised D9 above — an authenticated inbound init is
        // live evidence the tier carries peer→us, and answering it under MBB
        // with a relay to protect costs nothing (shadow probe; the latch is
        // the gate). So a suppressed LAN init is now ANSWERED rather than
        // refused. The anti-thrash it used to provide lives where it belongs:
        // `eligible` still governs everything OUTBOUND, so we still do not
        // promote into a flap.
        m.on_death(&a, DirectTier::Lan, DeathReason::HandshakeDeadline, true, t);
        assert!(
            !m.eligible(&a, DirectTier::Lan, t + Duration::from_secs(30)),
            "the tier is genuinely suppressed — outbound stays refused"
        );
        assert_eq!(
            m.inbound_init(
                &a,
                DirectTier::Lan,
                Incumbent::Relay,
                true,
                t + Duration::from_secs(30)
            ),
            Some(PathAction::Probe(DirectTier::Lan)),
            "#33 — a suppressed tier is still ANSWERED when there is a relay to \
             protect; going deaf here is what deadlocked pairs on one LAN"
        );
        let late = t + Duration::from_secs(61);
        assert_eq!(
            m.inbound_init(&a, DirectTier::Lan, Incumbent::Relay, true, late),
            Some(PathAction::Probe(DirectTier::Lan))
        );
        assert_eq!(
            m.inbound_init(
                &a,
                DirectTier::Lan,
                Incumbent::Direct(DirectTier::Public),
                true,
                late
            ),
            Some(PathAction::Install(DirectTier::Lan)),
            "direct-on-another-src re-points (no relay to protect)"
        );
        assert_eq!(
            m.inbound_init(&a, DirectTier::Lan, Incumbent::Relay, false, late),
            Some(PathAction::Install(DirectTier::Lan)),
            "MBB off re-points destructively"
        );
    }

    /// F1 — endpoint change resets penalties, strikes AND Q; the next failure
    /// restarts the escalation ladder on the ordinary window.
    #[test]
    fn endpoint_change_resets_penalties_strikes_and_q() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        m.on_death(
            &a,
            DirectTier::Public,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        m.on_death(
            &a,
            DirectTier::Public,
            DeathReason::HandshakeDeadline,
            true,
            t0 + Duration::from_secs(61),
        );
        let t = t0 + Duration::from_secs(120);
        assert!(!m.eligible(&a, DirectTier::Public, t), "sticky deny active");
        m.on_endpoint_change(&a);
        assert!(
            m.eligible(&a, DirectTier::Public, t),
            "reset restores eligibility"
        );
        assert_eq!(m.score(&a, DirectTier::Public, t), B_PUBLIC, "Q reset to 0");
        // Next failure books the ORDINARY window (fails restarted), not the
        // escalated one.
        m.on_death(
            &a,
            DirectTier::Public,
            DeathReason::HandshakeDeadline,
            true,
            t,
        );
        assert!(m.eligible(&a, DirectTier::Public, t + Duration::from_secs(61)));
    }

    /// F1 — a probe expiry books the penalty but NO Q event; a death slams Q.
    #[test]
    fn death_books_strike_and_penalty_and_probe_expire_books_no_q() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        pump_heard(&mut m, &a, DirectTier::Srflx, 14);
        let q_before = m.score(&a, DirectTier::Srflx, t0) - B_SRFLX;
        m.on_probe_started(&a, DirectTier::Srflx, t0);
        m.on_probe_result(&a, DirectTier::Srflx, ProbeOutcome::Expired, true, t0);
        assert!(!m.eligible(&a, DirectTier::Srflx, t0 + Duration::from_secs(30)));
        let far = t0 + Duration::from_secs(3600); // penalty fully decayed
        let q_after = m.score(&a, DirectTier::Srflx, far) - B_SRFLX;
        assert!(
            (q_after - q_before).abs() < 1e-9,
            "expiry must not touch Q (penalty already encodes it — F1)"
        );
        m.on_death(&a, DirectTier::Srflx, DeathReason::RxStale, true, far);
        let q_slammed = m.score(&a, DirectTier::Srflx, far + Duration::from_secs(3600)) - B_SRFLX;
        assert_eq!(q_slammed, Q_DEATH_SLAM, "death slams Q to the floor");
    }

    /// P8 — resume clears every peer's scores + suppressions but keeps probe
    /// bookkeeping (the legacy resume path leaves `upgrade_probes` in flight).
    #[test]
    fn resume_clears_all_peers_but_keeps_probe_bookkeeping() {
        let mut m = PathMonitor::default();
        let (a, b) = (oid(1), oid(2));
        let t0 = Instant::now();
        m.on_death(
            &a,
            DirectTier::Lan,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        m.on_death(
            &b,
            DirectTier::Public,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        m.on_probe_started(&b, DirectTier::Srflx, t0);
        m.on_resume();
        let t = t0 + Duration::from_secs(1);
        assert!(m.eligible(&a, DirectTier::Lan, t));
        assert!(m.eligible(&b, DirectTier::Public, t));
        assert_eq!(m.score(&a, DirectTier::Lan, t), B_LAN);
        assert_eq!(
            m.probes_in_flight, 1,
            "in-flight probe bookkeeping survives"
        );
        assert_eq!(
            m.decide(&b, Incumbent::Relay, all_avail(), true, t, false),
            PathAction::Keep,
            "the surviving probe still serializes"
        );
    }

    #[test]
    fn classifier_and_stats_table() {
        assert_eq!(
            classify(PathAction::Keep, PathAction::Keep),
            DivergenceClass::Match
        );
        assert_eq!(
            classify(
                PathAction::Probe(DirectTier::Lan),
                PathAction::Probe(DirectTier::Lan)
            ),
            DivergenceClass::Match
        );
        for (l, m) in [
            (
                PathAction::Probe(DirectTier::Lan),
                PathAction::Probe(DirectTier::Srflx),
            ),
            (
                PathAction::Install(DirectTier::Lan),
                PathAction::Probe(DirectTier::Lan),
            ),
            (PathAction::Relay, PathAction::Keep),
            (PathAction::Keep, PathAction::Install(DirectTier::Public)),
        ] {
            assert_eq!(classify(l, m), DivergenceClass::Diverged);
        }
        let s = ShadowStats::default();
        assert_eq!(
            (s.decisions, s.diverged, s.harmful, s.post_death_eligible),
            (0, 0, 0, 0)
        );
    }

    /// The voluntary-switch guard: an adversarial record/query stream can
    /// never extract two voluntary switches within [`SWITCH_MIN_INTERVAL`].
    #[test]
    fn voluntary_switch_hysteresis_bound() {
        let mut h = Hysteresis::default();
        let t0 = Instant::now();
        assert!(h.voluntary_allowed(t0), "fresh peer may switch");
        h.record_switch(t0);
        let mut granted: Vec<Instant> = vec![t0];
        // Adversarial stream: query every second for 5 minutes, record every
        // grant (a granted voluntary switch IS a switch).
        for s in 1..300u64 {
            let t = t0 + Duration::from_secs(s);
            if h.voluntary_allowed(t) {
                h.record_switch(t);
                granted.push(t);
            }
        }
        for w in granted.windows(2) {
            assert!(
                w[1].duration_since(w[0]) >= SWITCH_MIN_INTERVAL,
                "two voluntary switches closer than the floor"
            );
        }
        assert_eq!(granted.len(), 10, "300 s / 30 s floor = 10 grants");
    }

    /// The probe-latch Q credit deducts observed latency (PR-B feeds it) and
    /// clears the tier's strikes like the legacy promote.
    #[test]
    fn probe_latch_credits_q_and_clears_strikes() {
        let mut m = PathMonitor::default();
        let a = oid(1);
        let t0 = Instant::now();
        // One failure (strike 1), then a successful probe.
        m.on_death(
            &a,
            DirectTier::Public,
            DeathReason::HandshakeDeadline,
            true,
            t0,
        );
        let t = t0 + Duration::from_secs(61);
        m.on_probe_started(&a, DirectTier::Public, t);
        m.on_probe_result(
            &a,
            DirectTier::Public,
            ProbeOutcome::Latched {
                latency_ms: Some(2000.0),
            },
            true,
            t,
        );
        // Sample = 100 − min(50, 2000/40=50) = 50; Q was slammed −100 →
        // −100 + 0.4×(50−(−100)) = −40.
        let q = m.score(&a, DirectTier::Public, t + Duration::from_secs(3600)) - B_PUBLIC;
        assert!(
            (q - (-40.0)).abs() < 1e-6,
            "latency-deducted latch credit (got {q})"
        );
        // Strikes cleared: the NEXT failure books the ordinary window again.
        m.on_death(&a, DirectTier::Public, DeathReason::RxStale, true, t);
        assert!(m.eligible(&a, DirectTier::Public, t + Duration::from_secs(61)));
    }
}
