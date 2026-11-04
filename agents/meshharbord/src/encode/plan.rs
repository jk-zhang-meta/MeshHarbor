// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-70 M3a — the media PLAN, in SHADOW.
//!
//! # What this is
//!
//! [`Plan`] is everything the media loop is allowed to know (FR-70 M3's
//! design, `docs/fr/FR-70-media-pipeline-leaves-the-runtime.md` §"M3 — the
//! plan handoff"): the encoder's target rate, the geometry to encode at, the
//! cadence, and the byte budget the backpressure gate judges the send queue
//! against. Today `media_pump_ffmpeg_dc` computes each of those INLINE,
//! scattered through one pass of a 3,000-line loop, against live shared
//! state. [`produce`] computes the same numbers ONCE, from explicit inputs, as
//! a pure function — the form M3b will make the loop read.
//!
//! # Why a shadow, and why at frame cadence
//!
//! M3a changes NO behaviour. The pump keeps every inline decision; at the top
//! of each pass it also calls [`produce`] with the facts it has at that
//! instant and, where each inline value is computed later in the same pass,
//! compares the two ([`Shadow`]). A divergence is counted per field
//! ([`PlanDivergences`], on the heartbeat as `plan_divergences`) and logged
//! once per session per field with both values. The retirement gate is the
//! operator's standing rule: the counter must read **fleet-zero** before M3b
//! flips the loop to read the plan and deletes the inline arithmetic — a
//! divergence is then a measured bug in the plan rather than a regression in
//! the field, which is the only way "byte-identical" is provable rather than
//! asserted.
//!
//! The comparison runs every pass, not once per viewer window: the AIMD's
//! additive increase is a per-frame step (`pre_encode_tick` runs per frame),
//! so a window-cadence plan would diverge by construction and its counter
//! could never reach zero (spec §"Crux (2) resolved").
//!
//! # Facts and decisions
//!
//! The producer reads FACTS and emits DECISIONS. What stays with the loop,
//! deliberately: the bytes in flight, the send-wait EMA (`direct_wait_ema_ms`
//! and its `gate_sw_*` cursors — a running MEASUREMENT of the loop's own
//! queue, which only reads like a decision), the live age of the frame on the
//! wire, and the captured frame's own dims. What the plan owns: the budget
//! triple, the cadence, the geometry, the target.
//!
//! One input is itself a decision the plan does not own yet: `target_bps` is
//! the rate governor's standing target. The controller is stateful and ticks
//! inside the pass; making it the plan's is M4 (one controller), not M3. What
//! M3a CAN check about the rate is the two places the loop decides a rate by
//! itself. The inline open is judged against the first target the controller
//! hands that encoder ([`Shadow::note_built`], [`Shadow::after_tick`]). A
//! make-before-break replacement is judged the same way when the plan held
//! while it opened ([`Shadow::note_rate_swap_adopted`],
//! [`Shadow::note_dims_swap_adopted`]); one that arrives after the plan moved
//! was built at the plan of its moment, and is counted apart
//! ([`Shadow::stale_swaps`]), never as a divergence. The field's first reads
//! (2026-10-21) found one of each: a stale `hevc_qsv` swap in a stall cascade,
//! and a `hevc_vaapi` dims replacement opened at the old frame's rate — the
//! shadow's first genuine finding.
//!
//! # Knobs are read once
//!
//! Every env/config knob the inline arithmetic reads per frame
//! (`constrained_queue_ms`, `direct_queue_ms`, `relay_max_bps`, the HRD
//! window, the dial caps, the refined-rung cap) is resolved ONCE per pump into
//! [`PlanKnobs`]. The shadow therefore adds no env read to the frame path
//! (FR-70's rule), and the producer is pure over its arguments — which is what
//! lets the B0 cells (`encode::sim`) drive it with the constants explicit.

use super::policy::{self, DimsInputs};
use super::rate_profile;
use super::resample;
use super::{PriorityCaps, aimd};

/// FR-70 M3 — everything the media loop is allowed to know. Computed by
/// [`produce`], published whole, read once at the top of a pass (M3b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The encoder's target, on the ladder `FfmpegEncoder::set_bitrate`
    /// applies (`aimd::coarsen_bitrate`). `0` = the controller has no target
    /// yet (before its first tick).
    pub bitrate_bps: u32,
    /// The geometry to encode at — the user's pick merged with the caps and
    /// the rungs (`policy::plan_dims`), reduced to the dims the resampler
    /// produces (`resample::target_dims`), so the loop never merges anything.
    /// `(0, 0)` = no geometry yet (no frame has been captured, so the native
    /// dims are unknown); the session's first encoder opens at its frame's
    /// dims, which M2 left to the inline open on purpose.
    pub dims: (u32, u32),
    /// Frames per second the loop may produce — the pacer's only input: the
    /// governor's paced rate when one is engaged, else the target. ⚠️ The loop
    /// paces itself ONLY below the target (`FpsPace` engages ≥ 5 fps under
    /// it); at the target the capture backend is the single pacer (rc.93 — a
    /// second pump-side floor halved the fps).
    pub fps: u32,
    /// FR-59 P2 / FR-74 P1 — the byte budget the gate compares the send queue
    /// against (the soft budget: link time at the reference rate).
    pub queue_budget_bytes: usize,
    /// FR-74 P1b — the HARD byte ceiling: the larger of the soft budget and
    /// the encoder's own HRD reservoir. At or above it the gate trips on bytes
    /// alone. Equal to the soft budget on a constrained path, whose gate has
    /// no wait qualifier.
    pub queue_hard_budget_bytes: usize,
    /// FR-74 P1b — the measured-wait bound (ms) that qualifies the soft
    /// budget: between soft and hard the gate trips only once the measured
    /// send wait has crossed it. `0` = bytes alone trip the soft budget — the
    /// constrained path's rule, which is what lets ONE gate function serve
    /// both transports (locked by
    /// `the_constrained_gate_is_the_unified_gate_at_lag_zero`).
    pub queue_lag_bound_ms: u64,
    /// Monotonic. Moves when any other field moves, so a plan recomputed with
    /// identical fields costs the reader nothing.
    pub epoch: u64,
}

impl Plan {
    /// Every field but the epoch.
    fn same_fields(&self, other: &Plan) -> bool {
        self.bitrate_bps == other.bitrate_bps
            && self.dims == other.dims
            && self.fps == other.fps
            && self.queue_budget_bytes == other.queue_budget_bytes
            && self.queue_hard_budget_bytes == other.queue_hard_budget_bytes
            && self.queue_lag_bound_ms == other.queue_lag_bound_ms
    }

    /// Does the plan carry a geometry yet?
    pub(crate) fn has_dims(&self) -> bool {
        self.dims.0 > 0 && self.dims.1 > 0
    }
}

/// The knobs the inline arithmetic reads from env/config per frame, resolved
/// ONCE per pump. Env and config are process-stable (the config registry is a
/// `OnceLock`), so these are the numbers the per-frame readers return — locked
/// by `the_knobs_resolve_to_what_the_per_frame_readers_read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlanKnobs {
    /// `encode::relay_max_bps` — the constrained path's nominal ceiling.
    pub relay_max_bps: u32,
    /// `rate_profile::constrained_queue_ms`.
    pub constrained_queue_ms: u64,
    /// `encode::constrained_queue_measured_enabled` (FR-59 P2).
    pub constrained_queue_measured: bool,
    /// `rate_profile::direct_queue_ms`.
    pub direct_queue_ms: u64,
    /// `rate_profile::direct_hrd_pct` — the HRD window before the AV1 floor.
    pub direct_hrd_pct: usize,
    /// `encode::idle_refine_cap_long_edge` — the refined rung's own bound.
    pub refined_cap: Option<u32>,
    /// The Priority dial's dims-caps (`encode::priority_relay_cap`).
    pub priority_caps: PriorityCaps,
}

impl PlanKnobs {
    pub(crate) fn from_env() -> Self {
        Self {
            relay_max_bps: super::relay_max_bps(),
            constrained_queue_ms: rate_profile::constrained_queue_ms(),
            constrained_queue_measured: super::constrained_queue_measured_enabled(),
            direct_queue_ms: rate_profile::direct_queue_ms(),
            direct_hrd_pct: rate_profile::direct_hrd_pct(),
            refined_cap: super::idle_refine_cap_long_edge(),
            priority_caps: PriorityCaps::from_env(),
        }
    }
}

/// The facts the producer reads — what the pump has at the top of a pass.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PlanInputs {
    /// Relay-TCP (constrained) or direct, as the pump currently believes.
    pub constrained: bool,
    /// The capture/encode target rate for this transport.
    pub target_fps: u32,
    /// The governor's fps-first pace (`None` = run at the target).
    pub paced_fps: Option<u32>,
    /// `RateGovernor::pipe_bps` — what the session believes the pipe carries
    /// (constrained only; `None` on direct).
    pub pipe_bps: Option<u32>,
    /// The ceiling the LAST planned frame was planned at (`last_ceiling_bps`):
    /// the direct budget's reference. ⚠️ Deliberately the previous frame's —
    /// the pump reads it at the gate, before this frame's ceiling exists, and
    /// a plan that used this frame's would gate differently on every pass
    /// the ceiling moves.
    pub ceiling_reference_bps: u32,
    /// The live encoder's HRD window (`rate_profile::hrd_pct_for` of its
    /// name), or the direct default while no encoder exists.
    pub hrd_pct: usize,
    /// The rate governor's standing target (`applied_bps`; 0 = none yet).
    pub target_bps: u32,
    /// The geometry decision's inputs: the native dims last captured (0 =
    /// unknown) and the control-plane state (merged target, merged dial cap,
    /// slow-link cap, refine state, soft cap).
    pub dims: DimsInputs,
}

/// The producer: the plan from the facts, pure. `prev` carries the epoch.
pub(crate) fn produce(inputs: &PlanInputs, knobs: &PlanKnobs, prev: Option<&Plan>) -> Plan {
    let (queue_budget_bytes, queue_hard_budget_bytes, queue_lag_bound_ms) = if inputs.constrained {
        // FR-59 P2 — denominated in the measured pipe when one is believed,
        // never above the nominal band; bytes alone trip it.
        let reference = rate_profile::constrained_queue_reference_bps(
            knobs.relay_max_bps,
            inputs.pipe_bps,
            knobs.constrained_queue_measured,
        );
        let budget =
            rate_profile::constrained_queue_budget_bytes_at(reference, knobs.constrained_queue_ms);
        (budget, budget, 0)
    } else {
        // FR-74 P1/P1b — link time at the path's ceiling, qualified by the
        // measured wait up to the encoder's own reservoir.
        let soft = rate_profile::direct_queue_budget_bytes_at(
            inputs.ceiling_reference_bps,
            knobs.direct_queue_ms,
        );
        let hard = rate_profile::direct_queue_hard_budget_bytes_at(
            inputs.ceiling_reference_bps,
            inputs.hrd_pct,
            knobs.direct_queue_ms,
        );
        (soft, hard, knobs.direct_queue_ms)
    };
    let fps = inputs.paced_fps.unwrap_or(inputs.target_fps);
    let dims = if inputs.dims.native_w == 0 || inputs.dims.native_h == 0 {
        (0, 0)
    } else {
        resample::target_dims(
            (inputs.dims.native_w, inputs.dims.native_h),
            policy::plan_dims(&inputs.dims).effective_target,
        )
    };
    let fields = Plan {
        bitrate_bps: ladder(inputs.target_bps),
        dims,
        fps,
        queue_budget_bytes,
        queue_hard_budget_bytes,
        queue_lag_bound_ms,
        epoch: 0,
    };
    let epoch = match prev {
        Some(p) if p.same_fields(&fields) => p.epoch,
        Some(p) => p.epoch + 1,
        None => 1,
    };
    Plan { epoch, ..fields }
}

/// The controller's target on the ladder the encoder applies; 0 stays 0.
fn ladder(bps: u32) -> u32 {
    if bps == 0 {
        0
    } else {
        aimd::coarsen_bitrate(bps)
    }
}

/// Per-field divergence counts for the session, on the heartbeat as
/// `plan_divergences`. The retirement gate reads every field at zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PlanDivergences {
    /// `queue_budget_bytes` vs the pump's `queue_budget`.
    pub budget: u32,
    /// `queue_hard_budget_bytes` vs the pump's `hard_budget`.
    pub hard_budget: u32,
    /// `queue_lag_bound_ms` vs the bound the pump's gate used.
    pub lag_bound: u32,
    /// The plan's triple through the one gate function vs the pump's verdict.
    pub gate: u32,
    /// `fps` vs the rate the pump paced to.
    pub fps: u32,
    /// `dims` vs the dims the pump planned this frame at, and the dims of
    /// every encoder the loop built.
    pub dims: u32,
    /// `bitrate_bps` vs the rate every encoder the loop built was built at.
    pub bitrate: u32,
}

impl std::fmt::Display for PlanDivergences {
    /// The heartbeat's form — the same shape `Debug` prints, written out so
    /// the fields are READ by the build that ships it (a derived `Debug` is
    /// not a read to the dead-code lint) and so a grep is stable:
    /// `PlanDivergences { budget: 0, hard_budget: 0, … }`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PlanDivergences {{ budget: {}, hard_budget: {}, lag_bound: {}, gate: {}, fps: {}, dims: {}, bitrate: {} }}",
            self.budget,
            self.hard_budget,
            self.lag_bound,
            self.gate,
            self.fps,
            self.dims,
            self.bitrate
        )
    }
}

/// One field's first divergence of the session, with both values, for the
/// pump to log once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirstDivergence {
    pub field: &'static str,
    pub plan: String,
    pub inline: String,
}

/// The plan a make-before-break replacement was SPAWNED under. The loop
/// decides a replacement's rate (and, for a dims swap, its dims) at the spawn,
/// so that plan — not the one in force when the open finishes, which on a
/// rebuild-bound backend can be seconds later — is the one it is judged
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SwapSpawn {
    bitrate_bps: u32,
    dims: (u32, u32),
}

/// A replacement adopted after the plan moved while it opened, for the pump
/// to log once per session. Not a divergence: the loop built it at the plan's
/// values of the moment it decided them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaleSwap {
    pub kind: &'static str,
    pub built_bps: u32,
    pub spawned_bps: u32,
    pub now_bps: u32,
    pub spawned_dims: (u32, u32),
    pub now_dims: (u32, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Budget,
    HardBudget,
    LagBound,
    Gate,
    Fps,
    Dims,
    Bitrate,
}

impl Field {
    fn name(self) -> &'static str {
        match self {
            Field::Budget => "budget",
            Field::HardBudget => "hard_budget",
            Field::LagBound => "lag_bound",
            Field::Gate => "gate",
            Field::Fps => "fps",
            Field::Dims => "dims",
            Field::Bitrate => "bitrate",
        }
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// The shadow: the plan of the current pass, the counters, and the encoder
/// the loop built since the controller last ticked.
#[derive(Debug, Default)]
pub(crate) struct Shadow {
    plan: Option<Plan>,
    counts: PlanDivergences,
    /// Fields already reported this session (one log line per field).
    reported: u8,
    /// The latest encoder the loop built since the last tick: the rate it was
    /// built at (raw; laddered at the comparison) and, when they are the
    /// loop's decision, its dims. A build the loop replaced before a tick is
    /// superseded, not judged.
    built: Option<(u32, Option<(u32, u32)>)>,
    /// Replacements adopted after the plan moved while they opened.
    stale_swaps: u32,
    /// Whether this session's first stale adoption has been reported.
    stale_reported: bool,
}

impl Shadow {
    /// The pass's plan, from the facts at this instant.
    pub(crate) fn produce(&mut self, inputs: &PlanInputs, knobs: &PlanKnobs) -> Plan {
        let plan = produce(inputs, knobs, self.plan.as_ref());
        self.plan = Some(plan);
        plan
    }

    /// The current pass's plan (test seam; the pump reads the counters).
    #[cfg(test)]
    pub(crate) fn plan(&self) -> Option<&Plan> {
        self.plan.as_ref()
    }

    /// How many distinct plans the session has had (0 = none yet).
    pub(crate) fn epoch(&self) -> u64 {
        self.plan.map_or(0, |p| p.epoch)
    }

    pub(crate) fn counts(&self) -> PlanDivergences {
        self.counts
    }

    fn diverge<T: PartialEq + std::fmt::Debug>(
        &mut self,
        field: Field,
        plan: T,
        inline: T,
        out: &mut Vec<FirstDivergence>,
    ) {
        if plan == inline {
            return;
        }
        let count = match field {
            Field::Budget => &mut self.counts.budget,
            Field::HardBudget => &mut self.counts.hard_budget,
            Field::LagBound => &mut self.counts.lag_bound,
            Field::Gate => &mut self.counts.gate,
            Field::Fps => &mut self.counts.fps,
            Field::Dims => &mut self.counts.dims,
            Field::Bitrate => &mut self.counts.bitrate,
        };
        *count = count.saturating_add(1);
        if self.reported & field.bit() == 0 {
            self.reported |= field.bit();
            out.push(FirstDivergence {
                field: field.name(),
                plan: format!("{plan:?}"),
                inline: format!("{inline:?}"),
            });
        }
    }

    /// The budget triple the pump's gate used this pass. On a constrained
    /// path the pump's hard budget IS its soft one and its gate has no wait
    /// bound, so the caller passes `(soft, soft, 0)`.
    pub(crate) fn check_budget(
        &mut self,
        inline_soft: usize,
        inline_hard: usize,
        inline_lag_ms: u64,
    ) -> Vec<FirstDivergence> {
        let mut out = Vec::new();
        let Some(plan) = self.plan else {
            return out;
        };
        self.diverge(
            Field::Budget,
            plan.queue_budget_bytes,
            inline_soft,
            &mut out,
        );
        self.diverge(
            Field::HardBudget,
            plan.queue_hard_budget_bytes,
            inline_hard,
            &mut out,
        );
        self.diverge(
            Field::LagBound,
            plan.queue_lag_bound_ms,
            inline_lag_ms,
            &mut out,
        );
        out
    }

    /// The gate's verdict: the plan's triple through the ONE gate function
    /// (`rate_profile::direct_gate_trips`) against the verdict the pump's two
    /// arms reached from the same facts.
    pub(crate) fn check_gate_verdict(
        &mut self,
        inflight: usize,
        measured_wait_ms: f64,
        inline_trips: bool,
    ) -> Vec<FirstDivergence> {
        let mut out = Vec::new();
        let Some(plan) = self.plan else {
            return out;
        };
        let trips = rate_profile::direct_gate_trips(
            inflight,
            plan.queue_budget_bytes,
            plan.queue_hard_budget_bytes,
            measured_wait_ms,
            plan.queue_lag_bound_ms,
        );
        self.diverge(Field::Gate, trips, inline_trips, &mut out);
        out
    }

    /// The rate the pump paced this pass to.
    pub(crate) fn check_fps(&mut self, inline_fps: u32) -> Vec<FirstDivergence> {
        let mut out = Vec::new();
        let Some(plan) = self.plan else {
            return out;
        };
        self.diverge(Field::Fps, plan.fps, inline_fps, &mut out);
        out
    }

    /// The dims this frame's plan produces. Skipped (no count) while the plan
    /// has no geometry — before the first frame.
    pub(crate) fn check_dims(&mut self, inline_dims: (u32, u32)) -> Vec<FirstDivergence> {
        let mut out = Vec::new();
        let Some(plan) = self.plan else {
            return out;
        };
        if !plan.has_dims() {
            return out;
        }
        self.diverge(Field::Dims, plan.dims, inline_dims, &mut out);
        out
    }

    /// The loop's inline open built an encoder at `rate_bps` and `dims`;
    /// judged at the next [`Self::after_tick`].
    pub(crate) fn note_built(&mut self, rate_bps: u32, dims: (u32, u32)) {
        self.built = Some((rate_bps, Some(dims)));
    }

    /// The controller ticked: its target becomes the plan's `bitrate_bps` (an
    /// epoch move when it changed — the controller republishing, not a
    /// divergence), and an encoder built since the last tick is judged
    /// against the plan: built at its rate, and at its dims. A `bitrate`
    /// divergence here is an encoder the controller re-rates on its very next
    /// tick — on a rebuild-bound backend, a second open.
    pub(crate) fn after_tick(&mut self, target_bps: u32) -> Vec<FirstDivergence> {
        let mut out = Vec::new();
        let Some(mut plan) = self.plan else {
            self.built = None;
            return out;
        };
        let bitrate = ladder(target_bps);
        if bitrate != plan.bitrate_bps {
            plan.bitrate_bps = bitrate;
            plan.epoch += 1;
            self.plan = Some(plan);
        }
        if let Some((rate, dims)) = self.built.take() {
            self.diverge(Field::Bitrate, plan.bitrate_bps, ladder(rate), &mut out);
            if let Some(dims) = dims
                && plan.has_dims()
            {
                self.diverge(Field::Dims, plan.dims, dims, &mut out);
            }
        }
        out
    }

    /// The plan in force when a replacement spawns; `None` before the first
    /// plan.
    pub(crate) fn swap_spawn(&self) -> Option<SwapSpawn> {
        self.plan.map(|p| SwapSpawn {
            bitrate_bps: p.bitrate_bps,
            dims: p.dims,
        })
    }

    /// The loop adopted a RATE replacement built at `rate_bps`. Its rate is
    /// the one thing the loop decided for it — `rebuild_spec` copies the live
    /// encoder's dims, which M2's pin holds while a dims swap opens — so the
    /// rate is all that is judged.
    pub(crate) fn note_rate_swap_adopted(
        &mut self,
        rate_bps: u32,
        spawned: Option<SwapSpawn>,
    ) -> Option<StaleSwap> {
        self.judge_swap("rate", rate_bps, None, spawned)
    }

    /// The loop adopted a DIMS replacement built at `rate_bps` and `dims`; it
    /// decided both.
    pub(crate) fn note_dims_swap_adopted(
        &mut self,
        rate_bps: u32,
        dims: (u32, u32),
        spawned: Option<SwapSpawn>,
    ) -> Option<StaleSwap> {
        self.judge_swap("dims", rate_bps, Some(dims), spawned)
    }

    /// Did the plan move while the replacement opened?
    ///
    /// **It held** — the common case, opens are milliseconds on most
    /// backends: the replacement is judged exactly as an inline open is,
    /// against the controller's first target after adoption
    /// ([`Self::after_tick`]). Re-rated on that tick although the plan did
    /// not move is a divergence: the loop built an encoder at a rate the plan
    /// does not stand behind. The field's driven read found one (2026-10-21,
    /// `hevc_vaapi`): a dims replacement for 1050×590 opened at the old
    /// 1600×900 frame's 25 M rung while the plan already aimed at the smaller
    /// frame, whose ceiling clamped the target to 8 M on the next tick.
    ///
    /// **It moved** — a QSV open runs 0.2–3.6 s and a stall cascade halves
    /// the target every few seconds, so on the field's first read (a
    /// `hevc_qsv` session) a replacement spawned at the 12 M rung arrived
    /// after the controller had reached 2.7 M. The loop built it at the plan
    /// of its moment; the re-rate is the plan's own movement. Counted apart,
    /// as `stale_swaps`, and not judged at the next tick. With no plan at the
    /// spawn there is nothing to have moved, and it is judged as held.
    fn judge_swap(
        &mut self,
        kind: &'static str,
        rate_bps: u32,
        dims: Option<(u32, u32)>,
        spawned: Option<SwapSpawn>,
    ) -> Option<StaleSwap> {
        let moved = match (spawned, self.plan) {
            (Some(spawned), Some(now)) => {
                let geometry_known = spawned.dims.0 > 0 && spawned.dims.1 > 0 && now.has_dims();
                now.bitrate_bps != spawned.bitrate_bps
                    || (dims.is_some() && geometry_known && now.dims != spawned.dims)
            }
            _ => false,
        };
        if !moved {
            self.built = Some((rate_bps, dims));
            return None;
        }
        let (spawned, now) = (spawned?, self.plan?);
        self.stale_swaps = self.stale_swaps.saturating_add(1);
        if self.stale_reported {
            return None;
        }
        self.stale_reported = true;
        Some(StaleSwap {
            kind,
            built_bps: rate_bps,
            spawned_bps: spawned.bitrate_bps,
            now_bps: now.bitrate_bps,
            spawned_dims: spawned.dims,
            now_dims: now.dims,
        })
    }

    /// Replacements adopted after the plan moved while they opened.
    pub(crate) fn stale_swaps(&self) -> u32 {
        self.stale_swaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::TargetResolution;

    const NOMINAL: u32 = 3_000_000;

    fn knobs() -> PlanKnobs {
        PlanKnobs {
            relay_max_bps: NOMINAL,
            constrained_queue_ms: 450,
            constrained_queue_measured: true,
            direct_queue_ms: 150,
            direct_hrd_pct: 100,
            refined_cap: None,
            priority_caps: PriorityCaps::default(),
        }
    }

    fn dims(native_w: u32, native_h: u32) -> DimsInputs {
        DimsInputs {
            native_w,
            native_h,
            merged_target: TargetResolution::Native,
            merged_priority_cap: None,
            slow_link_cap: None,
            refined: false,
            refined_cap: None,
            soft_cap: None,
        }
    }

    fn constrained(pipe_bps: Option<u32>) -> PlanInputs {
        PlanInputs {
            constrained: true,
            target_fps: 30,
            paced_fps: None,
            pipe_bps,
            ceiling_reference_bps: NOMINAL,
            hrd_pct: 200,
            target_bps: 0,
            dims: dims(1920, 1200),
        }
    }

    fn direct(ceiling: u32, hrd_pct: usize) -> PlanInputs {
        PlanInputs {
            constrained: false,
            target_fps: 60,
            paced_fps: None,
            pipe_bps: None,
            ceiling_reference_bps: ceiling,
            hrd_pct,
            target_bps: 0,
            dims: dims(1920, 1200),
        }
    }

    #[test]
    fn a_constrained_budget_is_the_reference_rate_s_window_floored_at_one_chunk() {
        // No belief: 450 ms of the nominal band.
        let p = produce(&constrained(None), &knobs(), None);
        assert_eq!(p.queue_budget_bytes, 168_750);
        assert_eq!(p.queue_hard_budget_bytes, p.queue_budget_bytes);
        assert_eq!(p.queue_lag_bound_ms, 0);
        // A measured pipe UNDER the band lowers it (FR-59 P2's field case:
        // 395 kbps through a phone hotspot).
        let p = produce(&constrained(Some(395_000)), &knobs(), None);
        assert_eq!(p.queue_budget_bytes, 22_218);
        // A measurement ABOVE the band never raises it.
        let p = produce(&constrained(Some(9_000_000)), &knobs(), None);
        assert_eq!(p.queue_budget_bytes, 168_750);
        // The one-chunk floor under an absurd reference.
        let p = produce(&constrained(Some(1)), &knobs(), None);
        assert_eq!(
            p.queue_budget_bytes,
            rate_profile::CONSTRAINED_QUEUE_MIN_BYTES
        );
        // With the measured denomination OFF the band stands.
        let k = PlanKnobs {
            constrained_queue_measured: false,
            ..knobs()
        };
        let p = produce(&constrained(Some(395_000)), &k, None);
        assert_eq!(p.queue_budget_bytes, 168_750);
    }

    #[test]
    fn a_direct_budget_is_the_ceiling_s_link_time_qualified_up_to_the_reservoir() {
        // 43 Mbps direct (FR-74 P1's CORPLAP-1 ceiling): soft = 150 ms of it,
        // hard = the larger of that and the 1× reservoir (43 M / 8 bytes).
        let p = produce(&direct(43_000_000, 100), &knobs(), None);
        assert_eq!(p.queue_budget_bytes, 806_250);
        assert_eq!(p.queue_hard_budget_bytes, 5_375_000);
        assert_eq!(p.queue_lag_bound_ms, 150);
        // AV1's floor at 200 % doubles the reservoir.
        let av1 = rate_profile::hrd_pct_for("av1_qsv", 100);
        let p = produce(&direct(43_000_000, av1), &knobs(), None);
        assert_eq!(p.queue_hard_budget_bytes, 10_750_000);
        // The 48 KiB floor on a thin ceiling.
        let p = produce(&direct(1_000_000, 100), &knobs(), None);
        assert_eq!(p.queue_budget_bytes, 48 * 1024);
        assert_eq!(p.queue_hard_budget_bytes, 125_000);
    }

    #[test]
    fn no_reference_rate_means_no_gate() {
        let p = produce(&direct(0, 100), &knobs(), None);
        assert_eq!(p.queue_budget_bytes, usize::MAX);
        assert_eq!(p.queue_hard_budget_bytes, usize::MAX);
        assert!(!rate_profile::direct_gate_trips(
            usize::MAX / 2,
            p.queue_budget_bytes,
            p.queue_hard_budget_bytes,
            1_000.0,
            p.queue_lag_bound_ms
        ));
        // A zero window disables the gate on either transport.
        let k = PlanKnobs {
            constrained_queue_ms: 0,
            direct_queue_ms: 0,
            ..knobs()
        };
        assert_eq!(
            produce(&constrained(None), &k, None).queue_budget_bytes,
            usize::MAX
        );
        assert_eq!(
            produce(&direct(43_000_000, 100), &k, None).queue_hard_budget_bytes,
            usize::MAX
        );
    }

    /// The constrained gate is `inflight >= budget`, bytes alone. The plan
    /// states it as the triple `(b, b, 0)` so ONE gate function serves both
    /// transports; this locks the algebra for every inflight and every wait.
    #[test]
    fn the_constrained_gate_is_the_unified_gate_at_lag_zero() {
        let p = produce(&constrained(Some(395_000)), &knobs(), None);
        let b = p.queue_budget_bytes;
        for inflight in [0, 1, b / 2, b - 1, b, b + 1, 10 * b, usize::MAX / 2] {
            for wait_ms in [0.0, 0.1, 149.0, 150.0, 5_000.0] {
                assert_eq!(
                    rate_profile::direct_gate_trips(
                        inflight,
                        p.queue_budget_bytes,
                        p.queue_hard_budget_bytes,
                        wait_ms,
                        p.queue_lag_bound_ms,
                    ),
                    inflight >= b,
                    "inflight {inflight} wait {wait_ms}"
                );
            }
        }
    }

    #[test]
    fn fps_is_the_pace_or_the_target() {
        let paced = PlanInputs {
            paced_fps: Some(45),
            ..direct(43_000_000, 100)
        };
        assert_eq!(produce(&paced, &knobs(), None).fps, 45);
        assert_eq!(produce(&direct(43_000_000, 100), &knobs(), None).fps, 60);
    }

    #[test]
    fn dims_are_plan_dims_through_the_resampler_s_rule_or_nothing_before_the_first_frame() {
        // No frame yet: no geometry, and the shadow skips the comparison.
        let blind = PlanInputs {
            dims: dims(0, 0),
            ..constrained(None)
        };
        let p = produce(&blind, &knobs(), None);
        assert_eq!(p.dims, (0, 0));
        assert!(!p.has_dims());
        // Native, uncapped.
        let p = produce(&constrained(None), &knobs(), None);
        assert_eq!(p.dims, (1920, 1200));
        assert!(p.has_dims());
        // The slow-link cap (FR-59 P5): 1280 long edge, aspect kept.
        let capped = PlanInputs {
            dims: DimsInputs {
                slow_link_cap: Some(1280),
                ..dims(1920, 1200)
            },
            ..constrained(None)
        };
        assert_eq!(produce(&capped, &knobs(), None).dims, (1280, 800));
        // A user box BELOW native is the box; one above it is the resampler's
        // no-op (no upscaling).
        let small = PlanInputs {
            dims: DimsInputs {
                merged_target: TargetResolution::Fixed {
                    width: 944,
                    height: 590,
                },
                ..dims(1920, 1200)
            },
            ..constrained(None)
        };
        assert_eq!(produce(&small, &knobs(), None).dims, (944, 590));
        let big = PlanInputs {
            dims: DimsInputs {
                merged_target: TargetResolution::Fixed {
                    width: 2560,
                    height: 1600,
                },
                ..dims(1920, 1200)
            },
            ..constrained(None)
        };
        assert_eq!(produce(&big, &knobs(), None).dims, (1920, 1200));
    }

    #[test]
    fn bitrate_is_the_controller_s_target_on_the_ladder() {
        assert_eq!(produce(&constrained(None), &knobs(), None).bitrate_bps, 0);
        let p = produce(
            &PlanInputs {
                target_bps: 2_600_000,
                ..constrained(None)
            },
            &knobs(),
            None,
        );
        assert_eq!(p.bitrate_bps, aimd::coarsen_bitrate(2_600_000));
        assert_eq!(p.bitrate_bps, 3_000_000);
    }

    /// The heartbeat prints the counters through `Display`, in the shape the
    /// field reads grep for.
    #[test]
    fn the_counters_print_as_the_heartbeat_greps_them() {
        let d = PlanDivergences {
            budget: 1,
            hard_budget: 2,
            lag_bound: 3,
            gate: 4,
            fps: 5,
            dims: 6,
            bitrate: 7,
        };
        assert_eq!(
            d.to_string(),
            "PlanDivergences { budget: 1, hard_budget: 2, lag_bound: 3, gate: 4, fps: 5, dims: 6, bitrate: 7 }"
        );
        assert_eq!(d.to_string(), format!("{d:?}"));
    }

    #[test]
    fn the_epoch_moves_only_when_a_field_does() {
        let k = knobs();
        let a = produce(&constrained(None), &k, None);
        assert_eq!(a.epoch, 1);
        let b = produce(&constrained(None), &k, Some(&a));
        assert_eq!(b.epoch, 1, "identical fields keep the epoch");
        assert_eq!(a, b);
        let c = produce(&constrained(Some(395_000)), &k, Some(&b));
        assert_eq!(c.epoch, 2, "a budget move is a plan move");
        let d = produce(&constrained(None), &k, Some(&c));
        assert_eq!(
            d.epoch, 3,
            "moving back is another — monotonic, never reused"
        );
    }

    /// The negative control's committed half: a planted divergence is counted
    /// on its field, reported once, and never bleeds into another field.
    #[test]
    fn the_shadow_counts_each_field_and_reports_the_first_once() {
        let mut s = Shadow::default();
        // Nothing to compare against before the first plan.
        assert!(s.check_budget(1, 1, 1).is_empty());
        assert_eq!(s.counts(), PlanDivergences::default());
        let plan = s.produce(&constrained(None), &knobs());
        // The inline values, exact: no divergence.
        assert!(
            s.check_budget(plan.queue_budget_bytes, plan.queue_hard_budget_bytes, 0)
                .is_empty()
        );
        assert_eq!(s.counts(), PlanDivergences::default());
        // A planted divergence on ONE field: counted and reported once...
        let first = s.check_budget(plan.queue_budget_bytes + 1, plan.queue_hard_budget_bytes, 0);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "budget");
        assert_eq!(first[0].plan, plan.queue_budget_bytes.to_string());
        assert_eq!(first[0].inline, (plan.queue_budget_bytes + 1).to_string());
        // ...the second time counted, not reported.
        assert!(
            s.check_budget(plan.queue_budget_bytes + 1, plan.queue_hard_budget_bytes, 0)
                .is_empty()
        );
        assert_eq!(
            s.counts(),
            PlanDivergences {
                budget: 2,
                ..Default::default()
            }
        );
        // Other fields untouched; each has its own first report.
        let first = s.check_fps(29);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "fps");
        assert_eq!(
            s.counts(),
            PlanDivergences {
                budget: 2,
                fps: 1,
                ..Default::default()
            }
        );
        // The gate verdict: the plan's triple against a pump that disagreed.
        let b = plan.queue_budget_bytes;
        assert!(
            s.check_gate_verdict(b, 0.0, true).is_empty(),
            "at the budget both trip"
        );
        let first = s.check_gate_verdict(b - 1, 0.0, true);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "gate");
        assert_eq!(first[0].plan, "false");
        assert_eq!(first[0].inline, "true");
        assert_eq!(s.counts().gate, 1);
    }

    #[test]
    fn the_shadow_skips_dims_until_the_plan_has_geometry() {
        let mut s = Shadow::default();
        s.produce(
            &PlanInputs {
                dims: dims(0, 0),
                ..constrained(None)
            },
            &knobs(),
        );
        assert!(s.check_dims((1920, 1200)).is_empty());
        assert_eq!(s.counts().dims, 0);
        s.produce(&constrained(None), &knobs());
        assert!(s.check_dims((1920, 1200)).is_empty());
        let first = s.check_dims((1280, 800));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "dims");
        assert_eq!(s.counts().dims, 1);
    }

    #[test]
    fn an_encoder_the_loop_built_is_judged_against_the_controller_s_first_target() {
        let mut s = Shadow::default();
        let plan = s.produce(
            &PlanInputs {
                target_bps: 2_000_000,
                ..constrained(None)
            },
            &knobs(),
        );
        assert_eq!(plan.bitrate_bps, 2_000_000);
        // Built at the controller's rate (a raw 2.1 M is the same rung): clean.
        s.note_built(2_100_000, (1920, 1200));
        assert!(s.after_tick(2_000_000).is_empty());
        assert_eq!(s.counts(), PlanDivergences::default());
        // The controller moved mid-pass: an epoch move, not a divergence...
        let epoch = s.epoch();
        assert!(s.after_tick(2_600_000).is_empty());
        assert_eq!(s.epoch(), epoch + 1);
        assert_eq!(s.plan().unwrap().bitrate_bps, 3_000_000);
        // ...and an encoder built at the OLD rung is the finding: the
        // controller re-rates it on its first tick (a second open on QSV).
        s.note_built(2_000_000, (1920, 1200));
        let first = s.after_tick(2_600_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "bitrate");
        assert_eq!(first[0].plan, "3000000");
        assert_eq!(first[0].inline, "2000000");
        assert_eq!(s.counts().bitrate, 1);
        // Built at the plan's rate but not its dims: a dims divergence.
        s.note_built(3_000_000, (1280, 800));
        let first = s.after_tick(3_000_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "dims");
        assert_eq!(
            s.counts(),
            PlanDivergences {
                bitrate: 1,
                dims: 1,
                ..Default::default()
            }
        );
        // A build is judged once.
        assert!(s.after_tick(3_000_000).is_empty());
        assert_eq!(s.counts().dims, 1);
    }

    /// The field's first read (2026-10-21, a hevc_qsv session in a stall
    /// cascade): the live encoder at the 20 M rung, a rate swap spawned when
    /// the controller said 10.7 M (the 12 M rung), the target at 5.4 M while
    /// it opened, adopted, then 2.74 M (the 3 M rung) on the next tick.
    fn qsv_cascade(s: &mut Shadow) -> Option<SwapSpawn> {
        s.produce(
            &PlanInputs {
                target_bps: 19_670_400,
                ..direct(43_000_000, 100)
            },
            &knobs(),
        );
        assert!(s.after_tick(10_708_885).is_empty());
        let spawned = s.swap_spawn();
        assert!(s.after_tick(5_396_362).is_empty());
        spawned
    }

    #[test]
    fn a_replacement_adopted_after_the_plan_moved_is_stale_not_a_divergence() {
        let mut s = Shadow::default();
        let spawned = qsv_cascade(&mut s);
        assert_eq!(spawned.map(|p| p.bitrate_bps), Some(12_000_000));
        assert_eq!(
            s.note_rate_swap_adopted(12_000_000, spawned),
            Some(StaleSwap {
                kind: "rate",
                built_bps: 12_000_000,
                spawned_bps: 12_000_000,
                now_bps: 6_000_000,
                spawned_dims: (1920, 1200),
                now_dims: (1920, 1200),
            })
        );
        // Not judged at the next tick: the re-rate is the plan's own movement.
        assert!(s.after_tick(2_744_302).is_empty());
        assert_eq!(s.counts(), PlanDivergences::default());
        assert_eq!(s.stale_swaps(), 1);
    }

    /// The same adoption judged the way M3a first shipped — at the
    /// controller's next tick, whatever the plan did meanwhile — is exactly
    /// the line the field logged.
    #[test]
    fn judged_at_the_next_tick_the_stale_adoption_reads_as_the_field_s_divergence() {
        let mut s = Shadow::default();
        qsv_cascade(&mut s);
        s.note_built(12_000_000, (1920, 1200));
        let first = s.after_tick(2_744_302);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "bitrate");
        assert_eq!(first[0].plan, "3000000");
        assert_eq!(first[0].inline, "12000000");
    }

    /// The field's driven read (2026-10-21, `hevc_vaapi`, direct): the target
    /// at 22.95 M (the 25 M rung) for 1600×900; a resolution move down spawned
    /// a dims replacement for 1050×590 at `min(last_ceiling, applied)` — the
    /// OLD frame's rate — the plan held through its 4 ms open, and the
    /// controller's first tick after adoption clamped to the smaller frame's
    /// ceiling, 9.87 M (the 8 M rung). The line the agent logged, exactly.
    #[test]
    fn a_dims_replacement_opened_at_the_old_frame_s_rate_is_a_divergence() {
        let mut s = Shadow::default();
        let plan = s.produce(
            &PlanInputs {
                target_bps: 22_950_000,
                ..direct(43_000_000, 100)
            },
            &knobs(),
        );
        assert_eq!(plan.bitrate_bps, 25_000_000);
        let spawned = s.swap_spawn();
        assert_eq!(
            s.note_dims_swap_adopted(25_000_000, plan.dims, spawned),
            None,
            "the plan held: not stale"
        );
        let first = s.after_tick(9_873_281);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "bitrate");
        assert_eq!(first[0].plan, "8000000");
        assert_eq!(first[0].inline, "25000000");
        assert_eq!(s.stale_swaps(), 0);
    }

    #[test]
    fn a_replacement_built_at_the_plan_that_held_is_clean() {
        let mut s = Shadow::default();
        let plan = s.produce(
            &PlanInputs {
                target_bps: 3_000_000,
                ..constrained(None)
            },
            &knobs(),
        );
        assert_eq!(s.note_rate_swap_adopted(3_000_000, s.swap_spawn()), None);
        assert!(s.after_tick(3_000_000).is_empty());
        assert_eq!(
            s.note_dims_swap_adopted(3_000_000, plan.dims, s.swap_spawn()),
            None
        );
        assert!(s.after_tick(3_000_000).is_empty());
        assert_eq!(s.counts(), PlanDivergences::default());
        assert_eq!(s.stale_swaps(), 0);
    }

    #[test]
    fn a_dims_replacement_is_judged_on_its_dims_and_a_rate_one_is_not() {
        let mut s = Shadow::default();
        let plan = s.produce(
            &PlanInputs {
                target_bps: 3_000_000,
                ..constrained(None)
            },
            &knobs(),
        );
        // A dims replacement built at other dims than the plan aims at.
        assert_eq!(
            s.note_dims_swap_adopted(3_000_000, (1280, 800), s.swap_spawn()),
            None
        );
        let first = s.after_tick(3_000_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].field, "dims");
        // A plan whose geometry moves while a dims replacement opens: stale,
        // and not judged at the tick.
        let spawned = s.swap_spawn();
        s.produce(
            &PlanInputs {
                target_bps: 3_000_000,
                dims: dims(2560, 1600),
                ..constrained(None)
            },
            &knobs(),
        );
        let stale = s.note_dims_swap_adopted(3_000_000, plan.dims, spawned);
        assert_eq!(stale.map(|x| x.kind), Some("dims"));
        assert!(s.after_tick(3_000_000).is_empty());
        // A RATE replacement's geometry is the live encoder's (M2's pin), not
        // its decision: moved geometry alone neither stales nor judges it.
        let rate_spawned = s.swap_spawn();
        s.produce(
            &PlanInputs {
                target_bps: 3_000_000,
                ..constrained(None)
            },
            &knobs(),
        );
        assert_eq!(s.note_rate_swap_adopted(3_000_000, rate_spawned), None);
        assert!(s.after_tick(3_000_000).is_empty());
        assert_eq!(s.counts().dims, 1);
        assert_eq!(s.stale_swaps(), 1);
    }

    #[test]
    fn a_replacement_spawned_before_any_plan_is_judged_as_held() {
        let mut s = Shadow::default();
        assert_eq!(s.swap_spawn(), None);
        // No plan at the tick either: nothing to judge against.
        assert_eq!(s.note_rate_swap_adopted(12_000_000, None), None);
        assert!(s.after_tick(12_000_000).is_empty());
        // A plan by the tick: judged there, as an inline open is.
        s.produce(
            &PlanInputs {
                target_bps: 3_000_000,
                ..constrained(None)
            },
            &knobs(),
        );
        assert_eq!(s.note_rate_swap_adopted(12_000_000, None), None);
        let first = s.after_tick(3_000_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].inline, "12000000");
        assert_eq!(s.stale_swaps(), 0);
    }

    #[test]
    fn a_stale_adoption_is_reported_once_and_counted_every_time() {
        let mut s = Shadow::default();
        let spawned = qsv_cascade(&mut s);
        assert!(s.note_rate_swap_adopted(12_000_000, spawned).is_some());
        assert!(s.note_rate_swap_adopted(12_000_000, spawned).is_none());
        assert_eq!(s.stale_swaps(), 2);
        assert!(s.after_tick(2_744_302).is_empty());
        assert_eq!(s.counts(), PlanDivergences::default());
    }

    /// The knobs the producer takes once are the numbers the per-frame readers
    /// return — whatever the environment says — and, at the built-in defaults,
    /// the shipped constants.
    #[test]
    fn the_knobs_resolve_to_what_the_per_frame_readers_read() {
        // Serialised against the tests that toggle the dial caps.
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let k = PlanKnobs::from_env();
        assert_eq!(k.relay_max_bps, crate::encode::relay_max_bps());
        assert_eq!(k.constrained_queue_ms, rate_profile::constrained_queue_ms());
        assert_eq!(
            k.constrained_queue_measured,
            crate::encode::constrained_queue_measured_enabled()
        );
        assert_eq!(k.direct_queue_ms, rate_profile::direct_queue_ms());
        assert_eq!(k.direct_hrd_pct, rate_profile::direct_hrd_pct());
        assert_eq!(k.refined_cap, crate::encode::idle_refine_cap_long_edge());
        for dial in [
            crate::encode::priority::BALANCED,
            crate::encode::priority::SHARPER,
            crate::encode::priority::SMOOTHER,
            42,
        ] {
            for constrained in [false, true] {
                assert_eq!(
                    crate::encode::priority_relay_cap_for(dial, constrained, &k.priority_caps),
                    crate::encode::priority_relay_cap(dial, constrained),
                    "dial {dial} constrained {constrained}"
                );
            }
        }
        // The budget the pump pre-resolves at start is the producer's.
        assert_eq!(
            rate_profile::constrained_queue_budget_bytes(k.relay_max_bps),
            rate_profile::constrained_queue_budget_bytes_at(
                k.relay_max_bps,
                k.constrained_queue_ms
            )
        );
        // And the pump's own hrd read is the producer's input.
        assert_eq!(
            rate_profile::hrd_pct_for("hevc_qsv", k.direct_hrd_pct),
            k.direct_hrd_pct
        );
    }
}
