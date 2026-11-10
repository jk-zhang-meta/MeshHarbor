// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P8b — the encode-policy module (item 2 of the P8 capture-truth
//! program): ONE place that decides the encode rung and the rate
//! ceiling, so the media pumps become executors.
//!
//! Why this exists (field history): every crisp-text investigation this
//! quarter ultimately needed the answer to "why is the stream at
//! 1024×640 right now?", and the answer was scattered across ~120 pump
//! lines that composed caps in one order on the frame path and a
//! *different* order in the idle-refine eligibility hook — which is how
//! the P7b mixed-dial bug shipped (the hook read the owner's dial while
//! the frame path applied the merged one). Both call sites now consume
//! the SAME [`plan_dims`] result, and the winning constraint is named
//! in [`DimsPlan::reason`] so the rung-change log finally explains
//! itself.
//!
//! Deliberately NOT here (yet): keyframe policy and fps/skip decisions
//! (event-driven, stage 2 of this item per the approved plan), and the
//! vp9 pump's bitrate formula (a real divergence — 0.20 bpp/s × quality
//! dial vs this module's 0.25 direct / 0.07 relay bpp/s × codec/chroma factors — kept
//! visible as "vp9 doesn't call [`rate_plan`]" instead of papered over).
//!
//! Everything here is pure over its inputs (the P5 merges and the
//! refine state are INPUTS, not lookups), so the whole decision table
//! unit-tests on the default build.

use crate::peer::{
    TargetResolution, aspect_preserved_target, effective_target_resolution, resolve_user_box,
};

/// Inputs to the resolution decision. All P5 floor-merges and the
/// idle-refine state are resolved by the CALLER — this module never
/// reaches into pipelines or atomics, which is what makes the frame
/// path and the eligibility hook provably consistent.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DimsInputs {
    pub native_w: u32,
    pub native_h: u32,
    /// Post-P5-merge controller resolution request.
    pub merged_target: TargetResolution,
    /// Post-P5-merge Priority cap (`priority_relay_cap` through
    /// `merged_priority_cap`). `None` = no dial caps this stream.
    pub merged_priority_cap: Option<u32>,
    /// FR-59 P5 — the slow-link profile's long-edge cap, resolved once at
    /// pump start from the pair's REMEMBERED rate. Merged with the dial cap
    /// by `min` (a dial that already asked for fewer pixels keeps them), but
    /// carried SEPARATELY so the rung can be attributed: before FR-70 P1 the
    /// two rode one slot and a profile cap logged as `priority-cap` — and
    /// the viewer, told "relay-limited", advised switching Priority to
    /// Sharper, which lifts a dial cap and does nothing against this one.
    pub slow_link_cap: Option<u32>,
    /// Idle-refine state: while refined the Priority cap is REPLACED by
    /// the refined rung (default `None` = full native).
    pub refined: bool,
    pub refined_cap: Option<u32>,
    /// Soft tier — fills in only when the (merged) controller request
    /// resolved to Native. FFmpeg pump: the encode-bound auto rung;
    /// vp9-444 pump: the SW-encode CPU cap.
    pub soft_cap: Option<u32>,
}

/// Which constraint decided the encode rung — the "why" every field
/// investigation has needed. Rendered into the rung-change log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RungReason {
    /// Nothing constrains the stream — native.
    Native,
    /// Native BECAUSE the idle refinement lifted a Priority cap that
    /// would otherwise clamp (crisp-at-rest in force).
    RefinedNative,
    /// The controller's own (merged) resolution pick.
    UserPick,
    /// The soft tier (encode-bound auto rung / vp9 SW cap).
    SoftCap,
    /// The (merged) Priority dial's relay/smoother cap.
    PriorityCap,
    /// FR-59 P5 — the slow-link profile's cap (the pair was REMEMBERED as
    /// slow at pump start). Named apart from `PriorityCap` because the
    /// remedies differ: a dial cap lifts with Priority → Sharper; this one
    /// lifts only on a later session, once the memory no longer says slow.
    SlowLinkCap,
    /// The refined rung's own long-edge bound
    /// (`idle_refine_max_edge` — refined, but not to full native).
    RefinedCap,
}

impl RungReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RungReason::Native => "native",
            RungReason::RefinedNative => "refined-native",
            RungReason::UserPick => "user-pick",
            RungReason::SoftCap => "soft-cap",
            RungReason::PriorityCap => "priority-cap",
            RungReason::SlowLinkCap => "slow-link-cap",
            RungReason::RefinedCap => "refined-cap",
        }
    }
}

/// The resolution decision + the two eligibility facts the idle-refine
/// hook needs — computed HERE so the hook and the frame path can never
/// diverge again (the P7b bug class).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DimsPlan {
    pub effective_target: TargetResolution,
    pub reason: RungReason,
    /// Would the UN-refined Priority cap clamp the native frame? (Refine
    /// eligibility term — deliberately ignores `refined`, because it
    /// asks "is there a cap worth lifting".)
    pub capped_below_native: bool,
    /// Did the (merged) controller request resolve to Native? An
    /// explicit pick is the user's — refine never overrides it.
    pub user_native: bool,
}

pub(crate) fn plan_dims(inp: &DimsInputs) -> DimsPlan {
    // FR-59 P5 / FR-70 P1 — the dial cap and the slow-link cap merge by
    // `min` exactly as they did when the caller pre-merged them into one
    // slot; they are only kept apart here so the winner can be NAMED.
    let merged_cap = match (inp.merged_priority_cap, inp.slow_link_cap) {
        (Some(dial), Some(slow)) => Some(dial.min(slow)),
        (dial, slow) => dial.or(slow),
    };
    // The slow-link cap is the binding one when it is the smaller (a tie
    // reads as the profile's: the dial's remedy would not lift it).
    let slow_link_binds = matches!(
        (inp.merged_priority_cap, inp.slow_link_cap),
        (None, Some(_))
    ) || matches!(
        (inp.merged_priority_cap, inp.slow_link_cap),
        (Some(dial), Some(slow)) if slow <= dial
    );
    let hard_cap = if inp.refined {
        inp.refined_cap
    } else {
        merged_cap
    };
    let effective = effective_target_resolution(
        inp.merged_target,
        inp.native_w,
        inp.native_h,
        hard_cap,
        inp.soft_cap,
    );
    let capped_below_native = merged_cap.is_some_and(|c| inp.native_w.max(inp.native_h) > c);
    let user_boxed = resolve_user_box(inp.merged_target, inp.native_w, inp.native_h);
    let user_native = matches!(user_boxed, TargetResolution::Native);

    let reason = match effective {
        TargetResolution::Native => {
            if inp.refined && capped_below_native {
                RungReason::RefinedNative
            } else {
                RungReason::Native
            }
        }
        fixed => {
            if user_boxed == fixed {
                RungReason::UserPick
            } else {
                let hard_dims = hard_cap
                    .map(|c| aspect_preserved_target(inp.native_w, inp.native_h, c))
                    .map(|(w, h)| TargetResolution::Fixed {
                        width: w,
                        height: h,
                    });
                if hard_dims == Some(fixed) {
                    if inp.refined {
                        RungReason::RefinedCap
                    } else if slow_link_binds {
                        RungReason::SlowLinkCap
                    } else {
                        RungReason::PriorityCap
                    }
                } else {
                    RungReason::SoftCap
                }
            }
        }
    };

    DimsPlan {
        effective_target: effective,
        reason,
        capped_below_native,
        user_native,
    }
}

/// The rate/quality half for the FFmpeg pump: the maxrate ceiling chain
/// (codec factor × chroma factor × bpp-scaled band × relay clamp ×
/// encode-pressure factor, floored at `MIN_BITRATE_BPS`) and the SIGNED
/// CQ bias (positive = sharper, negative = softer — see
/// `rate_profile::apply_cq_bias`). Takes the ACTUAL post-downscale
/// encode dims — `apply_target_resolution` can pass a frame through
/// untouched (non-BGRA, degenerate targets), and the ceiling must
/// follow what is truly encoded, not what was planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RatePlan {
    pub ceiling_bps: u32,
    pub cq_bias: i32,
}

/// FR-70 M3a.2 — the rate a make-before-break dims replacement opens at: the
/// controller's applied rate (before it has applied one, the remembered seed),
/// never above the ceiling of the dims the replacement is opened FOR. Using the
/// live frame's ceiling instead opened a move DOWN at a rate the controller
/// clamped on its first tick — a second open on a rebuild-bound backend.
pub(crate) fn replacement_open_bps(
    target_ceiling_bps: u32,
    applied_bps: u32,
    seed_bps: Option<u32>,
) -> u32 {
    match applied_bps {
        0 => seed_bps.map_or(target_ceiling_bps, |s| target_ceiling_bps.min(s)),
        applied => target_ceiling_bps.min(applied),
    }
}

/// `user_pick`: the rung IS the controller's explicit resolution pick
/// (`RungReason::UserPick`) — the constrained relief must not soften a
/// resolution the user chose on purpose (they may be reading at it).
/// `dial_pct`: the rc.445 per-dial ceiling factor
/// (`encode::dial_rate_factor_pct` — Smoother 70 / Balanced 85 /
/// Sharper 100), the rebuild-free replacement for the dial dims-caps: a
/// lower ceiling makes the HRD raise QP during motion continuously, so
/// motion frames shrink without any encoder rebuild, and a settled
/// desktop (which never reaches the ceiling) keeps full CQ quality.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rate_plan(
    encode_w: u32,
    encode_h: u32,
    native_w: u32,
    native_h: u32,
    target_fps: u32,
    constrained: bool,
    codec_label: &str,
    chroma444: bool,
    encode_factor: f32,
    user_pick: bool,
    dial_pct: usize,
) -> RatePlan {
    let rate_factor_pct = crate::encode::rate_profile::codec_rate_factor_pct(codec_label)
        * crate::encode::rate_profile::chroma_rate_factor_pct(codec_label, chroma444)
        / 100;
    let base_ceiling = crate::encode::rate_profile::ffmpeg_maxrate_bps_scaled(
        encode_w,
        encode_h,
        target_fps,
        constrained,
        rate_factor_pct,
    ) as u32;
    let base_ceiling =
        ((base_ceiling as u64).saturating_mul(dial_pct.clamp(30, 100) as u64) / 100) as u32;
    let ceiling_bps =
        (((base_ceiling as f32) * encode_factor) as u32).max(crate::encode::MIN_BITRATE_BPS);
    // The bias forks on transport. Unconstrained: the P7 sharpening
    // ladder — the [3, 12] Mbps maxrate floor really is headroom there,
    // spend it on rung text. Constrained: the relay clamp IS the
    // constraint, so the same ladder is backwards — it grew the rung's
    // motion frames past what the pipe drains per frame interval (field
    // 2026-08-21: CQ-18 deltas of 25-40 KB ≈ 100-160 ms serialization
    // each on a ~2 Mbps relay ⇒ bursty arrival ⇒ viewer flags decode
    // pressure ⇒ divisor parks at 3 ⇒ "9 fps, not fully smooth").
    // Below native on a constrained path the session is by definition in
    // its motion phase (refine lifts to native at rest), so SOFTEN
    // instead — smaller frames arrive steadily and the viewer-rate loop
    // recovers. Native encode keeps bias 0: the at-rest polish quality
    // is untouched. An explicit user pick is exempt (they chose it).
    let below_native = {
        let enc = encode_w as u64 * encode_h as u64;
        let native = native_w as u64 * native_h as u64;
        enc != 0 && native != 0 && enc < native
    };
    let cq_bias = if !constrained {
        crate::encode::rate_profile::scale_cq_bias(
            encode_w,
            encode_h,
            native_w,
            native_h,
            crate::encode::rate_profile::scale_cq_boost_steps(),
        ) as i32
    } else if below_native && !user_pick {
        -crate::encode::rate_profile::constrained_cq_relief()
    } else {
        0
    };
    RatePlan {
        ceiling_bps,
        cq_bias,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NW: u32 = 1920;
    const NH: u32 = 1200;

    /// FR-70 M3a.2 — the field's driven read (2026-10-21, `hevc_vaapi`,
    /// direct, 1600×900 native, a user-picked move down to 1050×590): the old
    /// frame's ceiling is the heartbeat's `target_bps` (22 950 000, the 25 M
    /// rung) and the new frame's is exactly the target the controller set on
    /// its first tick after adoption (9 873 281, the 8 M rung). A replacement
    /// opened at the old one was re-rated at once; opened at its own dims'
    /// ceiling, it starts where the controller will put it.
    #[test]
    fn a_dims_replacement_opens_at_the_ceiling_of_the_dims_it_is_opened_for() {
        let ceiling =
            |w, h| rate_plan(w, h, 1600, 900, 60, false, "HEVC", false, 1.0, true, 85).ceiling_bps;
        let (old, new) = (ceiling(1600, 900), ceiling(1050, 590));
        assert_eq!((old, new), (22_950_000, 9_873_281));
        let ladder = crate::encode::aimd::coarsen_bitrate;
        // Before: the old frame's ceiling — the field's inline 25 M.
        assert_eq!(
            ladder(replacement_open_bps(old, 22_950_000, None)),
            25_000_000
        );
        // After: the target dims' ceiling — the controller's 8 M.
        assert_eq!(
            ladder(replacement_open_bps(new, 22_950_000, None)),
            8_000_000
        );
        // Going UP the ceiling rises; the applied rate stands, as before.
        assert_eq!(replacement_open_bps(old, 8_000_000, None), 8_000_000);
    }

    #[test]
    fn a_replacement_before_any_applied_rate_opens_at_the_seed_under_the_ceiling() {
        assert_eq!(replacement_open_bps(9_000_000, 0, None), 9_000_000);
        assert_eq!(
            replacement_open_bps(9_000_000, 0, Some(4_000_000)),
            4_000_000
        );
        assert_eq!(
            replacement_open_bps(9_000_000, 0, Some(12_000_000)),
            9_000_000
        );
    }

    fn base() -> DimsInputs {
        DimsInputs {
            native_w: NW,
            native_h: NH,
            merged_target: TargetResolution::Native,
            merged_priority_cap: None,
            slow_link_cap: None,
            refined: false,
            refined_cap: None,
            soft_cap: None,
        }
    }

    // ── plan_dims: the decision table ──────────────────────────────────

    /// FR-70 P1 — the field case (CORPLAP-1, 2026-09-04): the dial caps are
    /// off by default, so the ONLY cap was the slow-link profile's 1280,
    /// and it logged as `priority-cap`. It must name itself.
    #[test]
    fn slow_link_cap_clamps_and_names_itself() {
        let p = plan_dims(&DimsInputs {
            slow_link_cap: Some(1280),
            ..base()
        });
        let TargetResolution::Fixed { width, height } = p.effective_target else {
            panic!("must clamp");
        };
        assert_eq!((width, height), aspect_preserved_target(NW, NH, 1280));
        assert_eq!(p.reason, RungReason::SlowLinkCap);
        assert_eq!(p.reason.as_str(), "slow-link-cap");
        assert!(p.capped_below_native, "there is a cap worth lifting");
        assert!(p.user_native);
    }

    /// The two caps merge by `min`, as they did in one slot — and the
    /// SMALLER one is the one named, because that is the one whose remedy
    /// the operator needs.
    #[test]
    fn the_smaller_of_dial_and_slow_link_cap_binds_and_is_named() {
        let dial_wins = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1024),
            slow_link_cap: Some(1280),
            ..base()
        });
        let TargetResolution::Fixed { width, .. } = dial_wins.effective_target else {
            panic!()
        };
        assert_eq!(width, aspect_preserved_target(NW, NH, 1024).0);
        assert_eq!(dial_wins.reason, RungReason::PriorityCap);

        let slow_wins = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1600),
            slow_link_cap: Some(1280),
            ..base()
        });
        let TargetResolution::Fixed { width, .. } = slow_wins.effective_target else {
            panic!()
        };
        assert_eq!(width, aspect_preserved_target(NW, NH, 1280).0);
        assert_eq!(slow_wins.reason, RungReason::SlowLinkCap);

        // A tie is the profile's: Sharper would not lift it.
        let tie = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1280),
            slow_link_cap: Some(1280),
            ..base()
        });
        assert_eq!(tie.reason, RungReason::SlowLinkCap);
    }

    /// An explicit pick still wins over the profile cap (the P5 promise),
    /// and a profile cap at or above native clamps nothing.
    #[test]
    fn slow_link_cap_respects_a_user_pick_and_never_upscales() {
        let pick = plan_dims(&DimsInputs {
            merged_target: TargetResolution::Fixed {
                width: 960,
                height: 600,
            },
            slow_link_cap: Some(1280),
            ..base()
        });
        assert_eq!(pick.reason, RungReason::UserPick);
        assert!(!pick.user_native);

        let wide = plan_dims(&DimsInputs {
            slow_link_cap: Some(1920),
            ..base()
        });
        assert_eq!(wide.effective_target, TargetResolution::Native);
        assert_eq!(wide.reason, RungReason::Native);
        assert!(!wide.capped_below_native);
    }

    #[test]
    fn unconstrained_native_is_native() {
        let p = plan_dims(&base());
        assert_eq!(p.effective_target, TargetResolution::Native);
        assert_eq!(p.reason, RungReason::Native);
        assert!(!p.capped_below_native);
        assert!(p.user_native);
    }

    #[test]
    fn priority_cap_clamps_and_names_itself() {
        let p = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1024),
            ..base()
        });
        let TargetResolution::Fixed { width, height } = p.effective_target else {
            panic!("must clamp");
        };
        assert_eq!((width, height), aspect_preserved_target(NW, NH, 1024));
        assert_eq!(p.reason, RungReason::PriorityCap);
        assert!(p.capped_below_native);
        assert!(p.user_native);
    }

    #[test]
    fn refined_lifts_the_priority_cap_to_native() {
        let p = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1024),
            refined: true,
            refined_cap: None,
            ..base()
        });
        assert_eq!(p.effective_target, TargetResolution::Native);
        assert_eq!(p.reason, RungReason::RefinedNative);
        // Eligibility fact stays true — there IS a cap worth holding
        // lifted; this is what keeps the keepalive hook honest.
        assert!(p.capped_below_native);
    }

    #[test]
    fn refined_with_max_edge_names_the_refined_cap() {
        let p = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1024),
            refined: true,
            refined_cap: Some(1600),
            ..base()
        });
        let TargetResolution::Fixed { width, height } = p.effective_target else {
            panic!("refined max-edge must clamp");
        };
        assert_eq!((width, height), aspect_preserved_target(NW, NH, 1600));
        assert_eq!(p.reason, RungReason::RefinedCap);
    }

    #[test]
    fn explicit_user_pick_wins_and_blocks_refine() {
        // 960×600 explicit pick: smaller than the 1280 cap ⇒ kept.
        let p = plan_dims(&DimsInputs {
            merged_target: TargetResolution::Fixed {
                width: 960,
                height: 600,
            },
            merged_priority_cap: Some(1280),
            ..base()
        });
        assert_eq!(p.reason, RungReason::UserPick);
        assert!(!p.user_native, "explicit pick must block refine");
        let TargetResolution::Fixed { width, .. } = p.effective_target else {
            panic!()
        };
        assert_eq!(width, 960);
    }

    #[test]
    fn soft_cap_fills_native_and_names_itself() {
        let p = plan_dims(&DimsInputs {
            soft_cap: Some(1600),
            ..base()
        });
        assert_eq!(p.reason, RungReason::SoftCap);
        let TargetResolution::Fixed { width, height } = p.effective_target else {
            panic!()
        };
        assert_eq!((width, height), aspect_preserved_target(NW, NH, 1600));
        // No priority cap ⇒ nothing for refine to lift.
        assert!(!p.capped_below_native);
    }

    #[test]
    fn hard_cap_beats_soft_cap_and_is_named() {
        let p = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1024),
            soft_cap: Some(1600),
            ..base()
        });
        assert_eq!(p.reason, RungReason::PriorityCap);
        let TargetResolution::Fixed { width, height } = p.effective_target else {
            panic!()
        };
        assert_eq!((width, height), aspect_preserved_target(NW, NH, 1024));
    }

    #[test]
    fn cap_at_or_above_native_does_not_clamp() {
        let p = plan_dims(&DimsInputs {
            merged_priority_cap: Some(1920),
            ..base()
        });
        assert_eq!(p.effective_target, TargetResolution::Native);
        assert_eq!(p.reason, RungReason::Native);
        assert!(!p.capped_below_native);
    }

    // ── rate_plan: the ceiling composition, pinned to field values ────

    #[test]
    fn ceiling_composition_pins_the_field_values() {
        // Env hygiene: these read node_env (FFMPEG_MAXRATE_KBPS,
        // RATE_FACTOR_*, RELAY_MAX_KBPS, SCALE_CQ_BOOST) — serialise
        // against the sibling env-mutating tests.
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // HEVC 4:2:0 on the relay at the Smoother rung — the exact
        // ceiling_bps=3000000 the winhost-b field log shows. Constrained ⇒
        // the sharpening ladder is OFF and the motion relief SOFTENS
        // (field 2026-08-21: the CQ-18 rung was the 9 fps equilibrium).
        let p = rate_plan(
            1024, 640, 1920, 1200, 30, true, "HEVC", false, 1.0, false, 100,
        );
        assert_eq!(p.ceiling_bps, 3_000_000);
        assert_eq!(p.cq_bias, -4);

        // The same rung as an explicit controller pick is exempt from
        // the relief — the user chose to live at it.
        let p = rate_plan(
            1024, 640, 1920, 1200, 30, true, "HEVC", false, 1.0, true, 100,
        );
        assert_eq!(p.cq_bias, 0);

        // Same rung, native encode (refined): factor band 125 % ⇒
        // clamp floor 3.75 M, raw 1920×1200×30×0.07×1.25 ≈ 6.05 M —
        // within band; relay still clamps to 3 M; cq_bias 0 at native
        // (the at-rest polish quality is untouched by the relief).
        let p = rate_plan(
            1920, 1200, 1920, 1200, 30, true, "HEVC", false, 1.0, false, 100,
        );
        assert_eq!(p.ceiling_bps, 3_000_000);
        assert_eq!(p.cq_bias, 0);

        // Direct HEVC at native 60 fps (FR-74 P1): raw 34.56 M × 1.25 =
        // 43.2 M, inside the scaled [3.75, 60] M band, no relay clamp.
        let p = rate_plan(
            1920, 1200, 1920, 1200, 60, false, "HEVC", false, 1.0, false, 100,
        );
        assert_eq!(p.ceiling_bps, 43_200_000);

        // Direct at the deep rung keeps the P7 sharpening ladder.
        let p = rate_plan(
            1024, 640, 1920, 1200, 60, false, "HEVC", false, 1.0, false, 100,
        );
        assert_eq!(p.cq_bias, 4);

        // Chroma 4:4:4 composes: 125 × 150 / 100 = 187 %; relay clamps.
        let p = rate_plan(
            1024, 640, 1920, 1200, 30, true, "HEVC", true, 1.0, false, 100,
        );
        assert_eq!(p.ceiling_bps, 3_000_000);

        // Encode-pressure factor scales below the clamp, floored at
        // MIN_BITRATE_BPS.
        let p = rate_plan(
            1024, 640, 1920, 1200, 30, true, "HEVC", false, 0.5, false, 100,
        );
        assert_eq!(p.ceiling_bps, 1_500_000);
        let p = rate_plan(
            1024, 640, 1920, 1200, 30, true, "HEVC", false, 0.01, false, 100,
        );
        assert_eq!(p.ceiling_bps, crate::encode::MIN_BITRATE_BPS);

        // rc.445 — the dial ceiling factor scales the (clamped) ceiling:
        // constrained Smoother = 3 M × 70 % = 2.1 M; Balanced 85 % = 2.55 M;
        // the MIN_BITRATE floor still holds underneath.
        let p = rate_plan(
            1920, 1200, 1920, 1200, 30, true, "HEVC", false, 1.0, false, 70,
        );
        assert_eq!(p.ceiling_bps, 2_100_000);
        let p = rate_plan(
            1920, 1200, 1920, 1200, 30, true, "HEVC", false, 1.0, false, 85,
        );
        assert_eq!(p.ceiling_bps, 2_550_000);
        // Direct Smoother: 43.2 M × 70 % = 30.24 M — mild squeeze, no clamp.
        let p = rate_plan(
            1920, 1200, 1920, 1200, 60, false, "HEVC", false, 1.0, false, 70,
        );
        assert_eq!(p.ceiling_bps, 30_240_000);
    }

    /// P8c invariant (accidental loop 2, refine→dims→ceiling): idle
    /// refine lifting the encode dims to native must never raise a
    /// CONSTRAINED path's ceiling past the relay clamp — the clamp
    /// flattens area growth, so refine sharpens pixels without
    /// inflating what a relay link is asked to carry.
    #[test]
    fn constrained_ceiling_is_flat_across_refine_dim_growth() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let capped = rate_plan(
            1024, 640, 2560, 1600, 30, true, "HEVC", false, 1.0, false, 100,
        );
        let refined = rate_plan(
            2560, 1600, 2560, 1600, 30, true, "HEVC", false, 1.0, false, 100,
        );
        assert_eq!(
            capped.ceiling_bps, refined.ceiling_bps,
            "refine raised the relay ceiling"
        );
        // Same invariant at the larger 4:4:4 factor product.
        let capped = rate_plan(
            1024, 640, 2560, 1600, 30, true, "HEVC", true, 1.0, false, 100,
        );
        let refined = rate_plan(
            2560, 1600, 2560, 1600, 30, true, "HEVC", true, 1.0, false, 100,
        );
        assert_eq!(capped.ceiling_bps, refined.ceiling_bps);
    }
}
