// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P8b stage 2 — the keyframe-force policy machine.
//!
//! The pending-force lifecycle used to live as five loose locals in
//! each DC pump (`kf_pending_since`, `last_force_rebuild`,
//! `kf_backstop_logged`, `resync_pending`, `was_locked_last_iter`),
//! with the ordering and the two field-regression guards (the rc.234
//! metronome, the rc.217 rebuild churn) enforced only by comment.
//! [`KeyframeGate`] owns that state behind intent-named transitions;
//! the pumps stay the executors (they hold the encoder and write the
//! logs — the gate never does either). Zero behavior change: every
//! method is a 1:1 relocation of a pump touch point, and the
//! regression guards are locked by the tests at the bottom instead of
//! tribal knowledge.
//!
//! What deliberately did NOT move:
//! - the settle keyframe (`rate_profile::SettleKeyframeGate`) — already
//!   its own machine;
//! - the VP9 pump's lock handling — it substitutes an overlay FRAME and
//!   requests the IDR through the shared `keyframe_requested` atomic (a
//!   different shape from the ffmpeg pump's direct lock-edge force);
//! - the `keyframe_requested` atomic itself — shared session infra, the
//!   gate only sees its consumed value;
//! - the VP9 scene-change detector — packet-size heuristics, vp9-only.

use std::time::{Duration, Instant};

/// Unanswered-force retry window (rc.234 — was the rc.214 "freeze-wedge
/// backstop"). If a forced keyframe (`pending_since` armed) has gone
/// unanswered for this long, re-issue the force — insurance against a force
/// swallowed across an encoder-rebuild boundary. Honouring encoders answer
/// in <100 ms so this fires ~never; the force-ignored rebuild fallback
/// ([`KEYFRAME_FORCE_REBUILD_AFTER`]) remains the real net for vp9_qsv.
///
/// HISTORY — the rc.214 form fired UNCONDITIONALLY whenever 4 s passed
/// without a key-flagged frame while frames flowed. With the 60 ms idle
/// keepalive frames ALWAYS flow, so the "wedge insurance" was in practice a
/// 4-second IDR METRONOME on every DC session — and each metronome IDR
/// QP-starves under the maxrate cap, painting the field-reported "text
/// blurs every ~3 s then re-sharpens" pulse (2026-07-25, DEVBOX viewing
/// WINHOST-A/REGAL) on every codec. Wedge safety is preserved without the
/// metronome: rc:keyframe rides the RELIABLE control DC (can't be lost in
/// transit), every force arms `pending_since`, this retry covers a
/// swallowed force, and the rebuild fallback covers force-ignoring
/// encoders. Locked by `backstop_is_never_a_metronome`.
pub const KEYFRAME_BACKSTOP: Duration = Duration::from_secs(4);

/// Force-ignored fallback (2026-07-24 field, the 14.5 s freeze): `vp9_qsv`
/// ignores runtime keyframe forcing (`pict_type=I` on the input frame — the
/// rc.98 class of bug; NVENC needed `forced-idr=1`, `hevc_qsv` honours the
/// pict_type, `vp9_qsv` evidently does neither), so a browser resync request
/// AND the [`KEYFRAME_BACKSTOP`] both fire uselessly: no key-FLAGGED packet
/// ever comes out, the browser's keyframe gate keeps dropping every delta
/// (field trace: 296 deltas dropped over 14.5 s while the browser begged at
/// 4 req/s), and recovery only happened when an AIMD bitrate move rebuilt the
/// encoder — whose FIRST frame is a guaranteed flagged IDR. This fallback
/// makes that recovery deterministic: if a forced keyframe hasn't produced a
/// key-flagged packet within this window, REBUILD the encoder. Honouring
/// encoders (nvenc, hevc_qsv) deliver the flagged key in <100 ms and never
/// trip this; only force-ignoring encoders pay the ~10-50 ms rebuild.
///
/// Mirrored in the libvpx VP9-444 pump for parity — libvpx force flags are
/// synchronous (the next encode IS the keyframe) so it should never fire
/// there; the mirror just guarantees NO pump can wedge on an unanswered
/// force, whatever encoder quirk ships next.
/// rc.219 — widened 1 s → 2.5 s. Field-proven (rc.217 logs): vp9_qsv accepts
/// `forced_idr=1` but STILL never key-flags a runtime-forced frame — every
/// resync waited the full window and paid a rebuild (at the cooldown rate, a
/// hiccup every ~10 s under sustained struggle). rc.219 instead gives
/// vp9_qsv a SHORT natural GOP (60 frames — see
/// `encode::ffmpeg::VP9_QSV_KEYFRAME_INTERVAL`), so a natural key normally
/// answers the force well inside this window and the rebuild becomes a true
/// last resort. Honouring encoders answer in <100 ms, so the wider window
/// costs them nothing.
///
/// rc.234 — widened again 2.5 s → 6.5 s: the 60-frame vp9_qsv GOP is counted
/// in ENCODED frames, and the viewer-rate skip divisor stretches it — at the
/// 12 fps shed floor a natural key is up to ~5 s away, so 2.5 s ALWAYS
/// rebuilt before the natural key could answer (field 2026-07-25, REGAL:
/// "rebuilding to emit a guarantee" cycling every ~11-13 s with
/// pending_ms≈2500 — each rebuild an IDR + rate-control cold start = a blur
/// pulse). 6.5 s lets the natural key win; honouring encoders still answer
/// in <100 ms and never reach it.
pub const KEYFRAME_FORCE_REBUILD_AFTER: Duration = Duration::from_millis(6500);

/// rc.217 churn guard for the force-ignored rebuild. Field regression
/// (2026-07-24, vp9_qsv): every viewer backlog event requested an IDR, the
/// ignored force tripped a rebuild ~1 s later, and the rebuild's own big IDR
/// re-spiked the viewer's decoder → another backlog → another rebuild —
/// "freezes every ~2 s", worse than the original bug. At most ONE forced
/// rebuild per this window; while cooling down an unanswered force is
/// abandoned (the next request re-arms). The real fix is `forced_idr=1` on
/// the qsv option set (encoder.rs) making forces work without any rebuild;
/// this bounds the blast radius wherever that still fails. Locked by
/// `rebuild_cooldown_bounds_churn`.
pub const KEYFRAME_FORCE_REBUILD_COOLDOWN: Duration = Duration::from_secs(10);

/// The force-ignored fallback's verdict for this iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuildVerdict {
    /// No force outstanding, or it hasn't aged past the window.
    NotDue,
    /// Rebuild the encoder NOW (the fresh encoder's first frame is a
    /// guaranteed key-flagged IDR). The pending force is consumed.
    Rebuild {
        /// How long the force went unanswered — for the pump's warn log.
        pending_ms: u64,
    },
    /// The force aged out but a rebuild happened within the cooldown —
    /// the force is ABANDONED (the next request re-arms). rc.217.
    CoolingDown,
}

/// One per pump instance. See the module docs.
pub struct KeyframeGate {
    /// When the oldest unanswered forced keyframe was requested.
    pending_since: Option<Instant>,
    /// Last force-ignored rebuild — the churn-guard clock.
    last_force_rebuild: Option<Instant>,
    /// One-shot (per pump life) marker for the backstop-retry log.
    backstop_logged: bool,
    /// A frame was shed at try_send-Full; the next frame that DOES
    /// enqueue schedules a resync keyframe (ffmpeg pump only).
    resync_pending: bool,
    /// Last observed lock state, for the edge detector.
    was_locked: bool,
}

impl KeyframeGate {
    pub fn new(initially_locked: bool) -> Self {
        Self {
            pending_since: None,
            last_force_rebuild: None,
            backstop_logged: false,
            resync_pending: false,
            was_locked: initially_locked,
        }
    }

    /// Lock-state edge detector (ffmpeg pump): true on ANY transition —
    /// the browser needs a clean refresh when the lock overlay paints or
    /// clears. The edge is CONSUMED even if the pump has no encoder to
    /// force this iteration (preserved pre-extraction semantics: a
    /// transition landing mid-rebuild loses its IDR; the viewer-request
    /// path covers the visible cases).
    pub fn lock_edge(&mut self, locked_now: bool) -> bool {
        let changed = locked_now != self.was_locked;
        self.was_locked = locked_now;
        changed
    }

    /// Unanswered-force retry — due ONLY while a force is armed (rc.234:
    /// gated on a real resync need, NOT wall-clock since the last IDR).
    pub fn backstop_due(&self, now: Instant) -> bool {
        self.pending_since
            .is_some_and(|t| now.duration_since(t) >= KEYFRAME_BACKSTOP)
    }

    /// One-shot per pump life: whether the backstop-retry log should be
    /// written this time.
    pub fn take_backstop_log(&mut self) -> bool {
        if self.backstop_logged {
            false
        } else {
            self.backstop_logged = true;
            true
        }
    }

    /// Arm the pending clock on the first unanswered force. Keeps the
    /// clock's ORIGIN (an already-armed clock is never reset), so the
    /// backstop retry never delays the rebuild fallback.
    pub fn arm_if_forced(&mut self, forced_this_iter: bool, now: Instant) {
        if forced_this_iter && self.pending_since.is_none() {
            self.pending_since = Some(now);
        }
    }

    /// Force-ignored fallback. On `Rebuild` the caller drops its encoder
    /// (dims too) so the next iteration reconstructs; either due branch
    /// consumes the pending force — the next request re-arms (rc.217:
    /// prevents the rebuild→IDR-burst→backlog→request→rebuild loop).
    pub fn rebuild_fallback(&mut self, now: Instant) -> RebuildVerdict {
        let Some(t) = self.pending_since else {
            return RebuildVerdict::NotDue;
        };
        let pending = now.duration_since(t);
        if pending < KEYFRAME_FORCE_REBUILD_AFTER {
            return RebuildVerdict::NotDue;
        }
        self.pending_since = None;
        let cooled = self
            .last_force_rebuild
            .is_none_or(|r| now.duration_since(r) >= KEYFRAME_FORCE_REBUILD_COOLDOWN);
        if cooled {
            self.last_force_rebuild = Some(now);
            RebuildVerdict::Rebuild {
                pending_ms: pending.as_millis() as u64,
            }
        } else {
            RebuildVerdict::CoolingDown
        }
    }

    /// A key-FLAGGED packet actually entered the send queue — every
    /// pending force is answered (backstop and rebuild stand down).
    pub fn on_key_frame_queued(&mut self) {
        self.pending_since = None;
    }

    /// A frame was shed at try_send-Full (ffmpeg pump): the next frame
    /// through schedules a resync keyframe so the browser recovers the
    /// deltas it missed during congestion.
    pub fn note_resync_needed(&mut self) {
        self.resync_pending = true;
    }

    /// Consume the resync request (at the first successful enqueue).
    pub fn take_resync(&mut self) -> bool {
        std::mem::take(&mut self.resync_pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> KeyframeGate {
        KeyframeGate::new(false)
    }

    /// rc.234 regression lock: with no force outstanding the backstop
    /// NEVER fires, no matter how long since the last IDR — the old
    /// unconditional form was a 4 s IDR metronome that QP-starved text
    /// on every codec.
    #[test]
    fn backstop_is_never_a_metronome() {
        let t0 = Instant::now();
        let g = gate();
        assert!(!g.backstop_due(t0 + Duration::from_secs(100)));
    }

    #[test]
    fn backstop_fires_only_while_armed_and_logs_once() {
        let t0 = Instant::now();
        let mut g = gate();
        g.arm_if_forced(true, t0);
        assert!(!g.backstop_due(t0 + Duration::from_secs(3)));
        assert!(g.backstop_due(t0 + Duration::from_secs(4)));
        assert!(g.take_backstop_log(), "first retry logs");
        assert!(!g.take_backstop_log(), "later retries stay quiet");
        // Answered — the retry stands down.
        g.on_key_frame_queued();
        assert!(!g.backstop_due(t0 + Duration::from_secs(60)));
    }

    /// The pending clock keeps its ORIGIN: re-forcing while armed never
    /// pushes the rebuild fallback out.
    #[test]
    fn arm_keeps_the_pending_origin() {
        let t0 = Instant::now();
        let mut g = gate();
        g.arm_if_forced(true, t0);
        g.arm_if_forced(true, t0 + Duration::from_secs(3));
        let verdict = g.rebuild_fallback(t0 + KEYFRAME_FORCE_REBUILD_AFTER);
        assert!(
            matches!(verdict, RebuildVerdict::Rebuild { pending_ms } if pending_ms >= 6500),
            "rebuild must be measured from the FIRST force, got {verdict:?}"
        );
    }

    /// rc.217 regression lock: at most one forced rebuild per cooldown
    /// window; while cooling, an aged force is abandoned (the next
    /// request re-arms) instead of queueing another rebuild.
    #[test]
    fn rebuild_cooldown_bounds_churn() {
        let t0 = Instant::now();
        let mut g = gate();
        g.arm_if_forced(true, t0);
        let first = g.rebuild_fallback(t0 + KEYFRAME_FORCE_REBUILD_AFTER);
        assert!(matches!(first, RebuildVerdict::Rebuild { .. }));

        // A new force immediately after — ages out during the cooldown.
        let t1 = t0 + KEYFRAME_FORCE_REBUILD_AFTER + Duration::from_millis(100);
        g.arm_if_forced(true, t1);
        let during = g.rebuild_fallback(t1 + KEYFRAME_FORCE_REBUILD_AFTER);
        assert_eq!(during, RebuildVerdict::CoolingDown);
        // The abandoned force is GONE — nothing fires later on its own.
        assert_eq!(
            g.rebuild_fallback(t1 + Duration::from_secs(60)),
            RebuildVerdict::NotDue
        );

        // Past the cooldown a fresh force rebuilds again.
        let t2 = t1 + Duration::from_secs(30);
        g.arm_if_forced(true, t2);
        assert!(matches!(
            g.rebuild_fallback(t2 + KEYFRAME_FORCE_REBUILD_AFTER),
            RebuildVerdict::Rebuild { .. }
        ));
    }

    #[test]
    fn key_frame_queued_stands_everything_down() {
        let t0 = Instant::now();
        let mut g = gate();
        g.arm_if_forced(true, t0);
        g.on_key_frame_queued();
        assert_eq!(
            g.rebuild_fallback(t0 + Duration::from_secs(60)),
            RebuildVerdict::NotDue
        );
    }

    #[test]
    fn resync_is_noted_and_consumed_once() {
        let mut g = gate();
        assert!(!g.take_resync());
        g.note_resync_needed();
        g.note_resync_needed();
        assert!(g.take_resync());
        assert!(!g.take_resync(), "consumed — one resync IDR per drop burst");
    }

    #[test]
    fn lock_edge_fires_on_both_transitions_only_on_change() {
        let mut g = KeyframeGate::new(false);
        assert!(!g.lock_edge(false));
        assert!(g.lock_edge(true), "lock transition");
        assert!(!g.lock_edge(true), "steady state is quiet");
        assert!(g.lock_edge(false), "unlock transition");
        assert!(!g.lock_edge(false));
    }
}
