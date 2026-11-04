// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-29 P1 — "did anything change?" for the X11 capture path.
//!
//! `scrap` on Linux is XShm, and `Capturer::frame()` performs a full-screen
//! `GetImage` on every call. Unlike Windows DXGI Desktop Duplication — which
//! answers `WouldBlock` when the desktop is unchanged — XShm has no
//! "nothing changed" signal at all, so an idle desktop pays the full readback
//! at the target frame rate forever. Measured on a 1080p Fedora Asahi host:
//! ~20 ms per frame and ~50 % of a CPU core to transmit a static screen.
//!
//! The pump already knows what to do with "no frame": `peer.rs` logs
//! `capture produced no frame (idle screen)` when `next_frame` yields `None`.
//! This module exists purely to make that existing path *reachable* on Linux
//! by answering the question XShm cannot.
//!
//! It runs on its own X11 connection (scrap owns its own and does not expose
//! it) and is created on the capture worker thread, which is where the whole
//! backend is already pinned for XShm thread-affinity reasons.

use super::{Damage, DirtyRect};
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::damage::{ConnectionExt as _, Damage as DamageId, ReportLevel};
use x11rb::rust_connection::RustConnection;

/// Force a capture at least this often even when the server reports no
/// damage. This bound is what makes P1 safe to default on: the failure mode
/// of a missed/coalesced damage event is a FROZEN stream, which is far worse
/// than a slow one, so a damage bug degrades to a stale tile that repairs
/// itself within a second rather than a dead session.
const DEFAULT_MAX_SKIP: Duration = Duration::from_millis(1000);

/// Cap on accumulated damage rects before collapsing to their bounding box.
/// Matches the WGC backend's constant and its reasoning: past this the
/// localisation is worthless, and a bounding box stays motion-TRUE — it
/// over-reports area, never under, which is the safe direction for every
/// consumer (ROI hints, `area_permille`, the rate profile's refine flip).
const MAX_DAMAGE_RECTS: usize = 256;

/// What the tracker decided for one capture tick.
pub enum Tick {
    /// Provably nothing changed and the safety valve is not due — the caller
    /// should report no frame and skip the readback entirely.
    Skip,
    /// Capture, and stamp the delivered frame with this damage.
    Capture(Damage),
}

/// Tracks whether the X11 root window changed since the last delivered frame.
///
/// Construction is fail-open by design — every error path yields `None` and
/// the caller keeps today's unconditional-capture behaviour. A capture backend
/// that refuses to produce frames because an *optimisation* could not
/// initialise would be a far worse defect than the cost it saves.
pub struct DamageTracker {
    conn: RustConnection,
    damage: DamageId,
    /// When we last actually let a capture through, for the safety valve.
    last_capture: Instant,
    max_skip: Duration,
    /// Rectangles reported since the last consumed capture. Empty means
    /// nothing changed. Kept across calls because the caller may ask more
    /// than once per delivered frame.
    rects: Vec<DirtyRect>,
    /// Set when the rect list overflowed `MAX_DAMAGE_RECTS`, or when we lost
    /// the ability to describe the damage precisely. The accumulated rects
    /// then collapse to their bounding box.
    overflowed: bool,
    /// Set when we know the screen changed but NOT where — a connection
    /// failure. Distinct from `overflowed`: there we still have a truthful
    /// bounding box, here we have nothing and must say `Unknown`.
    blind: bool,
}

impl DamageTracker {
    /// Open a tracker, or `None` if damage tracking is unavailable or
    /// switched off. Never returns an error: the caller's fallback is the
    /// pre-FR-29 behaviour, which is always correct, only slower.
    pub fn open() -> Option<Self> {
        Self::open_on(None)
    }

    /// [`Self::open`] against an explicit display; `None` is `$DISPLAY`, as
    /// `x11rb::connect` reads it.
    ///
    /// ⚠️ The seam a test uses instead of rewriting the process-wide
    /// `DISPLAY`, which every concurrently running test that talks to X would
    /// see (and the old test removed it outright afterwards, rather than
    /// restoring it).
    fn open_on(display: Option<&str>) -> Option<Self> {
        // Kill switch, through the canonical gate helper rather than a raw
        // `std::env::var`: that is what gives it the `ROOMLERD_` prefix, the
        // legacy prefix fallbacks, AND the config-file fallback — so an
        // operator can pin this in config.toml like any other gate instead of
        // only via the unit's environment.
        if !tunnel_core::env::flag("X11_DAMAGE", true) {
            tracing::info!(
                "capture: X11 damage tracking disabled by ROOMLERD_X11_DAMAGE — every tick will do a full readback"
            );
            return None;
        }

        let max_skip = tunnel_core::env::node_env("X11_DAMAGE_MAX_SKIP_MS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_MAX_SKIP);

        let (conn, screen_num) = x11rb::connect(display)
            .map_err(|e| tracing::info!(%e, "capture: no X11 connection for damage tracking"))
            .ok()?;
        let root = conn.setup().roots.get(screen_num)?.root;

        // The extension must be present AND negotiated before any damage
        // request is legal. Stepwise rather than chained: the request and the
        // reply fail with DIFFERENT error types (`ConnectionError` vs
        // `ReplyError`) and there is no `From` between them.
        let Ok(cookie) = conn.damage_query_version(1, 1) else {
            tracing::info!("capture: X server did not accept a DAMAGE version request");
            return None;
        };
        if let Err(e) = cookie.reply() {
            tracing::info!(%e, "capture: X server has no usable DAMAGE extension");
            return None;
        }

        let damage = conn.generate_id().ok()?;
        // RAW_RECTANGLES rather than NON_EMPTY (P1's level): we want WHERE it
        // changed, not just whether. One event per damaged rectangle, which we
        // accumulate between captures and cap at MAX_DAMAGE_RECTS — the storm
        // risk that argues for NON_EMPTY is bounded by that cap, and we are
        // polling the queue every tick anyway, so the events cost a drain we
        // were already doing.
        let Ok(cookie) = conn.damage_create(damage, root, ReportLevel::RAW_RECTANGLES) else {
            tracing::info!("capture: could not request damage on the root window");
            return None;
        };
        if let Err(e) = cookie.check() {
            tracing::info!(%e, "capture: the X server refused to watch the root window for damage");
            return None;
        }
        let _ = conn.flush();

        tracing::info!(
            max_skip_ms = max_skip.as_millis() as u64,
            "capture: X11 damage tracking active — an unchanged screen now skips the XShm readback"
        );
        Some(Self {
            conn,
            damage,
            // Start due, so the very first tick always captures.
            last_capture: crate::clock::instant_before(max_skip),
            max_skip,
            rects: Vec::new(),
            overflowed: false,
            blind: false,
        })
    }

    /// Decide this capture tick, and hand back the damage to stamp on the
    /// frame when it says capture.
    ///
    /// ⚠️ The valve-forced capture reports `Damage::Unknown`, NOT
    /// `Tracked(vec![])`. The valve exists precisely because a damage event
    /// may have been missed, so "we saw no rects" is not evidence that
    /// nothing changed — claiming `Tracked` there would tell the encoder to
    /// skip a region that may well have moved.
    pub fn tick(&mut self) -> Tick {
        self.drain_events();

        let valve_due = self.last_capture.elapsed() >= self.max_skip;
        if !valve_due && self.rects.is_empty() && !self.blind {
            return Tick::Skip;
        }

        let damage = if self.blind || (valve_due && self.rects.is_empty()) {
            Damage::Unknown
        } else if self.overflowed {
            Damage::Tracked(vec![bounding_box(&self.rects)])
        } else {
            Damage::Tracked(self.rects.clone())
        };
        self.consume();
        Tick::Capture(damage)
    }

    /// Absorb any queued events, accumulating what changed and where.
    ///
    /// A connection error sets `blind` rather than clearing state: if we can
    /// no longer tell what changed, the safe answer is "assume it did, and
    /// admit we cannot say where".
    fn drain_events(&mut self) {
        loop {
            match self.conn.poll_for_event() {
                Ok(Some(Event::DamageNotify(ev))) => {
                    if self.rects.len() >= MAX_DAMAGE_RECTS {
                        // Keep draining — the queue must not back up — but stop
                        // growing the list; `overflowed` collapses it later.
                        self.overflowed = true;
                        continue;
                    }
                    let a = ev.area;
                    if a.width > 0 && a.height > 0 {
                        self.rects.push(DirtyRect {
                            x: a.x.max(0) as u32,
                            y: a.y.max(0) as u32,
                            w: a.width as u32,
                            h: a.height as u32,
                        });
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(
                        %e,
                        "capture: X11 damage connection failed — assuming the screen changed from here on"
                    );
                    self.blind = true;
                    return;
                }
            }
        }
    }

    /// Clear the server-side region and re-arm the NON_EMPTY report.
    ///
    /// ⚠️ ORDER IS LOAD-BEARING: the caller subtracts BEFORE grabbing, never
    /// after. Damage that lands *during* a readback then raises a fresh event
    /// and is picked up on the next tick — at worst one redundant capture.
    /// Subtracting after the grab would instead discard exactly that damage,
    /// and the screen would silently stop updating until the safety valve
    /// fired. Slow is recoverable; frozen is the bug this must not create.
    fn consume(&mut self) {
        self.rects.clear();
        self.overflowed = false;
        self.blind = false;
        self.last_capture = Instant::now();
        if let Ok(cookie) = self
            .conn
            .damage_subtract(self.damage, x11rb::NONE, x11rb::NONE)
        {
            let _ = cookie.check();
        }
        let _ = self.conn.flush();
    }
}

/// Bounding box of a non-empty rect list. Used when the list overflows the
/// cap: coarse, but motion-TRUE — it over-reports area, never under, which is
/// the safe direction for every consumer of `Damage`.
fn bounding_box(rects: &[DirtyRect]) -> DirtyRect {
    let x0 = rects.iter().map(|r| r.x).min().unwrap_or(0);
    let y0 = rects.iter().map(|r| r.y).min().unwrap_or(0);
    let x1 = rects
        .iter()
        .map(|r| r.x.saturating_add(r.w))
        .max()
        .unwrap_or(0);
    let y1 = rects
        .iter()
        .map(|r| r.y.saturating_add(r.h))
        .max()
        .unwrap_or(0);
    DirtyRect {
        x: x0,
        y: y0,
        w: x1.saturating_sub(x0),
        h: y1.saturating_sub(y0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The overflow collapse must never UNDER-report: the box has to cover
    /// every rect that went into it, because a consumer that trusts a too-small
    /// region skips pixels that actually moved.
    #[test]
    fn bounding_box_covers_every_rect() {
        let rects = vec![
            DirtyRect {
                x: 10,
                y: 20,
                w: 5,
                h: 5,
            },
            DirtyRect {
                x: 100,
                y: 4,
                w: 2,
                h: 50,
            },
            DirtyRect {
                x: 0,
                y: 60,
                w: 1,
                h: 1,
            },
        ];
        let b = bounding_box(&rects);
        assert_eq!((b.x, b.y), (0, 4), "origin is the min corner");
        // Right edge 102 (100+2), bottom edge 61 (60+1).
        assert_eq!((b.w, b.h), (102, 57));
        for r in &rects {
            assert!(r.x >= b.x && r.y >= b.y, "rect starts inside the box");
            assert!(
                r.x + r.w <= b.x + b.w && r.y + r.h <= b.y + b.h,
                "rect ends inside the box"
            );
        }
    }

    /// A single rect must round-trip unchanged — the collapse is only allowed
    /// to coarsen when there is genuinely more than one region.
    #[test]
    fn bounding_box_of_one_rect_is_that_rect() {
        let r = DirtyRect {
            x: 7,
            y: 9,
            w: 11,
            h: 13,
        };
        let b = bounding_box(std::slice::from_ref(&r));
        assert_eq!((b.x, b.y, b.w, b.h), (r.x, r.y, r.w, r.h));
    }

    /// Both tests below write `ROOMLERD_X11_DAMAGE`, and libtest runs them on
    /// parallel threads of one process. Unserialised, the second could clear
    /// the kill switch between the first's set and its `open()`, which on a
    /// host WITH an X server hands back a tracker and fails the assertion.
    static KILL_SWITCH: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The kill switch must win even where an X server is present, because it
    /// is the operator's only lever if damage tracking misbehaves in the field.
    #[test]
    fn kill_switch_refuses_to_open() {
        let _serial = KILL_SWITCH.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: serialised with the other writer by KILL_SWITCH, and only
        // `DamageTracker::open` reads this variable.
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "X11_DAMAGE", "0") };
        assert!(DamageTracker::open().is_none());
        unsafe { tunnel_core::env::test_env::clear("X11_DAMAGE") };
    }

    /// `open()` must never panic and never propagate an error, on any host —
    /// including CI containers with no X server at all. Its failure mode is a
    /// `None` that costs performance, never a capture backend that won't start.
    ///
    /// The unreachable display is named through `open_on`, not written to the
    /// process-wide `DISPLAY` (see there).
    #[test]
    fn open_is_infallible_without_a_display() {
        let _serial = KILL_SWITCH.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: as above. Cleared so `open_on` gets past the kill switch to
        // the connect this test is here to exercise.
        unsafe { tunnel_core::env::test_env::clear("X11_DAMAGE") };
        let _ = DamageTracker::open_on(Some(":-1-not-a-display"));
    }
}
