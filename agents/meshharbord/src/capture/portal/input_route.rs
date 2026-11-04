// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P4, daemon side — the seam between the input arbiter and the portal
//! helper's stdin.
//!
//! While a portal capture with granted input is live, injected events belong
//! to the portal session, not to the OS injector: on the hosts this backend
//! exists for, enigo's XTest reaches nothing and uinput's events have no
//! reader (FR-45 field log). [`super::backend::PortalCapture`] registers a
//! sender here when its helper announces input; the arbiter's single
//! injection funnel consults [`try_route`] per event.
//!
//! ## Why a per-event check and not a backend choice
//!
//! The arbiter creates ONE process-wide injector, lazily, at the first
//! injected event — and the portal capture opens around the same moment, from
//! another task. Deciding "portal or OS" once at injector creation would race
//! that startup and freeze the loser in place for the life of the process.
//! A per-event lookup costs a mutex and makes the answer always current:
//! capture restarts, session ends, kill switch — the route follows.
//!
//! ## One desktop, so one active route — with correct handoff
//!
//! Every portal helper injects into the SAME physical desktop (one seat0
//! session per host), and the arbiter already arbitrates which session may
//! inject. So all arbitrated input should reach ONE portal helper. The
//! registry is therefore an ORDERED list of the live helpers, and [`try_route`]
//! always targets the OLDEST surviving one:
//!
//! - Registration APPENDS; it never overwrites. A second concurrent viewer's
//!   capture cannot silently steal the route from the first — the earlier
//!   finding where viewer B's `register` clobbered viewer A's slot and B's
//!   teardown then set it to `None`, leaving A falling through to the
//!   do-nothing OS injector, input-dead mid-session.
//! - The active target changes ONLY when the current owner's capture drops,
//!   which happens as that session ends. Because closing a portal session
//!   releases its own virtual devices, a key held via the departing helper is
//!   released by the compositor; a stale release routed to the new owner's
//!   helper lands on the same physical desktop and is a harmless no-op there.
//!   So a held modifier is never stranded — the route-steal stuck-key finding.
//! - Within one session the active target is STABLE for the session's whole
//!   life, so a key-down and its later up always reach the same helper.
//!
//! ⚠️ The one residual: concurrent multi-viewer portal input all funnels
//! through the oldest helper's RemoteDesktop session. On one physical desktop
//! that is correct (whoever holds the floor injects into the one screen), and
//! it is far better than the alternative of clobbering or splitting. If a
//! future host ever presents two independent portal desktops in one daemon,
//! this needs per-desktop routing — but no such host exists today.

use std::sync::Mutex;
use std::sync::mpsc::{SyncSender, TrySendError};

use crate::input::InputMsg;
use crate::input::reach::RouteKind;

struct Route {
    tx: SyncSender<InputMsg>,
    generation: u64,
    /// FR-93 P4 — the portal's RemoteDesktop session, or mutter's own: the
    /// same seam, and `input::reach` says which one owns injection.
    kind: RouteKind,
}

/// The live portal input helpers, oldest first. Empty ⇒ no portal route ⇒ the
/// caller uses the OS injector.
static ROUTES: Mutex<Vec<Route>> = Mutex::new(Vec::new());
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Append a live portal input sender and return its generation token for
/// [`unregister`]. Never replaces an existing route — a concurrent second
/// capture is added AFTER the first, and the first stays the active target
/// until it unregisters.
pub fn register(tx: SyncSender<InputMsg>, kind: RouteKind) -> u64 {
    let generation = GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let mut routes = ROUTES.lock().unwrap_or_else(|e| e.into_inner());
    routes.push(Route {
        tx,
        generation,
        kind,
    });
    generation
}

/// Remove the route registered under `generation`. If it was the active
/// (oldest) one, the next-oldest becomes active automatically — no gap, no
/// fall-through to the OS injector while another portal session is still live.
pub fn unregister(generation: u64) {
    let mut routes = ROUTES.lock().unwrap_or_else(|e| e.into_inner());
    routes.retain(|r| r.generation != generation);
}

/// FR-93 — is an input route live right now, and whose? Asked once per session
/// by `input::reach`: while one is, that RemoteDesktop session owns injection
/// (see [`try_route`]), so the OS injector's reach no longer decides anything.
/// The kind is the OLDEST route's, the one [`try_route`] targets.
pub fn active() -> Option<RouteKind> {
    ROUTES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .first()
        .map(|r| r.kind)
}

/// Offer one event to the portal route.
///
/// `true` means the portal OWNS this event — including when the target channel
/// was full and the event was dropped, because falling through to the OS
/// injector on overload would split one gesture across two backends. Targets
/// the OLDEST live helper; a helper whose channel has disconnected (its `Drop`
/// has not run yet) is skipped in favour of the next. `false` means no live
/// portal route at all: the caller injects normally.
pub fn try_route(msg: &InputMsg) -> bool {
    let routes = ROUTES.lock().unwrap_or_else(|e| e.into_inner());
    if routes.is_empty() {
        return false;
    }
    for r in routes.iter() {
        match r.tx.try_send(msg.clone()) {
            Ok(()) => return true,
            // The oldest live helper is the target and it is behind; drop
            // rather than split the gesture to the OS injector.
            Err(TrySendError::Full(_)) => return true,
            // This helper is gone but its Drop has not unregistered it yet —
            // hand off to the next-oldest.
            Err(TrySendError::Disconnected(_)) => continue,
        }
    }
    // Portal helpers exist but every one is mid-teardown. Still claim the
    // event: these sessions are ending, and the OS injector reaches nothing on
    // the hosts this backend serves.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::InputMsg;

    fn mv() -> InputMsg {
        InputMsg::MouseMove {
            x: 0.5,
            y: 0.5,
            mon: 0,
        }
    }

    /// ⚠️ One test drives all the registry states: the registry is
    /// process-global and cargo runs tests in this binary concurrently, so
    /// splitting these into separate `#[test]`s would make them race each
    /// other's registrations.
    #[test]
    fn route_lifecycle_and_handoff() {
        // No route: the caller keeps the event.
        assert!(!try_route(&mv()));
        assert_eq!(active(), None);

        // One viewer: events flow to it.
        let (tx_a, rx_a) = std::sync::mpsc::sync_channel(4);
        let gen_a = register(tx_a, RouteKind::Portal);
        assert!(try_route(&mv()));
        assert!(matches!(rx_a.try_recv(), Ok(InputMsg::MouseMove { .. })));

        // A SECOND viewer joins. It must NOT steal the route: events keep
        // going to A (the oldest), and B receives nothing yet.
        let (tx_b, rx_b) = std::sync::mpsc::sync_channel(4);
        let gen_b = register(tx_b, RouteKind::Mutter);
        assert!(try_route(&mv()));
        assert!(
            matches!(rx_a.try_recv(), Ok(InputMsg::MouseMove { .. })),
            "the first viewer stays the active target"
        );
        assert!(
            rx_b.try_recv().is_err(),
            "a second concurrent viewer does not steal the route"
        );
        // FR-93 P4 — the kind `input::reach` reports is the target's.
        assert_eq!(active(), Some(RouteKind::Portal), "the oldest route's kind");

        // A (the owner) leaves. The route HANDS OFF to B automatically —
        // never a gap that would fall through to the do-nothing OS injector.
        unregister(gen_a);
        assert!(try_route(&mv()));
        assert!(
            matches!(rx_b.try_recv(), Ok(InputMsg::MouseMove { .. })),
            "teardown of the owner promotes the next-oldest, not None"
        );
        assert_eq!(active(), Some(RouteKind::Mutter));

        // Full channel is still OWNED (dropped), never split to the OS backend.
        for _ in 0..8 {
            let _ = try_route(&mv());
        }
        assert!(try_route(&mv()), "a full channel still claims the event");

        // A stale unregister of the already-departed owner is a no-op — B
        // survives (an old capture's Drop racing a newer registration must
        // remove only its own entry).
        unregister(gen_a);
        assert!(try_route(&mv()));
        let _ = rx_b.try_recv();

        // Last viewer leaves: no route, caller falls back to the OS injector.
        unregister(gen_b);
        assert!(!try_route(&mv()));
        assert_eq!(active(), None);
    }
}
