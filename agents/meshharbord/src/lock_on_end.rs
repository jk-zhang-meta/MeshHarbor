// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-99 P3 — lock this computer when the last remote session ends.
//!
//! The owner's `lock_on_end` (`never` by default, `auto`, `always`; a fresh
//! Windows service install is written with `auto`, FR-99 decision 3) is read at
//! each session's START, together with what `auto` needs from that moment: was
//! the screen locked, and was anybody at the computer. The decision is kept per
//! session and applied when the LAST live session ends, whatever ended it (the
//! viewer's hangup, the person's Disconnect, a limit, a dropped connection).
//! Locking under a second controller who is still working would be a fault,
//! not a policy.
//!
//! | policy | the session began… | when the last session ends |
//! |---|---|---|
//! | `never` | — | nothing |
//! | `auto` | on a locked screen, or with nobody at the computer | lock |
//! | `auto` | unlocked, with someone at it | nothing |
//! | `always` | — | lock |
//!
//! `auto` restores what was found at the start. A person who unlocked the
//! computer during the session is locked out at its end and signs in again:
//! nothing here can tell their input from the controller's without the hooks
//! FR-92 bans.
//!
//! The mechanisms, from this process (the console worker):
//! - Windows: `LockWorkStation()`. For a service install the worker is SYSTEM
//!   in the console session; FR-99's P0 showed the call locks from there
//!   (2026-10-15). For a per-user install it is the person's own process.
//! - Linux: `loginctl lock-session` on seat0's active session.
//! - macOS: none yet. The setting is accepted, and an end that should lock
//!   says it could not.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use bson::oid::ObjectId;
use meshharbor_remote_control::models::LockOnEnd;
use tracing::{info, warn};

/// No local input for this long reads as nobody at the computer.
pub const UNATTENDED_AFTER: Duration = Duration::from_secs(5 * 60);

/// What `auto` reads at a session's start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Found {
    /// The screen was locked (or on the secure desktop).
    pub locked: bool,
    /// Nobody had used the computer for [`UNATTENDED_AFTER`].
    pub unattended: bool,
}

/// Should this session's end lock the computer?
pub fn wants_lock(policy: LockOnEnd, found: Found) -> bool {
    match policy {
        LockOnEnd::Never => false,
        LockOnEnd::Always => true,
        LockOnEnd::Auto => found.locked || found.unattended,
    }
}

// ── The owner's policy ──────────────────────────────────────────────────────

static POLICY: AtomicU8 = AtomicU8::new(0);

fn to_u8(p: LockOnEnd) -> u8 {
    match p {
        LockOnEnd::Never => 0,
        LockOnEnd::Auto => 1,
        LockOnEnd::Always => 2,
    }
}

/// Seed (at start-up) or re-seed (after a LOCAL `ConfigSet`) the owner's
/// `lock_on_end`. The next session's start reads it; a session already live
/// keeps the decision taken at its own start.
pub fn set_device_policy(p: LockOnEnd) {
    POLICY.store(to_u8(p), Ordering::Release);
}

/// The owner's policy, as it is now.
pub fn device_policy() -> LockOnEnd {
    match POLICY.load(Ordering::Acquire) {
        1 => LockOnEnd::Auto,
        2 => LockOnEnd::Always,
        _ => LockOnEnd::Never,
    }
}

// ── The server's ask (P3b) ──────────────────────────────────────────────────

/// Whether a server's ask may reach this install, so whether it advertises
/// `lock-on-end`: it has a way to lock, AND the lock can be lifted remotely
/// afterwards. That is the Windows service (its worker is SYSTEM in the
/// console session and reaches the secure desktop) and the Linux root daemon.
/// A per-user install's worker cannot reach the secure desktop, so a lock an
/// admin asked for would leave every later session at a padlock nobody can
/// lift remotely: such an install never advertises it, and the audit records
/// the ask as not enforced. The owner's own `lock_on_end` stays theirs on any
/// install. Read once per process.
pub fn can_honour_ask() -> bool {
    static CAN: OnceLock<bool> = OnceLock::new();
    *CAN.get_or_init(system_install)
}

#[cfg(all(target_os = "windows", feature = "system-context"))]
fn system_install() -> bool {
    use crate::system_context::worker_role::{WorkerRole, probe_self};
    matches!(probe_self(), Ok(WorkerRole::SystemContext))
}

#[cfg(all(target_os = "windows", not(feature = "system-context")))]
fn system_install() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn system_install() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn system_install() -> bool {
    false
}

/// The policy a session runs under: the owner's own, or stricter where the
/// device's access policy asked for stricter (`Request.lock_on_end`). Never
/// looser: the owner's setting is the floor.
pub fn effective_policy(device: LockOnEnd, ask: Option<LockOnEnd>) -> LockOnEnd {
    ask.map_or(device, |a| device.stricter(a))
}

/// Each session's ask, from its request until it goes live.
fn asks() -> &'static Mutex<HashMap<ObjectId, LockOnEnd>> {
    static ASKS: OnceLock<Mutex<HashMap<ObjectId, LockOnEnd>>> = OnceLock::new();
    ASKS.get_or_init(Default::default)
}

/// Record a session's ask before it goes live. `None` asks nothing, and
/// forgets an earlier ask for the same session.
pub fn set_session_ask(session: ObjectId, ask: Option<LockOnEnd>) {
    let mut a = asks().lock().unwrap_or_else(|p| p.into_inner());
    match ask {
        Some(l) => {
            a.insert(session, l);
        }
        None => {
            a.remove(&session);
        }
    }
}

fn take_session_ask(session: &ObjectId) -> Option<LockOnEnd> {
    asks()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(session)
}

// ── Which end locks ─────────────────────────────────────────────────────────

/// The live sessions and their decisions, and whether an end since the last
/// lock asked for one. The decisions live here, not on the screen, so they are
/// tested without locking anything.
#[derive(Default)]
pub struct Tracker {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    live: HashMap<ObjectId, bool>,
    pending: bool,
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A session went live. A second start for the same session (a re-offer
    /// builds a new peer under the same id) keeps the FIRST decision: what
    /// `auto` found then is what it must restore, not what the session has
    /// made of the screen since.
    pub fn started(&self, session: ObjectId, policy: LockOnEnd, found: Found) {
        let wants = wants_lock(policy, found);
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.live.entry(session).or_insert(wants);
    }

    /// A session ended. `true` when this end should lock now: it was the last
    /// live session, and it or an earlier one since the last lock asked for
    /// it. An end for a session never started here changes nothing.
    pub fn ended(&self, session: &ObjectId) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(wants) = s.live.remove(session) else {
            return false;
        };
        s.pending |= wants;
        if s.live.is_empty() && s.pending {
            s.pending = false;
            return true;
        }
        false
    }

    /// A session that never went live after all (its answer never left): it
    /// leaves without a say.
    pub fn forget(&self, session: &ObjectId) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.live.remove(session);
    }
}

fn tracker() -> &'static Tracker {
    static TRACKER: OnceLock<Tracker> = OnceLock::new();
    TRACKER.get_or_init(Tracker::new)
}

// ── The production hooks (the indicator's show and hide) ────────────────────

/// The session went live: read the policy (the owner's, made stricter by the
/// session's ask, if any), and what `auto` needs, now.
pub fn session_started(session: ObjectId) {
    let ask = take_session_ask(&session);
    let policy = effective_policy(device_policy(), ask);
    let found = if policy == LockOnEnd::Auto {
        probe_found()
    } else {
        Found::default()
    };
    if policy != LockOnEnd::Never {
        info!(%session, ?policy, ?ask, locked = found.locked, unattended = found.unattended,
            locks_at_end = wants_lock(policy, found), "lock_on_end: decided at the session's start");
    }
    tracker().started(session, policy, found);
}

/// The session ended, by whatever path. Locks when this was the last live
/// session and the decisions say so, on a thread of its own: the OS call may
/// take a moment, and the session's teardown must not wait on it.
pub fn session_ended(session: ObjectId) {
    // An ask for a session that ended before it went live goes with it.
    let _ = take_session_ask(&session);
    if tracker().ended(&session) {
        std::thread::spawn(move || match lock_now() {
            Ok(()) => {
                info!(%session, "lock_on_end: the last session ended; the computer is locked")
            }
            Err(e) => {
                warn!(%session, error = %e, "lock_on_end: the last session ended, but the computer could not be locked")
            }
        });
    }
}

/// A session that never went live (its answer never left).
pub fn session_aborted(session: ObjectId) {
    let _ = take_session_ask(&session);
    tracker().forget(&session);
}

// ── The platform ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn probe_found() -> Found {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    let locked = crate::lock_state::probe_lock_state() == crate::lock_state::LockState::Locked;
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: a stack LASTINPUTINFO with cbSize set, as the API requires.
    // Both ticks are the same 32-bit millisecond counter, so the wrapping
    // difference is the idle time even across a wrap.
    let unattended = unsafe { GetLastInputInfo(&mut lii) } != 0
        && u64::from(unsafe { GetTickCount() }.wrapping_sub(lii.dwTime))
            >= UNATTENDED_AFTER.as_millis() as u64;
    Found { locked, unattended }
}

#[cfg(target_os = "windows")]
fn lock_now() -> Result<(), String> {
    use windows_sys::Win32::System::Shutdown::LockWorkStation;
    // SAFETY: no arguments; fails (FALSE) where there is no interactive
    // session to lock, which is reported, never retried.
    if unsafe { LockWorkStation() } != 0 {
        Ok(())
    } else {
        Err(format!(
            "LockWorkStation failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// seat0's active session, as logind names it.
#[cfg(target_os = "linux")]
pub(crate) fn linux_active_session() -> Option<String> {
    let out = std::process::Command::new("loginctl")
        .args(["show-seat", "seat0", "--property=ActiveSession", "--value"])
        .output()
        .ok()?;
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !id.is_empty()).then_some(id)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_session_hint(id: &str, property: &str) -> bool {
    std::process::Command::new("loginctl")
        .args([
            "show-session",
            id,
            &format!("--property={property}"),
            "--value",
        ])
        .output()
        .ok()
        .is_some_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "yes")
}

#[cfg(target_os = "linux")]
fn probe_found() -> Found {
    match linux_active_session() {
        Some(id) => Found {
            locked: linux_session_hint(&id, "LockedHint"),
            unattended: linux_session_hint(&id, "IdleHint"),
        },
        // No active graphical session: nobody is at it.
        None => Found {
            locked: false,
            unattended: true,
        },
    }
}

#[cfg(target_os = "linux")]
fn lock_now() -> Result<(), String> {
    let id = linux_active_session().ok_or("seat0 has no active session to lock")?;
    let out = std::process::Command::new("loginctl")
        .args(["lock-session", &id])
        .output()
        .map_err(|e| format!("loginctl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "loginctl lock-session {id}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn probe_found() -> Found {
    Found::default()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn lock_now() -> Result<(), String> {
    Err("locking the screen is not supported on this platform yet".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKED: Found = Found {
        locked: true,
        unattended: false,
    };
    const AWAY: Found = Found {
        locked: false,
        unattended: true,
    };
    const HERE: Found = Found {
        locked: false,
        unattended: false,
    };

    /// The table in this module's documentation, cell by cell.
    #[test]
    fn the_policy_and_what_was_found_decide() {
        use LockOnEnd::*;
        for found in [LOCKED, AWAY, HERE] {
            assert!(!wants_lock(Never, found), "{found:?}");
            assert!(wants_lock(Always, found), "{found:?}");
        }
        assert!(wants_lock(Auto, LOCKED));
        assert!(wants_lock(Auto, AWAY));
        assert!(!wants_lock(Auto, HERE));
    }

    #[test]
    fn one_session_locks_at_its_end_only_when_it_asked() {
        let t = Tracker::new();
        let (a, b) = (ObjectId::new(), ObjectId::new());
        t.started(a, LockOnEnd::Auto, HERE);
        assert!(
            !t.ended(&a),
            "found unlocked with someone there: left as it was"
        );
        t.started(b, LockOnEnd::Auto, LOCKED);
        assert!(t.ended(&b), "found locked: locked again");
    }

    /// A session that ends while another is live waits: the lock comes at the
    /// last end, and only once.
    #[test]
    fn the_lock_waits_for_the_last_session() {
        let t = Tracker::new();
        let (a, b, c) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        t.started(a, LockOnEnd::Always, HERE);
        t.started(b, LockOnEnd::Never, HERE);
        assert!(!t.ended(&a), "b is still live");
        assert!(t.ended(&b), "the last end locks, for a's sake");
        t.started(c, LockOnEnd::Never, HERE);
        assert!(
            !t.ended(&c),
            "the lock was taken; nothing is pending any more"
        );
    }

    /// A re-offer starts the same session again: the first decision stands.
    #[test]
    fn a_re_offer_keeps_the_first_decision() {
        let t = Tracker::new();
        let a = ObjectId::new();
        t.started(a, LockOnEnd::Auto, LOCKED);
        // The controller unlocked the screen, then the viewer re-offered.
        t.started(a, LockOnEnd::Auto, HERE);
        assert!(t.ended(&a), "found locked at the start: locked again");
    }

    #[test]
    fn an_unknown_end_or_an_aborted_session_never_locks() {
        let t = Tracker::new();
        assert!(!t.ended(&ObjectId::new()));
        let a = ObjectId::new();
        t.started(a, LockOnEnd::Always, HERE);
        t.forget(&a);
        assert!(!t.ended(&a), "a session that never went live has no say");
        let b = ObjectId::new();
        t.started(b, LockOnEnd::Never, HERE);
        assert!(!t.ended(&b));
    }

    #[test]
    fn the_owner_policy_is_live() {
        set_device_policy(LockOnEnd::Always);
        assert_eq!(device_policy(), LockOnEnd::Always);
        set_device_policy(LockOnEnd::Auto);
        assert_eq!(device_policy(), LockOnEnd::Auto);
        set_device_policy(LockOnEnd::Never);
        assert_eq!(device_policy(), LockOnEnd::Never);
    }

    /// P3b — the server's ask tightens the owner's policy and never loosens
    /// it: the owner's setting is the floor.
    #[test]
    fn an_ask_can_only_tighten_the_owners_policy() {
        use LockOnEnd::*;
        for (device, ask, want) in [
            (Never, None, Never),
            (Never, Some(Auto), Auto),
            (Never, Some(Always), Always),
            (Auto, None, Auto),
            (Auto, Some(Never), Auto),
            (Auto, Some(Always), Always),
            (Always, Some(Never), Always),
            (Always, Some(Auto), Always),
        ] {
            assert_eq!(
                effective_policy(device, ask),
                want,
                "device {device:?}, ask {ask:?}"
            );
        }
    }

    /// P3b — a session's ask waits for its start and is taken there once; a
    /// `None` forgets an earlier one.
    #[test]
    fn a_sessions_ask_is_taken_once() {
        let s = ObjectId::new();
        set_session_ask(s, Some(LockOnEnd::Always));
        assert_eq!(take_session_ask(&s), Some(LockOnEnd::Always));
        assert_eq!(take_session_ask(&s), None, "taken once");
        set_session_ask(s, Some(LockOnEnd::Auto));
        set_session_ask(s, None);
        assert_eq!(take_session_ask(&s), None, "a None forgets it");
        // Another session's ask is its own.
        let t = ObjectId::new();
        set_session_ask(t, Some(LockOnEnd::Auto));
        assert_eq!(take_session_ask(&s), None);
        assert_eq!(take_session_ask(&t), Some(LockOnEnd::Auto));
    }
}
