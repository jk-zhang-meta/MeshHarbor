// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Lock-screen detection for the user-context worker (M3 Z-path).
//!
//! Background. The M5 verification on the field-test host + operator confirmed
//! the field gap: when the user presses Win+L (or Windows otherwise
//! switches the input desktop to `winsta0\Winlogon`), the user-
//! context agent worker stays alive — `WTSGetActiveConsoleSessionId`
//! doesn't change, the SCM supervisor's `decide_spawn` returns
//! `KeepCurrent`, the WS connection stays connected, the WebRTC
//! peer stays connected — but capture frames go black/stale because
//! the worker's desktop attachment (`winsta0\Default`) is no longer
//! visible, and input injection is silently dropped because
//! `SendInput` targets the wrong desktop.
//!
//! M3's Z-path closes this in the simplest possible way: detect the
//! lock transition from the user-context worker, paint a static
//! "Host is locked" overlay frame to the encoder until unlock, and
//! suppress input injection. No SYSTEM-context capture+input thread,
//! no IPC, no remote-unlock — just a dignified "we're paused"
//! signal so the operator doesn't see a frozen desktop and assume
//! the agent crashed.
//!
//! Detection mechanism. We poll `OpenInputDesktop` every 500 ms from
//! the user-context worker. Because the worker runs in the user's
//! security context — *not* SYSTEM — the call returns:
//!   - `Ok(Some(_))` with desktop name `"Default"` when the user is
//!     on their normal interactive desktop
//!   - `Ok(None)` (`ERROR_ACCESS_DENIED`) when the input desktop has
//!     transitioned to `winsta0\Winlogon` (the lock screen, UAC
//!     consent, or a service-launched secure prompt)
//!   - `Ok(Some(_))` with a different desktop name in unusual cases
//!     (Citrix / RDP custom desktops); we treat anything that isn't
//!     `Default` as "not visible to me" → locked from our POV.
//!
//! 500 ms is a calm cadence. The actual desktop transition takes
//! ~250 ms on Win11, so the worst case the user sees is one half-
//! second of "frozen" frames before the overlay kicks in. Could be
//! tightened to 250 ms if field reports show that's user-visible,
//! but a full second of poll-loop CPU work × N agents × forever is
//! not free.
//!
//! Why not `WTSRegisterSessionNotification`? It fires on
//! `WTS_SESSION_LOCK` / `WTS_SESSION_UNLOCK` exactly when we want,
//! but requires a top-level window owned by the calling process to
//! receive the WM_WTSSESSION_CHANGE message — the agent worker is
//! a console app with no message pump, so plumbing that in adds
//! more code than the polling loop saves. Polling is also more
//! robust to the "user opened a UAC prompt" case which doesn't
//! fire WTS_SESSION_LOCK but DOES switch the input desktop.

use std::time::Duration;

/// Observable state of the user's interactive desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Input desktop is `winsta0\Default` and we have access to it.
    /// Capture works, input injection works, normal operation.
    Unlocked,
    /// Input desktop is `winsta0\Winlogon` (or otherwise inaccessible
    /// to the user-context worker). Capture frames will be black or
    /// stale; input injection silently fails. The encoder should
    /// paint the "Host is locked" overlay until this flips back.
    Locked,
}

/// How often the lock-state poll loop wakes up. Tuned for "one half-
/// second of stale frames at worst is acceptable" against "we don't
/// burn a CPU core polling forever." Locked here so the encoder
/// pump and tests use the same value.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Pure: classify the result of an `OpenInputDesktop`-equivalent
/// probe into a `LockState`. Splitting this out from the polling
/// loop keeps the FFI surface a thin wrapper and the decision logic
/// (which has all the gotchas around desktop names) trivially
/// testable.
///
/// Inputs:
///   - `access_ok`: true when the OS handed us back a desktop
///     handle, false when the call returned ACCESS_DENIED or any
///     other failure. Behaviour treats *any* failure as Locked
///     because the most common cause of failure on a healthy host
///     is the desktop transition; spurious failures (resource
///     exhaustion etc.) are rare and falsely-locked is a softer
///     failure than falsely-unlocked.
///   - `desktop_name`: when access succeeded, the name returned
///     (e.g. `"Default"`). Empty string when access failed.
pub fn classify(access_ok: bool, desktop_name: &str) -> LockState {
    if !access_ok {
        return LockState::Locked;
    }
    // Desktop name comparison is case-sensitive per Win32 docs.
    // `winsta0\Default` is the canonical interactive desktop name
    // every user session has at logon. Anything else (Winlogon,
    // Citrix__1, etc.) is treated as "not visible from here" =
    // Locked, because the user-context capture/input plumbing only
    // works against Default.
    if desktop_name == "Default" {
        LockState::Unlocked
    } else {
        LockState::Locked
    }
}

/// Pure: classify a WTS `SessionFlags` value (from
/// `WTSINFOEX_LEVEL1_W`) into a `LockState`. Split out from the FFI so
/// the decision logic is trivially testable.
///
/// Modern Windows (8 / Server 2012 and later) reports
/// `WTS_SESSIONSTATE_LOCK = 0` and `WTS_SESSIONSTATE_UNLOCK = 1`.
/// `WTS_SESSIONSTATE_UNKNOWN` (-1) and any unexpected value return
/// `None` so the caller can fall back to another probe rather than
/// guessing — this probe is advisory, and a false "locked" is worse
/// than deferring to the desktop probe.
///
/// ⚠️ On **Windows 7 / Server 2008 R2** the LOCK/UNLOCK meanings are
/// REVERSED (a documented Microsoft defect). The fleet is Win10/11; if
/// that ever changes, gate this on the OS build before trusting it.
pub fn classify_session_flags(flags: i32) -> Option<LockState> {
    match flags {
        0 => Some(LockState::Locked),   // WTS_SESSIONSTATE_LOCK
        1 => Some(LockState::Unlocked), // WTS_SESSIONSTATE_UNLOCK
        _ => None,                      // WTS_SESSIONSTATE_UNKNOWN (-1) / unexpected
    }
}

#[cfg(target_os = "windows")]
mod win {
    use super::{LockState, classify, classify_session_flags};
    use crate::win_service::desktop;

    /// Probe the lock state from the user-context worker. Returns
    /// `Locked` when `OpenInputDesktop` denies access (the input
    /// desktop has transitioned to `winsta0\Winlogon`) OR when the
    /// returned desktop name isn't `"Default"`.
    ///
    /// **rc.24 M3 Change A** — reads the desktop name FROM THE
    /// INPUT-DESKTOP HANDLE we just opened (`d.raw()`), not from
    /// `current_thread_desktop_name()`. The prior implementation
    /// answered "what desktop is this tokio worker thread bound
    /// to?" — which depends on whichever tokio worker the
    /// `spawn_monitor` task happened to land on, NOT on the
    /// actual input-desktop state. Under the SystemContext worker,
    /// tokio threads have heterogeneous desktop bindings (the
    /// SystemContext input thread explicitly sets its own to
    /// `Default`; other tokio workers inherit whatever the process
    /// started with, which may not be `Default` after a session
    /// hand-off). A probe landing on the wrong thread → reads
    /// non-"Default" → classifies as `Locked` → input gets
    /// suppressed by `attach_input_handler` even though the real
    /// input desktop IS `Default` and the operator's clicks
    /// should go through to admin pwsh / elevated apps.
    ///
    /// Field repro on the field-test host between rc.7 (verified working) and
    /// rc.21: mouse stopped responding when the operator hovered
    /// an elevated pwsh window. See
    /// `docs/remote-control.md (§19 appendix)` for the
    /// bisect plan + alternatives (Change B = bind every tokio
    /// worker; Change C = refine suppression policy under
    /// SystemContext) if this fix alone proves insufficient.
    ///
    /// rc.25 — returns `(state, observed_name)` so the spawn_monitor
    /// transition log can include the actual desktop name the OS
    /// reported. Diagnostic value: when the field reports "admin
    /// pwsh input doesn't work", the log shows whether the probe
    /// is seeing "Default" (Change A is fine, look elsewhere) or
    /// some other name (the probe IS the bug; identify why the
    /// input desktop transitioned).
    pub fn probe_lock_state_detailed() -> (LockState, String) {
        match desktop::open_input_desktop() {
            Ok(Some(d)) => {
                // Read the desktop NAME from the handle we have,
                // not from the calling thread. `desktop_name_of`
                // calls `GetUserObjectInformationW(h, UOI_NAME,...)`
                // which queries the OS for the actual desktop
                // identity behind the handle. (RustDesk's
                // `inputDesktopSelected` uses the same pattern —
                // see docs/remote-control.md (§19 appendix).)
                match desktop::desktop_name_of(d.raw()) {
                    Ok(name) => {
                        let state = classify(true, &name);
                        (state, name)
                    }
                    // Fallback: if reading the name from the
                    // handle fails (very rare — typically a
                    // permission glitch on a custom Citrix
                    // desktop), assume Default and let input
                    // through. False-unlocked is the safer side:
                    // input goes through to whatever desktop IS
                    // active. A truly-locked input desktop would
                    // have failed `open_input_desktop` first.
                    Err(e) => {
                        tracing::trace!(error = %e, "lock_state: desktop_name_of failed; defaulting to Unlocked");
                        (classify(true, "Default"), "Default".to_string())
                    }
                }
            }
            Ok(None) => (classify(false, ""), "<access-denied>".to_string()),
            Err(e) => {
                // Unexpected — log once at trace level so the field
                // can spot it, but treat as Locked to be safe.
                tracing::trace!(error = %e, "lock_state: OpenInputDesktop probe failed unexpectedly");
                (classify(false, ""), "<probe-error>".to_string())
            }
        }
    }

    /// Back-compat wrapper for callers that only need the state.
    /// Discards the observed name. New diagnostic-aware code paths
    /// should use [`probe_lock_state_detailed`] directly.
    pub fn probe_lock_state() -> LockState {
        probe_lock_state_detailed().0
    }

    /// Probe the lock state via **WTS**, independent of the caller's
    /// window station. Returns `None` when there is no active console
    /// session, the query fails, or the OS reports
    /// `WTS_SESSIONSTATE_UNKNOWN`, so the caller can fall back.
    ///
    /// **FR-34 P3b — why this exists.** [`probe_lock_state`] classifies
    /// via `OpenInputDesktop`, whose result is the input desktop of the
    /// **calling process's window station**. That is correct from the
    /// user-context capture worker / a session that has already run
    /// `attach_to_winsta0()`. But the CONSENT path runs on the SCM
    /// **service** window station (`Service-0x0-…`) — the daemon only
    /// switches to `WinSta0` per-session, when input is wired, *after*
    /// consent — and the service station has its OWN `Default` desktop,
    /// so `OpenInputDesktop` there classifies `Unlocked` no matter what
    /// the interactive session is doing. On a perMachine/SYSTEM host the
    /// old consent probe therefore could NEVER report Locked. WTS asks
    /// the OS about the console session directly, from any station.
    pub fn probe_lock_state_service() -> Option<LockState> {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::RemoteDesktop::{
            WTS_CURRENT_SERVER_HANDLE, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSINFOEXW,
            WTSQuerySessionInformationW, WTSSessionInfoEx,
        };

        // 0xFFFFFFFF = no session currently attached to the console
        // (headless / pre-login) — nothing to report a lock for.
        let session_id = unsafe { WTSGetActiveConsoleSessionId() };
        if session_id == u32::MAX {
            return None;
        }

        let mut buffer: *mut u16 = std::ptr::null_mut();
        let mut bytes: u32 = 0;
        // SAFETY: WTS_CURRENT_SERVER_HANDLE is the documented "this
        // server" sentinel; session_id is a u32; WTSSessionInfoEx is a
        // documented info class; `&mut buffer` / `&mut bytes` are stack
        // ptrs the API writes into. On success `buffer` is OS-allocated
        // and released via WTSFreeMemory below.
        let ok = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE as HANDLE,
                session_id,
                WTSSessionInfoEx,
                &mut buffer,
                &mut bytes,
            )
        };
        if ok == 0 || buffer.is_null() {
            return None;
        }

        // For WTSSessionInfoEx the buffer is a `WTSINFOEXW`, not a
        // string — guard the returned size before reading it as one.
        let result = if (bytes as usize) >= std::mem::size_of::<WTSINFOEXW>() {
            // SAFETY: verified size ≥ WTSINFOEXW and the info class is
            // WTSSessionInfoEx, so the buffer is a valid WTSINFOEXW.
            let info = unsafe { &*(buffer as *const WTSINFOEXW) };
            if info.Level == 1 {
                // SAFETY: Level == 1 selects the Level1 union member.
                let flags = unsafe { info.Data.WTSInfoExLevel1.SessionFlags };
                classify_session_flags(flags)
            } else {
                None
            }
        } else {
            None
        };

        // SAFETY: pair Free with the successful Query above.
        unsafe { WTSFreeMemory(buffer as *mut core::ffi::c_void) };
        result
    }
}

#[cfg(not(target_os = "windows"))]
mod nowin {
    use super::LockState;
    /// Non-Windows hosts don't have the desktop-switch problem.
    /// Always report Unlocked so the encoder pump runs normally.
    pub fn probe_lock_state() -> LockState {
        LockState::Unlocked
    }
    pub fn probe_lock_state_detailed() -> (LockState, String) {
        (LockState::Unlocked, "Default".to_string())
    }
    /// No WTS session-lock concept off Windows — let the caller fall
    /// back to [`probe_lock_state`] (which is `Unlocked` here).
    ///
    /// FR-97 P2d-1 — except a Mac's GUI session, which can say: a consent
    /// panel is out of sight behind a locked screen, as Windows' is on the
    /// secure desktop, so the controller is told to unlock first. Still `None`
    /// outside a GUI session (the root half) and with `ROOMLERD_LOCK_HINT=0`.
    pub fn probe_lock_state_service() -> Option<LockState> {
        #[cfg(target_os = "macos")]
        if super::lock_hint_enabled() {
            return super::mac_locked_hint().map(|locked| {
                if locked {
                    LockState::Locked
                } else {
                    LockState::Unlocked
                }
            });
        }
        None
    }
}

#[cfg(not(target_os = "windows"))]
pub use nowin::{probe_lock_state, probe_lock_state_detailed, probe_lock_state_service};
#[cfg(target_os = "windows")]
pub use win::{probe_lock_state, probe_lock_state_detailed, probe_lock_state_service};

/// FR-97 P3b — how often a session asks whether its screen is locked: on
/// Linux logind, one `loginctl` run; on a Mac (P2d-1) the session dictionary,
/// one call. A lock is a person stepping away, so a couple of seconds late is
/// fine.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub const HINT_POLL: Duration = Duration::from_secs(2);

/// FR-97 P3b — Linux: logind's `LockedHint` for seat0's active session, the
/// screen a session sees. GNOME, KDE and light-locker set it; a locker that
/// does not (xscreensaver, i3lock) reads as unlocked, as `keep_busy` notes.
///
/// ⚠️ ADVISORY, and deliberately not a [`LockState`]. On Windows a lock moves
/// the input desktop where the worker can neither capture nor inject, so the
/// pump paints an overlay and suppresses input. A Linux lock screen is
/// captured like any other screen, and input reaches it: the person at the
/// viewer unlocks by typing. This feeds only the viewer's chip
/// (`rc:host_locked` with `input: "passes"`), never the overlay or the input
/// path. `ROOMLERD_LOCK_HINT=0` turns it off.
#[cfg(target_os = "linux")]
pub fn linux_locked_hint() -> bool {
    crate::lock_on_end::linux_active_session()
        .is_some_and(|id| crate::lock_on_end::linux_session_hint(&id, "LockedHint"))
}

/// FR-97 P2d-1 — a Mac: this session's screen is locked, or another user has
/// the console (`CGSSessionScreenIsLocked`, `kCGSSessionOnConsoleKey`, read as
/// keep busy reads them). `None` outside a GUI session: the root half has no
/// screen to ask about. Advisory, as on Linux; it never gates input.
#[cfg(target_os = "macos")]
pub fn mac_locked_hint() -> Option<bool> {
    #[cfg(feature = "enigo-input")]
    {
        crate::keep_busy::mac_screen_locked()
    }
    #[cfg(not(feature = "enigo-input"))]
    {
        None
    }
}

/// FR-97 P3b's kill switch for the lock hints (and P2d-1's on a Mac): on
/// unless `ROOMLERD_LOCK_HINT=0`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn lock_hint_enabled() -> bool {
    tunnel_core::env::node_env("LOCK_HINT").is_none_or(|v| v.trim() != "0")
}

/// The session's lock hint on this OS: logind's on Linux, the session
/// dictionary's on a Mac (unlocked when there is no session to ask).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn locked_hint() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux_locked_hint()
    }
    #[cfg(target_os = "macos")]
    {
        mac_locked_hint().unwrap_or(false)
    }
}

/// What the person at the viewer can do at this OS's lock screen, as the
/// `input` of `rc:host_locked`: a Linux lock screen takes input like any other
/// (`passes`); on a Mac it is not measured yet whether the lock screen's
/// password field takes injected keys, so the hint does not claim either way
/// (`unknown`).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub const LOCK_SCREEN_INPUT: &str = if cfg!(target_os = "linux") {
    "passes"
} else {
    "unknown"
};

/// Spawn a tokio task that polls `probe_lock_state` every
/// `POLL_INTERVAL` and emits transitions on the returned
/// `tokio::sync::watch::Receiver<LockState>`. The watch channel
/// is the right primitive here: late subscribers can read the
/// current value, and the pump only wakes when the value changes
/// (no busy loop on consumers).
///
/// ⚠️ The task ends when `until` is cancelled — the SESSION's end
/// (#1738). Dropping the returned `JoinHandle` does NOT stop it: tokio
/// detaches a task whose handle is dropped, it never aborts one. The
/// receiver-count exit (every `Receiver` gone) is only a backstop, and
/// it cannot fire while a consumer waits on `changed()`: that wait ends
/// only when the SENDER — owned by this task — drops. Before #1738 the
/// host-locked emitter was exactly such a consumer, so every session
/// left its monitor and its emitter polling for the life of the daemon.
pub fn spawn_monitor(
    until: tokio_util::sync::CancellationToken,
) -> (
    tokio::sync::watch::Receiver<LockState>,
    tokio::task::JoinHandle<()>,
) {
    spawn_monitor_every(POLL_INTERVAL, until)
}

/// [`spawn_monitor`] at `interval` (the tests poll fast).
fn spawn_monitor_every(
    interval: Duration,
    until: tokio_util::sync::CancellationToken,
) -> (
    tokio::sync::watch::Receiver<LockState>,
    tokio::task::JoinHandle<()>,
) {
    let (initial, initial_name) = probe_lock_state_detailed();
    tracing::info!(
        state = ?initial,
        desktop = %initial_name,
        "lock_state: monitor starting"
    );
    let (tx, rx) = tokio::sync::watch::channel(initial);
    let handle = tokio::spawn(async move {
        let mut last = initial;
        loop {
            tokio::select! {
                biased;
                _ = until.cancelled() => return,
                _ = tokio::time::sleep(interval) => {}
            }
            // Receiver-gone-shutdown, the BACKSTOP (the session's
            // `until` is the real end, #1738): when every receiver has
            // been dropped, the watch sender's `is_closed()` flips.
            // Without this check the monitor task can outlive its
            // consumers indefinitely because `tx.send()` only fires on
            // state *change* — a steady-Unlocked session never tries to
            // send, never notices the receivers are gone, and leaks the
            // task until runtime shutdown.
            if tx.is_closed() {
                return;
            }
            // rc.25 — use the detailed probe so the transition log
            // can carry the observed desktop name. Helps field
            // diagnose "input dropped while admin pwsh focused"
            // bugs by showing whether the probe saw "Default" (so
            // the bug is downstream) or "Winlogon"/other (so the
            // probe IS the bug).
            let (current, observed_name) = probe_lock_state_detailed();
            if current != last {
                tracing::info!(
                    from = ?last,
                    to = ?current,
                    desktop = %observed_name,
                    "lock_state: transition observed"
                );
                // We just confirmed the channel is open one tick
                // ago; if a race made it close between then and
                // now, the next tick's `is_closed` catches it.
                let _ = tx.send(current);
                last = current;
            }
        }
    });
    (rx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_default_with_access_is_unlocked() {
        assert_eq!(classify(true, "Default"), LockState::Unlocked);
    }

    #[test]
    fn classify_no_access_is_locked() {
        // The most common cause: input desktop transitioned to
        // Winlogon and the user-context probe got ACCESS_DENIED.
        assert_eq!(classify(false, ""), LockState::Locked);
        assert_eq!(classify(false, "Default"), LockState::Locked);
    }

    #[test]
    fn session_flags_lock_unlock_unknown() {
        // Modern Windows: 0 = LOCK, 1 = UNLOCK. FR-34 P3b consent probe.
        assert_eq!(classify_session_flags(0), Some(LockState::Locked));
        assert_eq!(classify_session_flags(1), Some(LockState::Unlocked));
        // WTS_SESSIONSTATE_UNKNOWN (-1) and any unexpected value must
        // return None so the emit path falls back rather than guessing
        // — a false "locked" indication is worse than deferring.
        assert_eq!(classify_session_flags(-1), None);
        assert_eq!(classify_session_flags(2), None);
    }

    #[test]
    fn classify_other_desktop_name_is_locked() {
        // Citrix / RDP / custom desktops aren't accessible to our
        // user-context capture either; treat as Locked.
        assert_eq!(classify(true, "Winlogon"), LockState::Locked);
        assert_eq!(classify(true, "Disconnect"), LockState::Locked);
        assert_eq!(classify(true, "Citrix__1"), LockState::Locked);
        assert_eq!(classify(true, ""), LockState::Locked);
    }

    #[test]
    fn classify_is_case_sensitive_on_default() {
        // Win32 documents desktop name compares as case-sensitive.
        // "default" lower-case is NOT the same desktop as "Default";
        // treat as Locked rather than risk a false-unlocked that
        // sends bad capture frames.
        assert_eq!(classify(true, "default"), LockState::Locked);
        assert_eq!(classify(true, "DEFAULT"), LockState::Locked);
    }

    /// #1738 — the monitor ends with its SESSION, even while a consumer
    /// waits on `changed()`. That consumer keeps the channel open, so the
    /// receiver-count exit can never fire: before the fix the pair polled
    /// for the life of the daemon, once per session ever held.
    #[tokio::test]
    async fn the_monitor_ends_with_its_session_even_while_a_consumer_waits() {
        const TICK: Duration = Duration::from_millis(10);
        let until = tokio_util::sync::CancellationToken::new();
        let (rx, monitor) = spawn_monitor_every(TICK, until.clone());
        // The host-locked emitter's shape: parked on `changed()`, which
        // only ends when the sender (the monitor's) drops.
        let mut waiting = rx.clone();
        let consumer = tokio::spawn(async move { while waiting.changed().await.is_ok() {} });

        // Many polls later, with the handle still held: both alive — the
        // leak's precondition, and proof the monitor is really polling.
        tokio::time::sleep(TICK * 20).await;
        assert!(
            !monitor.is_finished(),
            "the monitor runs while its session lives"
        );
        assert!(!consumer.is_finished());

        until.cancel();
        tokio::time::timeout(TICK * 50, monitor)
            .await
            .expect("the monitor ends when its session does")
            .unwrap();
        tokio::time::timeout(TICK * 50, consumer)
            .await
            .expect("the consumer's wait ends once the sender is gone")
            .unwrap();
        // A late reader still reads the last state, never a panic.
        let _last = *rx.borrow();
    }

    /// The backstop still holds: with every receiver gone, the monitor
    /// ends on its own even if nobody cancels it.
    #[tokio::test]
    async fn the_monitor_also_ends_when_every_receiver_is_gone() {
        const TICK: Duration = Duration::from_millis(10);
        let until = tokio_util::sync::CancellationToken::new();
        let (rx, monitor) = spawn_monitor_every(TICK, until);
        drop(rx);
        tokio::time::timeout(TICK * 50, monitor)
            .await
            .expect("no receiver left ⇒ the monitor ends")
            .unwrap();
    }

    #[test]
    fn poll_interval_is_500ms() {
        // Lock the cadence: too-fast burns CPU on every host with
        // an installed agent (forever); too-slow leaves a visible
        // freeze on lock that confuses operators.
        assert_eq!(POLL_INTERVAL, Duration::from_millis(500));
    }

    #[test]
    fn lock_state_round_trip() {
        // The PartialEq derive lets us compare LockState values in
        // the watch-channel send-only-on-change path. Pin the
        // contract: equal variants must compare equal.
        assert_eq!(LockState::Locked, LockState::Locked);
        assert_eq!(LockState::Unlocked, LockState::Unlocked);
        assert_ne!(LockState::Locked, LockState::Unlocked);
    }

    /// FR-97 P2d-1 — what each OS's lock hint tells the viewer about input:
    /// a Linux lock screen takes it (P3b's chip, unchanged); a Mac's is not
    /// measured, so it claims neither way.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn lock_screen_input_per_os() {
        let want = if cfg!(target_os = "linux") {
            "passes"
        } else {
            "unknown"
        };
        assert_eq!(LOCK_SCREEN_INPUT, want);
        assert_eq!(HINT_POLL, Duration::from_secs(2));
    }
}
