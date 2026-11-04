// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows keyboard-layout awareness + auto-switch (rc.227).
//!
//! The field symptom this fixes: viewer keyboard = German, remote =
//! Cyrillic Bulgarian → every typed Latin char resolves against the
//! remote's ACTIVE layout in `win_text::type_text`, `VkKeyScanExW`
//! returns -1, and the char falls back to VK_PACKET — which conhost /
//! legacy apps drop. Typing feels dead until the operator manually
//! presses ALT+SHIFT on the remote (flipping its active layout to a
//! Latin one). This module AUTOMATES that exact switch:
//!
//! 1. [`resolve_layout_for_char`] finds an INSTALLED layout that can
//!    produce the unreachable char (last-good-first, IME layouts
//!    excluded — never auto-switch INTO an IME).
//! 2. [`switch_active_layout`] posts `WM_INPUTLANGCHANGEREQUEST` to
//!    the foreground window — the OS's own ALT+SHIFT mechanism — and
//!    verify-polls `GetKeyboardLayout(fg_tid)` for ≤100 ms (the
//!    message is asynchronous and apps MAY ignore it).
//! 3. `win_text::type_text` then re-resolves and injects a real
//!    VK+scancode under the new layout. On verify timeout it falls
//!    back to VK_PACKET and arms a cooldown so a stubborn foreground
//!    app (games, custom message loops) degrades to today's behavior
//!    instead of stalling every keystroke.
//!
//! Status reporting: [`sample_active_layout`] publishes a
//! [`LayoutSnapshot`] (active + installed layouts as opaque 8-hex HKL
//! strings + BCP-47 tags) into a process-global watch channel; the
//! peer's control-DC emitter forwards it as `rc:layout` so the viewer
//! can render a layout chip and a manual picker. Manual switches
//! arrive as `rc:layout.set {hkl}` → [`request_set_layout`], which
//! validates the value against the CURRENT installed list (never
//! activates arbitrary wire input) — the resulting `rc:layout` push
//! is the implicit ack.
//!
//! Sampling runs on the INJECTOR worker thread (piggybacked on input
//! dispatch) — the only thread guaranteed desktop-bound under the
//! SYSTEM-context worker. `request_set_layout` spawns a fresh thread
//! per command (rare, user-clicked) with the same desktop-rebind
//! preamble.
//!
//! Kill switch: `ROOMLERD_AUTO_LAYOUT=0` (the older `ROOMLER_NODE_` and
//! prefix is still honoured) disables the per-char
//! auto-switch without a redeploy;
//! status reporting + manual set stay active.

#![cfg(all(target_os = "windows", feature = "enigo-input"))]

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use tunnel_core::env::node_env;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Globalization::LCIDToLocaleName;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyboardLayout, GetKeyboardLayoutList, HKL, VkKeyScanExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowThreadProcessId, PostMessageW, WM_INPUTLANGCHANGEREQUEST,
};

/// Verify-poll cadence + budget for [`switch_active_layout`]. The
/// injector thread is dedicated, so briefly blocking ≤100 ms is safe;
/// the cooldown prevents paying it per keystroke against apps that
/// ignore the request.
const VERIFY_POLL_MS: u64 = 5;
const VERIFY_TOTAL_MS: u64 = 100;
/// Cooldown armed after a verify timeout — VK_PACKET fallback runs
/// un-delayed until it expires.
pub(super) const SWITCH_COOLDOWN_MS: u64 = 3000;
/// Bound on auto-switches within one `type_text` call (multi-char
/// paste-as-keystrokes bursts; interactive typing is one char/call).
pub(super) const MAX_SWITCHES_PER_CALL: u32 = 8;

/// Cross-call hysteresis: the last layout an auto-switch landed on.
/// Checked before scanning the installed list so alternating-script
/// typing ping-pongs between exactly two layouts without a scan.
static LAST_GOOD_HKL: AtomicUsize = AtomicUsize::new(0);
/// `now_ms()` deadline until which auto-switching is suppressed.
static SWITCH_COOLDOWN_UNTIL_MS: AtomicU64 = AtomicU64::new(0);
/// Rate-limited switch logging: first 10, then every 50th.
static SWITCH_LOG_COUNT: AtomicU32 = AtomicU32::new(0);
/// Last HKL published through the watch channel (hot-path dedup).
static LAST_PUBLISHED_HKL: AtomicUsize = AtomicUsize::new(0);
/// Counter for [`maybe_sample_coarse`] (every 32nd mouse event).
static COARSE_SAMPLE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Whether the per-char auto-switch is enabled. Default ON;
/// `ROOMLERD_AUTO_LAYOUT=0|false|no|off` disables.
pub fn auto_layout_enabled() -> bool {
    static ENABLED: LazyLock<bool> =
        LazyLock::new(|| parse_auto_layout_flag(node_env("AUTO_LAYOUT").as_deref()));
    *ENABLED
}

/// Pure parse for the kill switch — inverted default vs
/// `parse_virtual_screen_flag` (this feature defaults ON).
pub(crate) fn parse_auto_layout_flag(value: Option<&str>) -> bool {
    match value {
        Some(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        None => true,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn cooldown_active() -> bool {
    now_ms() < SWITCH_COOLDOWN_UNTIL_MS.load(Ordering::Relaxed)
}

pub(super) fn arm_cooldown() {
    SWITCH_COOLDOWN_UNTIL_MS.store(now_ms() + SWITCH_COOLDOWN_MS, Ordering::Relaxed);
}

pub(super) fn record_good_layout(hkl: HKL) {
    LAST_GOOD_HKL.store(hkl as usize, Ordering::Relaxed);
}

/// Rate-limited switch log: `true` when this switch should be logged
/// at info (first 10, then every 50th).
pub(super) fn should_log_switch() -> bool {
    let n = SWITCH_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
    n < 10 || n.is_multiple_of(50)
}

/// Enumerate the host's installed keyboard layouts.
fn installed_layouts() -> Vec<HKL> {
    // SAFETY: standard two-call pattern — count, then fill.
    unsafe {
        let n = GetKeyboardLayoutList(0, std::ptr::null_mut());
        if n <= 0 {
            return Vec::new();
        }
        let mut v: Vec<HKL> = vec![std::ptr::null_mut(); n as usize];
        let got = GetKeyboardLayoutList(n, v.as_mut_ptr());
        v.truncate(got.max(0) as usize);
        v
    }
}

/// IME device layouts have 0xE in the device nibble (bits 28-31 of
/// the handle value). Auto-switching INTO an IME would leave the host
/// in composition mode — exclude them from candidate scans.
pub(crate) fn is_ime_layout_value(hkl_value: usize) -> bool {
    (hkl_value >> 28) & 0xF == 0xE
}

fn is_ime_layout(hkl: HKL) -> bool {
    is_ime_layout_value(hkl as usize)
}

/// Find an installed, non-IME layout (≠ active) that CAN produce
/// `unit`. Resolve order: the last auto-switch target first (cheap
/// two-layout ping-pong for mixed-script typing), then the installed
/// list in enumeration order. `None` → the char is reachable on no
/// installed layout (e.g. 'ä' with no German layout) — the caller
/// keeps today's VK_PACKET fallback.
pub(super) fn resolve_layout_for_char(unit: u16, active: HKL) -> Option<HKL> {
    // SAFETY: VkKeyScanExW is a pure lookup against a layout handle.
    let resolves =
        |hkl: HKL| super::win_text::decode_vk_scan(unsafe { VkKeyScanExW(unit, hkl) }).is_some();
    let installed = installed_layouts();
    let last = LAST_GOOD_HKL.load(Ordering::Relaxed);
    if last != 0 && last != active as usize {
        let last_hkl = last as HKL;
        if installed.iter().any(|&h| h as usize == last) && resolves(last_hkl) {
            return Some(last_hkl);
        }
    }
    installed
        .into_iter()
        .find(|&h| !std::ptr::eq(h, active) && !is_ime_layout(h) && resolves(h))
}

/// The programmatic ALT+SHIFT: ask the foreground window to activate
/// `target` and verify-poll the thread's layout for ≤100 ms. `false`
/// on timeout (app ignored the request — caller arms the cooldown).
pub(super) fn switch_active_layout(fg_hwnd: HWND, fg_tid: u32, target: HKL) -> bool {
    if fg_hwnd.is_null() {
        return false;
    }
    // SAFETY: PostMessageW with a valid-or-stale HWND is safe (a stale
    // handle just fails / no-ops → verify times out → cooldown).
    unsafe {
        PostMessageW(fg_hwnd, WM_INPUTLANGCHANGEREQUEST, 0, target as isize);
    }
    for _ in 0..(VERIFY_TOTAL_MS / VERIFY_POLL_MS) {
        std::thread::sleep(std::time::Duration::from_millis(VERIFY_POLL_MS));
        // SAFETY: plain read of the thread's active layout.
        let now = unsafe { GetKeyboardLayout(fg_tid) };
        if std::ptr::eq(now, target) {
            return true;
        }
    }
    false
}

/// Coarse script class for privacy-safe switch logging — lock-screen
/// passwords traverse `type_text`, so the literal char must NEVER be
/// logged (rc.121 precedent).
pub(super) fn script_class(c: char) -> &'static str {
    if c.is_ascii() {
        "latin"
    } else if ('\u{0400}'..='\u{04FF}').contains(&c) {
        "cyrillic"
    } else if ('\u{0370}'..='\u{03FF}').contains(&c) {
        "greek"
    } else {
        "other"
    }
}

// ── Status reporting (rc:layout over the control DC) ────────────────────────

/// Snapshot of the host's keyboard-layout state, published on change.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutSnapshot {
    /// Active layout as an opaque 8-hex HKL string (`format_hkl`).
    pub active_hkl: String,
    /// BCP-47 tag of the active layout ("bg-BG"), or the LANGID in
    /// hex when the OS can't name it.
    pub active_tag: String,
    /// Installed (non-IME) layouts as `(hkl_hex, tag)` pairs.
    pub installed: Vec<(String, String)>,
}

type LayoutWatchPair = (
    tokio::sync::watch::Sender<Option<LayoutSnapshot>>,
    tokio::sync::watch::Receiver<Option<LayoutSnapshot>>,
);

static LAYOUT_WATCH: LazyLock<LayoutWatchPair> = LazyLock::new(|| {
    let (tx, rx) = tokio::sync::watch::channel(None);
    (tx, rx)
});

/// Subscribe to layout-state changes. The receiver starts at the
/// last-known snapshot (`None` before the first input event).
pub fn subscribe() -> tokio::sync::watch::Receiver<Option<LayoutSnapshot>> {
    LAYOUT_WATCH.1.clone()
}

/// FR-97 P3e — every Windows session has layouts to report; the X11 module
/// answers this per host, and the peer asks both the same way.
pub fn offered() -> bool {
    true
}

/// FR-97 P3e — the last snapshot, for a control channel that just opened.
pub fn current() -> Option<LayoutSnapshot> {
    LAYOUT_WATCH.1.borrow().clone()
}

/// Opaque wire form of an HKL: the low 32 bits as 8 hex digits (HKLs
/// are sign-extended 32-bit handles on 64-bit Windows). The browser
/// echoes these back verbatim in `rc:layout.set`.
pub(crate) fn format_hkl(hkl: HKL) -> String {
    format!("{:08x}", (hkl as usize) & 0xffff_ffff)
}

/// Parse the wire form back. `None` on anything that isn't 1-16 hex
/// digits (defensive — the peer.rs arm pre-validates too).
pub(crate) fn parse_hkl(s: &str) -> Option<usize> {
    if s.is_empty() || s.len() > 16 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(s, 16).ok()
}

/// LANGID (LOWORD of the HKL) → BCP-47 tag via `LCIDToLocaleName`;
/// falls back to the LANGID in hex for layouts the OS can't name.
pub(crate) fn hkl_to_tag(hkl: HKL) -> String {
    const LOCALE_NAME_MAX_LENGTH: usize = 85;
    let langid = (hkl as usize) & 0xffff;
    let mut buf = [0u16; LOCALE_NAME_MAX_LENGTH];
    // SAFETY: buf is a valid out buffer of the documented max length.
    let n = unsafe { LCIDToLocaleName(langid as u32, buf.as_mut_ptr(), buf.len() as i32, 0) };
    if n > 1 {
        String::from_utf16_lossy(&buf[..(n as usize - 1)])
    } else {
        format!("{langid:04x}")
    }
}

/// Sample the foreground thread's active layout; publish a fresh
/// snapshot when it changed. Hot path (unchanged): 2 syscalls + 1
/// atomic swap. Call from the injector thread only (desktop-bound
/// under the SYSTEM-context worker).
pub fn sample_active_layout() {
    // SAFETY: null-safe — GetKeyboardLayout(0) returns the calling
    // thread's layout when there's no foreground window.
    let hkl = unsafe {
        let tid = GetWindowThreadProcessId(GetForegroundWindow(), std::ptr::null_mut());
        GetKeyboardLayout(tid)
    };
    if hkl.is_null() {
        return;
    }
    if LAST_PUBLISHED_HKL.swap(hkl as usize, Ordering::Relaxed) == hkl as usize {
        return;
    }
    publish_snapshot(hkl);
}

/// Sampling hook for high-rate event arms (mouse moves): samples every
/// 32nd call so a layout change surfaces within a second of activity
/// without paying per-event.
pub fn maybe_sample_coarse() {
    if COARSE_SAMPLE_COUNT
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(32)
    {
        sample_active_layout();
    }
}

fn publish_snapshot(active: HKL) {
    let installed = installed_layouts()
        .into_iter()
        .filter(|&h| !is_ime_layout(h))
        .map(|h| (format_hkl(h), hkl_to_tag(h)))
        .collect();
    let snap = LayoutSnapshot {
        active_hkl: format_hkl(active),
        active_tag: hkl_to_tag(active),
        installed,
    };
    let _ = LAYOUT_WATCH.0.send_replace(Some(snap));
}

/// Handle `rc:layout.set {hkl}` — the viewer's manual layout picker.
/// Runs on a FRESH thread per command (rare, user-clicked; never
/// `SetThreadDesktop` on a pooled runtime thread). Validates the value
/// against the CURRENT installed list, switches, then re-samples —
/// the resulting `rc:layout` push is the implicit ack (or the
/// unchanged state snaps the viewer's select back on failure).
pub fn request_set_layout(hkl_hex: String) {
    let spawned = std::thread::Builder::new()
        .name("roomlerd-layout-set".into())
        .spawn(move || {
            // SYSTEM-context worker: bind this fresh thread to the
            // interactive desktop first (same preamble as the
            // injector's construction).
            #[cfg(feature = "system-context")]
            {
                use crate::system_context::{desktop_rebind, worker_role};
                if matches!(
                    worker_role::probe_self(),
                    Ok(worker_role::WorkerRole::SystemContext)
                ) {
                    if let Err(e) = desktop_rebind::attach_to_winsta0() {
                        tracing::warn!(%e, "layout: attach_to_winsta0 failed — proceeding on current desktop");
                    }
                    if let Err(e) = desktop_rebind::try_change_desktop() {
                        tracing::warn!(%e, "layout: try_change_desktop failed — proceeding on current desktop");
                    }
                }
            }
            let Some(target) = parse_hkl(&hkl_hex) else {
                tracing::warn!(hkl = %hkl_hex, "layout: malformed rc:layout.set value — refusing");
                return;
            };
            // Never activate arbitrary wire input — only layouts the
            // host actually has installed right now.
            let matched = installed_layouts()
                .into_iter()
                .find(|&h| (h as usize) & 0xffff_ffff == target & 0xffff_ffff);
            let Some(hkl) = matched else {
                tracing::warn!(hkl = %hkl_hex, "layout: not an installed layout — refusing");
                return;
            };
            // SAFETY: plain foreground reads.
            let (fg_hwnd, fg_tid) = unsafe {
                let hwnd = GetForegroundWindow();
                let tid = GetWindowThreadProcessId(hwnd, std::ptr::null_mut());
                (hwnd, tid)
            };
            if switch_active_layout(fg_hwnd, fg_tid, hkl) {
                record_good_layout(hkl);
                tracing::info!(hkl = %hkl_hex, tag = %hkl_to_tag(hkl), "layout: manual switch applied");
            } else {
                tracing::warn!(hkl = %hkl_hex, "layout: foreground app ignored the switch request");
            }
            sample_active_layout();
        });
    if let Err(e) = spawned {
        tracing::warn!(%e, "layout: could not spawn set-layout thread");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auto_layout_flag_defaults_on() {
        assert!(parse_auto_layout_flag(None));
        assert!(parse_auto_layout_flag(Some("1")));
        assert!(parse_auto_layout_flag(Some("true")));
        assert!(parse_auto_layout_flag(Some("anything-else")));
        assert!(!parse_auto_layout_flag(Some("0")));
        assert!(!parse_auto_layout_flag(Some("false")));
        assert!(!parse_auto_layout_flag(Some("NO")));
        assert!(!parse_auto_layout_flag(Some(" off ")));
    }

    #[test]
    fn hkl_wire_roundtrip() {
        // 8-hex lower-32-bit form round-trips through parse.
        let v = parse_hkl("04070407").unwrap();
        assert_eq!(v, 0x0407_0407);
        assert_eq!(format!("{v:08x}"), "04070407");
        assert!(parse_hkl("").is_none());
        assert!(parse_hkl("xyz").is_none());
        assert!(parse_hkl("0123456789abcdef0").is_none(), "17 digits");
        assert!(parse_hkl("ABCDEF01").is_some(), "upper hex accepted");
    }

    #[test]
    fn ime_nibble_exclusion() {
        assert!(is_ime_layout_value(0xE001_0411), "Japanese IME");
        assert!(!is_ime_layout_value(0x0407_0407), "plain German");
        assert!(
            !is_ime_layout_value(0xF001_0402),
            "0xF device nibble is not an IME"
        );
    }

    #[test]
    fn script_class_never_leaks_the_char() {
        assert_eq!(script_class('a'), "latin");
        assert_eq!(script_class('Z'), "latin");
        assert_eq!(script_class('д'), "cyrillic");
        assert_eq!(script_class('Ω'), "greek");
        assert_eq!(script_class('中'), "other");
        assert_eq!(script_class('ä'), "other");
    }
}
