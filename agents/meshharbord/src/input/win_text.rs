// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows real-virtual-key text injection (rc.122).
//!
//! The browser sends each typed printable character as a `KeyText` message.
//! The previous path called `enigo.text()`, which on Windows injects every
//! character via `KEYEVENTF_UNICODE` (VK_PACKET). The **legacy Windows console
//! host** (Windows PowerShell 5.1 / cmd.exe in conhost) silently DROPS
//! VK_PACKET-injected characters — field-confirmed on REGAL-112500982: typed
//! letters never appeared in an elevated *Windows PowerShell*, but DID appear
//! in `pwsh` 7 / Windows Terminal (which accept VK_PACKET), while Enter /
//! Backspace (real virtual keys) worked everywhere. (rc.120 already proved this
//! is NOT a UIPI integrity block: worker = System 0x4000 > foreground
//! powershell.exe High 0x3000.)
//!
//! This module injects each character as a **real virtual key + scancode**
//! (`KEYEVENTF_SCANCODE`), resolved through the foreground window's active
//! keyboard layout via `VkKeyScanExW`, pressing Shift/Ctrl/Alt exactly as the
//! layout requires. Real key events are accepted by the legacy console.
//! Characters not present in the active layout (Latin under a Cyrillic-only
//! layout, emoji, CJK) fall back to `KEYEVENTF_UNICODE` — identical to the old
//! behaviour, so those cases are no worse than before (and still work in modern
//! terminals / GUI apps).
//!
//! ## Why not enigo
//!
//! enigo's `text()` is VK_PACKET-only. enigo's `key(Key::Unicode(c))` calls
//! `VkKeyScanExW` but keeps only the VK low byte and NEVER presses Shift
//! (keycodes.rs:1073 `VIRTUAL_KEY(vk as u16)`), so capitals and shifted symbols
//! ('A', '(', '!') would mis-type. Neither is usable, hence this hand-rolled path.
//!
//! ## Kill switch
//!
//! `ROOMLERD_UNICODE_TEXT=1` reverts to the old `enigo.text()`
//! (KEYEVENTF_UNICODE) path without a redeploy, in case the real-VK path
//! regresses on some host.

#![cfg(all(target_os = "windows", feature = "enigo-input"))]

use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetKeyState, GetKeyboardLayout, HKL, INPUT, INPUT_0, INPUT_KEYBOARD,
    KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MAPVK_VK_TO_VSC,
    MapVirtualKeyExW, SendInput, VK_CAPITAL, VK_CONTROL, VK_MENU, VK_RETURN, VK_SHIFT, VK_TAB,
    VkKeyScanExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

use tunnel_core::env::node_env;

/// Whether the operator has forced the old KEYEVENTF_UNICODE-only path.
pub(super) fn unicode_only() -> bool {
    matches!(
        node_env("UNICODE_TEXT").map(|s| s.trim().to_ascii_lowercase()),
        Some(v) if v == "1" || v == "true" || v == "yes" || v == "on"
    )
}

/// Build one keyboard `INPUT` record.
fn kbd(vk: u16, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &[INPUT]) {
    if inputs.is_empty() {
        return;
    }
    // SAFETY: `inputs` is a valid contiguous slice of INPUT; cbSize is the
    // element size. SendInput copies the records; no aliasing concerns.
    unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        );
    }
}

/// Decompose a `VkKeyScanExW` result into `(vk, shift, ctrl, alt)`, or `None`
/// when the character isn't reachable on the layout (`-1`) or maps to no key.
/// Pulled out as a pure fn so the bit math is unit-testable without the OS.
/// `pub(super)` so `layout::resolve_layout_for_char` scans candidate layouts
/// with exactly the same reachability semantics as the injection path.
pub(super) fn decode_vk_scan(res: i16) -> Option<(u16, bool, bool, bool)> {
    if res == -1 {
        return None;
    }
    let vk = (res & 0x00ff) as u16;
    if vk == 0 || vk == 0x00ff {
        return None;
    }
    let shift_state = ((res >> 8) & 0xff) as u8;
    Some((
        vk,
        shift_state & 0x01 != 0,
        shift_state & 0x02 != 0,
        shift_state & 0x04 != 0,
    ))
}

/// Whether pre-held-modifier neutralization is enabled (default ON).
/// `ROOMLERD_TEXT_MOD_NEUTRALIZE=0` (or the `text_mod_neutralize`
/// config key) reverts to the pre-2026-08 behaviour of layering the
/// layout's wanted modifiers ON TOP of whatever is physically held.
fn neutralize_enabled() -> bool {
    !matches!(
        node_env("TEXT_MOD_NEUTRALIZE").map(|s| s.trim().to_ascii_lowercase()),
        Some(v) if v == "0" || v == "false" || v == "no" || v == "off"
    )
}

/// One planned modifier transition: `(vk, down)`.
type ModStep = (u16, bool);

/// Plan the modifier presses/releases around a scancode tap so the OS sees
/// EXACTLY the modifier state the layout wants — regardless of what the
/// operator is physically holding.
///
/// The browser forwards Shift/Ctrl/Alt as REAL HID keys (they are physically
/// down on the host) while printable characters arrive separately as
/// `KeyText`. `VkKeyScanExW` computes the modifiers the REMOTE layout wants
/// from scratch; the old tap only ADDED wanted modifiers, so a held Shift
/// leaked into the tap: US-viewer `Shift+=` ('+') on a German host injected
/// a bare VK_OEM_PLUS scancode under physical Shift → '*'; German '|'
/// (AltGr+<) became Ctrl+Alt+SHIFT+< → dead key. Field report 2026-08-03.
///
/// `current`/`wanted` are `[ctrl, alt, shift]` (tap press order). Returns
/// `(pre, post)`: `pre` runs before the scancode, `post` after — `post`
/// restores the operator's physical state in reverse order, so their held
/// Shift keeps working for the NEXT chord (the browser still owns its
/// eventual release).
pub(super) fn plan_mod_transitions(
    current: [bool; 3],
    wanted: [bool; 3],
) -> (Vec<ModStep>, Vec<ModStep>) {
    const VKS: [u16; 3] = [VK_CONTROL, VK_MENU, VK_SHIFT];
    let mut pre: Vec<ModStep> = Vec::with_capacity(3);
    let mut post: Vec<ModStep> = Vec::with_capacity(3);
    for i in 0..3 {
        match (current[i], wanted[i]) {
            // Wanted but not held: press for the tap, release after.
            (false, true) => {
                pre.push((VKS[i], true));
                post.push((VKS[i], false));
            }
            // Held but unwanted: NEUTRALIZE — release for the tap, restore
            // after (the operator is still physically holding it).
            (true, false) => {
                pre.push((VKS[i], false));
                post.push((VKS[i], true));
            }
            // Held AND wanted: leave it alone (the old code pressed and
            // then RELEASED it, yanking a physically held modifier away
            // mid-chord). Not held and not wanted: nothing to do.
            _ => {}
        }
    }
    post.reverse();
    (pre, post)
}

/// Physical down-state of `[Ctrl, Alt, Shift]` right now. `GetAsyncKeyState`
/// reads the GLOBAL async state (injected keys from the browser's HID path
/// included), unlike the per-thread-queue `GetKeyState`.
fn physical_mods_down() -> [bool; 3] {
    // SAFETY: plain state queries.
    unsafe {
        [
            GetAsyncKeyState(VK_CONTROL as i32) as u16 & 0x8000 != 0,
            GetAsyncKeyState(VK_MENU as i32) as u16 & 0x8000 != 0,
            GetAsyncKeyState(VK_SHIFT as i32) as u16 & 0x8000 != 0,
        ]
    }
}

/// Tap a real virtual key (down+up) with the required modifier state, using
/// the scancode so the legacy console accepts it. `hkl` is the active layout.
/// Pre-held modifiers that the layout does NOT want are temporarily released
/// and restored afterwards (see [`plan_mod_transitions`]).
fn tap_vk(vk: u16, shift: bool, ctrl: bool, alt: bool, hkl: HKL) {
    // SAFETY: MapVirtualKeyExW with a valid VK + layout handle; returns 0 when
    // there's no scancode mapping, which we handle below.
    let scan = unsafe { MapVirtualKeyExW(vk as u32, MAPVK_VK_TO_VSC, hkl) } as u16;
    // With neutralization off, pretend nothing is held: the plan degrades to
    // exactly the legacy press-wanted/release-wanted sequence.
    let current = if neutralize_enabled() {
        physical_mods_down()
    } else {
        [false; 3]
    };
    let (pre, post) = plan_mod_transitions(current, [ctrl, alt, shift]);
    let mut inputs: Vec<INPUT> = Vec::with_capacity(pre.len() + post.len() + 2);
    for &(mvk, down) in &pre {
        inputs.push(kbd(mvk, 0, if down { 0 } else { KEYEVENTF_KEYUP }));
    }
    if scan != 0 {
        inputs.push(kbd(0, scan, KEYEVENTF_SCANCODE));
        inputs.push(kbd(0, scan, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP));
    } else {
        // No scancode mapping — fall back to a plain virtual-key tap.
        inputs.push(kbd(vk, 0, 0));
        inputs.push(kbd(vk, 0, KEYEVENTF_KEYUP));
    }
    for &(mvk, down) in &post {
        inputs.push(kbd(mvk, 0, if down { 0 } else { KEYEVENTF_KEYUP }));
    }
    send(&inputs);
}

/// Inject a single character via `KEYEVENTF_UNICODE` (VK_PACKET). Layout-
/// independent but dropped by the legacy console — the last-resort fallback.
fn send_unicode(c: char) {
    let mut buf = [0u16; 2];
    let units = c.encode_utf16(&mut buf);
    let mut inputs: Vec<INPUT> = Vec::with_capacity(units.len() * 2);
    for &u in units.iter() {
        inputs.push(kbd(0, u, KEYEVENTF_UNICODE));
        inputs.push(kbd(0, u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
    }
    send(&inputs);
}

/// Read the target's CapsLock toggle state. `GetKeyState`'s toggle bit is
/// per-thread-input-queue, and the SYSTEM-context worker doesn't pump messages,
/// so we briefly `AttachThreadInput` to the foreground thread to share its key
/// state for an accurate read. Best-effort: a failed attach falls back to the
/// worker's own state (CapsLock treated as off → no compensation).
fn capslock_on(fg_tid: u32) -> bool {
    // SAFETY: Attach/Detach are paired; GetKeyState reads thread-queue state.
    unsafe {
        let our_tid = GetCurrentThreadId();
        let attach = fg_tid != 0 && fg_tid != our_tid;
        if attach {
            AttachThreadInput(our_tid, fg_tid, 1);
        }
        let on = (GetKeyState(VK_CAPITAL as i32) & 0x0001) != 0;
        if attach {
            AttachThreadInput(our_tid, fg_tid, 0);
        }
        on
    }
}

/// Type `text` into the foreground window. Per character: real VK+scancode when
/// the active layout can produce it (legacy-console-compatible); when it can't
/// but ANOTHER installed layout can, auto-switch the foreground layout (rc.227
/// — the programmatic ALT+SHIFT, see `input::layout`) and inject under it;
/// else Unicode (VK_PACKET).
pub(super) fn type_text(text: &str) {
    // The active layout is the FOREGROUND thread's — that's what interprets the
    // injected scancodes. Read hwnd + tid + layout once per call; the hwnd is
    // needed by the auto-switch (WM_INPUTLANGCHANGEREQUEST targets it). A
    // focus change mid-string leaves them stale — the switch verify then
    // times out into the cooldown, and the char degrades to Unicode.
    // SAFETY: GetForegroundWindow may return null (no foreground); GetKeyboard-
    // Layout(0) then returns the calling thread's layout, a safe default.
    let (fg_hwnd, fg_tid): (windows_sys::Win32::Foundation::HWND, u32) = unsafe {
        let hwnd = GetForegroundWindow();
        let tid = GetWindowThreadProcessId(hwnd, std::ptr::null_mut());
        (hwnd, tid)
    };
    // SAFETY: plain read of the thread's active layout.
    let mut hkl: HKL = unsafe { GetKeyboardLayout(fg_tid) };
    // rc.123 — scancode injection is subject to the TARGET's CapsLock (unlike the
    // old KEYEVENTF_UNICODE path, which ignored it). REGAL-112500982 had CapsLock
    // toggled ON → every injected letter came out with inverted case. VkKeyScanExW
    // computes the shift state assuming CapsLock OFF, so when it's ON we flip the
    // shift bit for ALPHABETIC chars (CapsLock only affects letters). Non-letters
    // and the Unicode fallback are unaffected. Hosts with CapsLock off (e.g.
    // WINHOST-A) read `false` here → no change.
    let caps = capslock_on(fg_tid);
    let mut switches_this_call: u32 = 0;
    for c in text.chars() {
        match c {
            '\n' | '\r' => tap_vk(VK_RETURN, false, false, false, hkl),
            '\t' => tap_vk(VK_TAB, false, false, false, hkl),
            '\0' => {}
            _ => {
                let mut buf = [0u16; 2];
                let units = c.encode_utf16(&mut buf);
                if units.len() != 1 {
                    // Astral (emoji) — never a single VK on any layout.
                    send_unicode(c);
                    continue;
                }
                let unit = units[0];
                // SAFETY: single UTF-16 unit + valid layout handle.
                if let Some((vk, shift, ctrl, alt)) =
                    decode_vk_scan(unsafe { VkKeyScanExW(unit, hkl) })
                {
                    // Reachable on the ACTIVE layout — the common case,
                    // and the inherent hysteresis: it never triggers a
                    // switch, so same-script runs are switch-free.
                    let shift = if caps && c.is_alphabetic() {
                        !shift
                    } else {
                        shift
                    };
                    tap_vk(vk, shift, ctrl, alt, hkl);
                    continue;
                }
                // rc.227 — char unreachable on the active layout. The old
                // behavior (VK_PACKET) is dropped by conhost/legacy apps;
                // when another INSTALLED layout can produce the char,
                // switch the foreground layout to it — exactly what the
                // operator used to do manually with ALT+SHIFT.
                if !super::layout::auto_layout_enabled()
                    || switches_this_call >= super::layout::MAX_SWITCHES_PER_CALL
                    || super::layout::cooldown_active()
                {
                    send_unicode(c);
                    continue;
                }
                match super::layout::resolve_layout_for_char(unit, hkl) {
                    None => send_unicode(c), // reachable nowhere (e.g. 'ä', no German layout)
                    Some(candidate) => {
                        if super::layout::switch_active_layout(fg_hwnd, fg_tid, candidate) {
                            let from = hkl;
                            hkl = candidate;
                            super::layout::record_good_layout(candidate);
                            switches_this_call += 1;
                            if super::layout::should_log_switch() {
                                // Privacy: NEVER the literal char — script
                                // class only (lock-screen passwords flow
                                // through here).
                                tracing::info!(
                                    from = %super::layout::format_hkl(from),
                                    to = %super::layout::format_hkl(candidate),
                                    script = super::layout::script_class(c),
                                    "layout auto-switch OK"
                                );
                            }
                            // Publish the new state so the viewer chip
                            // flips immediately.
                            super::layout::sample_active_layout();
                            match decode_vk_scan(unsafe { VkKeyScanExW(unit, hkl) }) {
                                Some((vk, shift, ctrl, alt)) => {
                                    let shift = if caps && c.is_alphabetic() {
                                        !shift
                                    } else {
                                        shift
                                    };
                                    tap_vk(vk, shift, ctrl, alt, hkl);
                                }
                                // Shouldn't happen (resolve proved it) —
                                // defensive fallback.
                                None => send_unicode(c),
                            }
                        } else {
                            super::layout::arm_cooldown();
                            tracing::warn!(
                                from = %super::layout::format_hkl(hkl),
                                to = %super::layout::format_hkl(candidate),
                                "layout auto-switch: foreground app ignored WM_INPUTLANGCHANGEREQUEST — Unicode fallback + cooldown"
                            );
                            send_unicode(c);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_unreachable_is_none() {
        assert!(decode_vk_scan(-1).is_none());
    }

    #[test]
    fn decode_plain_letter() {
        // Vk 0x41 (VK_A), no modifiers.
        assert_eq!(decode_vk_scan(0x0041), Some((0x41, false, false, false)));
    }

    #[test]
    fn decode_shifted_symbol() {
        // VkKeyScan for '(' on US = VK_9 (0x39) + shift (high byte 0x01) = 0x0139.
        assert_eq!(decode_vk_scan(0x0139), Some((0x39, true, false, false)));
    }

    #[test]
    fn decode_altgr_combo() {
        // Ctrl+Alt (AltGr) state in the high byte (0x06) over VK_Q (0x51).
        assert_eq!(decode_vk_scan(0x0651), Some((0x51, false, true, true)));
    }

    #[test]
    fn decode_zero_vk_is_none() {
        assert!(decode_vk_scan(0x0100).is_none()); // shift set but VK == 0
    }

    // ── plan_mod_transitions (2026-08-04 neutralization) ────────────

    #[test]
    fn plan_legacy_no_held_presses_and_releases_wanted() {
        // current all-up + wanted ctrl/alt/shift = the legacy sequence:
        // press in ctrl,alt,shift order, release in reverse.
        let (pre, post) = plan_mod_transitions([false; 3], [true, true, true]);
        assert_eq!(
            pre,
            vec![(VK_CONTROL, true), (VK_MENU, true), (VK_SHIFT, true)]
        );
        assert_eq!(
            post,
            vec![(VK_SHIFT, false), (VK_MENU, false), (VK_CONTROL, false)]
        );
    }

    #[test]
    fn plan_held_shift_unwanted_is_neutralized_and_restored() {
        // The field bug: US-viewer Shift+'=' ('+') with German remote layout —
        // '+' is UNSHIFTED there, but the browser-held Shift leaked in → '*'.
        let (pre, post) = plan_mod_transitions([false, false, true], [false, false, false]);
        assert_eq!(pre, vec![(VK_SHIFT, false)]);
        assert_eq!(post, vec![(VK_SHIFT, true)]);
    }

    #[test]
    fn plan_altgr_with_held_shift_releases_shift_adds_ctrl_alt() {
        // '|' on German = AltGr+'<' (ctrl+alt wanted, shift NOT) while the
        // viewer physically holds Shift — the poisoned chord was
        // Ctrl+Alt+Shift+key = dead key.
        let (pre, post) = plan_mod_transitions([false, false, true], [true, true, false]);
        assert_eq!(
            pre,
            vec![(VK_CONTROL, true), (VK_MENU, true), (VK_SHIFT, false)]
        );
        assert_eq!(
            post,
            vec![(VK_SHIFT, true), (VK_MENU, false), (VK_CONTROL, false)]
        );
    }

    #[test]
    fn plan_held_and_wanted_is_left_alone() {
        // US 'A' with the operator physically holding Shift: wanted == held —
        // do NOT press-and-release (the old code yanked the held Shift away).
        let (pre, post) = plan_mod_transitions([false, false, true], [false, false, true]);
        assert!(pre.is_empty());
        assert!(post.is_empty());
    }

    #[test]
    fn plan_noop_when_nothing_held_nothing_wanted() {
        let (pre, post) = plan_mod_transitions([false; 3], [false; 3]);
        assert!(pre.is_empty());
        assert!(post.is_empty());
    }
}
