// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! HID usage (page 0x07) → Linux `KEY_*`, mirroring the kernel's own
//! `hid_keyboard[]`.
//!
//! Lives outside [`super::uinput_backend`] because two consumers need it and
//! they are behind *different* features: the uinput injector (FR-36 P4,
//! `uinput-input`) writes these codes to `/dev/uinput`, and the portal input
//! path (FR-45 P4, `portal-capture`) sends the very same codes through
//! `RemoteDesktop.NotifyKeyboardKeycode` — the portal takes evdev keycodes,
//! not X keycodes and not keysyms, exactly as gnome-remote-desktop sends them.
//!
//! ⚠️ This CANNOT be arithmetic. HID numbers letters alphabetically from
//! `0x04` = A, while Linux keycodes follow the physical QWERTY rows
//! (`KEY_Q` = 16 … `KEY_A` = 30 … `KEY_Z` = 44). A range-map would send
//! plausible, wrong keys — the worst kind, because it looks like it works.

#[rustfmt::skip]
pub(crate) const KEYMAP: &[(u32, u16)] = &[
    // a..z
    (0x04, 30), (0x05, 48), (0x06, 46), (0x07, 32), (0x08, 18), (0x09, 33),
    (0x0a, 34), (0x0b, 35), (0x0c, 23), (0x0d, 36), (0x0e, 37), (0x0f, 38),
    (0x10, 50), (0x11, 49), (0x12, 24), (0x13, 25), (0x14, 16), (0x15, 19),
    (0x16, 31), (0x17, 20), (0x18, 22), (0x19, 47), (0x1a, 17), (0x1b, 45),
    (0x1c, 21), (0x1d, 44),
    // 1..9, 0
    (0x1e, 2), (0x1f, 3), (0x20, 4), (0x21, 5), (0x22, 6),
    (0x23, 7), (0x24, 8), (0x25, 9), (0x26, 10), (0x27, 11),
    // enter, esc, backspace, tab, space
    (0x28, 28), (0x29, 1), (0x2a, 14), (0x2b, 15), (0x2c, 57),
    // punctuation
    (0x2d, 12), (0x2e, 13), (0x2f, 26), (0x30, 27), (0x31, 43), (0x32, 43),
    (0x33, 39), (0x34, 40), (0x35, 41), (0x36, 51), (0x37, 52), (0x38, 53),
    (0x39, 58),
    // F1..F12
    (0x3a, 59), (0x3b, 60), (0x3c, 61), (0x3d, 62), (0x3e, 63), (0x3f, 64),
    (0x40, 65), (0x41, 66), (0x42, 67), (0x43, 68), (0x44, 87), (0x45, 88),
    // navigation
    (0x46, 99), (0x47, 70), (0x48, 119), (0x49, 110), (0x4a, 102), (0x4b, 104),
    (0x4c, 111), (0x4d, 107), (0x4e, 109), (0x4f, 106), (0x50, 105),
    (0x51, 108), (0x52, 103),
    // keypad
    (0x53, 69), (0x54, 98), (0x55, 55), (0x56, 74), (0x57, 78), (0x58, 96),
    (0x59, 79), (0x5a, 80), (0x5b, 81), (0x5c, 75), (0x5d, 76), (0x5e, 77),
    (0x5f, 71), (0x60, 72), (0x61, 73), (0x62, 82), (0x63, 83),
    // non-US backslash, compose, power, keypad equals
    (0x64, 86), (0x65, 127), (0x66, 116), (0x67, 117),
    // modifiers
    (0xe0, 29), (0xe1, 42), (0xe2, 56), (0xe3, 125),
    (0xe4, 97), (0xe5, 54), (0xe6, 100), (0xe7, 126),
];

/// The evdev keycode for a HID usage, or `None`. An unmapped usage is
/// DROPPED by every consumer, never guessed at (FR-13's contract).
pub(crate) fn hid_to_evdev(code: u32) -> Option<u16> {
    KEYMAP
        .iter()
        .find(|&&(hid, _)| hid == code)
        .map(|&(_, k)| k)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the table: HID is alphabetical, evdev is physical.
    /// If someone "simplifies" this to arithmetic, these break.
    #[test]
    fn hid_to_evdev_is_not_arithmetic() {
        assert_eq!(hid_to_evdev(0x04), Some(30), "HID a → KEY_A");
        assert_eq!(hid_to_evdev(0x14), Some(16), "HID q → KEY_Q");
        assert_eq!(hid_to_evdev(0x1d), Some(44), "HID z → KEY_Z");
        // Arithmetic from 0x04 would give KEY_A + 16 = 46 for 'q'. It doesn't.
        assert_ne!(hid_to_evdev(0x14), Some(30 + 0x10));
    }

    #[test]
    fn hid_to_evdev_covers_modifiers_and_drops_unknowns() {
        assert_eq!(hid_to_evdev(0xe0), Some(29), "left ctrl");
        assert_eq!(hid_to_evdev(0xe7), Some(126), "right meta");
        assert_eq!(hid_to_evdev(0x00), None);
        assert_eq!(
            hid_to_evdev(0xffff),
            None,
            "unmapped is dropped, not guessed"
        );
    }

    /// Two keys must never share a code, or one of them presses the other.
    #[test]
    fn keymap_has_no_duplicate_hid_usages() {
        let mut seen = std::collections::HashSet::new();
        for &(hid, _) in KEYMAP {
            assert!(seen.insert(hid), "HID {hid:#x} mapped twice");
        }
    }
}
