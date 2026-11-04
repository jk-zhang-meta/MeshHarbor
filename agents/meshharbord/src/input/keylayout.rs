// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-36 P4b — turning text into physical keystrokes, for the `uinput` backend.
//!
//! evdev carries **physical keys**, not characters. A compositor applies its own
//! XKB layout to whatever a keyboard device reports, so "type the letter z"
//! means "press the key that produces z *under the layout this host is running*"
//! — on a German layout that is the key labelled `y`, and on a French one it is
//! a different key again. Get it wrong and the remote user watches mojibake
//! appear, which is worse than nothing happening.
//!
//! ## Why a table, and `libxkbcommon` only through `dlopen` (FR-97 P3f)
//!
//! xkbcommon is the correct general answer and LINKING it was rejected on
//! deployment grounds: it is a **dynamic system library**, and that would put
//! `libxkbcommon.so` in `roomlerd`'s `DT_NEEDED` on every Linux build. Headless
//! fleet hosts (cluster nodes, containers) have no reason to carry it, and a
//! missing `.so` does not degrade a feature — the loader refuses to start the
//! daemon at all. That exact failure already cost this project once, when
//! vendored FFmpeg dylibs baked a Homebrew path into the macOS agent and dyld
//! killed it at launch on every end-user Mac.
//!
//! So: **detect the layout, and type only with a map we trust**: the host's
//! own XKB keymap where libxkbcommon loads ([`xkb`], dlopen'd), else a verified
//! table. Never assume. A layout with neither keeps the old behaviour: one loud
//! warning naming what was detected, rather than silently typing wrong keys.

use std::process::Command;

/// A character's physical key, expressed in the same HID usage codes the wire
/// already carries, so it re-enters the injector through the normal key path
/// rather than a second, parallel one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStroke {
    pub hid: u32,
    pub shift: bool,
}

/// Layouts with a verified table. Deliberately short: each entry is a promise
/// that someone checked the mapping, and an unverified entry is worse than an
/// absent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Us,
}

impl Layout {
    /// Parse an XKB layout name (`us`, `us,de`, `gb`…). Only the FIRST group is
    /// considered: a multi-group setup means the user switches between them at
    /// will, so the active one is unknowable from here — and guessing the first
    /// is exactly the kind of assumption this module exists to avoid making
    /// silently, hence [`detect`] logging what it found.
    pub fn parse(name: &str) -> Option<Self> {
        match name.split(',').next()?.trim().to_ascii_lowercase().as_str() {
            "us" => Some(Layout::Us),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Layout::Us => "us",
        }
    }

    /// Map one character to the key that produces it under this layout.
    /// `None` = not typeable here (an unmapped character, or one needing a
    /// dead key / AltGr sequence this table does not model).
    pub fn stroke(self, ch: char) -> Option<KeyStroke> {
        match self {
            Layout::Us => us_stroke(ch),
        }
    }
}

/// US QWERTY. HID usage page 0x07, the same numbering the wire uses.
fn us_stroke(ch: char) -> Option<KeyStroke> {
    let s = |hid: u32, shift: bool| Some(KeyStroke { hid, shift });
    match ch {
        'a'..='z' => s(0x04 + (ch as u32 - 'a' as u32), false),
        'A'..='Z' => s(0x04 + (ch as u32 - 'A' as u32), true),
        '1'..='9' => s(0x1e + (ch as u32 - '1' as u32), false),
        '0' => s(0x27, false),
        // Shifted digit row.
        '!' => s(0x1e, true),
        '@' => s(0x1f, true),
        '#' => s(0x20, true),
        '$' => s(0x21, true),
        '%' => s(0x22, true),
        '^' => s(0x23, true),
        '&' => s(0x24, true),
        '*' => s(0x25, true),
        '(' => s(0x26, true),
        ')' => s(0x27, true),
        // Whitespace / control that a text payload legitimately carries.
        ' ' => s(0x2c, false),
        '\n' | '\r' => s(0x28, false),
        '\t' => s(0x2b, false),
        // Punctuation, unshifted then shifted.
        '-' => s(0x2d, false),
        '_' => s(0x2d, true),
        '=' => s(0x2e, false),
        '+' => s(0x2e, true),
        '[' => s(0x2f, false),
        '{' => s(0x2f, true),
        ']' => s(0x30, false),
        '}' => s(0x30, true),
        '\\' => s(0x31, false),
        '|' => s(0x31, true),
        ';' => s(0x33, false),
        ':' => s(0x33, true),
        '\'' => s(0x34, false),
        '"' => s(0x34, true),
        '`' => s(0x35, false),
        '~' => s(0x35, true),
        ',' => s(0x36, false),
        '<' => s(0x36, true),
        '.' => s(0x37, false),
        '>' => s(0x37, true),
        '/' => s(0x38, false),
        '?' => s(0x38, true),
        _ => None,
    }
}

/// What layout is this host configured for?
///
/// Most-specific-first: the session's own XKB hint, then the system
/// configuration.
///
/// ⚠️ Deliberately NO operator override knob. A new env knob would need a
/// config-surface key to be settable the normal way, and there is no string
/// bridge for that yet — but more importantly, if detection is wrong the fix is
/// to detect better, not to add a knob that papers over it. Add both together
/// if the field ever shows detection is insufficient. Returns the raw name alongside the
/// parsed layout so a caller can *say what it found* when it has no table —
/// "unsupported layout" is not actionable, "unsupported layout `de`" is.
pub fn detect() -> (Option<Layout>, String) {
    for name in [
        std::env::var("XKB_DEFAULT_LAYOUT").ok(),
        from_localectl(),
        from_keyfile("/etc/default/keyboard", "XKBLAYOUT"),
        from_keyfile("/etc/vconsole.conf", "KEYMAP"),
    ]
    .into_iter()
    .flatten()
    {
        let name = name.trim().trim_matches('"').to_string();
        if name.is_empty() {
            continue;
        }
        return (Layout::parse(&name), name);
    }
    (None, "unknown".into())
}

fn from_localectl() -> Option<String> {
    from_localectl_field("X11 Layout:")
}

fn from_localectl_field(field: &str) -> Option<String> {
    let out = Command::new("localectl").arg("status").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .find_map(|l| l.split_once(field).map(|(_, v)| v.trim().to_string()))
}

/// Read `KEY=value` from a shell-style config file. Tolerates quotes and
/// comments; returns `None` rather than erroring, because every source here is
/// best-effort by design.
fn from_keyfile(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// FR-97 P3f — typed text on any layout, through the host's own XKB keymap.
pub mod xkb;

/// One character's keystroke, in evdev codes, whichever way it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextStroke {
    pub key: u16,
    pub shift: bool,
    /// AltGr, pressed as the right Alt key ([`xkb::XkbStroke::level3`]).
    pub level3: bool,
}

/// How typed text becomes keys on this host: its own XKB keymap (FR-97 P3f),
/// else the verified table.
#[derive(Debug, Clone)]
pub enum TextKeys {
    Xkb(xkb::XkbText),
    Table(Layout),
}

impl TextKeys {
    /// For the layout [`detect`] found (`name`, and `table` where it has one):
    /// the host's XKB keymap where it compiles, else the table, else `None`,
    /// and typed text is refused as before P3f. `keys` is what the caller can
    /// emit. The string says which way, or why neither, for the log.
    pub fn for_host(name: &str, table: Option<Layout>, keys: &[u16]) -> (Option<Self>, String) {
        let xkb_said = if xkb::enabled() {
            match xkb::XkbText::compile(name, &variant_for(name), keys) {
                Ok(t) => {
                    let how = format!("the host's XKB keymap `{}`", t.name());
                    return (Some(Self::Xkb(t)), how);
                }
                Err(e) => format!("no XKB keymap: {e}"),
            }
        } else {
            "ROOMLERD_UINPUT_XKB=0".to_string()
        };
        match table {
            Some(l) => (
                Some(Self::Table(l)),
                format!("the verified `{}` table ({xkb_said})", l.as_str()),
            ),
            None => (None, format!("no verified table for `{name}` ({xkb_said})")),
        }
    }

    /// The keystroke that types `ch`, or `None` where there is none in one.
    pub fn stroke(&self, ch: char) -> Option<TextStroke> {
        match self {
            Self::Xkb(t) => t.stroke(ch).map(|s| TextStroke {
                key: s.key,
                shift: s.shift,
                level3: s.level3,
            }),
            Self::Table(l) => {
                let k = l.stroke(ch)?;
                Some(TextStroke {
                    key: crate::input::hid_evdev::hid_to_evdev(k.hid)?,
                    shift: k.shift,
                    level3: false,
                })
            }
        }
    }

    /// The layout typed for: `de`, `fr(bepo)`, `us`.
    pub fn name(&self) -> &str {
        match self {
            Self::Xkb(t) => t.name(),
            Self::Table(l) => l.as_str(),
        }
    }
}

/// The variant to compile `layout` with, from the SAME source [`detect`] took
/// the layout from: a variant beside another source's layout would describe a
/// keymap nobody configured. Empty is the layout's default.
fn variant_for(layout: &str) -> String {
    let unquote = |v: String| v.trim().trim_matches('"').to_string();
    let sources = [
        (
            std::env::var("XKB_DEFAULT_LAYOUT").ok(),
            std::env::var("XKB_DEFAULT_VARIANT").ok(),
        ),
        (from_localectl(), from_localectl_field("X11 Variant:")),
        (
            from_keyfile("/etc/default/keyboard", "XKBLAYOUT"),
            from_keyfile("/etc/default/keyboard", "XKBVARIANT"),
        ),
    ];
    sources
        .into_iter()
        .find(|(l, _)| l.clone().map(unquote).as_deref() == Some(layout))
        .and_then(|(_, v)| v.map(unquote))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: a character maps to the key that PRODUCES it, and the
    /// shift state is part of the answer, not an afterthought.
    #[test]
    fn us_maps_case_and_shift() {
        assert_eq!(
            Layout::Us.stroke('a'),
            Some(KeyStroke {
                hid: 0x04,
                shift: false
            })
        );
        assert_eq!(
            Layout::Us.stroke('A'),
            Some(KeyStroke {
                hid: 0x04,
                shift: true
            })
        );
        assert_eq!(
            Layout::Us.stroke('z'),
            Some(KeyStroke {
                hid: 0x1d,
                shift: false
            })
        );
        // Same physical key, different character — the shifted digit row.
        assert_eq!(
            Layout::Us.stroke('1'),
            Some(KeyStroke {
                hid: 0x1e,
                shift: false
            })
        );
        assert_eq!(
            Layout::Us.stroke('!'),
            Some(KeyStroke {
                hid: 0x1e,
                shift: true
            })
        );
        // '0' is NOT 0x1e+9 — it sits at the end of the HID digit block.
        assert_eq!(
            Layout::Us.stroke('0'),
            Some(KeyStroke {
                hid: 0x27,
                shift: false
            })
        );
        assert_eq!(
            Layout::Us.stroke(')'),
            Some(KeyStroke {
                hid: 0x27,
                shift: true
            })
        );
    }

    #[test]
    fn us_maps_whitespace_and_punctuation() {
        assert_eq!(Layout::Us.stroke(' ').unwrap().hid, 0x2c);
        assert_eq!(Layout::Us.stroke('\n').unwrap().hid, 0x28);
        assert_eq!(
            Layout::Us.stroke('\r').unwrap().hid,
            0x28,
            "CR types Enter too"
        );
        assert_eq!(Layout::Us.stroke('\t').unwrap().hid, 0x2b);
        assert_eq!(
            Layout::Us.stroke('/'),
            Some(KeyStroke {
                hid: 0x38,
                shift: false
            })
        );
        assert_eq!(
            Layout::Us.stroke('?'),
            Some(KeyStroke {
                hid: 0x38,
                shift: true
            })
        );
    }

    /// A character we cannot type must come back as `None` so the caller skips
    /// it. Returning *some* key would type a wrong character, which is the
    /// failure this module exists to prevent.
    #[test]
    fn untypeable_characters_are_none_not_a_guess() {
        assert_eq!(Layout::Us.stroke('é'), None);
        assert_eq!(Layout::Us.stroke('€'), None);
        assert_eq!(Layout::Us.stroke('日'), None);
        assert_eq!(Layout::Us.stroke('\u{0}'), None);
    }

    /// ⚠️ Only `us` has a verified table. Anything else must parse to `None` so
    /// the backend refuses rather than typing the US mapping at a host whose
    /// keys are somewhere else entirely.
    #[test]
    fn only_verified_layouts_parse() {
        assert_eq!(Layout::parse("us"), Some(Layout::Us));
        assert_eq!(Layout::parse("US"), Some(Layout::Us));
        assert_eq!(Layout::parse(" us "), Some(Layout::Us));
        // First group only — and a layout we have no table for stays None.
        assert_eq!(Layout::parse("us,de"), Some(Layout::Us));
        assert_eq!(Layout::parse("de"), None);
        assert_eq!(
            Layout::parse("de,us"),
            None,
            "first group decides; de is unverified"
        );
        assert_eq!(Layout::parse("fr"), None);
        assert_eq!(Layout::parse(""), None);
    }

    #[test]
    fn keyfile_parsing_tolerates_quotes_and_comments() {
        let dir = std::env::temp_dir().join(format!("kl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("keyboard");
        std::fs::write(&p, "# comment\nXKBMODEL=\"pc105\"\nXKBLAYOUT=\"gb\"\n").unwrap();
        assert_eq!(
            from_keyfile(p.to_str().unwrap(), "XKBLAYOUT"),
            Some("gb".into())
        );
        assert_eq!(from_keyfile(p.to_str().unwrap(), "NOPE"), None);
        assert_eq!(from_keyfile("/nonexistent/zzz", "XKBLAYOUT"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
