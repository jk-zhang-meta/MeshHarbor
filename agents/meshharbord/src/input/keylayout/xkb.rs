// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P3f — typed text on any layout, through the host's own XKB keymap.
//!
//! The parent module's table types only on a US layout, so a German or a
//! French host dropped every `key_text` the viewer sent (the mobile keyboard,
//! IME composition). This compiles the keymap a compositor builds by default
//! for the host's layout (rules `evdev`, model `pc105`, the layout and variant
//! [`super::detect`] names) with libxkbcommon, and asks it which key, at which
//! level, produces each character.
//!
//! - **dlopen'd, never linked.** libxkbcommon is a system library, and a
//!   `DT_NEEDED` entry would stop the daemon from starting on a host without
//!   it: the parent module's reason for its table. It is loaded on first use,
//!   like libpulse (`audio/pulse.rs`). Without it, the table serves a US host
//!   as before, and any other layout refuses as before.
//! - **One keystroke per character**: a level reached with no modifier, Shift,
//!   AltGr, or both. AltGr is `LevelThree`, pressed as the right Alt key, and
//!   only where the keymap makes that key `ISO_Level3_Shift`. A character that
//!   needs a dead key, NumLock or any other modifier is not typeable here, and
//!   is skipped as the table skips what it cannot reach.
//! - **The first group.** A multi-group setup (`us,de`) starts in its first
//!   group, and that is the one this types for; which group is active later is
//!   unknowable from here.
//!
//! Kill switch `ROOMLERD_UINPUT_XKB=0`: the table only, as before P3f.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::OnceLock;

/// FR-97 P3f — kill switch `ROOMLERD_UINPUT_XKB=0`.
pub fn enabled() -> bool {
    tunnel_core::env::flag("UINPUT_XKB", true)
}

/// One character's keystroke, in evdev key codes, which `/dev/uinput` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XkbStroke {
    pub key: u16,
    pub shift: bool,
    /// AltGr: the right Alt key, which this keymap makes `ISO_Level3_Shift`.
    pub level3: bool,
}

impl XkbStroke {
    /// Which stroke to use when a keymap reaches a character more than one
    /// way, best first: no AltGr; the main block over the keypad, whose keys a
    /// terminal in application-keypad mode reads as escape sequences rather
    /// than the character; any key over the ISO key, which a pc104 board does
    /// not have; and no Shift.
    fn rank(self) -> u8 {
        u8::from(self.level3) * 8
            + u8::from(is_keypad(self.key)) * 4
            + u8::from(self.key == KEY_102ND) * 2
            + u8::from(self.shift)
    }
}

/// `KEY_102ND`, the extra key an ISO board has beside the left Shift.
const KEY_102ND: u16 = 86;

/// The keypad's keys, by evdev code.
fn is_keypad(key: u16) -> bool {
    matches!(key, 55 | 71..=83 | 96 | 98 | 117 | 118 | 121)
}

/// A host's keymap, reduced to what typing needs: each reachable character's
/// keystroke.
#[derive(Debug, Clone)]
pub struct XkbText {
    strokes: HashMap<char, XkbStroke>,
    /// What it was compiled from, for the log: `de`, `fr(bepo)`.
    name: String,
}

impl XkbText {
    /// Compile the keymap for `layout` (an XKB layout list: `de`, `us,de`) and
    /// `variant` (empty for the default), and map every character it reaches.
    /// `keys` is the set of evdev codes the caller can emit: a stroke on any
    /// other key is left out. The error is the reason, for the log.
    pub fn compile(layout: &str, variant: &str, keys: &[u16]) -> Result<Self, String> {
        let layout = layout.trim();
        if layout.is_empty() || layout == "unknown" {
            return Err("no layout to compile".into());
        }
        let lib = lib()?;
        let rules = CString::new("evdev").expect("no NUL");
        let model = CString::new("pc105").expect("no NUL");
        let c_layout = CString::new(layout).map_err(|_| "a layout name with a NUL")?;
        let c_variant = CString::new(variant.trim()).map_err(|_| "a variant with a NUL")?;
        let names = RuleNames {
            rules: rules.as_ptr(),
            model: model.as_ptr(),
            layout: c_layout.as_ptr(),
            variant: c_variant.as_ptr(),
            options: std::ptr::null(),
        };
        // SAFETY: each call is to libxkbcommon's own entry point, through the
        // signature <xkbcommon/xkbcommon.h> declares for it. `names` and the
        // strings it points to outlive the compile; the context and keymap are
        // released before this returns, on every path.
        unsafe {
            let ctx = (lib.context_new)(0);
            if ctx.is_null() {
                return Err("xkb_context_new failed".into());
            }
            let keymap = (lib.keymap_new_from_names)(ctx, &names, 0);
            if keymap.is_null() {
                (lib.context_unref)(ctx);
                return Err(format!("no XKB keymap compiles for layout `{layout}`"));
            }
            let strokes = map_keymap(lib, keymap, keys);
            (lib.keymap_unref)(keymap);
            (lib.context_unref)(ctx);
            let name = if variant.trim().is_empty() {
                layout.to_string()
            } else {
                format!("{layout}({})", variant.trim())
            };
            Ok(Self { strokes, name })
        }
    }

    /// The keystroke that types `ch`, or `None` where this keymap has none in
    /// one stroke. A newline is Enter, as in the table.
    pub fn stroke(&self, ch: char) -> Option<XkbStroke> {
        let ch = if ch == '\r' { '\n' } else { ch };
        self.strokes.get(&ch).copied()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// evdev's key codes are XKB's less 8.
const EVDEV_OFFSET: u32 = 8;
/// `KEY_RIGHTALT`, the key a keymap makes `ISO_Level3_Shift` for AltGr.
const KEY_RIGHTALT: u16 = 100;
/// The `ISO_Level3_Shift` keysym.
const ISO_LEVEL3_SHIFT: u32 = 0xfe03;
const XKB_MOD_INVALID: u32 = 0xffff_ffff;

/// Walk every key at every level of the first group, keeping the simplest
/// stroke per character.
///
/// # Safety
/// `keymap` must be a live keymap from `lib`.
unsafe fn map_keymap(lib: &Lib, keymap: *mut c_void, keys: &[u16]) -> HashMap<char, XkbStroke> {
    let index = |name: &str| -> Option<u32> {
        let c = CString::new(name).ok()?;
        // SAFETY: a live keymap and a NUL-terminated name.
        let i = unsafe { (lib.mod_get_index)(keymap, c.as_ptr()) };
        (i != XKB_MOD_INVALID && i < 32).then_some(i)
    };
    let shift_mask = index("Shift").map_or(0, |i| 1u32 << i);
    // A keymap names the third level's modifier `Mod5` (real) or, from
    // libxkbcommon 1.8, `LevelThree` (virtual); a level may name either.
    let level3_mask = ["Mod5", "LevelThree"]
        .iter()
        .filter_map(|n| index(n))
        .fold(0u32, |m, i| m | (1 << i));
    // AltGr can be pressed only where the right Alt key IS level 3.
    // SAFETY: a live keymap.
    let ralt_is_level3 = unsafe {
        syms_at(lib, keymap, u32::from(KEY_RIGHTALT) + EVDEV_OFFSET, 0) == Some(ISO_LEVEL3_SHIFT)
    };
    let mut out: HashMap<char, XkbStroke> = HashMap::new();
    // SAFETY: a live keymap.
    let (min, max) = unsafe { ((lib.min_keycode)(keymap), (lib.max_keycode)(keymap)) };
    for keycode in min..=max {
        let Some(key) = keycode
            .checked_sub(EVDEV_OFFSET)
            .and_then(|k| u16::try_from(k).ok())
            .filter(|k| keys.contains(k))
        else {
            continue;
        };
        // SAFETY: a live keymap and a keycode in its range.
        if unsafe { (lib.num_layouts_for_key)(keymap, keycode) } == 0 {
            continue;
        }
        // SAFETY: as above, layout 0 exists for this key.
        let levels = unsafe { (lib.num_levels_for_key)(keymap, keycode, 0) };
        for level in 0..levels {
            // SAFETY: as above, and a level below the key's count.
            let Some(sym) = (unsafe { syms_at(lib, keymap, keycode, level) }) else {
                continue;
            };
            // SAFETY: a pure function of its argument.
            let Some(ch) = char::from_u32(unsafe { (lib.keysym_to_utf32)(sym) }) else {
                continue;
            };
            // `Return` is a carriage return to XKB; the text says newline.
            let ch = if ch == '\r' { '\n' } else { ch };
            if ch == '\0' || (ch.is_control() && ch != '\n' && ch != '\t') {
                continue;
            }
            let mut masks = [0u32; 8];
            // SAFETY: as above; the buffer holds `masks.len()` entries.
            let n = unsafe {
                (lib.key_get_mods_for_level)(
                    keymap,
                    keycode,
                    0,
                    level,
                    masks.as_mut_ptr(),
                    masks.len(),
                )
            };
            let reach = masks[..n.min(masks.len())]
                .iter()
                .copied()
                .find(|m| m & !(shift_mask | level3_mask) == 0);
            let Some(mask) = reach else { continue };
            let stroke = XkbStroke {
                key,
                shift: mask & shift_mask != 0,
                level3: mask & level3_mask != 0,
            };
            if stroke.level3 && !ralt_is_level3 {
                continue;
            }
            match out.get(&ch) {
                Some(have) if have.rank() <= stroke.rank() => {}
                _ => {
                    out.insert(ch, stroke);
                }
            }
        }
    }
    out
}

/// The one keysym at `level` of the first group, or `None` for none or many.
///
/// # Safety
/// `keymap` must be a live keymap from `lib`.
unsafe fn syms_at(lib: &Lib, keymap: *mut c_void, keycode: u32, level: u32) -> Option<u32> {
    let mut syms: *const u32 = std::ptr::null();
    // SAFETY: the caller's keymap; libxkbcommon owns the array it points at.
    let n = unsafe { (lib.key_get_syms_by_level)(keymap, keycode, 0, level, &mut syms) };
    if n != 1 || syms.is_null() {
        return None;
    }
    // SAFETY: libxkbcommon said the array holds one keysym.
    Some(unsafe { *syms })
}

// ── the library, loaded once ────────────────────────────────────────────────

#[repr(C)]
struct RuleNames {
    rules: *const c_char,
    model: *const c_char,
    layout: *const c_char,
    variant: *const c_char,
    options: *const c_char,
}

type ContextNewFn = unsafe extern "C" fn(c_int) -> *mut c_void;
type ContextUnrefFn = unsafe extern "C" fn(*mut c_void);
type KeymapNewFromNamesFn =
    unsafe extern "C" fn(*mut c_void, *const RuleNames, c_int) -> *mut c_void;
type KeymapUnrefFn = unsafe extern "C" fn(*mut c_void);
type KeycodeFn = unsafe extern "C" fn(*mut c_void) -> u32;
type NumLayoutsFn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
type NumLevelsFn = unsafe extern "C" fn(*mut c_void, u32, u32) -> u32;
type SymsByLevelFn = unsafe extern "C" fn(*mut c_void, u32, u32, u32, *mut *const u32) -> c_int;
type ModsForLevelFn = unsafe extern "C" fn(*mut c_void, u32, u32, u32, *mut u32, usize) -> usize;
type ModGetIndexFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> u32;
type KeysymToUtf32Fn = unsafe extern "C" fn(u32) -> u32;

/// The entry points, resolved once and never unloaded.
struct Lib {
    context_new: ContextNewFn,
    context_unref: ContextUnrefFn,
    keymap_new_from_names: KeymapNewFromNamesFn,
    keymap_unref: KeymapUnrefFn,
    min_keycode: KeycodeFn,
    max_keycode: KeycodeFn,
    num_layouts_for_key: NumLayoutsFn,
    num_levels_for_key: NumLevelsFn,
    key_get_syms_by_level: SymsByLevelFn,
    /// libxkbcommon 1.0 and later; an older library reads as absent.
    key_get_mods_for_level: ModsForLevelFn,
    mod_get_index: ModGetIndexFn,
    keysym_to_utf32: KeysymToUtf32Fn,
}

const CANDIDATES: &[&str] = &["libxkbcommon.so.0", "libxkbcommon.so"];

fn lib() -> Result<&'static Lib, String> {
    static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();
    LIB.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Lib, String> {
    let mut last = String::from("no candidates given");
    for name in CANDIDATES {
        let cname = CString::new(*name).expect("a library name has no NUL");
        // RTLD_NOW so a missing symbol surfaces here; RTLD_LOCAL so nothing
        // else resolves against it.
        // SAFETY: dlopen takes a NUL-terminated name; the handle is kept for
        // the life of the process (never dlclose'd), so the pointers below
        // stay valid.
        let handle = unsafe { libc::dlopen(cname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            last = dlerror_string().unwrap_or_else(|| format!("{name}: dlopen failed"));
            continue;
        }
        // SAFETY: each symbol is transmuted to the signature
        // <xkbcommon/xkbcommon.h> declares for it.
        unsafe {
            return Ok(Lib {
                context_new: std::mem::transmute::<*mut c_void, ContextNewFn>(sym(
                    handle,
                    "xkb_context_new",
                )?),
                context_unref: std::mem::transmute::<*mut c_void, ContextUnrefFn>(sym(
                    handle,
                    "xkb_context_unref",
                )?),
                keymap_new_from_names: std::mem::transmute::<*mut c_void, KeymapNewFromNamesFn>(
                    sym(handle, "xkb_keymap_new_from_names")?,
                ),
                keymap_unref: std::mem::transmute::<*mut c_void, KeymapUnrefFn>(sym(
                    handle,
                    "xkb_keymap_unref",
                )?),
                min_keycode: std::mem::transmute::<*mut c_void, KeycodeFn>(sym(
                    handle,
                    "xkb_keymap_min_keycode",
                )?),
                max_keycode: std::mem::transmute::<*mut c_void, KeycodeFn>(sym(
                    handle,
                    "xkb_keymap_max_keycode",
                )?),
                num_layouts_for_key: std::mem::transmute::<*mut c_void, NumLayoutsFn>(sym(
                    handle,
                    "xkb_keymap_num_layouts_for_key",
                )?),
                num_levels_for_key: std::mem::transmute::<*mut c_void, NumLevelsFn>(sym(
                    handle,
                    "xkb_keymap_num_levels_for_key",
                )?),
                key_get_syms_by_level: std::mem::transmute::<*mut c_void, SymsByLevelFn>(sym(
                    handle,
                    "xkb_keymap_key_get_syms_by_level",
                )?),
                key_get_mods_for_level: std::mem::transmute::<*mut c_void, ModsForLevelFn>(sym(
                    handle,
                    "xkb_keymap_key_get_mods_for_level",
                )?),
                mod_get_index: std::mem::transmute::<*mut c_void, ModGetIndexFn>(sym(
                    handle,
                    "xkb_keymap_mod_get_index",
                )?),
                keysym_to_utf32: std::mem::transmute::<*mut c_void, KeysymToUtf32Fn>(sym(
                    handle,
                    "xkb_keysym_to_utf32",
                )?),
            });
        }
    }
    Err(last)
}

/// # Safety
/// `handle` must be a live `dlopen` handle.
unsafe fn sym(handle: *mut c_void, name: &str) -> Result<*mut c_void, String> {
    let c = CString::new(name).expect("a symbol name has no NUL");
    // SAFETY: the caller guarantees the handle; `c` is NUL-terminated.
    let p = unsafe { libc::dlsym(handle, c.as_ptr()) };
    if p.is_null() {
        Err(format!("libxkbcommon has no {name} (older than 1.0?)"))
    } else {
        Ok(p)
    }
}

fn dlerror_string() -> Option<String> {
    // SAFETY: dlerror returns NULL or a NUL-terminated string valid until the
    // next dl* call on this thread; it is copied at once.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        None
    } else {
        // SAFETY: non-null and NUL-terminated, per dlerror's contract.
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

/// Against the host's real libxkbcommon and its XKB data. `ROOMLERD_TEST_XKB=1`
/// makes a missing library a failure rather than a skip, so the CI lane that
/// sets it cannot pass by running nothing.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::hid_evdev::{KEYMAP, hid_to_evdev};

    fn keys() -> Vec<u16> {
        KEYMAP.iter().map(|&(_, k)| k).collect()
    }

    fn compiled(layout: &str) -> Option<XkbText> {
        match XkbText::compile(layout, "", &keys()) {
            Ok(t) => Some(t),
            Err(e) => {
                assert!(
                    std::env::var("ROOMLERD_TEST_XKB").as_deref() != Ok("1"),
                    "ROOMLERD_TEST_XKB=1 but `{layout}` did not compile: {e}"
                );
                eprintln!("skipping: {e}");
                None
            }
        }
    }

    fn s(key: u16, shift: bool, level3: bool) -> Option<XkbStroke> {
        Some(XkbStroke { key, shift, level3 })
    }

    /// The verified table and the US keymap agree on every character the
    /// table has: the keymap is a superset, never a different answer.
    #[test]
    fn a_us_keymap_agrees_with_the_verified_table() {
        let Some(us) = compiled("us") else { return };
        let table = super::super::Layout::Us;
        let mut checked = 0;
        for cp in 0x20u32..0x7f {
            let ch = char::from_u32(cp).unwrap();
            let Some(t) = table.stroke(ch) else { continue };
            let want = s(hid_to_evdev(t.hid).unwrap(), t.shift, false);
            assert_eq!(us.stroke(ch), want, "{ch:?}");
            checked += 1;
        }
        assert_eq!(us.stroke('\n'), s(28, false, false), "Enter");
        assert_eq!(us.stroke('\r'), s(28, false, false), "CR types Enter too");
        assert_eq!(us.stroke('\t'), s(15, false, false), "Tab");
        assert!(checked >= 90, "{checked} characters compared");
        assert_eq!(us.stroke('é'), None, "US reaches no é in one stroke");
        eprintln!("xkb-real: the US keymap agrees with the table on {checked} characters");
    }

    /// German: Y and Z swap places, umlauts and ß have keys of their own, `@`
    /// and `€` are AltGr, and `< > |` sit on the extra ISO key.
    #[test]
    fn a_german_keymap_swaps_y_and_z_and_reaches_altgr() {
        let Some(de) = compiled("de") else { return };
        assert_eq!(
            de.stroke('z'),
            s(21, false, false),
            "z is the key a US board calls Y"
        );
        assert_eq!(de.stroke('y'), s(44, false, false));
        assert_eq!(de.stroke('Z'), s(21, true, false));
        assert_eq!(de.stroke('ß'), s(12, false, false));
        assert_eq!(de.stroke('ä'), s(40, false, false));
        assert_eq!(de.stroke('Ä'), s(40, true, false));
        assert_eq!(de.stroke('ö'), s(39, false, false));
        assert_eq!(de.stroke('ü'), s(26, false, false));
        assert_eq!(de.stroke('@'), s(16, false, true), "AltGr+Q");
        assert_eq!(de.stroke('€'), s(18, false, true), "AltGr+E");
        assert_eq!(de.stroke('<'), s(86, false, false), "the ISO key");
        assert_eq!(de.stroke('>'), s(86, true, false));
        assert_eq!(de.stroke('|'), s(86, false, true));
        assert_eq!(de.name(), "de");
        eprintln!("xkb-real: a German keymap types zyäöüß@€<>|");
    }

    /// French: AZERTY, the digits shifted, `é` and `à` on the digit row.
    #[test]
    fn a_french_keymap_is_azerty() {
        let Some(fr) = compiled("fr") else { return };
        assert_eq!(
            fr.stroke('a'),
            s(16, false, false),
            "a is the key a US board calls Q"
        );
        assert_eq!(fr.stroke('q'), s(30, false, false));
        assert_eq!(fr.stroke('1'), s(2, true, false), "digits are shifted");
        assert_eq!(fr.stroke('é'), s(3, false, false));
        assert_eq!(fr.stroke('à'), s(11, false, false));
        assert_eq!(fr.stroke('€'), s(18, false, true), "AltGr+E");
        eprintln!("xkb-real: a French keymap types aqé1à€");
    }

    /// A name the XKB data does not know compiles to nothing, and nothing is
    /// what the caller then types with: never a default layout in its place.
    #[test]
    fn an_unknown_layout_compiles_to_nothing() {
        if compiled("us").is_none() {
            return;
        }
        assert!(XkbText::compile("zz-no-such-layout", "", &keys()).is_err());
        assert!(XkbText::compile("", "", &keys()).is_err());
        assert!(XkbText::compile("unknown", "", &keys()).is_err());
    }

    /// A key the injector cannot emit is never in a stroke: without the ISO
    /// key, German `<` is out of reach rather than typed elsewhere.
    #[test]
    fn a_key_the_caller_cannot_emit_is_left_out() {
        if compiled("de").is_none() {
            return;
        }
        let without_iso: Vec<u16> = keys().into_iter().filter(|&k| k != 86).collect();
        let de = XkbText::compile("de", "", &without_iso).unwrap();
        assert_eq!(de.stroke('<'), None);
        assert_eq!(de.stroke('z'), s(21, false, false));
    }
}
