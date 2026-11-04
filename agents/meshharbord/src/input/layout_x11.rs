// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P3e — the X11 keyboard layout: which one is in use, and a switch to
//! another, for the viewer's layout chip and picker. The same two messages the
//! Windows module answers (`rc:layout`, `rc:layout.set`), through the same
//! snapshot and watch, so the peer's emitter serves both; `input::layout` is
//! this module on Linux.
//!
//! - **What a layout is here.** An X11 desktop configures up to four layouts as
//!   the XKB *groups* of one keymap (`setxkbmap us,de`; GNOME's input sources
//!   and KDE's layouts do the same), and switching layouts locks another group.
//!   The list is the root window's `_XKB_RULES_NAMES` (`us,de` and their
//!   variants), the names are the keymap's own (`English (US)`), and the one in
//!   use is XKB's locked group.
//! - **The tag.** A plain layout the table knows goes out as its BCP-47 tag
//!   (`de` → `de-DE`), so the chip reads as a Windows host's does and the
//!   viewer names it in its own language. A variant, or a layout the table does
//!   not know, goes out under the keymap's own name for it.
//! - **The token.** The picker echoes back an opaque hex string, here the
//!   layout's hash and its group: a click that arrives after the desktop
//!   changed its layouts is refused instead of locking whatever now sits in
//!   that group.
//! - **Reading** polls twice a second while a session watches, on a thread and
//!   a connection of its own (two round trips); with no session watching it
//!   holds no connection. **Switching** locks the group on a fresh connection,
//!   checks it took, and wakes the reader, whose next snapshot is the answer.
//! - **Not under Wayland**, where the layout is the compositor's and nothing
//!   shared reads or sets it (Xwayland's group is a copy), **nor on a system
//!   install**, which reaches the screen through DRM and has no X connection.
//!   Neither advertises `layout` ([`offered`]).
//! - **GNOME reports, and does not switch.** GNOME Shell puts its own input
//!   source back within 20 ms of a lock from outside it, so under GNOME the
//!   hello says `report` without `set`, and the viewer shows the chip with no
//!   picker ([`switchable`]).
//!
//! Kill switch `ROOMLERD_X11_LAYOUT=0`: no `layout` in the hello, no chip.

use std::sync::{Condvar, LazyLock, Mutex, Once};
use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::protocol::xkb::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{self, ConnectionExt as _};
use x11rb::rust_connection::RustConnection;

/// How often a watched layout is read.
const POLL: Duration = Duration::from_millis(500);
/// The longest wait before another try at a display that refused.
const RETRY_MAX: Duration = Duration::from_secs(30);
/// XKB's limit: a keymap has at most four groups.
const MAX_GROUPS: usize = 4;

/// FR-97 P3e — kill switch `ROOMLERD_X11_LAYOUT=0`.
pub fn enabled() -> bool {
    tunnel_core::env::flag("X11_LAYOUT", true)
}

/// This process can read and switch the layout: the switch is on and it runs
/// in an X11 session, with an X display and no Wayland one. The environment
/// is the same test `clipboard_reachable` makes; a system install has
/// neither variable, a Wayland session has both.
pub fn offered() -> bool {
    enabled()
        && x11_session(
            std::env::var_os("DISPLAY"),
            std::env::var_os("WAYLAND_DISPLAY"),
        )
}

fn x11_session(display: Option<std::ffi::OsString>, wayland: Option<std::ffi::OsString>) -> bool {
    display.is_some_and(|d| !d.is_empty()) && wayland.is_none_or(|w| w.is_empty())
}

/// A switch here stays switched. GNOME Shell keeps its own input source on
/// Xorg as well: an XKB group locked from outside it is put back within 20 ms
/// (measured on GNOME 46, FR-97 §8), and it has no public interface to switch
/// sources. Under GNOME the chip reports and the picker is not offered.
/// Budgie names itself `Budgie:GNOME`, and is taken at its word.
pub fn switchable() -> bool {
    !keeps_its_own_layout(std::env::var_os("XDG_CURRENT_DESKTOP"))
}

fn keeps_its_own_layout(desktop: Option<std::ffi::OsString>) -> bool {
    desktop.is_some_and(|d| {
        d.to_string_lossy()
            .split(':')
            .any(|name| name.trim().eq_ignore_ascii_case("GNOME"))
    })
}

/// Snapshot of the host's keyboard layouts, published on change. The same
/// shape as the Windows module's.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutSnapshot {
    /// The layout in use, as the token [`request_set_layout`] takes back.
    pub active_hkl: String,
    /// Its tag ([`tag_for`]).
    pub active_tag: String,
    /// Every configured layout as `(token, tag)`, in group order.
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

/// Set when a session subscribes or a switch was made: the reader reads now.
static WAKE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static READER: Once = Once::new();

/// Subscribe to layout changes, and start the reader the first time. The
/// receiver starts at the last snapshot (`None` before the first read).
pub fn subscribe() -> tokio::sync::watch::Receiver<Option<LayoutSnapshot>> {
    let rx = LAYOUT_WATCH.1.clone();
    if offered() {
        READER.call_once(|| {
            if let Err(e) = std::thread::Builder::new()
                .name("roomlerd-layout-x11".into())
                .spawn(reader)
            {
                tracing::warn!(%e, "layout: could not start the X11 layout reader");
            }
        });
        wake();
    }
    rx
}

/// The last snapshot, for a control channel that just opened.
pub fn current() -> Option<LayoutSnapshot> {
    LAYOUT_WATCH.1.borrow().clone()
}

fn wake() {
    let (lock, cvar) = &WAKE;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cvar.notify_all();
}

/// Waits up to `timeout` for a [`wake`]; `true` when one came.
fn wait_for_wake(timeout: Duration) -> bool {
    let (lock, cvar) = &WAKE;
    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    let (mut woken, _) = cvar
        .wait_timeout_while(guard, timeout, |w| !*w)
        .unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut *woken)
}

/// A session is watching: a receiver beyond the channel's own.
fn watched() -> bool {
    LAYOUT_WATCH.0.receiver_count() > 1
}

/// The reader thread: while a session watches, read every [`POLL`] (or at
/// once when woken) and publish what changed. Without a session it closes its
/// connection and sleeps until one subscribes.
fn reader() {
    let mut retry = Duration::from_secs(1);
    loop {
        if !watched() {
            wait_for_wake(Duration::from_secs(60));
            continue;
        }
        let Some(x) = Xkb::open() else {
            wait_for_wake(retry);
            retry = (retry * 2).min(RETRY_MAX);
            continue;
        };
        retry = Duration::from_secs(1);
        while watched() {
            match x.read() {
                Ok(layouts) => publish(layouts.snapshot()),
                Err(e) => {
                    tracing::info!(%e, "layout: the X11 layout read failed — reconnecting");
                    break;
                }
            }
            wait_for_wake(POLL);
        }
    }
}

fn publish(snap: Option<LayoutSnapshot>) {
    let Some(snap) = snap else { return };
    LAYOUT_WATCH.0.send_if_modified(|cur| {
        if cur.as_ref() == Some(&snap) {
            return false;
        }
        *cur = Some(snap);
        true
    });
}

/// Handle `rc:layout.set {hkl}`, the viewer's picker. A fresh thread and a
/// fresh connection per command (rare, a person's click). The token must name
/// a layout the desktop has configured right now ([`Layouts::group_of`]);
/// anything else is refused. The reader's next snapshot is the answer, so a
/// refused or reverted switch snaps the picker back.
pub fn request_set_layout(token: String) {
    if !offered() {
        tracing::info!(%token, "layout: rc:layout.set on a host that offers no layout — refusing");
        return;
    }
    if !switchable() {
        tracing::info!(
            %token,
            "layout: rc:layout.set under GNOME, which puts its own layout back — refusing"
        );
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("roomlerd-layout-set".into())
        .spawn(move || {
            let Some(x) = Xkb::open() else {
                tracing::warn!(%token, "layout: no X connection for the switch");
                return;
            };
            match x.read() {
                Ok(layouts) => match layouts.group_of(&token) {
                    Some(group) => match x.lock_group(group) {
                        Ok(true) => tracing::info!(
                            %token,
                            group,
                            tag = %layouts.tag(group),
                            "layout: manual switch applied"
                        ),
                        Ok(false) => tracing::warn!(
                            %token,
                            group,
                            "layout: the switch did not take (the desktop put its own back?)"
                        ),
                        Err(e) => tracing::warn!(%token, %e, "layout: the switch failed"),
                    },
                    None => tracing::warn!(
                        %token,
                        "layout: not a layout this desktop has configured now — refusing"
                    ),
                },
                Err(e) => tracing::warn!(%token, %e, "layout: could not read the layouts"),
            }
            wake();
        });
    if let Err(e) = spawned {
        tracing::warn!(%e, "layout: could not spawn the set-layout thread");
    }
}

/// One X connection with XKB in use.
struct Xkb {
    conn: RustConnection,
    root: xproto::Window,
    rules_atom: xproto::Atom,
}

impl Xkb {
    /// `None` without an X server, or one without XKB.
    fn open() -> Option<Self> {
        let (conn, screen) = x11rb::connect(None)
            .map_err(|e| tracing::info!(%e, "layout: no X connection for the layout"))
            .ok()?;
        let root = conn.setup().roots.get(screen)?.root;
        // XKB answers nothing else before UseExtension.
        let used = conn
            .xkb_use_extension(1, 0)
            .ok()?
            .reply()
            .map_err(|e| tracing::info!(%e, "layout: the X server has no XKB"))
            .ok()?;
        if !used.supported {
            tracing::info!("layout: the X server's XKB is too old");
            return None;
        }
        let rules_atom = conn
            .intern_atom(true, b"_XKB_RULES_NAMES")
            .ok()?
            .reply()
            .ok()?
            .atom;
        Some(Self {
            conn,
            root,
            rules_atom,
        })
    }

    fn read(&self) -> Result<Layouts, String> {
        let state = self
            .conn
            .xkb_get_state(xkb::ID::USE_CORE_KBD.into())
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?;
        let rules = if self.rules_atom == x11rb::NONE {
            Vec::new()
        } else {
            self.conn
                .get_property(
                    false,
                    self.root,
                    self.rules_atom,
                    xproto::AtomEnum::STRING,
                    0,
                    1024,
                )
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?
                .value
        };
        let names = self.group_names()?;
        Ok(Layouts::new(
            &rules,
            names,
            u8::from(state.locked_group).into(),
        ))
    }

    /// The keymap's own names for its groups, by group (empty where unnamed).
    fn group_names(&self) -> Result<Vec<String>, String> {
        let reply = self
            .conn
            .xkb_get_names(xkb::ID::USE_CORE_KBD.into(), xkb::NameDetail::GROUP_NAMES)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?;
        let present = u8::from(reply.group_names);
        let mut atoms = reply.value_list.groups.unwrap_or_default().into_iter();
        let mut names = Vec::new();
        for group in 0..MAX_GROUPS {
            if present & (1 << group) == 0 {
                names.push(String::new());
                continue;
            }
            let name = match atoms.next() {
                Some(atom) if atom != x11rb::NONE => self
                    .conn
                    .get_atom_name(atom)
                    .map_err(|e| e.to_string())?
                    .reply()
                    .map(|r| String::from_utf8_lossy(&r.name).into_owned())
                    .unwrap_or_default(),
                _ => String::new(),
            };
            names.push(name);
        }
        while names.last().is_some_and(String::is_empty) {
            names.pop();
        }
        Ok(names)
    }

    /// Lock `group`, then read it back: `Ok(true)` when it is the group in use.
    fn lock_group(&self, group: usize) -> Result<bool, String> {
        let g = u8::try_from(group).map_err(|e| e.to_string())?;
        self.conn
            .xkb_latch_lock_state(
                xkb::ID::USE_CORE_KBD.into(),
                xproto::ModMask::from(0u16),
                xproto::ModMask::from(0u16),
                true,
                xkb::Group::from(g),
                xproto::ModMask::from(0u16),
                false,
                0,
            )
            .map_err(|e| e.to_string())?
            .check()
            .map_err(|e| e.to_string())?;
        // The desktop's own handler runs on the same event; give it a moment
        // before reading what stuck.
        let deadline = Instant::now() + Duration::from_millis(300);
        loop {
            let now = self
                .conn
                .xkb_get_state(xkb::ID::USE_CORE_KBD.into())
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?;
            let locked = usize::from(u8::from(now.locked_group));
            if locked == group || Instant::now() >= deadline {
                return Ok(locked == group);
            }
            std::thread::sleep(Duration::from_millis(30));
        }
    }
}

/// One configured layout.
#[derive(Debug, Clone, PartialEq)]
struct Layout {
    /// The XKB layout (`de`), or empty where the rules do not say.
    code: String,
    /// Its variant (`nodeadkeys`), or empty.
    variant: String,
    /// The keymap's name for the group (`German (no dead keys)`), or empty.
    name: String,
}

/// The configured layouts and the one in use: pure, so it is tested without
/// an X server.
#[derive(Debug, Clone, PartialEq)]
struct Layouts {
    list: Vec<Layout>,
    active: usize,
}

impl Layouts {
    /// `rules`: the raw `_XKB_RULES_NAMES` value (rules, model, layouts,
    /// variants, options, each NUL-terminated). `names`: the keymap's group
    /// names by group. `locked`: XKB's locked group.
    fn new(rules: &[u8], names: Vec<String>, locked: usize) -> Self {
        let fields: Vec<&[u8]> = rules.split(|&b| b == 0).collect();
        let field = |i: usize| -> Vec<String> {
            fields
                .get(i)
                .map(|f| {
                    String::from_utf8_lossy(f)
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut codes = field(2);
        if codes.len() == 1 && codes[0].is_empty() {
            codes.clear();
        }
        let variants = field(3);
        let n = codes.len().max(names.len()).min(MAX_GROUPS);
        let list: Vec<Layout> = (0..n)
            .map(|i| Layout {
                code: codes.get(i).cloned().unwrap_or_default(),
                variant: variants.get(i).cloned().unwrap_or_default(),
                name: names.get(i).cloned().unwrap_or_default(),
            })
            .collect();
        // A locked group past the last wraps, as XKB's own default does.
        let active = if list.is_empty() {
            0
        } else {
            locked % list.len()
        };
        Self { list, active }
    }

    fn snapshot(&self) -> Option<LayoutSnapshot> {
        if self.list.is_empty() {
            return None;
        }
        let active = self.first_group_like(self.active);
        Some(LayoutSnapshot {
            active_hkl: self.token(active),
            active_tag: self.tag(active),
            installed: (0..self.list.len())
                .filter(|&g| self.first_group_like(g) == g)
                .map(|g| (self.token(g), self.tag(g)))
                .collect(),
        })
    }

    /// The first group with the same layout as `group`. Each layout is offered
    /// once, at its first group: GNOME configures its input sources with the
    /// locale's layout appended for its shortcuts (`us,de` is `us,de,us`), a
    /// group nobody chose, and listing it would show the same layout twice.
    fn first_group_like(&self, group: usize) -> usize {
        let key = |l: &Layout| (l.code.clone(), l.variant.clone());
        let Some(this) = self.list.get(group) else {
            return group;
        };
        // A group the rules do not name is only ever like itself.
        if this.code.is_empty() {
            return group;
        }
        (0..group)
            .find(|&g| key(&self.list[g]) == key(this))
            .unwrap_or(group)
    }

    fn tag(&self, group: usize) -> String {
        self.list.get(group).map(tag_for).unwrap_or_default()
    }

    /// The layout's hash (8 hex) and its group (1 hex).
    fn token(&self, group: usize) -> String {
        let l = &self.list[group];
        let spec = format!("{}({})\u{1f}{}", l.code, l.variant, l.name);
        format!("{:08x}{group:x}", fnv1a(spec.as_bytes()))
    }

    /// The group `token` names, when it names a layout configured now.
    fn group_of(&self, token: &str) -> Option<usize> {
        if token.len() != 9 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let group = usize::from_str_radix(&token[8..], 16).ok()?;
        (group < self.list.len() && self.token(group).eq_ignore_ascii_case(token)).then_some(group)
    }
}

/// What the chip shows for a layout: the BCP-47 tag of a plain layout the
/// table knows, else the keymap's name for it, else the XKB spelling.
fn tag_for(l: &Layout) -> String {
    if l.variant.is_empty()
        && let Some(tag) = bcp47(&l.code)
    {
        return tag.to_string();
    }
    if !l.name.is_empty() {
        return l.name.clone();
    }
    match (l.code.is_empty(), l.variant.is_empty()) {
        (true, _) => "?".to_string(),
        (false, true) => l.code.clone(),
        (false, false) => format!("{}({})", l.code, l.variant),
    }
}

/// XKB layout → BCP-47, for the layouts whose language the name settles. A
/// layout left out goes by the keymap's own name, never by a guess: `se` is
/// Swedish, and the viewer would read the bare code as Northern Sami.
fn bcp47(code: &str) -> Option<&'static str> {
    Some(match code {
        "us" => "en-US",
        "gb" => "en-GB",
        "au" => "en-AU",
        "nz" => "en-NZ",
        "za" => "en-ZA",
        "ie" => "en-IE",
        "ca" => "fr-CA",
        "de" => "de-DE",
        "at" => "de-AT",
        "ch" => "de-CH",
        "fr" => "fr-FR",
        "be" => "fr-BE",
        "es" => "es-ES",
        "latam" => "es-419",
        "pt" => "pt-PT",
        "br" => "pt-BR",
        "it" => "it-IT",
        "nl" => "nl-NL",
        "se" => "sv-SE",
        "no" => "nb-NO",
        "dk" => "da-DK",
        "fi" => "fi-FI",
        "is" => "is-IS",
        "fo" => "fo-FO",
        "ee" => "et-EE",
        "lv" => "lv-LV",
        "lt" => "lt-LT",
        "pl" => "pl-PL",
        "cz" => "cs-CZ",
        "sk" => "sk-SK",
        "hu" => "hu-HU",
        "si" => "sl-SI",
        "hr" => "hr-HR",
        "rs" => "sr-RS",
        "ba" => "bs-BA",
        "mk" => "mk-MK",
        "bg" => "bg-BG",
        "ro" => "ro-RO",
        "md" => "ro-MD",
        "al" => "sq-AL",
        "gr" => "el-GR",
        "tr" => "tr-TR",
        "mt" => "mt-MT",
        "ru" => "ru-RU",
        "ua" => "uk-UA",
        "by" => "be-BY",
        "kz" => "kk-KZ",
        "uz" => "uz-UZ",
        "ge" => "ka-GE",
        "am" => "hy-AM",
        "az" => "az-AZ",
        "il" => "he-IL",
        "ara" => "ar",
        "ir" => "fa-IR",
        "pk" => "ur-PK",
        "bd" => "bn-BD",
        "np" => "ne-NP",
        "lk" => "si-LK",
        "th" => "th-TH",
        "vn" => "vi-VN",
        "jp" => "ja-JP",
        "kr" => "ko-KR",
        "cn" => "zh-CN",
        "tw" => "zh-TW",
        "mn" => "mn-MN",
        "epo" => "eo",
        _ => return None,
    })
}

/// FNV-1a, 32 bits: a stable hash for the token, the same on every build.
fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5u32, |h, &b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(layouts: &str, variants: &str) -> Vec<u8> {
        format!("evdev\0pc105\0{layouts}\0{variants}\0grp:alt_shift_toggle\0").into_bytes()
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_x11_session_has_a_display_and_no_wayland_one() {
        let s = |v: &str| Some(std::ffi::OsString::from(v));
        assert!(x11_session(s(":0"), None));
        assert!(x11_session(s(":0"), s("")));
        assert!(
            !x11_session(s(":0"), s("wayland-0")),
            "Xwayland's group is a copy"
        );
        assert!(!x11_session(None, None), "a system install");
        assert!(!x11_session(s(""), None));
    }

    /// Measured on GNOME 46 on Xorg (FR-97 §8): an XKB group lock from outside
    /// GNOME Shell is back on its own source within 20 ms.
    #[test]
    fn gnome_keeps_its_own_layout_and_the_others_do_not() {
        let d = |v: &str| Some(std::ffi::OsString::from(v));
        for gnome in [
            "GNOME",
            "ubuntu:GNOME",
            "GNOME-Classic:GNOME",
            "GNOME-Flashback:GNOME",
            "Budgie:GNOME",
        ] {
            assert!(keeps_its_own_layout(d(gnome)), "{gnome}");
        }
        for other in ["KDE", "XFCE", "MATE", "X-Cinnamon", "LXQt", ""] {
            assert!(!keeps_its_own_layout(d(other)), "{other}");
        }
        assert!(
            !keeps_its_own_layout(None),
            "a bare window manager names none"
        );
    }

    #[test]
    fn two_layouts_and_the_second_in_use() {
        let l = Layouts::new(&rules("us,de", ","), names(&["English (US)", "German"]), 1);
        let s = l.snapshot().expect("a snapshot");
        assert_eq!(s.active_tag, "de-DE");
        assert_eq!(
            s.installed
                .iter()
                .map(|(_, t)| t.as_str())
                .collect::<Vec<_>>(),
            ["en-US", "de-DE"]
        );
        assert_eq!(s.active_hkl, s.installed[1].0);
        // The token is what the viewer's picker accepts back.
        for (token, _) in &s.installed {
            assert_eq!(token.len(), 9);
            assert!(token.bytes().all(|b| b.is_ascii_hexdigit()), "{token}");
        }
    }

    #[test]
    fn a_variant_goes_by_the_keymaps_own_name() {
        let l = Layouts::new(
            &rules("us,de", "dvorak,nodeadkeys"),
            names(&["English (Dvorak)", "German (no dead keys)"]),
            0,
        );
        let s = l.snapshot().expect("a snapshot");
        assert_eq!(s.active_tag, "English (Dvorak)");
        assert_eq!(s.installed[1].1, "German (no dead keys)");
        // Without a name: the XKB spelling, never the plain layout's tag.
        let bare = Layouts::new(&rules("de", "nodeadkeys"), Vec::new(), 0);
        assert_eq!(bare.snapshot().unwrap().active_tag, "de(nodeadkeys)");
    }

    #[test]
    fn a_layout_the_table_does_not_know_keeps_its_name() {
        let l = Layouts::new(&rules("dz", ""), names(&["Berber (Algeria, Latin)"]), 0);
        assert_eq!(l.snapshot().unwrap().active_tag, "Berber (Algeria, Latin)");
        let unnamed = Layouts::new(&rules("dz", ""), Vec::new(), 0);
        assert_eq!(unnamed.snapshot().unwrap().active_tag, "dz");
    }

    #[test]
    fn without_the_rules_property_the_group_names_serve() {
        let l = Layouts::new(&[], names(&["English (US)", "Russian"]), 1);
        let s = l.snapshot().expect("a snapshot");
        assert_eq!(s.installed.len(), 2);
        assert_eq!(s.active_tag, "Russian");
        assert!(
            Layouts::new(&[], Vec::new(), 0).snapshot().is_none(),
            "nothing known"
        );
    }

    /// GNOME's input sources `us, de`, as a GNOME 46 session on Xorg sets them
    /// (FR-97 §8, the P3e-1 field cell): `_XKB_RULES_NAMES` reads
    /// `"evdev", "pc105+inet", "us,de,us", ",,"`, the locale's layout appended
    /// as a third group for GNOME's shortcuts. Each layout is offered once.
    #[test]
    fn gnomes_locale_group_is_not_offered_twice() {
        let rules = b"evdev\0pc105+inet\0us,de,us\0,,\0\0";
        let names = || names(&["English (US)", "German", "English (US)"]);
        let s = Layouts::new(rules, names(), 1).snapshot().unwrap();
        assert_eq!(
            s.installed
                .iter()
                .map(|(_, t)| t.as_str())
                .collect::<Vec<_>>(),
            ["en-US", "de-DE"]
        );
        assert_eq!(s.active_tag, "de-DE");
        // The locale group in use reads as the layout it repeats.
        let on_locale = Layouts::new(rules, names(), 2);
        let s2 = on_locale.snapshot().unwrap();
        assert_eq!(s2.active_tag, "en-US");
        assert_eq!(s2.active_hkl, s2.installed[0].0);
        assert_eq!(on_locale.group_of(&s2.active_hkl), Some(0));
        // Groups the rules do not name are never merged.
        let unnamed = Layouts::new(&[], names(), 0).snapshot().unwrap();
        assert_eq!(unnamed.installed.len(), 3);
    }

    #[test]
    fn a_locked_group_past_the_last_wraps() {
        let l = Layouts::new(&rules("us,de", ","), Vec::new(), 3);
        assert_eq!(l.active, 1);
    }

    #[test]
    fn never_more_than_four_groups() {
        let l = Layouts::new(&rules("us,de,fr,ru,ua", ",,,,"), Vec::new(), 0);
        assert_eq!(l.list.len(), MAX_GROUPS);
    }

    #[test]
    fn a_token_names_its_group_only_while_that_layout_is_there() {
        let before = Layouts::new(&rules("us,de", ","), Vec::new(), 0);
        let de = before.token(1);
        assert_eq!(before.group_of(&de), Some(1));
        assert_eq!(before.group_of(&de.to_uppercase()), Some(1));
        // The desktop swapped its layouts: the old click locks nothing.
        let after = Layouts::new(&rules("us,fr", ","), Vec::new(), 0);
        assert_eq!(after.group_of(&de), None);
        let reordered = Layouts::new(&rules("de,us", ","), Vec::new(), 0);
        assert_eq!(
            reordered.group_of(&de),
            None,
            "the group is part of the token"
        );
        // Malformed, or past the last group.
        for bad in ["", "1", "zzzzzzzzz", "0000000001", &de[..8]] {
            assert_eq!(before.group_of(bad), None, "{bad}");
        }
        let past = format!("{}5", &de[..8]);
        assert_eq!(before.group_of(&past), None);
    }

    #[test]
    fn every_tag_in_the_table_is_well_formed() {
        for code in [
            "us", "gb", "au", "nz", "za", "ie", "ca", "de", "at", "ch", "fr", "be", "es", "latam",
            "pt", "br", "it", "nl", "se", "no", "dk", "fi", "is", "fo", "ee", "lv", "lt", "pl",
            "cz", "sk", "hu", "si", "hr", "rs", "ba", "mk", "bg", "ro", "md", "al", "gr", "tr",
            "mt", "ru", "ua", "by", "kz", "uz", "ge", "am", "az", "il", "ara", "ir", "pk", "bd",
            "np", "lk", "th", "vn", "jp", "kr", "cn", "tw", "mn", "epo",
        ] {
            let tag = bcp47(code).unwrap_or_else(|| panic!("{code} is in the table"));
            let mut parts = tag.split('-');
            let lang = parts.next().unwrap();
            assert!(
                (2..=3).contains(&lang.len()) && lang.bytes().all(|b| b.is_ascii_lowercase()),
                "{code} → {tag}"
            );
            for region in parts {
                assert!(
                    (region.len() == 2 && region.bytes().all(|b| b.is_ascii_uppercase()))
                        || (region.len() == 3 && region.bytes().all(|b| b.is_ascii_digit())),
                    "{code} → {tag}"
                );
            }
        }
        assert_eq!(bcp47("se"), Some("sv-SE"), "not Northern Sami");
        assert_eq!(bcp47("dz"), None);
    }

    #[test]
    fn the_hash_is_stable() {
        // A token is only ever compared within one daemon's life, but a hash
        // that changed with the toolchain would still be a surprise.
        assert_eq!(fnv1a(b""), 0x811c_9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
    }

    fn required() -> bool {
        std::env::var("ROOMLERD_TEST_X11").as_deref() == Ok("1")
    }

    fn setxkbmap(layouts: &str) -> bool {
        std::process::Command::new("setxkbmap")
            .args(["-layout", layouts])
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Puts the display's keymap back for the tests that share it.
    struct OneLayoutAgain;
    impl Drop for OneLayoutAgain {
        fn drop(&mut self) {
            setxkbmap("us");
        }
    }

    /// The real thing, on the X server the CI lane starts (`DISPLAY` from
    /// `xvfb-run`; `ROOMLERD_TEST_X11=1` makes its absence a failure): two
    /// layouts configured as `setxkbmap` does it, read back as the snapshot
    /// the viewer gets, and a switch to the second and back.
    #[test]
    fn x11_real_switch_round_trip() {
        let Some(x) = Xkb::open() else {
            assert!(
                !required(),
                "ROOMLERD_TEST_X11=1 but there is no X server with XKB"
            );
            eprintln!("no X server — skipping (ROOMLERD_TEST_X11=1 makes this a failure)");
            return;
        };
        // xvfb depends on x11-xkb-utils, the server's own keymap compiler.
        assert!(
            setxkbmap("us,de"),
            "setxkbmap could not configure two layouts"
        );
        let _restore = OneLayoutAgain;
        let before = x.read().expect("the layouts");
        assert_eq!(before.list.len(), 2, "{before:?}");
        let s = before.snapshot().expect("a snapshot");
        assert_eq!(
            s.installed
                .iter()
                .map(|(_, t)| t.as_str())
                .collect::<Vec<_>>(),
            ["en-US", "de-DE"]
        );
        assert!(x.lock_group(1).expect("the switch"), "group 2 locked");
        let after = x.read().expect("the layouts");
        assert_eq!(after.active, 1);
        assert_eq!(after.snapshot().expect("a snapshot").active_tag, "de-DE");
        assert_eq!(after.group_of(&s.installed[0].0), Some(0));
        assert!(x.lock_group(0).expect("the switch back"));
        eprintln!(
            "x11-real: the layouts {:?} read back, and the switch to de-DE and back took",
            s.installed
        );
    }
}
