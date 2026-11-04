// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-36 P4 — input injection through `/dev/uinput`, below the compositor.
//!
//! The companion to `capture::drm_backend`. Capture without input is a
//! read-only session, and the X11 injector cannot help here: `XTest` reaches
//! Xwayland clients only, so on a native Wayland desktop it silently does
//! nothing for everything else — and at the login greeter there is no X server
//! of ours to talk to at all.
//!
//! `uinput` sidesteps that the same way DRM capture does: it creates a virtual
//! **kernel input device**, so events enter through evdev underneath the
//! display server. libinput picks it up like any USB keyboard or tablet, which
//! means one code path for GNOME, KDE, XFCE, X11 and the greeter.
//!
//! ## Design notes worth knowing before editing
//!
//! - **Absolute pointer, not relative.** The wire carries normalised `0..1`
//!   coordinates precisely so the agent's resolution can change mid-session.
//!   A relative device would force us to track the pointer and guess at
//!   acceleration; an absolute one (`ABS_X`/`ABS_Y` over a fixed 0..=32767
//!   range, the convention for tablets) lands exactly where asked, and the
//!   compositor maps that onto whatever the screen currently is. Relative
//!   mode (FR-109 P2b) is the one exception: it carries movement, never a
//!   position, through a second, relative-only pointer made on its first
//!   frame (`open_rel_device`).
//! - **HID usage → Linux keycode is an explicit table.** It cannot be
//!   arithmetic: HID orders letters alphabetically (`0x04` = A) while Linux
//!   keycodes follow the physical QWERTY row order (`KEY_Q` = 16, `KEY_A` = 30).
//!   The table mirrors the kernel's own `hid_keyboard[]`.
//! - ⚠️ **The ioctl numbers are computed, and the computation is tested.**
//!   `_IOW` encoding is easy to get subtly wrong and a wrong number is not a
//!   compile error — it is a runtime `EINVAL` on a device that then silently
//!   does nothing. [`ioc`] is checked against published constants in the tests.
//! - ⚠️ **A newly created uinput device is not immediately usable.** udev and
//!   libinput enumerate it asynchronously; events written in the first few tens
//!   of milliseconds are delivered to nobody. We settle after `UI_DEV_CREATE`,
//!   which is why the first click after a session opens is not lost.

use anyhow::{Result, anyhow, bail};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tracing::{info, warn};

use super::hid_evdev::{KEYMAP, hid_to_evdev};
use super::{InputInjector, InputMsg, WheelMode, button_code};

const UINPUT_PATH: &str = "/dev/uinput";

// --- evdev event types / codes (linux/input-event-codes.h) ---
const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const SYN_REPORT: u16 = 0;
const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const REL_WHEEL: u16 = 0x08;
const REL_HWHEEL: u16 = 0x06;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const BTN_SIDE: u16 = 0x113;
const BTN_EXTRA: u16 = 0x114;
/// `KEY_LEFTSHIFT` — needed directly by the KeyText path, which presses shift
/// around a character rather than going through the HID table for it.
const KEY_LEFTSHIFT: u16 = 42;
/// FR-93 P4c — the other shift, so a viewer holding EITHER counts as holding
/// shift when KeyText decides whether to press it.
const KEY_RIGHTSHIFT: u16 = 54;
/// FR-97 P3f — AltGr: the right Alt key, where the keymap makes it level 3.
const KEY_RIGHTALT: u16 = 100;

/// Absolute axis range. 0..=32767 is the conventional span for an absolute
/// pointing device; the compositor scales it to the current screen, so this
/// stays correct across a resolution change without any resync.
const ABS_MAX: i32 = 32767;

/// Pixels of wheel delta per detent when the controller reports `Pixel` mode.
/// Browsers report roughly this per notch; evdev `REL_WHEEL` counts detents,
/// so a fractional remainder is carried rather than dropped — otherwise slow
/// trackpad scrolling would never accumulate to a click and simply do nothing.
const WHEEL_PIXELS_PER_DETENT: f32 = 53.0;

/// How long to let udev/libinput enumerate the new device before trusting it
/// to deliver events. Without this the first events after open go nowhere.
const SETTLE: Duration = Duration::from_millis(300);

/// FR-93 P4c — the settle, overridable for measuring it on a host
/// (`ROOMLERD_UINPUT_SETTLE_MS`, at most 5 s). Under load the default is not
/// always enough (measured on KDE: 2 of 8 first moves reached nobody); the
/// arbiter's warm-up (`input::arbiter`) is what makes the first event safe,
/// by opening the device a second or more before anything is written.
fn settle() -> Duration {
    tunnel_core::env::node_env("UINPUT_SETTLE_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(SETTLE, |ms| Duration::from_millis(ms.min(5000)))
}

// --- ioctl plumbing ---

/// The kernel's `_IOC` encoding: `dir << 30 | size << 16 | type << 8 | nr`.
///
/// Hand-rolled rather than pulled from a crate because the surface is four
/// constants, and because a wrong value fails at RUNTIME with `EINVAL` on a
/// device that then silently injects nothing — so it is worth having under a
/// test that checks it against the published numbers.
const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    ((dir << 30) | (size << 16) | (ty << 8) | nr) as libc::c_ulong
}
const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const UINPUT_IOCTL_BASE: u32 = b'U' as u32;

fn ui_dev_create() -> libc::c_ulong {
    ioc(IOC_NONE, UINPUT_IOCTL_BASE, 1, 0)
}
fn ui_dev_destroy() -> libc::c_ulong {
    ioc(IOC_NONE, UINPUT_IOCTL_BASE, 2, 0)
}
fn ui_dev_setup() -> libc::c_ulong {
    ioc(
        IOC_WRITE,
        UINPUT_IOCTL_BASE,
        3,
        std::mem::size_of::<UinputSetup>() as u32,
    )
}
fn ui_abs_setup() -> libc::c_ulong {
    ioc(
        IOC_WRITE,
        UINPUT_IOCTL_BASE,
        4,
        std::mem::size_of::<UinputAbsSetup>() as u32,
    )
}
fn ui_set_evbit() -> libc::c_ulong {
    ioc(IOC_WRITE, UINPUT_IOCTL_BASE, 100, 4)
}
fn ui_set_keybit() -> libc::c_ulong {
    ioc(IOC_WRITE, UINPUT_IOCTL_BASE, 101, 4)
}
fn ui_set_relbit() -> libc::c_ulong {
    ioc(IOC_WRITE, UINPUT_IOCTL_BASE, 102, 4)
}
fn ui_set_absbit() -> libc::c_ulong {
    ioc(IOC_WRITE, UINPUT_IOCTL_BASE, 103, 4)
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct InputId {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
}

#[repr(C)]
struct UinputSetup {
    id: InputId,
    name: [u8; 80],
    ff_effects_max: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct InputAbsinfo {
    value: i32,
    minimum: i32,
    maximum: i32,
    fuzz: i32,
    flat: i32,
    resolution: i32,
}

#[repr(C)]
struct UinputAbsSetup {
    code: u16,
    absinfo: InputAbsinfo,
}

#[repr(C)]
struct InputEvent {
    time: libc::timeval,
    type_: u16,
    code: u16,
    value: i32,
}

/// Runtime gate. **Default OFF**, matching `drm_backend`: a virtual input
/// device is host-global and visible to every application, so a host opts in
/// (`ROOMLERD_UINPUT=1`) rather than having one appear because it upgraded.
/// Pair it with `ROOMLERD_DRM_CAPTURE=1` on a Wayland host.
pub fn env_enabled() -> bool {
    tunnel_core::env::flag("UINPUT", false)
}

/// Is `/dev/uinput` present and writable by this process?
pub fn available() -> bool {
    OpenOptions::new().write(true).open(UINPUT_PATH).is_ok()
}

pub struct UinputInjector {
    dev: File,
    /// FR-109 P2b — a relative-only pointer beside the tablet, made on the
    /// first `mouse_rel` and destroyed with the injector, so no second device
    /// appears unless relative mode is used.
    rel: Option<File>,
    /// Carried wheel remainder, so sub-detent scrolling accumulates instead of
    /// being truncated to nothing on every event.
    wheel_rem: (f32, f32),
    /// Rate-limit for the "this event kind is not implemented" notice, so an
    /// unsupported stream cannot flood the daemon log.
    warned_text: bool,
    warned_touch: bool,
    warned_rel: bool,
    /// FR-36 P4b, FR-97 P3f — how typed text becomes keys on this host: its
    /// own XKB keymap, else the verified table; `None` refuses typed text. The
    /// raw layout name is kept even then, so the refusal can SAY what it found:
    /// "unsupported layout" is not actionable, "unsupported layout `de`" is.
    text_keys: Option<super::keylayout::TextKeys>,
    layout_name: String,
    /// FR-95 P2 — switched on by a system install by itself: inject only while
    /// the automatic capture reads the person's session (`seat_guard`).
    auto_system: bool,
    /// The automatic injector dropped input since it last injected: said once
    /// per closed spell, not per event.
    dropping: bool,
    /// FR-93 P4c — the shift keys a viewer holds down through `Key` (left,
    /// right), so KeyText neither presses shift again nor lets go of the
    /// viewer's own.
    shift_held: [bool; 2],
    /// FR-97 P3f — the right Alt key a viewer holds down, AltGr where the
    /// keymap makes it level 3: KeyText leaves it to them, as with shift.
    altgr_held: bool,
}

impl UinputInjector {
    /// FR-95 P2 — mark this injector as the automatic system capture's.
    pub fn for_auto_system(mut self) -> Self {
        self.auto_system = true;
        self
    }

    /// FR-95 P2 — whether input may reach the screen now. Always for a
    /// configured injector; for the automatic one, only while its capture
    /// reads the person's unlocked session, so a controller who cannot see
    /// the screen (the lock screen, the greeter) cannot type into it.
    fn may_inject(&mut self) -> bool {
        if !self.auto_system {
            return true;
        }
        #[cfg(feature = "drm-capture")]
        let open = crate::capture::seat_guard::viewing();
        #[cfg(not(feature = "drm-capture"))]
        let open = false;
        if open == self.dropping {
            self.dropping = !open;
            if open {
                info!("uinput: injecting again, the person's session is on screen (FR-95 P2)");
            } else {
                info!(
                    "uinput: dropping input while the person's session is not on screen, unlocked (FR-95 P2)"
                );
            }
        }
        open
    }

    pub fn new() -> Result<Self> {
        let dev = OpenOptions::new()
            .write(true)
            .open(UINPUT_PATH)
            .map_err(|e| anyhow!("open {UINPUT_PATH}: {e} (needs root or the `input` group)"))?;
        let fd = dev.as_raw_fd();

        // SAFETY: every ioctl below is a documented uinput setup call on a fd
        // we just opened; the argument is a plain integer or a #[repr(C)]
        // struct matching the kernel's, and each return is checked.
        unsafe {
            for ev in [EV_KEY, EV_REL, EV_ABS, EV_SYN] {
                ck(
                    libc::ioctl(fd, ui_set_evbit(), ev as libc::c_int),
                    "SET_EVBIT",
                )?;
            }
            // Every key this backend can ever emit must be declared up front —
            // an undeclared code is dropped by the kernel, silently.
            for code in KEYMAP.iter().map(|&(_, k)| k) {
                ck(
                    libc::ioctl(fd, ui_set_keybit(), code as libc::c_int),
                    "SET_KEYBIT",
                )?;
            }
            for btn in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA] {
                ck(
                    libc::ioctl(fd, ui_set_keybit(), btn as libc::c_int),
                    "SET_KEYBIT btn",
                )?;
            }
            for rel in [REL_WHEEL, REL_HWHEEL] {
                ck(
                    libc::ioctl(fd, ui_set_relbit(), rel as libc::c_int),
                    "SET_RELBIT",
                )?;
            }
            for abs in [ABS_X, ABS_Y] {
                ck(
                    libc::ioctl(fd, ui_set_absbit(), abs as libc::c_int),
                    "SET_ABSBIT",
                )?;
                let setup = UinputAbsSetup {
                    code: abs,
                    absinfo: InputAbsinfo {
                        minimum: 0,
                        maximum: ABS_MAX,
                        ..Default::default()
                    },
                };
                ck(libc::ioctl(fd, ui_abs_setup(), &setup), "ABS_SETUP")?;
            }

            let mut name = [0u8; 80];
            let label = b"Roomler Virtual Input";
            name[..label.len()].copy_from_slice(label);
            let setup = UinputSetup {
                id: InputId {
                    bustype: 0x03, // BUS_USB — the value libinput expects to see
                    vendor: 0x1209,
                    product: 0x0001,
                    version: 1,
                },
                name,
                ff_effects_max: 0,
            };
            ck(libc::ioctl(fd, ui_dev_setup(), &setup), "DEV_SETUP")?;
            ck(libc::ioctl(fd, ui_dev_create()), "DEV_CREATE")?;
        }

        // ⚠️ Load-bearing. udev and libinput enumerate the new device
        // asynchronously; anything written before they do reaches nobody, so
        // without this the first click of a session is simply lost.
        std::thread::sleep(settle());
        info!("input: backend=uinput (virtual kernel device, below the compositor)");

        let (layout, layout_name) = super::keylayout::detect();
        let keys: Vec<u16> = KEYMAP.iter().map(|&(_, k)| k).collect();
        let (text_keys, how) = super::keylayout::TextKeys::for_host(&layout_name, layout, &keys);
        match &text_keys {
            Some(_) => info!(
                detected = layout_name.as_str(),
                keys = how.as_str(),
                "uinput: typed text will be sent as physical keys for this layout"
            ),
            None => warn!(
                detected = layout_name.as_str(),
                why = how.as_str(),
                "uinput: no key map for this keyboard layout — typed text will NOT \
                 arrive (pointer and non-text keys are unaffected)"
            ),
        }

        Ok(Self {
            dev,
            rel: None,
            wheel_rem: (0.0, 0.0),
            warned_text: false,
            warned_touch: false,
            warned_rel: false,
            text_keys,
            layout_name,
            auto_system: false,
            dropping: false,
            shift_held: [false; 2],
            altgr_held: false,
        })
    }

    /// An injector over any writable file, with none of the device setup, so
    /// a test can read back exactly which events an `InputMsg` became. Its
    /// `Drop` ioctl then fails on a plain file, harmlessly.
    #[cfg(test)]
    fn over(dev: File) -> Self {
        Self {
            dev,
            rel: None,
            wheel_rem: (0.0, 0.0),
            warned_text: false,
            warned_touch: false,
            warned_rel: false,
            text_keys: None,
            layout_name: String::new(),
            auto_system: false,
            dropping: false,
            shift_held: [false; 2],
            altgr_held: false,
        }
    }

    /// As [`Self::over`], with a plain file standing in for the relative
    /// pointer, so a test reads back what `mouse_rel` became.
    #[cfg(test)]
    fn with_rel(mut self, rel: File) -> Self {
        self.rel = Some(rel);
        self
    }

    fn emit(&mut self, type_: u16, code: u16, value: i32) -> Result<()> {
        write_event(&mut self.dev, type_, code, value)
    }

    /// Publish the batch. evdev consumers act on the SYN_REPORT, not on the
    /// individual events, so a missing sync means the input simply never
    /// happens — it does not merely arrive late.
    fn sync(&mut self) -> Result<()> {
        self.emit(EV_SYN, SYN_REPORT, 0)
    }

    fn move_abs(&mut self, x: f32, y: f32) -> Result<()> {
        let clamp = |v: f32| (v.clamp(0.0, 1.0) * ABS_MAX as f32).round() as i32;
        self.emit(EV_ABS, ABS_X, clamp(x))?;
        self.emit(EV_ABS, ABS_Y, clamp(y))
    }
}

impl Drop for UinputInjector {
    fn drop(&mut self) {
        // SAFETY: destroying the devices we created, on our own fds.
        unsafe {
            if let Some(rel) = &self.rel {
                libc::ioctl(rel.as_raw_fd(), ui_dev_destroy());
            }
            libc::ioctl(self.dev.as_raw_fd(), ui_dev_destroy());
        }
    }
}

/// Write one event to a uinput device.
fn write_event(dev: &mut File, type_: u16, code: u16, value: i32) -> Result<()> {
    let ev = InputEvent {
        time: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        type_,
        code,
        value,
    };
    // SAFETY: `InputEvent` is #[repr(C)] and layout-compatible with the
    // kernel's `struct input_event`; we write exactly its size.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &ev as *const InputEvent as *const u8,
            std::mem::size_of::<InputEvent>(),
        )
    };
    dev.write_all(bytes)
        .map_err(|e| anyhow!("uinput write: {e}"))
}

/// FR-109 P2b — the relative-only pointer: `REL_X`/`REL_Y`, and buttons so
/// udev and libinput take it for a mouse (spec §8, P0 (3): both GNOME and KDE
/// add it as a pointer beside the tablet). It settles before it is returned,
/// as the tablet does, so the first frame written to it reaches libinput.
fn open_rel_device() -> Result<File> {
    let dev = OpenOptions::new()
        .write(true)
        .open(UINPUT_PATH)
        .map_err(|e| anyhow!("open {UINPUT_PATH}: {e}"))?;
    let fd = dev.as_raw_fd();
    // SAFETY: documented uinput setup calls on a fd we just opened; each
    // argument is a plain integer or a #[repr(C)] struct matching the
    // kernel's, and each return is checked.
    unsafe {
        for ev in [EV_KEY, EV_REL, EV_SYN] {
            ck(
                libc::ioctl(fd, ui_set_evbit(), ev as libc::c_int),
                "SET_EVBIT rel",
            )?;
        }
        for btn in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE] {
            ck(
                libc::ioctl(fd, ui_set_keybit(), btn as libc::c_int),
                "SET_KEYBIT rel",
            )?;
        }
        for rel in [REL_X, REL_Y] {
            ck(
                libc::ioctl(fd, ui_set_relbit(), rel as libc::c_int),
                "SET_RELBIT rel",
            )?;
        }
        let mut name = [0u8; 80];
        let label = b"Roomler Virtual Pointer";
        name[..label.len()].copy_from_slice(label);
        let setup = UinputSetup {
            id: InputId {
                bustype: 0x03,
                vendor: 0x1209,
                product: 0x0002,
                version: 1,
            },
            name,
            ff_effects_max: 0,
        };
        ck(libc::ioctl(fd, ui_dev_setup(), &setup), "DEV_SETUP rel")?;
        ck(libc::ioctl(fd, ui_dev_create()), "DEV_CREATE rel")?;
    }
    std::thread::sleep(settle());
    info!("uinput: relative pointer made for relative mode (FR-109 P2b)");
    Ok(dev)
}

fn ck(rc: libc::c_int, what: &str) -> Result<()> {
    if rc < 0 {
        bail!("uinput {what}: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

impl InputInjector for UinputInjector {
    fn inject(&mut self, event: InputMsg) -> Result<()> {
        if !self.may_inject() {
            return Ok(());
        }
        match event {
            InputMsg::MouseMove { x, y, .. } => {
                self.move_abs(x, y)?;
                self.sync()
            }
            InputMsg::MouseButton {
                btn, down, x, y, ..
            } => {
                // Position first, then the button, in ONE report: a click that
                // syncs its move separately can land at the old position if the
                // compositor samples between the two.
                self.move_abs(x, y)?;
                self.emit(EV_KEY, button_code(btn), i32::from(down))?;
                self.sync()
            }
            // #1945 — the arbiter's release-all: no EV_ABS, so the button
            // lets go where the pointer is. With one, a viewer that vanished
            // mid-drag threw the cursor to (0,0), GNOME's hot corner.
            InputMsg::MouseRelease { btn } => {
                self.emit(EV_KEY, button_code(btn), 0)?;
                self.sync()
            }
            // FR-109 — relative mode's press: no EV_ABS, so it lands where the
            // pointer is, the twin of the release above.
            InputMsg::MousePress { btn } => {
                self.emit(EV_KEY, button_code(btn), 1)?;
                self.sync()
            }
            // FR-109 P2b — the tablet is absolute by design (the module docs),
            // so relative motion goes through the relative-only pointer beside
            // it, made on the first frame. libinput hands relative-pointer
            // clients (a game camera) its unaccelerated deltas, which are the
            // counts sent; the cursor follows the accelerated ones.
            InputMsg::MouseRel { dx, dy } => {
                if dx == 0 && dy == 0 {
                    return Ok(());
                }
                if self.rel.is_none() {
                    // A test injector writes to plain files and never makes a
                    // real device (`with_rel` gives it one to read back).
                    if cfg!(test) {
                        return Ok(());
                    }
                    match open_rel_device() {
                        Ok(rel) => self.rel = Some(rel),
                        Err(e) => {
                            if !self.warned_rel {
                                self.warned_rel = true;
                                warn!(
                                    error = %format!("{e:#}"),
                                    "uinput: the relative pointer did not open; relative motion dropped (FR-109 P2b)"
                                );
                            }
                            return Ok(());
                        }
                    }
                }
                let Some(rel) = self.rel.as_mut() else {
                    return Ok(());
                };
                if dx != 0 {
                    write_event(rel, EV_REL, REL_X, dx)?;
                }
                if dy != 0 {
                    write_event(rel, EV_REL, REL_Y, dy)?;
                }
                write_event(rel, EV_SYN, SYN_REPORT, 0)
            }
            InputMsg::MouseWheel { dx, dy, mode } => {
                let scale = match mode {
                    WheelMode::Pixel => WHEEL_PIXELS_PER_DETENT,
                    WheelMode::Line => 1.0,
                    // A page is a large jump; treat it as a burst of detents
                    // rather than inventing a separate axis.
                    WheelMode::Page => 1.0 / 3.0,
                };
                let (mut rx, mut ry) = self.wheel_rem;
                rx += dx / scale;
                ry += dy / scale;
                let (cx, cy) = (rx.trunc() as i32, ry.trunc() as i32);
                self.wheel_rem = (rx - cx as f32, ry - cy as f32);
                if cx == 0 && cy == 0 {
                    return Ok(());
                }
                if cx != 0 {
                    self.emit(EV_REL, REL_HWHEEL, cx)?;
                }
                if cy != 0 {
                    // Browser dy is positive DOWN; evdev REL_WHEEL is positive UP.
                    self.emit(EV_REL, REL_WHEEL, -cy)?;
                }
                self.sync()
            }
            InputMsg::Key { code, down, .. } => {
                let Some(key) = hid_to_evdev(code) else {
                    // Same contract as the enigo backend (FR-13): an unmapped
                    // HID usage is DROPPED, never guessed at.
                    return Ok(());
                };
                match key {
                    KEY_LEFTSHIFT => self.shift_held[0] = down,
                    KEY_RIGHTSHIFT => self.shift_held[1] = down,
                    KEY_RIGHTALT => self.altgr_held = down,
                    _ => {}
                }
                self.emit(EV_KEY, key, i32::from(down))?;
                self.sync()
            }
            InputMsg::KeyText { text } => {
                // FR-36 P4b, FR-97 P3f. evdev carries PHYSICAL keys, so typing
                // text means pressing the key that produces each character
                // *under this host's layout*: from the host's own XKB keymap,
                // else the verified table. With neither it refuses loudly
                // rather than typing the US mapping at a keyboard whose keys
                // are elsewhere.
                let Some(keys) = self.text_keys.as_ref() else {
                    if !self.warned_text {
                        self.warned_text = true;
                        warn!(
                            detected = self.layout_name.as_str(),
                            "uinput: typed text dropped — no key map for this layout. \
                             Pointer and non-text keys still work."
                        );
                    }
                    return Ok(());
                };
                let name = keys.name().to_string();
                let strokes: Vec<_> = text.chars().map(|ch| keys.stroke(ch)).collect();
                let mut skipped = 0usize;
                for k in strokes {
                    let Some(k) = k else {
                        // A character this layout cannot reach in one stroke
                        // (CJK, or one needing a dead key). Skip it rather than
                        // substituting something wrong.
                        skipped += 1;
                        continue;
                    };
                    // FR-93 P4c — a modifier goes in a report of its OWN,
                    // before the key and after it. KWin (Plasma 6.6, measured)
                    // gives every key in a report the modifiers that report
                    // ENDS with: a key pressed together with shift's release
                    // came out unshifted, so "A" typed "a" and "!" typed "1".
                    // AltGr (FR-97 P3f) goes the same way, outside shift. A
                    // modifier the viewer is holding is theirs: neither
                    // pressed again nor let go of here.
                    let press_altgr = k.level3 && !self.altgr_held;
                    let press_shift = k.shift && !self.shift_held.contains(&true);
                    if press_altgr {
                        self.emit(EV_KEY, KEY_RIGHTALT, 1)?;
                        self.sync()?;
                    }
                    if press_shift {
                        self.emit(EV_KEY, KEY_LEFTSHIFT, 1)?;
                        self.sync()?;
                    }
                    self.emit(EV_KEY, k.key, 1)?;
                    self.emit(EV_KEY, k.key, 0)?;
                    // One report per character: a compositor coalescing an
                    // entire string into a single frame can drop repeats of the
                    // same key, which is exactly what typing "ll" looks like.
                    self.sync()?;
                    if press_shift {
                        self.emit(EV_KEY, KEY_LEFTSHIFT, 0)?;
                        self.sync()?;
                    }
                    if press_altgr {
                        self.emit(EV_KEY, KEY_RIGHTALT, 0)?;
                        self.sync()?;
                    }
                }
                if skipped > 0 && !self.warned_text {
                    self.warned_text = true;
                    warn!(
                        layout = name.as_str(),
                        skipped, "uinput: some characters are not typeable under this layout"
                    );
                }
                Ok(())
            }
            InputMsg::Touch { .. } => {
                if !self.warned_touch {
                    self.warned_touch = true;
                    warn!(
                        "uinput: touch events are not implemented (needs a multitouch ABS_MT device)"
                    );
                }
                Ok(())
            }
            InputMsg::Heartbeat { .. } => Ok(()),
            // FR-97 P4a — Windows only; a Linux agent never advertises `sas`.
            InputMsg::Sas => Ok(()),
        }
    }

    fn has_permission(&self) -> bool {
        true // constructing the device proved it
    }

    /// FR-92 P9 — keep busy's move: the same absolute report a controller's
    /// move makes, so it enters through libinput like a person's tablet and
    /// resets the compositor's idle clock. ⚠️ The kernel drops an `EV_ABS`
    /// that repeats the axis's current value, so a "move" to where the
    /// device already is resets nothing — keep busy never sends one twice.
    fn move_norm(&mut self, x: f64, y: f64) -> Result<()> {
        if !self.may_inject() {
            return Ok(());
        }
        self.move_abs(x as f32, y as f32)?;
        self.sync()
    }

    fn automatic(&self) -> bool {
        self.auto_system
    }
}

// The HID usage → evdev keycode table lives in `super::hid_evdev` — FR-45 P4's
// portal input path sends the same codes through NotifyKeyboardKeycode, and the
// two consumers are behind different features.

#[cfg(test)]
mod tests {
    use super::*;

    /// A wrong ioctl number is not a compile error — it is a runtime EINVAL on
    /// a device that then silently injects nothing. Pin the encoding against
    /// the published constants.
    #[test]
    fn ioctl_numbers_match_the_published_values() {
        assert_eq!(ui_dev_create(), 0x5501);
        assert_eq!(ui_dev_destroy(), 0x5502);
        assert_eq!(ui_set_evbit(), 0x4004_5564);
        assert_eq!(ui_set_keybit(), 0x4004_5565);
        assert_eq!(ui_set_relbit(), 0x4004_5566);
        assert_eq!(ui_set_absbit(), 0x4004_5567);
    }

    /// The kernel structs are an ABI. A size change means we would hand the
    /// kernel a differently-shaped struct under the same ioctl number.
    #[test]
    fn kernel_struct_sizes_are_the_abi() {
        assert_eq!(std::mem::size_of::<InputId>(), 8);
        assert_eq!(std::mem::size_of::<UinputSetup>(), 92);
        assert_eq!(std::mem::size_of::<InputAbsinfo>(), 24);
        assert_eq!(std::mem::size_of::<UinputAbsSetup>(), 28);
        // timeval (16 on 64-bit) + u16 + u16 + i32
        assert_eq!(std::mem::size_of::<InputEvent>(), 24);
    }

    // The HID→evdev table tests moved to `super::super::hid_evdev` with the
    // table itself.

    use crate::input::Button;

    /// Inject one event into an injector over a plain file and decode what
    /// it wrote, as `(type, code, value)`.
    fn written(msg: InputMsg) -> Vec<(u16, u16, i32)> {
        written_seq(vec![msg])
    }

    /// As [`written`], for a sequence through ONE injector that has a
    /// verified layout (KeyText types nothing without one).
    fn written_seq(msgs: Vec<InputMsg>) -> Vec<(u16, u16, i32)> {
        written_with(
            crate::input::keylayout::TextKeys::Table(crate::input::keylayout::Layout::Us),
            msgs,
        )
    }

    /// As [`written_seq`], typing with `keys`.
    fn written_with(
        keys: crate::input::keylayout::TextKeys,
        msgs: Vec<InputMsg>,
    ) -> Vec<(u16, u16, i32)> {
        use std::io::{Read, Seek};
        let mut file = tempfile::tempfile().expect("a temp file");
        let mut inj = UinputInjector::over(file.try_clone().expect("clone the fd"));
        inj.text_keys = Some(keys);
        for msg in msgs {
            inj.inject(msg).expect("inject");
        }
        drop(inj);
        let mut bytes = Vec::new();
        file.rewind().expect("rewind");
        file.read_to_end(&mut bytes).expect("read back");
        bytes
            .chunks_exact(std::mem::size_of::<InputEvent>())
            .map(|ev| {
                // After the 16-byte timeval: u16 type, u16 code, i32 value.
                let n = |at: usize| u16::from_ne_bytes([ev[at], ev[at + 1]]);
                let value = i32::from_ne_bytes([ev[20], ev[21], ev[22], ev[23]]);
                (n(16), n(18), value)
            })
            .collect()
    }

    /// #1945 — the arbiter's release-all lets go where the pointer IS: one
    /// key-up and a SYN, no EV_ABS. With a position, a viewer that vanished
    /// mid-drag threw the cursor to (0,0), GNOME's Activities hot corner.
    #[test]
    fn a_release_never_moves_the_pointer() {
        assert_eq!(
            written(InputMsg::MouseRelease { btn: Button::Left }),
            [(EV_KEY, BTN_LEFT, 0), (EV_SYN, SYN_REPORT, 0)]
        );
    }

    /// FR-109 — relative mode's press, the release's twin: one key-down and a
    /// SYN, no EV_ABS.
    #[test]
    fn a_relative_press_never_moves_the_pointer() {
        assert_eq!(
            written(InputMsg::MousePress { btn: Button::Left }),
            [(EV_KEY, BTN_LEFT, 1), (EV_SYN, SYN_REPORT, 0)]
        );
    }

    /// FR-109 P2b — relative motion never touches the absolute tablet: no
    /// EV_ABS jump, no stray EV_REL.
    #[test]
    fn relative_motion_writes_nothing_to_the_tablet() {
        assert_eq!(written(InputMsg::MouseRel { dx: 40, dy: 7 }), []);
    }

    /// Events as `(type, code, value)`.
    type Events = Vec<(u16, u16, i32)>;

    /// Decode what one plain file received.
    fn read_back(mut file: File) -> Events {
        use std::io::{Read, Seek};
        let mut bytes = Vec::new();
        file.rewind().expect("rewind");
        file.read_to_end(&mut bytes).expect("read back");
        bytes
            .chunks_exact(std::mem::size_of::<InputEvent>())
            .map(|ev| {
                let n = |at: usize| u16::from_ne_bytes([ev[at], ev[at + 1]]);
                (
                    n(16),
                    n(18),
                    i32::from_ne_bytes([ev[20], ev[21], ev[22], ev[23]]),
                )
            })
            .collect()
    }

    /// Inject into an injector with a relative pointer, both over plain files;
    /// returns what (the tablet, the relative pointer) received.
    fn written_rel(msgs: Vec<InputMsg>, auto_system: bool) -> (Events, Events) {
        let tablet = tempfile::tempfile().expect("a temp file");
        let rel = tempfile::tempfile().expect("a temp file");
        let mut inj = UinputInjector::over(tablet.try_clone().expect("clone"))
            .with_rel(rel.try_clone().expect("clone"));
        inj.auto_system = auto_system;
        for msg in msgs {
            inj.inject(msg).expect("inject");
        }
        drop(inj);
        (read_back(tablet), read_back(rel))
    }

    /// FR-109 P2b — relative motion goes to the relative pointer as `REL_X` /
    /// `REL_Y` and one SYN per frame; a zero axis is left out and an all-zero
    /// frame writes nothing.
    #[test]
    fn relative_motion_goes_to_the_relative_pointer() {
        let (tablet, rel) = written_rel(
            vec![
                InputMsg::MouseRel { dx: 100, dy: -5 },
                InputMsg::MouseRel { dx: 0, dy: 3 },
                InputMsg::MouseRel { dx: 0, dy: 0 },
            ],
            false,
        );
        assert_eq!(tablet, []);
        assert_eq!(
            rel,
            [
                (EV_REL, REL_X, 100),
                (EV_REL, REL_Y, -5),
                (EV_SYN, SYN_REPORT, 0),
                (EV_REL, REL_Y, 3),
                (EV_SYN, SYN_REPORT, 0),
            ]
        );
    }

    /// FR-95 P2's rule holds for relative motion too: the automatic system
    /// capture's injector drops it while nobody's session is on screen.
    #[test]
    fn the_automatic_injector_drops_relative_motion_off_screen() {
        let (tablet, rel) = written_rel(vec![InputMsg::MouseRel { dx: 100, dy: 0 }], true);
        assert_eq!(tablet, []);
        assert_eq!(rel, []);
    }

    /// The control: a viewer's own button-up still positions first, in the
    /// same report — so the decoding above can see a move when there is one.
    #[test]
    fn a_button_up_from_a_viewer_still_lands_where_it_points() {
        let half = (0.5 * ABS_MAX as f32).round() as i32;
        assert_eq!(
            written(InputMsg::MouseButton {
                btn: Button::Left,
                down: false,
                x: 0.5,
                y: 0.5,
                mon: 0,
            }),
            [
                (EV_ABS, ABS_X, half),
                (EV_ABS, ABS_Y, half),
                (EV_KEY, BTN_LEFT, 0),
                (EV_SYN, SYN_REPORT, 0),
            ]
        );
    }

    const SYN: (u16, u16, i32) = (EV_SYN, SYN_REPORT, 0);
    /// `KEY_A` — what `Layout::Us` strokes for both "a" and "A".
    const KEY_A: u16 = 30;

    /// FR-93 P4c — KWin gives every key in a report the modifiers that
    /// report ENDS with, so shift goes in reports of its own: pressed before
    /// the key, released after it. One report for all three typed "a".
    #[test]
    fn a_shifted_character_keeps_shift_in_reports_of_its_own() {
        assert_eq!(
            written_seq(vec![InputMsg::KeyText { text: "A".into() }]),
            [
                (EV_KEY, KEY_LEFTSHIFT, 1),
                SYN,
                (EV_KEY, KEY_A, 1),
                (EV_KEY, KEY_A, 0),
                SYN,
                (EV_KEY, KEY_LEFTSHIFT, 0),
                SYN,
            ]
        );
    }

    /// FR-97 P3f — AltGr goes in reports of its own around the key, as shift
    /// does, and outside it. On a German keymap `@` is AltGr+Q, `z` the key a
    /// US board calls Y, and `Ä` shift with no AltGr.
    #[test]
    fn a_level3_character_keeps_altgr_in_reports_of_its_own() {
        let keys: Vec<u16> = KEYMAP.iter().map(|&(_, k)| k).collect();
        let de = match crate::input::keylayout::xkb::XkbText::compile("de", "", &keys) {
            Ok(t) => crate::input::keylayout::TextKeys::Xkb(t),
            Err(e) => {
                assert!(
                    std::env::var("ROOMLERD_TEST_XKB").as_deref() != Ok("1"),
                    "ROOMLERD_TEST_XKB=1 but: {e}"
                );
                eprintln!("skipping: {e}");
                return;
            }
        };
        const KEY_Q: u16 = 16;
        const KEY_Y: u16 = 21;
        const KEY_APOSTROPHE: u16 = 40;
        assert_eq!(
            written_with(
                de,
                vec![InputMsg::KeyText {
                    text: "@zÄ".into()
                }]
            ),
            [
                (EV_KEY, KEY_RIGHTALT, 1),
                SYN,
                (EV_KEY, KEY_Q, 1),
                (EV_KEY, KEY_Q, 0),
                SYN,
                (EV_KEY, KEY_RIGHTALT, 0),
                SYN,
                (EV_KEY, KEY_Y, 1),
                (EV_KEY, KEY_Y, 0),
                SYN,
                (EV_KEY, KEY_LEFTSHIFT, 1),
                SYN,
                (EV_KEY, KEY_APOSTROPHE, 1),
                (EV_KEY, KEY_APOSTROPHE, 0),
                SYN,
                (EV_KEY, KEY_LEFTSHIFT, 0),
                SYN,
            ]
        );
    }

    /// What a desktop browser sends for Shift+A: the shift as a `Key`, then
    /// the letter as KeyText. The viewer's shift is theirs — not pressed
    /// again, not let go of — so no left shift appears at all.
    #[test]
    fn a_shift_the_viewer_holds_is_left_alone() {
        let right_shift = |down| InputMsg::Key {
            code: 0xe5,
            down,
            mods: 0,
        };
        assert_eq!(
            written_seq(vec![
                right_shift(true),
                InputMsg::KeyText { text: "A".into() },
                right_shift(false),
            ]),
            [
                (EV_KEY, KEY_RIGHTSHIFT, 1),
                SYN,
                (EV_KEY, KEY_A, 1),
                (EV_KEY, KEY_A, 0),
                SYN,
                (EV_KEY, KEY_RIGHTSHIFT, 0),
                SYN,
            ]
        );
    }

    /// The control: an unshifted character is still one report.
    #[test]
    fn an_unshifted_character_is_one_report() {
        assert_eq!(
            written_seq(vec![InputMsg::KeyText { text: "a".into() }]),
            [(EV_KEY, KEY_A, 1), (EV_KEY, KEY_A, 0), SYN]
        );
    }
}
