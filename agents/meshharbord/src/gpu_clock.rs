// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Session-scoped NVIDIA GPU clock pin (NVML) — kills the idle-P-state
//! encode-latency ramp on NVENC senders.
//!
//! Field story (DEVBOX, RTX 5090): an idle desktop lets the GPU drop into a
//! low P-state; the first seconds of a remote-desktop session encode at
//! ~20 ms/frame until the clocks ramp, and light-motion sessions can bounce
//! in and out of the slow state indefinitely. A manual `nvidia-smi -lgc`
//! (lock graphics clocks) was field-validated to fix it — this module is
//! that lever, applied automatically for exactly the lifetime of remote
//! sessions. (Parsec's "boost" service does the same thing.)
//!
//! Design constraints:
//!
//! * **Default OFF** (`ROOMLERD_GPU_CLOCK_PIN` unset/`0`). Locking
//!   clocks raises idle power/heat while engaged — strictly an opt-in until
//!   field hours accumulate. `1`/`true` = auto (pin graphics clocks to
//!   [70% of max, max] on every NVIDIA device); `"<min>,<max>"` = explicit
//!   MHz band.
//! * **No separate privileged service.** Setting locked clocks needs admin
//!   root — which the perMachine SCM / SystemContext installs already have
//!   (the daemon runs as SYSTEM). Per-user installs get
//!   `NVML_ERROR_NO_PERMISSION` and log a hint instead of failing.
//! * **NVML is dlopen'd** (`nvml.dll` / `libnvidia-ml.so.1`), never linked:
//!   non-NVIDIA hosts and CI pay nothing, no build-time dependency on the
//!   CUDA stack.
//! * **Never leave clocks pinned.** The pin is engaged while ≥1
//!   remote-desktop session is live and dropped (clocks reset) when the
//!   last session ends or the signaling loop rebuilds its session map; a
//!   boot-time [`reset_stale_pins`] sweep heals the pins of a crashed
//!   predecessor (Drop never ran).
//!
//! Pure parse + counting logic is unit-tested on the default build; the FFI
//! paths are field-gated (CI has no NVIDIA device).

use std::ffi::{c_char, c_uint, c_void};
use std::sync::Mutex;

use libloading::Library;
use tunnel_core::env::node_env;

const NVML_SUCCESS: i32 = 0;
const NVML_ERROR_NO_PERMISSION: i32 = 4;
/// `nvmlClockType_t::NVML_CLOCK_GRAPHICS` — the clock domain `-lgc` locks
/// (the video/NVENC clock follows it on shipping SKUs).
const NVML_CLOCK_GRAPHICS: c_uint = 0;
/// `NVML_DEVICE_NAME_V2_BUFFER_SIZE`.
const NAME_BUF: usize = 96;

/// Parsed `ROOMLERD_GPU_CLOCK_PIN` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// Unset / `0` / `false` / unparsable — feature disabled (default).
    Off,
    /// `1` / `true` — pin to [70% of max graphics clock, max] per device.
    Auto,
    /// `"<min>,<max>"` MHz, validated `0 < min <= max`.
    Explicit { min_mhz: u32, max_mhz: u32 },
}

/// Pure + exported so the accepted grammar is locked by tests. Garbage
/// degrades to `Off` (never a panic, never a surprise pin).
pub fn parse_pin_mode(raw: Option<&str>) -> PinMode {
    let Some(raw) = raw else { return PinMode::Off };
    let v = raw.trim();
    match v {
        "" | "0" | "false" => PinMode::Off,
        "1" | "true" => PinMode::Auto,
        _ => {
            let Some((min, max)) = v.split_once(',') else {
                return PinMode::Off;
            };
            match (min.trim().parse::<u32>(), max.trim().parse::<u32>()) {
                (Ok(min_mhz), Ok(max_mhz)) if min_mhz > 0 && min_mhz <= max_mhz => {
                    PinMode::Explicit { min_mhz, max_mhz }
                }
                _ => PinMode::Off,
            }
        }
    }
}

/// The band to pin, given a device's max graphics clock. Auto = [70%, max]
/// — high enough to hold encode latency flat, below max to leave thermal
/// headroom. Pure for tests.
pub fn pin_band(mode: PinMode, device_max_mhz: u32) -> Option<(u32, u32)> {
    match mode {
        PinMode::Off => None,
        PinMode::Auto => {
            if device_max_mhz == 0 {
                None
            } else {
                Some((device_max_mhz * 7 / 10, device_max_mhz))
            }
        }
        PinMode::Explicit { min_mhz, max_mhz } => Some((min_mhz, max_mhz)),
    }
}

type FnInit = unsafe extern "C" fn() -> i32;
type FnShutdown = unsafe extern "C" fn() -> i32;
type FnDeviceCount = unsafe extern "C" fn(*mut c_uint) -> i32;
type FnDeviceByIndex = unsafe extern "C" fn(c_uint, *mut *mut c_void) -> i32;
type FnDeviceName = unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint) -> i32;
type FnMaxClock = unsafe extern "C" fn(*mut c_void, c_uint, *mut c_uint) -> i32;
type FnSetLocked = unsafe extern "C" fn(*mut c_void, c_uint, c_uint) -> i32;
type FnResetLocked = unsafe extern "C" fn(*mut c_void) -> i32;

/// dlopen'd NVML with the handful of symbols we use. The raw fn pointers
/// are copies out of the `Library` — the struct keeps `_lib` alive so they
/// stay valid for its lifetime.
struct Nvml {
    _lib: Library,
    init: FnInit,
    shutdown: FnShutdown,
    device_count: FnDeviceCount,
    device_by_index: FnDeviceByIndex,
    device_name: FnDeviceName,
    max_clock: FnMaxClock,
    set_locked: FnSetLocked,
    reset_locked: FnResetLocked,
}

impl Nvml {
    fn load() -> Option<Self> {
        #[cfg(windows)]
        let candidates: &[&str] = &["nvml.dll"];
        #[cfg(not(windows))]
        let candidates: &[&str] = &["libnvidia-ml.so.1", "libnvidia-ml.so"];
        let lib = candidates.iter().find_map(|name| {
            // SAFETY: loading a well-known driver library by name; no
            // initialisation routines beyond the OS loader run here.
            unsafe { Library::new(name).ok() }
        })?;
        // SAFETY: symbol names + signatures match nvml.h for every driver
        // generation that ships these entry points; copied out as plain fn
        // pointers kept valid by `_lib`.
        unsafe {
            let init = *lib.get::<FnInit>(b"nvmlInit_v2\0").ok()?;
            let shutdown = *lib.get::<FnShutdown>(b"nvmlShutdown\0").ok()?;
            let device_count = *lib.get::<FnDeviceCount>(b"nvmlDeviceGetCount_v2\0").ok()?;
            let device_by_index = *lib
                .get::<FnDeviceByIndex>(b"nvmlDeviceGetHandleByIndex_v2\0")
                .ok()?;
            let device_name = *lib.get::<FnDeviceName>(b"nvmlDeviceGetName\0").ok()?;
            let max_clock = *lib.get::<FnMaxClock>(b"nvmlDeviceGetMaxClockInfo\0").ok()?;
            let set_locked = *lib
                .get::<FnSetLocked>(b"nvmlDeviceSetGpuLockedClocks\0")
                .ok()?;
            let reset_locked = *lib
                .get::<FnResetLocked>(b"nvmlDeviceResetGpuLockedClocks\0")
                .ok()?;
            Some(Self {
                _lib: lib,
                init,
                shutdown,
                device_count,
                device_by_index,
                device_name,
                max_clock,
                set_locked,
                reset_locked,
            })
        }
    }

    fn devices(&self) -> Vec<*mut c_void> {
        let mut count: c_uint = 0;
        // SAFETY: out-pointer to a local; NVML initialised by the caller.
        if unsafe { (self.device_count)(&mut count) } != NVML_SUCCESS {
            return Vec::new();
        }
        let mut out = Vec::new();
        for i in 0..count {
            let mut handle: *mut c_void = std::ptr::null_mut();
            // SAFETY: out-pointer to a local; index bounded by the count.
            if unsafe { (self.device_by_index)(i, &mut handle) } == NVML_SUCCESS
                && !handle.is_null()
            {
                out.push(handle);
            }
        }
        out
    }

    fn name(&self, device: *mut c_void) -> String {
        let mut buf = [0i8; NAME_BUF];
        // SAFETY: buffer sized to NVML_DEVICE_NAME_V2_BUFFER_SIZE.
        if unsafe {
            (self.device_name)(device, buf.as_mut_ptr() as *mut c_char, NAME_BUF as c_uint)
        } != NVML_SUCCESS
        {
            return "unknown".into();
        }
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// RAII pin: holds NVML loaded and the set of devices whose graphics clocks
/// this process locked; `Drop` resets them and shuts NVML down.
pub struct GpuClockPin {
    nvml: Nvml,
    pinned: Vec<*mut c_void>,
}

// SAFETY: NVML is documented thread-safe and its device handles are
// process-global opaque identifiers (not memory this struct owns); the pin
// is only ever used behind the module Mutex.
unsafe impl Send for GpuClockPin {}

impl GpuClockPin {
    /// Attempt to engage the pin. `None` when the feature is off, NVML is
    /// absent (non-NVIDIA host), or no device accepted the lock (e.g. a
    /// per-user install without admin rights — logged as a hint).
    fn engage() -> Option<Self> {
        let mode = parse_pin_mode(node_env("GPU_CLOCK_PIN").as_deref());
        if mode == PinMode::Off {
            return None;
        }
        let Some(nvml) = Nvml::load() else {
            tracing::debug!("gpu-clock pin enabled but NVML is not loadable (non-NVIDIA host?)");
            return None;
        };
        // SAFETY: entry point of the loaded library; balanced by shutdown.
        let rc = unsafe { (nvml.init)() };
        if rc != NVML_SUCCESS {
            tracing::info!(rc, "gpu-clock pin: nvmlInit failed — skipped");
            return None;
        }
        let mut pinned = Vec::new();
        for device in nvml.devices() {
            let mut max: c_uint = 0;
            // SAFETY: valid device handle from devices(); out-ptr to local.
            let band = if unsafe { (nvml.max_clock)(device, NVML_CLOCK_GRAPHICS, &mut max) }
                == NVML_SUCCESS
            {
                pin_band(mode, max)
            } else {
                pin_band(mode, 0)
            };
            let Some((min_mhz, max_mhz)) = band else {
                continue;
            };
            // SAFETY: valid device handle; plain u32 args.
            let rc = unsafe { (nvml.set_locked)(device, min_mhz, max_mhz) };
            match rc {
                NVML_SUCCESS => {
                    tracing::info!(
                        device = %nvml.name(device),
                        min_mhz,
                        max_mhz,
                        "gpu-clock pin engaged (session active)"
                    );
                    pinned.push(device);
                }
                NVML_ERROR_NO_PERMISSION => {
                    tracing::info!(
                        device = %nvml.name(device),
                        "gpu-clock pin: no permission — needs the service (SYSTEM) install \
                         or admin; skipped"
                    );
                }
                _ => {
                    tracing::debug!(device = %nvml.name(device), rc, "gpu-clock pin: set failed");
                }
            }
        }
        if pinned.is_empty() {
            // SAFETY: balances the successful init above.
            unsafe { (nvml.shutdown)() };
            return None;
        }
        Some(Self { nvml, pinned })
    }
}

impl Drop for GpuClockPin {
    fn drop(&mut self) {
        for device in &self.pinned {
            // SAFETY: handles were valid at engage; reset is idempotent.
            let _ = unsafe { (self.nvml.reset_locked)(*device) };
        }
        // SAFETY: balances the successful init in engage().
        unsafe { (self.nvml.shutdown)() };
        tracing::info!(
            devices = self.pinned.len(),
            "gpu-clock pin released (last session ended)"
        );
    }
}

static PIN: Mutex<Option<GpuClockPin>> = Mutex::new(None);

/// Session-count hook for the signaling loop: call after every mutation of
/// the remote-desktop peers map. Engages the pin on 0→N, releases it (and
/// resets the clocks) at 0. Cheap when the feature is off (env parse only).
pub fn on_sessions_changed(active_sessions: usize) {
    let Ok(mut guard) = PIN.lock() else { return };
    if active_sessions > 0 {
        if guard.is_none() {
            *guard = GpuClockPin::engage();
        }
    } else {
        // Drop resets the clocks.
        *guard = None;
    }
}

/// Boot-time sweep: a crashed/killed predecessor never ran `Drop`, so its
/// locked clocks survive it. When the feature is enabled, reset the lock on
/// every device once at startup. No-op when off / NVML absent.
pub fn reset_stale_pins() {
    if parse_pin_mode(node_env("GPU_CLOCK_PIN").as_deref()) == PinMode::Off {
        return;
    }
    let Some(nvml) = Nvml::load() else { return };
    // SAFETY: entry point of the loaded library; balanced below.
    if unsafe { (nvml.init)() } != NVML_SUCCESS {
        return;
    }
    let mut reset = 0usize;
    for device in nvml.devices() {
        // SAFETY: valid handle; reset is idempotent (no-op if not locked).
        if unsafe { (nvml.reset_locked)(device) } == NVML_SUCCESS {
            reset += 1;
        }
    }
    // SAFETY: balances the init above.
    unsafe { (nvml.shutdown)() };
    if reset > 0 {
        tracing::info!(
            devices = reset,
            "gpu-clock boot sweep: cleared stale clock locks"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_the_three_forms_and_rejects_garbage() {
        assert_eq!(parse_pin_mode(None), PinMode::Off);
        assert_eq!(parse_pin_mode(Some("0")), PinMode::Off);
        assert_eq!(parse_pin_mode(Some("false")), PinMode::Off);
        assert_eq!(parse_pin_mode(Some("")), PinMode::Off);
        assert_eq!(parse_pin_mode(Some("1")), PinMode::Auto);
        assert_eq!(parse_pin_mode(Some("true")), PinMode::Auto);
        assert_eq!(
            parse_pin_mode(Some("1500,3000")),
            PinMode::Explicit {
                min_mhz: 1500,
                max_mhz: 3000
            }
        );
        assert_eq!(
            parse_pin_mode(Some(" 1500 , 3000 ")),
            PinMode::Explicit {
                min_mhz: 1500,
                max_mhz: 3000
            }
        );
        // Inverted band, zero min, non-numeric → Off, never a surprise pin.
        assert_eq!(parse_pin_mode(Some("3000,1500")), PinMode::Off);
        assert_eq!(parse_pin_mode(Some("0,3000")), PinMode::Off);
        assert_eq!(parse_pin_mode(Some("banana")), PinMode::Off);
        assert_eq!(parse_pin_mode(Some("1500")), PinMode::Off);
    }

    #[test]
    fn band_is_seventy_percent_to_max_in_auto() {
        assert_eq!(pin_band(PinMode::Auto, 3000), Some((2100, 3000)));
        assert_eq!(pin_band(PinMode::Auto, 0), None, "no max info → no pin");
        assert_eq!(
            pin_band(
                PinMode::Explicit {
                    min_mhz: 1500,
                    max_mhz: 2800
                },
                3000
            ),
            Some((1500, 2800)),
            "explicit band ignores the queried max"
        );
        assert_eq!(pin_band(PinMode::Off, 3000), None);
    }

    #[test]
    fn session_hook_is_inert_when_disabled() {
        // Env is unset in CI → engage() short-circuits at Off before any
        // FFI; the hook must be safely callable from the signaling loop
        // regardless of hardware.
        on_sessions_changed(1);
        on_sessions_changed(2);
        on_sessions_changed(0);
        assert!(PIN.lock().unwrap().is_none());
    }
}
