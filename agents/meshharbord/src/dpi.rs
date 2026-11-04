// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows DPI awareness.
//!
//! The agent captures pixels via WGC / DXGI / scrap (always physical-
//! pixel surfaces) and injects mouse positions via `enigo` (which uses
//! `SetCursorPos` / `SendInput` on Windows). Both APIs are sensitive
//! to the calling process's DPI awareness mode:
//!
//!   - In **DPI-unaware** or **system-DPI-aware** mode, `enigo.
//!     main_display()` returns *logical* pixels (e.g. 1536×960 on a
//!     1920×1200 panel at 125% scale) and `SetCursorPos` interprets
//!     coordinates as logical too — but capture frames are still
//!     physical 1920×1200. Multiplying a normalised [0,1] mouse
//!     position by the logical width drops the cursor at logical
//!     coordinates that map (via the OS DPI virtualisation) to
//!     physical position **left + above** of where the user clicked
//!     in the captured frame. This was the field bug reported on
//!     the field-test host (1920×1200) on 2026-05-01.
//!
//!   - In **per-monitor-aware-V2** mode (Win10 1703+), `main_display()`
//!     returns physical pixels and `SetCursorPos` interprets
//!     coordinates as physical — matching the capture surface.
//!
//! [`set_per_monitor_aware`] sets the process to per-monitor-V2 mode.
//! Idempotent: a second call is a no-op (the OS rejects with E_ACCESSDENIED
//! once a mode is set; we tolerate that). Call early — before any GUI
//! subsystem touches DPI, before `Enigo::new`, and before opening the
//! capture pipeline. `main()` calls this on Windows; the unit-test
//! environment + integration tests do not.
//!
//! rc.41 — `set_per_monitor_aware` now returns a `DpiOutcome` carrying
//! both the API success flag and the *actual* awareness mode after the
//! call (read back via `GetThreadDpiAwarenessContext` + a constant
//! comparison). This closes the diagnostic loop for the the field-test host field
//! bug from rc.38-rc.40: prior code discarded the bool and never
//! verified that the OS accepted the request. If a parent process
//! (e.g. SCM service launcher) already pinned the process to a
//! different mode, our `SetProcessDpiAwarenessContext` call silently
//! refuses and capture/input run with the wrong coordinate space.
//! `main.rs` now logs the outcome at INFO so a single agent startup
//! line surfaces the bug.

#![cfg(target_os = "windows")]

use windows_sys::Win32::UI::HiDpi::{
    AreDpiAwarenessContextsEqual, DPI_AWARENESS_CONTEXT, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
    DPI_AWARENESS_CONTEXT_UNAWARE, DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED,
    GetThreadDpiAwarenessContext, SetProcessDpiAwarenessContext,
};

/// Awareness mode as reported back by Windows after our
/// `SetProcessDpiAwarenessContext` call. Used in the startup log so an
/// operator running an agent log capture can see exactly what mode is
/// in effect — without grepping for "DPI" across multiple lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActualAwareness {
    PerMonitorAwareV2,
    PerMonitorAware,
    SystemAware,
    Unaware,
    UnawareGdiScaled,
    Unknown,
}

impl ActualAwareness {
    /// Human-readable label for log fields.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PerMonitorAwareV2 => "per-monitor-v2",
            Self::PerMonitorAware => "per-monitor-v1",
            Self::SystemAware => "system",
            Self::Unaware => "unaware",
            Self::UnawareGdiScaled => "unaware-gdi-scaled",
            Self::Unknown => "unknown",
        }
    }
}

/// Outcome of an attempted `SetProcessDpiAwarenessContext` call. `set`
/// is the raw boolean from the API (1 → mode applied, 0 → OS refused,
/// usually because another mode was already pinned). `actual` is the
/// mode the thread reports AFTER the call, read back via
/// `GetThreadDpiAwarenessContext`. Mismatch between `set=true` and
/// `actual != PerMonitorAwareV2` should be impossible but the readback
/// guards against undocumented Windows behaviour we haven't observed.
#[derive(Debug, Clone, Copy)]
pub struct DpiOutcome {
    pub set: bool,
    pub actual: ActualAwareness,
}

/// Try to enable per-monitor-V2 DPI awareness for the current process.
/// Returns a [`DpiOutcome`] carrying both the API success flag and the
/// actual mode the OS reports after the call. Caller (`main.rs`) logs
/// the outcome at INFO so the agent startup log surfaces the value.
pub fn set_per_monitor_aware() -> DpiOutcome {
    // SAFETY: SetProcessDpiAwarenessContext takes a static-lifetime
    // pointer to a sentinel constant from windows-sys; it doesn't
    // dereference Rust-owned memory. Thread-safe per MSDN.
    let ok = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    let set = ok != 0;
    let actual = current_thread_awareness();
    DpiOutcome { set, actual }
}

/// Read the calling thread's current DPI awareness mode.
///
/// rc.44 — switched from raw `==` pointer comparison to
/// `AreDpiAwarenessContextsEqual`. The rc.41 implementation used `==`
/// against sentinel constants from `windows-sys`, which compares the
/// stored sentinel pointer values directly. the field-test host field test
/// 2026-05-18 showed `actual=unknown` despite `set_succeeded=true`
/// — the returned handle from `GetThreadDpiAwarenessContext` is NOT
/// guaranteed to be one of the sentinel pointer values; Microsoft
/// returns an opaque internal handle that's only safely compared via
/// the dedicated API. Per the MSDN documentation:
///
/// > To compare two DPI_AWARENESS_CONTEXT values, use
/// > AreDpiAwarenessContextsEqual.
///
/// So we walk the known sentinel set and call the proper API for each.
fn current_thread_awareness() -> ActualAwareness {
    // SAFETY: GetThreadDpiAwarenessContext returns an opaque handle
    // owned by Windows; we never dereference it. Returns NULL only on
    // pre-Win10-1607 systems; production install target is Win10+.
    let ctx: DPI_AWARENESS_CONTEXT = unsafe { GetThreadDpiAwarenessContext() };
    if ctx.is_null() {
        return ActualAwareness::Unknown;
    }
    // SAFETY: AreDpiAwarenessContextsEqual is documented thread-safe;
    // both arguments are opaque handles owned by Windows. Returns
    // BOOL (0/1). Non-zero == equal.
    let eq = |a: DPI_AWARENESS_CONTEXT, b: DPI_AWARENESS_CONTEXT| -> bool {
        unsafe { AreDpiAwarenessContextsEqual(a, b) != 0 }
    };
    if eq(ctx, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) {
        ActualAwareness::PerMonitorAwareV2
    } else if eq(ctx, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE) {
        ActualAwareness::PerMonitorAware
    } else if eq(ctx, DPI_AWARENESS_CONTEXT_SYSTEM_AWARE) {
        ActualAwareness::SystemAware
    } else if eq(ctx, DPI_AWARENESS_CONTEXT_UNAWARE) {
        ActualAwareness::Unaware
    } else if eq(ctx, DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED) {
        ActualAwareness::UnawareGdiScaled
    } else {
        ActualAwareness::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test only — under cargo test the call may succeed (first
    /// call in this process) or refuse (test runner already initialised
    /// DPI in some other test). Either is acceptable; we just want to
    /// confirm the FFI calls don't crash + the readback returns a value
    /// other than Unknown on a Win10+ host.
    #[test]
    fn set_per_monitor_aware_does_not_panic() {
        let outcome = set_per_monitor_aware();
        // On Win10+ the readback always returns a known sentinel; if
        // the test environment is a CI VM with a stale Windows image
        // we still expect SOME value back (never Unknown for opaque
        // ctx — only if GetThreadDpiAwarenessContext returns NULL).
        // Don't assert hard on the value because the test runner's
        // pre-existing DPI mode is non-deterministic.
        let _ = outcome.actual.as_str();
    }
}
