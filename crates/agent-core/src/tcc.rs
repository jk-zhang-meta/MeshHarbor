// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! macOS TCC (privacy-permission) probes.
//!
//! macOS never *errors* when a permission is missing — CGDisplayStream
//! happily delivers wallpaper-only frames without Screen Recording, and
//! CGEventPost silently swallows events without Accessibility. Both read
//! as product bugs ("black screen", "input does nothing") with nothing in
//! the logs. These probes exist so the agent SAYS what the OS will not.
//!
//! The grants are keyed on the binary's code signature (an ad-hoc cdhash
//! for the unsigned builds), so a binary update can invalidate them — on
//! the next start these fire again and name the fix.

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CFTypeRef;
    fn CGPreflightScreenCaptureAccess() -> bool;
    fn CGRequestScreenCaptureAccess() -> bool;
}

// AXIsProcessTrusted returns a Carbon `Boolean` (unsigned char), not a
// C99 `_Bool` — declare it as u8, or the ABI is technically wrong.
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> u8;
    fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> u8;
    static kAXTrustedCheckOptionPrompt: CFStringRef;
}

// The prompting variant takes a CFDictionary, so we need just enough
// CoreFoundation to build a one-entry one. Deliberately not a `core-foundation`
// crate dependency: four symbols and two opaque pointers, on a platform where
// the whole capture stack is already raw FFI.
type CFTypeRef = *const std::ffi::c_void;
type CFStringRef = CFTypeRef;
type CFDictionaryRef = CFTypeRef;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: CFTypeRef;
    static kCFTypeDictionaryKeyCallBacks: std::ffi::c_void;
    static kCFTypeDictionaryValueCallBacks: std::ffi::c_void;
    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        num_values: isize,
        key_callbacks: *const std::ffi::c_void,
        value_callbacks: *const std::ffi::c_void,
    ) -> CFDictionaryRef;
    fn CFRelease(cf: CFTypeRef);
}

/// Is Screen Recording granted to this process?
pub fn screen_recording_granted() -> bool {
    unsafe { CGPreflightScreenCaptureAccess() }
}

/// Pop the one-time system prompt. Also registers the app in the Screen
/// Recording pane so the operator only has to flip a toggle instead of
/// hunting for a "+" button. Returns the current grant state — the user's
/// answer lands asynchronously, after a restart.
pub fn request_screen_recording() -> bool {
    static REQUESTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *REQUESTED.get_or_init(|| {
        tracing::info!("tcc: requesting Screen Recording once for this process");
        unsafe { CGRequestScreenCaptureAccess() }
    })
}

/// Is this process trusted for Accessibility (input injection)?
pub fn accessibility_trusted() -> bool {
    static GRANT: std::sync::Mutex<super::privacy_cache::GrantCache> =
        std::sync::Mutex::new(super::privacy_cache::GrantCache::new());
    GRANT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .query(std::time::Instant::now(), || unsafe {
            AXIsProcessTrusted() != 0
        })
}

/// Ask for Accessibility, popping the system prompt if it has not been
/// answered yet.
///
/// The counterpart to [`request_screen_recording`], and it was missing: the
/// agent probed Accessibility but never REQUESTED it, so the toggle could only
/// ever be added by hand — while the screen-capture one at least registered
/// itself in the pane. Returns the current state; like the capture prompt, the
/// operator's answer lands asynchronously and is picked up on the next start.
///
/// `kAXTrustedCheckOptionPrompt` is a CFString key, so this needs a real
/// CFDictionary rather than the bare bool the probe uses.
pub fn request_accessibility() -> bool {
    // SAFETY: all four calls are standard CF/AX entry points; the dictionary
    // is created with retained-value semantics and released on exit.
    unsafe {
        let key = kAXTrustedCheckOptionPrompt;
        if key.is_null() {
            // Framework symbol unavailable — fall back to a plain probe rather
            // than passing a NULL key into CFDictionaryCreate.
            return accessibility_trusted();
        }
        let value = kCFBooleanTrue;
        let opts = CFDictionaryCreate(
            std::ptr::null(),
            &key,
            &value,
            1,
            &kCFTypeDictionaryKeyCallBacks as *const _,
            &kCFTypeDictionaryValueCallBacks as *const _,
        );
        let trusted = AXIsProcessTrustedWithOptions(opts) != 0;
        if !opts.is_null() {
            CFRelease(opts);
        }
        trusted
    }
}

/// Open the System Settings pane for a permission, so the operator lands on
/// the exact toggle instead of being told to go find it.
///
/// The URL scheme is the documented way in; the pane anchors
/// (`Privacy_ScreenCapture`, `Privacy_Accessibility`) have been stable across
/// the System Preferences → System Settings rewrite. Best-effort: a failure
/// here is not worth failing anything else over, and the caller has already
/// printed the path in words.
pub fn open_settings_pane(anchor: &str) {
    let url = format!("x-apple.systempreferences:com.apple.preference.security?{anchor}");
    let _ = std::process::Command::new("open").arg(&url).spawn();
}

/// Settings anchor for the Screen Recording toggle.
pub const PANE_SCREEN_RECORDING: &str = "Privacy_ScreenCapture";
/// Settings anchor for the Accessibility toggle.
pub const PANE_ACCESSIBILITY: &str = "Privacy_Accessibility";

/// Is this process inside a GUI login session?
///
/// The root LaunchDaemon is not, and never can be — session 0 has no
/// WindowServer, so it cannot capture the screen or post CGEvents no matter
/// what TCC says. Reporting "permission missing" for that process invites the
/// operator to go looking for a toggle that would change nothing; the honest
/// statement is that the capability does not exist there at all.
///
/// `CGSessionCopyCurrentDictionary` returning NULL is the canonical test — it
/// asks the window server about THIS process rather than guessing from a uid,
/// which would be wrong for a root process that IS in a session (`sudo` from a
/// terminal) and for a non-root one that is not.
pub fn has_gui_session() -> bool {
    // SAFETY: the call takes no arguments and returns either NULL or a
    // retained CFDictionary, which we release.
    unsafe {
        let d = CGSessionCopyCurrentDictionary();
        if d.is_null() {
            return false;
        }
        CFRelease(d);
        true
    }
}
