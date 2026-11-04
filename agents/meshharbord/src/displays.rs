// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Host display enumeration for `rc:agent.hello`.
//!
//! Reports each attached monitor's index + pixel dimensions so the
//! admin UI can show what displays are available on a controlled host
//! (multi-monitor support is plumbed through `DisplayInfo.monitor` in
//! the rest of the stack but the enumeration was stubbed as a single
//! 1920×1080 entry until this module).
//!
//! Today: backed by `scrap::Display::all()` when the `scrap-capture`
//! feature is on (cross-platform via DXGI on Windows, X11 on Linux,
//! CoreGraphics on macOS). Without the feature we return a single
//! generic entry so the wire protocol still has at least one display
//! record — matches the pre-0.1.31 behaviour.
//!
//! Limitations inherited from `scrap`:
//! - No display name (reported as `"display-N"` where N is the index).
//!   Real names would need per-OS APIs (`GetMonitorInfoW` on Windows,
//!   `CGDisplayCreateUUIDFromDisplayID` on macOS, `XRandR` output
//!   names on Linux).
//! - No DPI scale (reported as 1.0). DXGI does expose DPI via
//!   `GetDpiForMonitor` on Windows — worth adding once the admin UI
//!   uses `scale` for something other than display.
//! - Primary-monitor flag: we mark index 0 as primary. DXGI's
//!   enumeration puts the primary first by convention; on X11 the
//!   ordering is less reliable. Good enough for the UI indicator.

use meshharbor_remote_control::models::DisplayInfo;

/// Enumerate attached monitors. Always returns at least one
/// `DisplayInfo` — a `1920×1080` "primary" stub on builds without
/// `scrap-capture` or hosts where enumeration failed.
///
/// Cheap one-shot call, safe to invoke from the signaling hello
/// preamble. On Windows + DXGI the enumeration takes <5 ms; on X11
/// slightly more but still sub-frame.
pub fn enumerate() -> Vec<DisplayInfo> {
    #[cfg(feature = "scrap-capture")]
    {
        match scrap::Display::all() {
            Ok(displays) if !displays.is_empty() => {
                return displays
                    .into_iter()
                    .enumerate()
                    .map(|(i, d)| DisplayInfo {
                        index: i as u8,
                        name: format!("display-{i}"),
                        width_px: d.width() as u32,
                        height_px: d.height() as u32,
                        scale: 1.0,
                        primary: i == 0,
                    })
                    .collect();
            }
            Ok(_) => {
                // Enumeration returned zero displays — headless VM,
                // X server not yet ready, etc. Fall through to the
                // stub so the hello payload isn't empty.
                tracing::warn!("displays: scrap returned zero displays; using stub");
            }
            Err(e) => {
                tracing::warn!(%e, "displays: scrap enumeration failed; using stub");
            }
        }
    }
    vec![stub_primary()]
}

/// Single 1920×1080 "primary" entry. Used on builds compiled without
/// `scrap-capture` (signalling-only CI images) and as a safety-net
/// return value when enumeration fails on a real host.
fn stub_primary() -> DisplayInfo {
    DisplayInfo {
        index: 0,
        name: "primary".into(),
        width_px: 1920,
        height_px: 1080,
        scale: 1.0,
        primary: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_returns_at_least_one_display() {
        // The `rc:agent.hello` contract is "at least one display" —
        // an agent with zero DisplayInfo entries would fail schema
        // validation on the server side. Confirm the enumerator
        // never returns an empty Vec even on headless CI runners.
        let list = enumerate();
        assert!(!list.is_empty(), "enumerator must return ≥ 1 display");
    }

    #[test]
    fn stub_reports_primary() {
        let s = stub_primary();
        assert_eq!(s.index, 0);
        assert!(s.primary);
        assert_eq!(s.width_px, 1920);
        assert_eq!(s.height_px, 1080);
    }

    #[test]
    fn first_entry_is_marked_primary() {
        // Whether scrap ran or we fell back to the stub, the first
        // entry should always be primary — that's the convention the
        // UI reads.
        let list = enumerate();
        assert!(list[0].primary, "first display must be marked primary");
        // Additional displays must not also claim primary.
        for (i, d) in list.iter().enumerate().skip(1) {
            assert!(!d.primary, "display {i} should not be primary");
        }
    }
}
