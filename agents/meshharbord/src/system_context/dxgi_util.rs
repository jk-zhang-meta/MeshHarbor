// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! DXGI adapter + output enumeration for the SystemContext capture path.
//!
//! Phase 0 (rc.105) — DIAGNOSTICS for the hybrid-GPU ("Optimus")
//! slow-capture bug. Field host WINHOST-B (Intel iGPU drives the display +
//! NVIDIA RTX PRO 3000 dGPU render-only; SystemContext) caps HEVC-over-DC
//! at ~12 fps because the capture grab itself takes ~85 ms/frame — the
//! signature of the GDI BitBlt fallback (capture_pump swaps DXGI→GDI
//! after repeated DXGI errors). The suspected trigger: on Optimus,
//! `scrap::Display::primary()` can bind Desktop Duplication to the
//! render-only dGPU (which owns NO output), so `DuplicateOutput` fails
//! and we fall to slow GDI.
//!
//! This module logs, at capture-worker startup, every DXGI adapter and
//! its outputs so a single `rc:logs-fetch` shows:
//!   * which adapter OWNS the primary output (its top-left is the desktop
//!     origin 0,0) — Desktop Duplication must bind to THIS adapter;
//!   * whether a render-only dGPU exposes ZERO attached outputs — the
//!     Optimus signature.
//!
//! Phase 1 will reuse the primary-output-owning adapter to bind a fresh
//! Desktop Duplication backend to the correct adapter.
//!
//! Gated on `mf-encoder` because that feature pulls in the `windows`
//! crate (the production `full-hw` build has it). A system-context build
//! without `mf-encoder` simply skips the logging.

#![cfg(all(target_os = "windows", feature = "mf-encoder"))]

use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ADAPTER_FLAG, DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_ERROR_NOT_FOUND,
    IDXGIAdapter1, IDXGIFactory1, IDXGIOutput,
};

/// Walk every DXGI adapter + output and log it at INFO. Best-effort: any
/// DXGI error is logged at WARN and enumeration stops — this is purely a
/// diagnostic and must never block capture startup.
pub fn log_adapters_and_outputs() {
    unsafe {
        let factory: IDXGIFactory1 = match CreateDXGIFactory1() {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "dxgi-util: CreateDXGIFactory1 failed — capture adapter enumeration skipped"
                );
                return;
            }
        };

        let mut primary_owner: Option<String> = None;
        let mut adapter_index: u32 = 0;
        loop {
            let adapter: IDXGIAdapter1 = match factory.EnumAdapters1(adapter_index) {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => {
                    tracing::warn!(?e, index = adapter_index, "dxgi-util: EnumAdapters1 failed");
                    break;
                }
            };
            let desc = match adapter.GetDesc1() {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(?e, index = adapter_index, "dxgi-util: GetDesc1 failed");
                    adapter_index += 1;
                    continue;
                }
            };
            let name = utf16_trim(&desc.Description);
            let vendor = format!("{:#06x}", desc.VendorId);
            let device = format!("{:#06x}", desc.DeviceId);
            let software =
                (DXGI_ADAPTER_FLAG(desc.Flags as i32).0 & DXGI_ADAPTER_FLAG_SOFTWARE.0) != 0;

            let mut outputs: Vec<String> = Vec::new();
            let mut output_index: u32 = 0;
            loop {
                let output: IDXGIOutput = match adapter.EnumOutputs(output_index) {
                    Ok(o) => o,
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(_) => break,
                };
                if let Ok(od) = output.GetDesc() {
                    let dev = utf16_trim(&od.DeviceName);
                    let r = od.DesktopCoordinates;
                    let attached = od.AttachedToDesktop.as_bool();
                    // Windows places the primary monitor's top-left at the
                    // virtual-desktop origin (0,0) by convention.
                    let is_primary = attached && r.left == 0 && r.top == 0;
                    if is_primary {
                        primary_owner = Some(name.clone());
                    }
                    outputs.push(format!(
                        "{dev} attached={attached} primary={is_primary} rect=({},{},{},{})",
                        r.left, r.top, r.right, r.bottom
                    ));
                }
                output_index += 1;
            }

            let output_count = outputs.len();
            tracing::info!(
                "dxgi-util: SystemContext capture adapter[{adapter_index}] '{name}' \
                 vendor={vendor} device={device} software={software} \
                 output_count={output_count} outputs={outputs:?}"
            );
            adapter_index += 1;
        }

        match primary_owner {
            Some(owner) => tracing::info!(
                "dxgi-util: PRIMARY output (desktop origin 0,0) is owned by adapter '{owner}' \
                 — Desktop Duplication should bind to THIS adapter (Phase 1 fix target)"
            ),
            None => tracing::warn!(
                "dxgi-util: NO adapter reported a primary output at origin (0,0) — \
                 capture adapter selection is ambiguous on this host"
            ),
        }
    }
}

/// Trim a fixed-size NUL-terminated UTF-16 buffer (DXGI descriptions /
/// device names) to a `String`.
fn utf16_trim(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
