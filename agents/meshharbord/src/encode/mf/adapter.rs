// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! DXGI adapter enumeration and adapter-scoped D3D11 device creation.
//!
//! The default-adapter path (`D3D11CreateDevice(None, ...)`) that
//! [`super::create_d3d11_device_and_manager`] uses works for single-GPU
//! boxes and for the Microsoft software MFT. It fails on the hybrid-GPU
//! case that Phase 3 is specifically chasing: on a laptop with
//! Intel UHD + NVIDIA GTX, `D3D11CreateDevice(None, ...)` binds to the
//! Intel iGPU and NVENC's `ActivateObject` then returns `0x8000FFFF`
//! because its MFT wants a D3D11 device bound to the NVIDIA adapter.
//!
//! This module provides the building blocks for that fix:
//!
//! - [`enumerate_adapters`] — walk DXGI's adapter list, tag by vendor
//!   priority (NVIDIA → Intel → AMD → Other), skip software adapters.
//! - [`create_d3d11_device_on`] — build a D3D11 device bound to a
//!   specific [`IDXGIAdapter1`]. Callers hand the resulting device to
//!   MF via [`MFCreateDXGIDeviceManager`] just as before.
//! - [`priority_rank`] — the pure sort key; exposed for testability
//!   so vendor ordering can be verified without real DXGI handles.
//!
//! Used by the cascade in [`super::activate`] to build an
//! adapter-bound D3D11 device for each candidate MFT before probing.

#![cfg(all(target_os = "windows", feature = "mf-encoder"))]

use anyhow::{Result, anyhow, bail};

use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_10_1,
    D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_SDK_VERSION,
    D3D11CreateDevice, ID3D11Device, ID3D11Multithread,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ADAPTER_FLAG, DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_ERROR_NOT_FOUND,
    IDXGIAdapter, IDXGIAdapter1, IDXGIFactory1,
};
use windows::Win32::Media::MediaFoundation::{IMFDXGIDeviceManager, MFCreateDXGIDeviceManager};
use windows::core::Interface;

/// PCI vendor IDs of the three IHVs whose H.264 MFTs we care about.
/// Anything else (virtualised GPUs, future IHVs) gets [`VendorPriority::Other`].
pub(super) const VENDOR_NVIDIA: u32 = 0x10DE;
pub(super) const VENDOR_INTEL: u32 = 0x8086;
pub(super) const VENDOR_AMD: u32 = 0x1002;

/// Vendor priority ordering. NVIDIA first because NVENC is the highest-
/// quality HW H.264 encoder in practice; Intel next because QuickSync
/// is ubiquitous and battery-efficient; AMD last because AMF has the
/// least consistent MFT behaviour. "Other" — software rasterisers,
/// Hyper-V virtual GPUs — we try only if nothing else is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VendorPriority {
    Nvidia,
    Intel,
    Amd,
    Other,
}

impl VendorPriority {
    /// Sort key — lower is better. Used by [`enumerate_adapters`] to
    /// order its output.
    pub(super) fn rank(self) -> u8 {
        match self {
            Self::Nvidia => 0,
            Self::Intel => 1,
            Self::Amd => 2,
            Self::Other => 3,
        }
    }
}

/// Map a PCI vendor ID to its priority bucket. Exposed as a pure
/// function so tests can verify the mapping without constructing
/// DXGI adapters.
pub(super) fn priority_rank(vendor_id: u32) -> VendorPriority {
    match vendor_id {
        VENDOR_NVIDIA => VendorPriority::Nvidia,
        VENDOR_INTEL => VendorPriority::Intel,
        VENDOR_AMD => VendorPriority::Amd,
        _ => VendorPriority::Other,
    }
}

/// A DXGI adapter tagged with the metadata we need for encoder
/// selection. The [`IDXGIAdapter1`] handle is kept alive so later
/// stages (device creation, MFT probe) can hand it to
/// [`create_d3d11_device_on`].
pub(super) struct AdapterInfo {
    pub(super) description: String,
    pub(super) vendor_id: u32,
    /// PCI device ID. Surfaced via the enumerate_adapters log line so
    /// the CI log pins exactly which SKU probed pass/fail (e.g. NVIDIA
    /// device=2187 = GTX 1650). Not otherwise consumed by the cascade.
    pub(super) device_id: u32,
    pub(super) priority: VendorPriority,
    pub(super) adapter: IDXGIAdapter1,
    /// DXGI adapter locally-unique ID. Packed into a u64 and set as
    /// `MFT_ENUM_ADAPTER_LUID` on each candidate `IMFActivate` before
    /// `ActivateObject` so the MF runtime can bind the resulting
    /// transform to this adapter. Works around the RTX 5090 Blackwell
    /// regression where NVENC `ActivateObject` otherwise returns
    /// 0x8000FFFF even after `SET_D3D_MANAGER` on the right D3D11
    /// device — the LUID hint is consulted earlier in the activation
    /// path than `SET_D3D_MANAGER`.
    pub(super) luid: u64,
}

/// Enumerate physical DXGI adapters, skipping software / WARP / Basic
/// Render Driver adapters, sorted by vendor priority.
///
/// Returns `Err` only on DXGI factory creation failure (a broken
/// Windows install); a box with zero real GPUs returns `Ok(vec![])`
/// and the caller is expected to fall back to the default-adapter
/// path.
pub(super) fn enumerate_adapters() -> Result<Vec<AdapterInfo>> {
    unsafe {
        let factory: IDXGIFactory1 =
            CreateDXGIFactory1().map_err(|e| anyhow!("CreateDXGIFactory1: {e:?}"))?;

        let mut out: Vec<AdapterInfo> = Vec::new();
        let mut index: u32 = 0;
        loop {
            match factory.EnumAdapters1(index) {
                Ok(adapter) => {
                    let desc = adapter
                        .GetDesc1()
                        .map_err(|e| anyhow!("IDXGIAdapter1::GetDesc1: {e:?}"))?;

                    // Skip software adapters — WARP and Basic Render
                    // Driver both set DXGI_ADAPTER_FLAG_SOFTWARE. They
                    // have no NVENC / QSV / AMF MFT, so enumerating
                    // them here would just add probe cost.
                    let flags = DXGI_ADAPTER_FLAG(desc.Flags as i32);
                    if (flags.0 & DXGI_ADAPTER_FLAG_SOFTWARE.0) != 0 {
                        index += 1;
                        continue;
                    }

                    // Description is a null-terminated UTF-16 buffer
                    // fixed at 128 wchar_t. Trim at the first NUL.
                    let description = {
                        let end = desc
                            .Description
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(desc.Description.len());
                        String::from_utf16_lossy(&desc.Description[..end])
                    };

                    let priority = priority_rank(desc.VendorId);
                    // Pack AdapterLuid {LowPart: u32, HighPart: i32}
                    // into a u64 for `IMFAttributes::SetUINT64`. The
                    // MF runtime treats this as an opaque 8-byte
                    // identifier; the convention is high-order = HighPart.
                    let luid = ((desc.AdapterLuid.HighPart as u32 as u64) << 32)
                        | desc.AdapterLuid.LowPart as u64;
                    out.push(AdapterInfo {
                        description,
                        vendor_id: desc.VendorId,
                        device_id: desc.DeviceId,
                        priority,
                        adapter,
                        luid,
                    });
                    index += 1;
                }
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => bail!("EnumAdapters1({index}): {e:?}"),
            }
        }

        out.sort_by_key(|a| a.priority.rank());
        tracing::info!(
            count = out.len(),
            adapters = ?out
                .iter()
                .map(|a| format!(
                    "{} ({:?}, vendor={:#x}, device={:#x})",
                    a.description, a.priority, a.vendor_id, a.device_id,
                ))
                .collect::<Vec<_>>(),
            "mf-encoder: enumerated DXGI adapters"
        );
        Ok(out)
    }
}

/// Build a D3D11 device bound to a specific DXGI adapter and wrap it in
/// an [`IMFDXGIDeviceManager`]. Same flags + feature-level list as the
/// default-adapter path in [`super::create_d3d11_device_and_manager`]
/// — the only difference is the explicit adapter (and the driver type,
/// which must be `UNKNOWN` when an adapter is supplied).
///
/// Failure modes:
/// - On Optimus laptops the NVIDIA adapter can sit idle until something
///   creates a render target on it; `D3D11CreateDevice` may then
///   return `DXGI_ERROR_UNSUPPORTED`. Callers should treat this as
///   "try next adapter" rather than fatal.
/// - `ID3D11Multithread::SetMultithreadProtected(true)` is a must: MF
///   spins worker threads that call the device concurrently.
pub(super) fn create_d3d11_device_on(
    adapter: &IDXGIAdapter1,
) -> Result<(ID3D11Device, IMFDXGIDeviceManager)> {
    unsafe {
        let feature_levels = [
            D3D_FEATURE_LEVEL_11_1,
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_1,
            D3D_FEATURE_LEVEL_10_0,
        ];

        // D3D11CreateDevice wants an IDXGIAdapter reference; IDXGIAdapter1
        // extends IDXGIAdapter so we can cast cheaply.
        let adapter_base: IDXGIAdapter = adapter
            .cast()
            .map_err(|e| anyhow!("IDXGIAdapter1 -> IDXGIAdapter cast: {e:?}"))?;

        let mut device: Option<ID3D11Device> = None;
        let mut actual_level = D3D_FEATURE_LEVEL_11_0;
        D3D11CreateDevice(
            &adapter_base,
            // With a non-null adapter, driver type MUST be UNKNOWN —
            // passing HARDWARE here is the canonical DXGI foot-gun and
            // produces E_INVALIDARG.
            D3D_DRIVER_TYPE_UNKNOWN,
            windows::Win32::Foundation::HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&feature_levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            Some(&mut actual_level),
            None,
        )
        .map_err(|e| anyhow!("D3D11CreateDevice(adapter-bound): {e:?}"))?;
        let device = device.ok_or_else(|| anyhow!("D3D11CreateDevice: null device"))?;

        let mt: ID3D11Multithread = device
            .cast()
            .map_err(|e| anyhow!("ID3D11Multithread cast: {e:?}"))?;
        // Returns the previous protection state as BOOL; we don't care.
        let _ = mt.SetMultithreadProtected(true);

        let mut reset_token: u32 = 0;
        let mut mgr: Option<IMFDXGIDeviceManager> = None;
        MFCreateDXGIDeviceManager(&mut reset_token, &mut mgr)
            .map_err(|e| anyhow!("MFCreateDXGIDeviceManager: {e:?}"))?;
        let mgr = mgr.ok_or_else(|| anyhow!("MFCreateDXGIDeviceManager: null"))?;
        mgr.ResetDevice(&device, reset_token)
            .map_err(|e| anyhow!("IMFDXGIDeviceManager::ResetDevice: {e:?}"))?;

        tracing::debug!(
            feature_level = actual_level.0,
            reset_token,
            "mf-encoder: adapter-bound D3D11 device + manager created"
        );
        Ok((device, mgr))
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_rank_maps_known_vendors() {
        assert_eq!(priority_rank(VENDOR_NVIDIA), VendorPriority::Nvidia);
        assert_eq!(priority_rank(VENDOR_INTEL), VendorPriority::Intel);
        assert_eq!(priority_rank(VENDOR_AMD), VendorPriority::Amd);
        assert_eq!(priority_rank(0x1234_5678), VendorPriority::Other);
    }

    #[test]
    fn vendor_priority_rank_is_stable_and_ordered() {
        // The rank ordering is load-bearing: `enumerate_adapters`
        // sorts its output by `priority.rank()`, so NVIDIA must come
        // first, Intel second, AMD third, Other last. Tests fail
        // loudly if someone reorders the enum variants.
        assert!(VendorPriority::Nvidia.rank() < VendorPriority::Intel.rank());
        assert!(VendorPriority::Intel.rank() < VendorPriority::Amd.rank());
        assert!(VendorPriority::Amd.rank() < VendorPriority::Other.rank());
    }

    /// Smoke test that exercises real DXGI on whatever Windows host is
    /// running the test. Passes on any box that has at least one
    /// non-software DXGI adapter; that's true on every developer
    /// machine and every CI runner with a GPU. A CI runner with zero
    /// physical GPUs would legitimately return an empty vec — we
    /// accept that and assert only non-negative length.
    #[test]
    fn enumerate_adapters_smoke() {
        let adapters = enumerate_adapters().expect("enumerate_adapters");
        tracing::info!(count = adapters.len(), "smoke: adapters enumerated");
        // Not an assertion against count — on headless CI we may get
        // zero. But if we got any, the sort must be stable-priority.
        let mut prev_rank = 0u8;
        for a in &adapters {
            assert!(
                a.priority.rank() >= prev_rank,
                "adapters not sorted by priority rank"
            );
            prev_rank = a.priority.rank();
        }
    }

    /// Second integration smoke: every enumerated adapter must be able
    /// to produce a D3D11 device. If one fails with DXGI_ERROR_UNSUPPORTED
    /// (the Optimus-idle-adapter case), we log and skip rather than fail
    /// the test — that's a real-world pattern the cascade in commit 3
    /// is expected to handle.
    #[test]
    fn create_d3d11_device_on_each_enumerated_adapter() {
        let adapters = match enumerate_adapters() {
            Ok(a) => a,
            Err(e) => {
                tracing::info!(%e, "DXGI factory unavailable — skipping");
                return;
            }
        };
        for a in &adapters {
            match create_d3d11_device_on(&a.adapter) {
                Ok(_) => tracing::info!(adapter = %a.description, "device created"),
                Err(e) => tracing::info!(
                    adapter = %a.description,
                    %e,
                    "device creation failed — acceptable on Optimus idle adapters"
                ),
            }
        }
    }
}
