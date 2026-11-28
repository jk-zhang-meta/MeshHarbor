// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows PDH per-process GPU dedicated-VRAM fallback (FR-139 §3).
//!
//! Under WDDM, NVML often returns `NVML_VALUE_NOT_AVAILABLE` for per-process
//! VRAM. Dynamically loads `pdh.dll` inside `gpu-sampler` and queries
//! `\GPU Process Memory(*)\Dedicated Usage`, parsing `pid_<N>_luid_...`
//! instance names into `pid -> MiB`. Best-effort: returns an empty map if PDH
//! counters are disabled or unavailable.

use std::collections::HashMap;

/// Parse a PDH GPU Process Memory instance name
/// (`pid_1234_luid_0x00000000_0x00010A4C_phys_0`) into `(pid, adapter_luid)`.
pub fn parse_pdh_gpu_instance(instance: &str) -> Option<(u32, String)> {
    let rest = instance.strip_prefix("pid_")?;
    let mut parts = rest.split('_');
    let pid = parts.next()?.parse::<u32>().ok()?;
    let luid = if let Some(idx) = rest.find("_luid_") {
        let after = &rest[idx + "_luid_".len()..];
        let segs: Vec<&str> = after.split('_').take(2).collect();
        if segs.len() == 2 {
            format!("{}_{}", segs[0], segs[1])
        } else {
            after.to_string()
        }
    } else {
        "unknown".to_string()
    };
    Some((pid, luid))
}

/// Parse just the PID from a PDH GPU Process Memory instance name.
pub fn parse_pdh_gpu_instance_pid(instance: &str) -> Option<u32> {
    parse_pdh_gpu_instance(instance).map(|(pid, _)| pid)
}

/// Resolve per-process dedicated VRAM from `(pid, adapter_luid) -> MiB` ONLY
/// when the attribution is unambiguous (single adapter for this PID AND the
/// PID is only seen on a single GPU). Multi-GPU processes return `None`
/// (unknown) instead of inflating per-card and per-user VRAM.
#[allow(dead_code)] // Used on Windows WDDM NVML fallback and unit tests.
pub fn lookup_unambiguous_vram_mb(
    by_pid_luid: &HashMap<(u32, String), u32>,
    pid: u32,
    pid_gpu_count: usize,
) -> Option<u32> {
    if pid_gpu_count > 1 {
        return None;
    }
    let mut found: Option<u32> = None;
    for ((p, _luid), &mb) in by_pid_luid {
        if *p == pid {
            if found.is_some() {
                // Process holds VRAM on >1 adapters -> ambiguous without LUID match.
                return None;
            }
            found = Some(mb);
        }
    }
    found
}

/// Query `\GPU Process Memory(*)\Dedicated Usage` via dynamically loaded `pdh.dll`,
/// keyed by `(pid, adapter_luid)` to avoid summing across multiple GPUs.
#[cfg(windows)]
pub fn sample_process_vram_mb() -> HashMap<(u32, String), u32> {
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;

    type PdhStatus = i32;
    type FnOpenQuery = unsafe extern "system" fn(*const u16, usize, *mut *mut c_void) -> PdhStatus;
    type FnAddCounter =
        unsafe extern "system" fn(*mut c_void, *const u16, usize, *mut *mut c_void) -> PdhStatus;
    type FnCollect = unsafe extern "system" fn(*mut c_void) -> PdhStatus;
    type FnGetArray = unsafe extern "system" fn(
        *mut c_void,
        u32,
        *mut u32,
        *mut u32,
        *mut PdhFmtCountervalueItemW,
    ) -> PdhStatus;
    type FnCloseQuery = unsafe extern "system" fn(*mut c_void) -> PdhStatus;

    #[repr(C)]
    union PdhValue {
        long_value: i32,
        double_value: f64,
        large_value: i64,
    }

    #[repr(C)]
    struct PdhFmtCountervalue {
        c_status: u32,
        val: PdhValue,
    }

    #[repr(C)]
    struct PdhFmtCountervalueItemW {
        sz_name: *mut u16,
        fmt_value: PdhFmtCountervalue,
    }

    const PDH_FMT_LARGE: u32 = 0x0000_0400;
    const PDH_MORE_DATA: PdhStatus = 0x8000_07D2u32 as i32;

    let mut out = HashMap::new();
    // Load `pdh.dll` strictly from System32 (`LOAD_LIBRARY_SEARCH_SYSTEM32`) so
    // a planted DLL in CWD/PATH can never be loaded inside a SYSTEM child.
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };
    let dll_w: Vec<u16> = "pdh.dll\0".encode_utf16().collect();
    // SAFETY: NUL-terminated UTF-16; System32-only search flag.
    let module = unsafe {
        LoadLibraryExW(
            dll_w.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return out;
    }
    struct LibGuard(windows_sys::Win32::Foundation::HMODULE);
    impl Drop for LibGuard {
        fn drop(&mut self) {
            // SAFETY: module came from LoadLibraryExW and is freed once.
            unsafe { FreeLibrary(self.0) };
        }
    }
    let _lib_guard = LibGuard(module);
    let (open_q, add_c, collect, get_arr, close_q): (
        FnOpenQuery,
        FnAddCounter,
        FnCollect,
        FnGetArray,
        FnCloseQuery,
    ) = unsafe {
        let Some(p_open) = GetProcAddress(module, c"PdhOpenQueryW".as_ptr().cast()) else {
            return out;
        };
        let Some(p_add) = GetProcAddress(module, c"PdhAddEnglishCounterW".as_ptr().cast()) else {
            return out;
        };
        let Some(p_collect) = GetProcAddress(module, c"PdhCollectQueryData".as_ptr().cast()) else {
            return out;
        };
        let Some(p_arr) = GetProcAddress(module, c"PdhGetFormattedCounterArrayW".as_ptr().cast())
        else {
            return out;
        };
        let Some(p_close) = GetProcAddress(module, c"PdhCloseQuery".as_ptr().cast()) else {
            return out;
        };
        (
            std::mem::transmute::<_, FnOpenQuery>(p_open),
            std::mem::transmute::<_, FnAddCounter>(p_add),
            std::mem::transmute::<_, FnCollect>(p_collect),
            std::mem::transmute::<_, FnGetArray>(p_arr),
            std::mem::transmute::<_, FnCloseQuery>(p_close),
        )
    };

    let mut query: *mut c_void = std::ptr::null_mut();
    if unsafe { open_q(std::ptr::null(), 0, &mut query) } != 0 || query.is_null() {
        return out;
    }

    let path: Vec<u16> = OsStr::new("\\GPU Process Memory(*)\\Dedicated Usage")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut counter: *mut c_void = std::ptr::null_mut();
    if unsafe { add_c(query, path.as_ptr(), 0, &mut counter) } == 0
        && !counter.is_null()
        && unsafe { collect(query) } == 0
    {
        let mut buf_size: u32 = 0;
        let mut item_count: u32 = 0;
        let st = unsafe {
            get_arr(
                counter,
                PDH_FMT_LARGE,
                &mut buf_size,
                &mut item_count,
                std::ptr::null_mut(),
            )
        };
        if st == PDH_MORE_DATA && buf_size > 0 && item_count > 0 {
            let mut buf = vec![0u8; buf_size as usize];
            let items_ptr = buf.as_mut_ptr() as *mut PdhFmtCountervalueItemW;
            if unsafe {
                get_arr(
                    counter,
                    PDH_FMT_LARGE,
                    &mut buf_size,
                    &mut item_count,
                    items_ptr,
                )
            } == 0
            {
                let items = unsafe { std::slice::from_raw_parts(items_ptr, item_count as usize) };
                for item in items {
                    if item.sz_name.is_null() || item.fmt_value.c_status != 0 {
                        continue;
                    }
                    let mut len = 0usize;
                    while unsafe { *item.sz_name.add(len) } != 0 && len < 256 {
                        len += 1;
                    }
                    let slice = unsafe { std::slice::from_raw_parts(item.sz_name, len) };
                    let name = String::from_utf16_lossy(slice);
                    if let Some((pid, luid)) = parse_pdh_gpu_instance(&name) {
                        let bytes = unsafe { item.fmt_value.val.large_value }.max(0) as u64;
                        let mb = (bytes / (1024 * 1024)) as u32;
                        if mb > 0 {
                            *out.entry((pid, luid)).or_insert(0) += mb;
                        }
                    }
                }
            }
        }
    }
    unsafe {
        let _ = close_q(query);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr139_pdh_instance_pid_parser() {
        assert_eq!(
            parse_pdh_gpu_instance("pid_4812_luid_0x00000000_0x00010A4C_phys_0"),
            Some((4812, "0x00000000_0x00010A4C".to_string()))
        );
        assert_eq!(
            parse_pdh_gpu_instance_pid("pid_4812_luid_0x00000000_0x00010A4C_phys_0"),
            Some(4812)
        );
        assert_eq!(parse_pdh_gpu_instance_pid("_Total"), None);

        let mut map = HashMap::new();
        map.insert((100, "0x0_0x1".to_string()), 4096);
        assert_eq!(lookup_unambiguous_vram_mb(&map, 100, 1), Some(4096));
        // Multi-GPU PID must return None (unknown) rather than double-counting.
        assert_eq!(lookup_unambiguous_vram_mb(&map, 100, 2), None);
        map.insert((100, "0x0_0x2".to_string()), 2048);
        assert_eq!(lookup_unambiguous_vram_mb(&map, 100, 1), None);
    }
}
