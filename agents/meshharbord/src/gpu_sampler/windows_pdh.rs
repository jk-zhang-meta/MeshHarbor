// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows PDH per-process GPU dedicated-VRAM fallback (FR-139 §3).
//!
//! Under WDDM, NVML often returns `NVML_VALUE_NOT_AVAILABLE` for per-process
//! VRAM. Dynamically loads `pdh.dll` inside `gpu-sampler` and queries
//! `\GPU Process Memory(*)\Dedicated Usage`, parsing `pid_<N>_luid_...`
//! instance names into `pid -> MiB`. Best-effort: returns an empty map if PDH
//! counters are disabled or unavailable.

#[cfg(windows)]
use std::collections::HashMap;

/// Parse a PDH GPU Process Memory instance name (`pid_1234_luid_0x0_...`) into its PID.
pub fn parse_pdh_gpu_instance_pid(instance: &str) -> Option<u32> {
    let rest = instance.strip_prefix("pid_")?;
    let digits = rest.split('_').next()?;
    digits.parse::<u32>().ok()
}

/// Query `\GPU Process Memory(*)\Dedicated Usage` via dynamically loaded `pdh.dll`.
#[cfg(windows)]
pub fn sample_process_vram_mb() -> HashMap<u32, u32> {
    use std::ffi::{c_void, OsStr};
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
    let Ok(lib) = (unsafe { libloading::Library::new("pdh.dll") }) else {
        return out;
    };
    let (open_q, add_c, collect, get_arr, close_q) = unsafe {
        let Ok(open_q) = lib.get::<FnOpenQuery>(b"PdhOpenQueryW\0") else {
            return out;
        };
        let Ok(add_c) = lib.get::<FnAddCounter>(b"PdhAddEnglishCounterW\0") else {
            return out;
        };
        let Ok(collect) = lib.get::<FnCollect>(b"PdhCollectQueryData\0") else {
            return out;
        };
        let Ok(get_arr) = lib.get::<FnGetArray>(b"PdhGetFormattedCounterArrayW\0") else {
            return out;
        };
        let Ok(close_q) = lib.get::<FnCloseQuery>(b"PdhCloseQuery\0") else {
            return out;
        };
        (*open_q, *add_c, *collect, *get_arr, *close_q)
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
            if unsafe { get_arr(counter, PDH_FMT_LARGE, &mut buf_size, &mut item_count, items_ptr) }
                == 0
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
                    if let Some(pid) = parse_pdh_gpu_instance_pid(&name) {
                        let bytes = unsafe { item.fmt_value.val.large_value }.max(0) as u64;
                        let mb = (bytes / (1024 * 1024)) as u32;
                        if mb > 0 {
                            *out.entry(pid).or_insert(0) += mb;
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
            parse_pdh_gpu_instance_pid("pid_4812_luid_0x00000000_0x00010A4C_phys_0"),
            Some(4812)
        );
        assert_eq!(parse_pdh_gpu_instance_pid("_Total"), None);
    }
}
