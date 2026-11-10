// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P0d — the machine's native CPU architecture, for the hello.
//!
//! The hardware, not this binary: an x86_64 build under Rosetta 2 on Apple
//! silicon, or under emulation on Windows on Arm, reports `aarch64` and says
//! it is emulated. The server counts the fleet's capability words by OS and by
//! this (`scripts/fr97-caps-census.sh`), so a claim can be judged against the
//! machines that make it.

/// Rust's `target_arch` spelling for a machine name as an OS reports it
/// (`uname -m`, a Windows machine type), or `None` for one we do not know.
pub(crate) fn canonical(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" | "x64" => Some("x86_64"),
        "aarch64" | "arm64" | "arm64e" => Some("aarch64"),
        "x86" | "i386" | "i486" | "i586" | "i686" => Some("x86"),
        "arm" | "armv6l" | "armv7l" | "armv7" | "armhf" => Some("arm"),
        _ => None,
    }
}

/// `(the machine's native architecture, this process runs under emulation)`.
/// Falls back to this build's own architecture where the OS says nothing.
pub(crate) fn native() -> (String, bool) {
    let ours = canonical(std::env::consts::ARCH).unwrap_or(std::env::consts::ARCH);
    let native = os_native().unwrap_or_else(|| ours.to_string());
    let emulated = native != ours;
    (native, emulated)
}

#[cfg(target_os = "linux")]
fn os_native() -> Option<String> {
    // SAFETY: `utsname` is plain data, zeroed here and filled by `uname`.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return None;
    }
    // SAFETY: `uname` NUL-terminates `machine` within its buffer.
    let m = unsafe { std::ffi::CStr::from_ptr(u.machine.as_ptr()) }.to_string_lossy();
    canonical(&m).map(str::to_string)
}

#[cfg(target_os = "macos")]
fn os_native() -> Option<String> {
    // `sysctl.proc_translated` is 1 for a process under Rosetta 2 and 0 for a
    // native one; an Intel Mac has no such key. Only Apple silicon translates,
    // so a translated process sits on `aarch64`, and an untranslated one on
    // the architecture it was built for.
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: a fixed C-string name, an int out-param with its size, no new value.
    let rc = unsafe {
        libc::sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && v == 1).then(|| "aarch64".to_string())
}

#[cfg(windows)]
fn os_native() -> Option<String> {
    use windows_sys::Win32::Foundation::{BOOL, HANDLE};
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows_sys::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT,
        IMAGE_FILE_MACHINE_I386,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // Looked up at run time, not imported: kernel32 exports it only since
    // Windows 10 1511, and a static import of a missing export stops the whole
    // daemon from loading. Without it, the build's own architecture stands.
    type IsWow64Process2 = unsafe extern "system" fn(HANDLE, *mut u16, *mut u16) -> BOOL;
    let kernel32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    // SAFETY: a NUL-terminated module name; kernel32 is loaded in every process.
    let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
    if module.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated export name.
    let found = unsafe { GetProcAddress(module, c"IsWow64Process2".as_ptr().cast()) }?;
    // SAFETY: the export's documented signature.
    let is_wow64_process2 = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, IsWow64Process2>(found)
    };
    let (mut process, mut machine) = (0u16, 0u16);
    // SAFETY: the current-process pseudo-handle needs no close; both
    // out-params are plain `u16`s the call fills.
    if unsafe { is_wow64_process2(GetCurrentProcess(), &mut process, &mut machine) } == 0 {
        return None;
    }
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => Some("x86_64"),
        IMAGE_FILE_MACHINE_ARM64 => Some("aarch64"),
        IMAGE_FILE_MACHINE_I386 => Some("x86"),
        IMAGE_FILE_MACHINE_ARMNT => Some("arm"),
        _ => None,
    }
    .map(str::to_string)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn os_native() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_names_read_as_target_arch() {
        for (raw, want) in [
            ("x86_64", "x86_64"),
            ("AMD64", "x86_64"),
            ("aarch64", "aarch64"),
            ("arm64", "aarch64"),
            ("i686", "x86"),
            ("armv7l", "arm"),
            (" aarch64\n", "aarch64"),
        ] {
            assert_eq!(canonical(raw), Some(want), "{raw:?}");
        }
        for unknown in ["riscv64", "s390x", ""] {
            assert_eq!(canonical(unknown), None, "{unknown:?}");
        }
    }

    /// The test host reports a known architecture, and a build for the
    /// runner's own architecture is not emulated there.
    #[test]
    fn this_machine_reports_its_architecture() {
        let (native, emulated) = native();
        assert!(
            canonical(&native).is_some() || native == std::env::consts::ARCH,
            "{native}"
        );
        if emulated {
            assert_ne!(Some(native.as_str()), canonical(std::env::consts::ARCH));
        }
    }
}
