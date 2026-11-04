// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-77 P3 — the hardware + driver fingerprint the probe cache is keyed by.
//!
//! What the encoder probe's answer depends on, and nothing else: the GPUs
//! present and the driver versions the vendor encode libraries come from
//! (NVENC, the Intel media runtime and AMF all ship INSIDE the display
//! driver), plus the OS build (Media Foundation's codec set). A change to any
//! of them re-probes; nothing else does.
//!
//! - **Windows** reads the display class in the registry — every installed
//!   display-driver instance with its `DriverDesc` / `DriverVersion` /
//!   `MatchingDeviceId` — which is exactly what a driver update rewrites,
//!   plus the OS build + UBR. No DXGI, no WMI: both spin up more machinery
//!   than the probe cache saves.
//! - **Linux** reads sysfs (`/sys/class/drm/card*`: PCI ids + kernel driver),
//!   the NVIDIA module version, the kernel release, and the identity (size +
//!   mtime) of the userspace driver libraries the FFmpeg backends dlopen.
//! - **macOS** returns `None`: the probe there is ~120 ms and VideoToolbox
//!   ships with the OS, so there is nothing worth caching and no driver
//!   identity to key on. No key ⇒ no cache, by construction.

/// One string, sorted and deterministic, that changes iff the encoder
/// hardware or its drivers did. `None` = this platform has no fingerprint
/// (the cache is then not used).
pub(crate) fn fingerprint() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        win::fingerprint()
    }
    #[cfg(target_os = "linux")]
    {
        Some(linux::fingerprint_at(std::path::Path::new("/")))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

/// FR-99 — the Windows build number (`CurrentBuildNumber`, e.g. `19041` for
/// 10 2004), read from the same key the fingerprint reads. `None` when it
/// cannot be read, which callers treat as "too old for the feature".
///
/// Gated on the overlay feature because the privacy curtain is its only
/// caller: in a Windows build without it the function is dead, and CI's
/// `-D warnings` lanes say so.
#[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
pub(crate) fn windows_build() -> Option<u32> {
    win::build_number()
}

/// The one shape both platforms produce: `platform;os=<build>;hw=<sorted parts>`.
fn compose(platform: &str, os: &str, parts: &[String]) -> String {
    format!("{platform};os={os};hw={}", parts.join(";"))
}

#[cfg(target_os = "windows")]
mod win {
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    };

    /// The display adapters class — one `NNNN` subkey per installed display
    /// driver instance, current and previous.
    const DISPLAY_CLASS: &str =
        r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
    const NT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// RAII wrapper so no HKEY leaks on an early return.
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle came from RegOpenKeyExW and is closed once.
                unsafe { RegCloseKey(self.0) };
            }
        }
    }

    fn open(parent: HKEY, path: &str) -> Option<Key> {
        let wpath = wide(path);
        let mut out: HKEY = ptr::null_mut();
        // SAFETY: `wpath` is NUL-terminated and outlives the call; `out` is a
        // valid out-pointer.
        let rc = unsafe {
            RegOpenKeyExW(
                parent,
                wpath.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut out,
            )
        };
        (rc == ERROR_SUCCESS && !out.is_null()).then_some(Key(out))
    }

    fn subkeys(key: &Key) -> Vec<String> {
        let mut names = Vec::new();
        let mut index = 0u32;
        loop {
            let mut buf = vec![0u16; 256];
            let mut len = buf.len() as u32;
            // SAFETY: the buffer is len wide chars; the remaining out-params
            // are optional and passed as null per the API contract.
            let rc = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                // ERROR_MORE_DATA on an over-long name, or a transient failure:
                // skip the entry rather than truncate the enumeration.
                index += 1;
                if index > 4096 {
                    break;
                }
                continue;
            }
            names.push(String::from_utf16_lossy(&buf[..len as usize]));
            index += 1;
        }
        names
    }

    /// Raw value bytes + type via the standard size-then-read double call.
    fn raw_value(key: &Key, name: &str) -> Option<(u32, Vec<u8>)> {
        let wname = wide(name);
        let mut len: u32 = 0;
        let mut ty: u32 = 0;
        // SAFETY: sizing call with a null data pointer, per RegQueryValueExW.
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                wname.as_ptr(),
                ptr::null_mut(),
                &mut ty,
                ptr::null_mut(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` has `len` bytes and `len` is passed back in/out.
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                wname.as_ptr(),
                ptr::null_mut(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        (rc == ERROR_SUCCESS).then_some((ty, buf))
    }

    fn string_value(key: &Key, name: &str) -> Option<String> {
        let (ty, buf) = raw_value(key, name)?;
        if ty != REG_SZ && ty != REG_EXPAND_SZ {
            return None;
        }
        let wide_chars: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        Some(String::from_utf16_lossy(&wide_chars))
    }

    fn dword_value(key: &Key, name: &str) -> Option<u32> {
        let (ty, buf) = raw_value(key, name)?;
        (ty == REG_DWORD && buf.len() >= 4)
            .then(|| u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    #[cfg(feature = "viewer-indicator")]
    pub(super) fn build_number() -> Option<u32> {
        let k = open(HKEY_LOCAL_MACHINE, NT_VERSION)?;
        string_value(&k, "CurrentBuildNumber")?.trim().parse().ok()
    }

    pub(super) fn fingerprint() -> Option<String> {
        let class = open(HKEY_LOCAL_MACHINE, DISPLAY_CLASS)?;
        let mut adapters: Vec<String> = Vec::new();
        for sub in subkeys(&class) {
            // `0000`..`NNNN` are driver instances; `Properties` and friends
            // are not.
            if sub.len() != 4 || !sub.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Some(k) = open(class.0, &sub) else {
                continue;
            };
            let desc = string_value(&k, "DriverDesc");
            let ver = string_value(&k, "DriverVersion");
            if desc.is_none() && ver.is_none() {
                continue;
            }
            adapters.push(format!(
                "{}|{}|{}",
                desc.unwrap_or_default(),
                ver.unwrap_or_default(),
                string_value(&k, "MatchingDeviceId").unwrap_or_default()
            ));
        }
        adapters.sort();
        adapters.dedup();
        let os = open(HKEY_LOCAL_MACHINE, NT_VERSION)
            .map(|k| {
                format!(
                    "{}.{}",
                    string_value(&k, "CurrentBuildNumber").unwrap_or_default(),
                    dword_value(&k, "UBR").unwrap_or(0)
                )
            })
            .unwrap_or_default();
        Some(super::compose("windows", &os, &adapters))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::time::UNIX_EPOCH;

    /// The userspace driver libraries the FFmpeg backends dlopen. Presence
    /// AND identity (size + mtime) — a package upgrade that keeps the path
    /// still changes the fingerprint. Absent files contribute nothing.
    const DRIVER_FILES: &[&str] = &[
        "usr/lib/x86_64-linux-gnu/libnvidia-encode.so.1",
        "usr/lib/x86_64-linux-gnu/libcuda.so.1",
        "usr/lib/wsl/lib/libcuda.so.1",
        "usr/lib/wsl/lib/libd3d12.so",
        "usr/lib/x86_64-linux-gnu/dri/iHD_drv_video.so",
        "usr/lib/x86_64-linux-gnu/dri/radeonsi_drv_video.so",
        "usr/lib/x86_64-linux-gnu/dri/d3d12_drv_video.so",
        "usr/lib/x86_64-linux-gnu/libmfx-gen.so.1.2",
        "usr/lib/x86_64-linux-gnu/libvpl.so.2",
        "usr/lib/x86_64-linux-gnu/libva.so.2",
        "usr/lib/x86_64-linux-gnu/libamfrt64.so.1",
        "opt/amdgpu/lib/x86_64-linux-gnu/libamfrt64.so.1",
    ];

    /// Rooted so a test can stand up a fake `/sys` + `/proc` tree.
    pub(super) fn fingerprint_at(root: &Path) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(root.join("sys/class/drm")) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                // `cardN` only: `renderDN` and the connectors (`card0-HDMI-A-1`)
                // all point at the same device.
                if !name.starts_with("card") || name.contains('-') {
                    continue;
                }
                let dev = entry.path().join("device");
                let read = |f: &str| {
                    std::fs::read_to_string(dev.join(f))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default()
                };
                let vendor = read("vendor");
                if vendor.is_empty() {
                    continue;
                }
                let driver = std::fs::read_link(dev.join("driver"))
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .unwrap_or_default();
                parts.push(format!(
                    "{vendor}:{} {}:{} rev {} {driver}",
                    read("device"),
                    read("subsystem_vendor"),
                    read("subsystem_device"),
                    read("revision")
                ));
            }
        }
        for rel in DRIVER_FILES {
            if let Ok(md) = std::fs::metadata(root.join(rel)) {
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                parts.push(format!("{rel} {} {mtime}", md.len()));
            }
        }
        parts.sort();
        parts.dedup();
        let mut os = std::fs::read_to_string(root.join("proc/sys/kernel/osrelease"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if let Ok(nv) = std::fs::read_to_string(root.join("proc/driver/nvidia/version"))
            && let Some(line) = nv.lines().next()
        {
            os.push_str(" nvidia:");
            os.push_str(line.trim());
        }
        super::compose("linux", &os, &parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_is_deterministic_and_carries_every_part() {
        let a = compose("x", "b1", &["p2".into(), "p1".into()]);
        assert_eq!(a, "x;os=b1;hw=p2;p1");
        assert_eq!(a, compose("x", "b1", &["p2".into(), "p1".into()]));
        assert_ne!(a, compose("x", "b2", &["p2".into(), "p1".into()]));
    }

    /// The real call must not panic on any platform — on macOS it is `None`
    /// by design, elsewhere it is whatever the box has.
    #[test]
    fn fingerprint_does_not_panic() {
        let fp = fingerprint();
        if cfg!(target_os = "macos") {
            assert!(fp.is_none(), "macOS has no probe cache key by design");
        } else if let Some(fp) = fp {
            assert!(fp.contains(";os="), "shape: {fp}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fingerprint_reads_sysfs_and_changes_with_the_driver() {
        let root = std::env::temp_dir().join(format!("roomler-hwid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dev = root.join("sys/class/drm/card0/device");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::create_dir_all(root.join("sys/class/drm/card0-HDMI-A-1")).unwrap();
        std::fs::create_dir_all(root.join("proc/sys/kernel")).unwrap();
        for (f, v) in [
            ("vendor", "0x8086"),
            ("device", "0x9a49"),
            ("subsystem_vendor", "0x17aa"),
            ("subsystem_device", "0x22d8"),
            ("revision", "0x01"),
        ] {
            std::fs::write(dev.join(f), format!("{v}\n")).unwrap();
        }
        std::fs::create_dir_all(root.join("drivers/i915")).unwrap();
        std::os::unix::fs::symlink(root.join("drivers/i915"), dev.join("driver")).unwrap();
        std::fs::write(root.join("proc/sys/kernel/osrelease"), "6.8.0-45-generic\n").unwrap();

        let a = linux::fingerprint_at(&root);
        assert!(
            a.contains("0x8086:0x9a49 0x17aa:0x22d8 rev 0x01 i915"),
            "{a}"
        );
        assert!(a.contains("os=6.8.0-45-generic"), "{a}");
        assert_eq!(a, linux::fingerprint_at(&root), "deterministic");

        // A driver package landing changes the key; a connector dir never did.
        let lib = root.join("usr/lib/x86_64-linux-gnu/dri");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(lib.join("iHD_drv_video.so"), b"driver").unwrap();
        let b = linux::fingerprint_at(&root);
        assert_ne!(a, b);
        assert!(b.contains("iHD_drv_video.so 6 "), "{b}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
