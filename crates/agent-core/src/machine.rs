// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Stable machine fingerprint derivation.
//!
//! The server uses `(tenant_id, machine_id)` as a unique key, so `machine_id`
//! must be stable across restarts but unique per physical host. We derive a
//! SHA-256 of:
//!   - OS hostname (cheap, stable unless user renames the machine)
//!   - OS kind + arch (cheap, stable)
//!   - the config dir path (acts as a "user install" scope so one box can
//!     enroll multiple agent configs without colliding)
//!
//! For v1 this is good enough. A future refinement would read the DMI product
//! UUID on Linux / IOKit on macOS / WMI on Windows for a true hardware ID,
//! but those paths add platform-specific deps and root/admin requirements
//! we don't need yet.

use sha2::{Digest, Sha256};
use std::path::Path;

pub fn derive_machine_id(config_path: &Path) -> String {
    let mut hasher = Sha256::new();

    if let Ok(host) = hostname() {
        hasher.update(host.as_bytes());
    }
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(std::env::consts::ARCH.as_bytes());
    hasher.update(config_path.to_string_lossy().as_bytes());

    hex::encode(hasher.finalize())
}

/// OS hostname (POSIX `gethostname` on Unix, `COMPUTERNAME` env var
/// on Windows). Exposed for `logs_upload.rs` so the agent's uploader
/// can hash the hostname into `host_id_hash` per the rc.58 plan.
pub fn hostname() -> std::io::Result<String> {
    // `hostname` crate is another dep; keep things simple with `uname -n`
    // (POSIX) / Windows GetComputerName (via HOSTNAME env var).
    #[cfg(unix)]
    {
        // SAFETY: gethostname(3) takes a buffer and writes a NUL-terminated
        // string into it. 256 bytes is enough for POSIX-conformant hosts.
        let mut buf = [0u8; 256];
        let ret = unsafe { libc_gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return Ok(String::from_utf8_lossy(&buf[..nul]).into_owned());
        }
        Err(std::io::Error::last_os_error())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "hostname"))
    }
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "gethostname"]
    fn libc_gethostname(name: *mut core::ffi::c_char, len: usize) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn is_deterministic_for_same_config_path() {
        let p = PathBuf::from("/tmp/test-meshharbor/config.toml");
        let a = derive_machine_id(&p);
        let b = derive_machine_id(&p);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn differs_for_different_config_paths() {
        let a = derive_machine_id(&PathBuf::from("/tmp/a.toml"));
        let b = derive_machine_id(&PathBuf::from("/tmp/b.toml"));
        assert_ne!(a, b);
    }
}
