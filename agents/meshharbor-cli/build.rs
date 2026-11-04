// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Embeds a Windows VERSIONINFO resource into `roomler.exe`.
//!
//! Same rationale as `agents/meshharbord/build.rs` -- see that file for the
//! full explanation of why this uses `embed-resource`'s per-binary
//! `compile_for` rather than `winres` / `winresource` (whose
//! `cargo:rustc-link-lib=dylib=resource` would leak a second RT_VERSION
//! resource into `meshharbor-setup.exe`, which depends on this crate and already
//! embeds its own via tauri-build).
//!
//! `roomler.exe` is doubly exposed: it ships standalone in the tunnel zip AND
//! is bundled inside both agent MSIs (P4b), so an anonymous binary here shows
//! up on every node in the fleet.
//!
//! No-op on every non-Windows host.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(windows)]
    windows_version_info::embed();
}

#[cfg(windows)]
mod windows_version_info {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    /// `0.3.0-rc.238` -> `(0, 3, 238)`; a 0.4+ final carries its PATCH
    /// (`0.4.1` -> `(0, 4, 1)`), a pre-0.4 final keeps the legacy 65535 —
    /// the #760 era split. Mirrors the MSI ProductVersion remap in
    /// `release-agent.yml` so the EXE file version and the MSI product
    /// version agree.
    fn file_version(pkg_version: &str) -> (u16, u16, u16) {
        let (core, rc) = match pkg_version.split_once("-rc.") {
            Some((core, rc)) => (core, Some(rc.parse::<u32>().unwrap_or(0).min(65535) as u16)),
            None => (pkg_version, None),
        };
        let mut parts = core.split('.');
        let major: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch: u16 = parts
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
            .min(65535) as u16;
        let build = match rc {
            Some(rc) => rc,
            None if (major, minor) >= (0, 4) => patch,
            None => 65535,
        };
        (major, minor, build)
    }

    pub fn embed() {
        // Build scripts compile for the host; guard the TARGET too so a
        // Windows box cross-compiling to Linux does not staple a PE resource
        // onto an ELF.
        if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
            return;
        }

        let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
        let (major, minor, build) = file_version(&pkg_version);
        let file_version_str = format!("{major}.{minor}.{build}.0");

        // Numeric literals instead of `#include <winver.h>` keep the resource
        // self-contained: VS_VERSION_INFO = 1, VOS_NT_WINDOWS32 = 0x40004,
        // VFT_APP = 0x1.
        let rc = format!(
            r#"1 VERSIONINFO
FILEVERSION {major},{minor},{build},0
PRODUCTVERSION {major},{minor},{build},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "G ROX LTD"
            VALUE "FileDescription", "Roomler CLI (tunnel + mesh client)"
            VALUE "FileVersion", "{file_version_str}"
            VALUE "InternalName", "roomler"
            VALUE "LegalCopyright", "Copyright (C) 2026 G ROX LTD"
            VALUE "OriginalFilename", "roomler.exe"
            VALUE "ProductName", "Roomler"
            VALUE "ProductVersion", "{pkg_version}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
        );

        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));
        let rc_path = out_dir.join("roomler-version.rc");
        fs::write(&rc_path, rc).expect("failed to write the VERSIONINFO resource script");

        let result = embed_resource::compile_for(&rc_path, ["roomler"], embed_resource::NONE);

        if env::var("CI").is_ok() {
            result
                .manifest_required()
                .expect("VERSIONINFO embedding failed in CI (rc.exe / llvm-rc unavailable?)");
        } else if let Err(err) = result.manifest_optional() {
            println!("cargo:warning=roomler VERSIONINFO not embedded: {err:?}");
        }
    }
}
