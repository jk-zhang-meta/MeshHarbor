// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(3): records the OLD -> NEW mapping, so it must name both sides.
//! Embeds a Windows VERSIONINFO resource into `roomlerd.exe`.
//!
//! Authenticode says *who* signed a binary. VERSIONINFO is what Explorer's
//! Details tab, Task Manager's Publisher column, `Get-Process | Select
//! Company`, and most corporate AV/EDR consoles actually read. Until this
//! landed, `roomlerd.exe` -- a binary that runs as a LocalSystem service on
//! managed corporate fleets -- had NO version resource at all: no
//! CompanyName, no ProductName, no FileVersion, no copyright. That is an
//! independent AV heuristic signal on top of being unsigned, and it makes
//! the binary anonymous in every inventory tool an IT department runs.
//!
//! # Why `embed-resource` and not `winres` / `winresource`
//!
//! `winresource::WindowsResource::compile()` emits
//! `cargo:rustc-link-lib=dylib=resource`, and link-lib directives from a
//! dependency's build script propagate into the final link of every
//! DOWNSTREAM binary. This crate is a path dependency of BOTH Tauri crates
//! (`roomler-agent-tray` -> `meshharbor-desktop.exe`, `meshharbor-setup` ->
//! `meshharbor-setup.exe`), and both already embed their own VS_VERSION_INFO
//! via `tauri_build::build()`. The result would be two RT_VERSION resources
//! in each of those EXEs, with the winner decided by linker order.
//!
//! `embed_resource::compile_for(rc, ["roomlerd"], NONE)` emits
//! `cargo:rustc-link-arg-bin=roomlerd=...` -- scoped to one binary of one
//! package, and structurally incapable of leaking. It is also already in the
//! dependency graph (pulled by tauri-build), so it adds no supply-chain
//! surface.
//!
//! No-op on every non-Windows host.
//!
//! It also sets `cfg(hive_host)` ([`hive_host`], FR-90 P1h).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    hive_host();
    windows_main_stack();

    #[cfg(windows)]
    windows_version_info::embed();
}

/// The main thread's stack on Windows: 8 MiB, what Linux gives it.
///
/// Windows reserves for the main thread whatever the PE header says — 1 MiB
/// by the MSVC linker's default — and `main` polls `daemon_main` right on that
/// thread (`block_on`). In a DEBUG build that one poll frame was already close
/// to 1 MiB: the state machine of a function with forty-odd command arms keeps
/// a slot for every temporary of every arm, and the clap parse runs on top of
/// it. FR-102 P3's two `enroll` flags tipped it over, and every invocation —
/// `--version` included — died with "thread 'main' has overflowed its stack"
/// before printing a byte (measured: the future itself is ~12 KB, and the same
/// parse outside the runtime succeeds). Only the FR-85 recorder lane noticed,
/// because it is the one CI job that runs the debug binary on Windows.
///
/// A release build's frames are far smaller, but the same creep there would
/// take every Windows device down at service start, so the headroom applies to
/// both. It is a reserve, not a commit — pages are committed only as the stack
/// grows. Threads created with an explicit size (std's, tokio's) are
/// unaffected; any thread the OS creates at the image default gets the same
/// reserve. Keyed on the TARGET, like [`hive_host`]: a build script runs on the
/// host. `-bin=meshharbord` scopes it to this one binary, as the version
/// resource below is.
///
/// ⚠️ The bin name is `meshharbord` (the `[[bin]]` in Cargo.toml), NOT the
/// package/lib name `roomlerd`. `cargo:rustc-link-arg-bin=<NAME>` names a BIN
/// TARGET; naming the package made cargo reject the whole build on Windows
/// MSVC with "does not have a bin target with the name roomlerd" (the FR-21
/// `meshharbord` output-binary rename reached Cargo.toml but this script still
/// named the retired bin — the daemon did not build on Windows at all).
fn windows_main_stack() {
    const STACK_BYTES: u64 = 8 * 1024 * 1024;
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => println!("cargo:rustc-link-arg-bin=meshharbord=/STACK:{STACK_BYTES}"),
        Ok("gnu") | Ok("gnullvm") => {
            println!("cargo:rustc-link-arg-bin=meshharbord=-Wl,--stack,{STACK_BYTES}")
        }
        _ => {}
    }
}

/// FR-90 P1h — `cfg(hive_host)`: this build hosts agent sessions. That is the
/// `hive` feature, on an operating system whose session launcher exists:
/// Linux, macOS from P1h, and Windows from P1i-2, as the console user only.
/// One name at the forty-odd sites that would each
/// spell `all(feature = "hive", any(target_os = …))`, so the next system is
/// one line here. Read from Cargo's environment, not `cfg!`: a build script
/// runs on the HOST, and these describe the TARGET.
fn hive_host() {
    println!("cargo::rustc-check-cfg=cfg(hive_host)");
    let hive = std::env::var_os("CARGO_FEATURE_HIVE").is_some();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if hive && matches!(os.as_str(), "linux" | "macos" | "windows") {
        println!("cargo::rustc-cfg=hive_host");
    }
}

#[cfg(windows)]
mod windows_version_info {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    /// Windows FILEVERSION is four u16 fields and Windows Installer ignores
    /// the fourth for comparison, so `CARGO_PKG_VERSION_*` would render every
    /// single rc of `0.3.0-rc.N` as the identical `0.3.0.0`.
    ///
    /// Use the same remap `release-agent.yml` applies to the MSI
    /// ProductVersion, so the EXE's file version and the MSI's product
    /// version agree: `0.3.0-rc.238` -> `0.3.238.0`, and — mirroring the
    /// #760 era split in `artifact_version::msi_product_version_for` — a
    /// 0.4+ final carries its PATCH (`0.4.1` -> `0.4.1.0`) while a pre-0.4
    /// final keeps the legacy 65535 answer. Nothing asserts the copies
    /// agree at build time; they agree by the discipline the workflow
    /// comment's copy-list enforces (this file is on that list).
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
            // Finals: era split at 0.4 (see the doc comment above).
            None if (major, minor) >= (0, 4) => patch,
            None => 65535,
        };
        (major, minor, build)
    }

    pub fn embed() {
        // Build scripts compile for the host, so `cfg(windows)` above is a
        // host check. Guard the TARGET too: a Windows box cross-compiling to
        // Linux must not try to staple a PE resource onto an ELF.
        if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
            return;
        }

        let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
        let (major, minor, build) = file_version(&pkg_version);
        let file_version_str = format!("{major}.{minor}.{build}.0");

        // Deliberately no `#include <winver.h>`: rc.exe's include path is not
        // guaranteed when it is invoked outside a Visual Studio developer
        // prompt. VS_VERSION_INFO is 1, VOS_NT_WINDOWS32 is 0x40004 and
        // VFT_APP is 0x1, so numeric literals make the resource
        // self-contained.
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
            VALUE "FileDescription", "Roomler Daemon"
            VALUE "FileVersion", "{file_version_str}"
            VALUE "InternalName", "meshharbord"
            VALUE "LegalCopyright", "Copyright (C) 2026 G ROX LTD"
            VALUE "OriginalFilename", "meshharbord.exe"
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
        let rc_path = out_dir.join("meshharbord-version.rc");
        fs::write(&rc_path, rc).expect("failed to write the VERSIONINFO resource script");

        // The bin TARGET is `meshharbord` (Cargo.toml `[[bin]]`), not the
        // package name `roomlerd`: `compile_for` scopes the resource to one
        // bin, and naming a bin that does not exist is the same hard cargo
        // error as the stack link-arg above.
        let result = embed_resource::compile_for(&rc_path, ["meshharbord"], embed_resource::NONE);

        // A missing rc.exe/llvm-rc must not break a developer's local build,
        // but it must never silently ship a release binary with no version
        // block -- exactly the state this build script exists to fix.
        if env::var("CI").is_ok() {
            result
                .manifest_required()
                .expect("VERSIONINFO embedding failed in CI (rc.exe / llvm-rc unavailable?)");
        } else if let Err(err) = result.manifest_optional() {
            println!("cargo:warning=roomlerd VERSIONINFO not embedded: {err:?}");
        }
    }
}
