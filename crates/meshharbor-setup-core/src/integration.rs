// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR-BEGIN
// What is left here is the WINDOWS half. The per-user install DIR is named by
// the extract step, not by this module, and the release zip still carries a
// roomler-tunnel.exe alias for hosts that already have it on PATH — so the
// occurrences below describe a layout this module only appends to.
// The LINUX half is done: FR-46 flipped the symlink to `~/.local/bin/roomler`
// and REMOVES a pre-rename one instead of stranding it, which is what the
// objection recorded here actually asked for. docs/fr/FR-46
//! Per-platform integration after the CLI archive is extracted.
//!
//! Three jobs, each `#[cfg]`-gated to its OS:
//!
//! - **Windows**: append the install dir to the user-PATH registry
//!   value at `HKCU\Environment`. Best-effort Start-Menu shortcut
//!   creation in v1 — the .lnk write is deferred to Phase B; v1 just
//!   ensures `roomler-tunnel` is on PATH so the operator can run it
//!   from any shell.
//! - **Linux**: symlink the binary into `~/.local/bin/roomler`, and
//!   remove a pre-rename `roomler-tunnel` symlink if one is there.
//!   `.desktop` file is deferred to Phase B (it's only useful with
//!   the first-forward feature so the desktop entry has a meaningful
//!   `Exec=…` line).
//! - **macOS**: same as Linux for v1 — symlink into `~/.local/bin/`.
//!   LaunchAgent plist deferred to Phase B.
//!
//! Returns a [`IntegrationReport`] describing what we actually
//! changed so the SPA can render an honest "what we did" summary on
//! the Done step.

use std::path::{Path, PathBuf};

// `Context` (anyhow's `.with_context(…)` trait) is only used by
// `integrate_unix` — cfg-gated to keep the Windows build's
// unused-import lint quiet.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Summary of what `integrate` did. The orchestrator forwards this
/// into the `IntegrationDone` progress event so the SPA renders the
/// right Done-step text per platform.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrationReport {
    /// True when the user's PATH (Windows) was updated, or a symlink
    /// landed in `~/.local/bin` (Linux/macOS).
    pub path_updated: bool,
    /// True when a Start-Menu shortcut / .desktop file / LaunchAgent
    /// was created. v1 leaves this false (Phase B deliverable).
    pub shortcut_created: bool,
    /// Resolved path the operator should run / add to their shell rc.
    /// e.g. `C:\Users\foo\AppData\Local\Programs\roomler-tunnel\
    /// roomler-tunnel.exe` (Windows) or `/home/foo/.local/bin/
    /// roomler` (Linux).
    pub binary_path: PathBuf,
}

/// Wire up the freshly-extracted CLI into the operator's shell PATH.
///
/// `tunnel_binary` is the absolute path to the `roomler-tunnel(.exe)`
/// the extractor located inside `<install_root>`. `install_root` is
/// the per-user install dir (`%LOCALAPPDATA%\Programs\roomler-tunnel`
/// on Windows; the extractor's dest dir on Linux/macOS).
///
/// Returns a structured report on success. Best-effort: a failure to
/// edit PATH on Windows logs + returns the binary path with
/// `path_updated=false` so the SPA can show "we couldn't auto-add to
/// PATH; here's the command to run".
pub fn integrate(install_root: &Path, tunnel_binary: &Path) -> Result<IntegrationReport> {
    #[cfg(target_os = "windows")]
    {
        integrate_windows(install_root, tunnel_binary)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = install_root; // suppress unused-var on these targets
        integrate_unix(tunnel_binary)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = install_root;
        let _ = tunnel_binary;
        anyhow::bail!(
            "platform integration not implemented for this OS; the binary is at {}",
            tunnel_binary.display()
        )
    }
}

// ─── Windows ────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn integrate_windows(install_root: &Path, tunnel_binary: &Path) -> Result<IntegrationReport> {
    let dir = install_root.to_path_buf();
    let path_updated = match append_user_path_segment(&dir) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                error = %e,
                dir = %dir.display(),
                "could not append install dir to user PATH"
            );
            false
        }
    };
    Ok(IntegrationReport {
        path_updated,
        shortcut_created: false, // deferred to Phase B
        binary_path: tunnel_binary.to_path_buf(),
    })
}

/// Append `segment` to the user's `HKCU\Environment\Path` registry
/// value. Idempotent: returns Ok with no write if `segment` is
/// already present (case-insensitively).
///
/// Uses `REG_EXPAND_SZ` for the value type — Windows accepts both
/// `REG_SZ` and `REG_EXPAND_SZ`; sticking with whichever was already
/// there avoids spuriously changing the type. New (empty) PATH
/// defaults to `REG_EXPAND_SZ` per the agent installer's convention.
///
/// Broadcasts a `WM_SETTINGCHANGE` message so already-open Explorer
/// + freshly-spawned shells pick up the new value without a logout.
/// Existing terminal sessions inherit the PATH from their parent so
/// they won't see the change until restarted — operator-acceptable.
#[cfg(target_os = "windows")]
pub fn append_user_path_segment(segment: &Path) -> Result<()> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ, RegCloseKey,
        RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };

    let key_name: Vec<u16> = OsString::from("Environment")
        .encode_wide()
        .chain([0])
        .collect();
    let value_name: Vec<u16> = OsString::from("Path").encode_wide().chain([0]).collect();

    let mut hkey: windows_sys::Win32::System::Registry::HKEY = ptr::null_mut();
    let access = KEY_READ | KEY_SET_VALUE;
    // SAFETY: RegOpenKeyExW is FFI; pointers come from owned local
    // buffers and out-pointers we pass in. Caller has no shared state.
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, key_name.as_ptr(), 0, access, &mut hkey) };
    // Registry API returns WIN32_ERROR = u32; ERROR_SUCCESS is also
    // u32 in windows-sys-0.59. Compare without the legacy `as i32`
    // cast (which was wrong in earlier handwritten versions of this
    // file — windows-sys cleaned up the typedef in 0.5x).
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegOpenKeyExW(HKCU\\Environment) failed with code {rc}");
    }

    // Read existing value (if any).
    let mut value_type: u32 = REG_SZ;
    let mut buf_size: u32 = 0;
    // First call: size probe.
    // SAFETY: RegQueryValueExW with null data pointer is the documented
    // size-probe form; out params are owned locals.
    unsafe {
        RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            ptr::null(),
            &mut value_type,
            ptr::null_mut(),
            &mut buf_size,
        );
    }
    let mut buf: Vec<u16> = vec![0; (buf_size as usize / 2).max(1)];
    let mut buf_size_io = buf_size;
    // SAFETY: buf is sized per probe + at least 1 element.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            ptr::null(),
            &mut value_type,
            buf.as_mut_ptr().cast::<u8>(),
            &mut buf_size_io,
        )
    };
    let existing = if rc == ERROR_SUCCESS {
        // Buffer includes trailing NUL — strip it for cleaner concat.
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    } else {
        // No existing PATH value (rare but possible) → start empty.
        String::new()
    };

    let segment_str = segment.to_string_lossy();
    if existing
        .split(';')
        .map(|s| s.trim().trim_end_matches('\\'))
        .any(|s| s.eq_ignore_ascii_case(segment_str.trim_end_matches('\\')))
    {
        // Already present — no-op.
        // SAFETY: hkey came from RegOpenKeyExW above.
        unsafe { RegCloseKey(hkey) };
        return Ok(());
    }

    let new_value = if existing.is_empty() {
        segment_str.into_owned()
    } else if existing.ends_with(';') {
        format!("{existing}{segment_str}")
    } else {
        format!("{existing};{segment_str}")
    };

    let new_wide: Vec<u16> = OsString::from(&new_value)
        .encode_wide()
        .chain([0])
        .collect();
    let type_to_write = if value_type == REG_EXPAND_SZ {
        REG_EXPAND_SZ
    } else {
        REG_SZ
    };
    // SAFETY: new_wide owns its bytes; cast to *const u8 is the
    // documented call shape for RegSetValueExW.
    let rc = unsafe {
        RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            type_to_write,
            new_wide.as_ptr().cast::<u8>(),
            (new_wide.len() * 2) as u32,
        )
    };
    // SAFETY: hkey came from RegOpenKeyExW above.
    unsafe { RegCloseKey(hkey) };
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegSetValueExW(HKCU\\Environment\\Path) failed with code {rc}");
    }

    // Broadcast environment-changed so Explorer + future shells see
    // it. Best-effort — failure here doesn't roll back the write.
    let env_param: Vec<u16> = OsString::from("Environment")
        .encode_wide()
        .chain([0])
        .collect();
    let mut result: usize = 0;
    // SAFETY: env_param outlives the call; result is owned local.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            env_param.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
    Ok(())
}

// ─── Linux + macOS ─────────────────────────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn integrate_unix(tunnel_binary: &Path) -> Result<IntegrationReport> {
    let symlink_path = unix_local_bin_path()?;
    if let Some(parent) = symlink_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    // Replace any existing symlink/file at the target.
    let _ = std::fs::remove_file(&symlink_path);
    // SAFETY: symlink is a safe filesystem op; both paths exist on
    // disk (extract step ran first; we just mkdir'd the parent).
    std::os::unix::fs::symlink(tunnel_binary, &symlink_path).with_context(|| {
        format!(
            "symlink {} → {}",
            symlink_path.display(),
            tunnel_binary.display()
        )
    })?;
    retire_legacy_symlink(&symlink_path);
    Ok(IntegrationReport {
        path_updated: true,
        shortcut_created: false, // deferred to Phase B
        binary_path: symlink_path,
    })
}

/// Remove the pre-rename `roomler-tunnel` symlink this wizard used to create.
///
/// FR-46: the anchor that used to sit on this module argued, correctly, that
/// flipping the name is a BEHAVIOUR change because it "leaves the old entry
/// stranded". That objection is answered by removing it rather than by not
/// renaming — an operator ends up with exactly one `roomler` on PATH instead of
/// one working name and one dangling one.
///
/// ⚠️ Only a SYMLINK is removed. This wizard has only ever created symlinks
/// here, so a regular file of that name is someone else's and is left alone.
/// Best-effort throughout: failing to tidy an old symlink must never fail an
/// install that has already succeeded.
// RETIRED-NAME-ANCHOR(3): the pre-rename symlink this exists to DELETE.
// Deletable once no host can still have one. docs/fr/FR-46
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn retire_legacy_symlink(current: &Path) {
    let Some(parent) = current.parent() else {
        return;
    };
    let legacy = parent.join("roomler-tunnel");
    if legacy
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        let _ = std::fs::remove_file(&legacy);
    }
}

/// Resolve `~/.local/bin/roomler`. The XDG-style path works
/// on both Linux and macOS — modern shells include it in PATH by
/// default; for the operators where it isn't, the Done step surfaces
/// a one-line `export PATH=…` they can drop into their shell rc.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_local_bin_path() -> Result<PathBuf> {
    let dirs = directories::UserDirs::new()
        .ok_or_else(|| anyhow::anyhow!("could not resolve user home dir"))?;
    Ok(dirs.home_dir().join(".local").join("bin").join("roomler"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_report_round_trip() {
        let report = IntegrationReport {
            path_updated: true,
            shortcut_created: false,
            binary_path: PathBuf::from(if cfg!(windows) {
                r"C:\Users\foo\bin\roomler.exe"
            } else {
                "/home/foo/.local/bin/roomler"
            }),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: IntegrationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
        assert!(json.contains("pathUpdated"));
        assert!(json.contains("shortcutCreated"));
        assert!(json.contains("binaryPath"));
    }

    #[test]
    fn integration_report_camel_case_keys() {
        let json = serde_json::to_string(&IntegrationReport::default()).unwrap();
        // snake_case (`path_updated`) would mean an SPA listener
        // bound to `pathUpdated` silently sees `undefined`. Lock the
        // shape.
        assert!(!json.contains("path_updated"));
        assert!(!json.contains("shortcut_created"));
        assert!(!json.contains("binary_path"));
    }
}
// RETIRED-NAME-ANCHOR-END
