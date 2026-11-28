// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D6 — registering the desktop companion to start at login, on the
//! platforms where MeshHarbor owns that registration.
//!
//! | platform | mechanism | who writes it | a person's opt-out |
//! |---|---|---|---|
//! | Windows perMachine | `HKLM\…\Run\MeshHarbor Desktop` | the elevated `service install --as-service` (MSI CA), self-healed by the SCM host at every start | the companion's per-user state; an `--autostart` launch exits |
//! | Windows perUser | `HKCU\…\Run\MeshHarbor Desktop` | the per-user `service install` (MSI CA) and the companion itself | the companion deletes the value and records the choice |
//! | Linux (.deb) | `/etc/xdg/autostart/meshharbor-desktop.desktop` | the package | `~/.config/autostart/meshharbor-desktop.desktop` with `Hidden=true` |
//! | macOS (.pkg) | the `fans.itachi.meshharbor.desktop` LaunchAgent (`RunAtLoad`) | the package's postinstall | macOS Login Items — not ours to write |
//!
//! Shared by the daemon and the companion so both spell the value, the
//! argument and the entry the same way. Pure helpers are tested on every
//! platform; the registry calls are Windows-only and take the subkey as a
//! parameter, so their tests run against a scratch key instead of the real
//! `Run` key.

use std::path::{Path, PathBuf};

/// The argument a login start passes: stay in the tray (or exit, for a
/// person who opted out) instead of opening the window.
pub const AUTOSTART_ARG: &str = "--autostart";
/// The argument the daemon's one-shot post-install launch passes: open the
/// Welcome tour.
pub const FIRST_RUN_ARG: &str = "--first-run";

/// `HKLM`/`HKCU` subkey that holds login-start commands.
pub const WINDOWS_RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// The value name under [`WINDOWS_RUN_SUBKEY`]. A compatibility surface:
/// renaming it strands every existing registration (two entries, then one
/// that nothing removes).
pub const WINDOWS_RUN_VALUE_NAME: &str = "MeshHarbor Desktop";

/// The companion's desktop-entry file name — the system autostart entry and
/// the per-user override MUST share it, since XDG autostart matches the two
/// by file name.
pub const XDG_ENTRY_FILE: &str = "meshharbor-desktop.desktop";
/// Where the `.deb` installs the system-wide autostart entry.
pub const XDG_SYSTEM_AUTOSTART: &str = "/etc/xdg/autostart/meshharbor-desktop.desktop";

/// The data of the Windows Run value: the quoted EXE path, then
/// [`AUTOSTART_ARG`]. Quoted always — `C:\Program Files\…` has a space, and an
/// unquoted Run command with a space is parsed by the shell as
/// `C:\Program` + arguments.
pub fn windows_run_command(exe: &Path) -> String {
    format!("\"{}\" {AUTOSTART_ARG}", exe.display())
}

/// What the Run value SHOULD be, or `None` for "no value".
///
/// `device_enabled` is the device's `companion_autostart`; `user_opted_out`
/// is a person's own "Start at login: off" and only applies to the per-user
/// (`HKCU`) value — the machine value serves every account, and a person's
/// opt-out is honoured by the companion at `--autostart` instead.
pub fn desired_run_value(
    device_enabled: bool,
    exe: &Path,
    exe_exists: bool,
    user_opted_out: bool,
) -> Option<String> {
    (device_enabled && exe_exists && !user_opted_out).then(|| windows_run_command(exe))
}

/// What to do to the registry to get from `current` to `desired`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunKeyAction {
    Keep,
    Write(String),
    Remove,
}

/// Plan the change. Pure: the registry is read and written by the caller.
pub fn plan_run_key(current: Option<&str>, desired: Option<&str>) -> RunKeyAction {
    match (current, desired) {
        (None, None) => RunKeyAction::Keep,
        (Some(c), Some(d)) if c == d => RunKeyAction::Keep,
        (_, Some(d)) => RunKeyAction::Write(d.to_string()),
        (Some(_), None) => RunKeyAction::Remove,
    }
}

/// Which Windows Run key owns an EXE's login start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// Under Program Files: a perMachine install, `HKLM`.
    Machine,
    /// Anywhere else (`%LOCALAPPDATA%\Programs\MeshHarbor`): per-user, `HKCU`.
    User,
}

/// Classify `exe` by its location. `program_files` are the candidate
/// Program Files roots (`%ProgramFiles%`, `%ProgramW6432%`); the comparison
/// is by whole path components and ignores case and slash direction.
pub fn windows_scope_for_exe(exe: &Path, program_files: &[PathBuf]) -> InstallScope {
    // String form on purpose: this is tested on every platform, and Linux's
    // `Path` does not split `C:\…` into components.
    fn norm(p: &Path) -> String {
        let mut s = p.to_string_lossy().replace('/', "\\").to_lowercase();
        while s.ends_with('\\') {
            s.pop();
        }
        s
    }
    let exe = norm(exe);
    let inside = program_files.iter().map(|d| norm(d)).any(|root| {
        !root.is_empty()
            && exe.len() > root.len()
            && exe.starts_with(&root)
            && exe.as_bytes()[root.len()] == b'\\'
    });
    if inside {
        InstallScope::Machine
    } else {
        InstallScope::User
    }
}

/// The Program Files roots of this machine, for [`windows_scope_for_exe`].
/// Empty off Windows.
pub fn program_files_dirs() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect()
}

/// Extract the executable path from a Windows `Run` registry command string.
///
/// Handles both quoted (`"C:\...\meshharbor-desktop.exe" --autostart`) and
/// unquoted paths (including unquoted paths containing spaces when terminated
/// by `.exe` + whitespace/end). Returns `None` for empty or unterminated-quote
/// inputs.
pub fn extract_run_command_exe(raw: &str) -> Option<&str> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        let exe = rest[..end].trim();
        return (!exe.is_empty()).then_some(exe);
    }
    // Unquoted path: look for a `.exe` boundary (ASCII case-insensitive)
    // followed by end-of-string or ASCII whitespace so paths with spaces
    // (e.g. `C:\Users\Jane Doe\...\meshharbor-desktop.exe --autostart`) are
    // preserved intact.
    let bytes = s.as_bytes();
    if bytes.len() >= 4 {
        for i in 0..=bytes.len() - 4 {
            if bytes[i..i + 4].eq_ignore_ascii_case(b".exe") {
                let end = i + 4;
                if end == bytes.len() || bytes[end].is_ascii_whitespace() {
                    let exe = s[..end].trim();
                    return (!exe.is_empty()).then_some(exe);
                }
            }
        }
    }
    // Fallback for unquoted non-.exe commands: first whitespace-delimited token.
    s.split_ascii_whitespace().next().filter(|t| !t.is_empty())
}

/// Normalize a Windows-style path into lowercase backslash-separated path
/// components, stripping any `\\?\` verbatim prefix. Returns `None` if the
/// path is empty or contains a parent-traversal (`..`) component.
fn normalized_win_components(raw: &str) -> Option<Vec<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let replaced = trimmed.replace('/', "\\");
    let stripped = replaced.strip_prefix(r"\\?\").unwrap_or(&replaced);
    let mut comps = Vec::new();
    for part in stripped.split('\\') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        comps.push(part.to_lowercase());
    }
    (!comps.is_empty()).then_some(comps)
}

/// Returns `true` **ONLY** when `raw_or_path` points inside the per-user
/// companion install directory: `%LOCALAPPDATA%\Programs\MeshHarbor\...` or
/// `<user-profile>\AppData\Local\Programs\MeshHarbor\...` (case-insensitive,
/// slash-normalized, whole path component boundary).
///
/// Never matches `C:\Program Files\MeshHarbor\...`, `C:\Program Files (x86)\...`,
/// `...\Programs\MeshHarborOther\...`, user data (`%LOCALAPPDATA%\meshharbor\...`),
/// or arbitrary paths.
pub fn is_per_user_companion_path(raw_or_path: &str, local_app_data: Option<&Path>) -> bool {
    let trimmed = raw_or_path.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Accept either a raw Run command (quoted or with `--args`) or a bare path.
    let candidate = if trimmed.starts_with('"') {
        match extract_run_command_exe(trimmed) {
            Some(exe) => exe,
            None => return false,
        }
    } else if let Some(exe) = extract_exe_if_present(trimmed) {
        exe
    } else {
        // Strip trailing CLI flags like ` --autostart` while preserving spaces
        // in plain paths (e.g. `C:\Users\Jane Doe\...\MeshHarbor\file`).
        trimmed
            .split(" --")
            .next()
            .map(str::trim)
            .unwrap_or(trimmed)
    };

    let Some(comps) = normalized_win_components(candidate) else {
        return false;
    };

    // Never match anything inside Program Files, even if a weird subpath
    // happened to contain `AppData\Local\Programs\MeshHarbor`.
    if comps
        .iter()
        .any(|c| c == "program files" || c == "program files (x86)")
    {
        return false;
    }

    // 1. Explicit `%LOCALAPPDATA%` match (covers redirected LocalAppData).
    if let Some(lad) = local_app_data
        && let Some(mut prefix) = normalized_win_components(&lad.to_string_lossy())
    {
        prefix.push("programs".to_string());
        prefix.push("meshharbor".to_string());
        if comps.len() > prefix.len() && comps[..prefix.len()] == prefix[..] {
            return true;
        }
    }

    // 2. Literal unexpanded `%LOCALAPPDATA%\Programs\MeshHarbor\...` (e.g. from
    //    an `EnvironmentVariableDataBlock` in a `.lnk` or `REG_EXPAND_SZ`).
    if comps.len() > 3
        && comps[0] == "%localappdata%"
        && comps[1] == "programs"
        && comps[2] == "meshharbor"
    {
        return true;
    }

    // 3. Standard `<drive>\<...>\<user>\AppData\Local\Programs\MeshHarbor\<child>`
    //    shape (used when SYSTEM enumerates `HKEY_USERS\<SID>` hives where
    //    `%LOCALAPPDATA%` belongs to SYSTEM, not the user). Requires at least
    //    two leading components (e.g. drive + profile folder) before `appdata`
    //    and at least one child component after `meshharbor`.
    if comps.len() >= 7 {
        for i in 2..=comps.len() - 5 {
            if comps[i] == "appdata"
                && comps[i + 1] == "local"
                && comps[i + 2] == "programs"
                && comps[i + 3] == "meshharbor"
            {
                return true;
            }
        }
    }

    false
}

fn extract_exe_if_present(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    for i in 0..=bytes.len() - 4 {
        if bytes[i..i + 4].eq_ignore_ascii_case(b".exe") {
            let end = i + 4;
            if end == bytes.len() || bytes[end].is_ascii_whitespace() {
                let exe = s[..end].trim();
                return (!exe.is_empty()).then_some(exe);
            }
        }
    }
    None
}

/// Should a per-machine install/daemon retire the current `HKCU\...\Run` value?
/// Returns `true` only when the value parses to an executable inside the
/// per-user companion folder (`%LOCALAPPDATA%\Programs\MeshHarbor\...`).
pub fn should_retire_hkcu_run_value(
    current_run_value: Option<&str>,
    local_app_data: Option<&Path>,
) -> bool {
    current_run_value
        .and_then(extract_run_command_exe)
        .is_some_and(|exe| is_per_user_companion_path(exe, local_app_data))
}

/// Should a per-machine install/daemon retire a user Start-menu `.lnk` whose
/// target resolves to `shortcut_target`? Returns `true` only when the target
/// points inside the per-user companion folder.
pub fn should_retire_user_shortcut_target(
    shortcut_target: &str,
    local_app_data: Option<&Path>,
) -> bool {
    is_per_user_companion_path(shortcut_target, local_app_data)
}

/// Is a subkey name directly under `HKEY_USERS` an interactive user profile
/// hive (e.g. `S-1-5-21-...`, `S-1-12-1-...`), skipping `.DEFAULT`,
/// `*_Classes`, and built-in service accounts (`S-1-5-18`/`19`/`20`)?
pub fn is_user_profile_sid_hive(sid: &str) -> bool {
    let lower = sid.trim().to_ascii_lowercase();
    if lower.is_empty()
        || lower == ".default"
        || lower.ends_with("_classes")
        || matches!(lower.as_str(), "s-1-5-18" | "s-1-5-19" | "s-1-5-20")
    {
        return false;
    }
    lower.starts_with("s-")
}

/// Parse the target path from a Windows `.lnk` (MS-SHLLINK) binary payload.
///
/// Pure Rust — avoids COM apartment initialization inside SYSTEM services and
/// makes `.lnk` inspection unit-testable on every platform. Checks:
/// 1. `LinkInfo` local base path + common path suffix (Unicode preferred over ANSI).
/// 2. `ExtraData` `EnvironmentVariableDataBlock` (`0xA000_0001`) target (Unicode
///    preferred over ANSI).
/// 3. `StringData` `WorkingDir` + `RelativePath` when neither block is present.
pub fn parse_lnk_target(data: &[u8]) -> Option<String> {
    const HEADER_SIZE: usize = 0x4C;
    const LINK_CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    const HAS_LINK_TARGET_ID_LIST: u32 = 1 << 0;
    const HAS_LINK_INFO: u32 = 1 << 1;
    const HAS_NAME: u32 = 1 << 2;
    const HAS_RELATIVE_PATH: u32 = 1 << 3;
    const HAS_WORKING_DIR: u32 = 1 << 4;
    const HAS_ARGUMENTS: u32 = 1 << 5;
    const HAS_ICON_LOCATION: u32 = 1 << 6;
    const IS_UNICODE: u32 = 1 << 7;
    const ENV_VAR_BLOCK_SIG: u32 = 0xA000_0001;

    fn read_u16(b: &[u8], off: usize) -> Option<u16> {
        let s = b.get(off..off + 2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
    fn read_u32(b: &[u8], off: usize) -> Option<u32> {
        let s = b.get(off..off + 4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn read_cstr_ansi(b: &[u8], off: usize) -> Option<String> {
        let tail = b.get(off..)?;
        let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }
    fn read_cstr_utf16le(b: &[u8], off: usize) -> Option<String> {
        let tail = b.get(off..)?;
        let mut units = Vec::new();
        let mut i = 0;
        while i + 1 < tail.len() {
            let u = u16::from_le_bytes([tail[i], tail[i + 1]]);
            if u == 0 {
                break;
            }
            units.push(u);
            i += 2;
        }
        Some(String::from_utf16_lossy(&units))
    }
    fn join_base_and_suffix(base: String, suffix: Option<String>) -> Option<String> {
        let base = base.trim().to_string();
        if base.is_empty() {
            return None;
        }
        match suffix
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(suf) => {
                if base.ends_with('\\') || suf.starts_with('\\') {
                    Some(format!("{base}{suf}"))
                } else {
                    Some(format!("{base}\\{suf}"))
                }
            }
            None => Some(base),
        }
    }

    if data.len() < HEADER_SIZE {
        return None;
    }
    if read_u32(data, 0)? as usize != HEADER_SIZE {
        return None;
    }
    if data.get(4..20)? != LINK_CLSID {
        return None;
    }
    let flags = read_u32(data, 20)?;
    let mut pos = HEADER_SIZE;

    // 1. Optional LinkTargetIDList
    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        let id_list_size = read_u16(data, pos)? as usize;
        pos = pos.checked_add(2)?.checked_add(id_list_size)?;
        if pos > data.len() {
            return None;
        }
    }

    // 2. Optional LinkInfo
    if flags & HAS_LINK_INFO != 0 {
        let info_size = read_u32(data, pos)? as usize;
        if info_size < 28 || pos.checked_add(info_size)? > data.len() {
            return None;
        }
        let info = &data[pos..pos + info_size];
        let info_hdr_size = read_u32(info, 4)? as usize;
        let info_flags = read_u32(info, 8)?;
        if info_flags & 0x01 != 0 {
            let local_base_off = read_u32(info, 16)? as usize;
            let suffix_off = read_u32(info, 24)? as usize;
            if info_hdr_size >= 0x24 {
                let local_base_u = read_u32(info, 28)? as usize;
                let suffix_u = read_u32(info, 32)? as usize;
                if local_base_u != 0
                    && let Some(base) = read_cstr_utf16le(info, local_base_u)
                {
                    let suf = (suffix_u != 0)
                        .then(|| read_cstr_utf16le(info, suffix_u))
                        .flatten();
                    if let Some(full) = join_base_and_suffix(base, suf) {
                        return Some(full);
                    }
                }
            }
            if local_base_off != 0
                && let Some(base) = read_cstr_ansi(info, local_base_off)
            {
                let suf = (suffix_off != 0)
                    .then(|| read_cstr_ansi(info, suffix_off))
                    .flatten();
                if let Some(full) = join_base_and_suffix(base, suf) {
                    return Some(full);
                }
            }
        }
        pos += info_size;
    }

    // 3. Optional StringData (strict MS-SHLLINK field order)
    let is_unicode = flags & IS_UNICODE != 0;
    let read_string_data = |pos: &mut usize| -> Option<String> {
        let count = read_u16(data, *pos)? as usize;
        *pos += 2;
        if is_unicode {
            let bytes = count.checked_mul(2)?;
            let slice = data.get(*pos..pos.checked_add(bytes)?)?;
            *pos += bytes;
            let units: Vec<u16> = slice
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        } else {
            let slice = data.get(*pos..pos.checked_add(count)?)?;
            *pos += count;
            Some(String::from_utf8_lossy(slice).into_owned())
        }
    };

    if flags & HAS_NAME != 0 {
        let _ = read_string_data(&mut pos)?;
    }
    let relative_path = if flags & HAS_RELATIVE_PATH != 0 {
        Some(read_string_data(&mut pos)?)
    } else {
        None
    };
    let working_dir = if flags & HAS_WORKING_DIR != 0 {
        Some(read_string_data(&mut pos)?)
    } else {
        None
    };
    if flags & HAS_ARGUMENTS != 0 {
        let _ = read_string_data(&mut pos)?;
    }
    if flags & HAS_ICON_LOCATION != 0 {
        let _ = read_string_data(&mut pos)?;
    }

    // 4. Optional ExtraData blocks (EnvironmentVariableDataBlock 0xA000_0001)
    while pos + 4 <= data.len() {
        let block_size = read_u32(data, pos)? as usize;
        if block_size < 4 {
            break;
        }
        if pos
            .checked_add(block_size)
            .is_none_or(|end| end > data.len())
        {
            break;
        }
        if block_size >= 8 {
            let sig = read_u32(data, pos + 4)?;
            if sig == ENV_VAR_BLOCK_SIG && block_size >= 8 + 260 + 520 {
                let block = &data[pos..pos + block_size];
                if let Some(u) = read_cstr_utf16le(block, 8 + 260) {
                    let trimmed = u.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
                if let Some(a) = read_cstr_ansi(block, 8) {
                    let trimmed = a.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
        pos += block_size;
    }

    // 5. Fallback: WorkingDir + non-traversing RelativePath.
    if let (Some(wd), Some(rel)) = (working_dir, relative_path) {
        let wd = wd.trim().trim_end_matches(['\\', '/']);
        let rel = rel
            .trim()
            .trim_start_matches(".\\")
            .trim_start_matches("./");
        if !wd.is_empty() && !rel.is_empty() && !rel.contains("..") {
            return Some(format!("{wd}\\{rel}"));
        }
    }

    None
}

/// Inspect a user's Start-menu `.lnk` shortcuts under `roaming_app_data`
/// (`<AppData>\Microsoft\Windows\Start Menu\Programs\...`) and retire any
/// whose MS-SHLLINK target points inside the per-user companion folder
/// (`%LOCALAPPDATA%\Programs\MeshHarbor\...`).
///
/// Never removes shortcuts pointing to Program Files or anywhere else, never
/// follows symlinks, and never touches user data under `%LOCALAPPDATA%\meshharbor\...`.
/// Prunes the `Start Menu\Programs\MeshHarbor` subfolder only when empty.
/// Returns the paths retired (or that would be retired when `dry_run` is true).
pub fn retire_stale_user_start_menu_shortcuts(
    roaming_app_data: &Path,
    local_app_data: Option<&Path>,
    dry_run: bool,
) -> Vec<PathBuf> {
    let programs = roaming_app_data
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs");
    let meshharbor_dir = programs.join("MeshHarbor");
    let candidates = [
        meshharbor_dir.join("MeshHarbor.lnk"),
        programs.join("MeshHarbor.lnk"),
    ];

    let is_symlink = |p: &Path| {
        std::fs::symlink_metadata(p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    };

    let mut retired = Vec::new();
    for candidate in candidates {
        if is_symlink(&candidate) {
            continue;
        }
        if candidate.parent().is_some_and(&is_symlink) {
            continue;
        }
        if !candidate.is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&candidate) else {
            continue;
        };
        let Some(target) = parse_lnk_target(&bytes) else {
            continue;
        };
        if !should_retire_user_shortcut_target(&target, local_app_data) {
            continue;
        }
        if dry_run || std::fs::remove_file(&candidate).is_ok() {
            retired.push(candidate);
        }
    }

    if !dry_run && !retired.is_empty() && !is_symlink(&meshharbor_dir) && meshharbor_dir.is_dir() {
        // Non-recursive: succeeds only if the subfolder is completely empty.
        let _ = std::fs::remove_dir(&meshharbor_dir);
    }

    retired
}

/// The per-user XDG autostart directory: `$XDG_CONFIG_HOME/autostart` when
/// that is set to an absolute path (the spec ignores a relative one), else
/// `~/.config/autostart`.
pub fn xdg_user_autostart_dir(
    xdg_config_home: Option<&str>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    // XDG is a POSIX spec: "absolute" means a leading `/`, whatever the
    // platform running the test thinks.
    if let Some(cfg) = xdg_config_home.filter(|c| c.starts_with('/')) {
        return Some(PathBuf::from(format!(
            "{}/autostart",
            cfg.trim_end_matches('/')
        )));
    }
    home.map(|h| PathBuf::from(format!("{}/.config/autostart", h.display())))
}

/// Does this desktop entry carry `Hidden=true` in its `[Desktop Entry]`
/// group? That is the XDG way to switch a system autostart entry off for
/// one user.
pub fn xdg_entry_hidden(content: &str) -> bool {
    let mut in_entry = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == "Hidden"
        {
            return v.trim().eq_ignore_ascii_case("true");
        }
    }
    false
}

/// A per-user autostart entry for the companion at `exe`, switched off
/// (`Hidden=true`) or on. Marked `X-MeshHarbor-Managed=true` so the companion
/// knows the file is its own to rewrite or delete.
pub fn xdg_user_entry(exe: &str, hidden: bool) -> String {
    // The Exec key quotes an argument with a space in double quotes.
    let exec = if exe.contains(' ') {
        format!("\"{exe}\"")
    } else {
        exe.to_string()
    };
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=MeshHarbor\n\
         Comment=Start the MeshHarbor companion at login\n\
         Exec={exec} {AUTOSTART_ARG}\n\
         Icon=meshharbor-desktop\n\
         Terminal=false\n\
         X-GNOME-Autostart-Phase=Applications\n\
         X-GNOME-Autostart-Delay=5\n\
         X-MeshHarbor-Managed=true\n\
         Hidden={hidden}\n"
    )
}

/// Registry access for the Run value. Windows-only; every call takes the
/// subkey so tests can point it at a scratch key.
#[cfg(windows)]
pub mod registry {
    use super::RunKeyAction;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, REG_SZ, RRF_RT_REG_SZ,
        RegDeleteKeyValueW, RegEnumKeyExW, RegGetValueW, RegSetKeyValueW,
    };

    /// Which hive.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Hive {
        LocalMachine,
        CurrentUser,
    }

    impl Hive {
        fn hkey(self) -> HKEY {
            match self {
                Hive::LocalMachine => HKEY_LOCAL_MACHINE,
                Hive::CurrentUser => HKEY_CURRENT_USER,
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn os_err(code: u32) -> std::io::Error {
        std::io::Error::from_raw_os_error(code as i32)
    }

    fn read_value_from_hkey(
        root: HKEY,
        subkey: &str,
        name: &str,
    ) -> std::io::Result<Option<String>> {
        let (k, n) = (wide(subkey), wide(name));
        let mut bytes: u32 = 0;
        // SAFETY: a size query — null data pointer, valid out-param.
        let rc = unsafe {
            RegGetValueW(
                root,
                k.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if rc != ERROR_SUCCESS {
            return Err(os_err(rc));
        }
        let mut buf = vec![0u16; (bytes as usize).div_ceil(2).max(1)];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: `buf` holds `len` bytes; RegGetValueW NUL-terminates.
        let rc = unsafe {
            RegGetValueW(
                root,
                k.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if rc != ERROR_SUCCESS {
            return Err(os_err(rc));
        }
        let chars = (len as usize / 2).min(buf.len());
        let end = buf[..chars].iter().position(|&c| c == 0).unwrap_or(chars);
        Ok(Some(String::from_utf16_lossy(&buf[..end])))
    }

    fn delete_value_from_hkey(root: HKEY, subkey: &str, name: &str) -> std::io::Result<bool> {
        let (k, n) = (wide(subkey), wide(name));
        // SAFETY: NUL-terminated wide buffers.
        let rc = unsafe { RegDeleteKeyValueW(root, k.as_ptr(), n.as_ptr()) };
        match rc {
            ERROR_SUCCESS => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            other => Err(os_err(other)),
        }
    }

    /// Read a `REG_SZ` value; `Ok(None)` when the key or the value is absent.
    pub fn read_value(hive: Hive, subkey: &str, name: &str) -> std::io::Result<Option<String>> {
        read_value_from_hkey(hive.hkey(), subkey, name)
    }

    /// Write a `REG_SZ` value, creating the key when needed.
    pub fn write_value(hive: Hive, subkey: &str, name: &str, data: &str) -> std::io::Result<()> {
        let (k, n, d) = (wide(subkey), wide(name), wide(data));
        // SAFETY: NUL-terminated wide buffers; size in bytes includes the NUL.
        let rc = unsafe {
            RegSetKeyValueW(
                hive.hkey(),
                k.as_ptr(),
                n.as_ptr(),
                REG_SZ,
                d.as_ptr().cast(),
                (d.len() * 2) as u32,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(os_err(rc));
        }
        Ok(())
    }

    /// Delete a value; `Ok(false)` when there was nothing to delete.
    pub fn delete_value(hive: Hive, subkey: &str, name: &str) -> std::io::Result<bool> {
        delete_value_from_hkey(hive.hkey(), subkey, name)
    }

    /// Bring the value at `subkey\name` to `desired` (`None` = absent) and
    /// say what was done.
    pub fn sync_value(
        hive: Hive,
        subkey: &str,
        name: &str,
        desired: Option<&str>,
    ) -> std::io::Result<RunKeyAction> {
        let current = read_value(hive, subkey, name)?;
        let action = super::plan_run_key(current.as_deref(), desired);
        match &action {
            RunKeyAction::Keep => {}
            RunKeyAction::Write(data) => write_value(hive, subkey, name, data)?,
            RunKeyAction::Remove => {
                delete_value(hive, subkey, name)?;
            }
        }
        Ok(action)
    }

    /// Read `WINDOWS_RUN_VALUE_NAME` under `HKCU\<subkey>` and delete it ONLY
    /// when [`super::should_retire_hkcu_run_value`] says it points inside the
    /// per-user companion folder (`%LOCALAPPDATA%\Programs\MeshHarbor\...`).
    /// Never removes entries pointing to Program Files or anywhere else.
    pub fn retire_per_user_run_value_in_hkcu(
        subkey: &str,
        local_app_data: Option<&Path>,
    ) -> std::io::Result<bool> {
        let current = read_value(Hive::CurrentUser, subkey, super::WINDOWS_RUN_VALUE_NAME)?;
        if !super::should_retire_hkcu_run_value(current.as_deref(), local_app_data) {
            return Ok(false);
        }
        delete_value(Hive::CurrentUser, subkey, super::WINDOWS_RUN_VALUE_NAME)
    }

    fn loaded_user_sids() -> Vec<String> {
        let mut sids = Vec::new();
        let mut index = 0u32;
        loop {
            let mut buf = vec![0u16; 256];
            let mut len = buf.len() as u32;
            // SAFETY: `HKEY_USERS` is a predefined open handle; `buf` holds `len`
            // wide chars; remaining optional out-params are null per Win32 docs.
            let rc = unsafe {
                RegEnumKeyExW(
                    HKEY_USERS,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                index += 1;
                if index > 4096 {
                    break;
                }
                continue;
            }
            let sid = String::from_utf16_lossy(&buf[..len as usize]);
            if super::is_user_profile_sid_hive(&sid) {
                sids.push(sid);
            }
            index += 1;
        }
        sids
    }

    /// Read-only inspection counterpart of [`retire_per_user_run_values_in_loaded_hku`]
    /// for `--dry-run` reporting.
    pub fn find_per_user_run_values_in_loaded_hku(subkey: &str) -> Vec<String> {
        let mut matches = Vec::new();
        for sid in loaded_user_sids() {
            let user_subkey = format!(r"{sid}\{subkey}");
            let Ok(current) =
                read_value_from_hkey(HKEY_USERS, &user_subkey, super::WINDOWS_RUN_VALUE_NAME)
            else {
                continue;
            };
            if super::should_retire_hkcu_run_value(current.as_deref(), None) {
                matches.push(format!(
                    r"HKU\{user_subkey}\{}",
                    super::WINDOWS_RUN_VALUE_NAME
                ));
            }
        }
        matches
    }

    /// Enumerate loaded user hives under `HKEY_USERS\<SID>` (skipping
    /// `.DEFAULT`, `*_Classes`, and built-in service SIDs) when running as
    /// SYSTEM in a perMachine SCM service or MSI custom action, and delete
    /// `<SID>\<subkey>\MeshHarbor Desktop` ONLY when its command points inside
    /// `\AppData\Local\Programs\MeshHarbor\` (or `%LOCALAPPDATA%\Programs\MeshHarbor\`).
    /// Returns descriptions of the retired registry values.
    pub fn retire_per_user_run_values_in_loaded_hku(subkey: &str) -> Vec<String> {
        let mut retired = Vec::new();
        for sid in loaded_user_sids() {
            let user_subkey = format!(r"{sid}\{subkey}");
            let Ok(current) =
                read_value_from_hkey(HKEY_USERS, &user_subkey, super::WINDOWS_RUN_VALUE_NAME)
            else {
                continue;
            };
            if !super::should_retire_hkcu_run_value(current.as_deref(), None) {
                continue;
            }
            if matches!(
                delete_value_from_hkey(HKEY_USERS, &user_subkey, super::WINDOWS_RUN_VALUE_NAME),
                Ok(true)
            ) {
                retired.push(format!(
                    r"HKU\{user_subkey}\{}",
                    super::WINDOWS_RUN_VALUE_NAME
                ));
            }
        }
        retired
    }

    /// Test-only: remove a scratch key and everything under it.
    #[cfg(test)]
    pub(crate) fn delete_tree(hive: Hive, subkey: &str) {
        use windows_sys::Win32::System::Registry::RegDeleteTreeW;
        // Refuse anything that is not a scratch key: this must never be able
        // to take a real key with it.
        assert!(subkey.starts_with(r"Software\MeshHarborTest\"), "{subkey}");
        let k = wide(subkey);
        // SAFETY: NUL-terminated wide buffer; absent key is a no-op error.
        unsafe { RegDeleteTreeW(hive.hkey(), k.as_ptr()) };
        // And the (empty) scratch parent — `RegDeleteKeyW` refuses a key that
        // still has subkeys, so a concurrent test's key is never touched.
        let parent = wide(r"Software\MeshHarborTest");
        // SAFETY: as above.
        unsafe {
            windows_sys::Win32::System::Registry::RegDeleteKeyW(hive.hkey(), parent.as_ptr())
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_command_quotes_a_path_with_spaces() {
        let exe = Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe");
        assert_eq!(
            windows_run_command(exe),
            r#""C:\Program Files\MeshHarbor\meshharbor-desktop.exe" --autostart"#
        );
        // Quoted even without a space: one shape, so a comparison with what
        // is in the registry never flips on the install path.
        assert_eq!(
            windows_run_command(Path::new(r"D:\r\meshharbor-desktop.exe")),
            r#""D:\r\meshharbor-desktop.exe" --autostart"#
        );
    }

    #[test]
    fn desired_value_table() {
        let exe = Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe");
        let on = Some(windows_run_command(exe));
        // (device_enabled, exe_exists, user_opted_out) → desired
        let table = [
            ((true, true, false), on.clone()),
            ((true, true, true), None), // a person switched it off (HKCU)
            ((true, false, false), None), // daemon-only install / -SkipDesktop
            ((false, true, false), None), // the device kill switch
            ((false, false, true), None),
        ];
        for ((device, exists, opted_out), want) in table {
            assert_eq!(
                desired_run_value(device, exe, exists, opted_out),
                want,
                "device={device} exists={exists} opted_out={opted_out}"
            );
        }
    }

    #[test]
    fn plan_table() {
        use RunKeyAction::*;
        let v = r#""C:\x\meshharbor-desktop.exe" --autostart"#;
        assert_eq!(plan_run_key(None, None), Keep);
        assert_eq!(plan_run_key(Some(v), Some(v)), Keep);
        assert_eq!(plan_run_key(None, Some(v)), Write(v.to_string()));
        assert_eq!(
            plan_run_key(
                Some(r#""C:\old\meshharbor-desktop.exe" --autostart"#),
                Some(v)
            ),
            Write(v.to_string()),
            "a moved install rewrites the value"
        );
        assert_eq!(plan_run_key(Some(v), None), Remove);
    }

    #[test]
    fn scope_follows_program_files() {
        let pf = [
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];
        assert_eq!(
            windows_scope_for_exe(
                Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe"),
                &pf
            ),
            InstallScope::Machine
        );
        assert_eq!(
            windows_scope_for_exe(
                Path::new(r"c:/program files/MESHHARBOR/meshharbor-desktop.exe"),
                &pf
            ),
            InstallScope::Machine,
            "case and slash direction do not matter"
        );
        assert_eq!(
            windows_scope_for_exe(
                Path::new(r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe"),
                &pf
            ),
            InstallScope::User
        );
        assert_eq!(
            windows_scope_for_exe(
                Path::new(r"C:\Program Files Extra\meshharbor-desktop.exe"),
                &pf
            ),
            InstallScope::User,
            "a sibling directory that merely starts with the same letters is not inside it"
        );
        assert_eq!(
            windows_scope_for_exe(
                Path::new(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe"),
                &[]
            ),
            InstallScope::User,
            "no Program Files root known ⇒ per-user, never a guess at HKLM"
        );
    }

    #[test]
    fn xdg_dir_honours_an_absolute_config_home_only() {
        let home = Path::new("/home/ana");
        assert_eq!(
            xdg_user_autostart_dir(Some("/cfg"), Some(home)),
            Some(PathBuf::from("/cfg/autostart"))
        );
        assert_eq!(
            xdg_user_autostart_dir(Some("relative/cfg"), Some(home)),
            Some(PathBuf::from("/home/ana/.config/autostart")),
            "the XDG spec says a relative XDG_CONFIG_HOME is ignored"
        );
        assert_eq!(
            xdg_user_autostart_dir(None, Some(home)),
            Some(PathBuf::from("/home/ana/.config/autostart"))
        );
        assert_eq!(xdg_user_autostart_dir(Some(""), None), None);
    }

    #[test]
    fn hidden_is_read_from_the_desktop_entry_group_only() {
        assert!(xdg_entry_hidden(
            "[Desktop Entry]\nName=MeshHarbor\nHidden=true\n"
        ));
        assert!(xdg_entry_hidden("[Desktop Entry]\nHidden = True\n"));
        assert!(!xdg_entry_hidden("[Desktop Entry]\nHidden=false\n"));
        assert!(!xdg_entry_hidden("[Desktop Entry]\nName=MeshHarbor\n"));
        assert!(
            !xdg_entry_hidden("[Desktop Entry]\nName=R\n[Desktop Action x]\nHidden=true\n"),
            "a key in another group does not hide the entry"
        );
        assert!(!xdg_entry_hidden("# Hidden=true\n[Desktop Entry]\n"));
    }

    #[test]
    fn user_entry_round_trips_through_the_parser() {
        let off = xdg_user_entry("/usr/bin/meshharbor-desktop", true);
        assert!(off.starts_with("[Desktop Entry]\n"), "{off}");
        assert!(
            off.contains("Exec=/usr/bin/meshharbor-desktop --autostart\n"),
            "{off}"
        );
        assert!(off.contains("X-MeshHarbor-Managed=true\n"), "{off}");
        assert!(xdg_entry_hidden(&off));
        let on = xdg_user_entry("/usr/bin/meshharbor-desktop", false);
        assert!(!xdg_entry_hidden(&on));
        let spaced = xdg_user_entry("/opt/My Apps/meshharbor-desktop", false);
        assert!(
            spaced.contains("Exec=\"/opt/My Apps/meshharbor-desktop\" --autostart\n"),
            "{spaced}"
        );
    }

    /// The registry round trip against a SCRATCH key under HKCU — never the
    /// real Run key — cleaned up before and after.
    #[cfg(windows)]
    #[test]
    fn registry_sync_round_trip_on_a_scratch_key() {
        use registry::{Hive, delete_tree, read_value, sync_value};
        let scratch = format!(
            r"Software\MeshHarborTest\companion-autostart-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        delete_tree(Hive::CurrentUser, &scratch);
        let v = windows_run_command(Path::new(
            r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe",
        ));

        assert_eq!(
            read_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME).unwrap(),
            None
        );
        assert_eq!(
            sync_value(
                Hive::CurrentUser,
                &scratch,
                WINDOWS_RUN_VALUE_NAME,
                Some(&v)
            )
            .unwrap(),
            RunKeyAction::Write(v.clone())
        );
        assert_eq!(
            read_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME).unwrap(),
            Some(v.clone())
        );
        assert_eq!(
            sync_value(
                Hive::CurrentUser,
                &scratch,
                WINDOWS_RUN_VALUE_NAME,
                Some(&v)
            )
            .unwrap(),
            RunKeyAction::Keep,
            "idempotent"
        );
        assert_eq!(
            sync_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME, None).unwrap(),
            RunKeyAction::Remove
        );
        assert_eq!(
            read_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME).unwrap(),
            None
        );
        assert_eq!(
            sync_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME, None).unwrap(),
            RunKeyAction::Keep,
            "removing an absent value is a no-op, not an error"
        );
        delete_tree(Hive::CurrentUser, &scratch);
    }

    #[test]
    fn extract_run_command_exe_handles_quoted_unquoted_and_malformed() {
        assert_eq!(
            extract_run_command_exe(
                r#""C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe" --autostart"#
            ),
            Some(r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe")
        );
        assert_eq!(
            extract_run_command_exe(
                r#"  "C:\Program Files\MeshHarbor\meshharbor-desktop.exe" --autostart  "#
            ),
            Some(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe")
        );
        assert_eq!(
            extract_run_command_exe(
                r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe --autostart"
            ),
            Some(r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe")
        );
        assert_eq!(
            extract_run_command_exe(
                r"C:\Users\Jane Doe\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe --autostart"
            ),
            Some(r"C:\Users\Jane Doe\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe")
        );
        assert_eq!(
            extract_run_command_exe(
                r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe"
            ),
            Some(r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe")
        );
        assert_eq!(extract_run_command_exe(""), None);
        assert_eq!(extract_run_command_exe("   "), None);
        assert_eq!(extract_run_command_exe(r#""""#), None);
        assert_eq!(extract_run_command_exe(r#""unterminated"#), None);
    }

    #[test]
    fn per_user_companion_path_matches_only_per_user_programs_dir() {
        let lad = Some(Path::new(r"C:\Users\ana\AppData\Local"));
        // Positive cases: quoted/unquoted, mixed slashes, mixed case, verbatim prefix, redirected LAD.
        for positive in [
            r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe",
            r#""C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe" --autostart"#,
            r"c:/users/ANA/appdata/local/programs/meshharbor/MESHHARBOR-DESKTOP.EXE",
            r"\\?\C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe",
            r"C:\Users\Jane Doe\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe --autostart",
            r"C:\Users\other\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe",
            r"%LOCALAPPDATA%\Programs\MeshHarbor\meshharbor-desktop.exe",
        ] {
            assert!(
                is_per_user_companion_path(positive, lad),
                "expected match for {positive}"
            );
            assert!(
                is_per_user_companion_path(positive, None),
                "expected match without LOCALAPPDATA for {positive}"
            );
        }

        // Redirected LocalAppData outside AppData\Local matches only when local_app_data is supplied.
        let redirected_lad = Some(Path::new(r"D:\Profiles\ana\LocalData"));
        let redirected_exe =
            r"D:\Profiles\ana\LocalData\Programs\MeshHarbor\meshharbor-desktop.exe";
        assert!(is_per_user_companion_path(redirected_exe, redirected_lad));
        assert!(!is_per_user_companion_path(redirected_exe, None));

        // Negative cases: Program Files, sibling folder names, USER DATA, bare folder, traversal.
        for negative in [
            r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe",
            r#""C:\Program Files\MeshHarbor\meshharbor-desktop.exe" --autostart"#,
            r"C:\Program Files (x86)\MeshHarbor\meshharbor-desktop.exe",
            r"C:\Users\ana\AppData\Local\Programs\MeshHarborOther\meshharbor-desktop.exe",
            r"C:\Users\ana\AppData\Local\meshharbor\meshharbor\config.toml",
            r"C:\Users\ana\AppData\Local\meshharbor\desktop\desktop-state.json",
            r"C:\Users\ana\AppData\Roaming\meshharbor\meshharbor\config.toml",
            r"C:\Users\ana\AppData\Local\Programs\MeshHarbor",
            r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\..\Other\meshharbor-desktop.exe",
            r"C:\Program Files\Fake\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe",
            r"C:\Tools\meshharbor-desktop.exe",
            "",
            "   ",
        ] {
            assert!(
                !is_per_user_companion_path(negative, lad),
                "must NEVER match {negative}"
            );
            assert!(
                !is_per_user_companion_path(negative, None),
                "must NEVER match (no LAD) {negative}"
            );
        }
    }

    #[test]
    fn retire_run_value_and_shortcut_decisions() {
        let lad = Some(Path::new(r"C:\Users\ana\AppData\Local"));
        assert!(!should_retire_hkcu_run_value(None, lad));
        assert!(should_retire_hkcu_run_value(
            Some(
                r#""C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe" --autostart"#
            ),
            lad
        ));
        assert!(!should_retire_hkcu_run_value(
            Some(r#""C:\Program Files\MeshHarbor\meshharbor-desktop.exe" --autostart"#),
            lad
        ));
        assert!(should_retire_user_shortcut_target(
            r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe",
            lad
        ));
        assert!(!should_retire_user_shortcut_target(
            r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe",
            lad
        ));
        assert!(!should_retire_user_shortcut_target(
            r"C:\Users\ana\AppData\Local\meshharbor\desktop\desktop-state.json",
            lad
        ));
    }

    #[test]
    fn user_profile_sid_hive_filter_skips_system_and_classes() {
        assert!(is_user_profile_sid_hive("S-1-5-21-123456789-1000"));
        assert!(is_user_profile_sid_hive("S-1-12-1-987654321-1001"));
        assert!(!is_user_profile_sid_hive(".DEFAULT"));
        assert!(!is_user_profile_sid_hive("S-1-5-21-123456789-1000_Classes"));
        assert!(!is_user_profile_sid_hive("S-1-5-18"));
        assert!(!is_user_profile_sid_hive("S-1-5-19"));
        assert!(!is_user_profile_sid_hive("S-1-5-20"));
        assert!(!is_user_profile_sid_hive(""));
    }

    /// Build a synthetic MS-SHLLINK `.lnk` payload with a `LinkInfo` local base
    /// path (ANSI or Unicode) for cross-platform parser unit tests.
    fn synthetic_lnk_link_info(local_base: &str, unicode: bool) -> Vec<u8> {
        let mut out = vec![0u8; 0x4C];
        out[0..4].copy_from_slice(&(0x4Cu32).to_le_bytes());
        out[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        // HAS_LINK_INFO (0x02)
        out[20..24].copy_from_slice(&0x02u32.to_le_bytes());

        let hdr_size: u32 = if unicode { 0x24 } else { 0x1C };
        let mut info = vec![0u8; hdr_size as usize];
        info[4..8].copy_from_slice(&hdr_size.to_le_bytes());
        info[8..12].copy_from_slice(&0x01u32.to_le_bytes()); // VolumeIDAndLocalBasePath

        // Minimal 16-byte VolumeID placeholder.
        let vol_off = info.len() as u32;
        info[12..16].copy_from_slice(&vol_off.to_le_bytes());
        info.extend_from_slice(&16u32.to_le_bytes());
        info.extend_from_slice(&[0u8; 12]);

        let ansi_off = info.len() as u32;
        info[16..20].copy_from_slice(&ansi_off.to_le_bytes());
        if unicode {
            // Put a dummy ANSI placeholder so the test proves Unicode wins.
            info.extend_from_slice(b"C:\\Fallback\\wrong.exe\0");
        } else {
            info.extend_from_slice(local_base.as_bytes());
            info.push(0);
        }

        let suffix_off = info.len() as u32;
        info[24..28].copy_from_slice(&suffix_off.to_le_bytes());
        info.push(0);

        if unicode {
            let uni_off = info.len() as u32;
            info[28..32].copy_from_slice(&uni_off.to_le_bytes());
            for u in local_base.encode_utf16().chain(std::iter::once(0)) {
                info.extend_from_slice(&u.to_le_bytes());
            }
            let uni_suf_off = info.len() as u32;
            info[32..36].copy_from_slice(&uni_suf_off.to_le_bytes());
            info.extend_from_slice(&0u16.to_le_bytes());
        }

        let total = info.len() as u32;
        info[0..4].copy_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&info);
        out
    }

    /// Build a synthetic MS-SHLLINK `.lnk` using an `EnvironmentVariableDataBlock`
    /// (`0xA000_0001`) without `LinkInfo`.
    fn synthetic_lnk_env_block(target: &str) -> Vec<u8> {
        let mut out = vec![0u8; 0x4C];
        out[0..4].copy_from_slice(&(0x4Cu32).to_le_bytes());
        out[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        // HAS_EXP_STRING (0x200)
        out[20..24].copy_from_slice(&0x200u32.to_le_bytes());

        let mut block = vec![0u8; 0x314];
        block[0..4].copy_from_slice(&(0x314u32).to_le_bytes());
        block[4..8].copy_from_slice(&0xA000_0001u32.to_le_bytes());
        let ansi = target.as_bytes();
        let copy_len = ansi.len().min(259);
        block[8..8 + copy_len].copy_from_slice(&ansi[..copy_len]);
        for (idx, u) in target.encode_utf16().take(259).enumerate() {
            let pos = 8 + 260 + idx * 2;
            block[pos..pos + 2].copy_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&block);
        out.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
        out
    }

    #[test]
    fn parse_lnk_target_handles_ansi_unicode_env_block_and_rejects_junk() {
        let user_exe = r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe";
        let pf_exe = r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe";
        let env_exe = r"%LOCALAPPDATA%\Programs\MeshHarbor\meshharbor-desktop.exe";

        assert_eq!(
            parse_lnk_target(&synthetic_lnk_link_info(user_exe, false)).as_deref(),
            Some(user_exe)
        );
        assert_eq!(
            parse_lnk_target(&synthetic_lnk_link_info(pf_exe, true)).as_deref(),
            Some(pf_exe)
        );
        assert_eq!(
            parse_lnk_target(&synthetic_lnk_env_block(env_exe)).as_deref(),
            Some(env_exe)
        );
        assert_eq!(parse_lnk_target(b""), None);
        assert_eq!(parse_lnk_target(b"not a shortcut"), None);
    }

    #[test]
    fn retire_stale_start_menu_shortcuts_removes_only_per_user_and_preserves_program_files_and_data()
     {
        let tmp = tempfile::tempdir().unwrap();
        let roaming = tmp.path().join("AppData").join("Roaming");
        let local = tmp.path().join("AppData").join("Local");
        let programs = roaming
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs");
        let mh_dir = programs.join("MeshHarbor");
        std::fs::create_dir_all(&mh_dir).unwrap();

        // User data that must NEVER be touched.
        let user_data = local
            .join("meshharbor")
            .join("desktop")
            .join("desktop-state.json");
        std::fs::create_dir_all(user_data.parent().unwrap()).unwrap();
        std::fs::write(&user_data, r#"{"first_run_done":true}"#).unwrap();

        let stale_lnk = mh_dir.join("MeshHarbor.lnk");
        let pf_lnk = programs.join("MeshHarbor.lnk");
        std::fs::write(
            &stale_lnk,
            synthetic_lnk_link_info(
                r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe",
                true,
            ),
        )
        .unwrap();
        std::fs::write(
            &pf_lnk,
            synthetic_lnk_link_info(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe", false),
        )
        .unwrap();

        // Dry-run reports the stale shortcut without deleting it.
        let planned = retire_stale_user_start_menu_shortcuts(&roaming, Some(&local), true);
        assert_eq!(planned, vec![stale_lnk.clone()]);
        assert!(stale_lnk.exists());

        // Real run removes ONLY the stale per-user .lnk and prunes empty MeshHarbor subfolder.
        let removed = retire_stale_user_start_menu_shortcuts(&roaming, Some(&local), false);
        assert_eq!(removed, vec![stale_lnk.clone()]);
        assert!(!stale_lnk.exists());
        assert!(
            !mh_dir.exists(),
            "empty Start Menu\\Programs\\MeshHarbor dir should be pruned"
        );
        assert!(
            pf_lnk.exists(),
            "Program Files shortcut must survive untouched"
        );
        assert!(user_data.exists(), "user data must NEVER be deleted");
    }

    #[cfg(windows)]
    #[test]
    fn registry_retire_per_user_run_value_on_scratch_key() {
        use registry::{
            Hive, delete_tree, read_value, retire_per_user_run_value_in_hkcu, write_value,
        };
        let scratch = format!(
            r"Software\MeshHarborTest\retire-per-user-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        delete_tree(Hive::CurrentUser, &scratch);

        let lad = Path::new(r"C:\Users\ana\AppData\Local");
        // Program Files Run value is NEVER retired.
        let pf_cmd = windows_run_command(Path::new(
            r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe",
        ));
        write_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME, &pf_cmd).unwrap();
        assert!(!retire_per_user_run_value_in_hkcu(&scratch, Some(lad)).unwrap());
        assert_eq!(
            read_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME).unwrap(),
            Some(pf_cmd)
        );

        // Stale per-user Run value IS retired.
        let user_cmd = windows_run_command(Path::new(
            r"C:\Users\ana\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe",
        ));
        write_value(
            Hive::CurrentUser,
            &scratch,
            WINDOWS_RUN_VALUE_NAME,
            &user_cmd,
        )
        .unwrap();
        assert!(retire_per_user_run_value_in_hkcu(&scratch, Some(lad)).unwrap());
        assert_eq!(
            read_value(Hive::CurrentUser, &scratch, WINDOWS_RUN_VALUE_NAME).unwrap(),
            None
        );

        // Second call is an idempotent no-op.
        assert!(!retire_per_user_run_value_in_hkcu(&scratch, Some(lad)).unwrap());
        delete_tree(Hive::CurrentUser, &scratch);
    }
}
