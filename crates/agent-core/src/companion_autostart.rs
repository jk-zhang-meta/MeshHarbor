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
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyValueW,
        RegGetValueW, RegSetKeyValueW,
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

    /// Read a `REG_SZ` value; `Ok(None)` when the key or the value is absent.
    pub fn read_value(hive: Hive, subkey: &str, name: &str) -> std::io::Result<Option<String>> {
        let (k, n) = (wide(subkey), wide(name));
        let mut bytes: u32 = 0;
        // SAFETY: a size query — null data pointer, valid out-param.
        let rc = unsafe {
            RegGetValueW(
                hive.hkey(),
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
                hive.hkey(),
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
        let (k, n) = (wide(subkey), wide(name));
        // SAFETY: NUL-terminated wide buffers.
        let rc = unsafe { RegDeleteKeyValueW(hive.hkey(), k.as_ptr(), n.as_ptr()) };
        match rc {
            ERROR_SUCCESS => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            other => Err(os_err(other)),
        }
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
}
