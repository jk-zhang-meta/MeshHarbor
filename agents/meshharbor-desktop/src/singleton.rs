// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Desktop companion singleton version handover.
//!
//! Ensures a newer companion (or a per-machine Program Files companion
//! superseding a stale per-user `%LOCALAPPDATA%\Programs\MeshHarbor` tray)
//! cleanly replaces an older running companion BEFORE
//! `tauri-plugin-single-instance` acquires the OS lock — while older or
//! equal same-scope launches continue to yield cleanly so there are NEVER two
//! trays running at once.
//!
//! Pure semver parsing, handover decisions, and instance-file persistence live
//! in `meshharbor_node_core::companion_handover` so every platform runs their
//! unit tests.

#[cfg(windows)]
use meshharbor_node_core::companion_autostart::{InstallScope, windows_scope_for_exe};
use meshharbor_node_core::companion_autostart::program_files_dirs;
#[cfg(windows)]
use meshharbor_node_core::companion_handover::default_handover_pid_path;
use meshharbor_node_core::companion_handover::{
    CompanionInstanceRecord, HandoverDecision, decide_handover_with_local_app_data,
    default_instance_path, load_instance_from, remove_instance_if_pid, save_instance_to,
};
use std::path::{Path, PathBuf};

/// Run BEFORE `tauri_plugin_single_instance::init` so a newer (or higher-scope
/// Program Files over stale per-user) companion can cleanly replace an older
/// running instance and take over the single-instance lock.
pub fn prepare_takeover(my_version: &str) {
    let Ok(my_exe) = std::env::current_exe() else {
        return;
    };
    let my_pid = std::process::id();
    let pf = program_files_dirs();
    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let instance_path = default_instance_path();

    // Candidate targets: `(pid, expected_exe, came_from_instance_file)`.
    let mut targets: Vec<(u32, PathBuf, bool)> = Vec::new();

    if let Some(ref path) = instance_path
        && let Some(rec) = load_instance_from(path)
        && rec.pid != my_pid
    {
        if is_pid_alive(rec.pid) {
            let running_exe = PathBuf::from(&rec.exe_path);
            let decision = decide_handover_with_local_app_data(
                my_version,
                &my_exe,
                Some(&rec.version),
                Some(running_exe.as_path()),
                &pf,
                local_app_data.as_deref(),
            );
            tracing::info!(
                my_version,
                running_pid = rec.pid,
                running_version = %rec.version,
                ?decision,
                "singleton handover check against companion-instance.json"
            );
            if decision == HandoverDecision::TakeOver {
                targets.push((rec.pid, running_exe, true));
            }
        } else {
            // Stale crash residue — drop only if it still names that dead PID.
            remove_instance_if_pid(path, rec.pid);
        }
    }

    // Windows: also catch legacy pre-T11 companions running out of
    // `%LOCALAPPDATA%\Programs\MeshHarbor\` that never wrote
    // `companion-instance.json`.
    #[cfg(windows)]
    if windows_scope_for_exe(&my_exe, &pf) == InstallScope::Machine {
        for (pid, proc_exe) in
            win_proc::find_per_user_companion_procs(my_pid, local_app_data.as_deref())
        {
            if targets.iter().any(|(existing, _, _)| *existing == pid) {
                continue;
            }
            let decision = decide_handover_with_local_app_data(
                my_version,
                &my_exe,
                None,
                Some(proc_exe.as_path()),
                &pf,
                local_app_data.as_deref(),
            );
            if decision == HandoverDecision::TakeOver {
                tracing::info!(
                    my_version,
                    stale_pid = pid,
                    stale_exe = %proc_exe.display(),
                    "singleton handover taking over from legacy per-user companion"
                );
                targets.push((pid, proc_exe, false));
            }
        }
    }

    for (pid, expected_exe, try_graceful_file) in targets {
        let gone = terminate_older_companion(pid, &expected_exe, try_graceful_file);
        tracing::info!(
            pid,
            gone,
            exe = %expected_exe.display(),
            "singleton handover wait completed"
        );
        if gone && let Some(ref path) = instance_path {
            remove_instance_if_pid(path, pid);
        }
    }
}

/// Persist this companion's live PID, version, and executable path once it owns
/// the OS single-instance lock.
pub fn record_own_instance(my_version: &str) {
    let Some(path) = default_instance_path() else {
        return;
    };
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let rec = CompanionInstanceRecord {
        pid: std::process::id(),
        version: my_version.to_string(),
        exe_path,
    };
    if let Err(e) = save_instance_to(&path, &rec) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "could not write companion-instance.json"
        );
    }
}

/// Remove `companion-instance.json` on clean exit if it still names our PID.
pub fn clear_own_instance_record() {
    if let Some(path) = default_instance_path() {
        remove_instance_if_pid(&path, std::process::id());
    }
}

/// Watch the per-user cooperative handover file (`companion-handover.pid`) on
/// Windows so a T11+ older companion exits cleanly (releasing its tray icon
/// and sending `CompanionBye`) when a newer companion asks to take over.
#[cfg(windows)]
pub async fn handover_watch_loop(app: tauri::AppHandle) {
    let Some(path) = default_handover_pid_path() else {
        return;
    };
    let own_pid = std::process::id();
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Ok(contents) = std::fs::read_to_string(&path)
            && meshharbor_node_core::companion_handover::pid_file_requests_pid(&contents, own_pid)
        {
            tracing::info!(
                pid = own_pid,
                path = %path.display(),
                "meshharbor-desktop observed cooperative handover request; exiting"
            );
            crate::companion_hello::notify_bye_and_exit(&app);
            return;
        }
    }
}

fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        meshharbor_node_core::companion_handover::unix_proc::is_pid_alive(pid)
    }
    #[cfg(windows)]
    {
        win_proc::is_pid_alive(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

fn terminate_older_companion(pid: u32, expected_exe: &Path, try_graceful_file: bool) -> bool {
    #[cfg(unix)]
    {
        let _ = try_graceful_file;
        meshharbor_node_core::companion_handover::unix_proc::terminate_verified_gracefully(
            pid,
            expected_exe,
            std::time::Duration::from_secs(3),
        )
    }
    #[cfg(windows)]
    {
        win_proc::terminate_verified(pid, expected_exe, try_graceful_file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, expected_exe, try_graceful_file);
        false
    }
}

#[cfg(windows)]
mod win_proc {
    use meshharbor_node_core::companion_autostart::is_per_user_companion_path;
    use meshharbor_node_core::companion_handover::default_handover_pid_path;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::{
        CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    };

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: handle owned exclusively by this guard.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct FileRemoveGuard(PathBuf);
    impl Drop for FileRemoveGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn normalize(p: &Path) -> String {
        let s = p.to_string_lossy().replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        s.to_lowercase()
    }

    fn query_full_image_name(h: HANDLE) -> Option<PathBuf> {
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        // SAFETY: `h` has `PROCESS_QUERY_LIMITED_INFORMATION`; buffer is valid.
        let ok = unsafe {
            QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        };
        if ok == 0 || len == 0 {
            return None;
        }
        Some(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
    }

    fn path_matches_expected(actual: &Path, expected: &Path) -> bool {
        let actual_norm = normalize(actual);
        let expected_norm = normalize(expected);
        if expected_norm.is_empty() {
            return actual
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .is_some_and(|n| n.starts_with("meshharbor-desktop.exe"));
        }
        actual_norm == expected_norm || actual_norm == format!("{expected_norm}.old")
    }

    pub fn is_pid_alive(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        // SAFETY: plain OpenProcess; closed by OwnedHandle.
        let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, FALSE, pid) };
        if h.is_null() {
            return false;
        }
        let h = OwnedHandle(h);
        // SAFETY: zero-ms wait tests whether the process object is signaled (exited).
        unsafe { WaitForSingleObject(h.0, 0) != WAIT_OBJECT_0 }
    }

    /// Find running `meshharbor-desktop.exe` processes whose executable path
    /// lives inside `%LOCALAPPDATA%\Programs\MeshHarbor\...`.
    pub fn find_per_user_companion_procs(
        own_pid: u32,
        local_app_data: Option<&Path>,
    ) -> Vec<(u32, PathBuf)> {
        // SAFETY: documented ToolHelp process snapshot call.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let _snap = OwnedHandle(snap);
        // SAFETY: POD struct initialized with dwSize per Win32 docs.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if unsafe { Process32FirstW(snap, &mut entry) } == 0 {
            return Vec::new();
        }
        let mut found = Vec::new();
        loop {
            let pid = entry.th32ProcessID;
            if pid != 0 && pid != own_pid {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let image = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
                if image.starts_with("meshharbor-desktop.exe") {
                    // SAFETY: plain OpenProcess; handle owned below.
                    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
                    if !h.is_null() {
                        let h = OwnedHandle(h);
                        if let Some(path) = query_full_image_name(h.0)
                            && is_per_user_companion_path(&path.to_string_lossy(), local_app_data)
                        {
                            found.push((pid, path));
                        }
                    }
                }
            }
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
        found
    }

    /// Ask a verified older companion PID to exit (cooperatively via the
    /// per-user handover file when `try_graceful_file` is true, then
    /// `TerminateProcess` if still alive) and wait up to 3 s total for exit so
    /// the OS single-instance lock is released before proceeding.
    pub fn terminate_verified(pid: u32, expected_exe: &Path, try_graceful_file: bool) -> bool {
        // SAFETY: pin the process handle before verifying image path so PID
        // reuse cannot race between check and termination.
        let h = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                pid,
            )
        };
        if h.is_null() {
            return !is_pid_alive(pid);
        }
        let h = OwnedHandle(h);
        if !query_full_image_name(h.0)
            .is_some_and(|actual| path_matches_expected(&actual, expected_exe))
        {
            return false;
        }

        let mut remaining_ms: u32 = 3000;
        if try_graceful_file && let Some(handover_path) = default_handover_pid_path() {
            if let Some(parent) = handover_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _guard = std::fs::write(&handover_path, format!("{pid}\n"))
                .ok()
                .map(|()| FileRemoveGuard(handover_path));
            // Give a T11+ companion up to 1 s to exit cleanly (remove tray icon
            // and send CompanionBye) before escalating to TerminateProcess.
            let waited = unsafe { WaitForSingleObject(h.0, 1000) };
            if waited == WAIT_OBJECT_0 {
                return true;
            }
            remaining_ms = 2000;
        }

        // SAFETY: `h` is pinned and verified to be the older companion above.
        unsafe {
            TerminateProcess(h.0, 0);
        }
        // SAFETY: `h` has `PROCESS_SYNCHRONIZE`; wait is bounded.
        unsafe { WaitForSingleObject(h.0, remaining_ms) == WAIT_OBJECT_0 }
    }
}
