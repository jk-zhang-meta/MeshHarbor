// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #1686 — find a running companion by the file it was STARTED from, never by
//! its image name.
//!
//! On the reporting host an old companion kept running through an update from
//! an image that had been unlinked into `$Extend\$Deleted`. Windows then lists
//! the process under that entry's name — a file reference plus four random
//! bytes, `00240000000AA4A74B077E87` — and `tasklist /FI "IMAGENAME eq
//! meshharbor-desktop.exe"` matches nothing, so every name-based check
//! (`tasklist`, `taskkill /IM`) was blind to it: the refresh logged
//! `respawned=false`, the old companion kept the single-instance lock, and
//! every launch of the new one exited 0. How the running image got unlinked
//! is not reproduced — for an ordinary or elevated caller Windows refuses a
//! delete, a replace-rename and a raw POSIX-disposition delete of a mapped
//! image alike — but the two refreshers racing on that host (the SCM host and
//! the elevated worker, each renaming and deleting the other's files) are in
//! the logs, and a name check has no business deciding either way.
//!
//! The loader's record of the main module does not follow the file: the first
//! entry of the process's module list keeps answering the path the process
//! was started from (`C:\Program Files\MeshHarbor\meshharbor-desktop.exe`) — as WMI's
//! `ExecutablePath` (the PEB's `ImagePathName`) did for that very process.
//! That is the identity used here (see [`loaded_path`] for the one API trap).
//! The image name only pre-filters which processes are worth opening: the
//! companion's own name, a renamed-aside `…exe.old`, or an extension-less
//! `$Deleted` entry name.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, HANDLE, HMODULE, INVALID_HANDLE_VALUE, STILL_ACTIVE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExW};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_READ,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};

/// A running process started from the companion's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompanionProcess {
    pub pid: u32,
    /// Terminal Services session; `None` when the lookup was refused.
    pub session: Option<u32>,
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: we own this handle and close it exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Every running process whose main module was loaded from `exe`
/// (case-insensitive, `\\?\` prefix ignored). The caller's own process is
/// never included. An unreadable process (access denied, protected) is
/// skipped: this answers "which companions can we see", and a companion is an
/// ordinary user-session process every caller of this can open.
pub fn find(exe: &Path) -> Vec<CompanionProcess> {
    let want = normalize(exe);
    let own = std::process::id();
    let file_name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mut out = Vec::new();
    for (pid, image) in snapshot() {
        if pid == own || pid == 0 || !worth_opening(&image, &file_name) {
            continue;
        }
        if let Some(path) = loaded_path(pid)
            && matches_companion_path(&path, &want)
        {
            out.push(CompanionProcess {
                pid,
                session: session_of(pid),
            });
        }
    }
    out
}

fn matches_companion_path(path: &Path, normalized_exe: &str) -> bool {
    let norm = normalize(path);
    norm == normalized_exe || norm == format!("{normalized_exe}.old")
}

struct QuitSentinelGuard(PathBuf);
impl Drop for QuitSentinelGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn verify_handle_matches(h: HANDLE, pid: u32, want: &str) -> bool {
    // Prefer the loader's initial module entry when `PROCESS_VM_READ` is
    // available (immune to later file renames), falling back to
    // `QueryFullProcessImageNameW` on the already-pinned kernel process handle
    // `h` (which matches both `exe` and `exe.old` without PID-reuse races).
    let vm_path = unsafe {
        let h_vm = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if h_vm.is_null() {
            None
        } else {
            let h_vm = OwnedHandle(h_vm);
            started_from(h_vm.0)
        }
    };
    vm_path
        .or_else(|| query_full_image_name(h))
        .is_some_and(|p| matches_companion_path(&p, want))
}

/// Stop each pid that is STILL a process started from `exe`, and wait (up to
/// `timeout` in total) for it to be gone. Returns the pids confirmed exited.
///
/// Primary path (`SYSTEM` service host on perMachine installs, and same-IL
/// per-user installs across all versions): open one handle with
/// `PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`,
/// verify the executable path on that pinned handle, and `TerminateProcess`.
///
/// Cross-integrity fallback (unprivileged Medium-IL per-user daemon vs a
/// companion manually launched elevated at High IL): Windows MIC denies
/// `PROCESS_TERMINATE` and UIPI blocks `WM_COPYDATA` without UAC. Never spawn
/// `exe` with CLI flags (which UIPI drops on elevated receivers and which
/// causes pre-0.4.167 receivers to focus/show their window). Instead, pin each
/// target via `PROCESS_QUERY_LIMITED_INFORMATION`, write a PID-scoped sidecar
/// `<exe>.quit` in the install directory (unaffected by UIPI; watched by
/// 0.4.167+ companions), and poll `GetExitCodeProcess` on the pinned handle. If
/// an elevated pre-0.4.167 companion does not exit within `timeout`, omit it
/// from `gone` so `swap()` aborts cleanly without renaming the live EXE aside.
pub fn terminate_verified(exe: &Path, pids: &[u32], timeout: Duration) -> Vec<u32> {
    let want = normalize(exe);
    let deadline = std::time::Instant::now() + timeout;
    let mut gone = Vec::new();
    let mut cooperative_wait: Vec<(u32, OwnedHandle)> = Vec::new();
    for &pid in pids {
        // SAFETY: plain OpenProcess; the handle is owned below.
        let h = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                pid,
            )
        };
        if !h.is_null() {
            let h = OwnedHandle(h);
            if !verify_handle_matches(h.0, pid, &want) {
                continue;
            }
            // SAFETY: `h` is a live process handle with PROCESS_TERMINATE, just
            // verified to be ours. The exit code (1) marks a kill, distinct from
            // the tray's own clean quit.
            unsafe {
                TerminateProcess(h.0, 1);
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            // SAFETY: `h` has SYNCHRONIZE; the wait is bounded.
            let waited =
                unsafe { WaitForSingleObject(h.0, left.as_millis().min(u32::MAX as u128) as u32) };
            if waited == WAIT_OBJECT_0 {
                gone.push(pid);
            }
            continue;
        }
        let h_lim = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
        if h_lim.is_null() {
            continue;
        }
        let h_lim = OwnedHandle(h_lim);
        if query_full_image_name(h_lim.0).is_some_and(|p| matches_companion_path(&p, &want)) {
            cooperative_wait.push((pid, h_lim));
        }
    }
    if !cooperative_wait.is_empty() {
        let quit_path = PathBuf::from(format!("{}.quit", exe.display()));
        let payload = cooperative_wait
            .iter()
            .map(|(pid, _)| pid.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let _sentinel = std::fs::write(&quit_path, format!("{payload}\n"))
            .ok()
            .map(|()| QuitSentinelGuard(quit_path));
        while !cooperative_wait.is_empty() && std::time::Instant::now() < deadline {
            cooperative_wait.retain(|(pid, h_lim)| {
                let mut code = 0u32;
                // SAFETY: `h_lim` has `PROCESS_QUERY_LIMITED_INFORMATION`.
                let ok = unsafe { GetExitCodeProcess(h_lim.0, &mut code) };
                if ok != 0 && (code as i32) != STILL_ACTIVE {
                    gone.push(*pid);
                    false
                } else {
                    true
                }
            });
            if !cooperative_wait.is_empty() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    gone
}

/// Image names worth opening: the companion's own, a renamed-aside copy
/// (`meshharbor-desktop.exe.old`), and an extension-less name — what Windows
/// reports once the file behind a running image was POSIX-deleted into
/// `$Extend\$Deleted` (a bare file id such as `00240000000AA4A74B077E87`).
pub(crate) fn worth_opening(image: &str, companion_file_name: &str) -> bool {
    let image = image.to_ascii_lowercase();
    image == companion_file_name
        || image.starts_with(companion_file_name)
        || (!image.contains('.') && !image.is_empty())
}

fn snapshot() -> Vec<(u32, String)> {
    // SAFETY: TH32CS_SNAPPROCESS + pid 0 is the documented call form.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let _guard = OwnedHandle(snap);
    // SAFETY: zeroed POD, then the documented dwSize init.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    // SAFETY: `snap` is valid; `entry` lives across the calls.
    if unsafe { Process32FirstW(snap, &mut entry) } == 0 {
        return out;
    }
    loop {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        out.push((
            entry.th32ProcessID,
            String::from_utf16_lossy(&entry.szExeFile[..len]),
        ));
        // SAFETY: as above.
        if unsafe { Process32NextW(snap, &mut entry) } == 0 {
            break;
        }
    }
    out
}

/// The path the process's main module was loaded from — the loader's
/// module-list entry, which a later rename of the file does not change.
///
/// ⚠️ With an EXPLICIT module handle, not `NULL`. Measured after renaming a
/// running image `X.exe` → `X.exe.old`: `K32GetModuleFileNameExW(h, NULL)` and
/// `QueryFullProcessImageNameW` both answer `X.exe.old` (they follow the file),
/// while the first entry of the module list — and WMI's `ExecutablePath`, the
/// PEB's `ImagePathName` — still answer `X.exe`.
fn loaded_path(pid: u32) -> Option<PathBuf> {
    // SAFETY: plain OpenProcess; owned below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
    if !h.is_null() {
        let h = OwnedHandle(h);
        if let Some(p) = started_from(h.0) {
            return Some(p);
        }
    }
    // Fallback for elevated companion processes in the user session where
    // `PROCESS_VM_READ` is denied to a medium-integrity per-user daemon.
    let h_lim = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if h_lim.is_null() {
        return None;
    }
    let h_lim = OwnedHandle(h_lim);
    query_full_image_name(h_lim.0)
}

fn query_full_image_name(h: HANDLE) -> Option<PathBuf> {
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: `h` has at least `PROCESS_QUERY_LIMITED_INFORMATION`; `buf` & `len` valid.
    let ok =
        unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    if ok == 0 || len == 0 {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
}

/// [`loaded_path`] on a handle the caller already holds (with at least
/// `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`).
fn started_from(h: HANDLE) -> Option<PathBuf> {
    // The FIRST module of the list is the executable itself.
    let mut first: HMODULE = std::ptr::null_mut();
    let mut needed = 0u32;
    // SAFETY: `h` has QUERY_INFORMATION|VM_READ (caller's contract); the
    // out-buffer holds one HMODULE and its size is passed; `needed` is a
    // valid out-pointer.
    let ok = unsafe {
        K32EnumProcessModules(
            h,
            &mut first,
            std::mem::size_of::<HMODULE>() as u32,
            &mut needed,
        )
    };
    if ok == 0 || first.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 32_768];
    // SAFETY: `h` as above; `first` is a module of that process; `buf` is
    // sized as passed.
    let n = unsafe { K32GetModuleFileNameExW(h, first, buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(&buf[..n as usize])))
}

fn session_of(pid: u32) -> Option<u32> {
    let mut sid = 0u32;
    // SAFETY: out-pointer valid for the call.
    (unsafe { ProcessIdToSessionId(pid, &mut sid) } != 0).then_some(sid)
}

/// Compare paths the way Windows does: case-insensitively, without the
/// `\\?\` verbatim prefix `canonicalize` adds.
pub(crate) fn normalize(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_companion_its_renamed_copy_or_a_file_id_is_worth_opening() {
        let name = "meshharbor-desktop.exe";
        assert!(worth_opening("meshharbor-desktop.exe", name));
        assert!(worth_opening("MESHHARBOR-DESKTOP.EXE", name));
        assert!(worth_opening("meshharbor-desktop.exe.old", name));
        // A running image whose file was POSIX-deleted (#1686, measured).
        assert!(worth_opening("00240000000AA4A74B077E87", name));
        assert!(!worth_opening("explorer.exe", name));
        assert!(!worth_opening("meshharbord.exe", name));
        assert!(!worth_opening("", name));
    }

    #[test]
    fn paths_compare_like_windows_does() {
        assert_eq!(
            normalize(Path::new(
                r"\\?\C:\Program Files\MeshHarbor\meshharbor-desktop.exe"
            )),
            normalize(Path::new(
                r"c:\program files\meshharbor\MESHHARBOR-DESKTOP.EXE"
            ))
        );
        assert_ne!(
            normalize(Path::new(
                r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe"
            )),
            normalize(Path::new(
                r"C:\Users\x\AppData\Local\Programs\MeshHarbor\meshharbor-desktop.exe"
            ))
        );
    }

    /// #1686: identity by the path a program was STARTED from, and stop by pid.
    /// Start a program from a path, then do to its file what the refresh does
    /// to the companion's — rename it aside — and check `find` still names it,
    /// with its session, and `terminate_verified` stops it.
    ///
    /// What this cannot do is recreate the field state itself. On the reporting
    /// host the old companion ran from an image POSIX-unlinked into
    /// `$Extend\$Deleted` (it was listed as `00240000000AA4A74B077E87`, and
    /// `tasklist /FI "IMAGENAME eq meshharbor-desktop.exe"` matched nothing),
    /// while WMI's `ExecutablePath` — the loader's record `find` reads —
    /// still said `C:\Program Files\MeshHarbor\meshharbor-desktop.exe`. For an
    /// ordinary and an elevated caller Windows refuses every way of unlinking
    /// a running image's file (delete, replace-rename, a raw
    /// `FileDispositionInfoEx` POSIX delete — all measured, err 5), so the
    /// refusals are asserted below as the premise they are: a change in any of
    /// them is news worth failing on.
    #[test]
    fn a_running_program_is_found_by_its_started_from_path_and_stopped_by_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A unique name: a real `meshharbor-desktop.exe` may be running on the
        // machine that runs this test, and must neither match nor be touched.
        let name = format!("fr1686-probe-{}.exe", std::process::id());
        let exe = dir.path().join(&name);
        let system32 = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        std::fs::copy(Path::new(&system32).join(r"System32\cmd.exe"), &exe).expect("copy cmd.exe");
        let mut child = std::process::Command::new(&exe)
            .args(["/c", "ping -n 30 127.0.0.1 > nul"])
            .spawn()
            .expect("spawn the probe");

        let found = find(&exe);
        let me = found.iter().find(|p| p.pid == child.id()).copied();
        let own_session = session_of(std::process::id());

        // The refresh's first move on the companion's file: rename it aside.
        let aside = dir.path().join(format!("{name}.old"));
        std::fs::rename(&exe, &aside).expect("rename a running image aside");
        let found_after_rename = find(&exe).iter().any(|p| p.pid == child.id());
        // A running image's file refuses deletion, and a replace onto it.
        let delete_refused = std::fs::remove_file(&aside).is_err();
        let newer = dir.path().join("newer.bin");
        std::fs::write(&newer, b"the next swap's copy").expect("write the next copy");
        let replace_refused = std::fs::rename(&newer, &aside).is_err();

        let stopped = terminate_verified(&exe, &[child.id()], Duration::from_secs(10));
        let _ = child.kill();
        let _ = child.wait();

        let me = me.expect("found by the path it was started from");
        assert_eq!(
            me.session, own_session,
            "reported in the session it runs in"
        );
        assert!(
            found_after_rename,
            "still found by its started-from path after a rename"
        );
        assert!(
            delete_refused,
            "premise: a running image's file refuses a plain delete"
        );
        assert!(replace_refused, "premise: … and a replace-rename onto it");
        assert_eq!(
            stopped,
            vec![child.id()],
            "stopped by pid, confirmed exited"
        );
        assert!(
            find(&exe).iter().all(|p| p.pid != child.id()),
            "gone once stopped"
        );
    }

    /// The pid-reuse guard: a pid handed to `terminate_verified` that is NOT
    /// (or no longer) a process started from `exe` is left running — the
    /// check and the kill are one handle, so a reused pid cannot be killed on
    /// the strength of what `find` saw earlier.
    #[test]
    fn a_pid_that_does_not_verify_against_the_path_is_left_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let system32 = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let ours = dir
            .path()
            .join(format!("fr1686-ours-{}.exe", std::process::id()));
        let other = dir
            .path()
            .join(format!("fr1686-other-{}.exe", std::process::id()));
        for p in [&ours, &other] {
            std::fs::copy(Path::new(&system32).join(r"System32\cmd.exe"), p).expect("copy cmd.exe");
        }
        let mut bystander = std::process::Command::new(&other)
            .args(["/c", "ping -n 30 127.0.0.1 > nul"])
            .spawn()
            .expect("spawn the bystander");

        // The bystander's pid, claimed to be a process started from `ours`.
        let stopped = terminate_verified(&ours, &[bystander.id()], Duration::from_secs(2));
        let still_running = bystander.try_wait().ok().flatten().is_none();
        let _ = bystander.kill();
        let _ = bystander.wait();

        assert!(
            stopped.is_empty(),
            "nothing it could not verify is counted as stopped"
        );
        assert!(
            still_running,
            "a process started from another path is never killed"
        );
    }
}
