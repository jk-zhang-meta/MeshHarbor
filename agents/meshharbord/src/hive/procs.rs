// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1h — a harness's process, from outside its session task.
//!
//! Each harness leads its own process group (`process_group(0)`), so its
//! tools go down with it. A service manager reaches that group only when it
//! kills a whole cgroup: systemd's `KillMode=control-group` does, launchd
//! does not, and nothing does for a daemon that runs unsupervised. So the
//! daemon takes its harnesses down itself when it leaves ([`super::wind_down`]),
//! and a daemon resuming what a crashed one hosted first takes down a harness
//! the crash left running — two harnesses on one Claude Code history would
//! each write it.
//!
//! A pid alone does not name a process across time: the pid of a harness that
//! ended may belong to anything by now. [`started`] adds the process's start
//! time, and a group is signalled only when both still match.
//!
//! P1i-2 — on Windows a harness's group is its Job Object, which the session
//! task holds and which ends with the daemon that holds it
//! (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), so a crash leaves no harness
//! running there. [`take_down`] still ends what it is given, by pid.

use std::time::{Duration, Instant};

/// When `pid` started, as a token that differs for every process ever given
/// that pid: on Linux the boot id and the start time in clock ticks since
/// boot, on macOS the start time in microseconds since the epoch, on Windows
/// the creation time in 100 ns units since 1601. `None`: no such process (or
/// none this daemon may read).
pub(crate) fn started(pid: u32) -> Option<String> {
    imp::started(pid)
}

/// P1j — the Claude Code that ran an adopt hook `pid`: the hook's nearest
/// ancestor that is not a shell. Claude Code runs a hook's command line
/// through `/bin/sh -c`, and a shell that forks the command instead of
/// exec'ing it stands between the two and exits with the hook — dash does
/// (Claude Code 2.1.293 on Ubuntu's dash 0.5.12, the field run). Taken for
/// the terminal, that shell ended every adopted session at the next sweep,
/// and the next turn's hook offered the session again as a new record.
/// Claude Code is never a shell, and a shell that exec'd the hook is not
/// there at all. `None`: no such process, or more shells than any wrapper.
///
/// FR-97 P4c — on Windows Claude Code runs a hook through Git Bash or
/// PowerShell, and the installed `roomler.exe` is a shim that starts
/// `roomlerd.exe cli` and waits for it, so the shim stands there too:
/// `claude.exe → bash.exe → roomler.exe → roomlerd.exe`. Windows keeps a
/// process's parent pid after that parent ends, so a "parent" created after
/// its child is another process that took a dead one's pid, and is no one's
/// terminal ([`imp::parent`]).
pub(crate) fn hook_terminal(pid: u32) -> Option<u32> {
    let mut p = imp::parent(pid)?;
    for _ in 0..MAX_WRAPPERS {
        if !is_wrapper(&imp::name(p)?) {
            return Some(p);
        }
        p = imp::parent(p)?;
    }
    None
}

/// What a hook's command line may run under, by process name.
#[cfg(unix)]
const WRAPPERS: [&str; 8] = ["sh", "dash", "bash", "zsh", "ksh", "mksh", "ash", "fish"];
/// … on Windows: the shells Claude Code runs a hook through, and the shim.
/// Compared without regard to case, as Windows compares file names.
#[cfg(windows)]
const WRAPPERS: [&str; 9] = [
    "bash.exe",
    "sh.exe",
    "dash.exe",
    "zsh.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "roomler.exe",
    "roomler-shim.exe",
];

fn is_wrapper(name: &str) -> bool {
    if cfg!(windows) {
        WRAPPERS.iter().any(|w| name.eq_ignore_ascii_case(w))
    } else {
        WRAPPERS.contains(&name)
    }
}

/// The most wrappers between a hook and the Claude Code that ran it: on
/// Windows the shim is one more than any shell chain.
const MAX_WRAPPERS: usize = if cfg!(windows) { 4 } else { 3 };

/// Signal `pid`'s process group (the group a harness leads).
#[cfg(unix)]
pub(crate) fn signal_group(pid: u32, signal: libc::c_int) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    if pid <= 1 {
        return;
    }
    // SAFETY: a plain syscall; the negative pid addresses the group.
    unsafe {
        libc::kill(-pid, signal);
    }
}

/// Whether anything is left in `pid`'s process group.
#[cfg(unix)]
pub(crate) fn group_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 1 {
        return false;
    }
    // SAFETY: signal 0 delivers nothing; it only asks whether the group
    // exists. EPERM still means it does.
    let rc = unsafe { libc::kill(-pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// SIGTERM to each group — a harness exits cleanly on it and Claude Code
/// records its running cost — then SIGKILL, after `grace`, to any group still
/// there. Returns once every group is gone, or after the SIGKILL.
#[cfg(unix)]
pub(crate) async fn take_down(pids: &[u32], grace: Duration) {
    if pids.is_empty() {
        return;
    }
    for &pid in pids {
        signal_group(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline && pids.iter().any(|&p| group_alive(p)) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for &pid in pids {
        if group_alive(pid) {
            signal_group(pid, libc::SIGKILL);
        }
    }
}

/// P1i-2 — Windows has no signal a console-less harness could catch, so each
/// process is ended outright (`TerminateProcess`), then this waits up to
/// `grace` for every one to be gone. Its tools are its Job Object's, which ends
/// them when its last handle closes: with the session task, or with the daemon.
#[cfg(windows)]
pub(crate) async fn take_down(pids: &[u32], grace: Duration) {
    if pids.is_empty() {
        return;
    }
    for &pid in pids {
        imp::terminate(pid);
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline && pids.iter().any(|&p| imp::alive(p)) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(target_os = "linux")]
mod imp {
    pub(super) fn started(pid: u32) -> Option<String> {
        // Field 22 of /proc/<pid>/stat is the start time in clock ticks since
        // boot. Field 2, the command, is parenthesised and may hold spaces,
        // so the fields are counted from its closing parenthesis: the first
        // after it is field 3.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let ticks: u64 = stat
            .rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        Some(format!("{}:{ticks}", boot.trim()))
    }

    pub(super) fn parent(pid: u32) -> Option<u32> {
        // Field 4, the parent pid: the first after the command's closing
        // parenthesis is field 3 (the state).
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let ppid: u32 = stat
            .rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        (ppid > 1).then_some(ppid)
    }

    pub(super) fn name(pid: u32) -> Option<String> {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        Some(comm.trim_end_matches('\n').to_string())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    /// The process's BSD info: its start time, parent and name.
    fn bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
        let pid = libc::c_int::try_from(pid).ok()?;
        // SAFETY: the buffer is a zeroed `proc_bsdinfo` this frame owns,
        // passed with its own size; the call writes at most that much.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        (n == size).then_some(info)
    }

    pub(super) fn started(pid: u32) -> Option<String> {
        let info = bsdinfo(pid)?;
        Some(format!(
            "{}",
            info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec
        ))
    }

    pub(super) fn parent(pid: u32) -> Option<u32> {
        let info = bsdinfo(pid)?;
        (info.pbi_ppid > 1).then_some(info.pbi_ppid)
    }

    pub(super) fn name(pid: u32) -> Option<String> {
        let info = bsdinfo(pid)?;
        let bytes: Vec<u8> = info
            .pbi_comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8(bytes).ok()
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    };

    /// `pid` opened with `access`, if it is still running: a process that
    /// ended stays openable while anything holds a handle to it, and its
    /// creation time with it, so a dead one must not read as the live one.
    fn open_running(pid: u32, access: u32) -> Option<HANDLE> {
        // 0 is the idle process and 4 the kernel's; neither is a harness.
        if pid <= 4 {
            return None;
        }
        // SAFETY: a plain open; every caller closes the handle.
        let h = unsafe { OpenProcess(access | PROCESS_SYNCHRONIZE, 0, pid) };
        if h.is_null() {
            return None;
        }
        // SAFETY: a live handle opened with SYNCHRONIZE; a 0 ms wait only asks.
        if unsafe { WaitForSingleObject(h, 0) } != WAIT_TIMEOUT {
            // SAFETY: the handle opened above, closed once.
            unsafe { CloseHandle(h) };
            return None;
        }
        Some(h)
    }

    /// A running `pid`'s creation time, in 100 ns units since 1601.
    fn created(pid: u32) -> Option<u64> {
        let h = open_running(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: a live handle with QUERY_LIMITED_INFORMATION; four valid
        // out-params.
        let ok =
            unsafe { GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) } != 0;
        // SAFETY: the handle `open_running` gave us, closed once.
        unsafe { CloseHandle(h) };
        ok.then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    pub(super) fn started(pid: u32) -> Option<String> {
        created(pid).map(|t| t.to_string())
    }

    /// `pid`'s entry in a snapshot of every process: its parent's pid and its
    /// executable's file name.
    fn entry(pid: u32) -> Option<(u32, String)> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        // SAFETY: a plain snapshot; closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: zeroing a POD struct, then `dwSize` as the API requires.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        // SAFETY: a live snapshot and a sized entry, walked to its end.
        let mut more = unsafe { Process32FirstW(snap, &mut e) } != 0;
        while more {
            if e.th32ProcessID == pid {
                let len = e
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(e.szExeFile.len());
                found = Some((
                    e.th32ParentProcessID,
                    String::from_utf16_lossy(&e.szExeFile[..len]),
                ));
                break;
            }
            // SAFETY: as above.
            more = unsafe { Process32NextW(snap, &mut e) } != 0;
        }
        // SAFETY: the snapshot opened above, closed once.
        unsafe { CloseHandle(snap) };
        found
    }

    /// `pid`'s parent, if it is still the process that made `pid`. Windows
    /// keeps the parent's pid after the parent ends, and the pid may belong to
    /// another process by now: a "parent" that started after its child is
    /// that other process.
    pub(super) fn parent(pid: u32) -> Option<u32> {
        let (ppid, _) = entry(pid)?;
        if ppid <= 4 {
            return None;
        }
        (created(ppid)? <= created(pid)?).then_some(ppid)
    }

    pub(super) fn name(pid: u32) -> Option<String> {
        entry(pid).map(|(_, name)| name)
    }

    /// A child of `pid`, any one: what a test needs to find the process a
    /// wrapper it started is running.
    #[cfg(test)]
    pub(super) fn child_of(pid: u32) -> Option<u32> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        // SAFETY: as in `entry`.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: as in `entry`.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        // SAFETY: as in `entry`.
        let mut more = unsafe { Process32FirstW(snap, &mut e) } != 0;
        while more {
            if e.th32ParentProcessID == pid {
                found = Some(e.th32ProcessID);
                break;
            }
            // SAFETY: as in `entry`.
            more = unsafe { Process32NextW(snap, &mut e) } != 0;
        }
        // SAFETY: the snapshot opened above, closed once.
        unsafe { CloseHandle(snap) };
        found
    }

    pub(super) fn alive(pid: u32) -> bool {
        match open_running(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            Some(h) => {
                // SAFETY: the handle `open_running` gave us, closed once.
                unsafe { CloseHandle(h) };
                true
            }
            None => false,
        }
    }

    pub(super) fn terminate(pid: u32) {
        // SAFETY: GetCurrentProcessId has no preconditions.
        if pid == unsafe { GetCurrentProcessId() } {
            return;
        }
        if let Some(h) = open_running(pid, PROCESS_TERMINATE) {
            // SAFETY: a live handle opened with PROCESS_TERMINATE; closed once.
            unsafe {
                TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
    }
}

#[cfg(all(test, windows))]
mod win_tests {
    use super::*;

    fn ping() -> std::process::Child {
        std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn a_live_process_has_a_start_time_that_holds_and_a_dead_one_has_none() {
        let me = std::process::id();
        let a = started(me).expect("this process's own start time");
        assert_eq!(started(me), Some(a), "the same process, the same token");
        let mut child = std::process::Command::new("cmd")
            .args(["/d", "/c", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        // `child` still holds its handle, so the ended process stays openable:
        // the token must say it ended all the same.
        child.wait().unwrap();
        assert_eq!(started(pid), None, "an ended process has no start time");
        assert_eq!(started(0), None);
        assert_eq!(started(4), None);
    }

    #[tokio::test]
    async fn take_down_ends_each_process_it_is_given() {
        let mut child = ping();
        let pid = child.id();
        assert!(imp::alive(pid));
        take_down(&[pid], Duration::from_secs(5)).await;
        assert!(!imp::alive(pid), "gone once take_down returns");
        assert!(child.wait().is_ok());
    }

    #[test]
    fn the_daemon_and_the_kernel_are_never_ended() {
        imp::terminate(std::process::id());
        imp::terminate(0);
        imp::terminate(4);
        assert!(imp::alive(std::process::id()), "still here");
    }

    /// FR-97 P4c — a hook's terminal is past every wrapper: here `cmd.exe`
    /// runs `ping` as Git Bash or PowerShell runs a hook's command line, and
    /// the terminal found from the ping is this test process, which is no
    /// wrapper.
    #[test]
    fn a_hooks_terminal_is_found_past_its_wrappers() {
        let mut wrapper = std::process::Command::new("cmd")
            .args(["/d", "/c", "ping -n 30 127.0.0.1 >NUL"])
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let hook = loop {
            if let Some(p) = imp::child_of(wrapper.id()) {
                break p;
            }
            assert!(Instant::now() < deadline, "cmd started nothing");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(is_wrapper("CMD.EXE"), "names compare without case");
        assert_eq!(imp::name(wrapper.id()).as_deref(), Some("cmd.exe"));
        assert_eq!(hook_terminal(hook), Some(std::process::id()));
        imp::terminate(hook);
        let _ = wrapper.kill();
        let _ = wrapper.wait();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn a_live_process_has_a_start_time_that_holds_and_a_dead_one_has_none() {
        let me = std::process::id();
        let a = started(me).expect("this process's own start time");
        assert_eq!(started(me), Some(a), "the same process, the same token");
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert_eq!(started(pid), None, "a reaped process has no start time");
    }

    #[test]
    fn a_hook_belongs_to_its_nearest_ancestor_that_is_not_a_shell() {
        let me = std::process::id();
        // Run directly, as a shell that exec'd the command leaves it.
        let mut direct = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert_eq!(hook_terminal(direct.id()), Some(me));
        direct.kill().unwrap();
        direct.wait().unwrap();

        // Run through `sh -c` by a shell that forks it, as dash runs a hook's
        // command line for Claude Code; a background job keeps the shell
        // between the two whatever the shell.
        let dir = tempfile::tempdir().unwrap();
        let said = dir.path().join("pid");
        let mut sh = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 30 & echo $! > '{}'; wait", said.display()))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let hook = loop {
            if let Some(p) = std::fs::read_to_string(&said)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
            {
                break p;
            }
            assert!(Instant::now() < deadline, "the shell never named its job");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(imp::parent(hook), Some(sh.id()), "the shell stands between");
        assert_eq!(hook_terminal(hook), Some(me), "and the terminal is past it");
        // SAFETY: a plain syscall to the job this test started.
        unsafe {
            libc::kill(libc::pid_t::try_from(hook).unwrap(), libc::SIGKILL);
        }
        sh.wait().unwrap();
    }

    #[tokio::test]
    async fn take_down_ends_a_group_that_ignores_sigterm_too() {
        // A group leader that ignores SIGTERM, and a tool beneath it.
        let mut stubborn = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 60 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = stubborn.id();
        assert!(group_alive(pid));
        take_down(&[pid], Duration::from_millis(300)).await;
        stubborn.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while group_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!group_alive(pid), "every process in the group is gone");
    }

    #[test]
    fn pid_zero_and_one_are_never_signalled() {
        // `kill(0, …)` is our own group and `kill(-1, …)` is everyone:
        // neither may ever be reached from a recorded pid.
        assert!(!group_alive(0));
        assert!(!group_alive(1));
        signal_group(0, 0);
        signal_group(1, 0);
    }
}
