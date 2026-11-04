// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #2465 — the worker an earlier host of THIS service left running.
//!
//! The SCM worker (`meshharbord run --supervisor scm`) is in no job object and
//! waits only on its stop event (#1683), so a host that dies without a stop (a
//! crash, a `TerminateProcess`) leaves its worker running: connected, holding
//! the config's single-instance lock, and supervised by nobody. Every host the
//! SCM's recovery (#2087) started next spawned a worker that lost that lock, so
//! the service could only flap while a `roomlerd` it no longer controlled kept
//! the device online, and a deliberate `Stop-Service` could not stop it.
//!
//! **The rule** ([`is_orphaned_worker`]): the SCM runs one host process per
//! service, and a host supervises at most one worker. The reaper runs only
//! while this host supervises none (before its first spawn, and after its
//! worker refused), so a running `roomlerd.exe run --supervisor scm` belongs
//! to a host that is gone, or is one this host lost track of. Only this
//! service spawns that command line: a per-user install runs `--supervisor
//! task`. It is keyed on who spawned the worker, never on when: creation
//! times are wall clock, and a guest whose clock was corrected backwards
//! measured an orphan as nine hours younger than the host that replaced it.
//!
//! The process is matched by its image NAME, from the process list, and
//! never by its full path. The name is fixed when the process is created. The
//! path is not: an update replaces an exe that is in use by renaming it away,
//! and a full-path rule would then spare the very orphan that outlived the
//! update.
//!
//! **How it ends**: `TerminateProcess`, never its stop event. The stop event
//! is the OS-stop path, on which an ephemeral device self-unenrolls
//! (`updater::should_self_unenroll`). The worker this host spawns next
//! reconnects the device.
//!
//! **Identity is the handle, not the pid**: each process is opened once, its
//! image and command line are read through that handle, and the same handle
//! terminates it, so a recycled pid is never hit.

use std::time::Duration;

use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, GetLastError, INVALID_HANDLE_VALUE, UNICODE_STRING, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};

use super::supervisor::OwnedHandle;

/// How long a terminated orphan gets to be gone. Termination is asynchronous,
/// and its single-instance mutexes are released only once it has exited.
const REAP_WAIT: Duration = Duration::from_secs(5);

/// The exit code an orphan is terminated with. Its host is gone, so nobody
/// reads it; it only marks the process in a debugger or an EDR trail.
const REAPED_EXIT_CODE: u32 = 1;

/// The largest buffer `ProcessCommandLineInformation` can need: a
/// `UNICODE_STRING` header followed by at most `u16::MAX` bytes of text.
const CMDLINE_BUF_BYTES: usize = std::mem::size_of::<UNICODE_STRING>() + u16::MAX as usize + 1;

/// One process running this binary, as the reaper reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub pid: u32,
    /// The full Win32 image path. Logged, never matched on: an update renames
    /// an in-use exe away, so an orphan's path can be anything.
    pub image: String,
    pub cmdline: String,
}

/// What one pass found and did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReapReport {
    /// The process list could be taken at all.
    pub listed: bool,
    /// Processes running this binary, other than this host, that were read.
    pub inspected: usize,
    /// Orphans that were terminated and are gone.
    pub reaped: usize,
    /// Processes running this binary that could not be read, or an orphan that
    /// would not end: either may still hold the single-instance lock.
    pub unresolved: usize,
}

impl ReapReport {
    /// Whether the pass can vouch that no orphan of this service is left.
    pub fn complete(&self) -> bool {
        self.listed && self.unresolved == 0
    }
}

/// Split a Windows command line into arguments. It covers what a host spawns:
/// a program path that may be quoted, then arguments without spaces or quotes.
/// A quote toggles quoting, and whitespace outside quotes ends an argument.
fn split_args(cmdline: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut started = false;
    for ch in cmdline.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started {
        args.push(cur);
    }
    args
}

/// Is `cmdline` an SCM worker's: the `run` subcommand first, with `--supervisor
/// scm` among its arguments, exactly as [`super::worker_args`] builds it?
/// Nothing else this binary runs as matches: the host itself (`service-run`),
/// the CLI (`cli …`), netd, a Scheduled-Task worker (`run --supervisor task`),
/// a hand-started `run`, or the updater's helpers.
pub fn is_scm_worker_cmdline(cmdline: &str) -> bool {
    let args = split_args(cmdline);
    if args.get(1).map(String::as_str) != Some("run") {
        return false;
    }
    let rest = &args[2..];
    rest.windows(2)
        .any(|w| w[0] == "--supervisor" && w[1] == "scm")
        || rest.iter().any(|a| a == "--supervisor=scm")
}

/// The rule, pure so it is tested without a process: an SCM worker that is
/// neither this host nor a worker this host supervises. The candidates are
/// already the processes with this binary's image name ([`pids_named`]). The
/// callers pass `supervised` empty, because they run only while this host
/// supervises no worker; the parameter keeps the rule honest if that changes.
pub fn is_orphaned_worker(c: &Candidate, own_pid: u32, supervised: &[u32]) -> bool {
    c.pid != own_pid && !supervised.contains(&c.pid) && is_scm_worker_cmdline(&c.cmdline)
}

/// One pass: find this service's orphaned workers and end them. Best-effort
/// and bounded: it never fails the host, and whatever it could not settle is
/// counted in [`ReapReport::unresolved`].
pub fn reap_orphaned_workers() -> ReapReport {
    let own_pid = std::process::id();
    let own_image = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            tracing::warn!(error = %e, "orphan check: cannot resolve this host's own image; skipped");
            return ReapReport::default();
        }
    };
    let Some(name) = own_image.rsplit(['\\', '/']).next().map(str::to_owned) else {
        return ReapReport::default();
    };
    let Some(pids) = pids_named(&name) else {
        tracing::warn!("orphan check: cannot list processes; skipped");
        return ReapReport::default();
    };
    let mut report = ReapReport {
        listed: true,
        ..ReapReport::default()
    };
    for pid in pids.into_iter().filter(|&p| p != own_pid) {
        let (h, c) = match open_candidate(pid) {
            Opened::Gone => continue,
            Opened::Unreadable(err) => {
                report.unresolved += 1;
                tracing::warn!(
                    pid,
                    win32_error = err,
                    "orphan check: a process running this binary could not be read, so it cannot \
                     be ruled out as a worker an earlier host left behind"
                );
                continue;
            }
            Opened::Read(h, c) => (h, c),
        };
        report.inspected += 1;
        if !is_orphaned_worker(&c, own_pid, &[]) {
            continue;
        }
        tracing::warn!(
            pid,
            image = %c.image,
            cmdline = %c.cmdline,
            "supervisor: an earlier host of this service left its worker running; ending it so \
             this host's own worker can take over (#2465)"
        );
        if terminate_and_wait(&h) {
            report.reaped += 1;
        } else {
            report.unresolved += 1;
            tracing::warn!(
                pid,
                wait_ms = REAP_WAIT.as_millis() as u64,
                "orphan check: the orphaned worker did not end"
            );
        }
    }
    report
}

/// The pids of every process whose image file name is `name`, or `None` when
/// the process list cannot be taken.
fn pids_named(name: &str) -> Option<Vec<u32>> {
    // SAFETY: a plain snapshot, closed below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return None;
    }
    let snap = OwnedHandle::new(snap)?;
    // SAFETY: zeroing a POD struct, then `dwSize` as the API requires.
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut pids = Vec::new();
    // SAFETY: a live snapshot and a sized entry, walked to its end.
    let mut more = unsafe { Process32FirstW(snap.raw(), &mut e) } != 0;
    while more {
        let len = e
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(e.szExeFile.len());
        if String::from_utf16_lossy(&e.szExeFile[..len]).eq_ignore_ascii_case(name) {
            pids.push(e.th32ProcessID);
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap.raw(), &mut e) } != 0;
    }
    Some(pids)
}

enum Opened {
    /// It ended before it could be read.
    Gone,
    /// It is running, but could not be opened or read (a Win32 error).
    Unreadable(u32),
    /// It is running, and this handle can read, wait on and terminate it.
    Read(OwnedHandle, Candidate),
}

fn open_candidate(pid: u32) -> Opened {
    // SAFETY: a plain open; the handle is owned below.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    let Some(h) = OwnedHandle::new(raw) else {
        // SAFETY: thread-local error read.
        let err = unsafe { GetLastError() };
        // ERROR_INVALID_PARAMETER: no such process any more.
        return if err == ERROR_INVALID_PARAMETER {
            Opened::Gone
        } else {
            Opened::Unreadable(err)
        };
    };
    // A process that ended stays openable while a handle is held, so only a
    // running one is a candidate.
    // SAFETY: a live handle opened with SYNCHRONIZE; a 0 ms wait only asks.
    if unsafe { WaitForSingleObject(h.raw(), 0) } != WAIT_TIMEOUT {
        return Opened::Gone;
    }
    let (Some(image), Some(cmdline)) = (image_of(&h), cmdline_of(&h)) else {
        // SAFETY: thread-local error read.
        return Opened::Unreadable(unsafe { GetLastError() });
    };
    Opened::Read(
        h,
        Candidate {
            pid,
            image,
            cmdline,
        },
    )
}

/// The full Win32 path of the process's image.
fn image_of(h: &OwnedHandle) -> Option<String> {
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: a live handle with QUERY_LIMITED_INFORMATION; `len` is the
    // buffer's size in characters, and the call writes back how many it used.
    let ok = unsafe {
        QueryFullProcessImageNameW(h.raw(), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// The process's command line (`ProcessCommandLineInformation`, which needs
/// only QUERY_LIMITED_INFORMATION). One call with the largest buffer the text
/// can need, so there is no size probe.
fn cmdline_of(h: &OwnedHandle) -> Option<String> {
    // u64 storage: the buffer starts with a UNICODE_STRING, which holds a pointer.
    let mut buf = vec![0u64; CMDLINE_BUF_BYTES.div_ceil(8)];
    let bytes = buf.len() * 8;
    let mut used = 0u32;
    // SAFETY: a live handle with QUERY_LIMITED_INFORMATION and a writable
    // buffer of `bytes` bytes.
    let status = unsafe {
        NtQueryInformationProcess(
            h.raw(),
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast(),
            bytes as u32,
            &mut used,
        )
    };
    if status < 0 {
        return None;
    }
    // SAFETY: on success the buffer starts with a UNICODE_STRING; it is
    // properly aligned (u64 storage).
    let us = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
    if us.Buffer.is_null() || us.Length == 0 {
        return Some(String::new());
    }
    // Its text lives in this same buffer. Refuse anything that points
    // outside it rather than read through a stray pointer.
    let start = buf.as_ptr() as usize;
    let text = us.Buffer as usize;
    let len = usize::from(us.Length);
    if text < start || text + len > start + bytes || !len.is_multiple_of(2) {
        return None;
    }
    // SAFETY: bounds-checked above: `len` bytes from `text` lie inside `buf`.
    let chars = unsafe { std::slice::from_raw_parts(us.Buffer, len / 2) };
    Some(String::from_utf16_lossy(chars))
}

/// Terminate through the handle the process was read with, and wait for it
/// to be gone.
fn terminate_and_wait(h: &OwnedHandle) -> bool {
    // SAFETY: a live handle opened with TERMINATE.
    if unsafe { TerminateProcess(h.raw(), REAPED_EXIT_CODE) } == 0 {
        // It may have ended on its own in between.
        // SAFETY: a live handle opened with SYNCHRONIZE.
        return unsafe { WaitForSingleObject(h.raw(), 0) } == WAIT_OBJECT_0;
    }
    // SAFETY: as above; the wait is bounded.
    unsafe { WaitForSingleObject(h.raw(), REAP_WAIT.as_millis() as u32) == WAIT_OBJECT_0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = r"C:\Program Files\Roomler\roomlerd.exe";

    fn cand(pid: u32, image: &str, cmdline: &str) -> Candidate {
        Candidate {
            pid,
            image: image.to_string(),
            cmdline: cmdline.to_string(),
        }
    }

    /// The command lines measured on 0.4.132 and 0.4.143 (#2465), and what
    /// `worker_args` builds today: if `worker_args` changes, the reaper must
    /// change with it, or it would silently stop finding orphans.
    #[test]
    fn an_scm_worker_is_recognised() {
        for c in [
            r#""C:\Program Files\Roomler\roomlerd.exe" run --supervisor scm --stop-event Global\roomler-worker-stop-2452-3"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" run --supervisor scm --stop-event Global\roomler-worker-stop-1812-0 --sas-event Global\roomler-sas-1812"#,
            r"C:\Roomler\roomlerd.exe run --supervisor scm",
            r"C:\Roomler\roomlerd.exe run --supervisor=scm",
        ] {
            assert!(is_scm_worker_cmdline(c), "{c}");
        }
        let built = format!("\"{EXE}\" {}", super::super::worker_args().join(" "));
        assert!(is_scm_worker_cmdline(&built), "{built}");
    }

    /// Everything else this binary runs as is never a worker to end.
    #[test]
    fn nothing_else_is_an_scm_worker() {
        for c in [
            r#""C:\Program Files\Roomler\roomlerd.exe" service-run"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" run"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" run --supervisor task"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" netd"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" cli ssh mars"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" cli run --supervisor scm"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" self-update --check-only"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" run --supervisor"#,
            r#""C:\Program Files\Roomler\roomlerd.exe" run --stop-event scm"#,
            "",
        ] {
            assert!(!is_scm_worker_cmdline(c), "{c}");
        }
    }

    #[test]
    fn a_quoted_program_path_is_one_argument() {
        assert_eq!(
            split_args(r#""C:\Program Files\Roomler\roomlerd.exe" run  --supervisor scm"#),
            [
                r"C:\Program Files\Roomler\roomlerd.exe",
                "run",
                "--supervisor",
                "scm"
            ]
        );
    }

    /// Each condition is necessary: this host, a worker it supervises and a
    /// non-worker are all left alone.
    #[test]
    fn the_rule_needs_every_condition() {
        let worker = r#""C:\Program Files\Roomler\roomlerd.exe" run --supervisor scm --stop-event Global\roomler-worker-stop-2452-3"#;
        let own = 1812;
        assert!(is_orphaned_worker(&cand(3248, EXE, worker), own, &[]));
        assert!(
            !is_orphaned_worker(&cand(own, EXE, worker), own, &[]),
            "this host"
        );
        assert!(
            !is_orphaned_worker(&cand(3248, EXE, worker), own, &[3248]),
            "supervised"
        );
        assert!(
            !is_orphaned_worker(&cand(3248, EXE, &worker.replace(" scm", " task")), own, &[]),
            "a Scheduled-Task worker"
        );
    }

    /// An update replaces an exe that is in use by renaming it away, so an
    /// orphan that outlived an update no longer runs from the install path.
    /// It is still this service's worker, and the rule must still end it: a
    /// full-path rule would spare exactly that one, and the service would then
    /// stop cleanly beside it.
    #[test]
    fn a_worker_whose_file_was_renamed_away_is_still_an_orphan() {
        let worker = r#""C:\Program Files\Roomler\roomlerd.exe" run --supervisor scm --stop-event Global\roomler-worker-stop-2452-3"#;
        let renamed = cand(3248, r"C:\Config.Msi\3f1a2b.rbf", worker);
        assert!(is_orphaned_worker(&renamed, 1812, &[]));
    }

    #[test]
    fn a_report_vouches_only_when_it_saw_everything() {
        let full = ReapReport {
            listed: true,
            inspected: 3,
            reaped: 1,
            unresolved: 0,
        };
        assert!(full.complete());
        assert!(
            !ReapReport {
                unresolved: 1,
                ..full
            }
            .complete()
        );
        assert!(
            !ReapReport {
                listed: false,
                ..full
            }
            .complete()
        );
    }

    /// The FFI path, read through this test process: its image is the running
    /// binary and its command line is readable, so the reaper's decoding of
    /// `ProcessCommandLineInformation` holds.
    #[test]
    fn this_process_reads_back_as_itself() {
        let Opened::Read(_h, c) = open_candidate(std::process::id()) else {
            panic!("could not read this process");
        };
        let exe = std::env::current_exe().unwrap();
        let exe_path = exe.to_string_lossy();
        let exe_path = exe_path.strip_prefix(r"\\?\").unwrap_or(&exe_path);
        assert!(c.image.eq_ignore_ascii_case(exe_path), "{c:?}");
        let name = exe.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            c.cmdline.to_lowercase().contains(&name.to_lowercase()),
            "{c:?}"
        );
        assert!(!is_scm_worker_cmdline(&c.cmdline), "{c:?}");
    }

    /// A pass in a test process ends nothing: nothing runs this test binary as
    /// an SCM worker. It must still list the processes and finish.
    #[test]
    fn a_pass_in_a_test_process_ends_nothing() {
        let r = reap_orphaned_workers();
        assert!(r.listed, "{r:?}");
        assert_eq!(r.reaped, 0, "{r:?}");
    }
}
