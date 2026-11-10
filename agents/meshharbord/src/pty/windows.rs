// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The Windows half of [`crate::pty`] — ConPTY.
//!
//! Windows has no pty pair to open. Instead the console host owns the terminal:
//! [`CreatePseudoConsole`] hands back an `HPCON`, and a process is attached to
//! it by passing that handle through a **process-thread attribute list** on
//! `CreateProcess`. The child then talks to a real console, and the console
//! host renders VT sequences into the pipe we read.
//!
//! Three consequences worth knowing, because none of them have Unix analogues:
//!
//! * **The pipe ends are crossed.** `CreatePseudoConsole` takes the handles IT
//!   will use — the READ end of our input pipe and the WRITE end of our output
//!   pipe — and we keep the opposite ends. Handing it the wrong ones produces a
//!   session that connects and never echoes, which is a miserable thing to
//!   debug.
//! * **We must close our copies of the child's ends** after `CreateProcess`,
//!   exactly as Unix must close the pty slave: while any handle to the write
//!   end survives, our read never reports EOF and a finished session hangs.
//! * **There are no process groups.** Teardown is a job object, so closing it
//!   kills the shell *and everything it started* — the same guarantee
//!   `killpg` gives, obtained differently.
//!
//! # Async
//!
//! Anonymous pipes on Windows are synchronous, and there is no `AsyncFd`
//! equivalent to register them with. Both directions therefore run on
//! [`spawn_blocking`](tokio::task::spawn_blocking) threads with a small channel
//! in front — the same shape the Unix pumps have, one layer lower. A session is
//! two blocking threads; sessions are counted in single digits, so that is a
//! fair trade against the complexity of overlapped I/O on named pipes.

use std::io;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::WinSize;

/// An owned Win32 handle. Closing is the only thing we need from it, but we
/// need that to be automatic — a leaked pipe end is exactly the bug that turns
/// "the session ended" into "the session hangs".
#[derive(Debug)]
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own this handle and drop runs once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: a Win32 HANDLE is just a kernel-object index; the API is thread-safe
// for the operations used here (ReadFile/WriteFile on distinct handles,
// CloseHandle once). The raw pointer inside is what makes the compiler
// conservative, not any real thread affinity.
unsafe impl Send for Owned {}
unsafe impl Sync for Owned {}

/// A pseudoconsole.
///
/// ⚠️ **Closing this is what ends the session's output stream**, and that is the
/// single biggest difference from a Unix pty. A pty master reports `EIO` — read
/// as EOF — as soon as the last process holding the slave exits. ConPTY does
/// not: the **console host** owns the write end of our output pipe and keeps it
/// open for as long as the pseudoconsole exists. A reader waiting for EOF after
/// the shell exits therefore waits forever.
///
/// So the session spawns a waiter that closes this the moment the child exits,
/// which is what lets the read pump drain and finish. Closing is idempotent
/// (the waiter and `Drop` both do it), hence the atomic rather than a plain
/// `HPCON`.
///
/// ⚠️ `HPCON` is an `isize` in windows-sys, NOT a pointer — so "empty" is `0`
/// and it is initialised with `0`, not `null_mut()`. Easy to get wrong by
/// analogy with `HANDLE`, declared right beside it as `*mut c_void`.
#[derive(Debug)]
struct PseudoConsole(std::sync::atomic::AtomicIsize);

impl PseudoConsole {
    fn get(&self) -> HPCON {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Close once, whoever gets there first.
    fn close(&self) {
        let h = self.0.swap(0, std::sync::atomic::Ordering::AcqRel);
        if h != 0 {
            // ⚠️ BLOCKS until the console host has drained what it still owes
            // the output pipe — which is why teardown kills the shell FIRST.
            // A live child keeps refilling, and this would wait on it.
            unsafe { ClosePseudoConsole(h) };
        }
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        self.close();
    }
}

unsafe impl Send for PseudoConsole {}
unsafe impl Sync for PseudoConsole {}

/// A pseudoconsole with a shell attached.
#[derive(Debug)]
pub struct PtyProcess {
    /// Kept alive for the session; the waiter closes it when the child exits.
    _pc: Arc<PseudoConsole>,
    /// Our end of the child's stdout/stderr.
    out_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    /// Leftover bytes from a chunk larger than the caller's buffer.
    pending: Vec<u8>,
    /// The child's exit status, published by the waiter. `None` once taken.
    exit_rx: Option<tokio::sync::oneshot::Receiver<u32>>,
    /// Cached once awaited, so `wait` is safe to call more than once.
    exit: Option<u32>,
    /// Killing this kills the shell and everything it started. The HANDLE is
    /// only closed on drop — teardown goes through `TerminateJobObject`, which
    /// is idempotent and leaves the handle valid.
    job: Arc<Owned>,
    handle: PtyHandle,
}

/// Write + resize half, cloneable across tasks.
#[derive(Clone, Debug)]
pub struct PtyHandle {
    in_tx: mpsc::Sender<Vec<u8>>,
    pc: Arc<PseudoConsole>,
}

fn last_error(what: &str) -> String {
    format!("{what}: {}", io::Error::last_os_error())
}

/// Which shell to run when the client asked for a login shell.
///
/// PowerShell if present, else `cmd.exe`. `%COMSPEC%` is deliberately NOT
/// consulted: it describes the DAEMON's environment (SYSTEM's), not the
/// session's.
fn default_shell() -> String {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let pwsh = format!(r"{sysroot}\System32\WindowsPowerShell\v1.0\powershell.exe");
    if std::path::Path::new(&pwsh).exists() {
        return pwsh;
    }
    format!(r"{sysroot}\System32\cmd.exe")
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl PtyProcess {
    /// Start a shell (or `shell -c <command>`) on a fresh pseudoconsole.
    pub fn spawn(
        command: Option<&str>,
        _term: &str,
        size: WinSize,
        run_as: &crate::exec::RunAs,
    ) -> Result<Self, String> {
        // Which identity — decided BEFORE anything is allocated, so a session
        // that will be refused never gets a pseudoconsole or a process.
        //
        // `Named` is refused here for the same reason `exec::apply_run_as`
        // refuses it: becoming an arbitrary local user on Windows needs that
        // user's credentials, which this daemon does not have and will not ask
        // for. Refusing is the point — quietly running as SYSTEM instead is
        // precisely the lie P5c/P5d exist to prevent.
        let as_console_user = match run_as {
            crate::exec::RunAs::Daemon => false,
            crate::exec::RunAs::ConsoleUser => true,
            other => {
                return Err(format!(
                    "cannot open an interactive session as {}: becoming an arbitrary local \
                     account on Windows requires that user's credentials, which this daemon \
                     does not have. Use account_mode `console_user` for the signed-in user, \
                     or `daemon` to accept running as SYSTEM.",
                    other.label()
                ));
            }
        };

        let size = size.sane();
        let (in_read, in_write) = pipe()?;
        let (out_read, out_write) = pipe()?;

        // ⚠️ CROSSED ON PURPOSE: the console gets the ends IT uses — it READS
        // the input pipe and WRITES the output pipe. We keep the opposites.
        let mut hpc: HPCON = 0;
        let coord = COORD {
            X: size.cols as i16,
            Y: size.rows as i16,
        };
        // SAFETY: both handles are live and owned; `hpc` is a valid out-param.
        let hr = unsafe { CreatePseudoConsole(coord, in_read.0, out_write.0, 0, &mut hpc) };
        if hr != 0 {
            return Err(format!("CreatePseudoConsole failed (hr={hr:#x})"));
        }
        let pc = Arc::new(PseudoConsole(std::sync::atomic::AtomicIsize::new(hpc)));

        let shell = default_shell();
        let cmdline = match command {
            Some(c) if shell.ends_with("cmd.exe") => format!("\"{shell}\" /C {c}"),
            Some(c) => format!("\"{shell}\" -NoLogo -Command {c}"),
            None if shell.ends_with("cmd.exe") => format!("\"{shell}\""),
            None => format!("\"{shell}\" -NoLogo"),
        };

        let pi = if as_console_user {
            spawn_attached_as_console_user(&pc, &cmdline, in_read.0, out_write.0)?
        } else {
            spawn_attached(&pc, &cmdline, in_read.0, out_write.0)?
        };
        let process = Owned(pi.hProcess);
        // The thread handle is of no use to us and would leak.
        let _thread = Owned(pi.hThread);

        // Everything the child started dies with the job. Windows has no
        // process group to signal, so this IS the `killpg` equivalent — and it
        // must be set up before anything can escape.
        let job = Arc::new(make_job(pi.hProcess)?);

        // THE WAITER. Without this the session never ends: the console host
        // holds the output pipe's write end for as long as the pseudoconsole
        // lives, so the read pump would block on a `ReadFile` that can never
        // return 0 even though the shell exited minutes ago. Closing the
        // pseudoconsole here is what produces EOF.
        //
        // It also owns the process handle outright and publishes the exit code,
        // which avoids the alternative — duplicating the handle so two owners
        // can both wait on it, and racing over which one closes it.
        let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<u32>();
        let pc_for_waiter = pc.clone();
        tokio::task::spawn_blocking(move || {
            let process = process; // whole-value capture; see the pumps below
            // SAFETY: a handle this closure owns for its whole lifetime.
            let code = unsafe {
                WaitForSingleObject(process.0, INFINITE);
                let mut code: u32 = 1;
                if GetExitCodeProcess(process.0, &mut code) == 0 {
                    1
                } else {
                    code
                }
            };

            // Closing the pseudoconsole is what ends the output stream, and it
            // is ORDERED, not timed: `ClosePseudoConsole` blocks until the
            // console host has finished writing what it owes the pipe, so the
            // read pump sees every byte and then EOF.
            //
            // ⚠️ An earlier revision waited here for the byte counter to go
            // quiet before closing, believing the close truncated buffered
            // output. It did not: the missing output was the child writing to
            // the PARENT's std handles (see `spawn_attached`), so the drain was
            // a timing workaround for a handle bug and never delivered a byte.
            // Removed rather than kept "just in case" — a sleep whose purpose
            // is misremembered is how teardown latency becomes permanent.
            pc_for_waiter.close();
            let _ = exit_tx.send(code);
        });

        // Close OUR copies of the child's ends. While either survives, the
        // reader never sees EOF and a finished session hangs — the same trap as
        // failing to close the pty slave on Unix.
        drop(in_read);
        drop(out_write);

        let (out_tx, out_rx) = mpsc::channel::<io::Result<Vec<u8>>>(64);
        let reader = out_read;
        tokio::task::spawn_blocking(move || {
            // ⚠️ Rust 2021 captures closure state by FIELD, so writing only
            // `reader.0` would capture the raw `HANDLE` — a `*mut c_void`,
            // which is not `Send` — and the `unsafe impl Send for Owned` above
            // would never apply. Re-binding the whole value forces it to be
            // captured as an `Owned`, which is both `Send` and the thing whose
            // `Drop` closes the handle.
            let reader = reader;
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let mut read: u32 = 0;
                // SAFETY: `buf` is valid for `buf.len()` writes; the handle is
                // owned by this closure for its whole lifetime.
                let ok = unsafe {
                    ReadFile(
                        reader.0,
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                };
                // A broken pipe here is the normal end of a session — the
                // console host closed its side because the pseudoconsole was
                // closed, which the waiter does once the child has exited AND
                // the host has gone quiet.
                if ok == 0 || read == 0 {
                    break;
                }
                if out_tx
                    .blocking_send(Ok(buf[..read as usize].to_vec()))
                    .is_err()
                {
                    break; // nobody is reading; the session is being torn down
                }
            }
        });

        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(64);
        let writer = in_write;
        tokio::task::spawn_blocking(move || {
            // Whole-value capture, for the same reason as the reader above.
            let writer = writer;
            while let Some(chunk) = in_rx.blocking_recv() {
                let mut off = 0usize;
                while off < chunk.len() {
                    let mut wrote: u32 = 0;
                    // SAFETY: writing a subslice we own to a handle we own.
                    let ok = unsafe {
                        WriteFile(
                            writer.0,
                            chunk[off..].as_ptr(),
                            (chunk.len() - off) as u32,
                            &mut wrote,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 || wrote == 0 {
                        return;
                    }
                    off += wrote as usize;
                }
            }
        });

        debug!(
            %shell, cols = size.cols, rows = size.rows,
            console_user = as_console_user,
            "ssh: conpty session started"
        );
        Ok(Self {
            handle: PtyHandle {
                in_tx,
                pc: pc.clone(),
            },
            _pc: pc,
            out_rx,
            pending: Vec::new(),
            exit_rx: Some(exit_rx),
            exit: None,
            job,
        })
    }

    pub fn handle(&self) -> PtyHandle {
        self.handle.clone()
    }

    /// Read one chunk of terminal output. `Ok(0)` means the session ended.
    ///
    /// A chunk larger than the caller's buffer is kept in `pending` rather than
    /// truncated — dropping the tail would corrupt the VT stream, and a torn
    /// escape sequence is the kind of bug that shows up as an occasional
    /// garbled prompt long after the session that caused it.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        match self.out_rx.recv().await {
            None => Ok(0),
            Some(Err(e)) => Err(e),
            Some(Ok(chunk)) => {
                let n = chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.pending.extend_from_slice(&chunk[n..]);
                }
                Ok(n)
            }
        }
    }

    /// The shell's exit status, in SSH's unsigned form.
    ///
    /// Cached, so calling it twice is safe — the pump awaits it and `Drop` must
    /// not care whether anyone already did.
    pub async fn wait(&mut self) -> u32 {
        if let Some(code) = self.exit {
            return code;
        }
        let code = match self.exit_rx.take() {
            // The waiter is gone without sending, which can only happen if the
            // runtime is shutting down. `1` is the honest answer: we do not
            // know that it succeeded.
            None => 1,
            Some(rx) => rx.await.unwrap_or(1),
        };
        // A Windows exit code is a full u32 and can carry an NTSTATUS
        // (0xC0000005 …). SSH's status is unsigned too, but anything outside
        // 0..=255 is not an exit code a shell would report, so map it to a
        // plain failure rather than something meaningless.
        let code = if code <= 255 { code } else { 1 };
        self.exit = Some(code);
        code
    }

    /// Kill the shell and everything it started.
    ///
    /// `TerminateJobObject` rather than closing the handle: it is idempotent,
    /// it leaves the handle valid for `Drop`, and one call reaches every
    /// process in the job — no enumeration, and no race with a child that
    /// spawns while a snapshot is being walked.
    pub fn kill_group(&self) {
        if !self.job.0.is_null() {
            // SAFETY: a job handle this struct owns.
            unsafe { TerminateJobObject(self.job.0, 1) };
        }
    }
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        // ORDER MATTERS: kill the job first so the shell stops producing, and
        // only then let `_pc` drop. `ClosePseudoConsole` blocks until the
        // console host has drained its output, which a live child would keep
        // refilling — the reason a naive teardown hangs.
        self.kill_group();
    }
}

impl PtyHandle {
    pub async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.in_tx
            .send(buf.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pty input closed"))
    }

    pub fn resize(&self, size: WinSize) -> io::Result<()> {
        let size = size.sane();
        let coord = COORD {
            X: size.cols as i16,
            Y: size.rows as i16,
        };
        // SAFETY: a pseudoconsole this struct keeps alive via the Arc.
        let hr = unsafe { ResizePseudoConsole(self.pc.get(), coord) };
        if hr != 0 {
            return Err(io::Error::other(format!(
                "ResizePseudoConsole failed (hr={hr:#x})"
            )));
        }
        Ok(())
    }
}

/// An inheritable anonymous pipe, `(read, write)`.
fn pipe() -> Result<(Owned, Owned), String> {
    let mut r: HANDLE = std::ptr::null_mut();
    let mut w: HANDLE = std::ptr::null_mut();
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: both out-params are valid; `sa` outlives the call.
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
        return Err(last_error("CreatePipe"));
    }
    Ok((Owned(r), Owned(w)))
}

/// A `STARTUPINFOEXW` wired to a pseudoconsole, ready for either
/// `CreateProcessW` (daemon identity) or `CreateProcessAsUserW` (the signed-in
/// console user).
///
/// Built once and shared by both, because everything that is easy to get
/// catastrophically wrong here — the by-value HPCON, the bounded handle list,
/// the std handles — is identical for the two, and a second copy would be a
/// second chance to get one of them wrong in only one of them.
///
/// Owns the attribute-list buffer, so the `si` it hands out must not outlive
/// it. `Drop` runs `DeleteProcThreadAttributeList`.
struct AttachedStartupInfo {
    si: STARTUPINFOEXW,
    // Kept alive because `si.lpAttributeList` points INTO it.
    _buf: Vec<u8>,
    // Same: the handle list attribute points at this array.
    _inherit: Box<[HANDLE; 2]>,
}

impl Drop for AttachedStartupInfo {
    fn drop(&mut self) {
        if !self.si.lpAttributeList.is_null() {
            // SAFETY: initialised in `new`, deleted once.
            unsafe { DeleteProcThreadAttributeList(self.si.lpAttributeList) };
        }
    }
}

impl AttachedStartupInfo {
    fn new(pc: &PseudoConsole, child_in: HANDLE, child_out: HANDLE) -> Result<Self, String> {
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

        // TWO attributes: the pseudoconsole, and the handle list that bounds
        // what inheritance actually hands over (see the `STARTF_USESTDHANDLES`
        // note below for why inheritance has to be on at all).
        let mut bytes: usize = 0;
        // SAFETY: the first call is DOCUMENTED to fail with the size written out.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut bytes) };
        if bytes == 0 {
            return Err(last_error("InitializeProcThreadAttributeList (sizing)"));
        }
        let mut attr_buf = vec![0u8; bytes];
        let attr_list = attr_buf.as_mut_ptr() as *mut _;
        // SAFETY: buffer is exactly the size the sizing call asked for.
        if unsafe { InitializeProcThreadAttributeList(attr_list, 2, 0, &mut bytes) } == 0 {
            return Err(last_error("InitializeProcThreadAttributeList"));
        }
        // Owned from here on, so every early return below frees the list.
        let mut this = Self {
            si,
            _buf: attr_buf,
            _inherit: Box::new([child_in, child_out]),
        };
        this.si.lpAttributeList = attr_list;

        // ⚠️ `bInheritHandles=TRUE` alone hands the child EVERY inheritable
        // handle in this process — not just the two it needs. In a daemon that
        // is other sessions' pipes; whoever inherits a write end keeps it open,
        // so the owner's reader never EOFs and that session hangs forever.
        // Measured 2026-08-20: unscoped inheritance turned an 8 s test suite
        // into 41 min with three hangs. The handle list is what makes
        // inheritance mean "exactly these two".
        //
        // SAFETY: `_inherit` is owned by `this` and outlives the CreateProcess
        // call the caller makes with this `si`.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                this._inherit.as_mut_ptr() as *const core::ffi::c_void,
                std::mem::size_of::<HANDLE>() * 2,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("UpdateProcThreadAttribute(HANDLE_LIST)"));
        }
        // SAFETY: `pc` outlives the CreateProcess call, which is the only
        // requirement on the value an attribute points at.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                // ⚠️ The HPCON **VALUE**, cast to a pointer — NOT a pointer to
                // it. `lpValue` is by-value for this attribute (Microsoft's own
                // sample passes `hPC` directly with `cbSize = sizeof(HPCON)`),
                // and getting it wrong is silent: `CreateProcessW` SUCCEEDS and
                // the child dies instantly with `0xC0000142`
                // STATUS_DLL_INIT_FAILED because its console never initialised.
                // The only visible symptom is an empty session, so check the
                // child's exit code before suspecting the pipes.
                pc.get() as *const core::ffi::c_void,
                std::mem::size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("UpdateProcThreadAttribute(PSEUDOCONSOLE)"));
        }

        // ⚠️ `USESTDHANDLES` with THREE NULLS. Both halves matter.
        //
        // WITHOUT the flag, the child inherits the PARENT's std-handle VALUES.
        // For a GUI app or a SYSTEM service those are null and the console
        // subsystem fills in console handles — which is why Microsoft's sample
        // omits the flag and why this looked fine. For a parent whose stdout is
        // a PIPE (a daemon started from a shell, or `cargo test` under a
        // runner) the child gets a handle value that means nothing to it, and
        // everything it writes to stdout vanishes. The console still attaches,
        // so the symptom is maximally misleading: the title is set, `ESC[2J`
        // renders, `> CON` works, the exit status is right, and only the
        // program's own output is missing. Measured 2026-08-20 —
        // `echo con-4417 > CON` came back and `echo stdout-4417` did not.
        //
        // NULL rather than the pseudoconsole's pipe ends, which is the obvious
        // thing to reach for and is WRONG: those ends belong to the console
        // HOST. Handing the child `in_read` puts two readers on one pipe, so
        // the child and the host race for the operator's keystrokes and an
        // interactive shell never reliably sees its input — measured, the
        // session hung instead of exiting. NULL is what lets ConDrv assign
        // real CONSOLE handles, which is what a console program wants in both
        // directions.
        this.si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        this.si.StartupInfo.hStdInput = std::ptr::null_mut();
        this.si.StartupInfo.hStdOutput = std::ptr::null_mut();
        this.si.StartupInfo.hStdError = std::ptr::null_mut();
        Ok(this)
    }
}

/// `CreateProcessW` with the pseudoconsole attached — the DAEMON identity:
/// the worker's, which is the signed-in user on an attended install and SYSTEM
/// in SystemContext mode (FR-94 §2).
fn spawn_attached(
    pc: &PseudoConsole,
    cmdline: &str,
    child_in: HANDLE,
    child_out: HANDLE,
) -> Result<PROCESS_INFORMATION, String> {
    let mut startup = AttachedStartupInfo::new(pc, child_in, child_out)?;
    let si = &mut startup.si;

    let mut cmd = wide(cmdline);
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `cmd` is a NUL-terminated mutable UTF-16 buffer, as
    // CreateProcessW requires (it may write to it).
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            // Inheritance is ON because `STARTF_USESTDHANDLES` above requires
            // it — a std handle the child cannot inherit is a std handle it
            // cannot use. EOF is unaffected: the ends handed over here are the
            // CONSOLE's (`CreatePseudoConsole` owns them), and what ends the
            // output stream is `ClosePseudoConsole`, not the child's copies.
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // `startup` drops here, freeing the attribute list.
    if ok == 0 {
        return Err(last_error("CreateProcessW"));
    }
    Ok(pi)
}

/// `CreateProcessAsUserW` with the pseudoconsole attached — an interactive
/// shell as the user signed in at the console, which is what a device policy
/// of `account_mode = console_user` promises.
///
/// This exists because the promise has to be kept on the INTERACTIVE path too.
/// One-shot commands have honoured `console_user` since P5b; before this, a
/// shell on the same device silently could not, and the only honest thing the
/// server could do was refuse. On a corp-managed laptop that cannot host
/// `sshd` at all, "as the signed-in domain user" is the whole point.
///
/// Requires the daemon to be SYSTEM — `WTSQueryUserToken` returns
/// `ERROR_PRIVILEGE_NOT_HELD` otherwise. Only a SystemContext worker is: an
/// attended worker, which serves SSH, runs as the signed-in user even under a
/// perMachine install (FR-94 §2). Reported as a refusal with that reason,
/// never as a fallback to the daemon's own identity.
fn spawn_attached_as_console_user(
    pc: &PseudoConsole,
    cmdline: &str,
    child_in: HANDLE,
    child_out: HANDLE,
) -> Result<PROCESS_INFORMATION, String> {
    use crate::win_service::supervisor;

    let Some(session) = supervisor::active_console_session_id() else {
        return Err(
            "no user is signed in at the console, so there is no session to open a shell in. \
             Set this device's SSH policy to `daemon` if a SYSTEM shell is intended."
                .into(),
        );
    };
    let token = match supervisor::query_user_token(session) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Err(format!(
                "console session {session} has no user token (nobody is signed in at the \
                 console); there is no identity to open a shell as"
            ));
        }
        Err(e) => {
            return Err(format!(
                "cannot obtain the console user's token ({e}): only a daemon running as SYSTEM \
                 may, and on an attended Windows install the worker that serves SSH runs as the \
                 signed-in user. Its `daemon` mode already opens shells as that user."
            ));
        }
    };

    // The user's OWN environment, exactly as the one-shot path builds it: a
    // shell started without it has no PATH and no USERPROFILE, which does not
    // read as a policy decision to the person typing into it — it reads as a
    // broken shell.
    let env = supervisor::EnvBlock::for_token(token.raw())
        .map_err(|e| format!("CreateEnvironmentBlock for the console user failed: {e}"))?;

    let mut startup = AttachedStartupInfo::new(pc, child_in, child_out)?;
    // Interactive desktop, matching every other console-user spawn: the shell's
    // profile may touch things that need one.
    let mut desktop = wide(r"winsta0\default");
    startup.si.StartupInfo.lpDesktop = desktop.as_mut_ptr();

    // FR-97 P5b — in the person's profile, where OpenSSH starts their shell,
    // read from the token the shell runs under. Unreadable (or switched off),
    // it starts where this process is, as before: the shell is still the
    // person, so that costs a directory, never a privilege.
    let profile = if crate::exec::ssh_starts_in_home() {
        let dir = crate::win_identity::profile_dir_of_token(token.raw());
        if dir.is_none() {
            warn!(session, "console user's profile directory unreadable");
        }
        dir.map(|d| wide(&d))
    } else {
        None
    };
    let mut cmd = wide(cmdline);
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `token` is a live primary token for the console session; `cmd`
    // is a NUL-terminated mutable UTF-16 buffer; the env block, the attribute
    // list and the directory all outlive the call.
    let ok = unsafe {
        CreateProcessAsUserW(
            token.raw(),
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            // Bounded by the handle list — see `AttachedStartupInfo`.
            1,
            // No `CREATE_NO_WINDOW`: the pseudoconsole IS this child's console,
            // and suppressing console creation fights the attribute that just
            // gave it one.
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env.raw,
            profile.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            &startup.si.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateProcessAsUserW"));
    }
    Ok(pi)
}

/// A job object that kills its members when the last handle closes.
fn make_job(process: HANDLE) -> Result<Owned, String> {
    // SAFETY: an unnamed job object with default security.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(last_error("CreateJobObjectW"));
    }
    let job = Owned(job);
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `info` matches the class being set and outlives the call.
    let ok = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error("SetInformationJobObject"));
    }
    // SAFETY: both handles are live and owned.
    if unsafe { AssignProcessToJobObject(job.0, process) } == 0 {
        // Not fatal on its own — the session still works, it just loses the
        // "kills descendants" guarantee. Say so rather than pretend.
        warn!(
            err = %io::Error::last_os_error(),
            "ssh: could not put the session in a job object — descendants may outlive it"
        );
    }
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `named:<account>` is refused on Windows for the same reason
    /// `exec::apply_run_as` refuses it: becoming an arbitrary local user needs
    /// that user's credentials. The refusal must SAY that — and must never be
    /// a quiet downgrade to the daemon's own (SYSTEM) identity, which is the
    /// exact failure P5c and P5d exist to prevent.
    #[test]
    fn a_named_account_is_refused_rather_than_silently_downgraded() {
        let who = crate::exec::RunAs::Named("someone".into());
        let err = PtyProcess::spawn(None, "xterm", WinSize { cols: 80, rows: 24 }, &who)
            .expect_err("a named local account cannot be assumed on Windows");
        assert!(
            err.contains("credentials"),
            "the refusal must be explicit about WHY, got {err:?}"
        );
    }

    /// `console_user` is now ATTEMPTED (P4b) rather than refused outright — but
    /// only a SYSTEM daemon can obtain the console token, and a test process is
    /// not one. So this asserts the shape of the failure: it must name the
    /// SYSTEM requirement, and it must NOT hand back a working shell, because a
    /// shell running as SYSTEM when the policy said `console_user` is precisely
    /// the lie this design exists to prevent.
    ///
    /// The success side of the same path is field-proven, not unit-tested:
    /// `WTSQueryUserToken` needs a real signed-in console session, which CI
    /// does not have.
    #[test]
    fn console_user_is_attempted_and_fails_loudly_without_system() {
        let who = crate::exec::RunAs::ConsoleUser;
        match PtyProcess::spawn(None, "xterm", WinSize { cols: 80, rows: 24 }, &who) {
            Err(e) => assert!(
                e.contains("SYSTEM") || e.contains("signed in"),
                "the failure must explain what console_user needs, got {e:?}"
            ),
            // Only reachable if the suite is run AS SYSTEM with a user signed
            // in — then the session is genuinely the console user's, which is
            // the feature working.
            Ok(p) => p.kill_group(),
        }
    }

    /// P4b (shipped in rc.429): a ConPTY session streams the application's
    /// output through the pipes and reports its exit status (`exit 3` → 3).
    ///
    /// The defect this test was written to catch, and now guards against: a
    /// session that came back holding only the console host's own
    /// init/teardown VT (`ESC[?9001h … ESC[2J … title`) and none of the
    /// application's output, on cmd.exe and PowerShell alike, however long the
    /// post-exit drain waited. Until that was fixed the test was ignored and
    /// the SSH server refused Windows PTY requests, so nothing shipped a
    /// session that would come back empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_streams_output_and_reports_its_exit_status() {
        let mut pty = PtyProcess::spawn(
            Some("Write-Output conpty-marker-4417; exit 3"),
            "xterm",
            WinSize { cols: 80, rows: 24 },
            &crate::exec::RunAs::Daemon,
        )
        .expect("a conpty session");

        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match pty.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("conpty-marker-4417"),
            "expected the command's output, got {text:?}"
        );
        assert_eq!(pty.wait().await, 3, "the shell's exit code must survive");
    }

    /// Resizing a live pseudoconsole is accepted — a client window change must
    /// not fail the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_live_console_can_be_resized() {
        let mut pty = PtyProcess::spawn(
            None,
            "xterm",
            WinSize { cols: 80, rows: 24 },
            &crate::exec::RunAs::Daemon,
        )
        .expect("a conpty session");
        pty.handle()
            .resize(WinSize {
                cols: 160,
                rows: 50,
            })
            .expect("resizing a live pseudoconsole");
        pty.kill_group();
        let _ = pty.wait().await;
    }
}
