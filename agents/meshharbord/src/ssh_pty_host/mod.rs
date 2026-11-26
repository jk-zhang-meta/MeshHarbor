// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Out-of-process detached PTY session host (`meshharbord ssh-pty-host`).
//!
//! Runs as a separate process outside the daemon's restart/update kill domain
//! (Linux `systemd-run --scope`, non-systemd/macOS `setsid`, Windows staged
//! binary + `spawn_detached_no_inherit` + named Job Object).
//!
//! Security & hygiene invariants:
//! - Dispatched BEFORE clap, logging, config, or instance lock (`exit_if_requested`).
//! - Immediately closes every inherited fd >= 3 and redirects stdio to `/dev/null`
//!   so it NEVER holds the daemon's TUN fd, socket, or instance lock.
//! - Holds ZERO secrets — only the serialized `SessionDescriptor` and its HMAC
//!   `seal`. The daemon verifies seals and client resume proofs statelessly.
//! - Frozen `0x00 Terminate` IPC frame works across all future/past daemon versions.
//! - Independently enforces wall+monotonic deadline, detach TTL, and 10 min
//!   orphan TTL (fails closed if the daemon disappears or is downgraded).

#[cfg(feature = "ssh-server")]
use std::ffi::OsStr;
#[cfg(feature = "ssh-server")]
use std::path::{Path, PathBuf};
#[cfg(feature = "ssh-server")]
use std::time::{Duration, Instant};

#[cfg(feature = "ssh-server")]
use meshharbor_node_core::pty_resume::{
    DEFAULT_RING_BYTES, ExitStatusInfo, IPC_VERSION, MAX_DATA_CHUNK, NoticeKind, PersistStatus,
    ReplayKind, RunAsDescriptor, STREAM_STDIN, STREAM_STDOUT, SessionDescriptor, TerminateReason,
    clamp_dims,
    frame::WireFrame,
    ipc::{
        AttachStartFrame, HostHelloFrame, HostState, IpcFrame, SpawnErrorFrame, SpawnSpec,
        SpawnedFrame,
    },
    now_unix_ms,
    seq::{ByteRing, C2sHostDedup, VtScreenTracker},
};
#[cfg(feature = "ssh-server")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "ssh-server")]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "ssh-server")]
use tokio::sync::mpsc;

/// Hidden subcommand name (`meshharbord ssh-pty-host --meta-file <path>`).
pub const SUBCOMMAND: &str = "ssh-pty-host";

/// Bootstrap metadata written by `ssh_persist` to a `0600` temp file and
/// unlinked immediately by the host on startup (zero secrets inside).
#[cfg(feature = "ssh-server")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostBootstrapMeta {
    pub endpoint: String,
    pub descriptor_json: Vec<u8>,
    pub seal: [u8; 32],
    #[serde(default)]
    pub scope_unit: Option<String>,
    #[serde(default)]
    pub job_name: Option<String>,
    /// Expected daemon uid allowed to connect via `SO_PEERCRED`/`getpeereid`.
    #[serde(default)]
    pub allowed_uid: Option<u32>,
}

/// Returns `true` when invoked as `<exe> ssh-pty-host ...`.
#[cfg(feature = "ssh-server")]
pub fn requested() -> bool {
    std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == OsStr::new(SUBCOMMAND))
}

/// Pre-clap dispatch in `main.rs` (mirrors `sftp_builtin::exit_if_requested`).
/// Never touches daemon logs, config, or instance locks.
#[cfg(feature = "ssh-server")]
pub fn exit_if_requested() {
    if !requested() {
        return;
    }

    // 1. Parse `--meta-file <path>` BEFORE closing fds or creating runtime.
    let meta_path = match parse_meta_file_arg() {
        Some(p) => p,
        None => std::process::exit(2),
    };

    // 2. Read & immediately remove bootstrap metadata file.
    let meta_bytes = match std::fs::read(&meta_path) {
        Ok(b) => {
            let _ = std::fs::remove_file(&meta_path);
            b
        }
        Err(_) => std::process::exit(3),
    };
    let meta: HostBootstrapMeta = match serde_json::from_slice(&meta_bytes) {
        Ok(m) => m,
        Err(_) => std::process::exit(4),
    };

    // 3. Close every inherited fd >= 3, detach stdio to /dev/null, harden dumpable.
    harden_process_before_runtime();

    let code = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => {
            let res = rt.block_on(run_host(meta));
            if res.is_ok() { 0 } else { 1 }
        }
        Err(_) => 1,
    };
    std::process::exit(code);
}

#[cfg(feature = "ssh-server")]
fn parse_meta_file_arg() -> Option<PathBuf> {
    let mut it = std::env::args_os().skip(2);
    while let Some(arg) = it.next() {
        if arg == OsStr::new("--meta-file") {
            return it.next().map(PathBuf::from);
        }
    }
    None
}

#[cfg(feature = "ssh-server")]
fn harden_process_before_runtime() {
    #[cfg(unix)]
    {
        // Redirect stdin/stdout/stderr to /dev/null so the host never holds a
        // parent pipe or tty open.
        unsafe {
            let null_path = c"/dev/null";
            let devnull = libc::open(null_path.as_ptr(), libc::O_RDWR);
            if devnull >= 0 {
                let _ = libc::dup2(devnull, 0);
                let _ = libc::dup2(devnull, 1);
                let _ = libc::dup2(devnull, 2);
                if devnull > 2 {
                    libc::close(devnull);
                }
            }
        }
        close_inherited_fds_from(3);

        #[cfg(target_os = "linux")]
        unsafe {
            // Prevent non-root ptrace attachment to the session host.
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

#[cfg(all(unix, feature = "ssh-server"))]
fn close_inherited_fds_from(first_fd: i32) {
    // Fast path on Linux >= 5.9: `SYS_close_range(3, !0, 0)`.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: raw syscall with no pointers; closes inherited fds >= 3.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first_fd as libc::c_uint,
                libc::c_uint::MAX,
                0 as libc::c_uint,
            )
        };
        if rc == 0 {
            return;
        }
    }

    // Fallback: enumerate `/proc/self/fd` (Linux) or `/dev/fd` (macOS).
    let fd_dir = if Path::new("/proc/self/fd").is_dir() {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    if let Ok(entries) = std::fs::read_dir(fd_dir) {
        let mut to_close = Vec::new();
        for ent in entries.flatten() {
            if let Ok(name) = ent.file_name().into_string()
                && let Ok(fd) = name.parse::<i32>()
                && fd >= first_fd
            {
                to_close.push(fd);
            }
        }
        for fd in to_close {
            unsafe {
                libc::close(fd);
            }
        }
        return;
    }

    // Last resort: bounded scan up to RLIMIT_NOFILE (capped at 4096).
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(256, 4096) as i32;
    for fd in first_fd..max_fd {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Measure actual OS restart-survival isolation from inside the host process.
#[cfg(feature = "ssh-server")]
fn measure_persist_status(scope_unit: Option<&str>) -> PersistStatus {
    #[cfg(target_os = "linux")]
    {
        if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
            return PersistStatus::degraded("container");
        }
        if let Some(unit) = scope_unit {
            if let Ok(cg) = std::fs::read_to_string("/proc/self/cgroup")
                && cg.contains(unit)
            {
                return PersistStatus::survives();
            }
            return PersistStatus::degraded("cgroup_escape_unverified");
        }
        if !Path::new("/run/systemd/system").exists() {
            return PersistStatus::survives();
        }
        PersistStatus::degraded("systemd_same_cgroup")
    }
    #[cfg(target_os = "macos")]
    {
        let _ = scope_unit;
        PersistStatus::survives()
    }
    #[cfg(windows)]
    {
        let _ = scope_unit;
        PersistStatus::survives()
    }
}

#[cfg(feature = "ssh-server")]
enum InternalEvent {
    PtyOutput(Vec<u8>),
    PtyExited(ExitStatusInfo),
    StdinAck { conn_id: u64, upto: u64 },
    ConnDropped(u64),
    ClientFrame { conn_id: u64, frame: IpcFrame },
}

#[cfg(feature = "ssh-server")]
struct HostCore {
    descriptor_json: Vec<u8>,
    descriptor: SessionDescriptor,
    seal: [u8; 32],
    persist: PersistStatus,
    scope_unit: Option<String>,
    job_name: Option<String>,
    state: HostState,
    ring: ByteRing,
    vt: VtScreenTracker,
    dedup: C2sHostDedup,
    pty_handle: Option<crate::pty::PtyHandle>,
    /// Bounded non-blocking channel to dedicated PTY stdin writer task so full
    /// PTY stdin buffers NEVER stall `Terminate` or deadline ticks!
    stdin_tx: Option<mpsc::Sender<(u64, u64, Vec<u8>)>>,
    pty_kill_tx: Option<tokio::sync::oneshot::Sender<u32>>,
    child_pid: Option<u32>,
    exit_status: Option<ExitStatusInfo>,
    /// Active attached daemon IPC connection (at most ONE client attached).
    active_attach: Option<(u64, mpsc::Sender<IpcFrame>)>,
    /// All currently open daemon IPC control/attach connections.
    conns: std::collections::HashMap<u64, mpsc::Sender<IpcFrame>>,
    /// When the last client detached (for snapshot offline duration + detach TTL).
    detached_since: Option<Instant>,
    /// When the last daemon connection dropped (for fail-closed 10 min orphan TTL).
    orphan_since: Option<Instant>,
    /// When the child process exited (for exit linger TTL).
    exited_since: Option<Instant>,
    /// Client requested `WireFrame::Terminate`; exit host right after delivering `Exited`.
    terminating_for_client: bool,
    terminating_deadline: Option<Instant>,
    /// Monotonic deadline mirroring wall-clock `descriptor.deadline_ms`.
    deadline_at: Instant,
    deadline_warned: bool,
    detach_ttl: Duration,
    orphan_ttl: Duration,
}

#[cfg(feature = "ssh-server")]
impl HostCore {
    fn new(meta: HostBootstrapMeta) -> Result<Self, String> {
        let descriptor: SessionDescriptor = serde_json::from_slice(&meta.descriptor_json)
            .map_err(|e| format!("invalid descriptor json: {e}"))?;
        let now_ms = now_unix_ms();
        let rem_deadline_ms = descriptor.deadline_ms.saturating_sub(now_ms);
        let max_ms = meshharbor_remote_control::models::ssh_limits::MAX_SESSION_SECS * 1000;
        let deadline_dur = Duration::from_millis(rem_deadline_ms.min(max_ms));
        let detach_ttl = Duration::from_millis(descriptor.detach_ttl_ms.min(max_ms).max(10_000));
        let orphan_ttl = Duration::from_millis(descriptor.orphan_ttl_ms.clamp(30_000, 3_600_000));
        let persist = measure_persist_status(meta.scope_unit.as_deref());

        Ok(Self {
            descriptor_json: meta.descriptor_json,
            descriptor,
            seal: meta.seal,
            persist,
            scope_unit: meta.scope_unit,
            job_name: meta.job_name,
            state: HostState::AwaitingSpawn,
            ring: ByteRing::new(DEFAULT_RING_BYTES),
            vt: VtScreenTracker::new(80, 24, 1000),
            dedup: C2sHostDedup::new(),
            pty_handle: None,
            stdin_tx: None,
            pty_kill_tx: None,
            child_pid: None,
            exit_status: None,
            active_attach: None,
            conns: std::collections::HashMap::new(),
            detached_since: Some(Instant::now()),
            orphan_since: Some(Instant::now()),
            exited_since: None,
            terminating_for_client: false,
            terminating_deadline: None,
            deadline_at: Instant::now() + deadline_dur,
            deadline_warned: false,
            detach_ttl,
            orphan_ttl,
        })
    }

    fn make_hello(&self) -> IpcFrame {
        IpcFrame::HostHello(HostHelloFrame {
            ipc_min: IPC_VERSION,
            ipc_max: IPC_VERSION,
            build: env!("CARGO_PKG_VERSION").to_string(),
            descriptor_json: self.descriptor_json.clone(),
            seal: self.seal,
            state: self.state,
            s2c_head: self.ring.head_offset(),
            c2s_next: self.dedup.next_expected(),
            attached: self.active_attach.is_some(),
            child_pid: self.child_pid,
            exit_status: self.exit_status.clone(),
            persist: self.persist.clone(),
            scope_unit: self.scope_unit.clone(),
            job_name: self.job_name.clone(),
        })
    }

    fn run_as_from_spec(desc: &RunAsDescriptor) -> crate::exec::RunAs {
        match desc {
            RunAsDescriptor::Daemon => crate::exec::RunAs::Daemon,
            RunAsDescriptor::ConsoleUser => crate::exec::RunAs::ConsoleUser,
            RunAsDescriptor::Named { username, .. } => crate::exec::RunAs::Named(username.clone()),
        }
    }

    fn send_to_conn(&self, conn_id: u64, frame: IpcFrame) {
        if let Some(tx) = self.conns.get(&conn_id) {
            let _ = tx.try_send(frame);
        }
    }

    /// Send to the active viewer; if its channel is saturated or closed, drop
    /// that lagging attachment cleanly (never silently skip stdout or Exited
    /// frames!) so the viewer reconnects and replays losslessly from `last_rx`.
    fn send_to_active(&mut self, frame: IpcFrame) {
        if let Some((conn_id, tx)) = &self.active_attach
            && tx.try_send(frame).is_err()
        {
            let cid = *conn_id;
            self.active_attach = None;
            self.detached_since = Some(Instant::now());
            self.conns.remove(&cid);
        }
    }

    fn is_active_conn(&self, conn_id: u64) -> bool {
        self.active_attach
            .as_ref()
            .is_some_and(|(id, _)| *id == conn_id)
    }

    fn handle_spawn(&mut self, conn_id: u64, spec: SpawnSpec, ev_tx: &mpsc::Sender<InternalEvent>) {
        if self.state != HostState::AwaitingSpawn {
            self.send_to_conn(
                conn_id,
                IpcFrame::SpawnError(SpawnErrorFrame {
                    message: "host already spawned".into(),
                }),
            );
            return;
        }
        let (cols, rows) = clamp_dims(spec.cols, spec.rows);
        self.ring = ByteRing::new((spec.ring_bytes as usize).clamp(64 * 1024, 16 * 1024 * 1024));
        self.vt.resize(cols, rows);
        let run_as = Self::run_as_from_spec(&spec.run_as);
        let size = crate::pty::WinSize { cols, rows };
        let mut pty = match crate::pty::PtyProcess::spawn_with_env(
            spec.command.as_deref(),
            &spec.term,
            size,
            &run_as,
            &spec.env,
        ) {
            Ok(p) => p,
            Err(e) => {
                self.send_to_conn(
                    conn_id,
                    IpcFrame::SpawnError(SpawnErrorFrame { message: e }),
                );
                return;
            }
        };

        #[cfg(unix)]
        pty.hard_kill_on_drop();

        let pid = pty.child_pid().unwrap_or(0);
        self.child_pid = Some(pid);
        let pty_handle = pty.handle();
        let write_handle = pty_handle.clone();
        self.pty_handle = Some(pty_handle);
        self.state = HostState::Running;

        // Dedicated non-blocking stdin writer task: writes to PTY slave without
        // ever stalling `HostCore` control/terminate/deadline processing!
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<(u64, u64, Vec<u8>)>(256);
        self.stdin_tx = Some(stdin_tx);
        let ack_tx = ev_tx.clone();
        tokio::spawn(async move {
            while let Some((cid, upto, bytes)) = stdin_rx.recv().await {
                if !bytes.is_empty() && write_handle.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = ack_tx
                    .send(InternalEvent::StdinAck { conn_id: cid, upto })
                    .await;
            }
        });

        // Spawn reader + waiter task owning `pty` so kill signal works cleanly.
        let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<u32>();
        self.pty_kill_tx = Some(kill_tx);
        let out_tx = ev_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let exit_code: u32 = loop {
                tokio::select! {
                    biased;
                    grace = &mut kill_rx => {
                        let grace_ms = grace.unwrap_or(1500);
                        #[cfg(unix)]
                        {
                            pty.kill_group();
                            let _ = tokio::time::timeout(
                                Duration::from_millis(u64::from(grace_ms.min(5000))),
                                pty.wait(),
                            ).await;
                            break pty.terminate_and_wait().await.unwrap_or(143);
                        }
                        #[cfg(windows)]
                        {
                            let _ = grace_ms;
                            break pty.terminate_and_wait().await.unwrap_or(1);
                        }
                    }
                    res = pty.read(&mut buf) => {
                        match res {
                            Ok(0) | Err(_) => break pty.wait().await,
                            Ok(n) => {
                                if out_tx.send(InternalEvent::PtyOutput(buf[..n].to_vec())).await.is_err() {
                                    break pty.wait().await;
                                }
                            }
                        }
                    }
                }
            };
            let _ = out_tx
                .send(InternalEvent::PtyExited(ExitStatusInfo::from_ssh_u32(
                    exit_code,
                )))
                .await;
        });

        self.send_to_conn(conn_id, IpcFrame::Spawned(SpawnedFrame { child_pid: pid }));
    }

    fn handle_attach(&mut self, conn_id: u64, req: AttachStartFrame) {
        let Some(tx) = self.conns.get(&conn_id).cloned() else {
            return;
        };

        // Preempt any prior active attachment cleanly (make-before-break!).
        if let Some((old_id, old_tx)) = self.active_attach.take()
            && old_id != conn_id
        {
            let _ = old_tx.try_send(IpcFrame::Wire(WireFrame::Notice(NoticeKind::Superseded)));
        }

        let offline_secs = self
            .detached_since
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        self.detached_since = None;
        self.orphan_since = None;

        let (cols, rows) = clamp_dims(req.cols, req.rows);
        let can_replay = self.ring.can_replay_from(req.last_rx);
        let gap_bytes = self.ring.gap_from(req.last_rx);
        let max_snap_bytes = meshharbor_node_core::pty_resume::MAX_FRAME_BYTES.saturating_sub(1024);
        let (replay_kind, snapshot_payload) = if can_replay {
            (ReplayKind::Bytes, None)
        } else if req.snapshot_allowed && self.vt.is_healthy() {
            match self.vt.build_snapshot(gap_bytes, offline_secs) {
                Some(snap) if snap.len() <= max_snap_bytes => (ReplayKind::Snapshot, Some(snap)),
                _ => (ReplayKind::Bytes, None),
            }
        } else {
            (ReplayKind::Bytes, None)
        };

        let attached = WireFrame::Attached(meshharbor_node_core::pty_resume::frame::AttachedFrame {
            server_proof: req.server_proof,
            replay: replay_kind,
            gap_bytes,
            c2s_acked: self.dedup.next_expected(),
        });
        if tx.try_send(IpcFrame::Wire(attached)).is_err() {
            self.conns.remove(&conn_id);
            self.detached_since = Some(Instant::now());
            return;
        }

        match snapshot_payload {
            Some(bytes) => {
                let alt = self.vt.is_alternate_screen();
                let (vt_cols, vt_rows) = self.vt.size();
                if tx
                    .try_send(IpcFrame::Wire(WireFrame::Snapshot {
                        at_seq: self.ring.head_offset(),
                        alt_screen: alt,
                        cols: vt_cols,
                        rows: vt_rows,
                        bytes,
                    }))
                    .is_err()
                {
                    self.conns.remove(&conn_id);
                    self.detached_since = Some(Instant::now());
                    return;
                }
                // Force SIGWINCH redraw in alternate-screen TUI apps (vim/htop/nvitop).
                if alt && let Some(handle) = &self.pty_handle {
                    let tweak = if cols > 2 { cols - 1 } else { cols + 1 };
                    let _ = handle.resize(crate::pty::WinSize { cols: tweak, rows });
                }
            }
            None => {
                let start = req.last_rx.max(self.ring.base_offset());
                if let Some(missed) = self.ring.read_from(start) {
                    let mut seq = start;
                    for chunk in missed.chunks(MAX_DATA_CHUNK) {
                        if tx
                            .try_send(IpcFrame::Wire(WireFrame::Data {
                                stream: STREAM_STDOUT,
                                seq,
                                bytes: chunk.to_vec(),
                            }))
                            .is_err()
                        {
                            self.conns.remove(&conn_id);
                            self.detached_since = Some(Instant::now());
                            return;
                        }
                        seq = seq.saturating_add(chunk.len() as u64);
                    }
                }
            }
        }

        // Apply client's current geometry.
        self.vt.resize(cols, rows);
        if let Some(handle) = &self.pty_handle {
            let _ = handle.resize(crate::pty::WinSize { cols, rows });
        }

        if let Some(status) = &self.exit_status
            && tx
                .try_send(IpcFrame::Wire(WireFrame::Exited(status.clone())))
                .is_err()
        {
            self.conns.remove(&conn_id);
            self.detached_since = Some(Instant::now());
            return;
        }

        self.active_attach = Some((conn_id, tx));
    }

    fn handle_wire(&mut self, conn_id: u64, wf: WireFrame) -> bool {
        let is_active = self.is_active_conn(conn_id);
        match wf {
            WireFrame::Data { stream, seq, bytes } if stream == STREAM_STDIN && is_active => {
                if let Some(tx) = &self.stdin_tx {
                    if let Ok(permit) = tx.try_reserve() {
                        let fresh = self.dedup.accept(seq, &bytes).to_vec();
                        let upto = self.dedup.next_expected();
                        if fresh.is_empty() {
                            drop(permit);
                            self.send_to_conn(
                                conn_id,
                                IpcFrame::Wire(WireFrame::Ack {
                                    stream: STREAM_STDIN,
                                    upto,
                                }),
                            );
                        } else {
                            permit.send((conn_id, upto, fresh));
                        }
                    }
                } else {
                    self.send_to_conn(
                        conn_id,
                        IpcFrame::Wire(WireFrame::Ack {
                            stream: STREAM_STDIN,
                            upto: self.dedup.next_expected(),
                        }),
                    );
                }
            }
            WireFrame::Ack { stream, upto }
                if stream == STREAM_STDOUT
                    && is_active
                    && self.state == HostState::Exited
                    && upto >= self.ring.head_offset() =>
            {
                // Once the client has acknowledged everything up through child
                // exit, the host can exit cleanly without lingering.
                return true;
            }
            WireFrame::Resize { cols, rows } if is_active => {
                let (cols, rows) = clamp_dims(cols, rows);
                self.vt.resize(cols, rows);
                if let Some(handle) = &self.pty_handle {
                    let _ = handle.resize(crate::pty::WinSize { cols, rows });
                }
            }
            WireFrame::Ping { t_ms } => {
                self.send_to_conn(conn_id, IpcFrame::Wire(WireFrame::Pong { t_ms }));
            }
            WireFrame::Detach if is_active => {
                self.active_attach = None;
                self.detached_since = Some(Instant::now());
            }
            WireFrame::Terminate if is_active => {
                if let Some(status) = self.exit_status.clone() {
                    self.send_to_active(IpcFrame::Wire(WireFrame::Exited(status)));
                    return true;
                }
                self.terminating_for_client = true;
                self.terminating_deadline = Some(Instant::now() + Duration::from_secs(2));
                self.terminate_child(1500);
            }
            _ => {}
        }
        false
    }

    fn terminate_child(&mut self, grace_ms: u32) {
        self.stdin_tx = None;
        if let Some(kill_tx) = self.pty_kill_tx.take() {
            let _ = kill_tx.send(grace_ms);
        }
        self.pty_handle = None;
    }

    fn should_expire(&mut self) -> Option<TerminateReason> {
        let now = Instant::now();
        let wall_now = now_unix_ms();

        // Hard deadline check (both monotonic & wall clock).
        if now >= self.deadline_at || wall_now >= self.descriptor.deadline_ms {
            return Some(TerminateReason::Expired);
        }
        if !self.deadline_warned
            && self.deadline_at.saturating_duration_since(now) <= Duration::from_secs(60)
        {
            self.deadline_warned = true;
            let in_ms = self
                .deadline_at
                .saturating_duration_since(now)
                .as_millis() as u64;
            self.send_to_active(IpcFrame::Wire(WireFrame::Notice(
                NoticeKind::DeadlineSoon { in_ms },
            )));
        }

        // Fail-closed orphan TTL when no daemon is connected.
        if let Some(since) = self.orphan_since
            && self.conns.is_empty()
            && since.elapsed() >= self.orphan_ttl
        {
            return Some(TerminateReason::OrphanTimeout);
        }

        // Detach TTL when no client is attached.
        if let Some(since) = self.detached_since
            && self.active_attach.is_none()
            && since.elapsed() >= self.detach_ttl
        {
            return Some(TerminateReason::DetachTimeout);
        }

        // Post-exit linger cap (max 5 min after child exits without client ACK).
        if let Some(since) = self.exited_since
            && since.elapsed() >= Duration::from_secs(300)
        {
            return Some(TerminateReason::Shutdown);
        }

        // AwaitingSpawn timeout: if daemon never sent Spawn within 15 s, exit.
        if self.state == HostState::AwaitingSpawn
            && self
                .detached_since
                .is_some_and(|s| s.elapsed() >= Duration::from_secs(15))
        {
            return Some(TerminateReason::OrphanTimeout);
        }

        None
    }
}

#[cfg(feature = "ssh-server")]
async fn run_host(meta: HostBootstrapMeta) -> Result<(), String> {
    let endpoint = meta.endpoint.clone();
    let allowed_uid = meta.allowed_uid;
    let mut core = HostCore::new(meta)?;

    let (ev_tx, mut ev_rx) = mpsc::channel::<InternalEvent>(256);
    let (new_conn_tx, mut new_conn_rx) = mpsc::channel::<(u64, mpsc::Sender<IpcFrame>)>(16);

    #[cfg(unix)]
    let listener_task = {
        let ep = endpoint.clone();
        let ev_tx = ev_tx.clone();
        let new_conn_tx = new_conn_tx.clone();
        let listener = bind_unix_socket(&ep)?;
        tokio::spawn(async move {
            let mut next_id: u64 = 1;
            while let Ok((stream, _)) = listener.accept().await {
                if !verify_unix_peer(&stream, allowed_uid) {
                    continue;
                }
                let conn_id = next_id;
                next_id += 1;
                let (out_tx, out_rx) = mpsc::channel::<IpcFrame>(512);
                if new_conn_tx.send((conn_id, out_tx)).await.is_err() {
                    break;
                }
                let ev_tx = ev_tx.clone();
                tokio::spawn(pump_ipc_conn(conn_id, stream, out_rx, ev_tx));
            }
        })
    };

    #[cfg(windows)]
    let listener_task = {
        let ep = endpoint.clone();
        let ev_tx = ev_tx.clone();
        let new_conn_tx = new_conn_tx.clone();
        let _ = allowed_uid;
        tokio::spawn(async move {
            use tokio::net::windows::named_pipe::ServerOptions;
            let mut next_id: u64 = 1;
            let mut first = true;
            loop {
                let mut opts = ServerOptions::new();
                if first {
                    opts.first_pipe_instance(true);
                    first = false;
                }
                let Ok(server) = opts.create(&ep) else {
                    break;
                };
                if server.connect().await.is_err() {
                    continue;
                }
                let conn_id = next_id;
                next_id += 1;
                let (out_tx, out_rx) = mpsc::channel::<IpcFrame>(512);
                if new_conn_tx.send((conn_id, out_tx)).await.is_err() {
                    break;
                }
                let ev_tx = ev_tx.clone();
                tokio::spawn(pump_ipc_conn(conn_id, server, out_rx, ev_tx));
            }
        })
    };

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            Some((conn_id, out_tx)) = new_conn_rx.recv() => {
                core.orphan_since = None;
                let hello = core.make_hello();
                let _ = out_tx.try_send(hello);
                core.conns.insert(conn_id, out_tx);
            }
            Some(ev) = ev_rx.recv() => {
                match ev {
                    InternalEvent::PtyOutput(data) => {
                        let seq = core.ring.push(&data);
                        core.vt.process(&data);
                        if core.active_attach.is_some() {
                            let mut off = seq;
                            for chunk in data.chunks(MAX_DATA_CHUNK) {
                                core.send_to_active(IpcFrame::Wire(WireFrame::Data {
                                    stream: STREAM_STDOUT,
                                    seq: off,
                                    bytes: chunk.to_vec(),
                                }));
                                off = off.saturating_add(chunk.len() as u64);
                            }
                        }
                    }
                    InternalEvent::PtyExited(status) => {
                        core.state = HostState::Exited;
                        core.exit_status = Some(status.clone());
                        core.exited_since = Some(Instant::now());
                        core.pty_handle = None;
                        core.stdin_tx = None;
                        core.send_to_active(IpcFrame::Wire(WireFrame::Exited(status)));
                        if core.terminating_for_client {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            break;
                        }
                    }
                    InternalEvent::StdinAck { conn_id, upto } => {
                        core.send_to_conn(
                            conn_id,
                            IpcFrame::Wire(WireFrame::Ack {
                                stream: STREAM_STDIN,
                                upto,
                            }),
                        );
                    }
                    InternalEvent::ConnDropped(conn_id) => {
                        core.conns.remove(&conn_id);
                        if core.active_attach.as_ref().is_some_and(|(id, _)| *id == conn_id) {
                            core.active_attach = None;
                            core.detached_since = Some(Instant::now());
                        }
                        if core.conns.is_empty() {
                            core.orphan_since = Some(Instant::now());
                        }
                    }
                    InternalEvent::ClientFrame { conn_id, frame } => {
                        match frame {
                            IpcFrame::Terminate(t) => {
                                core.terminate_child(t.grace_ms);
                                break;
                            }
                            IpcFrame::Ping { t_ms } => {
                                core.send_to_conn(conn_id, IpcFrame::Pong { t_ms });
                            }
                            IpcFrame::DaemonDetaching(d) => {
                                core.send_to_active(IpcFrame::Wire(WireFrame::Notice(
                                    NoticeKind::TargetRestarting {
                                        reason: d.reason,
                                        eta_ms: d.eta_ms,
                                        to_version: d.to_version,
                                    },
                                )));
                                core.orphan_since = Some(Instant::now());
                            }
                            IpcFrame::Spawn(spec) => {
                                core.handle_spawn(conn_id, spec, &ev_tx);
                            }
                            IpcFrame::AttachStart(req) => {
                                core.handle_attach(conn_id, req);
                            }
                            IpcFrame::Wire(wf) => {
                                let should_exit = core.handle_wire(conn_id, wf);
                                if should_exit {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ = tick.tick() => {
                if core.terminating_deadline.is_some_and(|d| Instant::now() >= d) {
                    break;
                }
                if core.should_expire().is_some() {
                    core.terminate_child(1500);
                    break;
                }
            }
        }
    }

    listener_task.abort();
    // Give the PTY cleanup task a brief moment to send SIGKILL and reap.
    tokio::time::sleep(Duration::from_millis(120)).await;
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&endpoint);
    }
    Ok(())
}

#[cfg(feature = "ssh-server")]
async fn pump_ipc_conn<S>(
    conn_id: u64,
    stream: S,
    mut out_rx: mpsc::Receiver<IpcFrame>,
    ev_tx: mpsc::Sender<InternalEvent>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if frame.write_to(&mut wr).await.is_err() {
                break;
            }
        }
    });

    while let Ok(Some(frame)) = IpcFrame::read_from(&mut rd).await {
        if ev_tx
            .send(InternalEvent::ClientFrame { conn_id, frame })
            .await
            .is_err()
        {
            break;
        }
    }

    writer.abort();
    let _ = ev_tx.send(InternalEvent::ConnDropped(conn_id)).await;
}

#[cfg(all(unix, feature = "ssh-server"))]
fn bind_unix_socket(path: &str) -> Result<tokio::net::UnixListener, String> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _ = std::fs::remove_file(p);
    // Bind under umask(077) so the socket inode is NEVER world-accessible even
    // for a microsecond between bind(2) and chmod(2).
    let prev = unsafe { libc::umask(0o077) };
    let res = tokio::net::UnixListener::bind(p);
    unsafe {
        libc::umask(prev);
    }
    res.map_err(|e| format!("bind uds {path}: {e}"))
}

#[cfg(all(unix, feature = "ssh-server"))]
fn verify_unix_peer(stream: &tokio::net::UnixStream, allowed_uid: Option<u32>) -> bool {
    let Ok(cred) = stream.peer_cred() else {
        return false;
    };
    let peer_uid = cred.uid();
    let my_uid = unsafe { libc::geteuid() };
    peer_uid == 0 || peer_uid == my_uid || allowed_uid.is_some_and(|u| peer_uid == u)
}
