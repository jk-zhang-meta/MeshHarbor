// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Daemon-side persistent SSH session registry, device master key,
//! detached `ssh-pty-host` spawner, boot-time adoption, pre-restart announcement,
//! and explicit revocation across every teardown path.

#[cfg(feature = "ssh-server")]
pub mod subsystem;

#[cfg(feature = "ssh-server")]
use std::collections::HashMap;
#[cfg(feature = "ssh-server")]
use std::path::{Path, PathBuf};
#[cfg(feature = "ssh-server")]
use std::sync::{Mutex, OnceLock};
#[cfg(feature = "ssh-server")]
use std::time::Duration;

use meshharbor_node_core::pty_resume::TerminateReason;
#[cfg(feature = "ssh-server")]
use meshharbor_node_core::pty_resume::{
    PersistStatus, RefuseReason, SessionDescriptor, SessionId,
    ipc::{
        AttachStartFrame, DaemonDetachingFrame, HostHelloFrame, HostState, IpcFrame, SpawnSpec,
        TerminateFrame,
    },
    now_unix_ms,
    proof::{
        MasterKey, compute_server_proof, derive_resume_secret, seal_descriptor,
        verify_client_proof, verify_descriptor_seal,
    },
};
#[cfg(feature = "ssh-server")]
use meshharbor_remote_control::models::ssh_limits;
use serde::{Deserialize, Serialize};
#[cfg(feature = "ssh-server")]
use tracing::{debug, info, warn};
#[cfg(feature = "ssh-server")]
use zeroize::Zeroizing;

#[cfg(feature = "ssh-server")]
use crate::ssh_pty_host::HostBootstrapMeta;

/// Maximum detached persistent sessions retained per principal before the
/// principal's oldest detached session is LRU-evicted.
pub const MAX_DETACHED_PER_PRINCIPAL: usize = 4;

/// Summary of one live persistent SSH session (for `meshharbord ssh-sessions list`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentSessionInfo {
    pub sid: String,
    pub org_id: String,
    pub principal: String,
    pub client_key_fp: String,
    pub created_ms: u64,
    pub deadline_ms: u64,
    pub attached: bool,
    pub survives_restart: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_unit: Option<String>,
}

/// Platform-unified local IPC stream to a `ssh-pty-host` process.
#[cfg(all(unix, feature = "ssh-server"))]
pub type HostIpcStream = tokio::net::UnixStream;

#[cfg(all(windows, feature = "ssh-server"))]
pub type HostIpcStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(feature = "ssh-server")]
#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub sid: SessionId,
    pub endpoint: String,
    pub descriptor: SessionDescriptor,
    pub descriptor_json: Vec<u8>,
    pub seal: [u8; 32],
    pub persist: PersistStatus,
    pub scope_unit: Option<String>,
    pub job_name: Option<String>,
    pub child_pid: Option<u32>,
    pub attached: bool,
    pub last_detached_ms: u64,
}

#[cfg(feature = "ssh-server")]
#[derive(Debug, Clone)]
struct Tombstone {
    sid: SessionId,
    reason: RefuseReason,
    deadline_ms: u64,
}

#[cfg(feature = "ssh-server")]
#[derive(Default)]
struct RegistryState {
    state_dir: Option<PathBuf>,
    master: Option<MasterKey>,
    sessions: HashMap<SessionId, SessionEntry>,
    /// Keyed by `(org_id, client_key_fp)` -> tombstone so late clients receive
    /// an exact `Refused::Ended` / `Refused::Revoked` instead of ambiguous auth fail.
    tombstones: HashMap<(String, String), Tombstone>,
}

#[cfg(feature = "ssh-server")]
static REGISTRY: OnceLock<Mutex<RegistryState>> = OnceLock::new();

#[cfg(feature = "ssh-server")]
fn reg() -> &'static Mutex<RegistryState> {
    REGISTRY.get_or_init(|| Mutex::new(RegistryState::default()))
}

/// Whether persistent resumable SSH is enabled on this device.
/// Respects emergency env kill switch `MESHHARBORD_SSH_RESUME=0`.
pub fn resume_enabled_globally() -> bool {
    if let Ok(v) = std::env::var("MESHHARBORD_SSH_RESUME") {
        let t = v.trim();
        if t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off") {
            return false;
        }
    }
    true
}

/// Whether VT100 snapshot fallback (>4 MiB offline gap) is enabled locally.
pub fn snapshot_enabled_globally() -> bool {
    if let Ok(v) = std::env::var("MESHHARBORD_SSH_RESUME_SNAPSHOT") {
        let t = v.trim();
        if t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off") {
            return false;
        }
    }
    true
}

/// Initialize the state directory and device-local master key (`ssh-resume.key`).
/// Safe to call multiple times (updates directory if changed, e.g. in tests).
#[cfg(feature = "ssh-server")]
pub fn init_state_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("create ssh-persist state dir {}: {e}", dir.display()))?;
    let key_path = dir.join("ssh-resume.key");
    let master = MasterKey::load_or_create(&key_path)
        .map_err(|e| format!("load/create {}: {e}", key_path.display()))?;
    let sessions_dir = sessions_dir_for(dir);
    std::fs::create_dir_all(&sessions_dir)
        .map_err(|e| format!("create {}: {e}", sessions_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sessions_dir, std::fs::Permissions::from_mode(0o700));
    }
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    g.state_dir = Some(dir.to_path_buf());
    g.master = Some(master);
    Ok(())
}

#[cfg(not(feature = "ssh-server"))]
pub fn init_state_dir(_dir: &std::path::Path) -> Result<(), String> {
    Ok(())
}

/// Read the device master key (loading lazily from default state dir if needed).
#[cfg(feature = "ssh-server")]
pub fn master_key() -> Result<MasterKey, String> {
    {
        let g = reg().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = &g.master {
            return Ok(m.clone());
        }
    }
    let dir = default_state_dir();
    init_state_dir(&dir)?;
    let g = reg().lock().unwrap_or_else(|e| e.into_inner());
    g.master
        .clone()
        .ok_or_else(|| "ssh-resume master key unavailable".to_string())
}

#[cfg(feature = "ssh-server")]
pub fn state_dir() -> PathBuf {
    let g = reg().lock().unwrap_or_else(|e| e.into_inner());
    g.state_dir.clone().unwrap_or_else(default_state_dir)
}

#[cfg(feature = "ssh-server")]
fn default_state_dir() -> PathBuf {
    if let Ok(p) = std::env::var("MESHHARBORD_SSH_PERSIST_DIR")
        && !p.trim().is_empty()
    {
        return PathBuf::from(p.trim());
    }
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root {
            return PathBuf::from("/run/meshharbor");
        }
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR")
            && !xdg.trim().is_empty()
        {
            return PathBuf::from(xdg).join("meshharbor");
        }
    }
    crate::config::default_config_path()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("/tmp/meshharbor"))
}

static PENDING_UPDATE_VERSION: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Record the target version when an update is about to restart the daemon so
/// `announce_restart` includes `to_version` and `"update"` automatically.
pub fn record_pending_update_version(version: &str) {
    *PENDING_UPDATE_VERSION
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(version.to_string());
}

/// Read the pending target update version if an update triggered the shutdown.
pub fn pending_update_version() -> Option<String> {
    PENDING_UPDATE_VERSION
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(feature = "ssh-server")]
fn sessions_dir_for(state_dir: &Path) -> PathBuf {
    state_dir.join("ssh-sessions")
}

#[cfg(feature = "ssh-server")]
fn endpoint_for(state_dir: &Path, sid: &SessionId) -> String {
    #[cfg(unix)]
    {
        sessions_dir_for(state_dir)
            .join(format!("{}.sock", sid.to_hex()))
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(windows)]
    {
        let _ = state_dir;
        format!(r"\\.\pipe\meshharbor-ssh-{}", sid.to_hex())
    }
}

/// Outcome of looking up a connecting client's SSH public key fingerprint
/// against live persistent sessions and ended tombstones.
#[cfg(feature = "ssh-server")]
#[derive(Debug, Clone)]
pub enum ResumeLookup {
    Live(SessionId),
    Tombstone {
        sid: SessionId,
        reason: RefuseReason,
    },
    None,
}

/// Look up whether `client_key_fp` belongs to a live persistent session or
/// tombstone in `org_id`. Called by `ssh.rs::auth_publickey` after `take_grant_for`.
#[cfg(feature = "ssh-server")]
pub fn lookup_resume_key(org_id: &str, client_key_fp: &str) -> ResumeLookup {
    let now = now_unix_ms();
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    // Prune expired tombstones.
    g.tombstones.retain(|_, t| t.deadline_ms > now);

    for entry in g.sessions.values() {
        if entry.descriptor.org_id == org_id
            && entry.descriptor.client_key_fp == client_key_fp
            && entry.descriptor.deadline_ms > now
        {
            return ResumeLookup::Live(entry.sid);
        }
    }
    if let Some(t) = g
        .tombstones
        .get(&(org_id.to_string(), client_key_fp.to_string()))
    {
        return ResumeLookup::Tombstone {
            sid: t.sid,
            reason: t.reason.clone(),
        };
    }
    ResumeLookup::None
}

/// Count of live persistent SSH sessions currently managed by this daemon.
pub fn live_session_count() -> usize {
    #[cfg(feature = "ssh-server")]
    {
        reg()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .len()
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        0
    }
}

/// List all live persistent sessions for `meshharbord ssh-sessions list`.
pub fn list_sessions() -> Vec<PersistentSessionInfo> {
    #[cfg(feature = "ssh-server")]
    {
        let g = reg().lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<PersistentSessionInfo> = g
            .sessions
            .values()
            .map(|e| PersistentSessionInfo {
                sid: e.sid.to_hex(),
                org_id: e.descriptor.org_id.clone(),
                principal: e.descriptor.principal.clone(),
                client_key_fp: e.descriptor.client_key_fp.clone(),
                created_ms: e.descriptor.created_ms,
                deadline_ms: e.descriptor.deadline_ms,
                attached: e.attached,
                survives_restart: e.persist.survives_restart,
                persist_reason: e.persist.reason.clone(),
                child_pid: e.child_pid,
                scope_unit: e.scope_unit.clone(),
            })
            .collect();
        out.sort_by_key(|s| s.created_ms);
        out
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        Vec::new()
    }
}

/// Result returned when opening a brand-new persistent PTY session.
#[cfg(feature = "ssh-server")]
pub struct SpawnedPersistent {
    pub entry: SessionEntry,
    pub resume_secret: Zeroizing<[u8; 32]>,
    pub stream: HostIpcStream,
}

/// Spawn a detached `meshharbord ssh-pty-host`, verify its `HostHello`, issue
/// `Spawn(spec)`, register it, and return the live IPC stream ready for attach.
#[cfg(feature = "ssh-server")]
pub async fn spawn_session(
    descriptor: SessionDescriptor,
    spec: SpawnSpec,
) -> Result<SpawnedPersistent, RefuseReason> {
    if !resume_enabled_globally() {
        return Err(RefuseReason::Policy {
            detail: "persistent SSH sessions are disabled on this device".into(),
        });
    }

    let master = master_key().map_err(|e| RefuseReason::Internal { detail: e })?;
    let base_dir = state_dir();
    let sessions_dir = sessions_dir_for(&base_dir);
    let _ = std::fs::create_dir_all(&sessions_dir);

    // Enforce global concurrency cap (8) and per-principal detached cap (4).
    let evict_sid: Option<SessionEntry> = {
        let g = reg().lock().unwrap_or_else(|e| e.into_inner());
        let mut own_detached: Vec<&SessionEntry> = g
            .sessions
            .values()
            .filter(|e| {
                e.descriptor.org_id == descriptor.org_id
                    && e.descriptor.principal == descriptor.principal
                    && !e.attached
            })
            .collect();
        if own_detached.len() >= MAX_DETACHED_PER_PRINCIPAL {
            own_detached.sort_by_key(|e| e.last_detached_ms);
            Some(own_detached[0].clone())
        } else if g.sessions.len() >= ssh_limits::MAX_CONCURRENT_PER_AGENT {
            return Err(RefuseReason::Busy {
                detail: format!(
                    "device reached limit of {} concurrent SSH sessions",
                    ssh_limits::MAX_CONCURRENT_PER_AGENT
                ),
            });
        } else {
            None
        }
    };
    if let Some(old) = evict_sid {
        let _ = terminate_entry(&old, TerminateReason::DetachTimeout).await;
    }

    let sid = descriptor.sid;
    let descriptor_json = serde_json::to_vec(&descriptor).map_err(|e| RefuseReason::Internal {
        detail: format!("serialize descriptor: {e}"),
    })?;
    let seal = seal_descriptor(&master, &descriptor_json);
    let resume_secret = derive_resume_secret(&master, &sid, &descriptor_json);
    let endpoint = endpoint_for(&base_dir, &sid);

    let scope_unit = planned_scope_unit(&sid);
    let job_name = planned_job_name(&sid);

    #[cfg(unix)]
    let allowed_uid = Some(unsafe { libc::geteuid() });
    #[cfg(not(unix))]
    let allowed_uid = None;

    let meta = HostBootstrapMeta {
        endpoint: endpoint.clone(),
        descriptor_json: descriptor_json.clone(),
        seal,
        scope_unit: scope_unit.clone(),
        job_name: job_name.clone(),
        allowed_uid,
    };

    let meta_path = sessions_dir.join(format!("{}.boot.json", sid.to_hex()));
    write_private_json(&meta_path, &meta).map_err(|e| RefuseReason::Internal {
        detail: format!("write host bootstrap meta: {e}"),
    })?;

    // Launch detached host process.
    let spawn_res = spawn_detached_host(&base_dir, &meta_path, scope_unit.as_deref());
    if let Err(e) = spawn_res {
        let _ = std::fs::remove_file(&meta_path);
        return Err(RefuseReason::Internal {
            detail: format!("spawn ssh-pty-host failed: {e}"),
        });
    }

    // Connect to host IPC (up to 3.5 s while systemd-run / process boots).
    let mut stream = connect_host_with_retry(&endpoint, Duration::from_millis(3500))
        .await
        .map_err(|e| {
            let _ = std::fs::remove_file(&meta_path);
            RefuseReason::Internal {
                detail: format!("connect to ssh-pty-host failed: {e}"),
            }
        })?;

    // Read HostHello and verify seal.
    let hello = read_host_hello(&mut stream, Duration::from_secs(2))
        .await
        .map_err(|e| RefuseReason::Internal { detail: e })?;

    if !verify_descriptor_seal(&master, &hello.descriptor_json, &hello.seal) {
        let _ = IpcFrame::Terminate(TerminateFrame {
            reason: TerminateReason::Revoked,
            grace_ms: 500,
        })
        .write_to(&mut stream)
        .await;
        return Err(RefuseReason::Internal {
            detail: "host hello seal verification failed".into(),
        });
    }

    // Ask host to spawn PTY.
    IpcFrame::Spawn(spec)
        .write_to(&mut stream)
        .await
        .map_err(|e| RefuseReason::Internal {
            detail: format!("send Spawn to host: {e}"),
        })?;

    let child_pid = match tokio::time::timeout(Duration::from_secs(5), IpcFrame::read_from(&mut stream))
        .await
        .map_err(|_| RefuseReason::Internal {
            detail: "timed out waiting for host Spawned reply".into(),
        })?
        .map_err(|e| RefuseReason::Internal {
            detail: format!("read Spawned from host: {e}"),
        })? {
        Some(IpcFrame::Spawned(s)) => Some(s.child_pid),
        Some(IpcFrame::SpawnError(err)) => {
            return Err(RefuseReason::Policy { detail: err.message });
        }
        other => {
            return Err(RefuseReason::Internal {
                detail: format!("unexpected host reply to Spawn: {other:?}"),
            });
        }
    };

    #[cfg(windows)]
    {
        // Track active Windows named-pipe sessions for boot-time adoption.
        let marker = sessions_dir.join(format!("{}.pipe", sid.to_hex()));
        let _ = std::fs::write(&marker, endpoint.as_bytes());
    }

    let entry = SessionEntry {
        sid,
        endpoint,
        descriptor,
        descriptor_json,
        seal,
        persist: hello.persist,
        scope_unit: hello.scope_unit,
        job_name: hello.job_name,
        child_pid,
        attached: true,
        last_detached_ms: now_unix_ms(),
    };
    reg()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .sessions
        .insert(sid, entry.clone());

    info!(
        sid = %sid.short_hex(),
        survives = entry.persist.survives_restart,
        reason = ?entry.persist.reason,
        child_pid = ?entry.child_pid,
        "ssh-persist: detached PTY session started"
    );

    Ok(SpawnedPersistent {
        entry,
        resume_secret,
        stream,
    })
}

/// Verified attach handle returned to `ssh.rs` for verbatim wire relay.
#[cfg(feature = "ssh-server")]
pub struct AttachedPersistent {
    pub entry: SessionEntry,
    pub stream: HostIpcStream,
}

/// Verify a client's `Attach` proof statelessly and connect to the surviving
/// `ssh-pty-host` IPC stream, sending `AttachStart` so the host begins replay/snapshot.
#[cfg(feature = "ssh-server")]
#[allow(clippy::too_many_arguments)]
pub async fn verify_and_attach(
    org_id: &str,
    sid: &SessionId,
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    client_proof: &[u8; 32],
    host_key_fp: &str,
    client_key_fp: &str,
    last_rx: u64,
    c2s_next_client: u64,
    cols: u16,
    rows: u16,
) -> Result<AttachedPersistent, RefuseReason> {
    let now = now_unix_ms();
    let entry = {
        let g = reg().lock().unwrap_or_else(|e| e.into_inner());
        match g.sessions.get(sid) {
            Some(e) if e.descriptor.org_id == org_id => e.clone(),
            _ => {
                if let Some(t) = g
                    .tombstones
                    .get(&(org_id.to_string(), client_key_fp.to_string()))
                {
                    return Err(t.reason.clone());
                }
                return Err(RefuseReason::UnknownSession);
            }
        }
    };

    if now >= entry.descriptor.deadline_ms {
        let _ = terminate_entry(&entry, TerminateReason::Expired).await;
        return Err(RefuseReason::Expired);
    }

    // Re-check 2FA vs key-list auth at resume time.
    if entry.descriptor.key_list_auth && meshharbor_node_core::two_factor::active() {
        let _ = terminate_entry(&entry, TerminateReason::PolicyChanged).await;
        return Err(RefuseReason::Revoked {
            detail: "two-factor authentication is now enabled; key-list session revoked".into(),
        });
    }

    // Re-check client key fingerprint matches descriptor.
    if entry.descriptor.client_key_fp != client_key_fp {
        return Err(RefuseReason::BadProof);
    }

    let master = master_key().map_err(|e| RefuseReason::Internal { detail: e })?;
    let secret = derive_resume_secret(&master, sid, &entry.descriptor_json);
    if !verify_client_proof(
        &secret,
        sid,
        server_nonce,
        client_nonce,
        host_key_fp,
        client_key_fp,
        client_proof,
    ) {
        return Err(RefuseReason::BadProof);
    }

    let server_proof = compute_server_proof(&secret, sid, client_nonce, server_nonce);

    let mut stream = connect_host_once(&entry.endpoint, Duration::from_secs(2))
        .await
        .map_err(|_| {
            // Host died unexpectedly — remove stale entry.
            remove_entry_as_ended(&entry, None);
            RefuseReason::UnknownSession
        })?;

    let hello = read_host_hello(&mut stream, Duration::from_secs(2))
        .await
        .map_err(|e| RefuseReason::Internal { detail: e })?;
    if !verify_descriptor_seal(&master, &hello.descriptor_json, &hello.seal) {
        let _ = IpcFrame::Terminate(TerminateFrame {
            reason: TerminateReason::Revoked,
            grace_ms: 500,
        })
        .write_to(&mut stream)
        .await;
        remove_entry_as_revoked(&entry, "descriptor seal mismatch");
        return Err(RefuseReason::Revoked {
            detail: "descriptor seal verification failed".into(),
        });
    }

    IpcFrame::AttachStart(AttachStartFrame {
        last_rx,
        c2s_next_client,
        cols,
        rows,
        snapshot_allowed: snapshot_enabled_globally(),
        server_proof,
    })
    .write_to(&mut stream)
    .await
    .map_err(|e| RefuseReason::Internal {
        detail: format!("send AttachStart: {e}"),
    })?;

    {
        let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = g.sessions.get_mut(sid) {
            e.attached = true;
        }
    }

    Ok(AttachedPersistent { entry, stream })
}

/// Mark a session as detached (client connection dropped or user sent `~d`).
#[cfg(feature = "ssh-server")]
pub fn mark_detached(sid: &SessionId) {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = g.sessions.get_mut(sid) {
        e.attached = false;
        e.last_detached_ms = now_unix_ms();
    }
}

/// Record that a session exited cleanly and remove it from live registry.
#[cfg(feature = "ssh-server")]
pub fn mark_ended(sid: &SessionId, status: meshharbor_node_core::pty_resume::ExitStatusInfo) {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = g.sessions.remove(sid) {
        g.tombstones.insert(
            (entry.descriptor.org_id, entry.descriptor.client_key_fp),
            Tombstone {
                sid: entry.sid,
                reason: RefuseReason::Ended { status },
                deadline_ms: entry.descriptor.deadline_ms,
            },
        );
    }
}

#[cfg(feature = "ssh-server")]
fn remove_entry_as_ended(
    entry: &SessionEntry,
    status: Option<meshharbor_node_core::pty_resume::ExitStatusInfo>,
) {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    g.sessions.remove(&entry.sid);
    if let Some(st) = status {
        g.tombstones.insert(
            (
                entry.descriptor.org_id.clone(),
                entry.descriptor.client_key_fp.clone(),
            ),
            Tombstone {
                sid: entry.sid,
                reason: RefuseReason::Ended { status: st },
                deadline_ms: entry.descriptor.deadline_ms,
            },
        );
    }
}

#[cfg(feature = "ssh-server")]
fn remove_entry_as_revoked(entry: &SessionEntry, detail: &str) {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    g.sessions.remove(&entry.sid);
    g.tombstones.insert(
        (
            entry.descriptor.org_id.clone(),
            entry.descriptor.client_key_fp.clone(),
        ),
        Tombstone {
            sid: entry.sid,
            reason: RefuseReason::Revoked {
                detail: detail.to_string(),
            },
            deadline_ms: entry.descriptor.deadline_ms,
        },
    );
}

/// Boot-time adoption: scan `ssh-sessions/` for surviving `ssh-pty-host`
/// processes, verify seals and device-local gates, register valid hosts, and
/// hard-terminate expired, tampered, or policy-disallowed hosts.
#[cfg(feature = "ssh-server")]
pub async fn adopt_all<F>(gate_allows: F) -> usize
where
    F: Fn(&SessionDescriptor) -> Result<(), String>,
{
    let Ok(master) = master_key() else {
        return 0;
    };
    let dir = sessions_dir_for(&state_dir());
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };

    let mut adopted = 0usize;
    let now = now_unix_ms();

    for ent in entries.flatten() {
        let path = ent.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        // Clean up any leftover bootstrap temp files older than 30 s.
        if fname.ends_with(".boot.json") {
            let _ = std::fs::remove_file(&path);
            continue;
        }

        #[cfg(unix)]
        let (sid_hex, endpoint) = match fname.strip_suffix(".sock") {
            Some(h) => (h.to_string(), path.to_string_lossy().into_owned()),
            None => continue,
        };
        #[cfg(windows)]
        let (sid_hex, endpoint) = match fname.strip_suffix(".pipe") {
            Some(h) => (
                h.to_string(),
                std::fs::read_to_string(&path).unwrap_or_else(|_| format!(r"\\.\pipe\meshharbor-ssh-{h}")),
            ),
            None => continue,
        };

        let Ok(expected_sid) = SessionId::from_hex(&sid_hex) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };

        let Ok(mut stream) = connect_host_once(&endpoint, Duration::from_secs(2)).await else {
            // Stale socket/marker from a host that already exited.
            let _ = std::fs::remove_file(&path);
            continue;
        };

        let Ok(hello) = read_host_hello(&mut stream, Duration::from_secs(2)).await else {
            let _ = send_terminate(&mut stream, TerminateReason::HostUnresponsive, 500).await;
            let _ = std::fs::remove_file(&path);
            continue;
        };

        // 1. Cryptographic seal verification.
        if !verify_descriptor_seal(&master, &hello.descriptor_json, &hello.seal) {
            warn!(sid = %expected_sid.short_hex(), "ssh-persist: killing host with invalid seal");
            let _ = send_terminate(&mut stream, TerminateReason::Revoked, 500).await;
            stop_os_handle(hello.scope_unit.as_deref());
            let _ = std::fs::remove_file(&path);
            continue;
        }

        // 2. Parse descriptor and check sid matches filename.
        let Ok(desc) = serde_json::from_slice::<SessionDescriptor>(&hello.descriptor_json) else {
            let _ = send_terminate(&mut stream, TerminateReason::Revoked, 500).await;
            stop_os_handle(hello.scope_unit.as_deref());
            continue;
        };
        if desc.sid != expected_sid {
            warn!("ssh-persist: killing host with mismatched sid/endpoint");
            let _ = send_terminate(&mut stream, TerminateReason::Revoked, 500).await;
            stop_os_handle(hello.scope_unit.as_deref());
            continue;
        }

        // 3. Deadline + device-local gate re-check.
        if now >= desc.deadline_ms {
            let _ = send_terminate(&mut stream, TerminateReason::Expired, 500).await;
            stop_os_handle(hello.scope_unit.as_deref());
            continue;
        }
        if let Err(why) = gate_allows(&desc) {
            warn!(sid = %desc.sid.short_hex(), %why, "ssh-persist: terminating adopted host disallowed by current policy");
            let _ = send_terminate(&mut stream, TerminateReason::PolicyChanged, 1000).await;
            stop_os_handle(hello.scope_unit.as_deref());
            continue;
        }

        // 4. Register valid surviving host (exited hosts also registered so returning client gets Exited!).
        let entry = SessionEntry {
            sid: desc.sid,
            endpoint,
            descriptor: desc,
            descriptor_json: hello.descriptor_json,
            seal: hello.seal,
            persist: hello.persist,
            scope_unit: hello.scope_unit,
            job_name: hello.job_name,
            child_pid: hello.child_pid,
            attached: false,
            last_detached_ms: now,
        };
        if hello.state == HostState::Exited
            && let Some(status) = hello.exit_status
        {
            remove_entry_as_ended(&entry, Some(status));
        }
        reg()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .insert(entry.sid, entry);
        adopted += 1;
    }

    if adopted > 0 {
        info!(adopted, "ssh-persist: adopted surviving detached SSH PTY sessions");
    }
    adopted
}

#[cfg(not(feature = "ssh-server"))]
pub async fn adopt_all<F>(_gate_allows: F) -> usize
where
    F: Fn(&()) -> Result<(), String>,
{
    0
}

/// Notify every surviving PTY host that the daemon is about to restart/update
/// (bounded at 300 ms). Hosts immediately emit `Notice::TargetRestarting` to
/// attached clients and start their 10-minute fail-closed orphan timer.
pub async fn announce_restart(reason: &str, eta_ms: u64, to_version: Option<String>) {
    let pending_ver = PENDING_UPDATE_VERSION
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let effective_ver = to_version.or(pending_ver);
    let effective_reason = if effective_ver.is_some() {
        "update"
    } else {
        reason
    };
    let effective_eta = if effective_ver.is_some() {
        eta_ms.max(8_000)
    } else {
        eta_ms
    };
    #[cfg(feature = "ssh-server")]
    {
        let entries: Vec<SessionEntry> = reg()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .values()
            .cloned()
            .collect();
        if entries.is_empty() {
            return;
        }
        let futs = entries.into_iter().map(|entry| {
            let reason = effective_reason.to_string();
            let to_version = effective_ver.clone();
            async move {
                if let Ok(mut stream) =
                    connect_host_once(&entry.endpoint, Duration::from_millis(200)).await
                {
                    let _ = read_host_hello(&mut stream, Duration::from_millis(120)).await;
                    let _ = IpcFrame::DaemonDetaching(DaemonDetachingFrame {
                        eta_ms: effective_eta,
                        reason,
                        to_version,
                    })
                    .write_to(&mut stream)
                    .await;
                }
            }
        });
        let _ = tokio::time::timeout(Duration::from_millis(300), futures::future::join_all(futs))
            .await;
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        let _ = (effective_reason, effective_eta, effective_ver);
    }
}

/// Explicitly terminate every persistent session matching `pred`.
/// Used for org leave, `rc:goodbye`, `drop_runtime_slot`, `rc:ssh.revoke`, etc.
#[cfg(feature = "ssh-server")]
pub async fn terminate_where<F>(pred: F, reason: TerminateReason) -> usize
where
    F: Fn(&SessionDescriptor) -> bool,
{
    let targets: Vec<SessionEntry> = {
        let g = reg().lock().unwrap_or_else(|e| e.into_inner());
        g.sessions
            .values()
            .filter(|e| pred(&e.descriptor))
            .cloned()
            .collect()
    };
    let count = targets.len();
    for entry in targets {
        let _ = terminate_entry(&entry, reason).await;
    }
    count
}

/// Terminate all persistent sessions for a specific tenant/org.
pub async fn terminate_org(org_id: &str, reason: TerminateReason) -> usize {
    #[cfg(feature = "ssh-server")]
    {
        terminate_where(|d| d.org_id == org_id, reason).await
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        let _ = (org_id, reason);
        0
    }
}

/// Terminate a single persistent session scoped to `org_id` (used by `rc:ssh.revoke`).
pub async fn terminate_session_in_org(
    org_id: &str,
    sid_hex: &str,
    reason: TerminateReason,
) -> usize {
    #[cfg(feature = "ssh-server")]
    {
        let q = sid_hex.trim().to_ascii_lowercase();
        terminate_where(|d| d.org_id == org_id && d.sid.to_hex() == q, reason).await
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        let _ = (org_id, sid_hex, reason);
        0
    }
}

/// Terminate by grant IDs, principal, or all (used by `ServerMsg::SshRevoke`).
pub async fn terminate_by_revoke(
    org_id: &str,
    grant_ids: Option<&[String]>,
    principal: Option<&str>,
    all: bool,
) -> usize {
    #[cfg(feature = "ssh-server")]
    {
        terminate_where(
            |d| {
                if d.org_id != org_id {
                    return false;
                }
                if all {
                    return true;
                }
                if let Some(p) = principal
                    && d.principal == p
                {
                    return true;
                }
                if let Some(ids) = grant_ids
                    && let Some(gid) = &d.grant_id
                    && ids.iter().any(|x| x == gid)
                {
                    return true;
                }
                false
            },
            TerminateReason::Revoked,
        )
        .await
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        let _ = (org_id, grant_ids, principal, all);
        0
    }
}

/// Terminate a single persistent session by full hex ID or unique prefix
/// (used by `meshharbord ssh-sessions kill <sid>`).
pub async fn kill_session(sid_or_prefix: &str) -> Result<bool, String> {
    #[cfg(feature = "ssh-server")]
    {
        let q = sid_or_prefix.trim().to_ascii_lowercase();
        let matched: Vec<SessionEntry> = {
            let g = reg().lock().unwrap_or_else(|e| e.into_inner());
            g.sessions
                .values()
                .filter(|e| e.sid.to_hex().starts_with(&q))
                .cloned()
                .collect()
        };
        if matched.is_empty() {
            return Ok(false);
        }
        if matched.len() > 1 {
            return Err(format!("ambiguous session prefix `{q}` matches {} sessions", matched.len()));
        }
        terminate_entry(&matched[0], TerminateReason::UserCancelled).await?;
        Ok(true)
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        let _ = sid_or_prefix;
        Ok(false)
    }
}

/// Terminate ALL persistent sessions and optionally rotate `ssh-resume.key`
/// (called by `CloseAccess`, uninstall, and `meshharbord ssh-sessions kill-all`).
pub async fn terminate_all(reason: TerminateReason, rotate_key: bool) -> Result<usize, String> {
    #[cfg(feature = "ssh-server")]
    {
        let targets: Vec<SessionEntry> = {
            let g = reg().lock().unwrap_or_else(|e| e.into_inner());
            g.sessions.values().cloned().collect()
        };
        let mut killed = 0usize;
        for entry in targets {
            let _ = terminate_entry(&entry, reason).await;
            killed += 1;
        }
        if rotate_key {
            let dir = state_dir();
            let new_key = MasterKey::generate();
            let _ = new_key.save_atomic(&dir.join("ssh-resume.key"));
            let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
            g.master = Some(new_key);
        }
        Ok(killed)
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        let _ = (reason, rotate_key);
        Ok(0)
    }
}

#[cfg(feature = "ssh-server")]
async fn terminate_entry(entry: &SessionEntry, reason: TerminateReason) -> Result<(), String> {
    remove_entry_as_revoked(entry, &format!("{reason:?}"));
    if let Ok(mut stream) = connect_host_once(&entry.endpoint, Duration::from_secs(1)).await {
        let _ = read_host_hello(&mut stream, Duration::from_millis(500)).await;
        let _ = send_terminate(&mut stream, reason, 1500).await;
    }
    stop_os_handle(entry.scope_unit.as_deref());
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&entry.endpoint);
    }
    #[cfg(windows)]
    {
        let marker = sessions_dir_for(&state_dir()).join(format!("{}.pipe", entry.sid.to_hex()));
        let _ = std::fs::remove_file(marker);
    }
    Ok(())
}

#[cfg(feature = "ssh-server")]
async fn send_terminate(
    stream: &mut HostIpcStream,
    reason: TerminateReason,
    grace_ms: u32,
) -> Result<(), String> {
    IpcFrame::Terminate(TerminateFrame { reason, grace_ms })
        .write_to(stream)
        .await
        .map_err(|e| format!("send 0x00 Terminate: {e}"))
}

#[cfg(feature = "ssh-server")]
async fn read_host_hello(
    stream: &mut HostIpcStream,
    timeout: Duration,
) -> Result<HostHelloFrame, String> {
    match tokio::time::timeout(timeout, IpcFrame::read_from(stream))
        .await
        .map_err(|_| "timed out reading HostHello".to_string())?
        .map_err(|e| format!("read HostHello: {e}"))?
    {
        Some(IpcFrame::HostHello(h)) => Ok(h),
        other => Err(format!("expected HostHello, got {other:?}")),
    }
}

#[cfg(feature = "ssh-server")]
async fn connect_host_once(endpoint: &str, timeout: Duration) -> Result<HostIpcStream, String> {
    #[cfg(unix)]
    {
        tokio::time::timeout(timeout, tokio::net::UnixStream::connect(endpoint))
            .await
            .map_err(|_| "uds connect timed out".to_string())?
            .map_err(|e| format!("uds connect {endpoint}: {e}"))
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match ClientOptions::new().open(endpoint) {
                Ok(c) => return Ok(c),
                Err(e) if std::time::Instant::now() < deadline => {
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => return Err(format!("open pipe {endpoint}: {e}")),
            }
        }
    }
}

#[cfg(feature = "ssh-server")]
async fn connect_host_with_retry(endpoint: &str, budget: Duration) -> Result<HostIpcStream, String> {
    let deadline = std::time::Instant::now() + budget;
    let mut last_err = String::from("host did not bind ipc");
    while std::time::Instant::now() < deadline {
        match connect_host_once(endpoint, Duration::from_millis(250)).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_err = e;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
    Err(last_err)
}

#[cfg(feature = "ssh-server")]
fn planned_scope_unit(sid: &SessionId) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if Path::new("/run/systemd/system").exists()
            && !Path::new("/.dockerenv").exists()
            && !Path::new("/run/.containerenv").exists()
            && find_systemd_run().is_some()
        {
            return Some(format!("meshharbor-ssh-{}.scope", sid.short_hex()));
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sid;
        None
    }
}

#[cfg(feature = "ssh-server")]
fn planned_job_name(sid: &SessionId) -> Option<String> {
    #[cfg(windows)]
    {
        let prefix = if crate::win_identity::is_local_system() {
            "Global"
        } else {
            "Local"
        };
        Some(format!(r"{prefix}\MeshHarbor.ssh.{}", sid.short_hex()))
    }
    #[cfg(not(windows))]
    {
        let _ = sid;
        None
    }
}

#[cfg(all(target_os = "linux", feature = "ssh-server"))]
fn find_systemd_run() -> Option<&'static str> {
    ["/usr/bin/systemd-run", "/bin/systemd-run"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
}

#[cfg(feature = "ssh-server")]
fn stop_os_handle(scope_unit: Option<&str>) {
    #[cfg(target_os = "linux")]
    if let Some(unit) = scope_unit {
        let mut cmd = std::process::Command::new("systemctl");
        if unsafe { libc::geteuid() } != 0 {
            cmd.arg("--user");
        }
        let _ = cmd
            .args(["stop", unit])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = scope_unit;
    }
}

#[cfg(feature = "ssh-server")]
fn write_private_json<T: Serialize>(path: &Path, val: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(val).map_err(std::io::Error::other)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &bytes)
    }
}

/// Reset the in-memory registry (simulating a daemon restart without killing
/// detached `ssh-pty-host` processes). Used only by integration tests.
#[cfg(feature = "ssh-server")]
#[doc(hidden)]
pub fn reset_in_memory_registry_for_restart_simulation() {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    g.sessions.clear();
    g.tombstones.clear();
    g.master = None;
}

/// Launch `meshharbord ssh-pty-host --meta-file <meta_path>` outside the
/// daemon's restart/update kill domain.
#[cfg(feature = "ssh-server")]
fn spawn_detached_host(
    base_dir: &Path,
    meta_path: &Path,
    scope_unit: Option<&str>,
) -> Result<(), String> {
    let exe = if cfg!(debug_assertions)
        && let Ok(override_bin) = std::env::var("MESHHARBORD_SSH_PTY_HOST_BIN")
        && !override_bin.trim().is_empty()
    {
        PathBuf::from(override_bin.trim())
    } else {
        std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?
    };

    #[cfg(target_os = "linux")]
    {
        let _ = base_dir;
        if let Some(unit) = scope_unit
            && let Some(srun) = find_systemd_run()
        {
            let mut cmd = std::process::Command::new(srun);
            if unsafe { libc::geteuid() } != 0 {
                cmd.arg("--user");
            }
            cmd.args([
                "--scope",
                "--collect",
                &format!("--unit={unit}"),
                "--",
            ])
            .arg(&exe)
            .arg(crate::ssh_pty_host::SUBCOMMAND)
            .arg("--meta-file")
            .arg(meta_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
            match cmd.spawn() {
                Ok(_child) => return Ok(()),
                Err(e) => {
                    debug!(%e, "ssh-persist: systemd-run --scope failed; falling back to setsid");
                }
            }
        }
        // Fallback for non-systemd Linux, WSL, containers, or tests.
        spawn_unix_setsid(&exe, meta_path)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (base_dir, scope_unit);
        spawn_unix_setsid(&exe, meta_path)
    }

    #[cfg(windows)]
    {
        let _ = scope_unit;
        use std::os::windows::process::CommandExt;
        // Stage binary outside MSI install dir so Restart Manager never terminates it.
        let staged = stage_windows_host_binary(base_dir, &exe).unwrap_or(exe);
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let try_flags = |flags: u32| {
            std::process::Command::new(&staged)
                .arg(crate::ssh_pty_host::SUBCOMMAND)
                .arg("--meta-file")
                .arg(meta_path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .creation_flags(flags)
                .spawn()
        };
        try_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW)
            .or_else(|_| try_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW))
            .map(|_| ())
            .map_err(|e| format!("CreateProcess ssh-pty-host: {e}"))
    }
}

#[cfg(all(unix, feature = "ssh-server"))]
fn spawn_unix_setsid(exe: &Path, meta_path: &Path) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg(crate::ssh_pty_host::SUBCOMMAND)
        .arg("--meta-file")
        .arg(meta_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: `setsid` is async-signal-safe with zero heap allocations.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("spawn setsid ssh-pty-host: {e}"))
}

#[cfg(all(windows, feature = "ssh-server"))]
fn stage_windows_host_binary(base_dir: &Path, exe: &Path) -> std::io::Result<PathBuf> {
    let hosts_dir = base_dir
        .join("session-hosts")
        .join(env!("CARGO_PKG_VERSION"));
    std::fs::create_dir_all(&hosts_dir)?;
    let dst = hosts_dir.join("meshharbord-session-host.exe");
    let need_copy = match (std::fs::metadata(exe), std::fs::metadata(&dst)) {
        (Ok(src_m), Ok(dst_m)) => src_m.len() != dst_m.len(),
        _ => true,
    };
    if need_copy {
        let tmp = hosts_dir.join(format!("stage-{}.tmp", std::process::id()));
        std::fs::copy(exe, &tmp)?;
        let _ = std::fs::rename(&tmp, &dst).or_else(|_| std::fs::copy(&tmp, &dst).map(|_| ()));
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(dst)
}
