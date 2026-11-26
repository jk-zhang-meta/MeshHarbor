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
        AttachStartFrame, DaemonDetachingFrame, HostHelloFrame, IpcFrame, SpawnSpec,
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
    pub attach_gen: u64,
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
    /// Per-session supervisor IPC keepalive cancellations so healthy detached
    /// sessions keep `conns` non-empty while `meshharbord` is alive (and the
    /// 10-minute fail-closed orphan timer fires ONLY when the daemon dies).
    keepalives: HashMap<SessionId, tokio_util::sync::CancellationToken>,
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

/// Fast pre-check used by `ssh.rs::subsystem_request` before sending
/// `channel_success` so a broken/read-only state dir triggers clean classic
/// SSH fallback on the same authenticated connection.
#[cfg(feature = "ssh-server")]
pub fn ensure_state_dir_ready() -> bool {
    master_key().is_ok()
}

#[cfg(not(feature = "ssh-server"))]
pub fn ensure_state_dir_ready() -> bool {
    false
}

#[cfg(feature = "ssh-server")]
pub fn state_dir() -> PathBuf {
    let g = reg().lock().unwrap_or_else(|e| e.into_inner());
    g.state_dir.clone().unwrap_or_else(default_state_dir)
}

#[cfg(feature = "ssh-server")]
fn default_state_dir() -> PathBuf {
    crate::rc_continuity::platform_runtime_state_dir()
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
    if !resume_enabled_globally() {
        return ResumeLookup::None;
    }
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
    pub attach_gen: u64,
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
        endpoint: endpoint.clone(),
        descriptor,
        descriptor_json,
        seal,
        persist: hello.persist,
        scope_unit: hello.scope_unit,
        job_name: hello.job_name,
        child_pid,
        attached: true,
        attach_gen: 1,
        last_detached_ms: now_unix_ms(),
    };
    reg()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .sessions
        .insert(sid, entry.clone());
    start_keepalive_monitor(sid, endpoint);

    info!(
        sid = %sid.short_hex(),
        survives = entry.persist.survives_restart,
        reason = ?entry.persist.reason,
        child_pid = ?entry.child_pid,
        "ssh-persist: detached PTY session started"
    );

    Ok(SpawnedPersistent {
        entry,
        attach_gen: 1,
        resume_secret,
        stream,
    })
}

/// Verified attach handle returned to `ssh.rs` for verbatim wire relay.
#[cfg(feature = "ssh-server")]
pub struct AttachedPersistent {
    pub entry: SessionEntry,
    pub attach_gen: u64,
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
    client_key_in_authorized_list: bool,
    last_rx: u64,
    c2s_next_client: u64,
    cols: u16,
    rows: u16,
) -> Result<AttachedPersistent, RefuseReason> {
    if !resume_enabled_globally() {
        return Err(RefuseReason::Policy {
            detail: "persistent SSH sessions are disabled on this device".into(),
        });
    }
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

    // Re-check 2FA and ssh_authorized_keys membership at resume time.
    if entry.descriptor.key_list_auth {
        if meshharbor_node_core::two_factor::active() {
            let _ = terminate_entry(&entry, TerminateReason::PolicyChanged).await;
            return Err(RefuseReason::Revoked {
                detail: "two-factor authentication is now enabled; key-list session revoked".into(),
            });
        }
        if !client_key_in_authorized_list {
            let _ = terminate_entry(&entry, TerminateReason::PolicyChanged).await;
            return Err(RefuseReason::Revoked {
                detail: "client key was removed from ssh_authorized_keys".into(),
            });
        }
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
    // Always derive endpoint deterministically from state_dir + sid rather than
    // trusting any external path.
    let endpoint = endpoint_for(&state_dir(), sid);

    let mut stream = connect_host_once(&endpoint, Duration::from_secs(2))
        .await
        .map_err(|_| {
            // Host died unexpectedly — remove stale entry and leave a tombstone
            // so late clients receive a clean terminal refusal.
            remove_entry_with_reason(&entry, RefuseReason::UnknownSession);
            RefuseReason::UnknownSession
        })?;

    let hello = read_host_hello(&mut stream, Duration::from_secs(2))
        .await
        .map_err(|e| RefuseReason::Internal { detail: e })?;
    if hello.descriptor_json != entry.descriptor_json
        || !verify_descriptor_seal(&master, &hello.descriptor_json, &hello.seal)
    {
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

    let attach_gen = {
        let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = g.sessions.get_mut(sid) {
            e.attach_gen = e.attach_gen.saturating_add(1);
            e.attached = true;
            e.attach_gen
        } else {
            1
        }
    };

    Ok(AttachedPersistent {
        entry,
        attach_gen,
        stream,
    })
}

/// Mark a session as detached ONLY if `attach_gen` still matches the active
/// attachment generation (so a superseded relay closing late never flips a
/// newer live attachment to detached!).
#[cfg(feature = "ssh-server")]
pub fn mark_detached(sid: &SessionId, attach_gen: u64) {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = g.sessions.get_mut(sid)
        && e.attach_gen == attach_gen
    {
        e.attached = false;
        e.last_detached_ms = now_unix_ms();
    }
}

/// Record that a session exited cleanly and remove it from live registry.
#[cfg(feature = "ssh-server")]
pub fn mark_ended(sid: &SessionId, status: meshharbor_node_core::pty_resume::ExitStatusInfo) {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tok) = g.keepalives.remove(sid) {
        tok.cancel();
    }
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
fn remove_entry_with_reason(entry: &SessionEntry, reason: RefuseReason) {
    let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tok) = g.keepalives.remove(&entry.sid) {
        tok.cancel();
    }
    g.sessions.remove(&entry.sid);
    g.tombstones.insert(
        (
            entry.descriptor.org_id.clone(),
            entry.descriptor.client_key_fp.clone(),
        ),
        Tombstone {
            sid: entry.sid,
            reason,
            deadline_ms: entry.descriptor.deadline_ms,
        },
    );
}

#[cfg(feature = "ssh-server")]
fn remove_entry_as_revoked(entry: &SessionEntry, detail: &str) {
    remove_entry_with_reason(
        entry,
        RefuseReason::Revoked {
            detail: detail.to_string(),
        },
    );
}

/// Spawn a lightweight supervisor IPC keepalive connection to `endpoint` so
/// `ssh-pty-host`'s `conns` stays non-empty while `meshharbord` is healthy.
/// When `meshharbord` crashes or stops, the OS closes this socket and the host
/// starts its 10-minute fail-closed orphan timer.
#[cfg(feature = "ssh-server")]
fn start_keepalive_monitor(sid: SessionId, endpoint: String) {
    let tok = tokio_util::sync::CancellationToken::new();
    {
        let mut g = reg().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = g.keepalives.insert(sid, tok.clone()) {
            old.cancel();
        }
    }
    tokio::spawn(async move {
        let Ok(mut stream) = connect_host_once(&endpoint, Duration::from_secs(2)).await else {
            return;
        };
        if read_host_hello(&mut stream, Duration::from_secs(2)).await.is_err() {
            return;
        }
        let mut iv = tokio::time::interval(Duration::from_secs(30));
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        iv.tick().await;
        loop {
            tokio::select! {
                _ = tok.cancelled() => break,
                _ = iv.tick() => {
                    let ping = IpcFrame::Ping { t_ms: now_unix_ms() };
                    if ping.write_to(&mut stream).await.is_err() {
                        break;
                    }
                    match tokio::time::timeout(Duration::from_secs(5), IpcFrame::read_from(&mut stream)).await {
                        Ok(Ok(Some(IpcFrame::Pong { .. }))) => {}
                        _ => break,
                    }
                }
            }
        }
    });
}

/// Read-only inspection of live persistent SSH sessions on disk (used by
/// `meshharbord ssh-sessions list`). Never deletes bootstrap files, unlinks
/// sockets, or terminates running hosts.
#[cfg(feature = "ssh-server")]
pub async fn list_sessions_readonly() -> Vec<PersistentSessionInfo> {
    let Ok(master) = master_key() else {
        return Vec::new();
    };
    let base_dir = state_dir();
    let dir = sessions_dir_for(&base_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in entries.flatten() {
        let path = ent.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        #[cfg(unix)]
        let sid_hex = match fname.strip_suffix(".sock") {
            Some(h) => h,
            None => continue,
        };
        #[cfg(windows)]
        let sid_hex = match fname.strip_suffix(".pipe") {
            Some(h) => h,
            None => continue,
        };
        let Ok(expected_sid) = SessionId::from_hex(sid_hex) else {
            continue;
        };
        let endpoint = endpoint_for(&base_dir, &expected_sid);
        let Ok(mut stream) = connect_host_once(&endpoint, Duration::from_secs(1)).await else {
            continue;
        };
        let Ok(hello) = read_host_hello(&mut stream, Duration::from_secs(1)).await else {
            continue;
        };
        if !verify_descriptor_seal(&master, &hello.descriptor_json, &hello.seal) {
            continue;
        }
        let Ok(desc) = serde_json::from_slice::<SessionDescriptor>(&hello.descriptor_json) else {
            continue;
        };
        if desc.sid != expected_sid {
            continue;
        }
        out.push(PersistentSessionInfo {
            sid: desc.sid.to_hex(),
            org_id: desc.org_id,
            principal: desc.principal,
            client_key_fp: desc.client_key_fp,
            created_ms: desc.created_ms,
            deadline_ms: desc.deadline_ms,
            attached: hello.attached,
            survives_restart: hello.persist.survives_restart,
            persist_reason: hello.persist.reason,
            child_pid: hello.child_pid,
            scope_unit: hello.scope_unit,
        });
    }
    out.sort_by_key(|s| s.created_ms);
    out
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
    let base_dir = state_dir();
    let dir = sessions_dir_for(&base_dir);
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

        // Only clean up stale `.boot.json` files older than 30 s so a concurrent
        // spawn is never disrupted.
        if fname.ends_with(".boot.json") {
            let is_stale = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|mtime| mtime.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_secs(30));
            if is_stale {
                let _ = std::fs::remove_file(&path);
            }
            continue;
        }

        #[cfg(unix)]
        let sid_hex = match fname.strip_suffix(".sock") {
            Some(h) => h.to_string(),
            None => continue,
        };
        #[cfg(windows)]
        let sid_hex = match fname.strip_suffix(".pipe") {
            Some(h) => h.to_string(),
            None => continue,
        };

        let Ok(expected_sid) = SessionId::from_hex(&sid_hex) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        let endpoint = endpoint_for(&base_dir, &expected_sid);

        let mut stream = match connect_host_once_io(&endpoint, Duration::from_secs(2)).await {
            Ok(s) => s,
            Err(kind) => {
                // Only unlink socket/marker when the OS confirms no listener is bound.
                if matches!(
                    kind,
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) {
                    let _ = std::fs::remove_file(&path);
                }
                continue;
            }
        };

        let Ok(hello) = read_host_hello(&mut stream, Duration::from_secs(2)).await else {
            let _ = send_terminate(&mut stream, TerminateReason::HostUnresponsive, 500).await;
            let _ = wait_stream_eof(&mut stream, Duration::from_millis(800)).await;
            let _ = std::fs::remove_file(&path);
            continue;
        };

        // 1. Cryptographic seal verification.
        if !verify_descriptor_seal(&master, &hello.descriptor_json, &hello.seal) {
            warn!(sid = %expected_sid.short_hex(), "ssh-persist: killing host with invalid seal");
            let _ = send_terminate(&mut stream, TerminateReason::Revoked, 500).await;
            let _ = wait_stream_eof(&mut stream, Duration::from_millis(800)).await;
            stop_os_handle(hello.scope_unit.clone()).await;
            let _ = std::fs::remove_file(&path);
            continue;
        }

        // 2. Parse descriptor and check sid matches filename.
        let Ok(desc) = serde_json::from_slice::<SessionDescriptor>(&hello.descriptor_json) else {
            let _ = send_terminate(&mut stream, TerminateReason::Revoked, 500).await;
            let _ = wait_stream_eof(&mut stream, Duration::from_millis(800)).await;
            stop_os_handle(hello.scope_unit.clone()).await;
            continue;
        };
        if desc.sid != expected_sid {
            warn!("ssh-persist: killing host with mismatched sid/endpoint");
            let _ = send_terminate(&mut stream, TerminateReason::Revoked, 500).await;
            let _ = wait_stream_eof(&mut stream, Duration::from_millis(800)).await;
            stop_os_handle(hello.scope_unit.clone()).await;
            continue;
        }

        // 3. Deadline + device-local gate re-check (leave tombstones so returning
        // clients stop retrying immediately with an exact reason).
        if now >= desc.deadline_ms {
            let _ = send_terminate(&mut stream, TerminateReason::Expired, 500).await;
            let _ = wait_stream_eof(&mut stream, Duration::from_millis(800)).await;
            stop_os_handle(hello.scope_unit.clone()).await;
            reg().lock().unwrap_or_else(|e| e.into_inner()).tombstones.insert(
                (desc.org_id.clone(), desc.client_key_fp.clone()),
                Tombstone {
                    sid: desc.sid,
                    reason: RefuseReason::Expired,
                    deadline_ms: desc.deadline_ms.max(now.saturating_add(300_000)),
                },
            );
            continue;
        }
        if let Err(why) = gate_allows(&desc) {
            warn!(sid = %desc.sid.short_hex(), %why, "ssh-persist: terminating adopted host disallowed by current policy");
            let _ = send_terminate(&mut stream, TerminateReason::PolicyChanged, 1000).await;
            let _ = wait_stream_eof(&mut stream, Duration::from_millis(1200)).await;
            stop_os_handle(hello.scope_unit.clone()).await;
            reg().lock().unwrap_or_else(|e| e.into_inner()).tombstones.insert(
                (desc.org_id.clone(), desc.client_key_fp.clone()),
                Tombstone {
                    sid: desc.sid,
                    reason: RefuseReason::Revoked { detail: why },
                    deadline_ms: desc.deadline_ms,
                },
            );
            continue;
        }

        // 4. Register valid surviving host (including exited hosts lingering for
        // output replay + exit-code delivery) and arm daemon keepalive monitor.
        let entry = SessionEntry {
            sid: desc.sid,
            endpoint: endpoint.clone(),
            descriptor: desc,
            descriptor_json: hello.descriptor_json,
            seal: hello.seal,
            persist: hello.persist,
            scope_unit: hello.scope_unit,
            job_name: hello.job_name,
            child_pid: hello.child_pid,
            attached: false,
            attach_gen: 0,
            last_detached_ms: now,
        };
        let sid = entry.sid;
        reg()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .insert(sid, entry);
        start_keepalive_monitor(sid, endpoint);
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
    let endpoint = endpoint_for(&state_dir(), &entry.sid);
    let reason_wire = match reason {
        TerminateReason::Expired => RefuseReason::Expired,
        _ => RefuseReason::Revoked {
            detail: format!("{reason:?}"),
        },
    };
    remove_entry_with_reason(entry, reason_wire);
    if let Ok(mut stream) = connect_host_once(&endpoint, Duration::from_secs(1)).await {
        let _ = read_host_hello(&mut stream, Duration::from_millis(500)).await;
        let _ = send_terminate(&mut stream, reason, 1500).await;
        // Wait briefly for host to exit cleanly before forcing OS kill / unlinking socket.
        let _ = wait_stream_eof(&mut stream, Duration::from_secs(2)).await;
    }
    stop_os_handle(entry.scope_unit.clone()).await;
    #[cfg(unix)]
    {
        // Only unlink after termination attempt; ignore NotFound if host already cleaned up.
        let _ = std::fs::remove_file(&endpoint);
    }
    #[cfg(windows)]
    {
        let marker = sessions_dir_for(&state_dir()).join(format!("{}.pipe", entry.sid.to_hex()));
        let _ = std::fs::remove_file(marker);
    }
    Ok(())
}

#[cfg(feature = "ssh-server")]
async fn wait_stream_eof(stream: &mut HostIpcStream, budget: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(rem, IpcFrame::read_from(stream)).await {
            Ok(Ok(None)) | Ok(Err(_)) => return true,
            Ok(Ok(Some(_))) => continue,
            Err(_) => return false,
        }
    }
    false
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
async fn connect_host_once_io(
    endpoint: &str,
    timeout: Duration,
) -> Result<HostIpcStream, std::io::ErrorKind> {
    #[cfg(unix)]
    {
        tokio::time::timeout(timeout, tokio::net::UnixStream::connect(endpoint))
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)?
            .map_err(|e| e.kind())
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match ClientOptions::new().open(endpoint) {
                Ok(c) => return Ok(c),
                Err(e) if std::time::Instant::now() < deadline => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        return Err(e.kind());
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => return Err(e.kind()),
            }
        }
    }
}

#[cfg(feature = "ssh-server")]
async fn connect_host_once(endpoint: &str, timeout: Duration) -> Result<HostIpcStream, String> {
    connect_host_once_io(endpoint, timeout)
        .await
        .map_err(|k| format!("connect {endpoint}: {k:?}"))
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
async fn stop_os_handle(scope_unit: Option<String>) {
    #[cfg(target_os = "linux")]
    if let Some(unit) = scope_unit {
        let _ = tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new("systemctl");
            if unsafe { libc::geteuid() } != 0 {
                cmd.arg("--user");
            }
            let _ = cmd
                .args(["kill", "-s", "KILL", "--no-block", &unit])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        })
        .await;
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
    for (_, tok) in g.keepalives.drain() {
        tok.cancel();
    }
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
                Ok(mut child) => {
                    // Reap launcher child in background so it never sits as a zombie.
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                    return Ok(());
                }
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
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn setsid ssh-pty-host: {e}"))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
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
