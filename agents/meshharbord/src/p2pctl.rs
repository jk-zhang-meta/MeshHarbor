// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Daemon-side Unified Overlay P2P Control Plane (`p2pctl`, TCP 41642).
//!
//! Serves and dials authenticated peer-to-peer control requests over the
//! overlay-intercepted TCP port [`P2P_CTL_PORT`] (`41642`):
//! - `DeviceInfo`: peer OS, version, SSH port/host pubkey, exec availability,
//!   and RDP availability/port/certificate SHA-256 pin for offline `mh rdp`
//!   and Companion device lists.
//! - `SshGrant`: offline capability-backed SSH grant admission through the
//!   shared [`crate::ssh::admit_grant`] gate (`allow_via_service: false`).
//! - `Exec`: offline capability-backed command execution through the shared
//!   [`crate::exec::admit`] gate (`allow_via_service: false`) with atomic
//!   persisted `(origin, jti, req_id, req_digest)` replay/crash-retry
//!   protection and a bounded offline audit journal.
//!
//! Security boundaries:
//! 1. `WgDevice` unconditionally drops packets to TCP `41642` unless the inner
//!    IPv4 source is the decrypting WG peer's exact `/32` overlay IP.
//! 2. Every connection executes a mutual X25519 + HMAC-SHA256 `hello` handshake
//!    bound to `(tenant_id, origin_wg_pubkey, target_wg_pubkey, origin_nonce,
//!    target_nonce)` derived from the peers' static WireGuard keypair DH secret.
//! 3. Origins check `NetmapPeer::supports_p2pctl` BEFORE dialing TCP `41642`,
//!    and verify the server's `hello` proof BEFORE sending any request payload
//!    or trusting `P2pDeviceInfo`.
//! 4. FR-127 protected devices (`cfg.protected == true`) refuse all `p2pctl`
//!    requests.
//! 5. Cached `offline_cap` JWTs stay strictly daemon-internal and are NEVER
//!    logged or surfaced over LocalAPI.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::collections::HashMap;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::io::Write as _;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::path::PathBuf;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use meshharbor_remote_control::models::{ConsentMode, exec_limits, ssh_limits};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use meshharbor_remote_control::offline_cap::{
    OfflineCapClaims, VERB_EXEC, VERB_SSH, VerifyContext, verify_offline_cap,
};
use meshharbor_remote_control::p2pctl::P2pDeviceInfo;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use meshharbor_remote_control::p2pctl::{
    P2P_CTL_FIRST_FRAME_TIMEOUT, P2P_CTL_PORT, P2P_CTL_VERSION, P2pClientRequest, P2pHelloInit,
    P2pHelloResp, P2pReq, P2pResp, compute_hello_proof, decode_hex, derive_hello_mac_key,
    encode_hex, read_frame, verify_hello_proof, write_frame,
};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use meshharbor_remote_control::signaling::{NetmapPeer, OverlayNetworkInfo};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use sha2::{Digest as _, Sha256};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use tokio::net::TcpStream;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use tracing::{debug, info, warn};
use tunnel_core::localapi::Response;

use crate::config::AgentConfig;

/// Short-lived cache for verified `P2pDeviceInfo` answers per peer IP.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
const DEVICE_INFO_CACHE_TTL: Duration = Duration::from_secs(15);

/// Maximum size of one tenant's offline audit journal file (512 KiB).
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
const MAX_OFFLINE_AUDIT_BYTES: u64 = 512 * 1024;

/// Maximum concurrent p2pctl connections allowed from a single peer overlay IP
/// before/after handshake so one peer cannot exhaust tasks.
#[cfg(feature = "overlay-netstack")]
const MAX_CONNS_PER_PEER: usize = 8;

/// Maximum pre-capability refusal audit entries written per peer IP per minute
/// so an unprivileged peer cannot fill the 512 KiB audit journal with noise.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
const MAX_REFUSAL_AUDIT_PER_PEER_PER_MIN: usize = 10;

/// Maximum persisted exec replay reservations per tenant before pruning oldest.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
const MAX_REPLAY_ENTRIES: usize = 4096;

/// Single-use SSH grant redeem window when minted offline (60 s, matching server).
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
const OFFLINE_SSH_GRANT_REDEEM_MS: u64 = 60_000;

/// Whether the `p2pctl` overlay control plane is enabled on this node.
/// Built-in default: ON (`p2p_control_enabled = false` or
/// `MESHHARBORD_P2P_CONTROL_ENABLED=0` disables it).
pub fn enabled(cfg: &AgentConfig) -> bool {
    if cfg.p2p_control_enabled == Some(false) {
        return false;
    }
    tunnel_core::env::flag("P2P_CONTROL_ENABLED", true)
}

/// One netmap peer indexed in the in-memory [`PeerDirectory`].
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub node_id: String,
    pub agent_id: Option<String>,
    pub name: String,
    pub overlay_ip: Ipv4Addr,
    pub wg_public_key: String,
    pub wg_public_bytes: [u8; 32],
    pub supports_p2pctl: bool,
    pub backbone_only: bool,
    pub reachable: bool,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[derive(Clone)]
pub struct TenantDirectory {
    pub tenant_id: String,
    pub self_agent_id: String,
    pub self_wg_pubkey: String,
    pub self_wg_secret: [u8; 32],
    pub self_ip: String,
    pub network: OverlayNetworkInfo,
    pub peers_by_ip: HashMap<Ipv4Addr, PeerEntry>,
    pub peers: Vec<PeerEntry>,
    pub socks_port: Option<u16>,
    info_cache: HashMap<(Ipv4Addr, String), (Instant, P2pDeviceInfo)>,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn peer_directory() -> &'static Mutex<HashMap<String, TenantDirectory>> {
    static DIR: OnceLock<Mutex<HashMap<String, TenantDirectory>>> = OnceLock::new();
    DIR.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Daemon-internal offline capability cache (NEVER exposed via LocalAPI) ───

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[derive(Clone)]
struct CachedCap {
    token: String,
    exp_secs: u64,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
type CapCacheMap = HashMap<(String, String, String), CachedCap>;

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn cap_cache() -> &'static Mutex<CapCacheMap> {
    static CAPS: OnceLock<Mutex<CapCacheMap>> = OnceLock::new();
    CAPS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn sanitize_component(s: &str) -> String {
    let clean: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if clean.is_empty() {
        "default".into()
    } else {
        clean
    }
}

/// Decode the unverified JWT payload segment solely to index our own cached
/// token by `(tenant_id, claims.tgt, claims.verb)` on the originating side.
/// The TARGET always cryptographically verifies the signature against its
/// trusted `offline_cap_keys` before honoring anything.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn parse_unverified_cap_claims(token: &str) -> Option<OfflineCapClaims> {
    let mut parts = token.trim().split('.');
    let _hdr = parts.next()?;
    let payload_b64 = parts.next()?;
    let _sig = parts.next()?;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Cache a server-issued `offline_cap` JWT daemon-internally. Never logs the
/// token and never exposes it on LocalAPI.
pub fn store_offline_cap(tenant_id: &str, token: &str) {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let Some(claims) = parse_unverified_cap_claims(token) else {
            return;
        };
        if claims.tid != tenant_id
            || (claims.verb != VERB_SSH && claims.verb != VERB_EXEC)
            || claims.tgt.trim().is_empty()
            || claims.exp <= now_unix_secs()
        {
            return;
        }
        let key = (
            tenant_id.to_string(),
            claims.tgt.clone(),
            claims.verb.clone(),
        );
        let mut guard = cap_cache().lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(
            key,
            CachedCap {
                token: token.to_string(),
                exp_secs: claims.exp,
            },
        );
        debug!(
            tenant = %tenant_id,
            target = %claims.tgt,
            verb = %claims.verb,
            "p2pctl: cached offline capability daemon-internally"
        );
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (tenant_id, token);
    }
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn get_offline_cap(tenant_id: &str, target_agent_id: &str, verb: &str) -> Option<String> {
    let now = now_unix_secs();
    let mut guard = cap_cache().lock().unwrap_or_else(|e| e.into_inner());
    let key = (
        tenant_id.to_string(),
        target_agent_id.to_string(),
        verb.to_string(),
    );
    match guard.get(&key) {
        Some(c) if c.exp_secs > now => Some(c.token.clone()),
        Some(_) => {
            guard.remove(&key);
            None
        }
        None => None,
    }
}

// ── Atomic persisted offline exec replay / crash-retry reservation ──────────

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ReplayRecord {
    org: String,
    jti: String,
    req_id: String,
    req_digest: String,
    ts_ms: u64,
    #[serde(default)]
    exp_ms: u64,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
type ReplayKey = (String, String, String);
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
type ReplayMap = HashMap<PathBuf, HashMap<ReplayKey, u64>>;

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn replay_lock() -> &'static Mutex<ReplayMap> {
    static LOCK: OnceLock<Mutex<ReplayMap>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn audit_io_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn valid_wire_request_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn truncate_utf8_to_bytes(s: &mut String, max_bytes: usize) -> bool {
    if s.len() <= max_bytes {
        return false;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn fit_exec_resp_to_frame(mut resp: P2pResp) -> P2pResp {
    use meshharbor_remote_control::p2pctl::P2P_CTL_MAX_FRAME_BYTES;
    const SAFE_BUDGET: usize = P2P_CTL_MAX_FRAME_BYTES - 512;
    // Shrink stdout/stderr iteratively so JSON escaping overhead is also accounted for.
    for _ in 0..8 {
        let cur_len = match serde_json::to_vec(&resp) {
            Ok(v) => v.len(),
            Err(_) => break,
        };
        if cur_len <= SAFE_BUDGET {
            break;
        }
        let excess = cur_len - SAFE_BUDGET + 256;
        let P2pResp::Exec {
            stdout,
            stderr,
            truncated,
            ..
        } = &mut resp
        else {
            break;
        };
        let total_out = stdout.len() + stderr.len();
        if total_out == 0 {
            break;
        }
        let trim_stdout = (excess * stdout.len())
            .div_ceil(total_out)
            .min(stdout.len());
        let trim_stderr = excess.saturating_sub(trim_stdout).min(stderr.len());
        if trim_stdout > 0 {
            let target = stdout.len().saturating_sub(trim_stdout);
            truncate_utf8_to_bytes(stdout, target);
            *truncated = true;
        }
        if trim_stderr > 0 {
            let target = stderr.len().saturating_sub(trim_stderr);
            truncate_utf8_to_bytes(stderr, target);
            *truncated = true;
        }
    }
    resp
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn compact_replay_journal(path: &Path, live: &HashMap<ReplayKey, u64>, now_ms: u64) {
    let Some(parent) = path.parent() else {
        return;
    };
    if ensure_private_dir(parent).is_err() {
        return;
    }
    let tmp = path.with_extension(format!(
        "jsonl.tmp.{}.{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let Ok(mut f) = opts.open(&tmp) else {
        return;
    };
    let mut ok = true;
    for ((org, jti, req_id), &exp_ms) in live {
        if exp_ms <= now_ms {
            continue;
        }
        let rec = ReplayRecord {
            org: org.clone(),
            jti: jti.clone(),
            req_id: req_id.clone(),
            req_digest: String::new(),
            ts_ms: now_ms,
            exp_ms,
        };
        if let Ok(line) = serde_json::to_string(&rec)
            && writeln!(f, "{line}").is_err()
        {
            ok = false;
            break;
        }
    }
    if ok && f.sync_all().is_ok() {
        drop(f);
        let _ = std::fs::rename(&tmp, path);
    } else {
        drop(f);
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn replay_file_path(config_path: &Path, tenant_id: &str) -> Option<PathBuf> {
    let dir = config_path.parent()?.join("overlay");
    Some(dir.join(format!(
        "offline-exec-replay-{}.jsonl",
        sanitize_component(tenant_id)
    )))
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn audit_file_path(config_path: &Path, tenant_id: &str) -> Option<PathBuf> {
    let dir = config_path.parent()?.join("overlay");
    Some(dir.join(format!(
        "offline-audit-{}.jsonl",
        sanitize_component(tenant_id)
    )))
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create dir {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn open_private_append(path: &Path) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn exec_request_digest(shell: &str, command: &str, timeout_ms: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(shell.as_bytes());
    hasher.update([0]);
    hasher.update(command.as_bytes());
    hasher.update([0]);
    hasher.update(timeout_ms.to_be_bytes());
    encode_hex(&hasher.finalize())
}

/// Atomically reserve `(org, jti, req_id, req_digest)` on disk (`sync_all`)
/// BEFORE launching an offline `exec` command.
///
/// Returns `Ok(())` only on first reservation; returns `Err(...)` if the same
/// `(org, jti, req_id)` was already reserved in this run or before a crash,
/// preventing replay and crash-retry double execution.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[allow(clippy::too_many_arguments)]
fn reserve_offline_exec_once(
    config_path: &Path,
    tenant_id: &str,
    org: &str,
    jti: &str,
    req_id: &str,
    req_digest: &str,
    cap_exp_ms: u64,
) -> Result<(), String> {
    const FALLBACK_REPLAY_TTL_MS: u64 = 24 * 3600 * 1000;
    let path = replay_file_path(config_path, tenant_id)
        .ok_or_else(|| "cannot resolve offline exec replay journal path".to_string())?;
    let now_ms = now_unix_ms();
    let eff_exp_ms = cap_exp_ms.max(now_ms.saturating_add(60_000));
    let mut map = replay_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut loaded_had_expired = false;
    let entries = map.entry(path.clone()).or_insert_with(|| {
        let mut loaded = HashMap::new();
        if let Ok(raw) = std::fs::read_to_string(&path) {
            for line in raw.lines() {
                if let Ok(rec) = serde_json::from_str::<ReplayRecord>(line) {
                    let rec_exp = if rec.exp_ms > 0 {
                        rec.exp_ms
                    } else {
                        rec.ts_ms.saturating_add(FALLBACK_REPLAY_TTL_MS)
                    };
                    if rec_exp > now_ms {
                        loaded.insert((rec.org, rec.jti, rec.req_id), rec_exp);
                    } else {
                        loaded_had_expired = true;
                    }
                }
            }
        }
        loaded
    });
    let before = entries.len();
    entries.retain(|_, exp| *exp > now_ms);
    let pruned = loaded_had_expired || entries.len() < before;
    if pruned {
        compact_replay_journal(&path, entries, now_ms);
    }
    let key = (org.to_string(), jti.to_string(), req_id.to_string());
    if entries.contains_key(&key) {
        return Err(
            "duplicate or replayed offline exec request_id — refused to prevent double execution"
                .into(),
        );
    }
    if entries.len() >= MAX_REPLAY_ENTRIES {
        return Err(
            "offline exec replay reservation table is full — retry after older capabilities expire"
                .into(),
        );
    }
    let rec = ReplayRecord {
        org: org.to_string(),
        jti: jti.to_string(),
        req_id: req_id.to_string(),
        req_digest: req_digest.to_string(),
        ts_ms: now_ms,
        exp_ms: eff_exp_ms,
    };
    let line = serde_json::to_string(&rec).map_err(|e| format!("encode replay record: {e}"))?;
    let mut f = open_private_append(&path)?;
    writeln!(f, "{line}").map_err(|e| format!("write replay record: {e}"))?;
    f.sync_all()
        .map_err(|e| format!("sync replay record: {e}"))?;
    entries.insert(key, eff_exp_ms);
    Ok(())
}

// ── Bounded offline audit journal (redacted, owner-only, flushed on reconnect) ─

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OfflineAuditEntry {
    pub ts_ms: u64,
    pub tenant_id: String,
    pub verb: String,
    pub caller: String,
    pub origin_agent_id: String,
    pub cap_jti: String,
    pub request_id: String,
    pub allowed: bool,
    pub detail: String,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn refusal_audit_rate_lock() -> &'static Mutex<HashMap<Ipv4Addr, (Instant, usize)>> {
    static LOCK: OnceLock<Mutex<HashMap<Ipv4Addr, (Instant, usize)>>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn allow_refusal_audit(peer_ip: Ipv4Addr) -> bool {
    let now = Instant::now();
    let mut map = refusal_audit_rate_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.retain(|_, (since, _)| now.saturating_duration_since(*since) < Duration::from_secs(60));
    let entry = map.entry(peer_ip).or_insert((now, 0));
    if now.saturating_duration_since(entry.0) >= Duration::from_secs(60) {
        *entry = (now, 0);
    }
    if entry.1 >= MAX_REFUSAL_AUDIT_PER_PEER_PER_MIN {
        return false;
    }
    entry.1 += 1;
    true
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn append_offline_audit(config_path: &Path, entry: &OfflineAuditEntry) -> Result<(), String> {
    let Some(path) = audit_file_path(config_path, &entry.tenant_id) else {
        return Err("cannot resolve offline audit journal path".into());
    };
    let _guard = audit_io_lock().lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() >= MAX_OFFLINE_AUDIT_BYTES
    {
        warn!(
            tenant = %entry.tenant_id,
            path = %path.display(),
            "p2pctl: offline audit journal reached 512 KiB cap; refusing further writes until control-WS reconnect drains it"
        );
        return Err(
            "offline audit journal reached 512 KiB capacity — reconnect control-WS to flush".into(),
        );
    }
    let mut redacted = entry.clone();
    redacted.detail = crate::exec::redactor()
        .apply(&redacted.detail)
        .chars()
        .take(512)
        .collect();
    let line =
        serde_json::to_string(&redacted).map_err(|e| format!("encode offline audit entry: {e}"))?;
    let mut f = open_private_append(&path)?;
    writeln!(f, "{line}")
        .and_then(|()| f.sync_all())
        .map_err(|e| {
            warn!(tenant = %entry.tenant_id, %e, "p2pctl: failed to append offline audit entry");
            format!("write offline audit entry: {e}")
        })?;
    Ok(())
}

/// Best-effort audit helper for pre-cap refusals, rate-limited per peer IP so
/// unprivileged peers cannot exhaust the 512 KiB audit journal.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn append_refusal_audit_rate_limited(
    config_path: &Path,
    peer_ip: Ipv4Addr,
    entry: &OfflineAuditEntry,
) {
    if allow_refusal_audit(peer_ip) {
        let _ = append_offline_audit(config_path, entry);
    }
}

/// Atomically rotate and drain any pending offline audit journal segments when
/// the control-WS reconnects so concurrent appends are never lost.
pub fn drain_offline_audit_on_reconnect(config_path: &Path, tenant_id: &str) -> usize {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let Some(path) = audit_file_path(config_path, tenant_id) else {
            return 0;
        };
        let rotated = {
            let _guard = audit_io_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut segments: Vec<PathBuf> = Vec::new();
            let prefix = format!(
                "offline-audit-{}.jsonl.draining.",
                sanitize_component(tenant_id)
            );
            if let Some(dir) = path.parent()
                && let Ok(rd) = std::fs::read_dir(dir)
            {
                for ent in rd.flatten() {
                    if let Some(name) = ent.file_name().to_str()
                        && name.starts_with(&prefix)
                    {
                        segments.push(ent.path());
                    }
                }
            }
            let draining = path.with_extension(format!(
                "jsonl.draining.{}.{}",
                std::process::id(),
                rand::random::<u32>()
            ));
            if std::fs::rename(&path, &draining).is_ok() {
                segments.push(draining);
            }
            segments
        };
        let mut count = 0usize;
        for seg in rotated {
            let Ok(raw) = std::fs::read_to_string(&seg) else {
                continue;
            };
            for line in raw.lines() {
                if let Ok(entry) = serde_json::from_str::<OfflineAuditEntry>(line) {
                    info!(
                        tenant = %entry.tenant_id,
                        verb = %entry.verb,
                        caller = %entry.caller,
                        origin = %entry.origin_agent_id,
                        cap_jti = %entry.cap_jti,
                        request_id = %entry.request_id,
                        allowed = entry.allowed,
                        detail = %entry.detail,
                        ts_ms = entry.ts_ms,
                        "p2pctl: drained offline audit entry on reconnect"
                    );
                    count += 1;
                }
            }
            let _ = std::fs::remove_file(&seg);
        }
        count
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (config_path, tenant_id);
        0
    }
}

/// Update the in-memory `PeerDirectory` for `tenant_id` from a live or
/// cache-seeded netmap snapshot. Runs even when on-disk netmap caching is off.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub fn update_tenant_directory(
    tenant_id: &str,
    self_agent_id: &str,
    keypair: &tunnel_core::overlay::WgKeypair,
    self_ip: &str,
    network: &OverlayNetworkInfo,
    peers: &[NetmapPeer],
    socks_port: Option<u16>,
) {
    let mut by_ip = HashMap::with_capacity(peers.len());
    let mut list = Vec::with_capacity(peers.len());
    for p in peers {
        let Ok(ip) = p.overlay_ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let Some(pk_bytes) = tunnel_core::overlay::decode_public(&p.wg_public_key) else {
            continue;
        };
        let entry = PeerEntry {
            node_id: p.node_id.to_hex(),
            agent_id: p.agent_id.map(|id| id.to_hex()),
            name: p.name.clone(),
            overlay_ip: ip,
            wg_public_key: p.wg_public_key.clone(),
            wg_public_bytes: pk_bytes,
            supports_p2pctl: p.supports_p2pctl,
            backbone_only: p.backbone_only,
            reachable: p.reachable,
        };
        by_ip.insert(ip, entry.clone());
        list.push(entry);
    }
    let mut guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
    let prev_cache = guard
        .get(tenant_id)
        .map(|d| d.info_cache.clone())
        .unwrap_or_default();
    let info_cache = prev_cache
        .into_iter()
        .filter(|((ip, pk), _)| by_ip.get(ip).is_some_and(|p| p.wg_public_key == *pk))
        .collect();
    guard.insert(
        tenant_id.to_string(),
        TenantDirectory {
            tenant_id: tenant_id.to_string(),
            self_agent_id: self_agent_id.to_string(),
            self_wg_pubkey: keypair.public_base64(),
            self_wg_secret: keypair.secret.to_bytes(),
            self_ip: self_ip.to_string(),
            network: network.clone(),
            peers_by_ip: by_ip,
            peers: list,
            socks_port,
            info_cache,
        },
    );
}

/// Remove a tenant's in-memory `PeerDirectory` and cached offline capabilities
/// (on revocation, `Goodbye`, or overlay disable).
pub fn clear_tenant_directory(tenant_id: &str) {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        peer_directory()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(tenant_id);
        cap_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(tid, _, _), _| tid != tenant_id);
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant_id;
    }
}

/// Snapshot the known peers for `tenant_id` (empty on non-overlay builds or
/// before any netmap/cache has loaded).
pub fn tenant_peers(tenant_id: &str) -> Vec<PeerEntry> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        peer_directory()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tenant_id)
            .map(|d| d.peers.clone())
            .unwrap_or_default()
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant_id;
        Vec::new()
    }
}

/// Lookup one peer by overlay IP in `tenant_id`.
pub fn lookup_by_ip(tenant_id: &str, ip: Ipv4Addr) -> Option<PeerEntry> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        peer_directory()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tenant_id)
            .and_then(|d| d.peers_by_ip.get(&ip).cloned())
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (tenant_id, ip);
        None
    }
}

/// Lookup a peer by agent_id, node_id, overlay IP, or case-insensitive name.
pub fn lookup_by_target(tenant_id: &str, target: &str) -> Option<PeerEntry> {
    let q = target.trim();
    if q.is_empty() {
        return None;
    }
    let ip_q = q.parse::<Ipv4Addr>().ok();
    tenant_peers(tenant_id).into_iter().find(|p| {
        ip_q == Some(p.overlay_ip)
            || p.node_id.eq_ignore_ascii_case(q)
            || p.agent_id
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(q))
            || p.name.eq_ignore_ascii_case(q)
    })
}

/// Tenant self-name from the live/cached `PeerDirectory`, if known.
pub fn tenant_self_name(tenant_id: &str) -> Option<String> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get(tenant_id)
            .and_then(|d| d.network.self_name.clone())
            .filter(|s| !s.trim().is_empty())
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant_id;
        None
    }
}

/// Tenant ACL mode string from the live/cached `PeerDirectory`, if known.
pub fn tenant_acl_mode(tenant_id: &str) -> Option<String> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
        let _dir = guard.get(tenant_id)?;
        Some("unknown".into())
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant_id;
        None
    }
}

/// Server context passed into the `SplitTun` accept loop on port `41642`.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[derive(Clone)]
pub struct ServerCtx {
    pub tenant_id: String,
    pub self_agent_id: String,
    pub self_wg_pubkey: String,
    pub keypair: tunnel_core::overlay::WgKeypair,
    pub cfg: Arc<AgentConfig>,
    pub services: crate::ssh::SessionServices,
    pub remote_cfg: crate::remote_config::RemoteConfigServices,
    /// Optional peer table override for isolated unit tests.
    pub peer_override: Option<Arc<Mutex<HashMap<Ipv4Addr, PeerEntry>>>>,
    /// Optional network/self-IP override for isolated unit tests.
    pub net_override: Option<(String, OverlayNetworkInfo)>,
    /// Optional wall-clock override (Unix seconds) for deterministic unit tests.
    pub now_secs_override: Option<u64>,
    /// Shared live control-WS attachment flag from `OverlayRuntime`. When `true`,
    /// offline capabilities are refused so server-side revocations cannot be
    /// bypassed while the target itself is online.
    pub control_ws_attached: Option<Arc<std::sync::atomic::AtomicBool>>,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
impl ServerCtx {
    pub fn new(
        cfg: &AgentConfig,
        keypair: tunnel_core::overlay::WgKeypair,
        services: crate::ssh::SessionServices,
        remote_cfg: crate::remote_config::RemoteConfigServices,
    ) -> Self {
        Self {
            tenant_id: cfg.tenant_id.clone(),
            self_agent_id: cfg.agent_id.clone(),
            self_wg_pubkey: keypair.public_base64(),
            keypair,
            cfg: Arc::new(cfg.clone()),
            services,
            remote_cfg,
            peer_override: None,
            net_override: None,
            now_secs_override: None,
            control_ws_attached: None,
        }
    }

    pub fn with_control_ws_attached(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.control_ws_attached = Some(flag);
        self
    }

    fn is_control_ws_attached(&self) -> bool {
        self.control_ws_attached
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn lookup_peer(&self, peer_ip: Ipv4Addr) -> Option<PeerEntry> {
        if let Some(ov) = &self.peer_override {
            return ov
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&peer_ip)
                .cloned();
        }
        lookup_by_ip(&self.tenant_id, peer_ip)
    }

    fn current_network(&self) -> Option<(String, OverlayNetworkInfo)> {
        if let Some(ov) = &self.net_override {
            return Some(ov.clone());
        }
        let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
        let dir = guard.get(&self.tenant_id)?;
        Some((dir.self_ip.clone(), dir.network.clone()))
    }

    fn now_secs(&self) -> u64 {
        self.now_secs_override.unwrap_or_else(now_unix_secs)
    }
}

/// Accept loop for intercepted TCP connections to `<overlay_ip>:41642`.
#[cfg(feature = "overlay-netstack")]
pub async fn accept_loop(mut listener: tunnel_core::overlay::netstack::NsListener, ctx: ServerCtx) {
    struct PeerConnGuard {
        counts: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
        peer_ip: Ipv4Addr,
    }
    impl Drop for PeerConnGuard {
        fn drop(&mut self) {
            let mut g = self.counts.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = g.get_mut(&self.peer_ip) {
                if *n <= 1 {
                    g.remove(&self.peer_ip);
                } else {
                    *n -= 1;
                }
            }
        }
    }

    let per_peer_conns: Arc<Mutex<HashMap<Ipv4Addr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    info!(
        port = P2P_CTL_PORT,
        tenant = %ctx.tenant_id,
        "p2pctl: serving intercepted overlay control port"
    );
    while let Some(stream) = listener.accept().await {
        let peer_ip = match stream.peer_addr().ip() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => continue,
        };
        let admitted = {
            let mut g = per_peer_conns.lock().unwrap_or_else(|e| e.into_inner());
            let count = g.entry(peer_ip).or_insert(0);
            if *count >= MAX_CONNS_PER_PEER {
                false
            } else {
                *count += 1;
                true
            }
        };
        if !admitted {
            debug!(%peer_ip, "p2pctl: per-peer concurrent connection cap reached — dropping");
            continue;
        }
        let guard = PeerConnGuard {
            counts: per_peer_conns.clone(),
            peer_ip,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _conn_guard = guard;
            if let Err(e) = serve_conn(stream, peer_ip, ctx).await {
                debug!(%peer_ip, err = %e, "p2pctl: connection closed");
            }
        });
    }
    info!(
        port = P2P_CTL_PORT,
        tenant = %ctx.tenant_id,
        "p2pctl: intercepted overlay control port closed"
    );
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn random_nonce_32() -> Result<[u8; 32], String> {
    let mut buf = [0u8; 32];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| "CSPRNG failure generating p2pctl nonce".to_string())?;
    Ok(buf)
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn parse_consent_mode(raw: Option<&str>) -> Option<ConsentMode> {
    match raw {
        Some("auto") => Some(ConsentMode::Auto),
        _ => Some(ConsentMode::Prompt),
    }
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn resolve_host_shell(requested: &str) -> String {
    use meshharbor_remote_control::models::{ExecPolicy, OsKind};
    let os = if cfg!(windows) {
        OsKind::Windows
    } else if cfg!(target_os = "macos") {
        OsKind::Macos
    } else {
        OsKind::Linux
    };
    ExecPolicy::resolve_shell(requested, os)
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn local_device_info(cfg: &AgentConfig) -> P2pDeviceInfo {
    let rdp = crate::rdp_caps::current();
    let ssh_host_pubkey = if cfg.ssh_enabled {
        let pk = crate::ssh::host_public_key(cfg);
        (!pk.is_empty()).then_some(pk)
    } else {
        None
    };
    P2pDeviceInfo {
        os: std::env::consts::OS.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        ssh_enabled: cfg.ssh_enabled,
        ssh_port: cfg.ssh_enabled.then(|| cfg.effective_ssh_port()),
        ssh_host_pubkey,
        exec_enabled: cfg.exec_enabled && !cfg.protected,
        rdp_available: Some(rdp.available),
        rdp_port: rdp.port,
        rdp_cert_sha256: rdp.cert_sha256,
        supports_p2pctl: true,
    }
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn handle_offline_ssh_grant(
    ctx: &ServerCtx,
    peer: &PeerEntry,
    offline_cap: &str,
    request_id: &str,
    public_key: String,
    requested_session_secs: u64,
    two_factor_code: Option<String>,
) -> P2pResp {
    let err_resp = |msg: String, tf: Option<String>| P2pResp::SshGrant {
        address: None,
        port: None,
        grant_id: None,
        host_pubkey: None,
        expires_at_ms: None,
        error: Some(msg),
        two_factor: tf,
    };

    if ctx.is_control_ws_attached() {
        return err_resp(
            "target control-WS is online; use online SSH authorization instead of offline capability"
                .into(),
            None,
        );
    }

    let Some((self_ip, network)) = ctx.current_network() else {
        return err_resp("overlay network state unavailable".into(), None);
    };
    let Some(net_id) = network.network_id else {
        return err_resp(
            "offline capabilities require network_id in netmap".into(),
            None,
        );
    };
    let net_hex = net_id.to_hex();
    let claims = match verify_offline_cap(
        offline_cap,
        &network.offline_cap_keys,
        VerifyContext {
            expected_verb: VERB_SSH,
            expected_tid: &ctx.tenant_id,
            expected_net: &net_hex,
            expected_tgt: &ctx.self_agent_id,
            expected_opk: &peer.wg_public_key,
            now_secs: ctx.now_secs(),
            not_before_ms: network.offline_caps_not_before_ms,
        },
    ) {
        Ok(c) => c,
        Err(why) => {
            append_refusal_audit_rate_limited(
                ctx.remote_cfg.config_path(),
                peer.overlay_ip,
                &OfflineAuditEntry {
                    ts_ms: now_unix_ms(),
                    tenant_id: ctx.tenant_id.clone(),
                    verb: "ssh_grant".into(),
                    caller: peer.name.clone(),
                    origin_agent_id: peer
                        .agent_id
                        .clone()
                        .unwrap_or_else(|| peer.node_id.clone()),
                    cap_jti: String::new(),
                    request_id: request_id.to_string(),
                    allowed: false,
                    detail: why.clone(),
                },
            );
            return err_resp(why, None);
        }
    };

    let account_mode = claims
        .ssh_account_mode
        .clone()
        .unwrap_or_else(|| "console_user".to_string());
    if meshharbor_remote_control::models::SshAccountMode::from_wire(&account_mode).is_none() {
        return err_resp(
            format!("offline_cap carries unknown ssh_account_mode {account_mode:?}"),
            None,
        );
    }
    let cap_max_secs = claims
        .ssh_max_session_secs
        .unwrap_or(ssh_limits::MAX_SESSION_SECS)
        .clamp(1, ssh_limits::MAX_SESSION_SECS);
    let session_secs = if requested_session_secs == 0 {
        cap_max_secs
    } else {
        requested_session_secs.min(cap_max_secs)
    };
    let grant_id = bson::oid::ObjectId::new().to_hex();
    let expires_at_ms = now_unix_ms().saturating_add(OFFLINE_SSH_GRANT_REDEEM_MS);
    let consent_mode = parse_consent_mode(claims.consent_mode.as_deref());

    // Fail closed if the offline audit journal is full or unwritable BEFORE
    // admitting an SSH grant into the daemon.
    if let Err(why) = append_offline_audit(
        ctx.remote_cfg.config_path(),
        &OfflineAuditEntry {
            ts_ms: now_unix_ms(),
            tenant_id: ctx.tenant_id.clone(),
            verb: "ssh_grant".into(),
            caller: claims.caller.clone(),
            origin_agent_id: claims.org.clone(),
            cap_jti: claims.jti.clone(),
            request_id: request_id.to_string(),
            allowed: true,
            detail: format!("admitting grant_id={grant_id} session_secs={session_secs}"),
        },
    ) {
        return err_resp(why, None);
    }

    let outcome = crate::ssh::admit_grant(
        &ctx.cfg,
        crate::ssh::SshGrantAdmitInput {
            grant_id: grant_id.clone(),
            public_key,
            caller: claims.caller.clone(),
            account_mode,
            account: claims.ssh_account.clone(),
            expires_at_ms,
            session_secs,
            consent_mode,
            via_service: false,
            allow_via_service: false,
            one_command: false,
            two_factor_code,
            org_id: Some(ctx.tenant_id.clone()),
            principal_id: None,
            // Offline P2P grants have no live server revocation channel; do not
            // open persistent resumable sessions on offline grants.
            resume_allowed: Some(false),
        },
    );

    match outcome {
        crate::ssh::SshGrantAdmitOutcome::Recorded => {
            let host_pk = crate::ssh::host_public_key(&ctx.cfg);
            P2pResp::SshGrant {
                address: Some(self_ip),
                port: Some(ctx.cfg.effective_ssh_port()),
                grant_id: Some(grant_id),
                host_pubkey: (!host_pk.is_empty()).then_some(host_pk),
                expires_at_ms: Some(expires_at_ms),
                error: None,
                two_factor: None,
            }
        }
        crate::ssh::SshGrantAdmitOutcome::Refused(r) => {
            let reason = r.deny_reason();
            let tf = reason.two_factor().map(str::to_string);
            let msg = reason.message().to_string();
            let _ = append_offline_audit(
                ctx.remote_cfg.config_path(),
                &OfflineAuditEntry {
                    ts_ms: now_unix_ms(),
                    tenant_id: ctx.tenant_id.clone(),
                    verb: "ssh_grant".into(),
                    caller: claims.caller,
                    origin_agent_id: claims.org,
                    cap_jti: claims.jti,
                    request_id: request_id.to_string(),
                    allowed: false,
                    detail: format!("refused: {msg}"),
                },
            );
            err_resp(msg, tf)
        }
        crate::ssh::SshGrantAdmitOutcome::HandToService => err_resp(
            "SSH grants requiring the Windows SYSTEM service cannot run offline".into(),
            None,
        ),
        crate::ssh::SshGrantAdmitOutcome::UnsupportedBuild => {
            err_resp("this build lacks the `ssh-server` feature".into(), None)
        }
    }
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[allow(clippy::too_many_arguments)]
async fn handle_offline_exec(
    ctx: &ServerCtx,
    peer: &PeerEntry,
    offline_cap: &str,
    request_id: String,
    shell: String,
    command: String,
    timeout_ms: u64,
    two_factor_code: Option<String>,
) -> P2pResp {
    let err_resp = |msg: String| P2pResp::Exec {
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        duration_ms: 0,
        error: Some(msg),
    };

    if ctx.is_control_ws_attached() {
        return err_resp(
            "target control-WS is online; use online exec authorization instead of offline capability"
                .into(),
        );
    }

    let Some((_self_ip, network)) = ctx.current_network() else {
        return err_resp("overlay network state unavailable".into());
    };
    let Some(net_id) = network.network_id else {
        return err_resp("offline capabilities require network_id in netmap".into());
    };
    let net_hex = net_id.to_hex();
    let claims = match verify_offline_cap(
        offline_cap,
        &network.offline_cap_keys,
        VerifyContext {
            expected_verb: VERB_EXEC,
            expected_tid: &ctx.tenant_id,
            expected_net: &net_hex,
            expected_tgt: &ctx.self_agent_id,
            expected_opk: &peer.wg_public_key,
            now_secs: ctx.now_secs(),
            not_before_ms: network.offline_caps_not_before_ms,
        },
    ) {
        Ok(c) => c,
        Err(why) => {
            append_refusal_audit_rate_limited(
                ctx.remote_cfg.config_path(),
                peer.overlay_ip,
                &OfflineAuditEntry {
                    ts_ms: now_unix_ms(),
                    tenant_id: ctx.tenant_id.clone(),
                    verb: "exec".into(),
                    caller: peer.name.clone(),
                    origin_agent_id: peer
                        .agent_id
                        .clone()
                        .unwrap_or_else(|| peer.node_id.clone()),
                    cap_jti: String::new(),
                    request_id,
                    allowed: false,
                    detail: why.clone(),
                },
            );
            return err_resp(why);
        }
    };

    if !valid_wire_request_id(&request_id) {
        return err_resp("invalid request_id format".into());
    }

    // Enforce exec shell allowlist ceiling from capability claims using the
    // exact same `ExecPolicy::resolve_shell` mapping as online exec.
    let effective_shell = resolve_host_shell(&shell);
    if let Some(ref allowed_shells) = claims.exec_shells
        && !allowed_shells.is_empty()
        && !allowed_shells
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&effective_shell))
    {
        let why = format!(
            "shell {:?} is not permitted by this offline capability (allowed: {:?})",
            effective_shell, allowed_shells
        );
        let _ = append_offline_audit(
            ctx.remote_cfg.config_path(),
            &OfflineAuditEntry {
                ts_ms: now_unix_ms(),
                tenant_id: ctx.tenant_id.clone(),
                verb: "exec".into(),
                caller: claims.caller,
                origin_agent_id: claims.org,
                cap_jti: claims.jti,
                request_id,
                allowed: false,
                detail: why.clone(),
            },
        );
        return err_resp(why);
    }

    let cap_max_timeout = claims
        .exec_max_timeout_ms
        .unwrap_or(exec_limits::MAX_TIMEOUT_MS)
        .min(exec_limits::MAX_TIMEOUT_MS);
    let clamped_timeout = exec_limits::clamp_timeout_ms(timeout_ms).min(cap_max_timeout);

    let (consent_broker, indicator) = match &ctx.services.asker {
        crate::ssh::Asker::Here { broker, indicator } => (broker.clone(), indicator.clone()),
        crate::ssh::Asker::Worker(_) => {
            return err_resp("offline exec cannot run via Windows worker consent relay".into());
        }
    };

    // Atomic persisted replay/crash-retry reservation BEFORE any consent-prompt
    // or indicator side effect so a duplicate `request_id` can never rewrite or
    // interfere with an active prompt.
    let digest = exec_request_digest(&effective_shell, &command, clamped_timeout);
    if let Err(why) = reserve_offline_exec_once(
        ctx.remote_cfg.config_path(),
        &ctx.tenant_id,
        &claims.org,
        &claims.jti,
        &request_id,
        &digest,
        claims.exp.saturating_mul(1000),
    ) {
        let _ = append_offline_audit(
            ctx.remote_cfg.config_path(),
            &OfflineAuditEntry {
                ts_ms: now_unix_ms(),
                tenant_id: ctx.tenant_id.clone(),
                verb: "exec".into(),
                caller: claims.caller,
                origin_agent_id: claims.org,
                cap_jti: claims.jti,
                request_id,
                allowed: false,
                detail: why.clone(),
            },
        );
        return err_resp(why);
    }

    // Never pass peer-supplied `request_id` into consent broker filenames: use
    // a freshly generated target-local identifier for consent/indicator state.
    let local_consent_id = format!("p2p-{}", bson::oid::ObjectId::new().to_hex());

    let admitted = match crate::exec::admit(
        crate::exec::ExecAdmitInput {
            request_id: local_consent_id.clone(),
            shell: effective_shell.clone(),
            command: command.clone(),
            timeout_ms: clamped_timeout,
            max_output_bytes: 40 * 1024,
            cwd: None,
            caller: claims.caller.clone(),
            consent_mode: parse_consent_mode(claims.consent_mode.as_deref()),
            via_service: false,
            allow_via_service: false,
            run_as: claims.exec_run_as.clone(),
            two_factor_code,
            prompt_org_label: String::new(),
        },
        &crate::exec::ExecAdmitServices {
            remote_cfg: &ctx.remote_cfg,
            consent_broker: &consent_broker,
            indicator: &indicator,
        },
    ) {
        Ok(a) => a,
        Err(why) => {
            let _ = append_offline_audit(
                ctx.remote_cfg.config_path(),
                &OfflineAuditEntry {
                    ts_ms: now_unix_ms(),
                    tenant_id: ctx.tenant_id.clone(),
                    verb: "exec".into(),
                    caller: claims.caller,
                    origin_agent_id: claims.org,
                    cap_jti: claims.jti,
                    request_id,
                    allowed: false,
                    detail: why.clone(),
                },
            );
            return err_resp(why);
        }
    };

    let decision = consent_broker
        .request_with_mode(&local_consent_id, admitted.consent_mode)
        .await;
    indicator.hide_prompt(&local_consent_id);
    if !decision.granted() {
        let why = format!("the operator at this device did not approve the command ({decision:?})");
        let _ = append_offline_audit(
            ctx.remote_cfg.config_path(),
            &OfflineAuditEntry {
                ts_ms: now_unix_ms(),
                tenant_id: ctx.tenant_id.clone(),
                verb: "exec".into(),
                caller: claims.caller,
                origin_agent_id: claims.org,
                cap_jti: claims.jti,
                request_id,
                allowed: false,
                detail: why.clone(),
            },
        );
        return err_resp(why);
    }

    // Fail closed if we cannot persist the pre-execution audit record (e.g.
    // journal full at 512 KiB or disk unwritable).
    if let Err(why) = append_offline_audit(
        ctx.remote_cfg.config_path(),
        &OfflineAuditEntry {
            ts_ms: now_unix_ms(),
            tenant_id: ctx.tenant_id.clone(),
            verb: "exec".into(),
            caller: claims.caller.clone(),
            origin_agent_id: claims.org.clone(),
            cap_jti: claims.jti.clone(),
            request_id: request_id.clone(),
            allowed: true,
            detail: format!("launching shell={} cmd={}", effective_shell, command),
        },
    ) {
        return err_resp(why);
    }

    let outcome = crate::exec::shared()
        .run(admitted.req, &crate::exec::redactor())
        .await;
    let _ = append_offline_audit(
        ctx.remote_cfg.config_path(),
        &OfflineAuditEntry {
            ts_ms: now_unix_ms(),
            tenant_id: ctx.tenant_id.clone(),
            verb: "exec".into(),
            caller: claims.caller,
            origin_agent_id: claims.org,
            cap_jti: claims.jti,
            request_id,
            allowed: outcome.error.is_none(),
            detail: format!(
                "shell={} exit={:?} cmd={}",
                effective_shell, outcome.exit_code, command
            ),
        },
    );
    fit_exec_resp_to_frame(P2pResp::Exec {
        exit_code: outcome.exit_code,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        truncated: outcome.truncated,
        duration_ms: outcome.duration_ms,
        error: outcome.error,
    })
}

/// Serve one `p2pctl` connection after `SplitTun` accepted it.
///
/// Generic over `AsyncRead + AsyncWrite + Unpin` so unit tests can exercise the
/// exact server handshake and request dispatch over `tokio::io::duplex` or TCP.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub async fn serve_conn<S>(mut stream: S, peer_ip: Ipv4Addr, ctx: ServerCtx) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let init: P2pHelloInit =
        tokio::time::timeout(P2P_CTL_FIRST_FRAME_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| "timed out awaiting p2pctl hello".to_string())?
            .map_err(|e| format!("read hello init: {e}"))?;

    if init.v != P2P_CTL_VERSION {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some(format!("unsupported p2pctl version {}", init.v)),
            },
        )
        .await;
        return Err("unsupported version".into());
    }
    if init.tenant_id != ctx.tenant_id || init.target_node_id != ctx.self_wg_pubkey {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("tenant or target identity mismatch".into()),
            },
        )
        .await;
        return Err("identity mismatch".into());
    }
    let Some(origin_nonce) = decode_hex(&init.origin_nonce_hex) else {
        return Err("invalid origin nonce hex".into());
    };
    if origin_nonce.len() != 32 {
        return Err("origin nonce must be 32 bytes".into());
    }

    let Some(peer) = ctx.lookup_peer(peer_ip) else {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("unknown peer overlay IP".into()),
            },
        )
        .await;
        return Err("unknown peer IP".into());
    };
    if peer.backbone_only {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("backbone-only peer refused on p2pctl".into()),
            },
        )
        .await;
        return Err("backbone-only peer refused".into());
    }
    if init.origin_node_id != peer.wg_public_key {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("origin identity does not match peer WG key".into()),
            },
        )
        .await;
        return Err("origin WG key mismatch".into());
    }

    let target_nonce = random_nonce_32()?;
    let shared = ctx.keypair.dh(&peer.wg_public_bytes);
    let mac_key = derive_hello_mac_key(&shared);
    let server_proof = compute_hello_proof(
        &mac_key,
        b"server",
        &ctx.tenant_id,
        &peer.wg_public_key,
        &ctx.self_wg_pubkey,
        &origin_nonce,
        &target_nonce,
    );
    write_frame(
        &mut stream,
        &P2pHelloResp {
            v: P2P_CTL_VERSION,
            target_nonce_hex: encode_hex(&target_nonce),
            server_proof_hex: server_proof,
            error: None,
        },
    )
    .await
    .map_err(|e| format!("write hello resp: {e}"))?;

    let req_env: P2pClientRequest =
        tokio::time::timeout(P2P_CTL_FIRST_FRAME_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| "timed out awaiting p2pctl client request".to_string())?
            .map_err(|e| format!("read client request: {e}"))?;

    if req_env.v != P2P_CTL_VERSION
        || !verify_hello_proof(
            &mac_key,
            b"client",
            &ctx.tenant_id,
            &peer.wg_public_key,
            &ctx.self_wg_pubkey,
            &origin_nonce,
            &target_nonce,
            &req_env.client_proof_hex,
        )
    {
        let _ = write_frame(
            &mut stream,
            &P2pResp::Error {
                code: "auth_failed".into(),
                message: "p2pctl client hello proof verification failed".into(),
            },
        )
        .await;
        return Err("client hello proof failed".into());
    }

    // FR-127 — protected devices refuse ALL offline P2P control requests.
    if ctx.cfg.protected {
        let _ = write_frame(
            &mut stream,
            &P2pResp::Error {
                code: "protected".into(),
                message: "this device is protected (FR-127); offline P2P control is refused".into(),
            },
        )
        .await;
        return Ok(());
    }

    let resp = match req_env.req {
        P2pReq::DeviceInfo => P2pResp::DeviceInfo(local_device_info(&ctx.cfg)),
        P2pReq::SshGrant {
            offline_cap,
            request_id,
            public_key,
            session_secs,
            two_factor_code,
        } => handle_offline_ssh_grant(
            &ctx,
            &peer,
            &offline_cap,
            &request_id,
            public_key,
            session_secs,
            two_factor_code,
        ),
        P2pReq::Exec {
            offline_cap,
            request_id,
            shell,
            command,
            timeout_ms,
            two_factor_code,
        } => {
            handle_offline_exec(
                &ctx,
                &peer,
                &offline_cap,
                request_id,
                shell,
                command,
                timeout_ms,
                two_factor_code,
            )
            .await
        }
    };
    write_frame(&mut stream, &resp)
        .await
        .map_err(|e| format!("write response: {e}"))?;
    Ok(())
}

/// Execute one authenticated `p2pctl` request/response exchange over an open
/// stream. Verifies the server's X25519+HMAC `hello` proof BEFORE sending
/// `req` so an unprivileged port-41642 squatter never receives capability
/// tokens, TOTP codes, commands, or spoofed metadata.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub async fn exchange_on_stream<S>(
    mut stream: S,
    tenant_id: &str,
    self_keypair: &tunnel_core::overlay::WgKeypair,
    target_wg_pubkey: &str,
    target_wg_bytes: &[u8; 32],
    req: P2pReq,
    timeout: Duration,
) -> Result<P2pResp, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let self_wg_pubkey = self_keypair.public_base64();
    let origin_nonce = random_nonce_32()?;
    let init = P2pHelloInit {
        v: P2P_CTL_VERSION,
        tenant_id: tenant_id.to_string(),
        origin_node_id: self_wg_pubkey.clone(),
        target_node_id: target_wg_pubkey.to_string(),
        origin_nonce_hex: encode_hex(&origin_nonce),
    };
    tokio::time::timeout(timeout, async {
        write_frame(&mut stream, &init)
            .await
            .map_err(|e| format!("send hello init: {e}"))?;
        let hello_resp: P2pHelloResp = read_frame(&mut stream)
            .await
            .map_err(|e| format!("read hello resp: {e}"))?;
        if let Some(err) = hello_resp.error {
            return Err(format!("p2pctl hello refused: {err}"));
        }
        if hello_resp.v != P2P_CTL_VERSION {
            return Err(format!("unexpected p2pctl version {}", hello_resp.v));
        }
        let target_nonce = decode_hex(&hello_resp.target_nonce_hex)
            .ok_or_else(|| "invalid target nonce hex".to_string())?;
        if target_nonce.len() != 32 {
            return Err("target nonce must be 32 bytes".to_string());
        }
        let shared = self_keypair.dh(target_wg_bytes);
        let mac_key = derive_hello_mac_key(&shared);
        if !verify_hello_proof(
            &mac_key,
            b"server",
            tenant_id,
            &self_wg_pubkey,
            target_wg_pubkey,
            &origin_nonce,
            &target_nonce,
            &hello_resp.server_proof_hex,
        ) {
            return Err(
                "p2pctl server hello proof failed (untrusted listener on port 41642)".into(),
            );
        }
        let client_proof = compute_hello_proof(
            &mac_key,
            b"client",
            tenant_id,
            &self_wg_pubkey,
            target_wg_pubkey,
            &origin_nonce,
            &target_nonce,
        );
        let env = P2pClientRequest {
            v: P2P_CTL_VERSION,
            client_proof_hex: client_proof,
            req,
        };
        write_frame(&mut stream, &env)
            .await
            .map_err(|e| format!("send request: {e}"))?;
        let resp: P2pResp = read_frame(&mut stream)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        Ok(resp)
    })
    .await
    .map_err(|_| format!("p2pctl exchange timed out after {}ms", timeout.as_millis()))?
}

/// Dial TCP `peer_ip:P2P_CTL_PORT` either directly (OS-TUN) or via the
/// netstack loopback SOCKS5 proxy when running in netstack mode.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
async fn dial_peer(
    peer_ip: Ipv4Addr,
    socks_port: Option<u16>,
    timeout: Duration,
) -> Result<TcpStream, String> {
    tokio::time::timeout(timeout, async {
        match socks_port {
            None => TcpStream::connect((peer_ip, P2P_CTL_PORT))
                .await
                .map_err(|e| format!("connect {peer_ip}:{P2P_CTL_PORT}: {e}")),
            Some(port) => {
                let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .map_err(|e| format!("connect netstack socks5 127.0.0.1:{port}: {e}"))?;
                stream
                    .write_all(&[0x05, 0x01, 0x00])
                    .await
                    .map_err(|e| format!("socks5 greet: {e}"))?;
                let mut sel = [0u8; 2];
                stream
                    .read_exact(&mut sel)
                    .await
                    .map_err(|e| format!("socks5 select: {e}"))?;
                if sel != [0x05, 0x00] {
                    return Err(format!("socks5 rejected no-auth: {sel:?}"));
                }
                let oct = peer_ip.octets();
                let p = P2P_CTL_PORT.to_be_bytes();
                let req = [
                    0x05, 0x01, 0x00, 0x01, oct[0], oct[1], oct[2], oct[3], p[0], p[1],
                ];
                stream
                    .write_all(&req)
                    .await
                    .map_err(|e| format!("socks5 connect write: {e}"))?;
                let mut hdr = [0u8; 4];
                stream
                    .read_exact(&mut hdr)
                    .await
                    .map_err(|e| format!("socks5 connect reply: {e}"))?;
                if hdr[0] != 0x05 || hdr[1] != 0x00 {
                    return Err(format!("socks5 connect failed (rep={:#x})", hdr[1]));
                }
                let drain_len = match hdr[3] {
                    0x01 => 4 + 2,
                    0x04 => 16 + 2,
                    0x03 => {
                        let n = stream
                            .read_u8()
                            .await
                            .map_err(|e| format!("socks5 bnd len: {e}"))?;
                        n as usize + 2
                    }
                    other => return Err(format!("socks5 unknown bnd atyp {other:#x}")),
                };
                let mut sink = vec![0u8; drain_len];
                stream
                    .read_exact(&mut sink)
                    .await
                    .map_err(|e| format!("socks5 bnd drain: {e}"))?;
                Ok(stream)
            }
        }
    })
    .await
    .map_err(|_| format!("dial {peer_ip}:{P2P_CTL_PORT} timed out"))?
}

/// Query `P2pReq::DeviceInfo` from a peer over `p2pctl`.
///
/// Refuses to dial peers without `supports_p2pctl` or marked `backbone_only`.
/// Caches verified results for [`DEVICE_INFO_CACHE_TTL`].
pub async fn query_device_info(
    tenant_id: &str,
    peer_ip: Ipv4Addr,
    timeout: Duration,
) -> Option<P2pDeviceInfo> {
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (tenant_id, peer_ip, timeout);
        None
    }
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let (self_secret, peer, socks_port) = {
            let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
            let dir = guard.get(tenant_id)?;
            let peer = dir.peers_by_ip.get(&peer_ip)?;
            if !peer.supports_p2pctl || peer.backbone_only {
                return None;
            }
            let cache_key = (peer_ip, peer.wg_public_key.clone());
            if let Some((at, info)) = dir.info_cache.get(&cache_key)
                && at.elapsed() < DEVICE_INFO_CACHE_TTL
            {
                return Some(info.clone());
            }
            (dir.self_wg_secret, peer.clone(), dir.socks_port)
        };
        let keypair = tunnel_core::overlay::WgKeypair::from_secret_bytes(self_secret);
        let stream = match dial_peer(peer_ip, socks_port, timeout).await {
            Ok(s) => s,
            Err(e) => {
                debug!(%peer_ip, err = %e, "p2pctl: device_info dial failed");
                return None;
            }
        };
        match exchange_on_stream(
            stream,
            tenant_id,
            &keypair,
            &peer.wg_public_key,
            &peer.wg_public_bytes,
            P2pReq::DeviceInfo,
            timeout,
        )
        .await
        {
            Ok(P2pResp::DeviceInfo(info)) => {
                let mut guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(dir) = guard.get_mut(tenant_id)
                    && dir
                        .peers_by_ip
                        .get(&peer_ip)
                        .is_some_and(|cur| cur.wg_public_key == peer.wg_public_key)
                {
                    dir.info_cache.insert(
                        (peer_ip, peer.wg_public_key.clone()),
                        (Instant::now(), info.clone()),
                    );
                }
                Some(info)
            }
            Ok(P2pResp::Error { code, message }) => {
                debug!(%peer_ip, %code, %message, "p2pctl: device_info refused by peer");
                None
            }
            Ok(_) => None,
            Err(e) => {
                warn!(%peer_ip, err = %e, "p2pctl: device_info exchange failed");
                None
            }
        }
    }
}

/// Origin-side offline fallback for `LocalAPI::SshSession` (`mh ssh` / `mh scp` / SFTP).
pub async fn ssh_session_offline(
    tenant_id: &str,
    node: &str,
    public_key: &str,
    session_secs: u64,
    two_factor_code: Option<&str>,
) -> Response {
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (tenant_id, node, public_key, session_secs, two_factor_code);
        Response::Error {
            message: "not connected to the server — SSH grants need the control connection (check `mh status`)".into(),
        }
    }
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let request_id = bson::oid::ObjectId::new().to_hex();
        let Some((self_secret, peer, socks_port)) = ({
            let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
            let dir = guard.get(tenant_id);
            dir.and_then(|d| {
                let q = node.trim();
                let ip_q = q.parse::<Ipv4Addr>().ok();
                let peer = d.peers.iter().find(|p| {
                    ip_q == Some(p.overlay_ip)
                        || p.node_id.eq_ignore_ascii_case(q)
                        || p.agent_id
                            .as_deref()
                            .is_some_and(|a| a.eq_ignore_ascii_case(q))
                        || p.name.eq_ignore_ascii_case(q)
                })?;
                Some((d.self_wg_secret, peer.clone(), d.socks_port))
            })
        }) else {
            return Response::Error {
                message: format!(
                    "not connected to the server and peer {node:?} is not in the cached overlay netmap"
                ),
            };
        };
        if !peer.supports_p2pctl || peer.backbone_only {
            return Response::Error {
                message: format!(
                    "not connected to the server and {node:?} does not support offline p2pctl"
                ),
            };
        }
        let Some(target_agent_id) = peer.agent_id.as_deref() else {
            return Response::Error {
                message: format!("peer {node:?} has no agent_id for offline SSH"),
            };
        };
        let Some(offline_cap) = get_offline_cap(tenant_id, target_agent_id, VERB_SSH) else {
            return Response::Error {
                message: format!(
                    "not connected to the server and no cached offline SSH capability is available for {node:?}"
                ),
            };
        };
        let keypair = tunnel_core::overlay::WgKeypair::from_secret_bytes(self_secret);
        let stream = match dial_peer(peer.overlay_ip, socks_port, Duration::from_secs(5)).await {
            Ok(s) => s,
            Err(e) => {
                return Response::Error {
                    message: format!("offline SSH dial to {node} failed: {e}"),
                };
            }
        };
        let req = P2pReq::SshGrant {
            offline_cap,
            request_id: request_id.clone(),
            public_key: public_key.to_string(),
            session_secs,
            two_factor_code: two_factor_code.map(str::to_string),
        };
        match exchange_on_stream(
            stream,
            tenant_id,
            &keypair,
            &peer.wg_public_key,
            &peer.wg_public_bytes,
            req,
            Duration::from_secs(15),
        )
        .await
        {
            Ok(P2pResp::SshGrant {
                address,
                port,
                grant_id,
                host_pubkey,
                expires_at_ms,
                error,
                two_factor,
            }) => Response::SshSession {
                request_id,
                node: node.to_string(),
                address,
                port,
                host_pubkey,
                grant_id,
                expires_at_ms,
                error,
                two_factor,
                resume: false,
            },
            Ok(P2pResp::Error { message, .. }) => Response::Error { message },
            Ok(_) => Response::Error {
                message: "unexpected response from peer on p2pctl".into(),
            },
            Err(e) => Response::Error { message: e },
        }
    }
}

/// Origin-side offline fallback for `LocalAPI::ExecRemote` (`mh exec`).
pub async fn exec_offline(
    tenant_id: &str,
    node: &str,
    shell: &str,
    command: &str,
    timeout_ms: u64,
    two_factor_code: Option<&str>,
) -> Response {
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (tenant_id, node, shell, command, timeout_ms, two_factor_code);
        Response::Error {
            message: "not connected to the server — remote commands need the control connection (check `mh status`)".into(),
        }
    }
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let request_id = bson::oid::ObjectId::new().to_hex();
        let Some((self_secret, peer, socks_port)) = ({
            let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
            let dir = guard.get(tenant_id);
            dir.and_then(|d| {
                let q = node.trim();
                let ip_q = q.parse::<Ipv4Addr>().ok();
                let peer = d.peers.iter().find(|p| {
                    ip_q == Some(p.overlay_ip)
                        || p.node_id.eq_ignore_ascii_case(q)
                        || p.agent_id
                            .as_deref()
                            .is_some_and(|a| a.eq_ignore_ascii_case(q))
                        || p.name.eq_ignore_ascii_case(q)
                })?;
                Some((d.self_wg_secret, peer.clone(), d.socks_port))
            })
        }) else {
            return Response::Error {
                message: format!(
                    "not connected to the server and peer {node:?} is not in the cached overlay netmap"
                ),
            };
        };
        if !peer.supports_p2pctl || peer.backbone_only {
            return Response::Error {
                message: format!(
                    "not connected to the server and {node:?} does not support offline p2pctl"
                ),
            };
        }
        let Some(target_agent_id) = peer.agent_id.as_deref() else {
            return Response::Error {
                message: format!("peer {node:?} has no agent_id for offline exec"),
            };
        };
        let Some(offline_cap) = get_offline_cap(tenant_id, target_agent_id, VERB_EXEC) else {
            return Response::Error {
                message: format!(
                    "not connected to the server and no cached offline exec capability is available for {node:?}"
                ),
            };
        };
        let keypair = tunnel_core::overlay::WgKeypair::from_secret_bytes(self_secret);
        let stream = match dial_peer(peer.overlay_ip, socks_port, Duration::from_secs(5)).await {
            Ok(s) => s,
            Err(e) => {
                return Response::Error {
                    message: format!("offline exec dial to {node} failed: {e}"),
                };
            }
        };
        let budget = exec_limits::clamp_timeout_ms(timeout_ms);
        let exchange_timeout = Duration::from_millis(budget) + Duration::from_secs(30);
        let req = P2pReq::Exec {
            offline_cap,
            request_id: request_id.clone(),
            shell: shell.to_string(),
            command: command.to_string(),
            timeout_ms: budget,
            two_factor_code: two_factor_code.map(str::to_string),
        };
        match exchange_on_stream(
            stream,
            tenant_id,
            &keypair,
            &peer.wg_public_key,
            &peer.wg_public_bytes,
            req,
            exchange_timeout,
        )
        .await
        {
            Ok(P2pResp::Exec {
                exit_code,
                stdout,
                stderr,
                truncated,
                duration_ms,
                error,
            }) => Response::ExecResult {
                request_id,
                node: node.to_string(),
                exit_code,
                stdout,
                stderr,
                truncated,
                duration_ms,
                error,
            },
            Ok(P2pResp::Error { message, .. }) => Response::Error { message },
            Ok(_) => Response::Error {
                message: "unexpected response from peer on p2pctl".into(),
            },
            Err(e) => Response::Error { message: e },
        }
    }
}

#[cfg(all(test, any(feature = "overlay-l3", feature = "overlay-netstack")))]
mod tests {
    use super::*;
    use meshharbor_remote_control::offline_cap::{
        OFFLINE_CAP_AUDIENCE, OFFLINE_CAP_MAX_SKEW_SECS, OfflineCapSigner,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tunnel_core::overlay::WgKeypair;

    fn test_services_and_remote(
        cfg: &AgentConfig,
    ) -> (
        tempfile::TempDir,
        crate::ssh::SessionServices,
        crate::remote_config::RemoteConfigServices,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let broker = crate::consent::ConsentBroker::new(
            crate::consent::Mode::AutoGrant,
            dir.path().join("consent"),
        )
        .unwrap();
        let services = crate::ssh::SessionServices {
            power_activity: None,
            asker: crate::ssh::Asker::Here {
                broker,
                indicator: crate::indicator::ViewerIndicator::disabled(),
            },
            activity: None,
            lifecycle: None,
        };
        let remote_cfg = crate::remote_config::RemoteConfigServices::new(
            cfg_path,
            Arc::new(tokio::sync::Mutex::new(())),
            cfg.exec_allowed(),
            cfg.remote_config_allowed(),
        );
        (dir, services, remote_cfg)
    }

    fn make_peer_entry(kp: &WgKeypair, ip: Ipv4Addr, supports_p2pctl: bool) -> PeerEntry {
        PeerEntry {
            node_id: bson::oid::ObjectId::new().to_hex(),
            agent_id: Some("660000000000000000000004".into()),
            name: "peer-a".into(),
            overlay_ip: ip,
            wg_public_key: kp.public_base64(),
            wg_public_bytes: kp.public.to_bytes(),
            supports_p2pctl,
            backbone_only: false,
            reachable: true,
        }
    }

    fn test_net(
        net_id: bson::oid::ObjectId,
        keys: Vec<String>,
        not_before_ms: Option<u64>,
    ) -> OverlayNetworkInfo {
        OverlayNetworkInfo {
            cidr: "100.64.0.0/10".into(),
            cidrs: vec!["100.64.0.0/10".into()],
            org_relay_fallback_v1: false,
            org_relay_loss_v1: false,
            path_quality_v1: false,
            mtu: 1280,
            magic_domain: None,
            nameservers: vec![],
            self_name: None,
            self_node_id: None,
            self_name_revision: None,
            stun_urls: vec![],
            strict_stun: false,
            central_relay_denied: false,
            relay_probe_targets: vec![],
            backbone_probe_targets: vec![],
            auth_revision: 1,
            network_id: Some(net_id),
            offline_cap_keys: keys,
            offline_caps_not_before_ms: not_before_ms,
            offline_max_age_s: Some(14 * 86_400),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mint_cap(
        signer: &OfflineCapSigner,
        verb: &str,
        tid: &str,
        net_id: bson::oid::ObjectId,
        tgt: &str,
        opk: &str,
        iat: u64,
        exp: u64,
        exec_shells: Option<Vec<String>>,
    ) -> String {
        signer
            .mint(&OfflineCapClaims {
                aud: OFFLINE_CAP_AUDIENCE.into(),
                verb: verb.into(),
                net: net_id.to_hex(),
                tid: tid.into(),
                tgt: tgt.into(),
                org: "660000000000000000000004".into(),
                opk: opk.into(),
                caller: "alice (via peer-a)".into(),
                jti: bson::oid::ObjectId::new().to_hex(),
                iat,
                exp,
                ssh_account_mode: (verb == VERB_SSH).then(|| "daemon".into()),
                ssh_account: None,
                ssh_max_session_secs: (verb == VERB_SSH).then_some(3600),
                exec_shells,
                exec_run_as: (verb == VERB_EXEC).then(|| "system".into()),
                exec_max_timeout_ms: (verb == VERB_EXEC).then_some(30_000),
                consent_mode: Some("auto".into()),
            })
            .unwrap()
    }

    #[tokio::test]
    async fn fr139_p2pctl_mutual_hello_and_device_info_roundtrip() {
        let origin_kp = WgKeypair::generate();
        let target_kp = WgKeypair::generate();
        let origin_ip = Ipv4Addr::new(100, 64, 0, 10);

        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-p2p".into();
        cfg.agent_id = "agent-target".into();
        cfg.ssh_enabled = true;
        cfg.exec_enabled = true;
        cfg.protected = false;
        let (_tmp, services, remote_cfg) = test_services_and_remote(&cfg);

        let mut peers = HashMap::new();
        peers.insert(origin_ip, make_peer_entry(&origin_kp, origin_ip, true));
        let mut ctx = ServerCtx::new(&cfg, target_kp.clone(), services, remote_cfg);
        ctx.peer_override = Some(Arc::new(Mutex::new(peers)));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let srv = tokio::spawn(serve_conn(server_io, origin_ip, ctx));
        let resp = exchange_on_stream(
            client_io,
            "tenant-p2p",
            &origin_kp,
            &target_kp.public_base64(),
            &target_kp.public.to_bytes(),
            P2pReq::DeviceInfo,
            Duration::from_secs(2),
        )
        .await
        .expect("mutual hello + device_info must succeed");
        srv.await.unwrap().expect("server clean finish");

        match resp {
            P2pResp::DeviceInfo(info) => {
                assert!(info.supports_p2pctl);
                assert!(info.ssh_enabled);
                assert!(info.exec_enabled);
                assert_eq!(info.os, std::env::consts::OS);
                assert!(info.rdp_available.is_some());
            }
            other => panic!("expected DeviceInfo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fr139_p2pctl_rejects_unprivileged_squatter_before_sending_request() {
        let origin_kp = WgKeypair::generate();
        let real_target_kp = WgKeypair::generate();
        let squatter_kp = WgKeypair::generate();

        let (client_io, mut squatter_io) = tokio::io::duplex(16 * 1024);
        let saw_request_frame = Arc::new(AtomicBool::new(false));
        let saw_clone = Arc::clone(&saw_request_frame);

        let squatter = tokio::spawn(async move {
            let init: P2pHelloInit = read_frame(&mut squatter_io).await.unwrap();
            let fake_nonce = [0x99u8; 32];
            let wrong_shared = squatter_kp.dh(&origin_kp.public.to_bytes());
            let wrong_key = derive_hello_mac_key(&wrong_shared);
            let origin_nonce = decode_hex(&init.origin_nonce_hex).unwrap();
            let forged_proof = compute_hello_proof(
                &wrong_key,
                b"server",
                &init.tenant_id,
                &init.origin_node_id,
                &init.target_node_id,
                &origin_nonce,
                &fake_nonce,
            );
            write_frame(
                &mut squatter_io,
                &P2pHelloResp {
                    v: P2P_CTL_VERSION,
                    target_nonce_hex: encode_hex(&fake_nonce),
                    server_proof_hex: forged_proof,
                    error: None,
                },
            )
            .await
            .unwrap();
            if read_frame::<_, P2pClientRequest>(&mut squatter_io)
                .await
                .is_ok()
            {
                saw_clone.store(true, Ordering::SeqCst);
            }
        });

        let err = exchange_on_stream(
            client_io,
            "tenant-p2p",
            &origin_kp,
            &real_target_kp.public_base64(),
            &real_target_kp.public.to_bytes(),
            P2pReq::Exec {
                offline_cap: "secret-cap-token".into(),
                request_id: "r1".into(),
                shell: "sh".into(),
                command: "id".into(),
                timeout_ms: 5000,
                two_factor_code: Some("123456".into()),
            },
            Duration::from_secs(2),
        )
        .await
        .expect_err("forged server proof must be rejected");
        assert!(
            err.contains("server hello proof failed"),
            "unexpected error: {err}"
        );
        squatter.await.unwrap();
        assert!(
            !saw_request_frame.load(Ordering::SeqCst),
            "origin must NEVER transmit request payload or capability token to an unverified squatter"
        );
    }

    #[tokio::test]
    async fn fr139_p2pctl_refuses_fr127_protected_device() {
        let origin_kp = WgKeypair::generate();
        let target_kp = WgKeypair::generate();
        let origin_ip = Ipv4Addr::new(100, 64, 0, 11);

        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-prot".into();
        cfg.agent_id = "agent-prot".into();
        cfg.protected = true;
        let (_tmp, services, remote_cfg) = test_services_and_remote(&cfg);

        let mut peers = HashMap::new();
        peers.insert(origin_ip, make_peer_entry(&origin_kp, origin_ip, true));
        let mut ctx = ServerCtx::new(&cfg, target_kp.clone(), services, remote_cfg);
        ctx.peer_override = Some(Arc::new(Mutex::new(peers)));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let srv = tokio::spawn(serve_conn(server_io, origin_ip, ctx));
        let resp = exchange_on_stream(
            client_io,
            "tenant-prot",
            &origin_kp,
            &target_kp.public_base64(),
            &target_kp.public.to_bytes(),
            P2pReq::DeviceInfo,
            Duration::from_secs(2),
        )
        .await
        .expect("handshake succeeds then returns protected refusal");
        srv.await.unwrap().expect("server clean finish");

        match resp {
            P2pResp::Error { code, .. } => assert_eq!(code, "protected"),
            other => panic!("expected protected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fr139_p2pctl_skips_legacy_peer_without_supports_p2pctl() {
        let origin_kp = WgKeypair::generate();
        let legacy_kp = WgKeypair::generate();
        let legacy_ip = Ipv4Addr::new(100, 64, 0, 99);
        let tid = format!("tenant-legacy-{}", bson::oid::ObjectId::new().to_hex());

        let net = test_net(bson::oid::ObjectId::new(), Vec::new(), None);
        let legacy_peer = NetmapPeer {
            node_id: bson::oid::ObjectId::new(),
            overlay_ip: legacy_ip.to_string(),
            name: "legacy".into(),
            wg_public_key: legacy_kp.public_base64(),
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            caps: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            supports_org_relay: false,
            supports_overlay_echo: false,
            supports_p2pctl: false,
            relay_strategy: None,
            prefer_relay_ms: None,
            routes: vec![],
            agent_id: Some(bson::oid::ObjectId::new()),
            ingress_rules: None,
            ingress_rules_preview: None,
            backbone_only: false,
        };
        update_tenant_directory(
            &tid,
            "self-a",
            &origin_kp,
            "100.64.0.1",
            &net,
            &[legacy_peer],
            None,
        );
        let started = Instant::now();
        let info = query_device_info(&tid, legacy_ip, Duration::from_secs(5)).await;
        assert!(info.is_none());
        assert!(started.elapsed() < Duration::from_millis(200));

        // Origin offline SSH and exec also refuse legacy peers cleanly.
        let ssh_resp = ssh_session_offline(&tid, "legacy", "ssh-ed25519 AAAA", 60, None).await;
        assert!(
            matches!(ssh_resp, Response::Error { ref message } if message.contains("does not support offline p2pctl"))
        );
        let exec_resp = exec_offline(&tid, "legacy", "sh", "id", 5000, None).await;
        assert!(
            matches!(exec_resp, Response::Error { ref message } if message.contains("does not support offline p2pctl"))
        );
        clear_tenant_directory(&tid);
    }

    #[cfg(feature = "ssh-server")]
    #[tokio::test]
    async fn fr139_p2pctl_offline_ssh_grant_positive_and_negative_matrix() {
        let origin_kp = WgKeypair::generate();
        let target_kp = WgKeypair::generate();
        let origin_ip = Ipv4Addr::new(100, 64, 0, 21);
        let net_id = bson::oid::ObjectId::new();
        let tid = "6600000000000000000000a1";
        let tgt = "6600000000000000000000b1";
        let now = now_unix_secs();
        let signer = OfflineCapSigner::from_jwt_secrets("jwt-secret-ssh", &[]);

        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = tid.into();
        cfg.agent_id = tgt.into();
        cfg.ssh_enabled = true;
        cfg.protected = false;
        let (_tmp, services, remote_cfg) = test_services_and_remote(&cfg);

        let mut peers = HashMap::new();
        peers.insert(origin_ip, make_peer_entry(&origin_kp, origin_ip, true));
        let mut base_ctx = ServerCtx::new(&cfg, target_kp.clone(), services, remote_cfg);
        base_ctx.peer_override = Some(Arc::new(Mutex::new(peers)));
        base_ctx.net_override = Some((
            "100.64.0.22".into(),
            test_net(net_id, signer.public_keys_b64().to_vec(), None),
        ));
        base_ctx.now_secs_override = Some(now);

        // Generate a real Ed25519 OpenSSH public key for admission.
        let kp_priv = russh::keys::ssh_key::private::PrivateKey::from(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[0x33u8; 32]),
        );
        let ssh_pubkey = kp_priv.public_key().to_openssh().unwrap();

        // 1. Positive offline SSH grant succeeds and records grant!
        let valid_cap = mint_cap(
            &signer,
            VERB_SSH,
            tid,
            net_id,
            tgt,
            &origin_kp.public_base64(),
            now - 60,
            now + 3600,
            None,
        );
        let (c_io, s_io) = tokio::io::duplex(16 * 1024);
        let srv = tokio::spawn(serve_conn(s_io, origin_ip, base_ctx.clone()));
        let resp = exchange_on_stream(
            c_io,
            tid,
            &origin_kp,
            &target_kp.public_base64(),
            &target_kp.public.to_bytes(),
            P2pReq::SshGrant {
                offline_cap: valid_cap.clone(),
                request_id: "req-ssh-ok".into(),
                public_key: ssh_pubkey.clone(),
                session_secs: 600,
                two_factor_code: None,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        srv.await.unwrap().unwrap();
        match resp {
            P2pResp::SshGrant {
                address,
                port,
                grant_id,
                error,
                ..
            } => {
                assert!(error.is_none(), "unexpected error: {error:?}");
                assert_eq!(address.as_deref(), Some("100.64.0.22"));
                assert_eq!(port, Some(cfg.effective_ssh_port()));
                assert!(grant_id.is_some());
            }
            other => panic!("expected SshGrant, got {other:?}"),
        }

        // Helper to test negative caps against SshGrant.
        let run_neg = |cap: String, ctx: ServerCtx| {
            let origin_kp = origin_kp.clone();
            let target_kp = target_kp.clone();
            let ssh_pubkey = ssh_pubkey.clone();
            async move {
                let (c_io, s_io) = tokio::io::duplex(16 * 1024);
                let srv = tokio::spawn(serve_conn(s_io, origin_ip, ctx));
                let resp = exchange_on_stream(
                    c_io,
                    tid,
                    &origin_kp,
                    &target_kp.public_base64(),
                    &target_kp.public.to_bytes(),
                    P2pReq::SshGrant {
                        offline_cap: cap,
                        request_id: "req-ssh-neg".into(),
                        public_key: ssh_pubkey,
                        session_secs: 600,
                        two_factor_code: None,
                    },
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
                srv.await.unwrap().unwrap();
                match resp {
                    P2pResp::SshGrant {
                        error, grant_id, ..
                    } => {
                        assert!(grant_id.is_none());
                        error.expect("negative cap must return error")
                    }
                    other => panic!("expected SshGrant error, got {other:?}"),
                }
            }
        };

        // 2. Cross-verb (exec cap used for ssh) -> refused.
        let exec_cap = mint_cap(
            &signer,
            VERB_EXEC,
            tid,
            net_id,
            tgt,
            &origin_kp.public_base64(),
            now - 60,
            now + 3600,
            None,
        );
        assert!(
            run_neg(exec_cap, base_ctx.clone())
                .await
                .contains("verb mismatch")
        );

        // 3. Cross-net -> refused.
        let other_net_cap = mint_cap(
            &signer,
            VERB_SSH,
            tid,
            bson::oid::ObjectId::new(),
            tgt,
            &origin_kp.public_base64(),
            now - 60,
            now + 3600,
            None,
        );
        assert!(
            run_neg(other_net_cap, base_ctx.clone())
                .await
                .contains("network mismatch")
        );

        // 4. Cross-target -> refused.
        let other_tgt_cap = mint_cap(
            &signer,
            VERB_SSH,
            tid,
            net_id,
            "6600000000000000000000ff",
            &origin_kp.public_base64(),
            now - 60,
            now + 3600,
            None,
        );
        assert!(
            run_neg(other_tgt_cap, base_ctx.clone())
                .await
                .contains("target device mismatch")
        );

        // 5. Wrong opk -> refused.
        let wrong_opk_cap = mint_cap(
            &signer,
            VERB_SSH,
            tid,
            net_id,
            tgt,
            &WgKeypair::generate().public_base64(),
            now - 60,
            now + 3600,
            None,
        );
        assert!(
            run_neg(wrong_opk_cap, base_ctx.clone())
                .await
                .contains("origin WireGuard key mismatch")
        );

        // 6. Expired -> refused.
        let expired_cap = mint_cap(
            &signer,
            VERB_SSH,
            tid,
            net_id,
            tgt,
            &origin_kp.public_base64(),
            now - 7200,
            now - 10,
            None,
        );
        assert!(
            run_neg(expired_cap, base_ctx.clone())
                .await
                .contains("expired")
        );

        // 7. Clock skew (future iat) -> refused.
        let skewed_cap = mint_cap(
            &signer,
            VERB_SSH,
            tid,
            net_id,
            tgt,
            &origin_kp.public_base64(),
            now + OFFLINE_CAP_MAX_SKEW_SECS + 60,
            now + 7200,
            None,
        );
        assert!(
            run_neg(skewed_cap, base_ctx.clone())
                .await
                .contains("clock skew")
        );

        // 8. Pre-not_before_ms revocation -> refused.
        let mut revoked_ctx = base_ctx.clone();
        revoked_ctx.net_override = Some((
            "100.64.0.22".into(),
            test_net(
                net_id,
                signer.public_keys_b64().to_vec(),
                Some((now - 10) * 1000),
            ),
        ));
        assert!(run_neg(valid_cap, revoked_ctx).await.contains("not_before"));
    }

    #[tokio::test]
    async fn fr139_p2pctl_offline_exec_positive_shell_ceiling_atomic_replay_and_audit_drain() {
        let origin_kp = WgKeypair::generate();
        let target_kp = WgKeypair::generate();
        let origin_ip = Ipv4Addr::new(100, 64, 0, 31);
        let net_id = bson::oid::ObjectId::new();
        let tid = "6600000000000000000000c1";
        let tgt = "6600000000000000000000d1";
        let now = now_unix_secs();
        let signer = OfflineCapSigner::from_jwt_secrets("jwt-secret-exec", &[]);

        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = tid.into();
        cfg.agent_id = tgt.into();
        cfg.exec_enabled = true;
        cfg.protected = false;
        let (_tmp, services, remote_cfg) = test_services_and_remote(&cfg);
        let cfg_path = remote_cfg.config_path().to_path_buf();

        let mut peers = HashMap::new();
        peers.insert(origin_ip, make_peer_entry(&origin_kp, origin_ip, true));
        let mut ctx = ServerCtx::new(&cfg, target_kp.clone(), services, remote_cfg);
        ctx.peer_override = Some(Arc::new(Mutex::new(peers)));
        ctx.net_override = Some((
            "100.64.0.32".into(),
            test_net(net_id, signer.public_keys_b64().to_vec(), None),
        ));
        ctx.now_secs_override = Some(now);

        let cap = mint_cap(
            &signer,
            VERB_EXEC,
            tid,
            net_id,
            tgt,
            &origin_kp.public_base64(),
            now - 60,
            now + 3600,
            Some(vec!["sh".into()]),
        );

        // 1. Disallowed shell ceiling ("bash" not in ["sh"]) -> refused!
        {
            let (c_io, s_io) = tokio::io::duplex(16 * 1024);
            let srv = tokio::spawn(serve_conn(s_io, origin_ip, ctx.clone()));
            let resp = exchange_on_stream(
                c_io,
                tid,
                &origin_kp,
                &target_kp.public_base64(),
                &target_kp.public.to_bytes(),
                P2pReq::Exec {
                    offline_cap: cap.clone(),
                    request_id: "req-exec-shell-deny".into(),
                    shell: "bash".into(),
                    command: "echo nope".into(),
                    timeout_ms: 5000,
                    two_factor_code: None,
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            srv.await.unwrap().unwrap();
            match resp {
                P2pResp::Exec { error, .. } => {
                    assert!(error.unwrap().contains("not permitted"));
                }
                other => panic!("expected Exec error, got {other:?}"),
            }
        }

        // 2. Positive offline exec runs real command and returns stdout!
        {
            let (c_io, s_io) = tokio::io::duplex(16 * 1024);
            let srv = tokio::spawn(serve_conn(s_io, origin_ip, ctx.clone()));
            let resp = exchange_on_stream(
                c_io,
                tid,
                &origin_kp,
                &target_kp.public_base64(),
                &target_kp.public.to_bytes(),
                P2pReq::Exec {
                    offline_cap: cap.clone(),
                    request_id: "req-exec-once-1".into(),
                    shell: "sh".into(),
                    command: "echo offline-ok".into(),
                    timeout_ms: 5000,
                    two_factor_code: None,
                },
                Duration::from_secs(10),
            )
            .await
            .unwrap();
            srv.await.unwrap().unwrap();
            match resp {
                P2pResp::Exec {
                    exit_code,
                    stdout,
                    error,
                    ..
                } => {
                    assert!(error.is_none(), "unexpected error: {error:?}");
                    assert_eq!(exit_code, Some(0));
                    assert_eq!(stdout.trim(), "offline-ok");
                }
                other => panic!("expected Exec result, got {other:?}"),
            }
        }

        // 3. Replay / crash-retry of the exact same request_id (even after clearing
        //    in-memory replay map to simulate daemon crash+restart!) MUST be refused!
        replay_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        {
            let (c_io, s_io) = tokio::io::duplex(16 * 1024);
            let srv = tokio::spawn(serve_conn(s_io, origin_ip, ctx.clone()));
            let resp = exchange_on_stream(
                c_io,
                tid,
                &origin_kp,
                &target_kp.public_base64(),
                &target_kp.public.to_bytes(),
                P2pReq::Exec {
                    offline_cap: cap.clone(),
                    request_id: "req-exec-once-1".into(),
                    shell: "sh".into(),
                    command: "echo should-not-run-twice".into(),
                    timeout_ms: 5000,
                    two_factor_code: None,
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            srv.await.unwrap().unwrap();
            match resp {
                P2pResp::Exec {
                    exit_code,
                    stdout,
                    error,
                    ..
                } => {
                    assert!(exit_code.is_none());
                    assert!(stdout.is_empty());
                    assert!(
                        error.unwrap().contains("duplicate or replayed"),
                        "crash-retry must be deduplicated from disk"
                    );
                }
                other => panic!("expected deduplicated Exec error, got {other:?}"),
            }
        }

        // 4. Online target control-WS MUST refuse offline_cap exec so server-side
        // revocations cannot be bypassed while the target is online.
        {
            let online_ctx = ctx
                .clone()
                .with_control_ws_attached(Arc::new(std::sync::atomic::AtomicBool::new(true)));
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let srv = tokio::spawn(serve_conn(server_io, origin_ip, online_ctx));
            let resp = exchange_on_stream(
                client_io,
                tid,
                &origin_kp,
                &target_kp.public_base64(),
                &target_kp.public.to_bytes(),
                P2pReq::Exec {
                    offline_cap: cap.clone(),
                    request_id: "req-online-block".into(),
                    shell: "sh".into(),
                    command: "echo should_not_run".into(),
                    timeout_ms: 5_000,
                    two_factor_code: None,
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            srv.await.unwrap().unwrap();
            match resp {
                P2pResp::Exec { error, .. } => {
                    assert!(
                        error.unwrap_or_default().contains("control-WS is online"),
                        "online target must refuse offline_cap"
                    );
                }
                other => panic!("expected online-refused Exec error, got {other:?}"),
            }
        }

        // 5. Offline audit journal recorded all 4 entries (1 shell refusal,
        // 1 pre-exec launch record, 1 completion record, 1 replay refusal) and
        // drains cleanly on reconnect.
        let drained = drain_offline_audit_on_reconnect(&cfg_path, tid);
        assert_eq!(drained, 4);
        assert_eq!(drain_offline_audit_on_reconnect(&cfg_path, tid), 0);
    }
}
