// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Remote Desktop restart continuity (`rc-continuity.json`).
//!
//! When `meshharbord` shuts down cleanly (e.g. self-update or service restart),
//! live non-external, non-shared remote control sessions are written to a short-lived
//! (120 s TTL) HMAC-sealed file `<state_dir>/rc-continuity.json` using the device's
//! local `MasterKey` (`ssh-resume.key`, HKDF label `fr141/rc-continuity/v1`).
//!
//! On the next daemon boot:
//! 1. `load_and_consume_on_boot()` reads the file, immediately unlinks it on disk,
//!    verifies the constant-time HMAC seal, and loads unexpired entries into memory.
//! 2. When a reconnecting viewer presents a server-validated `continues: Some(prev_sid)`
//!    on `ServerMsg::Request`, `take_matching(...)` checks:
//!    - `prev_sid` exists, is unexpired (`<= 120 s`), and is consumed single-use;
//!    - `org_id` and `controller_user_id` match identically;
//!    - requested permissions and audio do NOT escalate beyond what the prior
//!      session was actually granted.
//! 3. A match bypasses re-prompting for on-host consent / 2FA while keeping the
//!    "Being viewed by …" host banner and audit trail intact.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use bson::oid::ObjectId;
use meshharbor_node_core::pty_resume::now_unix_ms;
use meshharbor_node_core::pty_resume::proof::{
    MasterKey, seal_rc_continuity, verify_rc_continuity,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Validity window for remote-desktop restart continuity records (120 seconds).
pub const CONTINUITY_TTL_MS: u64 = 120_000;

const CONTINUITY_FILENAME: &str = "rc-continuity.json";
const MASTER_KEY_FILENAME: &str = "ssh-resume.key";

#[derive(Debug, Clone)]
struct ActiveRcSession {
    session_id: ObjectId,
    org_id: String,
    controller_user_id: ObjectId,
    permissions_bits: u16,
    audio_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RcContinuityRecord {
    pub prev_session_id: String,
    pub org_id: String,
    pub controller_user_id: String,
    pub permissions_bits: u16,
    pub audio_enabled: bool,
    pub expires_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SealedContinuityFile {
    version: u8,
    payload_b64: String,
    seal_hex: String,
}

#[derive(Default)]
struct ContinuityStore {
    active: HashMap<ObjectId, ActiveRcSession>,
    pending: HashMap<ObjectId, RcContinuityRecord>,
}

static STORE: OnceLock<Mutex<ContinuityStore>> = OnceLock::new();

fn store() -> &'static Mutex<ContinuityStore> {
    STORE.get_or_init(|| Mutex::new(ContinuityStore::default()))
}

/// Resolve the runtime state directory shared with `ssh_persist`.
pub fn state_dir() -> PathBuf {
    #[cfg(feature = "ssh-server")]
    {
        crate::ssh_persist::state_dir()
    }
    #[cfg(not(feature = "ssh-server"))]
    {
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
}

/// Record a live, non-external, non-shared remote control session so a graceful
/// daemon restart can preserve its consent/2FA continuity for 120 seconds.
pub fn register_active(
    session_id: ObjectId,
    org_id: String,
    controller_user_id: ObjectId,
    permissions_bits: u16,
    audio_enabled: bool,
) {
    let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
    g.active.insert(
        session_id,
        ActiveRcSession {
            session_id,
            org_id,
            controller_user_id,
            permissions_bits,
            audio_enabled,
        },
    );
}

/// Remove a session when it ends cleanly (controller hangup, host disconnect,
/// admin terminate, etc.) so it is never carried across a later restart.
pub fn unregister_active(session_id: ObjectId) {
    let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
    g.active.remove(&session_id);
}

/// Persist sealed continuity records for all currently live sessions in `live_ids`
/// right before graceful daemon shutdown.
pub fn save_active_for_restart(live_ids: &[ObjectId]) -> Result<usize, String> {
    let now = now_unix_ms();
    let expires_at_ms = now.saturating_add(CONTINUITY_TTL_MS);
    let records: Vec<RcContinuityRecord> = {
        let g = store().lock().unwrap_or_else(|e| e.into_inner());
        live_ids
            .iter()
            .filter_map(|sid| g.active.get(sid))
            .map(|a| RcContinuityRecord {
                prev_session_id: a.session_id.to_hex(),
                org_id: a.org_id.clone(),
                controller_user_id: a.controller_user_id.to_hex(),
                permissions_bits: a.permissions_bits,
                audio_enabled: a.audio_enabled,
                expires_at_ms,
            })
            .collect()
    };
    let dir = state_dir();
    save_records_to_dir(&dir, &records)
}

pub fn save_records_to_dir(dir: &Path, records: &[RcContinuityRecord]) -> Result<usize, String> {
    let path = dir.join(CONTINUITY_FILENAME);
    if records.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(0);
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("create rc-continuity dir {}: {e}", dir.display()))?;
    let key_path = dir.join(MASTER_KEY_FILENAME);
    let master = MasterKey::load_or_create(&key_path)
        .map_err(|e| format!("load/create {}: {e}", key_path.display()))?;
    let payload_json =
        serde_json::to_vec(records).map_err(|e| format!("serialize rc-continuity: {e}"))?;
    let seal = seal_rc_continuity(&master, &payload_json);
    let envelope = SealedContinuityFile {
        version: 1,
        payload_b64: base64::engine::general_purpose::STANDARD.encode(&payload_json),
        seal_hex: hex::encode(seal),
    };
    let encoded =
        serde_json::to_vec(&envelope).map_err(|e| format!("encode rc-continuity envelope: {e}"))?;
    let tmp = dir.join("rc-continuity.json.tmp");
    write_restricted(&tmp, &encoded)
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    info!(
        count = records.len(),
        ttl_secs = CONTINUITY_TTL_MS / 1000,
        "fr141: saved sealed rc-continuity records for restart"
    );
    Ok(records.len())
}

/// Load and immediately delete `<state_dir>/rc-continuity.json` during daemon boot.
pub fn load_and_consume_on_boot() -> usize {
    let dir = state_dir();
    load_and_consume_from_dir(&dir)
}

pub fn load_and_consume_from_dir(dir: &Path) -> usize {
    let path = dir.join(CONTINUITY_FILENAME);
    let raw = match std::fs::read(&path) {
        Ok(b) => {
            // Single-use on disk: delete immediately before validation so a crash
            // or tampered file cannot replay indefinitely.
            let _ = std::fs::remove_file(&path);
            b
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            warn!(path = %path.display(), %e, "fr141: failed to read rc-continuity file");
            let _ = std::fs::remove_file(&path);
            return 0;
        }
    };

    let envelope = match serde_json::from_slice::<SealedContinuityFile>(&raw) {
        Ok(v) if v.version == 1 => v,
        Ok(v) => {
            warn!(version = v.version, "fr141: unsupported rc-continuity file version");
            return 0;
        }
        Err(e) => {
            warn!(%e, "fr141: malformed rc-continuity envelope");
            return 0;
        }
    };

    let key_path = dir.join(MASTER_KEY_FILENAME);
    let master = match MasterKey::load_or_create(&key_path) {
        Ok(m) => m,
        Err(e) => {
            warn!(%e, "fr141: failed to load master key for rc-continuity verification");
            return 0;
        }
    };

    let payload_json = match base64::engine::general_purpose::STANDARD.decode(&envelope.payload_b64)
    {
        Ok(b) => b,
        Err(e) => {
            warn!(%e, "fr141: invalid rc-continuity payload base64");
            return 0;
        }
    };
    let seal_bytes = match hex::decode(&envelope.seal_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            warn!("fr141: invalid rc-continuity seal length");
            return 0;
        }
    };
    if !verify_rc_continuity(&master, &payload_json, &seal_bytes) {
        warn!("fr141: rc-continuity HMAC verification failed — discarding records");
        return 0;
    }

    let records: Vec<RcContinuityRecord> = match serde_json::from_slice(&payload_json) {
        Ok(v) => v,
        Err(e) => {
            warn!(%e, "fr141: malformed rc-continuity record payload");
            return 0;
        }
    };

    let now = now_unix_ms();
    let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
    let mut loaded = 0usize;
    for rec in records {
        if rec.expires_at_ms <= now {
            continue;
        }
        if let Ok(sid) = ObjectId::parse_str(&rec.prev_session_id) {
            g.pending.insert(sid, rec);
            loaded += 1;
        }
    }
    if loaded > 0 {
        info!(count = loaded, "fr141: loaded sealed rc-continuity records on boot");
    }
    loaded
}

/// Consume a matching, unexpired continuity record (single-use) if:
/// - `prev_sid` exists and is unexpired;
/// - `org_id` and `controller_user_id` match exactly;
/// - `requested_permissions_bits` is a subset of the prior session's granted bits
///   (no permission escalation);
/// - `requested_audio` does not escalate from `false` to `true`.
pub fn take_matching(
    prev_sid: ObjectId,
    org_id: &str,
    controller_user_id: ObjectId,
    requested_permissions_bits: u16,
    requested_audio: bool,
) -> bool {
    let now = now_unix_ms();
    let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
    g.pending.retain(|_, rec| rec.expires_at_ms > now);
    let Some(rec) = g.pending.get(&prev_sid) else {
        return false;
    };
    let user_hex = controller_user_id.to_hex();
    let no_perm_escalation =
        (requested_permissions_bits & rec.permissions_bits) == requested_permissions_bits;
    let no_audio_escalation = !requested_audio || rec.audio_enabled;
    if rec.org_id == org_id
        && rec.controller_user_id == user_hex
        && no_perm_escalation
        && no_audio_escalation
    {
        g.pending.remove(&prev_sid);
        debug!(%prev_sid, %controller_user_id, "fr141: rc-continuity record matched and consumed");
        true
    } else {
        warn!(
            %prev_sid,
            %controller_user_id,
            org_match = (rec.org_id == org_id),
            user_match = (rec.controller_user_id == user_hex),
            no_perm_escalation,
            no_audio_escalation,
            "fr141: rc-continuity record rejected due to scope/permission mismatch"
        );
        false
    }
}

fn write_restricted(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_rc_continuity_round_trip_single_use_and_no_escalation() {
        let dir = tempfile::tempdir().unwrap();
        let sid = ObjectId::new();
        let user = ObjectId::new();
        let other_user = ObjectId::new();
        let now = now_unix_ms();

        let rec = RcContinuityRecord {
            prev_session_id: sid.to_hex(),
            org_id: "org-alpha".into(),
            controller_user_id: user.to_hex(),
            permissions_bits: 0b0011, // e.g. VIEW | INPUT
            audio_enabled: false,
            expires_at_ms: now + 60_000,
        };
        assert_eq!(save_records_to_dir(dir.path(), &[rec]).unwrap(), 1);
        assert!(dir.path().join(CONTINUITY_FILENAME).exists());

        // Boot load consumes and unlinks the on-disk file.
        assert_eq!(load_and_consume_from_dir(dir.path()), 1);
        assert!(!dir.path().join(CONTINUITY_FILENAME).exists());

        // Wrong org / wrong user / permission escalation / audio escalation all fail without consuming.
        assert!(!take_matching(sid, "org-beta", user, 0b0011, false));
        assert!(!take_matching(sid, "org-alpha", other_user, 0b0011, false));
        assert!(!take_matching(sid, "org-alpha", user, 0b0111, false));
        assert!(!take_matching(sid, "org-alpha", user, 0b0011, true));

        // Subset permissions (0b0001 <= 0b0011) succeeds once and is consumed.
        assert!(take_matching(sid, "org-alpha", user, 0b0001, false));
        // Second use is rejected (single-use).
        assert!(!take_matching(sid, "org-alpha", user, 0b0001, false));
    }

    #[test]
    fn fr141_rc_continuity_rejects_tampered_seal_and_expired_records() {
        let dir = tempfile::tempdir().unwrap();
        let sid_expired = ObjectId::new();
        let sid_tampered = ObjectId::new();
        let user = ObjectId::new();
        let now = now_unix_ms();

        // Expired record is discarded on boot load.
        let expired = RcContinuityRecord {
            prev_session_id: sid_expired.to_hex(),
            org_id: "org-alpha".into(),
            controller_user_id: user.to_hex(),
            permissions_bits: 0b0001,
            audio_enabled: false,
            expires_at_ms: now.saturating_sub(1_000),
        };
        assert_eq!(save_records_to_dir(dir.path(), &[expired]).unwrap(), 1);
        assert_eq!(load_and_consume_from_dir(dir.path()), 0);
        assert!(!take_matching(sid_expired, "org-alpha", user, 0b0001, false));

        // Tampered seal is rejected and file deleted.
        let valid = RcContinuityRecord {
            prev_session_id: sid_tampered.to_hex(),
            org_id: "org-alpha".into(),
            controller_user_id: user.to_hex(),
            permissions_bits: 0b0001,
            audio_enabled: false,
            expires_at_ms: now + 60_000,
        };
        assert_eq!(save_records_to_dir(dir.path(), &[valid]).unwrap(), 1);
        let path = dir.path().join(CONTINUITY_FILENAME);
        let mut env: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        env["seal_hex"] = serde_json::Value::String("00".repeat(32));
        std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();

        assert_eq!(load_and_consume_from_dir(dir.path()), 0);
        assert!(!path.exists());
        assert!(!take_matching(sid_tampered, "org-alpha", user, 0b0001, false));
    }
}
