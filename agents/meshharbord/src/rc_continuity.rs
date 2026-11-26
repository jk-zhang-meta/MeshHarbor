// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Remote Desktop restart continuity (`rc-continuity.json`).
//!
//! When `meshharbord` shuts down cleanly (e.g. self-update or service restart),
//! live non-external, non-shared remote control sessions across ALL org loops
//! are merged and written to a short-lived (120 s TTL) HMAC-sealed file
//! `<state_dir>/rc-continuity.json` using the device's local `MasterKey`
//! (`ssh-resume.key`, HKDF label `fr141/rc-continuity/v1`).
//!
//! Security invariants enforced on boot & resume:
//! 1. **Atomic single-use claim on disk**: `load_and_consume_on_boot()` atomically
//!    renames `rc-continuity.json` to a unique claimed path BEFORE reading it and
//!    unlinks the claimed copy. If the rename fails (e.g. read-only FS), continuity
//!    is refused fail-closed so two generations can never consume the same file.
//! 2. **2FA assurance binding**: records seal the exact 2FA enrollment fingerprint
//!    verified for the original session (`None` if 2FA was off). Enabling or
//!    re-enrolling 2FA before restart invalidates 2FA bypass and requires a fresh code.
//! 3. **Consent authority binding**: records seal whether the original session was
//!    approved via owner-side consent (`Email`/`Push`). Changing policy from
//!    `Auto`/`Prompt` to `Email`/`Push` refuses continuation so owner approval runs.
//! 4. **Recording approval & Ask-feature preservation**: recording host-prompt
//!    policy (`record_prompt_window_ms`) and explicitly host-approved `Ask`
//!    features (`approved_ask_bits`: clipboard/files/audio) are sealed separately
//!    from desktop admission so restarting neither bypasses recording prompts nor
//!    silently strips already-approved features (while still obeying any `Off` floor).

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

/// Bitmask for host-approved `FeaturePolicy::Ask` features carried across restart.
pub const ASK_BIT_CLIPBOARD: u8 = 1 << 0;
pub const ASK_BIT_FILES: u8 = 1 << 1;
pub const ASK_BIT_AUDIO: u8 = 1 << 2;

const CONTINUITY_FILENAME: &str = "rc-continuity.json";
const MASTER_KEY_FILENAME: &str = "ssh-resume.key";

/// Metadata captured when a non-external, non-shared RC session becomes live.
#[derive(Debug, Clone)]
pub struct ActiveRcSession {
    pub session_id: ObjectId,
    pub org_id: String,
    pub controller_user_id: ObjectId,
    pub permissions_bits: u16,
    pub audio_enabled: bool,
    /// Exact 2FA enrollment fingerprint verified when this session was admitted
    /// (`None` if 2FA was off at admission time).
    pub two_factor_fingerprint: Option<String>,
    /// `true` only when the prior session was approved by owner-side consent (`Email`/`Push`).
    pub owner_side_approved: bool,
    /// Independent recording host-prompt window (ms) from the original session.
    pub record_prompt_window_ms: Option<u64>,
    /// Bitmask of `FeaturePolicy::Ask` features approved on the original session.
    pub approved_ask_bits: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RcContinuityRecord {
    pub prev_session_id: String,
    pub org_id: String,
    pub controller_user_id: String,
    pub permissions_bits: u16,
    pub audio_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub two_factor_fingerprint: Option<String>,
    #[serde(default)]
    pub owner_side_approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_prompt_window_ms: Option<u64>,
    #[serde(default)]
    pub approved_ask_bits: u8,
    pub expires_at_ms: u64,
}

/// Verified continuity attributes returned when `take_matching` succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedContinuity {
    pub owner_side_approved: bool,
    pub record_prompt_window_ms: Option<u64>,
    pub approved_ask_bits: u8,
}

/// Parameters evaluated against a pending continuity record on reconnect.
#[derive(Debug, Clone, Copy)]
pub struct MatchRequest<'a> {
    pub prev_sid: ObjectId,
    pub org_id: &'a str,
    pub controller_user_id: ObjectId,
    pub requested_permissions_bits: u16,
    pub requested_audio: bool,
    pub current_two_factor_fp: Option<&'a str>,
    pub requires_owner_side_consent: bool,
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
    /// Merged shutdown snapshot per org so multi-org loops never overwrite each other.
    shutdown_staged: HashMap<ObjectId, RcContinuityRecord>,
    pending: HashMap<ObjectId, RcContinuityRecord>,
}

static STORE: OnceLock<Mutex<ContinuityStore>> = OnceLock::new();

fn store() -> &'static Mutex<ContinuityStore> {
    STORE.get_or_init(|| Mutex::new(ContinuityStore::default()))
}

/// Resolve the runtime state directory shared with `ssh_persist`.
/// Never picks Linux-only `/run/meshharbor` on macOS.
pub fn state_dir() -> PathBuf {
    #[cfg(feature = "ssh-server")]
    {
        crate::ssh_persist::state_dir()
    }
    #[cfg(not(feature = "ssh-server"))]
    {
        platform_runtime_state_dir()
    }
}

/// Cross-platform runtime state directory helper shared by `rc_continuity` and `ssh_persist`.
pub fn platform_runtime_state_dir() -> PathBuf {
    if let Ok(p) = std::env::var("MESHHARBORD_SSH_PERSIST_DIR")
        && !p.trim().is_empty()
    {
        return PathBuf::from(p.trim());
    }
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "macos")]
    {
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root {
            return PathBuf::from("/var/run/meshharbor");
        }
    }
    crate::config::default_config_path()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| std::env::temp_dir().join("meshharbor"))
}

/// Record a live, non-external, non-shared remote control session so a graceful
/// daemon restart can preserve its exact verified approvals for 120 seconds.
pub fn register_active(session: ActiveRcSession) {
    let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
    g.active.insert(session.session_id, session);
}

/// Remove a session on EVERY real end (including signaling-loss teardown, host
/// disconnect, idle limit, or server terminate) so stale entries never accumulate.
pub fn unregister_active(session_id: ObjectId) {
    let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
    g.active.remove(&session_id);
}

/// Stage live sessions for one org loop during graceful shutdown and atomically
/// write the merged union across all org loops that have shut down so far.
pub fn save_active_for_restart(live_ids: &[ObjectId]) -> Result<usize, String> {
    let now = now_unix_ms();
    let expires_at_ms = now.saturating_add(CONTINUITY_TTL_MS);
    let merged: Vec<RcContinuityRecord> = {
        let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
        g.shutdown_staged.retain(|_, rec| rec.expires_at_ms > now);
        for sid in live_ids {
            if let Some(a) = g.active.get(sid).cloned() {
                g.shutdown_staged.insert(
                    *sid,
                    RcContinuityRecord {
                        prev_session_id: a.session_id.to_hex(),
                        org_id: a.org_id.clone(),
                        controller_user_id: a.controller_user_id.to_hex(),
                        permissions_bits: a.permissions_bits,
                        audio_enabled: a.audio_enabled,
                        two_factor_fingerprint: a.two_factor_fingerprint.clone(),
                        owner_side_approved: a.owner_side_approved,
                        record_prompt_window_ms: a.record_prompt_window_ms,
                        approved_ask_bits: a.approved_ask_bits,
                        expires_at_ms,
                    },
                );
            }
        }
        g.shutdown_staged.values().cloned().collect()
    };
    let dir = state_dir();
    save_records_to_dir(&dir, &merged)
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
    let tmp = dir.join(format!("rc-continuity.{}.tmp", std::process::id()));
    write_restricted(&tmp, &encoded).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    info!(
        count = records.len(),
        ttl_secs = CONTINUITY_TTL_MS / 1000,
        "fr141: saved sealed rc-continuity records for restart"
    );
    Ok(records.len())
}

/// Atomically claim, load, verify, and unlink `<state_dir>/rc-continuity.json` during daemon boot.
pub fn load_and_consume_on_boot() -> usize {
    let dir = state_dir();
    load_and_consume_from_dir(&dir)
}

pub fn load_and_consume_from_dir(dir: &Path) -> usize {
    let path = dir.join(CONTINUITY_FILENAME);
    if !path.exists() {
        return 0;
    }
    // Atomic single-use claim BEFORE reading: if the directory is read-only or
    // another generation already claimed the file, rename fails and continuity
    // is refused fail-closed so two generations can NEVER consume the same record.
    let claimed_path = dir.join(format!(
        "rc-continuity.claimed.{}.{}.json",
        std::process::id(),
        now_unix_ms()
    ));
    if let Err(e) = std::fs::rename(&path, &claimed_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(
                path = %path.display(),
                %e,
                "fr141: failed to atomically claim rc-continuity file — refusing continuity"
            );
        }
        return 0;
    }

    let raw = match std::fs::read(&claimed_path) {
        Ok(b) => {
            let _ = std::fs::remove_file(&claimed_path);
            b
        }
        Err(e) => {
            warn!(path = %claimed_path.display(), %e, "fr141: failed to read claimed rc-continuity file");
            let _ = std::fs::remove_file(&claimed_path);
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

/// Peek the approved `Ask` feature bitmask for an unexpired record (non-consuming)
/// so pre-masking can check whether a feature was already host-approved.
pub fn peek_approved_ask_bits(prev_sid: ObjectId, org_id: &str, controller_user_id: ObjectId) -> u8 {
    let now = now_unix_ms();
    let g = store().lock().unwrap_or_else(|e| e.into_inner());
    let user_hex = controller_user_id.to_hex();
    g.pending
        .get(&prev_sid)
        .filter(|r| {
            r.expires_at_ms > now && r.org_id == org_id && r.controller_user_id == user_hex
        })
        .map_or(0, |r| r.approved_ask_bits)
}

/// Consume a matching, unexpired continuity record (single-use) if:
/// - `prev_sid` exists and is unexpired;
/// - `org_id` and `controller_user_id` match exactly;
/// - requested permissions & audio do not escalate beyond the prior grant;
/// - if 2FA is currently active (`current_two_factor_fp.is_some()`), the prior
///   session verified the EXACT SAME 2FA enrollment fingerprint;
/// - if current policy requires owner-side consent (`Email`/`Push`), the prior
///   session was ALSO owner-side approved.
pub fn take_matching(req: MatchRequest<'_>) -> Option<MatchedContinuity> {
    let now = now_unix_ms();
    let mut g = store().lock().unwrap_or_else(|e| e.into_inner());
    g.pending.retain(|_, rec| rec.expires_at_ms > now);
    let rec = g.pending.get(&req.prev_sid)?;
    let user_hex = req.controller_user_id.to_hex();
    let no_perm_escalation =
        (req.requested_permissions_bits & rec.permissions_bits) == req.requested_permissions_bits;
    let no_audio_escalation = !req.requested_audio || rec.audio_enabled;
    let two_factor_ok = match req.current_two_factor_fp {
        None => true,
        Some(cur_fp) => cur_fp != "unreadable" && rec.two_factor_fingerprint.as_deref() == Some(cur_fp),
    };
    let consent_authority_ok = !req.requires_owner_side_consent || rec.owner_side_approved;

    if rec.org_id == req.org_id
        && rec.controller_user_id == user_hex
        && no_perm_escalation
        && no_audio_escalation
        && two_factor_ok
        && consent_authority_ok
    {
        let rec = g.pending.remove(&req.prev_sid)?;
        debug!(
            prev_sid = %req.prev_sid,
            controller = %req.controller_user_id,
            owner_side_approved = rec.owner_side_approved,
            approved_ask_bits = rec.approved_ask_bits,
            "fr141: rc-continuity record matched and consumed"
        );
        Some(MatchedContinuity {
            owner_side_approved: rec.owner_side_approved,
            record_prompt_window_ms: rec.record_prompt_window_ms,
            approved_ask_bits: rec.approved_ask_bits,
        })
    } else {
        warn!(
            prev_sid = %req.prev_sid,
            controller = %req.controller_user_id,
            org_match = (rec.org_id == req.org_id),
            user_match = (rec.controller_user_id == user_hex),
            no_perm_escalation,
            no_audio_escalation,
            two_factor_ok,
            consent_authority_ok,
            "fr141: rc-continuity record rejected due to scope/assurance mismatch"
        );
        None
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
    fn fr141_rc_continuity_round_trip_single_use_and_assurance_binding() {
        let dir = tempfile::tempdir().unwrap();
        let sid = ObjectId::new();
        let user = ObjectId::new();
        let other_user = ObjectId::new();
        let now = now_unix_ms();

        let rec = RcContinuityRecord {
            prev_session_id: sid.to_hex(),
            org_id: "org-alpha".into(),
            controller_user_id: user.to_hex(),
            permissions_bits: 0b0011,
            audio_enabled: false,
            two_factor_fingerprint: Some("fp-v1".into()),
            owner_side_approved: false,
            record_prompt_window_ms: Some(30_000),
            approved_ask_bits: ASK_BIT_CLIPBOARD,
            expires_at_ms: now + 60_000,
        };
        assert_eq!(save_records_to_dir(dir.path(), &[rec]).unwrap(), 1);
        assert!(dir.path().join(CONTINUITY_FILENAME).exists());

        // Atomic rename-claim consumes and unlinks the on-disk file.
        assert_eq!(load_and_consume_from_dir(dir.path()), 1);
        assert!(!dir.path().join(CONTINUITY_FILENAME).exists());

        let base = MatchRequest {
            prev_sid: sid,
            org_id: "org-alpha",
            controller_user_id: user,
            requested_permissions_bits: 0b0001,
            requested_audio: false,
            current_two_factor_fp: Some("fp-v1"),
            requires_owner_side_consent: false,
        };

        // Wrong org / wrong user / permission escalation / audio escalation / changed 2FA / newly required owner consent all fail.
        assert!(take_matching(MatchRequest { org_id: "org-beta", ..base }).is_none());
        assert!(take_matching(MatchRequest { controller_user_id: other_user, ..base }).is_none());
        assert!(take_matching(MatchRequest { requested_permissions_bits: 0b0111, ..base }).is_none());
        assert!(take_matching(MatchRequest { requested_audio: true, ..base }).is_none());
        assert!(take_matching(MatchRequest { current_two_factor_fp: Some("fp-v2"), ..base }).is_none());
        assert!(take_matching(MatchRequest { requires_owner_side_consent: true, ..base }).is_none());

        // Matching subset with same 2FA fingerprint succeeds once and returns preserved policy metadata.
        let matched = take_matching(base).expect("must match");
        assert_eq!(matched.record_prompt_window_ms, Some(30_000));
        assert_eq!(matched.approved_ask_bits, ASK_BIT_CLIPBOARD);
        assert!(!matched.owner_side_approved);
        // Single-use: second match rejected.
        assert!(take_matching(base).is_none());
    }

    #[test]
    fn fr141_rc_continuity_refuses_2fa_bypass_when_2fa_was_enabled_after_start() {
        let dir = tempfile::tempdir().unwrap();
        let sid = ObjectId::new();
        let user = ObjectId::new();
        let now = now_unix_ms();

        // Original session opened while 2FA was OFF (`two_factor_fingerprint: None`).
        let rec = RcContinuityRecord {
            prev_session_id: sid.to_hex(),
            org_id: "org-alpha".into(),
            controller_user_id: user.to_hex(),
            permissions_bits: 0b0001,
            audio_enabled: false,
            two_factor_fingerprint: None,
            owner_side_approved: false,
            record_prompt_window_ms: None,
            approved_ask_bits: 0,
            expires_at_ms: now + 60_000,
        };
        assert_eq!(save_records_to_dir(dir.path(), &[rec]).unwrap(), 1);
        assert_eq!(load_and_consume_from_dir(dir.path()), 1);

        // After enabling 2FA before restart, continuation MUST be refused!
        assert!(
            take_matching(MatchRequest {
                prev_sid: sid,
                org_id: "org-alpha",
                controller_user_id: user,
                requested_permissions_bits: 0b0001,
                requested_audio: false,
                current_two_factor_fp: Some("newly-enabled-fp"),
                requires_owner_side_consent: false,
            })
            .is_none()
        );
    }

    #[test]
    fn fr141_rc_continuity_rejects_tampered_seal_and_expired_records() {
        let dir = tempfile::tempdir().unwrap();
        let sid_expired = ObjectId::new();
        let sid_tampered = ObjectId::new();
        let user = ObjectId::new();
        let now = now_unix_ms();

        let expired = RcContinuityRecord {
            prev_session_id: sid_expired.to_hex(),
            org_id: "org-alpha".into(),
            controller_user_id: user.to_hex(),
            permissions_bits: 0b0001,
            audio_enabled: false,
            two_factor_fingerprint: None,
            owner_side_approved: false,
            record_prompt_window_ms: None,
            approved_ask_bits: 0,
            expires_at_ms: now.saturating_sub(1_000),
        };
        assert_eq!(save_records_to_dir(dir.path(), &[expired]).unwrap(), 1);
        assert_eq!(load_and_consume_from_dir(dir.path()), 0);

        let valid = RcContinuityRecord {
            prev_session_id: sid_tampered.to_hex(),
            org_id: "org-alpha".into(),
            controller_user_id: user.to_hex(),
            permissions_bits: 0b0001,
            audio_enabled: false,
            two_factor_fingerprint: None,
            owner_side_approved: false,
            record_prompt_window_ms: None,
            approved_ask_bits: 0,
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
    }
}
