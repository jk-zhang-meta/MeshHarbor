// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Local `0600` session store for resumable `mh ssh` sessions.
//!
//! Enables `mh ssh <dev> --sessions`, `mh ssh <dev> --resume [id]`, and
//! `mh ssh <dev> --kill <id>` across local terminal crashes or `~d` detaches.
//! Skipped when the user passes `--ephemeral`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use meshharbor_node_core::pty_resume::{SessionId, now_unix_ms};
use serde::{Deserialize, Serialize};

/// Persisted client-side resume credentials (stored mode `0600`, deleted on exit/kill).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub sid: SessionId,
    pub device: String,
    pub address: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<u16>,
    pub host_pubkey: String,
    pub session_privkey_openssh: String,
    pub resume_secret_hex: String,
    pub created_ms: u64,
    pub deadline_ms: u64,
    pub last_rx: u64,
    pub c2s_next: u64,
}

impl StoredSession {
    pub fn resume_secret(&self) -> Result<[u8; 32]> {
        let raw = hex::decode(self.resume_secret_hex.trim())
            .context("decoding stored resume_secret_hex")?;
        if raw.len() != 32 {
            bail!("stored resume_secret has invalid length {}", raw.len());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }

    pub fn is_expired(&self) -> bool {
        now_unix_ms() >= self.deadline_ms
    }
}

pub fn default_store_dir() -> Result<PathBuf> {
    if let Ok(override_dir) = std::env::var("MESHHARBOR_SSH_STORE_DIR")
        && !override_dir.trim().is_empty()
    {
        return Ok(PathBuf::from(override_dir.trim()));
    }
    let proj = directories::ProjectDirs::from("fans", "itachi", "meshharbor")
        .context("could not resolve platform state directory")?;
    Ok(proj.data_local_dir().join("ssh-sessions"))
}

pub fn save_in(dir: &Path, session: &StoredSession) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let final_path = dir.join(format!("{}.json", session.sid.to_hex()));
    let tmp_path = dir.join(format!("{}.json.tmp", session.sid.to_hex()));
    let bytes = serde_json::to_vec_pretty(session)?;
    write_private(&tmp_path, &bytes)?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

pub fn save(session: &StoredSession) -> Result<PathBuf> {
    let dir = default_store_dir()?;
    save_in(&dir, session)
}

pub fn delete_in(dir: &Path, sid: &SessionId) {
    let _ = std::fs::remove_file(dir.join(format!("{}.json", sid.to_hex())));
}

pub fn delete(sid: &SessionId) {
    if let Ok(dir) = default_store_dir() {
        delete_in(&dir, sid);
    }
}

pub fn list_in(dir: &Path, device_filter: Option<&str>) -> Vec<StoredSession> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let now = now_unix_ms();
    let mut out = Vec::new();
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read(&path) else {
            continue;
        };
        let Ok(sess) = serde_json::from_slice::<StoredSession>(&raw) else {
            continue;
        };
        if sess.deadline_ms <= now {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        if let Some(dev) = device_filter
            && !sess.device.eq_ignore_ascii_case(dev)
        {
            continue;
        }
        out.push(sess);
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.created_ms));
    out
}

pub fn list_for_device(device: &str) -> Vec<StoredSession> {
    default_store_dir()
        .map(|d| list_in(&d, Some(device)))
        .unwrap_or_default()
}

pub fn find_by_prefix_in(dir: &Path, device: &str, prefix: Option<&str>) -> Result<StoredSession> {
    let all = list_in(dir, Some(device));
    if all.is_empty() {
        bail!("no saved resumable SSH sessions found for `{device}`");
    }
    match prefix {
        None => Ok(all[0].clone()),
        Some(p) => {
            let q = p.trim().to_ascii_lowercase();
            let matched: Vec<StoredSession> = all
                .into_iter()
                .filter(|s| s.sid.to_hex().starts_with(&q))
                .collect();
            match matched.len() {
                0 => bail!("no saved SSH session for `{device}` matches `{q}`"),
                1 => Ok(matched.into_iter().next().unwrap()),
                n => bail!("ambiguous session prefix `{q}` matches {n} sessions"),
            }
        }
    }
}

pub fn find_by_prefix(device: &str, prefix: Option<&str>) -> Result<StoredSession> {
    let dir = default_store_dir()?;
    find_by_prefix_in(&dir, device, prefix)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
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
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_local_store_roundtrip_prefix_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let sid = SessionId::generate();
        let now = now_unix_ms();
        let sess = StoredSession {
            sid,
            device: "gpu-node-a".into(),
            address: "100.64.0.10".into(),
            port: 2222,
            socks_port: None,
            host_pubkey: "ssh-ed25519 AAAA".into(),
            session_privkey_openssh: "PRIVATE".into(),
            resume_secret_hex: hex::encode([0x42u8; 32]),
            created_ms: now,
            deadline_ms: now + 60_000,
            last_rx: 512,
            c2s_next: 12,
        };
        save_in(dir.path(), &sess).unwrap();

        let found =
            find_by_prefix_in(dir.path(), "gpu-node-a", Some(&sid.short_hex()[..6])).unwrap();
        assert_eq!(found.sid, sid);
        assert_eq!(found.resume_secret().unwrap(), [0x42u8; 32]);

        delete_in(dir.path(), &sid);
        assert!(list_in(dir.path(), Some("gpu-node-a")).is_empty());
    }
}
