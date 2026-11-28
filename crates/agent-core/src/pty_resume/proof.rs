// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Stateless HKDF/HMAC cryptography for FR-141 resume seals, resume proofs,
//! and remote-desktop restart continuity records.
//!
//! Security model:
//! - The target daemon holds a single 32-byte device-local `MasterKey`
//!   (`ssh-resume.key`, `0600` / protected ACL). It is NEVER sent on the wire
//!   and NEVER exposed in `DesiredConfig`.
//! - Each detached `ssh-pty-host` holds ZERO secrets — only `(descriptor_json, seal)`.
//! - Any future generation of `meshharbord` verifies `seal` and recomputes
//!   `resume_secret = HKDF(master, salt=sid, info="fr141/resume/v1" || SHA256(D))`
//!   statelessly without storing per-session secrets on disk.
//! - Rotating `MasterKey` immediately invalidates every outstanding resume token.

use std::fmt;
use std::path::Path;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::SessionId;

type HmacSha256 = Hmac<Sha256>;

const LABEL_SEAL: &[u8] = b"fr141/seal/v1";
const LABEL_RESUME: &[u8] = b"fr141/resume/v1";
const LABEL_RC_CONTINUITY: &[u8] = b"fr141/rc-continuity/v1";
const DOMAIN_ATTACH_CLIENT: &[u8] = b"fr141-attach-c";
const DOMAIN_ATTACH_SERVER: &[u8] = b"fr141-attach-s";

/// 32-byte device-local master key (zeroized on drop; never logged).
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        rand::rng().fill_bytes(&mut raw);
        Self(Zeroizing::new(raw))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Load an existing 32-byte hex/raw key from `path`, or generate & persist
    /// a new one atomically with `0600` permissions on Unix.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        if let Ok(raw) = std::fs::read(path)
            && let Some(key) = decode_key_file(&raw)
        {
            return Ok(key);
        }
        let key = Self::generate();
        key.save_atomic(path)?;
        Ok(key)
    }

    /// Persist hex-encoded key atomically with strict file permissions.
    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let encoded = Zeroizing::new(hex::encode(self.as_bytes()));
        let tmp = path.with_extension("key.tmp");
        write_restricted_file(&tmp, encoded.as_bytes())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

fn decode_key_file(raw: &[u8]) -> Option<MasterKey> {
    if raw.len() == 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(raw);
        return Some(MasterKey::from_bytes(b));
    }
    let s = std::str::from_utf8(raw).ok()?.trim();
    if s.len() == 64
        && let Ok(bytes) = hex::decode(s)
        && bytes.len() == 32
    {
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes);
        return Some(MasterKey::from_bytes(b));
    }
    None
}

fn write_restricted_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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

fn hkdf_subkey(master: &MasterKey, salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(salt, master.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out)
        .expect("32-byte HKDF-SHA256 output is always valid");
    out
}

/// Compute `seal = HMAC(HKDF(master, "", "fr141/seal/v1"), descriptor_json)`.
pub fn seal_descriptor(master: &MasterKey, descriptor_json: &[u8]) -> [u8; 32] {
    let key = hkdf_subkey(master, None, LABEL_SEAL);
    let mut mac = HmacSha256::new_from_slice(&*key).expect("HMAC accepts 32-byte key");
    mac.update(descriptor_json);
    mac.finalize().into_bytes().into()
}

/// Verify a descriptor seal in constant time.
pub fn verify_descriptor_seal(master: &MasterKey, descriptor_json: &[u8], seal: &[u8; 32]) -> bool {
    let expected = seal_descriptor(master, descriptor_json);
    bool::from(expected.ct_eq(seal))
}

/// Compute `resume_secret = HKDF(master, salt=sid, info="fr141/resume/v1" || SHA256(D))`.
pub fn derive_resume_secret(
    master: &MasterKey,
    sid: &SessionId,
    descriptor_json: &[u8],
) -> Zeroizing<[u8; 32]> {
    let d_hash = Sha256::digest(descriptor_json);
    let mut info = Vec::with_capacity(LABEL_RESUME.len() + 32);
    info.extend_from_slice(LABEL_RESUME);
    info.extend_from_slice(&d_hash);
    hkdf_subkey(master, Some(sid.as_bytes()), &info)
}

/// Client attach proof bound to session ID, both fresh nonces, host key fp, and client key fp.
pub fn compute_client_proof(
    resume_secret: &[u8; 32],
    sid: &SessionId,
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    host_key_fp: &str,
    client_key_fp: &str,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(resume_secret).expect("HMAC accepts 32-byte key");
    mac.update(DOMAIN_ATTACH_CLIENT);
    mac.update(sid.as_bytes());
    mac.update(server_nonce);
    mac.update(client_nonce);
    mac.update(&(host_key_fp.len() as u32).to_be_bytes());
    mac.update(host_key_fp.as_bytes());
    mac.update(&(client_key_fp.len() as u32).to_be_bytes());
    mac.update(client_key_fp.as_bytes());
    mac.finalize().into_bytes().into()
}

pub fn verify_client_proof(
    resume_secret: &[u8; 32],
    sid: &SessionId,
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    host_key_fp: &str,
    client_key_fp: &str,
    presented: &[u8; 32],
) -> bool {
    let expected = compute_client_proof(
        resume_secret,
        sid,
        server_nonce,
        client_nonce,
        host_key_fp,
        client_key_fp,
    );
    bool::from(expected.ct_eq(presented))
}

/// Mutual server attach proof proving the daemon owns the same device master key.
pub fn compute_server_proof(
    resume_secret: &[u8; 32],
    sid: &SessionId,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(resume_secret).expect("HMAC accepts 32-byte key");
    mac.update(DOMAIN_ATTACH_SERVER);
    mac.update(sid.as_bytes());
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().into()
}

pub fn verify_server_proof(
    resume_secret: &[u8; 32],
    sid: &SessionId,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    presented: &[u8; 32],
) -> bool {
    let expected = compute_server_proof(resume_secret, sid, client_nonce, server_nonce);
    bool::from(expected.ct_eq(presented))
}

/// Seal a remote-desktop restart continuity file under `fr141/rc-continuity/v1`.
pub fn seal_rc_continuity(master: &MasterKey, payload_json: &[u8]) -> [u8; 32] {
    let key = hkdf_subkey(master, None, LABEL_RC_CONTINUITY);
    let mut mac = HmacSha256::new_from_slice(&*key).expect("HMAC accepts 32-byte key");
    mac.update(payload_json);
    mac.finalize().into_bytes().into()
}

/// Verify a remote-desktop restart continuity seal in constant time.
pub fn verify_rc_continuity(master: &MasterKey, payload_json: &[u8], seal: &[u8; 32]) -> bool {
    let expected = seal_rc_continuity(master, payload_json);
    bool::from(expected.ct_eq(seal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_seal_tamper_and_proof_verification() {
        let master = MasterKey::generate();
        let other_master = MasterKey::generate();
        let sid = SessionId::generate();
        let other_sid = SessionId::generate();
        let desc = br#"{"sid":"000102030405060708090a0b0c0d0e0f","deadline_ms":999999}"#;

        let seal = seal_descriptor(&master, desc);
        assert!(verify_descriptor_seal(&master, desc, &seal));
        assert!(!verify_descriptor_seal(&other_master, desc, &seal));
        let mut tampered = desc.to_vec();
        tampered[20] ^= 0x01;
        assert!(!verify_descriptor_seal(&master, &tampered, &seal));

        let secret = derive_resume_secret(&master, &sid, desc);
        let secret_other_sid = derive_resume_secret(&master, &other_sid, desc);
        assert_ne!(&*secret, &*secret_other_sid);

        let s_nonce = [1u8; 32];
        let c_nonce = [2u8; 32];
        let wrong_nonce = [3u8; 32];
        let c_proof = compute_client_proof(
            &secret,
            &sid,
            &s_nonce,
            &c_nonce,
            "SHA256:host",
            "SHA256:cli",
        );
        assert!(verify_client_proof(
            &secret,
            &sid,
            &s_nonce,
            &c_nonce,
            "SHA256:host",
            "SHA256:cli",
            &c_proof
        ));
        assert!(!verify_client_proof(
            &secret,
            &sid,
            &wrong_nonce,
            &c_nonce,
            "SHA256:host",
            "SHA256:cli",
            &c_proof
        ));
        assert!(!verify_client_proof(
            &secret,
            &sid,
            &s_nonce,
            &c_nonce,
            "SHA256:mitm",
            "SHA256:cli",
            &c_proof
        ));
        assert!(!verify_client_proof(
            &secret,
            &sid,
            &s_nonce,
            &c_nonce,
            "SHA256:host",
            "SHA256:other",
            &c_proof
        ));
        assert!(!verify_client_proof(
            &secret_other_sid,
            &sid,
            &s_nonce,
            &c_nonce,
            "SHA256:host",
            "SHA256:cli",
            &c_proof
        ));

        let s_proof = compute_server_proof(&secret, &sid, &c_nonce, &s_nonce);
        assert!(verify_server_proof(
            &secret, &sid, &c_nonce, &s_nonce, &s_proof
        ));
        assert!(!verify_server_proof(
            &secret,
            &sid,
            &wrong_nonce,
            &s_nonce,
            &s_proof
        ));

        // RC continuity seal isolation from SSH descriptor seal.
        let rc_seal = seal_rc_continuity(&master, desc);
        assert_ne!(rc_seal, seal);
        assert!(verify_rc_continuity(&master, desc, &rc_seal));
        assert!(!verify_rc_continuity(&other_master, desc, &rc_seal));
    }

    #[test]
    fn fr141_master_key_load_or_create_persists_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-resume.key");
        let k1 = MasterKey::load_or_create(&path).unwrap();
        let k2 = MasterKey::load_or_create(&path).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
        assert_eq!(format!("{k1:?}"), "MasterKey(<redacted>)");
    }
}
