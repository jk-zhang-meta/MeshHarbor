// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Unified Overlay P2P Control Plane (`p2pctl`, TCP port `41642`).
//!
//! Pure wire types, bounded length-prefixed JSON framing (64 KiB cap), and
//! mutual X25519 + HMAC-SHA256 `hello` proof verification.
//!
//! Security model:
//! 1. At `WgDevice` ingress (`Ingress::permits_inner`), packets destined to
//!    [`P2P_CTL_PORT`] are UNCONDITIONALLY dropped unless their source IP is
//!    the decrypting peer's exact `/32` overlay IP (even under `RpfMode::Warn`
//!    or `RpfMode::Off`, and refusing routed subnet sources), while remaining
//!    subject to tenant inbound WG ACLs under `enforce`.
//! 2. Because a pre-FR-139 host or a host with `p2p_control_enabled = false`
//!    could have an unprivileged local process bound to TCP `41642`, origins
//!    gate dialing on `NetmapPeer::supports_p2pctl` AND run a mutual X25519 +
//!    HMAC-SHA256 `hello` proof bound to `(tenant_id, origin_node_id,
//!    target_node_id, origin_nonce, target_nonce)` using the WireGuard static
//!    keypair DH shared secret BEFORE trusting `device_info` or transmitting
//!    any offline capability token, TOTP code, or command.

use std::io;
use std::time::Duration;

use ring::{hkdf, hmac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Overlay-intercepted TCP port for the P2P control plane.
/// Deliberately distinct from Tailscale (`41641`) and MeshHarbor direct UDP
/// (`43648+`).
pub const P2P_CTL_PORT: u16 = 41642;

/// Wire protocol version.
pub const P2P_CTL_VERSION: u32 = 1;

/// Hard maximum JSON frame size on `p2pctl` (64 KiB) to prevent memory DoS.
pub const P2P_CTL_MAX_FRAME_BYTES: usize = 64 * 1024;

/// Maximum time the server waits for the client's first `hello` frame.
pub const P2P_CTL_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

const HELLO_HKDF_SALT: &[u8] = b"meshharbor/p2pctl-hello/v1";
const HELLO_HKDF_INFO: &[u8] = b"meshharbor/p2pctl-hello-mac/v1";

/// Client → Server initial handshake frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pHelloInit {
    pub v: u32,
    pub tenant_id: String,
    pub origin_node_id: String,
    pub target_node_id: String,
    /// 32 random bytes, lowercase hex (64 chars).
    pub origin_nonce_hex: String,
}

/// Server → Client handshake response carrying the server's proof of holding
/// the target's WireGuard static private key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pHelloResp {
    pub v: u32,
    /// 32 random bytes, lowercase hex (64 chars). Empty on error.
    #[serde(default)]
    pub target_nonce_hex: String,
    /// Hex-encoded HMAC-SHA256 server proof. Empty on error.
    #[serde(default)]
    pub server_proof_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Client → Server authenticated request frame (sent ONLY after verifying
/// [`P2pHelloResp::server_proof_hex`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pClientRequest {
    pub v: u32,
    /// Hex-encoded HMAC-SHA256 client proof bound to both nonces + identities.
    pub client_proof_hex: String,
    pub req: P2pReq,
}

/// Typed `p2pctl` request verbs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum P2pReq {
    /// Query peer capabilities and host/RDP certificate pins.
    DeviceInfo,
    /// Request an offline SSH grant backed by a server-signed `offline_cap`
    /// with `verb == "ssh"`.
    SshGrant {
        offline_cap: String,
        request_id: String,
        public_key: String,
        session_secs: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        two_factor_code: Option<String>,
    },
    /// Execute one bounded command offline backed by a server-signed
    /// `offline_cap` with `verb == "exec"`.
    Exec {
        offline_cap: String,
        request_id: String,
        shell: String,
        command: String,
        timeout_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        two_factor_code: Option<String>,
    },
}

/// Metadata returned by `P2pReq::DeviceInfo` after mutual authentication.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pDeviceInfo {
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ssh_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_pubkey: Option<String>,
    #[serde(default)]
    pub exec_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_cert_sha256: Option<String>,
    #[serde(default)]
    pub supports_p2pctl: bool,
}

/// Server → Client response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum P2pResp {
    DeviceInfo(P2pDeviceInfo),
    SshGrant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_pubkey: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        two_factor: Option<String>,
    },
    Exec {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(default)]
        stdout: String,
        #[serde(default)]
        stderr: String,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        duration_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Error {
        code: String,
        message: String,
    },
}

/// Derive the 32-byte HMAC-SHA256 key from the WireGuard static X25519 shared
/// secret (`DH(origin_wg_secret, target_wg_pub) == DH(target_wg_secret, origin_wg_pub)`).
pub fn derive_hello_mac_key(shared_dh: &[u8; 32]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HELLO_HKDF_SALT);
    let prk = salt.extract(shared_dh);
    let okm = prk
        .expand(&[HELLO_HKDF_INFO], hkdf::HKDF_SHA256)
        .expect("HKDF expand 32 bytes");
    let mut out = [0u8; 32];
    okm.fill(&mut out).expect("fill 32 bytes");
    out
}

fn hello_transcript(
    role: &[u8],
    tenant_id: &str,
    origin_node_id: &str,
    target_node_id: &str,
    origin_nonce: &[u8],
    target_nonce: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        role.len()
            + tenant_id.len()
            + origin_node_id.len()
            + target_node_id.len()
            + origin_nonce.len()
            + target_nonce.len()
            + 6,
    );
    buf.extend_from_slice(role);
    buf.push(0);
    buf.extend_from_slice(tenant_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(origin_node_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(target_node_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(origin_nonce);
    buf.push(0);
    buf.extend_from_slice(target_nonce);
    buf
}

/// Compute hex-encoded HMAC-SHA256 proof for `role` (`b"server"` or `b"client"`).
pub fn compute_hello_proof(
    mac_key: &[u8; 32],
    role: &[u8],
    tenant_id: &str,
    origin_node_id: &str,
    target_node_id: &str,
    origin_nonce: &[u8],
    target_nonce: &[u8],
) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
    let msg = hello_transcript(
        role,
        tenant_id,
        origin_node_id,
        target_node_id,
        origin_nonce,
        target_nonce,
    );
    let tag = hmac::sign(&key, &msg);
    encode_hex(tag.as_ref())
}

/// Constant-time verification of a hex-encoded `hello` proof via `ring::hmac::verify`.
#[allow(clippy::too_many_arguments)]
pub fn verify_hello_proof(
    mac_key: &[u8; 32],
    role: &[u8],
    tenant_id: &str,
    origin_node_id: &str,
    target_node_id: &str,
    origin_nonce: &[u8],
    target_nonce: &[u8],
    proof_hex: &str,
) -> bool {
    let Some(tag) = decode_hex(proof_hex.trim()) else {
        return false;
    };
    if tag.len() != 32 {
        return false;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
    let msg = hello_transcript(
        role,
        tenant_id,
        origin_node_id,
        target_node_id,
        origin_nonce,
        target_nonce,
    );
    hmac::verify(&key, &msg, &tag).is_ok()
}

/// Lowercase hex encode helper (avoids extra crate dep in `remote_control`).
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode even-length ASCII hex string into bytes.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let hex_val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Some(out)
}

/// Write one length-prefixed JSON frame (`u32` big-endian length + body),
/// enforcing [`P2P_CTL_MAX_FRAME_BYTES`].
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("p2pctl encode: {e}")))?;
    if body.is_empty() || body.len() > P2P_CTL_MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("p2pctl frame size {} out of bounds", body.len()),
        ));
    }
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "p2pctl frame length overflow"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

/// Read one length-prefixed JSON frame, rejecting lengths outside
/// `1..=P2P_CTL_MAX_FRAME_BYTES` BEFORE allocating the body buffer.
pub async fn read_frame<R, T>(r: &mut R) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 || len > P2P_CTL_MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("p2pctl frame size {len} exceeds limit {P2P_CTL_MAX_FRAME_BYTES}"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("p2pctl decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr139_hello_proof_binds_role_identities_and_nonces() {
        let shared = [0xABu8; 32];
        let key = derive_hello_mac_key(&shared);
        let n1 = [0x11u8; 32];
        let n2 = [0x22u8; 32];

        let srv = compute_hello_proof(&key, b"server", "tid-1", "node-a", "node-b", &n1, &n2);
        assert!(verify_hello_proof(
            &key, b"server", "tid-1", "node-a", "node-b", &n1, &n2, &srv
        ));
        // Wrong role, wrong tenant, swapped node ids, wrong nonce, or wrong key must fail.
        assert!(!verify_hello_proof(
            &key, b"client", "tid-1", "node-a", "node-b", &n1, &n2, &srv
        ));
        assert!(!verify_hello_proof(
            &key, b"server", "tid-2", "node-a", "node-b", &n1, &n2, &srv
        ));
        assert!(!verify_hello_proof(
            &key, b"server", "tid-1", "node-b", "node-a", &n1, &n2, &srv
        ));
        let other_key = derive_hello_mac_key(&[0xCDu8; 32]);
        assert!(!verify_hello_proof(
            &other_key, b"server", "tid-1", "node-a", "node-b", &n1, &n2, &srv
        ));
    }

    #[tokio::test]
    async fn fr139_frame_roundtrip_and_oversize_refusal() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let msg = P2pHelloInit {
            v: P2P_CTL_VERSION,
            tenant_id: "t1".into(),
            origin_node_id: "n1".into(),
            target_node_id: "n2".into(),
            origin_nonce_hex: encode_hex(&[0x55u8; 32]),
        };
        write_frame(&mut a, &msg).await.unwrap();
        let got: P2pHelloInit = read_frame(&mut b).await.unwrap();
        assert_eq!(got, msg);

        // Oversize length prefix (> 64 KiB) rejected before allocation.
        let bad_len = ((P2P_CTL_MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        a.write_all(&bad_len).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame::<_, P2pHelloInit>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
