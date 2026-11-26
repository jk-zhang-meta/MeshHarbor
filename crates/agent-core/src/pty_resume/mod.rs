// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Resumable SSH wire protocol (`meshharbor-pty@v1`), daemon↔host
//! local IPC framing, stateless HKDF/HMAC resume authentication, byte-offset
//! replay ring, and VT100 snapshot/shadow engine.
//!
//! Shared between `meshharbord` (daemon + `ssh-pty-host`) and `meshharbor-cli`
//! (`mh ssh`). All parsing and state-machine code here is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

pub mod frame;
pub mod ipc;
pub mod proof;
pub mod seq;

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// SSH subsystem name negotiated by resumable `mh ssh` clients.
pub const SUBSYSTEM_NAME: &str = "meshharbor-pty@v1";

/// Current wire protocol version.
pub const PROTO_VERSION: u16 = 1;

/// Current local daemon↔host IPC version.
pub const IPC_VERSION: u16 = 1;

/// Default host-side s2c byte replay ring size (4 MiB).
pub const DEFAULT_RING_BYTES: usize = 4 * 1024 * 1024;

/// Maximum serialized frame payload length (1 MiB) accepted on wire or IPC.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum bytes in a single `Data` frame (64 KiB).
pub const MAX_DATA_CHUNK: usize = 64 * 1024;

/// Maximum unacknowledged client-to-server input buffered while disconnected (64 KiB).
pub const MAX_C2S_QUEUE_BYTES: usize = 64 * 1024;

/// Default orphan timeout: if no daemon attaches to a PTY host for 10 minutes
/// (e.g. daemon crashed, uninstalled, or downgraded), the host terminates itself.
pub const DEFAULT_ORPHAN_TTL_SECS: u64 = 600;

/// Maximum terminal dimensions enforced by VT100 trackers.
pub const MAX_COLS: u16 = 1000;
pub const MAX_ROWS: u16 = 500;

/// Maximum VT100 scrollback lines kept in the host snapshot tracker.
pub const VT_SCROLLBACK_LEN: usize = 1000;

/// Stream identifiers carried by `Data`, `Ack`, and `Eof` frames.
pub const STREAM_STDIN: u8 = 0;
pub const STREAM_STDOUT: u8 = 1;
pub const STREAM_STDERR: u8 = 2;

/// 128-bit random session identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Generate a fresh cryptographically random session ID.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Full 32-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short 16-character lowercase hex prefix (for systemd unit names & UI).
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..8])
    }

    /// Parse a 32-character hex string into a `SessionId`.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.len() != 32 {
            return Err(format!("expected 32 hex chars, got {}", trimmed.len()));
        }
        let raw = hex::decode(trimmed).map_err(|e| format!("invalid hex session id: {e}"))?;
        let mut out = [0u8; 16];
        out.copy_from_slice(&raw);
        Ok(Self(out))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", self.short_hex())
    }
}

impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Interactive PTY vs lossless pipes mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Pty,
    Pipes,
}

/// Measured survival verdict reported by the target at `Open`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistStatus {
    pub survives_restart: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PersistStatus {
    pub fn survives() -> Self {
        Self {
            survives_restart: true,
            reason: None,
        }
    }

    pub fn degraded(reason: impl Into<String>) -> Self {
        Self {
            survives_restart: false,
            reason: Some(reason.into()),
        }
    }
}

/// Resolved execution identity frozen into the sealed session descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunAsDescriptor {
    Daemon,
    ConsoleUser,
    Named {
        username: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gid: Option<u32>,
    },
}

/// Authoritative session descriptor held by the detached PTY host alongside its
/// HMAC seal (`proof::seal_descriptor`). The host cannot tamper with any field
/// without failing daemon seal verification during adoption or attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDescriptor {
    pub sid: SessionId,
    pub org_id: String,
    pub agent_id: String,
    /// Stable principal identifier (grant caller / user id or key-list fingerprint).
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// SHA-256 fingerprint of the client's SSH session key.
    pub client_key_fp: String,
    /// SHA-256 fingerprint of the target's SSH host key.
    pub host_key_fp: String,
    pub run_as: RunAsDescriptor,
    pub mode: SessionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd_digest: Option<String>,
    pub created_ms: u64,
    pub deadline_ms: u64,
    pub detach_ttl_ms: u64,
    pub orphan_ttl_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub two_factor_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_iat_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_exp_ms: Option<u64>,
    #[serde(default)]
    pub via_service: bool,
    #[serde(default)]
    pub key_list_auth: bool,
    #[serde(default)]
    pub policy_digest: String,
    #[serde(default)]
    pub epoch: u64,
}

/// Replay mode chosen by the host on `Attach`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayKind {
    Bytes,
    Snapshot,
}

/// Terminal process exit status reported by `Exited` or `Refused::Ended`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatusInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

impl ExitStatusInfo {
    pub fn from_code(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }

    pub fn from_ssh_u32(code: u32) -> Self {
        Self {
            code: Some(code.min(255) as i32),
            signal: None,
        }
    }

    pub fn ssh_exit_code(&self) -> i32 {
        self.code.unwrap_or(1)
    }
}

/// Signals accepted in pipes mode (`Signal` frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalKind {
    Int,
    Term,
    Hup,
    Kill,
}

/// Server-to-client asynchronous session notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NoticeKind {
    TargetRestarting {
        reason: String,
        eta_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_version: Option<String>,
    },
    DeadlineSoon {
        in_ms: u64,
    },
    Superseded,
}

/// Terminal refusal returned by `Refused`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RefuseReason {
    UnknownSession,
    BadProof,
    Expired,
    Revoked {
        #[serde(default)]
        detail: String,
    },
    Ended {
        status: ExitStatusInfo,
    },
    Policy {
        #[serde(default)]
        detail: String,
    },
    Busy {
        #[serde(default)]
        detail: String,
    },
    UnsupportedProto {
        server_max: u16,
    },
    Internal {
        #[serde(default)]
        detail: String,
    },
}

impl RefuseReason {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Internal { .. })
    }
}

/// Reason attached to the frozen `0x00 Terminate` IPC command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminateReason {
    UserCancelled,
    Revoked,
    Expired,
    OrphanTimeout,
    DetachTimeout,
    PolicyChanged,
    OrgRemoved,
    CloseAccess,
    HostUnresponsive,
    Shutdown,
}

/// Allowlist filter for environment variables forwarded via `Open.env`.
/// Permits only locale, timezone, and color capability hints (`LANG`, `LC_*`,
/// `TZ`, `COLORTERM`), rejecting control characters and oversized entries.
pub fn filter_open_env(env: &[(String, String)]) -> Vec<(String, String)> {
    const MAX_ENTRIES: usize = 16;
    const MAX_KEY_LEN: usize = 64;
    const MAX_VAL_LEN: usize = 256;

    let mut out = Vec::new();
    for (k, v) in env {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        if k.is_empty() || k.len() > MAX_KEY_LEN || v.len() > MAX_VAL_LEN {
            continue;
        }
        let allowed = k == "LANG"
            || k == "TZ"
            || k == "COLORTERM"
            || (k.starts_with("LC_")
                && k[3..]
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'));
        if !allowed {
            continue;
        }
        if v.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            continue;
        }
        out.push((k.clone(), v.clone()));
    }
    out
}

/// Current wall-clock time in Unix milliseconds.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Clamp terminal dimensions into the safe VT100 envelope.
pub fn clamp_dims(cols: u16, rows: u16) -> (u16, u16) {
    let c = if cols == 0 { 80 } else { cols.min(MAX_COLS) };
    let r = if rows == 0 { 24 } else { rows.min(MAX_ROWS) };
    (c, r)
}
