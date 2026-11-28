// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Local daemon ↔ `meshharbord ssh-pty-host` IPC framing.
//!
//! Shares the exact length-prefixed framing of `frame.rs`:
//! - `0x00`: **FROZEN FOREVER** `Terminate { reason, grace_ms }` — any future or
//!   past daemon version can terminate any PTY host version cleanly.
//! - `0x01..=0x50`: Verbatim `meshharbor-pty@v1` [`WireFrame`] relayed directly.
//! - `0x81..=0x88`: Daemon↔host lifecycle control frames.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use super::frame::{
    FrameError, WireFrame, encode_raw, is_wire_frame_type, json_decode, json_encode,
    read_raw_frame, write_raw_frame,
};
use super::{ExitStatusInfo, PersistStatus, RunAsDescriptor, SessionMode, TerminateReason};

/// **FROZEN FOREVER** IPC type tag for terminating a PTY host.
/// Never reassign or break backwards parsing of this frame!
pub const IPC_TYPE_TERMINATE: u8 = 0x00;
pub const IPC_TYPE_HOST_HELLO: u8 = 0x81;
pub const IPC_TYPE_SPAWN: u8 = 0x82;
pub const IPC_TYPE_SPAWNED: u8 = 0x83;
pub const IPC_TYPE_ATTACH_START: u8 = 0x84;
pub const IPC_TYPE_DAEMON_DETACHING: u8 = 0x85;
pub const IPC_TYPE_PING: u8 = 0x86;
pub const IPC_TYPE_PONG: u8 = 0x87;
pub const IPC_TYPE_SPAWN_ERROR: u8 = 0x88;

/// Lifecycle state reported by `ssh-pty-host` in `HostHello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    AwaitingSpawn,
    Running,
    Exited,
}

/// First frame emitted by `ssh-pty-host` on every accepted daemon IPC connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostHelloFrame {
    pub ipc_min: u16,
    pub ipc_max: u16,
    pub build: String,
    /// Exact canonical JSON bytes of `SessionDescriptor` covered by `seal`.
    pub descriptor_json: Vec<u8>,
    pub seal: [u8; 32],
    pub state: HostState,
    pub s2c_head: u64,
    pub c2s_next: u64,
    pub attached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<ExitStatusInfo>,
    pub persist: PersistStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_name: Option<String>,
}

/// Sent on the first daemon→host connection immediately after `HostHello` when
/// `state == HostState::AwaitingSpawn`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnSpec {
    pub mode: SessionMode,
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<(String, String)>,
    pub run_as: RunAsDescriptor,
    pub ring_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnedFrame {
    pub child_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnErrorFrame {
    pub message: String,
}

/// Sent by the daemon when a verified SSH client attaches to an adopted or live host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachStartFrame {
    pub last_rx: u64,
    pub c2s_next_client: u64,
    pub cols: u16,
    pub rows: u16,
    pub snapshot_allowed: bool,
    /// Server proof computed by the daemon (host holds zero secrets) so the
    /// host can immediately emit `WireFrame::Attached` followed by replay/snapshot.
    pub server_proof: [u8; 32],
}

/// Sent by the daemon before restarting/updating (bounded <= 300 ms).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonDetachingFrame {
    pub eta_ms: u64,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
}

/// Frozen `0x00` kill payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateFrame {
    #[serde(default = "default_terminate_reason")]
    pub reason: TerminateReason,
    #[serde(default = "default_grace_ms")]
    pub grace_ms: u32,
}

fn default_terminate_reason() -> TerminateReason {
    TerminateReason::Revoked
}

fn default_grace_ms() -> u32 {
    1500
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcFrame {
    Terminate(TerminateFrame),
    HostHello(HostHelloFrame),
    Spawn(SpawnSpec),
    Spawned(SpawnedFrame),
    SpawnError(SpawnErrorFrame),
    AttachStart(AttachStartFrame),
    DaemonDetaching(DaemonDetachingFrame),
    Ping { t_ms: u64 },
    Pong { t_ms: u64 },
    Wire(WireFrame),
}

impl IpcFrame {
    pub fn encode_parts(&self) -> Result<(u8, Vec<u8>), FrameError> {
        match self {
            Self::Terminate(t) => Ok((IPC_TYPE_TERMINATE, json_encode(IPC_TYPE_TERMINATE, t)?)),
            Self::HostHello(h) => Ok((IPC_TYPE_HOST_HELLO, json_encode(IPC_TYPE_HOST_HELLO, h)?)),
            Self::Spawn(s) => Ok((IPC_TYPE_SPAWN, json_encode(IPC_TYPE_SPAWN, s)?)),
            Self::Spawned(s) => Ok((IPC_TYPE_SPAWNED, json_encode(IPC_TYPE_SPAWNED, s)?)),
            Self::SpawnError(e) => {
                Ok((IPC_TYPE_SPAWN_ERROR, json_encode(IPC_TYPE_SPAWN_ERROR, e)?))
            }
            Self::AttachStart(a) => Ok((
                IPC_TYPE_ATTACH_START,
                json_encode(IPC_TYPE_ATTACH_START, a)?,
            )),
            Self::DaemonDetaching(d) => Ok((
                IPC_TYPE_DAEMON_DETACHING,
                json_encode(IPC_TYPE_DAEMON_DETACHING, d)?,
            )),
            Self::Ping { t_ms } => Ok((IPC_TYPE_PING, t_ms.to_be_bytes().to_vec())),
            Self::Pong { t_ms } => Ok((IPC_TYPE_PONG, t_ms.to_be_bytes().to_vec())),
            Self::Wire(w) => w.encode_parts(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let (ty, body) = self.encode_parts()?;
        encode_raw(ty, &body)
    }

    pub fn decode_parts(frame_type: u8, body: &[u8]) -> Result<Self, FrameError> {
        match frame_type {
            // Frozen 0x00 Terminate: tolerate empty or future-schema payloads so
            // any version can ALWAYS kill a host!
            IPC_TYPE_TERMINATE => {
                let parsed = if body.is_empty() {
                    TerminateFrame {
                        reason: TerminateReason::Revoked,
                        grace_ms: default_grace_ms(),
                    }
                } else {
                    serde_json::from_slice(body).unwrap_or(TerminateFrame {
                        reason: TerminateReason::Revoked,
                        grace_ms: default_grace_ms(),
                    })
                };
                Ok(Self::Terminate(parsed))
            }
            IPC_TYPE_HOST_HELLO => Ok(Self::HostHello(json_decode(frame_type, body)?)),
            IPC_TYPE_SPAWN => Ok(Self::Spawn(json_decode(frame_type, body)?)),
            IPC_TYPE_SPAWNED => Ok(Self::Spawned(json_decode(frame_type, body)?)),
            IPC_TYPE_SPAWN_ERROR => Ok(Self::SpawnError(json_decode(frame_type, body)?)),
            IPC_TYPE_ATTACH_START => Ok(Self::AttachStart(json_decode(frame_type, body)?)),
            IPC_TYPE_DAEMON_DETACHING => Ok(Self::DaemonDetaching(json_decode(frame_type, body)?)),
            IPC_TYPE_PING => {
                if body.len() != 8 {
                    return Err(FrameError::Malformed(
                        frame_type,
                        "ipc ping must be 8 bytes".into(),
                    ));
                }
                Ok(Self::Ping {
                    t_ms: u64::from_be_bytes(body[0..8].try_into().unwrap()),
                })
            }
            IPC_TYPE_PONG => {
                if body.len() != 8 {
                    return Err(FrameError::Malformed(
                        frame_type,
                        "ipc pong must be 8 bytes".into(),
                    ));
                }
                Ok(Self::Pong {
                    t_ms: u64::from_be_bytes(body[0..8].try_into().unwrap()),
                })
            }
            ty if is_wire_frame_type(ty) => WireFrame::decode_parts(ty, body).map(Self::Wire),
            other => Err(FrameError::UnknownType(other)),
        }
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Self>, FrameError> {
        let Some((ty, body)) = read_raw_frame(r).await? else {
            return Ok(None);
        };
        Self::decode_parts(ty, &body).map(Some)
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), FrameError> {
        let (ty, body) = self.encode_parts()?;
        write_raw_frame(w, ty, &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_frozen_0x00_terminate_accepts_any_payload() {
        // Empty payload still decodes as Terminate.
        let got = IpcFrame::decode_parts(IPC_TYPE_TERMINATE, &[]).expect("empty 0x00");
        assert!(matches!(got, IpcFrame::Terminate(_)));

        // Unknown future payload still decodes as Terminate.
        let got2 =
            IpcFrame::decode_parts(IPC_TYPE_TERMINATE, b"{\"future\":99}").expect("future 0x00");
        assert!(matches!(got2, IpcFrame::Terminate(_)));

        // Standard roundtrip.
        let f = IpcFrame::Terminate(TerminateFrame {
            reason: TerminateReason::CloseAccess,
            grace_ms: 500,
        });
        let (ty, body) = f.encode_parts().unwrap();
        assert_eq!(ty, 0x00);
        assert_eq!(IpcFrame::decode_parts(ty, &body).unwrap(), f);
    }
}
