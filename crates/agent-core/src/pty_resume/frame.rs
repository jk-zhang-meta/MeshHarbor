// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Wire protocol framing and codec for `meshharbor-pty@v1`.
//!
//! Frame layout (both SSH subsystem wire and local IPC):
//! ```text
//! [u32 BE length (1..=MAX_FRAME_BYTES)] [u8 frame_type] [payload (length - 1 bytes)]
//! ```
//! High-frequency data frames (`Data`, `Ack`, `Snapshot`, `Resize`, `Ping`, `Pong`)
//! use compact binary payloads with zero base64 expansion; low-frequency control
//! frames use forward-compatible JSON payloads.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    ExitStatusInfo, MAX_DATA_CHUNK, MAX_FRAME_BYTES, NoticeKind, PersistStatus, RefuseReason,
    ReplayKind, SessionId, SessionMode, SignalKind,
};

pub const WIRE_HELLO: u8 = 0x01;
pub const WIRE_OPEN: u8 = 0x02;
pub const WIRE_OPENED: u8 = 0x03;
pub const WIRE_ATTACH: u8 = 0x04;
pub const WIRE_ATTACHED: u8 = 0x05;
pub const WIRE_DATA: u8 = 0x10;
pub const WIRE_ACK: u8 = 0x11;
pub const WIRE_SNAPSHOT: u8 = 0x12;
pub const WIRE_RESIZE: u8 = 0x13;
pub const WIRE_SIGNAL: u8 = 0x14;
pub const WIRE_EOF: u8 = 0x15;
pub const WIRE_PING: u8 = 0x20;
pub const WIRE_PONG: u8 = 0x21;
pub const WIRE_NOTICE: u8 = 0x30;
pub const WIRE_EXITED: u8 = 0x40;
pub const WIRE_DETACH: u8 = 0x41;
pub const WIRE_TERMINATE: u8 = 0x42;
pub const WIRE_REFUSED: u8 = 0x50;

/// Returns `true` if `frame_type` is in the `meshharbor-pty@v1` wire range.
pub const fn is_wire_frame_type(frame_type: u8) -> bool {
    matches!(
        frame_type,
        WIRE_HELLO
            | WIRE_OPEN
            | WIRE_OPENED
            | WIRE_ATTACH
            | WIRE_ATTACHED
            | WIRE_DATA
            | WIRE_ACK
            | WIRE_SNAPSHOT
            | WIRE_RESIZE
            | WIRE_SIGNAL
            | WIRE_EOF
            | WIRE_PING
            | WIRE_PONG
            | WIRE_NOTICE
            | WIRE_EXITED
            | WIRE_DETACH
            | WIRE_TERMINATE
            | WIRE_REFUSED
    )
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame length {0} out of bounds (1..={MAX_FRAME_BYTES})")]
    InvalidLength(u32),
    #[error("unknown frame type 0x{0:02x}")]
    UnknownType(u8),
    #[error("malformed payload for frame 0x{0:02x}: {1}")]
    Malformed(u8, String),
    #[error("data chunk {0} exceeds {MAX_DATA_CHUNK} bytes")]
    DataTooLarge(usize),
}

/// Wire messages exchanged over SSH subsystem `meshharbor-pty@v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireFrame {
    Hello(HelloFrame),
    Open(OpenFrame),
    Opened(OpenedFrame),
    Attach(AttachFrame),
    Attached(AttachedFrame),
    Data {
        stream: u8,
        seq: u64,
        bytes: Vec<u8>,
    },
    Ack {
        stream: u8,
        upto: u64,
    },
    Snapshot {
        at_seq: u64,
        alt_screen: bool,
        cols: u16,
        rows: u16,
        bytes: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Signal {
        signal: SignalKind,
    },
    Eof {
        stream: u8,
    },
    Ping {
        t_ms: u64,
    },
    Pong {
        t_ms: u64,
    },
    Notice(NoticeKind),
    Exited(ExitStatusInfo),
    Detach,
    Terminate,
    Refused(RefuseReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloFrame {
    pub proto_max: u16,
    pub server_nonce: [u8; 32],
    #[serde(default)]
    pub caps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFrame {
    pub mode: SessionMode,
    #[serde(default)]
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedFrame {
    pub session_id: SessionId,
    pub resume_secret: [u8; 32],
    pub persist: PersistStatus,
    pub deadline_ms: u64,
    pub detach_ttl_ms: u64,
    pub ring_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachFrame {
    pub session_id: SessionId,
    pub client_nonce: [u8; 32],
    pub proof: [u8; 32],
    /// Cumulative stdout/pty byte offset already received by the client.
    pub last_rx: u64,
    /// Optional stderr byte offset for pipes mode.
    #[serde(default)]
    pub last_rx_stderr: u64,
    /// Next c2s byte offset the client intends to send (informational).
    pub c2s_next: u64,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachedFrame {
    pub server_proof: [u8; 32],
    pub replay: ReplayKind,
    pub gap_bytes: u64,
    /// Cumulative c2s byte offset already written into the PTY by the host.
    pub c2s_acked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignalPayload {
    signal: SignalKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EofPayload {
    stream: u8,
}

impl WireFrame {
    /// Encode into `(frame_type, body)` without the 4-byte length prefix.
    pub fn encode_parts(&self) -> Result<(u8, Vec<u8>), FrameError> {
        let (ty, body) = match self {
            Self::Hello(h) => (WIRE_HELLO, json_encode(WIRE_HELLO, h)?),
            Self::Open(o) => (WIRE_OPEN, json_encode(WIRE_OPEN, o)?),
            Self::Opened(o) => (WIRE_OPENED, json_encode(WIRE_OPENED, o)?),
            Self::Attach(a) => (WIRE_ATTACH, json_encode(WIRE_ATTACH, a)?),
            Self::Attached(a) => (WIRE_ATTACHED, json_encode(WIRE_ATTACHED, a)?),
            Self::Data { stream, seq, bytes } => {
                if bytes.len() > MAX_DATA_CHUNK {
                    return Err(FrameError::DataTooLarge(bytes.len()));
                }
                let mut buf = Vec::with_capacity(9 + bytes.len());
                buf.push(*stream);
                buf.extend_from_slice(&seq.to_be_bytes());
                buf.extend_from_slice(bytes);
                (WIRE_DATA, buf)
            }
            Self::Ack { stream, upto } => {
                let mut buf = Vec::with_capacity(9);
                buf.push(*stream);
                buf.extend_from_slice(&upto.to_be_bytes());
                (WIRE_ACK, buf)
            }
            Self::Snapshot {
                at_seq,
                alt_screen,
                cols,
                rows,
                bytes,
            } => {
                let mut buf = Vec::with_capacity(13 + bytes.len());
                buf.extend_from_slice(&at_seq.to_be_bytes());
                buf.push(u8::from(*alt_screen));
                buf.extend_from_slice(&cols.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
                buf.extend_from_slice(bytes);
                (WIRE_SNAPSHOT, buf)
            }
            Self::Resize { cols, rows } => {
                let mut buf = Vec::with_capacity(4);
                buf.extend_from_slice(&cols.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
                (WIRE_RESIZE, buf)
            }
            Self::Signal { signal } => (
                WIRE_SIGNAL,
                json_encode(WIRE_SIGNAL, &SignalPayload { signal: *signal })?,
            ),
            Self::Eof { stream } => (
                WIRE_EOF,
                json_encode(WIRE_EOF, &EofPayload { stream: *stream })?,
            ),
            Self::Ping { t_ms } => (WIRE_PING, t_ms.to_be_bytes().to_vec()),
            Self::Pong { t_ms } => (WIRE_PONG, t_ms.to_be_bytes().to_vec()),
            Self::Notice(n) => (WIRE_NOTICE, json_encode(WIRE_NOTICE, n)?),
            Self::Exited(e) => (WIRE_EXITED, json_encode(WIRE_EXITED, e)?),
            Self::Detach => (WIRE_DETACH, Vec::new()),
            Self::Terminate => (WIRE_TERMINATE, Vec::new()),
            Self::Refused(r) => (WIRE_REFUSED, json_encode(WIRE_REFUSED, r)?),
        };
        if 1 + body.len() > MAX_FRAME_BYTES {
            return Err(FrameError::InvalidLength((1 + body.len()) as u32));
        }
        Ok((ty, body))
    }

    /// Encode with 4-byte BE length prefix and 1-byte type tag.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let (ty, body) = self.encode_parts()?;
        encode_raw(ty, &body)
    }

    /// Decode from `(frame_type, body)`.
    pub fn decode_parts(frame_type: u8, body: &[u8]) -> Result<Self, FrameError> {
        match frame_type {
            WIRE_HELLO => Ok(Self::Hello(json_decode(frame_type, body)?)),
            WIRE_OPEN => Ok(Self::Open(json_decode(frame_type, body)?)),
            WIRE_OPENED => Ok(Self::Opened(json_decode(frame_type, body)?)),
            WIRE_ATTACH => Ok(Self::Attach(json_decode(frame_type, body)?)),
            WIRE_ATTACHED => Ok(Self::Attached(json_decode(frame_type, body)?)),
            WIRE_DATA => {
                if body.len() < 9 {
                    return Err(FrameError::Malformed(frame_type, "data frame too short".into()));
                }
                let payload = &body[9..];
                if payload.len() > MAX_DATA_CHUNK {
                    return Err(FrameError::DataTooLarge(payload.len()));
                }
                let stream = body[0];
                let seq = u64::from_be_bytes(body[1..9].try_into().unwrap());
                Ok(Self::Data {
                    stream,
                    seq,
                    bytes: payload.to_vec(),
                })
            }
            WIRE_ACK => {
                if body.len() != 9 {
                    return Err(FrameError::Malformed(frame_type, "ack frame must be 9 bytes".into()));
                }
                Ok(Self::Ack {
                    stream: body[0],
                    upto: u64::from_be_bytes(body[1..9].try_into().unwrap()),
                })
            }
            WIRE_SNAPSHOT => {
                if body.len() < 13 {
                    return Err(FrameError::Malformed(
                        frame_type,
                        "snapshot frame too short".into(),
                    ));
                }
                let at_seq = u64::from_be_bytes(body[0..8].try_into().unwrap());
                let alt_screen = body[8] != 0;
                let cols = u16::from_be_bytes(body[9..11].try_into().unwrap());
                let rows = u16::from_be_bytes(body[11..13].try_into().unwrap());
                Ok(Self::Snapshot {
                    at_seq,
                    alt_screen,
                    cols,
                    rows,
                    bytes: body[13..].to_vec(),
                })
            }
            WIRE_RESIZE => {
                if body.len() != 4 {
                    return Err(FrameError::Malformed(
                        frame_type,
                        "resize frame must be 4 bytes".into(),
                    ));
                }
                Ok(Self::Resize {
                    cols: u16::from_be_bytes(body[0..2].try_into().unwrap()),
                    rows: u16::from_be_bytes(body[2..4].try_into().unwrap()),
                })
            }
            WIRE_SIGNAL => {
                let p: SignalPayload = json_decode(frame_type, body)?;
                Ok(Self::Signal { signal: p.signal })
            }
            WIRE_EOF => {
                let p: EofPayload = json_decode(frame_type, body)?;
                Ok(Self::Eof { stream: p.stream })
            }
            WIRE_PING => {
                if body.len() != 8 {
                    return Err(FrameError::Malformed(frame_type, "ping must be 8 bytes".into()));
                }
                Ok(Self::Ping {
                    t_ms: u64::from_be_bytes(body[0..8].try_into().unwrap()),
                })
            }
            WIRE_PONG => {
                if body.len() != 8 {
                    return Err(FrameError::Malformed(frame_type, "pong must be 8 bytes".into()));
                }
                Ok(Self::Pong {
                    t_ms: u64::from_be_bytes(body[0..8].try_into().unwrap()),
                })
            }
            WIRE_NOTICE => Ok(Self::Notice(json_decode(frame_type, body)?)),
            WIRE_EXITED => Ok(Self::Exited(json_decode(frame_type, body)?)),
            WIRE_DETACH => Ok(Self::Detach),
            WIRE_TERMINATE => Ok(Self::Terminate),
            WIRE_REFUSED => Ok(Self::Refused(json_decode(frame_type, body)?)),
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

/// Encode `(frame_type, body)` into a length-prefixed buffer.
pub fn encode_raw(frame_type: u8, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    let total = 1usize
        .checked_add(body.len())
        .ok_or(FrameError::InvalidLength(u32::MAX))?;
    if total > MAX_FRAME_BYTES {
        return Err(FrameError::InvalidLength(total as u32));
    }
    let mut out = Vec::with_capacity(4 + total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.push(frame_type);
    out.extend_from_slice(body);
    Ok(out)
}

/// Read one length-prefixed raw frame from an async stream.
/// Returns `Ok(None)` on clean EOF before the header begins.
pub async fn read_raw_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<(u8, Vec<u8>)>, FrameError> {
    let mut len_buf = [0u8; 4];
    let first = match r.read_exact(&mut len_buf[..1]).await {
        Ok(_) => len_buf[0],
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    };
    len_buf[0] = first;
    r.read_exact(&mut len_buf[1..]).await?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || (len as usize) > MAX_FRAME_BYTES {
        return Err(FrameError::InvalidLength(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    let ty = payload[0];
    let body = payload.split_off(1);
    Ok(Some((ty, body)))
}

/// Write one length-prefixed raw frame to an async stream and flush.
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame_type: u8,
    body: &[u8],
) -> Result<(), FrameError> {
    let raw = encode_raw(frame_type, body)?;
    w.write_all(&raw).await?;
    w.flush().await?;
    Ok(())
}

/// Incremental non-async decoder for SSH channel data chunks (e.g. `russh` callbacks).
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete `(frame_type, body)` if buffered.
    pub fn next_raw(&mut self) -> Result<Option<(u8, Vec<u8>)>, FrameError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.buf[0..4].try_into().unwrap());
        if len == 0 || (len as usize) > MAX_FRAME_BYTES {
            self.buf.clear();
            return Err(FrameError::InvalidLength(len));
        }
        let need = 4 + len as usize;
        if self.buf.len() < need {
            return Ok(None);
        }
        let ty = self.buf[4];
        let body = self.buf[5..need].to_vec();
        self.buf.drain(..need);
        Ok(Some((ty, body)))
    }

    pub fn next_wire(&mut self) -> Result<Option<WireFrame>, FrameError> {
        let Some((ty, body)) = self.next_raw()? else {
            return Ok(None);
        };
        WireFrame::decode_parts(ty, &body).map(Some)
    }

    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}

pub(crate) fn json_encode<T: Serialize>(ty: u8, value: &T) -> Result<Vec<u8>, FrameError> {
    serde_json::to_vec(value).map_err(|e| FrameError::Malformed(ty, e.to_string()))
}

pub(crate) fn json_decode<T: for<'de> Deserialize<'de>>(
    ty: u8,
    body: &[u8],
) -> Result<T, FrameError> {
    serde_json::from_slice(body).map_err(|e| FrameError::Malformed(ty, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_wire_frame_roundtrip_all_variants() {
        let sid = SessionId::generate();
        let samples = vec![
            WireFrame::Hello(HelloFrame {
                proto_max: 1,
                server_nonce: [7u8; 32],
                caps: vec!["snapshot".into()],
            }),
            WireFrame::Open(OpenFrame {
                mode: SessionMode::Pty,
                term: "xterm-256color".into(),
                cols: 120,
                rows: 40,
                command: Some("htop".into()),
                env: vec![("LANG".into(), "en_US.UTF-8".into())],
            }),
            WireFrame::Opened(OpenedFrame {
                session_id: sid,
                resume_secret: [3u8; 32],
                persist: PersistStatus::survives(),
                deadline_ms: 1_900_000_000_000,
                detach_ttl_ms: 43_200_000,
                ring_bytes: 4 * 1024 * 1024,
            }),
            WireFrame::Attach(AttachFrame {
                session_id: sid,
                client_nonce: [9u8; 32],
                proof: [11u8; 32],
                last_rx: 12345,
                last_rx_stderr: 0,
                c2s_next: 77,
                cols: 100,
                rows: 30,
            }),
            WireFrame::Attached(AttachedFrame {
                server_proof: [12u8; 32],
                replay: ReplayKind::Bytes,
                gap_bytes: 0,
                c2s_acked: 70,
            }),
            WireFrame::Data {
                stream: 1,
                seq: 9876543210,
                bytes: b"hello world\r\n".to_vec(),
            },
            WireFrame::Ack {
                stream: 1,
                upto: 9876543223,
            },
            WireFrame::Snapshot {
                at_seq: 5_000_000,
                alt_screen: true,
                cols: 80,
                rows: 24,
                bytes: b"\x1b[2Jhi".to_vec(),
            },
            WireFrame::Resize { cols: 132, rows: 50 },
            WireFrame::Signal {
                signal: SignalKind::Int,
            },
            WireFrame::Eof { stream: 0 },
            WireFrame::Ping { t_ms: 42 },
            WireFrame::Pong { t_ms: 42 },
            WireFrame::Notice(NoticeKind::TargetRestarting {
                reason: "update".into(),
                eta_ms: 8000,
                to_version: Some("0.4.219".into()),
            }),
            WireFrame::Exited(ExitStatusInfo::from_code(0)),
            WireFrame::Detach,
            WireFrame::Terminate,
            WireFrame::Refused(RefuseReason::Revoked {
                detail: "policy".into(),
            }),
        ];

        let mut dec = FrameDecoder::new();
        for f in &samples {
            let wire = f.encode().expect("encode");
            // Feed byte-by-byte to stress fragmentation.
            for chunk in wire.chunks(3) {
                dec.push(chunk);
            }
            let got = dec.next_wire().expect("decode").expect("complete");
            assert_eq!(&got, f);
        }
        assert!(dec.next_wire().expect("empty").is_none());
    }

    #[test]
    fn fr141_frame_rejects_oversized_and_zero_length() {
        let mut dec = FrameDecoder::new();
        dec.push(&0u32.to_be_bytes());
        assert!(matches!(dec.next_raw(), Err(FrameError::InvalidLength(0))));

        let mut dec2 = FrameDecoder::new();
        let huge = (MAX_FRAME_BYTES as u32) + 1;
        dec2.push(&huge.to_be_bytes());
        assert!(matches!(
            dec2.next_raw(),
            Err(FrameError::InvalidLength(n)) if n == huge
        ));
    }
}
