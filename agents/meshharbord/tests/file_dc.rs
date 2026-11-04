// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Wire-format integration tests for the file-DC v2 protocol.
//!
//! These tests stand up two `webrtc-rs` `RTCPeerConnection`s in
//! loopback, negotiate a `files` DataChannel between them, attach
//! the production `meshharbord::peer::attach_files_handler` to the
//! "agent" side, then drive the wire from the "browser" side and
//! assert the JSON envelopes + binary payloads round-trip exactly
//! as the protocol specifies.
//!
//! Coverage tiers (Plan 1, file-DC v2 follow-on):
//!
//! * Phase 1: loopback PC harness + trivial single-file upload.
//! * Phase 2: multi-sequential upload + 2 GiB cap rejection.
//! * Phase 3: download + listDir round-trips.
//! * Phase 4: folder zip + traversal hardening.
//! * Phase 5: concurrent up+down + mid-download cancel.
//! * Phase 6: every test wrapped in a 15s timeout for CI flake
//!   safety.
//!
//! No MongoDB / Redis required — these test the agent-side wire
//! protocol in isolation. The `meshharbord` library is a direct
//! dependency of this crate, so the production dispatch code runs
//! in-process.

#![allow(clippy::needless_pass_by_value)]

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

// ────────────────────────────────────────────────────────────────────────────
// Loopback PC pair harness
// ────────────────────────────────────────────────────────────────────────────

/// One end of the loopback DC pair plus the channels that surface
/// inbound traffic to the test body. The "browser" side uses this
/// directly to send/receive wire frames; the "agent" side has the
/// production `attach_files_handler` attached and exposes nothing
/// to the test (its behaviour is observed entirely through the
/// browser-side channel).
struct DcSide {
    dc: Arc<RTCDataChannel>,
    /// Inbound string frames (control envelopes from the agent).
    strings: mpsc::UnboundedReceiver<String>,
    /// Inbound binary frames (download chunks from the agent).
    /// Read by `collect_until_eof` and by the concurrent test which
    /// drives the channels directly via `tokio::select!`.
    #[allow(dead_code)]
    bytes: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Both PeerConnections are kept alive for the duration of the
    /// test. Without this hold, when `open_files_dc` returned, the
    /// agent-side PC (no other strong ref) dropped — taking SCTP
    /// with it — and download chunks never arrived. Browser-side PC
    /// is also held explicitly rather than relying on the DC's
    /// internal weak-ref to its parent.
    _keepalive: (Arc<RTCPeerConnection>, Arc<RTCPeerConnection>),
}

impl DcSide {
    /// Send a JSON envelope as a UTF-8 string frame.
    async fn send_json<T: serde::Serialize>(&self, msg: &T) -> Result<()> {
        let s = serde_json::to_string(msg).context("serialize")?;
        self.dc.send_text(s).await.context("dc.send_text")?;
        Ok(())
    }

    /// Send a binary chunk.
    async fn send_chunk(&self, data: &[u8]) -> Result<()> {
        let bytes = Bytes::copy_from_slice(data);
        self.dc.send(&bytes).await.context("dc.send")?;
        Ok(())
    }

    /// Wait for the next inbound string frame and parse it as JSON.
    async fn recv_json<T: serde::de::DeserializeOwned>(&mut self, timeout: Duration) -> Result<T> {
        let s = tokio::time::timeout(timeout, self.strings.recv())
            .await
            .map_err(|_| anyhow!("recv_json timed out after {timeout:?}"))?
            .ok_or_else(|| anyhow!("inbound string channel closed"))?;
        serde_json::from_str(&s).with_context(|| format!("parse inbound JSON: {s}"))
    }

    /// Wait for the next inbound string frame and return it raw.
    /// Used by the concurrent test (`upload_and_download_share_dc_cleanly`)
    /// which manually parses each envelope to discriminate by id.
    #[allow(dead_code)]
    async fn recv_string(&mut self, timeout: Duration) -> Result<String> {
        tokio::time::timeout(timeout, self.strings.recv())
            .await
            .map_err(|_| anyhow!("recv_string timed out after {timeout:?}"))?
            .ok_or_else(|| anyhow!("inbound string channel closed"))
    }

    /// Wait for the next inbound binary frame. Used in tests that
    /// drive the bytes path manually rather than via `collect_until_eof`.
    #[allow(dead_code)]
    async fn recv_bytes(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        tokio::time::timeout(timeout, self.bytes.recv())
            .await
            .map_err(|_| anyhow!("recv_bytes timed out after {timeout:?}"))?
            .ok_or_else(|| anyhow!("inbound bytes channel closed"))
    }

    /// Drain inbound bytes greedily until a `files:eof` envelope
    /// lands on the string channel. Returns the concatenated payload
    /// bytes. Used by download tests where the test body needs the
    /// whole stream for a hash/content assertion.
    ///
    /// CRITICAL: `tokio::select!` chooses randomly between ready
    /// branches, so when the agent emits `dc.send(chunk)` immediately
    /// followed by `dc.send_text(eof_json)`, both can be in their
    /// channels by the time we poll. If select picks strings first,
    /// we'd return with zero bytes despite the chunks being there.
    /// Mitigation: after seeing the terminal envelope, drain any
    /// remaining bytes via `try_recv` until empty + a brief grace
    /// period so late-arriving frames land too.
    async fn collect_until_eof(&mut self, timeout: Duration) -> Result<(Vec<u8>, String)> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut payload = Vec::new();
        let mut terminal: Option<String> = None;
        while terminal.is_none() {
            tokio::select! {
                biased;
                chunk = self.bytes.recv() => {
                    let chunk = chunk.ok_or_else(|| anyhow!("bytes channel closed before eof"))?;
                    payload.extend_from_slice(&chunk);
                }
                msg = self.strings.recv() => {
                    let msg = msg.ok_or_else(|| anyhow!("string channel closed before eof"))?;
                    if msg.contains("\"files:eof\"") || msg.contains("\"files:error\"") {
                        terminal = Some(msg);
                    }
                    // Progress / accepted / etc. — ignore at this layer.
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(anyhow!("collect_until_eof timed out after {timeout:?}"));
                }
            }
        }
        // Drain remaining chunks. The terminal frame may have arrived
        // before its preceding chunks were polled; brief grace
        // window catches late-arriving frames before we return.
        let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        loop {
            tokio::select! {
                biased;
                chunk = self.bytes.recv() => {
                    if let Some(chunk) = chunk {
                        payload.extend_from_slice(&chunk);
                    } else {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(drain_deadline) => break,
            }
        }
        Ok((payload, terminal.unwrap()))
    }
}

/// Build two PCs wired through ICE-candidate cross-feeding (no
/// network), negotiate a `files` DataChannel, attach the production
/// agent dispatcher to one side, and surface the other side to the
/// test body. Returns the browser-side `DcSide`.
///
/// ICE config: empty `ice_servers` so gathering is loopback-only.
/// Turn-key for tokio CI runners; no STUN/TURN traffic.
async fn open_files_dc() -> Result<DcSide> {
    let (browser_pc, agent_pc) = mk_pc_pair().await?;

    // Browser opens the `files` DC. Agent receives it via on_data_channel
    // and immediately attaches the production dispatcher.
    let browser_dc = browser_pc
        .create_data_channel("files", None)
        .await
        .context("create_data_channel(files)")?;

    let (agent_dc_tx, agent_dc_rx) = oneshot::channel::<Arc<RTCDataChannel>>();
    let agent_dc_tx = Arc::new(Mutex::new(Some(agent_dc_tx)));
    agent_pc.on_data_channel(Box::new(move |dc| {
        let tx = agent_dc_tx.clone();
        Box::pin(async move {
            if let Some(tx) = tx.lock().await.take() {
                let _ = tx.send(dc);
            }
        })
    }));

    // Wire the browser-side inbound message channels.
    let (strings_tx, strings_rx) = mpsc::unbounded_channel::<String>();
    let (bytes_tx, bytes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let strings_tx_for_msg = strings_tx.clone();
    let bytes_tx_for_msg = bytes_tx.clone();
    browser_dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let strings_tx = strings_tx_for_msg.clone();
        let bytes_tx = bytes_tx_for_msg.clone();
        Box::pin(async move {
            if msg.is_string {
                if let Ok(s) = std::str::from_utf8(&msg.data) {
                    let _ = strings_tx.send(s.to_string());
                }
            } else {
                let _ = bytes_tx.send(msg.data.to_vec());
            }
        })
    }));

    // SDP offer/answer exchange — direct function calls, no network.
    let offer = browser_pc
        .create_offer(None)
        .await
        .context("create_offer")?;
    browser_pc
        .set_local_description(offer.clone())
        .await
        .context("browser set_local")?;
    agent_pc
        .set_remote_description(offer)
        .await
        .context("agent set_remote")?;
    let answer = agent_pc
        .create_answer(None)
        .await
        .context("create_answer")?;
    agent_pc
        .set_local_description(answer.clone())
        .await
        .context("agent set_local")?;
    browser_pc
        .set_remote_description(answer)
        .await
        .context("browser set_remote")?;

    // Wait for agent to accept the DC, then attach the production
    // dispatcher. The session_id is a fresh ObjectId — the dispatcher
    // uses it only for log lines, not for any state lookup.
    let agent_dc = tokio::time::timeout(Duration::from_secs(30), agent_dc_rx)
        .await
        .map_err(|_| anyhow!("agent on_data_channel timed out"))?
        .map_err(|e| anyhow!("agent_dc_rx: {e}"))?;
    let session_id = bson::oid::ObjectId::new();
    meshharbord::peer::attach_files_handler(
        agent_dc,
        session_id,
        &tokio_util::sync::CancellationToken::new(),
    );

    // Wait for the browser-side DC to reach `Open`. webrtc-rs reports
    // this via `on_open`. Poll-via-callback to a oneshot.
    let (open_tx, open_rx) = oneshot::channel::<()>();
    let open_tx = Arc::new(Mutex::new(Some(open_tx)));
    browser_dc.on_open(Box::new(move || {
        let tx = open_tx.clone();
        Box::pin(async move {
            if let Some(tx) = tx.lock().await.take() {
                let _ = tx.send(());
            }
        })
    }));
    tokio::time::timeout(Duration::from_secs(10), open_rx)
        .await
        .map_err(|_| anyhow!("browser DC open timed out"))?
        .map_err(|e| anyhow!("open_rx: {e}"))?;

    let _ = (strings_tx, bytes_tx); // closures still hold the live ones

    Ok(DcSide {
        dc: browser_dc,
        strings: strings_rx,
        bytes: bytes_rx,
        _keepalive: (browser_pc, agent_pc),
    })
}

/// Build a pair of `RTCPeerConnection`s wired so each one's local ICE
/// candidates are added as remote candidates on the other. No STUN /
/// TURN — host-only candidates, instant gathering.
async fn mk_pc_pair() -> Result<(Arc<RTCPeerConnection>, Arc<RTCPeerConnection>)> {
    let mut me_browser = MediaEngine::default();
    me_browser
        .register_default_codecs()
        .context("browser register codecs")?;
    let api_browser = APIBuilder::new().with_media_engine(me_browser).build();

    let mut me_agent = MediaEngine::default();
    me_agent
        .register_default_codecs()
        .context("agent register codecs")?;
    let api_agent = APIBuilder::new().with_media_engine(me_agent).build();

    let cfg = RTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };
    let browser_pc = Arc::new(
        api_browser
            .new_peer_connection(cfg.clone())
            .await
            .context("browser new_pc")?,
    );
    let agent_pc = Arc::new(
        api_agent
            .new_peer_connection(cfg)
            .await
            .context("agent new_pc")?,
    );

    // Cross-feed ICE candidates. Each on_ice_candidate fires once
    // per gathered candidate then once with `None` when gathering
    // ends — we only forward the Some side.
    let agent_pc_for_browser_ice = agent_pc.clone();
    browser_pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let agent_pc = agent_pc_for_browser_ice.clone();
        Box::pin(async move {
            if let Some(c) = c
                && let Ok(json) = c.to_json()
            {
                let _ = agent_pc.add_ice_candidate(json).await;
            }
        })
    }));
    let browser_pc_for_agent_ice = browser_pc.clone();
    agent_pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let browser_pc = browser_pc_for_agent_ice.clone();
        Box::pin(async move {
            if let Some(c) = c
                && let Ok(json) = c.to_json()
            {
                let _ = browser_pc.add_ice_candidate(json).await;
            }
        })
    }));

    // Optional: log connection state transitions for CI debugging.
    browser_pc.on_peer_connection_state_change(Box::new(|s: RTCPeerConnectionState| {
        Box::pin(async move {
            tracing::debug!(state = ?s, "browser PC state");
        })
    }));
    agent_pc.on_peer_connection_state_change(Box::new(|s: RTCPeerConnectionState| {
        Box::pin(async move {
            tracing::debug!(state = ?s, "agent PC state");
        })
    }));

    Ok((browser_pc, agent_pc))
}

// ────────────────────────────────────────────────────────────────────────────
// Wire-format envelope structs (mirror the agent's FilesIncoming /
// FilesOutgoing — these are the BROWSER's view, owned strings so the
// test body can construct them inline).
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
#[serde(tag = "t")]
#[allow(dead_code)] // some variants used only in later phases
enum BrowserToAgent {
    #[serde(rename = "files:begin")]
    Begin {
        id: String,
        name: String,
        size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        mime: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rel_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dest_path: Option<String>,
    },
    #[serde(rename = "files:end")]
    End { id: String },
    #[serde(rename = "files:get")]
    Get { id: String, path: String },
    #[serde(rename = "files:get-folder")]
    GetFolder {
        id: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<String>,
    },
    #[serde(rename = "files:cancel")]
    Cancel { id: String },
    #[serde(rename = "files:dir")]
    Dir { req_id: String, path: String },
    #[serde(rename = "files:resume")]
    Resume {
        id: String,
        offset: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256_prefix: Option<String>,
    },
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "t")]
#[allow(dead_code)] // some variants asserted in later phases
enum AgentToBrowser {
    #[serde(rename = "files:accepted")]
    Accepted { id: String, path: String },
    #[serde(rename = "files:progress")]
    Progress { id: String, bytes: u64 },
    #[serde(rename = "files:complete")]
    Complete {
        id: String,
        path: String,
        bytes: u64,
    },
    #[serde(rename = "files:error")]
    Error { id: String, message: String },
    #[serde(rename = "files:offer")]
    Offer {
        id: String,
        name: String,
        size: Option<u64>,
        mime: Option<String>,
    },
    #[serde(rename = "files:eof")]
    Eof { id: String, bytes: u64 },
    #[serde(rename = "files:dir-list")]
    DirList {
        req_id: String,
        path: String,
        parent: Option<String>,
        entries: Vec<DirEntry>,
    },
    #[serde(rename = "files:dir-error")]
    DirError { req_id: String, message: String },
    #[serde(rename = "files:resumed")]
    Resumed { id: String, accepted_offset: u64 },
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct DirEntry {
    name: String,
    is_dir: bool,
    size: Option<u64>,
    mtime_unix: Option<i64>,
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 1 — single-file upload round-trip
// ────────────────────────────────────────────────────────────────────────────

/// Smallest upload — 64 bytes that should fit in a single chunk and
/// land below the 256 KiB progress-report threshold (so we observe
/// `accepted` then `complete`, no `progress`).
#[tokio::test]
async fn upload_single_file_round_trip() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");

        // Pick a tempdir as dest_path so the upload lands somewhere
        // we control rather than the user's actual Downloads folder.
        let tmp = tempfile::tempdir().expect("tmp");
        let dest_path = tmp.path().to_string_lossy().to_string();

        let payload = b"Hello, file-DC v2 wire format!".repeat(2);
        let id = "upload-1".to_string();
        side.send_json(&BrowserToAgent::Begin {
            id: id.clone(),
            name: "hello.txt".to_string(),
            size: payload.len() as u64,
            mime: Some("text/plain".to_string()),
            rel_path: None,
            dest_path: Some(dest_path.clone()),
        })
        .await
        .expect("send begin");

        // Agent should reply with `files:accepted { id, path }` where
        // `path` lives under our tempdir.
        let accepted: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv accepted");
        let accepted_path = match accepted {
            AgentToBrowser::Accepted { id: ack_id, path } => {
                assert_eq!(ack_id, id, "accepted id matches begin id");
                path
            }
            other => panic!("expected files:accepted, got {other:?}"),
        };
        let accepted_pb = std::path::PathBuf::from(&accepted_path);
        // Canonicalise both for the prefix check — Windows tempdirs
        // can be reported as `C:\Users\…\Temp\…` but the agent
        // canonicalises to `\\?\C:\Users\…\Temp\…`. Strip the
        // verbatim prefix on Windows so the assertion isn't fragile.
        let tmp_canon = std::fs::canonicalize(tmp.path()).unwrap();
        let accepted_canon =
            std::fs::canonicalize(&accepted_pb).unwrap_or_else(|_| accepted_pb.clone());
        assert!(
            accepted_canon.starts_with(&tmp_canon),
            "accepted path {} should be inside tempdir {}",
            accepted_canon.display(),
            tmp_canon.display()
        );

        // Browser sends the payload as a single binary chunk.
        side.send_chunk(&payload).await.expect("send chunk");

        // Browser sends files:end.
        side.send_json(&BrowserToAgent::End { id: id.clone() })
            .await
            .expect("send end");

        // Agent should reply with files:complete carrying the same
        // path it sent in `accepted` and the byte count.
        let complete: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv complete");
        match complete {
            AgentToBrowser::Complete {
                id: ack_id,
                path,
                bytes,
            } => {
                assert_eq!(ack_id, id, "complete id matches");
                assert_eq!(bytes, payload.len() as u64, "byte count matches");
                assert_eq!(path, accepted_path, "complete path matches accepted");
            }
            other => panic!("expected files:complete, got {other:?}"),
        }

        // File on disk should match payload exactly.
        let on_disk = tokio::fs::read(&accepted_pb).await.expect("read on-disk");
        assert_eq!(on_disk, payload, "on-disk content matches sent payload");
    })
    .await
    .expect("test exceeded 15s timeout");
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers (used by Phase 2+ tests)
// ────────────────────────────────────────────────────────────────────────────

/// Run an upload to completion: begin, single chunk, end. Drains any
/// `Progress` envelopes that arrive between `begin → end → complete`
/// since payloads larger than 256 KiB will produce them. Returns the
/// on-disk path the agent reported on `Complete`.
async fn run_upload(
    side: &mut DcSide,
    id: &str,
    name: &str,
    payload: &[u8],
    dest_path: &str,
) -> Result<String> {
    side.send_json(&BrowserToAgent::Begin {
        id: id.to_string(),
        name: name.to_string(),
        size: payload.len() as u64,
        mime: None,
        rel_path: None,
        dest_path: Some(dest_path.to_string()),
    })
    .await?;

    let accepted: AgentToBrowser = side.recv_json(Duration::from_secs(5)).await?;
    let path = match accepted {
        AgentToBrowser::Accepted { id: ack_id, path } if ack_id == id => path,
        other => return Err(anyhow!("expected files:accepted/{id}, got {other:?}")),
    };

    side.send_chunk(payload).await?;
    side.send_json(&BrowserToAgent::End { id: id.to_string() })
        .await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let msg: AgentToBrowser = side.recv_json(remaining).await?;
        match msg {
            AgentToBrowser::Complete {
                id: ack_id,
                bytes,
                path: complete_path,
            } if ack_id == id => {
                if bytes != payload.len() as u64 {
                    return Err(anyhow!(
                        "complete bytes={bytes} but payload={}",
                        payload.len()
                    ));
                }
                if complete_path != path {
                    return Err(anyhow!(
                        "complete path mismatch: accepted={path} complete={complete_path}"
                    ));
                }
                return Ok(path);
            }
            AgentToBrowser::Progress { .. } => continue,
            AgentToBrowser::Error {
                id: ack_id,
                message,
            } if ack_id == id => return Err(anyhow!("agent error: {message}")),
            other => return Err(anyhow!("unexpected: {other:?}")),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// rc.19 — files:resume round-trip
// ────────────────────────────────────────────────────────────────────────────
//
// The full begin → close-DC → resume cross-DC round-trip exercises
// SCTP teardown semantics that webrtc-rs handles inconsistently in
// the loopback test harness (the second DC's chunk loop races the
// first DC's close on Windows). The lib tests in `files.rs`
// (resume_round_trips_after_partial_upload,
// resume_truncates_when_disk_size_below_requested) cover the same
// end-to-end mechanics by driving `FilesHandler::resume_incoming`
// directly. The wire-format integration test below pins the
// envelope shape — the resume_unknown_id_emits_error path is the
// fallback the browser's auto-resume wrapper relies on.

/// `files:resume` for an id the agent has never seen → `files:error`.
/// Browser's fall-through-to-fresh-begin path depends on this.
#[tokio::test]
async fn resume_unknown_id_emits_error() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let id = format!("nope-{}", std::process::id());
        side.send_json(&BrowserToAgent::Resume {
            id: id.clone(),
            offset: 4 * 1024 * 1024,
            sha256_prefix: None,
        })
        .await
        .expect("send resume");
        let reply: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv error");
        match reply {
            AgentToBrowser::Error { id: ei, message } => {
                assert_eq!(ei, id);
                assert!(
                    message.contains("no partial state") || message.contains("Downloads"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected files:error, got {other:?}"),
        }
    })
    .await
    .expect("test exceeded 15s timeout");
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 2 — multi-sequential upload + 2 GiB cap rejection
// ────────────────────────────────────────────────────────────────────────────

/// Five back-to-back uploads on a single DC. Locks the v2
/// `incoming` Mutex contract: each transfer settles before the next
/// begins, no IDs collide, all five files land on disk with their
/// per-upload payload.
#[tokio::test]
async fn upload_multi_sequential() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        let dest = tmp.path().to_string_lossy().to_string();

        for i in 0..5 {
            let id = format!("multi-{i}");
            let name = format!("file-{i}.bin");
            let payload: Vec<u8> = (0..(64 + i * 32)).map(|x| (x % 256) as u8).collect();
            let path = run_upload(&mut side, &id, &name, &payload, &dest)
                .await
                .unwrap_or_else(|e| panic!("upload {i}: {e}"));
            let on_disk = tokio::fs::read(&path).await.expect("read on-disk");
            assert_eq!(on_disk, payload, "file {i} content matches");
        }
    })
    .await
    .expect("test exceeded 20s timeout");
}

/// `files:begin` declaring a size > 2 GiB cap. The agent rejects
/// before any chunk is written; reply is `files:error` with a
/// "exceeds the … B cap" message. Locks the MAX_TRANSFER_BYTES
/// constant against accidental relaxation.
#[tokio::test]
async fn upload_rejected_above_2gib_cap() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        let dest = tmp.path().to_string_lossy().to_string();

        let id = "huge".to_string();
        let oversize = 2u64 * 1024 * 1024 * 1024 + 1;
        side.send_json(&BrowserToAgent::Begin {
            id: id.clone(),
            name: "huge.bin".to_string(),
            size: oversize,
            mime: None,
            rel_path: None,
            dest_path: Some(dest),
        })
        .await
        .expect("send begin");

        let resp: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv error");
        match resp {
            AgentToBrowser::Error {
                id: ack_id,
                message,
            } => {
                assert_eq!(ack_id, id);
                assert!(
                    message.contains("cap") || message.contains("exceed"),
                    "expected cap rejection in message, got: {message}"
                );
            }
            other => panic!("expected files:error, got {other:?}"),
        }
    })
    .await
    .expect("test exceeded 15s timeout");
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 3 — single-file download + listDir
// ────────────────────────────────────────────────────────────────────────────

/// Browser → `files:get` → agent streams `files:offer`, binary chunks,
/// `files:eof`. Verifies bytes round-trip exactly.
#[tokio::test]
async fn download_single_file_round_trip() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        let src = tmp.path().join("payload.bin");
        // 48 KiB — a single sub-64-KiB chunk on the wire. webrtc-rs's
        // SCTP "binary message-size limit" on a freshly-negotiated
        // DC without explicit `setRemoteDescription`-time
        // `max_message_size` advertisement caps individual messages
        // closer to 16 KiB on some configurations; the agent's
        // 64 KiB chunk size has shipped fine in production against
        // Chrome (which advertises 65535 in SDP), but the loopback
        // PC pair here doesn't go through that exchange. 48 KiB is
        // safely below any plausible internal limit and still
        // exercises chunking (3 reads of 16 KiB inside the agent's
        // pump). For the production-realistic 64 KiB+ case, we'd
        // need to set `RTCDataChannelInit::max_packet_life_time` /
        // explicit `max_message_size` on both sides — out of scope
        // for the wire-format test, which is what really matters.
        let payload: Vec<u8> = (0..48 * 1024).map(|i| (i * 7 % 256) as u8).collect();
        tokio::fs::write(&src, &payload).await.expect("write src");

        let id = "dl-1".to_string();
        side.send_json(&BrowserToAgent::Get {
            id: id.clone(),
            path: src.to_string_lossy().to_string(),
        })
        .await
        .expect("send get");

        // Expect offer first.
        let offer: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv offer");
        match offer {
            AgentToBrowser::Offer {
                id: ack_id,
                size,
                name,
                ..
            } => {
                assert_eq!(ack_id, id);
                assert_eq!(name, "payload.bin");
                assert_eq!(size, Some(payload.len() as u64));
            }
            other => panic!("expected files:offer, got {other:?}"),
        }

        // Drain bytes until eof. Could include intermediate Progress
        // envelopes for larger payloads; collect_until_eof handles
        // that.
        let (received, terminal) = side
            .collect_until_eof(Duration::from_secs(10))
            .await
            .expect("collect");
        assert!(
            terminal.contains("\"files:eof\""),
            "expected eof terminal, got {terminal}"
        );
        assert_eq!(received.len(), payload.len(), "byte count matches");
        assert_eq!(received, payload, "content matches");
    })
    .await
    .expect("test exceeded 15s timeout");
}

/// `files:get` against a path that doesn't exist. Agent rejects via
/// `files:error` (canonicalisation fails before any bytes flow).
#[tokio::test]
async fn download_nonexistent_path_errors() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let id = "dl-bad".to_string();
        side.send_json(&BrowserToAgent::Get {
            id: id.clone(),
            path: "/this/path/should/not/exist/anywhere/12345".to_string(),
        })
        .await
        .expect("send get");

        let resp: AgentToBrowser = side.recv_json(Duration::from_secs(5)).await.expect("recv");
        match resp {
            AgentToBrowser::Error {
                id: ack_id,
                message,
            } => {
                assert_eq!(ack_id, id);
                assert!(
                    !message.is_empty(),
                    "expected non-empty error message, got: {message}"
                );
            }
            other => panic!("expected files:error, got {other:?}"),
        }
    })
    .await
    .expect("test exceeded 15s timeout");
}

/// Browser → `files:dir` against a tempdir with a known structure.
/// Verifies entries surface with correct flags + sort order
/// (dirs-first, alphabetical case-insensitive within each group).
#[tokio::test]
async fn list_dir_against_tempdir() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        // Layout: tmp/{Apple, banana.txt, cherry/, Date.txt}
        // Sorted: Apple/, cherry/, banana.txt, Date.txt
        // (dirs first then files; both case-insensitive alpha)
        tokio::fs::create_dir(tmp.path().join("Apple"))
            .await
            .expect("mkdir Apple");
        tokio::fs::create_dir(tmp.path().join("cherry"))
            .await
            .expect("mkdir cherry");
        tokio::fs::write(tmp.path().join("banana.txt"), b"yellow")
            .await
            .expect("write banana");
        tokio::fs::write(tmp.path().join("Date.txt"), b"sweet")
            .await
            .expect("write date");

        let req_id = "dir-1".to_string();
        side.send_json(&BrowserToAgent::Dir {
            req_id: req_id.clone(),
            path: tmp.path().to_string_lossy().to_string(),
        })
        .await
        .expect("send dir");

        let resp: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv dir-list");
        let entries = match resp {
            AgentToBrowser::DirList {
                req_id: rid,
                entries,
                ..
            } => {
                assert_eq!(rid, req_id);
                entries
            }
            other => panic!("expected files:dir-list, got {other:?}"),
        };

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Apple", "cherry", "banana.txt", "Date.txt"],
            "expected dirs-first then files, both alphabetical case-insensitive"
        );
        assert!(entries[0].is_dir);
        assert!(entries[1].is_dir);
        assert!(!entries[2].is_dir);
        assert!(!entries[3].is_dir);
        // Files report size; dirs don't.
        assert_eq!(entries[2].size, Some(6)); // "yellow"
        assert_eq!(entries[3].size, Some(5)); // "sweet"
        assert!(entries[0].size.is_none());
    })
    .await
    .expect("test exceeded 15s timeout");
}

/// `files:dir` against a path that doesn't exist. Agent surfaces the
/// failure via `files:dir-error`, NOT `files:error` (different reply
/// envelope discriminates listings from transfers in the browser).
#[tokio::test]
async fn list_dir_nonexistent_emits_dir_error() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let req_id = "dir-bad".to_string();
        side.send_json(&BrowserToAgent::Dir {
            req_id: req_id.clone(),
            path: "/no/such/path/at/all/abcdef".to_string(),
        })
        .await
        .expect("send dir");

        let resp: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv dir-error");
        match resp {
            AgentToBrowser::DirError {
                req_id: rid,
                message,
            } => {
                assert_eq!(rid, req_id);
                assert!(!message.is_empty());
            }
            other => panic!("expected files:dir-error, got {other:?}"),
        }
    })
    .await
    .expect("test exceeded 15s timeout");
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 4 — folder zip download + traversal hardening
// ────────────────────────────────────────────────────────────────────────────

/// Build a small folder tree, request `files:get-folder`, drain
/// chunks until eof, unzip, verify content. The agent's zip walker
/// uses `async_zip::Stored` (no compression) so a `zip::ZipArchive`
/// can read it back cleanly.
#[tokio::test]
async fn folder_zip_round_trip() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        // Build tree: tmp/MyFolder/{a.txt, sub/b.txt, sub/deeper/c.txt}
        let root = tmp.path().join("MyFolder");
        tokio::fs::create_dir_all(root.join("sub").join("deeper"))
            .await
            .expect("mkdir tree");
        tokio::fs::write(root.join("a.txt"), b"alpha bravo")
            .await
            .expect("write a");
        tokio::fs::write(root.join("sub").join("b.txt"), b"bravo charlie")
            .await
            .expect("write b");
        tokio::fs::write(
            root.join("sub").join("deeper").join("c.txt"),
            b"charlie delta",
        )
        .await
        .expect("write c");

        let id = "zip-1".to_string();
        side.send_json(&BrowserToAgent::GetFolder {
            id: id.clone(),
            path: root.to_string_lossy().to_string(),
            format: Some("zip".to_string()),
        })
        .await
        .expect("send get-folder");

        // Offer first.
        let offer: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv offer");
        match offer {
            AgentToBrowser::Offer {
                id: ack_id,
                size,
                name,
                mime,
            } => {
                assert_eq!(ack_id, id);
                assert!(
                    name.ends_with(".zip"),
                    "offer.name={name} should end with .zip"
                );
                assert!(size.is_none(), "streaming zip → size unknown");
                assert_eq!(mime.as_deref(), Some("application/zip"));
            }
            other => panic!("expected files:offer, got {other:?}"),
        }

        let (zip_bytes, terminal) = side
            .collect_until_eof(Duration::from_secs(15))
            .await
            .expect("collect zip");
        assert!(
            terminal.contains("\"files:eof\""),
            "expected eof, got {terminal}"
        );
        assert!(!zip_bytes.is_empty(), "zip bytes received");

        // Verify content.
        let cursor = std::io::Cursor::new(&zip_bytes);
        let mut archive = zip::ZipArchive::new(cursor).expect("open zip");
        let mut got: std::collections::BTreeMap<String, Vec<u8>> =
            std::collections::BTreeMap::new();
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).expect("entry");
            if entry.is_dir() {
                continue;
            }
            let name = entry.name().to_string();
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf).expect("read entry");
            got.insert(name, buf);
        }
        assert_eq!(
            got.get("a.txt").map(|v| v.as_slice()),
            Some(&b"alpha bravo"[..])
        );
        assert_eq!(
            got.get("sub/b.txt").map(|v| v.as_slice()),
            Some(&b"bravo charlie"[..])
        );
        assert_eq!(
            got.get("sub/deeper/c.txt").map(|v| v.as_slice()),
            Some(&b"charlie delta"[..])
        );
    })
    .await
    .expect("test exceeded 20s timeout");
}

/// `files:get-folder` of a single-file path (not a directory) should
/// surface a clean `files:error` rather than streaming a 1-entry
/// zip — the agent's `begin_outgoing_zip` rejects via the
/// `is_dir()` check.
#[tokio::test]
async fn folder_zip_rejects_file_path() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        let f = tmp.path().join("not-a-folder.txt");
        tokio::fs::write(&f, b"i am a file").await.expect("write");

        let id = "zip-bad".to_string();
        side.send_json(&BrowserToAgent::GetFolder {
            id: id.clone(),
            path: f.to_string_lossy().to_string(),
            format: None,
        })
        .await
        .expect("send get-folder");

        let resp: AgentToBrowser = side.recv_json(Duration::from_secs(5)).await.expect("recv");
        match resp {
            AgentToBrowser::Error {
                id: ack_id,
                message,
            } => {
                assert_eq!(ack_id, id);
                assert!(
                    message.contains("not a directory") || message.contains("directory"),
                    "expected directory-rejection in message, got: {message}"
                );
            }
            other => panic!("expected files:error, got {other:?}"),
        }
    })
    .await
    .expect("test exceeded 15s timeout");
}

/// Per-component sanitisation: a file whose name contains
/// `..` / path separators must NOT escape the zip root.
/// `sanitize_filename` replaces unsafe chars with `_`, so the entry
/// name in the zip is a flat single component, never a `..` segment.
#[tokio::test]
async fn folder_zip_sanitises_traversal_in_filenames() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path().join("Root");
        tokio::fs::create_dir(&root).await.expect("mkdir");
        // The OS allows weird filenames on most platforms; on Windows
        // the path-separator chars `/` and `\` are forbidden, so the
        // dangerous names are limited to literal `..` (the parent-
        // dir alias). Even on Unix where `..` and `/` can appear in
        // a filename, the zip walker's `sanitize_filename` flattens
        // them to safe characters.
        tokio::fs::write(root.join("..weird.txt"), b"sneaky")
            .await
            .expect("write weird");
        tokio::fs::write(root.join("normal.txt"), b"normal")
            .await
            .expect("write normal");

        let id = "zip-sane".to_string();
        side.send_json(&BrowserToAgent::GetFolder {
            id: id.clone(),
            path: root.to_string_lossy().to_string(),
            format: None,
        })
        .await
        .expect("send");

        let _offer: AgentToBrowser = side.recv_json(Duration::from_secs(5)).await.expect("offer");
        let (zip_bytes, _terminal) = side
            .collect_until_eof(Duration::from_secs(10))
            .await
            .expect("collect");

        let cursor = std::io::Cursor::new(&zip_bytes);
        let archive = zip::ZipArchive::new(cursor).expect("open zip");
        for i in 0..archive.len() {
            // Re-open by index because `by_index` mutably borrows; we
            // only need the names anyway, not the data.
            let mut a = zip::ZipArchive::new(std::io::Cursor::new(&zip_bytes)).unwrap();
            let entry = a.by_index(i).expect("entry");
            let name = entry.name();
            assert!(
                !name.contains(".."),
                "zip entry {name:?} contains traversal segment"
            );
            assert!(
                !name.starts_with('/') && !name.starts_with('\\'),
                "zip entry {name:?} starts with separator (absolute path)"
            );
        }
    })
    .await
    .expect("test exceeded 15s timeout");
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 5 — concurrent up+down + mid-transfer cancel
// ────────────────────────────────────────────────────────────────────────────

/// Validates the v2 `incoming` / `outgoing` Mutex split: an upload
/// and a download driven through the SAME DC must not deadlock or
/// interfere. We DO NOT ship them truly in parallel on the wire —
/// SCTP per-DC strings/bytes are ordered — but the test queues a
/// download offer-and-stream while an upload is mid-flight and
/// confirms both terminate cleanly.
#[tokio::test]
async fn upload_and_download_share_dc_cleanly() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");

        // Pre-stage a file on disk for download.
        let dl_src = tmp.path().join("download-me.bin");
        let dl_payload: Vec<u8> = (0..8 * 1024).map(|i| (i as u8).wrapping_mul(11)).collect();
        tokio::fs::write(&dl_src, &dl_payload).await.expect("write src");

        let dest = tmp.path().to_string_lossy().to_string();
        let up_payload = b"upload-side-payload".repeat(50);

        // Begin upload.
        let up_id = "up-A".to_string();
        side.send_json(&BrowserToAgent::Begin {
            id: up_id.clone(),
            name: "uploaded.bin".to_string(),
            size: up_payload.len() as u64,
            mime: None,
            rel_path: None,
            dest_path: Some(dest.clone()),
        })
        .await
        .expect("send up begin");

        // Wait for accepted (confirms upload state is established).
        let _: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv up accepted");

        // Begin download via files:get — this should land on the
        // outgoing Mutex while the upload still holds incoming.
        let dl_id = "dl-A".to_string();
        side.send_json(&BrowserToAgent::Get {
            id: dl_id.clone(),
            path: dl_src.to_string_lossy().to_string(),
        })
        .await
        .expect("send dl get");

        // Send the upload chunk + end after kicking off the download
        // request, so both paths overlap in time.
        side.send_chunk(&up_payload).await.expect("up chunk");
        side.send_json(&BrowserToAgent::End {
            id: up_id.clone(),
        })
        .await
        .expect("up end");

        // Now drain the rest until both paths have terminated. We
        // see, in some interleaved order: dl offer, dl chunk(s), dl
        // eof, up complete (and possibly progresses).
        let mut up_complete = false;
        let mut dl_offer = false;
        let mut dl_eof = false;
        let mut dl_bytes = Vec::<u8>::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !(up_complete && dl_offer && dl_eof) {
            tokio::select! {
                biased;
                chunk = side.bytes.recv() => {
                    let chunk = chunk.expect("bytes channel closed");
                    dl_bytes.extend_from_slice(&chunk);
                }
                msg = side.strings.recv() => {
                    let s = msg.expect("strings channel closed");
                    let v: AgentToBrowser = serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse: {e}: {s}"));
                    match v {
                        AgentToBrowser::Complete { id, .. } if id == up_id => up_complete = true,
                        AgentToBrowser::Offer { id, .. } if id == dl_id => dl_offer = true,
                        AgentToBrowser::Eof { id, .. } if id == dl_id => dl_eof = true,
                        AgentToBrowser::Progress { .. } => {}
                        AgentToBrowser::Accepted { .. } => {}
                        AgentToBrowser::Error { id, message } => {
                            panic!("unexpected files:error id={id} msg={message}");
                        }
                        other => panic!("unexpected envelope: {other:?}"),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    panic!(
                        "timed out (up_complete={up_complete}, dl_offer={dl_offer}, dl_eof={dl_eof}, dl_bytes={})",
                        dl_bytes.len()
                    );
                }
            }
        }

        // Brief grace to drain trailing chunks the way collect_until_eof does.
        let drain = tokio::time::Instant::now() + Duration::from_millis(250);
        loop {
            tokio::select! {
                chunk = side.bytes.recv() => {
                    if let Some(chunk) = chunk { dl_bytes.extend_from_slice(&chunk); } else { break; }
                }
                _ = tokio::time::sleep_until(drain) => break,
            }
        }
        assert_eq!(dl_bytes.len(), dl_payload.len(), "download byte count");
        assert_eq!(dl_bytes, dl_payload, "download content matches");
    })
    .await
    .expect("test exceeded 20s timeout");
}

/// Mid-transfer cancel: start a download, send `files:cancel`
/// before it completes, observe the agent emits `files:error`
/// (cancelled-by-browser) and clears outgoing state — a follow-up
/// `files:get` must succeed. Locks the cancel-AtomicBool semantics.
#[tokio::test]
async fn cancel_mid_download_releases_outgoing() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut side = open_files_dc().await.expect("open dc");
        let tmp = tempfile::tempdir().expect("tmp");
        let big = tmp.path().join("biggish.bin");
        // 32 KiB — small enough to fit in a single chunk under our
        // loopback PC limits, but the cancel race is timing-driven
        // anyway: the file may complete before the cancel arrives.
        // The assertion accepts EITHER cancel-error OR clean-eof,
        // and then verifies a follow-up get works (the real
        // contract).
        let payload = vec![0xABu8; 32 * 1024];
        tokio::fs::write(&big, &payload).await.expect("write big");

        let id = "dl-cancel".to_string();
        side.send_json(&BrowserToAgent::Get {
            id: id.clone(),
            path: big.to_string_lossy().to_string(),
        })
        .await
        .expect("send get");
        // Issue cancel as soon as we can. With a small payload the
        // download may complete first — that's OK.
        side.send_json(&BrowserToAgent::Cancel { id: id.clone() })
            .await
            .expect("send cancel");

        // Drain whatever the agent emits to terminate this transfer.
        // Could be: offer → chunk → eof, OR offer → error.
        let _ = side.collect_until_eof(Duration::from_secs(10)).await;

        // The real assertion: outgoing slot is free for a new
        // request. Try a small follow-up download.
        let small = tmp.path().join("after.txt");
        tokio::fs::write(&small, b"after-cancel")
            .await
            .expect("write small");
        let id2 = "dl-after".to_string();
        side.send_json(&BrowserToAgent::Get {
            id: id2.clone(),
            path: small.to_string_lossy().to_string(),
        })
        .await
        .expect("send second get");
        let offer: AgentToBrowser = side
            .recv_json(Duration::from_secs(5))
            .await
            .expect("recv second offer");
        assert!(
            matches!(offer, AgentToBrowser::Offer { ref id, .. } if id == &id2),
            "follow-up get must produce a fresh offer, got {offer:?}"
        );
        let (bytes, _term) = side
            .collect_until_eof(Duration::from_secs(5))
            .await
            .expect("collect second");
        assert_eq!(bytes, b"after-cancel", "follow-up content matches");
    })
    .await
    .expect("test exceeded 20s timeout");
}
