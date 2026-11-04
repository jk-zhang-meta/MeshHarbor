// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Clipboard data-channel handler.
//!
//! Round-trip clipboard content between the browser controller and
//! the agent host over the WebRTC `clipboard` data channel (a
//! reliable, ordered DC). Protocol v2 (0.3.0-rc.227+) carries text
//! AND PNG images, write-acks, and unsolicited change events for
//! auto-sync; every v2 element is additive so v1 peers interoperate
//! untouched.
//!
//! Wire protocol (JSON control frames + raw binary image frames):
//!
//! ```text
//! // Browser -> Agent
//! { "t": "clipboard:write", "text": "hello", "id": "cb-…"? }        // id v2: requests an ack
//! { "t": "clipboard:write-chunk", "id": "abc123", "seq": 0, "text": "...", "last": false }
//! { "t": "clipboard:read", "req_id": 42?, "accept": ["text","image"]? }
//! { "t": "clipboard:subscribe", "events": ["text","image"] }        // v2 auto-sync
//! { "t": "clipboard:unsubscribe" }                                  // v2
//! { "t": "clipboard:img-begin", "id": "cb-…", "w": 1920, "h": 1080,
//!   "bytes": 123456, "format": "png" }                              // v2, then ≤16 KiB binary frames
//! { "t": "clipboard:img-end", "id": "cb-…" }                        // v2
//!
//! // Agent -> Browser
//! { "t": "clipboard:content", "text": "hello", "req_id": Option<u64> }
//! { "t": "clipboard:content-chunk", "req_id": …, "seq": 0, "text": "...", "last": false }
//! { "t": "clipboard:write-ack", "id": "cb-…", "bytes": 5 }          // v2, only for id-stamped writes
//! { "t": "clipboard:event", "kind": "text", "text": "..." }         // v2, after subscribe
//! { "t": "clipboard:event-chunk", "event_id": "ev-1", "seq": 0, "text": "...", "last": false }
//! { "t": "clipboard:img-begin", "id": "aimg-0", "w": …, "h": …, "bytes": …,
//!   "format": "png", "req_id": Option<u64> }                        // v2, then 64 KiB binary frames
//! { "t": "clipboard:img-end", "id": "aimg-0", "bytes": … }          // v2
//! { "t": "clipboard:error", "message": "reason", "req_id": Option<u64>, "id": Option<String> }
//! ```
//!
//! `req_id` round-trips an optional u64 from the read request so the
//! browser can pair responses to its requests. On an image reply it
//! distinguishes "answer to your read" (present) from "unsolicited
//! change event" (absent). Text is canonical LF on the wire; the
//! worker converts to the host's convention (`CRLF` on Windows) on
//! every write and back on every read — see [`host_to_wire`] /
//! [`wire_to_host`]. Change events are pushed only after an explicit
//! `clipboard:subscribe`, and the CLIPBOARD permission bit gates the
//! whole DC (enforced in `peer.rs::attach_clipboard_handler`).
//!
//! rc.44 — chunked variants. The single-envelope `clipboard:write`
//! shape sent a `text` field unbounded by length, which on payloads
//! over ~50 KB hit webrtc-rs's SCTP `max_message_size=65536` default
//! and threw `failed to handle_inbound: ErrChunk`, killing the data
//! channel + session (a third field-test host field repro 2026-05-19, every 1-2 min
//! sessions). The chunked variants cap each envelope at ~14 KB to
//! stay well under the SCTP ceiling; the receiver reassembles by
//! `id` (write) / `req_id` (read response) and applies on `last`.
//! Total payload is capped at [`MAX_CLIPBOARD_BYTES`] (1 MB) to
//! prevent OOM by malicious clients.
//!
//! Thread-pinning: `arboard::Clipboard` on Windows uses Win32's
//! OpenClipboard/SetClipboardData, which are thread-affine and also
//! require a Windows message pump on the owner thread — easiest to
//! satisfy by parking a dedicated OS thread that owns the clipboard
//! handle and services Read/Write via a `std::sync::mpsc` command
//! channel. Same pattern the `input` / `capture` modules use.

#![cfg(feature = "clipboard")]

use anyhow::{Context, Result};
use std::sync::mpsc as std_mpsc;
use std::thread;
use tokio::sync::oneshot;

/// Command sent to the clipboard worker thread. Replies come back
/// over the oneshot carried in each variant.
pub(crate) enum ClipboardCmd {
    Read {
        reply: oneshot::Sender<Result<String>>,
    },
    Write {
        text: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// v2 — read the host clipboard as a PNG image. `Ok(None)` when
    /// the clipboard holds no image content.
    ReadImage {
        reply: oneshot::Sender<Result<Option<PngImage>>>,
    },
    /// v2 — decode the PNG and place it on the host clipboard.
    WriteImage {
        png: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// v2.1 — read the host clipboard as HTML (+ its plain-text alt).
    /// `Ok(None)` when the clipboard holds no HTML content.
    ReadHtml {
        reply: oneshot::Sender<Result<Option<HtmlPayload>>>,
    },
    /// v2.1 — write HTML + plain-text alternate to the host clipboard
    /// atomically (one clipboard transaction, both formats — a paste
    /// target picks the richest it understands).
    WriteHtml {
        html: String,
        text: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// v2.2 — read the host clipboard's NATIVE formats (RTF + html +
    /// text). `Ok(None)` when no RTF is present (the html/text lanes
    /// cover that). Windows-only in practice — elsewhere always None.
    ReadNative {
        reply: oneshot::Sender<Result<Option<NativePayload>>>,
    },
    /// v2.2 — write RTF + html + text to the host clipboard (html+text
    /// in one arboard transaction, RTF appended via
    /// `set_without_clear`). Windows-only; an error elsewhere.
    WriteNative {
        payload: Box<NativePayload>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// v2 — install a change watcher subscription. The worker switches
    /// from blocking `recv()` to a tick loop while ANY subscription is
    /// live and pushes [`ClipboardChange`]s into each subscription's `tx`
    /// when the HOST clipboard changes. Fire-and-forget: no reply.
    ///
    /// Multi-user P3: keyed by a caller-held token — pre-P3 this was a
    /// single slot, so with two concurrent sessions the second session's
    /// subscribe silently STOLE the first's change feed and either
    /// session's unsubscribe killed both.
    Watch {
        id: u64,
        events: WatchEvents,
        tx: tokio::sync::mpsc::Sender<ClipboardChange>,
    },
    /// v2 — remove ONE watcher subscription by its token (browser
    /// unsubscribed or the DC closed). Fire-and-forget, idempotent.
    Unwatch { id: u64 },
    /// Kept as an affordance for future deterministic shutdowns (e.g.
    /// a test harness that wants to join the worker). Today the
    /// `Clipboard` handle has no Drop impl — dropping the last
    /// `Sender` returns `Err` from `rx.recv()` which ends the worker
    /// loop naturally.
    #[allow(dead_code)]
    Shutdown,
}

/// Handle to a thread-pinned `arboard::Clipboard`. Cheap to clone
/// (`Sender` is Arc'd internally) so multiple data channels in the
/// same session can share one worker.
#[derive(Clone)]
pub struct Clipboard {
    tx: std_mpsc::Sender<ClipboardCmd>,
}

impl Clipboard {
    /// Spin up the worker thread. The `arboard::Clipboard` is
    /// constructed on the worker so the handle never crosses thread
    /// boundaries, which matters on Windows (the OpenClipboard
    /// ownership is per-thread).
    pub fn new() -> Result<Self> {
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();
        let (tx, rx) = std_mpsc::channel::<ClipboardCmd>();

        thread::Builder::new()
            .name("roomlerd-clipboard".into())
            .spawn(move || {
                let mut cb = match arboard::Clipboard::new() {
                    Ok(c) => {
                        let _ = ready_tx.send(Ok(()));
                        c
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow::anyhow!("arboard::Clipboard::new: {e}")));
                        return;
                    }
                };
                // Content the worker itself last wrote (remote-initiated
                // writes) — the change watcher compares against these so
                // a browser-originated write is never echoed back to the
                // browser as a "host change".
                let mut marks = SelfMarks::default();
                // Multi-user P3 — N concurrent subscriptions (one per
                // session), each with its OWN change baseline so a
                // late-joining session isn't immediately pushed the
                // pre-existing clipboard as a "change".
                let mut watchers: std::collections::HashMap<u64, WatcherState> =
                    std::collections::HashMap::new();
                // FR-97 P3e-3a — the X11 change gate, opened with the first
                // watcher and kept; `None` outside an X11 session.
                #[cfg(target_os = "linux")]
                let mut gate: Option<x11_gate::Gate> = None;
                #[cfg(target_os = "linux")]
                let mut gate_tried = false;
                loop {
                    // Block indefinitely when nothing is watching (the
                    // pre-v2 behavior — zero idle wakeups); poll at the
                    // tick cadence while any watcher is installed.
                    #[cfg(target_os = "linux")]
                    let tick = if gate.is_some() {
                        GATED_TICK
                    } else {
                        WATCH_TICK
                    };
                    #[cfg(not(target_os = "linux"))]
                    let tick = WATCH_TICK;
                    let cmd = if !watchers.is_empty() {
                        match rx.recv_timeout(tick) {
                            Ok(c) => Some(c),
                            Err(std_mpsc::RecvTimeoutError::Timeout) => None,
                            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    } else {
                        match rx.recv() {
                            Ok(c) => Some(c),
                            Err(_) => break,
                        }
                    };
                    match cmd {
                        Some(ClipboardCmd::Read { reply }) => {
                            let _ = reply.send(worker_read_text(&mut cb));
                        }
                        Some(ClipboardCmd::Write { text, reply }) => {
                            let _ = reply.send(worker_write_text(&mut cb, &text, &mut marks));
                        }
                        Some(ClipboardCmd::ReadImage { reply }) => {
                            let _ = reply.send(worker_read_image(&mut cb));
                        }
                        Some(ClipboardCmd::WriteImage { png, reply }) => {
                            let _ = reply.send(worker_write_image(&mut cb, &png, &mut marks));
                        }
                        Some(ClipboardCmd::ReadHtml { reply }) => {
                            let _ = reply.send(worker_read_html(&mut cb));
                        }
                        Some(ClipboardCmd::WriteHtml { html, text, reply }) => {
                            let _ =
                                reply.send(worker_write_html(&mut cb, &html, &text, &mut marks));
                        }
                        Some(ClipboardCmd::ReadNative { reply }) => {
                            let _ = reply.send(worker_read_native(&mut cb));
                        }
                        Some(ClipboardCmd::WriteNative { payload, reply }) => {
                            let _ = reply.send(worker_write_native(&mut cb, &payload, &mut marks));
                        }
                        Some(ClipboardCmd::Watch { id, events, tx }) => {
                            #[cfg(target_os = "linux")]
                            let gate_seq = {
                                if gate.is_none() && !gate_tried {
                                    gate_tried = true;
                                    gate = x11_gate::Gate::open();
                                }
                                gate_tick(&mut gate)
                            };
                            #[cfg(not(target_os = "linux"))]
                            let gate_seq = None;
                            watchers.insert(id, install_watcher(&mut cb, events, tx, gate_seq));
                        }
                        Some(ClipboardCmd::Unwatch { id }) => {
                            watchers.remove(&id);
                        }
                        Some(ClipboardCmd::Shutdown) => break,
                        None => {
                            // Dead receivers (session died without an
                            // explicit unsubscribe) are dropped so the
                            // worker can fall back to blocking recv.
                            watchers.retain(|_, w| !w.receiver_gone());
                            // One read of the gate per tick, for every watcher.
                            #[cfg(target_os = "linux")]
                            let gate_seq = gate_tick(&mut gate);
                            #[cfg(not(target_os = "linux"))]
                            let gate_seq = None;
                            for w in watchers.values_mut() {
                                watch_tick(&mut cb, w, &marks, gate_seq);
                            }
                        }
                    }
                    // FR-97 P3e-3a — no watcher, no gate: an idle worker
                    // blocks on its commands and would read no events, and
                    // an X server buffers what a client does not read.
                    #[cfg(target_os = "linux")]
                    if watchers.is_empty() && gate.is_some() {
                        gate = None;
                        gate_tried = false;
                    }
                }
            })
            .context("spawning clipboard worker")?;

        ready_rx
            .recv()
            .context("clipboard worker ack")?
            .context("clipboard worker init")?;

        Ok(Self { tx })
    }

    /// Read the current clipboard text. Empty string on "no text
    /// content" (clipboard holds image/file/nothing). Errors if the
    /// worker has died or the OS clipboard is locked by another
    /// process.
    pub async fn read(&self) -> Result<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::Read { reply: reply_tx })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// Replace the clipboard with the given text.
    pub async fn write(&self, text: String) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::Write {
                text,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// v2 — read the host clipboard as a PNG image. `Ok(None)` when
    /// the clipboard holds no image content.
    pub async fn read_image(&self) -> Result<Option<PngImage>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::ReadImage { reply: reply_tx })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// v2 — decode `png` and place it on the host clipboard.
    pub async fn write_image(&self, png: Vec<u8>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::WriteImage {
                png,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// v2.1 — read the host clipboard as HTML (+ plain-text alt);
    /// `None` when it holds no HTML.
    pub async fn read_html(&self) -> Result<Option<HtmlPayload>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::ReadHtml { reply: reply_tx })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// v2.1 — write HTML + plain-text alternate atomically.
    pub async fn write_html(&self, html: String, text: String) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::WriteHtml {
                html,
                text,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// v2.2 — read the native formats (RTF + alternates); `None` when
    /// the clipboard holds no RTF.
    pub async fn read_native(&self) -> Result<Option<NativePayload>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::ReadNative { reply: reply_tx })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// v2.2 — write RTF + html + text (Windows).
    pub async fn write_native(&self, payload: NativePayload) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ClipboardCmd::WriteNative {
                payload: Box::new(payload),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("clipboard worker dropped reply"))?
    }

    /// v2.2 — the process-shared clipboard worker. One worker (and one
    /// set of echo self-marks) serves every consumer — the per-session
    /// DC handlers AND the loopback bridge — so a bridge write is
    /// never echoed back by a concurrently-subscribed session watcher.
    /// `None` when the OS clipboard is unavailable (headless).
    pub fn shared() -> Option<Clipboard> {
        static SHARED: std::sync::OnceLock<Option<Clipboard>> = std::sync::OnceLock::new();
        SHARED
            .get_or_init(|| match Clipboard::new() {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(%e, "clipboard: shared worker init failed — clipboard disabled");
                    None
                }
            })
            .clone()
    }

    /// v2 — install a change-watcher SUBSCRIPTION. Changes arrive on `tx`;
    /// the worker drops pushes when the channel is full and retries on the
    /// next tick. Returns the subscription token for [`Clipboard::unwatch`].
    ///
    /// Multi-user P3: N subscriptions coexist (one per session); pre-P3 the
    /// single slot meant a 2nd session's subscribe stole the 1st's feed and
    /// either unsubscribe killed both.
    pub(crate) fn watch(
        &self,
        events: WatchEvents,
        tx: tokio::sync::mpsc::Sender<ClipboardChange>,
    ) -> Result<u64> {
        static NEXT_WATCH_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT_WATCH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.tx
            .send(ClipboardCmd::Watch { id, events, tx })
            .map_err(|_| anyhow::anyhow!("clipboard worker gone"))?;
        Ok(id)
    }

    /// v2 — remove ONE subscription by token. Idempotent, fire-and-forget.
    pub(crate) fn unwatch(&self, id: u64) {
        let _ = self.tx.send(ClipboardCmd::Unwatch { id });
    }
}

// No Drop impl. `Clipboard` is `Clone` (the Sender is Arc'd internally);
// a Drop-sends-Shutdown would fire on every clone drop, including the
// first, killing the worker prematurely. With no Drop, the worker
// exits naturally when all Sender clones are dropped and `rx.recv()`
// returns `Err(RecvError)` — which ends the worker loop. `ClipboardCmd::
// Shutdown` is still honoured for deterministic shutdowns inside the
// test suite.

// ── Clipboard protocol v2: change watcher + images ──────────────────────────

/// Which change kinds a [`ClipboardCmd::Watch`] subscription wants
/// pushed. Image watching is honoured on Windows only (no cheap
/// change signal elsewhere — see [`watch_tick`]); text + html work
/// everywhere arboard does.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WatchEvents {
    pub text: bool,
    pub image: bool,
    pub html: bool,
    /// v2.2 — RTF-bearing native events (Windows only; needs the
    /// viewer side to run a loopback bridge to consume them).
    pub native: bool,
}

/// A PNG-encoded clipboard image (the wire form on the clipboard DC).
#[derive(Debug, Clone)]
pub struct PngImage {
    pub w: u32,
    pub h: u32,
    pub png: Vec<u8>,
}

/// v2.1 — HTML clipboard content + its plain-text alternate. The pair
/// travels together so the receiving side writes BOTH formats in one
/// clipboard transaction (rich-aware paste targets pick the HTML,
/// plain editors the text).
#[derive(Debug, Clone)]
pub struct HtmlPayload {
    pub html: String,
    pub text: String,
}

/// v2.2 — NATIVE clipboard content: RTF (the only format that carries
/// a document's EMBEDDED images as self-contained bytes) plus the
/// html/text alternates. Only reachable through an agent — no browser
/// API exposes RTF — which is what the loopback clipboard bridge is
/// for. `rtf` is required (else the html/text lanes suffice); `html`
/// and `text` may be empty.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NativePayload {
    /// Raw RTF bytes (Windows "Rich Text Format" registered format).
    #[serde(with = "base64_bytes")]
    pub rtf: Vec<u8>,
    #[serde(default)]
    pub html: String,
    #[serde(default)]
    pub text: String,
}

/// Serde adapter: `Vec<u8>` ⇄ base64 string (the bridge's JSON body).
mod base64_bytes {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Host-clipboard change pushed to a [`ClipboardCmd::Watch`] subscriber.
#[derive(Debug)]
pub(crate) enum ClipboardChange {
    Text(String),
    Image(PngImage),
    Html(HtmlPayload),
    Native(Box<NativePayload>),
}

/// Watcher tick cadence. Windows gets a fast tick because the
/// unchanged-path is a single `GetClipboardSequenceNumber` syscall
/// (no clipboard open); elsewhere every tick reads + hashes the text,
/// so poll at 1 Hz.
#[cfg(windows)]
const WATCH_TICK: std::time::Duration = std::time::Duration::from_millis(200);
#[cfg(not(windows))]
const WATCH_TICK: std::time::Duration = std::time::Duration::from_millis(1000);

/// FR-97 P3e-3a — behind the X11 change gate an unchanged tick is one event
/// drain on a local socket, so it runs at Windows' cadence.
#[cfg(target_os = "linux")]
const GATED_TICK: std::time::Duration = std::time::Duration::from_millis(200);

/// Content the worker itself last wrote to the OS clipboard. The
/// change watcher treats matching state as "our own write" and stays
/// silent — one half of the echo-suppression loop (the browser holds
/// the other half in its `createClipboardEchoGate`).
#[derive(Default)]
struct SelfMarks {
    /// `GetClipboardSequenceNumber` observed right after our own write.
    #[cfg(windows)]
    seq: u32,
    /// FNV-1a of the canonical (LF) text we last wrote.
    text_hash: u64,
    /// FNV-1a of the deterministic re-encode of the image we last
    /// wrote (our own encoder — byte-identical to what a later
    /// [`watch_tick`] re-encode produces, unlike the browser's PNG
    /// bytes which come from a different encoder).
    img_hash: u64,
    /// v2.1 — [`html_event_hash`] of the READ-BACK of the html we
    /// last wrote (the OS re-wraps CF_HTML, so hashing our input
    /// would never match what a later tick reads).
    html_hash: u64,
    /// v2.2 — FNV of the RTF bytes we last wrote. Custom registered
    /// formats round-trip verbatim (no OS re-wrap), so the input hash
    /// matches a later tick's read.
    #[cfg_attr(not(windows), allow(dead_code))]
    native_hash: u64,
}

struct WatcherState {
    events: WatchEvents,
    tx: tokio::sync::mpsc::Sender<ClipboardChange>,
    /// Windows' sequence number, or (FR-97 P3e-3a) the X11 change gate's
    /// counter, as this watcher last saw it.
    #[cfg(any(windows, target_os = "linux"))]
    last_seen_seq: u32,
    last_text_hash: u64,
    last_img_hash: u64,
    last_html_hash: u64,
    #[cfg_attr(not(windows), allow(dead_code))]
    last_native_hash: u64,
    /// Set when `try_send` hit a full channel or a read failed
    /// transiently — the next tick bypasses the unchanged-seq early
    /// exit and re-attempts.
    retry: bool,
}

impl WatcherState {
    /// Multi-user P3 — a subscription whose consumer died (session torn
    /// down without an explicit unsubscribe): the worker reaps it on the
    /// next tick so an all-dead registry falls back to blocking recv.
    fn receiver_gone(&self) -> bool {
        self.tx.is_closed()
    }
}

/// `GetClipboardSequenceNumber` via clipboard-win. `None` when the
/// calling thread's window station denies clipboard access.
#[cfg(windows)]
fn win_clipboard_seq() -> Option<u32> {
    clipboard_win::raw::seq_num().map(|n| n.get())
}

/// FR-97 P3e-3a — the gate's counter for this tick; a gate whose connection
/// broke is dropped, and its watchers fall back to the ungated path.
#[cfg(target_os = "linux")]
fn gate_tick(gate: &mut Option<x11_gate::Gate>) -> Option<u32> {
    let seq = gate.as_mut().and_then(x11_gate::Gate::seq);
    if seq.is_none() {
        *gate = None;
    }
    seq
}

/// FR-97 P3e-3a — the X11 clipboard's change gate, Windows' sequence number
/// for an X11 session: XFixes reports every change of the CLIPBOARD
/// selection's owner, and a copy is exactly that. A tick that saw no event
/// reads nothing, so copied images can be watched (each read is a full
/// transfer and a PNG encode, which a blind 1 Hz poll could not afford) and
/// text no longer costs a read and a hash every second.
///
/// - **Only an X11 session**: an X display and no Wayland one. Under Wayland
///   the clipboard is the compositor's, and Xwayland's copy of it is
///   unmeasured, so images stay unwatched there, as before.
/// - **Our own writes** change the owner too; the content hashes in
///   [`SelfMarks`] still swallow them, as on every OS.
/// - A connection that breaks drops the gate, and the watcher falls back to
///   reading text every tick and leaving images alone.
///
/// Kill switch `ROOMLERD_CLIPBOARD_X11_WATCH=0`: no gate, as before P3e-3a.
#[cfg(target_os = "linux")]
pub(crate) mod x11_gate {
    use std::sync::OnceLock;

    use x11rb::connection::Connection as _;
    use x11rb::protocol::Event;
    use x11rb::protocol::xfixes::{self, ConnectionExt as _};
    use x11rb::protocol::xproto::{self, ConnectionExt as _};
    use x11rb::rust_connection::RustConnection;

    /// FR-97 P3e-3a — kill switch `ROOMLERD_CLIPBOARD_X11_WATCH=0`.
    pub fn enabled() -> bool {
        tunnel_core::env::flag("CLIPBOARD_X11_WATCH", true)
    }

    fn x11_session() -> bool {
        std::env::var_os("DISPLAY").is_some_and(|d| !d.is_empty())
            && std::env::var_os("WAYLAND_DISPLAY").is_none_or(|w| w.is_empty())
    }

    pub struct Gate {
        conn: RustConnection,
        clipboard: xproto::Atom,
        seq: u32,
    }

    impl Gate {
        /// `None` outside an X11 session, with the switch off, or without
        /// XFixes.
        pub fn open() -> Option<Self> {
            if !enabled() || !x11_session() {
                return None;
            }
            Self::connect()
        }

        /// The gate on `$DISPLAY`'s server, whatever session this is: what
        /// [`Gate::open`] does once it decided to (and what the real-X test
        /// drives, since a WSLg shell names a Wayland display too).
        pub(super) fn connect() -> Option<Self> {
            let (conn, screen) = x11rb::connect(None)
                .map_err(|e| tracing::info!(%e, "clipboard: no X connection for the change gate"))
                .ok()?;
            let root = conn.setup().roots.get(screen)?.root;
            conn.xfixes_query_version(5, 0).ok()?.reply().ok()?;
            let clipboard = conn
                .intern_atom(false, b"CLIPBOARD")
                .ok()?
                .reply()
                .ok()?
                .atom;
            conn.xfixes_select_selection_input(
                root,
                clipboard,
                xfixes::SelectionEventMask::SET_SELECTION_OWNER
                    | xfixes::SelectionEventMask::SELECTION_WINDOW_DESTROY
                    | xfixes::SelectionEventMask::SELECTION_CLIENT_CLOSE,
            )
            .ok()?
            .check()
            .ok()?;
            Some(Self {
                conn,
                clipboard,
                // Never 0: the watcher reads 0 as "no counter".
                seq: 1,
            })
        }

        /// The change counter, one more for every owner change since the
        /// last call. `None` once the connection broke.
        pub fn seq(&mut self) -> Option<u32> {
            loop {
                match self.conn.poll_for_event() {
                    Ok(Some(Event::XfixesSelectionNotify(e))) if e.selection == self.clipboard => {
                        self.seq = self.seq.wrapping_add(1).max(1);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => return Some(self.seq),
                    Err(e) => {
                        tracing::info!(%e, "clipboard: the change gate's X connection broke");
                        return None;
                    }
                }
            }
        }
    }

    /// Whether copied images on this host are watched: an X11 session whose
    /// server takes the gate. Asked once, for the hello.
    pub fn available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| Gate::open().is_some())
    }
}

/// FNV-1a 64 over raw bytes. Mirrors the browser-side
/// `hashClipboardText` / `hashClipboardBytes` helpers in
/// `useRemoteControl.ts` — both sides hash identical canonical bytes,
/// which is what makes cross-side echo suppression sound.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn worker_read_text(cb: &mut arboard::Clipboard) -> Result<String> {
    match cb.get_text() {
        // Canonicalize to wire form (LF) so browser-side hashing and
        // display are host-convention-free.
        Ok(t) => Ok(host_to_wire(&t)),
        // Clipboard holds no text (image / files / empty). Not an
        // error on the wire: an empty `clipboard:content` lets a rich
        // read fall through to the image path, and old UIs surface
        // "empty clipboard" instead of a scary error toast.
        Err(arboard::Error::ContentNotAvailable) => Ok(String::new()),
        Err(e) => Err(anyhow::anyhow!("clipboard get_text: {e}")),
    }
}

fn worker_write_text(
    cb: &mut arboard::Clipboard,
    wire_text: &str,
    marks: &mut SelfMarks,
) -> Result<()> {
    // Hash the canonical form BEFORE host conversion — the watcher
    // hashes `host_to_wire(get_text())`, which round-trips back to
    // exactly these bytes.
    let canonical_hash = fnv1a64(host_to_wire(wire_text).as_bytes());
    cb.set_text(wire_to_host(wire_text))
        .map_err(|e| anyhow::anyhow!("clipboard set_text: {e}"))?;
    marks.text_hash = canonical_hash;
    #[cfg(windows)]
    {
        marks.seq = win_clipboard_seq().unwrap_or(0);
    }
    Ok(())
}

fn worker_read_image(cb: &mut arboard::Clipboard) -> Result<Option<PngImage>> {
    let img = match cb.get_image() {
        Ok(i) => i,
        Err(arboard::Error::ContentNotAvailable) => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("clipboard get_image: {e}")),
    };
    let (w, h) = (img.width as u32, img.height as u32);
    if u64::from(w) * u64::from(h) > MAX_IMAGE_PIXELS {
        anyhow::bail!("clipboard image {w}x{h} exceeds the {MAX_IMAGE_PIXELS}-pixel cap");
    }
    let png = rgba_to_png(w, h, &img.bytes)?;
    if png.len() > CLIPBOARD_IMAGE_MAX_BYTES {
        anyhow::bail!(
            "clipboard image PNG is {} bytes (cap {CLIPBOARD_IMAGE_MAX_BYTES})",
            png.len()
        );
    }
    Ok(Some(PngImage { w, h, png }))
}

fn worker_write_image(
    cb: &mut arboard::Clipboard,
    png_bytes: &[u8],
    marks: &mut SelfMarks,
) -> Result<()> {
    let (w, h, rgba) = png_to_rgba(png_bytes)?;
    cb.set_image(arboard::ImageData {
        width: w as usize,
        height: h as usize,
        bytes: std::borrow::Cow::Borrowed(&rgba),
    })
    .map_err(|e| anyhow::anyhow!("clipboard set_image: {e}"))?;
    // Echo mark: hash our own deterministic re-encode of the pixels we
    // just wrote — matches what watch_tick would produce when it reads
    // this image back. (The inbound browser PNG hashes differently —
    // different encoder.) Belt-and-suspenders next to the seq mark:
    // catches the coalesced-seq race where another app also touched
    // the clipboard between our write and the next tick.
    if let Ok(reenc) = rgba_to_png(w, h, &rgba) {
        marks.img_hash = fnv1a64(&reenc);
    }
    #[cfg(windows)]
    {
        marks.seq = win_clipboard_seq().unwrap_or(0);
    }
    Ok(())
}

/// v2.1 — combined dedup hash for an html+text clipboard state. Both
/// the self-marks (post-write read-back) and the watcher tick hash the
/// SAME reading of the same clipboard, so echo suppression holds even
/// though the OS re-wraps CF_HTML on every write. The 0x1F separator
/// prevents (html="ab", text="c") colliding with (html="a", text="bc").
pub(crate) fn html_event_hash(html: &str, text: &str) -> u64 {
    let mut bytes = Vec::with_capacity(html.len() + text.len() + 1);
    bytes.extend_from_slice(html.as_bytes());
    bytes.push(0x1f);
    bytes.extend_from_slice(host_to_wire(text).as_bytes());
    fnv1a64(&bytes)
}

fn worker_read_html(cb: &mut arboard::Clipboard) -> Result<Option<HtmlPayload>> {
    let html = match cb.get().html() {
        Ok(h) => h,
        Err(arboard::Error::ContentNotAvailable) => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("clipboard get html: {e}")),
    };
    if html.is_empty() || html.len() > CLIPBOARD_HTML_MAX_BYTES {
        return Ok(None);
    }
    // The plain-text alternate rides along so the receiving side can
    // write both formats. Missing text (html-only producers) → empty.
    let text = match cb.get_text() {
        Ok(t) => host_to_wire(&t),
        Err(_) => String::new(),
    };
    Ok(Some(HtmlPayload { html, text }))
}

fn worker_write_html(
    cb: &mut arboard::Clipboard,
    html: &str,
    wire_text: &str,
    marks: &mut SelfMarks,
) -> Result<()> {
    let text_host = wire_to_host(wire_text);
    let alt = if text_host.is_empty() {
        None
    } else {
        Some(text_host.as_str())
    };
    // One clipboard transaction, both formats (arboard wraps the
    // CF_HTML header on Windows; text/html target on X11; NSPasteboard
    // html type on macOS).
    cb.set_html(html, alt)
        .map_err(|e| anyhow::anyhow!("clipboard set_html: {e}"))?;
    marks.text_hash = fnv1a64(host_to_wire(wire_text).as_bytes());
    // Echo mark from the READ-BACK — the OS re-wraps CF_HTML, so a
    // later tick reads different bytes than our input; hash what the
    // tick will actually see. Read-back failure → mark from the input
    // (better than nothing; the Windows seq mark still guards).
    marks.html_hash = match cb.get().html() {
        Ok(back) => html_event_hash(&back, wire_text),
        Err(_) => html_event_hash(html, wire_text),
    };
    #[cfg(windows)]
    {
        marks.seq = win_clipboard_seq().unwrap_or(0);
    }
    Ok(())
}

/// v2.2 — Windows RTF access via clipboard-win's raw API (arboard has
/// no custom-format surface). The "Rich Text Format" registered id is
/// process-stable; the open guard retries briefly against other apps
/// holding the clipboard.
#[cfg(windows)]
fn read_rtf_raw() -> Option<Vec<u8>> {
    let fmt = clipboard_win::register_format("Rich Text Format")?;
    let _guard = clipboard_win::Clipboard::new_attempts(10).ok()?;
    let mut out = Vec::new();
    match clipboard_win::raw::get_vec(fmt.get(), &mut out) {
        Ok(_) if !out.is_empty() && out.len() <= CLIPBOARD_NATIVE_MAX_BYTES => Some(out),
        _ => None,
    }
}

/// Append RTF to the CURRENT clipboard contents (no clear — the
/// html/text formats written moments earlier stay). Second transaction
/// after the arboard write; the tiny between-open race is acceptable
/// (worst case: a concurrent copy wins, which is the right outcome).
#[cfg(windows)]
fn append_rtf_raw(rtf: &[u8]) -> Result<()> {
    let fmt = clipboard_win::register_format("Rich Text Format")
        .ok_or_else(|| anyhow::anyhow!("RegisterClipboardFormat failed"))?;
    let _guard = clipboard_win::Clipboard::new_attempts(10)
        .map_err(|e| anyhow::anyhow!("open clipboard for RTF append: {e}"))?;
    clipboard_win::raw::set_without_clear(fmt.get(), rtf)
        .map_err(|e| anyhow::anyhow!("set RTF: {e}"))
}

fn worker_read_native(cb: &mut arboard::Clipboard) -> Result<Option<NativePayload>> {
    #[cfg(windows)]
    {
        let Some(rtf) = read_rtf_raw() else {
            return Ok(None);
        };
        let html = cb.get().html().unwrap_or_default();
        let text = cb.get_text().map(|t| host_to_wire(&t)).unwrap_or_default();
        if rtf.len() + html.len() + text.len() > CLIPBOARD_NATIVE_MAX_BYTES {
            return Ok(None);
        }
        Ok(Some(NativePayload { rtf, html, text }))
    }
    #[cfg(not(windows))]
    {
        let _ = cb;
        Ok(None)
    }
}

fn worker_write_native(
    cb: &mut arboard::Clipboard,
    payload: &NativePayload,
    marks: &mut SelfMarks,
) -> Result<()> {
    #[cfg(windows)]
    {
        if payload.rtf.is_empty() {
            anyhow::bail!("native write without RTF — use the html/text lanes");
        }
        // html+text first (one arboard transaction, clears the board),
        // then append the RTF format.
        if !payload.html.is_empty() {
            worker_write_html(cb, &payload.html, &payload.text, marks)?;
        } else {
            worker_write_text(cb, &payload.text, marks)?;
        }
        append_rtf_raw(&payload.rtf)?;
        marks.native_hash = fnv1a64(&payload.rtf);
        marks.seq = win_clipboard_seq().unwrap_or(0);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (cb, payload, marks);
        anyhow::bail!("native clipboard formats are Windows-only")
    }
}

/// Build the initial watcher state: snapshot the CURRENT clipboard so
/// pre-existing content is never pushed on subscribe — only changes
/// from here on.
fn install_watcher(
    cb: &mut arboard::Clipboard,
    events: WatchEvents,
    tx: tokio::sync::mpsc::Sender<ClipboardChange>,
    gate_seq: Option<u32>,
) -> WatcherState {
    // Image watching needs the Windows sequence-number gate to bound
    // `get_image` calls; without it (a window station that denies
    // clipboard access) fall back to text-only watching. FR-97 P3e-3a —
    // on Linux, the X11 change gate (`gate_seq`, `None` without one).
    #[cfg(windows)]
    let events = if events.image && win_clipboard_seq().is_none() {
        tracing::warn!("clipboard: no sequence-number access — image watching disabled");
        WatchEvents {
            image: false,
            ..events
        }
    } else {
        events
    };
    #[cfg(windows)]
    let _ = gate_seq;
    #[cfg(target_os = "linux")]
    let events = WatchEvents {
        image: events.image && gate_seq.is_some(),
        native: false,
        ..events
    };
    #[cfg(not(any(windows, target_os = "linux")))]
    let events = {
        let _ = gate_seq;
        WatchEvents {
            image: false,
            native: false,
            ..events
        }
    };
    let text_hash = match cb.get_text() {
        Ok(t) => fnv1a64(host_to_wire(&t).as_bytes()),
        Err(_) => 0,
    };
    // Snapshot current html too — otherwise the first tick after
    // subscribe would push pre-existing rich content.
    let html_hash = match cb.get().html() {
        Ok(h) => {
            let text = cb.get_text().map(|t| host_to_wire(&t)).unwrap_or_default();
            html_event_hash(&h, &text)
        }
        Err(_) => 0,
    };
    // Snapshot current RTF too (Windows) so pre-existing native
    // content isn't pushed on subscribe.
    #[cfg(windows)]
    let native_hash = read_rtf_raw().map(|r| fnv1a64(&r)).unwrap_or(0);
    #[cfg(not(windows))]
    let native_hash = 0;
    WatcherState {
        events,
        tx,
        #[cfg(windows)]
        last_seen_seq: win_clipboard_seq().unwrap_or(0),
        #[cfg(target_os = "linux")]
        last_seen_seq: gate_seq.unwrap_or(0),
        last_text_hash: text_hash,
        last_img_hash: 0,
        last_html_hash: html_hash,
        last_native_hash: native_hash,
        retry: false,
    }
}

/// One watcher tick. Cheap when nothing changed (Windows: one
/// syscall; elsewhere: one text read + hash). Text wins over image
/// when both are present.
fn watch_tick(
    cb: &mut arboard::Clipboard,
    w: &mut WatcherState,
    marks: &SelfMarks,
    gate_seq: Option<u32>,
) {
    #[cfg(windows)]
    {
        let _ = gate_seq;
        if let Some(seq) = win_clipboard_seq() {
            if !w.retry && seq == w.last_seen_seq {
                return;
            }
            w.last_seen_seq = seq;
            if seq != 0 && seq == marks.seq {
                // The change was our own write — swallow.
                w.retry = false;
                return;
            }
        }
        // Sequence number unavailable → hash polling below still works.
    }
    // FR-97 P3e-3a — the X11 change gate: no owner change, nothing read.
    // Our own writes pass it and are swallowed by the hashes below.
    #[cfg(target_os = "linux")]
    match gate_seq {
        Some(seq) => {
            if !w.retry && seq == w.last_seen_seq {
                return;
            }
            w.last_seen_seq = seq;
        }
        // No gate, or it broke: text is read every tick, images never.
        None => w.events.image = false,
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = gate_seq;
    w.retry = false;
    // v2.2 — richest format wins, native (RTF) on top: only RTF
    // carries a document's EMBEDDED images. Below it: html (carries a
    // text alt) beats plain text beats image.
    #[cfg(windows)]
    if w.events.native
        && let Some(rtf) = read_rtf_raw()
    {
        let h = fnv1a64(&rtf);
        if h == w.last_native_hash || h == marks.native_hash {
            w.last_native_hash = h;
            return;
        }
        let html = cb.get().html().unwrap_or_default();
        let text = cb.get_text().map(|t| host_to_wire(&t)).unwrap_or_default();
        if rtf.len() + html.len() + text.len() > CLIPBOARD_NATIVE_MAX_BYTES {
            w.last_native_hash = h;
            return;
        }
        match w
            .tx
            .try_send(ClipboardChange::Native(Box::new(NativePayload {
                rtf,
                html,
                text,
            }))) {
            Ok(()) => w.last_native_hash = h,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => w.retry = true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
        return;
    }
    // v2.1 — html (carries a text alt) beats plain text beats image.
    if w.events.html
        && let Ok(html) = cb.get().html()
        && !html.is_empty()
        && html.len() <= CLIPBOARD_HTML_MAX_BYTES
    {
        let text = cb.get_text().map(|t| host_to_wire(&t)).unwrap_or_default();
        let h = html_event_hash(&html, &text);
        if h == w.last_html_hash || h == marks.html_hash {
            w.last_html_hash = h;
            return;
        }
        match w
            .tx
            .try_send(ClipboardChange::Html(HtmlPayload { html, text }))
        {
            Ok(()) => w.last_html_hash = h,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => w.retry = true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
        return;
    }
    let text = match cb.get_text() {
        Ok(t) => host_to_wire(&t),
        Err(arboard::Error::ContentNotAvailable) => String::new(),
        Err(_) => {
            // Transient (another process holds the clipboard open) —
            // re-attempt next tick even if the seq doesn't move again.
            w.retry = true;
            return;
        }
    };
    if !text.is_empty() {
        if !w.events.text {
            return;
        }
        let h = fnv1a64(text.as_bytes());
        if h == w.last_text_hash || h == marks.text_hash {
            w.last_text_hash = h;
            return;
        }
        if text.len() > MAX_CLIPBOARD_BYTES {
            // Too big to auto-push; remember it so we don't re-read
            // every tick. Explicit reads still serve it (chunked).
            w.last_text_hash = h;
            return;
        }
        match w.tx.try_send(ClipboardChange::Text(text)) {
            Ok(()) => w.last_text_hash = h,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => w.retry = true,
            // Forwarder task gone — an Unwatch is on its way; stay quiet.
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
        // Load-bearing on Windows and Linux, where the image block below
        // follows; redundant everywhere else, where it is the last statement
        // of the function. Scoped rather than removed — deleting it would
        // fall through into the image path.
        #[cfg_attr(not(any(windows, target_os = "linux")), allow(clippy::needless_return))]
        return;
    }
    // Empty text — maybe an image. Only behind a change gate (Windows'
    // sequence number; FR-97 P3e-3a, the X11 gate), which bounds how often
    // we pay for a full image read + PNG encode.
    #[cfg(any(windows, target_os = "linux"))]
    if w.events.image {
        let img = match cb.get_image() {
            Ok(i) => i,
            Err(_) => return,
        };
        let (iw, ih) = (img.width as u32, img.height as u32);
        if u64::from(iw) * u64::from(ih) > MAX_IMAGE_PIXELS {
            return;
        }
        let Ok(png) = rgba_to_png(iw, ih, &img.bytes) else {
            return;
        };
        if png.len() > CLIPBOARD_IMAGE_MAX_BYTES {
            return;
        }
        let h = fnv1a64(&png);
        if h == w.last_img_hash || h == marks.img_hash {
            w.last_img_hash = h;
            return;
        }
        match w
            .tx
            .try_send(ClipboardChange::Image(PngImage { w: iw, h: ih, png }))
        {
            Ok(()) => w.last_img_hash = h,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => w.retry = true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

// ── Line-ending canonicalization (clipboard protocol v2) ────────────────────
//
// The wire format is canonical LF. The browser normalizes CRLF/CR → LF
// before sending and before hashing (its echo-suppression gate compares
// content hashes); the agent mirrors that on every OS-clipboard
// boundary. Without this, LF-only multiline text written verbatim into
// the Win32 clipboard violates the CF_UNICODETEXT CRLF convention —
// classic edit controls, cmd.exe and several editors mis-render it
// (lines run together / split oddly), which presented in the field as
// "pasted lines in the wrong order". It also makes hash-based echo
// suppression sound: both sides hash the same canonical bytes.

/// Canonicalize host-clipboard text to wire form: `\r\n` → `\n`,
/// lone `\r` → `\n`. Applied to every `get_text` result before it is
/// sent, hashed or compared.
pub(crate) fn host_to_wire(text: &str) -> String {
    if !text.contains('\r') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

/// Expand canonical LF to CRLF for the Windows clipboard. Idempotent —
/// input is canonicalized first, so pre-existing `\r\n` sequences come
/// out as exactly one `\r\n`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn lf_to_crlf(text: &str) -> String {
    host_to_wire(text).replace('\n', "\r\n")
}

/// Convert wire text (canonical LF) to the host's clipboard line-ending
/// convention before `set_text`: CRLF on Windows, canonical LF elsewhere.
pub(crate) fn wire_to_host(text: &str) -> String {
    #[cfg(windows)]
    {
        lf_to_crlf(text)
    }
    #[cfg(not(windows))]
    {
        host_to_wire(text)
    }
}

/// Incoming clipboard DC message shape. Parsed from the JSON payload
/// the browser sends; the handler in `peer.rs` dispatches on the `t`
/// discriminator.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "t")]
pub(crate) enum ClipboardIncoming {
    #[serde(rename = "clipboard:write")]
    Write {
        text: String,
        /// v2 — optional browser-assigned write id. When present the
        /// agent replies `clipboard:write-ack { id, bytes }` after the
        /// OS clipboard write succeeds (the browser gates its deferred
        /// Ctrl+V keystroke on that ack). Old browsers omit it → no
        /// ack, exact v1 behavior.
        #[serde(default)]
        id: Option<String>,
    },
    #[serde(rename = "clipboard:write-chunk")]
    WriteChunk {
        id: String,
        seq: u32,
        text: String,
        last: bool,
    },
    #[serde(rename = "clipboard:read")]
    Read {
        #[serde(default)]
        req_id: Option<u64>,
        /// v2 — content kinds the browser can handle in the reply.
        /// `["text","image"]` lets the agent answer an image-holding
        /// clipboard with `clipboard:img-begin` + binary frames.
        /// Empty (old browsers) means text-only replies.
        #[serde(default)]
        accept: Vec<String>,
    },
    /// v2 — start pushing unsolicited `clipboard:event` /
    /// `clipboard:img-begin` messages when the HOST clipboard changes.
    /// `events` lists the kinds the browser wants (`"text"`,
    /// `"image"`); image watching is honoured on Windows only.
    #[serde(rename = "clipboard:subscribe")]
    Subscribe {
        #[serde(default)]
        events: Vec<String>,
    },
    /// v2 — stop pushing change events (toggle flipped off). Also
    /// implied by the DC closing.
    #[serde(rename = "clipboard:unsubscribe")]
    Unsubscribe,
    /// v2 — image write header. Binary frames totalling `bytes` bytes
    /// of PNG follow on the same DC, terminated by `clipboard:img-end`
    /// with the matching `id`.
    #[serde(rename = "clipboard:img-begin")]
    ImgBegin {
        id: String,
        w: u32,
        h: u32,
        bytes: u64,
        #[serde(default)]
        format: String,
    },
    /// v2 — image write trailer; the agent decodes the accumulated PNG
    /// and writes it to the OS clipboard, then acks with the `id`.
    #[serde(rename = "clipboard:img-end")]
    ImgEnd { id: String },
    /// v2.1 — HTML write header. Binary frames totalling
    /// `html_bytes + text_bytes` follow (html UTF-8 first, then the
    /// plain-text alt), terminated by `clipboard:html-end`.
    #[serde(rename = "clipboard:html-begin")]
    HtmlBegin {
        id: String,
        html_bytes: u64,
        text_bytes: u64,
    },
    /// v2.1 — HTML write trailer; the agent splits the accumulated
    /// bytes, writes html+text atomically, then acks with the `id`.
    #[serde(rename = "clipboard:html-end")]
    HtmlEnd { id: String },
    /// v2.2 — NATIVE write header. Binary frames totalling
    /// `rtf_bytes + html_bytes + text_bytes` follow (rtf, then html
    /// UTF-8, then text UTF-8), terminated by `clipboard:native-end`.
    #[serde(rename = "clipboard:native-begin")]
    NativeBegin {
        id: String,
        rtf_bytes: u64,
        html_bytes: u64,
        text_bytes: u64,
    },
    /// v2.2 — NATIVE write trailer; the agent splits and writes
    /// RTF + html + text, then acks with the `id`.
    #[serde(rename = "clipboard:native-end")]
    NativeEnd { id: String },
}

/// Hard ceiling on the total reassembled clipboard payload — both
/// for inbound writes (browser → agent) and outbound content
/// (agent → browser when chunking the read response). Anything above
/// this is dropped with an error reply. 1 MB is comfortably above
/// any reasonable clipboard text payload (a 200-page novel manuscript
/// is ~500 KB UTF-8) and well under the 100 MB-ish where SCTP's
/// buffer accounting gets uncomfortable.
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// Soft byte budget per outbound chunk. Stays well under webrtc-rs's
/// SCTP `max_message_size=65536` ceiling so the JSON envelope
/// overhead + UTF-8 expansion can't push a chunk over the boundary.
/// Used by the agent's `clipboard:content-chunk` emitter; the
/// browser uses the same constant on its `clipboard:write-chunk`
/// emitter (`useRemoteControl.ts::CLIPBOARD_CHUNK_BYTES`). Keep both
/// in lockstep.
pub const CHUNK_BYTES: usize = 14 * 1024;

/// Per-session reassembler for `clipboard:write-chunk` envelopes.
/// One instance per [`attach_clipboard_handler`] invocation; lookups
/// keyed by the browser-assigned `id`. Drops entries on the final
/// chunk (`last: true`) and on the next call to [`Self::write_chunk`]
/// that exceeds [`MAX_CLIPBOARD_BYTES`] (sets the entry to an
/// "errored" sentinel via removal — caller emits the error reply).
#[derive(Default)]
pub(crate) struct WriteReassembler {
    in_flight: std::collections::HashMap<String, WriteAccumulator>,
}

pub(crate) struct WriteAccumulator {
    buf: String,
    next_seq: u32,
}

/// Outcome of feeding one chunk through the reassembler. `Pending`
/// means more chunks are expected; `Complete(text)` means the
/// `last` bit fired and the caller should write `text` to the OS
/// clipboard; `Rejected(reason)` means the chunk violated an
/// invariant (size cap exceeded, seq out of order) and the caller
/// should emit a `clipboard:error` reply with the reason.
#[derive(Debug)]
pub(crate) enum WriteChunkOutcome {
    Pending,
    Complete(String),
    Rejected(String),
}

impl WriteReassembler {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed one inbound `clipboard:write-chunk` envelope.
    pub(crate) fn feed(
        &mut self,
        id: String,
        seq: u32,
        text: String,
        last: bool,
    ) -> WriteChunkOutcome {
        // Pull the existing accumulator out by value so we don't have
        // to juggle a borrow of `self.in_flight` across the rejection
        // paths (which need to drop the entry). If no accumulator
        // exists yet, this is the first chunk for `id`.
        let mut acc = self.in_flight.remove(&id).unwrap_or(WriteAccumulator {
            buf: String::new(),
            next_seq: 0,
        });
        if seq != acc.next_seq {
            // Drop the partial: the sender's state is unrecoverable;
            // they need to restart with a fresh `id`.
            return WriteChunkOutcome::Rejected(format!(
                "clipboard chunk seq mismatch — expected {}, got {seq}",
                acc.next_seq
            ));
        }
        if acc.buf.len() + text.len() > MAX_CLIPBOARD_BYTES {
            // Drop the partial: caller hit the hard cap.
            return WriteChunkOutcome::Rejected(format!(
                "clipboard payload exceeds {MAX_CLIPBOARD_BYTES}-byte cap"
            ));
        }
        acc.buf.push_str(&text);
        acc.next_seq = acc.next_seq.saturating_add(1);
        if last {
            WriteChunkOutcome::Complete(acc.buf)
        } else {
            self.in_flight.insert(id, acc);
            WriteChunkOutcome::Pending
        }
    }

    /// Number of in-flight write transactions. Test-only helper.
    #[cfg(test)]
    pub(crate) fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }
}

/// Split a UTF-8 string into JSON-safe chunks of at most
/// [`CHUNK_BYTES`] bytes each, splitting on UTF-8 codepoint
/// boundaries so reassembly via plain string concatenation always
/// yields the original. The agent's `clipboard:content-chunk`
/// emitter uses this; tests lock the boundary handling.
/// Hard ceiling on a PNG image payload on the clipboard DC, both
/// directions. Above this the agent refuses inbound transfers and the
/// watcher skips auto-pushing (explicit reads get an error). 8 MiB
/// comfortably covers 4K screenshots (typically 1–4 MiB as PNG) while
/// bounding memory and DC head-of-line blocking.
pub const CLIPBOARD_IMAGE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Decompression-bomb guard: reject images whose HEADER declares more
/// pixels than a 4096×4096 canvas before allocating the RGBA buffer
/// (that's already 64 MiB at 4 B/px; a crafted 20000×20000 PNG would
/// otherwise balloon to 1.6 GB from a few KB on the wire).
pub const MAX_IMAGE_PIXELS: u64 = 4096 * 4096;

/// v2.1 — cap on an HTML clipboard payload (html + text alt combined)
/// on the wire, both directions. Chrome's sanitized copies inline
/// styles aggressively (a big table can reach hundreds of KB); 4 MiB
/// gives generous headroom while bounding memory + DC head-of-line.
pub const CLIPBOARD_HTML_MAX_BYTES: usize = 4 * 1024 * 1024;

/// v2.2 — cap on a NATIVE clipboard payload (RTF + html + text
/// combined) on the wire and through the loopback bridge. RTF embeds
/// images as hex (≈2× the binary size), so a Word selection with a
/// few pictures runs to megabytes; 16 MiB bounds memory + DC
/// head-of-line while covering real documents.
pub const CLIPBOARD_NATIVE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Binary frame size for agent → browser image sends. 64 KiB matches
/// the folder-zip download pump (field-proven; Chrome's inbound SCTP
/// message cap is 256 KiB). The browser → agent direction uses 16 KiB
/// frames instead — webrtc-rs's inbound `max_message_size` is 65536
/// and 64 KiB frames sat exactly on that boundary (see the files-DC
/// pump comment in `useRemoteControl.ts`).
pub(crate) const IMG_FRAME_BYTES_TX: usize = 64 * 1024;

/// Encode raw RGBA8 pixels to PNG (the clipboard-DC wire format for
/// images). Runs on the clipboard worker thread — blocking there is
/// fine.
pub(crate) fn rgba_to_png(w: u32, h: u32, rgba: &[u8]) -> Result<Vec<u8>> {
    let expected = (w as usize)
        .checked_mul(h as usize)
        .and_then(|p| p.checked_mul(4))
        .ok_or_else(|| anyhow::anyhow!("image dimensions overflow"))?;
    if rgba.len() != expected {
        anyhow::bail!(
            "rgba buffer is {} bytes, expected {expected} for {w}x{h}",
            rgba.len()
        );
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().context("png write_header")?;
        writer
            .write_image_data(rgba)
            .context("png write_image_data")?;
    }
    Ok(out)
}

/// Decode a PNG into RGBA8. Enforces [`MAX_IMAGE_PIXELS`] from the
/// header BEFORE allocating the pixel buffer (bomb guard). Non-RGBA
/// color types are expanded (palette → RGB, 16-bit → 8-bit) and
/// padded to RGBA with opaque alpha.
pub(crate) fn png_to_rgba(png_bytes: &[u8]) -> Result<(u32, u32, Vec<u8>)> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().context("png read_info")?;
    let info = reader.info();
    let (w, h) = (info.width, info.height);
    if w == 0 || h == 0 {
        anyhow::bail!("png has a zero dimension");
    }
    if u64::from(w) * u64::from(h) > MAX_IMAGE_PIXELS {
        anyhow::bail!("png {w}x{h} exceeds the {MAX_IMAGE_PIXELS}-pixel cap");
    }
    let out_size = reader
        .output_buffer_size()
        .ok_or_else(|| anyhow::anyhow!("png output size overflows"))?;
    let mut buf = vec![0u8; out_size];
    let out = reader.next_frame(&mut buf).context("png next_frame")?;
    buf.truncate(out.buffer_size());
    let rgba = match out.color_type {
        png::ColorType::Rgba => buf,
        png::ColorType::Rgb => {
            let mut v = Vec::with_capacity(buf.len() / 3 * 4);
            for px in buf.chunks_exact(3) {
                v.extend_from_slice(px);
                v.push(0xff);
            }
            v
        }
        png::ColorType::Grayscale => {
            let mut v = Vec::with_capacity(buf.len() * 4);
            for &g in &buf {
                v.extend_from_slice(&[g, g, g, 0xff]);
            }
            v
        }
        png::ColorType::GrayscaleAlpha => {
            let mut v = Vec::with_capacity(buf.len() * 2);
            for px in buf.chunks_exact(2) {
                v.extend_from_slice(&[px[0], px[0], px[0], px[1]]);
            }
            v
        }
        other => anyhow::bail!("unsupported png color type after expand: {other:?}"),
    };
    Ok((w, h, rgba))
}

/// Reassembles an inbound browser → agent RICH transfer (image OR
/// html): a `clipboard:img-begin`/`clipboard:html-begin` header, raw
/// binary frames, then the matching `-end` trailer. One transfer in
/// flight at a time — the browser serializes them, so anonymous
/// binary frames always belong to the last announced header; a new
/// begin replaces (drops) a dangling one. Byte twin of
/// [`WriteReassembler`]; rejections mirror its reason-string contract.
#[derive(Default)]
pub(crate) struct RichRx {
    in_flight: Option<RichRxInFlight>,
}

enum RichRxKind {
    Image { w: u32, h: u32 },
    Html { html_bytes: usize },
    Native { rtf_bytes: usize, html_bytes: usize },
}

struct RichRxInFlight {
    id: String,
    kind: RichRxKind,
    declared: usize,
    buf: Vec<u8>,
}

/// Completed inbound rich payload from [`RichRx::end`].
#[derive(Debug)]
pub(crate) enum RichPayload {
    Image(PngImage),
    Html(HtmlPayload),
    Native(Box<NativePayload>),
}

impl RichRx {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn replace_dangling(&mut self) {
        if let Some(stale) = self.in_flight.take() {
            // The browser serializes transfers; a dangling one means it
            // gave up mid-stream (reload / error). Replace it.
            tracing::debug!(stale = %stale.id, "clipboard: replacing dangling rich transfer");
        }
    }

    pub(crate) fn begin_image(
        &mut self,
        id: String,
        w: u32,
        h: u32,
        bytes: u64,
        format: &str,
    ) -> Result<(), String> {
        if !format.eq_ignore_ascii_case("png") {
            return Err(format!(
                "unsupported clipboard image format {format:?} (png only)"
            ));
        }
        if bytes == 0 || bytes > CLIPBOARD_IMAGE_MAX_BYTES as u64 {
            return Err(format!(
                "clipboard image {bytes} bytes outside the (0, {CLIPBOARD_IMAGE_MAX_BYTES}] cap"
            ));
        }
        if w == 0 || h == 0 || u64::from(w) * u64::from(h) > MAX_IMAGE_PIXELS {
            return Err(format!(
                "clipboard image dims {w}x{h} outside the {MAX_IMAGE_PIXELS}-pixel cap"
            ));
        }
        self.replace_dangling();
        self.in_flight = Some(RichRxInFlight {
            id,
            kind: RichRxKind::Image { w, h },
            declared: bytes as usize,
            buf: Vec::with_capacity(bytes as usize),
        });
        Ok(())
    }

    pub(crate) fn begin_html(
        &mut self,
        id: String,
        html_bytes: u64,
        text_bytes: u64,
    ) -> Result<(), String> {
        let total = html_bytes.saturating_add(text_bytes);
        if html_bytes == 0 || total > CLIPBOARD_HTML_MAX_BYTES as u64 {
            return Err(format!(
                "clipboard html payload {total} bytes outside the (0, {CLIPBOARD_HTML_MAX_BYTES}] cap"
            ));
        }
        self.replace_dangling();
        self.in_flight = Some(RichRxInFlight {
            id,
            kind: RichRxKind::Html {
                html_bytes: html_bytes as usize,
            },
            declared: total as usize,
            buf: Vec::with_capacity(total as usize),
        });
        Ok(())
    }

    pub(crate) fn begin_native(
        &mut self,
        id: String,
        rtf_bytes: u64,
        html_bytes: u64,
        text_bytes: u64,
    ) -> Result<(), String> {
        let total = rtf_bytes
            .saturating_add(html_bytes)
            .saturating_add(text_bytes);
        if rtf_bytes == 0 || total > CLIPBOARD_NATIVE_MAX_BYTES as u64 {
            return Err(format!(
                "clipboard native payload {total} bytes outside the (0, {CLIPBOARD_NATIVE_MAX_BYTES}] cap"
            ));
        }
        self.replace_dangling();
        self.in_flight = Some(RichRxInFlight {
            id,
            kind: RichRxKind::Native {
                rtf_bytes: rtf_bytes as usize,
                html_bytes: html_bytes as usize,
            },
            declared: total as usize,
            buf: Vec::with_capacity(total as usize),
        });
        Ok(())
    }

    pub(crate) fn frame(&mut self, data: &[u8]) -> Result<(), String> {
        let Some(f) = self.in_flight.as_mut() else {
            return Err("binary frame with no rich transfer in flight".into());
        };
        if f.buf.len() + data.len() > f.declared {
            let id = f.id.clone();
            self.in_flight = None;
            return Err(format!("rich transfer {id} overflowed its declared length"));
        }
        f.buf.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn end(&mut self, id: &str) -> Result<RichPayload, String> {
        let Some(f) = self.in_flight.take() else {
            return Err("end with no rich transfer in flight".into());
        };
        if f.id != id {
            return Err(format!("end id {id:?} does not match in-flight {:?}", f.id));
        }
        if f.buf.len() != f.declared {
            return Err(format!(
                "rich transfer {id} ended at {} of {} declared bytes",
                f.buf.len(),
                f.declared
            ));
        }
        match f.kind {
            RichRxKind::Image { w, h } => Ok(RichPayload::Image(PngImage { w, h, png: f.buf })),
            RichRxKind::Html { html_bytes } => {
                let (html_raw, text_raw) = f.buf.split_at(html_bytes.min(f.buf.len()));
                let html = String::from_utf8(html_raw.to_vec())
                    .map_err(|_| format!("rich transfer {id}: html is not valid UTF-8"))?;
                let text = String::from_utf8(text_raw.to_vec())
                    .map_err(|_| format!("rich transfer {id}: text is not valid UTF-8"))?;
                Ok(RichPayload::Html(HtmlPayload { html, text }))
            }
            RichRxKind::Native {
                rtf_bytes,
                html_bytes,
            } => {
                let (rtf_raw, rest) = f.buf.split_at(rtf_bytes.min(f.buf.len()));
                let (html_raw, text_raw) = rest.split_at(html_bytes.min(rest.len()));
                let html = String::from_utf8(html_raw.to_vec())
                    .map_err(|_| format!("rich transfer {id}: html is not valid UTF-8"))?;
                let text = String::from_utf8(text_raw.to_vec())
                    .map_err(|_| format!("rich transfer {id}: text is not valid UTF-8"))?;
                Ok(RichPayload::Native(Box::new(NativePayload {
                    rtf: rtf_raw.to_vec(),
                    html,
                    text,
                })))
            }
        }
    }

    /// Test-only visibility.
    #[cfg(test)]
    pub(crate) fn is_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }
}

pub(crate) fn split_into_chunks(text: &str) -> Vec<&str> {
    if text.len() <= CHUNK_BYTES {
        // Even a string with all 4-byte UTF-8 codepoints fits in one
        // chunk if `text.len()` is already under the limit — String
        // tracks byte length, so this is correct.
        return vec![text];
    }
    let mut out = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let target_end = (start + CHUNK_BYTES).min(text.len());
        // Walk back to the nearest UTF-8 boundary. `is_char_boundary`
        // is O(1) per call. At worst we walk back 3 bytes (max
        // continuation-byte run for valid UTF-8).
        let mut end = target_end;
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        // `end == start` shouldn't happen for a non-empty text with
        // CHUNK_BYTES ≥ 4 (max codepoint width), but guard anyway:
        // emit at least one full codepoint per chunk to avoid an
        // infinite loop. `char_indices()` gives us the next boundary
        // strictly past `start`.
        if end == start {
            end = text[start..]
                .char_indices()
                .nth(1)
                .map(|(i, _)| start + i)
                .unwrap_or(text.len());
        }
        out.push(&text[start..end]);
        start = end;
    }
    out
}

/// FR-97 P3e-3a — the change gate against a real X server (CI's Xvfb step,
/// `ROOMLERD_TEST_X11=1`): another client takes CLIPBOARD, as a copy does, and
/// the gate counts it and then holds. Only under `ROOMLERD_TEST_X11=1`: taking
/// CLIPBOARD empties the clipboard of whoever is at that display.
#[cfg(all(test, target_os = "linux"))]
mod x11_gate_tests {
    use super::x11_gate::Gate;
    use x11rb::connection::Connection as _;
    use x11rb::protocol::xproto::{ConnectionExt as _, CreateWindowAux, WindowClass};
    use x11rb::wrapper::ConnectionExt as _;

    #[test]
    fn x11_real_the_gate_counts_a_copy() {
        if std::env::var("ROOMLERD_TEST_X11").as_deref() != Ok("1") {
            eprintln!("ROOMLERD_TEST_X11 unset — skipping (the Xvfb lane sets it)");
            return;
        }
        let mut gate = Gate::connect().expect("ROOMLERD_TEST_X11=1 but the gate did not open");
        let before = gate.seq().expect("a counter");
        let (conn, screen) = x11rb::connect(None).expect("the same X server");
        let root = conn.setup().roots[screen].root;
        let win = conn.generate_id().unwrap();
        conn.create_window(
            0,
            win,
            root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_ONLY,
            0,
            &CreateWindowAux::new(),
        )
        .unwrap();
        let clipboard = conn
            .intern_atom(false, b"CLIPBOARD")
            .unwrap()
            .reply()
            .unwrap()
            .atom;
        conn.set_selection_owner(win, clipboard, x11rb::CURRENT_TIME)
            .unwrap();
        conn.sync().unwrap();
        let mut after = before;
        for _ in 0..50 {
            after = gate.seq().expect("a counter");
            if after != before {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_ne!(after, before, "the owner change was counted");
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Only an owner change moves it. The lane runs one test at a time; a
        // parallel run may have another test take CLIPBOARD meanwhile, so a
        // later count must come with an owner other than ours.
        let later = gate.seq().expect("a counter");
        if later != after {
            let owner = conn
                .get_selection_owner(clipboard)
                .unwrap()
                .reply()
                .unwrap()
                .owner;
            assert_ne!(owner, win, "the counter moved while CLIPBOARD stayed ours");
        }
        eprintln!("x11-real: the clipboard gate counted an owner change ({before} → {after})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_incoming_write() {
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:write","text":"hi"}"#).unwrap();
        match m {
            ClipboardIncoming::Write { text, .. } => assert_eq!(text, "hi"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_incoming_read_with_req_id() {
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:read","req_id":42}"#).unwrap();
        match m {
            ClipboardIncoming::Read { req_id, .. } => assert_eq!(req_id, Some(42)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_incoming_read_without_req_id() {
        let m: ClipboardIncoming = serde_json::from_str(r#"{"t":"clipboard:read"}"#).unwrap();
        match m {
            ClipboardIncoming::Read { req_id, .. } => assert_eq!(req_id, None),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_discriminator_fails_to_parse() {
        let res: serde_json::Result<ClipboardIncoming> =
            serde_json::from_str(r#"{"t":"clipboard:delete"}"#);
        assert!(res.is_err(), "unknown discriminator must not parse");
    }

    #[test]
    fn parse_incoming_write_chunk() {
        let m: ClipboardIncoming = serde_json::from_str(
            r#"{"t":"clipboard:write-chunk","id":"abc","seq":3,"text":"hello","last":true}"#,
        )
        .unwrap();
        match m {
            ClipboardIncoming::WriteChunk {
                id,
                seq,
                text,
                last,
            } => {
                assert_eq!(id, "abc");
                assert_eq!(seq, 3);
                assert_eq!(text, "hello");
                assert!(last);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn write_reassembler_accumulates_then_completes_on_last() {
        let mut r = WriteReassembler::new();
        assert!(matches!(
            r.feed("x".into(), 0, "hel".into(), false),
            WriteChunkOutcome::Pending
        ));
        assert_eq!(r.in_flight_count(), 1);
        assert!(matches!(
            r.feed("x".into(), 1, "lo ".into(), false),
            WriteChunkOutcome::Pending
        ));
        match r.feed("x".into(), 2, "world".into(), true) {
            WriteChunkOutcome::Complete(text) => assert_eq!(text, "hello world"),
            other => panic!("expected Complete, got {other:?}"),
        }
        assert_eq!(r.in_flight_count(), 0, "completed entry must be dropped");
    }

    #[test]
    fn write_reassembler_interleaves_multiple_ids() {
        let mut r = WriteReassembler::new();
        r.feed("a".into(), 0, "AA".into(), false);
        r.feed("b".into(), 0, "BB".into(), false);
        assert_eq!(r.in_flight_count(), 2);
        let a = r.feed("a".into(), 1, "aa".into(), true);
        let b = r.feed("b".into(), 1, "bb".into(), true);
        assert!(
            matches!(a, WriteChunkOutcome::Complete(ref s) if s == "AAaa"),
            "got {a:?}"
        );
        assert!(
            matches!(b, WriteChunkOutcome::Complete(ref s) if s == "BBbb"),
            "got {b:?}"
        );
        assert_eq!(r.in_flight_count(), 0);
    }

    #[test]
    fn write_reassembler_rejects_out_of_order_seq() {
        let mut r = WriteReassembler::new();
        r.feed("x".into(), 0, "first".into(), false);
        match r.feed("x".into(), 5, "wat".into(), false) {
            WriteChunkOutcome::Rejected(reason) => {
                assert!(reason.contains("seq mismatch"), "reason was: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(
            r.in_flight_count(),
            0,
            "rejected entry must be dropped so a fresh start works"
        );
    }

    #[test]
    fn write_reassembler_rejects_oversized_payload() {
        let mut r = WriteReassembler::new();
        // Build up just over the 1 MB cap across 2 chunks of 600 KB each.
        let chunk = "x".repeat(600 * 1024);
        let first = r.feed("big".into(), 0, chunk.clone(), false);
        assert!(matches!(first, WriteChunkOutcome::Pending), "got {first:?}");
        match r.feed("big".into(), 1, chunk, true) {
            WriteChunkOutcome::Rejected(reason) => {
                assert!(
                    reason.contains("byte cap"),
                    "reason should mention the cap: {reason}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(r.in_flight_count(), 0);
    }

    #[test]
    fn split_into_chunks_passes_through_small_text() {
        let chunks = split_into_chunks("hello");
        assert_eq!(chunks, vec!["hello"]);
    }

    #[test]
    fn split_into_chunks_splits_long_ascii_at_chunk_bytes() {
        let text = "a".repeat(CHUNK_BYTES * 3);
        let chunks = split_into_chunks(&text);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.len() <= CHUNK_BYTES));
        // Round-trip via concatenation reproduces the original.
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn split_into_chunks_respects_utf8_codepoint_boundary() {
        // Build a string slightly over CHUNK_BYTES where a multi-byte
        // codepoint straddles the natural split point. The chunker
        // must walk back to the previous boundary so each chunk parses
        // as valid UTF-8.
        //
        // Crafting: fill to (CHUNK_BYTES - 2) with ASCII, then a 4-byte
        // codepoint (🦀 = 4 bytes UTF-8). The natural split at
        // CHUNK_BYTES lands in the middle of the crab — chunker must
        // either emit the codepoint whole in chunk 0 or push it whole
        // to chunk 1.
        let prefix = "a".repeat(CHUNK_BYTES - 2);
        let text = format!("{prefix}🦀b");
        let chunks = split_into_chunks(&text);
        // Concatenation always reproduces the original — strongest
        // invariant. The number of chunks doesn't matter for this
        // assertion.
        assert_eq!(chunks.concat(), text);
        // Each chunk must be valid UTF-8 (slicing &str at a non-boundary
        // would panic before we got here; we additionally assert each
        // chunk is non-empty + within byte budget).
        for c in &chunks {
            assert!(!c.is_empty(), "no empty chunks");
            assert!(
                c.len() <= CHUNK_BYTES,
                "chunk len {} exceeds budget {}",
                c.len(),
                CHUNK_BYTES
            );
        }
    }

    #[test]
    fn split_into_chunks_handles_empty_string() {
        // Empty text → single empty chunk (caller still emits
        // `clipboard:content-chunk { text: "", last: true }` once).
        let chunks = split_into_chunks("");
        assert_eq!(chunks, vec![""]);
    }

    // ── v2: parse locks for the additive fields + new variants ─────────

    #[test]
    fn parse_incoming_write_with_id() {
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:write","text":"hi","id":"cb-7"}"#).unwrap();
        match m {
            ClipboardIncoming::Write { text, id } => {
                assert_eq!(text, "hi");
                assert_eq!(id.as_deref(), Some("cb-7"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_incoming_write_without_id_stays_v1_compatible() {
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:write","text":"hi"}"#).unwrap();
        match m {
            ClipboardIncoming::Write { id, .. } => assert!(id.is_none()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_incoming_read_with_accept() {
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:read","req_id":1,"accept":["text","image"]}"#)
                .unwrap();
        match m {
            ClipboardIncoming::Read { req_id, accept } => {
                assert_eq!(req_id, Some(1));
                assert_eq!(accept, vec!["text", "image"]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_incoming_read_without_accept_stays_v1_compatible() {
        let m: ClipboardIncoming = serde_json::from_str(r#"{"t":"clipboard:read"}"#).unwrap();
        match m {
            ClipboardIncoming::Read { accept, .. } => assert!(accept.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_incoming_subscribe_unsubscribe() {
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:subscribe","events":["text","image"]}"#)
                .unwrap();
        match m {
            ClipboardIncoming::Subscribe { events } => assert_eq!(events, vec!["text", "image"]),
            other => panic!("unexpected: {other:?}"),
        }
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:unsubscribe"}"#).unwrap();
        assert!(matches!(m, ClipboardIncoming::Unsubscribe));
    }

    #[test]
    fn parse_incoming_img_begin_end() {
        let m: ClipboardIncoming = serde_json::from_str(
            r#"{"t":"clipboard:img-begin","id":"cb-1","w":2,"h":3,"bytes":99,"format":"png"}"#,
        )
        .unwrap();
        match m {
            ClipboardIncoming::ImgBegin {
                id,
                w,
                h,
                bytes,
                format,
            } => {
                assert_eq!(
                    (id.as_str(), w, h, bytes, format.as_str()),
                    ("cb-1", 2, 3, 99, "png")
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:img-end","id":"cb-1"}"#).unwrap();
        match m {
            ClipboardIncoming::ImgEnd { id } => assert_eq!(id, "cb-1"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── v2: line-ending canonicalization ───────────────────────────────

    #[test]
    fn host_to_wire_normalizes_all_conventions() {
        assert_eq!(host_to_wire("a\r\nb\r\nc"), "a\nb\nc");
        assert_eq!(host_to_wire("a\rb"), "a\nb");
        assert_eq!(host_to_wire("a\nb"), "a\nb");
        assert_eq!(
            host_to_wire("mixed\r\nand\rand\nend\r"),
            "mixed\nand\nand\nend\n"
        );
        assert_eq!(host_to_wire(""), "");
        // No CR at all → passthrough (fast path).
        assert_eq!(host_to_wire("plain"), "plain");
    }

    #[test]
    fn lf_to_crlf_is_idempotent() {
        assert_eq!(lf_to_crlf("a\nb"), "a\r\nb");
        assert_eq!(
            lf_to_crlf("a\r\nb"),
            "a\r\nb",
            "existing CRLF must not double"
        );
        assert_eq!(lf_to_crlf(lf_to_crlf("x\ny\nz").as_str()), "x\r\ny\r\nz");
        // Lone CR is normalized too, not passed through.
        assert_eq!(lf_to_crlf("a\rb"), "a\r\nb");
    }

    #[test]
    fn wire_to_host_matches_platform_convention() {
        let out = wire_to_host("l1\nl2");
        #[cfg(windows)]
        assert_eq!(out, "l1\r\nl2");
        #[cfg(not(windows))]
        assert_eq!(out, "l1\nl2");
    }

    // ── v2: FNV-1a 64 (cross-side echo-suppression hash) ───────────────

    #[test]
    fn fnv1a64_matches_published_vectors() {
        // Standard FNV-1a 64 test vectors — the browser-side
        // `hashClipboardText`/`hashClipboardBytes` in useRemoteControl.ts
        // lock the SAME values; if either side changes, echo
        // suppression silently breaks.
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
    }

    // ── v2: PNG codec ──────────────────────────────────────────────────

    #[test]
    fn png_roundtrip_2x2_rgba() {
        let rgba: Vec<u8> = vec![
            255, 0, 0, 255, /* */ 0, 255, 0, 128, //
            0, 0, 255, 255, /* */ 255, 255, 255, 0,
        ];
        let png = rgba_to_png(2, 2, &rgba).unwrap();
        let (w, h, back) = png_to_rgba(&png).unwrap();
        assert_eq!((w, h), (2, 2));
        assert_eq!(back, rgba);
    }

    #[test]
    fn rgba_to_png_rejects_wrong_buffer_len() {
        let err = rgba_to_png(2, 2, &[0u8; 3]).unwrap_err();
        assert!(err.to_string().contains("expected"), "got: {err}");
    }

    #[test]
    fn png_to_rgba_rejects_garbage() {
        assert!(png_to_rgba(b"not a png at all").is_err());
    }

    #[test]
    fn png_to_rgba_rejects_decompression_bomb_before_alloc() {
        // Hand-craft a PNG whose IHDR declares 20000x20000 RGBA
        // (400 MPx — a 1.6 GB output buffer) followed by EMPTY
        // IDAT/IEND chunks. png 0.18's `read_info` parses this header
        // happily (its own byte limit only fires later, at frame
        // decode), so without OUR header-stage pixel cap the
        // `vec![0u8; output_buffer_size]` allocation would balloon to
        // 1.6 GB from a 70-byte wire payload. The cap must fire first.
        fn crc32(data: &[u8]) -> u32 {
            let mut crc: u32 = 0xffff_ffff;
            for &b in data {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xedb8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }
        let mut png_bytes: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        let mut ihdr: Vec<u8> = Vec::new();
        ihdr.extend_from_slice(b"IHDR");
        ihdr.extend_from_slice(&20000u32.to_be_bytes()); // width
        ihdr.extend_from_slice(&20000u32.to_be_bytes()); // height
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, no interlace
        png_bytes.extend_from_slice(&13u32.to_be_bytes());
        png_bytes.extend_from_slice(&ihdr);
        png_bytes.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        for tag in [b"IDAT", b"IEND"] {
            png_bytes.extend_from_slice(&0u32.to_be_bytes());
            png_bytes.extend_from_slice(tag);
            png_bytes.extend_from_slice(&crc32(tag).to_be_bytes());
        }
        let err = png_to_rgba(&png_bytes).unwrap_err();
        assert!(
            err.to_string().contains("pixel cap"),
            "must fail on the header cap, got: {err}"
        );
    }

    #[test]
    fn png_to_rgba_expands_rgb_to_opaque_rgba() {
        // Encode a 1x2 RGB (no alpha) PNG with the png crate directly,
        // then decode through our helper — alpha must come back 255.
        let rgb: Vec<u8> = vec![10, 20, 30, 40, 50, 60];
        let mut buf = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut buf, 1, 2);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&rgb).unwrap();
        }
        let (w, h, rgba) = png_to_rgba(&buf).unwrap();
        assert_eq!((w, h), (1, 2));
        assert_eq!(rgba, vec![10, 20, 30, 255, 40, 50, 60, 255]);
    }

    // ── v2/v2.1: inbound rich reassembler (image + html) ───────────────

    fn expect_image(p: RichPayload) -> PngImage {
        match p {
            RichPayload::Image(img) => img,
            other => panic!("expected image payload, got {other:?}"),
        }
    }

    fn expect_html(p: RichPayload) -> HtmlPayload {
        match p {
            RichPayload::Html(h) => h,
            other => panic!("expected html payload, got {other:?}"),
        }
    }

    #[test]
    fn rich_rx_image_happy_path() {
        let mut rx = RichRx::new();
        rx.begin_image("i1".into(), 2, 2, 6, "png").unwrap();
        rx.frame(&[1, 2, 3]).unwrap();
        rx.frame(&[4, 5, 6]).unwrap();
        let img = expect_image(rx.end("i1").unwrap());
        assert_eq!((img.w, img.h), (2, 2));
        assert_eq!(img.png, vec![1, 2, 3, 4, 5, 6]);
        assert!(!rx.is_in_flight());
    }

    #[test]
    fn rich_rx_image_rejects_bad_begin() {
        let mut rx = RichRx::new();
        assert!(
            rx.begin_image("i".into(), 2, 2, 6, "jpeg").is_err(),
            "png only"
        );
        assert!(
            rx.begin_image("i".into(), 2, 2, 0, "png").is_err(),
            "zero bytes"
        );
        assert!(
            rx.begin_image(
                "i".into(),
                2,
                2,
                CLIPBOARD_IMAGE_MAX_BYTES as u64 + 1,
                "png"
            )
            .is_err(),
            "over byte cap"
        );
        assert!(
            rx.begin_image("i".into(), 100_000, 100_000, 6, "png")
                .is_err(),
            "over pixel cap"
        );
        assert!(!rx.is_in_flight());
    }

    #[test]
    fn rich_rx_rejects_overflow_and_drops_transfer() {
        let mut rx = RichRx::new();
        rx.begin_image("i1".into(), 2, 2, 4, "png").unwrap();
        assert!(rx.frame(&[1, 2, 3, 4, 5]).is_err(), "over declared length");
        assert!(!rx.is_in_flight(), "overflow must drop the transfer");
        assert!(rx.frame(&[1]).is_err(), "no transfer in flight");
    }

    #[test]
    fn rich_rx_rejects_mismatched_end() {
        let mut rx = RichRx::new();
        rx.begin_image("i1".into(), 2, 2, 2, "png").unwrap();
        rx.frame(&[1, 2]).unwrap();
        assert!(rx.end("other").is_err(), "id mismatch");
        assert!(!rx.is_in_flight());

        rx.begin_image("i2".into(), 2, 2, 4, "png").unwrap();
        rx.frame(&[1, 2]).unwrap();
        let err = rx.end("i2").unwrap_err();
        assert!(err.contains("2 of 4"), "length mismatch surfaces: {err}");
    }

    #[test]
    fn rich_rx_new_begin_replaces_dangling_transfer() {
        let mut rx = RichRx::new();
        rx.begin_image("stale".into(), 2, 2, 100, "png").unwrap();
        rx.frame(&[9; 10]).unwrap();
        rx.begin_html("fresh".into(), 5, 2).unwrap();
        rx.frame(b"<b>xy").unwrap();
        rx.frame(b"hi").unwrap();
        let p = expect_html(rx.end("fresh").unwrap());
        assert_eq!(p.html, "<b>xy");
        assert_eq!(p.text, "hi");
    }

    #[test]
    fn rich_rx_html_happy_path_splits_on_declared_lengths() {
        let mut rx = RichRx::new();
        let html = "<b>bold</b> und ümlaut";
        let text = "bold und ümlaut";
        rx.begin_html("h1".into(), html.len() as u64, text.len() as u64)
            .unwrap();
        // Feed across an arbitrary boundary (mid-multibyte is fine —
        // the split happens at declared lengths on the full buffer).
        let combined = [html.as_bytes(), text.as_bytes()].concat();
        rx.frame(&combined[..10]).unwrap();
        rx.frame(&combined[10..]).unwrap();
        let p = expect_html(rx.end("h1").unwrap());
        assert_eq!(p.html, html);
        assert_eq!(p.text, text);
        assert!(!rx.is_in_flight());
    }

    #[test]
    fn rich_rx_html_rejects_bad_begin_and_bad_utf8() {
        let mut rx = RichRx::new();
        assert!(rx.begin_html("h".into(), 0, 5).is_err(), "zero html bytes");
        assert!(
            rx.begin_html("h".into(), CLIPBOARD_HTML_MAX_BYTES as u64, 1)
                .is_err(),
            "combined size over the cap"
        );
        assert!(!rx.is_in_flight());
        // Invalid UTF-8 in the html half is rejected at end().
        rx.begin_html("h2".into(), 2, 0).unwrap();
        rx.frame(&[0xff, 0xfe]).unwrap();
        let err = rx.end("h2").unwrap_err();
        assert!(err.contains("UTF-8"), "got: {err}");
    }

    // ── v2.2: native (RTF) lane ────────────────────────────────────────

    #[test]
    fn parse_incoming_native_begin_end() {
        let m: ClipboardIncoming = serde_json::from_str(
            r#"{"t":"clipboard:native-begin","id":"cb-n1","rtf_bytes":10,"html_bytes":4,"text_bytes":2}"#,
        )
        .unwrap();
        match m {
            ClipboardIncoming::NativeBegin {
                id,
                rtf_bytes,
                html_bytes,
                text_bytes,
            } => {
                assert_eq!(
                    (id.as_str(), rtf_bytes, html_bytes, text_bytes),
                    ("cb-n1", 10, 4, 2)
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:native-end","id":"cb-n1"}"#).unwrap();
        match m {
            ClipboardIncoming::NativeEnd { id } => assert_eq!(id, "cb-n1"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rich_rx_native_splits_three_ways() {
        let mut rx = RichRx::new();
        let rtf = br"{\rtf1 hi}";
        rx.begin_native("n1".into(), rtf.len() as u64, 4, 2)
            .unwrap();
        let mut combined = rtf.to_vec();
        combined.extend_from_slice(b"<b>x");
        combined.extend_from_slice(b"hi");
        rx.frame(&combined[..7]).unwrap();
        rx.frame(&combined[7..]).unwrap();
        match rx.end("n1").unwrap() {
            RichPayload::Native(p) => {
                assert_eq!(p.rtf, rtf.to_vec());
                assert_eq!(p.html, "<b>x");
                assert_eq!(p.text, "hi");
            }
            other => panic!("expected native, got {other:?}"),
        }
        // Zero rtf_bytes and over-cap totals are rejected at begin.
        assert!(rx.begin_native("n2".into(), 0, 4, 2).is_err());
        assert!(
            rx.begin_native("n3".into(), CLIPBOARD_NATIVE_MAX_BYTES as u64, 1, 0)
                .is_err()
        );
    }

    #[test]
    fn native_payload_serde_base64_roundtrip() {
        // The bridge's JSON body: rtf travels base64; html/text default
        // to empty when omitted.
        let p = NativePayload {
            rtf: vec![0x7b, 0x5c, 0x72, 0x74, 0x66, 0xff],
            html: "<i>x</i>".into(),
            text: "x".into(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"rtf\":\"e1xydGb/\""), "got: {json}");
        let back: NativePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rtf, p.rtf);
        assert_eq!(back.html, p.html);
        assert_eq!(back.text, p.text);
        let sparse: NativePayload = serde_json::from_str(r#"{"rtf":"AQI="}"#).unwrap();
        assert_eq!(sparse.rtf, vec![1, 2]);
        assert_eq!(sparse.html, "");
        assert_eq!(sparse.text, "");
        assert!(serde_json::from_str::<NativePayload>(r#"{"rtf":"not base64!!"}"#).is_err());
    }

    // ── v2.1: html parse locks + event hash ────────────────────────────

    #[test]
    fn parse_incoming_html_begin_end() {
        let m: ClipboardIncoming = serde_json::from_str(
            r#"{"t":"clipboard:html-begin","id":"cb-9","html_bytes":120,"text_bytes":30}"#,
        )
        .unwrap();
        match m {
            ClipboardIncoming::HtmlBegin {
                id,
                html_bytes,
                text_bytes,
            } => {
                assert_eq!((id.as_str(), html_bytes, text_bytes), ("cb-9", 120, 30));
            }
            other => panic!("unexpected: {other:?}"),
        }
        let m: ClipboardIncoming =
            serde_json::from_str(r#"{"t":"clipboard:html-end","id":"cb-9"}"#).unwrap();
        match m {
            ClipboardIncoming::HtmlEnd { id } => assert_eq!(id, "cb-9"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn html_event_hash_separates_html_from_text_and_canonicalizes() {
        // Separator prevents boundary collisions…
        assert_ne!(html_event_hash("ab", "c"), html_event_hash("a", "bc"));
        // …and the text half is canonicalized like every other text
        // hash (CRLF == LF), while the html half is hashed verbatim.
        assert_eq!(
            html_event_hash("<p>x</p>", "l1\r\nl2"),
            html_event_hash("<p>x</p>", "l1\nl2")
        );
        assert_ne!(
            html_event_hash("<p>x</p>", "t"),
            html_event_hash("<p>y</p>", "t")
        );
    }

    /// The clipboard worker init may fail on headless CI runners that
    /// have no X server; accept that as a clean skip. If it does
    /// construct, a basic write/read round-trip works AND — locked in
    /// the same test because Windows `OpenClipboard` is process-wide
    /// exclusive and parallel tests would race — dropping a clone must
    /// NOT shut the worker down. The DC handler in `peer.rs` clones
    /// the cb into the per-message closure; if the old Drop impl sent
    /// Shutdown on clone drop, the second clipboard:read on a live
    /// session would fail with "clipboard worker gone" (user-reported
    /// on 0.1.33).
    ///
    /// On Windows, the OS clipboard is inherently racy — apps like
    /// paste-history / password managers may overwrite it between
    /// our `set_text` and `get_text` calls. The *content* assertions
    /// here are best-effort; the invariant this test locks is
    /// "worker survives a clone drop", expressed by the final write
    /// succeeding without "worker gone".
    #[tokio::test]
    async fn write_then_read_round_trip_and_survives_clone_drop() {
        let Ok(cb) = Clipboard::new() else {
            eprintln!("arboard not available in this env — skipping");
            return;
        };
        let payload = "roomler clipboard smoke test";
        cb.write(payload.to_string()).await.unwrap();
        // Soft read — another process may have already clobbered the
        // clipboard. Only enforce content equality when the read
        // actually returned our payload.
        if let Ok(back) = cb.read().await {
            if back == payload {
                // Good — OS let us keep our own write.
            } else {
                eprintln!("clipboard was overwritten externally; content check skipped");
            }
        } else {
            eprintln!("clipboard read hit transient OS error; content check skipped");
        }

        // Now drop a clone. This is the load-bearing assertion: if
        // the old Drop impl's Shutdown still ran on clone-drop, the
        // original's next `send` would return `SendError` and
        // `write()` would surface "clipboard worker gone". Soft-read
        // afterwards — we don't care what's in the OS clipboard,
        // only that our handle's worker is alive.
        {
            let clone = cb.clone();
            let _ = clone.write("from clone".to_string()).await;
        } // clone drops here; worker MUST stay alive.
        cb.write("from original".to_string())
            .await
            .expect("worker must still be alive after a clone was dropped");
        let _ = cb.read().await;
    }
}
