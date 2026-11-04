// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The **signaling seam** the tunnel-session driver rides.
//!
//! [`crate::driver::run_tunnel_session`] speaks the `rc:tunnel.*` control
//! protocol over this pair instead of owning a WebSocket, so the SAME driver
//! serves both the `meshharbor` CLI (which backs it with a tokio-tungstenite
//! WS carrying a `TunnelClient` JWT) and — at P3b-2 — the `meshharbord` daemon
//! (which backs it with its existing agent-WS multiplexer + a per-session
//! `ServerMsg` channel). The split into a cloneable **sink** + a single-consumer
//! **source** maps 1:1 onto how `forward.rs` already worked: an
//! `mpsc::Sender<ClientMsg>` fanned into every per-flow task, and one owned
//! `SplitStream` moved from the setup wait into the dispatch loop.

use async_trait::async_trait;
use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};

/// The **egress** half — every `ClientMsg` the driver emits (hello/open, the SDP
/// offer, ICE trickle, per-flow forward-requests, half-close + closed audit)
/// goes through here. Cloned (as `Arc<dyn TunnelSignalingSink>`) into every
/// per-flow task, so it must be `Send + Sync`. A concrete impl MUST preserve
/// FIFO order across concurrent `send`s: the CLI's `WsSignaling` funnels them
/// through one `mpsc` + one writer task — never a shared locked sink, whose
/// interleaving under concurrency could differ from today's.
#[async_trait]
pub trait TunnelSignalingSink: Send + Sync + 'static {
    /// Enqueue one `ClientMsg` toward the server. Errors only on a dead link.
    async fn send(&self, msg: ClientMsg) -> anyhow::Result<()>;
}

/// The **ingress** half — the driver pulls each typed `ServerMsg` from here.
/// Owned by ONE consumer at a time; `&mut self` makes concurrent consumption a
/// compile error, matching `forward.rs`'s invariant that the WS read half is
/// owned by the setup wait and then moved into the dispatch loop. The impl
/// absorbs the transport's own frames — WebSocket Ping/Close, non-`rc:` noise —
/// so the driver only ever sees a typed `ServerMsg`. `None` = the link closed;
/// the driver's setup waits map that to an error so "server gone mid-open" stays
/// a hard failure, not a clean session end.
#[async_trait]
pub trait TunnelSignalingSource: Send + 'static {
    /// The next `ServerMsg`, or `None` once the link is gone for good.
    async fn recv(&mut self) -> Option<ServerMsg>;
}
