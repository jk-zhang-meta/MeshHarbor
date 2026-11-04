// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #1754 — how a tunnel peer tells the signaling loop that its client is gone.
//!
//! The exit agent's tunnel peers live in the signaling loop's session maps and
//! are removed by exactly two things: a `rc:tunnel.terminate` from the server,
//! or the control WS ending. Nothing else observed the data plane. So a client
//! that never sent its terminate — an older CLI, a crashed process, a network
//! that vanished — left its peer in the map for the life of the connection,
//! with every ICE socket, the eight-channel DC pool and, on the relayed
//! flavours, the TURN allocation. Field-measured on 0.4.110 against a macOS
//! exit agent: five `roomler kill`s of the same forward took the daemon's UDP
//! sockets 5 → 11 → 16, still held minutes later.
//!
//! This channel is the agent's own observation of the data plane, independent
//! of anything the client or the server says. A peer sends one [`TunnelReap`]
//! when the transport under it reports the remote gone; the loop's reap arm
//! removes the session from both maps, closes what it held, and tells the
//! server so a client that is somehow still alive learns its session ended.
//!
//! One channel per org loop, created beside the overlay "Disconnect" channel
//! in `signaling::run` and borrowed into every connection, so a reap that
//! lands during a reconnect gap is drained by the next connection rather
//! than lost. Per org, not per process: a process-global sender would land a
//! secondary org's reap in the primary's maps.

use bson::oid::ObjectId;
use tokio::sync::mpsc;

/// Which transport event reported the client gone. Carried for the one log
/// line the reap arm writes; the arm's action is the same for all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapSignal {
    /// `RTCPeerConnectionState::Failed` — ICE has not heard from the remote
    /// for the disconnected + failed timeouts (5 s + 25 s in the vendored
    /// webrtc-ice) while both ends ping every 2 s. Terminal: tunnel-core has
    /// no ICE restart, and a peer in this state frees nothing until closed.
    PcFailed,
    /// `RTCPeerConnectionState::Closed` — reachable only through a local
    /// `close()`. Kept as the net under any close that skipped the map.
    PcClosed,
    /// A pool DataChannel's `on_close`: the remote closed its peer cleanly,
    /// so every channel's read loop hit EOF within milliseconds.
    DcClosed,
    /// The QUIC accept task ended. It serves exactly one connection, so its
    /// end means that connection is over — closed by the client, or idle
    /// past quinn's 30 s with the 8 s keepalives no longer arriving.
    QuicConnEnded,
}

impl ReapSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            ReapSignal::PcFailed => "pc_failed",
            ReapSignal::PcClosed => "pc_closed",
            ReapSignal::DcClosed => "dc_closed",
            ReapSignal::QuicConnEnded => "quic_conn_ended",
        }
    }
}

impl std::fmt::Display for ReapSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// "Session `session_id`'s client is gone" — the whole message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelReap {
    pub session_id: ObjectId,
    pub signal: ReapSignal,
}

/// The sender half a peer holds. A plain `mpsc::Sender`: the handlers that
/// hold one capture nothing else of the peer, so no handler keeps its own
/// peer connection alive.
pub type ReapSender = mpsc::Sender<TunnelReap>;

/// Capacity of the per-org channel. A closing WebRTC peer can report up to
/// nine times (eight channels' `on_close` and the state change) before the
/// per-peer latch in `peer.rs` suppresses the rest, and nobody drains the
/// channel during a reconnect gap; 128 leaves room for many sessions ending
/// at once without a sender ever parking.
pub const TUNNEL_REAP_CAP: usize = 128;

/// Hand `reap` to the loop from inside a transport callback without holding
/// the callback up: the send runs on its own task, so a webrtc state
/// transition (which awaits its handler inline) never waits on the loop,
/// and a full channel parks this task instead of dropping the report. The
/// send fails only when the org loop itself is gone.
pub fn notify(tx: &ReapSender, reap: TunnelReap) {
    let tx = tx.clone();
    tokio::spawn(async move {
        if tx.send(reap).await.is_err() {
            tracing::debug!(
                session_id = %reap.session_id,
                signal = %reap.signal,
                "tunnel reap dropped: the org loop is gone"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_names_are_stable_log_tokens() {
        for (s, name) in [
            (ReapSignal::PcFailed, "pc_failed"),
            (ReapSignal::PcClosed, "pc_closed"),
            (ReapSignal::DcClosed, "dc_closed"),
            (ReapSignal::QuicConnEnded, "quic_conn_ended"),
        ] {
            assert_eq!(s.as_str(), name);
            assert_eq!(s.to_string(), name);
        }
    }

    #[tokio::test]
    async fn notify_delivers_to_the_receiver() {
        let (tx, mut rx) = mpsc::channel::<TunnelReap>(TUNNEL_REAP_CAP);
        let reap = TunnelReap {
            session_id: ObjectId::new(),
            signal: ReapSignal::DcClosed,
        };
        notify(&tx, reap);
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("delivered within 2 s")
            .expect("channel open");
        assert_eq!(got, reap);
    }
}
