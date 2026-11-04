// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2d-2 and P2d-3 — the replica stream on the device (spec §3b, "The
//! carrier" and "The stream"): the source's endpoint for a grant, the
//! member's dial, the token and the opening exchange, on the `direct` rung
//! (P2d-2a), the `relay` rung (P2d-2b) and the `derp` rung (P2d-2c); then
//! the events, the blobs and the acks (P2d-3).
//!
//! | Side | On | Does |
//! |---|---|---|
//! | source | `rc:hive.replica.grant` | registers the grant at once, then stands its endpoint up: on `direct`, one UDP socket, STUN asked on that very socket, a QUIC server on it; on `relay`, a TURN allocation and a QUIC server over it; on `derp`, a QUIC server over its own `/derp` connection, on a route of the stream's own toward the member's key. Answers `rc:hive.replica.ready` with its certificate, and its addresses or its key |
//! | source | `rc:hive.replica.candidate` | the member's relayed address: a TURN permission for it, held until the allocation lands |
//! | source | the member's connection | serves ONE: the token first, then the member's hello, answered from its chain; then the events past where the member's copy ends, from the store and then as they are appended, and each blob the member asks for |
//! | member | `rc:hive.replica.dial` | on `relay`, first its own allocation, on the source's TURN worker, and its relayed address sent for the source's permission; on `derp`, a route of the stream's own toward the source's key; then the source dialed, the certificate pinned, the token presented, and where its copy ends said |
//! | member | the source's answer and events | a copy off the source's chain set aside past the point both hold; then each event's blobs asked for and kept, the event applied through the store's chain check, each frame acked once on disk, and the tip reported to the server as it moves |
//! | either | the server's `rc:hive.replica.close`, the connection's end, or the grant's | the endpoint, its socket and its allocation or route go, and the server is told why |
//!
//! A member asks for each stream it follows ([`super::follow`], P2d-3b), and
//! a build carries both sides from then on, advertising `hive-stream`. It
//! renews each at half its grant's life, the renewal's stream followed beside
//! the old one until it answers, and the old one let go then (P2d-4).
//!
//! ⚠️ What a member holds of these streams in memory is bounded across all of
//! them, by this device's budgets for event bytes and blob bytes
//! ([`EVENT_BUDGET`], [`BLOB_BUDGET`]): 32 sources must not each make it hold
//! their largest at once.
//!
//! ⚠️ On `derp`, never the tunnel's route ([`DerpMux::tunnel_conn_for`]):
//! that one is one per peer, last one wins, so a stream on it would take a
//! `quic-derp-v1` tunnel's route between the same two devices, and two
//! streams between one pair would take each other's. Each stream has its own
//! ([`DerpMux::hive_conn_for`], by its grant's id).
//!
//! [`DerpMux::tunnel_conn_for`]: tunnel_core::transport::derp::DerpMux::tunnel_conn_for
//! [`DerpMux::hive_conn_for`]: tunnel_core::transport::derp::DerpMux::hive_conn_for
//!
//! ⚠️ Every endpoint and every connection ends by the grant's `ttl_secs` at
//! the latest, whatever the other side does: each holds a UDP socket (and on
//! `relay` an allocation), and sockets leaked one grant at a time are how a
//! daemon ran out of ports before (`docs/tunnels.md`).
//!
//! ⚠️ A grant is registered BEFORE its endpoint is stood up, so the server's
//! `close` ends a setup still in flight. The server gives up on a source
//! silent for 30 s and ignores a later `ready`, and a TURN allocation was
//! measured at ~20 s on a UDP-hostile network (#1761): an endpoint registered
//! only once built would wait out its whole grant, holding its socket and its
//! allocation, with nobody coming.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use bson::oid::ObjectId;
use meshharbor_hive_node::checkpoint::{Digest, WorkspaceSnap, chunk_bytes};
use meshharbor_hive_node::store::{StoreError, Substitute};
use meshharbor_hive_node::stream::{self as wire, BlobMsg, EventMeta, Mark, MemberMsg, SourceMsg};
use meshharbor_hive_node::{ChainError, ChainTip, EventEnvelope, TranscriptEvent};
use meshharbor_remote_control::hive::{
    HiveStreamPath, HiveStreamRefusal, is_dialable, stream_limits,
};
use meshharbor_remote_control::signaling::{ClientMsg, IceServer};
use meshharbor_remote_control::turn_url;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};
use tunnel_core::transport::derp::{DerpTunnelHandle, parse_pubkey_hex};
use tunnel_core::transport::quic::{
    self, ConnectionError, QuicConnection, QuicPeer, RecvStream, SendStream,
};
use tunnel_core::transport::relay::{self, RelayConn, RelayUdpSocket};

use super::Supervisor;
use crate::hive::packer;
use crate::hive::store::{StoreHandle, WriterError};

/// How long each address is tried, and how long the source waits for the
/// member's token once it connected.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long STUN waits for an answer, per server.
const STUN_TIMEOUT: Duration = Duration::from_secs(2);
/// How long each side waits for the other's frame in the opening exchange.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest close `reason` this device sends.
const MAX_REASON_CHARS: usize = 64;
/// How long the member waits after its own permissions' datagrams before it
/// dials over its relay, so they are installed on the TURN server first
/// (tunnel-core's `QUIC_PERMIT_SETTLE`).
const PERMIT_SETTLE: Duration = Duration::from_millis(300);
/// The member's addresses a source holds for a grant whose allocation has
/// not landed yet. A member sends one; the bound keeps a replay from growing
/// the entry.
const MAX_HELD_CANDIDATES: usize = 16;
/// The most sessions this device follows at once, as a member
/// ([`super::follow`]).
pub(super) const MAX_FOLLOWING: usize = 32;
/// P2d-4 — the most streams this device follows at once, as a member: each
/// session followed, and its renewal beside it. Each holds a UDP socket, and
/// on the relay rung an allocation; a dial past it is closed `busy`.
pub(super) const MAX_MEMBER_STREAMS: usize = 2 * MAX_FOLLOWING;
/// P2d-3 — the event bytes a source sends past the member's last ack before
/// it waits for the next: enough to keep a path busy, and all a member that
/// stopped reading leaves unread on its connection, well under the
/// flow-control window its blobs need beside it.
const AHEAD_BYTES: u64 = 4 * 1024 * 1024;
/// P2d-3 — how long a read in the middle of something (an event's JSON, a
/// blob, the next stream of a wave) waits for its next byte. A total time
/// would cut a slow path short; none would let a side that stopped part way
/// hold the stream to its grant's end.
const STALL: Duration = Duration::from_secs(60);
/// P2f-2b — how long a member waits for the answer to its `want_pack`: the
/// source makes the pack as the session's account, within `hive-pack`'s own
/// limit, and a margin.
const PACK_ANSWER: Duration = Duration::from_secs(packer::PACK_TIMEOUT.as_secs() + 30);
// The stream's limit on a want's haves is the account's git's.
const _: () = assert!(wire::MAX_WANT_HAVES == crate::hive::workspace::MAX_HAVES);
/// P2d-3 — the most often a member reports its tip while events land.
const TIP_EVERY: Duration = Duration::from_secs(5);
/// P2d-3 — the event bytes this device holds in memory as a member, across
/// every stream it follows: two of the largest the stream carries.
pub(super) const EVENT_BUDGET: usize = 2 * wire::MAX_EVENT_BYTES;
/// P2d-3 — the blob bytes, likewise: a wave's worth, four of the largest.
pub(super) const BLOB_BUDGET: usize = 4 * wire::MAX_STREAM_BLOB;

// P2d-3 — what the limits promise, held at build time. The largest event a
// device records fits the stream: a checkpoint's manifest, a stream-json
// line, an adopted session's line; a producer raised past it fails the build
// here, not a copy in the field. And each budget holds the largest thing it
// counts, so a wait for it always ends.
const _: () = {
    assert!(crate::hive::checkpointer::MAX_HEADER < wire::MAX_EVENT_BYTES);
    assert!(super::MAX_LINE < wire::MAX_EVENT_BYTES);
    assert!(tunnel_core::localapi::hive_adopt::MAX_LINE < wire::MAX_EVENT_BYTES);
    assert!(EVENT_BUDGET >= wire::MAX_EVENT_BYTES);
    assert!(BLOB_BUDGET >= wire::MAX_STREAM_BLOB);
};
/// P2d-3 — the code a side closes the connection with when it ends the
/// stream on its own word, which the close's reason carries.
const ENDED: u32 = 2;

/// Which side of a stream this device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Source,
    Member,
}

/// A stream this device is a side of, by grant.
pub(crate) struct Stream {
    pub(super) session_id: ObjectId,
    pub(super) role: Role,
    /// The rung the grant named.
    path: HiveStreamPath,
    /// The source's answer to the hello, once the member heard it.
    pub(super) answer: Option<SourceMsg>,
    /// The source's allocation on the relay rung, once it landed: the
    /// member's permission is installed through it.
    relay: Option<Arc<dyn RelayConn>>,
    /// The member's relayed addresses that arrived before the allocation.
    held: Vec<SocketAddr>,
    /// P2d-3 — the blobs this side carried: sent, as the source; kept, as
    /// the member.
    blobs: u64,
    task: tokio::task::AbortHandle,
}

impl Stream {
    /// P2d-3b — whether the member's stream got past its opening exchange:
    /// its rung carried, whatever ended it after.
    fn answered(&self) -> bool {
        self.answer
            .as_ref()
            .is_some_and(|a| !matches!(a, SourceMsg::Refused { .. }))
    }
}

/// `rc:hive.replica.grant`, as the source reads it.
pub(crate) struct Grant {
    pub grant_id: ObjectId,
    pub session_id: ObjectId,
    pub fence: u64,
    pub member_id: ObjectId,
    pub path: Option<HiveStreamPath>,
    pub token: String,
    pub ice_servers: Vec<IceServer>,
    /// On `derp`, the member's WireGuard key: whom the stream's route faces.
    pub member_derp_pubkey: Option<String>,
    pub ttl_secs: u32,
}

/// `rc:hive.replica.dial`, as the member reads it.
pub(crate) struct Dial {
    pub grant_id: ObjectId,
    pub session_id: ObjectId,
    pub fence: u64,
    pub source_id: ObjectId,
    pub path: Option<HiveStreamPath>,
    pub token: String,
    pub cert_fingerprint: String,
    pub addrs: Vec<String>,
    pub ice_servers: Vec<IceServer>,
    /// On `derp`, the source's WireGuard key: whom the stream's route faces.
    pub derp_pubkey: Option<String>,
    pub ttl_secs: u32,
}

/// What the source stood up for a grant.
struct Endpoint {
    peer: QuicPeer,
    fingerprint: String,
    addrs: Vec<String>,
    /// On the relay rung, the allocation the endpoint rides.
    relay: Option<Arc<dyn RelayConn>>,
    /// On the derp rung, this device's own key, which the member dials.
    derp_pubkey: Option<String>,
}

/// The STUN servers among `ice`, resolved: an IP literal as it is, a name
/// through the resolver, IPv4 only, as the overlay's STUN is. Best effort: a
/// server that does not resolve is skipped, and host candidates still serve
/// a member on the same network.
async fn stun_servers(ice: &[IceServer]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for url in ice.iter().flat_map(|s| s.urls.iter()) {
        let Some(rest) = url.strip_prefix("stun:") else {
            continue;
        };
        let host_port = rest.split(['?', '#']).next().unwrap_or(rest);
        match tokio::net::lookup_host(host_port).await {
            Ok(addrs) => out.extend(addrs.filter(SocketAddr::is_ipv4).take(1)),
            Err(e) => debug!(%url, %e, "hive stream: a STUN server did not resolve"),
        }
    }
    out
}

/// The TURN server among `ice` the grant minted credentials for, with a
/// UDP url, picked as the tunnel's client picks it (`driver.rs`
/// `pick_turn_creds`): its urls, username and credential.
fn turn_creds(ice: &[IceServer]) -> Option<(Vec<String>, String, String)> {
    ice.iter().find_map(|s| match (&s.username, &s.credential) {
        (Some(u), Some(c)) if relay::turn_udp_server(&s.urls).is_some() => {
            Some((s.urls.clone(), u.clone(), c.clone()))
        }
        _ => None,
    })
}

/// The source's endpoint on the `direct` rung: one UDP socket, STUN asked
/// on it first so the reflexive address is the mapping QUIC then uses, and
/// a QUIC server on that same socket.
async fn direct_endpoint(ice: &[IceServer]) -> anyhow::Result<Endpoint> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let stun = stun_servers(ice).await;
    let mut addrs = quic::gather_candidates(&socket, &stun, STUN_TIMEOUT).await;
    if addrs.is_empty() {
        // No route found: loopback still serves a member on this host, as a
        // test's is. The bound `0.0.0.0` is no address to dial.
        let port = socket.local_addr()?.port();
        addrs.push(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    let (peer, fingerprint) = QuicPeer::server_from_socket(socket.into_std()?)?;
    let addrs = addrs
        .into_iter()
        .take(stream_limits::MAX_ADDRS)
        .map(|a| a.to_string())
        .collect();
    Ok(Endpoint {
        peer,
        fingerprint,
        addrs,
        relay: None,
        derp_pubkey: None,
    })
}

/// The source's endpoint on the `derp` rung: a QUIC server over this
/// device's own `/derp` connection, on the stream's own route toward the
/// member's key (by the grant's id), the MTU clamped under the relay's frame
/// cap. The member dials this device's key, so `ready` names it and no
/// address.
fn derp_endpoint(handle: &DerpTunnelHandle, g: &Grant) -> anyhow::Result<Endpoint> {
    let member = g
        .member_derp_pubkey
        .as_deref()
        .and_then(parse_pubkey_hex)
        .context("the grant names no member key")?;
    let conn = handle.mux.hive_conn_for(member, g.grant_id.bytes());
    let sock = Arc::new(RelayUdpSocket::new(Arc::new(conn))?);
    let (peer, fingerprint) = QuicPeer::server_over_derp(sock)?;
    Ok(Endpoint {
        peer,
        fingerprint,
        addrs: Vec::new(),
        relay: None,
        derp_pubkey: Some(handle.self_pubkey_hex.clone()),
    })
}

/// The source's endpoint on the `relay` rung: a TURN allocation from the
/// grant's credentials, a QUIC server over it, and the relayed address to
/// dial, as the tunnel's exit stands its own up (`tunnel/quic_peer.rs`
/// `setup_over_relay`).
async fn relay_endpoint(ice: &[IceServer]) -> anyhow::Result<Endpoint> {
    let (urls, user, cred) = turn_creds(ice).context("the grant carries no TURN server")?;
    let turn = relay::allocate_relay_from_ice(&urls, &user, &cred).await?;
    let relay: Arc<dyn RelayConn> = Arc::new(turn);
    let relayed = relay.local_addr()?;
    let sock = Arc::new(RelayUdpSocket::new(Arc::clone(&relay))?);
    let (peer, fingerprint) = QuicPeer::server_over_abstract_socket(sock)?;
    Ok(Endpoint {
        peer,
        fingerprint,
        addrs: vec![relayed.to_string()],
        relay: Some(relay),
        derp_pubkey: None,
    })
}

/// A TURN permission for `addr` on `relay`, installed by one datagram to
/// it: the TURN client creates a permission on its first send, and the
/// other side's QUIC endpoint drops a one-byte datagram as no packet.
async fn permit(relay: &Arc<dyn RelayConn>, addr: SocketAddr) {
    if let Err(e) = relay.send_to(b"\x00", addr).await {
        debug!(%addr, %e, "hive stream: a permission's datagram did not go");
    }
}

/// `rc:hive.replica.ready`, refused in `word`.
fn refusal(grant_id: ObjectId, word: HiveStreamRefusal, why: String) -> ClientMsg {
    info!(grant = %grant_id, refused = word.as_str(), %why, "hive stream: a grant not served");
    ClientMsg::HiveReplicaReady {
        grant_id,
        refused: Some(word),
        detail: Some(why),
        cert_fingerprint: None,
        addrs: Vec::new(),
        derp_pubkey: None,
    }
}

/// `msg` sent on `tx` from a task of its own: the signalling loop never
/// waits on its own outbound queue.
fn answer(tx: mpsc::Sender<ClientMsg>, msg: ClientMsg) {
    tokio::spawn(async move {
        let _ = tx.send(msg).await;
    });
}

async fn write_frame<T: Serialize>(send: &mut SendStream, msg: &T) -> anyhow::Result<()> {
    send.write_all(&wire::encode(msg)).await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> anyhow::Result<T> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header).await?;
    let len = wire::frame_len(header)?;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(wire::decode(&body)?)
}

/// The first address that connects, each tried for [`CONNECT_TIMEOUT`].
async fn connect_first(peer: &QuicPeer, addrs: &[SocketAddr]) -> Option<QuicConnection> {
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, peer.connect(*addr)).await {
            Ok(Ok(conn)) => return Some(conn),
            Ok(Err(e)) => debug!(%addr, %e, "hive stream: an address did not connect"),
            Err(_) => debug!(%addr, "hive stream: an address did not answer in time"),
        }
    }
    None
}

/// P2d-3 — `buf` filled from `recv`, each piece within [`STALL`] of the
/// last. A stream that ends first is `cut`'s word.
async fn read_within(recv: &mut RecvStream, buf: &mut [u8], cut: &str) -> Result<(), String> {
    let mut got = 0;
    while got < buf.len() {
        match tokio::time::timeout(STALL, recv.read(&mut buf[got..])).await {
            Ok(Ok(Some(n))) if n > 0 => got += n,
            Ok(Ok(_)) => return Err(cut.to_string()),
            Ok(Err(_)) => return Err("closed".to_string()),
            Err(_) => return Err("stalled".to_string()),
        }
    }
    Ok(())
}

/// P2d-3 — the reason a stream ended, in the close's words. Below this,
/// `closed` is a connection the other side let go. This side's own word
/// ends the connection with it, for the other side to read as the close's
/// reason. When the other side ended it on its word, that word, as
/// `<side>:<word>` and held to letters, digits and `_` (the other side is a
/// device of the org, not a trusted one); when it just let go, `gone`.
fn ended_by(conn: &QuicConnection, side: &str, gone: &str, reason: String) -> String {
    if reason != "closed" {
        conn.close(ENDED.into(), reason.as_bytes());
        return reason;
    }
    let word: String = match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(c))
            if c.error_code.into_inner() == u64::from(ENDED) =>
        {
            String::from_utf8_lossy(&c.reason)
                .chars()
                .filter(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || *ch == '_')
                .take(32)
                .collect()
        }
        _ => String::new(),
    };
    if word.is_empty() {
        gone.to_string()
    } else {
        format!("{side}:{word}")
    }
}

/// P2d-3 — what a source sent and the member acked.
#[derive(Default)]
struct Sent {
    /// Each frame sent and not yet acked: its last event's seq and hash,
    /// and the event bytes sent up to and with it.
    frames: VecDeque<(u64, [u8; 32], u64)>,
    /// Event bytes sent, in all.
    bytes: u64,
    /// The event bytes the member acked, and the seq of its last ack.
    acked_bytes: u64,
    acked_seq: u64,
}

/// P2d-3 — one `events` frame, once the member's acks bring what is in
/// flight under [`AHEAD_BYTES`]: its listing, then each event's JSON, byte
/// for byte. Recorded as sent before it is written, so the member's ack
/// never finds it missing.
async fn send_events(
    send: &mut SendStream,
    sent: &Mutex<Sent>,
    acked: &mut watch::Receiver<u64>,
    envs: &[EventEnvelope],
) -> Result<(), String> {
    let Some(last) = envs.last() else {
        return Ok(());
    };
    if let Some(big) = envs
        .iter()
        .find(|e| e.event_json.len() > wire::MAX_EVENT_BYTES)
    {
        warn!(
            session = %big.session, seq = big.seq, len = big.event_json.len(),
            "hive stream: an event past the stream's limit — no copy follows past it"
        );
        return Err("event_too_large".to_string());
    }
    loop {
        let ahead = {
            let s = sent.lock().unwrap_or_else(|e| e.into_inner());
            s.bytes - s.acked_bytes
        };
        if ahead < AHEAD_BYTES {
            break;
        }
        if acked.changed().await.is_err() {
            // The reader is gone, and its reason ends the stream.
            return std::future::pending().await;
        }
    }
    let len: u64 = envs.iter().map(|e| e.event_json.len() as u64).sum();
    {
        let mut s = sent.lock().unwrap_or_else(|e| e.into_inner());
        s.bytes += len;
        let upto = s.bytes;
        s.frames.push_back((last.seq, last.hash(), upto));
    }
    let listing = SourceMsg::Events {
        events: envs.iter().map(EventMeta::of).collect(),
    };
    if write_frame(send, &listing).await.is_err() {
        return Err("closed".to_string());
    }
    for env in envs {
        if send.write_all(env.event_json.as_bytes()).await.is_err() {
            return Err("closed".to_string());
        }
    }
    Ok(())
}

/// P2d-3 — the events past `cursor` the store holds, a frame at a time,
/// until it holds no more: the catch-up, and the fill after a gap or a feed
/// that lagged.
async fn send_from_store(
    store: &StoreHandle,
    sid: &str,
    send: &mut SendStream,
    sent: &Mutex<Sent>,
    acked: &mut watch::Receiver<u64>,
    cursor: &mut u64,
) -> Result<(), String> {
    loop {
        let page = store
            .page_within(sid, *cursor, wire::MAX_BATCH, wire::BATCH_BYTES)
            .await
            .map_err(|e| {
                warn!(session = sid, %e, "hive stream: the store could not be read");
                "store_error".to_string()
            })?;
        let Some(next) = page.last().map(|e| e.seq) else {
            return Ok(());
        };
        send_events(send, sent, acked, &page).await?;
        *cursor = next;
    }
}

/// P2f-2b — what the member's reader hands the blob sender: the blobs it
/// needs, or the pack it wants against what its own repository holds.
enum Work {
    Need(Vec<Digest>),
    Pack { commit: String, haves: Vec<String> },
}

/// P2f-2b — what a source's hello offers of the have and want: whether it
/// answers `want_pack`, and (P2f-2c) the whole packs it holds only a
/// substitute for, whose blobs are not there to ask for.
#[derive(Debug, Default)]
struct PackOffer {
    packs: bool,
    stand_ins: Vec<String>,
}

/// P2d-3 — the member's frames, until it lets the connection go or sends
/// what it may not. An `ack` must name the last event of a frame sent and
/// not yet acked, by its hash; a `need` goes to the blob sender, and the
/// next frame is read once it was taken. P2f-2b — so does a `want_pack`,
/// held to the wire's rules and to [`wire::MAX_WANTS`].
async fn read_member(
    mut recv: RecvStream,
    sent: &Mutex<Sent>,
    acked: watch::Sender<u64>,
    need: mpsc::Sender<Work>,
) -> String {
    // P2f-2b — the commits this stream's member asked a pack for.
    let mut wanted: HashSet<String> = HashSet::new();
    loop {
        let msg: MemberMsg = match read_frame(&mut recv).await {
            Ok(m) => m,
            Err(e) if e.is::<wire::FrameError>() => return "bad_frame".to_string(),
            Err(_) => return "closed".to_string(),
        };
        match msg {
            MemberMsg::Ack { seq, hash } => {
                let mut s = sent.lock().unwrap_or_else(|e| e.into_inner());
                let Some(at) = s
                    .frames
                    .iter()
                    .position(|f| f.0 == seq && hex::encode(f.1) == hash)
                else {
                    return "bad_ack".to_string();
                };
                let upto = s.frames[at].2;
                s.frames.drain(..=at);
                s.acked_bytes = upto;
                s.acked_seq = seq;
                drop(s);
                let _ = acked.send(seq);
            }
            MemberMsg::Need { blobs } => {
                if wire::check_need(&blobs).is_err() {
                    return "bad_frame".to_string();
                }
                if need.send(Work::Need(blobs)).await.is_err() {
                    // The blob sender ended, and its reason ends the stream.
                    return std::future::pending().await;
                }
            }
            // P2f-2b — the pack against what the member's repository holds.
            MemberMsg::WantPack { commit, haves } => {
                if wire::check_want_pack(&commit, &haves).is_err()
                    || wanted.len() >= wire::MAX_WANTS
                    || !wanted.insert(commit.clone())
                {
                    return "bad_frame".to_string();
                }
                if need.send(Work::Pack { commit, haves }).await.is_err() {
                    return std::future::pending().await;
                }
            }
            MemberMsg::Hello { .. } => return "bad_frame".to_string(),
        }
    }
}

/// P2d-3 — one wave's blobs, each on the stream the source opened for it,
/// all read at once: a stream left waiting for another would fill the
/// connection's flow-control window under it, and the one waited for could
/// then never arrive. Each must be one the wave asked for, at the length
/// asked, and come once.
async fn read_wave(
    conn: &QuicConnection,
    wave: &[(Digest, u64)],
) -> Result<Vec<(Digest, Vec<u8>)>, String> {
    let asked: Arc<Mutex<HashMap<Digest, u64>>> =
        Arc::new(Mutex::new(wave.iter().copied().collect()));
    let mut readers = tokio::task::JoinSet::new();
    for _ in wave {
        let uni = match tokio::time::timeout(STALL, conn.accept_uni()).await {
            Ok(Ok(uni)) => uni,
            Ok(Err(_)) => return Err("closed".to_string()),
            Err(_) => return Err("stalled".to_string()),
        };
        readers.spawn(read_blob(uni, Arc::clone(&asked)));
    }
    let mut out = Vec::with_capacity(wave.len());
    while let Some(done) = readers.join_next().await {
        match done {
            Ok(Ok(blob)) => out.push(blob),
            Ok(Err(why)) => return Err(why),
            Err(_) => return Err("bad_blob".to_string()),
        }
    }
    Ok(out)
}

/// P2d-3 — one blob's stream: its header held to what the wave asked for
/// before a byte of the blob is read, then its bytes.
async fn read_blob(
    mut uni: RecvStream,
    asked: Arc<Mutex<HashMap<Digest, u64>>>,
) -> Result<(Digest, Vec<u8>), String> {
    let (hash, len) = match tokio::time::timeout(STALL, read_frame::<BlobMsg>(&mut uni)).await {
        Ok(Ok(BlobMsg::Blob { hash, len })) => (hash, len),
        // P2f-2b — a pack's answer where a blob of the wave was to come:
        // nothing this wave asked for.
        Ok(Ok(_)) => return Err("bad_blob".to_string()),
        Ok(Err(e)) if e.is::<wire::FrameError>() => return Err("bad_blob".to_string()),
        Ok(Err(_)) => return Err("closed".to_string()),
        Err(_) => return Err("stalled".to_string()),
    };
    // Taken once: a second stream for one blob is not one the wave asked for.
    let wanted = asked
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&hash);
    if wanted != Some(len) {
        return Err("bad_blob".to_string());
    }
    let mut bytes = vec![0u8; len as usize];
    read_within(&mut uni, &mut bytes, "bad_blob").await?;
    Ok((hash, bytes))
}

/// P2d-3 — `diverged {at}`: the member's copy past `at` set aside, the one
/// rewrite a store allows, and only of an older fence's tail. `at` must be a
/// point the member named, genesis or one of its hello's checkpoints: a
/// source's word alone never moves a copy back.
/// P2f-2b — whether `commit` is the workspace of one of `sid`'s checkpoints
/// whose pack is whole: the one thing a member's `want_pack` may name, and a
/// source packs nothing else for it.
async fn whole_pack_commit(store: &StoreHandle, sid: &str, commit: &str) -> Result<bool, String> {
    let envs = store.of_kind(sid, "checkpoint", super::MAX_CHAIN).await?;
    Ok(envs.iter().any(|env| {
        matches!(
            TranscriptEvent::from_json(&env.event_json),
            Some(TranscriptEvent::Checkpoint(cp))
                if cp.workspace.as_ref().is_some_and(|ws| {
                    ws.commit == commit && ws.base.is_none() && !ws.pack.is_empty()
                })
        )
    }))
}

async fn set_aside(
    store: &StoreHandle,
    sid: &str,
    hello: &MemberMsg,
    at: &Mark,
) -> Result<(), String> {
    let named = match hello {
        MemberMsg::Hello { checkpoints, .. } => *at == Mark::genesis() || checkpoints.contains(at),
        _ => false,
    };
    if !named {
        return Err("bad_answer".to_string());
    }
    match store.set_aside_after(sid, at.seq).await {
        Ok(moved) => {
            info!(
                session = sid,
                at = at.seq,
                moved,
                "hive stream: a copy off the source's chain set aside"
            );
            Ok(())
        }
        Err(WriterError::Store(StoreError::NotOlderThanFloor {
            seq, fence, floor, ..
        })) => {
            warn!(
                session = sid,
                at = at.seq,
                seq,
                fence,
                floor,
                "hive stream: the copy's tail is of the current fence, and is never set aside"
            );
            Err("diverged_at_floor".to_string())
        }
        Err(WriterError::Store(StoreError::Purged { .. })) => Err("purged".to_string()),
        Err(e) => {
            warn!(session = sid, %e, "hive stream: the copy could not be set aside");
            Err("store_error".to_string())
        }
    }
}

/// P2d-3 — the close's word for an event the store refused. P2e-5b —
/// `not_fence_end`: below the floor, an older fence's event at the `seq` its
/// fence ended at that is not the event it ended with. The source holds a
/// chain the record does not, so the member waits and asks again.
fn refused_word(e: &WriterError) -> &'static str {
    match e {
        WriterError::Store(StoreError::Chain(ChainError::StaleFence { .. })) => "stale_fence",
        WriterError::Store(StoreError::Chain(ChainError::NotFenceEnd { .. })) => "not_fence_end",
        WriterError::Store(StoreError::Chain(ChainError::Gap { .. })) => "gap",
        WriterError::Store(StoreError::Chain(ChainError::Broken { .. })) => "broken_chain",
        WriterError::Store(StoreError::Purged { .. }) => "purged",
        _ => "store_error",
    }
}

impl Supervisor {
    /// `rc:hive.replica.grant`: what needs only this device's word is
    /// answered at once; otherwise the grant is registered, and its task
    /// spawned, under one lock, so a server `close` finds it from the first
    /// moment, its endpoint still being stood up or not. The task stands the
    /// endpoint up, answers `ready` on `tx`, and serves.
    pub(super) fn take_grant(
        self: &Arc<Self>,
        g: Grant,
        primary: bool,
        tx: mpsc::Sender<ClientMsg>,
    ) {
        let grant_id = g.grant_id;
        if !primary {
            return answer(
                tx,
                refusal(
                    grant_id,
                    HiveStreamRefusal::Other,
                    "this device serves streams for its primary organization only".into(),
                ),
            );
        }
        let path = match g.path {
            Some(p) => p,
            None => {
                return answer(
                    tx,
                    refusal(
                        grant_id,
                        HiveStreamRefusal::PathUnavailable,
                        "a rung this build cannot name".into(),
                    ),
                );
            }
        };
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        if streams.contains_key(&grant_id) {
            // A replay: the stream this grant started answers it.
            return debug!(grant = %grant_id, "hive stream: a grant this device holds already");
        }
        // Counted with the endpoints still being stood up: each holds its
        // socket already.
        if streams.values().filter(|s| s.role == Role::Source).count()
            >= stream_limits::MAX_PER_SOURCE
        {
            drop(streams);
            return answer(
                tx,
                refusal(
                    grant_id,
                    HiveStreamRefusal::Busy,
                    format!(
                        "this device serves {} streams already",
                        stream_limits::MAX_PER_SOURCE
                    ),
                ),
            );
        }
        let session_id = g.session_id;
        let task = tokio::spawn(Arc::clone(self).run_grant(g, tx));
        streams.insert(
            grant_id,
            Stream {
                session_id,
                role: Role::Source,
                path,
                answer: None,
                relay: None,
                held: Vec::new(),
                blobs: 0,
                task: task.abort_handle(),
            },
        );
    }

    /// One registered grant's life, by its `ttl_secs` at most: the endpoint
    /// stood up, `ready` sent, ONE connection served.
    async fn run_grant(self: Arc<Self>, g: Grant, tx: mpsc::Sender<ClientMsg>) {
        let deadline = Instant::now() + Duration::from_secs(u64::from(g.ttl_secs));
        let ep = match tokio::time::timeout_at(deadline, self.stand_up(&g)).await {
            Ok(Ok(ep)) => ep,
            Ok(Err((word, why))) => {
                // Forgotten before the server hears, so the slot is free by
                // then; the ready says why, and the server forgets the
                // grant itself, so no close follows.
                self.forget_stream(g.grant_id);
                let _ = tx.send(refusal(g.grant_id, word, why)).await;
                return;
            }
            Err(_) => return self.stream_ended(g.grant_id, "expired"),
        };
        // The allocation kept in the entry and the addresses held for it
        // permitted BEFORE the ready: the member dials only once told to,
        // and its opening Initials need the permission.
        let Some(held) = self.endpoint_up(g.grant_id, ep.relay.as_ref()) else {
            // Closed meanwhile: nobody to answer.
            return;
        };
        if let Some(relay) = &ep.relay {
            for addr in held {
                permit(relay, addr).await;
            }
        }
        info!(
            grant = %g.grant_id, session = %g.session_id, member = %g.member_id,
            path = ?g.path, addrs = ?ep.addrs, "hive stream: serving"
        );
        let ready = ClientMsg::HiveReplicaReady {
            grant_id: g.grant_id,
            refused: None,
            detail: None,
            cert_fingerprint: Some(ep.fingerprint),
            addrs: ep.addrs,
            derp_pubkey: ep.derp_pubkey,
        };
        if tx.send(ready).await.is_err() {
            return self.stream_ended(g.grant_id, "disconnected");
        }
        drop(tx);
        let reason = self.serve_one(ep.peer, &g, deadline).await;
        self.stream_ended(g.grant_id, &reason);
    }

    /// A registered grant's endpoint: the store asked whether this device
    /// holds the session, then the grant's rung stood up. A refusal in the
    /// word `ready` carries.
    async fn stand_up(&self, g: &Grant) -> Result<Endpoint, (HiveStreamRefusal, String)> {
        let Ok(store) = &self.store else {
            return Err((
                HiveStreamRefusal::NotHeld,
                "the replica store is unavailable".into(),
            ));
        };
        match store.chain_tip(&g.session_id.to_hex()).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err((
                    HiveStreamRefusal::NotHeld,
                    "this device holds nothing of the session".into(),
                ));
            }
            Err(e) => {
                return Err((
                    HiveStreamRefusal::NotHeld,
                    format!("the replica store could not be read: {e}"),
                ));
            }
        }
        match g.path {
            // The member climbs down a rung on `path_unavailable`.
            Some(HiveStreamPath::Relay) => relay_endpoint(&g.ice_servers).await.map_err(|e| {
                (
                    HiveStreamRefusal::PathUnavailable,
                    format!("no relay: {e:#}"),
                )
            }),
            Some(HiveStreamPath::Derp) => {
                let Some(handle) = self.derp_handle() else {
                    return Err((
                        HiveStreamRefusal::PathUnavailable,
                        "this device has no live DERP connection".into(),
                    ));
                };
                derp_endpoint(&handle, g).map_err(|e| {
                    (
                        HiveStreamRefusal::PathUnavailable,
                        format!("no DERP endpoint: {e:#}"),
                    )
                })
            }
            _ => direct_endpoint(&g.ice_servers).await.map_err(|e| {
                (
                    HiveStreamRefusal::Other,
                    format!("the endpoint could not be bound: {e}"),
                )
            }),
        }
    }

    /// This device's DERP mux, the primary org's: the one Hive streams ride,
    /// as every Hive frame is the primary org's. `None` without the overlay
    /// features, or while the overlay is down.
    pub(super) fn derp_handle(&self) -> Option<DerpTunnelHandle> {
        #[cfg(test)]
        if let Some(forced) = self
            .derp_for_tests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return forced;
        }
        crate::tunnel::netwatch::primary_derp_tunnel_handle()
    }

    /// The endpoint is up: on the relay rung its allocation kept for the
    /// member's permission, and the addresses held until now returned.
    /// `None` when the grant was closed meanwhile.
    fn endpoint_up(
        &self,
        grant_id: ObjectId,
        relay: Option<&Arc<dyn RelayConn>>,
    ) -> Option<Vec<SocketAddr>> {
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        let s = streams.get_mut(&grant_id)?;
        s.relay = relay.cloned();
        Some(std::mem::take(&mut s.held))
    }

    /// `rc:hive.replica.candidate`: the member's relayed address on the
    /// relay rung, for this source's TURN permission. Without one the TURN
    /// server drops the member's opening Initials, since the source, the
    /// QUIC server, never sends first. Permitted at once when the
    /// allocation is up, held until it lands otherwise.
    pub(super) fn take_candidate(&self, grant_id: ObjectId, addr: &str, primary: bool) {
        if !primary {
            return debug!(grant = %grant_id, "hive stream: a candidate on a secondary org's connection — ignored");
        }
        let Some(addr) = addr.parse::<SocketAddr>().ok().filter(is_dialable) else {
            return debug!(grant = %grant_id, %addr, "hive stream: a candidate no member could hold — dropped");
        };
        let relay = {
            let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
            let Some(s) = streams
                .get_mut(&grant_id)
                .filter(|s| s.role == Role::Source && s.path == HiveStreamPath::Relay)
            else {
                return debug!(grant = %grant_id, "hive stream: a candidate for no relay stream this device serves");
            };
            match &s.relay {
                Some(relay) => Arc::clone(relay),
                None if s.held.len() < MAX_HELD_CANDIDATES => return s.held.push(addr),
                None => {
                    return debug!(grant = %grant_id, "hive stream: candidates past the limit — dropped");
                }
            }
        };
        tokio::spawn(async move { permit(&relay, addr).await });
    }

    /// One connection, until `deadline` at most: the member's token, then
    /// its hello answered from this device's chain. The reason it ended, as
    /// the close says it.
    async fn serve_one(&self, peer: QuicPeer, g: &Grant, deadline: Instant) -> String {
        let served = tokio::time::timeout_at(deadline, async {
            let conn = match peer.accept().await {
                Some(Ok(conn)) => conn,
                Some(Err(e)) => return format!("accept failed: {e}"),
                None => return "endpoint_closed".to_string(),
            };
            // The server is out of the byte path: this token is what keeps
            // the endpoint from serving whoever reaches its address.
            match tokio::time::timeout(CONNECT_TIMEOUT, quic::server_authenticate(&conn, &g.token))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    conn.close(1u32.into(), b"auth failed");
                    return "auth_failed".to_string();
                }
            }
            let (mut send, mut recv) =
                match tokio::time::timeout(HELLO_TIMEOUT, conn.accept_bi()).await {
                    Ok(Ok(halves)) => halves,
                    _ => return "no_hello".to_string(),
                };
            let hello: MemberMsg =
                match tokio::time::timeout(HELLO_TIMEOUT, read_frame(&mut recv)).await {
                    Ok(Ok(h)) => h,
                    Ok(Err(e)) if e.is::<wire::FrameError>() => return "bad_frame".to_string(),
                    _ => return "no_hello".to_string(),
                };
            // The token proved the grant; the hello must be for it.
            let refuse = |reason: &str| SourceMsg::Refused {
                reason: reason.into(),
            };
            let (answer, member_tip) = match &hello {
                MemberMsg::Hello { session, .. } if *session != g.session_id.to_hex() => {
                    (refuse("wrong_session"), 0)
                }
                MemberMsg::Hello { fence, .. } if *fence != g.fence => (refuse("wrong_fence"), 0),
                MemberMsg::Hello { tip, .. } => {
                    let live = self.session_live(g.session_id);
                    let answer = match &self.store {
                        Ok(store) => match store.answer_hello(hello.clone(), live).await {
                            Ok(a) => a,
                            Err(e) => SourceMsg::Refused {
                                reason: format!("the store could not answer: {e}"),
                            },
                        },
                        Err(_) => refuse("not_held"),
                    };
                    (answer, tip.seq)
                }
                // A need or an ack before any hello.
                _ => (refuse("not_a_hello"), 0),
            };
            let refused = matches!(answer, SourceMsg::Refused { .. });
            if write_frame(&mut send, &answer).await.is_err() {
                return "member_gone".to_string();
            }
            if refused {
                // Held until the member lets go, HELLO_TIMEOUT at most: the
                // last to receive is the one to close (quinn's
                // `Connection::close`). Closed under its data, the
                // connection would lose the refusal, and the member would
                // hear no answer where there is one; an acknowledgement is
                // not enough, since a receiver may drop what it acknowledged
                // but had not yet read once the close arrives.
                let _ = send.finish();
                let _ = tokio::time::timeout(HELLO_TIMEOUT, conn.closed()).await;
                return "refused".to_string();
            }
            // P2d-3 — the events from where the opening exchange left the
            // member: its own tip, or the point both hold.
            let from = match &answer {
                SourceMsg::Diverged { at, .. } => at.seq,
                _ => member_tip,
            };
            let Ok(store) = &self.store else {
                // A served answer read the store.
                return "not_held".to_string();
            };
            let sid = g.session_id.to_hex();
            self.serve_events(
                store,
                &conn,
                send,
                recv,
                g.grant_id,
                g.session_id,
                &sid,
                from,
            )
            .await
        })
        .await;
        served.unwrap_or_else(|_| "expired".to_string())
    }

    /// P2d-3 — the source's side once the opening exchange is done: the
    /// events past `from`, from the store and then as they are appended, no
    /// more than [`AHEAD_BYTES`] past the member's last ack; each blob the
    /// member asks for, on a stream of its own; and the member's acks, each
    /// checked against what was sent. Until the member lets the connection
    /// go or sends what it may not, or the grant ends (the caller's
    /// deadline). The reason it ended, as the close says it.
    #[allow(clippy::too_many_arguments)]
    async fn serve_events(
        &self,
        store: &StoreHandle,
        conn: &QuicConnection,
        mut send: SendStream,
        recv: RecvStream,
        grant_id: ObjectId,
        session: ObjectId,
        sid: &str,
        from: u64,
    ) -> String {
        // Subscribe FIRST, then catch up from the store: an event appended in
        // between is in one or the other, and the cursor drops what is in
        // both (the viewer's `follow`, `view.rs`).
        let mut feed = store.subscribe();
        let sent = Mutex::new(Sent::default());
        let (acked_tx, mut acked) = watch::channel(0u64);
        let (need_tx, need_rx) = mpsc::channel(1);
        let events = async {
            let mut cursor = from;
            if let Err(why) =
                send_from_store(store, sid, &mut send, &sent, &mut acked, &mut cursor).await
            {
                return why;
            }
            loop {
                let step = match feed.recv().await {
                    Ok(env) if env.session == sid && env.seq > cursor => {
                        if env.seq == cursor + 1 {
                            let one = std::slice::from_ref(&*env);
                            send_events(&mut send, &sent, &mut acked, one)
                                .await
                                .map(|()| cursor = env.seq)
                        } else {
                            // Out of step: the store has what came between.
                            send_from_store(store, sid, &mut send, &sent, &mut acked, &mut cursor)
                                .await
                        }
                    }
                    Ok(_) => Ok(()),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        debug!(
                            session = sid,
                            lagged = n,
                            "hive stream: the feed lagged — re-reading the store"
                        );
                        send_from_store(store, sid, &mut send, &sent, &mut acked, &mut cursor).await
                    }
                    Err(broadcast::error::RecvError::Closed) => Err("store_closed".to_string()),
                };
                if let Err(why) = step {
                    return why;
                }
            }
        };
        let reason = tokio::select! {
            why = events => why,
            why = read_member(recv, &sent, acked_tx, need_tx) => why,
            why = self.send_blobs(conn, store, grant_id, session, sid, need_rx) => why,
        };
        let reason = ended_by(conn, "member", "closed", reason);
        let s = sent.lock().unwrap_or_else(|e| e.into_inner());
        info!(
            grant = %grant_id, session = sid, from, acked = s.acked_seq,
            sent_bytes = s.bytes, %reason, "hive stream: served"
        );
        reason
    }

    /// P2d-3 — each blob the member asks for, in its order, on a stream of
    /// its own: `blob {hash, len}`, then its bytes. A blob this store does
    /// not hold for the session ends the stream (`blob_missing`): the event
    /// naming it was sent, and a source keeps a checkpoint's blobs before
    /// the checkpoint, so this copy cannot finish the member's.
    async fn send_blobs(
        &self,
        conn: &QuicConnection,
        store: &StoreHandle,
        grant_id: ObjectId,
        session: ObjectId,
        sid: &str,
        mut need: mpsc::Receiver<Work>,
    ) -> String {
        while let Some(work) = need.recv().await {
            let blobs = match work {
                Work::Need(blobs) => blobs,
                // P2f-2b — answered on a stream of its own, as a blob is.
                Work::Pack { commit, haves } => {
                    let answer = self
                        .answer_want_pack(store, session, sid, &commit, &haves)
                        .await;
                    let Ok(mut uni) = conn.open_uni().await else {
                        return "closed".to_string();
                    };
                    if write_frame(&mut uni, &answer).await.is_err() {
                        return "closed".to_string();
                    }
                    let _ = uni.finish();
                    continue;
                }
            };
            for hash in blobs {
                let bytes = match store.get_blob(sid, hash.0).await {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        warn!(session = sid, blob = %hash, "hive stream: a blob the member asked for is not held here");
                        return "blob_missing".to_string();
                    }
                    Err(e) => {
                        warn!(session = sid, blob = %hash, %e, "hive stream: a blob could not be read");
                        return "store_error".to_string();
                    }
                };
                if bytes.len() > wire::MAX_STREAM_BLOB {
                    warn!(session = sid, blob = %hash, len = bytes.len(), "hive stream: a blob past the stream's limit");
                    return "blob_too_large".to_string();
                }
                let Ok(mut uni) = conn.open_uni().await else {
                    return "closed".to_string();
                };
                let header = BlobMsg::Blob {
                    hash,
                    len: bytes.len() as u64,
                };
                if write_frame(&mut uni, &header).await.is_err()
                    || uni.write_all(&bytes).await.is_err()
                {
                    return "closed".to_string();
                }
                let _ = uni.finish();
                self.count_blob(grant_id);
            }
        }
        // The reader let `need` go, and its reason ends the stream.
        std::future::pending().await
    }

    /// `rc:hive.replica.dial`: dial the source and say where this copy
    /// ends. Not this device's to follow: closed at once, in words.
    pub(super) fn follow_dial(self: &Arc<Self>, d: Dial, primary: bool) {
        if !primary {
            return self.report_close(d.grant_id, "secondary_org");
        }
        // P2d-3b — the gate that survives a compromised server: a copy is
        // followed only while the owner lets this device hold copies.
        // P2f-1b — or it is the copy of a teleport this device was prepared
        // for (P2f-1a), the one it will run.
        if !self.cfg.replica && !self.teleport_admitted(d.session_id, d.fence) {
            return self.report_close(d.grant_id, "replica_disabled");
        }
        let path = match d.path {
            Some(p) => p,
            None => {
                self.on_dial_dropped(d.session_id, "path_unavailable");
                return self.report_close(d.grant_id, "path_unavailable");
            }
        };
        let grant_id = d.grant_id;
        let session_id = d.session_id;
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        if streams.contains_key(&grant_id) {
            // A replay: the stream this dial started follows it.
            return debug!(grant = %grant_id, "hive stream: a dial this device follows already");
        }
        if streams.values().filter(|s| s.role == Role::Member).count() >= MAX_MEMBER_STREAMS {
            drop(streams);
            self.on_dial_dropped(session_id, "busy");
            return self.report_close(grant_id, "busy");
        }
        let ttl_secs = d.ttl_secs;
        let sup = Arc::clone(self);
        let task = tokio::spawn(async move {
            let reason = sup.follow_one(&d).await;
            sup.stream_ended(d.grant_id, &reason);
        });
        streams.insert(
            grant_id,
            Stream {
                session_id,
                role: Role::Member,
                path,
                answer: None,
                relay: None,
                held: Vec::new(),
                blobs: 0,
                task: task.abort_handle(),
            },
        );
        drop(streams);
        // P2d-3b — the ask for this session has its answer: followed, or
        // (P2d-4) followed beside the stream it renews.
        self.on_dialed(session_id, grant_id, ttl_secs);
    }

    /// The member's side of one stream, by the grant's life at most.
    async fn follow_one(self: &Arc<Self>, d: &Dial) -> String {
        let Ok(store) = &self.store else {
            return "store_unavailable".to_string();
        };
        let sid = d.session_id.to_hex();
        // A member of it, by this device's own record of what it joined.
        match store.memberships().await {
            Ok(m) if m.iter().any(|m| m.session == sid) => {}
            Ok(_) => return "not_a_member".to_string(),
            Err(e) => {
                warn!(grant = %d.grant_id, %e, "hive stream: the memberships could not be read");
                return "store_unavailable".to_string();
            }
        }
        let addrs: Vec<SocketAddr> = d
            .addrs
            .iter()
            .take(stream_limits::MAX_ADDRS)
            .filter_map(|a| a.parse().ok())
            .filter(is_dialable)
            .collect();
        // On `derp` the source is dialed by its key, never an address.
        if addrs.is_empty() && d.path != Some(HiveStreamPath::Derp) {
            return "no_address".to_string();
        }
        let deadline = Instant::now() + Duration::from_secs(u64::from(d.ttl_secs));
        let followed = tokio::time::timeout_at(deadline, async {
            let (peer, targets) = match d.path {
                Some(HiveStreamPath::Relay) => match self.member_relay(d, &addrs).await {
                    Ok(peer) => (peer, addrs.clone()),
                    Err(why) => return why,
                },
                Some(HiveStreamPath::Derp) => match self.member_derp(d) {
                    Ok((peer, at)) => (peer, vec![at]),
                    Err(why) => return why,
                },
                _ => match QuicPeer::client(
                    "0.0.0.0:0".parse().expect("a bind address"),
                    &d.cert_fingerprint,
                ) {
                    Ok(peer) => (peer, addrs.clone()),
                    Err(e) => return format!("the client could not be bound: {e}"),
                },
            };
            let Some(conn) = connect_first(&peer, &targets).await else {
                return "unreachable".to_string();
            };
            if quic::client_authenticate(&conn, &d.token).await.is_err() {
                return "auth_failed".to_string();
            }
            let (mut send, mut recv) = match conn.open_bi().await {
                Ok(halves) => halves,
                Err(e) => return format!("no stream: {e}"),
            };
            let hello = match store.member_hello(&sid, d.fence).await {
                Ok(h) => h,
                Err(e) => return format!("no hello: {e}"),
            };
            if write_frame(&mut send, &hello).await.is_err() {
                return "source_gone".to_string();
            }
            let answer: SourceMsg =
                match tokio::time::timeout(HELLO_TIMEOUT, read_frame(&mut recv)).await {
                    Ok(Ok(a)) => a,
                    Ok(Err(e)) if e.is::<wire::FrameError>() => return "bad_frame".to_string(),
                    _ => return "no_answer".to_string(),
                };
            info!(grant = %d.grant_id, session = %d.session_id, source = %d.source_id, answer = ?answer, "hive stream: the source answered");
            // P2f-2c — what the source says it stands in for is held to the
            // wire's rules before anything is taken from it.
            if let SourceMsg::Hello { stand_ins, .. } | SourceMsg::Diverged { stand_ins, .. } =
                &answer
                && wire::check_stand_ins(stand_ins).is_err()
            {
                return ended_by(&conn, "source", "source_closed", "bad_frame".to_string());
            }
            let refused = matches!(answer, SourceMsg::Refused { .. });
            if let Some(s) = self
                .streams
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&d.grant_id)
            {
                s.answer = Some(answer.clone());
            }
            if refused {
                return "refused".to_string();
            }
            // P2d-4 — it carries: a renewal's stream is the one followed
            // from here, and the stream it renews is let go before this one
            // touches the copy.
            self.on_answered(d.session_id, d.grant_id);
            // P2d-3 — a copy off the source's chain is set aside past the
            // point both hold before it takes the source's events.
            if let SourceMsg::Diverged { at, .. } = &answer
                && let Err(why) = set_aside(store, &sid, &hello, at).await
            {
                return ended_by(&conn, "source", "source_closed", why);
            }
            // P2d-3b — a session over on the source is followed only until
            // the copy holds all of it: where the source's chain ends.
            // P2f-2b — the source answers `want_pack`; P2f-2c — and the
            // whole packs it holds only a substitute for, asked for so.
            let offer = match &answer {
                SourceMsg::Hello {
                    packs, stand_ins, ..
                }
                | SourceMsg::Diverged {
                    packs, stand_ins, ..
                } => PackOffer {
                    packs: *packs,
                    stand_ins: stand_ins.clone(),
                },
                _ => PackOffer::default(),
            };
            let until = match &answer {
                SourceMsg::Hello {
                    tip, live: false, ..
                } => Some(tip.seq),
                SourceMsg::Diverged {
                    tip: Some(tip),
                    live: false,
                    ..
                } => Some(tip.seq),
                _ => None,
            };
            self.follow_events(store, &conn, send, recv, d, &sid, until, &offer)
                .await
        })
        .await;
        // P2d-3 — where the copy ends now, whatever ended the stream, the
        // grant's end among them, which cuts it off mid-way.
        self.report_tip(d.session_id).await;
        followed.unwrap_or_else(|_| "expired".to_string())
    }

    /// P2d-3 — the member's side once the opening exchange is done: each
    /// `events` frame read, each event's blobs asked for and kept before the
    /// event is applied through the store's chain check, and the frame acked
    /// once all of it is on disk; the tip reported to the server as it
    /// moves. Until the source lets the connection go or sends what it may
    /// not, or the grant ends (the caller's deadline).
    ///
    /// P2d-3b — `until`: a session over on the source ends at that seq, and
    /// the member lets the stream go (`caught_up`) once its copy holds it,
    /// at once when it does already: nothing more will be appended.
    #[allow(clippy::too_many_arguments)]
    async fn follow_events(
        &self,
        store: &StoreHandle,
        conn: &QuicConnection,
        mut send: SendStream,
        mut recv: RecvStream,
        d: &Dial,
        sid: &str,
        until: Option<u64>,
        offer: &PackOffer,
    ) -> String {
        let (moved, moves) = watch::channel(());
        let applying = async {
            if let Some(end) = until {
                let held = store
                    .chain_tip(sid)
                    .await
                    .ok()
                    .flatten()
                    .map_or(0, |t| t.seq);
                if held >= end {
                    return "caught_up".to_string();
                }
            }
            loop {
                let frame: SourceMsg = match read_frame(&mut recv).await {
                    Ok(f) => f,
                    Err(e) if e.is::<wire::FrameError>() => return "bad_frame".to_string(),
                    Err(_) => return "closed".to_string(),
                };
                // Past the opening exchange, events are all a source says.
                let SourceMsg::Events { events } = frame else {
                    return "bad_frame".to_string();
                };
                if wire::check_events(&events).is_err() {
                    return "bad_frame".to_string();
                }
                let mut tip = None;
                for meta in &events {
                    match self
                        .take_event(
                            store,
                            conn,
                            &mut send,
                            &mut recv,
                            d.grant_id,
                            (d.session_id, sid),
                            offer,
                            meta,
                        )
                        .await
                    {
                        Ok(t) => tip = Some(t),
                        Err(why) => return why,
                    }
                }
                if let Some(tip) = tip {
                    if write_frame(&mut send, &wire::ack_of(&tip)).await.is_err() {
                        return "closed".to_string();
                    }
                    let _ = moved.send(());
                    if until.is_some_and(|end| tip.seq >= end) {
                        return "caught_up".to_string();
                    }
                }
            }
        };
        let reason = tokio::select! {
            why = applying => why,
            // Never ends: the applier's end is the stream's.
            () = self.report_tips(d.session_id, moves) => "closed".to_string(),
        };
        ended_by(conn, "source", "source_closed", reason)
    }

    /// P2d-3 — one event of a frame: its JSON read within this device's event
    /// budget, the blobs it names that the store lacks asked for and kept,
    /// then the event applied. Its tip, or the close's word.
    #[allow(clippy::too_many_arguments)]
    async fn take_event(
        &self,
        store: &StoreHandle,
        conn: &QuicConnection,
        send: &mut SendStream,
        recv: &mut RecvStream,
        grant_id: ObjectId,
        (session, sid): (ObjectId, &str),
        offer: &PackOffer,
        meta: &EventMeta,
    ) -> Result<ChainTip, String> {
        // At most MAX_EVENT_BYTES (`check_events`), which the budget holds.
        let len = meta.len as usize;
        let Ok(_held) = self.replica_events.acquire_many(len as u32).await else {
            return Err("closed".to_string());
        };
        let mut json = vec![0u8; len];
        read_within(recv, &mut json, "bad_frame").await?;
        let Ok(json) = String::from_utf8(json) else {
            return Err("bad_frame".to_string());
        };
        let env = meta.envelope(sid, json);
        let tip = env.tip();
        // P2f-2b — a checkpoint's whole pack, stood in for by a pack against
        // what the folder this session will run in holds, when one is kept or
        // the source answers the want: its own blobs are not asked for.
        let mut stood_in = HashSet::new();
        if let Some(TranscriptEvent::Checkpoint(cp)) = env.event()
            && let Some(ws) = cp.workspace.as_ref()
            && ws.base.is_none()
            && !ws.pack.is_empty()
            && self
                .stand_in(store, conn, send, grant_id, (session, sid), offer, ws)
                .await?
        {
            stood_in.extend(ws.pack.iter().map(|c| c.hash));
        }
        self.fetch_blobs(store, conn, send, grant_id, sid, &env, &stood_in)
            .await?;
        // Held already when another stream of the session carried it first
        // (a renewal beside the stream it replaces), its blobs before it.
        match store.apply_unless_held(env).await {
            Ok(_) => Ok(tip),
            Err(e) => {
                warn!(session = sid, seq = meta.seq, %e, "hive stream: an event refused");
                Err(refused_word(&e).to_string())
            }
        }
    }

    /// P2d-3 — the blobs `env` names that the store lacks, asked for and
    /// kept, a wave at a time: as many as this device's blob budget holds, at
    /// most [`wire::MAX_NEED`], the budget taken BEFORE the `need` goes, so
    /// every blob of a wave is read the moment it arrives.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_blobs(
        &self,
        store: &StoreHandle,
        conn: &QuicConnection,
        send: &mut SendStream,
        grant_id: ObjectId,
        sid: &str,
        env: &EventEnvelope,
        stood_in: &HashSet<Digest>,
    ) -> Result<(), String> {
        let mut missing = Vec::new();
        for (hash, len) in wire::blobs_named(env) {
            if stood_in.contains(&hash) {
                continue;
            }
            if wire::check_blob_len(len).is_err() {
                warn!(session = sid, seq = env.seq, blob = %hash, len, "hive stream: an event names a blob past the stream's limit");
                return Err("blob_too_large".to_string());
            }
            match store.has_blob(sid, hash.0).await {
                Ok(true) => {}
                Ok(false) => missing.push((hash, len)),
                Err(e) => {
                    warn!(session = sid, blob = %hash, %e, "hive stream: the store could not say whether it holds a blob");
                    return Err("store_error".to_string());
                }
            }
        }
        self.fetch_list(store, conn, send, grant_id, sid, &missing)
            .await
    }

    /// P2d-3 — `missing`, asked for and kept a wave at a time: as many as
    /// this device's blob budget holds, at most [`wire::MAX_NEED`], the
    /// budget taken BEFORE the `need` goes, so every blob of a wave is read
    /// the moment it arrives.
    async fn fetch_list(
        &self,
        store: &StoreHandle,
        conn: &QuicConnection,
        send: &mut SendStream,
        grant_id: ObjectId,
        sid: &str,
        missing: &[(Digest, u64)],
    ) -> Result<(), String> {
        let mut rest = missing;
        while !rest.is_empty() {
            // At least one, each at most MAX_STREAM_BLOB, which the budget
            // holds four of: the budget is never asked for more than it has.
            let (mut n, mut bytes) = (0, 0u64);
            while n < rest.len()
                && n < wire::MAX_NEED
                && (n == 0 || bytes + rest[n].1 <= BLOB_BUDGET as u64)
            {
                bytes += rest[n].1;
                n += 1;
            }
            let (wave, after) = rest.split_at(n);
            rest = after;
            let Ok(_held) = self.replica_blobs.acquire_many(bytes as u32).await else {
                return Err("closed".to_string());
            };
            let need = MemberMsg::Need {
                blobs: wave.iter().map(|(h, _)| *h).collect(),
            };
            if write_frame(send, &need).await.is_err() {
                return Err("closed".to_string());
            }
            for (hash, bytes) in read_wave(conn, wave).await? {
                match store.put_named_blob(sid, hash.0, bytes).await {
                    Ok(()) => self.count_blob(grant_id),
                    Err(WriterError::Store(StoreError::BlobMismatch { .. })) => {
                        return Err("bad_blob".to_string());
                    }
                    Err(WriterError::Store(StoreError::Purged { .. })) => {
                        return Err("purged".to_string());
                    }
                    Err(e) => {
                        warn!(session = sid, blob = %hash, %e, "hive stream: a blob could not be kept");
                        return Err("store_error".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// P2f-2b — whether a checkpoint's whole pack (`ws`) is stood in for: by
    /// a substitute this store keeps already, or by one the source makes now
    /// against what the folder this device will run the session in holds
    /// (git's have and want). Asked only of a source that answers it
    /// (`packs`), and only while the whole pack's own blobs are not all here:
    /// for a teleport this device was prepared for with the server's
    /// `have_want`, and (P2f-2c) for a whole pack the source holds only a
    /// substitute for, whose blobs are not there to ask for, then with no
    /// haves where this device has none to offer. `Ok(false)`: its own blobs
    /// are asked for, as before.
    #[allow(clippy::too_many_arguments)]
    async fn stand_in(
        &self,
        store: &StoreHandle,
        conn: &QuicConnection,
        send: &mut SendStream,
        grant_id: ObjectId,
        (session, sid): (ObjectId, &str),
        offer: &PackOffer,
        ws: &WorkspaceSnap,
    ) -> Result<bool, String> {
        match store.substitute(sid, &ws.commit).await {
            Ok(Some(_)) => return Ok(true),
            Ok(None) => {}
            Err(e) => {
                warn!(session = sid, %e, "hive stream: the store could not say whether it keeps a substitute");
                return Err("store_error".to_string());
            }
        }
        if !offer.packs {
            return Ok(false);
        }
        let place = self.have_want_place(session);
        let stood_in = offer.stand_ins.contains(&ws.commit);
        if place.is_none() && !stood_in {
            return Ok(false);
        }
        let mut whole_here = true;
        for c in &ws.pack {
            match store.has_blob(sid, c.hash.0).await {
                Ok(true) => {}
                Ok(false) => {
                    whole_here = false;
                    break;
                }
                Err(_) => return Err("store_error".to_string()),
            }
        }
        if whole_here {
            // Every one of its blobs is here: nothing to stand in for.
            return Ok(false);
        }
        let held = match &place {
            Some((order, account, folder)) => self.haves_for(order, account, folder, ws).await,
            None => None,
        };
        let haves = match held {
            Some(haves) => haves,
            // P2f-2c — a whole pack made again from the source's repository.
            None if stood_in => Vec::new(),
            None => return Ok(false),
        };
        let want = MemberMsg::WantPack {
            commit: ws.commit.clone(),
            haves: haves.clone(),
        };
        if write_frame(send, &want).await.is_err() {
            return Err("closed".to_string());
        }
        // Its own stream: the source may have sent events past this one on
        // the stream they share, which this one is read before.
        let answer = tokio::time::timeout(PACK_ANSWER, async {
            let mut uni = conn.accept_uni().await.map_err(|_| "closed".to_string())?;
            read_frame::<BlobMsg>(&mut uni).await.map_err(|e| {
                if e.is::<wire::FrameError>() {
                    "bad_frame".to_string()
                } else {
                    "closed".to_string()
                }
            })
        })
        .await;
        let answer = match answer {
            Ok(Ok(a)) => a,
            Ok(Err(why)) => return Err(why),
            Err(_) => return Err("stalled".to_string()),
        };
        match answer {
            BlobMsg::Pack {
                commit,
                against,
                chunks,
            } => {
                if wire::check_pack(&ws.commit, &haves, &commit, &against, &chunks).is_err() {
                    return Err("bad_pack".to_string());
                }
                let list: Vec<(Digest, u64)> = chunks.iter().map(|c| (c.hash, c.len)).collect();
                self.fetch_list(store, conn, send, grant_id, sid, &list)
                    .await?;
                let thin = against.len();
                let sub = Substitute {
                    commit,
                    against,
                    chunks,
                };
                match store.put_substitute(sid, sub).await {
                    Ok(()) => {}
                    Err(WriterError::Store(StoreError::Purged { .. })) => {
                        return Err("purged".to_string());
                    }
                    Err(e) => {
                        warn!(session = sid, %e, "hive stream: a substitute could not be kept");
                        return Err("store_error".to_string());
                    }
                }
                if thin == 0 {
                    info!(
                        session = sid, commit = %ws.commit,
                        "hive stream: the workspace's whole pack came, made again by the source"
                    );
                } else {
                    info!(
                        session = sid, commit = %ws.commit, against = thin,
                        "hive stream: the workspace came as a pack against this folder's repository"
                    );
                }
                Ok(true)
            }
            BlobMsg::NoPack { why, .. } => {
                info!(
                    session = sid, commit = %ws.commit, %why,
                    "hive stream: no pack against this folder's repository — the whole pack instead"
                );
                Ok(false)
            }
            // A blob nobody asked for.
            BlobMsg::Blob { .. } => Err("bad_blob".to_string()),
        }
    }

    /// P2f-2b — what the folder this device will run the session in holds
    /// that a pack can be made against: the person's `HEAD` where the
    /// checkpoint was taken, when this repository holds it, and its own
    /// `HEAD`. Asked of the account's own git, as the account. `None`:
    /// nothing to offer, or nothing could be asked.
    async fn haves_for(
        &self,
        order: &super::StartOrder,
        account: &str,
        folder: &std::path::Path,
        ws: &WorkspaceSnap,
    ) -> Option<Vec<String>> {
        let (who, dest) = match self.copy_place(order, account, folder) {
            Ok(place) => place,
            Err(e) => {
                debug!(session = %order.session_id, %e, "hive stream: no place to ask the folder's repository from");
                return None;
            }
        };
        let req = packer::Request {
            v: packer::REQUEST_V,
            folder: dest.folder,
            state_dir: dest.state_dir,
            ask: packer::Ask::Holds {
                candidates: ws.head.iter().cloned().collect(),
            },
        };
        let (mut haves, head) = match packer::ask(&self.checkpoint_runner(), &who, &req).await {
            Ok(packer::Answer::Holds { held, head }) => (held, head),
            Ok(_) => return None,
            Err(e) => {
                debug!(session = %order.session_id, %e, "hive stream: the folder's repository could not be asked");
                return None;
            }
        };
        if let Some(h) = head
            && !haves.contains(&h)
        {
            haves.push(h);
        }
        haves.retain(|h| *h != ws.commit);
        haves.truncate(wire::MAX_WANT_HAVES);
        (!haves.is_empty()).then_some(haves)
    }

    /// P2f-2b — the answer to a member's `want_pack`: the pack that brings
    /// `commit` into a repository holding `haves`, made as the session's
    /// account from its own repository, its chunks kept as blobs of the
    /// session for the member to `need` as any blob. Only for the commit of
    /// one of the session's whole packs. Anything else is `no_pack`, in a
    /// word, and the member takes the whole pack. P2f-2c — a want with no
    /// haves only for a whole pack this copy holds only a substitute for
    /// (`held_whole` otherwise: its blobs are here to ask for); and made from
    /// where the session runs here, or, when it does not run here now, from
    /// where its last launch here kept it was worked on.
    async fn answer_want_pack(
        &self,
        store: &StoreHandle,
        session: ObjectId,
        sid: &str,
        commit: &str,
        haves: &[String],
    ) -> BlobMsg {
        let no = |why: &str| BlobMsg::NoPack {
            commit: commit.to_string(),
            why: why.to_string(),
        };
        match whole_pack_commit(store, sid, commit).await {
            Ok(true) => {}
            Ok(false) => return no("not_a_whole_pack"),
            Err(e) => {
                warn!(session = sid, %e, "hive stream: the checkpoints could not be read for a want");
                return no("store_error");
            }
        }
        if haves.is_empty() {
            match store.stand_ins(sid, wire::MAX_WANTS).await {
                Ok(stand_ins) if stand_ins.iter().any(|c| c == commit) => {}
                Ok(_) => return no("held_whole"),
                Err(e) => {
                    warn!(session = sid, %e, "hive stream: the stand-ins could not be read for a want");
                    return no("store_error");
                }
            }
        }
        let place = match self.workplace(session) {
            Some(place) => place,
            None => match self.kept_workplace(store, sid).await {
                Some(place) => Arc::new(place),
                None => return no("not_live"),
            },
        };
        let req = packer::Request {
            v: packer::REQUEST_V,
            folder: place.folder.clone(),
            state_dir: place.state_dir.clone(),
            ask: packer::Ask::Pack {
                commit: commit.to_string(),
                haves: haves.to_vec(),
            },
        };
        let (against, pack) = match packer::ask(&self.checkpoint_runner(), &place.who, &req).await {
            Ok(packer::Answer::Pack { against, pack }) => (against, pack),
            Ok(_) => return no("other"),
            Err(e) => {
                warn!(session = sid, commit, %e, "hive stream: no pack against the member's repository");
                return no("pack_failed");
            }
        };
        let (chunks, blobs) = chunk_bytes(&pack);
        for blob in blobs {
            if let Err(e) = store.put_blob(sid, blob).await {
                warn!(session = sid, %e, "hive stream: a pack's chunk could not be kept");
                return no("store_error");
            }
        }
        if against.is_empty() {
            info!(
                session = sid,
                commit,
                bytes = pack.len(),
                "hive stream: a whole pack made again for the member"
            );
        } else {
            info!(
                session = sid,
                commit,
                against = against.len(),
                bytes = pack.len(),
                "hive stream: a pack against the member's repository"
            );
        }
        BlobMsg::Pack {
            commit: commit.to_string(),
            against,
            chunks,
        }
    }

    /// P2f-2c — where a session that does not run here now was last worked
    /// on, as its launch here kept it, and as whom: the account resolved as a
    /// start resolves it, now. `None` when nothing was kept, or that account
    /// cannot be run as now.
    async fn kept_workplace(&self, store: &StoreHandle, sid: &str) -> Option<packer::Workplace> {
        let kept = match store.workplace(sid).await {
            Ok(Some(kept)) => kept,
            Ok(None) => return None,
            Err(e) => {
                warn!(session = sid, %e, "hive stream: the store could not say where the session was worked on");
                return None;
            }
        };
        match self.who_for(&kept.account) {
            Ok(who) => Some(packer::Workplace {
                who,
                folder: std::path::PathBuf::from(kept.folder),
                state_dir: std::path::PathBuf::from(kept.state_dir),
            }),
            Err(e) => {
                warn!(session = sid, %e, "hive stream: the account the session ran as cannot be run as now");
                None
            }
        }
    }

    /// P2d-3 — the member's tip reported as its stream moves it: at once,
    /// then at most every [`TIP_EVERY`], what lands meanwhile in one report
    /// after it. Never returns; the stream's end is the caller's to report.
    async fn report_tips(&self, session: ObjectId, mut moves: watch::Receiver<()>) {
        while moves.changed().await.is_ok() {
            loop {
                self.report_tip(session).await;
                let rest = tokio::time::sleep(TIP_EVERY);
                tokio::pin!(rest);
                let mut due = false;
                loop {
                    tokio::select! {
                        () = &mut rest => break,
                        moved = moves.changed() => {
                            if moved.is_err() {
                                return std::future::pending().await;
                            }
                            due = true;
                        }
                    }
                }
                if !due {
                    break;
                }
            }
        }
        std::future::pending().await
    }

    /// P2d-3b — whether `session` is not over on this device: it runs here,
    /// or its hosted record will resume it here. What a source tells its
    /// member: a member caught up with a session that is over lets go.
    ///
    /// P2e-5c — or it moves here: a promotion moved the session to this
    /// device, whose start at that fence is on its way or being taken, the
    /// copy put in place first. ⚠️ Without it, from the lease's move until
    /// that start launched, the new primary told every member it streamed to
    /// that the session was over, and a member that held its copy whole
    /// parked it, while the session went on here.
    pub(super) fn session_live(&self, session: ObjectId) -> bool {
        self.holds_live(session)
            || self
                .hosted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&session.to_hex())
                .is_some()
            || self.moving_here(session)
    }

    /// P2d-3 — one more blob carried on `grant_id`'s stream.
    fn count_blob(&self, grant_id: ObjectId) {
        if let Some(s) = self
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&grant_id)
        {
            s.blobs += 1;
        }
    }

    /// The member's client on the derp rung: a QUIC client over this device's
    /// own `/derp` connection, on the stream's own route toward the source's
    /// key (by the grant's id), and the address that route answers to. The
    /// reason, in the close's words, when it cannot.
    fn member_derp(&self, d: &Dial) -> Result<(QuicPeer, SocketAddr), String> {
        let Some(handle) = self.derp_handle() else {
            return Err("no_derp".to_string());
        };
        let Some(source) = d.derp_pubkey.as_deref().and_then(parse_pubkey_hex) else {
            return Err("no_derp_key".to_string());
        };
        let conn = handle.mux.hive_conn_for(source, d.grant_id.bytes());
        let at = conn.synth_peer();
        let sock =
            RelayUdpSocket::new(Arc::new(conn)).map_err(|e| format!("no socket over DERP: {e}"))?;
        let peer = QuicPeer::client_over_derp(Arc::new(sock), &d.cert_fingerprint)
            .map_err(|e| format!("the client could not be built: {e}"))?;
        Ok((peer, at))
    }

    /// The member's client on the relay rung: its own allocation, on the
    /// source's TURN worker first, a QUIC client over it, its relayed
    /// address sent through the server for the source's permission, and its
    /// own permission for each of the source's addresses. The reason, in the
    /// close's words, when it cannot.
    async fn member_relay(&self, d: &Dial, source: &[SocketAddr]) -> Result<QuicPeer, String> {
        let Some((granted, user, cred)) = turn_creds(&d.ice_servers) else {
            return Err("no_turn".to_string());
        };
        // The source's relayed address names its TURN worker: two
        // allocations on one worker relay to each other, across workers
        // they may not (`driver.rs` `setup_quic_over_relay`). The granted
        // urls follow, should the pinned one not answer.
        let mut urls = Vec::with_capacity(granted.len() + 1);
        if let Some(ip) = source.first().map(SocketAddr::ip) {
            let host = match ip {
                IpAddr::V6(v6) => format!("[{v6}]"),
                IpAddr::V4(v4) => v4.to_string(),
            };
            let port = turn_url::first_udp_port(granted.iter().map(String::as_str));
            urls.push(format!("turn:{host}:{port}?transport=udp"));
        }
        urls.extend(granted);
        let turn = relay::allocate_relay_from_ice(&urls, &user, &cred)
            .await
            .map_err(|e| {
                debug!(grant = %d.grant_id, error = %format!("{e:#}"), "hive stream: no allocation");
                "allocate_failed".to_string()
            })?;
        let relay: Arc<dyn RelayConn> = Arc::new(turn);
        let ours = relay
            .local_addr()
            .map_err(|e| format!("no relayed address: {e}"))?;
        let sock = RelayUdpSocket::new(Arc::clone(&relay))
            .map_err(|e| format!("no socket over the relay: {e}"))?;
        let peer = QuicPeer::client_over_abstract_socket(Arc::new(sock), &d.cert_fingerprint)
            .map_err(|e| format!("the client could not be built: {e}"))?;
        // Awaited, not dropped on a full queue: without it the source never
        // permits this allocation, and nothing ever connects.
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let candidate = ClientMsg::HiveReplicaCandidate {
            grant_id: d.grant_id,
            addr: ours.to_string(),
        };
        match tx {
            Some(tx) if tx.send(candidate).await.is_ok() => {}
            _ => return Err("disconnected".to_string()),
        }
        // This allocation's own permission for each of the source's
        // addresses, before the first Initial, as the tunnel's client sends
        // it. The TURN client would install it on that first send anyway,
        // so this only spares the first Initial a race.
        for addr in source {
            permit(&relay, *addr).await;
        }
        tokio::time::sleep(PERMIT_SETTLE).await;
        Ok(peer)
    }

    /// A stream's task ended on its own: forget it, and tell the server why.
    /// A member's own follow hears it too (P2d-3b).
    fn stream_ended(self: &Arc<Self>, grant_id: ObjectId, reason: &str) {
        let gone = self
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&grant_id);
        if let Some(s) = gone {
            info!(
                grant = %grant_id, session = %s.session_id, role = ?s.role, %reason,
                answer = ?s.answer, "hive stream: ended"
            );
            self.report_close(grant_id, reason);
            if s.role == Role::Member {
                self.on_stream_over(s.session_id, grant_id, reason, s.answered());
            }
        }
    }

    /// A stream refused before it began: forgotten without a close, since
    /// the `ready` that refused it ends it on the server.
    fn forget_stream(&self, grant_id: ObjectId) {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&grant_id);
    }

    fn report_close(&self, grant_id: ObjectId, reason: &str) {
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(tx) = tx {
            let reason: String = reason.chars().take(MAX_REASON_CHARS).collect();
            let _ = tx.try_send(ClientMsg::HiveReplicaClose { grant_id, reason });
        }
    }

    /// P2d-4 — a stream this device lets go on its own word, from outside its
    /// task: the old stream once its renewal carries (`renewed`), a renewal
    /// a newer dial replaced (`replaced`). It ends here at once, and the
    /// server is told why, which tells the other side. Its follow moved on
    /// already, so is not told.
    pub(super) fn end_stream(&self, grant_id: ObjectId, reason: &str) {
        let gone = self
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&grant_id);
        if let Some(s) = gone {
            s.task.abort();
            info!(grant = %grant_id, session = %s.session_id, role = ?s.role, %reason, "hive stream: let go");
            self.report_close(grant_id, reason);
        }
    }

    /// The server's `rc:hive.replica.close`: the stream ends here at once,
    /// its endpoint still being stood up or not, and nothing is said back
    /// (the server already forgot the grant).
    pub(super) fn close_stream(self: &Arc<Self>, grant_id: ObjectId, reason: &str) {
        let gone = self
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&grant_id);
        if let Some(s) = gone {
            s.task.abort();
            info!(grant = %grant_id, session = %s.session_id, role = ?s.role, %reason, "hive stream: closed by the server");
            // P2d-3b — a member's own follow hears it, in the server's word:
            // `member_left` stops it, any other is a stream's end.
            if s.role == Role::Member {
                self.on_stream_over(s.session_id, grant_id, reason, s.answered());
            }
        }
    }

    /// The source's answer to this member's hello on `grant_id`, once heard.
    #[cfg(all(test, unix))]
    pub(super) fn stream_answer(&self, grant_id: ObjectId) -> Option<SourceMsg> {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&grant_id)
            .and_then(|s| s.answer.clone())
    }

    /// Whether this device is a side of `grant_id` now.
    #[cfg(all(test, unix))]
    pub(super) fn holds_stream(&self, grant_id: ObjectId) -> bool {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&grant_id)
    }

    /// The streams this device serves now, as a source, its endpoints still
    /// being stood up among them.
    #[cfg(all(test, unix))]
    pub(super) fn serving(&self) -> usize {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|s| s.role == Role::Source)
            .count()
    }

    /// The DERP mux this device's streams ride in a test: `Some` a test's
    /// own, `None` none at all.
    #[cfg(all(test, unix))]
    pub(super) fn use_derp_for_tests(&self, handle: Option<DerpTunnelHandle>) {
        *self
            .derp_for_tests
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    /// P2d-3b — `session` hosted here, as one that runs or will resume: a
    /// source that holds it says it is live.
    #[cfg(all(test, unix))]
    pub(super) fn host_for_tests(&self, session: ObjectId) {
        self.hosted.lock().unwrap_or_else(|e| e.into_inner()).put(
            crate::hive::hosted::HostedSession {
                session: session.to_hex(),
                fence: 1,
                harness: "claude-code".into(),
                harness_session: "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70".into(),
                folder: "/tmp".into(),
                account: "dev".into(),
                starter: ObjectId::new().to_hex(),
                starter_email: String::new(),
                turns: 0,
                running: None,
                approvals: Vec::new(),
                resumed_at: None,
                quick_resumes: 0,
                harness_pid: None,
                harness_started: None,
                replicated: true,
                lease: false,
                fork_of: None,
            },
        );
    }

    /// The blobs `grant_id`'s stream carried so far: sent, as the source;
    /// kept, as the member. `None` once the stream is over.
    #[cfg(all(test, unix))]
    pub(super) fn stream_blobs(&self, grant_id: ObjectId) -> Option<u64> {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&grant_id)
            .map(|s| s.blobs)
    }

    /// The member's addresses held for `grant_id`'s allocation.
    #[cfg(all(test, unix))]
    pub(super) fn held_candidates(&self, grant_id: ObjectId) -> usize {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&grant_id)
            .map_or(0, |s| s.held.len())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::tests::{Rig, rig, rig_with};
    use super::*;
    use meshharbor_hive_node::checkpoint::{Checkpoint, snapshot_whole};
    use meshharbor_hive_node::{GENESIS, TranscriptEvent};
    use std::net::Ipv4Addr;
    use webrtc::turn::auth::{AuthHandler, generate_auth_key};
    use webrtc::turn::relay::relay_static::RelayAddressGeneratorStatic;
    use webrtc::turn::server::Server;
    use webrtc::turn::server::config::{ConnConfig, ServerConfig};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const TURN_USER: &str = "hive-tester";
    const TURN_PASS: &str = "turn-secret";
    const TURN_REALM: &str = "meshharbor.test";

    /// Long-term-credential auth for the one test user.
    struct StaticAuth;
    impl AuthHandler for StaticAuth {
        fn auth_handle(
            &self,
            _username: &str,
            realm: &str,
            _src: SocketAddr,
        ) -> Result<Vec<u8>, webrtc::turn::Error> {
            Ok(generate_auth_key(TURN_USER, realm, TURN_PASS))
        }
    }

    /// An in-process TURN server on loopback, its relayed addresses on
    /// loopback too, and the ICE servers a relay grant would carry for it
    /// (as tunnel-core's `quinn_runs_over_two_turn_allocations` stands it
    /// up). Keep the server for the test's life.
    async fn loopback_turn() -> (Server, Vec<IceServer>) {
        let conn = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = conn.local_addr().unwrap();
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address: "127.0.0.1".to_owned(),
                    net: Arc::new(webrtc::util::vnet::net::Net::new(None)),
                }),
            }],
            realm: TURN_REALM.to_owned(),
            auth_handler: Arc::new(StaticAuth),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .expect("an in-process TURN server");
        let ice = vec![IceServer {
            urls: vec![format!("turn:{addr}?transport=udp")],
            username: Some(TURN_USER.into()),
            credential: Some(TURN_PASS.into()),
        }];
        (server, ice)
    }

    /// A grant for `session_id` on `path`, as the server would send it.
    fn grant(session_id: ObjectId, path: HiveStreamPath) -> Grant {
        Grant {
            grant_id: ObjectId::new(),
            session_id,
            fence: 1,
            member_id: ObjectId::new(),
            path: Some(path),
            token: TOKEN.into(),
            ice_servers: Vec::new(),
            member_derp_pubkey: None,
            ttl_secs: 30,
        }
    }

    /// Append notes to `sid` in `r`'s store, at fence 1.
    fn note(r: &Rig, sid: ObjectId, texts: &[&str]) {
        for text in texts {
            r.store.append(
                &sid.to_hex(),
                1,
                TranscriptEvent::Note {
                    text: (*text).into(),
                },
            );
        }
    }

    /// The `ready` a grant is answered with, as the server hears it. The
    /// source hosts the session, so says it is live (P2d-3b): its member
    /// follows on past the catch-up, as every stream did before.
    async fn ready_of(src: &Rig, g: Grant, primary: bool) -> ClientMsg {
        src.sup.host_for_tests(g.session_id);
        ready_as_is(src, g, primary).await
    }

    /// [`ready_of`], the source hosting nothing of its own accord: a session
    /// over there, unless the test hosted it.
    async fn ready_as_is(src: &Rig, g: Grant, primary: bool) -> ClientMsg {
        let (tx, mut rx) = mpsc::channel(4);
        src.sup.take_grant(g, primary, tx);
        tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .expect("a ready within 15 s")
            .expect("a ready")
    }

    /// The word a `ready` refuses with, or `None` for one that serves; a
    /// refusal never names an endpoint.
    fn refusal_of(ready: ClientMsg) -> Option<HiveStreamRefusal> {
        let ClientMsg::HiveReplicaReady {
            refused,
            cert_fingerprint,
            ..
        } = ready
        else {
            panic!("not a ready: {ready:?}");
        };
        assert!(
            refused.is_none() || cert_fingerprint.is_none(),
            "a refusal names no endpoint"
        );
        refused
    }

    /// The member told to dial what `ready` names, as the server would tell
    /// it, with `ice` the grant carried.
    fn dial(
        mem: &Rig,
        g: (ObjectId, ObjectId, Option<HiveStreamPath>),
        ready: ClientMsg,
        token: &str,
        ice: Vec<IceServer>,
    ) {
        dial_for(mem, g, ready, token, ice, 30);
    }

    /// [`dial`], the member holding the grant to `ttl_secs`.
    fn dial_for(
        mem: &Rig,
        g: (ObjectId, ObjectId, Option<HiveStreamPath>),
        ready: ClientMsg,
        token: &str,
        ice: Vec<IceServer>,
        ttl_secs: u32,
    ) {
        let (grant_id, session_id, path) = g;
        let ClientMsg::HiveReplicaReady {
            refused: None,
            cert_fingerprint: Some(fp),
            addrs,
            derp_pubkey,
            ..
        } = ready
        else {
            panic!("not ready: {ready:?}");
        };
        if path == Some(HiveStreamPath::Derp) {
            assert!(addrs.is_empty(), "no address on derp");
            assert!(derp_pubkey.is_some(), "the source's key to dial");
        } else {
            assert!(!addrs.is_empty(), "somewhere to dial");
        }
        mem.sup.follow_dial(
            Dial {
                grant_id,
                session_id,
                fence: 1,
                source_id: ObjectId::new(),
                path,
                token: token.into(),
                cert_fingerprint: fp,
                addrs,
                ice_servers: ice,
                derp_pubkey,
                ttl_secs,
            },
            true,
        );
    }

    /// A device whose owner lets it hold copies (`hive_replica`): a member.
    /// Its connection does not start following on its own (P2d-3b): a test
    /// drives that itself, so the connection's asks never race the test's.
    fn member_rig() -> Rig {
        rig_with(
            true,
            4,
            |c| c.replica = true,
            |s| s.without_follow_at_connect(),
        )
    }

    /// The source serves `g`, a session live there, and the member is told
    /// to dial it with `token`.
    async fn served_on(src: &Rig, mem: &Rig, g: Grant, token: &str) -> ObjectId {
        let ids = (g.grant_id, g.session_id, g.path);
        let ice = g.ice_servers.clone();
        let ready = ready_of(src, g, true).await;
        dial(mem, ids, ready, token, ice);
        ids.0
    }

    /// [`served_on`], the source hosting nothing of its own accord: a
    /// session over there, unless the test hosted it.
    async fn served_as_is(src: &Rig, mem: &Rig, g: Grant, token: &str) -> ObjectId {
        let ids = (g.grant_id, g.session_id, g.path);
        let ice = g.ice_servers.clone();
        let ready = ready_as_is(src, g, true).await;
        dial(mem, ids, ready, token, ice);
        ids.0
    }

    /// [`served_on`] a direct grant for `sid`.
    async fn served(src: &Rig, mem: &Rig, sid: ObjectId, token: &str) -> ObjectId {
        served_on(src, mem, grant(sid, HiveStreamPath::Direct), token).await
    }

    async fn answer_of(mem: &Rig, grant_id: ObjectId) -> SourceMsg {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(a) = mem.sup.stream_answer(grant_id) {
                return a;
            }
            assert!(Instant::now() < deadline, "the member heard no answer");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The reason of the next `rc:hive.replica.close` the rig's device
    /// sends the server for `grant_id`, or `None` when none comes within
    /// 15 s, so a test compares it in its own words.
    async fn close_of(r: &mut Rig, grant_id: ObjectId) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let msg = tokio::time::timeout_at(deadline, r.reports.recv())
                .await
                .ok()?
                .expect("the reporter is open");
            if let ClientMsg::HiveReplicaClose {
                grant_id: g,
                reason,
            } = msg
                && g == grant_id
            {
                return Some(reason);
            }
        }
    }

    /// The relayed address the rig's device, a member, sends the server for
    /// `grant_id`'s source to permit, or `None` within 15 s.
    async fn candidate_of(r: &mut Rig, grant_id: ObjectId) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let msg = tokio::time::timeout_at(deadline, r.reports.recv())
                .await
                .ok()?
                .expect("the reporter is open");
            if let ClientMsg::HiveReplicaCandidate { grant_id: g, addr } = msg
                && g == grant_id
            {
                return Some(addr);
            }
        }
    }

    /// What `follow_one` does up to its hello, by hand, so a test can send
    /// what a member of this build never would: the endpoint `ready` names
    /// dialed, the token presented, one stream open. The client is returned
    /// with the rest, since its endpoint ends with it.
    async fn dial_by_hand(ready: ClientMsg) -> (QuicPeer, QuicConnection, SendStream, RecvStream) {
        let ClientMsg::HiveReplicaReady {
            refused: None,
            cert_fingerprint: Some(fp),
            addrs,
            ..
        } = ready
        else {
            panic!("not ready: {ready:?}");
        };
        let peer = QuicPeer::client("0.0.0.0:0".parse().unwrap(), &fp).unwrap();
        let addrs: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        let conn = connect_first(&peer, &addrs)
            .await
            .expect("the endpoint answers");
        quic::client_authenticate(&conn, TOKEN).await.unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        (peer, conn, send, recv)
    }

    /// A STUN server that answers nothing: a direct endpoint takes
    /// [`STUN_TIMEOUT`] to stand up against it.
    fn silent_stun(sock: &std::net::UdpSocket) -> Vec<IceServer> {
        vec![IceServer {
            urls: vec![format!("stun:{}", sock.local_addr().unwrap())],
            username: None,
            credential: None,
        }]
    }

    /// The member dials the source the grant stood up, pinning its
    /// certificate and presenting the token, and hears where its copy
    /// stands: an empty copy is a prefix, answered with the source's tip. A
    /// close the server sends ends the member's side at once, and the
    /// source's ends with its connection, and says so.
    #[tokio::test]
    async fn a_member_dials_its_source_and_hears_where_its_copy_stands() {
        let mut src = rig(true, 4);
        let mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        let tip = src.store.chain_tip(&sid.to_hex()).await.unwrap().unwrap();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(
            answer_of(&mem, grant_id).await,
            SourceMsg::Hello {
                v: wire::STREAM_V,
                tip: Mark {
                    seq: tip.seq,
                    hash: hex::encode(tip.hash),
                },
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            },
            "an empty copy is a prefix"
        );
        mem.sup.close_stream(grant_id, "test");
        assert!(!mem.sup.holds_stream(grant_id), "the member's side is gone");
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("closed"),
            "the source's ends with the member's connection"
        );
        assert!(!src.sup.holds_stream(grant_id), "and the source's");
    }

    /// The relay rung, end to end, over a TURN server: each side its own
    /// allocation, the member's relayed address relayed to the source for
    /// its permission, and the same opening exchange over both.
    #[tokio::test]
    async fn a_member_follows_its_source_over_two_turn_allocations() {
        let (_turn, ice) = loopback_turn().await;
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        let tip = src.store.chain_tip(&sid.to_hex()).await.unwrap().unwrap();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let mut g = grant(sid, HiveStreamPath::Relay);
        g.ice_servers = ice;
        let grant_id = served_on(&src, &mem, g, TOKEN).await;
        let addr = candidate_of(&mut mem, grant_id)
            .await
            .expect("the member sends its relayed address");
        src.sup.take_candidate(grant_id, &addr, true);
        assert_eq!(
            answer_of(&mem, grant_id).await,
            SourceMsg::Hello {
                v: wire::STREAM_V,
                tip: Mark {
                    seq: tip.seq,
                    hash: hex::encode(tip.hash),
                },
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            },
            "over both allocations"
        );
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");
    }

    /// Without its permission on the source's allocation, the member's
    /// opening Initials never arrive: the source, the QUIC server, never
    /// sends first, so the TURN server drops them.
    #[tokio::test]
    async fn without_its_permission_the_members_initials_never_arrive() {
        let (_turn, ice) = loopback_turn().await;
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let mut g = grant(sid, HiveStreamPath::Relay);
        g.ice_servers = ice;
        let grant_id = served_on(&src, &mem, g, TOKEN).await;
        // The candidate is sent, and not passed on.
        assert!(candidate_of(&mut mem, grant_id).await.is_some());
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("unreachable"),
            "no permission, no connection"
        );
        assert!(mem.sup.stream_answer(grant_id).is_none());
        src.sup.close_stream(grant_id, "test");
    }

    /// A candidate that arrives before the source's allocation landed is
    /// held, and permitted once it lands, before the ready. (A TURN
    /// permission is an IP's alone, so the held address's port need not be
    /// the member's.)
    #[tokio::test]
    async fn a_candidate_before_the_allocation_is_permitted_when_it_lands() {
        let (_turn, ice) = loopback_turn().await;
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let mut g = grant(sid, HiveStreamPath::Relay);
        g.ice_servers = ice.clone();
        let ids = (g.grant_id, g.session_id, g.path);
        // Live there, so the member follows on past its catch-up.
        src.sup.host_for_tests(sid);
        let (tx, mut rx) = mpsc::channel(4);
        src.sup.take_grant(g, true, tx);
        // One thread, nothing awaited yet: the grant's task has not run.
        src.sup.take_candidate(ids.0, "127.0.0.1:9", true);
        assert_eq!(src.sup.held_candidates(ids.0), 1, "held for the allocation");
        let ready = rx.recv().await.expect("a ready");
        dial(&mem, ids, ready, TOKEN, ice);
        // The member's own candidate is not passed on: the held one permits it.
        assert!(candidate_of(&mut mem, ids.0).await.is_some());
        assert!(
            matches!(answer_of(&mem, ids.0).await, SourceMsg::Hello { .. }),
            "permitted by the held address"
        );
        mem.sup.close_stream(ids.0, "test");
        src.sup.close_stream(ids.0, "test");
    }

    /// A grant is registered before its endpoint is stood up, so the
    /// server's close ends a setup still in flight: no endpoint is left to
    /// wait out the grant, and no ready follows.
    #[tokio::test]
    async fn a_close_while_the_endpoint_is_stood_up_ends_it() {
        let src = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut g = grant(sid, HiveStreamPath::Direct);
        g.ice_servers = silent_stun(&silent);
        let grant_id = g.grant_id;
        let (tx, mut rx) = mpsc::channel(4);
        src.sup.take_grant(g, true, tx);
        assert!(
            src.sup.holds_stream(grant_id),
            "registered before its endpoint is up"
        );
        // Into the STUN round, then the server's close.
        tokio::time::sleep(Duration::from_millis(200)).await;
        src.sup.close_stream(grant_id, "test");
        assert!(!src.sup.holds_stream(grant_id));
        if let Ok(Some(m)) = tokio::time::timeout(STUN_TIMEOUT * 2, rx.recv()).await {
            panic!("a ready for a closed grant: {m:?}");
        }
    }

    /// Two DERP muxes, a source's and a member's, wired back to back as the
    /// server's `/derp` relay joins two devices: what one sends toward the
    /// other's key arrives at the other stamped with the sender's.
    fn derp_pair() -> (DerpTunnelHandle, DerpTunnelHandle) {
        use tunnel_core::transport::derp::{DerpMux, DerpPubKey, OutboundFrame, pubkey_hex};
        fn pump(mut out: mpsc::Receiver<OutboundFrame>, from: DerpPubKey, to: Arc<DerpMux>) {
            tokio::spawn(async move {
                while let Some((_, frame)) = out.recv().await {
                    if frame.len() >= 32 && frame[..32] == to.self_pubkey() {
                        let mut stamped = from.to_vec();
                        stamped.extend_from_slice(&frame[32..]);
                        to.deliver(&stamped);
                    }
                }
            });
        }
        let (ka, kb) = ([0xA1u8; 32], [0xB2u8; 32]);
        let (a, a_out) = DerpMux::new(ka);
        let (b, b_out) = DerpMux::new(kb);
        pump(a_out, ka, Arc::clone(&b));
        pump(b_out, kb, Arc::clone(&a));
        (
            DerpTunnelHandle {
                mux: a,
                self_pubkey_hex: pubkey_hex(&ka),
            },
            DerpTunnelHandle {
                mux: b,
                self_pubkey_hex: pubkey_hex(&kb),
            },
        )
    }

    /// The derp rung, end to end: the source serves over its own `/derp`
    /// connection on the stream's own route toward the member's key, `ready`
    /// names its key and no address, and the member dials that key.
    #[tokio::test]
    async fn a_member_follows_its_source_over_derp() {
        let (on_src, on_mem) = derp_pair();
        let src = rig(true, 4);
        let mem = member_rig();
        src.sup.use_derp_for_tests(Some(on_src.clone()));
        mem.sup.use_derp_for_tests(Some(on_mem.clone()));
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        let tip = src.store.chain_tip(&sid.to_hex()).await.unwrap().unwrap();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let mut g = grant(sid, HiveStreamPath::Derp);
        g.member_derp_pubkey = Some(on_mem.self_pubkey_hex.clone());
        let ids = (g.grant_id, g.session_id, g.path);
        let ready = ready_of(&src, g, true).await;
        let ClientMsg::HiveReplicaReady { derp_pubkey, .. } = &ready else {
            panic!("not a ready: {ready:?}");
        };
        assert_eq!(
            derp_pubkey.as_deref(),
            Some(on_src.self_pubkey_hex.as_str()),
            "the source's own key"
        );
        dial(&mem, ids, ready, TOKEN, Vec::new());
        assert_eq!(
            answer_of(&mem, ids.0).await,
            SourceMsg::Hello {
                v: wire::STREAM_V,
                tip: Mark {
                    seq: tip.seq,
                    hash: hex::encode(tip.hash),
                },
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            },
            "over DERP"
        );
        mem.sup.close_stream(ids.0, "test");
        src.sup.close_stream(ids.0, "test");
    }

    /// Streams between one pair carry at once on DERP, each on its own
    /// route, and leave the pair's tunnel route alone: the tunnel's route is
    /// one per peer, so a stream on it would have taken a `quic-derp-v1`
    /// tunnel's, and the second stream the first's.
    #[tokio::test]
    async fn streams_between_one_pair_carry_at_once_beside_its_tunnel() {
        let (on_src, on_mem) = derp_pair();
        let src = rig(true, 4);
        let mem = member_rig();
        src.sup.use_derp_for_tests(Some(on_src.clone()));
        mem.sup.use_derp_for_tests(Some(on_mem.clone()));
        // What a `quic-derp-v1` tunnel between the same two devices holds.
        let tunnel_at_src = on_src.mux.tunnel_conn_for(on_mem.mux.self_pubkey());
        let tunnel_at_mem = on_mem.mux.tunnel_conn_for(on_src.mux.self_pubkey());
        let (s1, s2) = (ObjectId::new(), ObjectId::new());
        note(&src, s1, &["one"]);
        note(&src, s2, &["two"]);
        mem.store.join(&s1.to_hex(), "owner", 1).await.unwrap();
        mem.store.join(&s2.to_hex(), "owner", 1).await.unwrap();

        let mut ids = Vec::new();
        for sid in [s1, s2] {
            let mut g = grant(sid, HiveStreamPath::Derp);
            g.member_derp_pubkey = Some(on_mem.self_pubkey_hex.clone());
            ids.push(served_on(&src, &mem, g, TOKEN).await);
        }
        for (n, grant_id) in ids.iter().enumerate() {
            assert!(
                matches!(answer_of(&mem, *grant_id).await, SourceMsg::Hello { .. }),
                "stream {n} answered"
            );
        }
        tunnel_at_src
            .send_to(&[0xC3, 0, 0, 0, 1], tunnel_at_src.synth_peer())
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), tunnel_at_mem.recv_from(&mut buf))
                .await
                .expect("the tunnel's packet arrives on its own route")
                .unwrap();
        assert_eq!(&buf[..n], &[0xC3, 0, 0, 0, 1]);
        for grant_id in ids {
            mem.sup.close_stream(grant_id, "test");
            src.sup.close_stream(grant_id, "test");
        }
    }

    /// A derp grant or dial this device cannot carry is refused in words: no
    /// live DERP connection, a grant naming no member key, a dial naming no
    /// source key.
    #[tokio::test]
    async fn a_derp_grant_or_dial_this_device_cannot_carry_is_refused() {
        let src = rig(true, 4);
        let mut mem = member_rig();
        src.sup.use_derp_for_tests(None);
        mem.sup.use_derp_for_tests(None);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let mut g = grant(sid, HiveStreamPath::Derp);
        g.member_derp_pubkey = Some("1f".repeat(32));
        assert_eq!(
            refusal_of(ready_of(&src, g, true).await),
            Some(HiveStreamRefusal::PathUnavailable),
            "no live DERP connection"
        );
        let (on_src, on_mem) = derp_pair();
        src.sup.use_derp_for_tests(Some(on_src));
        assert_eq!(
            refusal_of(ready_of(&src, grant(sid, HiveStreamPath::Derp), true).await),
            Some(HiveStreamRefusal::PathUnavailable),
            "a grant that names no member key"
        );

        let derp_dial = |key: Option<String>| Dial {
            grant_id: ObjectId::new(),
            session_id: sid,
            fence: 1,
            source_id: ObjectId::new(),
            path: Some(HiveStreamPath::Derp),
            token: TOKEN.into(),
            cert_fingerprint: "00".repeat(32),
            addrs: Vec::new(),
            ice_servers: Vec::new(),
            derp_pubkey: key,
            ttl_secs: 30,
        };
        let d = derp_dial(Some("2e".repeat(32)));
        let grant_id = d.grant_id;
        mem.sup.follow_dial(d, true);
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("no_derp"),
            "no live DERP connection"
        );
        mem.sup.use_derp_for_tests(Some(on_mem));
        let d = derp_dial(None);
        let grant_id = d.grant_id;
        mem.sup.follow_dial(d, true);
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("no_derp_key"),
            "a dial that names no source key"
        );
    }

    /// P2d-3 — a copy whose tail is of the current fence is never set aside,
    /// whatever the source says: told it diverged (at genesis, no checkpoint
    /// shared), the member ends the stream with its copy as it was, and the
    /// source hears why.
    #[tokio::test]
    async fn a_tail_of_the_current_fence_is_never_set_aside() {
        let mut src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        note(&mem, sid, &["something else"]);
        let before = tip(&mem, sid).await;
        assert!(before.is_some());

        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("diverged_at_floor")
        );
        assert_eq!(tip(&mem, sid).await, before, "nothing of the copy moved");
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("member:diverged_at_floor"),
            "the source hears why"
        );
    }

    /// P2d-3 — a copy whose tail a promotion cut off (an older fence's
    /// events past the newest checkpoint both hold) sets that tail aside and
    /// takes the new primary's events in its place.
    #[tokio::test]
    async fn a_tail_a_promotion_cut_off_is_set_aside_for_the_sources() {
        let src = rig(true, 4);
        let mem = member_rig();
        let sid = ObjectId::new();
        let s = sid.to_hex();
        note(&src, sid, &["shared"]);
        checkpoint(&src, sid, &[], true).await;
        mem.store.join(&s, "owner", 1).await.unwrap();
        for env in src.store.page(&s, 0, 10).await.unwrap() {
            mem.store.apply(env).await.unwrap();
        }
        // The old primary's last word, which reached the member and never
        // the new primary; then the promotion: the new primary writes at
        // fence 2, and the member's floor is raised to it.
        put(&mem, sid, 1, said("the old primary's last word"));
        put(&src, sid, 2, said("the new primary's first"));
        put(&src, sid, 2, said("and its second"));
        mem.store.raise_floor(&s, 2).await.unwrap();
        let common = src.store.page(&s, 1, 1).await.unwrap().remove(0);

        let grant_id = served(&src, &mem, sid, TOKEN).await;
        let end = tip(&src, sid).await.unwrap();
        assert_eq!(tip_at(&mem, sid, end.seq).await, end);
        assert_eq!(
            mem.store.page(&s, 0, 10).await.unwrap(),
            src.store.page(&s, 0, 10).await.unwrap(),
            "the copy is the new primary's chain, event for event"
        );
        // Read once the copy followed: a stream that ended takes its answer
        // with it.
        assert_eq!(
            answer_of(&mem, grant_id).await,
            SourceMsg::Diverged {
                at: Mark {
                    seq: 2,
                    hash: hex::encode(common.hash()),
                },
                tip: Some(Mark {
                    seq: end.seq,
                    hash: hex::encode(end.hash),
                }),
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            },
            "past the newest checkpoint both hold"
        );
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");
    }

    /// A member that presents another token is turned away before any
    /// hello: the source says `auth_failed`, and the member hears nothing.
    #[tokio::test]
    async fn a_wrong_token_is_turned_away_before_any_hello() {
        let mut src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let grant_id = served(&src, &mem, sid, "not-the-token-the-source-holds").await;
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("auth_failed"),
            "the source turns the connection away"
        );
        let theirs = close_of(&mut mem, grant_id).await;
        assert!(mem.sup.stream_answer(grant_id).is_none(), "no answer");
        assert!(
            theirs.as_deref().is_some_and(|t| !t.is_empty()),
            "the member says why: {theirs:?}"
        );
    }

    /// A grant the source cannot serve is refused in its own word, and no
    /// endpoint is stood up for it.
    #[tokio::test]
    async fn a_grant_the_source_cannot_serve_is_refused_in_words() {
        let src = rig(true, 4);
        src.sup.use_derp_for_tests(None);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        let mut derp = grant(sid, HiveStreamPath::Derp);
        derp.member_derp_pubkey = Some("1f".repeat(32));
        assert_eq!(
            refusal_of(ready_of(&src, derp, true).await),
            Some(HiveStreamRefusal::PathUnavailable),
            "a derp grant on a device with no DERP connection"
        );
        let unnamed = Grant {
            path: None,
            ..grant(sid, HiveStreamPath::Direct)
        };
        assert_eq!(
            refusal_of(ready_of(&src, unnamed, true).await),
            Some(HiveStreamRefusal::PathUnavailable),
            "a rung this build cannot name"
        );
        assert_eq!(
            refusal_of(ready_of(&src, grant(sid, HiveStreamPath::Relay), true).await),
            Some(HiveStreamRefusal::PathUnavailable),
            "a relay grant that carries no TURN server"
        );
        assert_eq!(
            refusal_of(ready_of(&src, grant(ObjectId::new(), HiveStreamPath::Direct), true).await),
            Some(HiveStreamRefusal::NotHeld),
            "a session it holds nothing of"
        );
        assert_eq!(
            refusal_of(ready_of(&src, grant(sid, HiveStreamPath::Direct), false).await),
            Some(HiveStreamRefusal::Other),
            "a secondary org's connection"
        );
        assert_eq!(src.sup.serving(), 0, "nothing stood up");
    }

    /// A source at its limit refuses the next grant `busy`, its endpoints
    /// still being stood up counted, and serves again once one ends.
    #[tokio::test]
    async fn a_source_at_its_limit_refuses_busy() {
        let src = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut held = Vec::new();
        for _ in 0..stream_limits::MAX_PER_SOURCE {
            let mut g = grant(sid, HiveStreamPath::Direct);
            g.ice_servers = silent_stun(&silent);
            held.push(g.grant_id);
            let (tx, _rx) = mpsc::channel(4);
            src.sup.take_grant(g, true, tx);
        }
        assert_eq!(src.sup.serving(), stream_limits::MAX_PER_SOURCE);
        assert_eq!(
            refusal_of(ready_of(&src, grant(sid, HiveStreamPath::Direct), true).await),
            Some(HiveStreamRefusal::Busy),
            "one past the limit, while all are still being stood up"
        );
        src.sup.close_stream(held[0], "test");
        let g = grant(sid, HiveStreamPath::Direct);
        held.push(g.grant_id);
        assert_eq!(
            refusal_of(ready_of(&src, g, true).await),
            None,
            "a slot freed is served again"
        );
        for grant_id in held {
            src.sup.close_stream(grant_id, "test");
        }
        assert_eq!(src.sup.serving(), 0);
    }

    /// A grant or a dial this device holds already is not taken twice: a
    /// replay answers nothing, and the stream it started is left alone.
    #[tokio::test]
    async fn a_grant_or_dial_held_already_is_not_taken_twice() {
        let mut src = rig(true, 4);
        let mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let g = grant(sid, HiveStreamPath::Direct);
        let replay = Grant {
            grant_id: g.grant_id,
            ..grant(sid, HiveStreamPath::Direct)
        };
        let ids = (g.grant_id, g.session_id, g.path);
        let ready = ready_of(&src, g, true).await;
        let (tx, mut rx) = mpsc::channel(4);
        src.sup.take_grant(replay, true, tx);
        assert!(
            rx.recv().await.is_none(),
            "a replayed grant answers nothing"
        );

        dial(&mem, ids, ready.clone(), TOKEN, Vec::new());
        dial(&mem, ids, ready, TOKEN, Vec::new());
        assert!(
            matches!(answer_of(&mem, ids.0).await, SourceMsg::Hello { .. }),
            "the first is followed through"
        );
        // The follow the server's close ends is the one connected: had a
        // replay taken its place, the first would hold its connection on.
        mem.sup.close_stream(ids.0, "test");
        assert_eq!(
            close_of(&mut src, ids.0).await.as_deref(),
            Some("closed"),
            "the one connection let go"
        );
    }

    /// A member follows at most its limit of streams at once, each session
    /// followed and its renewal beside it (P2d-4); a dial past it is closed
    /// `busy`, and nothing is dialed.
    #[tokio::test]
    async fn a_member_follows_at_most_its_limit() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        // A socket that takes the member's packets and answers none.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let to_silence = || Dial {
            grant_id: ObjectId::new(),
            session_id: sid,
            fence: 1,
            source_id: ObjectId::new(),
            path: Some(HiveStreamPath::Direct),
            token: TOKEN.into(),
            cert_fingerprint: "00".repeat(32),
            addrs: vec![silent.local_addr().unwrap().to_string()],
            ice_servers: Vec::new(),
            derp_pubkey: None,
            ttl_secs: 30,
        };
        let mut following = Vec::new();
        // As many sessions as the follow takes, each with its renewal
        // beside it: counted here, not read from the limit under test.
        for _ in 0..2 * MAX_FOLLOWING {
            let d = to_silence();
            following.push(d.grant_id);
            mem.sup.follow_dial(d, true);
        }
        assert!(
            following.iter().all(|g| mem.sup.holds_stream(*g)),
            "every session followed with its renewal beside it"
        );
        let past = to_silence();
        let grant_id = past.grant_id;
        mem.sup.follow_dial(past, true);
        assert!(
            !mem.sup.holds_stream(grant_id),
            "one past the limit is not followed"
        );
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("busy"),
            "and is closed in its word"
        );
        for grant_id in following {
            mem.sup.close_stream(grant_id, "test");
        }
    }

    /// Every side ends with its grant at the latest, whatever the other
    /// does: an endpoint nobody dials, and a member whose source never
    /// answers.
    #[tokio::test]
    async fn every_side_ends_with_its_grant() {
        let mut src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let mut g = grant(sid, HiveStreamPath::Direct);
        g.ttl_secs = 1;
        let grant_id = g.grant_id;
        assert_eq!(refusal_of(ready_of(&src, g, true).await), None);
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("expired"),
            "the endpoint nobody dialed"
        );
        assert!(!src.sup.holds_stream(grant_id));

        // A socket that takes the member's packets and answers none.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let grant_id = ObjectId::new();
        mem.sup.follow_dial(
            Dial {
                grant_id,
                session_id: sid,
                fence: 1,
                source_id: ObjectId::new(),
                path: Some(HiveStreamPath::Direct),
                token: TOKEN.into(),
                cert_fingerprint: "00".repeat(32),
                addrs: vec![silent.local_addr().unwrap().to_string()],
                ice_servers: Vec::new(),
                derp_pubkey: None,
                ttl_secs: 1,
            },
            true,
        );
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("expired"),
            "the member its source never answered"
        );
        assert!(!mem.sup.holds_stream(grant_id));
    }

    /// A dial for a session this device never joined is closed at once,
    /// and nothing is dialed.
    #[tokio::test]
    async fn a_dial_for_a_session_not_joined_is_closed_unasked() {
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("not_a_member"),
            "a session never joined"
        );
        src.sup.close_stream(grant_id, "test");
    }

    /// A dial this device does not follow is closed at once, in its own
    /// word, and nothing is dialed: one on a secondary org's connection,
    /// and one on a rung this build cannot name.
    #[tokio::test]
    async fn a_dial_this_device_does_not_follow_is_closed_unasked() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let dial = |path| Dial {
            grant_id: ObjectId::new(),
            session_id: sid,
            fence: 1,
            source_id: ObjectId::new(),
            path,
            token: TOKEN.into(),
            cert_fingerprint: "00".repeat(32),
            addrs: vec!["127.0.0.1:9".into()],
            ice_servers: Vec::new(),
            derp_pubkey: None,
            ttl_secs: 30,
        };
        for (d, primary, word) in [
            (dial(Some(HiveStreamPath::Direct)), false, "secondary_org"),
            (dial(None), true, "path_unavailable"),
        ] {
            let grant_id = d.grant_id;
            mem.sup.follow_dial(d, primary);
            assert!(!mem.sup.holds_stream(grant_id), "{word}: nothing followed");
            assert_eq!(
                close_of(&mut mem, grant_id).await.as_deref(),
                Some(word),
                "{word}: closed in its word"
            );
        }
    }

    /// A relay dial that carries no TURN server is closed `no_turn`: the
    /// member has nothing to allocate on.
    #[tokio::test]
    async fn a_relay_dial_without_a_turn_server_is_closed() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let grant_id = ObjectId::new();
        mem.sup.follow_dial(
            Dial {
                grant_id,
                session_id: sid,
                fence: 1,
                source_id: ObjectId::new(),
                path: Some(HiveStreamPath::Relay),
                token: TOKEN.into(),
                cert_fingerprint: "00".repeat(32),
                addrs: vec!["198.51.100.4:49152".into()],
                ice_servers: Vec::new(),
                derp_pubkey: None,
                ttl_secs: 30,
            },
            true,
        );
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("no_turn"),
            "nothing to allocate on"
        );
    }

    /// A dial that names no address a source could hold is closed
    /// `no_address`, before anything is dialed. (The two here are ones QUIC
    /// itself refuses, so a member that tried them would end `unreachable`
    /// at once, and send nothing either way.)
    #[tokio::test]
    async fn a_dial_to_nowhere_a_source_could_be_is_closed() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let grant_id = ObjectId::new();
        mem.sup.follow_dial(
            Dial {
                grant_id,
                session_id: sid,
                fence: 1,
                source_id: ObjectId::new(),
                path: Some(HiveStreamPath::Direct),
                token: TOKEN.into(),
                cert_fingerprint: "00".repeat(32),
                addrs: vec!["0.0.0.0:41000".into(), "192.168.1.20:0".into()],
                ice_servers: Vec::new(),
                derp_pubkey: None,
                ttl_secs: 30,
            },
            true,
        );
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("no_address"),
            "nowhere a source could be"
        );
    }

    /// A candidate no member could hold is never permitted, and one for no
    /// relay stream of this device's is dropped.
    #[tokio::test]
    async fn only_a_candidate_a_member_could_hold_is_held() {
        let src = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        // A relay grant whose allocation never lands: its TURN server is
        // silent, so what arrives meanwhile is held, or is not.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut g = grant(sid, HiveStreamPath::Relay);
        g.ice_servers = vec![IceServer {
            urls: vec![format!(
                "turn:{}?transport=udp",
                silent.local_addr().unwrap()
            )],
            username: Some(TURN_USER.into()),
            credential: Some(TURN_PASS.into()),
        }];
        let grant_id = g.grant_id;
        let (tx, _rx) = mpsc::channel(4);
        src.sup.take_grant(g, true, tx);
        for nowhere in [
            "224.0.0.251:5353",
            "255.255.255.255:9",
            "0.0.0.0:9",
            "relay.example:3478",
        ] {
            src.sup.take_candidate(grant_id, nowhere, true);
        }
        assert_eq!(
            src.sup.held_candidates(grant_id),
            0,
            "nothing a member could hold"
        );
        src.sup.take_candidate(grant_id, "198.51.100.4:3478", false);
        assert_eq!(
            src.sup.held_candidates(grant_id),
            0,
            "nor on a secondary org's connection"
        );
        src.sup.take_candidate(grant_id, "198.51.100.4:3478", true);
        assert_eq!(src.sup.held_candidates(grant_id), 1);
        src.sup.close_stream(grant_id, "test");
    }

    /// A hello that is not the grant's, for another session or under
    /// another fence, is refused in words although its token was right:
    /// the token proves the grant, and the hello must be for it. The
    /// refusal reaches the member before the source lets the connection go.
    #[tokio::test]
    async fn a_hello_that_is_not_the_grants_is_refused() {
        let mut src = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        for (session, fence, word) in [
            (ObjectId::new().to_hex(), 1, "wrong_session"),
            (sid.to_hex(), 2, "wrong_fence"),
        ] {
            let g = grant(sid, HiveStreamPath::Direct);
            let grant_id = g.grant_id;
            let (_peer, conn, mut send, mut recv) =
                dial_by_hand(ready_of(&src, g, true).await).await;
            let hello = MemberMsg::Hello {
                v: wire::STREAM_V,
                session,
                fence,
                tip: Mark::genesis(),
                floor: 1,
                checkpoints: Vec::new(),
            };
            write_frame(&mut send, &hello).await.unwrap();
            let answer: SourceMsg = tokio::time::timeout(HELLO_TIMEOUT, read_frame(&mut recv))
                .await
                .expect("an answer in time")
                .expect("the refusal arrives whole");
            assert_eq!(
                answer,
                SourceMsg::Refused {
                    reason: word.into()
                },
                "{word}"
            );
            // The member, the last to receive, lets go, and the source
            // then ends, saying it refused.
            conn.close(0u32.into(), b"done");
            assert_eq!(
                close_of(&mut src, grant_id).await.as_deref(),
                Some("refused"),
                "{word}: the source says it refused"
            );
        }
    }

    /// A frame that announces more than the limit is refused on its
    /// header: the source does not wait for a body it would not read, and
    /// says so.
    #[tokio::test]
    async fn a_frame_past_the_limit_is_refused_before_it_is_read() {
        let mut src = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        let g = grant(sid, HiveStreamPath::Direct);
        let grant_id = g.grant_id;
        let (_peer, conn, mut send, _recv) = dial_by_hand(ready_of(&src, g, true).await).await;
        let past = u32::try_from(wire::MAX_FRAME + 1).unwrap();
        send.write_all(&past.to_le_bytes()).await.unwrap();
        // The header alone: a reader that took it would wait for the body,
        // and end `no_hello` when the stream finishes short of it.
        send.finish().unwrap();
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("bad_frame"),
            "refused on the header"
        );
        conn.close(0u32.into(), b"done");
    }

    fn said(text: &str) -> TranscriptEvent {
        TranscriptEvent::Note { text: text.into() }
    }

    /// `event` appended to `sid` in `r`'s store at `fence`, as the device
    /// that runs the session writes it.
    fn put(r: &Rig, sid: ObjectId, fence: u64, event: TranscriptEvent) {
        r.store.append(&sid.to_hex(), fence, event);
    }

    /// A checkpoint of `sid` in `r`'s store at fence 1, a file for each of
    /// `blobs`, the blobs kept BEFORE the checkpoint as a device keeps them
    /// (`keep`), or none of them. The blobs' names, in order.
    async fn checkpoint(r: &Rig, sid: ObjectId, blobs: &[&[u8]], keep: bool) -> Vec<Digest> {
        let mut files = Vec::new();
        for (i, bytes) in blobs.iter().enumerate() {
            let (snap, _) = snapshot_whole(&format!("f{i}"), 0o600, bytes, None);
            if keep {
                r.store
                    .put_blob(&sid.to_hex(), bytes.to_vec())
                    .await
                    .unwrap();
            }
            files.push(snap);
        }
        let names = files.iter().map(|f| f.chunks[0].hash).collect();
        let cp = Checkpoint {
            n: 1,
            turn: 1,
            files,
            skipped: Vec::new(),
            workspace: None,
        };
        put(r, sid, 1, TranscriptEvent::Checkpoint(cp));
        names
    }

    async fn tip(r: &Rig, sid: ObjectId) -> Option<ChainTip> {
        r.store.chain_tip(&sid.to_hex()).await.unwrap()
    }

    /// The member's tip of `sid` once its copy reaches `seq`, within 15 s.
    async fn tip_at(mem: &Rig, sid: ObjectId, seq: u64) -> ChainTip {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(t) = tip(mem, sid).await
                && t.seq >= seq
            {
                return t;
            }
            assert!(
                Instant::now() < deadline,
                "the member's copy never reached seq {seq}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The hash in the `rc:hive.replica.tip` the rig's device, a member,
    /// sends for `sid` at `seq`, or `None` within 15 s.
    async fn tip_report_of(r: &mut Rig, sid: ObjectId, seq: u64) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let msg = tokio::time::timeout_at(deadline, r.reports.recv())
                .await
                .ok()?
                .expect("the reporter is open");
            if let ClientMsg::HiveReplicaTip {
                session_id,
                seq: at,
                hash,
                ..
            } = msg
                && session_id == sid
                && at == seq
            {
                return Some(hash);
            }
        }
    }

    /// The hello of a member that holds nothing of `sid` yet.
    fn empty_hello(sid: ObjectId) -> MemberMsg {
        MemberMsg::Hello {
            v: wire::STREAM_V,
            session: sid.to_hex(),
            fence: 1,
            tip: Mark::genesis(),
            floor: 1,
            checkpoints: Vec::new(),
        }
    }

    /// The `events` frames a source sends until it falls quiet for a
    /// second, each read whole, as the envelopes they carry. Quiet means no
    /// frame began, so the stream is whole for the next call.
    async fn frames_until_quiet(recv: &mut RecvStream, sid: ObjectId) -> Vec<Vec<EventEnvelope>> {
        let mut frames = Vec::new();
        loop {
            let Ok(frame) =
                tokio::time::timeout(Duration::from_secs(1), read_frame::<SourceMsg>(recv)).await
            else {
                return frames;
            };
            let SourceMsg::Events { events } = frame.unwrap() else {
                panic!("not an events frame");
            };
            let mut envs = Vec::new();
            for meta in events {
                let mut json = vec![0u8; meta.len as usize];
                recv.read_exact(&mut json).await.unwrap();
                envs.push(meta.envelope(&sid.to_hex(), String::from_utf8(json).unwrap()));
            }
            frames.push(envs);
        }
    }

    /// A source by hand, so a test can send what a source of this build
    /// never would: a QUIC server on loopback the member is told to dial for
    /// `sid`, its connection taken, its token checked and its hello read.
    async fn source_by_hand(
        mem: &Rig,
        sid: ObjectId,
    ) -> (QuicPeer, ObjectId, QuicConnection, SendStream, RecvStream) {
        let (peer, fingerprint) = QuicPeer::server("127.0.0.1:0".parse().unwrap()).unwrap();
        let at = peer.local_addr().unwrap();
        let grant_id = ObjectId::new();
        mem.sup.follow_dial(
            Dial {
                grant_id,
                session_id: sid,
                fence: 1,
                source_id: ObjectId::new(),
                path: Some(HiveStreamPath::Direct),
                token: TOKEN.into(),
                cert_fingerprint: fingerprint,
                addrs: vec![at.to_string()],
                ice_servers: Vec::new(),
                derp_pubkey: None,
                ttl_secs: 30,
            },
            true,
        );
        let conn = tokio::time::timeout(Duration::from_secs(15), peer.accept())
            .await
            .expect("the member dials")
            .expect("a connection comes")
            .expect("and it connects");
        quic::server_authenticate(&conn, TOKEN).await.unwrap();
        let (send, mut recv) = conn.accept_bi().await.unwrap();
        let hello: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert!(matches!(hello, MemberMsg::Hello { .. }), "{hello:?}");
        (peer, grant_id, conn, send, recv)
    }

    /// `envs` as one `events` frame, written by hand.
    async fn send_by_hand(send: &mut SendStream, envs: &[EventEnvelope]) {
        let listing = SourceMsg::Events {
            events: envs.iter().map(EventMeta::of).collect(),
        };
        write_frame(send, &listing).await.unwrap();
        for env in envs {
            send.write_all(env.event_json.as_bytes()).await.unwrap();
        }
    }

    /// P2d-3 — a member that holds nothing takes the source's whole chain,
    /// more than one frame of it, then each event the source appends, and
    /// says where its copy ends.
    #[tokio::test]
    async fn a_member_catches_up_then_follows_the_live_tail() {
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        let texts: Vec<String> = (0..wire::MAX_BATCH + 20)
            .map(|i| format!("note {i}"))
            .collect();
        note(
            &src,
            sid,
            &texts.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let grant_id = served(&src, &mem, sid, TOKEN).await;
        let caught = tip(&src, sid).await.unwrap();
        assert_eq!(
            tip_at(&mem, sid, caught.seq).await,
            caught,
            "the source's chain, every event of it"
        );
        put(&src, sid, 1, said("after the catch-up"));
        let live = tip(&src, sid).await.unwrap();
        assert_eq!(
            tip_at(&mem, sid, live.seq).await,
            live,
            "and what the source appends after"
        );
        assert_eq!(
            tip_report_of(&mut mem, sid, live.seq).await,
            Some(hex::encode(live.hash)),
            "the member says where its copy ends"
        );
        assert!(mem.sup.holds_stream(grant_id), "and goes on following");
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");
    }

    /// P2d-3 — the blobs a checkpoint names reach the member before the
    /// checkpoint, and only those it lacked are sent: one it held already
    /// is never asked for. An empty file's blob is one like any other.
    #[tokio::test]
    async fn a_checkpoints_blobs_are_asked_for_and_kept_before_it() {
        let src = rig(true, 4);
        let mem = member_rig();
        let sid = ObjectId::new();
        let s = sid.to_hex();
        note(&src, sid, &["before"]);
        let blobs: [&[u8]; 4] = [b"one\n", b"two\n", b"", b"three\n"];
        let names = checkpoint(&src, sid, &blobs, true).await;
        note(&src, sid, &["after"]);
        mem.store.join(&s, "owner", 1).await.unwrap();
        mem.store.put_blob(&s, blobs[1].to_vec()).await.unwrap();

        let grant_id = served(&src, &mem, sid, TOKEN).await;
        let end = tip(&src, sid).await.unwrap();
        assert_eq!(tip_at(&mem, sid, end.seq).await, end);
        for (name, bytes) in names.iter().zip(blobs) {
            assert_eq!(
                mem.store.get_blob(&s, name.0).await.unwrap().as_deref(),
                Some(bytes),
                "{name}"
            );
        }
        assert_eq!(
            src.sup.stream_blobs(grant_id),
            Some(3),
            "only what the member lacked was sent"
        );
        assert_eq!(mem.sup.stream_blobs(grant_id), Some(3), "and each kept");
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");
    }

    /// P2d-3 — a blob the source does not hold ends the stream before the
    /// checkpoint naming it: the copy stops short of the checkpoint rather
    /// than hold it without its files, and the member hears why.
    #[tokio::test]
    async fn a_checkpoint_whose_blob_never_comes_is_never_applied() {
        let mut src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["before"]);
        checkpoint(&src, sid, &[b"never kept".as_slice()], false).await;
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("blob_missing")
        );
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("source:blob_missing"),
            "the member hears why"
        );
        assert_eq!(
            tip(&mem, sid).await.map(|t| t.seq),
            Some(1),
            "the copy stops before the checkpoint"
        );
    }

    /// P2d-3 — two streams of one session reach a member at once while a
    /// renewal comes up beside the stream it replaces: whichever carries an
    /// event first applies it, the other finds it held, and neither ends.
    #[tokio::test]
    async fn two_streams_of_one_session_carry_it_at_once() {
        let src = rig(true, 4);
        let mem = member_rig();
        let sid = ObjectId::new();
        let texts: Vec<String> = (0..200).map(|i| format!("note {i}")).collect();
        note(
            &src,
            sid,
            &texts.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();

        let first = served(&src, &mem, sid, TOKEN).await;
        let second = served(&src, &mem, sid, TOKEN).await;
        let end = tip(&src, sid).await.unwrap();
        assert_eq!(tip_at(&mem, sid, end.seq).await, end);
        put(&src, sid, 1, said("live"));
        let live = tip(&src, sid).await.unwrap();
        assert_eq!(tip_at(&mem, sid, live.seq).await, live);
        // Long enough for the slower of the two to carry it as well.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for grant_id in [first, second] {
            assert!(mem.sup.holds_stream(grant_id), "neither ended");
            mem.sup.close_stream(grant_id, "test");
            src.sup.close_stream(grant_id, "test");
        }
    }

    /// P2d-3 — a source sends no further past the member's last ack than
    /// its window, and an ack lets it go on from where it stopped.
    #[tokio::test]
    async fn a_source_goes_no_further_than_its_window_past_the_last_ack() {
        let src = rig(true, 4);
        let sid = ObjectId::new();
        // Each over a frame's bytes, so each comes alone.
        let big = "x".repeat(wire::BATCH_BYTES);
        note(&src, sid, &[big.as_str(); 8]);
        let g = grant(sid, HiveStreamPath::Direct);
        let (_peer, conn, mut send, mut recv) = dial_by_hand(ready_of(&src, g, true).await).await;
        write_frame(&mut send, &empty_hello(sid)).await.unwrap();
        let answer: SourceMsg = read_frame(&mut recv).await.unwrap();
        assert!(matches!(answer, SourceMsg::Hello { .. }), "{answer:?}");

        let first = frames_until_quiet(&mut recv, sid).await;
        let sent: u64 = first
            .iter()
            .flatten()
            .map(|e| e.event_json.len() as u64)
            .sum();
        assert!(
            (AHEAD_BYTES..AHEAD_BYTES + big.len() as u64 + 64).contains(&sent),
            "the window and one frame past it at most, not {sent}"
        );
        let stopped = first.last().unwrap().last().unwrap().seq;
        assert!(stopped < 8, "not every event");
        // An ack of the second frame frees what it covers.
        let acked = first[1].last().unwrap();
        write_frame(&mut send, &wire::ack_of(&acked.tip()))
            .await
            .unwrap();
        let more = frames_until_quiet(&mut recv, sid).await;
        assert_eq!(
            more.first().map(|f| f[0].seq),
            Some(stopped + 1),
            "an ack lets the source go on, from where it stopped"
        );
        conn.close(0u32.into(), b"done");
    }

    /// P2d-3 — an ack must name what was sent, by its hash: one that does
    /// not ends the stream, in the source's word.
    #[tokio::test]
    async fn an_ack_for_what_was_never_sent_ends_the_stream() {
        let mut src = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        let g = grant(sid, HiveStreamPath::Direct);
        let grant_id = g.grant_id;
        let (_peer, conn, mut send, mut recv) = dial_by_hand(ready_of(&src, g, true).await).await;
        write_frame(&mut send, &empty_hello(sid)).await.unwrap();
        let _: SourceMsg = read_frame(&mut recv).await.unwrap();
        let frames = frames_until_quiet(&mut recv, sid).await;
        let last = frames.last().unwrap().last().unwrap();
        let forged = MemberMsg::Ack {
            seq: last.seq,
            hash: "ab".repeat(32),
        };
        write_frame(&mut send, &forged).await.unwrap();
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("bad_ack")
        );
        conn.close(0u32.into(), b"done");
    }

    /// P2d-3 — an event that does not follow the member's tip is refused by
    /// its store, and nothing of it kept: the member ends the stream in the
    /// store's word.
    #[tokio::test]
    async fn an_event_off_the_chain_is_refused_and_nothing_of_it_kept() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let (_peer, grant_id, _conn, mut send, _recv) = source_by_hand(&mem, sid).await;
        let hello = SourceMsg::Hello {
            v: wire::STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: false,
            stand_ins: Vec::new(),
        };
        write_frame(&mut send, &hello).await.unwrap();
        let mut env = EventEnvelope::next(&sid.to_hex(), None, 1, 0, &said("forged"));
        env.prev_hash = [7; 32];
        send_by_hand(&mut send, &[env]).await;
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("broken_chain")
        );
        assert_eq!(tip(&mem, sid).await, None, "nothing of it kept");
    }

    /// P2e-5b — a member that joins after a move holds a floor above every
    /// event the old primary wrote. Joined as before P2e-5b it refuses the
    /// first of them; joined with where that fence ended, it takes them over
    /// the stream up to there, then the new primary's.
    #[tokio::test]
    async fn a_member_joined_after_a_move_takes_the_history_below_its_floor() {
        let src = rig(true, 4);
        let sid = ObjectId::new();
        let s = sid.to_hex();
        // The old primary's history, which the new one held before the move,
        // then the new primary's own, at fence 2.
        put(&src, sid, 1, said("one"));
        put(&src, sid, 1, said("two"));
        let ended = tip_at(&src, sid, 2).await;
        put(&src, sid, 2, said("three"));
        let last = tip_at(&src, sid, 3).await;

        let mut before = member_rig();
        before.store.join(&s, "owner", 2).await.unwrap();
        let grant_id = served(&src, &before, sid, TOKEN).await;
        assert_eq!(
            close_of(&mut before, grant_id).await.as_deref(),
            Some("stale_fence"),
            "no end named: the whole history is below the floor"
        );
        assert_eq!(tip(&before, sid).await, None);
        src.sup.close_stream(grant_id, "test");

        let mem = member_rig();
        let end = meshharbor_hive_node::FenceEnd {
            fence: 1,
            seq: ended.seq,
            hash: ended.hash,
        };
        mem.store
            .join_with_ends(&s, "owner", 2, vec![end])
            .await
            .unwrap();
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(tip_at(&mem, sid, 3).await, last);
        assert_eq!(
            mem.store.page(&s, 0, 10).await.unwrap(),
            src.store.page(&s, 0, 10).await.unwrap(),
            "the copy is the new primary's chain, event for event"
        );
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");
    }

    /// P2e-5b — at the `seq` its fence ended, an older fence's event that is
    /// not the one it ended with is refused, and nothing of it kept: the
    /// member ends the stream `not_fence_end`.
    #[tokio::test]
    async fn an_event_at_a_fences_end_that_is_not_its_end_is_refused() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        let s = sid.to_hex();
        let end = meshharbor_hive_node::FenceEnd {
            fence: 1,
            seq: 1,
            hash: [9; 32],
        };
        mem.store
            .join_with_ends(&s, "owner", 2, vec![end])
            .await
            .unwrap();
        let (_peer, grant_id, _conn, mut send, _recv) = source_by_hand(&mem, sid).await;
        let hello = SourceMsg::Hello {
            v: wire::STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: false,
            stand_ins: Vec::new(),
        };
        write_frame(&mut send, &hello).await.unwrap();
        let other = EventEnvelope::next(&s, None, 1, 0, &said("not where fence 1 ended"));
        send_by_hand(&mut send, &[other]).await;
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("not_fence_end"),
            "the member ends the stream in the chain's word"
        );
        assert_eq!(tip(&mem, sid).await, None, "nothing of it kept");
    }

    /// P2d-3 — a member reads only the blobs it asked for, at the length
    /// asked, hashing to their names: anything else ends the stream, and
    /// the checkpoint naming them is not applied.
    #[tokio::test]
    async fn a_blob_not_as_asked_ends_the_stream() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let (snap, _) = snapshot_whole("f", 0o600, b"asked for", None);
        let asked = snap.chunks[0].hash;
        let cp = TranscriptEvent::Checkpoint(Checkpoint {
            n: 1,
            turn: 1,
            files: vec![snap],
            skipped: Vec::new(),
            workspace: None,
        });
        let env = EventEnvelope::next(&sid.to_hex(), None, 1, 0, &cp);
        let other: &[u8] = b"something else";
        for (case, hash, bytes) in [
            ("another blob", Digest::of(other), other),
            ("another length", asked, other),
            ("other bytes", asked, b"asked fox".as_slice()),
        ] {
            let (_peer, grant_id, conn, mut send, mut recv) = source_by_hand(&mem, sid).await;
            let hello = SourceMsg::Hello {
                v: wire::STREAM_V,
                tip: Mark::genesis(),
                live: true,
                packs: false,
                stand_ins: Vec::new(),
            };
            write_frame(&mut send, &hello).await.unwrap();
            send_by_hand(&mut send, std::slice::from_ref(&env)).await;
            let need: MemberMsg = read_frame(&mut recv).await.unwrap();
            assert_eq!(
                need,
                MemberMsg::Need { blobs: vec![asked] },
                "{case}: it asks for what the checkpoint names"
            );
            let mut uni = conn.open_uni().await.unwrap();
            let header = BlobMsg::Blob {
                hash,
                len: bytes.len() as u64,
            };
            write_frame(&mut uni, &header).await.unwrap();
            uni.write_all(bytes).await.unwrap();
            let _ = uni.finish();
            assert_eq!(
                close_of(&mut mem, grant_id).await.as_deref(),
                Some("bad_blob"),
                "{case}"
            );
            assert_eq!(tip(&mem, sid).await, None, "{case}: not applied");
        }
    }

    /// P2d-3 — `diverged` must be at a point the member named, genesis or
    /// one of its hello's checkpoints: a source's word alone never moves a
    /// copy back, even a tail the store would let it set aside.
    #[tokio::test]
    async fn a_diverged_point_the_member_never_named_moves_nothing() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        let s = sid.to_hex();
        mem.store.join(&s, "owner", 1).await.unwrap();
        note(&mem, sid, &["one", "two", "three"]);
        // An older fence's tail: the store would set it aside if asked.
        mem.store.raise_floor(&s, 2).await.unwrap();
        let before = tip(&mem, sid).await;
        let first = mem.store.page(&s, 0, 1).await.unwrap().remove(0);
        let (_peer, grant_id, _conn, mut send, _recv) = source_by_hand(&mem, sid).await;
        let at = Mark {
            seq: 1,
            hash: hex::encode(first.hash()),
        };
        write_frame(
            &mut send,
            &SourceMsg::Diverged {
                at,
                tip: None,
                live: true,
                packs: false,
                stand_ins: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("bad_answer"),
            "a point of the copy, but none the member named"
        );
        assert_eq!(tip(&mem, sid).await, before, "nothing moved");
    }

    /// P2d-3 — an event announced past the stream's limit is refused on its
    /// listing, before a byte of it is read.
    #[tokio::test]
    async fn an_event_announced_past_the_limit_is_refused_unread() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let (_peer, grant_id, _conn, mut send, _recv) = source_by_hand(&mem, sid).await;
        let hello = SourceMsg::Hello {
            v: wire::STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: false,
            stand_ins: Vec::new(),
        };
        write_frame(&mut send, &hello).await.unwrap();
        let listing = SourceMsg::Events {
            events: vec![EventMeta {
                seq: 1,
                fence: 1,
                ts_ms: 0,
                prev_hash: GENESIS,
                len: wire::MAX_EVENT_BYTES as u64 + 1,
            }],
        };
        write_frame(&mut send, &listing).await.unwrap();
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("bad_frame")
        );
    }

    use super::super::follow::{Phase, Renewing, WANT_TIMEOUT};

    /// P2d-3b — the next `rc:hive.replica.want` the rig's device sends for
    /// `sid` on `path`, any other skipped, or `None` within 5 s: its fence,
    /// its seq and the key it names.
    async fn want_on(
        r: &mut Rig,
        sid: ObjectId,
        path: HiveStreamPath,
    ) -> Option<(u64, u64, Option<String>)> {
        want_on_within(r, sid, path, Duration::from_secs(5)).await
    }

    /// [`want_on`], within `within`.
    async fn want_on_within(
        r: &mut Rig,
        sid: ObjectId,
        path: HiveStreamPath,
        within: Duration,
    ) -> Option<(u64, u64, Option<String>)> {
        let deadline = Instant::now() + within;
        loop {
            let msg = tokio::time::timeout_at(deadline, r.reports.recv())
                .await
                .ok()?
                .expect("the reporter is open");
            if let ClientMsg::HiveReplicaWant {
                session_id,
                fence,
                seq,
                path: Some(p),
                derp_pubkey,
                ..
            } = msg
                && session_id == sid
                && p == path
            {
                return Some((fence, seq, derp_pubkey));
            }
        }
    }

    /// Whether the rig's device asks for `sid` at all within `within`.
    async fn asks_within(r: &mut Rig, sid: ObjectId, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, r.reports.recv()).await {
            if let ClientMsg::HiveReplicaWant { session_id, .. } = msg
                && session_id == sid
            {
                return true;
            }
        }
        false
    }

    /// `sid`'s follow once it is `phase`, within 5 s.
    async fn phase_of(r: &Rig, sid: ObjectId, phase: Phase) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if r.sup.follow_phase(sid) == Some(phase) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{sid}'s follow never became {phase:?}: {:?}",
                r.sup.follow_phase(sid)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// P2d-3b — each copy held asks for its stream from the top of the
    /// ladder, naming its fence and where the copy ends.
    #[tokio::test]
    async fn each_copy_held_asks_for_its_stream_from_the_top() {
        let mut mem = member_rig();
        let (a, b) = (ObjectId::new(), ObjectId::new());
        mem.store.join(&a.to_hex(), "owner", 3).await.unwrap();
        mem.store.join(&b.to_hex(), "archive", 4).await.unwrap();
        put(&mem, b, 4, said("held already"));
        mem.sup.follow_all().await;
        let mut asked = HashMap::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while asked.len() < 2 {
            let msg = tokio::time::timeout_at(deadline, mem.reports.recv())
                .await
                .expect("an ask for each copy within 5 s")
                .expect("the reporter is open");
            if let ClientMsg::HiveReplicaWant {
                session_id,
                fence,
                seq,
                path,
                derp_pubkey,
                ..
            } = msg
            {
                asked.insert(session_id, (fence, seq, path, derp_pubkey));
            }
        }
        assert_eq!(
            asked.get(&a),
            Some(&(3, 0, Some(HiveStreamPath::Direct), None)),
            "a copy that holds nothing yet"
        );
        assert_eq!(
            asked.get(&b),
            Some(&(4, 1, Some(HiveStreamPath::Direct), None)),
            "a copy that ends at its first event"
        );
    }

    /// P2d-3b — the ladder: each rung that does not carry, a rung down, the
    /// floor naming this device's DERP key; past the bottom, a wait, then
    /// the top again. Never ratchet.
    #[tokio::test]
    async fn the_ladder_climbs_down_and_back_to_the_top() {
        use HiveStreamPath::{Derp, Direct, Relay};
        let mut mem = member_rig();
        let (here, _there) = derp_pair();
        let key = here.self_pubkey_hex.clone();
        mem.sup.use_derp_for_tests(Some(here));
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some(), "the top");
        mem.sup.on_refused(
            sid,
            1,
            Some(Direct),
            Some(HiveStreamRefusal::PathUnavailable),
        );
        assert!(want_on(&mut mem, sid, Relay).await.is_some(), "a rung down");
        mem.sup
            .on_refused(sid, 1, Some(Relay), Some(HiveStreamRefusal::NoAnswer));
        let (_, _, named) = want_on(&mut mem, sid, Derp).await.expect("the floor");
        assert_eq!(named, Some(key), "naming this device's own key");
        mem.sup
            .on_refused(sid, 1, Some(Derp), Some(HiveStreamRefusal::PathUnavailable));
        assert_eq!(
            mem.sup.follow_phase(sid),
            Some(Phase::Waiting),
            "past the bottom, a wait"
        );
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "then the top again"
        );
    }

    /// P2d-3b — a refusal that says "not now" waits, and asks again on the
    /// same rung.
    #[tokio::test]
    async fn a_refusal_that_says_later_asks_again_on_the_same_rung() {
        use HiveStreamPath::{Direct, Relay};
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        mem.sup.on_refused(
            sid,
            1,
            Some(Direct),
            Some(HiveStreamRefusal::PathUnavailable),
        );
        assert!(want_on(&mut mem, sid, Relay).await.is_some());
        mem.sup
            .on_refused(sid, 1, Some(Relay), Some(HiveStreamRefusal::SourceOffline));
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Waiting));
        assert!(
            want_on(&mut mem, sid, Relay).await.is_some(),
            "the same rung, after a wait"
        );
    }

    /// P2d-3b — a member the server says is none asks no more, until a join;
    /// and a refusal for no ask in flight (another rung, another fence)
    /// moves nothing.
    #[tokio::test]
    async fn a_member_told_it_is_none_asks_no_more_until_a_join() {
        use HiveStreamPath::{Direct, Relay};
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        mem.sup
            .on_refused(sid, 1, Some(Relay), Some(HiveStreamRefusal::NotAMember));
        mem.sup
            .on_refused(sid, 2, Some(Direct), Some(HiveStreamRefusal::NotAMember));
        assert_eq!(
            mem.sup.follow_phase(sid),
            Some(Phase::Wanting(Direct)),
            "neither was the answer to the ask in flight"
        );
        mem.sup
            .on_refused(sid, 1, Some(Direct), Some(HiveStreamRefusal::NotAMember));
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Stopped));
        assert!(
            !asks_within(&mut mem, sid, Duration::from_millis(700)).await,
            "no more asks"
        );
        mem.sup.follow_joined(sid, 2);
        assert_eq!(
            want_on(&mut mem, sid, Direct).await.map(|w| w.0),
            Some(2),
            "a join starts it again, at its fence"
        );
    }

    /// P2d-3b — a stream that never got past its opening exchange asks a
    /// rung down; one that carried, from the top. The end of a stream that
    /// is not the one followed moves nothing.
    #[tokio::test]
    async fn a_stream_that_did_not_carry_asks_a_rung_down() {
        use HiveStreamPath::{Direct, Relay};
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        let (g1, g2, g3) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        mem.sup.on_dialed(sid, g1, 30);
        mem.sup.on_stream_over(sid, g1, "unreachable", false);
        assert!(want_on(&mut mem, sid, Relay).await.is_some(), "a rung down");
        mem.sup.on_dialed(sid, g2, 30);
        // P2d-4 — beside it, and followed once it answers.
        mem.sup.on_dialed(sid, g3, 30);
        mem.sup.on_answered(sid, g3);
        mem.sup.on_stream_over(sid, g2, "expired", true);
        assert_eq!(
            mem.sup.follow_phase(sid),
            Some(Phase::Following(g3)),
            "an older stream's end"
        );
        mem.sup.on_stream_over(sid, g3, "expired", true);
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "one that carried: from the top"
        );
    }

    /// P2d-3b — a copy of a session that is over on its source lets the
    /// stream go once it holds all of it, and the session is parked: asked
    /// for no more.
    #[tokio::test]
    async fn a_copy_of_a_session_over_is_parked_once_whole() {
        let mut src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two", "three"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .is_some()
        );
        // The server's half, played here: the source hosts nothing of it.
        let grant_id = served_as_is(&src, &mem, grant(sid, HiveStreamPath::Direct), TOKEN).await;
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("caught_up"),
            "the copy holds all of a session that is over"
        );
        assert_eq!(tip(&mem, sid).await, tip(&src, sid).await);
        phase_of(&mem, sid, Phase::Parked).await;
        assert_eq!(
            close_of(&mut src, grant_id).await.as_deref(),
            Some("member:caught_up"),
            "and the source hears why"
        );
        assert!(
            !asks_within(&mut mem, sid, Duration::from_millis(700)).await,
            "asked for no more"
        );
    }

    /// P2e-5c — a copy of a session that moves to its source, whose start
    /// for it is still on its way, follows on once whole: the session runs on
    /// there, and is never parked.
    #[tokio::test]
    async fn a_session_moving_to_its_source_is_followed_on_once_whole() {
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        // The promotion's move, kept for the start right behind it.
        src.sup.receive_move(super::super::Moved {
            session_id: sid,
            fence: 2,
            turns: 1,
            from_device_id: ObjectId::new(),
            from_device_name: "mars".into(),
            from_folder: "/srv/work".into(),
            moved_by_name: "Alice".into(),
            moved_at_ms: 1_791_813_720_000,
            earlier: Vec::new(),
        });
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .is_some()
        );
        let grant_id = served_as_is(&src, &mem, grant(sid, HiveStreamPath::Direct), TOKEN).await;
        let end = tip(&src, sid).await.unwrap();
        assert_eq!(tip_at(&mem, sid, end.seq).await, end);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            mem.sup.holds_stream(grant_id),
            "still following: the session runs on there"
        );
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Following(grant_id)));
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");
    }

    /// P2e-5c — a newer join while a stream is followed: that stream's end,
    /// in a word that would stop or park the follow, is about the fence the
    /// session left, so the session is asked for again, at its new fence.
    #[tokio::test]
    async fn a_stop_for_a_stream_a_newer_join_overtook_asks_again() {
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert_eq!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .map(|w| w.0),
            Some(1)
        );
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        phase_of(&mem, sid, Phase::Following(grant_id)).await;
        // The session moves while it is followed: the member's join at fence 2.
        mem.store.join(&sid.to_hex(), "owner", 2).await.unwrap();
        mem.sup.follow_joined(sid, 2);
        assert_eq!(
            mem.sup.follow_phase(sid),
            Some(Phase::Following(grant_id)),
            "the stream followed goes on until it ends"
        );
        mem.sup.close_stream(grant_id, "member_left");
        assert_eq!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .map(|w| w.0),
            Some(2),
            "asked for again at its new fence, never stopped"
        );
        src.sup.close_stream(grant_id, "test");
    }

    /// P2e-5c — a newer join overtakes an ask out: the session is asked for
    /// again at once, at the new fence, never after the old ask's timeout,
    /// and the old ask's refusal, naming the fence it asked at, moves
    /// nothing.
    #[tokio::test]
    async fn a_newer_join_asks_again_at_once_while_an_ask_is_out() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert_eq!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .map(|w| w.0),
            Some(1)
        );
        mem.store.join(&sid.to_hex(), "owner", 2).await.unwrap();
        mem.sup.follow_joined(sid, 2);
        assert_eq!(
            want_on_within(
                &mut mem,
                sid,
                HiveStreamPath::Direct,
                Duration::from_secs(1)
            )
            .await
            .map(|w| w.0),
            Some(2),
            "asked again at once, at the new fence"
        );
        mem.sup.on_refused(
            sid,
            1,
            Some(HiveStreamPath::Direct),
            Some(HiveStreamRefusal::StaleFence),
        );
        assert!(
            matches!(mem.sup.follow_phase(sid), Some(Phase::Wanting(_))),
            "the old ask's refusal moves nothing: {:?}",
            mem.sup.follow_phase(sid)
        );
        // A refusal of the ask at the new fence is that ask's own: it stops.
        mem.sup.on_refused(
            sid,
            2,
            Some(HiveStreamPath::Direct),
            Some(HiveStreamRefusal::NotAMember),
        );
        assert_eq!(
            mem.sup.follow_phase(sid),
            Some(Phase::Stopped),
            "a stop about the fence it asked at is taken"
        );
    }

    /// P2d-3b — a copy of a session still live on its source follows on,
    /// whole or not.
    #[tokio::test]
    async fn a_live_session_is_followed_on_once_whole() {
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .is_some()
        );
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        let end = tip(&src, sid).await.unwrap();
        assert_eq!(tip_at(&mem, sid, end.seq).await, end);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(mem.sup.holds_stream(grant_id), "still following");
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Following(grant_id)));
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");
    }

    /// P2d-3b — the server's `member_left` stops a follow.
    #[tokio::test]
    async fn a_member_let_go_stops_following() {
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .is_some()
        );
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        phase_of(&mem, sid, Phase::Following(grant_id)).await;
        mem.sup.close_stream(grant_id, "member_left");
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Stopped));
        assert!(!asks_within(&mut mem, sid, Duration::from_millis(700)).await);
        src.sup.close_stream(grant_id, "test");
    }

    /// P2d-3b — at most [`MAX_FOLLOWING`] copies are asked for or followed
    /// at once; the rest wait their turn, and take the first slot freed.
    #[tokio::test]
    async fn as_many_are_asked_for_as_may_be_and_the_rest_wait() {
        let mem = member_rig();
        let sessions: Vec<ObjectId> = (0..=MAX_FOLLOWING).map(|_| ObjectId::new()).collect();
        for s in &sessions {
            mem.store.join(&s.to_hex(), "archive", 1).await.unwrap();
        }
        mem.sup.follow_all().await;
        let phases: Vec<Option<Phase>> =
            sessions.iter().map(|s| mem.sup.follow_phase(*s)).collect();
        let queued: Vec<ObjectId> = sessions
            .iter()
            .zip(&phases)
            .filter(|(_, p)| **p == Some(Phase::Queued))
            .map(|(s, _)| *s)
            .collect();
        assert_eq!(queued.len(), 1, "one waits its turn: {phases:?}");
        assert_eq!(
            phases
                .iter()
                .filter(|p| matches!(p, Some(Phase::Wanting(_))))
                .count(),
            MAX_FOLLOWING
        );
        let first = sessions
            .iter()
            .find(|s| matches!(mem.sup.follow_phase(**s), Some(Phase::Wanting(_))))
            .copied()
            .unwrap();
        mem.sup.on_refused(
            first,
            1,
            Some(HiveStreamPath::Direct),
            Some(HiveStreamRefusal::SourceOffline),
        );
        phase_of(&mem, queued[0], Phase::Wanting(HiveStreamPath::Direct)).await;
    }

    /// FR-90 P2f-1b — on a device whose owner holds no copies, a connection
    /// follows the copy of a teleport it was prepared for, and none other it
    /// holds: a leftover of a teleport that is over waits for the purge.
    #[tokio::test]
    async fn a_connection_of_a_device_that_holds_no_copies_follows_its_teleports_copy() {
        let r = rig(true, 4);
        let (teleport, leftover) = (ObjectId::new(), ObjectId::new());
        r.store
            .join(&teleport.to_hex(), "teleport", 1)
            .await
            .unwrap();
        r.store
            .join(&leftover.to_hex(), "teleport", 1)
            .await
            .unwrap();
        let mut prepared = super::super::tests::order(&r);
        (prepared.session_id, prepared.fence) = (teleport, 2);
        r.sup.admit_teleport(&prepared, None);
        let (tx, mut reports) = mpsc::channel(64);
        r.sup.connected(tx);
        let deadline = Instant::now() + Duration::from_millis(3000);
        let mut asked = Vec::new();
        while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, reports.recv()).await {
            if let ClientMsg::HiveReplicaWant { session_id, .. } = msg {
                asked.push(session_id);
            }
        }
        assert_eq!(asked, [teleport], "the teleport's copy, and only that");
    }

    /// P2d-3b — the primary organization's connection starts following each
    /// copy held, as a device's does when it comes back; a device whose
    /// owner holds no copies asks for none.
    #[tokio::test]
    async fn a_connection_follows_each_copy_held() {
        for (replica, asks) in [(true, true), (false, false)] {
            let r = rig_with(true, 4, |c| c.replica = replica, |s| s);
            let sid = ObjectId::new();
            r.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
            let (tx, mut reports) = mpsc::channel(64);
            r.sup.connected(tx);
            let deadline = Instant::now() + Duration::from_millis(if asks { 5000 } else { 700 });
            let mut asked = false;
            while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, reports.recv()).await {
                if let ClientMsg::HiveReplicaWant { session_id, .. } = msg
                    && session_id == sid
                {
                    asked = true;
                    break;
                }
            }
            assert_eq!(asked, asks, "hive_replica {replica}");
        }
    }

    /// P2d-3b — a device whose owner holds no copies (`hive_replica` off)
    /// follows no dial, whatever the server says: the gate that survives a
    /// compromised server.
    #[tokio::test]
    async fn a_device_that_holds_no_copies_follows_no_dial() {
        let src = rig(true, 4);
        let mut mem = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("replica_disabled")
        );
        assert!(!mem.sup.holds_stream(grant_id));
        src.sup.close_stream(grant_id, "test");
    }

    /// FR-90 P2f-1b — a device whose owner holds no copies follows the dial
    /// of a teleport it was prepared for (P2f-1a): the copy it will run. The
    /// gate holds for anything else: once the session launched there, the
    /// admission is done with, and the next dial is refused again.
    #[tokio::test]
    async fn a_device_that_holds_no_copies_follows_a_teleports_dial() {
        let src = rig(true, 4);
        let mut mem = rig(true, 4);
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        mem.store.join(&sid.to_hex(), "teleport", 1).await.unwrap();
        // Prepared for the start at fence 2: its join, at fence 1, is the
        // teleport's.
        let mut prepared = super::super::tests::order(&mem);
        (prepared.session_id, prepared.fence) = (sid, 2);
        mem.sup.admit_teleport(&prepared, None);
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(
            tip_at(&mem, sid, 2).await.seq,
            2,
            "the teleport's copy follows the source"
        );
        mem.sup.close_stream(grant_id, "test");
        src.sup.close_stream(grant_id, "test");

        mem.sup.forget_teleport(sid, 2);
        let grant_id = served(&src, &mem, sid, TOKEN).await;
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("replica_disabled"),
            "the admission is done with"
        );
        src.sup.close_stream(grant_id, "test");
    }

    /// P2d-4 — [`served`], the member holding the grant to `ttl_secs` and
    /// the source to its usual 30 s: what ends the source's side before then
    /// is the member's word, never the source's clock.
    async fn served_for(src: &Rig, mem: &Rig, sid: ObjectId, ttl_secs: u32) -> ObjectId {
        let g = grant(sid, HiveStreamPath::Direct);
        let ids = (g.grant_id, g.session_id, g.path);
        let ready = ready_of(src, g, true).await;
        dial_for(mem, ids, ready, TOKEN, Vec::new(), ttl_secs);
        ids.0
    }

    /// A dial for `sid` to a socket that takes the member's packets and
    /// answers none: a stream that stays in its opening exchange.
    fn to_silence(sid: ObjectId, grant_id: ObjectId, silent: &std::net::UdpSocket) -> Dial {
        Dial {
            grant_id,
            session_id: sid,
            fence: 1,
            source_id: ObjectId::new(),
            path: Some(HiveStreamPath::Direct),
            token: TOKEN.into(),
            cert_fingerprint: "00".repeat(32),
            addrs: vec![silent.local_addr().unwrap().to_string()],
            ice_servers: Vec::new(),
            derp_pubkey: None,
            ttl_secs: 30,
        }
    }

    /// P2d-4 — at half its grant's life a member asks for its stream again,
    /// from the top, and follows the renewal's stream beside the old one;
    /// once the new one answers, the old one is let go (`renewed`), the
    /// source's side of it too, and the new one carries the live tail.
    #[tokio::test]
    async fn a_stream_is_renewed_before_its_grant_ends() {
        use HiveStreamPath::Direct;
        let src = rig(true, 4);
        let mut mem = member_rig();
        let sid = ObjectId::new();
        note(&src, sid, &["one", "two"]);
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        // Renewed at 5 s, ended at 10 s.
        let old = served_for(&src, &mem, sid, 10).await;
        phase_of(&mem, sid, Phase::Following(old)).await;
        let end = tip(&src, sid).await.unwrap();
        assert_eq!(tip_at(&mem, sid, end.seq).await, end);

        // Short of the grant's end (10 s), when the follow would ask from
        // the top anyway.
        assert!(
            want_on_within(&mut mem, sid, Direct, Duration::from_secs(8))
                .await
                .is_some(),
            "the renewal, from the top, at half the grant's life"
        );
        assert!(
            mem.sup.holds_stream(old),
            "the old stream carries on meanwhile"
        );
        let new = served_for(&src, &mem, sid, 30).await;
        assert_eq!(
            close_of(&mut mem, old).await.as_deref(),
            Some("renewed"),
            "the old one let go once the new one answered"
        );
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Following(new)));
        assert!(mem.sup.holds_stream(new) && !mem.sup.holds_stream(old));
        let deadline = Instant::now() + Duration::from_secs(3);
        while src.sup.holds_stream(old) {
            assert!(
                Instant::now() < deadline,
                "the source's side of the old one ends with the member's word"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        put(&src, sid, 1, said("live"));
        let live = tip(&src, sid).await.unwrap();
        assert_eq!(
            tip_at(&mem, sid, live.seq).await,
            live,
            "the new one carries the live tail"
        );
        mem.sup.close_stream(new, "test");
        src.sup.close_stream(new, "test");
    }

    /// P2d-4 — a renewal asks from the top whatever rung the stream it
    /// renews is on (never ratchet), and climbs down a rung on its own
    /// answers; past the bottom it is let go, the stream followed carries on
    /// to its end, and that end asks again from the top.
    #[tokio::test]
    async fn a_renewal_asks_from_the_top_and_without_a_rung_lets_the_stream_be() {
        use HiveStreamPath::{Direct, Relay};
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        mem.sup.on_refused(
            sid,
            1,
            Some(Direct),
            Some(HiveStreamRefusal::PathUnavailable),
        );
        assert!(
            want_on(&mut mem, sid, Relay).await.is_some(),
            "the follow fell to relay"
        );
        let g = ObjectId::new();
        mem.sup.on_dialed(sid, g, 1);
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "the renewal asks from the top: never ratchet"
        );
        mem.sup.on_refused(
            sid,
            1,
            Some(Direct),
            Some(HiveStreamRefusal::PathUnavailable),
        );
        assert!(
            want_on_within(&mut mem, sid, Relay, Duration::from_secs(2))
                .await
                .is_some(),
            "a rung down, for the renewal"
        );
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Following(g)));
        // The bottom's answer: a dial on a rung this build cannot name,
        // turned away.
        let mut nowhere = to_silence(
            sid,
            ObjectId::new(),
            &std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        );
        nowhere.path = None;
        mem.sup.follow_dial(nowhere, true);
        assert_eq!(
            mem.sup.follow_renewal(sid),
            None,
            "past the bottom: no renewal this time"
        );
        assert_eq!(
            mem.sup.follow_phase(sid),
            Some(Phase::Following(g)),
            "the stream followed carries on"
        );
        assert!(
            !asks_within(&mut mem, sid, Duration::from_millis(700)).await,
            "nothing more is asked while it does"
        );
        mem.sup.on_stream_over(sid, g, "expired", true);
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "its end asks again from the top"
        );
    }

    /// P2d-4 — a renewal's ask unanswered is taken for `no_answer` on its
    /// own clock: the timeout of an ask it moved on from moves nothing.
    #[tokio::test]
    async fn a_renewal_ask_times_out_on_its_own_clock() {
        use HiveStreamPath::{Direct, Relay};
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        mem.sup.on_dialed(sid, ObjectId::new(), 1);
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "the renewal"
        );
        let first = Instant::now();
        let gap = WANT_TIMEOUT / 2;
        tokio::time::sleep(gap).await;
        mem.sup.on_refused(
            sid,
            1,
            Some(Direct),
            Some(HiveStreamRefusal::PathUnavailable),
        );
        assert!(
            want_on_within(&mut mem, sid, Relay, Duration::from_secs(2))
                .await
                .is_some()
        );
        // Past the first ask's timeout, short of the second's.
        tokio::time::sleep_until(first + WANT_TIMEOUT + gap / 2).await;
        assert_eq!(
            mem.sup.follow_renewal(sid),
            Some((1, Renewing::Wanting(Relay))),
            "the first ask's timeout moved nothing"
        );
        tokio::time::sleep_until(first + gap + WANT_TIMEOUT + gap / 2).await;
        assert_eq!(
            mem.sup.follow_renewal(sid),
            None,
            "the second's own: past the bottom"
        );
    }

    /// P2d-4 — a dial beside the stream followed is its renewal. The stream
    /// followed that ends with its renewal dialed hands over to it, asking
    /// nothing, and from the renewal's rung: one that then does not carry
    /// asks a rung down from there.
    #[tokio::test]
    async fn a_stream_that_ends_hands_over_to_its_renewal() {
        use HiveStreamPath::{Direct, Relay};
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        mem.sup.on_refused(
            sid,
            1,
            Some(Direct),
            Some(HiveStreamRefusal::PathUnavailable),
        );
        assert!(
            want_on(&mut mem, sid, Relay).await.is_some(),
            "the follow fell to relay"
        );
        let (old, new) = (ObjectId::new(), ObjectId::new());
        mem.sup.on_dialed(sid, old, 1);
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "its renewal, on direct"
        );
        mem.sup.on_dialed(sid, new, 30);
        let renewing = Some((
            0,
            Renewing::Dialed {
                grant: new,
                ttl_secs: 30,
            },
        ));
        assert_eq!(
            mem.sup.follow_renewal(sid),
            renewing,
            "a dial beside the stream followed is its renewal"
        );
        mem.sup.on_dialed(sid, old, 1);
        assert_eq!(
            mem.sup.follow_renewal(sid),
            renewing,
            "a replay of the dial followed moves nothing"
        );
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Following(old)));
        mem.sup.on_stream_over(sid, old, "expired", true);
        assert_eq!(
            mem.sup.follow_phase(sid),
            Some(Phase::Following(new)),
            "its renewal follows on"
        );
        assert!(
            !asks_within(&mut mem, sid, Duration::from_millis(700)).await,
            "asking nothing"
        );
        mem.sup.on_stream_over(sid, new, "unreachable", false);
        assert!(
            want_on_within(&mut mem, sid, Relay, Duration::from_secs(2))
                .await
                .is_some(),
            "a rung down from the renewal's own"
        );
    }

    /// P2d-4 — an end of the stream followed that lets the session be (the
    /// server's `member_left`) lets its renewal's stream go too, in the same
    /// word.
    #[tokio::test]
    async fn a_member_let_go_lets_its_renewal_go_too() {
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(
            want_on(&mut mem, sid, HiveStreamPath::Direct)
                .await
                .is_some()
        );
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (followed, renewal) = (ObjectId::new(), ObjectId::new());
        mem.sup
            .follow_dial(to_silence(sid, followed, &silent), true);
        mem.sup.follow_dial(to_silence(sid, renewal, &silent), true);
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Following(followed)));
        mem.sup.close_stream(followed, "member_left");
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Stopped));
        assert_eq!(
            close_of(&mut mem, renewal).await.as_deref(),
            Some("member_left"),
            "the renewal's stream let go, in the same word"
        );
        assert!(!mem.sup.holds_stream(renewal));
    }

    /// P2d-4 — a renewal asked for when the connection went is asked for
    /// again on the next one, on its rung, its answer having been the old
    /// connection's; and it goes with the stream followed, whose end asks
    /// again from the top.
    #[tokio::test]
    async fn a_connection_asks_again_for_a_renewal_in_flight() {
        use HiveStreamPath::Direct;
        let mut mem = member_rig();
        let sid = ObjectId::new();
        mem.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        mem.sup.follow_joined(sid, 1);
        assert!(want_on(&mut mem, sid, Direct).await.is_some());
        let g = ObjectId::new();
        mem.sup.on_dialed(sid, g, 1);
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "the renewal"
        );
        mem.sup.follow_all().await;
        assert!(
            want_on_within(&mut mem, sid, Direct, Duration::from_secs(2))
                .await
                .is_some(),
            "asked again on the next connection"
        );
        assert_eq!(mem.sup.follow_phase(sid), Some(Phase::Following(g)));
        mem.sup.on_stream_over(sid, g, "expired", true);
        assert_eq!(
            mem.sup.follow_renewal(sid),
            None,
            "the renewal goes with the stream followed"
        );
        assert!(
            want_on(&mut mem, sid, Direct).await.is_some(),
            "whose end asks again from the top"
        );
    }

    // ─── P2f-2b: the have and want ──────────────────────────────────────────

    /// `git` as a person runs it in `dir`.
    fn person(dir: &std::path::Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .args([
                "-c",
                "user.name=Person",
                "-c",
                "user.email=person@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn have_git() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok()
    }

    /// A rig whose children run in this process, git's discovery stopping at
    /// `/tmp`, where every rig's root is.
    fn packing_rig(replica: bool) -> Rig {
        rig_with(
            true,
            4,
            move |c| c.replica = replica,
            |mut s| {
                s.checkpoint_runner = Some(crate::hive::checkpointer::Runner::InProcess {
                    ceiling: std::path::PathBuf::from("/tmp"),
                });
                s.without_follow_at_connect()
            },
        )
    }

    /// The person's repository at `<root>/src`, a commit of its own, and the
    /// session's first checkpoint of it: the person's `HEAD`, the workspace
    /// (its pack whole) and that pack's blobs.
    fn checkpointed_repo(
        root: &std::path::Path,
        sid: ObjectId,
    ) -> (String, WorkspaceSnap, Vec<Vec<u8>>) {
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        person(&src, &["init", "-q"]);
        std::fs::write(src.join("lib.rs"), "pub fn f() {}\n").unwrap();
        person(&src, &["add", "-A"]);
        person(&src, &["commit", "-q", "-m", "first"]);
        let head = person(&src, &["rev-parse", "HEAD"]);
        std::fs::write(src.join("main.rs"), "fn main() {}\n").unwrap();
        let git = crate::hive::workspace::Git::under(root);
        let state = root.join("src-state");
        match crate::hive::workspace::checkpoint(&git, &src, &state, &sid.to_hex(), 1, 1, None) {
            crate::hive::workspace::Outcome::Taken { snap, blobs } => (head, snap, blobs),
            crate::hive::workspace::Outcome::Skipped(why) => panic!("{why}"),
        }
    }

    /// A checkpoint holding the workspace `ws` and no file: the first event
    /// of `sid`.
    fn workspace_event(sid: ObjectId, ws: &WorkspaceSnap) -> EventEnvelope {
        let cp = TranscriptEvent::Checkpoint(Checkpoint {
            n: 1,
            turn: 1,
            files: Vec::new(),
            skipped: Vec::new(),
            workspace: Some(ws.clone()),
        });
        EventEnvelope::next(&sid.to_hex(), None, 1, 0, &cp)
    }

    /// `blobs` on streams of their own, as a source answers a `need`.
    async fn serve_by_hand(conn: &QuicConnection, blobs: &[(Digest, Vec<u8>)]) {
        for (hash, bytes) in blobs {
            let mut uni = conn.open_uni().await.unwrap();
            let header = BlobMsg::Blob {
                hash: *hash,
                len: bytes.len() as u64,
            };
            write_frame(&mut uni, &header).await.unwrap();
            uni.write_all(bytes).await.unwrap();
            let _ = uni.finish();
        }
    }

    /// `mem`, a teleport's target for `sid` whose folder is a clone of the
    /// person's repository from a remote as it were (`--no-local`), or, not
    /// `cloned`, an empty folder in no repository; prepared with the
    /// server's `have_want` or without.
    async fn teleports_target(
        mem: &Rig,
        sid: ObjectId,
        have_want: bool,
        cloned: bool,
    ) -> std::path::PathBuf {
        let root = mem.root.path();
        let clone = root.join(format!("clone-{sid}"));
        if cloned {
            person(
                root,
                &[
                    "clone",
                    "-q",
                    "--no-local",
                    &root.join("src").display().to_string(),
                    &clone.display().to_string(),
                ],
            );
        } else {
            std::fs::create_dir_all(&clone).unwrap();
        }
        mem.store.join(&sid.to_hex(), "teleport", 1).await.unwrap();
        let mut prepared = super::super::tests::order(mem);
        (prepared.session_id, prepared.fence) = (sid, 2);
        let place = have_want.then(|| ("dev".to_string(), clone.clone()));
        mem.sup.admit_teleport(&prepared, place);
        clone
    }

    /// P2f-2b — a teleport's target, prepared with the server's `have_want`,
    /// takes a checkpoint's whole pack as one against what its clone holds:
    /// it asks a source that answers wants for the pack against its clone's
    /// `HEAD`, takes the answer's chunks as any blobs, keeps them as a
    /// substitute, and applies the checkpoint holding none of the whole
    /// pack's own blobs.
    #[tokio::test]
    async fn a_teleports_target_takes_the_whole_pack_against_its_clone() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let mem = packing_rig(false);
        let sid = ObjectId::new();
        let s = sid.to_hex();
        let root = mem.root.path().to_path_buf();
        let (head, snap, _whole) = checkpointed_repo(&root, sid);
        assert!(snap.base.is_none() && snap.head.as_deref() == Some(head.as_str()));
        teleports_target(&mem, sid, true, true).await;
        let env = workspace_event(sid, &snap);

        let (_peer, _grant_id, conn, mut send, mut recv) = source_by_hand(&mem, sid).await;
        let hello = SourceMsg::Hello {
            v: wire::STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: true,
            stand_ins: Vec::new(),
        };
        write_frame(&mut send, &hello).await.unwrap();
        send_by_hand(&mut send, std::slice::from_ref(&env)).await;
        let want: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert_eq!(
            want,
            MemberMsg::WantPack {
                commit: snap.commit.clone(),
                haves: vec![head.clone()],
            },
            "it names what its clone holds, once"
        );
        let (pack, against) = crate::hive::workspace::pack_against(
            &crate::hive::workspace::Git::under(&root),
            &root.join("src"),
            &root.join("src-state"),
            &snap.commit,
            std::slice::from_ref(&head),
        )
        .unwrap();
        let (chunks, blobs) = chunk_bytes(&pack);
        let mut uni = conn.open_uni().await.unwrap();
        let answer = BlobMsg::Pack {
            commit: snap.commit.clone(),
            against: against.clone(),
            chunks: chunks.clone(),
        };
        write_frame(&mut uni, &answer).await.unwrap();
        let _ = uni.finish();
        let need: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert_eq!(
            need,
            MemberMsg::Need {
                blobs: chunks.iter().map(|c| c.hash).collect()
            },
            "the pack's chunks, asked for as any blobs"
        );
        let named: Vec<(Digest, Vec<u8>)> = chunks.iter().map(|c| c.hash).zip(blobs).collect();
        serve_by_hand(&conn, &named).await;
        let ack: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert!(
            matches!(ack, MemberMsg::Ack { seq: 1, .. }),
            "applied: {ack:?}"
        );
        assert_eq!(
            mem.store.substitute(&s, &snap.commit).await.unwrap(),
            Some(Substitute {
                commit: snap.commit.clone(),
                against,
                chunks,
            }),
            "kept in place of the whole pack"
        );
        for c in &snap.pack {
            assert!(
                !mem.store.has_blob(&s, c.hash.0).await.unwrap(),
                "none of the whole pack's own blobs came"
            );
        }
    }

    /// P2f-2b — a source that cannot answer (`no_pack`) leaves the target to
    /// take the whole pack by its blobs, as before; a target whose folder
    /// holds nothing to be thin against never asks, nor one the server gave
    /// no `have_want`.
    #[tokio::test]
    async fn without_a_pack_against_its_clone_the_target_takes_the_whole_pack() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let mem = packing_rig(false);
        let root = mem.root.path().to_path_buf();
        let first = ObjectId::new();
        let (_head, snap, whole) = checkpointed_repo(&root, first);
        let names: Vec<Digest> = snap.pack.iter().map(|c| c.hash).collect();
        let named: Vec<(Digest, Vec<u8>)> = names.iter().copied().zip(whole).collect();
        for (case, have_want, cloned) in [
            ("no_pack", true, true),
            ("nothing held", true, false),
            ("no have_want", false, true),
        ] {
            let sid = ObjectId::new();
            let s = sid.to_hex();
            teleports_target(&mem, sid, have_want, cloned).await;
            let env = workspace_event(sid, &snap);
            let (_peer, _grant_id, conn, mut send, mut recv) = source_by_hand(&mem, sid).await;
            let hello = SourceMsg::Hello {
                v: wire::STREAM_V,
                tip: Mark::genesis(),
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            };
            write_frame(&mut send, &hello).await.unwrap();
            send_by_hand(&mut send, std::slice::from_ref(&env)).await;
            let mut first: MemberMsg = read_frame(&mut recv).await.unwrap();
            if have_want && cloned {
                assert!(
                    matches!(first, MemberMsg::WantPack { .. }),
                    "{case}: {first:?}"
                );
                let mut uni = conn.open_uni().await.unwrap();
                let none = BlobMsg::NoPack {
                    commit: snap.commit.clone(),
                    why: "not_live".into(),
                };
                write_frame(&mut uni, &none).await.unwrap();
                let _ = uni.finish();
                first = read_frame(&mut recv).await.unwrap();
            }
            assert_eq!(
                first,
                MemberMsg::Need {
                    blobs: names.clone()
                },
                "{case}: the whole pack, by its blobs"
            );
            serve_by_hand(&conn, &named).await;
            let ack: MemberMsg = read_frame(&mut recv).await.unwrap();
            assert!(
                matches!(ack, MemberMsg::Ack { seq: 1, .. }),
                "{case}: {ack:?}"
            );
            assert_eq!(
                mem.store.substitute(&s, &snap.commit).await.unwrap(),
                None,
                "{case}: nothing stands in for it"
            );
        }
    }

    /// P2f-2b — a source answers a member's `want_pack` with the pack against
    /// what the member holds, made from the session's repository while it
    /// runs there and kept as blobs the member then asks for as any; and
    /// `no_pack`, in a word, for a commit that is no whole pack of the chain,
    /// or a session that does not run there.
    #[tokio::test]
    async fn a_source_answers_a_want_with_a_pack_or_says_why_not() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let src = packing_rig(false);
        let root = src.root.path().to_path_buf();
        let running = ObjectId::new();
        let (head, snap, whole) = checkpointed_repo(&root, running);
        let away = ObjectId::new();
        for sid in [running, away] {
            for b in &whole {
                src.store.put_blob(&sid.to_hex(), b.clone()).await.unwrap();
            }
            let cp = Checkpoint {
                n: 1,
                turn: 1,
                files: Vec::new(),
                skipped: Vec::new(),
                workspace: Some(snap.clone()),
            };
            put(&src, sid, 1, TranscriptEvent::Checkpoint(cp));
            src.sup.host_for_tests(sid);
        }
        // `running` runs here; `away` is only hosted.
        src.sup.workplace_for_tests(
            running,
            packer::Workplace {
                who: crate::hive::materializer::Who {
                    account: None,
                    env: Vec::new(),
                },
                folder: root.join("src"),
                state_dir: root.join("src-state"),
            },
        );
        let ask = |commit: &str, haves: &[String]| MemberMsg::WantPack {
            commit: commit.to_string(),
            haves: haves.to_vec(),
        };
        let answer_on = |conn: QuicConnection| async move {
            let mut uni = conn.accept_uni().await.unwrap();
            read_frame::<BlobMsg>(&mut uni).await.unwrap()
        };

        let g = grant(running, HiveStreamPath::Direct);
        let (_peer, conn, mut send, mut recv) = dial_by_hand(ready_of(&src, g, true).await).await;
        write_frame(&mut send, &empty_hello(running)).await.unwrap();
        let hello: SourceMsg = read_frame(&mut recv).await.unwrap();
        assert!(
            matches!(hello, SourceMsg::Hello { packs: true, .. }),
            "it says it answers wants: {hello:?}"
        );
        write_frame(&mut send, &ask(&snap.commit, std::slice::from_ref(&head)))
            .await
            .unwrap();
        let BlobMsg::Pack {
            commit,
            against,
            chunks,
        } = answer_on(conn.clone()).await
        else {
            panic!("a pack");
        };
        assert_eq!(
            (commit.as_str(), against.as_slice()),
            (snap.commit.as_str(), std::slice::from_ref(&head))
        );
        let whole_len: u64 = snap.pack.iter().map(|c| c.len).sum();
        let pack_len: u64 = chunks.iter().map(|c| c.len).sum();
        assert!(
            pack_len < whole_len,
            "thin against the member's HEAD: {pack_len} of {whole_len}"
        );
        let need = MemberMsg::Need {
            blobs: chunks.iter().map(|c| c.hash).collect(),
        };
        write_frame(&mut send, &need).await.unwrap();
        for c in &chunks {
            let mut uni = conn
                .accept_uni()
                .await
                .expect("each of the pack's chunks, served as any blob");
            let BlobMsg::Blob { hash, len } = read_frame::<BlobMsg>(&mut uni).await.unwrap() else {
                panic!("a blob");
            };
            let mut bytes = vec![0u8; len as usize];
            uni.read_exact(&mut bytes).await.unwrap();
            assert_eq!(
                (hash, Digest::of(&bytes)),
                (c.hash, c.hash),
                "served as any blob"
            );
        }
        write_frame(
            &mut send,
            &ask(&"e".repeat(40), std::slice::from_ref(&head)),
        )
        .await
        .unwrap();
        assert_eq!(
            answer_on(conn.clone()).await,
            BlobMsg::NoPack {
                commit: "e".repeat(40),
                why: "not_a_whole_pack".into()
            }
        );
        conn.close(0u32.into(), b"done");

        let g = grant(away, HiveStreamPath::Direct);
        let (_peer, conn, mut send, mut recv) = dial_by_hand(ready_of(&src, g, true).await).await;
        write_frame(&mut send, &empty_hello(away)).await.unwrap();
        let _: SourceMsg = read_frame(&mut recv).await.unwrap();
        write_frame(&mut send, &ask(&snap.commit, std::slice::from_ref(&head)))
            .await
            .unwrap();
        assert_eq!(
            answer_on(conn.clone()).await,
            BlobMsg::NoPack {
                commit: snap.commit.clone(),
                why: "not_live".into()
            },
            "a session that does not run here"
        );
        conn.close(0u32.into(), b"done");
    }

    /// P2f-2b — the answer to a `want_pack` is held to it: a pack of another
    /// commit, or one thin against what the member did not name, ends the
    /// stream `bad_pack`, and a blob in its place `bad_blob`; nothing is
    /// applied, and nothing kept to stand in for the whole pack.
    #[tokio::test]
    async fn a_pack_that_is_not_the_one_asked_for_ends_the_stream() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let mut mem = packing_rig(false);
        let root = mem.root.path().to_path_buf();
        let (head, snap, _whole) = checkpointed_repo(&root, ObjectId::new());
        let (chunks, _) = chunk_bytes(b"no pack at all");
        let cases = [
            (
                "another commit's",
                BlobMsg::Pack {
                    commit: "e".repeat(40),
                    against: vec![head.clone()],
                    chunks: chunks.clone(),
                },
                "bad_pack",
            ),
            (
                "thin against what it did not name",
                BlobMsg::Pack {
                    commit: snap.commit.clone(),
                    against: vec!["d".repeat(40)],
                    chunks: chunks.clone(),
                },
                "bad_pack",
            ),
            (
                "a blob",
                BlobMsg::Blob {
                    hash: chunks[0].hash,
                    len: chunks[0].len,
                },
                "bad_blob",
            ),
        ];
        for (case, answer, word) in cases {
            let sid = ObjectId::new();
            let s = sid.to_hex();
            teleports_target(&mem, sid, true, true).await;
            let env = workspace_event(sid, &snap);
            let (_peer, grant_id, conn, mut send, mut recv) = source_by_hand(&mem, sid).await;
            let hello = SourceMsg::Hello {
                v: wire::STREAM_V,
                tip: Mark::genesis(),
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            };
            write_frame(&mut send, &hello).await.unwrap();
            send_by_hand(&mut send, std::slice::from_ref(&env)).await;
            let want: MemberMsg = read_frame(&mut recv).await.unwrap();
            assert!(
                matches!(want, MemberMsg::WantPack { .. }),
                "{case}: {want:?}"
            );
            let mut uni = conn.open_uni().await.unwrap();
            write_frame(&mut uni, &answer).await.unwrap();
            let _ = uni.finish();
            assert_eq!(
                close_of(&mut mem, grant_id).await.as_deref(),
                Some(word),
                "{case}"
            );
            assert_eq!(tip(&mem, sid).await, None, "{case}: not applied");
            assert_eq!(
                mem.store.substitute(&s, &snap.commit).await.unwrap(),
                None,
                "{case}: nothing kept"
            );
        }
    }

    /// P2f-2b — a target that holds every blob of a whole pack already has
    /// nothing to stand in for: it applies the checkpoint asking for nothing.
    #[tokio::test]
    async fn a_target_holding_the_whole_pack_asks_for_nothing() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let mem = packing_rig(false);
        let root = mem.root.path().to_path_buf();
        let sid = ObjectId::new();
        let s = sid.to_hex();
        let (_head, snap, whole) = checkpointed_repo(&root, sid);
        teleports_target(&mem, sid, true, true).await;
        for b in whole {
            mem.store.put_blob(&s, b).await.unwrap();
        }
        let env = workspace_event(sid, &snap);
        let (_peer, _grant_id, _conn, mut send, mut recv) = source_by_hand(&mem, sid).await;
        let hello = SourceMsg::Hello {
            v: wire::STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: true,
            stand_ins: Vec::new(),
        };
        write_frame(&mut send, &hello).await.unwrap();
        send_by_hand(&mut send, std::slice::from_ref(&env)).await;
        let ack: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert!(
            matches!(ack, MemberMsg::Ack { seq: 1, .. }),
            "applied, nothing asked: {ack:?}"
        );
        assert_eq!(mem.store.substitute(&s, &snap.commit).await.unwrap(), None);
    }

    /// P2f-2b — a member's `want_pack` is held to the wire's rules before a
    /// pack is made, and a stream carries one per commit, at most
    /// [`wire::MAX_WANTS`]: a want that names its commit among its haves, one for a
    /// commit asked already, and one past them end the stream `bad_frame`,
    /// unanswered. Each want before it is answered on a stream of its own.
    #[tokio::test]
    async fn a_want_that_breaks_the_wires_rules_ends_the_stream() {
        let (c, h) = ("c".repeat(40), "a".repeat(40));
        let want = |commit: &str, have: &str| MemberMsg::WantPack {
            commit: commit.to_string(),
            haves: vec![have.to_string()],
        };
        let many: Vec<MemberMsg> = (0..=wire::MAX_WANTS)
            .map(|i| want(&format!("{i:040x}"), &h))
            .collect();
        let cases = [
            ("its commit among its haves", vec![want(&c, &c)]),
            ("a commit asked again", vec![want(&c, &h), want(&c, &h)]),
            ("past the stream's wants", many),
        ];
        let mut src = rig(true, 4);
        for (case, wants) in cases {
            let sid = ObjectId::new();
            note(&src, sid, &["one"]);
            let g = grant(sid, HiveStreamPath::Direct);
            let grant_id = g.grant_id;
            let (_peer, conn, mut send, mut recv) =
                dial_by_hand(ready_of(&src, g, true).await).await;
            write_frame(&mut send, &empty_hello(sid)).await.unwrap();
            let _: SourceMsg = read_frame(&mut recv).await.unwrap();
            let (last, answered) = wants.split_last().unwrap();
            for w in answered {
                write_frame(&mut send, w).await.unwrap();
                let mut uni = conn
                    .accept_uni()
                    .await
                    .expect("each want before it answered");
                let answer: BlobMsg = read_frame(&mut uni).await.unwrap();
                assert!(
                    matches!(answer, BlobMsg::NoPack { .. }),
                    "{case}: {answer:?}"
                );
            }
            write_frame(&mut send, last).await.unwrap();
            assert_eq!(
                close_of(&mut src, grant_id).await.as_deref(),
                Some("bad_frame"),
                "{case}"
            );
            conn.close(0u32.into(), b"done");
        }
    }

    // ─── P2f-2c: a whole pack a source holds only a substitute for ─────────

    /// `src`'s copy of each of `sids`, as a teleport's target keeps one: the
    /// first checkpoint of the person's repository at `<root>/src`, its whole
    /// pack's own blobs NOT held, and a substitute for it against the
    /// person's `HEAD`. The workspace, the whole pack's blobs, and the
    /// substitute.
    async fn standing_in(
        src: &Rig,
        sids: &[ObjectId],
    ) -> (WorkspaceSnap, Vec<Vec<u8>>, Substitute) {
        let root = src.root.path().to_path_buf();
        let (head, snap, whole) = checkpointed_repo(&root, sids[0]);
        let (pack, against) = crate::hive::workspace::pack_against(
            &crate::hive::workspace::Git::under(&root),
            &root.join("src"),
            &root.join("src-state"),
            &snap.commit,
            std::slice::from_ref(&head),
        )
        .unwrap();
        let (chunks, blobs) = chunk_bytes(&pack);
        let sub = Substitute {
            commit: snap.commit.clone(),
            against,
            chunks,
        };
        for &sid in sids {
            let s = sid.to_hex();
            let cp = Checkpoint {
                n: 1,
                turn: 1,
                files: Vec::new(),
                skipped: Vec::new(),
                workspace: Some(snap.clone()),
            };
            put(src, sid, 1, TranscriptEvent::Checkpoint(cp));
            for b in &blobs {
                src.store.put_blob(&s, b.clone()).await.unwrap();
            }
            src.store.put_substitute(&s, sub.clone()).await.unwrap();
            src.sup.host_for_tests(sid);
        }
        (snap, whole, sub)
    }

    /// `src`'s answer to a want of `commit` with no haves, on a stream of
    /// `sid` dialed by hand: the hello it said, and the answer.
    async fn wanted_whole(
        src: &Rig,
        sid: ObjectId,
        commit: &str,
    ) -> (SourceMsg, BlobMsg, QuicConnection, SendStream) {
        let g = grant(sid, HiveStreamPath::Direct);
        let (_peer, conn, mut send, mut recv) = dial_by_hand(ready_of(src, g, true).await).await;
        write_frame(&mut send, &empty_hello(sid)).await.unwrap();
        let hello: SourceMsg = read_frame(&mut recv).await.unwrap();
        let want = MemberMsg::WantPack {
            commit: commit.to_string(),
            haves: Vec::new(),
        };
        write_frame(&mut send, &want).await.unwrap();
        let mut uni = conn.accept_uni().await.expect("an answer");
        let answer: BlobMsg = read_frame(&mut uni).await.unwrap();
        (hello, answer, conn, send)
    }

    /// P2f-2c — a source that holds a whole pack only as a substitute says
    /// so in its hello, and answers a want with no haves with that pack made
    /// again from its repository: whole, as many objects as the checkpoint's
    /// own pack, its chunks served as any blob. A want with no haves for a
    /// whole pack held by its own blobs is answered `held_whole`: those are
    /// there to ask for.
    #[tokio::test]
    async fn a_source_makes_again_the_whole_pack_it_holds_only_a_substitute_for() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let src = packing_rig(false);
        let root = src.root.path().to_path_buf();
        let stood = ObjectId::new();
        let (snap, whole, _sub) = standing_in(&src, &[stood]).await;
        src.sup.workplace_for_tests(
            stood,
            packer::Workplace {
                who: crate::hive::materializer::Who {
                    account: None,
                    env: Vec::new(),
                },
                folder: root.join("src"),
                state_dir: root.join("src-state"),
            },
        );
        let (hello, answer, conn, mut send) = wanted_whole(&src, stood, &snap.commit).await;
        assert!(
            matches!(&hello, SourceMsg::Hello { stand_ins, .. } if *stand_ins == [snap.commit.clone()]),
            "it says what it stands in for: {hello:?}"
        );
        let BlobMsg::Pack {
            commit,
            against,
            chunks,
        } = answer
        else {
            panic!("a pack: {answer:?}");
        };
        assert_eq!(
            (commit.as_str(), against.len()),
            (snap.commit.as_str(), 0),
            "whole, against nothing"
        );
        let need = MemberMsg::Need {
            blobs: chunks.iter().map(|c| c.hash).collect(),
        };
        write_frame(&mut send, &need).await.unwrap();
        let mut pack = Vec::new();
        for c in &chunks {
            let mut uni = conn
                .accept_uni()
                .await
                .expect("each of the pack's chunks, served as any blob");
            let BlobMsg::Blob { hash, len } = read_frame::<BlobMsg>(&mut uni).await.unwrap() else {
                panic!("a blob");
            };
            let mut bytes = vec![0u8; len as usize];
            uni.read_exact(&mut bytes).await.unwrap();
            assert_eq!((hash, Digest::of(&bytes)), (c.hash, c.hash));
            pack.extend(bytes);
        }
        let objects = |p: &[u8]| u32::from_be_bytes(p[8..12].try_into().unwrap());
        assert!(pack.starts_with(b"PACK"));
        assert_eq!(
            objects(&pack),
            objects(&whole.concat()),
            "as many objects as the checkpoint's own whole pack"
        );
        conn.close(0u32.into(), b"done");

        // The same whole pack, held by its own blobs.
        let held = ObjectId::new();
        for b in &whole {
            src.store.put_blob(&held.to_hex(), b.clone()).await.unwrap();
        }
        let cp = Checkpoint {
            n: 1,
            turn: 1,
            files: Vec::new(),
            skipped: Vec::new(),
            workspace: Some(snap.clone()),
        };
        put(&src, held, 1, TranscriptEvent::Checkpoint(cp));
        src.sup.host_for_tests(held);
        let (hello, answer, conn, _send) = wanted_whole(&src, held, &snap.commit).await;
        assert!(
            matches!(&hello, SourceMsg::Hello { stand_ins, .. } if stand_ins.is_empty()),
            "{hello:?}"
        );
        assert_eq!(
            answer,
            BlobMsg::NoPack {
                commit: snap.commit.clone(),
                why: "held_whole".into()
            }
        );
        conn.close(0u32.into(), b"done");
    }

    /// P2f-2c — a session that does not run on its source is packed for from
    /// where its last launch there kept it was worked on, as its account; one
    /// with nothing kept is answered `not_live`.
    #[tokio::test]
    async fn a_source_packs_from_where_a_session_no_longer_running_was_worked_on() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let src = packing_rig(false);
        let root = src.root.path().to_path_buf();
        let (kept, lost) = (ObjectId::new(), ObjectId::new());
        let (snap, _whole, _sub) = standing_in(&src, &[kept, lost]).await;
        let workplace = meshharbor_hive_node::store::WorkplaceRecord {
            account: "dev".into(),
            folder: root.join("src").display().to_string(),
            state_dir: root.join("src-state").display().to_string(),
        };
        src.store
            .put_workplace(&kept.to_hex(), workplace)
            .await
            .unwrap();
        let (_hello, answer, conn, _send) = wanted_whole(&src, kept, &snap.commit).await;
        assert!(
            matches!(&answer, BlobMsg::Pack { against, .. } if against.is_empty()),
            "from where it was kept: {answer:?}"
        );
        conn.close(0u32.into(), b"done");
        let (_hello, answer, conn, _send) = wanted_whole(&src, lost, &snap.commit).await;
        assert_eq!(
            answer,
            BlobMsg::NoPack {
                commit: snap.commit.clone(),
                why: "not_live".into()
            },
            "nothing kept"
        );
        conn.close(0u32.into(), b"done");
    }

    /// P2f-2c — a member asks a whole pack its source holds only a
    /// substitute for by a want with no haves, where it has none to offer;
    /// takes the pack the source makes again as any blobs, keeps it as a
    /// substitute against nothing, and applies the checkpoint. A source
    /// whose hello lists a stand-in that is no commit id is let go
    /// `bad_frame`, nothing taken from it.
    #[tokio::test]
    async fn a_member_asks_for_the_whole_pack_its_source_stands_in_for() {
        if !have_git() {
            return eprintln!("no git here");
        }
        // A member that holds copies: its owner's offer is what lets it follow.
        let mut mem = packing_rig(true);
        let root = mem.root.path().to_path_buf();
        let sid = ObjectId::new();
        let s = sid.to_hex();
        let (_head, snap, whole) = checkpointed_repo(&root, sid);
        mem.store.join(&s, "owner", 1).await.unwrap();
        let env = workspace_event(sid, &snap);
        let (_peer, _grant_id, conn, mut send, mut recv) = source_by_hand(&mem, sid).await;
        let hello = SourceMsg::Hello {
            v: wire::STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: true,
            stand_ins: vec![snap.commit.clone()],
        };
        write_frame(&mut send, &hello).await.unwrap();
        send_by_hand(&mut send, std::slice::from_ref(&env)).await;
        let want: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert_eq!(
            want,
            MemberMsg::WantPack {
                commit: snap.commit.clone(),
                haves: Vec::new(),
            },
            "a want with no haves: it has none to offer"
        );
        // Any pack of the commit does: the checkpoint's own bytes here.
        let (chunks, blobs) = chunk_bytes(&whole.concat());
        let mut uni = conn.open_uni().await.unwrap();
        let answer = BlobMsg::Pack {
            commit: snap.commit.clone(),
            against: Vec::new(),
            chunks: chunks.clone(),
        };
        write_frame(&mut uni, &answer).await.unwrap();
        let _ = uni.finish();
        let need: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert_eq!(
            need,
            MemberMsg::Need {
                blobs: chunks.iter().map(|c| c.hash).collect()
            }
        );
        let named: Vec<(Digest, Vec<u8>)> = chunks.iter().map(|c| c.hash).zip(blobs).collect();
        serve_by_hand(&conn, &named).await;
        let ack: MemberMsg = read_frame(&mut recv).await.unwrap();
        assert!(
            matches!(ack, MemberMsg::Ack { seq: 1, .. }),
            "applied: {ack:?}"
        );
        assert_eq!(
            mem.store.substitute(&s, &snap.commit).await.unwrap(),
            Some(Substitute {
                commit: snap.commit.clone(),
                against: Vec::new(),
                chunks,
            }),
            "kept, against nothing"
        );

        let other = ObjectId::new();
        mem.store.join(&other.to_hex(), "owner", 1).await.unwrap();
        let (_peer, grant_id, _conn, mut send, _recv) = source_by_hand(&mem, other).await;
        let hello = SourceMsg::Hello {
            v: wire::STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: true,
            stand_ins: vec!["HEAD".into()],
        };
        write_frame(&mut send, &hello).await.unwrap();
        assert_eq!(
            close_of(&mut mem, grant_id).await.as_deref(),
            Some("bad_frame"),
            "a stand-in that is no commit id"
        );
    }
}
