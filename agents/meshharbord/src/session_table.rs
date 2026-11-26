// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-130 — the org loop's remote-control sessions, kept through the loss of
//! the control socket. A port of upstream's FR-138 (P2a, P2a-2, P2b, P4-0 and
//! P4-1; the labels below, C1, L7, M1 and the like, are that work's review
//! findings).
//!
//! Until this, each connection owned its session map and every way it could
//! end closed every peer in it (`close_all_peers`), so a server restart ended
//! every live session although its pixels never crossed the server. The map now
//! lives in the org loop that redials ([`crate::signaling::run`]) and is lent to
//! each connection. A session in it is either **attached** to the current
//! connection or **kept** (detached) with a hard deadline, waiting for the next
//! connection's claim (`kept_sessions` in the hello), which the server answers
//! with `rc:session.resumed` or `rc:terminate`.
//!
//! Which way a connection ends decides ([`ConnExit::kind`]): the twelve exits
//! that lost only the path keep what can be kept, and the four that ended the
//! process, the machine's wake or the device's standing close every peer, kept
//! ones included. A refused token closes them too (`run`'s `AuthRejected`
//! arm).
//!
//! ⚠️ **Nothing leaves the table except through [`close_within_budget`].**
//! `AgentPeer`'s `Drop` does not close its `RTCPeerConnection`, and a WebRTC
//! peer that is dropped frees nothing: its UDP sockets belong to tasks its ICE
//! agent spawned. A kept peer that is dropped is exactly the leak that once ate
//! a host's ephemeral port range. So every path out of `kept` closes, the table
//! closes what it holds even when it is dropped, and a peer is kept only when
//! three things hold: the device's switch is on ([`survive_enabled`]), the
//! server this connection spoke to announced a window above 0, and the session
//! was live, its peer not dead.
//!
//! FR-130 P2b — on a supervised Mac a delegated session's peer lives in the GUI
//! worker, so the daemon's loop holds a RECORD of it instead ([`Record`]): no
//! peer, but the claim, the deadline and what the server must hear. The worker
//! keeps the peer on a delegated table of its own ([`SessionTable::for_worker`]),
//! driven by the daemon's orders (`Detached`, `Resumed`, `Close`, `Ended`), and
//! closes it there, through the same budget.
//!
//! Off is today: with the switch off, or no window ever announced, every exit
//! closes every peer as `close_all_peers` did, the same order, label and line.
//!
//! And the switch alone changes nothing else either (P4-0). The server's end
//! said peer to peer (C1), a delegated session offered `keepable` and its
//! record (P2b), and the daemon serving a message about a session it holds (A1)
//! each wait for a window this connection's server announced and has not
//! withdrawn ([`SessionTable::window_open`]). So a device the server announces
//! no window to behaves exactly as with the switch off, and the server alone
//! stages the fleet, the switch's default being on (P4-1).
//!
//! Never kept, whatever the window: an external session (FR-52) and one opened
//! through a device share, whose lease the centre must keep renewing.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bson::oid::ObjectId;
use meshharbor_remote_control::{
    models::{EndReason, RpcCap},
    signaling::ClientMsg,
};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::delegate::{DelegateHost, WorkerOrder};
use crate::peer::AgentPeer;
use crate::signaling::close_within_budget;

/// The device's own ceiling on the server's window: a wrong setting cannot keep
/// a peer for an hour. With [`crate::signaling`]'s close budget it bounds a kept
/// peer's life at 125 s from its detach (spec §4.9).
pub(crate) const WINDOW_CAP: Duration = Duration::from_secs(120);

/// How often a peer kept after a net change is looked at: it closes once its
/// connection leaves `Connected` (spec §4.2).
const NETCHANGE_LOOK_EVERY: Duration = Duration::from_millis(250);

/// A session's own queue, between the senders it holds and the connection's.
/// The connection's size (`PEER_OUTBOUND_CAP`).
const LINK_CAP: usize = 64;

/// What kept sessions' links hand the table: a session's own end, once, and
/// the activity its recording and its curtain report for the audit (L9).
const ENDED_CAP: usize = 64;

/// What the server must hear and that waits for room: an end, or a kept
/// session's report, on the current connection or the next one. No more than
/// the device's capacity can be live, so this is generous. Full, a report
/// goes before an end does.
const PENDING_CAP: usize = 64;

/// How long `rc:ended` may take on the control channel before the close goes
/// ahead without it: the idle warning's bound.
const SAY_BUDGET: Duration = Duration::from_secs(2);

/// The device's switch: `rc_sessions_survive_reattach` in the config, or
/// `MESHHARBORD_RC_SESSIONS_SURVIVE_REATTACH`. Default ON (P4-1): only `0`, `false`,
/// `no` or `off` turns it off, and an empty or unknown value is on. Device-side,
/// never pushable (`DesiredConfig` has no such field), read once per connection.
/// On, it says `rc-resume` and changes nothing else until a window is announced
/// (P4-0).
pub(crate) fn survive_enabled() -> bool {
    tunnel_core::env::flag("RC_SESSIONS_SURVIVE_REATTACH", true)
}

/// FR-130 P2b — whether this connection builds sessions it may keep: the
/// switch. P2b lifts P2a-2's L11 hold on a loop that holds the delegation host:
/// a supervised Mac's daemon keeps what it can (records for keepable delegated
/// sessions, peers for its own), and anything it cannot keep (an older
/// worker's session, none attached) it does not claim. Nothing new acts until
/// this connection's server announces a window ([`SessionTable::window_open`]).
pub(crate) fn connection_keeps(switch_on: bool, _delegation_host: bool) -> bool {
    switch_on
}

/// `rc-resume` in the hello's `AgentCaps.rpc`, and in every heartbeat that
/// re-announces the caps, exactly while the switch is on. Matched by equality on
/// both sides ([`RpcCap`]).
pub(crate) fn apply_resume_word(rpc: &mut Vec<String>, on: bool) {
    let word = RpcCap::RcResume.wire();
    if !on {
        rpc.retain(|w| w != word);
    } else if !rpc.iter().any(|w| w == word) {
        rpc.push(word.to_string());
    }
}

/// The sixteen ways a connection ends, one per arm of `connect_once` and
/// `handle_server_msg` that used to call `close_all_peers`. (Upstream counts
/// seventeen: its goodbye before a sleep, FR-55 P4, is not in this tree.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ConnExit {
    /// A stop, an update, a restart.
    Shutdown,
    /// A resume from suspend, at least `RESUME_SKEW_MIN` napped: read by the
    /// wall-clock check, or measured at the RX deadline where the monotonic
    /// clock counts the sleep ([`ConnExit::after_rx_deadline`]).
    ResumeFromSuspend,
    /// No inbound frame within the RX deadline.
    RxDeadline,
    /// The net-change probe, two strikes.
    NetChangeProbe,
    /// The net-change re-probe ping failed.
    NetChangeReprobe,
    /// The keepalive ping unanswered, two strikes.
    KeepaliveUnanswered,
    /// The keepalive ping could not be sent.
    KeepaliveSendFailed,
    /// The net-change probe ping could not be sent.
    NetChangePingFailed,
    /// The heartbeat could not be sent.
    HeartbeatSendFailed,
    /// A peer's message could not be flushed.
    OutboundFlushFailed,
    /// The pong reply failed.
    PongReplyFailed,
    /// The server closed the socket.
    ServerClosed,
    /// A read error. A roll takes this arm.
    ReadError,
    /// The pong RTT degraded, two strikes.
    PongRttDegraded,
    /// `rc:goodbye`: deleted, refused, displaced.
    Goodbye,
    /// FR-40's key rotation.
    KeyRotated,
}

/// What an exit means for the sessions the connection held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitKind {
    /// The process, the machine or the device's standing ended: every peer
    /// closes, kept ones included.
    Terminal,
    /// Only the path to the server ended: a session is kept for its claim.
    Transient,
    /// The path ended after the host's addresses moved: kept, but closed once
    /// its connection leaves `Connected`, since the RC path has no ICE restart.
    NetChange,
}

impl ConnExit {
    pub(crate) const ALL: [ConnExit; 16] = [
        ConnExit::Shutdown,
        ConnExit::ResumeFromSuspend,
        ConnExit::RxDeadline,
        ConnExit::NetChangeProbe,
        ConnExit::NetChangeReprobe,
        ConnExit::KeepaliveUnanswered,
        ConnExit::KeepaliveSendFailed,
        ConnExit::NetChangePingFailed,
        ConnExit::HeartbeatSendFailed,
        ConnExit::OutboundFlushFailed,
        ConnExit::PongReplyFailed,
        ConnExit::ServerClosed,
        ConnExit::ReadError,
        ConnExit::PongRttDegraded,
        ConnExit::Goodbye,
        ConnExit::KeyRotated,
    ];

    /// Spec §2.2 and §4.1. A resume from suspend stays terminal: after a nap
    /// that long the viewer's ICE consent has long failed.
    pub(crate) fn kind(self) -> ExitKind {
        match self {
            ConnExit::Shutdown
            | ConnExit::ResumeFromSuspend
            | ConnExit::Goodbye
            | ConnExit::KeyRotated => ExitKind::Terminal,
            ConnExit::NetChangeProbe
            | ConnExit::NetChangeReprobe
            | ConnExit::NetChangePingFailed => ExitKind::NetChange,
            ConnExit::RxDeadline
            | ConnExit::KeepaliveUnanswered
            | ConnExit::KeepaliveSendFailed
            | ConnExit::HeartbeatSendFailed
            | ConnExit::OutboundFlushFailed
            | ConnExit::PongReplyFailed
            | ConnExit::ServerClosed
            | ConnExit::ReadError
            | ConnExit::PongRttDegraded => ExitKind::Transient,
        }
    }

    /// The exit's name in the log lines, and the close's reason when it closes.
    pub(crate) fn label(self) -> &'static str {
        match self {
            ConnExit::Shutdown => "shutdown",
            ConnExit::ResumeFromSuspend => "resume_from_suspend",
            ConnExit::RxDeadline => "rx_deadline",
            ConnExit::NetChangeProbe => "netchange_probe",
            ConnExit::NetChangeReprobe => "netchange_reprobe",
            ConnExit::KeepaliveUnanswered => "keepalive_unanswered",
            ConnExit::KeepaliveSendFailed => "keepalive_send_failed",
            ConnExit::NetChangePingFailed => "netchange_ping_failed",
            ConnExit::HeartbeatSendFailed => "heartbeat_send_failed",
            ConnExit::OutboundFlushFailed => "outbound_flush_failed",
            ConnExit::PongReplyFailed => "pong_reply_failed",
            ConnExit::ServerClosed => "server_closed",
            ConnExit::ReadError => "read_error",
            ConnExit::PongRttDegraded => "pong_rtt_degraded",
            ConnExit::Goodbye => "goodbye",
            ConnExit::KeyRotated => "key_rotated",
        }
    }

    /// FR-130 P2b — the exit a daemon's `Detached` names, from its label. One
    /// this build does not know (a newer daemon's) reads as a transient exit,
    /// or a net change's when the order says the addresses moved, so the
    /// worker keeps what the daemon will claim and looks at it as it should.
    pub(crate) fn from_label(label: &str, netchange: bool) -> ConnExit {
        Self::ALL
            .into_iter()
            .find(|e| e.label() == label)
            .unwrap_or(if netchange {
                ConnExit::NetChangeProbe
            } else {
                ConnExit::ReadError
            })
    }

    /// P2a-2 (M2) — the exit the RX deadline's arm takes, from the pause its
    /// late keepalive tick measured (`tunnel_core::frozen::did_not_run_for`).
    /// Windows' monotonic clock counts a sleep, so there a resume from suspend
    /// never trips the wall-clock check (#3530): the RX deadline trips at the
    /// first keepalive after the wake instead. A pause of at least
    /// `RESUME_SKEW_MIN` is that resume, terminal as the wall-clock one is,
    /// since the viewer's ICE consent has long failed. A shorter pause, or
    /// none, stays the transient RX deadline.
    ///
    /// ⚠️ The seam upstream FR-140 (#3619) plugs into: it swaps the signal that
    /// measures `paused`, and this rule, FR-130's line, stays. Today's measure
    /// reads a freeze (SIGSTOP, a VM pause) that long as a pause too, after
    /// which the viewer's ICE consent has failed all the same.
    pub(crate) fn after_rx_deadline(paused: Option<Duration>) -> ConnExit {
        match paused {
            Some(paused) if paused >= crate::signaling::RESUME_SKEW_MIN => {
                ConnExit::ResumeFromSuspend
            }
            _ => ConnExit::RxDeadline,
        }
    }
}

/// What the table needs of a peer: [`AgentPeer`] in the daemon, a counting
/// stand-in in the tests, so that every path into Closed can be counted.
pub(crate) trait TablePeer: Send + Sync + 'static {
    /// Close the peer, and every socket its ICE agent owns with it. Only ever
    /// awaited through [`close_within_budget`].
    fn close(&self) -> impl Future<Output = ()> + Send + '_;
    /// Stop serving the session without closing its transport (FR-27 P10).
    fn stop_serving(&self);
    /// Whether the peer's connection is `Connected` now.
    fn is_connected(&self) -> bool;
    /// Say `text` on the session's control channel: best effort and bounded.
    fn say_on_control(&self, text: String) -> impl Future<Output = ()> + Send + '_;
    /// Whether the peer's connection is `Failed` or `Closed`: it cannot come
    /// back (M1).
    fn is_dead(&self) -> bool;
    /// FR-101 P3 — the audit's last sample, taken before the close. `None` when
    /// there is nothing worth it (the stand-in in the tests has none).
    fn final_stats(
        &self,
        session_id: ObjectId,
    ) -> impl Future<Output = Option<ClientMsg>> + Send + '_ {
        let _ = session_id;
        async { None }
    }
}

impl TablePeer for AgentPeer {
    fn final_stats(
        &self,
        session_id: ObjectId,
    ) -> impl Future<Output = Option<ClientMsg>> + Send + '_ {
        crate::signaling::final_session_stats(session_id, self)
    }

    fn close(&self) -> impl Future<Output = ()> + Send + '_ {
        AgentPeer::close(self)
    }

    fn stop_serving(&self) {
        AgentPeer::stop_serving(self)
    }

    fn is_connected(&self) -> bool {
        AgentPeer::is_connected(self)
    }

    fn is_dead(&self) -> bool {
        AgentPeer::is_dead(self)
    }

    fn say_on_control(&self, text: String) -> impl Future<Output = ()> + Send + '_ {
        // The stash the idle warning rides: the control channel, once the
        // viewer opened it.
        let (_, control) = self.idle_handles();
        async move {
            let dc = control.lock().await.clone();
            if let Some(dc) = dc {
                let _ = tokio::time::timeout(SAY_BUDGET, dc.send_text(text)).await;
            }
        }
    }
}

/// Which end a session met, for what follows it beyond the close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RealEnd {
    /// The server's end, a deadline, a terminal exit: a recording waits for
    /// its controller (FR-85's grace).
    Ended,
    /// The person at the device ended it (Disconnect, the idle limit): a
    /// recording stops now.
    HostEnded,
}

/// What a session's REAL end does beyond closing its peer: the recording's
/// end, and the banner, whose last end may lock the screen (FR-99). A detach
/// calls none of it: the session is live and its pixels still flow.
pub(crate) type EndHook = Arc<dyn Fn(ObjectId, RealEnd) + Send + Sync>;

/// The daemon's [`EndHook`], what `close_all_peers` did for every session.
pub(crate) fn real_end_hook(indicator: crate::indicator::ViewerIndicator) -> EndHook {
    Arc::new(move |session_id, end| {
        #[cfg(feature = "recording")]
        match end {
            RealEnd::Ended => crate::recording::remote::session_ended(session_id),
            RealEnd::HostEnded => crate::recording::remote::host_ended(session_id),
        }
        #[cfg(not(feature = "recording"))]
        let _ = end;
        indicator.hide_session(session_id.to_hex());
    })
}

/// FR-130 — one session's sender, re-pointable.
///
/// Every sender the session holds is a clone of [`Self::sender`]: the
/// `AgentPeer` (its ICE-candidate handler, the state handler that sends
/// `Terminate` on `Failed`, the watchdog), its `record` context and its
/// `privacy` reporter. A task forwards what they send to the connection the
/// table points the link at, and the table points it at each new connection.
/// While the session is kept the link drops what it is given and never waits,
/// except what the server must hear anyway, which it hands to the table: the
/// session's own `Terminate` (the table closes the peer and queues the end),
/// and its recording's and curtain's activity (queued for the audit, L9).
pub(crate) struct SessionLink {
    tx: mpsc::Sender<ClientMsg>,
    route: watch::Sender<Route>,
}

#[derive(Clone)]
enum Route {
    /// This connection's outbound queue.
    To(mpsc::Sender<ClientMsg>),
    /// No connection: nobody reads what the session says.
    Kept,
}

impl SessionLink {
    /// `own_end_to_table`: the session's own end goes to the table in both
    /// routes, attached too (FR-130 P2b).
    fn new(
        session_id: ObjectId,
        to: mpsc::Sender<ClientMsg>,
        ended: mpsc::Sender<(ObjectId, ClientMsg)>,
        own_end_to_table: bool,
    ) -> Self {
        let (tx, rx) = mpsc::channel(LINK_CAP);
        let (route, route_rx) = watch::channel(Route::To(to));
        tokio::spawn(forward(session_id, rx, route_rx, ended, own_end_to_table));
        Self { tx, route }
    }

    /// The sender every holder of the session clones.
    pub(crate) fn sender(&self) -> mpsc::Sender<ClientMsg> {
        self.tx.clone()
    }

    fn point_at(&self, to: mpsc::Sender<ClientMsg>) {
        self.route.send_replace(Route::To(to));
    }

    fn keep(&self) {
        self.route.send_replace(Route::Kept);
    }
}

/// `msg` is the session's own end: its state handler's `Terminate` on `Failed`,
/// or its watchdog's.
fn is_own_end(msg: &ClientMsg, session_id: ObjectId) -> bool {
    matches!(msg, ClientMsg::Terminate { session_id: s, .. } if *s == session_id)
}

/// P2a-2 (L9) — what a kept session says that the server must still hear: its
/// own end, and the activity its recording and its curtain report for the
/// audit. The server keeps the host's claims apart from its own decisions, so
/// a report dropped in a gap is a hole in that record.
fn heard_while_kept(msg: &ClientMsg, session_id: ObjectId) -> bool {
    is_own_end(msg, session_id)
        || matches!(
            msg,
            ClientMsg::RecordingActivity { .. } | ClientMsg::PrivacyActivity { .. }
        )
}

/// The link's task. While attached it waits for room on the connection's queue
/// as a direct send did, and moves the moment the route does, so a send that was
/// waiting on a connection that died is never stuck. While kept it never waits:
/// what the server must hear goes to the table, and the rest is dropped.
async fn forward(
    session_id: ObjectId,
    mut rx: mpsc::Receiver<ClientMsg>,
    mut route: watch::Receiver<Route>,
    ended: mpsc::Sender<(ObjectId, ClientMsg)>,
    own_end_to_table: bool,
) {
    // `false` once the table let the link go (its session closed): the route
    // stays where it last was, as a direct send's would.
    let mut movable = true;
    while let Some(msg) = rx.recv().await {
        // FR-130 P2b — a record's or a worker's delegated session: its own end
        // is the table's in both routes. A full table queue routes it as
        // before, so it is never lost to the table's being busy.
        let msg = if own_end_to_table && is_own_end(&msg, session_id) {
            match ended.try_send((session_id, msg)) {
                Ok(()) => continue,
                Err(e) => e.into_inner().1,
            }
        } else {
            msg
        };
        let mut next = Some(msg);
        while let Some(msg) = next.take() {
            let to = route.borrow_and_update().clone();
            match to {
                Route::Kept => {
                    // Never waits: a full queue costs the report, and the
                    // deadline still closes the peer.
                    if heard_while_kept(&msg, session_id)
                        && ended.try_send((session_id, msg)).is_err()
                    {
                        debug!(
                            session_id = %session_id,
                            "rc: a kept session's report met a full table queue; dropped (FR-130)"
                        );
                    }
                }
                Route::To(tx) if movable => tokio::select! {
                    biased;
                    moved = route.changed() => {
                        if moved.is_err() {
                            movable = false;
                        }
                        next = Some(msg);
                    }
                    permit = tx.reserve() => match permit {
                        Ok(permit) => permit.send(msg),
                        // The connection is gone. A route that moved meanwhile
                        // takes the message; otherwise it is dropped, as a send
                        // into a closed queue was.
                        Err(_) => {
                            if route.has_changed().unwrap_or(false) {
                                next = Some(msg);
                            }
                        }
                    },
                },
                Route::To(tx) => {
                    let _ = tx.send(msg).await;
                }
            }
        }
    }
}

/// `rc:ended` on the control channel: the session's end, said peer to peer,
/// because the viewer's signalling cannot reach it during the gap (spec §4.3).
/// The same `reason` and `limit` the `rc:terminate` carries.
fn ended_text(terminate: &ClientMsg) -> Option<String> {
    let ClientMsg::Terminate { reason, limit, .. } = terminate else {
        return None;
    };
    Some(ended_json(reason, limit.as_deref()))
}

/// The `rc:ended` frame itself, `{"t":"rc:ended","reason":…,"limit"?:…}`, as
/// the viewer parses it (`parseControlInbound`, `useRemoteControl.ts`).
fn ended_json(reason: &EndReason, limit: Option<&str>) -> String {
    let mut said = serde_json::json!({ "t": "rc:ended", "reason": reason });
    if let Some(limit) = limit {
        said["limit"] = serde_json::Value::from(limit);
    }
    said.to_string()
}

/// An end for the server about a session the table no longer holds: gone at
/// its deadline, or dead (M1).
fn gone(session_id: ObjectId, reason: EndReason) -> ClientMsg {
    ClientMsg::Terminate {
        session_id,
        reason,
        limit: None,
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A session attached to the current connection.
struct Live<P> {
    peer: P,
    /// `None`: never kept. A delegated session (FR-43), an external one
    /// (FR-52, D3), one opened through a device share, or one built while
    /// the switch was off.
    link: Option<SessionLink>,
}

/// A session kept through the loss of its connection.
struct Kept<P> {
    peer: P,
    link: SessionLink,
    since: Instant,
    /// Set once, at the detach. No reconnect moves it: a claim the server has
    /// not answered by then is a claim refused.
    deadline: Instant,
    /// Detached by a net-change exit: closed once it leaves `Connected`.
    netchange: bool,
    exit: ConnExit,
}

/// FR-130 P2b — the daemon's record of a delegated session it will claim. The
/// GUI worker holds the peer, while the claim, the deadline and what the server
/// must hear are the daemon's.
struct Record {
    /// Where the worker's replies about the session go
    /// ([`DelegateHost::bind`]): to the connection while attached; while kept,
    /// what the server must hear goes to the table and the rest is dropped.
    link: SessionLink,
    /// `None` while attached.
    kept: Option<RecordKept>,
    /// The attach generation it was made under ([`DelegateHost::generation`]):
    /// a record of an older one belongs to a worker that is gone (A9).
    generation: u64,
}

/// FR-130 P2b — a record kept through the loss of its connection.
struct RecordKept {
    since: Instant,
    /// Set once, at the detach; the worker was sent the same window.
    deadline: Instant,
    exit: ConnExit,
}

/// What the table must act on next ([`SessionTable::next_event`]).
#[derive(Debug)]
pub(crate) enum TableEvent {
    /// A kept session's deadline passed.
    Deadline,
    /// A kept session's peer said its own end (it failed).
    Ended(ObjectId, Box<ClientMsg>),
    /// A kept session reported activity for the audit (L9).
    Report(Box<ClientMsg>),
    /// This connection's queue has room for what waits (L7). `None`: the
    /// queue closed, and what waits goes on the next connection.
    Room(Option<mpsc::OwnedPermit<ClientMsg>>),
    /// Time to look at the peers kept after a net change.
    Look,
}

/// FR-130 — the org loop's remote-control sessions. See the module doc.
pub(crate) struct SessionTable<P: TablePeer = AgentPeer> {
    attached: HashMap<ObjectId, Live<P>>,
    kept: HashMap<ObjectId, Kept<P>>,
    /// What the server must hear and that waits for room on this
    /// connection's queue, or for the next connection, in order (L7): ends
    /// said at the device, a kept session's own end and its reports, the
    /// answer for a claim the device can no longer honour.
    pending_ends: VecDeque<ClientMsg>,
    /// This connection's switch.
    survive: bool,
    /// The window the server this connection speaks to announced, capped;
    /// `None` = none, or withdrawn.
    window: Option<Duration>,
    /// This connection's outbound queue, while one is up.
    current: Option<mpsc::Sender<ClientMsg>>,
    /// `rc_max_sessions`: kept sessions count against it.
    capacity: usize,
    on_end: EndHook,
    ended_tx: mpsc::Sender<(ObjectId, ClientMsg)>,
    ended_rx: mpsc::Receiver<(ObjectId, ClientMsg)>,
    /// The next look at the peers kept after a net change. An instant, not a
    /// period: a loop that comes round often must not push it back.
    next_look: Option<Instant>,
    /// FR-130 P2b — the daemon's records of the delegated sessions it will
    /// claim. Empty everywhere but a loop that holds the delegation host.
    records: HashMap<ObjectId, Record>,
    /// FR-130 P2b — the delegation host, for a loop that holds it: where the
    /// records' links are bound and the worker's orders go.
    host: Option<DelegateHost>,
    /// FR-130 P2b — this is a GUI worker's delegated table: its sessions are
    /// the daemon's to claim, and its peers close themselves on their own end
    /// (B6).
    worker: bool,
}

impl<P: TablePeer> SessionTable<P> {
    pub(crate) fn new(capacity: usize, on_end: EndHook) -> Self {
        let (ended_tx, ended_rx) = mpsc::channel(ENDED_CAP);
        Self {
            attached: HashMap::new(),
            kept: HashMap::new(),
            pending_ends: VecDeque::new(),
            survive: false,
            window: None,
            current: None,
            capacity: capacity.max(1),
            on_end,
            ended_tx,
            ended_rx,
            next_look: None,
            records: HashMap::new(),
            host: None,
            worker: false,
        }
    }

    /// FR-130 P2b (B1) — a GUI worker's delegated table: the sessions the
    /// daemon said it will claim through its control-socket loss. Its switch is
    /// on, since the daemon's decided it, and what it says goes up `channel`,
    /// the delegation channel, which spans the worker's own connections.
    pub(crate) fn for_worker(
        capacity: usize,
        on_end: EndHook,
        channel: &mpsc::Sender<ClientMsg>,
    ) -> Self {
        let mut table = Self::new(capacity, on_end);
        table.survive = true;
        table.current = Some(channel.clone());
        table.worker = true;
        table
    }

    /// FR-130 P2b — this loop holds the delegation host: its records' links
    /// are bound there, and its orders go to the attached worker.
    pub(crate) fn set_host(&mut self, host: DelegateHost) {
        self.host = Some(host);
    }

    /// FR-130 P2b (A3) — the gate crossed `session_id`'s offer to the worker:
    /// a session whose params crossed `keepable` gets a record, attached to
    /// this connection, and the worker's replies about it are bound to the
    /// record's link. Anything else (the switch off, no window open on this
    /// connection, an older worker, no connection) gets none and is served as
    /// today. `generation` is the attach generation the gate read
    /// ([`Self::live_generation`]).
    pub(crate) fn cross_offer(&mut self, session_id: ObjectId, generation: Option<u64>) {
        let Some(host) = self.host.clone() else {
            return;
        };
        let hex = session_id.to_hex();
        if !self.window_open() || !host.is_keepable(&hex) {
            return;
        }
        let (Some(current), Some(generation)) = (self.current.clone(), generation) else {
            return;
        };
        let link = SessionLink::new(session_id, current, self.ended_tx.clone(), true);
        host.bind(hex, link.sender());
        if self
            .records
            .insert(
                session_id,
                Record {
                    link,
                    kept: None,
                    generation,
                },
            )
            .is_some()
        {
            debug!(session_id = %session_id, "rc: a delegated session re-offered; its record replaced (FR-130)");
        }
        info!(
            session_id = %session_id,
            generation,
            "rc: a delegated session the daemon will claim through its control socket's loss; \
             the GUI worker keeps its peer (FR-130 P2b)"
        );
    }

    /// FR-130 P2b — whether the table keeps a record of this delegated session.
    #[cfg(test)]
    pub(crate) fn holds_record(&self, session_id: &ObjectId) -> bool {
        self.records.contains_key(session_id)
    }

    /// FR-130 P2b (A7) — the server ended a delegated session, `reason` and
    /// `limit` its `rc:terminate`'s: its record goes, the worker is ORDERED to
    /// end it (`Ended`), and the `Terminate` crosses to it as today.
    pub(crate) fn drop_record(
        &mut self,
        session_id: &ObjectId,
        reason: &EndReason,
        limit: Option<&str>,
    ) {
        let live = self.live_generation();
        let Some(record) = self.records.remove(session_id) else {
            return;
        };
        let mut told = false;
        if let Some(host) = &self.host {
            let hex = session_id.to_hex();
            host.unbind(&hex);
            if Some(record.generation) == live {
                told = host.send_order(crate::delegate::DelegateFrame::Ended {
                    session_id: hex,
                    reason: *reason,
                    limit: limit.map(str::to_string),
                });
            }
        }
        info!(
            session_id = %session_id,
            ?reason,
            ?limit,
            told,
            kept_ms = record.kept.as_ref().map(|k| millis(k.since.elapsed())),
            "rc session closed (delegated): the server ended it; the GUI worker is told and \
             closes its peer (FR-130 P2b)"
        );
    }

    /// FR-130 P2b — the GUI worker's delegated table.
    pub(crate) fn is_worker(&self) -> bool {
        self.worker
    }

    /// FR-130 P2b (B5) — the worker's half of a detach: the daemon's
    /// `Detached` names the sessions it will claim, and only those are kept,
    /// until `window` from now at most ([`WINDOW_CAP`]).
    pub(crate) async fn detach_named(
        &mut self,
        sessions: &[ObjectId],
        exit: ConnExit,
        window: Duration,
    ) {
        let window = window.min(WINDOW_CAP);
        let now = Instant::now();
        let netchange = exit.kind() == ExitKind::NetChange;
        let mut closing: Vec<(ObjectId, P, &'static str, EndReason)> = Vec::new();
        for session_id in sessions {
            let Some(live) = self.attached.remove(session_id) else {
                debug!(
                    session_id = %session_id,
                    "rc: a detach names a session this table does not hold attached (FR-130 P2b)"
                );
                continue;
            };
            let Some(link) = live.link else {
                closing.push((
                    *session_id,
                    live.peer,
                    "ws_disconnect",
                    EndReason::AgentDisconnect,
                ));
                continue;
            };
            if live.peer.is_dead() {
                closing.push((*session_id, live.peer, "dead", EndReason::Error));
                continue;
            }
            if self.kept.len() >= self.capacity {
                closing.push((
                    *session_id,
                    live.peer,
                    "over_capacity",
                    EndReason::AgentDisconnect,
                ));
                continue;
            }
            if netchange && !live.peer.is_connected() {
                closing.push((
                    *session_id,
                    live.peer,
                    "netchange_not_connected",
                    EndReason::AgentDisconnect,
                ));
                continue;
            }
            link.keep();
            info!(
                session_id = %session_id,
                exit = exit.label(),
                window_s = window.as_secs(),
                netchange,
                "rc session detached (delegated): the daemon will claim it; its peer is kept for \
                 the daemon's window at most (FR-130 P2b)"
            );
            self.kept.insert(
                *session_id,
                Kept {
                    peer: live.peer,
                    link,
                    since: now,
                    deadline: now + window,
                    netchange,
                    exit,
                },
            );
        }
        if netchange && self.next_look.is_none() {
            self.next_look = Some(now + NETCHANGE_LOOK_EVERY);
        }
        for (session_id, peer, why, reason) in closing {
            (self.on_end)(session_id, RealEnd::Ended);
            info!(
                session_id = %session_id,
                why,
                exit = exit.label(),
                "rc session closed at the daemon's detach: it could not be kept (FR-130 P2b)"
            );
            close_within_budget(peer.close(), session_id, why).await;
            self.queue_end(gone(session_id, reason));
        }
    }

    /// FR-130 P2b (B5) — the daemon's `Close`: the session closes, with its real
    /// end, and nothing goes up (the daemon decided).
    pub(crate) async fn close_session(&mut self, session_id: ObjectId, why: &'static str) {
        if self.kept.contains_key(&session_id) {
            return self.close_kept(session_id, why).await;
        }
        let Some(live) = self.attached.remove(&session_id) else {
            debug!(session_id = %session_id, why, "rc: a close for a session this table does not hold (FR-130 P2b)");
            return;
        };
        (self.on_end)(session_id, RealEnd::Ended);
        info!(
            session_id = %session_id,
            why,
            "rc session closed (delegated): the daemon closed it (FR-130 P2b)"
        );
        close_within_budget(live.peer.close(), session_id, why).await;
    }

    /// FR-130 P2b (B9, D5) — the attached sessions' links stop waiting on the
    /// channel, and hand the table what the server must hear, until
    /// [`Self::unpause`].
    pub(crate) fn pause(&mut self) {
        for live in self.attached.values() {
            if let Some(link) = &live.link {
                link.keep();
            }
        }
    }

    /// FR-130 P2b (review MEDIUM-1) — the channel to the daemon ended, `cause`
    /// its why, and this process lives on: close every delegated session,
    /// attached and kept, and tell the daemon each is gone (`agent_disconnect`).
    pub(crate) async fn close_at_channel_end(&mut self, cause: &str) {
        self.pause();
        let attached: Vec<(ObjectId, Live<P>)> = self.attached.drain().collect();
        let kept: Vec<ObjectId> = self.kept.keys().copied().collect();
        if attached.is_empty() && kept.is_empty() {
            return;
        }
        info!(
            cause,
            attached = attached.len(),
            kept = kept.len(),
            "rc: the channel to the daemon ended; its delegated sessions close, since the daemon \
             ended each as `error` (FR-130 P2b)"
        );
        for (session_id, live) in attached {
            info!(
                session_id = %session_id,
                cause,
                "rc session closed (delegated, attached): the channel to the daemon ended \
                 (FR-130 P2b)"
            );
            (self.on_end)(session_id, RealEnd::Ended);
            close_within_budget(live.peer.close(), session_id, "channel_ended").await;
            self.queue_end(gone(session_id, EndReason::AgentDisconnect));
        }
        for session_id in kept {
            info!(
                session_id = %session_id,
                cause,
                "rc session closed (delegated, kept): the channel to the daemon ended \
                 (FR-130 P2b)"
            );
            self.close_kept(session_id, "channel_ended").await;
            self.queue_end(gone(session_id, EndReason::AgentDisconnect));
        }
    }

    /// FR-130 P2b (review HIGH-1) — the daemon's `Ended`: the server ended a
    /// session this worker table holds, attached or kept.
    pub(crate) async fn end_ordered(
        &mut self,
        session_id: ObjectId,
        reason: &EndReason,
        limit: Option<&str>,
        grace: Duration,
    ) -> bool {
        let Some(peer) = self.take(&session_id, "ended") else {
            debug!(
                session_id = %session_id,
                "rc: the daemon's end of a delegated session this table no longer holds (FR-130 P2b)"
            );
            return false;
        };
        (self.on_end)(session_id, RealEnd::Ended);
        if let Some(stats) = peer.final_stats(session_id).await {
            self.queue_end(stats);
        }
        info!(
            session_id = %session_id,
            ?reason,
            ?limit,
            "rc session closed (delegated): the daemon ordered its end; said on its control \
             channel, the peer closes after the grace (FR-130 P2b)"
        );
        self.close_terminated(peer, session_id, reason, limit, grace)
            .await;
        true
    }

    /// FR-130 P2b (B9) — the channel is back: the attached sessions' links
    /// point at it.
    pub(crate) fn unpause(&mut self) {
        let Some(to) = self.current.clone() else {
            return;
        };
        for live in self.attached.values() {
            if let Some(link) = &live.link {
                link.point_at(to.clone());
            }
        }
    }

    /// FR-130 P2b (B4, B5) — one of the daemon's orders, on a GUI worker's
    /// delegated table.
    pub(crate) async fn obey(
        &mut self,
        order: WorkerOrder,
        channel: &mpsc::Sender<ClientMsg>,
        grace: Duration,
    ) {
        let parse = |s: &str| ObjectId::parse_str(s).ok();
        match order {
            WorkerOrder::Detached {
                sessions,
                exit,
                netchange,
                keep_ms,
            } => {
                let ids: Vec<ObjectId> = sessions.iter().filter_map(|s| parse(s)).collect();
                let exit = ConnExit::from_label(&exit, netchange);
                self.detach_named(&ids, exit, Duration::from_millis(keep_ms))
                    .await;
            }
            WorkerOrder::Resumed { session_id } => {
                if let Some(sid) = parse(&session_id) {
                    self.resume(sid, channel).await;
                }
            }
            WorkerOrder::Close { session_id, reason } => {
                if let Some(sid) = parse(&session_id) {
                    info!(session_id = %sid, %reason, "rc: the daemon closes a delegated session (FR-130 P2b)");
                    self.close_session(sid, "daemon_close").await;
                }
            }
            WorkerOrder::Ended {
                session_id,
                reason,
                limit,
            } => {
                if let Some(sid) = parse(&session_id) {
                    self.end_ordered(sid, &reason, limit.as_deref(), grace)
                        .await;
                }
            }
            WorkerOrder::Paused { cause } => self.close_at_channel_end(&cause).await,
            WorkerOrder::Attached => self.unpause(),
        }
    }

    /// FR-130 P2b (B7) — the person at the device ended a session (Disconnect,
    /// the idle limit) that this table holds: kept (any table), or attached on
    /// a GUI worker's delegated table.
    pub(crate) fn end_by_device(
        &mut self,
        session_id: ObjectId,
        terminate: ClientMsg,
        why: &'static str,
        grace: Duration,
    ) -> bool {
        if self.kept.contains_key(&session_id) {
            return self.end_kept_by_device(session_id, terminate, why, grace);
        }
        if !self.worker {
            return false;
        }
        let Some(live) = self.attached.remove(&session_id) else {
            return false;
        };
        (self.on_end)(session_id, RealEnd::HostEnded);
        live.peer.stop_serving();
        info!(
            session_id = %session_id,
            why,
            grace_ms = millis(grace),
            "rc session closed (delegated): ended at the device; its end goes up the channel and \
             the peer closes after the grace (FR-130 P2b)"
        );
        let Live { peer, link } = live;
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            close_within_budget(peer.close(), session_id, why).await;
            drop(link);
        });
        self.queue_end(terminate);
        true
    }

    /// FR-130 P2b (A9) — the attach generation of the worker attached now.
    /// `None` for a loop that does not hold the delegation host.
    pub(crate) fn live_generation(&self) -> Option<u64> {
        self.host.as_ref().map(DelegateHost::generation)
    }

    /// FR-130 P2b (A9) — the records whose worker is still the one attached.
    fn live_records(&self) -> impl Iterator<Item = (&ObjectId, &Record)> {
        let live = self.live_generation();
        self.records
            .iter()
            .filter(move |(_, r)| Some(r.generation) == live)
    }

    /// FR-130 P2b — a record leaves: its replies are unbound, and its worker
    /// told to close the peer.
    fn close_record(&mut self, session_id: ObjectId, why: &'static str) {
        let Some(record) = self.records.remove(&session_id) else {
            return;
        };
        if let Some(host) = &self.host {
            let hex = session_id.to_hex();
            host.unbind(&hex);
            host.send_order(crate::delegate::DelegateFrame::Close {
                session_id: hex,
                reason: why.to_string(),
            });
        }
        info!(
            session_id = %session_id,
            why,
            kept_ms = record.kept.as_ref().map(|k| millis(k.since.elapsed())),
            "rc session closed (delegated): its record ended; the GUI worker closes its peer \
             (FR-130 P2b)"
        );
    }

    /// FR-130 P2b (A9) — the records of a worker that is gone leave.
    fn prune_records(&mut self) {
        let live = self.live_generation();
        let stale: Vec<ObjectId> = self
            .records
            .iter()
            .filter(|(_, r)| Some(r.generation) != live)
            .map(|(s, _)| *s)
            .collect();
        for session_id in stale {
            self.close_record(session_id, "worker_gone");
            self.queue_end(gone(session_id, EndReason::Error));
        }
    }

    /// FR-130 P2b (A4) — the daemon's half of a transient exit with a window:
    /// every attached record of the worker attached now is kept with the same
    /// deadline, and the worker gets one `Detached` naming them.
    fn detach_records(&mut self, exit: ConnExit, window: Duration, now: Instant) {
        self.prune_records();
        let Some(host) = self.host.clone() else {
            return;
        };
        let mut attached: Vec<ObjectId> = self
            .records
            .iter()
            .filter(|(_, r)| r.kept.is_none())
            .map(|(s, _)| *s)
            .collect();
        if attached.is_empty() {
            return;
        }
        attached.sort();
        let mut kept = self.kept.len() + self.records.values().filter(|r| r.kept.is_some()).count();
        let mut detached: Vec<String> = Vec::new();
        let mut closing: Vec<ObjectId> = Vec::new();
        for session_id in attached {
            if kept >= self.capacity {
                closing.push(session_id);
                continue;
            }
            let Some(record) = self.records.get_mut(&session_id) else {
                continue;
            };
            record.link.keep();
            record.kept = Some(RecordKept {
                since: now,
                deadline: now + window,
                exit,
            });
            kept += 1;
            info!(
                session_id = %session_id,
                exit = exit.label(),
                window_s = window.as_secs(),
                "rc session detached (delegated): the GUI worker keeps its peer until the server \
                 answers the claim, for the window at most (FR-130 P2b)"
            );
            detached.push(session_id.to_hex());
        }
        if !detached.is_empty() {
            let count = detached.len();
            let told = host.send_order(crate::delegate::DelegateFrame::Detached {
                sessions: detached,
                exit: exit.label().to_string(),
                netchange: exit.kind() == ExitKind::NetChange,
                keep_ms: millis(window),
            });
            if !told {
                warn!(
                    count,
                    "rc: the GUI worker could not be told of the detach; it keeps serving its \
                     sessions until the daemon's next order (FR-130 P2b)"
                );
            }
        }
        for session_id in closing {
            self.close_record(session_id, "over_capacity");
        }
    }

    /// FR-130 P2b (A6) — the server accepted the claim of a record.
    fn resume_record(&mut self, session_id: ObjectId, outbound: &mpsc::Sender<ClientMsg>) -> bool {
        let live = self.live_generation();
        let Some(record) = self.records.get_mut(&session_id) else {
            return false;
        };
        let Some(kept) = &record.kept else {
            debug!(session_id = %session_id, "rc:session.resumed for a delegated session already attached");
            return true;
        };
        let refused = if Some(record.generation) != live {
            Some("worker_gone")
        } else if Instant::now() >= kept.deadline {
            Some("claim_late")
        } else {
            None
        };
        if let Some(why) = refused {
            self.close_record(session_id, why);
            self.queue_end(gone(session_id, EndReason::AgentDisconnect));
            return false;
        }
        let (exit, since) = (kept.exit, kept.since);
        record.link.point_at(outbound.clone());
        record.kept = None;
        let told = self.host.as_ref().is_some_and(|h| {
            h.send_order(crate::delegate::DelegateFrame::Resumed {
                session_id: session_id.to_hex(),
            })
        });
        info!(
            session_id = %session_id,
            exit = exit.label(),
            kept_ms = millis(since.elapsed()),
            told,
            "rc session resumed (delegated): re-attached to the new connection; the GUI worker \
             told (FR-130 P2b)"
        );
        true
    }

    /// A connection is up: its switch, read once. The window starts unannounced
    /// and the deadlines that already passed close here. With the switch off
    /// nothing kept can be claimed, so it closes. Returns the claim, the hello's
    /// `kept_sessions`.
    pub(crate) async fn begin_connection(&mut self, survive: bool) -> Vec<ObjectId> {
        self.survive = survive;
        self.window = None;
        self.current = None;
        // FR-130 P2b (A9) — what a gone worker held is never claimed.
        self.prune_records();
        self.close_due().await;
        if !survive {
            let kept: Vec<ObjectId> = self.kept.keys().copied().collect();
            for session_id in kept {
                self.close_kept(session_id, "switch_off").await;
            }
            let kept: Vec<ObjectId> = self
                .records
                .iter()
                .filter(|(_, r)| r.kept.is_some())
                .map(|(s, _)| *s)
                .collect();
            for session_id in kept {
                self.close_record(session_id, "switch_off");
            }
        }
        self.kept_ids()
    }

    /// The hello went out on a connection whose queue is `outbound`: what the
    /// device ended during the gap follows it, the way FR-40 says its rotation
    /// again.
    pub(crate) fn connected(&mut self, outbound: &mpsc::Sender<ClientMsg>) {
        self.current = Some(outbound.clone());
        self.flush_pending();
    }

    /// Whether this connection builds sessions it may keep: its switch.
    pub(crate) fn keeps_sessions(&self) -> bool {
        self.survive
    }

    /// FR-130 P4-0 — this connection's server announced a window and has not
    /// withdrawn it. What everything new waits for, where the switch alone
    /// once decided: the server's end said peer to peer (C1,
    /// [`Self::close_terminated`]), a delegated session offered `keepable` and
    /// its record ([`Self::cross_offer`]), and the daemon serving a session it
    /// holds ([`Self::keeping`]).
    pub(crate) fn window_open(&self) -> bool {
        self.survive && self.window.is_some()
    }

    /// FR-130 P4-0 — A1's gate (`crate::delegate::served_by_daemon`): this loop
    /// keeps sessions now. A window is open, or a session is still kept from an
    /// earlier connection, whose peer is this loop's to close.
    pub(crate) fn keeping(&self) -> bool {
        self.window_open() || self.has_kept()
    }

    /// `rc:agent.resume_window`: the window, capped at [`WINDOW_CAP`], or `None`
    /// when withdrawn (0). Ignored with the switch off.
    pub(crate) fn set_window(&mut self, secs: u32) -> Option<Duration> {
        if !self.survive {
            debug!(
                secs,
                "rc: a resume window for a device whose switch is off; ignored (FR-130)"
            );
            return None;
        }
        self.window = (secs > 0).then(|| Duration::from_secs(u64::from(secs)).min(WINDOW_CAP));
        info!(
            secs,
            kept_s = self.window.map(|w| w.as_secs()),
            "rc: the server announced a resume window (FR-130)"
        );
        self.window
    }

    /// A link for a session this connection builds, pointed at `outbound`. On
    /// a GUI worker's delegated table its own end goes to the table in both
    /// routes, so its peer closes itself (B6).
    pub(crate) fn link(
        &self,
        session_id: ObjectId,
        outbound: &mpsc::Sender<ClientMsg>,
    ) -> SessionLink {
        SessionLink::new(
            session_id,
            outbound.clone(),
            self.ended_tx.clone(),
            self.worker,
        )
    }

    /// A live session, attached. `link` is `None` for a session never kept.
    /// One the table already held under that id is closed first: a peer it
    /// lets go of is a peer it closes.
    pub(crate) async fn insert(
        &mut self,
        session_id: ObjectId,
        peer: P,
        link: Option<SessionLink>,
    ) {
        if let Some(old) = self.take(&session_id, "displaced") {
            warn!(session_id = %session_id, "rc: a session the table held was displaced; closing it");
            close_within_budget(old.close(), session_id, "displaced").await;
        }
        self.attached.insert(session_id, Live { peer, link });
    }

    /// An attached session's peer.
    pub(crate) fn get(&self, session_id: &ObjectId) -> Option<&P> {
        self.attached.get(session_id).map(|l| &l.peer)
    }

    /// P2a-2 (C1) — close a session the server ended, its `rc:terminate` (a
    /// kick, the maximum length, a refused claim), once the caller took it out
    /// ([`Self::take`]). Attached or kept, its viewer may not have rejoined
    /// since a resume, and to a viewer a peer that just dies reads as a drop,
    /// which it redials; on an owner's or an auto-consent device that undoes
    /// the kick. So control stops at once, the end is said on the control
    /// channel (`rc:ended`, which the viewer reads as it reads `rc:terminate`:
    /// the first of the two wins), and the peer closes after `grace`, on a task
    /// of its own, so the loop waits for neither.
    ///
    /// Off is today: with the switch off it closes here, within the budget,
    /// and says nothing. P4-0 — and so it does with no window open on this
    /// connection ([`Self::window_open`]): none announced, as to a device the
    /// server's scope does not cover, or one withdrawn. A session kept under
    /// an earlier connection's window is no exception: with no window its
    /// claim is refused `agent_disconnect` at the hello, an end its viewer
    /// redials after anyway.
    pub(crate) async fn close_terminated(
        &self,
        peer: P,
        session_id: ObjectId,
        reason: &EndReason,
        limit: Option<&str>,
        grace: Duration,
    ) {
        if !(self.worker || self.window_open()) {
            close_within_budget(peer.close(), session_id, "terminate").await;
            return;
        }
        peer.stop_serving();
        info!(
            session_id = %session_id,
            ?reason,
            ?limit,
            grace_ms = millis(grace),
            "rc: the server's end is said on the session's control channel; the peer closes \
             after the grace (FR-130)"
        );
        let said = ended_json(reason, limit);
        tokio::spawn(async move {
            peer.say_on_control(said).await;
            tokio::time::sleep(grace).await;
            close_within_budget(peer.close(), session_id, "terminate").await;
        });
    }

    /// The attached sessions, the ones this connection serves.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ObjectId, &P)> {
        self.attached.iter().map(|(s, l)| (s, &l.peer))
    }

    /// Every live session, kept ones included: what counts against capacity.
    /// FR-130 P2b (A10) — a delegated session's record too, while its worker
    /// is the one attached.
    pub(crate) fn len(&self) -> usize {
        self.attached.len() + self.kept.len() + self.live_records().count()
    }

    #[cfg(test)]
    pub(crate) fn attached_len(&self) -> usize {
        self.attached.len()
    }

    pub(crate) fn holds(&self, session_id: &ObjectId) -> bool {
        self.attached.contains_key(session_id) || self.kept.contains_key(session_id)
    }

    pub(crate) fn has_kept(&self) -> bool {
        !self.kept.is_empty() || self.live_records().any(|(_, r)| r.kept.is_some())
    }

    /// The kept sessions, in a stable order: the hello's claim. FR-130 P2b
    /// (A5) — the kept records of the worker attached now with them.
    pub(crate) fn kept_ids(&self) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = self.kept.keys().copied().collect();
        ids.extend(
            self.live_records()
                .filter(|(_, r)| r.kept.is_some())
                .map(|(s, _)| *s),
        );
        ids.sort();
        ids
    }

    /// FR-141 — every live session id held by this table (attached, kept, or
    /// live delegated record), used right before graceful shutdown to persist
    /// short-lived `rc-continuity.json` records.
    pub(crate) fn live_session_ids(&self) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = self
            .attached
            .keys()
            .chain(self.kept.keys())
            .copied()
            .collect();
        ids.extend(self.live_records().map(|(s, _)| *s));
        ids.sort();
        ids.dedup();
        ids
    }

    /// FR-141 — warn every live viewer peer-to-peer on its control DataChannel
    /// right before graceful daemon shutdown/update (`limit: "restart"`) so the
    /// browser preserves the last video frame and displays a soft reconnecting
    /// banner instead of dropping into an error state.
    pub(crate) async fn notify_restart_before_shutdown(
        &self,
        eta_ms: u64,
        to_version: Option<&str>,
        grace: Duration,
    ) {
        let mut payload = serde_json::json!({
            "t": "rc:ended",
            "reason": EndReason::AgentDisconnect,
            "limit": "restart",
            "eta_ms": eta_ms,
        });
        if let Some(ver) = to_version {
            payload["to_version"] = serde_json::Value::from(ver);
        }
        let said = payload.to_string();
        let mut notified = 0usize;
        for live in self.attached.values() {
            live.peer.say_on_control(said.clone()).await;
            notified += 1;
        }
        for kept in self.kept.values() {
            kept.peer.say_on_control(said.clone()).await;
            notified += 1;
        }
        if notified > 0 && !grace.is_zero() {
            info!(
                notified,
                eta_ms,
                ?to_version,
                grace_ms = millis(grace),
                "fr141: announced graceful restart to live remote-control peers"
            );
            tokio::time::sleep(grace).await;
        }
    }

    /// A new request would put a session beside a kept peer past the device's
    /// capacity: it is refused as busy. FR-130 P2b (A10) — or beside a kept
    /// delegated session.
    pub(crate) fn full_beside_kept(&self) -> bool {
        self.has_kept() && self.len() >= self.capacity
    }

    /// Take a session out to end it: the server's terminate (a refused claim
    /// for a kept one), a re-offer, the device's end of an attached one. The
    /// caller closes it within the budget, as each of those arms always has.
    pub(crate) fn take(&mut self, session_id: &ObjectId, why: &'static str) -> Option<P> {
        if let Some(live) = self.attached.remove(session_id) {
            return Some(live.peer);
        }
        let kept = self.kept.remove(session_id)?;
        info!(
            session_id = %session_id,
            why,
            kept_ms = millis(kept.since.elapsed()),
            "rc session closed: a kept session ended (FR-130)"
        );
        Some(kept.peer)
    }

    /// The server accepted the claim: the session goes on, its senders pointed
    /// at this connection. `false` when it cannot: the table no longer holds
    /// it (its deadline came first), its deadline passed, or its peer died
    /// meanwhile (M1). The table closes what it still held and tells the
    /// server itself, reliably (L7): `agent_disconnect`, or `error` for a peer
    /// that died.
    pub(crate) async fn resume(
        &mut self,
        session_id: ObjectId,
        outbound: &mpsc::Sender<ClientMsg>,
    ) -> bool {
        if self.attached.contains_key(&session_id) {
            debug!(session_id = %session_id, "rc:session.resumed for a session already attached");
            return true;
        }
        if self.records.contains_key(&session_id) {
            return self.resume_record(session_id, outbound);
        }
        let Some(kept) = self.kept.remove(&session_id) else {
            info!(
                session_id = %session_id,
                "rc:session.resumed for a session this device no longer holds; telling the \
                 server it is gone (FR-130)"
            );
            self.queue_end(gone(session_id, EndReason::AgentDisconnect));
            return false;
        };
        let refused = if kept.peer.is_dead() {
            Some(("dead_at_claim", EndReason::Error))
        } else if Instant::now() >= kept.deadline {
            Some(("claim_late", EndReason::AgentDisconnect))
        } else {
            None
        };
        if let Some((why, reason)) = refused {
            self.kept.insert(session_id, kept);
            self.close_kept(session_id, why).await;
            self.queue_end(gone(session_id, reason));
            return false;
        }
        kept.link.point_at(outbound.clone());
        info!(
            session_id = %session_id,
            exit = kept.exit.label(),
            kept_ms = millis(kept.since.elapsed()),
            "rc session resumed: re-attached to the new connection (FR-130)"
        );
        self.attached.insert(
            session_id,
            Live {
                peer: kept.peer,
                link: Some(kept.link),
            },
        );
        true
    }

    /// The connection ended by `exit`. A terminal exit or the switch off
    /// closes every peer, kept ones included. With no window announced on
    /// this connection, what it built closes as before, and what the last one
    /// kept keeps its own deadline (M3). Otherwise every attached session that
    /// can be kept is kept until its deadline, and the rest close.
    pub(crate) async fn end_connection(&mut self, exit: ConnExit) {
        self.current = None;
        let kind = exit.kind();
        if kind == ExitKind::Terminal || !self.survive {
            return self.close_all(exit.label()).await;
        }
        let Some(window) = self.window else {
            // M3 — the window comes after the hello, so a connection can end
            // before it: its server never said whether it keeps sessions.
            if self.has_kept() {
                info!(
                    kept = self.kept_ids().len(),
                    exit = exit.label(),
                    "rc: the connection ended before its server announced a window; the kept \
                     sessions keep their deadlines (FR-130)"
                );
            }
            return self.close_attached().await;
        };
        let now = Instant::now();
        let netchange = kind == ExitKind::NetChange;
        let mut closing: Vec<(ObjectId, P, &'static str)> = Vec::new();
        let mut dead: Vec<ObjectId> = Vec::new();
        let attached: Vec<(ObjectId, Live<P>)> = self.attached.drain().collect();
        for (session_id, live) in attached {
            let Some(link) = live.link else {
                closing.push((session_id, live.peer, "ws_disconnect"));
                continue;
            };
            // M1 — dead: it cannot come back, and its own `Terminate`, sent
            // once on `Failed`, may have gone with the connection that died.
            if live.peer.is_dead() {
                closing.push((session_id, live.peer, "dead"));
                dead.push(session_id);
                continue;
            }
            // FR-130 P2b — a kept record holds a place as a kept peer does.
            if self.kept_ids().len() >= self.capacity {
                closing.push((session_id, live.peer, "over_capacity"));
                continue;
            }
            // The host's addresses moved and the peer is already off its path:
            // it cannot come back without an ICE restart.
            if netchange && !live.peer.is_connected() {
                closing.push((session_id, live.peer, "netchange_not_connected"));
                continue;
            }
            link.keep();
            info!(
                session_id = %session_id,
                exit = exit.label(),
                window_s = window.as_secs(),
                netchange,
                "rc session detached: its peer is kept until the server answers the claim, \
                 for the window at most (FR-130)"
            );
            self.kept.insert(
                session_id,
                Kept {
                    peer: live.peer,
                    link,
                    since: now,
                    deadline: now + window,
                    netchange,
                    exit,
                },
            );
        }
        // FR-130 P2b (A4) — and every attached record of the worker attached now.
        self.detach_records(exit, window, now);
        if netchange && self.next_look.is_none() {
            self.next_look = Some(now + NETCHANGE_LOOK_EVERY);
        }
        for (session_id, peer, why) in closing {
            (self.on_end)(session_id, RealEnd::Ended);
            info!(
                session_id = %session_id,
                why,
                exit = exit.label(),
                "rc session closed at the control socket's loss: it could not be kept (FR-130)"
            );
            close_within_budget(peer.close(), session_id, why).await;
        }
        // The server detached these with the rest, so it hears their end on
        // the next connection.
        for session_id in dead {
            self.queue_end(gone(session_id, EndReason::Error));
        }
    }

    /// Close every peer, attached and kept: a terminal exit, a refused token,
    /// the loop's end. The attached half is `close_all_peers` as it was, the same
    /// order, label and line.
    pub(crate) async fn close_all(&mut self, why: &'static str) {
        self.close_attached().await;
        let kept: Vec<ObjectId> = self.kept.keys().copied().collect();
        for session_id in kept {
            self.close_kept(session_id, why).await;
        }
        // FR-130 P2b — and every record: its worker closes the peer.
        let records: Vec<ObjectId> = self.records.keys().copied().collect();
        for session_id in records {
            self.close_record(session_id, why);
        }
    }

    /// FR-130 P2b — the records attached to the connection that ended, closed
    /// with it: a terminal exit, no window (M3), an exit without its arm.
    fn close_attached_records(&mut self, why: &'static str) {
        let attached: Vec<ObjectId> = self
            .records
            .iter()
            .filter(|(_, r)| r.kept.is_none())
            .map(|(s, _)| *s)
            .collect();
        for session_id in attached {
            self.close_record(session_id, why);
        }
    }

    /// The attached half of [`Self::close_all`], `close_all_peers` as it was.
    ///
    /// rc.24 — each real end takes its banner down: before, the indicator hid
    /// only on `rc:terminate`, which never comes when the socket itself drops,
    /// and after a web deploy the "Being viewed by" frame stayed painted while
    /// the controller could not reconnect ("agent capacity exceeded"). A kept
    /// session's banner stays up, because its session is still live.
    async fn close_attached(&mut self) {
        // FR-130 P2b — a GUI worker's delegated table speaks up the delegation
        // channel, which no connection of its own ends.
        if !self.worker {
            self.current = None;
        }
        self.close_attached_records("ws_disconnect");
        if self.attached.is_empty() {
            return;
        }
        let count = self.attached.len();
        let attached: Vec<(ObjectId, Live<P>)> = self.attached.drain().collect();
        for (session_id, live) in attached {
            (self.on_end)(session_id, RealEnd::Ended);
            close_within_budget(live.peer.close(), session_id, "ws_disconnect").await;
        }
        info!(
            count,
            "torn down peers + hid indicator overlays on ws disconnect"
        );
    }

    /// A connection ended without its exit arm (a `?`, such as a failed send
    /// of an answer): what it left attached closes. Kept sessions stay.
    pub(crate) async fn close_stranded(&mut self) {
        self.current = None;
        self.close_attached_records("connection_ended");
        if self.attached.is_empty() {
            return;
        }
        warn!(
            count = self.attached.len(),
            "a connection ended without its exit arm; closing the sessions it left attached"
        );
        let attached: Vec<(ObjectId, Live<P>)> = self.attached.drain().collect();
        for (session_id, live) in attached {
            (self.on_end)(session_id, RealEnd::Ended);
            close_within_budget(live.peer.close(), session_id, "connection_ended").await;
        }
    }

    /// The person at the device ended a kept session (Disconnect, the idle
    /// limit): it stops serving at once, says `rc:ended` on its control channel,
    /// closes after `grace`, and its `terminate` goes to the server on the
    /// current connection, or the next. `false` when the session is not kept.
    pub(crate) fn end_kept_by_device(
        &mut self,
        session_id: ObjectId,
        terminate: ClientMsg,
        why: &'static str,
        grace: Duration,
    ) -> bool {
        let Some(kept) = self.kept.remove(&session_id) else {
            return false;
        };
        (self.on_end)(session_id, RealEnd::HostEnded);
        kept.peer.stop_serving();
        info!(
            session_id = %session_id,
            why,
            kept_ms = millis(kept.since.elapsed()),
            grace_ms = millis(grace),
            "rc session closed: ended at the device while kept; said on its control channel, \
             and its end goes to the server (FR-130)"
        );
        let said = ended_text(&terminate);
        let Kept { peer, link, .. } = kept;
        tokio::spawn(async move {
            if let Some(said) = said {
                peer.say_on_control(said).await;
            }
            tokio::time::sleep(grace).await;
            close_within_budget(peer.close(), session_id, why).await;
            drop(link);
        });
        self.queue_end(terminate);
        true
    }

    /// What the server must hear (an end, or a kept session's report): on the
    /// current connection, or the next one. In order, and never lost to a full
    /// queue (L7): what does not fit waits, and goes the moment the queue has
    /// room ([`TableEvent::Room`]). Never waits itself.
    pub(crate) fn queue_end(&mut self, msg: ClientMsg) {
        self.pending_ends.push_back(msg);
        while self.pending_ends.len() > PENDING_CAP {
            // A report goes before an end does.
            let at = self
                .pending_ends
                .iter()
                .position(|m| !matches!(m, ClientMsg::Terminate { .. }))
                .unwrap_or(0);
            let dropped = self.pending_ends.remove(at);
            warn!(
                ?dropped,
                "rc: too much waits for room for the server; dropping one (FR-130)"
            );
        }
        self.flush_pending();
    }

    /// Hand what waits to this connection's queue, in order, while it has
    /// room. The rest waits for [`TableEvent::Room`], or the next connection.
    fn flush_pending(&mut self) {
        let Some(tx) = self.current.clone() else {
            return;
        };
        while let Some(msg) = self.pending_ends.pop_front() {
            match tx.try_send(msg) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(msg)) => {
                    self.pending_ends.push_front(msg);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(msg)) => {
                    self.pending_ends.push_front(msg);
                    self.current = None;
                    return;
                }
            }
        }
    }

    /// The next thing the table must act on: a deadline, a kept peer's own
    /// end or report, a look at the peers kept after a net change, room on
    /// this connection's queue for what waits. Pends while nothing is kept and
    /// nothing waits. Cancel-safe, for a `select!` arm.
    pub(crate) async fn next_event(&mut self) -> TableEvent {
        let deadline = self
            .kept
            .values()
            .map(|k| k.deadline)
            .chain(
                self.records
                    .values()
                    .filter_map(|r| r.kept.as_ref().map(|k| k.deadline)),
            )
            .min();
        let look = self
            .next_look
            .filter(|_| self.kept.values().any(|k| k.netchange));
        let room = self
            .current
            .clone()
            .filter(|_| !self.pending_ends.is_empty());
        tokio::select! {
            biased;
            Some((session_id, msg)) = self.ended_rx.recv() => {
                if is_own_end(&msg, session_id) {
                    TableEvent::Ended(session_id, Box::new(msg))
                } else {
                    TableEvent::Report(Box::new(msg))
                }
            }
            () = sleep_until(deadline) => TableEvent::Deadline,
            () = sleep_until(look) => TableEvent::Look,
            permit = room_on(room) => TableEvent::Room(permit),
        }
    }

    /// Act on `event`. Every close goes through [`close_within_budget`].
    pub(crate) async fn serve(&mut self, event: TableEvent) {
        match event {
            TableEvent::Deadline => self.close_due().await,
            TableEvent::Ended(session_id, msg) => {
                if self.records.contains_key(&session_id) {
                    // FR-130 P2b — a delegated session's own end, from its
                    // worker (its peer failed, the person ended it) or from
                    // the channel's end: the record goes, and the server
                    // hears it, on this connection or after the next hello.
                    self.close_record(session_id, "ended");
                    self.queue_end(*msg);
                } else if self.kept.contains_key(&session_id) {
                    self.close_kept(session_id, "failed").await;
                    self.queue_end(*msg);
                } else if self.worker
                    && let Some(live) = self.attached.remove(&session_id)
                {
                    // FR-130 P2b (B6) — a GUI worker's delegated peer that
                    // failed closes itself: after a roll the server that
                    // would echo its end no longer holds the session.
                    (self.on_end)(session_id, RealEnd::Ended);
                    info!(
                        session_id = %session_id,
                        "rc session closed (delegated): its peer ended itself; its end goes up the \
                         channel (FR-130 P2b)"
                    );
                    close_within_budget(live.peer.close(), session_id, "failed").await;
                    self.queue_end(*msg);
                } else if self.attached.contains_key(&session_id) {
                    // Resumed before this was read: say it on this connection,
                    // as an attached peer's own end always went.
                    self.queue_end(*msg);
                }
            }
            // L9 — ends nothing: the audit hears it on this connection, or the
            // next.
            TableEvent::Report(msg) => self.queue_end(*msg),
            TableEvent::Room(Some(permit)) => {
                if let Some(msg) = self.pending_ends.pop_front() {
                    permit.send(msg);
                }
                self.flush_pending();
            }
            // The queue closed under it: the connection is ending.
            TableEvent::Room(None) => self.current = None,
            TableEvent::Look => {
                let left: Vec<ObjectId> = self
                    .kept
                    .iter()
                    .filter(|(_, k)| k.netchange && !k.peer.is_connected())
                    .map(|(s, _)| *s)
                    .collect();
                for session_id in left {
                    self.close_kept(session_id, "netchange_left_connected")
                        .await;
                    // FR-130 P2b — on a GUI worker's delegated table the
                    // daemon holds the claim: it hears the session is gone,
                    // and does not claim it.
                    if self.worker {
                        self.queue_end(gone(session_id, EndReason::AgentDisconnect));
                    }
                }
                self.next_look = self
                    .kept
                    .values()
                    .any(|k| k.netchange)
                    .then(|| Instant::now() + NETCHANGE_LOOK_EVERY);
            }
        }
    }

    async fn close_due(&mut self) {
        let now = Instant::now();
        let due: Vec<ObjectId> = self
            .kept
            .iter()
            .filter(|(_, k)| k.deadline <= now)
            .map(|(s, _)| *s)
            .collect();
        for session_id in due {
            self.close_kept(session_id, "deadline").await;
            // FR-130 P2b (review LOW-2) — on a GUI worker's delegated table the
            // daemon holds the claim: it hears the session is gone.
            if self.worker {
                self.queue_end(gone(session_id, EndReason::AgentDisconnect));
            }
        }
        // FR-130 P2b (A8, D4) — a kept record past the daemon's deadline: its
        // worker is told to close, and its own deadline closes it anyway.
        let due: Vec<ObjectId> = self
            .records
            .iter()
            .filter(|(_, r)| r.kept.as_ref().is_some_and(|k| k.deadline <= now))
            .map(|(s, _)| *s)
            .collect();
        for session_id in due {
            self.close_record(session_id, "deadline");
        }
    }

    async fn close_kept(&mut self, session_id: ObjectId, why: &'static str) {
        let Some(kept) = self.kept.remove(&session_id) else {
            return;
        };
        (self.on_end)(session_id, RealEnd::Ended);
        info!(
            session_id = %session_id,
            why,
            kept_ms = millis(kept.since.elapsed()),
            "rc session closed: a kept session ended (FR-130)"
        );
        close_within_budget(kept.peer.close(), session_id, why).await;
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Room on `to`, a connection's queue that something waits for. `None` when
/// it closed. Pends with nothing to wait for.
async fn room_on(to: Option<mpsc::Sender<ClientMsg>>) -> Option<mpsc::OwnedPermit<ClientMsg>> {
    match to {
        Some(tx) => tx.reserve_owned().await.ok(),
        None => std::future::pending().await,
    }
}

/// The backstop: a table dropped while it holds a peer still closes it, within
/// the budget, on a task of its own. Every return of the org loop closes the
/// table first, so this reads as a WARN when it ever runs.
impl<P: TablePeer> Drop for SessionTable<P> {
    fn drop(&mut self) {
        let mut peers: Vec<(ObjectId, P)> =
            self.attached.drain().map(|(s, l)| (s, l.peer)).collect();
        peers.extend(self.kept.drain().map(|(s, k)| (s, k.peer)));
        if peers.is_empty() {
            return;
        }
        for (session_id, _) in &peers {
            (self.on_end)(*session_id, RealEnd::Ended);
        }
        warn!(
            count = peers.len(),
            "rc: the session table was dropped holding live peers; closing them"
        );
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(async move {
                    for (session_id, peer) in peers {
                        close_within_budget(peer.close(), session_id, "table_dropped").await;
                    }
                });
            }
            Err(_) => tracing::error!(
                "rc: no runtime to close the dropped table's peers; their sockets stay \
                 open until the process exits"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::models::{PrivacyActivityKind, RecordingActivityKind};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A peer that counts its closes: every path into Closed is counted.
    #[derive(Clone, Default)]
    struct Fake(Arc<FakeState>);

    #[derive(Default)]
    struct FakeState {
        closes: AtomicUsize,
        stopped: AtomicBool,
        connected: AtomicBool,
        /// Its connection `Failed` or `Closed` (M1).
        dead: AtomicBool,
        said: Mutex<Vec<String>>,
    }

    impl Fake {
        fn connected() -> Self {
            let f = Self::default();
            f.set_connected(true);
            f
        }
        fn set_connected(&self, on: bool) {
            self.0.connected.store(on, Ordering::SeqCst);
        }
        /// `Failed` (or `Closed`), with no word from it: the report that
        /// would have said so went with a connection that died.
        fn set_dead(&self) {
            self.set_connected(false);
            self.0.dead.store(true, Ordering::SeqCst);
        }
        fn closes(&self) -> usize {
            self.0.closes.load(Ordering::SeqCst)
        }
        fn stopped(&self) -> bool {
            self.0.stopped.load(Ordering::SeqCst)
        }
        fn said(&self) -> Vec<serde_json::Value> {
            self.0
                .said
                .lock()
                .unwrap()
                .iter()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect()
        }
    }

    impl TablePeer for Fake {
        async fn close(&self) {
            self.0.closes.fetch_add(1, Ordering::SeqCst);
        }
        fn stop_serving(&self) {
            self.0.stopped.store(true, Ordering::SeqCst);
        }
        fn is_connected(&self) -> bool {
            self.0.connected.load(Ordering::SeqCst)
        }
        async fn say_on_control(&self, text: String) {
            self.0.said.lock().unwrap().push(text);
        }
        fn is_dead(&self) -> bool {
            self.0.dead.load(Ordering::SeqCst)
        }
    }

    /// The real ends the hook saw: the banner, the lock and the recording.
    #[derive(Clone, Default)]
    struct Ends(Arc<Mutex<Vec<(ObjectId, RealEnd)>>>);

    impl Ends {
        fn hook(&self) -> EndHook {
            let me = self.clone();
            Arc::new(move |s, e| me.0.lock().unwrap().push((s, e)))
        }
        fn all(&self) -> Vec<(ObjectId, RealEnd)> {
            self.0.lock().unwrap().clone()
        }
    }

    struct Session {
        id: ObjectId,
        peer: Fake,
        /// What the peer's handlers hold: the link's sender, or the
        /// connection's when the session is never kept.
        held: mpsc::Sender<ClientMsg>,
    }

    struct Rig {
        table: SessionTable<Fake>,
        ends: Ends,
        conn: mpsc::Receiver<ClientMsg>,
        tx: mpsc::Sender<ClientMsg>,
        sessions: Vec<Session>,
    }

    impl Rig {
        fn closes(&self) -> usize {
            self.sessions.iter().map(|s| s.peer.closes()).sum()
        }
    }

    /// A table on a connection whose switch is `survive` and whose server
    /// announced `window`, holding `n` live sessions built the way the offer arm
    /// builds them.
    async fn rig(survive: bool, window: Option<u32>, n: usize) -> Rig {
        rig_with(8, survive, window, n).await
    }

    async fn rig_with(capacity: usize, survive: bool, window: Option<u32>, n: usize) -> Rig {
        let ends = Ends::default();
        let mut table = SessionTable::new(capacity, ends.hook());
        let (tx, conn) = mpsc::channel(64);
        assert!(table.begin_connection(survive).await.is_empty());
        table.connected(&tx);
        if let Some(w) = window {
            table.set_window(w);
        }
        let mut sessions = Vec::new();
        for _ in 0..n {
            sessions.push(attach(&mut table, &tx).await);
        }
        Rig {
            table,
            ends,
            conn,
            tx,
            sessions,
        }
    }

    async fn attach(table: &mut SessionTable<Fake>, tx: &mpsc::Sender<ClientMsg>) -> Session {
        let id = ObjectId::new();
        let peer = Fake::connected();
        let link = table.keeps_sessions().then(|| table.link(id, tx));
        let held = link
            .as_ref()
            .map_or_else(|| tx.clone(), SessionLink::sender);
        table.insert(id, peer.clone(), link).await;
        Session { id, peer, held }
    }

    /// The next connection: its claim, and its queue.
    async fn reconnect(
        table: &mut SessionTable<Fake>,
    ) -> (
        Vec<ObjectId>,
        mpsc::Sender<ClientMsg>,
        mpsc::Receiver<ClientMsg>,
    ) {
        let (tx, rx) = mpsc::channel(64);
        let claim = table.begin_connection(true).await;
        table.connected(&tx);
        (claim, tx, rx)
    }

    fn terminate(session_id: ObjectId, reason: EndReason, limit: Option<&str>) -> ClientMsg {
        ClientMsg::Terminate {
            session_id,
            reason,
            limit: limit.map(str::to_string),
        }
    }

    /// The table's next event: a test never waits for ever (on a paused clock
    /// the ten minutes pass at once).
    async fn next(table: &mut SessionTable<Fake>) -> TableEvent {
        tokio::time::timeout(Duration::from_secs(600), table.next_event())
            .await
            .expect("the table has something to act on")
    }

    /// Until the link's task has taken everything sent on `held` (one thread:
    /// once it has, it has also routed it).
    async fn settled(held: &mpsc::Sender<ClientMsg>) {
        while held.capacity() < held.max_capacity() {
            tokio::task::yield_now().await;
        }
    }

    fn ice(session_id: ObjectId) -> ClientMsg {
        ClientMsg::Ice {
            session_id,
            candidate: serde_json::json!("candidate:1 1 udp 1 10.0.0.1 9 typ host"),
        }
    }

    fn recording_activity(session_id: ObjectId) -> ClientMsg {
        ClientMsg::RecordingActivity {
            session_id,
            kind: RecordingActivityKind::Started,
            name: None,
            bytes: None,
            duration_ms: None,
            reason: None,
        }
    }

    fn privacy_activity(session_id: ObjectId) -> ClientMsg {
        ClientMsg::PrivacyActivity {
            session_id,
            kind: PrivacyActivityKind::On,
            reason: None,
        }
    }

    /// Serve the table's events for `d`, as the loop does wherever it waits.
    /// On a paused clock the wait passes at once.
    async fn serve_for(table: &mut SessionTable<Fake>, d: Duration) {
        let _ = tokio::time::timeout(d, async {
            loop {
                let event = table.next_event().await;
                table.serve(event).await;
            }
        })
        .await;
    }

    /// The signalling loop's code without its tests and with every blank
    /// removed, so a check reads the same however rustfmt wraps a line.
    fn signaling_code() -> String {
        include_str!("signaling.rs")
            .split("\nmod tests {")
            .next()
            .unwrap()
            .split_whitespace()
            .collect()
    }

    /// `connect_once` from its start to its select loop: the setup.
    fn connection_setup(code: &str) -> &str {
        code.split("asyncfnconnect_once(")
            .nth(1)
            .and_then(|rest| rest.split("drop(setup_stage);").next())
            .expect("connect_once and the end of its setup")
    }

    // ─── The sixteen arms ───────────────────────────────────────────────────
    //
    // Each runs the arm with the switch on and a 60 s window announced, two
    // live sessions in the table. Written first: at the pin every arm closes
    // every peer, so the twelve transient arms fail there.

    async fn the_arm_keeps_every_session(exit: ConnExit) {
        let mut r = rig(true, Some(60), 2).await;
        r.table.end_connection(exit).await;
        assert_eq!(r.closes(), 0, "{exit:?} closed a peer it should keep");
        assert_eq!(r.table.kept_ids().len(), 2, "{exit:?} keeps both sessions");
        assert_eq!(
            r.table.attached_len(),
            0,
            "{exit:?}: nothing stays attached"
        );
        assert!(
            r.ends.all().is_empty(),
            "{exit:?}: a detach takes no banner down, locks nothing, ends no recording"
        );
        r.table.close_all("test_end").await;
        assert_eq!(r.closes(), 2);
    }

    async fn the_arm_closes_every_peer(exit: ConnExit) {
        let mut r = rig(true, Some(60), 2).await;
        r.table.end_connection(exit).await;
        for s in &r.sessions {
            assert_eq!(s.peer.closes(), 1, "{exit:?} must close {}", s.id);
        }
        assert_eq!(r.table.len(), 0, "{exit:?} leaves nothing in the table");
        assert_eq!(
            r.ends.all().len(),
            2,
            "{exit:?}: each real end takes its banner down"
        );
    }

    macro_rules! per_arm {
        ($($name:ident: $exit:ident => $how:ident,)*) => {$(
            #[tokio::test]
            async fn $name() {
                $how(ConnExit::$exit).await
            }
        )*};
    }

    per_arm! {
        arm_shutdown_closes_every_peer: Shutdown => the_arm_closes_every_peer,
        arm_resume_from_suspend_closes_every_peer: ResumeFromSuspend => the_arm_closes_every_peer,
        arm_rx_deadline_keeps_its_sessions: RxDeadline => the_arm_keeps_every_session,
        arm_netchange_probe_keeps_its_sessions: NetChangeProbe => the_arm_keeps_every_session,
        arm_netchange_reprobe_keeps_its_sessions: NetChangeReprobe => the_arm_keeps_every_session,
        arm_keepalive_unanswered_keeps_its_sessions: KeepaliveUnanswered => the_arm_keeps_every_session,
        arm_keepalive_send_failed_keeps_its_sessions: KeepaliveSendFailed => the_arm_keeps_every_session,
        arm_netchange_ping_failed_keeps_its_sessions: NetChangePingFailed => the_arm_keeps_every_session,
        arm_heartbeat_send_failed_keeps_its_sessions: HeartbeatSendFailed => the_arm_keeps_every_session,
        arm_outbound_flush_failed_keeps_its_sessions: OutboundFlushFailed => the_arm_keeps_every_session,
        arm_pong_reply_failed_keeps_its_sessions: PongReplyFailed => the_arm_keeps_every_session,
        arm_server_closed_keeps_its_sessions: ServerClosed => the_arm_keeps_every_session,
        arm_read_error_keeps_its_sessions: ReadError => the_arm_keeps_every_session,
        arm_pong_rtt_degraded_keeps_its_sessions: PongRttDegraded => the_arm_keeps_every_session,
        arm_goodbye_closes_every_peer: Goodbye => the_arm_closes_every_peer,
        arm_key_rotated_closes_every_peer: KeyRotated => the_arm_closes_every_peer,
    }

    #[test]
    fn twelve_arms_keep_and_four_close() {
        let terminal: Vec<ConnExit> = ConnExit::ALL
            .into_iter()
            .filter(|e| e.kind() == ExitKind::Terminal)
            .collect();
        assert_eq!(
            terminal,
            [
                ConnExit::Shutdown,
                ConnExit::ResumeFromSuspend,
                ConnExit::Goodbye,
                ConnExit::KeyRotated
            ]
        );
        let netchange: Vec<ConnExit> = ConnExit::ALL
            .into_iter()
            .filter(|e| e.kind() == ExitKind::NetChange)
            .collect();
        assert_eq!(
            netchange,
            [
                ConnExit::NetChangeProbe,
                ConnExit::NetChangeReprobe,
                ConnExit::NetChangePingFailed
            ]
        );
        let labels: std::collections::HashSet<&str> =
            ConnExit::ALL.iter().map(|e| e.label()).collect();
        assert_eq!(labels.len(), 16, "every exit has its own label");
    }

    /// Every arm of the connection ends through the table, under its own name,
    /// and nothing else closes the connection's peers: the per-arm tests above
    /// are the arms the loop runs. The RX deadline's arm takes its name from
    /// how late its tick came (M2), so it names no exit itself.
    #[test]
    fn every_arm_of_the_connection_ends_through_the_table() {
        let src = include_str!("signaling.rs");
        let code = src.split("\nmod tests {").next().unwrap();
        for exit in ConnExit::ALL {
            let call = format!("end_connection(ConnExit::{exit:?})");
            let arms = usize::from(exit != ConnExit::RxDeadline);
            assert_eq!(
                code.matches(&call).count(),
                arms,
                "{call} must be the arm's one call"
            );
        }
        assert_eq!(
            signaling_code()
                .matches("end_connection(ConnExit::after_rx_deadline(Some(late)))")
                .count(),
            1,
            "the RX deadline's arm ends as the tick's lateness says (M2)"
        );
        assert!(
            !code.contains("close_all_peers("),
            "a connection's peers close only through the session table"
        );
        assert_eq!(
            code.matches("close_all(\"token_refused\")").count(),
            1,
            "a refused token closes every peer, kept ones included"
        );
    }

    // ─── Off is today ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn with_the_switch_off_every_arm_closes_every_peer() {
        for exit in ConnExit::ALL {
            // A window sent to a device whose switch is off changes nothing.
            let mut r = rig(false, Some(60), 2).await;
            assert!(!r.table.keeps_sessions());
            r.table.end_connection(exit).await;
            assert_eq!(
                r.closes(),
                2,
                "{exit:?} with the switch off closes every peer"
            );
            assert_eq!(r.table.len(), 0, "{exit:?}");
        }
    }

    #[tokio::test]
    async fn with_no_window_every_arm_closes_every_peer() {
        for window in [None, Some(0)] {
            for exit in ConnExit::ALL {
                let mut r = rig(true, window, 2).await;
                r.table.end_connection(exit).await;
                assert_eq!(
                    r.closes(),
                    2,
                    "{exit:?}, window {window:?}: every peer closes"
                );
                assert_eq!(r.table.len(), 0, "{exit:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_window_withdrawn_keeps_nothing_at_the_next_exit() {
        let mut r = rig(true, Some(60), 1).await;
        assert_eq!(r.table.set_window(0), None);
        r.table.end_connection(ConnExit::ReadError).await;
        assert_eq!(r.closes(), 1);
    }

    /// A supervised Mac's delegated session (P2b's) and an external one (D3)
    /// are built with no link, and end as today: closed at every exit.
    #[tokio::test]
    async fn a_delegated_or_external_session_closes_at_a_transient_exit() {
        let mut r = rig(true, Some(60), 1).await;
        let id = ObjectId::new();
        let never = Fake::connected();
        r.table.insert(id, never.clone(), None).await;
        r.table.end_connection(ConnExit::ReadError).await;
        assert_eq!(
            never.closes(),
            1,
            "a session with no link is closed as before"
        );
        assert_eq!(r.table.kept_ids(), vec![r.sessions[0].id]);
        r.table.close_all("test_end").await;
    }

    /// A connection that ends through a `?` (a failed send of an answer) has no
    /// exit arm: `run` closes what it left attached, and keeps what was kept.
    #[tokio::test]
    async fn a_connection_that_ends_without_its_arm_strands_nothing() {
        let mut r = rig(true, Some(60), 1).await;
        r.table.end_connection(ConnExit::ReadError).await;
        let (_, tx2, _conn2) = reconnect(&mut r.table).await;
        let fresh = attach(&mut r.table, &tx2).await;
        r.table.close_stranded().await;
        assert_eq!(fresh.peer.closes(), 1, "the attached one closes");
        assert_eq!(r.closes(), 0, "the kept one waits for its claim");
        assert_eq!(r.table.kept_ids(), vec![r.sessions[0].id]);
        r.table.close_all("test_end").await;
    }

    // ─── The paths into Closed (spec §4.2's diagram) ─────────────────────────

    #[tokio::test(start_paused = true)]
    async fn the_deadline_closes_a_kept_session() {
        let mut r = rig(true, Some(60), 1).await;
        r.table.end_connection(ConnExit::ReadError).await;
        let early = tokio::time::timeout(Duration::from_secs(59), r.table.next_event()).await;
        assert!(early.is_err(), "nothing is due inside the window");
        let event = next(&mut r.table).await;
        assert!(matches!(event, TableEvent::Deadline), "{event:?}");
        r.table.serve(event).await;
        assert_eq!(r.closes(), 1);
        assert_eq!(r.table.len(), 0);
        assert_eq!(r.ends.all(), vec![(r.sessions[0].id, RealEnd::Ended)]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_device_caps_the_window_at_two_minutes() {
        let mut r = rig(true, None, 1).await;
        assert_eq!(r.table.set_window(3600), Some(WINDOW_CAP));
        r.table.end_connection(ConnExit::ReadError).await;
        let early = tokio::time::timeout(Duration::from_secs(119), r.table.next_event()).await;
        assert!(early.is_err(), "kept for the cap, not the server's hour");
        let event = next(&mut r.table).await;
        r.table.serve(event).await;
        assert_eq!(r.closes(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnect_does_not_move_the_deadline() {
        let mut r = rig(true, Some(60), 1).await;
        r.table.end_connection(ConnExit::ReadError).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        let (claim, _tx2, _conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![r.sessions[0].id], "the hello claims it");
        r.table.set_window(60);
        let early = tokio::time::timeout(Duration::from_secs(29), r.table.next_event()).await;
        assert!(early.is_err());
        let event = next(&mut r.table).await;
        r.table.serve(event).await;
        assert_eq!(r.closes(), 1, "closed 60 s after the detach, unanswered");
    }

    #[tokio::test(start_paused = true)]
    async fn a_claim_answered_after_its_deadline_is_refused() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        r.table.end_connection(ConnExit::ReadError).await;
        let (claim, tx2, _conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![id]);
        tokio::time::sleep(Duration::from_secs(61)).await;
        assert!(!r.table.resume(id, &tx2).await, "too late: refused");
        assert_eq!(r.closes(), 1);
        assert_eq!(r.table.len(), 0);
    }

    #[tokio::test]
    async fn a_resumed_session_is_attached_and_sends_on_the_new_connection() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        let held = r.sessions[0].held.clone();
        r.table.end_connection(ConnExit::ReadError).await;
        // Kept: what the peer says goes nowhere, and never waits.
        held.send(ice(id)).await.unwrap();
        settled(&held).await;
        let (claim, tx2, mut conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![id]);
        assert!(r.table.resume(id, &tx2).await);
        assert_eq!(r.table.attached_len(), 1);
        assert!(!r.table.has_kept());
        held.send(ice(id)).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), conn2.recv())
            .await
            .expect("the resumed session's sender reaches the new connection");
        assert!(matches!(got, Some(ClientMsg::Ice { .. })), "{got:?}");
        assert!(
            conn2.try_recv().is_err(),
            "what it said while kept was dropped"
        );
        assert!(
            r.conn.try_recv().is_err(),
            "nothing reached the dead connection"
        );
        r.table.close_all("test_end").await;
        assert_eq!(r.closes(), 1);
    }

    /// The bug a single re-pointed `AgentPeer::outbound` would have: the state
    /// handler's clone, taken at creation, would still be the dead connection's.
    #[tokio::test]
    async fn a_resumed_peer_that_fails_sends_its_terminate_on_the_new_connection() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        let state_handler = r.sessions[0].held.clone();
        r.table.end_connection(ConnExit::ReadError).await;
        drop(r.conn);
        let (_, tx2, mut conn2) = reconnect(&mut r.table).await;
        assert!(r.table.resume(id, &tx2).await);
        state_handler
            .send(terminate(id, EndReason::Error, None))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), conn2.recv())
            .await
            .expect("the Terminate reaches the new connection");
        match got {
            Some(ClientMsg::Terminate {
                session_id,
                reason: EndReason::Error,
                ..
            }) => assert_eq!(session_id, id),
            other => panic!("not the peer's Terminate: {other:?}"),
        }
        r.table.close_all("test_end").await;
    }

    #[tokio::test]
    async fn a_kept_peer_that_fails_is_closed_and_its_end_queued() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        r.table.end_connection(ConnExit::ReadError).await;
        r.sessions[0]
            .held
            .send(terminate(id, EndReason::Error, None))
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(2), r.table.next_event())
            .await
            .expect("the link hands the session's own end to the table");
        assert!(
            matches!(event, TableEvent::Ended(s, _) if s == id),
            "{event:?}"
        );
        r.table.serve(event).await;
        assert_eq!(r.closes(), 1, "the table closes it");
        let (claim, _tx2, mut conn2) = reconnect(&mut r.table).await;
        assert!(claim.is_empty(), "a closed session is not claimed");
        match conn2.try_recv() {
            Ok(ClientMsg::Terminate {
                session_id,
                reason: EndReason::Error,
                ..
            }) => assert_eq!(session_id, id),
            other => panic!("the next connection says its end: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_kept_peers_sends_never_wait_on_the_bounded_queue() {
        let ends = Ends::default();
        let mut table: SessionTable<Fake> = SessionTable::new(8, ends.hook());
        // A connection's queue with one slot, full, that nobody reads.
        let (tx, _conn) = mpsc::channel(1);
        tx.try_send(ice(ObjectId::new())).unwrap();
        table.begin_connection(true).await;
        table.connected(&tx);
        table.set_window(60);
        let s = attach(&mut table, &tx).await;
        let id = s.id;
        let held = s.held.clone();
        let sender = tokio::spawn(async move {
            for _ in 0..200 {
                held.send(ice(id)).await.unwrap();
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !sender.is_finished(),
            "attached, a full connection queue holds the session's sends back, as before"
        );
        table.end_connection(ConnExit::ReadError).await;
        tokio::time::timeout(Duration::from_secs(2), sender)
            .await
            .expect("kept, the sends that waited go through at once")
            .unwrap();
        let held = s.held.clone();
        tokio::time::timeout(Duration::from_secs(2), async move {
            for _ in 0..1000 {
                held.send(ice(id)).await.unwrap();
            }
        })
        .await
        .expect("and every later send never waits");
        table.close_all("test_end").await;
        assert_eq!(s.peer.closes(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn after_a_net_change_a_kept_peer_that_leaves_connected_closes_at_once() {
        let mut r = rig(true, Some(60), 2).await;
        // One peer already off its path when the arm runs.
        r.sessions[1].peer.set_connected(false);
        r.table.end_connection(ConnExit::NetChangePingFailed).await;
        assert_eq!(
            r.sessions[1].peer.closes(),
            1,
            "not Connected at the detach: closed at once"
        );
        assert_eq!(r.table.kept_ids(), vec![r.sessions[0].id]);
        // Still Connected: kept.
        let early = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = r.table.next_event().await;
                r.table.serve(event).await;
            }
        })
        .await;
        assert!(early.is_err());
        assert_eq!(r.sessions[0].peer.closes(), 0);
        r.sessions[0].peer.set_connected(false);
        let event = next(&mut r.table).await;
        assert!(matches!(event, TableEvent::Look), "{event:?}");
        r.table.serve(event).await;
        assert_eq!(
            r.sessions[0].peer.closes(),
            1,
            "left Connected: closed at once"
        );
        assert_eq!(r.table.len(), 0);
    }

    /// The connection's loop comes round on its other arms far more often than
    /// the look's period: the look still comes at its time.
    #[tokio::test(start_paused = true)]
    async fn a_busy_loop_does_not_push_the_look_back() {
        let mut r = rig(true, Some(60), 1).await;
        r.table.end_connection(ConnExit::NetChangeProbe).await;
        r.sessions[0].peer.set_connected(false);
        let mut looked = false;
        for _ in 0..5 {
            let turn = tokio::time::timeout(Duration::from_millis(100), r.table.next_event()).await;
            if let Ok(event) = turn {
                r.table.serve(event).await;
                looked = true;
                break;
            }
        }
        assert!(
            looked,
            "the look comes at its time, however often the loop turns"
        );
        assert_eq!(r.closes(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn after_another_arm_a_kept_peer_that_leaves_connected_waits_for_its_watchdog() {
        let mut r = rig(true, Some(60), 1).await;
        r.table.end_connection(ConnExit::ReadError).await;
        r.sessions[0].peer.set_connected(false);
        let early = tokio::time::timeout(Duration::from_secs(30), r.table.next_event()).await;
        assert!(
            early.is_err(),
            "a path the roll did not touch may come back"
        );
        assert_eq!(r.closes(), 0);
        r.table.close_all("test_end").await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_disconnect_in_the_gap_closes_and_queues_its_end() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        let peer = r.sessions[0].peer.clone();
        r.table.end_connection(ConnExit::ReadError).await;
        let said = terminate(id, EndReason::HostDisconnect, None);
        assert!(
            r.table
                .end_kept_by_device(id, said, "host_disconnect", Duration::from_secs(1))
        );
        assert!(peer.stopped(), "stops serving at once");
        assert_eq!(
            r.ends.all(),
            vec![(id, RealEnd::HostEnded)],
            "the recording stops, the banner comes down"
        );
        assert_eq!(peer.closes(), 0, "the close waits for the grace");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(peer.closes(), 1, "closed after the grace");
        assert_eq!(
            peer.said(),
            vec![serde_json::json!({"t": "rc:ended", "reason": "host_disconnect"})],
            "the viewer hears it peer to peer"
        );
        assert_eq!(r.table.len(), 0);
        let (claim, _tx2, mut conn2) = reconnect(&mut r.table).await;
        assert!(claim.is_empty(), "an ended session is not claimed");
        match conn2.try_recv() {
            Ok(ClientMsg::Terminate {
                session_id,
                reason: EndReason::HostDisconnect,
                limit: None,
            }) => assert_eq!(session_id, id),
            other => panic!("the next connection says host_disconnect: {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_idle_limit_in_the_gap_ends_as_idle_timeout() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        let peer = r.sessions[0].peer.clone();
        r.table.end_connection(ConnExit::ReadError).await;
        let said = terminate(id, EndReason::IdleTimeout, Some("idle"));
        assert!(
            r.table
                .end_kept_by_device(id, said, "idle_timeout", Duration::ZERO)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(peer.closes(), 1);
        assert_eq!(
            peer.said(),
            vec![serde_json::json!({"t": "rc:ended", "reason": "idle_timeout", "limit": "idle"})]
        );
        let (_, _tx2, mut conn2) = reconnect(&mut r.table).await;
        assert!(matches!(
            conn2.try_recv(),
            Ok(ClientMsg::Terminate {
                reason: EndReason::IdleTimeout,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn an_end_at_the_device_for_a_session_not_kept_is_not_the_tables() {
        let mut r = rig(true, Some(60), 1).await;
        let said = terminate(r.sessions[0].id, EndReason::HostDisconnect, None);
        assert!(
            !r.table
                .end_kept_by_device(r.sessions[0].id, said, "host_disconnect", Duration::ZERO),
            "an attached session ends through the connection's own arm"
        );
        assert_eq!(r.closes(), 0);
        r.table.close_all("test_end").await;
    }

    #[tokio::test]
    async fn a_kept_session_ended_on_a_live_connection_says_so_at_once() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        r.table.end_connection(ConnExit::ReadError).await;
        let (_, _tx2, mut conn2) = reconnect(&mut r.table).await;
        let said = terminate(id, EndReason::HostDisconnect, None);
        assert!(
            r.table
                .end_kept_by_device(id, said, "host_disconnect", Duration::ZERO)
        );
        assert!(matches!(
            conn2.try_recv(),
            Ok(ClientMsg::Terminate {
                reason: EndReason::HostDisconnect,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_refused_token_closes_every_peer_kept_ones_included() {
        let mut r = rig(true, Some(60), 2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        assert_eq!(r.table.kept_ids().len(), 2);
        // `run`'s AuthRejected arm.
        r.table.close_all("token_refused").await;
        assert_eq!(r.closes(), 2);
        assert_eq!(r.table.len(), 0);
        assert_eq!(r.ends.all().len(), 2);
    }

    #[tokio::test]
    async fn a_terminal_exit_closes_kept_sessions_too() {
        for exit in ConnExit::ALL
            .into_iter()
            .filter(|e| e.kind() == ExitKind::Terminal)
        {
            let mut r = rig(true, Some(60), 1).await;
            r.table.end_connection(ConnExit::ReadError).await;
            let (claim, tx2, _conn2) = reconnect(&mut r.table).await;
            assert_eq!(claim.len(), 1);
            r.table.set_window(60);
            let fresh = attach(&mut r.table, &tx2).await;
            r.table.end_connection(exit).await;
            assert_eq!(r.closes(), 1, "{exit:?} closes the kept session");
            assert_eq!(fresh.peer.closes(), 1, "{exit:?} closes the attached one");
            assert_eq!(r.table.len(), 0);
        }
    }

    #[tokio::test]
    async fn the_switch_off_at_the_next_connection_closes_what_was_kept() {
        let mut r = rig(true, Some(60), 1).await;
        r.table.end_connection(ConnExit::ReadError).await;
        let claim = r.table.begin_connection(false).await;
        assert!(claim.is_empty(), "nothing is claimed without the verb");
        assert_eq!(r.closes(), 1);
    }

    #[tokio::test]
    async fn kept_sessions_count_against_the_capacity() {
        let mut r = rig_with(2, true, Some(60), 2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        let (claim, tx2, _conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim.len(), 2);
        assert!(r.table.full_beside_kept(), "a third is refused as busy");
        assert!(r.table.resume(claim[0], &tx2).await);
        assert!(
            r.table.full_beside_kept(),
            "one kept beside one resumed: still full"
        );
        assert!(r.table.resume(claim[1], &tx2).await);
        assert!(
            !r.table.full_beside_kept(),
            "nothing kept: the server's gate decides, as before"
        );
        r.table.close_all("test_end").await;
    }

    #[tokio::test]
    async fn the_table_never_keeps_more_than_the_capacity() {
        let mut r = rig_with(1, true, Some(60), 2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        assert_eq!(r.table.kept_ids().len(), 1);
        assert_eq!(r.closes(), 1, "the one over the capacity closes");
        r.table.close_all("test_end").await;
        assert_eq!(r.closes(), 2);
    }

    #[tokio::test]
    async fn a_terminate_for_a_kept_session_takes_it_out() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        r.table.end_connection(ConnExit::ReadError).await;
        // The `Terminate` arm, for a claim refused: takes it out and closes it
        // within the budget, as it always closed an attached one.
        let peer = r.table.take(&id, "terminate").expect("kept");
        close_within_budget(peer.close(), id, "terminate").await;
        assert_eq!(r.closes(), 1);
        assert!(!r.table.holds(&id));
    }

    #[tokio::test]
    async fn a_table_dropped_holding_peers_still_closes_them() {
        let mut r = rig(true, Some(60), 2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        let tx = r.tx.clone();
        let fresh = attach(&mut r.table, &tx).await;
        let Rig {
            table, sessions, ..
        } = r;
        drop(table);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sessions.iter().map(|s| s.peer.closes()).sum::<usize>(), 2);
        assert_eq!(fresh.peer.closes(), 1);
    }

    #[test]
    fn the_resume_word_follows_the_switch_by_equality() {
        let mut rpc = vec!["rc-overlay-auto".to_string()];
        apply_resume_word(&mut rpc, true);
        apply_resume_word(&mut rpc, true);
        assert_eq!(
            rpc,
            ["rc-overlay-auto", "rc-resume"],
            "once, beside the others"
        );
        apply_resume_word(&mut rpc, false);
        assert_eq!(rpc, ["rc-overlay-auto"], "off says nothing");
    }

    #[test]
    fn rc_ended_carries_the_terminates_reason_and_limit() {
        let id = ObjectId::new();
        let text = ended_text(&terminate(id, EndReason::IdleTimeout, Some("idle"))).unwrap();
        let said: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            said,
            serde_json::json!({"t": "rc:ended", "reason": "idle_timeout", "limit": "idle"})
        );
        assert_eq!(ended_text(&ice(id)), None);
    }

    // ─── P2a-2: the review's device findings ────────────────────────────────

    /// C1 — the server ended a session the table holds: a kick, the maximum
    /// length, a refused claim. Its viewer may not have rejoined since a
    /// resume, and to it a peer that just dies reads as a drop, which it
    /// redials; on an owner's or an auto-consent device that undoes the kick.
    /// So control stops at once, the end is said on the control channel, and
    /// the peer closes after the grace, attached or kept alike.
    #[tokio::test(start_paused = true)]
    async fn the_servers_end_is_said_peer_to_peer_before_the_close() {
        for kept in [false, true] {
            let mut r = rig(true, Some(60), 1).await;
            let id = r.sessions[0].id;
            let peer = r.sessions[0].peer.clone();
            if kept {
                r.table.end_connection(ConnExit::ReadError).await;
            }
            let taken = r.table.take(&id, "terminate").expect("the table holds it");
            r.table
                .close_terminated(
                    taken,
                    id,
                    &EndReason::IdleTimeout,
                    Some("max_duration"),
                    Duration::from_secs(1),
                )
                .await;
            assert!(peer.stopped(), "kept={kept}: control ends at once");
            assert_eq!(
                peer.closes(),
                0,
                "kept={kept}: the close waits for the grace"
            );
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert_eq!(
                peer.said(),
                vec![serde_json::json!(
                    {"t": "rc:ended", "reason": "idle_timeout", "limit": "max_duration"}
                )],
                "kept={kept}: the viewer hears why, peer to peer"
            );
            assert_eq!(
                peer.closes(),
                1,
                "kept={kept}: closed once, after the grace"
            );
            assert!(!r.table.holds(&id));
        }
    }

    /// C1, off is today: the server's end closes the peer at once and says
    /// nothing on its channel.
    #[tokio::test(start_paused = true)]
    async fn with_the_switch_off_the_servers_end_closes_at_once() {
        let mut r = rig(false, None, 1).await;
        let id = r.sessions[0].id;
        let taken = r.table.take(&id, "terminate").expect("attached");
        r.table
            .close_terminated(
                taken,
                id,
                &EndReason::AdminTerminated,
                None,
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(r.closes(), 1, "closed before the call returns");
        assert!(
            r.sessions[0].peer.said().is_empty(),
            "nothing said on the channel"
        );
    }

    /// M1 — a peer that failed while attached said so only on the connection
    /// that died with it. Kept, it would wait out the window dead, and a claim
    /// could resume it. It closes at the exit instead, and its end goes to the
    /// next connection; a live peer beside it is kept.
    #[tokio::test]
    async fn a_dead_peer_is_closed_at_the_exit_and_its_end_said_next() {
        let mut r = rig(true, Some(60), 2).await;
        let (dead, live) = (r.sessions[0].id, r.sessions[1].id);
        r.sessions[0].peer.set_dead();
        r.table.end_connection(ConnExit::ReadError).await;
        assert_eq!(
            r.sessions[0].peer.closes(),
            1,
            "a dead peer is closed, never kept"
        );
        assert_eq!(r.sessions[1].peer.closes(), 0, "the live one is kept");
        assert_eq!(r.ends.all(), vec![(dead, RealEnd::Ended)]);
        let (claim, _tx2, mut conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![live], "the dead one is not claimed");
        match conn2.try_recv() {
            Ok(ClientMsg::Terminate {
                session_id,
                reason: EndReason::Error,
                limit: None,
            }) => assert_eq!(session_id, dead),
            other => panic!("the next connection says the dead one's end: {other:?}"),
        }
        r.table.close_all("test_end").await;
    }

    /// M1 — one that dies between the claim and its answer is not resumed:
    /// the answer closes it, and the server hears it is gone.
    #[tokio::test]
    async fn a_kept_peer_that_died_is_not_resumed() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        r.table.end_connection(ConnExit::ReadError).await;
        let (claim, tx2, mut conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![id]);
        r.sessions[0].peer.set_dead();
        assert!(
            !r.table.resume(id, &tx2).await,
            "a dead peer is not resumed"
        );
        assert_eq!(r.closes(), 1);
        assert!(!r.table.holds(&id));
        match conn2.try_recv() {
            Ok(ClientMsg::Terminate {
                session_id,
                reason: EndReason::Error,
                ..
            }) => assert_eq!(session_id, id),
            other => panic!("the server hears it is gone: {other:?}"),
        }
    }

    /// M2 — Windows' monotonic clock counts a sleep, so a resume from suspend
    /// there never trips the wall-clock check: the RX deadline trips at the
    /// first keepalive instead, with the pause the late tick measured. A pause
    /// that long ends the connection as the resume it is, which is terminal;
    /// a shorter one, or none, stays the transient RX deadline. A pure
    /// function of the pause: upstream FR-140 swaps the signal, not the rule.
    #[test]
    fn the_rx_deadline_reads_a_long_pause_as_a_resume_from_suspend() {
        let secs = Duration::from_secs;
        for (paused, exit) in [
            (Some(secs(120)), ConnExit::ResumeFromSuspend),
            (Some(secs(3600)), ConnExit::ResumeFromSuspend),
            (Some(secs(119)), ConnExit::RxDeadline),
            (Some(secs(30)), ConnExit::RxDeadline),
            (None, ConnExit::RxDeadline),
        ] {
            assert_eq!(ConnExit::after_rx_deadline(paused), exit, "{paused:?}");
        }
    }

    /// M3 — a connection that ends before its server announced a window
    /// closes what it built, as before. What the last connection kept keeps
    /// its own deadline, and the next connection claims it.
    #[tokio::test]
    async fn a_connection_that_ends_before_its_window_leaves_the_kept_ones() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        r.table.end_connection(ConnExit::ReadError).await;
        let (claim, tx2, _conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![id]);
        let fresh = attach(&mut r.table, &tx2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        assert_eq!(r.closes(), 0, "the kept one keeps its deadline");
        assert!(r.table.holds(&id));
        assert_eq!(
            fresh.peer.closes(),
            1,
            "what this connection built closes, as before"
        );
        let (claim, _tx3, _conn3) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![id], "the next connection claims it");
        r.table.close_all("test_end").await;
        assert_eq!(r.closes(), 1);
    }

    /// L7 — the answer to a claim the device can no longer honour reaches the
    /// server even when the connection's queue is full at that moment;
    /// dropped, the server would keep a session the device closed.
    #[tokio::test(start_paused = true)]
    async fn the_no_longer_held_answer_waits_for_room() {
        let ends = Ends::default();
        let mut table: SessionTable<Fake> = SessionTable::new(8, ends.hook());
        let (tx, mut conn) = mpsc::channel(1);
        table.begin_connection(true).await;
        table.connected(&tx);
        table.set_window(60);
        tx.try_send(ice(ObjectId::new())).unwrap();
        let gone = ObjectId::new();
        assert!(!table.resume(gone, &tx).await, "not held");
        assert!(
            matches!(conn.recv().await, Some(ClientMsg::Ice { .. })),
            "the loop reads its queue"
        );
        serve_for(&mut table, Duration::from_secs(1)).await;
        match conn.try_recv() {
            Ok(ClientMsg::Terminate {
                session_id,
                reason: EndReason::AgentDisconnect,
                ..
            }) => assert_eq!(session_id, gone),
            other => panic!("the answer goes out once there is room: {other:?}"),
        }
    }

    /// L7 — an end that meets this connection's queue full waits for room on
    /// this connection, in order, and not for the next connection.
    #[tokio::test(start_paused = true)]
    async fn an_end_that_meets_a_full_queue_goes_out_on_this_connection() {
        let mut r = rig(true, Some(60), 2).await;
        let (a, b) = (r.sessions[0].id, r.sessions[1].id);
        r.table.end_connection(ConnExit::ReadError).await;
        // The next connection's queue: one slot, full.
        let (tx2, mut conn2) = mpsc::channel(1);
        r.table.begin_connection(true).await;
        r.table.connected(&tx2);
        tx2.try_send(ice(ObjectId::new())).unwrap();
        for id in [a, b] {
            let said = terminate(id, EndReason::HostDisconnect, None);
            assert!(
                r.table
                    .end_kept_by_device(id, said, "host_disconnect", Duration::ZERO)
            );
        }
        assert!(
            matches!(conn2.recv().await, Some(ClientMsg::Ice { .. })),
            "the loop reads its queue: room for one"
        );
        for want in [a, b] {
            serve_for(&mut r.table, Duration::from_secs(1)).await;
            match conn2.try_recv() {
                Ok(ClientMsg::Terminate {
                    session_id,
                    reason: EndReason::HostDisconnect,
                    ..
                }) => assert_eq!(session_id, want, "in order"),
                other => {
                    panic!("the end goes out on this connection once there is room: {other:?}")
                }
            }
        }
    }

    /// L8 — between a connection's start and its loop the setup waits on the
    /// hello's send (up to `WS_SEND_TIMEOUT`) and on the overlay's start
    /// (unbounded). Both run inside `serving_kept`, so a kept session's
    /// deadline and an end at the device are served meanwhile (spec §4.9).
    #[test]
    fn the_setup_serves_what_was_kept_while_it_waits() {
        let code = signaling_code();
        let setup = connection_setup(&code);
        assert!(
            setup.contains("serving_kept(send_msg(&mutws,&hello),"),
            "the hello is sent while the kept sessions are served"
        );
        assert!(
            setup.contains("letstart=crate::overlay::maybe_start(")
                && setup
                    .contains("serving_kept(start,peers,side,kill_rx,idle_rx,&indicator).await"),
            "the overlay starts while the kept sessions are served"
        );
        assert!(
            setup.contains("serving_kept(dial,peers,side,kill_rx,idle_rx,&indicator).await"),
            "and so does the dial, whichever path to the centre it takes"
        );
    }

    /// L9 — what a kept session reports for the audit while no connection is
    /// up (its recording's and its curtain's activity) goes out on the next
    /// one, as its end would. Its ICE is still dropped, and a report ends
    /// nothing.
    #[tokio::test(start_paused = true)]
    async fn a_kept_sessions_activity_reaches_the_next_connection() {
        let mut r = rig(true, Some(60), 1).await;
        let id = r.sessions[0].id;
        let held = r.sessions[0].held.clone();
        r.table.end_connection(ConnExit::ReadError).await;
        held.send(recording_activity(id)).await.unwrap();
        held.send(ice(id)).await.unwrap();
        held.send(privacy_activity(id)).await.unwrap();
        settled(&held).await;
        serve_for(&mut r.table, Duration::from_millis(100)).await;
        let (claim, _tx2, mut conn2) = reconnect(&mut r.table).await;
        assert_eq!(claim, vec![id], "a report ends nothing");
        assert!(
            matches!(conn2.try_recv(), Ok(ClientMsg::RecordingActivity { session_id, .. }) if session_id == id),
            "the recording's activity reaches the audit"
        );
        assert!(
            matches!(conn2.try_recv(), Ok(ClientMsg::PrivacyActivity { session_id, .. }) if session_id == id),
            "the curtain's activity reaches the audit"
        );
        assert!(conn2.try_recv().is_err(), "the ICE was dropped");
        assert_eq!(r.closes(), 0);
        r.table.close_all("test_end").await;
    }

    /// FR-130 P2b (R1, A11) — L11 lifted: a loop that holds the delegation
    /// host keeps what it can, with the switch on, as every loop does. What it
    /// cannot keep (an older worker's session, none attached) it does not
    /// claim, and the server ends that at the hello (D1). An unenrolled worker
    /// still speaks to no server and keeps nothing.
    #[test]
    fn p2b_a_loop_that_holds_the_delegation_host_keeps_with_the_switch() {
        assert!(connection_keeps(true, false));
        assert!(
            connection_keeps(true, true),
            "a supervised Mac's daemon keeps with the switch on"
        );
        assert!(!connection_keeps(false, false));
        assert!(!connection_keeps(false, true));
        assert!(
            signaling_code().contains(
                "letsurvive=crate::session_table::connection_keeps(\
                 crate::session_table::survive_enabled()&&!ctx.unenrolled,\
                 delegation.host().is_some()"
            ),
            "each connection reads its switch through it"
        );
    }

    /// The loop asks the table: a server's end closes through it (C1).
    #[test]
    fn the_signalling_loop_asks_the_table() {
        let code = signaling_code();
        assert!(
            code.contains("peers.close_terminated(peer,session_id,"),
            "C1: the server's end closes through the table"
        );
    }

    /// FR-130 D3 — an outsider's session is built with no link, so the table
    /// closes it at every exit, as before
    /// (`a_delegated_or_external_session_closes_at_a_transient_exit`). It is
    /// an outsider's when FR-52 sealed its answer, or when it was opened
    /// through a device share (its offer carries the share's lease), and the
    /// offer's one way into the table drops the link for it. A source check:
    /// the offer's arm needs a live socket, a binding and a peer.
    #[test]
    fn an_external_session_is_built_without_a_link() {
        let code = signaling_code();
        assert_eq!(
            code.matches("letexternal=extauth_mac.is_some()||shared_lease.is_some();")
                .count(),
            1,
            "D3: a session is an outsider's when FR-52 sealed its answer or a share opened it"
        );
        assert_eq!(
            code.matches(".insert(session_id,peer,").count(),
            1,
            "the offer's one way into the table"
        );
        assert!(
            code.contains("peers.insert(session_id,peer,link.filter(|_|!external))"),
            "D3: an outsider's session goes into the table with no link"
        );
    }

    // ─── FR-130 P4-0: the switch on with no window is the switch off ───────
    //
    // The switch's default is on (P4-1), so the server's window must be the
    // only thing that changes what a device does: a device the server's scope
    // does not cover is announced no window. So everything the switch alone
    // used to gate waits for a window this connection's server announced and
    // has not withdrawn. Each test below compares the switch on with no window
    // (none announced, one announced as 0, one withdrawn) against the switch
    // off, on what can be seen of a session: its peer's closes, whether it
    // stopped serving and what it said on its control channel, the end hook,
    // what stays held or kept, and what the server hears after the next hello.

    /// How the window stands when the device decides.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum NoWindow {
        /// The server announced none: a device the scope does not cover.
        Unannounced,
        /// It announced 0.
        Zero,
        /// It announced one and withdrew it (0) before the decision. A session
        /// the test builds is built under it.
        Withdrawn,
    }

    const NO_WINDOW: [NoWindow; 3] = [NoWindow::Unannounced, NoWindow::Zero, NoWindow::Withdrawn];

    /// `n` live sessions on a connection whose switch is `on`, the window
    /// standing as `w` once they are built.
    async fn no_window_rig(on: bool, w: NoWindow, n: usize) -> Rig {
        let built_under = (w == NoWindow::Withdrawn).then_some(60);
        let mut r = rig(on, built_under, n).await;
        if w != NoWindow::Unannounced {
            r.table.set_window(0);
        }
        r
    }

    fn drain(rx: &mut mpsc::Receiver<ClientMsg>) -> Vec<ClientMsg> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    /// What the next connection sees of the last one: its hello's claim, and
    /// what the server hears right after the hello.
    async fn next_hello(table: &mut SessionTable<Fake>) -> (usize, usize) {
        let on = table.keeps_sessions();
        let (tx, mut heard) = mpsc::channel(64);
        let claim = table.begin_connection(on).await.len();
        table.connected(&tx);
        (claim, drain(&mut heard).len())
    }

    /// What can be seen of a connection's end on the device.
    #[derive(Debug, PartialEq)]
    struct EndSurface {
        /// Per peer: its closes, whether it stopped serving, what it said.
        peers: Vec<(usize, bool, Vec<serde_json::Value>)>,
        /// The end hook: the banner, the lock, the recording.
        ends: Vec<RealEnd>,
        /// What still counts against the capacity, and what is kept.
        held: usize,
        kept: usize,
        /// Sent on the connection that ended.
        on_the_old: usize,
        /// The next hello's claim, and what the server hears after it.
        claim: usize,
        heard: usize,
    }

    async fn end_surface(mut r: Rig, exit: ConnExit) -> EndSurface {
        r.table.end_connection(exit).await;
        let peers = r
            .sessions
            .iter()
            .map(|s| (s.peer.closes(), s.peer.stopped(), s.peer.said()))
            .collect();
        let ends = r.ends.all().into_iter().map(|(_, e)| e).collect();
        let (held, kept) = (r.table.len(), r.table.kept_ids().len());
        let on_the_old = drain(&mut r.conn).len();
        let (claim, heard) = next_hello(&mut r.table).await;
        EndSurface {
            peers,
            ends,
            held,
            kept,
            on_the_old,
            claim,
            heard,
        }
    }

    /// The table at each of the sixteen arms: the switch on with no window
    /// ends a connection exactly as the switch off does, the same closes and
    /// hook calls, nothing kept and nothing queued for the server.
    #[tokio::test]
    async fn p4_0_with_no_window_every_arm_ends_as_with_the_switch_off() {
        for exit in ConnExit::ALL {
            let off = end_surface(rig(false, None, 2).await, exit).await;
            assert_eq!(
                off.peers,
                vec![(1, false, vec![]), (1, false, vec![])],
                "{exit:?}: off closes every peer"
            );
            assert_eq!((off.held, off.kept, off.claim), (0, 0, 0), "{exit:?}");
            for w in NO_WINDOW {
                let on = end_surface(no_window_rig(true, w, 2).await, exit).await;
                assert_eq!(
                    on, off,
                    "{exit:?}, {w:?}: the switch on with no window is the switch off"
                );
            }
        }
    }

    /// What can be seen of the server's end of a session (C1) on the device.
    #[derive(Debug, PartialEq)]
    struct TerminateSurface {
        /// Closed before the call returned.
        closed_at_once: usize,
        stopped: bool,
        /// Once the grace and more passed.
        closes: usize,
        said: Vec<serde_json::Value>,
    }

    /// The `Terminate` arm on the rig's first session: taken out, then C1.
    async fn terminate_surface(mut r: Rig) -> TerminateSurface {
        let id = r.sessions[0].id;
        let peer = r.sessions[0].peer.clone();
        let taken = r.table.take(&id, "terminate").expect("the table holds it");
        r.table
            .close_terminated(
                taken,
                id,
                &EndReason::AdminTerminated,
                Some("max_duration"),
                Duration::from_secs(1),
            )
            .await;
        let closed_at_once = peer.closes();
        let stopped = peer.stopped();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        TerminateSurface {
            closed_at_once,
            stopped,
            closes: peer.closes(),
            said: peer.said(),
        }
    }

    /// C1 — the server's end of an attached session (a kick, the maximum
    /// length) on a connection with no window closes the peer at once and
    /// says nothing on its channel, as with the switch off. With a window,
    /// one announced after the session went live too, it is said peer to peer
    /// first and the peer closes after the grace.
    #[tokio::test(start_paused = true)]
    async fn p4_0_with_no_window_the_servers_end_closes_at_once_as_off() {
        let off = terminate_surface(rig(false, None, 1).await).await;
        assert_eq!(
            (off.closed_at_once, off.stopped, off.closes),
            (1, false, 1),
            "{off:?}"
        );
        assert!(off.said.is_empty(), "{off:?}");
        for w in NO_WINDOW {
            let on = terminate_surface(no_window_rig(true, w, 1).await).await;
            assert_eq!(
                on, off,
                "{w:?}: the switch on with no window is the switch off"
            );
        }
        let mut r = rig(true, None, 1).await;
        r.table.set_window(60);
        let late = terminate_surface(r).await;
        assert_eq!(
            (late.closed_at_once, late.stopped, late.closes),
            (0, true, 1),
            "a window announced after the session went live: {late:?}"
        );
        assert_eq!(
            late.said,
            vec![serde_json::json!(
                {"t": "rc:ended", "reason": "admin_terminated", "limit": "max_duration"}
            )]
        );
    }

    /// C1 for a session kept under a window whose next connection is
    /// announced none (the server withdrew the device during the gap): the
    /// server refuses the claim and the peer closes at once, as off closes.
    /// Announced before the answer, as the server announces it to a device it
    /// covers, the end is said first.
    #[tokio::test(start_paused = true)]
    async fn p4_0_a_kept_sessions_end_on_a_connection_with_no_window_closes_at_once() {
        for announced in [false, true] {
            let mut r = rig(true, Some(60), 1).await;
            r.table.end_connection(ConnExit::ReadError).await;
            let (claim, _tx, _rx) = reconnect(&mut r.table).await;
            assert_eq!(claim.len(), 1, "announced={announced}: claimed");
            if announced {
                r.table.set_window(60);
            }
            let s = terminate_surface(r).await;
            assert_eq!(s.closes, 1, "announced={announced}: {s:?}");
            if announced {
                assert_eq!((s.closed_at_once, s.stopped), (0, true), "{s:?}");
                assert_eq!(s.said.len(), 1, "{s:?}");
            } else {
                assert_eq!((s.closed_at_once, s.stopped), (1, false), "{s:?}");
                assert!(s.said.is_empty(), "{s:?}");
            }
        }
    }

    /// FR-130 P4-0 — what the gates read. `window_open`: the switch and a
    /// window this connection was announced and has not had withdrawn, read at
    /// the decision, so one announced late counts from then. `keeping` (A1):
    /// that, or a session still kept from an earlier connection, whose peer is
    /// this loop's to close whatever the next connection is announced.
    #[tokio::test]
    async fn p4_0_the_gate_reads_the_window_at_the_decision() {
        let off = rig(false, Some(60), 0).await;
        assert!(
            !off.table.window_open() && !off.table.keeping(),
            "a window told to a device whose switch is off opens nothing"
        );
        for w in NO_WINDOW {
            let r = no_window_rig(true, w, 0).await;
            assert!(!r.table.window_open() && !r.table.keeping(), "{w:?}");
        }
        let mut r = rig(true, None, 1).await;
        r.table.set_window(60);
        assert!(r.table.window_open() && r.table.keeping(), "announced late");
        r.table.end_connection(ConnExit::ReadError).await;
        let (claim, _tx, _rx) = reconnect(&mut r.table).await;
        assert_eq!(claim.len(), 1);
        assert!(!r.table.window_open(), "each connection starts with none");
        assert!(r.table.keeping(), "a kept session is still this loop's");
        r.table.close_all("test_end").await;
        assert!(!r.table.keeping(), "nothing kept, no window: today's gate");
        assert_eq!(r.closes(), 1);
    }

    // ─── FR-130 P2b: Mac delegated sessions ─────────────────────────────────

    use crate::delegate::{DelegateFrame, SessionParams};

    struct RecordRig {
        table: SessionTable<Fake>,
        host: DelegateHost,
        frames: mpsc::Receiver<DelegateFrame>,
        conn: mpsc::Receiver<ClientMsg>,
        ids: Vec<ObjectId>,
    }

    fn keepable_params(id: ObjectId) -> SessionParams {
        SessionParams {
            session_id: id.to_hex(),
            shared_lease: None,
            codec: "h264".into(),
            transport: None,
            chroma: None,
            chunk_framing: false,
            audio: false,
            permissions: meshharbor_remote_control::permissions::Permissions::all(),
            controller_name: String::new(),
            input_mode: None,
            asking_org: None,
            record: None,
            rc_overlay: None,
            idle_secs: None,
            lock_on_end: None,
            initial_resolution: None,
            keepable: true,
        }
    }

    async fn record_rig(capacity: usize, window: Option<u32>, n: usize) -> RecordRig {
        let host = DelegateHost::new();
        let mut frames = host.attach_for_test();
        let mut table: SessionTable<Fake> = SessionTable::new(capacity, Ends::default().hook());
        table.set_host(host.clone());
        let (tx, conn) = mpsc::channel(64);
        assert!(table.begin_connection(true).await.is_empty());
        table.connected(&tx);
        host.set_outbound(tx.clone());
        if let Some(w) = window {
            table.set_window(w);
        }
        let mut ids = Vec::new();
        for _ in 0..n {
            let id = ObjectId::new();
            assert!(host.send_params(DelegateFrame::SessionParams(Box::new(keepable_params(id)))));
            table.cross_offer(id, table.live_generation());
            ids.push(id);
        }
        ids.sort();
        while frames.try_recv().is_ok() {}
        RecordRig {
            table,
            host,
            frames,
            conn,
            ids,
        }
    }

    async fn record_reconnect(
        r: &mut RecordRig,
    ) -> (
        Vec<ObjectId>,
        mpsc::Sender<ClientMsg>,
        mpsc::Receiver<ClientMsg>,
    ) {
        let (claim, tx, rx) = reconnect(&mut r.table).await;
        r.host.set_outbound(tx.clone());
        (claim, tx, rx)
    }

    fn sent(frames: &mut mpsc::Receiver<DelegateFrame>) -> Vec<DelegateFrame> {
        let mut out = Vec::new();
        while let Ok(f) = frames.try_recv() {
            out.push(f);
        }
        out
    }

    fn hexes(ids: &[ObjectId]) -> Vec<String> {
        ids.iter().map(|id| id.to_hex()).collect()
    }

    fn closes_of(frames: &[DelegateFrame]) -> Vec<String> {
        let mut out: Vec<String> = frames
            .iter()
            .filter_map(|f| match f {
                DelegateFrame::Close { session_id, .. } => Some(session_id.clone()),
                _ => None,
            })
            .collect();
        out.sort();
        out
    }

    fn resumes_of(frames: &[DelegateFrame]) -> Vec<String> {
        frames
            .iter()
            .filter_map(|f| match f {
                DelegateFrame::Resumed { session_id } => Some(session_id.clone()),
                _ => None,
            })
            .collect()
    }

    fn detaches_of(frames: &[DelegateFrame]) -> Vec<(Vec<String>, String, bool, u64)> {
        frames
            .iter()
            .filter_map(|f| match f {
                DelegateFrame::Detached {
                    sessions,
                    exit,
                    netchange,
                    keep_ms,
                } => Some((sessions.clone(), exit.clone(), *netchange, *keep_ms)),
                _ => None,
            })
            .collect()
    }

    fn endeds_of(frames: &[DelegateFrame]) -> Vec<(String, EndReason, Option<String>)> {
        frames
            .iter()
            .filter_map(|f| match f {
                DelegateFrame::Ended {
                    session_id,
                    reason,
                    limit,
                } => Some((session_id.clone(), *reason, limit.clone())),
                _ => None,
            })
            .collect()
    }

    fn ends_said(msgs: &[ClientMsg]) -> Vec<(ObjectId, EndReason)> {
        msgs.iter()
            .filter_map(|m| match m {
                ClientMsg::Terminate {
                    session_id, reason, ..
                } => Some((*session_id, *reason)),
                _ => None,
            })
            .collect()
    }

    fn stats(session_id: ObjectId) -> ClientMsg {
        serde_json::from_value(serde_json::json!({
            "t": "rc:session.stats",
            "session_id": session_id.to_hex(),
            "bytes_sent": 1, "bytes_recv": 1, "fps": 30.0, "rtt_ms": 10.0,
            "keyframe_requests": 0, "input_events": 0
        }))
        .expect("a stats sample")
    }

    fn ended(session_id: ObjectId, reason: EndReason, limit: Option<&str>) -> WorkerOrder {
        WorkerOrder::Ended {
            session_id: session_id.to_hex(),
            reason,
            limit: limit.map(str::to_string),
        }
    }

    fn sorted(mut ends: Vec<(ObjectId, RealEnd)>) -> Vec<(ObjectId, RealEnd)> {
        ends.sort_by_key(|(s, _)| *s);
        ends
    }

    /// FR-130 P2b — the signalling loop wires the delegated sessions through
    /// the tables: A1's gate, A2's word, A3's record, A7's end, the host given
    /// to the table that holds it, and the worker's delegated table (B1).
    #[test]
    fn p2b_the_signalling_loop_wires_the_delegated_sessions() {
        let code = signaling_code();
        for (needle, what) in [
            (
                "served_by_daemon(peers.keeping()",
                "A1: the gate asks the table first, while it keeps (P4-0)",
            ),
            ("session_keepable(", "A2: the params say keepable"),
            ("peers.cross_offer(", "A3: a crossed offer gets its record"),
            ("peers.drop_record(", "A7: a server end drops the record"),
            (
                "table.set_host(",
                "the host is lent to the table that holds it",
            ),
            (
                "SessionTable::for_worker(",
                "B1: the worker's delegated table",
            ),
            (
                "peers.drop_record(session_id,reason,limit.as_deref())",
                "the record's end carries the terminate's reason and limit",
            ),
            (
                "peers.cross_offer(*session_id,offer_generation)",
                "the record takes the generation read before the offer crossed",
            ),
            (
                ".obey(order,&self.channel,host_disconnect_grace())",
                "the worker's delegated table serves the daemon's orders",
            ),
        ] {
            assert!(code.contains(needle), "{what}: `{needle}`");
        }
        let read = code.find("letoffer_generation=peers.live_generation();");
        let send = code.find("&&delegate.send_to_worker(&msg)");
        assert!(
            read.is_some() && send.is_some() && read < send,
            "the generation is read before the send: {read:?} < {send:?}"
        );
        assert_eq!(
            code.matches("serving_delegated(").count(),
            4,
            "every non-transient sleep in `run` serves the orders lane"
        );
        assert!(
            code.contains("event=next_side(&mutside)=>serve_side(&mutside,event).await"),
            "the transient backoff serves the orders lane"
        );
        assert!(
            code.contains("event=next_side(side)=>serve_side(side,event).await"),
            "`serving_kept` serves the orders lane"
        );
    }

    #[tokio::test]
    async fn p2b_a_record_is_kept_at_every_transient_exit_and_the_worker_told_once() {
        for exit in ConnExit::ALL
            .into_iter()
            .filter(|e| e.kind() != ExitKind::Terminal)
        {
            let mut r = record_rig(8, Some(60), 2).await;
            r.table.end_connection(exit).await;
            assert_eq!(r.table.kept_ids(), r.ids, "{exit:?}: both are claimed");
            let frames = sent(&mut r.frames);
            let detached = detaches_of(&frames);
            assert_eq!(detached.len(), 1, "{exit:?}: one Detached a loss");
            let (sessions, label, netchange, keep_ms) = &detached[0];
            let mut sessions = sessions.clone();
            sessions.sort();
            assert_eq!(sessions, hexes(&r.ids), "{exit:?}");
            assert_eq!(label, exit.label(), "{exit:?}");
            assert_eq!(*netchange, exit.kind() == ExitKind::NetChange, "{exit:?}");
            assert_eq!(*keep_ms, 60_000, "{exit:?}: the window");
            assert!(closes_of(&frames).is_empty(), "{exit:?}: nothing closed");
        }
    }

    #[tokio::test]
    async fn p2b_a_terminal_exit_or_a_refused_token_drops_every_record() {
        for exit in ConnExit::ALL
            .into_iter()
            .filter(|e| e.kind() == ExitKind::Terminal)
        {
            let mut r = record_rig(8, Some(60), 2).await;
            assert_eq!(r.table.len(), 2, "{exit:?}: records count while live");
            r.table.end_connection(exit).await;
            let frames = sent(&mut r.frames);
            assert_eq!(closes_of(&frames), hexes(&r.ids), "{exit:?}: each closes");
            assert!(detaches_of(&frames).is_empty(), "{exit:?}");
            assert_eq!(r.table.len(), 0, "{exit:?}");
            let (claim, _tx, _rx) = record_reconnect(&mut r).await;
            assert!(claim.is_empty(), "{exit:?}: nothing claimed");
        }
        let mut r = record_rig(8, Some(60), 2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        let _ = sent(&mut r.frames);
        r.table.close_all("token_refused").await;
        assert_eq!(
            closes_of(&sent(&mut r.frames)),
            hexes(&r.ids),
            "a refused token closes the kept ones"
        );
        assert!(r.table.kept_ids().is_empty());
    }

    #[tokio::test]
    async fn p2b_with_no_window_no_record_is_made() {
        let mut r = record_rig(8, None, 1).await;
        assert!(!r.table.holds_record(&r.ids[0]), "no window, no record");
        r.table.end_connection(ConnExit::ReadError).await;
        assert!(r.table.kept_ids().is_empty());
        assert!(sent(&mut r.frames).is_empty(), "the worker is told nothing");
    }

    #[tokio::test]
    async fn p2b_resumed_reattaches_a_kept_record_and_tells_the_worker() {
        let mut r = record_rig(8, Some(60), 1).await;
        let id = r.ids[0];
        r.table.end_connection(ConnExit::ReadError).await;
        let _ = sent(&mut r.frames);
        let (claim, tx2, mut rx2) = record_reconnect(&mut r).await;
        assert_eq!(claim, vec![id]);
        assert!(r.table.resume(id, &tx2).await, "the claim is honoured");
        assert_eq!(resumes_of(&sent(&mut r.frames)), vec![id.to_hex()]);
        r.host.relay_upstream(ice(id));
        let got = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
            .await
            .ok()
            .flatten();
        assert!(
            matches!(got, Some(ClientMsg::Ice { session_id, .. }) if session_id == id),
            "the worker's reply reaches the new connection: {got:?}"
        );
        assert!(drain(&mut r.conn).is_empty(), "nothing on the old one");
    }

    #[tokio::test(start_paused = true)]
    async fn p2b_a_claim_answered_late_or_for_a_gone_worker_is_refused() {
        let mut r = record_rig(8, Some(60), 1).await;
        let id = r.ids[0];
        r.table.end_connection(ConnExit::ReadError).await;
        let _ = sent(&mut r.frames);
        let (claim, tx2, mut rx2) = record_reconnect(&mut r).await;
        assert_eq!(claim, vec![id]);
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(!r.table.resume(id, &tx2).await, "late");
        assert_eq!(closes_of(&sent(&mut r.frames)), vec![id.to_hex()]);
        assert!(
            ends_said(&drain(&mut rx2)).contains(&(id, EndReason::AgentDisconnect)),
            "the server hears it is gone"
        );

        let mut r = record_rig(8, Some(60), 1).await;
        let id = r.ids[0];
        r.table.end_connection(ConnExit::ReadError).await;
        let (claim, tx2, mut rx2) = record_reconnect(&mut r).await;
        assert_eq!(claim, vec![id], "claimed while its worker is attached");
        r.host.end_channel_for_test();
        assert!(!r.table.resume(id, &tx2).await, "its worker is gone");
        assert!(!r.table.holds_record(&id));
        assert!(ends_said(&drain(&mut rx2)).contains(&(id, EndReason::AgentDisconnect)));
    }

    #[tokio::test(start_paused = true)]
    async fn p2b_the_daemons_deadline_drops_the_record_and_closes_it_in_the_worker() {
        let mut r = record_rig(8, Some(60), 1).await;
        r.table.end_connection(ConnExit::ReadError).await;
        let _ = sent(&mut r.frames);
        serve_for(&mut r.table, Duration::from_secs(61)).await;
        assert_eq!(closes_of(&sent(&mut r.frames)), hexes(&r.ids));
        assert!(r.table.kept_ids().is_empty());
    }

    #[tokio::test]
    async fn p2b_a_workers_end_for_a_kept_record_follows_the_next_hello_in_order() {
        let mut r = record_rig(8, Some(60), 1).await;
        let id = r.ids[0];
        r.table.end_connection(ConnExit::ReadError).await;
        r.host.relay_upstream(recording_activity(id));
        r.host
            .relay_upstream(terminate(id, EndReason::HostDisconnect, None));
        serve_for(&mut r.table, Duration::from_millis(300)).await;
        assert!(
            drain(&mut r.conn).is_empty(),
            "nothing to the dead connection"
        );
        let (claim, _tx2, mut rx2) = record_reconnect(&mut r).await;
        assert!(claim.is_empty(), "an ended session is not claimed");
        let got = drain(&mut rx2);
        assert!(
            matches!(
                got.as_slice(),
                [
                    ClientMsg::RecordingActivity { session_id: a, .. },
                    ClientMsg::Terminate { session_id: b, reason: EndReason::HostDisconnect, .. },
                ] if *a == id && *b == id
            ),
            "the report, then the end, after the hello: {got:?}"
        );
    }

    #[tokio::test]
    async fn p2b_ice_and_stats_for_a_kept_record_are_dropped_and_never_wait() {
        let mut r = record_rig(8, Some(60), 1).await;
        let id = r.ids[0];
        r.table.end_connection(ConnExit::ReadError).await;
        for _ in 0..100 {
            r.host.relay_upstream(ice(id));
            r.host.relay_upstream(stats(id));
        }
        serve_for(&mut r.table, Duration::from_millis(300)).await;
        assert_eq!(r.table.kept_ids(), vec![id], "still kept for its claim");
        assert!(
            drain(&mut r.conn).is_empty(),
            "nothing to the dead connection"
        );
        let (_, _tx2, mut rx2) = record_reconnect(&mut r).await;
        assert!(drain(&mut rx2).is_empty(), "and nothing waits for the next");
    }

    #[tokio::test]
    async fn p2b_records_of_a_gone_worker_are_never_claimed_or_counted() {
        let mut r = record_rig(8, Some(60), 2).await;
        assert_eq!(r.table.len(), 2, "counted while their worker is attached");
        r.host.end_channel_for_test();
        assert_eq!(r.table.len(), 0, "not once it is gone");
        r.table.end_connection(ConnExit::ReadError).await;
        assert!(r.table.kept_ids().is_empty(), "never claimed");
        assert!(!r.table.has_kept());
        assert!(!r.table.full_beside_kept());
    }

    #[tokio::test]
    async fn p2b_a_worker_gone_while_the_socket_is_up_ends_its_records_as_error() {
        let mut r = record_rig(8, Some(60), 2).await;
        r.host.end_channel_for_test();
        serve_for(&mut r.table, Duration::from_millis(300)).await;
        let mut ended: Vec<ObjectId> = ends_said(&drain(&mut r.conn))
            .into_iter()
            .filter(|(_, reason)| *reason == EndReason::Error)
            .map(|(s, _)| s)
            .collect();
        ended.sort();
        assert_eq!(ended, r.ids, "each ends as error, once");
        assert!(!r.table.holds_record(&r.ids[0]));
    }

    #[tokio::test]
    async fn p2b_kept_records_count_against_the_capacity() {
        let mut r = record_rig(2, Some(60), 2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        assert!(
            r.table.full_beside_kept(),
            "a third request is refused as busy"
        );
        let _ = record_reconnect(&mut r).await;
        assert!(r.table.full_beside_kept(), "until the claim is answered");

        let mut r = record_rig(1, Some(60), 2).await;
        r.table.end_connection(ConnExit::ReadError).await;
        assert_eq!(r.table.kept_ids().len(), 1, "no more than the capacity");
        assert_eq!(
            closes_of(&sent(&mut r.frames)).len(),
            1,
            "the other closes in the worker"
        );
    }

    struct WorkerRig {
        table: SessionTable<Fake>,
        ends: Ends,
        channel: mpsc::Receiver<ClientMsg>,
        tx: mpsc::Sender<ClientMsg>,
        sessions: Vec<Session>,
    }

    impl WorkerRig {
        fn closes(&self) -> usize {
            self.sessions.iter().map(|s| s.peer.closes()).sum()
        }
    }

    async fn worker_rig(n: usize) -> WorkerRig {
        let ends = Ends::default();
        let (tx, channel) = mpsc::channel(64);
        let mut table = SessionTable::for_worker(8, ends.hook(), &tx);
        let mut sessions = Vec::new();
        for _ in 0..n {
            sessions.push(attach(&mut table, &tx).await);
        }
        WorkerRig {
            table,
            ends,
            channel,
            tx,
            sessions,
        }
    }

    const WINDOW: Duration = Duration::from_secs(60);

    #[tokio::test(start_paused = true)]
    async fn p2b_worker_detached_keeps_only_the_named_sessions_until_its_deadline() {
        let mut w = worker_rig(3).await;
        let (a, b) = (w.sessions[0].id, w.sessions[1].id);
        let mut named = vec![a, b];
        named.sort();
        w.table
            .detach_named(&named, ConnExit::ReadError, WINDOW)
            .await;
        assert_eq!(w.table.kept_ids(), named, "the named two are kept");
        assert_eq!(w.table.attached_len(), 1, "another stays attached");
        assert_eq!(w.closes(), 0);
        serve_for(&mut w.table, Duration::from_secs(61)).await;
        assert_eq!(w.sessions[0].peer.closes(), 1);
        assert_eq!(w.sessions[1].peer.closes(), 1);
        assert_eq!(w.sessions[2].peer.closes(), 0);
        assert_eq!(w.ends.all().len(), 2, "each kept one's real end");

        let mut w = worker_rig(1).await;
        let a = w.sessions[0].id;
        w.table
            .detach_named(&[a], ConnExit::ReadError, Duration::from_secs(600))
            .await;
        serve_for(&mut w.table, WINDOW_CAP + Duration::from_secs(1)).await;
        assert_eq!(w.closes(), 1, "a window past the cap is capped");
    }

    #[tokio::test]
    async fn p2b_worker_a_dead_peer_at_detached_closes_and_says_error_up_the_channel() {
        let mut w = worker_rig(1).await;
        let a = w.sessions[0].id;
        w.sessions[0].peer.set_dead();
        w.table
            .detach_named(&[a], ConnExit::ReadError, WINDOW)
            .await;
        assert_eq!(w.sessions[0].peer.closes(), 1);
        assert!(w.table.kept_ids().is_empty());
        assert_eq!(
            ends_said(&drain(&mut w.channel)),
            vec![(a, EndReason::Error)]
        );
    }

    #[tokio::test]
    async fn p2b_worker_resumed_reattaches_and_its_sends_go_up_the_channel_again() {
        let mut w = worker_rig(1).await;
        let id = w.sessions[0].id;
        let held = w.sessions[0].held.clone();
        w.table
            .detach_named(&[id], ConnExit::ReadError, WINDOW)
            .await;
        held.send(ice(id)).await.unwrap();
        settled(&held).await;
        assert!(drain(&mut w.channel).is_empty(), "kept, its ICE is dropped");
        let tx = w.tx.clone();
        assert!(w.table.resume(id, &tx).await);
        held.send(ice(id)).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), w.channel.recv())
            .await
            .ok()
            .flatten();
        assert!(
            matches!(got, Some(ClientMsg::Ice { session_id, .. }) if session_id == id),
            "resumed, it goes up the channel: {got:?}"
        );
        w.table.close_all("test_end").await;
    }

    #[tokio::test]
    async fn p2b_worker_a_delegated_peers_own_end_closes_it_at_once() {
        let mut w = worker_rig(2).await;
        let (a, b) = (w.sessions[0].id, w.sessions[1].id);
        w.sessions[0]
            .held
            .send(terminate(a, EndReason::Error, None))
            .await
            .unwrap();
        serve_for(&mut w.table, Duration::from_millis(300)).await;
        assert_eq!(
            w.sessions[0].peer.closes(),
            1,
            "attached, closed with no echo"
        );
        assert!(
            w.ends.all().contains(&(a, RealEnd::Ended)),
            "its real end ran: the banner, the recording"
        );
        w.table
            .detach_named(&[b], ConnExit::ReadError, WINDOW)
            .await;
        w.sessions[1]
            .held
            .send(terminate(b, EndReason::Error, None))
            .await
            .unwrap();
        serve_for(&mut w.table, Duration::from_millis(300)).await;
        assert_eq!(w.sessions[1].peer.closes(), 1, "kept, closed too");
        assert_eq!(
            ends_said(&drain(&mut w.channel)),
            vec![(a, EndReason::Error), (b, EndReason::Error)],
            "each end goes up the channel once"
        );
        assert_eq!(w.table.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn p2b_worker_a_disconnect_or_the_idle_limit_ends_it_and_its_end_goes_up() {
        let mut w = worker_rig(3).await;
        let (a, b, c) = (w.sessions[0].id, w.sessions[1].id, w.sessions[2].id);
        let mut named = vec![a, b];
        named.sort();
        w.table
            .detach_named(&named, ConnExit::ReadError, WINDOW)
            .await;
        let grace = Duration::from_millis(500);
        assert!(w.table.end_by_device(
            a,
            terminate(a, EndReason::HostDisconnect, None),
            "host_disconnect",
            grace
        ));
        assert!(w.table.end_by_device(
            b,
            terminate(b, EndReason::IdleTimeout, None),
            "idle_timeout",
            grace
        ));
        assert!(
            w.table.end_by_device(
                c,
                terminate(c, EndReason::HostDisconnect, None),
                "host_disconnect",
                grace
            ),
            "an attached one of this table too"
        );
        tokio::time::sleep(grace * 2).await;
        for s in &w.sessions {
            assert!(s.peer.stopped(), "{} stops at once", s.id);
            assert_eq!(s.peer.closes(), 1, "{} closes after the grace", s.id);
        }
        assert_eq!(w.sessions[0].peer.said()[0]["reason"], "host_disconnect");
        assert_eq!(w.sessions[1].peer.said()[0]["reason"], "idle_timeout");
        assert_eq!(
            ends_said(&drain(&mut w.channel)),
            vec![
                (a, EndReason::HostDisconnect),
                (b, EndReason::IdleTimeout),
                (c, EndReason::HostDisconnect),
            ]
        );
        assert!(
            w.ends
                .all()
                .iter()
                .all(|(_, end)| *end == RealEnd::HostEnded),
            "the person ended them"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn p2b_worker_a_server_end_of_a_kept_session_is_said_then_closes() {
        let mut w = worker_rig(1).await;
        let a = w.sessions[0].id;
        w.table
            .detach_named(&[a], ConnExit::ReadError, WINDOW)
            .await;
        assert_eq!(w.table.kept_ids(), vec![a], "kept");
        let peer = w.table.take(&a, "terminate").expect("held");
        let grace = Duration::from_millis(500);
        w.table
            .close_terminated(peer, a, &EndReason::AdminTerminated, None, grace)
            .await;
        tokio::time::sleep(grace * 2).await;
        assert_eq!(w.sessions[0].peer.said()[0]["reason"], "admin_terminated");
        assert_eq!(w.sessions[0].peer.closes(), 1);
    }

    #[tokio::test]
    async fn p2b_worker_close_closes_a_held_session_once_and_nothing_else() {
        let mut w = worker_rig(2).await;
        let (a, b) = (w.sessions[0].id, w.sessions[1].id);
        w.table
            .detach_named(&[b], ConnExit::ReadError, WINDOW)
            .await;
        w.table.close_session(a, "close").await;
        w.table.close_session(b, "deadline").await;
        w.table.close_session(ObjectId::new(), "deadline").await;
        w.table.close_session(a, "close").await;
        assert_eq!(w.sessions[0].peer.closes(), 1, "attached");
        assert_eq!(w.sessions[1].peer.closes(), 1, "kept");
        assert_eq!(w.table.len(), 0);
        assert_eq!(
            sorted(w.ends.all()),
            sorted(vec![(a, RealEnd::Ended), (b, RealEnd::Ended)])
        );
        assert!(drain(&mut w.channel).is_empty(), "nothing goes up");
    }

    #[tokio::test]
    async fn p2b_worker_a_paused_or_kept_link_never_waits_on_a_full_channel() {
        let ends = Ends::default();
        let (tx, _channel) = mpsc::channel(1);
        tx.try_send(ice(ObjectId::new())).unwrap();
        let mut table: SessionTable<Fake> = SessionTable::for_worker(8, ends.hook(), &tx);
        let a = attach(&mut table, &tx).await;
        let b = attach(&mut table, &tx).await;
        table.pause();
        let (held, id) = (a.held.clone(), a.id);
        let paused = tokio::time::timeout(Duration::from_secs(2), async move {
            for _ in 0..1000 {
                held.send(ice(id)).await.unwrap();
            }
        })
        .await;
        assert!(
            paused.is_ok(),
            "paused, an attached session's sends never wait"
        );
        table
            .detach_named(&[b.id], ConnExit::ReadError, WINDOW)
            .await;
        let (held, id) = (b.held.clone(), b.id);
        let kept = tokio::time::timeout(Duration::from_secs(2), async move {
            for _ in 0..1000 {
                held.send(ice(id)).await.unwrap();
            }
        })
        .await;
        assert!(kept.is_ok(), "kept, they never wait");
        table.close_all("test_end").await;
        assert_eq!(a.peer.closes() + b.peer.closes(), 2);
    }

    #[tokio::test]
    async fn p2b_review_a_refused_claim_is_ordered_to_the_worker() {
        let mut r = record_rig(8, Some(60), 1).await;
        let id = r.ids[0];
        r.table.end_connection(ConnExit::ReadError).await;
        let (claim, _tx, _rx) = record_reconnect(&mut r).await;
        assert_eq!(claim, vec![id], "claimed");
        let _ = sent(&mut r.frames);
        r.table.drop_record(&id, &EndReason::AdminTerminated, None);
        assert_eq!(
            endeds_of(&sent(&mut r.frames)),
            vec![(id.to_hex(), EndReason::AdminTerminated, None)],
            "the worker is ordered to end it, with the kick's reason"
        );
        assert!(!r.table.holds_record(&id));
    }

    #[tokio::test]
    async fn p2b_review_a_server_end_of_an_attached_record_is_ordered_to_its_worker() {
        let mut r = record_rig(8, Some(60), 2).await;
        let (a, b) = (r.ids[0], r.ids[1]);
        r.table
            .drop_record(&a, &EndReason::IdleTimeout, Some("max_duration"));
        assert_eq!(
            endeds_of(&sent(&mut r.frames)),
            vec![(
                a.to_hex(),
                EndReason::IdleTimeout,
                Some("max_duration".to_string())
            )],
            "the maximum length, ordered with its limit"
        );
        r.host.end_channel_for_test();
        let mut next_worker = r.host.attach_for_test();
        r.table.drop_record(&b, &EndReason::ControllerHangup, None);
        assert!(
            endeds_of(&sent(&mut next_worker)).is_empty(),
            "a gone worker's record is not the next worker's to end"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn p2b_review_the_worker_ends_a_session_on_the_daemons_order() {
        let mut w = worker_rig(2).await;
        let (a, b) = (w.sessions[0].id, w.sessions[1].id);
        w.table
            .detach_named(&[a], ConnExit::ReadError, WINDOW)
            .await;
        let tx = w.tx.clone();
        let grace = Duration::from_millis(500);
        w.table
            .obey(ended(a, EndReason::AdminTerminated, None), &tx, grace)
            .await;
        w.table
            .obey(
                ended(b, EndReason::IdleTimeout, Some("max_duration")),
                &tx,
                grace,
            )
            .await;
        assert!(
            w.sessions[0].peer.stopped() && w.sessions[1].peer.stopped(),
            "control stops at once"
        );
        tokio::time::sleep(grace * 2).await;
        let said = |s: &Session| {
            s.peer
                .said()
                .first()
                .map(|v| (v["reason"].clone(), v["limit"].clone()))
        };
        assert_eq!(
            said(&w.sessions[0]),
            Some((
                serde_json::json!("admin_terminated"),
                serde_json::Value::Null
            )),
            "kept: the kick is said on its control channel"
        );
        assert_eq!(
            said(&w.sessions[1]),
            Some((
                serde_json::json!("idle_timeout"),
                serde_json::json!("max_duration")
            )),
            "attached: the maximum length is said, with its limit"
        );
        assert_eq!(w.closes(), 2, "each closes once, after the grace");
        assert_eq!(
            sorted(w.ends.all()),
            sorted(vec![(a, RealEnd::Ended), (b, RealEnd::Ended)]),
            "each real end ran: the recording, the banner"
        );
        assert_eq!(w.table.len(), 0);
        assert!(
            w.table.take(&a, "terminate").is_none(),
            "the Terminate read after it finds nothing"
        );
        w.table
            .obey(ended(a, EndReason::AdminTerminated, None), &tx, grace)
            .await;
        tokio::time::sleep(grace * 2).await;
        assert_eq!(w.closes(), 2, "a second end closes nothing more");
    }

    #[tokio::test]
    async fn p2b_review_a_channel_end_closes_every_delegated_session() {
        let mut w = worker_rig(2).await;
        let (a, b) = (w.sessions[0].id, w.sessions[1].id);
        w.table
            .detach_named(&[b], ConnExit::ReadError, WINDOW)
            .await;
        let tx = w.tx.clone();
        w.table
            .obey(
                WorkerOrder::Paused {
                    cause: "Connection reset by peer (os error 54)".into(),
                },
                &tx,
                Duration::ZERO,
            )
            .await;
        assert_eq!(w.sessions[0].peer.closes(), 1, "attached: closed");
        assert_eq!(w.sessions[1].peer.closes(), 1, "kept: closed");
        assert_eq!(w.table.len(), 0, "nothing left for the next attach");
        assert_eq!(
            sorted(w.ends.all()),
            sorted(vec![(a, RealEnd::Ended), (b, RealEnd::Ended)]),
            "each real end ran"
        );
        let mut said = ends_said(&drain(&mut w.channel));
        said.sort_by_key(|(s, _)| *s);
        let mut gone = vec![
            (a, EndReason::AgentDisconnect),
            (b, EndReason::AgentDisconnect),
        ];
        gone.sort_by_key(|(s, _)| *s);
        assert_eq!(said, gone, "each says it is gone");
        w.table
            .obey(WorkerOrder::Attached, &tx, Duration::ZERO)
            .await;
        assert_eq!(w.closes(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn p2b_review_the_workers_own_deadline_says_the_session_is_gone() {
        let mut w = worker_rig(1).await;
        let a = w.sessions[0].id;
        w.table
            .detach_named(&[a], ConnExit::ReadError, WINDOW)
            .await;
        serve_for(&mut w.table, WINDOW + Duration::from_secs(1)).await;
        assert_eq!(w.sessions[0].peer.closes(), 1, "closed at its deadline");
        assert_eq!(
            ends_said(&drain(&mut w.channel)),
            vec![(a, EndReason::AgentDisconnect)],
            "the daemon hears it is gone"
        );
    }

    #[tokio::test]
    async fn p2b_review2_a_late_paused_says_each_session_it_closes_is_gone() {
        let mut w = worker_rig(1).await;
        let a = w.sessions[0].id;
        let mut r = record_rig(8, Some(60), 0).await;
        assert!(
            r.host
                .send_params(DelegateFrame::SessionParams(Box::new(keepable_params(a))))
        );
        r.table.cross_offer(a, r.table.live_generation());
        while r.frames.try_recv().is_ok() {}
        assert_eq!(r.table.len(), 1, "the record counts");

        let tx = w.tx.clone();
        w.table
            .obey(
                WorkerOrder::Paused {
                    cause: "Broken pipe (os error 32)".into(),
                },
                &tx,
                Duration::ZERO,
            )
            .await;
        assert_eq!(w.sessions[0].peer.closes(), 1, "closed");
        let up = drain(&mut w.channel);
        assert_eq!(
            ends_said(&up),
            vec![(a, EndReason::AgentDisconnect)],
            "its end goes up the channel"
        );

        for msg in up {
            r.host.relay_upstream(msg);
        }
        serve_for(&mut r.table, Duration::from_millis(300)).await;
        assert_eq!(r.table.len(), 0, "the record goes");
        assert_eq!(
            ends_said(&drain(&mut r.conn)),
            vec![(a, EndReason::AgentDisconnect)],
            "the server hears the end"
        );
    }

    async fn host_rig(on: bool, w: NoWindow, n: usize) -> RecordRig {
        let host = DelegateHost::new();
        let mut frames = host.attach_for_test();
        let mut table: SessionTable<Fake> = SessionTable::new(8, Ends::default().hook());
        table.set_host(host.clone());
        let (tx, conn) = mpsc::channel(64);
        assert!(table.begin_connection(on).await.is_empty());
        table.connected(&tx);
        host.set_outbound(tx.clone());
        if w == NoWindow::Withdrawn {
            table.set_window(60);
        }
        if w != NoWindow::Unannounced {
            table.set_window(0);
        }
        let mut ids = Vec::new();
        for _ in 0..n {
            let id = ObjectId::new();
            assert!(host.send_params(DelegateFrame::SessionParams(Box::new(keepable_params(id)))));
            table.cross_offer(id, table.live_generation());
            ids.push(id);
        }
        ids.sort();
        while frames.try_recv().is_ok() {}
        RecordRig {
            table,
            host,
            frames,
            conn,
            ids,
        }
    }

    fn told(frames: &[DelegateFrame]) -> Vec<&'static str> {
        frames
            .iter()
            .map(|f| match f {
                DelegateFrame::Detached { .. } => "detached",
                DelegateFrame::Resumed { .. } => "resumed",
                DelegateFrame::Close { .. } => "close",
                DelegateFrame::Ended { .. } => "ended",
                _ => "other",
            })
            .collect()
    }

    #[derive(Debug, PartialEq)]
    struct HostSurface {
        records: usize,
        len: usize,
        told: Vec<&'static str>,
        kept: usize,
        claim: usize,
        heard: usize,
    }

    async fn host_surface(mut r: RecordRig, exit: ConnExit) -> HostSurface {
        let records = r.ids.iter().filter(|s| r.table.holds_record(s)).count();
        let len = r.table.len();
        r.table
            .drop_record(&r.ids[0], &EndReason::AdminTerminated, None);
        r.table.end_connection(exit).await;
        let told = told(&sent(&mut r.frames));
        let kept = r.table.kept_ids().len();
        let (claim, heard) = next_hello(&mut r.table).await;
        HostSurface {
            records,
            len,
            told,
            kept,
            claim,
            heard: heard + drain(&mut r.conn).len(),
        }
    }

    #[tokio::test]
    async fn p4_0_with_no_window_the_delegation_host_is_the_switch_off() {
        for exit in ConnExit::ALL {
            let off = host_surface(host_rig(false, NoWindow::Unannounced, 2).await, exit).await;
            assert_eq!((off.records, off.len), (0, 0), "{exit:?}: {off:?}");
            assert!(off.told.is_empty(), "{exit:?}: {off:?}");
            for w in NO_WINDOW {
                let on = host_surface(host_rig(true, w, 2).await, exit).await;
                assert_eq!(
                    on, off,
                    "{exit:?}, {w:?}: the switch on with no window is the switch off"
                );
            }
        }
    }

    #[tokio::test]
    async fn p4_0_a_record_made_under_a_window_withdrawn_since_closes_at_the_exit() {
        for exit in ConnExit::ALL {
            let mut r = record_rig(8, Some(60), 1).await;
            assert!(r.table.holds_record(&r.ids[0]), "{exit:?}: made");
            assert_eq!(r.table.set_window(0), None);
            r.table.end_connection(exit).await;
            assert!(r.table.kept_ids().is_empty(), "{exit:?}");
            let frames = sent(&mut r.frames);
            assert_eq!(told(&frames), vec!["close"], "{exit:?}");
            assert_eq!(closes_of(&frames), hexes(&r.ids), "{exit:?}");
            assert!(!r.table.holds_record(&r.ids[0]), "{exit:?}");
        }
    }

    #[test]
    fn p4_0_the_signalling_loop_gates_on_the_window() {
        let code = signaling_code();
        for (needle, what) in [
            (
                "keepable:crate::delegate::session_keepable(peers.window_open(),",
                "A2: offered keepable only under a window",
            ),
            (
                "!crate::delegate::served_by_daemon(peers.keeping(),",
                "A1: the daemon serves what it holds while it keeps",
            ),
        ] {
            assert!(code.contains(needle), "{what}: `{needle}`");
        }
        for stale in [
            "session_keepable(peers.keeps_sessions()",
            "served_by_daemon(peers.keeps_sessions()",
        ] {
            assert!(
                !code.contains(stale),
                "the switch alone gates nothing new: `{stale}`"
            );
        }
    }

    /// FR-130 P4-1 — the switch defaults on. Only `0`, `false`, `no` or
    /// `off` turns it off; an empty or an unknown value keeps it on, as every
    /// default-on gate reads (`tunnel_core::env::flag`). The server's window
    /// still stages the fleet: with no window the switch on is the switch off
    /// (P4-0, the tests above).
    #[test]
    fn p4_1_the_switch_defaults_on() {
        let code: String = include_str!("session_table.rs")
            .split("\nmod tests {")
            .next()
            .unwrap()
            .split_whitespace()
            .collect();
        assert!(
            code.contains(
                "fnsurvive_enabled()->bool{tunnel_core::env::flag(\"RC_SESSIONS_SURVIVE_REATTACH\",true)}"
            ),
            "the switch reads default-on"
        );
        // That reading, on a suffix nothing else reads.
        const SUFFIX: &str = "FR130_P4_1_TEST_SWITCH";
        let var = format!("MESHHARBORD_{SUFFIX}");
        assert!(tunnel_core::env::flag(SUFFIX, true), "unset is on");
        for (value, on) in [
            ("", true),
            ("garbage", true),
            ("1", true),
            ("on", true),
            ("0", false),
            ("false", false),
            ("No", false),
            ("OFF", false),
        ] {
            // SAFETY: a suffix no other test reads, set and removed here alone.
            unsafe { std::env::set_var(&var, value) };
            assert_eq!(tunnel_core::env::flag(SUFFIX, true), on, "{value:?}");
        }
        unsafe { std::env::remove_var(&var) };
    }
}
