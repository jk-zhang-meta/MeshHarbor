// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-43 P2a — the daemon side of the GUI-worker delegation channel.
//!
//! macOS forces two processes (a root LaunchDaemon has no WindowServer; a
//! GUI-session process cannot create a `utun`) but not two enrollments. The
//! daemon holds the enrollment and the worker holds the screen, so an rc
//! session has to cross between them. This module owns the crossing.
//!
//! **P2a is the channel only.** It carries the handshake and liveness; the nine
//! rc-session payloads land in P2b. The channel ships on its own because it is
//! the invasive half — an exception to LocalAPI's request/response invariant
//! (`localapi::Request::RcAttach`) — and an exception deserves to be proven
//! before anything is built on top of it.
//!
//! ## Why a secret, when every other verb trusts the socket
//!
//! For every other LocalAPI verb the 0600 socket **is** the authorisation: a
//! caller that can open it is the owning user or root, and the verbs are things
//! that user is entitled to do. Attaching is not like that. The legitimate
//! worker is an ordinary process in the user's session — and so is an
//! attacker's. Without a secret, any process in that session could volunteer to
//! serve the device's remote-control sessions: to be the thing that sees the
//! screen and receives the keystrokes.
//!
//! So the daemon mints a fresh secret for each worker it spawns and hands it
//! over **on the worker's stdin**. It is never written to disk, never in argv,
//! and never leaves the host.
//!
//! ⚠️ Two obvious alternatives were measured on a real Mac and rejected, and
//! both failures are silent, which is why they were measured rather than
//! assumed:
//!
//! - **the environment** — `sudo` in the spawn chain runs under the stock
//!   `Defaults env_reset` and discards it. This is not hypothetical: P1's
//!   `ROOMLER_MACOS_SUPERVISED` marker went out this way and never reached a
//!   single worker, unnoticed because nothing read it yet.
//! - **an inherited socketpair**, where possession of the fd would BE the
//!   authorisation — strictly better, but `sudo` closes inherited descriptors
//!   too. Recorded under "Dead hypotheses" in the FR, including that
//!   `launchctl asuser` alone preserves them, so it returns if the chain ever
//!   drops `sudo`.
//!
//! ## Default-deny, three ways
//!
//! 1. No secret issued means refuse. That is the state whenever the supervisor
//!    is off or launchd owns the worker, so "the feature is disabled" is not a
//!    separate code path — it is the absence of a secret.
//! 2. One attached worker at a time. A second attach is refused rather than
//!    displacing the first, because displacement is a denial-of-service
//!    primitive for any local process that guesses right.
//! 3. The secret is revoked when the worker stops, so a worker the supervisor
//!    has already released cannot come back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use roomler_ai_remote_control::models::AgentCaps;
use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Bytes of entropy in a minted secret, hex-encoded on the wire. The channel is
/// local and the secret lives for one spawn, so this is far past what an
/// attacker could grind, and it costs nothing.
// Used by `mint`, which only the unix listener path calls in production; the
// tests exercise it on every platform.
#[cfg_attr(not(unix), allow(dead_code))]
const SECRET_BYTES: usize = 32;

/// Directory holding the delegation socket.
///
/// Deliberately NOT the LocalAPI directory. `/var/run/roomler` is `0700 root`
/// so that nothing unprivileged can even reach the control socket, and that is
/// worth keeping exactly as it is: the worker needs to traverse ITS directory,
/// and widening the control socket's would trade a real protection for an
/// unrelated feature.
#[cfg(unix)]
const DELEGATE_DIR: &str = "/var/run/roomler-delegate";

/// One frame on the delegation channel.
///
/// Newline-delimited JSON, matching the LocalAPI protocol's shape but not its
/// wire: this is a private protocol between two processes of one install, so it
/// lives here rather than in the shared protocol crate.
///
/// P2a carries the handshake and liveness. The rc-session payloads
/// (`SessionCreated` / `SdpOffer` / `SdpAnswer` / `Ice` / `Terminate` inbound,
/// `SdpAnswer` / `Ice` / `SessionStats` / `Terminate` outbound) land in P2b.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "d", rename_all = "snake_case")]
pub enum DelegateFrame {
    /// Daemon → worker, first frame: the attach was accepted.
    Attached {
        /// The daemon's version, so a worker can refuse a mismatch loudly
        /// instead of failing obscurely on a payload it cannot parse. Both ends
        /// ship in one binary, but the update path replaces them independently.
        daemon_version: String,
    },
    /// Either direction — liveness. A channel with no traffic is
    /// indistinguishable from a wedged one, and the daemon must be able to tell
    /// "no sessions right now" from "the worker is gone" *before* a controller
    /// is waiting on it.
    Ping,
    /// Either direction — the answer to [`DelegateFrame::Ping`].
    Pong,
    /// Daemon → worker: an rc-session message the daemon received on its
    /// control WS and is not able to serve itself.
    ///
    /// Carries `ServerMsg` verbatim rather than a translated shape. The two
    /// ends are the same binary, so a parallel representation would be a
    /// second definition of a wire that already exists — and the one thing
    /// worse than a protocol is two of them drifting apart.
    ToWorker { msg: Box<ServerMsg> },
    /// Worker → daemon: an rc-session message to put on the control WS.
    FromWorker { msg: Box<ClientMsg> },
    /// Worker → daemon: the worker's own capabilities, sent at attach and
    /// again whenever its `record` caps change (FR-85 P1e-mac: the person's
    /// remote-recording gate is live).
    ///
    /// FR-43 P2c. The daemon runs in session 0 and honestly reports
    /// `no-gui-session`; the worker is in the GUI session and holds the real
    /// grants. While a worker is attached, the DEVICE is a capture target, and
    /// the row has to say so or the dashboard tells the operator it is not one.
    WorkerCaps { caps: Box<AgentCaps> },
    /// Daemon → worker: everything the daemon resolved while answering
    /// `rc:session.request`, which the worker's `rc:sdp.offer` handler needs.
    SessionParams(Box<SessionParams>),
    /// #1882 — daemon → worker: the overlay's v4 blocks, as the daemon's
    /// `tunnel_core::overlay_footprint` has them.
    ///
    /// The worker runs no overlay (a GUI-session process cannot create a
    /// `utun`), yet it serves its OWN enrollment's remote-desktop sessions, and
    /// those resolve the device's `rc_overlay` against the worker's footprint.
    /// Empty, it read the `utunN` address as foreign, and a session meant to
    /// stay off the overlay offered it as a host candidate (field, 0.4.122:
    /// `overlay_blocks=0`). Sent after [`DelegateFrame::Attached`] and again
    /// with a [`DelegateFrame::Pong`] whenever the set has grown; the worker
    /// adds what it is told, since the registry only grows. An older worker
    /// skips the frame, as every reader here skips what it does not know.
    OverlayFootprint {
        v4_nets: Vec<(std::net::Ipv4Addr, u8)>,
    },
    /// FR-92 — daemon → worker: a `roomler keep-busy status|off` that reached
    /// the DAEMON's LocalAPI. A root caller — `roomler exec <mac> roomler
    /// keep-busy off` — never sees the worker's per-user socket, while on a
    /// supervised Mac it is the worker that runs keep busy. So the daemon
    /// asks; `off` stops it first. The answer is
    /// [`DelegateFrame::KeepBusyTold`] with the same `id`.
    ///
    /// ⚠️ Before this the daemon answered for its own engine, which never runs
    /// there: a root `off` said "off" while the worker kept moving the pointer
    /// (field, 0.4.126). An older worker skips the frame, and the daemon then
    /// answers for itself as before, after [`KEEP_BUSY_ASK_WAIT`].
    KeepBusyAsk { id: u64, off: bool },
    /// FR-92 — worker → daemon: the worker's keep-busy state, answering the
    /// [`DelegateFrame::KeepBusyAsk`] with this `id`.
    KeepBusyTold {
        id: u64,
        info: Box<tunnel_core::localapi::KeepBusyInfo>,
    },
}

/// FR-92 — how long the daemon waits for the worker's answer to a
/// [`DelegateFrame::KeepBusyAsk`]: a local `off` waits up to
/// [`crate::keep_busy::LOCAL_OFF_WAIT`] for the engine, plus the crossing.
pub const KEEP_BUSY_ASK_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Everything the daemon resolved for a session while answering
/// `rc:session.request`.
///
/// ⚠️ This type exists because the five "rc-session" messages are NOT
/// independent: `Request` RESOLVES a session's parameters and stashes them, and
/// `SdpOffer` CONSUMES them. Delegating only the latter left the worker
/// defaulting all seven — field-measured on 0.4.42, where the browser had
/// negotiated `data-channel-h264` while the worker, defaulting `transport` to
/// `None`, wrote 13 MB to the legacy RTP TRACK the browser was not reading.
/// Input kept working (a separate data channel), so the session looked alive
/// and showed nothing.
///
/// ⚠️ The RESOLVED values travel, not the `Request` itself. The daemon has
/// already told the SERVER what it chose, so its resolution is authoritative;
/// re-resolving in the worker would let the two disagree whenever their
/// capability probes differ — and they are different processes in different
/// sessions, so they can.
///
/// ⚠️ Adding a field here means adding it to the `Request` handler that fills
/// it AND the `SdpOffer` handler that reads it. A seventh parallel map keyed by
/// session id is the smell that made this bug possible; consolidating them is
/// the real cleanup, and this struct is the shape it should take.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionParams {
    /// Hex, like every other id this channel carries.
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_lease: Option<roomler_ai_remote_control::signaling::SharedSessionLease>,
    pub codec: String,
    pub transport: Option<String>,
    pub chroma: Option<String>,
    pub chunk_framing: bool,
    pub audio: bool,
    pub permissions: roomler_ai_remote_control::permissions::Permissions,
    pub controller_name: String,
    pub input_mode: Option<roomler_ai_remote_control::models::InputMode>,
    pub asking_org: Option<String>,
    /// FR-85 P1e-mac — the session's `record` context. A daemon older than
    /// P1e-mac sends none, and the session's `record` channel then refuses
    /// `unavailable`, exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<DelegatedRecord>,
    /// #1882 — whether the session may use the overlay, and the overlay
    /// blocks the daemon resolved it against: the worker runs no overlay, so
    /// it cannot read them itself. `None` (a daemon older than the field)
    /// reads as the default — off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rc_overlay: Option<crate::rc_overlay::RcOverlay>,
    /// FR-101 P4b-2 — the session's idle limit in seconds (`Request.idle_secs`).
    /// The worker keeps it: it owns the peer, the input and the screen the
    /// limit is measured on. `None` (no limit, or a daemon older than the
    /// field) never ends a session as idle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_secs: Option<u32>,
    /// FR-99 P3b — the device policy's lock ask (`Request.lock_on_end`). The
    /// worker takes it into the lock decision: the session goes live, and
    /// ends, in its process. `None` (nothing asked, or a daemon older than
    /// the field) leaves the owner's own `lock_on_end`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_on_end: Option<roomler_ai_remote_control::models::LockOnEnd>,
}

/// FR-85 P1e-mac — what a delegated session's `record` channel needs, carried
/// across the socket. The daemon resolves it while handling `Request` (was the
/// session consented on the host, so a recording must ask again?). The worker
/// is the half that owns the peer, the recorder and the person's own gates:
/// on a supervised Mac it IS the person, in their GUI session, holding the
/// Screen Recording grant it already captures with.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DelegatedRecord {
    /// Hex, like every other id this channel carries.
    pub controller_user_id: String,
    /// `Some` = the session was consented on the host, so a recording asks
    /// the host again within this window; `None` = auto-granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_window_ms: Option<u64>,
}

/// FR-85 P1e-mac — how many delegated `RECORD` sessions the daemon remembers
/// for [`DelegateHost::relay_upstream`]. Oldest out first: a claim about a
/// session this far back has no live session left for the server to file it
/// under anyway. Generous (≈ 30 KB), so a controller cannot push a live
/// recording's session out by opening sessions while it records.
const RECORD_SESSIONS_KEPT: usize = 1024;

/// What the worker's signalling loop receives over the delegation channel.
///
/// Two shapes, and the ORDER between them is load-bearing: params must land
/// before the offer that consumes them. They do, because both travel one
/// ordered channel and the server always sends `Request` before `SdpOffer`.
#[derive(Debug)]
pub enum WorkerInbound {
    /// Parameters for a session that is about to be offered.
    Params(Box<SessionParams>),
    /// An rc message to serve.
    Msg(Box<ServerMsg>),
}

/// The socket a worker running as `uid` dials.
///
/// Per-uid, so a console-user change cannot leave the new worker dialling the
/// old one's endpoint.
#[cfg(unix)]
pub fn socket_path(uid: u32) -> std::path::PathBuf {
    std::path::Path::new(DELEGATE_DIR).join(format!("{uid}.sock"))
}

/// The GUI worker's end of delegation: what the signalling loop reads and
/// writes while [`crate::delegate_worker`] owns the socket.
///
/// Two ordinary channels rather than the socket itself, because the socket
/// outlives a WS reconnect and the signalling loop does not. The attach loop
/// keeps the socket and reconnects it independently; the signalling loop just
/// sees messages arrive and replies leave.
pub struct WorkerLink {
    /// rc messages the daemon delegated, waiting for the signalling loop.
    pub inbound: tokio::sync::mpsc::Receiver<WorkerInbound>,
    /// Replies from a delegated session — the answer, its peer's ICE, its
    /// stats, its terminate — drained by the attach loop into `FromWorker`
    /// frames.
    ///
    /// ⚠️ ONE queue for all of them, deliberately. On the WS path the
    /// synchronous answer jumps the outbound queue (`handle_server_msg` holds
    /// `&mut ws` for its whole duration), so it always precedes the peer's
    /// first candidates. Here it does not, and that is safe because the
    /// CONTROLLER already buffers early ICE — `useRemoteControl.ts` keeps a
    /// `pendingRemoteIce` list precisely because `addIceCandidate` throws
    /// before `setRemoteDescription`, and flushes it once the answer lands.
    /// Checked rather than assumed; a priority queue here would be machinery
    /// for a guarantee nothing needs.
    pub outbound: tokio::sync::mpsc::Sender<ClientMsg>,
}

/// How this process takes part in delegation.
///
/// A process is the supervising DAEMON or the supervised WORKER, never both —
/// so this is one value rather than two options that could disagree, and
/// "neither" is the ordinary case on every platform.
pub enum Delegation {
    /// Not supervising and not supervised. Every platform but macOS, and macOS
    /// too until `macos_supervise_gui_worker` is on.
    Off,
    /// The root daemon: hands delegable rc messages to an attached worker, and
    /// puts the worker's replies on its own control WS.
    Daemon(DelegateHost),
    /// The GUI worker: serves what the daemon hands it, using the session
    /// state it already has.
    Worker(WorkerLink),
}

impl Delegation {
    /// The daemon's channel, when this process is the daemon.
    pub fn host(&self) -> Option<&DelegateHost> {
        match self {
            Delegation::Daemon(h) => Some(h),
            _ => None,
        }
    }

    /// The worker's two ends, when this process is the worker. Split so the
    /// receiver can be polled while the sender is lent to a session.
    pub fn worker_mut(
        &mut self,
    ) -> Option<(
        &mut tokio::sync::mpsc::Receiver<WorkerInbound>,
        &tokio::sync::mpsc::Sender<ClientMsg>,
    )> {
        match self {
            Delegation::Worker(link) => Some((&mut link.inbound, &link.outbound)),
            _ => None,
        }
    }
}

/// May this server message be handed to the GUI worker?
///
/// A **whitelist**: five variants in, everything else stays with the daemon.
///
/// ⚠️ The catch-all is deliberate, and it was not the first design. Listing
/// every variant would make the compiler force a decision on each new one —
/// the `RpcCap::wire()` pattern — but `ServerMsg` has ~25 variants of which
/// only these five are remote-desktop, and the rest are tunnel, SSH, RPC,
/// config and forwarding. An exhaustive arm would be a 25-line list that
/// conflicts with every parallel branch adding a variant, to guard a default
/// that is already the safe one: a new variant NOT being delegated is a
/// feature gap someone notices, while a new variant being delegated by
/// accident would hand device authority to an unprivileged process. The
/// catch-all fails in the right direction, so the test below locks the intent
/// instead of the compiler.
///
/// ⚠️ `Terminate` and `Ice` are shared with the TUNNEL subsystem, which the
/// daemon serves itself. They are delegable only because the tunnel arms carry
/// their own `Tunnel*` variants — if that ever stops being true, this
/// whitelist starts routing tunnel signalling into a GUI worker.
pub fn delegable_inbound(msg: &ServerMsg) -> bool {
    matches!(
        msg,
        ServerMsg::SessionCreated { .. }
            | ServerMsg::SharedLeaseRenewal { .. }
            | ServerMsg::SdpOffer { .. }
            | ServerMsg::SdpAnswer { .. }
            | ServerMsg::Ice { .. }
            | ServerMsg::Terminate { .. }
    )
}

/// May this client message come FROM the GUI worker and go up the control WS?
///
/// The mirror of [`delegable_inbound`], and the more security-relevant of the
/// two: the daemon's WS is the device's authenticated identity, so anything the
/// worker can put on it, the worker says **as the device**. An unprivileged
/// process must not be able to emit `SshActivity` (forging the device's own
/// account of itself), `ConfigStatus` (lying about what it applied),
/// `RpcResult`, or a `TunnelOpen`.
///
/// ⚠️ Consent is deliberately absent: FR-27 put the decision in the daemon
/// (`consent::strictest_of`, the local floor) and the prompt on the companion
/// surface, so a worker emitting a verdict would be answering a question it was
/// never asked.
///
/// FR-85 P1e-mac — one message passes WITHOUT being here:
/// `RecordingActivity`, and only for a session the daemon handed over with
/// `RECORD` ([`DelegateHost::relay_upstream`]). This whitelist stays pure, so
/// it still refuses it.
pub fn delegable_outbound(msg: &ClientMsg) -> bool {
    matches!(
        msg,
        ClientMsg::SdpAnswer { .. }
            | ClientMsg::Ice { .. }
            | ClientMsg::SessionStats { .. }
            | ClientMsg::Terminate { .. }
    )
}

/// FR-92 — one deny from any org is enough; an org that never said anything
/// (an older server) does not deny.
fn strictest_keep_busy(policies: &std::collections::BTreeMap<String, bool>) -> bool {
    policies.values().any(|d| *d)
}

/// #1882 — where a [`DelegateHost`] reads the overlay footprint it pushes to an
/// attached worker: the overlay's v4 blocks as `(network, prefix length)`.
pub type FootprintSource = fn() -> Vec<(std::net::Ipv4Addr, u8)>;

/// The daemon's end of the delegation channel.
#[derive(Clone, Default)]
pub struct DelegateHost {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The secret the currently-spawned worker was given. `None` means nobody
    /// may attach — the default, and the disabled state.
    secret: Mutex<Option<String>>,
    attached: AtomicBool,
    /// The socket path currently bound, so [`DelegateHost::revoke`] can unlink
    /// it. `None` = not listening.
    listening: Mutex<Option<std::path::PathBuf>>,
    /// The attached worker's capabilities, when it has sent them.
    ///
    /// Cleared when the channel closes — a row that keeps claiming a capture
    /// target which has gone hands the next session a black screen, which is
    /// the bug P2b existed to fix.
    worker_caps: Mutex<Option<AgentCaps>>,
    /// Where a worker's replies go: the control WS's outbound queue.
    ///
    /// Re-set on every WS (re)connect, because the sender belongs to the
    /// connection and not to the daemon. `None` = no live WS, and a worker
    /// reply is then dropped with a log line rather than queued for a socket
    /// that may never come back.
    outbound: Mutex<Option<tokio::sync::mpsc::Sender<ClientMsg>>>,
    /// The queue toward the attached worker. Set while a worker is attached,
    /// `None` otherwise — so "is anyone there?" and "where do I send it?" are
    /// one question with one answer, and cannot disagree.
    to_worker: Mutex<Option<tokio::sync::mpsc::Sender<DelegateFrame>>>,
    /// FR-85 P1e-mac — the sessions handed to the worker with `RECORD` in
    /// their grant: the only ones whose `RecordingActivity` it may put on the
    /// control WS. Bounded ([`RECORD_SESSIONS_KEPT`]) and never pruned on
    /// `Terminate`, because a recording outlives its session by the re-attach
    /// grace and its last claims come after.
    record_sessions: Mutex<std::collections::VecDeque<String>>,
    shared_sessions: Mutex<
        std::collections::VecDeque<(
            String,
            roomler_ai_remote_control::signaling::SharedSessionLease,
        )>,
    >,
    /// FR-92 — every org's last keep-busy policy (tenant hex → denied), as
    /// this daemon's control WS loops received it. On a supervised Mac the
    /// WORKER runs keep busy, while delegation itself is primary-only — so
    /// the daemon is the one place that hears every org, and it hands the
    /// worker the strictest ([`DelegateHost::note_keep_busy_policy`]).
    keep_busy: Mutex<std::collections::BTreeMap<String, bool>>,
    /// #1882 — where the frame loop reads the overlay footprint it pushes to
    /// an attached worker ([`DelegateFrame::OverlayFootprint`]). Set by the
    /// daemon to `tunnel_core::overlay_footprint::v4_nets`; unset (every test
    /// host) pushes nothing, so the frame-by-frame tests never meet the frame.
    footprint: Mutex<Option<FootprintSource>>,
    /// FR-92 — the keep-busy questions put to the worker and not yet answered
    /// ([`DelegateHost::ask_worker_keep_busy`]), by id. Emptied when the
    /// channel closes, so a caller is never left waiting on a worker that has
    /// gone.
    keep_busy_asks: Mutex<
        std::collections::HashMap<
            u64,
            tokio::sync::oneshot::Sender<tunnel_core::localapi::KeepBusyInfo>,
        >,
    >,
    next_keep_busy_ask: std::sync::atomic::AtomicU64,
}

/// `chown` a path to `uid`, keeping its existing group.
#[cfg(unix)]
fn chown_to(path: &std::path::Path, uid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains a NUL"))?;
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call;
    // `-1` for gid means "leave the group unchanged", which is the documented
    // contract of chown(2).
    let rc = unsafe { libc::chown(c.as_ptr(), uid, u32::MAX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl DelegateHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// #1882 — read the overlay footprint pushed to an attached worker from
    /// `source`. The daemon passes `tunnel_core::overlay_footprint::v4_nets`;
    /// without a source nothing is pushed.
    pub fn set_overlay_footprint(&self, source: FootprintSource) {
        *self.inner.footprint.lock().expect("footprint mutex") = Some(source);
    }

    /// The footprint frame to push to the worker, if the source holds blocks
    /// that `sent` (what this connection was last told) does not.
    fn footprint_update(&self, sent: &mut Vec<(std::net::Ipv4Addr, u8)>) -> Option<DelegateFrame> {
        let source = (*self.inner.footprint.lock().expect("footprint mutex"))?;
        let now = source();
        if now.is_empty() || now == *sent {
            return None;
        }
        sent.clone_from(&now);
        Some(DelegateFrame::OverlayFootprint { v4_nets: now })
    }

    /// Open (or re-open) the delegation socket for `uid` and mint the secret
    /// that authorises a worker on it. Returns the secret to hand the child.
    ///
    /// Two independent gates, and both are needed:
    ///
    /// - **the socket** is `0600` owned by `uid`, in a `0711` directory, so no
    ///   other unprivileged user can even open it;
    /// - **the secret** is what stops any OTHER process of that same uid — the
    ///   worker is an ordinary user process, and so is an attacker's.
    ///
    /// Errors are logged and swallowed: a daemon that cannot open this socket
    /// still supervises a worker that serves its own sessions, which is P1
    /// behaviour and fine. Refusing to spawn would trade a missing feature for
    /// a missing remote-desktop half.
    #[cfg(unix)]
    pub fn open_for(&self, uid: u32) -> String {
        let secret = self.mint();
        if let Err(e) = self.listen(uid) {
            tracing::warn!(uid, error = %e, "delegation: could not open the worker socket");
        }
        secret
    }

    /// Bind the per-uid socket and serve attaches on it until [`revoke`].
    #[cfg(unix)]
    fn listen(&self, uid: u32) -> std::io::Result<()> {
        self.listen_in(std::path::Path::new(DELEGATE_DIR), uid)
    }

    /// [`listen`] with the directory injected, so the permission bits — which
    /// are one of the two authorisation gates, not decoration — can be
    /// asserted by a test that is not root and cannot write to `/var/run`.
    #[cfg(unix)]
    fn listen_in(&self, dir: &std::path::Path, uid: u32) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir)?;
        // 0711: a worker must TRAVERSE to reach its socket, but nothing needs
        // to enumerate the directory, and not listing it means one user cannot
        // even learn that another has a worker.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711))?;

        let path = dir.join(format!("{uid}.sock"));
        // A stale socket from a previous daemon would make bind() fail with
        // EADDRINUSE; nothing else may live at this path.
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        // chown AFTER chmod: the window between them is 0600 root-owned, which
        // is closed, whereas the reverse order would briefly leave a uid-owned
        // socket at the default mode.
        chown_to(&path, uid)?;

        *self.inner.listening.lock().expect("listen mutex") = Some(path.clone());
        let host = self.clone();
        tokio::spawn(async move {
            tracing::info!(uid, path = %path.display(), "delegation: listening for the worker");
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let host = host.clone();
                        tokio::spawn(async move { host.serve_stream(stream).await });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "delegation: accept failed; stopping listener");
                        return;
                    }
                }
            }
        });
        Ok(())
    }

    /// Read the attach line off a fresh connection, then serve it.
    #[cfg(unix)]
    async fn serve_stream(&self, stream: UnixStream) {
        let (rd, wr) = tokio::io::split(stream);
        let mut lines = BufReader::new(rd).lines();
        let offered = match lines.next_line().await {
            Ok(Some(line)) => line.trim().to_string(),
            _ => {
                tracing::debug!("delegation: connection closed before offering a secret");
                return;
            }
        };
        self.serve(&offered, Box::new(lines.into_inner()), Box::new(wr))
            .await;
    }

    /// Mint a fresh secret, replacing any previous one.
    ///
    /// Synchronous on purpose: the critical section is one `Option<String>`
    /// swap, and an async lock would force every caller to be async —
    /// including `stop_worker`, which is deliberately blocking because it
    /// waits out a SIGTERM grace period.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn mint(&self) -> String {
        use rand::RngCore;
        let mut raw = [0u8; SECRET_BYTES];
        rand::rng().fill_bytes(&mut raw);
        let secret = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
        *self.inner.secret.lock().expect("secret mutex") = Some(secret.clone());
        secret
    }

    /// Point the channel at the current control WS's outbound queue.
    ///
    /// Called on every (re)connect. Until it is, a worker's replies are dropped
    /// — which is correct: there is no session without a WS, so a reply that
    /// arrives without one belongs to a session the server has already
    /// forgotten.
    pub fn set_outbound(&self, tx: tokio::sync::mpsc::Sender<ClientMsg>) {
        *self.inner.outbound.lock().expect("outbound mutex") = Some(tx);
    }

    /// Hand a server message to the attached worker.
    ///
    /// Returns `false` when there is no worker, which is the caller's signal to
    /// serve it locally exactly as before. ⚠️ It does NOT check
    /// [`delegable_inbound`] — that decision belongs at the call site, where
    /// the alternative (handling it locally) is visible.
    pub fn send_to_worker(&self, msg: &ServerMsg) -> bool {
        let tx = self
            .inner
            .to_worker
            .lock()
            .expect("to_worker mutex")
            .clone();
        let Some(tx) = tx else { return false };
        let sent = tx
            .try_send(DelegateFrame::ToWorker {
                msg: Box::new(msg.clone()),
            })
            .is_ok();
        if sent && let ServerMsg::Terminate { session_id, .. } = msg {
            self.inner
                .shared_sessions
                .lock()
                .expect("shared sessions mutex")
                .retain(|(sid, _)| *sid != session_id.to_hex());
        }
        sent
    }

    /// FR-92 — one org's keep-busy policy arrived on this daemon's control
    /// WS. The attached worker gets the STRICTEST of every org's (any org's
    /// deny stops keep busy device-wide), as an ordinary
    /// `rc:agent.keep_busy_policy`. The worker files it under its own tenant —
    /// the primary, the one org key its store keeps across restarts — which
    /// is exactly the device-wide answer it needs. No worker attached: it
    /// gets the same frame on attach ([`Self::keep_busy_replay`]).
    pub fn note_keep_busy_policy(&self, tenant: &str, denied: bool) {
        let strictest = {
            let mut m = self.inner.keep_busy.lock().expect("keep_busy mutex");
            m.insert(tenant.to_string(), denied);
            strictest_keep_busy(&m)
        };
        if self.send_to_worker(&ServerMsg::KeepBusyPolicy { denied: strictest }) {
            tracing::info!(
                denied = strictest,
                "delegation: keep-busy policy handed to the GUI worker"
            );
        }
    }

    /// FR-92 — ask the attached worker for its keep-busy state; with `off`,
    /// have it stop first. `None` = nobody to ask: no worker attached, a full
    /// queue, a worker that closed the channel, or no answer within `wait`
    /// (an older worker skips the question). The caller then answers for its
    /// own engine, as it did before the worker could be asked.
    pub async fn ask_worker_keep_busy(
        &self,
        off: bool,
        wait: std::time::Duration,
    ) -> Option<tunnel_core::localapi::KeepBusyInfo> {
        let tx = self
            .inner
            .to_worker
            .lock()
            .expect("to_worker mutex")
            .clone()?;
        let id = self
            .inner
            .next_keep_busy_ask
            .fetch_add(1, Ordering::Relaxed);
        let (answer_tx, answer_rx) = tokio::sync::oneshot::channel();
        self.inner
            .keep_busy_asks
            .lock()
            .expect("keep_busy_asks mutex")
            .insert(id, answer_tx);
        let answer = if tx.try_send(DelegateFrame::KeepBusyAsk { id, off }).is_ok() {
            match tokio::time::timeout(wait, answer_rx).await {
                Ok(Ok(info)) => Some(info),
                // No answer in time, or the channel closed under the question.
                _ => None,
            }
        } else {
            None
        };
        // Whatever happened, this question is over: a late answer to it finds
        // no one waiting and is dropped.
        self.inner
            .keep_busy_asks
            .lock()
            .expect("keep_busy_asks mutex")
            .remove(&id);
        answer
    }

    /// The worker's answer to [`Self::ask_worker_keep_busy`]. An `id` nobody
    /// is waiting for (a late answer, or one never asked) is dropped.
    fn keep_busy_told(&self, id: u64, info: tunnel_core::localapi::KeepBusyInfo) {
        let waiting = self
            .inner
            .keep_busy_asks
            .lock()
            .expect("keep_busy_asks mutex")
            .remove(&id);
        match waiting {
            Some(tx) => {
                let _ = tx.send(info);
            }
            None => tracing::debug!(id, "delegation: a keep-busy answer nobody is waiting for"),
        }
    }

    /// The keep-busy frame an attaching worker needs, once any org has said
    /// anything. A policy that arrived while no worker was attached (the
    /// connect-time push always does) would otherwise never reach it.
    fn keep_busy_replay(&self) -> Option<DelegateFrame> {
        let m = self.inner.keep_busy.lock().expect("keep_busy mutex");
        (!m.is_empty()).then(|| DelegateFrame::ToWorker {
            msg: Box::new(ServerMsg::KeepBusyPolicy {
                denied: strictest_keep_busy(&m),
            }),
        })
    }

    /// Hand the worker the parameters the daemon resolved for a session.
    ///
    /// Must reach the worker BEFORE the `SdpOffer` that consumes them. It does,
    /// because both travel the same ordered channel and the daemon resolves
    /// them while handling `Request`, which the server always sends first.
    pub fn has_shared_params(&self, sid: bson::oid::ObjectId) -> bool {
        self.inner
            .shared_sessions
            .lock()
            .expect("shared sessions mutex")
            .iter()
            .any(|(s, _)| *s == sid.to_hex())
    }
    pub fn send_params(&self, frame: DelegateFrame) -> bool {
        let shared = match &frame {
            DelegateFrame::SessionParams(p) => p
                .shared_lease
                .clone()
                .map(|scope| (p.session_id.clone(), scope)),
            _ => None,
        };
        if shared.is_some()
            && !self
                .inner
                .worker_caps
                .lock()
                .expect("worker caps mutex")
                .as_ref()
                .is_some_and(|c| {
                    c.has_rpc(roomler_ai_remote_control::models::RpcCap::SharedSessionLease)
                })
        {
            return false; // old GUI workers may not silently strip the shared lease
        }
        if shared.is_some()
            && self
                .inner
                .shared_sessions
                .lock()
                .expect("shared sessions mutex")
                .len()
                >= 64
        {
            return false;
        }
        // FR-85 P1e-mac — remembered HERE, where the grant crosses, so the
        // relay's admission of a worker's `RecordingActivity` cannot drift from
        // what the worker was actually given — and only once it DID cross: a
        // session nobody was attached to receive, or whose params a full queue
        // dropped, is not one any worker can have a recording of.
        let recorded = match &frame {
            DelegateFrame::SessionParams(p)
                if p.permissions
                    .contains(roomler_ai_remote_control::permissions::Permissions::RECORD) =>
            {
                Some(p.session_id.clone())
            }
            _ => None,
        };
        let tx = self
            .inner
            .to_worker
            .lock()
            .expect("to_worker mutex")
            .clone();
        let Some(tx) = tx else { return false };
        if tx.try_send(frame).is_err() {
            return false;
        }
        if let Some((sid, scope)) = shared {
            let mut held = self
                .inner
                .shared_sessions
                .lock()
                .expect("shared sessions mutex");
            if !held.iter().any(|(s, _)| *s == sid) {
                held.push_back((sid, scope));
            }
        }
        if let Some(session_id) = recorded {
            let mut held = self
                .inner
                .record_sessions
                .lock()
                .expect("record sessions mutex");
            if !held.iter().any(|s| *s == session_id) {
                held.push_back(session_id);
                while held.len() > RECORD_SESSIONS_KEPT {
                    held.pop_front();
                }
            }
        }
        true
    }

    /// FR-85 P1e-mac — the `record` caps this DEVICE should advertise, given
    /// who is attached: the worker's. A delegated session's `record` channel
    /// opens on the worker's peer and records with the worker's recorder,
    /// under the person's own gates, so theirs is the only true answer.
    ///
    /// `None` = no worker, or one that has not sent its caps: the caller keeps
    /// its own (on a root macOS daemon, nothing — `RootDaemon`). A worker older
    /// than P1e-mac sends an empty list, so the device advertises nothing it
    /// cannot serve.
    pub fn effective_record(&self) -> Option<Vec<String>> {
        let held = self.inner.worker_caps.lock().expect("worker caps mutex");
        held.as_ref().map(|c| c.record.clone())
    }

    /// The `permissions` this DEVICE should advertise, given who is attached.
    ///
    /// `None` = "nothing to override" — no worker, or one that has not sent its
    /// caps — and the caller keeps its own. ⚠️ Deliberately returns only the
    /// permission pair, not whole caps: codecs and encoders stay the DAEMON's,
    /// because the daemon is the half that answers `rc:session.request` and
    /// advertising one half's list while resolving with the other's is exactly
    /// the class of bug P2b-3 was. Both halves were measured to report
    /// identical codecs anyway (2026-09-01).
    pub fn effective_permissions(&self) -> Option<(Vec<String>, bool)> {
        let held = self.inner.worker_caps.lock().expect("worker caps mutex");
        held.as_ref().map(|c| {
            (
                c.permissions.clone().unwrap_or_default(),
                c.has_input_permission,
            )
        })
    }

    /// Forget the current secret — the worker it belonged to is gone.
    ///
    /// [`crate::macos_supervisor`] calls this from `stop_worker`, which takes a
    /// `&DelegateHost` for exactly this reason: revocation is not something a
    /// caller can forget at one of the four places a worker can stop.
    pub fn revoke(&self) {
        *self.inner.secret.lock().expect("secret mutex") = None;
        // FR-85 P1e-mac — and what that worker was handed. The next worker is
        // a new one (another console user, after a switch), and it must not
        // report on sessions it never had. A transient channel drop does not
        // come here, so a worker re-attaching keeps its memory, and the claims
        // a recording makes after its session ends still pass.
        self.inner
            .record_sessions
            .lock()
            .expect("record sessions mutex")
            .clear();
        // Unlink the socket too. The accept loop ends when the listener drops
        // with the process, but a path left behind is an endpoint a later
        // worker could dial and sit on forever waiting for a greeting.
        if let Some(path) = self.inner.listening.lock().expect("listen mutex").take() {
            let _ = std::fs::remove_file(path);
        }
        #[cfg(not(unix))]
        let _ = &self.inner.listening;
    }

    /// Serve one attach attempt. Returns when the channel closes.
    ///
    /// ⚠️ Every refusal is silent and identical from the caller's side: the
    /// connection simply closes. Distinguishing "wrong secret" from "already
    /// attached" from "not accepting" would hand a local attacker an oracle,
    /// and there is nothing a legitimate worker could usefully do differently.
    /// The daemon log says which, because the operator is not the attacker.
    pub async fn serve(
        &self,
        offered: &str,
        rd: Box<dyn AsyncRead + Send + Unpin>,
        wr: Box<dyn AsyncWrite + Send + Unpin>,
    ) {
        {
            // Scoped so the (std, non-async) guard is dropped before any await
            // below — holding it across one would be a deadlock waiting to
            // happen and a clippy error besides.
            let held = self.inner.secret.lock().expect("secret mutex");
            let Some(expected) = held.as_deref() else {
                tracing::warn!("delegation attach refused: no worker secret is currently issued");
                return;
            };
            if !secret_eq(expected, offered) {
                tracing::warn!("delegation attach refused: secret mismatch");
                return;
            }
        }
        if self
            .inner
            .attached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            tracing::warn!("delegation attach refused: a worker is already attached");
            return;
        }
        tracing::info!("delegation channel attached");
        let result = self.run(rd, wr).await;
        self.inner.attached.store(false, Ordering::Release);
        match result {
            Ok(()) => tracing::info!("delegation channel closed"),
            Err(e) => tracing::warn!(error = %e, "delegation channel ended with an error"),
        }
    }

    /// The frame loop: liveness, plus the rc-session messages in both
    /// directions (P2b).
    async fn run(
        &self,
        rd: Box<dyn AsyncRead + Send + Unpin>,
        mut wr: Box<dyn AsyncWrite + Send + Unpin>,
    ) -> std::io::Result<()> {
        write_frame(
            &mut wr,
            &DelegateFrame::Attached {
                daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        )
        .await?;
        // #1882 — the worker's OWN sessions need the overlay's blocks too.
        let mut footprint_sent = Vec::new();
        if let Some(frame) = self.footprint_update(&mut footprint_sent) {
            write_frame(&mut wr, &frame).await?;
        }
        // FR-92 — and keep busy needs the orgs' policy, which the server
        // pushed on connect, before this worker was here to hear it.
        if let Some(frame) = self.keep_busy_replay() {
            write_frame(&mut wr, &frame).await?;
        }

        // Bounded on purpose. An unbounded queue toward a worker that has
        // stopped reading is a memory leak that looks like a working channel;
        // a full one is a `send_to_worker` that returns false, and the caller
        // then serves locally, which is the honest degradation.
        let (to_worker_tx, mut to_worker_rx) = tokio::sync::mpsc::channel(64);
        *self.inner.to_worker.lock().expect("to_worker mutex") = Some(to_worker_tx);

        let mut lines = BufReader::new(rd).lines();
        loop {
            let line = tokio::select! {
                queued = to_worker_rx.recv() => {
                    match queued {
                        Some(frame) => {
                            write_frame(&mut wr, &frame).await?;
                            continue;
                        }
                        None => break,
                    }
                }
                line = lines.next_line() => match line? {
                    Some(l) => l,
                    None => break,
                },
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<DelegateFrame>(&line) {
                Ok(DelegateFrame::Ping) => {
                    write_frame(&mut wr, &DelegateFrame::Pong).await?;
                    // #1882 — a grown footprint rides the worker's own liveness
                    // cadence: the overlay may join well after the worker
                    // attached, and this loop has no timer of its own.
                    if let Some(frame) = self.footprint_update(&mut footprint_sent) {
                        write_frame(&mut wr, &frame).await?;
                    }
                }
                Ok(DelegateFrame::Pong) => {}
                Ok(DelegateFrame::Attached { .. }) => {
                    // Daemon to worker only. A worker sending it is confused
                    // about which end it is; say so rather than ignore it.
                    tracing::warn!("delegation: worker sent an `attached` frame; ignoring");
                }
                Ok(DelegateFrame::FromWorker { msg }) => self.relay_upstream(*msg),
                // FR-92 — the worker's keep-busy state, for a LocalAPI caller
                // of this daemon. Data for that caller only; nothing here
                // reaches the control WS.
                Ok(DelegateFrame::KeepBusyTold { id, info }) => self.keep_busy_told(id, *info),
                Ok(DelegateFrame::WorkerCaps { caps }) => {
                    tracing::info!(
                        permissions = ?caps.permissions,
                        has_input = caps.has_input_permission,
                        "delegation: worker announced its capabilities"
                    );
                    *self.inner.worker_caps.lock().expect("worker caps mutex") = Some(*caps);
                }
                Ok(
                    DelegateFrame::ToWorker { .. }
                    | DelegateFrame::SessionParams { .. }
                    | DelegateFrame::OverlayFootprint { .. }
                    | DelegateFrame::KeepBusyAsk { .. },
                ) => {
                    // Daemon → worker only. A worker sending one is confused
                    // about which end it is.
                    tracing::warn!("delegation: worker sent a daemon-only frame; ignoring");
                }
                Err(e) => {
                    // Do NOT close on an unknown frame: a NEWER worker may send
                    // something this daemon has never heard of, and an additive
                    // protocol is only additive if old readers skip what they
                    // do not know. Same rule as `AgentCaps.rpc`.
                    tracing::debug!(error = %e, "delegation: skipping an unparseable frame");
                }
            }
        }
        *self.inner.to_worker.lock().expect("to_worker mutex") = None;
        // ⚠️ Clear the caps with the channel. Keeping them would leave the row
        // advertising a capture target that has gone, and the next session
        // would get the black screen P2b existed to fix.
        *self.inner.worker_caps.lock().expect("worker caps mutex") = None;
        self.inner
            .shared_sessions
            .lock()
            .expect("shared sessions mutex")
            .clear();
        // FR-92 — and the questions it will now never answer: dropping each
        // sender ends its caller's wait at once instead of at the timeout.
        self.inner
            .keep_busy_asks
            .lock()
            .expect("keep_busy_asks mutex")
            .clear();
        Ok(())
    }

    /// Put a worker's reply on the control WS — if the whitelist allows it.
    ///
    /// ⚠️ The check is HERE, not at the worker, and that is the whole point:
    /// the worker is unprivileged and may be compromised, so a filter it
    /// applies to itself is not a filter. Anything it may put on this socket it
    /// says AS THE DEVICE.
    fn relay_upstream(&self, msg: ClientMsg) {
        let shared_challenge = if let ClientMsg::SharedLeaseChallenge {
            session_id,
            grant_id,
            lease_epoch,
            ..
        } = &msg
        {
            self.inner
                .shared_sessions
                .lock()
                .expect("shared sessions mutex")
                .iter()
                .any(|(sid, scope)| {
                    *sid == session_id.to_hex()
                        && scope.grant_id == *grant_id
                        && scope.lease_epoch == *lease_epoch
                })
        } else {
            false
        };
        if !delegable_outbound(&msg) && !self.records_session_of(&msg) && !shared_challenge {
            tracing::warn!(
                kind = msg_kind(&msg),
                "delegation: worker tried to send a message it is not allowed to; dropping"
            );
            return;
        }
        let tx = self.inner.outbound.lock().expect("outbound mutex").clone();
        match tx {
            Some(tx) => {
                if tx.try_send(msg).is_err() {
                    tracing::warn!("delegation: control WS queue full or closed; dropped a reply");
                }
            }
            None => tracing::debug!("delegation: no control WS; dropped a worker reply"),
        }
    }

    /// FR-85 P1e-mac — a `RecordingActivity` about a session this daemon handed
    /// to the worker with `RECORD`: the one message outside
    /// [`delegable_outbound`] a worker may send, and only about its own
    /// recordings.
    ///
    /// It is the host's ACCOUNT of a recording, as `SshActivity` is of an SSH
    /// session, which is why it is not simply whitelisted. But on a supervised
    /// Mac the worker IS the recorder, so there is no other account to give.
    /// The server bounds it again: it files a claim only for a live session of
    /// this agent whose grant holds `RECORD`.
    fn records_session_of(&self, msg: &ClientMsg) -> bool {
        let ClientMsg::RecordingActivity { session_id, .. } = msg else {
            return false;
        };
        let hex = session_id.to_hex();
        self.inner
            .record_sessions
            .lock()
            .expect("record sessions mutex")
            .iter()
            .any(|s| *s == hex)
    }
}

/// Write one newline-delimited frame and flush it.
///
/// Flushing per frame is deliberate: this channel is latency-sensitive at
/// session setup and idle the rest of the time, so there is nothing to batch
/// and a buffered ICE candidate is a slower session for no gain.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    wr: &mut W,
    frame: &DelegateFrame,
) -> std::io::Result<()> {
    let line = serde_json::to_string(frame).expect("DelegateFrame serialises");
    wr.write_all(line.as_bytes()).await?;
    wr.write_all(b"\n").await?;
    wr.flush().await
}

/// Constant-time comparison.
///
/// The channel is local, so a timing side channel is a stretch — but this is
/// the authorisation path, the fix is three lines, and "the attacker is already
/// local" is exactly the threat this secret exists for. Length is compared
/// first and in variable time on purpose: the length of a hex secret is not a
/// secret.
fn secret_eq(expected: &str, offered: &str) -> bool {
    use subtle::ConstantTimeEq;
    let a = expected.as_bytes();
    let b = offered.as_bytes();
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read one line from the client side, or `None` if the daemon just closed.
    async fn first_line(client: tokio::io::DuplexStream) -> Option<String> {
        let (rd, _wr) = tokio::io::split(client);
        BufReader::new(rd).lines().next_line().await.unwrap()
    }

    #[tokio::test]
    async fn refuses_when_no_secret_is_issued() {
        let host = DelegateHost::new();
        let (client, server) = tokio::io::duplex(1024);
        let (rd, wr) = tokio::io::split(server);
        host.serve("anything", Box::new(rd), Box::new(wr)).await;
        // A refusal is a close with no bytes written: the caller learns nothing.
        assert!(first_line(client).await.is_none());
    }

    #[tokio::test]
    async fn refuses_a_wrong_secret() {
        let host = DelegateHost::new();
        let _secret = host.mint();
        let (client, server) = tokio::io::duplex(1024);
        let (rd, wr) = tokio::io::split(server);
        host.serve("not-it", Box::new(rd), Box::new(wr)).await;
        assert!(
            first_line(client).await.is_none(),
            "a wrong secret must not be greeted"
        );
    }

    #[tokio::test]
    async fn accepts_the_right_secret_and_answers_liveness() {
        let host = DelegateHost::new();
        let secret = host.mint();
        assert_eq!(
            secret.len(),
            SECRET_BYTES * 2,
            "hex of {SECRET_BYTES} bytes"
        );

        let (client, server) = tokio::io::duplex(1024);
        let (rd, wr) = tokio::io::split(server);
        let h = host.clone();
        let task = tokio::spawn(async move { h.serve(&secret, Box::new(rd), Box::new(wr)).await });

        let (crd, mut cwr) = tokio::io::split(client);
        let mut lines = BufReader::new(crd).lines();
        let greeting = lines.next_line().await.unwrap().expect("greeting");
        assert!(greeting.contains("\"attached\""), "got {greeting}");

        cwr.write_all(b"{\"t\":\"ping\"}\n").await.unwrap();
        let pong = lines.next_line().await.unwrap().expect("pong");
        assert!(pong.contains("\"pong\""), "got {pong}");

        drop(cwr);
        drop(lines);
        task.await.unwrap();
    }

    /// #1882 — the source a test daemon's footprint is read from. A static,
    /// not the process-global registry, so no other test can change what this
    /// one sees.
    static TEST_FOOTPRINT: std::sync::Mutex<Vec<(std::net::Ipv4Addr, u8)>> =
        std::sync::Mutex::new(Vec::new());

    fn test_footprint() -> Vec<(std::net::Ipv4Addr, u8)> {
        TEST_FOOTPRINT.lock().unwrap().clone()
    }

    /// #1882 — the daemon tells an attached worker the overlay's blocks: right
    /// after `attached`, and again after a `pong` once they have grown — never
    /// twice for the same set, so liveness does not turn into a broadcast.
    #[tokio::test]
    async fn the_daemon_pushes_its_overlay_footprint_to_the_worker() {
        let a = (std::net::Ipv4Addr::new(100, 65, 4, 0), 22);
        let b = (std::net::Ipv4Addr::new(100, 65, 8, 0), 22);
        *TEST_FOOTPRINT.lock().unwrap() = vec![a];

        let host = DelegateHost::new();
        host.set_overlay_footprint(test_footprint);
        let secret = host.mint();
        let (client, server) = tokio::io::duplex(4096);
        let (rd, wr) = tokio::io::split(server);
        let h = host.clone();
        let task = tokio::spawn(async move { h.serve(&secret, Box::new(rd), Box::new(wr)).await });
        let (crd, mut cwr) = tokio::io::split(client);
        let mut lines = BufReader::new(crd).lines();
        async fn next<R: tokio::io::AsyncBufRead + Unpin>(
            lines: &mut tokio::io::Lines<R>,
        ) -> DelegateFrame {
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
                .await
                .expect("a frame within 5 s")
                .unwrap()
                .expect("a frame, not EOF");
            serde_json::from_str(&line).unwrap()
        }

        assert!(matches!(
            next(&mut lines).await,
            DelegateFrame::Attached { .. }
        ));
        match next(&mut lines).await {
            DelegateFrame::OverlayFootprint { v4_nets } => assert_eq!(v4_nets, [a]),
            other => panic!("expected the footprint after attached, got {other:?}"),
        }

        // Unchanged: a ping is answered, and nothing else follows it (the
        // next ping's pong would otherwise come second).
        cwr.write_all(b"{\"t\":\"ping\"}\n").await.unwrap();
        assert!(matches!(next(&mut lines).await, DelegateFrame::Pong));
        // Grown: the next ping's pong carries the new set behind it.
        TEST_FOOTPRINT.lock().unwrap().push(b);
        cwr.write_all(b"{\"t\":\"ping\"}\n").await.unwrap();
        assert!(matches!(next(&mut lines).await, DelegateFrame::Pong));
        match next(&mut lines).await {
            DelegateFrame::OverlayFootprint { v4_nets } => assert_eq!(v4_nets, [a, b]),
            other => panic!("expected the grown footprint, got {other:?}"),
        }

        // ⚠️ Both halves: the daemon sees EOF only when the whole client
        // stream is gone. Dropping the write half alone left this test
        // waiting on `task` forever (measured: 10 h, on the first draft).
        drop(cwr);
        drop(lines);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the daemon loop ends with its channel")
            .unwrap();
    }

    /// FR-92 — keep busy runs in the WORKER of a supervised Mac, and the
    /// server pushes the org policy to the DAEMON, on connect — before any
    /// worker is there. So: a policy heard before the attach is replayed
    /// right after it, and a later one goes straight through, always as the
    /// strictest of every org's (a secondary org's deny included).
    #[tokio::test]
    async fn the_worker_gets_the_strictest_keep_busy_policy_on_attach_and_on_change() {
        fn denied(frame: DelegateFrame) -> bool {
            match frame {
                DelegateFrame::ToWorker { msg } => match *msg {
                    ServerMsg::KeepBusyPolicy { denied } => denied,
                    other => panic!("expected a keep-busy policy, got {other:?}"),
                },
                other => panic!("expected a ToWorker frame, got {other:?}"),
            }
        }
        let host = DelegateHost::new();
        // Heard on connect, with no worker yet: the primary allows.
        host.note_keep_busy_policy("primary", false);
        let secret = host.mint();
        let (client, server) = tokio::io::duplex(4096);
        let (rd, wr) = tokio::io::split(server);
        let h = host.clone();
        let task = tokio::spawn(async move { h.serve(&secret, Box::new(rd), Box::new(wr)).await });
        let (crd, cwr) = tokio::io::split(client);
        let mut lines = BufReader::new(crd).lines();
        async fn next<R: tokio::io::AsyncBufRead + Unpin>(
            lines: &mut tokio::io::Lines<R>,
        ) -> DelegateFrame {
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
                .await
                .expect("a frame within 5 s")
                .unwrap()
                .expect("a frame, not EOF");
            serde_json::from_str(&line).unwrap()
        }
        assert!(matches!(
            next(&mut lines).await,
            DelegateFrame::Attached { .. }
        ));
        assert!(!denied(next(&mut lines).await), "replayed on attach");

        // A SECONDARY org denies: the worker hears the device-wide answer.
        host.note_keep_busy_policy("secondary", true);
        assert!(denied(next(&mut lines).await));
        // The primary allowing again changes nothing while the secondary
        // still denies.
        host.note_keep_busy_policy("primary", false);
        assert!(denied(next(&mut lines).await));
        // The secondary re-allows: allowed.
        host.note_keep_busy_policy("secondary", false);
        assert!(!denied(next(&mut lines).await));

        drop(cwr);
        drop(lines);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the daemon loop ends with its channel")
            .unwrap();
    }

    /// With no org heard from yet, an attaching worker gets no policy frame
    /// at all — silence is not a deny, and not an allow either.
    #[test]
    fn no_policy_heard_means_no_frame_on_attach() {
        let host = DelegateHost::new();
        assert!(host.keep_busy_replay().is_none());
        host.note_keep_busy_policy("primary", true);
        assert!(matches!(
            host.keep_busy_replay(),
            Some(DelegateFrame::ToWorker { .. })
        ));
    }

    /// Attach a fake worker and wait until the daemon's frame loop is up (its
    /// queue toward the worker exists only once it is): a ping answered.
    async fn attached_worker(
        host: &DelegateHost,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    ) {
        let secret = host.mint();
        let (client, server) = tokio::io::duplex(4096);
        let (rd, wr) = tokio::io::split(server);
        let h = host.clone();
        let task = tokio::spawn(async move { h.serve(&secret, Box::new(rd), Box::new(wr)).await });
        let (crd, mut cwr) = tokio::io::split(client);
        let mut lines = BufReader::new(crd).lines();
        assert!(matches!(
            next_frame(&mut lines).await,
            DelegateFrame::Attached { .. }
        ));
        cwr.write_all(b"{\"t\":\"ping\"}\n").await.unwrap();
        assert!(matches!(next_frame(&mut lines).await, DelegateFrame::Pong));
        (task, lines, cwr)
    }

    async fn next_frame<R: tokio::io::AsyncBufRead + Unpin>(
        lines: &mut tokio::io::Lines<R>,
    ) -> DelegateFrame {
        let line = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
            .await
            .expect("a frame within 5 s")
            .unwrap()
            .expect("a frame, not EOF");
        serde_json::from_str(&line).unwrap()
    }

    fn worker_says(on: bool, phase: &str) -> tunnel_core::localapi::KeepBusyInfo {
        tunnel_core::localapi::KeepBusyInfo {
            available: true,
            on,
            phase: phase.into(),
            pattern: "wander".into(),
            ..Default::default()
        }
    }

    /// FR-92 — `roomler exec <mac> roomler keep-busy off` reaches the ROOT
    /// daemon, while on a supervised Mac keep busy runs in the WORKER. The
    /// daemon asks the worker and answers with what it says. Field, 0.4.126:
    /// it answered for its own engine — "off" — while the worker kept moving
    /// the pointer.
    #[tokio::test]
    async fn a_keep_busy_question_is_answered_by_the_attached_worker() {
        let host = DelegateHost::new();
        let (task, mut lines, mut cwr) = attached_worker(&host).await;

        let h = host.clone();
        let asked = tokio::spawn(async move {
            h.ask_worker_keep_busy(true, std::time::Duration::from_secs(5))
                .await
        });
        let id = match next_frame(&mut lines).await {
            DelegateFrame::KeepBusyAsk { id, off } => {
                assert!(off, "an `off` crosses as an `off`");
                id
            }
            other => panic!("expected the question, got {other:?}"),
        };
        let mut told = worker_says(false, "off");
        told.reason = Some("stopped_locally".into());
        write_frame(
            &mut cwr,
            &DelegateFrame::KeepBusyTold {
                id,
                info: Box::new(told),
            },
        )
        .await
        .unwrap();
        let info = asked.await.unwrap().expect("the worker's answer");
        assert_eq!(
            (info.on, info.phase.as_str(), info.reason.as_deref()),
            (false, "off", Some("stopped_locally"))
        );
        assert!(
            host.inner.keep_busy_asks.lock().unwrap().is_empty(),
            "nothing is left waiting"
        );

        drop(cwr);
        drop(lines);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the daemon loop ends with its channel")
            .unwrap();
    }

    /// With no worker attached there is nobody to ask, and nothing to wait
    /// for: the caller answers for its own engine at once.
    #[tokio::test]
    async fn with_no_worker_a_keep_busy_question_returns_at_once() {
        let host = DelegateHost::new();
        let t0 = std::time::Instant::now();
        assert!(
            host.ask_worker_keep_busy(true, std::time::Duration::from_secs(5))
                .await
                .is_none()
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(1));
    }

    /// A worker that never answers (an older one skips the frame) costs the
    /// caller the bounded wait, no more. Its late answer finds nobody waiting
    /// and is dropped, and the channel lives on.
    #[tokio::test]
    async fn a_silent_worker_times_out_and_a_late_answer_is_dropped() {
        let host = DelegateHost::new();
        let (task, mut lines, mut cwr) = attached_worker(&host).await;

        let t0 = std::time::Instant::now();
        assert!(
            host.ask_worker_keep_busy(false, std::time::Duration::from_millis(200))
                .await
                .is_none()
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
        let id = match next_frame(&mut lines).await {
            DelegateFrame::KeepBusyAsk { id, off } => {
                assert!(!off, "a status is not an off");
                id
            }
            other => panic!("expected the question, got {other:?}"),
        };
        write_frame(
            &mut cwr,
            &DelegateFrame::KeepBusyTold {
                id,
                info: Box::new(worker_says(true, "running")),
            },
        )
        .await
        .unwrap();
        cwr.write_all(b"{\"t\":\"ping\"}\n").await.unwrap();
        assert!(matches!(next_frame(&mut lines).await, DelegateFrame::Pong));
        assert!(host.inner.keep_busy_asks.lock().unwrap().is_empty());

        drop(cwr);
        drop(lines);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the daemon loop ends with its channel")
            .unwrap();
    }

    /// A worker that goes away mid-question ends the caller's wait when the
    /// channel closes, not at the timeout.
    #[tokio::test]
    async fn a_worker_that_leaves_ends_the_wait_at_once() {
        let host = DelegateHost::new();
        let (task, mut lines, cwr) = attached_worker(&host).await;

        let h = host.clone();
        let t0 = std::time::Instant::now();
        let asked = tokio::spawn(async move {
            h.ask_worker_keep_busy(true, std::time::Duration::from_secs(30))
                .await
        });
        assert!(matches!(
            next_frame(&mut lines).await,
            DelegateFrame::KeepBusyAsk { .. }
        ));
        drop(cwr);
        drop(lines);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the daemon loop ends with its channel")
            .unwrap();
        let answer = tokio::time::timeout(std::time::Duration::from_secs(5), asked)
            .await
            .expect("the wait ends with the channel")
            .unwrap();
        assert!(answer.is_none());
        assert!(t0.elapsed() < std::time::Duration::from_secs(10));
    }

    /// The two frames' wire, which both halves of one install must agree on.
    #[test]
    fn the_keep_busy_frames_have_a_stable_wire() {
        let ask = serde_json::to_value(DelegateFrame::KeepBusyAsk { id: 7, off: true }).unwrap();
        assert_eq!(
            ask,
            serde_json::json!({"t": "keep_busy_ask", "d": {"id": 7, "off": true}})
        );
        let told = serde_json::to_string(&DelegateFrame::KeepBusyTold {
            id: 7,
            info: Box::new(worker_says(true, "running")),
        })
        .unwrap();
        match serde_json::from_str::<DelegateFrame>(&told).unwrap() {
            DelegateFrame::KeepBusyTold { id, info } => {
                assert_eq!((id, info.on, info.phase.as_str()), (7, true, "running"));
            }
            other => panic!("expected a told frame, got {other:?}"),
        }
    }

    /// An unknown frame must not close the channel: a NEWER worker may send one,
    /// and an additive protocol is only additive if old readers skip it.
    #[tokio::test]
    async fn an_unknown_frame_does_not_close_the_channel() {
        let host = DelegateHost::new();
        let secret = host.mint();
        let (client, server) = tokio::io::duplex(1024);
        let (rd, wr) = tokio::io::split(server);
        let h = host.clone();
        let task = tokio::spawn(async move { h.serve(&secret, Box::new(rd), Box::new(wr)).await });

        let (crd, mut cwr) = tokio::io::split(client);
        let mut lines = BufReader::new(crd).lines();
        let _greeting = lines.next_line().await.unwrap().expect("greeting");

        cwr.write_all(b"{\"t\":\"from_the_future\"}\n")
            .await
            .unwrap();
        cwr.write_all(b"{\"t\":\"ping\"}\n").await.unwrap();
        let pong = lines.next_line().await.unwrap().expect("still alive");
        assert!(pong.contains("\"pong\""), "got {pong}");

        drop(cwr);
        drop(lines);
        task.await.unwrap();
    }

    /// Revocation is what stops a worker the supervisor already released from
    /// coming back — the stale-orphan class that cost two releases in P1.
    #[tokio::test]
    async fn a_revoked_secret_stops_working() {
        let host = DelegateHost::new();
        let secret = host.mint();
        host.revoke();
        let (client, server) = tokio::io::duplex(1024);
        let (rd, wr) = tokio::io::split(server);
        host.serve(&secret, Box::new(rd), Box::new(wr)).await;
        assert!(first_line(client).await.is_none());
    }

    /// A second attach is refused, not allowed to displace the first: otherwise
    /// any local process that learned the secret could knock the real worker
    /// off at will.
    #[tokio::test]
    async fn a_second_attach_is_refused_rather_than_displacing() {
        let host = DelegateHost::new();
        let secret = host.mint();

        let (client1, server1) = tokio::io::duplex(1024);
        let (rd1, wr1) = tokio::io::split(server1);
        let h = host.clone();
        let s1 = secret.clone();
        let first = tokio::spawn(async move { h.serve(&s1, Box::new(rd1), Box::new(wr1)).await });

        let (crd1, cwr1) = tokio::io::split(client1);
        let mut l1 = BufReader::new(crd1).lines();
        assert!(
            l1.next_line().await.unwrap().unwrap().contains("attached"),
            "the first attach should be greeted"
        );

        let (client2, server2) = tokio::io::duplex(1024);
        let (rd2, wr2) = tokio::io::split(server2);
        host.serve(&secret, Box::new(rd2), Box::new(wr2)).await;
        assert!(
            first_line(client2).await.is_none(),
            "the second attach must be refused, not served"
        );

        drop(cwr1);
        drop(l1);
        let _ = first.await;
    }

    #[test]
    fn secret_comparison_rejects_prefixes_and_lengths() {
        assert!(secret_eq("abc", "abc"));
        assert!(!secret_eq("abc", "ab"));
        assert!(!secret_eq("ab", "abc"));
        assert!(!secret_eq("abc", "abd"));
        assert!(!secret_eq("", "x"));
    }
}

#[cfg(all(test, unix))]
mod socket_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// The socket's mode and ownership ARE an authorisation gate — the secret
    /// stops another process of the same user, and these stop every other user.
    /// A future change that widened them would look like a permissions tidy-up
    /// in review, so they are asserted.
    #[tokio::test]
    async fn the_socket_is_0600_and_the_directory_is_traversable_only() {
        let tmp = std::env::temp_dir().join(format!("roomler-deleg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let host = DelegateHost::new();
        let uid = unsafe { libc::getuid() };
        host.listen_in(&tmp, uid).expect("listen");

        let dir_mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o711,
            "directory must be traversable, not listable"
        );

        let sock = tmp.join(format!("{uid}.sock"));
        let md = std::fs::metadata(&sock).unwrap();
        assert_eq!(
            md.permissions().mode() & 0o777,
            0o600,
            "socket must be 0600"
        );
        assert_eq!(md.uid(), uid, "socket must belong to the worker's user");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// End to end over a real unix socket: the right secret is greeted, and a
    /// wrong one gets a close with no bytes — the property the whole design
    /// rests on, exercised through the actual transport rather than in-process.
    #[tokio::test]
    async fn a_real_connection_is_greeted_or_silently_closed() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let tmp = std::env::temp_dir().join(format!("roomler-deleg-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let host = DelegateHost::new();
        let uid = unsafe { libc::getuid() };
        let secret = host.mint();
        host.listen_in(&tmp, uid).expect("listen");
        let sock = tmp.join(format!("{uid}.sock"));

        // Wrong secret: closed, no bytes.
        let mut bad = tokio::net::UnixStream::connect(&sock).await.unwrap();
        bad.write_all(
            b"not-the-secret
",
        )
        .await
        .unwrap();
        let (brd, _bwr) = tokio::io::split(bad);
        assert!(
            BufReader::new(brd)
                .lines()
                .next_line()
                .await
                .unwrap()
                .is_none(),
            "a wrong secret must get no bytes at all"
        );

        // Right secret: greeted.
        let mut good = tokio::net::UnixStream::connect(&sock).await.unwrap();
        good.write_all(
            format!(
                "{secret}
"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let (grd, _gwr) = tokio::io::split(good);
        let greeting = BufReader::new(grd).lines().next_line().await.unwrap();
        assert!(
            greeting.is_some_and(|g| g.contains("attached")),
            "the right secret must be greeted"
        );

        host.revoke();
        assert!(!sock.exists(), "revoke must unlink the socket");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

/// The serde tag of a `ServerMsg`, for logs.
pub fn server_msg_kind(msg: &ServerMsg) -> String {
    serde_json::to_value(msg)
        .ok()
        .and_then(|v| v.get("t").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_else(|| "?".into())
}

/// The serde tag of a `ClientMsg`, for logs — a refusal that does not say WHAT
/// was refused is a refusal nobody can act on.
fn msg_kind(msg: &ClientMsg) -> String {
    serde_json::to_value(msg)
        .ok()
        .and_then(|v| v.get("t").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_else(|| "?".into())
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use roomler_ai_remote_control::models::EndReason;

    fn oid() -> bson::oid::ObjectId {
        bson::oid::ObjectId::new()
    }

    /// The five that make a remote-desktop session, and nothing else.
    ///
    /// This test is the guard the compiler is NOT providing: `delegable_inbound`
    /// ends in a catch-all, deliberately (see its docs), so widening the
    /// whitelist is a one-line edit that would read in review as "support the
    /// new message". Anything added here should be justified in the same breath.
    #[test]
    fn only_rc_session_messages_reach_the_worker() {
        assert!(delegable_inbound(&ServerMsg::SdpOffer {
            shared_lease: None,
            session_id: oid(),
            sdp: String::new(),
            ice_servers: Vec::new(),
            extauth_mac: None,
            peer_auth: None,
        }));
        assert!(delegable_inbound(&ServerMsg::Ice {
            session_id: oid(),
            candidate: serde_json::Value::Null,
        }));
        assert!(delegable_inbound(&ServerMsg::Terminate {
            session_id: oid(),
            reason: EndReason::ControllerHangup,
            limit: None,
        }));

        // The device's authority must never cross the boundary. A sample, not
        // the whole complement — the catch-all covers the rest, and each of
        // these would be a distinct escalation.
        assert!(!delegable_inbound(&ServerMsg::UpdateNow { pin: None }));
    }

    /// The daemon's WS is the DEVICE's identity: anything the worker can put on
    /// it, it says as the device. The more security-relevant direction.
    #[test]
    fn a_worker_may_only_answer_for_its_own_session() {
        assert!(delegable_outbound(&ClientMsg::SdpAnswer {
            session_id: oid(),
            sdp: String::new(),
            extauth_mac: None,
            peer_auth: None,
            peer_auth_verdict: None,
        }));
        assert!(delegable_outbound(&ClientMsg::Ice {
            session_id: oid(),
            candidate: serde_json::Value::Null,
        }));
        // FR-27 P10 — the banner's Disconnect on a supervised Mac is answered
        // by the WORKER (the session lives there), as `host_disconnect`.
        assert!(delegable_outbound(&ClientMsg::Terminate {
            session_id: oid(),
            reason: EndReason::HostDisconnect,
            limit: None,
        }));

        // Consent is the interesting refusal: FR-27 put the decision in the
        // DAEMON and the prompt on the companion surface, so a worker emitting
        // a verdict would be answering a question it was never asked.
        assert!(!delegable_outbound(&ClientMsg::Consent {
            session_id: oid(),
            granted: true,
            reason: None,
        }));
    }

    /// A refused message must be identifiable in the log — a refusal that does
    /// not say WHAT was refused is one nobody can act on.
    #[test]
    fn refusals_name_the_message() {
        let k = msg_kind(&ClientMsg::Terminate {
            session_id: oid(),
            reason: EndReason::AgentHangup,
            limit: None,
        });
        assert!(!k.is_empty() && k != "?", "got {k}");
    }
}

#[cfg(test)]
mod role_tests {
    use super::*;

    fn worker() -> Delegation {
        let (_in_tx, in_rx) = tokio::sync::mpsc::channel(4);
        let (out_tx, _out_rx) = tokio::sync::mpsc::channel(4);
        Delegation::Worker(WorkerLink {
            inbound: in_rx,
            outbound: out_tx,
        })
    }

    /// A process is the supervising DAEMON or the supervised WORKER, never
    /// both. The enum makes "both" unrepresentable; these assert that the
    /// accessors agree, so a future refactor cannot quietly hand a worker the
    /// daemon's channel — which would let it delegate rc messages to itself.
    #[test]
    fn a_process_is_one_role_or_neither() {
        let mut off = Delegation::Off;
        assert!(off.host().is_none());
        assert!(off.worker_mut().is_none());

        let mut daemon = Delegation::Daemon(DelegateHost::new());
        assert!(daemon.host().is_some());
        assert!(
            daemon.worker_mut().is_none(),
            "the daemon must never look like a worker"
        );

        let mut w = worker();
        assert!(
            w.host().is_none(),
            "a worker must never hold the daemon's channel"
        );
        assert!(w.worker_mut().is_some());
    }

    /// The worker's two ends are split so the receiver can be polled while the
    /// sender is lent to a session — the borrow shape `connect_once` needs.
    #[tokio::test]
    async fn the_worker_ends_carry_messages_in_both_directions() {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(4);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(4);
        let mut role = Delegation::Worker(WorkerLink {
            inbound: in_rx,
            outbound: out_tx,
        });
        let sid = bson::oid::ObjectId::new();
        in_tx
            .send(WorkerInbound::Msg(Box::new(ServerMsg::Ice {
                session_id: sid,
                candidate: serde_json::Value::Null,
            })))
            .await
            .unwrap();

        let (rx, tx) = role.worker_mut().expect("worker");
        let got = match rx.recv().await.expect("inbound") {
            WorkerInbound::Msg(m) => *m,
            other => panic!("expected a message, got {other:?}"),
        };
        assert!(
            delegable_inbound(&got),
            "only delegable kinds should arrive"
        );
        tx.send(ClientMsg::SdpAnswer {
            session_id: sid,
            sdp: "v=0".into(),
            extauth_mac: None,
            peer_auth: None,
            peer_auth_verdict: None,
        })
        .await
        .unwrap();
        let back = out_rx.recv().await.expect("outbound");
        assert!(
            delegable_outbound(&back),
            "a reply must be one the daemon will relay"
        );
    }
}

#[cfg(test)]
mod params_tests {
    use super::*;

    /// The bug this frame exists for, stated as a test.
    ///
    /// `Request` resolves a session's parameters; `SdpOffer` consumes them.
    /// Delegating only the latter left the worker defaulting `transport` to
    /// `None` — the legacy RTP track — while the browser read the
    /// `video-bytes` data channel it had negotiated. 13 MB encoded, nothing
    /// rendered, and input still working because it rides its own channel.
    ///
    /// So the value that must survive the crossing is `Some("data-channel-…")`
    /// staying `Some`, distinct from a session that genuinely negotiated the
    /// track path.
    #[test]
    fn the_negotiated_transport_survives_the_crossing() {
        let params = SessionParams {
            session_id: bson::oid::ObjectId::new().to_hex(),
            shared_lease: None,
            codec: "h264".into(),
            transport: Some("data-channel-h264".into()),
            chroma: None,
            chunk_framing: false,
            audio: true,
            permissions: roomler_ai_remote_control::permissions::Permissions::all(),
            controller_name: "someone".into(),
            input_mode: None,
            asking_org: None,
            record: None,
            rc_overlay: None,
            idle_secs: None,
            lock_on_end: None,
        };
        let wire = serde_json::to_string(&DelegateFrame::SessionParams(Box::new(params)))
            .expect("serialises");
        let back: DelegateFrame = serde_json::from_str(&wire).expect("round-trips");
        match back {
            DelegateFrame::SessionParams(p) => {
                assert_eq!(
                    p.transport.as_deref(),
                    Some("data-channel-h264"),
                    "a dropped transport is a black screen with a healthy log"
                );
                assert!(p.audio, "audio negotiation must not silently default off");
                assert!(
                    p.permissions
                        .contains(roomler_ai_remote_control::permissions::Permissions::FILES),
                    "permissions must not silently default: the FILES denial is                      how this bug first showed"
                );
            }
            other => panic!("expected SessionParams, got {other:?}"),
        }
    }

    /// `None` is a real negotiated value (the legacy track), not "unset" — so a
    /// future refactor must not collapse it with a missing field.
    #[test]
    fn an_absent_transport_is_distinguishable_from_a_present_one() {
        let mut p = SessionParams {
            session_id: bson::oid::ObjectId::new().to_hex(),
            shared_lease: None,
            codec: "h264".into(),
            transport: None,
            chroma: None,
            chunk_framing: false,
            audio: false,
            permissions: roomler_ai_remote_control::permissions::Permissions::empty(),
            controller_name: String::new(),
            input_mode: None,
            asking_org: None,
            record: None,
            rc_overlay: None,
            idle_secs: None,
            lock_on_end: None,
        };
        let track = serde_json::to_string(&p).unwrap();
        p.transport = Some("data-channel-h264".into());
        let dc = serde_json::to_string(&p).unwrap();
        assert_ne!(track, dc, "the two transports must not serialise alike");
    }

    fn params(
        session_id: &str,
        permissions: roomler_ai_remote_control::permissions::Permissions,
    ) -> SessionParams {
        SessionParams {
            session_id: session_id.to_string(),
            shared_lease: None,
            codec: "h264".into(),
            transport: None,
            chroma: None,
            chunk_framing: false,
            audio: false,
            permissions,
            controller_name: String::new(),
            input_mode: None,
            asking_org: None,
            record: None,
            rc_overlay: None,
            idle_secs: None,
            lock_on_end: None,
        }
    }

    /// #1882 — the worker runs no overlay, so the daemon's overlay blocks must
    /// cross WITH the decision: without them a supervised Mac's worker would
    /// read its own `utunN` address as foreign and offer it again. A frame
    /// from an older daemon carries neither and reads as off.
    #[test]
    fn the_overlay_decision_and_its_blocks_cross_and_absent_reads_off() {
        let mut p = params(
            &bson::oid::ObjectId::new().to_hex(),
            roomler_ai_remote_control::permissions::Permissions::all(),
        );
        p.rc_overlay = Some(crate::rc_overlay::RcOverlay {
            allow: false,
            v4_nets: vec![(std::net::Ipv4Addr::new(100, 65, 4, 0), 22)],
        });
        let wire = serde_json::to_string(&DelegateFrame::SessionParams(Box::new(p.clone())))
            .expect("serialises");
        match serde_json::from_str::<DelegateFrame>(&wire).expect("round-trips") {
            DelegateFrame::SessionParams(back) => assert_eq!(back.rc_overlay, p.rc_overlay),
            other => panic!("expected SessionParams, got {other:?}"),
        }

        p.rc_overlay = None;
        let older = serde_json::to_string(&p).unwrap();
        assert!(!older.contains("rc_overlay"), "{older}");
        let back: SessionParams = serde_json::from_str(&older).unwrap();
        assert!(!back.rc_overlay.unwrap_or_default().allow);
    }

    /// FR-85 P1e-mac — the record context crosses intact, and a frame from a
    /// daemon older than it (no `record` at all) still parses, as a session
    /// with no record context: its channel refuses `unavailable`, as before.
    #[test]
    fn the_record_context_crosses_and_an_older_frame_still_parses() {
        let mut p = params(
            &bson::oid::ObjectId::new().to_hex(),
            roomler_ai_remote_control::permissions::Permissions::all(),
        );
        let old_wire = serde_json::to_string(&DelegateFrame::SessionParams(Box::new(p.clone())))
            .expect("serialises");
        assert!(
            !old_wire.contains("record\""),
            "an absent context adds nothing to the wire: {old_wire}"
        );
        match serde_json::from_str::<DelegateFrame>(&old_wire).expect("parses") {
            DelegateFrame::SessionParams(back) => assert_eq!(back.record, None),
            other => panic!("expected SessionParams, got {other:?}"),
        }

        let controller = bson::oid::ObjectId::new().to_hex();
        p.record = Some(DelegatedRecord {
            controller_user_id: controller.clone(),
            prompt_window_ms: Some(30_000),
        });
        let wire =
            serde_json::to_string(&DelegateFrame::SessionParams(Box::new(p))).expect("serialises");
        match serde_json::from_str::<DelegateFrame>(&wire).expect("parses") {
            DelegateFrame::SessionParams(back) => assert_eq!(
                back.record,
                Some(DelegatedRecord {
                    controller_user_id: controller,
                    prompt_window_ms: Some(30_000),
                }),
                "a dropped window would record a host-consented session without asking"
            ),
            other => panic!("expected SessionParams, got {other:?}"),
        }
    }

    fn activity(session_id: bson::oid::ObjectId) -> ClientMsg {
        ClientMsg::RecordingActivity {
            session_id,
            kind: roomler_ai_remote_control::models::RecordingActivityKind::Started,
            name: None,
            bytes: None,
            duration_ms: None,
            reason: None,
        }
    }

    /// FR-85 P1e-mac — the worker may report recording activity ONLY about a
    /// session the daemon handed it with `RECORD`. Anything else is the
    /// device's own account of itself, forged by an unprivileged process.
    /// A worker "attached" the way `run` attaches one: its queue set. Deep
    /// enough for the bound test, and held so a send is never refused full.
    fn attach_worker(host: &DelegateHost) -> tokio::sync::mpsc::Receiver<DelegateFrame> {
        let (tx, rx) = tokio::sync::mpsc::channel(RECORD_SESSIONS_KEPT * 2);
        *host.inner.to_worker.lock().unwrap() = Some(tx);
        rx
    }

    fn hand_over(
        host: &DelegateHost,
        id: bson::oid::ObjectId,
        permissions: roomler_ai_remote_control::permissions::Permissions,
    ) -> bool {
        host.send_params(DelegateFrame::SessionParams(Box::new(params(
            &id.to_hex(),
            permissions,
        ))))
    }

    #[test]
    fn only_a_session_handed_over_with_record_may_report_recording_activity() {
        use roomler_ai_remote_control::permissions::Permissions;
        let host = DelegateHost::new();
        let _worker = attach_worker(&host);
        let (recorded, watched, never) = (
            bson::oid::ObjectId::new(),
            bson::oid::ObjectId::new(),
            bson::oid::ObjectId::new(),
        );
        assert!(hand_over(
            &host,
            recorded,
            Permissions::VIEW | Permissions::RECORD
        ));
        assert!(hand_over(
            &host,
            watched,
            Permissions::VIEW | Permissions::INPUT
        ));

        assert!(host.records_session_of(&activity(recorded)));
        assert!(
            !host.records_session_of(&activity(watched)),
            "a session without RECORD has no recording to report"
        );
        assert!(
            !host.records_session_of(&activity(never)),
            "a session this daemon never handed over"
        );
        assert!(
            !host.records_session_of(&ClientMsg::Terminate {
                session_id: recorded,
                reason: roomler_ai_remote_control::models::EndReason::AgentHangup,
                limit: None,
            }),
            "only RecordingActivity rides this admission"
        );
        assert!(
            !delegable_outbound(&activity(recorded)),
            "the whitelist itself stays pure"
        );
    }

    /// The memory is bounded, oldest out first, and a session handed over
    /// twice is noted once.
    #[test]
    fn the_record_session_memory_is_bounded() {
        use roomler_ai_remote_control::permissions::Permissions;
        let host = DelegateHost::new();
        let _worker = attach_worker(&host);
        let first = bson::oid::ObjectId::new();
        for id in std::iter::once(first)
            .chain((0..RECORD_SESSIONS_KEPT).map(|_| bson::oid::ObjectId::new()))
        {
            assert!(hand_over(&host, id, Permissions::RECORD));
        }
        assert!(
            !host.records_session_of(&activity(first)),
            "the oldest fell out"
        );
        let held = host.inner.record_sessions.lock().unwrap().len();
        assert_eq!(held, RECORD_SESSIONS_KEPT);
        let last = host
            .inner
            .record_sessions
            .lock()
            .unwrap()
            .back()
            .cloned()
            .unwrap();
        host.send_params(DelegateFrame::SessionParams(Box::new(params(
            &last,
            Permissions::RECORD,
        ))));
        assert_eq!(
            host.inner.record_sessions.lock().unwrap().len(),
            RECORD_SESSIONS_KEPT
        );
    }

    /// Review finding — "noted" means DELIVERED: with no worker attached (or
    /// a queue that refuses), no worker can have a recording of the session,
    /// so nobody may report on it.
    #[test]
    fn a_session_no_worker_received_is_not_noted() {
        use roomler_ai_remote_control::permissions::Permissions;
        let host = DelegateHost::new();
        let sid = bson::oid::ObjectId::new();
        assert!(
            !hand_over(&host, sid, Permissions::VIEW | Permissions::RECORD),
            "nobody attached: the params went nowhere"
        );
        assert!(!host.records_session_of(&activity(sid)));

        // A full queue drops them too.
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(DelegateFrame::Ping).unwrap();
        *host.inner.to_worker.lock().unwrap() = Some(tx);
        assert!(!hand_over(
            &host,
            sid,
            Permissions::VIEW | Permissions::RECORD
        ));
        assert!(!host.records_session_of(&activity(sid)));
    }

    /// Review finding — a revoked worker's sessions are forgotten, so the
    /// next worker (another console user, after a switch) cannot report on
    /// them.
    #[test]
    fn revoking_the_worker_forgets_what_it_was_handed() {
        use roomler_ai_remote_control::permissions::Permissions;
        let host = DelegateHost::new();
        let _worker = attach_worker(&host);
        let sid = bson::oid::ObjectId::new();
        assert!(hand_over(&host, sid, Permissions::RECORD));
        assert!(host.records_session_of(&activity(sid)));
        host.revoke();
        assert!(
            !host.records_session_of(&activity(sid)),
            "a replaced worker's sessions must not be reportable by the next one"
        );
    }

    /// Review finding — the relay itself, end to end: a handed-over RECORD
    /// session's activity reaches the control WS; anyone else's does not; and
    /// a whitelisted message still passes (the positive control of the relay).
    /// Without this, `relay_upstream` could stop consulting the admission and
    /// every other test here would stay green.
    #[test]
    fn the_relay_puts_only_a_handed_over_sessions_activity_on_the_ws() {
        use roomler_ai_remote_control::permissions::Permissions;
        let host = DelegateHost::new();
        let _worker = attach_worker(&host);
        let (ws_tx, mut ws_rx) = tokio::sync::mpsc::channel::<ClientMsg>(8);
        host.set_outbound(ws_tx);
        let (recorded, other) = (bson::oid::ObjectId::new(), bson::oid::ObjectId::new());
        assert!(hand_over(
            &host,
            recorded,
            Permissions::VIEW | Permissions::RECORD
        ));

        host.relay_upstream(activity(recorded));
        match ws_rx.try_recv() {
            Ok(ClientMsg::RecordingActivity { session_id, .. }) => assert_eq!(session_id, recorded),
            other => panic!("the handed-over session's activity must reach the WS, got {other:?}"),
        }
        host.relay_upstream(activity(other));
        assert!(
            ws_rx.try_recv().is_err(),
            "another session's activity must be dropped"
        );
        host.relay_upstream(ClientMsg::Terminate {
            session_id: recorded,
            reason: roomler_ai_remote_control::models::EndReason::AgentHangup,
            limit: None,
        });
        assert!(
            matches!(ws_rx.try_recv(), Ok(ClientMsg::Terminate { .. })),
            "the relay still carries the whitelist"
        );
    }

    /// FR-85 P1e-mac — while a worker is attached the DEVICE advertises the
    /// worker's `record` caps (it is the half that records); with none, the
    /// caller keeps its own; and an older worker's empty list advertises
    /// nothing rather than something it cannot serve.
    #[test]
    fn the_device_advertises_the_attached_workers_record_caps() {
        let host = DelegateHost::new();
        assert_eq!(
            host.effective_record(),
            None,
            "no worker: nothing to override"
        );
        let caps = AgentCaps {
            record: vec!["available".into(), "remote".into()],
            ..Default::default()
        };
        *host.inner.worker_caps.lock().unwrap() = Some(caps);
        assert_eq!(
            host.effective_record(),
            Some(vec!["available".to_string(), "remote".to_string()])
        );
        *host.inner.worker_caps.lock().unwrap() = Some(AgentCaps::default());
        assert_eq!(
            host.effective_record(),
            Some(Vec::new()),
            "an older worker says nothing, and so does the device"
        );
    }
}

#[cfg(test)]
mod shared_lease_delegation_tests {
    use super::*;
    use roomler_ai_remote_control::{models::RpcCap, signaling::SharedSessionLease};
    #[test]
    fn shared_lease_delegation_requires_worker_cap_and_exact_handed_scope() {
        let host = DelegateHost::new();
        let sid = bson::oid::ObjectId::new();
        let scope = SharedSessionLease {
            grant_id: bson::oid::ObjectId::new(),
            lease_epoch: "11111111-1111-4111-8111-111111111111".into(),
        };
        let (to_worker, mut worker) = tokio::sync::mpsc::channel(8);
        *host.inner.to_worker.lock().unwrap() = Some(to_worker);
        let params = || {
            DelegateFrame::SessionParams(Box::new(SessionParams {
                session_id: sid.to_hex(),
                shared_lease: Some(scope.clone()),
                codec: "h264".into(),
                transport: None,
                chroma: None,
                chunk_framing: false,
                audio: false,
                permissions: roomler_ai_remote_control::permissions::Permissions::VIEW,
                controller_name: "fixture".into(),
                input_mode: None,
                asking_org: None,
                record: None,
                rc_overlay: None,
                idle_secs: None,
                lock_on_end: None,
            }))
        };
        assert!(!host.send_params(params()));
        assert!(worker.try_recv().is_err());
        let mut caps = AgentCaps::default();
        caps.rpc.push(RpcCap::SharedSessionLease.wire().into());
        *host.inner.worker_caps.lock().unwrap() = Some(caps);
        assert!(host.send_params(params()));
        assert!(host.has_shared_params(sid));
        assert!(
            matches!(worker.try_recv().unwrap(),DelegateFrame::SessionParams(p) if p.shared_lease==Some(scope.clone()))
        );
        let (up, mut replies) = tokio::sync::mpsc::channel(8);
        host.set_outbound(up);
        let challenge = |grant| ClientMsg::SharedLeaseChallenge {
            session_id: sid,
            grant_id: grant,
            lease_epoch: scope.lease_epoch.clone(),
            challenge_id: 1,
        };
        assert!(
            !delegable_outbound(&challenge(scope.grant_id)),
            "not globally whitelisted as device authority"
        );
        host.relay_upstream(challenge(bson::oid::ObjectId::new()));
        assert!(replies.try_recv().is_err());
        host.relay_upstream(challenge(scope.grant_id));
        assert!(matches!(
            replies.try_recv().unwrap(),
            ClientMsg::SharedLeaseChallenge { .. }
        ));
        assert!(delegable_inbound(&ServerMsg::SharedLeaseRenewal {
            session_id: sid,
            grant_id: scope.grant_id,
            lease_epoch: scope.lease_epoch,
            challenge_id: 1
        }));
    }
}

#[cfg(test)]
mod shared_lease_params_scope_regressions {
    use super::*;
    use roomler_ai_remote_control::signaling::SharedSessionLease;
    #[tokio::test]
    async fn shared_lease_actual_params_roundtrip_after_end_cannot_reopen_offer_or_attach() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let sid = bson::oid::ObjectId::new();
        let scope = SharedSessionLease {
            grant_id: bson::oid::ObjectId::new(),
            lease_epoch: "11111111-1111-4111-8111-111111111111".into(),
        };
        let params = SessionParams {
            session_id: sid.to_hex(),
            shared_lease: Some(scope.clone()),
            codec: "h264".into(),
            transport: None,
            chroma: None,
            chunk_framing: false,
            audio: false,
            permissions: roomler_ai_remote_control::permissions::Permissions::VIEW,
            controller_name: "fixture".into(),
            input_mode: None,
            asking_org: None,
            record: None,
            rc_overlay: None,
            idle_secs: None,
            lock_on_end: None,
        };
        let raw = serde_json::to_string(&DelegateFrame::SessionParams(Box::new(params))).unwrap();
        let DelegateFrame::SessionParams(p) = serde_json::from_str(&raw).unwrap() else {
            panic!("actual Params frame")
        };
        let mut r = crate::shared_lease::SharedLeases::default();
        assert!(r.note_optional(sid, p.shared_lease.as_ref()));
        r.end(sid);
        let DelegateFrame::SessionParams(mut late) = serde_json::from_str(&raw).unwrap() else {
            panic!("late Params frame")
        };
        assert!(!r.note_optional(sid, late.shared_lease.as_ref()));
        late.shared_lease = None;
        assert!(!r.note_optional(sid, late.shared_lease.as_ref()));
        let (tx, _) = tokio::sync::mpsc::channel(8);
        for shared_lease in [Some(scope.clone()), None] {
            let offer = ServerMsg::SdpOffer {
                session_id: sid,
                shared_lease: shared_lease.clone(),
                sdp: String::new(),
                ice_servers: vec![],
                extauth_mac: None,
                peer_auth: None,
            };
            assert!(!r.offer(sid, &offer, &tx));
            let flag = Arc::new(AtomicBool::new(false));
            let f = flag.clone();
            assert!(!r.attach(
                sid,
                shared_lease.as_ref(),
                Arc::new(move || {
                    f.store(true, Ordering::SeqCst);
                })
            ));
            assert!(flag.load(Ordering::SeqCst));
        }
    }
}
