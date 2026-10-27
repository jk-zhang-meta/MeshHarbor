// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The supervisor: one per daemon, holding the sessions this device runs.
//!
//! # A start, end to end
//!
//! `handle_start` answers on the connection that asked, off the signaling
//! loop. Under one lock — starts are rare, and two of the same session must
//! not both launch — the supervisor checks, in order: the primary enrollment,
//! `hive_enabled`, the harness kind, a start it already runs (answered
//! `accepted` again and launched nothing: reconcile-on-connect re-sends a start
//! whose answer was lost), the account, the folder, capacity, and a harness
//! binary; then launches, and only a process that STARTED is `accepted`.
//!
//! # A session's life
//!
//! One task per session owns the harness's stdin, stdout and exit, so what it
//! sees happens in the order it happened: a prompt is written and recorded and
//! the session is `running`; a turn's `result` makes it `idle`; an exit — or a
//! stop, which closes stdin and signals the process group — makes it `ended`.
//! Reports go to the primary connection that is up NOW, and the latest of each
//! is replayed when a connection comes up, because a report sent into a dying
//! socket is lost and the server would otherwise show a stale state forever.
//!
//! # The fence (P2e-1)
//!
//! A session's lease is a fence, and the server's word on it only grows. A
//! start at an older fence than the run here is a stale frame, refused. A
//! start at a newer one, or `rc:hive.demote`, means the run here belongs to
//! the past: it is FENCED (its model calls, prompts and approval answers are
//! refused from that moment) and stopped, and a start waits until its task
//! has let go before it launches, so two harnesses never run on one history.
//! Whatever a run removes when it ends — its live entry, its hosted record —
//! it removes only at its own fence, so an old run's end never takes the new
//! run's with it.

use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bson::oid::ObjectId;
use roomler_ai_remote_control::hive::{
    HARNESS_CLAUDE_CODE, HiveApprovalStatus, HiveDrainRefusal, HiveForkOf, HiveManifestEntry,
    HivePlace, HiveRefusal, HiveRunState, HiveTurnStatus, hive_limits, promote_limits,
};
use roomler_ai_remote_control::signaling::ClientMsg;
use roomler_hive_node::checkpoint::Checkpoint;
#[cfg(unix)]
use roomler_hive_node::launch::unix_base_env;
use roomler_hive_node::launch::{
    APPROVE_TOOL, DISALLOWED_TOOLS, LaunchSpec, PERMISSION_MODE, SettingsSpec, attributed_prompt,
    config_dir_in, history_path_in, parent_history_in, toolbelt_mcp_config, user_input_line,
};
use roomler_hive_node::stream_json::{Limits, parse_line};
use roomler_hive_node::{TranscriptEvent, approval_outcome};
use roomler_node_core::config::AgentConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::process::{Child, ChildStdin};
use tokio::sync::{broadcast, mpsc, watch};

/// P1i-2 — on Windows a harness is a [`crate::hive_win::HarnessChild`]: started
/// into its Job Object as the console user, with the part of tokio's `Child`
/// the session task uses, its stdin an async file over the pipe.
#[cfg(windows)]
use crate::hive_win::HarnessChild as Child;
#[cfg(windows)]
type ChildStdin = tokio::fs::File;
use tracing::{debug, info, warn};

use super::gates::{self, HiveConfig};
use super::hosted::{Hosted, HostedSession, RunningTurn};
use super::lines::LineReader;
use super::materializer;
use super::resume_note;
use super::store::StoreHandle;
use super::toolbelt::{self, ApprovalEvent, Toolbelt};

/// How long an `ended` report is replayed on reconnect: long enough to cross
/// a control-WS flap, short enough not to replay history forever.
const ENDED_REPLAY: Duration = Duration::from_secs(10 * 60);
/// A session task's input channel: its prompts and its stop.
const INPUT_QUEUE: usize = 16;
/// Prompts a session holds — admitted, not yet written to the harness —
/// before it refuses the next. Half the input channel, so a stop always
/// finds room in it.
const MAX_WAITING: usize = INPUT_QUEUE / 2;
/// Runs as the session's account: makes the session's config directory (so
/// the daemon never writes into a tree that account owns), enters the folder,
/// then becomes the harness. Arguments are positional — no value is ever
/// interpolated into the script.
///
/// P1e — `$3`, when set, is the daemon-owned directory holding the session's
/// core memory, and `$4` the session's auto-memory directory: each file is
/// copied in AS THE ACCOUNT, and only when nothing is there yet — so a
/// resume keeps what the session has (its own edits included). A copy that
/// fails is skipped: memory never stops a session.
///
/// P1i-2 — on Windows `meshharbord hive-prep` does this, run as the console user
/// ([`crate::hive_win::prep`]); the harness's folder is its working directory.
#[cfg(unix)]
const WRAPPER: &str = r#"umask 077 && mkdir -p -- "$1" && { if [ -n "$3" ]; then if [ -f "$3/CLAUDE.md" ] && [ ! -e "$1/CLAUDE.md" ] && [ ! -L "$1/CLAUDE.md" ]; then cp -- "$3/CLAUDE.md" "$1/CLAUDE.md" 2>/dev/null; fi; if [ -f "$3/MEMORY.md" ] && [ ! -e "$4/MEMORY.md" ] && [ ! -L "$4/MEMORY.md" ]; then mkdir -p -- "$4" 2>/dev/null && cp -- "$3/MEMORY.md" "$4/MEMORY.md" 2>/dev/null; fi; fi; true; } && cd -- "$2" && shift 4 && exec "$@""#;
/// Each session's runtime files (settings, MCP config, toolbelt socket, core
/// memory): the daemon's own, cleared at boot.
#[cfg(target_os = "linux")]
const RUNTIME_DIR: &str = tunnel_core::localapi::hive_adopt::RUNTIME_DIR_LINUX;
#[cfg(target_os = "macos")]
const RUNTIME_DIR: &str = tunnel_core::localapi::hive_adopt::RUNTIME_DIR_MACOS;

/// The runtime root this daemon writes each session's files under. On Windows
/// (P1i-2) under the daemon's machine-global directory, where nothing clears
/// it at boot: each launch gives its session's directory its DACL again.
/// FR-90 P3-9-2b — and on Unix, a person's endpoints under `person-<uid>`.
pub(super) fn runtime_root() -> PathBuf {
    #[cfg(unix)]
    return PathBuf::from(RUNTIME_DIR);
    #[cfg(windows)]
    return crate::hive_win::runtime_root();
}
/// P1h — how long the daemon gives its harnesses to exit on SIGTERM when it
/// leaves ([`wind_down`]) before SIGKILL: within the 5 s a service manager
/// usually waits for a stop.
const WIND_DOWN_GRACE: Duration = Duration::from_secs(3);
/// P1e — how long a session's core memory waits for its start's launch,
/// and how many snapshots wait at once: the server sends one right before
/// each start, so anything older or more is not waiting for anything.
const MEMORY_WAIT: Duration = Duration::from_secs(10 * 60);
const MEMORY_PENDING: usize = 64;
/// P2e-5 — how long a session's move waits for its start, and how many wait
/// at once: the server sends one right before each moved start (and before
/// its re-send on connect), as it does core memory.
const MOVE_WAIT: Duration = MEMORY_WAIT;
const MOVE_PENDING: usize = MEMORY_PENDING;
/// P2f-1a — how long a teleport's prepare admits its session's join, and
/// how many teleports a device is prepared for at once: the join follows the
/// prepare's answer, and comes again at each connection until it is
/// answered. A later prepare of the same session replaces its admission.
const TELEPORT_ADMISSION: Duration = Duration::from_secs(promote_limits::TELEPORT_ADMISSION_SECS);
const TELEPORTS_PENDING: usize = MEMORY_PENDING;
/// P2e-5 — the most checkpoints a moved session's copy is put in place from:
/// a history only grows, so its chunks span every checkpoint since it began.
/// A longer chain is refused whole, never put in place cut short.
const MAX_CHAIN: usize = 20_000;
/// Longest stdout line kept; a longer one is consumed and skipped, never
/// buffered whole.
const MAX_LINE: usize = 8 * 1024 * 1024;
/// How long a stopped harness gets between SIGTERM and SIGKILL, and an
/// exiting one before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// P2e-1 — how long a start at a newer fence waits for the run it stops to
/// let go: a stop's whole path, both graces and the stderr tail's 2 s, with
/// room to spare. Past it the start is refused, and nothing launches beside
/// a harness that is still there.
const SUPERSEDE_WAIT: Duration = Duration::from_secs(2 * STOP_GRACE.as_secs() + 5);
/// P2e-2 — how long a leased run's model call waits for the server's word
/// on a new connection before it is refused: the word answers the device's
/// manifest, about a round trip after the connection is up, so this covers a
/// slow resume before the manifest too. Claude Code retries the refusal.
const LEASE_WAIT: Duration = Duration::from_secs(30);
/// P2e-2 — the server's words this daemon keeps at once. A word is kept only
/// for a session the device runs or hosts, so this bounds a server that sends
/// more than any device holds.
const MAX_LEASE_WORDS: usize = 256;
/// P2e-4 — how long a drained session's running turn goes on before it is
/// cut: the wire's bound, which the server waits for and a margin more.
const DRAIN_CUT: Duration = Duration::from_secs(promote_limits::DRAIN_TURN_CUT_SECS);
/// P2e-4 — how long a cut turn is given to end once the harness was told to
/// stop it. Past it the drain is refused, and the turn runs on.
const DRAIN_CUT_GRACE: Duration = Duration::from_secs(10);
/// P2e-4 — beyond the cut and its grace, how long a drain waits for its
/// session's answer: the last checkpoint.
const DRAIN_CHECKPOINT_WAIT: Duration = Duration::from_secs(50);

/// P2e-4 — when a drained session's running turn is cut, how long it is
/// given to end then, and how long the drain waits beyond both for its last
/// checkpoint (shorter in the tests).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DrainTiming {
    pub cut: Duration,
    pub grace: Duration,
    pub checkpoint: Duration,
}

impl Default for DrainTiming {
    fn default() -> Self {
        Self {
            cut: DRAIN_CUT,
            grace: DRAIN_CUT_GRACE,
            checkpoint: DRAIN_CHECKPOINT_WAIT,
        }
    }
}
/// How much of a failed harness's stderr its transcript note keeps — on the
/// device; the `ended` detail, which the server stores, never carries it.
const STDERR_TAIL: usize = 400;
/// The toolbelt's channel to its session task: an approval opening and
/// closing is two messages, and a session holds few open at once.
const APPROVAL_QUEUE: usize = 32;
/// Approvals per session whose newest frame a reconnect replays.
const APPROVAL_REPLAY: usize = 16;
/// P1d-2 — what the daemon hosts, beside the replica store.
const HOSTED_FILE: &str = "hosted.json";
/// P1d-2 — how long a harness that ended without being stopped waits before
/// its end counts. Under systemd a stop reaches the daemon first and the
/// harness a moment later, and a session cut by the daemon's own stop is
/// surviving the restart, not ending.
const SETTLE: Duration = Duration::from_secs(1);
/// P1d-2 — a resumed session the daemon does not outlive by this, restarting
/// again, counts towards [`MAX_QUICK_RESUMES`].
const RESUME_STABLE: Duration = Duration::from_secs(120);
/// P1d-2 — resumes in a row that a session did not outlive by
/// [`RESUME_STABLE`]: at this many it is ended instead, so a resume that
/// takes the daemon down cannot become a crash loop.
const MAX_QUICK_RESUMES: u32 = 3;
/// P1d-2 — how long a connection's manifest waits for the resume. Past it,
/// the manifest goes out without what is still resuming; the server ends
/// those, and stops them again when their launch reports in.
const RESUME_BUDGET: Duration = Duration::from_secs(60);

/// What `rc:hive.start` asks for, as the supervisor uses it.
#[derive(Debug, Clone)]
pub struct StartOrder {
    pub session_id: ObjectId,
    pub harness: String,
    pub harness_session: String,
    pub fence: u64,
    pub folder: String,
    pub user_id: ObjectId,
    pub user_email: String,
    pub caller: String,
    pub resume: bool,
    /// P2b-3b — checkpoint each turn's end: a session the server joined as
    /// replicated (its start's `replicated`, or a resume of one). P2c-4: a
    /// primary's join turns it on later, while the session runs.
    pub replicated: bool,
    /// P2e-2 — the session is leased: after a restart or a reconnect it runs,
    /// and calls the model, only on the server's word on that connection
    /// (`rc:hive.lease`). A start that says so is that word for its own
    /// connection.
    pub lease: bool,
    /// FR-90 P2f-3a — the session this one is a fork of, as every start of a
    /// fork carries it: at its first start here, the parent's copy is what
    /// it starts from ([`Supervisor::put_fork_in_place`]); for its life, its
    /// checkpoints keep the parent's history beside its own.
    pub fork_of: Option<HiveForkOf>,
    /// FR-90 P2f-4a — a terminal session this device adopted, whose terminal
    /// ended here, made a managed one: at its first start here the
    /// terminal's own history is put in place as the account it ran as
    /// ([`Supervisor::terminal_in_place`]), and the launch resumes it. Once the
    /// session's history is its own, a start launches it as any other.
    pub from_terminal: bool,
}

/// FR-90 P1e — a session's core memory, as `rc:hive.memory` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreMemory {
    pub session_id: ObjectId,
    pub fence: u64,
    pub brain_rev: u64,
    /// The org's facts, then the starter's.
    pub claude_md: Option<String>,
    /// The device's facts, for the auto-memory index.
    pub memory_md: Option<String>,
}

/// FR-90 P2e-5 — `rc:hive.move`: the record's word for the run that starts at
/// `fence`, sent right before its start. Kept for that start: it counts on
/// from `turns`, and puts the session's copy in place first when it ran on
/// another device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub session_id: ObjectId,
    pub fence: u64,
    /// The newest turn the session's room has a stub for.
    pub turns: u32,
    /// Where it ran before: this very device on a move back.
    pub from_device_id: ObjectId,
    /// FR-90 P2e-7 — that device's name and the folder it ran in, and who
    /// moved it and when: what the resume note says.
    pub from_device_name: String,
    pub from_folder: String,
    pub moved_by_name: String,
    pub moved_at_ms: u64,
    /// FR-90 P2f-5 — every place it ran before, oldest first, as the record's
    /// path map names them: the note says where earlier turns' paths live now.
    pub earlier: Vec<HivePlace>,
}

/// The device's answer to a start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub refused: Option<HiveRefusal>,
    pub account: Option<String>,
    pub detail: Option<String>,
}

impl Answer {
    fn refused(r: HiveRefusal, detail: impl Into<String>) -> Self {
        Self {
            refused: Some(r),
            account: None,
            detail: Some(detail.into()),
        }
    }

    fn accepted(account: &str) -> Self {
        Self {
            refused: None,
            account: Some(account.to_string()),
            detail: None,
        }
    }
}

/// Who a prompt came from: the user it is attributed to in the transcript
/// (by name) and on the turn's stub (by id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    pub user_id: ObjectId,
    pub name: String,
}

/// What the session task is fed.
enum Input {
    Prompt {
        author: Option<Author>,
        text: String,
    },
    Stop {
        reason: String,
    },
    /// P2e-4 — the session's lease is about to leave this device: no prompt
    /// begins, the running turn ends or is cut, the open approvals are
    /// withdrawn, a last checkpoint is taken, and `reply` hears where the
    /// copy ends.
    Drain {
        reply: tokio::sync::oneshot::Sender<Drained>,
    },
    /// P2e-4 — the server's word at the run's fence: the lease stayed, and
    /// the prompts held by the drain begin.
    Undrain,
    /// P2f-1a — a primary's join turned the running session replicated: its
    /// first checkpoint now when no turn runs, and where its copy ends told
    /// either way ([`checkpoint_now`]).
    Replicated,
}

/// P2e-4 — how a drain ended, as the session's task tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Drained {
    /// Quiet: the copy ends at `seq`, whose event's hash is `hash` (hex).
    At { seq: u64, hash: String },
    /// Not drained, and why: the session goes on as before.
    Not(String),
}

/// P2e-4 — a drain the session's task has taken up: its answer to come,
/// and the task's inputs, to lift it should the answer not come in time.
pub(crate) struct PendingDrain {
    answer: tokio::sync::oneshot::Receiver<Drained>,
    input: mpsc::Sender<Input>,
}

struct Live {
    fence: u64,
    account: String,
    /// Who started it — the one driver this device knows without the server
    /// saying so (P1c-2, [`Supervisor::drives_here`]).
    starter: ObjectId,
    input: mpsc::Sender<Input>,
    /// Prompts admitted and not yet begun — shared with the session task,
    /// which holds them while a turn runs (see `Task::prompt`).
    waiting: Arc<AtomicUsize>,
    /// P1a — the session's open approvals, which a driver answers.
    approvals: Arc<toolbelt::Pending>,
    /// P1h — the harness's pid, which leads its process group.
    pid: Option<u32>,
    /// P2c-3 — the server placed members besides this device: it checkpoints,
    /// and its tip is reported. P2c-4: shared with the session's task, which
    /// reads it at each turn's end, so a primary's join turns it on while the
    /// session runs.
    replicated: Arc<AtomicBool>,
    /// P2e-1 — a newer fence took the session (a start at one here, or
    /// `rc:hive.demote`): its model calls, prompts and approval answers are
    /// refused from now on, not once its harness has gone.
    fenced: bool,
    /// P2e-1 — changes once, closing, when the session's task has let go of
    /// it (`finish` or `let_go` returned): what a start at a newer fence
    /// waits for before it launches.
    gone: watch::Receiver<()>,
    /// P2e-2 — leased: after a reconnect its model calls wait for the
    /// server's word on the new connection. From its start, or from the
    /// first word while it runs.
    lease: bool,
    /// P2e-4 — drained for a move: no new prompt is taken. The server's word
    /// at this fence lifts it; a demote ends the run.
    draining: bool,
    /// P2f-2b — where it runs here and as whom, from its launch: what a
    /// member's `want_pack` is packed from ([`Supervisor::workplace`]).
    workplace: Arc<super::packer::Workplace>,
}

/// FR-90 P2f-1a — a teleport this device was prepared for: its prepare's
/// order (the session, and the start's fence) and when it passed.
struct Prepared {
    order: StartOrder,
    at: Instant,
    /// P2f-2b — the account the prepare's gates mapped the owner to and the
    /// folder they resolved, when the server let the copy's workspace come
    /// against what that folder's repository holds (`have_want`): what the
    /// stream's have and want asks about. `None`: the whole pack.
    have_want: Option<(String, PathBuf)>,
}

/// What a launch hands the session task.
struct Spawned {
    child: Child,
    /// The model token this run holds, with the sidecar.
    token: Option<String>,
    /// P1a — owned by the task, so it ends exactly when the session does.
    toolbelt: Toolbelt,
    /// P1d-2 — launched with `--resume`: the harness has its history.
    history: bool,
    /// P2b-3b — the session's checkpoints, taken while it is replicated.
    checkpoints: super::checkpointer::Checkpoints,
}

/// P1d-2 — where a session the device hosted stood when its last daemon
/// went down, as the session task takes it up again.
struct Resumed {
    turns: u32,
    /// The turn the restart cut, if one ran.
    cut: Option<RunningTurn>,
    /// The approvals it left open.
    approvals: Vec<String>,
    /// Whether the harness found its history (`--resume`).
    history: bool,
}

#[derive(Clone)]
struct Report {
    fence: u64,
    state: HiveRunState,
    detail: Option<String>,
    at: Instant,
}

/// How a harness is spawned. Production has exactly one way: as the account
/// the device mapped the starter to. The other exists for the tests, which
/// cannot become another account, and is unconstructible outside them — the
/// unit tests, and an integration test built with `hive-test-launcher`.
#[derive(Debug, Clone)]
enum Launcher {
    AsMappedAccount,
    #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
    AsDaemon {
        home: PathBuf,
    },
}

/// P1j — terminal sessions adopted on this device.
mod adopt;
mod follow;
mod purge;
mod replica;
mod retain;
mod stream;

pub struct Supervisor {
    cfg: HiveConfig,
    /// Per-session settings files (`<runtime>/<sid>/settings.json`): written
    /// by the daemon, readable by the session's account, writable only here.
    runtime: PathBuf,
    launcher: Launcher,
    store: Result<StoreHandle, String>,
    start_lock: tokio::sync::Mutex<()>,
    live: Mutex<HashMap<ObjectId, Live>>,
    reports: Mutex<HashMap<ObjectId, Report>>,
    /// The newest `rc:hive.turn` per session, replayed with the states.
    turns: Mutex<HashMap<ObjectId, ClientMsg>>,
    /// P1a-2 — the newest `rc:hive.approval` of each of a session's recent
    /// approvals, replayed with the states: an end lost in a dying socket
    /// would leave the room's stub saying "needs approval" for ever.
    approval_frames: Mutex<HashMap<ObjectId, Vec<(String, ClientMsg)>>>,
    reporter: Mutex<Option<mpsc::Sender<ClientMsg>>>,
    /// Every state as it is reported, for the viewers of that session.
    states: broadcast::Sender<(ObjectId, HiveRunState)>,
    /// P1a — a session's open approvals each time they change, for its
    /// viewers: a driver's card shows its buttons only while it is open.
    approvals: broadcast::Sender<(ObjectId, Vec<String>)>,
    /// How long an approval waits for a person (shorter in the tests).
    approval_timing: toolbelt::Timing,
    /// The viewer peers this device serves (P0d-2).
    viewers: super::view::Viewers,
    /// P0e — the model sidecar: its port once bound, the session tokens it
    /// honours, the provider key the helper printed, and when the primary
    /// connection was lost (the `offline_grace` clock).
    sidecar_port: tokio::sync::OnceCell<u16>,
    tokens: super::sidecar::Tokens,
    model_key: tokio::sync::Mutex<Option<(String, Instant)>>,
    offline_since: Mutex<Option<Instant>>,
    upstream: String,
    offline_grace: Duration,
    /// P1d-1 — an update is about to restart the daemon: new prompts and
    /// starts are refused, so no turn begins in the gap before the installer
    /// runs ([`Supervisor::begin_update`]).
    updating: std::sync::atomic::AtomicBool,
    /// P1d-2 — the sessions this device hosts, on disk ([`super::hosted`]).
    hosted: Mutex<Hosted>,
    /// P1d-2 — what the previous daemon hosted, until the first connection
    /// resumes it. A stop that comes first takes its session out.
    to_resume: Mutex<Vec<HostedSession>>,
    /// P1d-2 — set once that resume has run: a manifest waits for it.
    resumed: tokio::sync::OnceCell<()>,
    /// P1d-2 — the daemon is stopping ([`begin_shutdown`]): a harness that
    /// ends from now on went down with it, and its session is the next
    /// daemon's to resume.
    going_down: AtomicBool,
    /// P1e — core memory waiting for its start's launch, by (session, fence).
    memory: Mutex<HashMap<(ObjectId, u64), (CoreMemory, Instant)>>,
    /// P2e-5 — moves waiting for their start, by (session, fence).
    moves: Mutex<HashMap<(ObjectId, u64), (Moved, Instant)>>,
    /// P2f-1a — teleports this device was prepared for, by session: what
    /// admits that session's join in the teleport's role
    /// ([`Self::teleport_admitted`]), and (P2f-2b) where it will run here.
    teleports: Mutex<HashMap<ObjectId, Prepared>>,
    /// Test-only: the workplaces of sessions a test serves without running
    /// them ([`Self::workplace`]).
    #[cfg(all(test, unix))]
    test_workplaces: Mutex<HashMap<ObjectId, Arc<super::packer::Workplace>>>,
    /// P2e-5 — this device's own enrollment, which tells a move back (the
    /// session comes back where its state is) from a move here.
    agent_id: Option<ObjectId>,
    /// FR-90 P3-8-2b-2 — how a session's `ssh_run` reaches another device:
    /// this daemon's own SSH client, made at [`init`] from the daemon's
    /// config, which knows how its overlay dials. None in a supervisor
    /// built without one, and then `ssh_run` is not offered.
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    ssh_runner: Option<Arc<dyn super::ssh_tools::SshRunner>>,
    /// P1j — the terminal sessions this device mirrors ([`adopt`]), on disk.
    adopted: Mutex<adopt::AdoptedFile>,
    /// P1j — adopt offers waiting for the server's word, by offer id.
    adopt_offers: Mutex<HashMap<String, tokio::sync::oneshot::Sender<adopt::OfferAnswer>>>,
    /// P2d — the replica streams this device is a side of, by grant: the
    /// ones it serves as a source and the ones it follows as a member.
    streams: Mutex<HashMap<ObjectId, stream::Stream>>,
    /// P2d-3 — what the streams this device follows hold in memory, across
    /// all of them: event bytes, and blob bytes, each taken before it is
    /// read ([`stream::EVENT_BUDGET`], [`stream::BLOB_BUDGET`]).
    replica_events: tokio::sync::Semaphore,
    replica_blobs: tokio::sync::Semaphore,
    /// P2d-3b — what this device does about each session it holds a copy of
    /// as a member: the ask in flight, the stream followed, the wait.
    follows: Mutex<follow::Follows>,
    /// P2e-2 — the server's word for each leased session it holds here, by
    /// (session, fence): the connection it came on, held weakly. It counts
    /// only while that connection is the latest one (`reporter`).
    lease_words: Mutex<HashMap<(ObjectId, u64), mpsc::WeakSender<ClientMsg>>>,
    /// P2e-2 — wakes a model call waiting for its session's word.
    lease_heard: tokio::sync::Notify,
    /// P2e-2 — leased sessions the previous daemon hosted, held back for the
    /// server's word on a connection of this one, by session.
    awaiting_word: Mutex<HashMap<ObjectId, HostedSession>>,
    /// P2e-2 — how long a leased run's model call waits for the word.
    lease_wait: Duration,
    /// P2e-4 — a drain's bounds: the cut, its grace, the checkpoint's wait.
    drain_timing: DrainTiming,
    /// P2d-2c — a test's own DERP mux in place of the primary org's (`Some`),
    /// so one test stands a source and a member on two muxes wired to each
    /// other; `Some(None)` for none at all, whatever another test registered.
    #[cfg(test)]
    derp_for_tests: Mutex<Option<Option<tunnel_core::transport::derp::DerpTunnelHandle>>>,
    /// P2b-3b — how a test's sessions take their checkpoints (in-process,
    /// failing, never finishing); a device always runs `hive-checkpoint` as
    /// the account. P2d-6: an integration test's device too
    /// ([`init_as_daemon`]), in-process.
    #[cfg(any(test, all(unix, feature = "hive-test-launcher")))]
    checkpoint_runner: Option<super::checkpointer::Runner>,
    /// P2d-3b — whether a connection starts following every copy held, as
    /// a device's does; a test that drives the follow itself turns it off,
    /// so the connection's own asks do not race its own.
    #[cfg(test)]
    follow_at_connect: bool,
}

static SUPERVISOR: OnceLock<Arc<Supervisor>> = OnceLock::new();

/// FR-90 P1e — `rc:hive.memory`: kept for its start's launch. The primary
/// enrollment's only, like every Hive frame.
pub fn handle_memory(m: CoreMemory, is_primary: bool) {
    if !is_primary {
        warn!(session = %m.session_id, "hive: rc:hive.memory ignored — not the primary enrollment");
        return;
    }
    match global() {
        Some(sup) => sup.receive_memory(m),
        None => debug!(session = %m.session_id, "hive: rc:hive.memory with no supervisor"),
    }
}

/// FR-90 P2e-5 — `rc:hive.move`, just ahead of a moved start: kept for that
/// start ([`Supervisor::receive_move`]). The primary enrollment's only, like
/// every Hive frame.
pub fn handle_move(m: Moved, is_primary: bool) {
    if !is_primary {
        warn!(session = %m.session_id, "hive: rc:hive.move ignored — not the primary enrollment");
        return;
    }
    match global() {
        Some(sup) => sup.receive_move(m),
        None => debug!(session = %m.session_id, "hive: rc:hive.move with no supervisor"),
    }
}

/// FR-90 P2e-5 — `rc:hive.prepare`: could this device take the session over
/// ([`Supervisor::prepare`])? Answered with `rc:hive.prepare_ack` on `tx`, the
/// connection it came on. P2f-1a — a teleport's: could it run the session,
/// once it holds the copy it takes next ([`Supervisor::prepare_teleport`])?
/// P2f-2b — `have_want`: the server lets it take the workspace's first pack
/// against what its folder's repository holds.
pub fn handle_prepare(
    order: StartOrder,
    teleport: bool,
    have_want: bool,
    is_primary: bool,
    tx: mpsc::Sender<ClientMsg>,
) {
    let sup = global();
    tokio::spawn(async move {
        let (answer, tip) = match sup {
            // No tip: the copy is still to come.
            Some(sup) if teleport => (
                sup.prepare_teleport(&order, is_primary, have_want).await,
                None,
            ),
            Some(sup) => sup.prepare_with_tip(&order, is_primary).await,
            None => (
                Answer::refused(
                    HiveRefusal::HiveDisabled,
                    "agent sessions are not set up on this device",
                ),
                None,
            ),
        };
        let _ = tx.send(prepare_ack(&order, answer, tip)).await;
    });
}

/// FR-90 P2e-5 — a prepare's answer as `rc:hive.prepare_ack` says it; P2e-6a —
/// with where the copy ends, when ready.
fn prepare_ack(
    order: &StartOrder,
    a: Answer,
    tip: Option<roomler_ai_remote_control::hive::HiveCopyTip>,
) -> ClientMsg {
    ClientMsg::HivePrepareAck {
        session_id: order.session_id,
        fence: order.fence,
        refused: a.refused,
        account: a.account,
        detail: a
            .detail
            .map(|d| d.chars().take(hive_limits::MAX_DETAIL_LEN).collect()),
        tip,
    }
}

/// FR-90 P1d-2 — the daemon is stopping: an OS stop, a restart it asked for,
/// or an update's. Called first thing on the way out. What its harnesses do
/// from now on is going down with it.
pub fn begin_shutdown() {
    if let Some(s) = global() {
        s.begin_shutdown();
    }
}

/// FR-90 P1h — the daemon is leaving: take down every harness it launched
/// ([`super::procs`]), the way systemd's `KillMode=control-group` takes down
/// a whole unit and the way nothing does under launchd or for an
/// unsupervised daemon. [`begin_shutdown`] first, so each session task reads
/// its harness's exit as going down with the daemon: the session is kept for
/// the next daemon to resume, and nothing is reported. Bounded by
/// [`WIND_DOWN_GRACE`].
pub async fn wind_down() {
    if let Some(s) = global() {
        s.wind_down().await;
    }
}

/// FR-90 P1d-1 (AC7) — the sessions mid-turn on this daemon: what an update
/// waits for. Empty where no supervisor was set up.
pub fn turns_running() -> Vec<ObjectId> {
    global().map(|s| s.turns_running()).unwrap_or_default()
}

/// FR-90 P1d-1 — how long an update waits for [`turns_running`]: the
/// device's `hive_update_wait_secs`.
pub fn update_wait() -> Duration {
    global().map_or(gates::DEFAULT_UPDATE_WAIT, |s| s.update_wait())
}

/// FR-90 P1d-1 — the update is going ahead: hold new prompts and starts.
pub fn begin_update() {
    if let Some(s) = global() {
        s.begin_update();
    }
}

/// FR-90 P1d-1 — the update did not happen (the installer did not start):
/// take prompts and starts again.
pub fn end_update() {
    if let Some(s) = global() {
        s.end_update();
    }
}

/// Build the daemon's supervisor from its config. Called once at start; a
/// second call is a no-op. Built even with `hive_enabled = false`, so a start
/// is answered with the device's actual refusal rather than silence.
pub fn init(cfg: &AgentConfig) {
    let hive = HiveConfig::from_agent(cfg);
    // P3-4c-2 — files `vault_render` wrote for an earlier process: no lease
    // outlives the process that held it, so none of them is anyone's now.
    #[cfg(all(unix, feature = "vault"))]
    {
        let gone = super::vault_render::sweep(&runtime_root());
        if gone > 0 {
            info!(
                gone,
                "hive: removed the secrets directories an earlier process left"
            );
        }
        // P3-5b-2 — and the endpoints `vault_connect` served: their sockets
        // would only refuse, and their directories hold nothing else.
        let gone = super::vault_connect::sweep(&runtime_root());
        if gone > 0 {
            info!(
                gone,
                "hive: removed the proxy endpoints an earlier process left"
            );
        }
    }
    // P1h-2 — `hive` is in the release builds, so every device runs this. One
    // whose owner never turned agent sessions on keeps no store: nothing is
    // created for it, and a start is refused `hive_disabled` before a store
    // is needed. One that did keeps serving the transcripts its store holds.
    let path = store_path(|file| store_wanted(&hive, file.exists()));
    let store = match &path {
        Ok(Some(p)) => StoreHandle::spawn(Some(p)),
        Ok(None) => Err("agent sessions are off on this device".to_string()),
        Err(e) => Err(e.clone()),
    };
    match (&path, &store) {
        (Ok(None), _) => debug!("hive: agent sessions are off here — no replica store is kept"),
        (_, Err(e)) => {
            warn!(%e, "hive: the replica store is unavailable — every start will be refused")
        }
        _ => {}
    }
    // P1d-2 — what the previous daemon hosted, resumed at the first
    // connection. Without a data directory nothing can be.
    let hosted = match &path {
        Ok(Some(p)) => Hosted::load(p.with_file_name(HOSTED_FILE), &cfg.agent_id),
        _ => Hosted::in_memory(),
    };
    let mut sup = Supervisor::new(
        hive,
        runtime_root(),
        Launcher::AsMappedAccount,
        store,
        hosted,
    );
    sup.agent_id = ObjectId::parse_str(&cfg.agent_id).ok();
    // FR-90 P3-8-2b-2 — the daemon's own SSH client, dialing as its overlay
    // does; offered to a session only under `hive_ssh` ([`Supervisor::ssh_runner`]).
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    {
        sup.ssh_runner = Some(Arc::new(super::ssh_tools::DaemonSsh::new(cfg)));
    }
    let sup = Arc::new(sup);
    let _ = SUPERVISOR.set(Arc::clone(&sup));
    // P2g-3d — the device's own clock, for the copies its store keeps.
    if sup.store.is_ok() {
        sup.spawn_retention_clock();
    }
    // P1j — the adopt socket, only while the device's owner allows it; with
    // adopting off, a socket a predecessor left behind is taken away.
    if sup.cfg.adopt {
        tokio::spawn(async move {
            if let Err(e) = sup.adopt_listen().await {
                warn!(%e, "hive: the adopt socket could not be opened — nothing is adopted");
            }
        });
    } else {
        sup.adopt_remove_stale_socket();
    }
}

/// FR-90 P1j — `rc:hive.adopt_ack`: the server's word on an offer. The
/// primary enrollment's only, like every Hive frame.
pub fn handle_adopt_ack(
    adopt_id: &str,
    session_id: Option<ObjectId>,
    fence: Option<u64>,
    refused: Option<roomler_ai_remote_control::hive::HiveAdoptRefusal>,
    is_primary: bool,
) {
    if !is_primary {
        warn!(
            adopt_id,
            "hive: rc:hive.adopt_ack ignored — not the primary enrollment"
        );
        return;
    }
    let answer = match (refused, session_id) {
        (None, Some(sid)) => Ok((sid, fence.unwrap_or(1))),
        (Some(word), _) => Err(word),
        (None, None) => Err(roomler_ai_remote_control::hive::HiveAdoptRefusal::Other),
    };
    if let Some(sup) = global() {
        sup.adopt_answered(adopt_id, answer);
    }
}

/// FR-90 P1j — whether this device's owner allows adopting terminal
/// sessions: what decides whether it advertises `hive-adopt`.
pub fn adopt_enabled() -> bool {
    global().is_some_and(|s| s.cfg.adopt)
}

/// FR-90 P2c-3 — whether this device holds copies of its owner's sessions
/// run elsewhere: its owner's `hive_replica`, with the store open. What
/// decides whether it advertises `hive-replica`.
pub fn replica_enabled() -> bool {
    global().is_some_and(|s| s.cfg.replica && s.store.is_ok())
}

/// FR-90 P2c-3 — whether it also offers itself as the org's archive replica
/// (`hive_archive`, only ever with `hive_replica`): `hive-archive`.
pub fn archive_enabled() -> bool {
    global().is_some_and(|s| s.cfg.archive && s.store.is_ok())
}

/// FR-90 P2d-3b — whether this device carries the replica stream:
/// `hive-stream`. While its store is open, whatever its owner says of
/// holding copies: a primary serves its own sessions' members, and P2c-4
/// tells it it is replicated whether its owner holds others' copies or not.
pub fn stream_enabled() -> bool {
    global().is_some_and(|s| s.store.is_ok())
}

/// FR-90 P2c-3 — `rc:hive.replica.join`: answered with
/// `rc:hive.replica.join_ack` on the connection it came on, after the
/// device's own gates ([`replica`]). P2e-5b — with `fences`, where each fence
/// a promotion superseded ended, which a member's store keeps with the join.
pub fn handle_replica_join(
    session_id: ObjectId,
    fence: u64,
    role: Option<roomler_ai_remote_control::hive::HiveReplicaRole>,
    fences: Vec<roomler_ai_remote_control::hive::HiveFenceMark>,
    is_primary: bool,
    tx: mpsc::Sender<ClientMsg>,
) {
    tokio::spawn(async move {
        let (refused, detail) = match global() {
            Some(sup) => {
                let answer = sup
                    .answer_join(is_primary, session_id, fence, role, &fences)
                    .await;
                // P2d-3b — a copy now held asks for its stream.
                let member = role.is_some_and(|r| {
                    r != roomler_ai_remote_control::hive::HiveReplicaRole::Primary
                });
                if answer.0.is_none() && member {
                    sup.follow_joined(session_id, fence);
                }
                answer
            }
            None => (
                Some(roomler_ai_remote_control::hive::HiveJoinRefusal::ReplicaDisabled),
                Some("agent sessions are not set up on this device".to_string()),
            ),
        };
        let _ = tx
            .send(ClientMsg::HiveReplicaJoinAck {
                session_id,
                fence,
                refused,
                detail,
            })
            .await;
    });
}

/// FR-90 P2d — `rc:hive.replica.grant`: serve a stream of a session this
/// device holds to one of its members, answered with `rc:hive.replica.ready`
/// on the connection it came on ([`stream`]). The grant is registered before
/// its endpoint is stood up, so the server's close ends a setup in flight.
#[allow(clippy::too_many_arguments)]
pub fn handle_replica_grant(
    grant_id: ObjectId,
    session_id: ObjectId,
    fence: u64,
    member_id: ObjectId,
    path: Option<roomler_ai_remote_control::hive::HiveStreamPath>,
    token: String,
    ice_servers: Vec<roomler_ai_remote_control::signaling::IceServer>,
    member_derp_pubkey: Option<String>,
    ttl_secs: u32,
    is_primary: bool,
    tx: mpsc::Sender<ClientMsg>,
) {
    let g = stream::Grant {
        grant_id,
        session_id,
        fence,
        member_id,
        path,
        token,
        ice_servers,
        member_derp_pubkey,
        ttl_secs,
    };
    match global() {
        Some(sup) => sup.take_grant(g, is_primary, tx),
        None => {
            tokio::spawn(async move {
                let _ = tx
                    .send(ClientMsg::HiveReplicaReady {
                        grant_id,
                        refused: Some(roomler_ai_remote_control::hive::HiveStreamRefusal::NotHeld),
                        detail: Some("agent sessions are not set up on this device".into()),
                        cert_fingerprint: None,
                        addrs: Vec::new(),
                        derp_pubkey: None,
                    })
                    .await;
            });
        }
    }
}

/// FR-90 P2d — `rc:hive.replica.dial`: the source this device asked for is
/// ready; dial it as a member ([`stream`]).
#[allow(clippy::too_many_arguments)]
pub fn handle_replica_dial(
    grant_id: ObjectId,
    session_id: ObjectId,
    fence: u64,
    source_id: ObjectId,
    path: Option<roomler_ai_remote_control::hive::HiveStreamPath>,
    token: String,
    cert_fingerprint: String,
    addrs: Vec<String>,
    ice_servers: Vec<roomler_ai_remote_control::signaling::IceServer>,
    derp_pubkey: Option<String>,
    ttl_secs: u32,
    is_primary: bool,
) {
    if let Some(sup) = global() {
        sup.follow_dial(
            stream::Dial {
                grant_id,
                session_id,
                fence,
                source_id,
                path,
                token,
                cert_fingerprint,
                addrs,
                ice_servers,
                derp_pubkey,
                ttl_secs,
            },
            is_primary,
        );
    }
}

/// FR-90 P2d-2b — `rc:hive.replica.candidate`: a member's relayed address,
/// for the TURN permission of a relay stream this device serves
/// ([`stream`]).
pub fn handle_replica_candidate(grant_id: ObjectId, addr: String, is_primary: bool) {
    if let Some(sup) = global() {
        sup.take_candidate(grant_id, &addr, is_primary);
    }
}

/// FR-90 P2d — `rc:hive.replica.close`: the server ended a stream this
/// device is a side of.
pub fn handle_replica_close(grant_id: ObjectId, reason: String) {
    if let Some(sup) = global() {
        sup.close_stream(grant_id, &reason);
    }
}

/// FR-90 P2d-3b — `rc:hive.replica.refused`: no stream this time, for an ask
/// this device made ([`follow`]). The primary enrollment's only, like every
/// Hive frame.
pub fn handle_replica_refused(
    session_id: ObjectId,
    fence: u64,
    path: Option<roomler_ai_remote_control::hive::HiveStreamPath>,
    reason: Option<roomler_ai_remote_control::hive::HiveStreamRefusal>,
    is_primary: bool,
) {
    if !is_primary {
        return debug!(session = %session_id, "rc:hive.replica.refused on a secondary org's connection — ignored");
    }
    if let Some(sup) = global() {
        sup.on_refused(session_id, fence, path, reason);
    }
}

/// FR-90 P0f — an integration test's supervisor: sessions launch as the
/// daemon's OWN account, because a test process cannot become another one;
/// the store and the settings live where the test says.
///
/// ⚠️ Only with the `hive-test-launcher` feature, which no release build
/// enables — and even then refused when the daemon is root, so this can
/// never be how a session comes to run as root. One per process, like
/// [`init`]: a test that needs it gets a test binary of its own.
#[cfg(all(unix, feature = "hive-test-launcher"))]
pub fn init_as_daemon(
    cfg: &AgentConfig,
    store: &Path,
    runtime: &Path,
    home: &Path,
) -> Result<(), String> {
    // SAFETY: geteuid reads our own credentials.
    if unsafe { libc::geteuid() } == 0 {
        return Err("the test launcher never runs sessions as root".into());
    }
    let mut sup = Supervisor::new(
        HiveConfig::from_agent(cfg),
        runtime.to_path_buf(),
        Launcher::AsDaemon {
            home: home.to_path_buf(),
        },
        StoreHandle::spawn(Some(store)),
        Hosted::load(store.with_file_name(HOSTED_FILE), &cfg.agent_id),
    );
    sup.agent_id = ObjectId::parse_str(&cfg.agent_id).ok();
    // P2d-6 — this process's binary is a test's, which knows no
    // `hive-checkpoint`: a replicated session's checkpoints are taken in
    // process, through the same frames and checks, git's discovery stopping
    // at the test's own directory.
    sup.checkpoint_runner = Some(super::checkpointer::Runner::InProcess {
        ceiling: store
            .parent()
            .map_or_else(|| runtime.to_path_buf(), Path::to_path_buf),
    });
    let sup = Arc::new(sup);
    SUPERVISOR
        .set(Arc::clone(&sup))
        .map_err(|_| "a supervisor is already set up in this process".to_string())?;
    // P2g-3d — the device's own clock, as the daemon's own init starts it.
    if sup.store.is_ok() {
        sup.spawn_retention_clock();
    }
    // FR-90 P2f-4 — and the adopt socket, as the daemon's own init opens it:
    // a test device adopts a terminal session through the real hook client.
    if sup.cfg.adopt {
        tokio::spawn(async move {
            if let Err(e) = sup.adopt_listen().await {
                warn!(%e, "hive: the adopt socket could not be opened — nothing is adopted");
            }
        });
    }
    Ok(())
}

/// The daemon's supervisor, once [`init`] ran.
pub fn global() -> Option<Arc<Supervisor>> {
    SUPERVISOR.get().cloned()
}

/// `<data dir>/hive/hive.db`, in a directory locked to the daemon (0700, no
/// link on the way): other local users must not read anyone's transcript.
/// `Ok(None)` when `wanted` says this daemon keeps no store, and then
/// nothing is created (P1h-2).
fn store_path(wanted: impl FnOnce(&Path) -> bool) -> Result<Option<PathBuf>, String> {
    #[cfg(unix)]
    let dir = roomler_node_core::appdirs::project_dirs()
        .map(|p| p.data_local_dir().join("hive"))
        .ok_or("no data directory for the replica store")?;
    // P1i-2 — on Windows the service's machine-wide directory, which the
    // worker reaches whether it is SYSTEM or the console user elevated, so a
    // new worker finds what the last one kept.
    #[cfg(windows)]
    let dir = crate::hive_win::store_dir();
    let file = dir.join("hive.db");
    if !wanted(&file) {
        return Ok(None);
    }
    private_dir(&dir)?;
    Ok(Some(file))
}

/// FR-90 P1h-2 — whether this daemon keeps a replica store: while its owner
/// runs or adopts agent sessions, or (P2c) holds copies of sessions run
/// elsewhere, or once it holds one (whose transcripts are still served after
/// `hive_enabled` goes off). A device that never turned any of it on keeps
/// none.
fn store_wanted(hive: &HiveConfig, store_exists: bool) -> bool {
    hive.enabled || hive.adopt || hive.replica || store_exists
}

/// Create `dir` if missing and lock it to the daemon's account. A link on
/// the path that someone other than root could have made is refused, never
/// followed ([`untrusted_link`]).
#[cfg(unix)]
fn private_dir(dir: &Path) -> Result<(), String> {
    if let Some(link) = untrusted_link(dir) {
        return Err(format!("{} is a symbolic link", link.display()));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", dir.display()))
}

/// P1h-3 — the first link on `path`'s way that someone other than root could
/// have made, or `None`. A link that root owns, in a directory that root owns
/// and that nobody else may write to, could only have been made by root, so
/// following it gives nothing away: macOS's own `/var` → `/private/var` is one,
/// and the root daemon's data directory is under it (`/var/root`).
/// Field-found: with every link refused, as FR-85's
/// [`roomler_node_core::recording_dir::link_component`] refuses them, a Mac
/// opened no store and refused every session "/var is a symbolic link". Any
/// other link on the way is refused, as before.
#[cfg(unix)]
fn untrusted_link(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    let mut cur = PathBuf::new();
    for c in path.components() {
        cur.push(c.as_os_str());
        if matches!(c, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                let root_made = m.uid() == 0
                    && cur
                        .parent()
                        .and_then(|p| std::fs::metadata(p).ok())
                        .is_some_and(|p| p.uid() == 0 && p.mode() & 0o022 == 0);
                if !root_made {
                    return Some(cur);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    None
}

/// P1i-2 — on Windows: a protected DACL of SYSTEM and Administrators, set as
/// the directory is made (or again, on one already there), which is what
/// `0700` is for a daemon that runs as SYSTEM.
#[cfg(windows)]
fn private_dir(dir: &Path) -> Result<(), String> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    crate::hive_win::dir_with_dacl(dir, crate::hive_win::PRIVATE_DIR_SDDL)
}

/// `rc:hive.start` — answered on `tx`, the connection that asked, from a task
/// of its own: launching does I/O the signaling loop must not wait on.
pub fn handle_start(order: StartOrder, is_primary: bool, tx: mpsc::Sender<ClientMsg>) {
    tokio::spawn(async move {
        let (session_id, fence) = (order.session_id, order.fence);
        let answer = match global() {
            Some(sup) => {
                // P2e-2 — a leased start is the server's word on this
                // connection, kept before the launch: its first model call
                // must not wait for another.
                if order.lease && is_primary {
                    sup.record_word(session_id, fence, &tx);
                }
                sup.start(order, is_primary).await
            }
            None => Answer::refused(
                HiveRefusal::HiveDisabled,
                "agent sessions are not set up on this daemon",
            ),
        };
        let _ = tx
            .send(ClientMsg::HiveStartAck {
                session_id,
                fence,
                refused: answer.refused,
                account: answer.account,
                detail: answer.detail,
            })
            .await;
    });
}

/// `rc:hive.stop`. Idempotent: a session this device does not run is
/// reported `ended` at once, so the server's stop always completes.
pub fn handle_stop(session_id: ObjectId, fence: u64, reason: String, is_primary: bool) {
    if !is_primary {
        warn!(session = %session_id, "hive: rc:hive.stop ignored — not the primary enrollment");
        return;
    }
    match global() {
        Some(sup) => sup.stop(session_id, fence, reason),
        None => debug!(session = %session_id, "hive: rc:hive.stop with no supervisor"),
    }
}

/// FR-90 P2g-1 — `rc:hive.purge`: the session purged from this device
/// ([`Supervisor::purge`]), under the start lock, so no start of it races the
/// purge, and answered with `rc:hive.purge_ack` on `tx`, the connection it came
/// on. The primary enrollment's only, like every Hive frame. P2k-3 —
/// `leaving`: this device's copy alone, as a member that leaves, whose removal
/// is not final here.
pub fn handle_purge(
    purge_id: ObjectId,
    session_id: ObjectId,
    leaving: bool,
    is_primary: bool,
    tx: mpsc::Sender<ClientMsg>,
) {
    if !is_primary {
        warn!(session = %session_id, "hive: rc:hive.purge ignored — not the primary enrollment");
        return;
    }
    let Some(sup) = global() else {
        debug!(session = %session_id, "hive: rc:hive.purge with no supervisor");
        return;
    };
    tokio::spawn(async move {
        let ack = {
            let _serial = sup.start_lock.lock().await;
            sup.purge(purge_id, session_id, leaving).await
        };
        let _ = tx.send(ack).await;
    });
}

/// FR-90 P2g-4a — `rc:hive.purge_all`: this device's enrollment is being
/// removed, so every session it holds is purged ([`Supervisor::purge_all`]).
/// The primary enrollment's only, like every Hive frame: a secondary
/// organization's removal leaves the copies, which are the primary's.
pub fn handle_purge_all(purge_id: ObjectId, is_primary: bool) {
    if !is_primary {
        warn!(purge = %purge_id, "hive: rc:hive.purge_all ignored — not the primary enrollment");
        return;
    }
    let Some(sup) = global() else {
        debug!(purge = %purge_id, "hive: rc:hive.purge_all with no supervisor");
        return;
    };
    // #2294 — kept, so that the goodbye exit that follows can finish it.
    REMOVAL_PURGES.track(tokio::spawn(async move { sup.purge_all(purge_id).await }));
}

/// #2294 — how long a goodbye exit waits for a removal purge: enough to stop
/// a run and delete what it held, not so long that a hung purge keeps a
/// removed daemon up for good.
pub const REMOVAL_PURGE_LIMIT: Duration = Duration::from_secs(300);

/// #2294 — the removal purges this daemon started ([`handle_purge_all`]).
static REMOVAL_PURGES: RemovalPurges = RemovalPurges::new();

/// #2294 — before a goodbye exit (`AgentDeleted`): finish the removal purges
/// this daemon started, up to `limit` in all. Two goodbyes end one:
/// - the removal's own, which follows `rc:hive.purge_all` on the same socket;
/// - the refusal of a reconnect, after a pod roll dropped the socket
///   mid-purge.
///
/// The exit is a `process::exit(7)`, so either would otherwise cut the purge
/// short. Nothing in flight is no wait. The build says it does this
/// (`hive-purge-drain`), which is what lets the server's kick tell a purged
/// device at all.
pub async fn finish_removal_purge(limit: Duration) {
    match REMOVAL_PURGES.finish(limit).await {
        (0, _) => {}
        (n, true) => {
            info!(
                purges = n,
                "hive: this device's removal purge finished before it stops"
            );
        }
        (n, false) => warn!(
            purges = n,
            limit_secs = limit.as_secs(),
            "hive: this device's removal purge did not finish in time; it stops anyway"
        ),
    }
}

/// The removal purges in flight, each the task [`Supervisor::purge_all`]
/// runs in. A registry of its own so its tests do not share the daemon's.
pub(crate) struct RemovalPurges(Mutex<Vec<tokio::task::JoinHandle<usize>>>);

impl RemovalPurges {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    pub(crate) fn track(&self, task: tokio::task::JoinHandle<usize>) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(task);
    }

    /// Wait for every tracked purge, up to `limit` in all: how many were in
    /// flight, and whether they all finished. What it gives up on keeps
    /// running until the process ends.
    pub(crate) async fn finish(&self, limit: Duration) -> (usize, bool) {
        let tasks = std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()));
        let n = tasks.len();
        let deadline = tokio::time::Instant::now() + limit;
        for task in tasks {
            if tokio::time::timeout_at(deadline, task).await.is_err() {
                return (n, false);
            }
        }
        (n, true)
    }
}

/// FR-90 P2g-3d — `rc:hive.retain`: what keeps each copy this device asked
/// about, kept for the sessions it holds, and the device's own clock run at
/// once ([`Supervisor::retain_heard`]). The primary enrollment's only, like
/// every Hive frame.
pub fn handle_retain(
    words: Vec<roomler_ai_remote_control::hive::HiveRetainWord>,
    is_primary: bool,
) {
    if !is_primary {
        warn!("hive: rc:hive.retain ignored — not the primary enrollment");
        return;
    }
    let Some(sup) = global() else {
        debug!("hive: rc:hive.retain with no supervisor");
        return;
    };
    tokio::spawn(async move { sup.retain_heard(words).await });
}

/// FR-90 P2e-2 — `rc:hive.lease`: the server's word, on `tx`, the connection
/// it came on, that this device holds `session_id` at `fence`
/// ([`Supervisor::take_lease`]). The primary enrollment's only, like every
/// Hive frame.
pub fn handle_lease(
    session_id: ObjectId,
    fence: u64,
    is_primary: bool,
    tx: mpsc::Sender<ClientMsg>,
) {
    if !is_primary {
        warn!(session = %session_id, "hive: rc:hive.lease ignored — not the primary enrollment");
        return;
    }
    match global() {
        Some(sup) => sup.take_lease(session_id, fence, &tx),
        None => debug!(session = %session_id, "hive: rc:hive.lease with no supervisor"),
    }
}

/// FR-90 P2e-4 — `rc:hive.drain`: the session's lease is about to leave this
/// device ([`Supervisor::begin_drain`]), answered with `rc:hive.drained` on
/// `tx`, the connection it came on. The primary enrollment's only, like
/// every Hive frame: a secondary org's is refused.
pub fn handle_drain(
    session_id: ObjectId,
    fence: u64,
    is_primary: bool,
    tx: mpsc::Sender<ClientMsg>,
) {
    drain_with(global(), session_id, fence, is_primary, tx);
}

/// [`handle_drain`] on `sup`, the daemon's supervisor when it has one.
fn drain_with(
    sup: Option<Arc<Supervisor>>,
    session_id: ObjectId,
    fence: u64,
    is_primary: bool,
    tx: mpsc::Sender<ClientMsg>,
) {
    // Taken up HERE, in the order the frames came: a word that comes right
    // behind the drain must reach the session after it, or it would lift
    // nothing and the drain would hold the session for ever.
    let begun = match sup {
        Some(sup) if is_primary => match sup.begin_drain(session_id, fence) {
            Ok(answer) => Ok((sup, answer)),
            Err(refused) => Err(refused),
        },
        Some(_) => Err((
            HiveDrainRefusal::Other,
            "agent sessions run only for this device's primary organization".into(),
        )),
        None => Err((
            HiveDrainRefusal::NotRunning,
            "agent sessions are not set up on this device".into(),
        )),
    };
    tokio::spawn(async move {
        let answer = match begun {
            Ok((sup, answer)) => sup.drained(session_id, fence, answer).await,
            Err((word, why)) => drained_refused(session_id, fence, word, &why),
        };
        let _ = tx.send(answer).await;
    });
}

/// FR-90 P2e-4 — `rc:hive.drained` saying no, and why.
fn drained_refused(
    session_id: ObjectId,
    fence: u64,
    word: HiveDrainRefusal,
    why: &str,
) -> ClientMsg {
    ClientMsg::HiveDrained {
        session_id,
        fence,
        seq: None,
        hash: None,
        refused: Some(word),
        detail: Some(why.to_string()),
    }
}

/// FR-90 P2e-1 — `rc:hive.demote`: the session's lease is at `fence` on
/// another device ([`Supervisor::demote`]). The primary enrollment's only,
/// like every Hive frame; from a task of its own, since the store's floor is
/// raised first.
pub fn handle_demote(session_id: ObjectId, fence: u64, reason: String, is_primary: bool) {
    if !is_primary {
        warn!(session = %session_id, "hive: rc:hive.demote ignored — not the primary enrollment");
        return;
    }
    match global() {
        Some(sup) => {
            tokio::spawn(async move { sup.demote(session_id, fence, &reason).await });
        }
        None => debug!(session = %session_id, "hive: rc:hive.demote with no supervisor"),
    }
}

/// The primary enrollment's control WS came up: send reports there from now
/// on, and replay the latest of each — a report sent into the socket that
/// just died never arrived.
pub fn on_connected(tx: mpsc::Sender<ClientMsg>) {
    if let Some(sup) = global() {
        sup.connected(tx);
    }
}

impl Supervisor {
    /// FR-90 P3-7-3c — the hub a session's own egress opens its flows on:
    /// where the vault is offered and the device's owner turned `hive_net`
    /// on, once the daemon built its primary hub. None otherwise, and then
    /// `net_socks` and `net_forward` are not offered.
    #[cfg(feature = "vault")]
    fn net_hub(&self, vault: bool) -> Option<crate::tunnel::client_mgr::TunnelClientHub> {
        if vault && self.cfg.net {
            crate::tunnel::client_mgr::primary()
        } else {
            None
        }
    }

    /// FR-90 P3-8-2b-2 — how a session runs one command on another device
    /// (`ssh_run`): where the vault is offered and the device's owner turned
    /// `hive_ssh` on. None otherwise, and then `ssh_run` is not offered.
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    fn ssh_runner(&self, vault: bool) -> Option<Arc<dyn super::ssh_tools::SshRunner>> {
        if vault && self.cfg.ssh {
            self.ssh_runner.clone()
        } else {
            None
        }
    }

    fn new(
        cfg: HiveConfig,
        runtime: PathBuf,
        launcher: Launcher,
        store: Result<StoreHandle, String>,
        hosted: Hosted,
    ) -> Self {
        let to_resume = hosted.sessions().to_vec();
        let adopted = adopt::AdoptedFile::load(adopt::adopted_path(hosted.path()), hosted.agent());
        Self {
            cfg,
            runtime,
            launcher,
            store,
            start_lock: tokio::sync::Mutex::new(()),
            live: Mutex::new(HashMap::new()),
            reports: Mutex::new(HashMap::new()),
            turns: Mutex::new(HashMap::new()),
            approval_frames: Mutex::new(HashMap::new()),
            reporter: Mutex::new(None),
            states: broadcast::channel(64).0,
            approvals: broadcast::channel(64).0,
            approval_timing: toolbelt::Timing::default(),
            viewers: Default::default(),
            sidecar_port: tokio::sync::OnceCell::new(),
            tokens: Default::default(),
            model_key: tokio::sync::Mutex::new(None),
            offline_since: Mutex::new(None),
            upstream: super::sidecar::DEFAULT_UPSTREAM.to_string(),
            offline_grace: super::sidecar::OFFLINE_GRACE,
            updating: std::sync::atomic::AtomicBool::new(false),
            hosted: Mutex::new(hosted),
            to_resume: Mutex::new(to_resume),
            resumed: tokio::sync::OnceCell::new(),
            going_down: AtomicBool::new(false),
            memory: Mutex::new(HashMap::new()),
            moves: Mutex::new(HashMap::new()),
            teleports: Mutex::new(HashMap::new()),
            #[cfg(all(test, unix))]
            test_workplaces: Mutex::new(HashMap::new()),
            agent_id: None,
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            ssh_runner: None,
            adopted: Mutex::new(adopted),
            adopt_offers: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
            replica_events: tokio::sync::Semaphore::new(stream::EVENT_BUDGET),
            replica_blobs: tokio::sync::Semaphore::new(stream::BLOB_BUDGET),
            follows: Mutex::new(follow::Follows::default()),
            lease_words: Mutex::new(HashMap::new()),
            lease_heard: tokio::sync::Notify::new(),
            awaiting_word: Mutex::new(HashMap::new()),
            lease_wait: LEASE_WAIT,
            drain_timing: DrainTiming::default(),
            #[cfg(test)]
            derp_for_tests: Mutex::new(None),
            #[cfg(any(test, all(unix, feature = "hive-test-launcher")))]
            checkpoint_runner: None,
            #[cfg(test)]
            follow_at_connect: true,
        }
    }

    /// P2b-3b — how this daemon's sessions take their checkpoints.
    fn checkpoint_runner(&self) -> super::checkpointer::Runner {
        #[cfg(any(test, all(unix, feature = "hive-test-launcher")))]
        if let Some(run) = &self.checkpoint_runner {
            return run.clone();
        }
        super::checkpointer::Runner::Subprocess
    }

    /// P1e — keep a session's core memory for its start's launch. A document
    /// larger than any snapshot the server renders is no snapshot: dropped,
    /// and said so.
    pub(crate) fn receive_memory(&self, m: CoreMemory) {
        use roomler_ai_remote_control::hive::hive_limits::MAX_CORE_MEMORY_BYTES;
        let too_big = [&m.claude_md, &m.memory_md]
            .iter()
            .any(|d| d.as_ref().is_some_and(|s| s.len() > MAX_CORE_MEMORY_BYTES));
        if too_big {
            warn!(session = %m.session_id, "hive: core memory larger than any snapshot — dropped");
            return;
        }
        let mut pending = self.memory.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, (_, at)| at.elapsed() < MEMORY_WAIT);
        if pending.len() >= MEMORY_PENDING
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(k, _)| *k)
        {
            pending.remove(&oldest);
        }
        debug!(session = %m.session_id, rev = m.brain_rev, "hive: core memory received");
        pending.insert((m.session_id, m.fence), (m, Instant::now()));
    }

    /// P2e-5 — keep a session's move for its start at that fence.
    pub(crate) fn receive_move(&self, m: Moved) {
        let mut pending = self.moves.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, (_, at)| at.elapsed() < MOVE_WAIT);
        if pending.len() >= MOVE_PENDING
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(k, _)| *k)
        {
            pending.remove(&oldest);
        }
        info!(
            session = %m.session_id, fence = m.fence, turns = m.turns, from = %m.from_device_id,
            "hive: the session moves here"
        );
        pending.insert((m.session_id, m.fence), (m, Instant::now()));
    }

    /// P2e-5 — the move that came for this start, if one did: kept until the
    /// launch, so a start refused before it still finds it when re-sent.
    fn kept_move(&self, session: ObjectId, fence: u64) -> Option<Moved> {
        self.moves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(session, fence))
            .filter(|(_, at)| at.elapsed() < MOVE_WAIT)
            .map(|(m, _)| m.clone())
    }

    /// P2e-5c — whether a move of `session` is kept here, at any fence: the
    /// session moves to this device, and its start is on its way or being
    /// taken.
    fn moving_here(&self, session: ObjectId) -> bool {
        self.moves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|((s, _), (_, at))| *s == session && at.elapsed() < MOVE_WAIT)
    }

    /// P2e-5 — the start it came for launched.
    fn forget_move(&self, session: ObjectId, fence: u64) {
        self.moves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(session, fence));
    }

    /// P2e-5 — whether `m` brings the session from another device, whose
    /// state this one does not hold. A move back is the session coming back
    /// where its state is: the drain checkpointed it there, and nothing ran
    /// after. A device that does not know its own id puts the copy in place.
    fn moved_from_elsewhere(&self, m: &Moved) -> bool {
        self.agent_id != Some(m.from_device_id)
    }

    /// P2f-1a — a teleport's prepare passed for `session`, naming the start's
    /// `fence`: its join is admitted for [`TELEPORT_ADMISSION`]. A later
    /// prepare of the same session replaces it; past
    /// [`TELEPORTS_PENDING`], the oldest goes.
    fn admit_teleport(&self, order: &StartOrder, have_want: Option<(String, PathBuf)>) {
        let (session, fence) = (order.session_id, order.fence);
        let mut held = self.teleports.lock().unwrap_or_else(|e| e.into_inner());
        held.retain(|_, p| p.at.elapsed() < TELEPORT_ADMISSION);
        if held.len() >= TELEPORTS_PENDING
            && !held.contains_key(&session)
            && let Some(oldest) = held.iter().min_by_key(|(_, p)| p.at).map(|(s, _)| *s)
        {
            held.remove(&oldest);
        }
        info!(
            session = %session, fence, have_want = have_want.is_some(),
            "hive: prepared for a teleport — its join is admitted"
        );
        held.insert(
            session,
            Prepared {
                order: order.clone(),
                at: Instant::now(),
                have_want,
            },
        );
    }

    /// P2f-2b — where a session live here runs, and as whom: what a member's
    /// `want_pack` is packed from. `None` when it does not run here now.
    pub(super) fn workplace(&self, session: ObjectId) -> Option<Arc<super::packer::Workplace>> {
        let live = self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session)
            .map(|l| Arc::clone(&l.workplace));
        #[cfg(all(test, unix))]
        let live = live.or_else(|| {
            self.test_workplaces
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&session)
                .cloned()
        });
        live
    }

    /// Test-only: `session` served from `workplace` as if it ran here.
    #[cfg(all(test, unix))]
    pub(super) fn workplace_for_tests(
        &self,
        session: ObjectId,
        workplace: super::packer::Workplace,
    ) {
        self.test_workplaces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session, Arc::new(workplace));
    }

    /// P2f-2b — where a teleport this device was prepared for runs its
    /// session, when the server let the copy's workspace come against what
    /// its folder's repository holds: the order, the account and the folder.
    /// `None` without such an admission, or past its time.
    pub(super) fn have_want_place(
        &self,
        session: ObjectId,
    ) -> Option<(StartOrder, String, PathBuf)> {
        let held = self.teleports.lock().unwrap_or_else(|e| e.into_inner());
        let p = held
            .get(&session)
            .filter(|p| p.at.elapsed() < TELEPORT_ADMISSION)?;
        let (account, folder) = p.have_want.clone()?;
        Some((p.order.clone(), account, folder))
    }

    /// P2f-1a — whether a join of `session` at `fence` in the teleport's role
    /// follows a teleport's prepare that passed here: one that named the
    /// start's fence, one past the join's (the record's fence, before the
    /// move), within [`TELEPORT_ADMISSION`]. A join nobody prepared this
    /// device for is no teleport's: whether it may RUN the session is the
    /// prepare's to ask.
    fn teleport_admitted(&self, session: ObjectId, fence: u64) -> bool {
        self.teleports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session)
            .is_some_and(|p| {
                fence.checked_add(1) == Some(p.order.fence) && p.at.elapsed() < TELEPORT_ADMISSION
            })
    }

    /// P2f-1a — whether this device is prepared for a teleport now: it holds
    /// that copy to tell the server about, whatever its owner's
    /// `hive_replica` says ([`Self::reports_copies`]).
    fn prepared_for_teleport(&self) -> bool {
        self.teleports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|p| p.at.elapsed() < TELEPORT_ADMISSION)
    }

    /// P2f-1a — the session launched here at `fence`: a teleport prepared at
    /// that fence or before is done with.
    fn forget_teleport(&self, session: ObjectId, fence: u64) {
        let mut held = self.teleports.lock().unwrap_or_else(|e| e.into_inner());
        if held.get(&session).is_some_and(|p| p.order.fence <= fence) {
            held.remove(&session);
        }
    }

    /// P1e — the core memory that came for this start, once.
    fn take_memory(&self, session: ObjectId, fence: u64) -> Option<CoreMemory> {
        self.memory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(session, fence))
            .map(|(m, _)| m)
    }

    /// Sessions running now.
    pub fn live_count(&self) -> usize {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// P1d-1 (AC7) — the sessions mid-turn now: running, or waiting for an
    /// approval (a person answering is part of the turn).
    pub(crate) fn turns_running(&self) -> Vec<ObjectId> {
        let live: Vec<ObjectId> = self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect();
        let reports = self.reports.lock().unwrap_or_else(|e| e.into_inner());
        live.into_iter()
            .filter(|sid| {
                matches!(
                    reports.get(sid).map(|r| r.state),
                    Some(HiveRunState::Running | HiveRunState::AwaitingApproval)
                )
            })
            .collect()
    }

    pub(crate) fn update_wait(&self) -> Duration {
        self.cfg.update_wait
    }

    /// P1d-1 — the update is going ahead: refuse new prompts and starts
    /// until it has, or [`Self::end_update`] says it did not. A prompt
    /// already admitted still runs; the updater waits for it.
    pub(crate) fn begin_update(&self) {
        self.updating
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn end_update(&self) {
        self.updating
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn updating(&self) -> bool {
        self.updating.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) async fn start(self: &Arc<Self>, order: StartOrder, is_primary: bool) -> Answer {
        let session = order.session_id;
        let answer = {
            let _serial = self.start_lock.lock().await;
            self.start_locked(order, is_primary).await
        };
        // P2g-3d — a session this device runs now: what keeps its copy.
        if answer.refused.is_none() && is_primary {
            self.ask_retain(vec![session]);
        }
        answer
    }

    /// [`Self::start`], under `start_lock`.
    async fn start_locked(self: &Arc<Self>, order: StartOrder, is_primary: bool) -> Answer {
        let answer = self.decide_and_launch(&order, is_primary).await;
        match &answer.refused {
            None => info!(
                session = %order.session_id, account = ?answer.account, caller = %order.caller,
                "hive: session started"
            ),
            Some(r) => {
                info!(
                    session = %order.session_id, refused = r.as_str(), detail = ?answer.detail,
                    caller = %order.caller, "hive: session start refused"
                );
                // P1d-2 — a session refused here does not run here: nothing
                // of it is left to resume.
                if !self.holds_live(order.session_id) {
                    self.hosted_forget(order.session_id, order.fence);
                }
            }
        }
        answer
    }

    async fn decide_and_launch(self: &Arc<Self>, order: &StartOrder, is_primary: bool) -> Answer {
        if !is_primary {
            return Answer::refused(
                HiveRefusal::HiveDisabled,
                "agent sessions run only for this device's primary organization",
            );
        }
        if !self.cfg.enabled {
            return Answer::refused(
                HiveRefusal::HiveDisabled,
                "agent sessions are off on this device (hive_enabled)",
            );
        }
        if order.harness != HARNESS_CLAUDE_CODE {
            return Answer::refused(
                HiveRefusal::Other,
                format!("unknown harness {:?}", order.harness),
            );
        }
        // P2g-1 — a session purged here never comes back: removal is final.
        // Read under the start lock, which a purge holds for all its steps.
        if let Ok(store) = &self.store {
            match store.is_purged(&order.session_id.to_hex()).await {
                Ok(false) => {}
                Ok(true) => {
                    return Answer::refused(
                        HiveRefusal::Other,
                        "this session was purged from this device",
                    );
                }
                Err(e) => {
                    return Answer::refused(
                        HiveRefusal::Other,
                        format!(
                            "this device's store could not say whether the session was purged: {e}"
                        ),
                    );
                }
            }
        }
        // P2f-3a — a fork stays one: a start that does not say so takes what
        // this device hosts of it at this fence, so its checkpoints never
        // drop the parent's history.
        let adopted;
        let order = match self
            .hosted_get(order.session_id)
            .filter(|h| h.fence == order.fence && order.fork_of.is_none())
            .and_then(|h| h.fork_of)
        {
            Some(fork_of) => {
                adopted = StartOrder {
                    fork_of: Some(fork_of),
                    ..order.clone()
                };
                &adopted
            }
            None => order,
        };
        // P2f-3a — a fork names another session, by ids its names can hold.
        if let Some(parent) = &order.fork_of
            && (parent.session_id == order.session_id
                || roomler_hive_node::checkpoint::allowlist_of(
                    &order.harness_session,
                    Some(&parent.harness_session),
                )
                .is_err())
        {
            return Answer::refused(
                HiveRefusal::Other,
                "a fork must be made from another session, named by its ids",
            );
        }
        // P2f-4a — a session started from a terminal's history is that
        // terminal's, never a fork of another.
        if order.from_terminal && order.fork_of.is_some() {
            return Answer::refused(
                HiveRefusal::Other,
                "a start takes a terminal's history or forks a session, never both",
            );
        }
        // Idempotent on session + fence: the start may be a re-send of one
        // whose answer was lost.
        if let Some(account) = self.running(order.session_id, order.fence) {
            return Answer::accepted(&account);
        }
        // P2e-1 — the lease is a fence. A start older than the run here is a
        // stale frame; a newer one means that run belongs to the past, and it
        // stops before anything else is decided: whatever the gates below
        // say, the server has moved on from it. Two harnesses never run on
        // one history (§3d), so nothing launches until it has let go.
        if let Some((held, fenced)) = self.live_fence(order.session_id) {
            if held > order.fence {
                return Answer::refused(
                    HiveRefusal::Other,
                    format!("this device runs the session at a newer fence ({held})"),
                );
            }
            // The run at this very fence was fenced out by a newer one's
            // word: a start for it is as stale.
            if fenced && held == order.fence {
                return Answer::refused(
                    HiveRefusal::Other,
                    format!("a newer fence took the session from this device (fence {held})"),
                );
            }
            if let Err(e) = self
                .supersede(order.session_id, order.fence, "superseded")
                .await
            {
                return Answer::refused(HiveRefusal::LaunchFailed, e);
            }
        }
        // P2e-2 — a start supersedes a resume held back for the server's word:
        // at its own fence the start IS the word, and launches the session
        // itself; at a newer one, the held-back run belongs to the past.
        {
            let mut held_back = self.awaiting_word.lock().unwrap_or_else(|e| e.into_inner());
            if held_back
                .get(&order.session_id)
                .is_some_and(|h| h.fence <= order.fence)
            {
                held_back.remove(&order.session_id);
            }
        }
        // P1d-1 — the daemon is about to restart for an update: a session
        // launched now would be cut at once.
        if self.updating() {
            return Answer::refused(
                HiveRefusal::Other,
                "this device is about to restart for an update — start the session again in a minute",
            );
        }
        // P1d-2 — or stopping, for any reason.
        if self.going_down() {
            return Answer::refused(
                HiveRefusal::Other,
                "this device is restarting — start the session again in a minute",
            );
        }
        let account = match gates::account_for(&self.cfg, &order.user_id, &order.user_email) {
            Ok(a) => a,
            Err(r) => {
                return Answer::refused(r, "no hive_accounts entry maps you to a local account");
            }
        };
        // P1d-2 — a session this device hosted resumes as the account it ran
        // as, or not at all: its history is in that account's home, and a
        // remapped starter must not carry it into another.
        if let Some(ran_as) = self
            .hosted_get(order.session_id)
            .filter(|h| h.fence == order.fence)
            .map(|h| h.account)
            && ran_as != account
        {
            return Answer::refused(
                HiveRefusal::NoAccount,
                format!(
                    "hive_accounts now maps the starter to {account}, and the session ran as \
                     {ran_as}, whose home holds its history"
                ),
            );
        }
        let folder = match gates::folder_for(&self.cfg, &order.folder) {
            Ok(f) => f,
            Err(r) => {
                return Answer::refused(
                    r,
                    "the folder does not exist or is outside this device's hive_roots",
                );
            }
        };
        if self.live_count() >= self.cfg.max_sessions {
            return Answer::refused(
                HiveRefusal::AtCapacity,
                format!(
                    "this device already runs {} agent sessions (hive_max_sessions)",
                    self.cfg.max_sessions
                ),
            );
        }
        let store = match &self.store {
            Ok(s) => s.clone(),
            Err(e) => return Answer::refused(HiveRefusal::LaunchFailed, e.clone()),
        };
        // Decision 15 — on a Mac, an account whose `sudo` needs no password
        // gives its session root, whatever groups the session drops.
        if matches!(self.launcher, Launcher::AsMappedAccount)
            && let Err((r, detail)) =
                super::sudo::gate(&account, self.cfg.allow_passwordless_sudo).await
        {
            return Answer::refused(r, detail);
        }
        // P0e — with a model credential configured, the harness reaches the
        // provider only through the loopback sidecar, with a session token;
        // the key itself never enters the session.
        let sidecar = if self.cfg.api_key_helper.is_some() {
            match self.sidecar_port().await {
                Ok(port) => Some(port),
                Err(e) => return Answer::refused(HiveRefusal::LaunchFailed, e),
            }
        } else {
            None
        };
        // P2e-5 — a start the record moved here: it counts on from the
        // session's turns, and the session is taken over from its copy first
        // — unless this device hosts it at this fence already (a restart: its
        // state is here).
        let moved = self.kept_move(order.session_id, order.fence).filter(|_| {
            self.hosted_get(order.session_id)
                .is_none_or(|h| h.fence != order.fence)
        });
        let taken_over;
        let order = match &moved {
            Some(m) => {
                if let Err(why) = self.take_over(order, m, &account, &folder, &store).await {
                    warn!(session = %order.session_id, fence = order.fence, %why, "hive: the moved session was not taken over — its start is refused");
                    return Answer::refused(
                        HiveRefusal::LaunchFailed,
                        "this device could not take the session over from its copy \
                         (its log says why)",
                    );
                }
                // The history decides `--resume` or `--session-id`: a session
                // moved before its first prompt has none.
                taken_over = StartOrder {
                    resume: false,
                    ..order.clone()
                };
                &taken_over
            }
            None => order,
        };
        // P2f-3a — a fork: at its first start here, put in place from its
        // parent's copy; and told it is one at each launch that starts it
        // from the parent's history, until it has a history of its own.
        let fork_note = match &order.fork_of {
            Some(parent) => {
                let first = moved.is_none()
                    && self
                        .hosted_get(order.session_id)
                        .is_none_or(|h| h.fence != order.fence);
                match self
                    .fork_in_place(order, parent, &account, &folder, &store, first)
                    .await
                {
                    Ok(note) => note,
                    Err(refused) => return refused,
                }
            }
            None => None,
        };
        // P2f-4a — a terminal session this device adopted, made a managed
        // one: at its first start here, its terminal's own history put in
        // place as the account it ran as, and the session told so.
        let imported = if order.from_terminal {
            match self
                .terminal_in_place(order, &account, &folder, &store)
                .await
            {
                Ok(imported) => imported,
                Err(refused) => return refused,
            }
        } else {
            None
        };
        // P2e-7 — a session from another device is told it moved, once: the
        // note goes to the harness through its `SessionStart` hook.
        let moved_note = match &moved {
            Some(m) if self.moved_from_elsewhere(m) => {
                let open = last_open_call(&store, &order.session_id.to_hex()).await;
                let from = resume_note::Provenance {
                    by: &m.moved_by_name,
                    at_ms: m.moved_at_ms,
                    from_device: &m.from_device_name,
                    from_folder: &m.from_folder,
                    earlier: &m.earlier,
                };
                Some(resume_note::compose(&from, &folder, open.as_deref()))
            }
            _ => None,
        };
        let (terminal_note, terminal_turns) = match imported {
            Some(i) => (Some(i.note), Some(i.turns)),
            None => (None, None),
        };
        let note = [fork_note, terminal_note, moved_note]
            .into_iter()
            .flatten()
            .reduce(|mut all, next| {
                all.push_str(&next);
                all
            });
        match self.launch(
            order,
            &account,
            &folder,
            store,
            sidecar,
            moved.as_ref(),
            note.as_deref(),
            terminal_turns,
        ) {
            Ok(()) => {
                if moved.is_some() {
                    self.forget_move(order.session_id, order.fence);
                }
                self.forget_teleport(order.session_id, order.fence);
                // P2f-4a — a managed session now, served as any session is.
                if order.from_terminal {
                    self.made_managed(order.session_id);
                }
                Answer::accepted(&account)
            }
            Err((r, detail)) => Answer::refused(r, detail),
        }
    }

    /// P2e-5 — take over a session the record moved here. From another
    /// device, its copy as this device's store holds it is put in place
    /// first ([`Self::put_copy_in_place`]); on a move back its state is here
    /// already. Either way a session that has had turns must find its
    /// history: without it, Claude Code would start the conversation afresh,
    /// silently. `Err` says why, for this device's log.
    async fn take_over(
        &self,
        order: &StartOrder,
        m: &Moved,
        account: &str,
        folder: &Path,
        store: &StoreHandle,
    ) -> Result<(), String> {
        let (who, dest) = self.copy_place(order, account, folder)?;
        if self.moved_from_elsewhere(m) {
            self.put_copy_in_place(order, &who, &dest, store).await?;
        }
        // The daemon only looks at the entry, never reads it (P1d-2).
        let history = history_path_in(&dest.config_dir, &order.harness_session);
        if m.turns > 0 && std::fs::symlink_metadata(&history).is_err() {
            return Err(format!(
                "the session has had {} turns, and no history of them is here",
                m.turns
            ));
        }
        Ok(())
    }

    /// P2e-5 — a session moved here from another device: its copy, as this
    /// device's store holds it, put in place AS THE ACCOUNT before the
    /// harness resumes it — the config directory's files, and the folder
    /// through the account's own git ([`materializer`]) — and the folder held
    /// to the copy's tree. `Err` says why, for this device's log: what it
    /// names may be the account's own files, which never reach the server.
    async fn put_copy_in_place(
        &self,
        order: &StartOrder,
        who: &materializer::Who,
        dest: &materializer::Dest,
        store: &StoreHandle,
    ) -> Result<(), String> {
        let sid = order.session_id.to_hex();
        let chain = chain_of(store, &sid).await?;
        let Some(last) = chain.last() else {
            return Err("this device's copy holds no checkpoint".into());
        };
        let blobs = materializer::Blobs::Store {
            store,
            session: &sid,
        };
        let done =
            materializer::materialize(&self.checkpoint_runner(), who, &chain, dest, &blobs).await?;
        held_to_tree(last, &done)?;
        info!(
            session = %order.session_id, fence = order.fence, checkpoint = last.n,
            files = done.files, removed = done.removed,
            "hive: the moved session's copy is in place"
        );
        Ok(())
    }

    /// P2f-3a — a fork's state here before it launches. At its first start
    /// here (`first`: it was not moved here, nor is it hosted here at this
    /// fence), with nothing of it on this device yet, its folder is asked as
    /// a teleport's is, and its parent's copy is put in place under its ids
    /// ([`Self::put_fork_in_place`]). `Ok(Some(note))` when the launch starts
    /// it from the parent's history: what it is told then. `Ok(None)` once it
    /// has a history of its own.
    async fn fork_in_place(
        &self,
        order: &StartOrder,
        parent: &HiveForkOf,
        account: &str,
        folder: &Path,
        store: &StoreHandle,
        first: bool,
    ) -> Result<Option<String>, Answer> {
        let (who, dest) = self.copy_place(order, account, folder).map_err(|e| {
            warn!(session = %order.session_id, %e, "hive: where the fork goes is not known — its start is refused");
            Answer::refused(
                HiveRefusal::LaunchFailed,
                "this device could not tell where the fork goes (its log says why)",
            )
        })?;
        // The daemon only looks at the entries, never reads them (P1d-2).
        let here = |p: PathBuf| std::fs::symlink_metadata(p).is_ok();
        if here(history_path_in(&dest.config_dir, &order.harness_session)) {
            return Ok(None);
        }
        let from = parent_history_in(
            &dest.config_dir,
            &order.harness_session,
            &parent.harness_session,
        );
        if first && !here(from) {
            // P2f-3d — never into the folder its parent runs in here: two
            // harnesses would work one folder. The server compares the folder
            // only as typed (`same_folder`), and a clean repository passes the
            // folder's own question below. Both paths are resolved.
            if self
                .workplace(parent.session_id)
                .is_some_and(|w| w.folder == folder)
            {
                let why = "the session it forks runs in this folder".to_string();
                return Err(self.folder_taken(order, folder, why, "fork"));
            }
            if let Some(refused) = self.folder_refusal(order, account, "fork").await {
                return Err(refused);
            }
            self.put_fork_in_place(order, parent, &who, &dest, store)
                .await
                .map_err(|(r, detail)| Answer::refused(r, detail))?;
        }
        let project = dest
            .config_dir
            .join("projects")
            .join(format!("hive-{}", order.harness_session));
        let saved = here(project.join(&parent.harness_session).join("tool-results"))
            .then_some((parent.harness_session.as_str(), project.as_path()));
        let from = parent_folder(store, &parent.session_id.to_hex()).await;
        Ok(Some(resume_note::compose_fork(
            from.as_deref(),
            folder,
            saved,
        )))
    }

    /// P2f-3a — a fork's first start here: the last checkpoint of the
    /// session it is made from, as this device's copy holds it, put in place
    /// AS THE ACCOUNT under the fork's ids ([`materializer::forked`]): the
    /// parent's history, sub-agent transcripts and tool results under the
    /// fork's project name, the memory and `CLAUDE.md`, and the folder
    /// through the account's own git under the fork's refs. That checkpoint
    /// is where the fork is made; the server's half sees to this device's
    /// copy being current. Nothing to make it from is refused in words for
    /// the server; a failure to put it in place is said in this device's log,
    /// where what it names (the account's own files) stays.
    async fn put_fork_in_place(
        &self,
        order: &StartOrder,
        parent: &HiveForkOf,
        who: &materializer::Who,
        dest: &materializer::Dest,
        store: &StoreHandle,
    ) -> Result<(), (HiveRefusal, String)> {
        let psid = parent.session_id.to_hex();
        let failed = |why: String| {
            warn!(session = %order.session_id, parent = %psid, %why, "hive: the fork's copy was not put in place — its start is refused");
            (
                HiveRefusal::LaunchFailed,
                "this device could not put the fork's copy in place (its log says why)".to_string(),
            )
        };
        let chain = chain_of(store, &psid).await.map_err(failed)?;
        let Some(last) = chain.last() else {
            return Err((
                HiveRefusal::Other,
                "this device holds no copy of the session the fork is made from".to_string(),
            ));
        };
        let history = format!("projects/hive-{0}/{0}.jsonl", parent.harness_session);
        if !last.files.iter().any(|f| f.path == history) {
            return Err((
                HiveRefusal::Other,
                "the session the fork is made from has no conversation to fork yet".to_string(),
            ));
        }
        let moved = materializer::forked(&chain, &parent.harness_session, &order.harness_session)
            .map_err(failed)?;
        let blobs = materializer::Blobs::Store {
            store,
            session: &psid,
        };
        let done = materializer::materialize(&self.checkpoint_runner(), who, &moved, dest, &blobs)
            .await
            .map_err(failed)?;
        held_to_tree(last, &done).map_err(failed)?;
        info!(
            session = %order.session_id, fence = order.fence, parent = %psid,
            checkpoint = last.n, turn = last.turn, files = done.files, removed = done.removed,
            "hive: the fork's copy is in place, made from its parent's"
        );
        Ok(())
    }

    /// P2e-5 — where on this device a session's copy goes, and as whom: the
    /// places its harness runs from ([`Self::spawn`]'s), as its account.
    #[cfg(unix)]
    fn copy_place(
        &self,
        order: &StartOrder,
        account: &str,
        folder: &Path,
    ) -> Result<(materializer::Who, materializer::Dest), String> {
        let (home, who) = self.home_and_who(account)?;
        Ok((who, copy_dest(order, &home, folder)))
    }

    /// P2f-2c — whom `account` runs as on this device, as a start resolves
    /// it ([`Self::copy_place`]): what a pack for a member is made as once
    /// the session does not run here.
    #[cfg(unix)]
    pub(super) fn who_for(&self, account: &str) -> Result<materializer::Who, String> {
        self.home_and_who(account).map(|(_, who)| who)
    }

    /// The account's home, and whom it runs as, with that home's
    /// environment.
    #[cfg(unix)]
    fn home_and_who(&self, account: &str) -> Result<(PathBuf, materializer::Who), String> {
        let (home, as_account) = match &self.launcher {
            Launcher::AsMappedAccount => (
                crate::exec::account_home(account)?,
                Some(account.to_string()),
            ),
            #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
            Launcher::AsDaemon { home } => (home.clone(), None),
        };
        let path = harness_path(&home);
        let who = materializer::Who {
            account: as_account,
            env: unix_base_env(&home, account, Some(&path)),
        };
        Ok((home, who))
    }

    /// P2e-5 — on Windows, as the console user, whom `hive_accounts` must map
    /// the starter to, as for a start.
    #[cfg(windows)]
    fn copy_place(
        &self,
        order: &StartOrder,
        account: &str,
        folder: &Path,
    ) -> Result<(materializer::Who, materializer::Dest), String> {
        let console = crate::hive_win::console_user().map_err(|(_, e)| e)?;
        crate::hive_win::check_mapping(account, &console).map_err(|(_, e)| e)?;
        Ok((
            materializer::Who {
                account: Some(account.to_string()),
                env: Vec::new(),
            },
            copy_dest(order, &console.profile, folder),
        ))
    }

    /// P2f-2c — on Windows, as the console user `account` must map to: with
    /// nobody signed in, there is nobody to make a pack as.
    #[cfg(windows)]
    pub(super) fn who_for(&self, account: &str) -> Result<materializer::Who, String> {
        let console = crate::hive_win::console_user().map_err(|(_, e)| e)?;
        crate::hive_win::check_mapping(account, &console).map_err(|(_, e)| e)?;
        Ok(materializer::Who {
            account: Some(account.to_string()),
            env: Vec::new(),
        })
    }

    /// P2e-6a — [`Self::prepare`]'s answer, and when ready, where this
    /// device's copy of the session ends: what `rc:hive.prepare_ack` carries.
    /// A promotion away from an unreachable primary moves the lease to that
    /// tip, so it is read here, at the answer, never from an older report.
    pub(crate) async fn prepare_with_tip(
        self: &Arc<Self>,
        order: &StartOrder,
        is_primary: bool,
    ) -> (Answer, Option<roomler_ai_remote_control::hive::HiveCopyTip>) {
        let answer = self.prepare(order, is_primary).await;
        let tip = if answer.refused.is_none() {
            self.copy_tip(order.session_id).await
        } else {
            None
        };
        (answer, tip)
    }

    /// P2e-5 — `rc:hive.prepare`: could this device take the session over at
    /// `order.fence`? Every gate a start passes, as the device is configured
    /// now, and none of a start's side effects: nothing is stopped, nothing
    /// launched, no word kept. And the copy: this device holds the session's
    /// checkpoints, which a moved start is put in place from.
    pub(crate) async fn prepare(self: &Arc<Self>, order: &StartOrder, is_primary: bool) -> Answer {
        self.prepare_as(order, is_primary, false).await
    }

    /// FR-90 P2f-1a — `rc:hive.prepare` with `teleport`: could this device
    /// run the session at `order.fence`, once it holds the copy it takes
    /// next? Every gate [`Self::prepare`] applies but the copy. One that
    /// passes admits that session's join in the teleport's role for
    /// [`TELEPORT_ADMISSION`] ([`Self::teleport_admitted`]), whatever the
    /// owner's `hive_replica`: the gates that let a device RUN a session are
    /// these, and a device that runs it holds its copy anyway. P2f-2b — with
    /// `have_want`, the admission keeps the account and folder they passed,
    /// for the copy's workspace to come against that folder's repository.
    pub(crate) async fn prepare_teleport(
        self: &Arc<Self>,
        order: &StartOrder,
        is_primary: bool,
        have_want: bool,
    ) -> Answer {
        let answer = self.prepare_as(order, is_primary, true).await;
        if answer.refused.is_none() {
            // P2f-2d — a folder that holds work of its own is refused now,
            // before anything moves: the moved start would refuse it after
            // the lease moved.
            if let Some(account) = answer.account.as_deref()
                && let Some(refused) = self.folder_refusal(order, account, "teleport").await
            {
                return refused;
            }
            // P2f-2b — the account and folder the gates just passed, as the
            // start resolves them, kept for the copy's have and want.
            let place = answer
                .account
                .clone()
                .zip(gates::folder_for(&self.cfg, &order.folder).ok())
                .filter(|_| have_want);
            self.admit_teleport(order, place);
        }
        answer
    }

    /// P2f-2d — a teleport's folder asked, as the account, whether the copy
    /// may be put there: `None` when it may; else the refusal, which names a
    /// sibling folder for the person to make and teleport into instead, when
    /// it would be under `hive_roots`. Nothing is made for them. A folder that
    /// cannot be asked about is refused too, in words: the moved start would
    /// ask the same git. P2f-3a — and a fork's, at its first start: `what`
    /// names which, for the person.
    async fn folder_refusal(
        &self,
        order: &StartOrder,
        account: &str,
        what: &str,
    ) -> Option<Answer> {
        // The gates passed: it resolves.
        let folder = gates::folder_for(&self.cfg, &order.folder).ok()?;
        let (who, dest) = match self.copy_place(order, account, &folder) {
            Ok(place) => place,
            Err(e) => {
                return Some(Answer::refused(
                    HiveRefusal::Other,
                    format!("the folder could not be asked about: {e}"),
                ));
            }
        };
        let req = super::packer::Request {
            v: super::packer::REQUEST_V,
            folder: dest.folder.clone(),
            state_dir: dest.state_dir.clone(),
            ask: super::packer::Ask::Clean {
                sid: order.session_id.to_hex(),
            },
        };
        let why = match super::packer::ask(&self.checkpoint_runner(), &who, &req).await {
            Ok(super::packer::Answer::Clean { dirty: None }) => return None,
            Ok(super::packer::Answer::Clean { dirty: Some(why) }) => why,
            Ok(_) => "an answer to another question".to_string(),
            Err(e) => {
                return Some(Answer::refused(
                    HiveRefusal::Other,
                    format!("the folder could not be read as the account: {e}"),
                ));
            }
        };
        Some(self.folder_taken(order, &dest.folder, why, what))
    }

    /// P2f-2d — `folder` may not take `order`'s copy, for `why`: refused
    /// `folder_dirty`, naming a sibling folder for the person to make and
    /// `what` into instead, when it would be under `hive_roots`. A folder
    /// must be there to pass the gates, so the sibling is named, never made:
    /// allowed once made when its parent is. P2f-3d — a fork into the folder
    /// its parent runs in here says so the same way.
    fn folder_taken(&self, order: &StartOrder, folder: &Path, why: String, what: &str) -> Answer {
        let sibling = sibling_for(folder, order.session_id).filter(|s| {
            s.parent()
                .is_some_and(|p| gates::folder_for(&self.cfg, &p.display().to_string()).is_ok())
        });
        let detail = match sibling {
            Some(s) => format!(
                "{why}; make a sibling, e.g. `git worktree add {}`, and {what} there",
                s.display()
            ),
            None => why,
        };
        info!(session = %order.session_id, folder = %folder.display(), %detail, "hive: a {what} refused: its folder holds work of its own");
        Answer::refused(HiveRefusal::FolderDirty, detail)
    }

    /// [`Self::prepare`], and for a teleport ([`Self::prepare_teleport`])
    /// without the copy: it is still to come.
    async fn prepare_as(
        self: &Arc<Self>,
        order: &StartOrder,
        is_primary: bool,
        teleport: bool,
    ) -> Answer {
        if !is_primary {
            return Answer::refused(
                HiveRefusal::HiveDisabled,
                "agent sessions run only for this device's primary organization",
            );
        }
        if !self.cfg.enabled {
            return Answer::refused(
                HiveRefusal::HiveDisabled,
                "agent sessions are off on this device (hive_enabled)",
            );
        }
        if order.harness != HARNESS_CLAUDE_CODE {
            return Answer::refused(
                HiveRefusal::Other,
                format!("unknown harness {:?}", order.harness),
            );
        }
        if let Some(account) = self.running(order.session_id, order.fence) {
            return Answer::accepted(&account);
        }
        if let Some((held, _)) = self.live_fence(order.session_id)
            && held >= order.fence
        {
            return Answer::refused(
                HiveRefusal::Other,
                format!("this device runs the session at fence {held}"),
            );
        }
        if self.updating() {
            return Answer::refused(
                HiveRefusal::Other,
                "this device is about to restart for an update — ask again in a minute",
            );
        }
        if self.going_down() {
            return Answer::refused(
                HiveRefusal::Other,
                "this device is restarting — ask again in a minute",
            );
        }
        let account = match gates::account_for(&self.cfg, &order.user_id, &order.user_email) {
            Ok(a) => a,
            Err(r) => {
                return Answer::refused(r, "no hive_accounts entry maps you to a local account");
            }
        };
        if let Err(r) = gates::folder_for(&self.cfg, &order.folder) {
            return Answer::refused(
                r,
                "the folder does not exist or is outside this device's hive_roots",
            );
        }
        // A run of it here at an older fence gives its place up to the start.
        let others = self.live_count() - usize::from(self.holds_live(order.session_id));
        if others >= self.cfg.max_sessions {
            return Answer::refused(
                HiveRefusal::AtCapacity,
                format!(
                    "this device already runs {} agent sessions (hive_max_sessions)",
                    self.cfg.max_sessions
                ),
            );
        }
        let store = match &self.store {
            Ok(s) => s.clone(),
            Err(e) => return Answer::refused(HiveRefusal::LaunchFailed, e.clone()),
        };
        // P2f-1a — a teleport's copy comes after its prepare.
        if !teleport {
            match store
                .last_of_kind(&order.session_id.to_hex(), "checkpoint")
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Answer::refused(
                        HiveRefusal::Other,
                        "this device holds no copy of the session to take it over from",
                    );
                }
                Err(e) => return Answer::refused(HiveRefusal::LaunchFailed, e),
            }
        }
        if matches!(self.launcher, Launcher::AsMappedAccount)
            && let Err((r, detail)) =
                super::sudo::gate(&account, self.cfg.allow_passwordless_sudo).await
        {
            return Answer::refused(r, detail);
        }
        if self.cfg.api_key_helper.is_some()
            && let Err(e) = self.sidecar_port().await
        {
            return Answer::refused(HiveRefusal::LaunchFailed, e);
        }
        Answer::accepted(&account)
    }

    /// P1c-2 — the DEVICE's gate on a driver. The server names who drives a
    /// session; THIS device decides whom it lets act as one of its accounts:
    /// the session's starter (whom the start mapped), or someone its own
    /// `hive_accounts` maps to the account the session runs as. The gate that
    /// survives a wrong server, as `hive_accounts` already is for a start —
    /// a driver answers approvals too, so driving IS running code here as
    /// that account. `Err` says why, in words the viewer is shown.
    ///
    /// ⚠️ The starter is recognised by id, from the start order, never by the
    /// map: a server older than P1c-2 sends no address, and an account mapped
    /// by address must not lock the starter out of their own session.
    pub(crate) fn drives_here(
        &self,
        session: ObjectId,
        user: ObjectId,
        email: Option<&str>,
    ) -> Result<(), String> {
        let (starter, account) = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            match live.get(&session) {
                Some(l) => (l.starter, l.account.clone()),
                None => return Err("the session does not run on this device now".to_string()),
            }
        };
        if user == starter {
            return Ok(());
        }
        match gates::account_for(&self.cfg, &user, email.unwrap_or("")) {
            Ok(mapped) if mapped == account => Ok(()),
            Ok(_) => Err(format!(
                "this device's hive_accounts maps you to another account than {account}, \
                 which the session runs as — here you may read it, not drive it"
            )),
            Err(_) => Err("this device's hive_accounts maps you to no account — \
                 here you may read the session, not drive it"
                .to_string()),
        }
    }

    /// The account a live session runs as, when it runs at `fence` and no
    /// newer fence has taken it (P2e-1).
    fn running(&self, session: ObjectId, fence: u64) -> Option<String> {
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.get(&session)
            .filter(|l| l.fence == fence && !l.fenced)
            .map(|l| l.account.clone())
    }

    /// P2e-1 — the fence `session` runs at here, and whether a newer one has
    /// fenced that run out.
    fn live_fence(&self, session: ObjectId) -> Option<(u64, bool)> {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session)
            .map(|l| (l.fence, l.fenced))
    }

    /// Feed a prompt to a running session. The viewer peer (P0d-2) is what
    /// calls this; until then the tests do. A prompt that arrives while a turn
    /// runs waits for it (see `Task::prompt`).
    pub fn prompt(
        &self,
        session: ObjectId,
        author: Option<Author>,
        text: String,
    ) -> Result<(), String> {
        // P1d-1 — the daemon is about to restart for an update: a turn begun
        // now would be cut.
        if self.updating() {
            return Err(
                "this device is about to restart for an update — ask again in a minute".into(),
            );
        }
        // P1d-2 — it is stopping: a turn begun now would be cut, and its
        // number would not reach what the next daemon resumes.
        if self.going_down() {
            return Err("this device is restarting — ask again in a minute".into());
        }
        let (input, waiting) = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            match live.get(&session) {
                None => return Err("no such session on this device".into()),
                // P2e-1 — a newer fence took it: no turn begins here.
                Some(l) if l.fenced => {
                    return Err("the session has moved on from this device".into());
                }
                // P2e-4 — drained for a move: no turn begins either, until
                // the move is off.
                Some(l) if l.draining => {
                    return Err(
                        "the session is moving to another device — ask again in a minute".into(),
                    );
                }
                Some(l) => (l.input.clone(), Arc::clone(&l.waiting)),
            }
        };
        // A place is taken BEFORE the send, atomically, so two callers cannot
        // both have the last one.
        if waiting
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_WAITING).then_some(n + 1)
            })
            .is_err()
        {
            return Err(format!(
                "{MAX_WAITING} prompts are already waiting for this session"
            ));
        }
        input.try_send(Input::Prompt { author, text }).map_err(|_| {
            waiting.fetch_sub(1, Ordering::AcqRel);
            "the session is not taking prompts".to_string()
        })
    }

    pub(crate) fn stop(&self, session: ObjectId, fence: u64, reason: String) {
        // P1j — an adopted session is stopped by no longer mirroring it.
        if self.adopt_stop(session, fence) {
            return;
        }
        let input = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            match live.get(&session) {
                // A device holding a NEWER fence ignores a stop for an older
                // one: the session moved on (P2's promotion).
                Some(l) if l.fence > fence => {
                    info!(session = %session, held = l.fence, fence, "hive: stop for an older fence ignored");
                    return;
                }
                Some(l) => Some((l.input.clone(), l.fence)),
                None => None,
            }
        };
        match input {
            Some((tx, held)) => {
                if tx.try_send(Input::Stop { reason }).is_err() {
                    warn!(session = %session, "hive: stop could not reach the session task");
                }
                // P2e-1 — an OLDER run: the server has moved past it, and
                // nothing here runs the fence the stop names (a start at it
                // may be waiting for this very run to let go). Said so now,
                // as for any session not run here; a launch that comes after
                // is answered with a stop when it reports in.
                if held < fence {
                    self.report(
                        session,
                        fence,
                        HiveRunState::Ended,
                        Some("not running on this device".into()),
                    );
                }
            }
            // P1d-2 — hosted by the previous daemon and not resumed yet: it
            // ends here, without a launch.
            None if self.take_from_resume(session, fence) => {
                self.hosted_forget(session, fence);
                self.report(
                    session,
                    fence,
                    HiveRunState::Ended,
                    Some(format!("stopped ({reason}) before it resumed")),
                );
            }
            None => {
                // P2e-1 — and a resume that took it from the queue and waits
                // for the start lock now finds it forgotten (`resume`): the
                // stop came first.
                self.hosted_forget(session, fence);
                self.report(
                    session,
                    fence,
                    HiveRunState::Ended,
                    Some("not running on this device".into()),
                );
            }
        }
    }

    /// P1d-2 — take `session` out of what waits to resume, when it waits
    /// there at `fence` or an older one.
    ///
    /// P2e-2 — or out of what is held back for the server's word.
    fn take_from_resume(&self, session: ObjectId, fence: u64) -> bool {
        let sid = session.to_hex();
        let queued = {
            let mut q = self.to_resume.lock().unwrap_or_else(|e| e.into_inner());
            let before = q.len();
            q.retain(|h| !(h.session == sid && h.fence <= fence));
            q.len() != before
        };
        let mut held_back = self.awaiting_word.lock().unwrap_or_else(|e| e.into_inner());
        let waited = held_back.get(&session).is_some_and(|h| h.fence <= fence);
        if waited {
            held_back.remove(&session);
        }
        queued || waited
    }

    /// P2e-4 — `rc:hive.drain`: the session's lease is about to leave this
    /// device. The run here at `fence` takes no new prompt from now on, its
    /// running turn ends or is cut, its open approvals are withdrawn and a
    /// last checkpoint is taken; the answer says where the copy ends. The
    /// run stays up, idle: the server's word at this fence lifts the drain
    /// (the lease stayed), a demote ends the run (it moved). A drain that
    /// cannot finish is refused, and lifted: the session goes on as before.
    ///
    /// Taken up at once, in the order the frames came ([`handle_drain`]):
    /// the session's task reads its inputs in order, so a word that came
    /// after the drain lifts it. `Err` is the refusal: its word and why.
    pub(crate) fn begin_drain(
        &self,
        session: ObjectId,
        fence: u64,
    ) -> Result<PendingDrain, (HiveDrainRefusal, String)> {
        use HiveDrainRefusal::{NotRunning, Other};
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let l = match live.get_mut(&session) {
            Some(l) if l.fence == fence && !l.fenced => l,
            Some(l) if l.fence == fence => {
                return Err((
                    NotRunning,
                    "the session has moved on from this device".into(),
                ));
            }
            Some(l) => {
                let why = format!("this device runs the session at fence {}", l.fence);
                return Err((NotRunning, why));
            }
            None => return Err((NotRunning, "this device does not run the session".into())),
        };
        let (reply, answer) = tokio::sync::oneshot::channel();
        if l.input.try_send(Input::Drain { reply }).is_err() {
            return Err((Other, "the session is not taking anything now".into()));
        }
        l.draining = true;
        Ok(PendingDrain {
            answer,
            input: l.input.clone(),
        })
    }

    /// P2e-4 — the answer to a drain [`Self::begin_drain`] took up, as
    /// `rc:hive.drained` says it.
    pub(crate) async fn drained(
        &self,
        session: ObjectId,
        fence: u64,
        pending: PendingDrain,
    ) -> ClientMsg {
        use HiveDrainRefusal::{NotRunning, Other};
        let t = self.drain_timing;
        let bound = t.cut + t.grace + t.checkpoint;
        let answer = match tokio::time::timeout(bound, pending.answer).await {
            Ok(Ok(a)) => Ok(a),
            Ok(Err(_)) => Err((NotRunning, "the session ended before it drained")),
            // Lifted, so a drain that finishes later holds nothing back.
            Err(_) => {
                let _ = pending.input.try_send(Input::Undrain);
                Err((Other, "the drain did not finish in time"))
            }
        };
        match answer {
            Ok(Drained::At { seq, hash }) => {
                info!(session = %session, fence, seq, "hive: drained for a move");
                ClientMsg::HiveDrained {
                    session_id: session,
                    fence,
                    seq: Some(seq),
                    hash: Some(hash),
                    refused: None,
                    detail: None,
                }
            }
            Ok(Drained::Not(why)) => {
                self.lift_drain(session, fence);
                info!(session = %session, fence, %why, "hive: not drained");
                drained_refused(session, fence, Other, &why)
            }
            Err((word, why)) => {
                self.lift_drain(session, fence);
                info!(session = %session, fence, why, "hive: not drained");
                drained_refused(session, fence, word, why)
            }
        }
    }

    /// P2e-4 — the run at `fence` takes prompts again.
    fn lift_drain(&self, session: ObjectId, fence: u64) {
        if let Some(l) = self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&session)
            .filter(|l| l.fence == fence)
        {
            l.draining = false;
        }
    }

    /// P2e-1 — `rc:hive.demote`: the session's lease is at `fence`, on
    /// another device. The store's fence floor for it rises to `fence`
    /// first, so whatever a run here still writes is refused as it is on
    /// every member; then the run here at an older fence is fenced out and
    /// stopped, and what the device hosts forgets the session, so neither a
    /// restart nor a resume still waiting launches it (`resume` reads the
    /// record again under the start lock). The copy in the store stays:
    /// whether the device goes on holding one is its owner's `hive_replica`
    /// and the server's join.
    ///
    /// Under the start lock, so neither a resume nor a start in flight
    /// launches the session again behind the demote's back.
    pub(crate) async fn demote(&self, session: ObjectId, fence: u64, reason: &str) {
        let _serial = self.start_lock.lock().await;
        if let Ok(store) = &self.store
            && let Err(e) = store.raise_floor(&session.to_hex(), fence).await
        {
            debug!(session = %session, fence, %e, "hive: a demote's fence floor was not raised");
        }
        let ran = self
            .fence_out(session, fence, "demoted")
            .map(|(held, _)| held);
        // What is older than the lease's fence, and only that: a session
        // that came back is not this demote's.
        if let Some(older) = fence.checked_sub(1) {
            self.hosted_forget(session, older);
        }
        // P2e-2 — nor does one held back for the word at an older fence ever
        // launch, and the words for those fences are void.
        {
            let mut held_back = self.awaiting_word.lock().unwrap_or_else(|e| e.into_inner());
            if held_back.get(&session).is_some_and(|h| h.fence < fence) {
                held_back.remove(&session);
            }
        }
        self.lease_words
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(s, f), _| !(*s == session && *f < fence));
        info!(
            session = %session, fence, reason, ran = ?ran,
            "hive: demoted — the session is held at a newer fence elsewhere"
        );
    }

    /// P2e-1 — fence out the run of `session` here at a fence older than
    /// `fence`, and tell it to stop: from now on its model calls, prompts
    /// and approval answers are refused. Its fence, and what closes once its
    /// task has let go; `None` when no such run is here.
    fn fence_out(
        &self,
        session: ObjectId,
        fence: u64,
        why: &str,
    ) -> Option<(u64, watch::Receiver<()>)> {
        let (held, input, gone, already) = {
            let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            let l = live.get_mut(&session).filter(|l| l.fence < fence)?;
            let already = std::mem::replace(&mut l.fenced, true);
            (l.fence, l.input.clone(), l.gone.clone(), already)
        };
        if !already {
            info!(session = %session, held, fence, why, "hive: a newer fence took the session — its run here stops");
            let reason = format!("{why}: the session is at fence {fence}");
            if input.try_send(Input::Stop { reason }).is_err() {
                debug!(session = %session, "hive: the fenced run's task takes no more input");
            }
        }
        Some((held, gone))
    }

    /// P2e-1 — before a start at `fence` launches: the run here at an older
    /// fence is fenced out and stopped, and the start waits until its task
    /// has let go of the session. `Err` when it has not within
    /// [`SUPERSEDE_WAIT`].
    async fn supersede(&self, session: ObjectId, fence: u64, why: &str) -> Result<(), String> {
        let Some((held, mut gone)) = self.fence_out(session, fence, why) else {
            return Ok(());
        };
        // Nothing ever sends on it: it changes only by closing.
        match tokio::time::timeout(SUPERSEDE_WAIT, gone.changed()).await {
            Ok(_) => Ok(()),
            Err(_) => {
                warn!(session = %session, held, fence, "hive: the run a newer fence took did not let go");
                Err(format!(
                    "the session's run at fence {held} did not stop within {} s",
                    SUPERSEDE_WAIT.as_secs()
                ))
            }
        }
    }

    /// P2e-2 — `rc:hive.lease`: the server says on `tx` that this device holds
    /// `session` at `fence`. The word is kept for that connection; a run here
    /// at that fence is leased from now on (the first word makes it so, as a
    /// start's `lease` does), and its model calls go again; a leased session
    /// held back for the word launches. A word for a session this device
    /// neither runs nor hosts is not kept.
    pub(crate) fn take_lease(
        self: &Arc<Self>,
        session: ObjectId,
        fence: u64,
        tx: &mpsc::Sender<ClientMsg>,
    ) {
        let sid = session.to_hex();
        let held_back = self
            .awaiting_word
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&session);
        let queued = self
            .to_resume
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|h| h.session == sid);
        if !(self.holds_live(session) || held_back || queued || self.hosted_get(session).is_some())
        {
            debug!(session = %session, fence, "hive: a lease word for a session this device does not hold — not kept");
            return;
        }
        if !self.record_word(session, fence, tx) {
            return;
        }
        let (marked, undrain) = {
            let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            match live.get_mut(&session) {
                Some(l) if l.fence == fence && !l.fenced => {
                    l.lease = true;
                    // P2e-4 — drained for a move that is off: the lease
                    // stayed here, and the run takes prompts again.
                    let undrain = std::mem::take(&mut l.draining).then(|| l.input.clone());
                    (true, undrain)
                }
                _ => (false, None),
            }
        };
        if marked {
            self.hosted_update(session, fence, |h| h.lease = true);
        }
        if let Some(input) = undrain {
            info!(session = %session, fence, "hive: the server's word — the drain is lifted");
            let _ = input.try_send(Input::Undrain);
        }
        // Held back for this very word: it launches now, through every gate
        // a resume passes.
        let resume = {
            let mut held_back = self.awaiting_word.lock().unwrap_or_else(|e| e.into_inner());
            if held_back.get(&session).is_some_and(|h| h.fence == fence) {
                held_back.remove(&session)
            } else {
                None
            }
        };
        if let Some(h) = resume {
            info!(session = %session, fence, "hive: the server's word came — the leased session resumes");
            let me = Arc::clone(self);
            tokio::spawn(async move { me.resume(h).await });
        }
    }

    /// P2e-2 — keep the server's word for `session` at `fence`, said on `tx`,
    /// and wake whatever waits for it. A newer fence's word voids an older
    /// one's. Only a word on the latest connection is kept: one that comes
    /// late on an older connection must never take the place of the latest
    /// one's. (A connection is the latest before it reads its first frame:
    /// `on_connected` runs before the read loop.) `false` = not kept.
    pub(crate) fn record_word(
        &self,
        session: ObjectId,
        fence: u64,
        tx: &mpsc::Sender<ClientMsg>,
    ) -> bool {
        let latest = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|r| r.same_channel(tx));
        if !latest {
            debug!(session = %session, fence, "hive: a lease word on a connection that is not the latest — not kept");
            return false;
        }
        {
            let mut words = self.lease_words.lock().unwrap_or_else(|e| e.into_inner());
            words.retain(|(s, f), _| !(*s == session && *f < fence));
            if words.len() >= MAX_LEASE_WORDS && !words.contains_key(&(session, fence)) {
                warn!(session = %session, "hive: too many lease words kept — this one is not");
                return false;
            }
            words.insert((session, fence), tx.downgrade());
        }
        self.lease_heard.notify_waiters();
        true
    }

    /// P2e-2 — whether the server has said, on the connection that is the
    /// latest one now, that this device holds `session` at `fence`. A word on
    /// an older connection counts for nothing.
    pub(crate) fn has_word(&self, session: ObjectId, fence: u64) -> bool {
        let Some(latest) = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return false;
        };
        self.lease_words
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(session, fence))
            .and_then(mpsc::WeakSender::upgrade)
            .is_some_and(|said_on| said_on.same_channel(&latest))
    }

    /// P2e-2 — whether the run of `session` here at `fence` is leased.
    pub(crate) fn leased(&self, session: ObjectId, fence: u64) -> bool {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session)
            .is_some_and(|l| l.fence == fence && l.lease)
    }

    pub(crate) fn lease_heard(&self) -> &tokio::sync::Notify {
        &self.lease_heard
    }

    pub(crate) fn lease_wait(&self) -> Duration {
        self.lease_wait
    }

    pub(crate) fn connected(self: &Arc<Self>, tx: mpsc::Sender<ClientMsg>) {
        // P0e — online again; and when THIS connection closes, the
        // `offline_grace` clock starts (unless a newer one replaced it).
        *self.offline_since.lock().unwrap_or_else(|e| e.into_inner()) = None;
        {
            let watched = tx.clone();
            let me = Arc::downgrade(self);
            tokio::spawn(async move {
                watched.closed().await;
                if let Some(me) = me.upgrade() {
                    me.lost_connection(&watched);
                }
            });
        }
        let replay: Vec<(ObjectId, Report)> = {
            let mut reports = self.reports.lock().unwrap_or_else(|e| e.into_inner());
            reports.retain(|_, r| r.state != HiveRunState::Ended || r.at.elapsed() < ENDED_REPLAY);
            reports.iter().map(|(s, r)| (*s, r.clone())).collect()
        };
        let turns: Vec<ClientMsg> = {
            let mut turns = self.turns.lock().unwrap_or_else(|e| e.into_inner());
            // A session whose state report was pruned is history.
            turns.retain(|s, _| replay.iter().any(|(r, _)| r == s));
            turns.values().cloned().collect()
        };
        let approvals: Vec<ClientMsg> = {
            let mut all = self
                .approval_frames
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            all.retain(|s, _| replay.iter().any(|(r, _)| r == s));
            all.values()
                .flat_map(|l| l.iter().map(|(_, m)| m.clone()))
                .collect()
        };
        // Each session's newest turn and approvals, then its state: the
        // server applies them in order, and a stub before the state is how
        // they happened.
        for t in turns.into_iter().chain(approvals) {
            let _ = tx.try_send(t);
        }
        for (session_id, r) in replay {
            let _ = tx.try_send(ClientMsg::HiveState {
                session_id,
                fence: r.fence,
                state: Some(r.state),
                detail: r.detail,
            });
        }
        // Reports go here from now on — a resumed session's among them.
        *self.reporter.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx.clone());
        // P1b — and every session this device RUNS, now: the server ends the
        // ones it holds as running here that the list leaves out. A daemon
        // that restarted holds no replay of what it ran, so this is the only
        // way the server learns those sessions are over (finding 7).
        //
        // P1d-2 — but only once what the previous daemon hosted has resumed:
        // a manifest sent first would leave those sessions out, and the
        // server would end every one of them. The resume runs in a task of
        // its own, so the manifest's bound on waiting never cancels it
        // halfway through a session.
        let me = Arc::clone(self);
        let resume = tokio::spawn(async move { me.resume_once().await });
        let me = Arc::clone(self);
        tokio::spawn(async move {
            if tokio::time::timeout(RESUME_BUDGET, resume).await.is_err() {
                warn!(
                    "hive: the hosted sessions are still resuming — the manifest goes without them"
                );
            }
            let _ = tx.try_send(ClientMsg::HiveManifest {
                sessions: me.manifest(),
            });
            // P2c-3 — and every copy it holds, with its tip, once the
            // resumed sessions are among them. Only from a device that holds
            // copies or runs a replicated session: no other has one to tell.
            // P2g-3d — and each copy its own clock purged, whatever it holds
            // now: the server stops counting that copy.
            if let Some(manifest) = me.replica_manifest_frame().await {
                let _ = tx.try_send(manifest);
            }
            // P2g-3d — then what keeps each session it holds: the server's
            // word, which the device's own clock counts from.
            me.ask_retain_all().await;
            // P2d-3b — then each copy it holds asks for its stream, once the
            // server has heard where each one ends. Only while its owner lets
            // it hold copies at all; P2f-1b — else only the copies of the
            // teleports it was prepared for.
            if me.follows_at_connect() {
                if me.cfg.replica {
                    me.follow_all().await;
                } else {
                    me.follow_teleports().await;
                }
            }
        });
    }

    /// The sessions this device runs now, as the manifest names them.
    fn manifest(&self) -> Vec<HiveManifestEntry> {
        let mut m: Vec<HiveManifestEntry> = self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(session_id, l)| HiveManifestEntry {
                session_id: *session_id,
                fence: l.fence,
            })
            .collect();
        // P1j — and the terminal sessions it mirrors: the server ends what
        // the list leaves out.
        m.extend(
            self.adopt_manifest()
                .into_iter()
                .map(|(session_id, fence)| HiveManifestEntry { session_id, fence }),
        );
        // P2e-2 — and the leased sessions held back for the server's word:
        // the server answers each with the word, a demote or a stop, and ends
        // none of them as not run here.
        m.extend(
            self.awaiting_word
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|(session_id, h)| HiveManifestEntry {
                    session_id: *session_id,
                    fence: h.fence,
                }),
        );
        m
    }

    /// P1d-2 — resume what the previous daemon hosted: once, at the first
    /// connection of the primary enrollment, so a device that never comes
    /// back online launches nothing. A second connection waits for the same
    /// run.
    async fn resume_once(self: &Arc<Self>) {
        self.resumed
            .get_or_init(|| async {
                let n = self
                    .to_resume
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .len();
                if n > 0 {
                    info!(
                        sessions = n,
                        "hive: resuming what this device hosted before it restarted"
                    );
                }
                loop {
                    let next = {
                        let mut q = self.to_resume.lock().unwrap_or_else(|e| e.into_inner());
                        if q.is_empty() {
                            break;
                        }
                        q.remove(0)
                    };
                    self.resume(next).await;
                }
            })
            .await;
    }

    /// P1d-2 — one hosted session, through every gate a start passes, as the
    /// device is configured NOW: a device owner who turned sessions off,
    /// remapped the starter or moved `hive_roots`, then restarted, does not
    /// find the session back. One the gates refuse is reported ended, with
    /// the reason.
    async fn resume(self: &Arc<Self>, mut h: HostedSession) {
        let (Ok(session), Ok(starter)) = (
            ObjectId::parse_str(&h.session),
            ObjectId::parse_str(&h.starter),
        ) else {
            warn!(session = %h.session, "hive: a hosted session with an unreadable id — not resumed");
            self.hosted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&h.session);
            return;
        };
        // Under the start lock from here to the launch: a start the server
        // re-sent may launch the session first, and its entry is then the
        // live one's to keep.
        let _serial = self.start_lock.lock().await;
        if self.holds_live(session) {
            return;
        }
        // P2e-1 — taken from the queue before the lock: a demote that won
        // the lock meanwhile forgot the session here, and it is not resumed.
        // (Nothing is reported: its run is the new primary's now.)
        if self
            .hosted_get(session)
            .is_none_or(|cur| cur.fence != h.fence)
        {
            info!(session = %session, fence = h.fence, "hive: a hosted session was forgotten before it resumed — not resumed");
            return;
        }
        // P2e-2 — a leased session launches only on the server's word on
        // this connection. Until it comes it is held back, and listed in the
        // manifest, which the server answers with the word, a demote or a
        // stop. Checked and held under one lock: a word that lands meanwhile
        // finds it held back (`take_lease`) and launches it.
        if h.lease {
            let mut held_back = self.awaiting_word.lock().unwrap_or_else(|e| e.into_inner());
            if !self.has_word(session, h.fence) {
                info!(session = %session, fence = h.fence, "hive: a leased session waits for the server's word before it resumes");
                held_back.insert(session, h);
                return;
            }
        }
        let now = unix_now();
        let quick = match h.resumed_at {
            Some(at) if now.saturating_sub(at) < RESUME_STABLE.as_secs() => h.quick_resumes + 1,
            _ => 0,
        };
        if quick >= MAX_QUICK_RESUMES {
            self.not_resumed(
                session,
                h.fence,
                format!(
                    "the daemon restarted {quick} times within {} s of resuming it",
                    RESUME_STABLE.as_secs()
                ),
            );
            return;
        }
        // Counted BEFORE the launch: a resume that takes the daemon down is
        // the one the bound is for.
        // P1h — a harness the previous daemon launched and never took down
        // (it crashed, or was killed outright) is still running on this
        // history: it goes before the resume starts another on it.
        reap_leftover(&h).await;
        h.resumed_at = Some(now);
        h.quick_resumes = quick;
        {
            let mut hosted = self.hosted.lock().unwrap_or_else(|e| e.into_inner());
            // P2c-4 — `h` is the record as this daemon found it when it
            // began. A primary's join may have turned the session replicated
            // since (the server sends it at the very connection this resume
            // runs for): what the join set is kept, never written over.
            if hosted
                .get(&h.session)
                .is_some_and(|cur| cur.fence == h.fence && cur.replicated)
            {
                h.replicated = true;
            }
            hosted.put(h.clone());
        }
        let order = StartOrder {
            session_id: session,
            harness: h.harness,
            harness_session: h.harness_session,
            fence: h.fence,
            folder: h.folder,
            user_id: starter,
            user_email: h.starter_email,
            caller: "this device's resume".into(),
            // Decided by the history on disk, as for every launch.
            resume: false,
            replicated: h.replicated,
            lease: h.lease,
            // P2f-3a — a fork resumes as one: its checkpoints keep its
            // parent's history, and before its first prompt it still starts
            // from it.
            fork_of: h.fork_of,
            // P2f-4a — a session made managed from a terminal is hosted only
            // once its history was put in place: it resumes its own.
            from_terminal: false,
        };
        let answer = self.start_locked(order, true).await;
        if answer.refused.is_some() {
            self.not_resumed(
                session,
                h.fence,
                answer.detail.unwrap_or_else(|| "refused".into()),
            );
        }
    }

    /// P1d-2 — a hosted session will not resume: forgotten, and reported
    /// ended with why.
    fn not_resumed(&self, session: ObjectId, fence: u64, why: String) {
        info!(session = %session, %why, "hive: a hosted session was not resumed");
        self.hosted_forget(session, fence);
        self.report(
            session,
            fence,
            HiveRunState::Ended,
            Some(format!("not resumed after the device restarted: {why}")),
        );
    }

    // ─── What the device hosts (P1d-2, `super::hosted`) ─────────────────

    fn hosted_get(&self, session: ObjectId) -> Option<HostedSession> {
        self.hosted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session.to_hex())
            .cloned()
    }

    /// ⚠️ From [`Self::begin_shutdown`] on, what the device hosts is FROZEN:
    /// the teardown cuts turns and withdraws approvals, and the frames saying
    /// so go into connections that are closing. Recorded here, they would be
    /// lost twice — once on the wire, and again because the next daemon
    /// would find nothing left to report (field, 2026-10-08: an approval the
    /// teardown withdrew stayed "needed" on the server).
    ///
    /// P2e-1 — a run's own record only, at its `fence`.
    fn hosted_update(&self, session: ObjectId, fence: u64, f: impl FnOnce(&mut HostedSession)) {
        if self.going_down() {
            return;
        }
        self.hosted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .update_at(&session.to_hex(), fence, f);
    }

    /// Forget what the device hosts of `session` at `fence` or an older one
    /// (P2e-1): never a newer run's record.
    fn hosted_forget(&self, session: ObjectId, fence: u64) {
        if self.going_down() {
            return;
        }
        self.hosted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove_upto(&session.to_hex(), fence);
    }

    /// P1d-2 — the daemon is stopping (see the module-level
    /// [`begin_shutdown`]).
    pub(crate) fn begin_shutdown(&self) {
        if !self.going_down.swap(true, Ordering::SeqCst) {
            info!(
                sessions = self.live_count(),
                "hive: the daemon is stopping — its sessions are kept for the next start"
            );
        }
    }

    fn going_down(&self) -> bool {
        self.going_down.load(Ordering::SeqCst)
    }

    /// P1h — see [`wind_down`].
    pub(crate) async fn wind_down(&self) {
        self.begin_shutdown();
        let pids = self.harness_pids();
        if !pids.is_empty() {
            info!(
                harnesses = pids.len(),
                "hive: taking the harnesses down with the daemon"
            );
            super::procs::take_down(&pids, WIND_DOWN_GRACE).await;
        }
    }

    /// The pids of the harnesses running now.
    fn harness_pids(&self) -> Vec<u32> {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter_map(|l| l.pid)
            .collect()
    }

    /// P1d-2 — whether a harness that ended without being stopped went down
    /// with the daemon: told so now, or within [`SETTLE`].
    async fn went_down_with_daemon(&self) -> bool {
        if self.going_down() {
            return true;
        }
        tokio::time::sleep(SETTLE).await;
        self.going_down()
    }

    /// Record and send an approval's frame (`rc:hive.approval`), like
    /// [`Self::report_turn`]: the newest of each of the session's last
    /// [`APPROVAL_REPLAY`] approvals is replayed on the next connection.
    fn report_approval(&self, session: ObjectId, msg: ClientMsg) {
        let ClientMsg::HiveApproval { approval_id, .. } = &msg else {
            return;
        };
        {
            let mut all = self
                .approval_frames
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let list = all.entry(session).or_default();
            list.retain(|(a, _)| a != approval_id);
            list.push((approval_id.clone(), msg.clone()));
            if list.len() > APPROVAL_REPLAY {
                list.remove(0);
            }
        }
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(msg);
        }
    }

    /// Record and send a turn's stub (`rc:hive.turn`), like [`Self::report`].
    fn report_turn(&self, session: ObjectId, msg: ClientMsg) {
        self.turns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session, msg.clone());
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(msg);
        }
    }

    /// Record and send a state. `try_send` keeps reports in order and never
    /// blocks a session on a slow socket; what a full queue drops, the replay
    /// on the next connection carries.
    fn report(&self, session: ObjectId, fence: u64, state: HiveRunState, detail: Option<String>) {
        self.reports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                session,
                Report {
                    fence,
                    state,
                    detail: detail.clone(),
                    at: Instant::now(),
                },
            );
        // Viewers of the session hear it too (P0d-2); nobody watching is fine.
        let _ = self.states.send((session, state));
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(ClientMsg::HiveState {
                session_id: session,
                fence,
                state: Some(state),
                detail,
            });
        }
    }

    // ─── What the viewer peer (P0d-2, `super::view`) reads ──────────────

    /// The device's own `hive_enabled`.
    pub(crate) fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// P2d-5 — the device's own `hive_replica`: it holds copies of its
    /// owner's sessions run elsewhere, and serves a viewer from them.
    pub(crate) fn holds_copies(&self) -> bool {
        self.cfg.replica
    }

    /// P2i-1 — the device's own `hive_archive`: it offers itself as the
    /// organization's archive replica, whose copies a search is served from.
    pub(crate) fn offers_archive(&self) -> bool {
        self.cfg.archive
    }

    pub(crate) fn store_handle(&self) -> Result<StoreHandle, String> {
        self.store.clone()
    }

    /// Whether this device runs `session` now.
    pub(crate) fn holds_live(&self, session: ObjectId) -> bool {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&session)
    }

    /// The latest state reported for `session`, while it is remembered.
    pub(crate) fn run_state(&self, session: ObjectId) -> Option<HiveRunState> {
        self.reports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session)
            .map(|r| r.state)
    }

    /// Every state reported from now on, of every session.
    pub(crate) fn subscribe_states(&self) -> broadcast::Receiver<(ObjectId, HiveRunState)> {
        self.states.subscribe()
    }

    /// P1a — every change to any session's open approvals, from now on.
    pub(crate) fn subscribe_approvals(&self) -> broadcast::Receiver<(ObjectId, Vec<String>)> {
        self.approvals.subscribe()
    }

    /// The approvals open in `session` now; none for a session not live here.
    pub(crate) fn pending_approvals(&self, session: ObjectId) -> Vec<String> {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session)
            .map(|l| l.approvals.ids())
            .unwrap_or_default()
    }

    /// A driver's answer to one of `session`'s open approvals. The viewer
    /// peer calls this for a grant that may drive, and nothing else does.
    pub(crate) fn answer_approval(
        &self,
        session: ObjectId,
        approval: &str,
        decision: toolbelt::Decision,
        by: Author,
    ) -> Result<(), String> {
        let pending = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            match live.get(&session) {
                None => return Err("no such session on this device".into()),
                // P2e-1 — a newer fence took it: its approvals are no longer
                // this device's to answer.
                Some(l) if l.fenced => {
                    return Err("the session has moved on from this device".into());
                }
                Some(l) => Arc::clone(&l.approvals),
            }
        };
        if pending.answer(approval, toolbelt::Answer { decision, by }) {
            Ok(())
        } else {
            Err("that approval is not waiting (answered, expired or withdrawn)".into())
        }
    }

    pub(crate) fn viewers(&self) -> &super::view::Viewers {
        &self.viewers
    }

    /// Send a frame on the primary connection that is up NOW. Not replayed:
    /// a viewer's handshake that loses a frame times out, and the browser
    /// asks again.
    pub(crate) fn send(&self, msg: ClientMsg) {
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match tx {
            Some(tx) => {
                if tx.try_send(msg).is_err() {
                    debug!(
                        "hive: the control connection's queue is full — a view frame was dropped"
                    );
                }
            }
            None => debug!("hive: no control connection — a view frame was dropped"),
        }
    }

    // ─── The model sidecar's side of the supervisor (P0e) ───────────────

    /// The sidecar's port, binding it on first use.
    async fn sidecar_port(self: &Arc<Self>) -> Result<u16, String> {
        self.sidecar_port
            .get_or_try_init(|| async {
                let (listener, port) = super::sidecar::bind().await?;
                super::sidecar::serve(listener, Arc::downgrade(self));
                info!(port, "hive: the model sidecar listens on loopback");
                Ok::<u16, String>(port)
            })
            .await
            .copied()
    }

    pub(crate) fn tokens(&self) -> &super::sidecar::Tokens {
        &self.tokens
    }

    /// Whether `session` runs here at `fence`.
    pub(crate) fn runs_at(&self, session: ObjectId, fence: u64) -> bool {
        self.running(session, fence).is_some()
    }

    /// How long the primary connection has been gone; `None` while it is up.
    pub(crate) fn offline_for(&self) -> Option<Duration> {
        self.offline_since
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|t| t.elapsed())
    }

    pub(crate) fn offline_grace(&self) -> Duration {
        self.offline_grace
    }

    pub(crate) fn upstream(&self) -> &str {
        &self.upstream
    }

    /// `watched` closed: the device is offline — unless a newer connection
    /// already took its place.
    fn lost_connection(&self, watched: &mpsc::Sender<ClientMsg>) {
        let current = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|r| r.same_channel(watched));
        if current {
            let mut since = self.offline_since.lock().unwrap_or_else(|e| e.into_inner());
            if since.is_none() {
                *since = Some(Instant::now());
            }
        }
    }

    /// The provider key, from the device's helper, reused for [`KEY_TTL`].
    ///
    /// [`KEY_TTL`]: super::sidecar::KEY_TTL
    pub(crate) async fn model_key(&self) -> Result<String, String> {
        let mut cached = self.model_key.lock().await;
        if let Some((key, at)) = cached.as_ref()
            && at.elapsed() < super::sidecar::KEY_TTL
        {
            return Ok(key.clone());
        }
        let helper = self
            .cfg
            .api_key_helper
            .as_deref()
            .ok_or("this device has no model credential (hive_api_key_helper)")?;
        let key = super::sidecar::run_key_helper(helper).await?;
        *cached = Some((key.clone(), Instant::now()));
        Ok(key)
    }

    /// The provider refused the key: run the helper again next time.
    pub(crate) async fn forget_model_key(&self) {
        *self.model_key.lock().await = None;
    }

    /// The workspace a key not scoped to one makes its calls in.
    pub(crate) fn model_workspace(&self) -> Option<&str> {
        self.cfg.api_workspace_id.as_deref()
    }

    /// Tests only: a mock provider, and a shorter `offline_grace`.
    #[cfg(all(test, unix))]
    pub(crate) fn with_sidecar(mut self, upstream: String, offline_grace: Duration) -> Self {
        self.upstream = upstream;
        self.offline_grace = offline_grace;
        self
    }

    /// Tests only: a leased run's model call that gives up on the word in a
    /// test's lifetime.
    #[cfg(all(test, unix))]
    pub(crate) fn with_lease_wait(mut self, wait: Duration) -> Self {
        self.lease_wait = wait;
        self
    }

    /// Tests only: a drain that cuts its running turn, and gives up on the
    /// cut, in a test's lifetime.
    #[cfg(all(test, unix))]
    pub(crate) fn with_drain_timing(mut self, timing: DrainTiming) -> Self {
        self.drain_timing = timing;
        self
    }

    /// Tests only: an approval that expires in a test's lifetime.
    #[cfg(all(test, unix))]
    pub(crate) fn with_approval_timing(mut self, timing: toolbelt::Timing) -> Self {
        self.approval_timing = timing;
        self
    }

    /// P2d-3b — a test's supervisor whose connections do not start following
    /// (`follow_all`): the test drives the follow itself.
    #[cfg(all(test, unix))]
    pub(crate) fn without_follow_at_connect(mut self) -> Self {
        self.follow_at_connect = false;
        self
    }

    /// P2d-3b — whether a connection starts following every copy held: a
    /// device's always does.
    fn follows_at_connect(&self) -> bool {
        #[cfg(test)]
        {
            self.follow_at_connect
        }
        #[cfg(not(test))]
        {
            true
        }
    }

    fn finish(&self, session: ObjectId, fence: u64, token: Option<&str>, detail: String) {
        // Its model access ends with it.
        if let Some(token) = token {
            self.tokens.revoke(token);
        }
        self.unlive(session, fence);
        // P1d-2 — over, so nothing to resume.
        self.hosted_forget(session, fence);
        // P2e-2 — and its word goes with it.
        self.lease_words
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(session, fence));
        info!(session = %session, fence, %detail, "hive: session ended");
        self.report(session, fence, HiveRunState::Ended, Some(detail));
    }

    /// P2e-1 — the run of `session` at `fence` is no longer live here; one at
    /// another fence is not this run's to take.
    fn unlive(&self, session: ObjectId, fence: u64) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if live.get(&session).is_some_and(|l| l.fence == fence) {
            live.remove(&session);
        }
        drop(live);
        // FR-90 P3-4a — what the vault leased to this run goes with it. Every
        // way a run stops being live here passes through this.
        #[cfg(feature = "vault")]
        crate::vault::drop_run(session, fence);
        // FR-90 P3-7-3c — and so does every egress listener its tools opened,
        // with every connection on it.
        #[cfg(feature = "vault")]
        super::net_tools::drop_run(session, fence);
    }

    /// P1d-2 — a session resumed after its daemon went down. A turn the
    /// restart cut is reported interrupted, naming who asked; the approvals
    /// it left open are recorded and reported withdrawn; the transcript says
    /// what happened. The file forgets them only once all that is sent.
    fn report_resumed(&self, session: ObjectId, fence: u64, store: &StoreHandle, r: &Resumed) {
        let sid = session.to_hex();
        let mut words = vec!["The device restarted, and this session resumed".to_string()];
        if !r.history {
            words.push(
                "Claude Code's own history of it was not found, so the model starts afresh"
                    .to_string(),
            );
        }
        let cut_turn = r.cut.as_ref().map(|c| c.turn);
        if let Some(cut) = &r.cut {
            self.report_turn(
                session,
                ClientMsg::HiveTurn {
                    session_id: session,
                    fence,
                    turn: cut.turn,
                    status: Some(HiveTurnStatus::Interrupted),
                    prompted_by: cut
                        .prompted_by
                        .as_deref()
                        .and_then(|u| ObjectId::parse_str(u).ok()),
                    steps: 0,
                    duration_ms: None,
                    cost_usd: None,
                },
            );
            words.push(format!(
                "turn {} was cut by the restart — ask again to go on",
                cut.turn
            ));
        }
        for id in &r.approvals {
            store.append(
                &sid,
                fence,
                resolved(id.clone(), toolbelt::Ended::Withdrawn),
            );
            self.report_approval(
                session,
                ClientMsg::HiveApproval {
                    session_id: session,
                    fence,
                    approval_id: id.clone(),
                    turn: cut_turn,
                    status: Some(HiveApprovalStatus::Withdrawn),
                    answered_by: None,
                },
            );
        }
        store.append(
            &sid,
            fence,
            TranscriptEvent::Note {
                text: format!("{}.", words.join("; ")),
            },
        );
        self.hosted_update(session, fence, |h| {
            h.running = None;
            h.approvals.clear();
        });
    }

    /// P1d-2 — the session's harness went down with the daemon: let go of
    /// it here and say nothing, exactly as a daemon killed outright would.
    /// What the device hosts keeps it, and the next daemon resumes it.
    fn let_go(&self, session: ObjectId, fence: u64, token: Option<&str>) {
        if let Some(token) = token {
            self.tokens.revoke(token);
        }
        self.unlive(session, fence);
        info!(session = %session, fence, "hive: the session went down with the daemon — kept for the next start");
    }

    #[allow(clippy::too_many_arguments)]
    fn launch(
        self: &Arc<Self>,
        order: &StartOrder,
        account: &str,
        folder: &Path,
        store: StoreHandle,
        sidecar: Option<u16>,
        moved: Option<&Moved>,
        note: Option<&str>,
        // P2f-4a — a terminal session made a managed one counts on from the
        // turns its terminal began.
        terminal_turns: Option<u32>,
    ) -> Result<(), (HiveRefusal, String)> {
        // P1d-2 — a session this device hosted goes on where it stood.
        let prior = self
            .hosted_get(order.session_id)
            .filter(|h| h.fence == order.fence);
        let restarted = prior.is_some();
        // P1e — the core memory this start came with: shown to the session
        // only where the device's owner allows it (`hive_core_memory`).
        let memory = self.take_memory(order.session_id, order.fence);
        let shown = memory.as_ref().filter(|_| self.cfg.core_memory);
        let (approvals_tx, approvals_rx) = mpsc::channel(APPROVAL_QUEUE);
        let Spawned {
            child,
            token,
            toolbelt,
            history,
            checkpoints,
        } = self.spawn(order, account, folder, sidecar, approvals_tx, shown, note)?;
        // P1h — who the harness is, for whoever must take it down later: this
        // daemon when it leaves, or the next one after a crash.
        let pid = child.id();
        let started = pid.and_then(super::procs::started);
        if let Some(m) = &memory {
            store.append(
                &order.session_id.to_hex(),
                order.fence,
                TranscriptEvent::Note {
                    text: memory_note(m, self.cfg.core_memory),
                },
            );
        }
        // P2e-7 — and the resume note, as the harness is told it.
        if let Some(text) = note {
            store.append(
                &order.session_id.to_hex(),
                order.fence,
                TranscriptEvent::Note {
                    text: text.to_string(),
                },
            );
        }
        let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE);
        let waiting = Arc::new(AtomicUsize::new(0));
        let replicated = Arc::new(AtomicBool::new(order.replicated));
        // P2e-2 — leased by its start, or by what the device hosted of it.
        let lease = order.lease || prior.as_ref().is_some_and(|h| h.lease);
        // P2e-1 — dropped by the session's task once it has let go.
        let (gone_tx, gone) = watch::channel(());
        let workplace = Arc::new(checkpoints.workplace());
        // P2f-2c — kept beyond this run: a member that asks for a whole pack
        // once the session ended here is packed for from where it ran.
        if let (Some(folder), Some(state_dir)) =
            (workplace.folder.to_str(), workplace.state_dir.to_str())
        {
            let kept = roomler_hive_node::store::WorkplaceRecord {
                account: account.to_string(),
                folder: folder.to_string(),
                state_dir: state_dir.to_string(),
            };
            let (store, sid) = (store.clone(), order.session_id.to_hex());
            tokio::spawn(async move {
                if let Err(e) = store.put_workplace(&sid, kept).await {
                    warn!(session = %sid, %e, "hive: where the session runs could not be kept");
                }
            });
        }
        self.live.lock().unwrap_or_else(|e| e.into_inner()).insert(
            order.session_id,
            Live {
                fence: order.fence,
                account: account.to_string(),
                starter: order.user_id,
                input: input_tx,
                waiting: Arc::clone(&waiting),
                approvals: toolbelt.pending(),
                pid,
                replicated: Arc::clone(&replicated),
                fenced: false,
                gone,
                lease,
                draining: false,
                workplace,
            },
        );
        if prior.is_some() {
            self.hosted_update(order.session_id, order.fence, |h| {
                h.harness_pid = pid;
                h.harness_started = started.clone();
                // P2c-4 — a primary's join that came while this resumed:
                // read AFTER the session is live, as `take_up_replication`
                // writes the record before it looks for the live session.
                if h.replicated {
                    replicated.store(true, Ordering::SeqCst);
                }
            });
        }
        let resumed = match prior {
            Some(h) => Some(Resumed {
                turns: h.turns,
                cut: h.running,
                approvals: h.approvals,
                history,
            }),
            None => {
                let mut hosted = self.hosted.lock().unwrap_or_else(|e| e.into_inner());
                hosted.put(HostedSession {
                    session: order.session_id.to_hex(),
                    fence: order.fence,
                    harness: order.harness.clone(),
                    harness_session: order.harness_session.clone(),
                    folder: order.folder.clone(),
                    account: account.to_string(),
                    starter: order.user_id.to_hex(),
                    starter_email: order.user_email.clone(),
                    // P2e-5 — a session moved here counts on from its turns,
                    // P2f-4a and a terminal's from its terminal's.
                    turns: moved.map(|m| m.turns).or(terminal_turns).unwrap_or(0),
                    running: None,
                    approvals: Vec::new(),
                    resumed_at: None,
                    quick_resumes: 0,
                    harness_pid: pid,
                    harness_started: started.clone(),
                    // P2c-4 — the live flag, read under the record's lock:
                    // a primary's join that found no record yet set it.
                    replicated: replicated.load(Ordering::SeqCst),
                    lease,
                    fork_of: order.fork_of.clone(),
                });
                moved
                    .map(|m| m.turns)
                    // P2f-4a — and a terminal's history: its first turn
                    // reports no cost counted from the terminal's total.
                    .or(terminal_turns)
                    // P2f-3a — a fork's first launch resumes its parent's
                    // history: like a resumed process's, its first turn
                    // reports no cost rather than one counted from the
                    // parent's running total.
                    .or(order.fork_of.as_ref().map(|_| 0))
                    .map(|turns| Resumed {
                        turns,
                        cut: None,
                        approvals: Vec::new(),
                        history,
                    })
            }
        };
        // Up and waiting for its first prompt.
        self.report(order.session_id, order.fence, HiveRunState::Idle, None);
        // P1d-2 — and what its last daemon left behind, here, before the
        // launch returns: a connection's manifest goes out once the resume
        // has, and follows all of it. A move left nothing behind here.
        if restarted && let Some(r) = &resumed {
            self.report_resumed(order.session_id, order.fence, &store, r);
        }
        let sup = Arc::clone(self);
        let (session, fence) = (order.session_id, order.fence);
        tokio::spawn(async move {
            let inputs = Inputs {
                rx: input_rx,
                waiting,
                approvals: approvals_rx,
                toolbelt,
                checkpoints,
                replicated,
            };
            match run(&sup, session, fence, child, inputs, store, resumed).await {
                Some(detail) => sup.finish(session, fence, token.as_deref(), detail),
                None => sup.let_go(session, fence, token.as_deref()),
            }
            // P2e-1 — only now: a start at a newer fence launches once this
            // run has removed all it will.
            drop(gone_tx);
        });
        Ok(())
    }

    /// Spawn the harness as the session's account, through the wrapper; with
    /// the sidecar, also the model token this run holds; and the session's
    /// toolbelt, bound before the harness starts because the harness
    /// connects to it as it starts.
    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        &self,
        order: &StartOrder,
        account: &str,
        folder: &Path,
        sidecar: Option<u16>,
        approvals: mpsc::Sender<ApprovalEvent>,
        memory: Option<&CoreMemory>,
        note: Option<&str>,
    ) -> Result<Spawned, (HiveRefusal, String)> {
        // The account the session runs as: its home, its toolbelt socket's ids
        // (`None`: it runs as the daemon), and the groups the SESSION holds,
        // without its administrator groups (decision 13): what the relay needs.
        let (home, owner, uid, groups) = match &self.launcher {
            Launcher::AsMappedAccount => {
                let home =
                    crate::exec::account_home(account).map_err(|e| (HiveRefusal::NoAccount, e))?;
                let (uid, gid, mut groups) = crate::exec::session_account_ids(account)
                    .map_err(|e| (HiveRefusal::LaunchFailed, e))?;
                groups.push(gid);
                (home, Some((uid, gid)), uid, Some(groups))
            }
            #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
            Launcher::AsDaemon { home } => {
                // SAFETY: getuid reads our own credentials.
                (home.clone(), None, unsafe { libc::getuid() }, None)
            }
        };
        let harness = resolve_harness(&self.cfg, &home).ok_or_else(|| {
            (
                HiveRefusal::HarnessMissing,
                "Claude Code was not found (set hive_harness, or install it in ~/.local/bin, \
                 /usr/local/bin or /usr/bin)"
                    .to_string(),
            )
        })?;
        let sid = order.session_id.to_hex();
        // P3-4b — the vault tools, where the primary connection takes leases:
        // offered by the toolbelt and allowed in the settings, together.
        let vault = toolbelt::daemon_vault();
        // FR-90 P3-7-3c — and a session's own egress, where the owner offers it.
        #[cfg(feature = "vault")]
        let net = self.net_hub(vault.is_some());
        #[cfg(feature = "vault")]
        let net_tools = net.is_some();
        #[cfg(not(feature = "vault"))]
        let net_tools = false;
        // FR-90 P3-8-2b-2 — and `ssh_run`, where the owner offers it.
        #[cfg(all(feature = "vault", feature = "ssh-server"))]
        let ssh = self.ssh_runner(vault.is_some());
        #[cfg(all(feature = "vault", feature = "ssh-server"))]
        let ssh_tools = ssh.is_some();
        #[cfg(not(all(feature = "vault", feature = "ssh-server")))]
        let ssh_tools = false;
        let settings = write_settings(&self.runtime, &sid, vault.is_some(), net_tools, ssh_tools)
            .map_err(|e| {
            (
                HiveRefusal::LaunchFailed,
                format!("writing the session settings: {e}"),
            )
        })?;
        // P1a — the toolbelt, whose `approve` is the session's permission
        // tool: every tool call that needs one waits for a driver. Its relay
        // is this binary, started by the harness AS THE SESSION'S ACCOUNT:
        // one that account cannot run leaves the session without its
        // permission tool, and its first tool call ends it ("MCP tool …
        // not found") — far from the cause. Refused here, in words (field,
        // 2026-10-08: a daemon run from a 0750 home).
        let relay = own_exe().map_err(|e| (HiveRefusal::LaunchFailed, e))?;
        if let Some(groups) = &groups
            && !executable_by(Path::new(&relay), uid, groups)
        {
            return Err((
                HiveRefusal::LaunchFailed,
                format!(
                    "{account} cannot run {relay}, the session's toolbelt relay — install \
                     roomlerd where every account may execute it"
                ),
            ));
        }
        let dir = self.runtime.join(&sid);
        let run = toolbelt::Run {
            session: order.session_id,
            fence: order.fence,
            vault,
            // P3-4c-1 — `vault_exec` runs as the session does: its account,
            // dropped as decision 13 drops it, its home, its folder.
            #[cfg(feature = "vault")]
            exec: Some(super::vault_exec::ExecTarget {
                account: matches!(self.launcher, Launcher::AsMappedAccount)
                    .then(|| account.to_string()),
                home: home.clone(),
                folder: folder.to_path_buf(),
                // P3-4c-2 — `vault_render`'s files go under this run's own
                // directory, handed to the session's account.
                session_dir: dir.clone(),
                owner,
            }),
            #[cfg(feature = "vault")]
            net,
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            ssh,
        };
        let toolbelt = toolbelt::open(&dir, owner, uid, run, approvals, self.approval_timing)
            .map_err(|e| {
                (
                    HiveRefusal::LaunchFailed,
                    format!("opening the session's toolbelt: {e}"),
                )
            })?;
        let mcp = toolbelt_mcp_config(
            &relay,
            &[
                toolbelt::RELAY_SUBCOMMAND.to_string(),
                toolbelt.socket().to_string_lossy().into_owned(),
            ],
            toolbelt::TOOL_TIMEOUT_MS,
        );
        let mcp_config = write_doc(&dir, "mcp.json", &mcp).map_err(|e| {
            (
                HiveRefusal::LaunchFailed,
                format!("writing the session's MCP config: {e}"),
            )
        })?;
        let mut spec = LaunchSpec {
            session: order.harness_session.clone(),
            harness,
            folder: folder.to_path_buf(),
            state_dir: session_state_dir(&home, &sid),
            settings,
            mcp_config: Some(mcp_config),
            sidecar_base_url: sidecar.map(|port| format!("http://127.0.0.1:{port}/s/{sid}")),
            resume: order.resume,
            fork_of: None,
            permission_prompt_tool: Some(APPROVE_TOOL.to_string()),
            permission_mode: Some(PERMISSION_MODE.to_string()),
            disallowed_tools: DISALLOWED_TOOLS.iter().map(|t| t.to_string()).collect(),
        };
        spec.validate()
            .map_err(|e| (HiveRefusal::LaunchFailed, e.to_string()))?;
        decide_history(&mut spec, order)?;

        let mut cmd = tokio::process::Command::new("/bin/sh");
        // P1e — the core memory, into the daemon's own directory; the wrapper
        // copies it in as the account. One that cannot be written is said
        // in the log, and the session starts without it.
        // P2e-7 — the resume note, for the `SessionStart` hook to print; any
        // other launch leaves none, so a restart's resume adds nothing.
        leave_note(&dir, note, owner, order.session_id);
        let memory_dir = memory.and_then(|m| match write_memory(&dir, m, owner) {
            Ok(d) => Some(d),
            Err(e) => {
                warn!(session = %order.session_id, %e, "hive: core memory not written — the session starts without it");
                None
            }
        });
        cmd.arg("-c")
            .arg(WRAPPER)
            .arg("roomler-hive")
            .arg(spec.config_dir())
            .arg(&spec.folder)
            .arg(
                memory_dir
                    .as_deref()
                    .map_or_else(Default::default, |d| d.as_os_str().to_os_string()),
            )
            .arg(spec.auto_memory_dir())
            .arg(&spec.harness)
            .args(spec.args());
        // A clean environment: none of the daemon's (root's, with its
        // ROOMLERD_* knobs) reaches a user's session.
        let path = harness_path(&home);
        cmd.env_clear()
            .envs(unix_base_env(&home, account, Some(&path)))
            .envs(spec.env_overrides());
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            // Its own process group, so a stop reaches the tools it started.
            .process_group(0);
        // P2b-3b — a replicated session checkpoints each turn's end, as its
        // account, with the harness's own PATH so its `git` is found. Built
        // for every session: P2c-4's primary join can make one replicated
        // while it runs.
        let checkpoints = super::checkpointer::Checkpoints::new(
            self.checkpoint_runner(),
            super::checkpointer::Place {
                runtime_dir: dir.clone(),
                account: matches!(self.launcher, Launcher::AsMappedAccount)
                    .then(|| account.to_string()),
                owner,
                env: unix_base_env(&home, account, Some(&path)),
                harness_session: spec.session.clone(),
                fork_of: order.fork_of.as_ref().map(|f| f.harness_session.clone()),
                config_dir: spec.config_dir(),
                folder: spec.folder.clone(),
                state_dir: spec.state_dir.clone(),
            },
        );
        match &self.launcher {
            // The one privilege path exec, SSH and the PTY share (verified,
            // uid 0 refused), as an agent session runs (decision 13): none of
            // the account's administrator groups, and on Linux no privilege
            // gained by exec, so no `sudo` whatever sudoers says of it.
            Launcher::AsMappedAccount => crate::exec::apply_session_run_as(&mut cmd, account)
                .map_err(|e| (HiveRefusal::LaunchFailed, e))?,
            #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
            Launcher::AsDaemon { .. } => {}
        }
        // The session's token, never the provider's key: good for this
        // session at this fence, through the sidecar, and nothing else.
        // Minted last, and taken back if the start fails, so no launch that
        // did not happen leaves one behind.
        let token = sidecar.map(|_| self.tokens.mint(order.session_id, order.fence));
        if let Some(token) = &token {
            cmd.env("ANTHROPIC_API_KEY", token);
        }
        match cmd.spawn() {
            Ok(child) => Ok(Spawned {
                child,
                token,
                toolbelt,
                // P2f-3a — a fork's first launch resumes its parent's.
                history: spec.resume || spec.fork_of.is_some(),
                checkpoints,
            }),
            // The toolbelt goes with the failed start: dropping it removes
            // its socket.
            Err(e) => {
                if let Some(token) = &token {
                    self.tokens.revoke(token);
                }
                Err((
                    HiveRefusal::LaunchFailed,
                    format!("starting the harness: {e}"),
                ))
            }
        }
    }

    /// P1i-2 — the same on Windows, as the user signed in at the console, whom
    /// `account` must name (D2: nobody else, never SYSTEM). `roomlerd
    /// hive-prep` does the wrapper's work as that user first. The harness then
    /// starts SUSPENDED into a Job Object of its own and is resumed only once
    /// it is in it, with the folder as its working directory.
    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        &self,
        order: &StartOrder,
        account: &str,
        folder: &Path,
        sidecar: Option<u16>,
        approvals: mpsc::Sender<ApprovalEvent>,
        memory: Option<&CoreMemory>,
        note: Option<&str>,
    ) -> Result<Spawned, (HiveRefusal, String)> {
        use crate::hive_win;
        use crate::win_service::supervisor::{JobObject, spawn_into_job};
        let failed = |what: &str, e: String| (HiveRefusal::LaunchFailed, format!("{what}: {e}"));
        // The one way on Windows: as the console user. `console` holds the
        // user's token, which `who` only borrows, until both processes run.
        let Launcher::AsMappedAccount = &self.launcher;
        let console = hive_win::console_user()?;
        hive_win::check_mapping(account, &console)?;
        let who = console.spawn_as();
        let (home, peer, appdata) = (
            console.profile.clone(),
            console.sid.clone(),
            console.appdata.clone(),
        );
        let harness =
            hive_win::resolve_harness(self.cfg.harness.as_deref(), &home, appdata.as_deref())
                .ok_or_else(|| {
                    (
                        HiveRefusal::HarnessMissing,
                        "Claude Code was not found (set hive_harness, or install it with its \
                         native installer, into %USERPROFILE%\\.local\\bin, or with npm)"
                            .to_string(),
                    )
                })?;
        let sid = order.session_id.to_hex();
        let dir = self.runtime.join(&sid);
        session_dir(&self.runtime, &dir, &peer)
            .map_err(|e| failed("the session's runtime directory", e))?;
        // P3-4b — offered and allowed together, as on Unix.
        let vault = toolbelt::daemon_vault();
        // FR-90 P3-7-3c — and a session's own egress, as on Unix.
        #[cfg(feature = "vault")]
        let net = self.net_hub(vault.is_some());
        #[cfg(feature = "vault")]
        let net_tools = net.is_some();
        #[cfg(not(feature = "vault"))]
        let net_tools = false;
        // FR-90 P3-8-2b-2 — `ssh_run` runs nothing here, so Windows offers it
        // as every other OS does.
        #[cfg(all(feature = "vault", feature = "ssh-server"))]
        let ssh = self.ssh_runner(vault.is_some());
        #[cfg(all(feature = "vault", feature = "ssh-server"))]
        let ssh_tools = ssh.is_some();
        #[cfg(not(all(feature = "vault", feature = "ssh-server")))]
        let ssh_tools = false;
        let settings = write_settings(&self.runtime, &sid, vault.is_some(), net_tools, ssh_tools)
            .map_err(|e| failed("writing the session settings", e))?;
        let relay = own_exe().map_err(|e| (HiveRefusal::LaunchFailed, e))?;
        let run = toolbelt::Run {
            session: order.session_id,
            fence: order.fence,
            vault,
            // P3-4c-1 — no command runs with a value here: Windows has no
            // sandbox for one. The vault refuses `exec` first (AC13).
            #[cfg(feature = "vault")]
            exec: None,
            #[cfg(feature = "vault")]
            net,
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            ssh,
        };
        let toolbelt = toolbelt::open(peer, run, approvals, self.approval_timing)
            .map_err(|e| failed("opening the session's toolbelt", e))?;
        let mcp = toolbelt_mcp_config(
            &relay,
            &[
                toolbelt::RELAY_SUBCOMMAND.to_string(),
                toolbelt.socket().to_string_lossy().into_owned(),
            ],
            toolbelt::TOOL_TIMEOUT_MS,
        );
        let mcp_config = write_doc(&dir, "mcp.json", &mcp)
            .map_err(|e| failed("writing the session's MCP config", e))?;
        let mut spec = LaunchSpec {
            session: order.harness_session.clone(),
            harness,
            folder: folder.to_path_buf(),
            state_dir: session_state_dir(&home, &sid),
            settings,
            mcp_config: Some(mcp_config),
            sidecar_base_url: sidecar.map(|port| format!("http://127.0.0.1:{port}/s/{sid}")),
            resume: order.resume,
            fork_of: None,
            permission_prompt_tool: Some(APPROVE_TOOL.to_string()),
            permission_mode: Some(PERMISSION_MODE.to_string()),
            disallowed_tools: DISALLOWED_TOOLS.iter().map(|t| t.to_string()).collect(),
        };
        spec.validate()
            .map_err(|e| (HiveRefusal::LaunchFailed, e.to_string()))?;
        decide_history(&mut spec, order)?;
        let line = hive_win::harness_command_line(&spec.harness, &spec.args())
            .map_err(|e| (HiveRefusal::LaunchFailed, e))?;
        // P2e-7 — as on Unix; the directory's DACL hands it to the user.
        leave_note(&dir, note, None, order.session_id);
        let memory_dir = memory.and_then(|m| match write_memory(&dir, m, None) {
            Ok(d) => Some(d),
            Err(e) => {
                warn!(session = %order.session_id, %e, "hive: core memory not written — the session starts without it");
                None
            }
        });
        // The wrapper's work, as the user: the config directory, the memory
        // copied in, the folder opened.
        let prep = hive_win::PrepArgs {
            config_dir: spec.config_dir(),
            folder: spec.folder.clone(),
            memory_dir,
            auto_memory_dir: spec.auto_memory_dir(),
        }
        .command_line(Path::new(&relay))
        .map_err(|e| (HiveRefusal::LaunchFailed, e))?;
        // SAFETY: `console` holds the token `who` names, across the call.
        let prepared =
            blocking(|| unsafe { hive_win::run_prep(who, &prep, hive_win::PREP_TIMEOUT) });
        prepared.map_err(|e| failed("preparing the session as its account", e))?;
        let job = JobObject::kill_on_close()
            .map_err(|e| failed("making the harness's job", format!("{e:#}")))?;
        let token = sidecar.map(|_| self.tokens.mint(order.session_id, order.fence));
        let mut env = spec.env_overrides();
        if let Some(token) = &token {
            env.push(("ANTHROPIC_API_KEY".into(), token.into()));
        }
        // SAFETY: `console` holds the token `who` names, across the call.
        let started = unsafe { spawn_into_job(who, &line, Some(&spec.folder), &env, true, &job) };
        drop(console);
        // P2b-3b — a replicated session checkpoints each turn's end, as the
        // console user, whom `account` names. Built for every session, as on
        // Unix.
        let checkpoints = super::checkpointer::Checkpoints::new(
            self.checkpoint_runner(),
            super::checkpointer::Place {
                runtime_dir: dir.clone(),
                account: Some(account.to_string()),
                owner: None,
                env: Vec::new(),
                harness_session: spec.session.clone(),
                fork_of: order.fork_of.as_ref().map(|f| f.harness_session.clone()),
                config_dir: spec.config_dir(),
                folder: spec.folder.clone(),
                state_dir: spec.state_dir.clone(),
            },
        );
        match started {
            Ok(child) => Ok(Spawned {
                child: hive_win::HarnessChild::new(child, job),
                token,
                toolbelt,
                // P2f-3a — a fork's first launch resumes its parent's.
                history: spec.resume || spec.fork_of.is_some(),
                checkpoints,
            }),
            Err(e) => {
                if let Some(token) = &token {
                    self.tokens.revoke(token);
                }
                Err(failed("starting the harness", format!("{e:#}")))
            }
        }
    }
}

/// P1i-2 — run `f`, which blocks for as long as a short preparation takes,
/// without stalling the other tasks of a multi-thread runtime.
#[cfg(windows)]
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// P1i-2 — a session's runtime directory on Windows, under a root that is
/// SYSTEM's and Administrators' alone; the session's own directory is also
/// readable by its account (`peer`). Each launch gives each its DACL again.
/// P1i-4 — the account may examine the two above it, and nothing more
/// ([`crate::hive_win::PRIVATE_DIR_SDDL`]): Claude Code refuses a settings
/// file whose path it cannot examine.
#[cfg(windows)]
fn session_dir(runtime: &Path, dir: &Path, peer: &str) -> Result<(), String> {
    use crate::hive_win::{PRIVATE_DIR_SDDL, dir_with_dacl, session_dir_sddl};
    if let Some(hive) = runtime.parent() {
        if let Some(base) = hive.parent() {
            std::fs::create_dir_all(base).map_err(|e| format!("{}: {e}", base.display()))?;
        }
        dir_with_dacl(hive, PRIVATE_DIR_SDDL)?;
    }
    dir_with_dacl(runtime, PRIVATE_DIR_SDDL)?;
    dir_with_dacl(dir, &session_dir_sddl(peer))
}

/// `hive_harness`, or the first default location that holds an executable
/// file.
#[cfg(unix)]
fn resolve_harness(cfg: &HiveConfig, home: &Path) -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = match &cfg.harness {
        Some(h) => vec![h.clone()],
        None => vec![
            home.join(".local/bin/claude"),
            PathBuf::from("/usr/local/bin/claude"),
            // P1h — Homebrew's prefix on Apple silicon.
            #[cfg(target_os = "macos")]
            PathBuf::from("/opt/homebrew/bin/claude"),
            PathBuf::from("/usr/bin/claude"),
        ],
    };
    candidates.into_iter().find(|p| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

/// `<runtime>/<sid>/settings.json`, daemon-owned: readable by the session,
/// writable by nobody else. A link on the way is refused, never followed.
///
/// On Windows both directories are made first, each with its DACL
/// ([`session_dir`]), and the file takes the session directory's.
fn write_settings(
    runtime: &Path,
    sid: &str,
    vault_tools: bool,
    net_tools: bool,
    ssh_tools: bool,
) -> Result<PathBuf, String> {
    let dir = runtime.join(sid);
    #[cfg(unix)]
    for d in [runtime, dir.as_path()] {
        match std::fs::symlink_metadata(d) {
            Ok(m) if !m.file_type().is_dir() => {
                return Err(format!("{} is not a plain directory", d.display()));
            }
            Ok(_) => {}
            Err(_) => std::fs::create_dir(d).map_err(|e| format!("{}: {e}", d.display()))?,
        }
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("{}: {e}", d.display()))?;
    }
    // P2e-7 — the resume note's hook: this binary, as the account, printing
    // the note when the daemon left one. Without a path to name, no hook,
    // and a moved session resumes without its note.
    let session_start_hook = own_exe()
        .ok()
        .and_then(|exe| resume_note::hook_command(&exe, &dir.join(resume_note::NOTE_FILE)));
    // P3-4c-2 — the session's secrets directory, where `vault_render`
    // writes: Claude Code's Read tool is denied there (design §4). That is
    // UX, not the gate: the permit and a person's approval are.
    #[cfg_attr(not(all(unix, feature = "vault")), allow(unused_mut))]
    let mut extra_read_denies = Vec::new();
    #[cfg(all(unix, feature = "vault"))]
    if vault_tools {
        let secrets = dir.join(super::vault_render::SECRETS_DIR);
        extra_read_denies.push(format!("Read(/{}/**)", secrets.display()));
    }
    // P0e — the key helper is the DAEMON's (the sidecar runs it); the session
    // has no `apiKeyHelper`, so nothing in it can print the provider's key.
    let doc = SettingsSpec {
        api_key_helper: None,
        auto_memory_directory: None,
        sandbox_proxy: None,
        extra_read_denies,
        session_start_hook,
        // P3-4b — the vault's reads need no person: their gate is the
        // vault's own `secret:list`, decided and recorded by the server; and
        // (P3-4c-3) neither does asking a lease ahead, which hands nothing.
        allow_tools: vault_allow_tools(vault_tools),
        // P3-4c — and each of its uses asks one, whatever a repository's
        // own settings allow; so does each egress listener (P3-7-3c), and
        // each command run on another device (P3-8-2b-2).
        ask_tools: vault_use_tools(vault_tools, net_tools, ssh_tools),
    }
    .to_json();
    write_doc(&dir, "settings.json", &doc)
}

/// FR-90 P3-4b — the tools a session's settings allow without a person,
/// wherever the vault tools are offered: the vault's reads, and (P3-4c-3)
/// asking a lease ahead. Each is decided and recorded by the vault itself,
/// and none hands the session a value.
fn vault_allow_tools(vault_tools: bool) -> Vec<String> {
    if !vault_tools {
        return Vec::new();
    }
    #[cfg_attr(not(feature = "vault"), allow(unused_mut))]
    let mut tools = toolbelt::VAULT_TOOLS.map(String::from).to_vec();
    #[cfg(feature = "vault")]
    tools.extend(toolbelt::VAULT_AHEAD_TOOLS.map(String::from));
    tools
}

/// FR-90 P3-4c — the tools a session's settings ask a person for on every
/// call: the vault's uses, wherever the vault tools are offered.
///
/// FR-90 P3-7-3c — and a session's own egress, wherever it is offered: each
/// call opens a listener the session reaches a network through.
///
/// FR-90 P3-8-2b-2 — and `ssh_run`, wherever it is offered: each call runs a
/// command on another device, as whatever account that device maps.
fn vault_use_tools(vault_tools: bool, net_tools: bool, ssh_tools: bool) -> Vec<String> {
    #[cfg(feature = "vault")]
    if vault_tools {
        let mut ask: Vec<String> = toolbelt::VAULT_USE_TOOLS.map(String::from).to_vec();
        if net_tools {
            ask.extend(toolbelt::NET_TOOLS.map(String::from));
        }
        if ssh_tools {
            ask.extend(toolbelt::SSH_TOOLS.map(String::from));
        }
        return ask;
    }
    #[cfg(not(feature = "vault"))]
    let _ = (vault_tools, net_tools, ssh_tools);
    Vec::new()
}

/// `dir/name`, written whole (a temporary, then a rename) and `0644`: the
/// session reads it, and only the daemon writes it. `dir` is
/// [`write_settings`]'s, already made and checked.
fn write_doc(dir: &Path, name: &str, doc: &serde_json::Value) -> Result<PathBuf, String> {
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, doc.to_string()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// P1e — `<runtime>/<sid>/memory/`, daemon-owned: the snapshot's files, each
/// `0600` and handed to the session's account (`owner`; `None`: the session
/// runs as the daemon), in a `0755` directory the account cannot change. The
/// account reads them to copy them in; no other local account can, since a
/// session's `CLAUDE.md` carries its starter's own facts. A document the
/// snapshot does not carry is removed, so a file left by an earlier run can
/// never be copied for this one. A link in its place is refused, never
/// followed.
fn write_memory(dir: &Path, m: &CoreMemory, owner: Option<(u32, u32)>) -> Result<PathBuf, String> {
    let mem = dir.join("memory");
    match std::fs::symlink_metadata(&mem) {
        Ok(md) if !md.file_type().is_dir() => {
            return Err(format!("{} is not a plain directory", mem.display()));
        }
        Ok(_) => {}
        Err(_) => std::fs::create_dir(&mem).map_err(|e| format!("{}: {e}", mem.display()))?,
    }
    // On Windows it takes the session directory's DACL: the daemon's, and
    // readable by the session's account alone.
    #[cfg(unix)]
    std::fs::set_permissions(&mem, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("{}: {e}", mem.display()))?;
    for (name, body) in [("CLAUDE.md", &m.claude_md), ("MEMORY.md", &m.memory_md)] {
        match body {
            Some(text) => {
                write_private_text(&mem, name, text, owner)?;
            }
            None => match std::fs::remove_file(mem.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", mem.join(name).display())),
            },
        }
    }
    Ok(mem)
}

/// FR-90 P2e-7 — `dir`'s resume note, as [`write_private_text`] writes core
/// memory: the account's, `0600`. `None` removes one an earlier launch left.
/// One that cannot be written is said in the log: the session resumes
/// without it.
fn leave_note(dir: &Path, note: Option<&str>, owner: Option<(u32, u32)>, session: ObjectId) {
    let done = match note {
        Some(text) => write_private_text(dir, resume_note::NOTE_FILE, text, owner).map(|_| ()),
        None => match std::fs::remove_file(dir.join(resume_note::NOTE_FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        },
    };
    if let Err(e) = done {
        warn!(session = %session, %e, "hive: the resume note was not left");
    }
}

/// FR-90 P2e-7 — the last tool call `sid`'s store holds no result for, as the
/// resume note names it: a cut turn's, or one the old primary was in when it
/// went. `None` when there is none, or too much follows it to tell.
async fn last_open_call(store: &StoreHandle, sid: &str) -> Option<String> {
    const SCAN: usize = 4096;
    let used = store.last_of_kind(sid, "tool_use").await.ok()??;
    let Some(TranscriptEvent::ToolUse { id, name, input }) =
        TranscriptEvent::from_json(&used.event_json)
    else {
        return None;
    };
    let after = store.page(sid, used.seq, SCAN).await.ok()?;
    if after.len() >= SCAN {
        return None;
    }
    let answered = after.iter().any(|e| {
        matches!(
            TranscriptEvent::from_json(&e.event_json),
            Some(TranscriptEvent::ToolResult { tool_use_id, .. }) if tool_use_id == id
        )
    });
    (!answered).then(|| resume_note::describe_call(&name, &input))
}

/// P2e-5 — the checkpoints of session `sid` this device's store holds,
/// oldest first: what a copy of it is put in place from.
async fn chain_of(store: &StoreHandle, sid: &str) -> Result<Vec<Checkpoint>, String> {
    let mut chain = Vec::new();
    for env in store.of_kind(sid, "checkpoint", MAX_CHAIN).await? {
        match TranscriptEvent::from_json(&env.event_json) {
            Some(TranscriptEvent::Checkpoint(c)) => chain.push(c),
            _ => {
                return Err(format!(
                    "event {} is no checkpoint this build reads",
                    env.seq
                ));
            }
        }
    }
    Ok(chain)
}

/// P2e-5 — the folder a materialize put in place, held to `last`'s tree.
fn held_to_tree(last: &Checkpoint, done: &materializer::Done) -> Result<(), String> {
    let Some(ws) = &last.workspace else {
        return Ok(());
    };
    match &done.workspace {
        Some(placed) if placed.tree == ws.tree => Ok(()),
        Some(placed) => Err(format!(
            "the folder is at tree {}, the copy's is {}",
            placed.tree, ws.tree
        )),
        None => Err("the folder was not put in place".into()),
    }
}

/// P2f-3a — where the session a fork is made from last ran, as this device's
/// copy of it says: the folder of its newest `system/init`. `None` when the
/// copy holds none, or is not here.
async fn parent_folder(store: &StoreHandle, sid: &str) -> Option<String> {
    let init = store.last_of_kind(sid, "session_init").await.ok()??;
    match TranscriptEvent::from_json(&init.event_json) {
        Some(TranscriptEvent::SessionInit { cwd, .. }) => cwd.filter(|c| !c.is_empty()),
        _ => None,
    }
}

/// `dir/name`, whole: written to a temporary name created afresh at `0600`
/// (never through a link, nor into a file an earlier run left there),
/// handed to `owner` through the open file, then renamed into place — so it
/// is never readable by anyone else, not even while it is being written.
fn write_private_text(
    dir: &Path,
    name: &str,
    text: &str,
    owner: Option<(u32, u32)>,
) -> Result<PathBuf, String> {
    use std::io::Write;
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    let failed = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(failed(&tmp, e)),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| failed(&tmp, e))?;
    f.write_all(text.as_bytes()).map_err(|e| failed(&tmp, e))?;
    #[cfg(unix)]
    {
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| failed(&tmp, e))?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(|e| failed(&tmp, e))?;
        }
    }
    // On Windows the directory's DACL is the handover: the file is the
    // daemon's, and readable by the session's account alone.
    #[cfg(windows)]
    let _ = owner;
    drop(f);
    std::fs::rename(&tmp, &path).map_err(|e| failed(&path, e))?;
    Ok(path)
}

/// P1e — what the transcript says about the core memory a start came with.
fn memory_note(m: &CoreMemory, shown: bool) -> String {
    if !shown {
        return format!(
            "This start came with the organization's core memory (brain revision {}); this \
             device shows none to its sessions (hive_core_memory is off).",
            m.brain_rev
        );
    }
    let mut files = Vec::new();
    if m.claude_md.is_some() {
        files.push("CLAUDE.md");
    }
    if m.memory_md.is_some() {
        files.push("the auto-memory MEMORY.md");
    }
    if files.is_empty() {
        return format!(
            "Core memory: brain revision {}, with nothing in it for this session.",
            m.brain_rev
        );
    }
    format!(
        "Core memory from the organization's brain, revision {}: {}.",
        m.brain_rev,
        files.join(" and ")
    )
}

/// Whether the account `uid` (with `groups`) may execute `path`: `x` on the
/// file and on every directory above it — by the owner's bits when it owns
/// the entry, else the group's when one of its groups does, else everyone's;
/// the kernel's order. (A POSIX ACL that grants more is not read: refusing a
/// start it would have allowed is the safe mistake.)
#[cfg(unix)]
fn executable_by(path: &Path, uid: u32, groups: &[u32]) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut entry = Some(path);
    while let Some(p) = entry {
        let Ok(m) = std::fs::metadata(p) else {
            return false;
        };
        let bit = if m.uid() == uid {
            0o100
        } else if groups.contains(&m.gid()) {
            0o010
        } else {
            0o001
        };
        if m.mode() & bit == 0 {
            return false;
        }
        entry = p.parent();
    }
    true
}

/// The daemon's own binary, which the session's MCP config names as the
/// toolbelt's relay. After a package upgrade replaced it under a running
/// daemon, Linux names the old inode `<path> (deleted)`; the path itself
/// holds the new binary, and a relay is a relay in every version.
pub(super) fn own_exe() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("locating the daemon's binary: {e}"))?;
    let path = exe
        .to_str()
        .ok_or("the daemon's binary has a path that is not UTF-8")?;
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    if !Path::new(path).is_file() {
        return Err(format!("the daemon's binary is not at {path} any more"));
    }
    Ok(path.to_string())
}

/// A session's state directory in its account's home: its config directory,
/// and a shadow repository of its folder, live there.
fn session_state_dir(home: &Path, sid: &str) -> PathBuf {
    home.join(".roomler").join("hive").join(sid)
}

/// The `PATH` a session's harness, and its children run as its account,
/// find their tools on: the account's own first.
#[cfg(unix)]
fn harness_path(home: &Path) -> String {
    format!(
        "{home}/.local/bin:{home}/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
        home = home.display()
    )
}

/// FR-90 P2f-2d — where a teleport refused for its folder's own work could
/// go instead: `<folder>-hive-<the session id's last 8 digits>`, beside it
/// (design §6.3). The last digits, not the first: those are the id's
/// timestamp, the same for sessions made in the same second. `None` for a
/// folder with no name of its own.
fn sibling_for(folder: &Path, session: ObjectId) -> Option<PathBuf> {
    let name = folder.file_name()?.to_str()?;
    let hex = session.to_hex();
    Some(folder.with_file_name(format!("{name}-hive-{}", &hex[hex.len() - 8..])))
}

/// P2e-5 — a moved session's places under its account's `home`: where its
/// harness runs from, which its copy is put in place at. P2f-3a — a fork's
/// are its own, held to its allowlist.
fn copy_dest(order: &StartOrder, home: &Path, folder: &Path) -> materializer::Dest {
    let sid = order.session_id.to_hex();
    let state_dir = session_state_dir(home, &sid);
    materializer::Dest {
        harness_session: order.harness_session.clone(),
        fork_of: order.fork_of.as_ref().map(|f| f.harness_session.clone()),
        config_dir: config_dir_in(&state_dir),
        folder: folder.to_path_buf(),
        state_dir,
        sid,
    }
}

/// P1d-2 — what a launch resumes, decided for every launch (a resume, and a
/// start the server re-sent after a crash) by the session's own history:
/// Claude Code refuses `--session-id` for an id whose history exists, and
/// `--resume` for one without. P2f-3a — a fork with no history of its own
/// yet starts from its parent's, put in place under its project name at its
/// first start (`--resume <parent> --fork-session --session-id`); one whose
/// parent's history is not here either is refused, never started empty: the
/// person asked for that conversation. The daemon only looks at the entries,
/// never reads or follows them; the harness reads them as the account.
fn decide_history(spec: &mut LaunchSpec, order: &StartOrder) -> Result<(), (HiveRefusal, String)> {
    let own = std::fs::symlink_metadata(spec.history_path()).is_ok();
    spec.resume = order.resume || own;
    spec.fork_of = order
        .fork_of
        .as_ref()
        .filter(|_| !own)
        .map(|f| f.harness_session.clone());
    // The parent's id is part of a path: held to a UUID before it is one.
    spec.validate()
        .map_err(|e| (HiveRefusal::LaunchFailed, e.to_string()))?;
    if let Some(from) = spec.parent_history_path() {
        spec.resume = false;
        if std::fs::symlink_metadata(from).is_err() {
            return Err((
                HiveRefusal::LaunchFailed,
                "the conversation this fork starts from is not on this device".to_string(),
            ));
        }
    }
    Ok(())
}

/// The turn in progress.
struct Current {
    prompted_by: Option<ObjectId>,
    steps: u32,
    started: Instant,
}

/// One session's live state, owned by its task.
///
/// A TURN is one prompt and the harness's work on it, ended by the
/// stream-json `result`. Prompts are written ONE AT A TIME: one that arrives
/// while a turn runs waits in `queued`, because the harness would queue it
/// itself and its `result` would then close the wrong turn's stub.
struct Task<'a> {
    sup: &'a Supervisor,
    session: ObjectId,
    fence: u64,
    sid: String,
    store: StoreHandle,
    stdin: Option<ChildStdin>,
    state: HiveRunState,
    count: u32,
    current: Option<Current>,
    queued: std::collections::VecDeque<(Option<Author>, String)>,
    /// `Live::waiting`: a prompt's place is given back when it BEGINS.
    waiting: Arc<AtomicUsize>,
    /// The harness process's running cost at its last turn's end. `None`
    /// until a resumed process's first turn ends (P1d-2): Claude Code takes
    /// its running total back from the history's last `cost-state`, which
    /// only a clean exit writes, so where that process starts counting is
    /// not known here, and its first turn reports no cost rather than a
    /// wrong one.
    spent: Option<f64>,
    /// P1a — the approvals open now, in the order the toolbelt reported
    /// them: the task's own view, so the run state follows the transcript.
    open_approvals: Vec<String>,
    /// P2b-3b — the session's checkpoints, taken while it is replicated.
    checkpoints: super::checkpointer::Checkpoints,
    /// P2c-4 — whether it is replicated now ([`Live::replicated`]).
    replicated: Arc<AtomicBool>,
    /// P2b-3b — a turn ended and its checkpoint is still to be taken: the
    /// run loop takes it ([`checkpoint_or_stop`]) before the next prompt
    /// begins.
    checkpoint_due: bool,
    /// P2e-4 — the drain under way, or done ([`Input::Drain`]).
    drain: Option<Draining>,
    /// P2e-4 — the toolbelt's open approvals, which a drain withdraws.
    pending: Arc<toolbelt::Pending>,
    /// P2e-4 — when a drain cuts the running turn, and the grace after.
    drain_timing: DrainTiming,
}

/// P2e-4 — a drain under way, or done, in its session's task.
struct Draining {
    /// Those waiting for its answer: a drain asked again meanwhile waits for
    /// the same one.
    replies: Vec<tokio::sync::oneshot::Sender<Drained>>,
    /// When the running turn is cut, should it not have ended by then.
    cut_at: tokio::time::Instant,
    /// When a cut turn's grace runs out, once the harness was told to stop
    /// it.
    gives_up_at: Option<tokio::time::Instant>,
    /// A checkpoint was kept since the drain began, with no turn after it:
    /// the turn's end's, which the drain's last one would only repeat.
    kept: bool,
    /// The answer, once given: a drain asked again is answered with it.
    answer: Option<Drained>,
}

/// P2e-4 — how a checkpoint went, for the drain that needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Checkpointed {
    Kept,
    /// Not taken; the transcript says why, on the device.
    Failed,
    /// Not started: the daemon is stopping.
    NotStarted,
}

/// P2e-4 — a drain begins in `drain`, or joins the one under way. The open
/// approvals are withdrawn at once: a turn waiting on one could not end. On
/// fields, not the task, so the checkpoint's wait can take one up too.
fn take_up_drain(
    drain: &mut Option<Draining>,
    pending: &toolbelt::Pending,
    timing: DrainTiming,
    reply: tokio::sync::oneshot::Sender<Drained>,
) {
    if let Some(d) = drain.as_mut() {
        match &d.answer {
            Some(a) => {
                let _ = reply.send(a.clone());
            }
            None => d.replies.push(reply),
        }
        return;
    }
    *drain = Some(Draining {
        replies: vec![reply],
        cut_at: tokio::time::Instant::now() + timing.cut,
        gives_up_at: None,
        kept: false,
        answer: None,
    });
    pending.withdraw_all();
}

/// P2e-4 — the lease stayed: the drain in `drain` is over, and whoever still
/// waits for its answer hears that it did not drain. `true` when one was.
fn lift_drain(drain: &mut Option<Draining>) -> bool {
    let Some(d) = drain.take() else {
        return false;
    };
    for reply in d.replies {
        let _ = reply.send(Drained::Not("the lease stayed on this device".into()));
    }
    true
}

/// P2e-4 — how Claude Code marks the end of a turn it was told to stop, as
/// a user message: `[Request interrupted by user]`, or `… for tool use]`
/// during a tool's run.
const INTERRUPTED_MARKER: &str = "[Request interrupted by user";

/// P2e-4 — Claude Code's own interrupt for the running turn, as a line of
/// its stream-json input: the control request its SDK sends. Measured on
/// 2.1.280: the model call in flight is aborted at once, a `control_response`
/// answers it, then the [`INTERRUPTED_MARKER`] and the turn's `result`
/// (`error_during_execution`), and the same process takes the next prompt.
fn interrupt_line(turn: u32) -> String {
    let mut line = serde_json::json!({
        "type": "control_request",
        "request_id": format!("hive-drain-{turn}"),
        "request": { "subtype": "interrupt" },
    })
    .to_string();
    line.push('\n');
    line
}

/// P2e-4 — sleep until `at`; never, without one.
async fn until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// What a session task is fed, and the count of prompts it holds.
struct Inputs {
    rx: mpsc::Receiver<Input>,
    waiting: Arc<AtomicUsize>,
    /// P1a — the toolbelt's approvals as they open and close.
    approvals: mpsc::Receiver<ApprovalEvent>,
    toolbelt: Toolbelt,
    /// P2b-3b — the session's checkpoints, taken while it is replicated.
    checkpoints: super::checkpointer::Checkpoints,
    /// P2c-4 — whether it is replicated now ([`Live::replicated`]).
    replicated: Arc<AtomicBool>,
}

impl Task<'_> {
    fn set_state(&mut self, state: HiveRunState) {
        if self.state != state {
            self.state = state;
            self.sup.report(self.session, self.fence, state, None);
        }
    }

    /// The state the session is in, from what it is doing: an open approval
    /// outranks a running turn, which outranks waiting for a prompt.
    fn settle_state(&mut self) {
        let state = if !self.open_approvals.is_empty() {
            HiveRunState::AwaitingApproval
        } else if self.current.is_some() {
            HiveRunState::Running
        } else {
            HiveRunState::Idle
        };
        self.set_state(state);
    }

    /// P1a — an approval opened or closed: recorded where the session's
    /// events are, in their order; the server hears THAT it did (P1a-2,
    /// `rc:hive.approval`, no tool, no arguments); the run state follows.
    fn on_approval(&mut self, ev: ApprovalEvent) {
        let opened = matches!(ev, ApprovalEvent::Opened { .. });
        let (event, id, status, answered_by) = match ev {
            ApprovalEvent::Opened {
                id,
                tool_name,
                tool_use_id,
                input,
            } => {
                self.open_approvals.push(id.clone());
                let event = TranscriptEvent::ApprovalRequested {
                    id: id.clone(),
                    tool_name,
                    tool_use_id,
                    input,
                };
                (event, id, HiveApprovalStatus::Open, None)
            }
            ApprovalEvent::Closed { id, ended } => {
                self.open_approvals.retain(|a| *a != id);
                let (status, by) = approval_outcome_of(&ended);
                (resolved(id.clone(), ended), id, status, by)
            }
        };
        // P1d-2 — an approval is on disk before the server hears it opened,
        // and comes off after it hears how it ended: lost in between, the
        // resume withdraws it again, which the server applies only to one
        // still open.
        if opened {
            self.save_open_approvals();
        }
        // P2e-4 — one that opens while the session drains is withdrawn at
        // once, as those open when the drain began were: the turn must end.
        let withdraw = (opened && self.drain.is_some()).then(|| id.clone());
        self.store.append(&self.sid, self.fence, event);
        self.report_approval(id, status, answered_by);
        if !opened {
            self.save_open_approvals();
        }
        self.settle_state();
        let _ = self
            .sup
            .approvals
            .send((self.session, self.open_approvals.clone()));
        if let Some(id) = withdraw {
            self.pending.withdraw(&id);
        }
    }

    fn save_open_approvals(&self) {
        let open = self.open_approvals.clone();
        self.sup
            .hosted_update(self.session, self.fence, |h| h.approvals = open);
    }

    /// The session is ending with approvals still open: each is recorded as
    /// withdrawn, here, because the toolbelt's own word arrives after the
    /// task that would record it is gone.
    fn withdraw_open_approvals(&mut self) {
        for id in std::mem::take(&mut self.open_approvals) {
            self.store.append(
                &self.sid,
                self.fence,
                resolved(id.clone(), toolbelt::Ended::Withdrawn),
            );
            self.report_approval(id, HiveApprovalStatus::Withdrawn, None);
        }
        let _ = self.sup.approvals.send((self.session, Vec::new()));
    }

    fn report_approval(
        &self,
        approval_id: String,
        status: HiveApprovalStatus,
        answered_by: Option<ObjectId>,
    ) {
        let turn = self.current.as_ref().map(|_| self.count);
        self.sup.report_approval(
            self.session,
            ClientMsg::HiveApproval {
                session_id: self.session,
                fence: self.fence,
                approval_id,
                turn,
                status: Some(status),
                answered_by,
            },
        );
    }

    async fn prompt(&mut self, author: Option<Author>, text: String) {
        // P2e-4 — and none begins while the session drains for a move: one
        // admitted just before the drain waits for it to be lifted.
        if self.current.is_some() || self.checkpoint_due || self.drain.is_some() {
            self.queued.push_back((author, text));
            return;
        }
        self.begin(author, text).await;
    }

    /// The next prompt waiting begins; with none, the session settles.
    async fn next_prompt(&mut self) {
        // P2e-4 — held while the session drains for a move.
        if self.drain.is_some() {
            self.settle_state();
            return;
        }
        match self.queued.pop_front() {
            Some((author, text)) => self.begin(author, text).await,
            None => self.settle_state(),
        }
    }

    /// Write one prompt and open its turn.
    async fn begin(&mut self, author: Option<Author>, text: String) {
        // Out of the waiting count whatever happens next: a prompt that
        // cannot be written is not waiting either.
        let _ = self
            .waiting
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        let Some(w) = self.stdin.as_mut() else { return };
        // P1c-2 — the model is told who asked (`[Name] …`); the transcript
        // below keeps the prompt as typed, its author beside it.
        let mut out = user_input_line(&attributed_prompt(
            author.as_ref().map(|a| a.name.as_str()),
            &text,
        ));
        out.push('\n');
        if w.write_all(out.as_bytes()).await.is_err() || w.flush().await.is_err() {
            warn!(session = %self.session, "hive: the harness stopped reading prompts");
            return;
        }
        self.count += 1;
        let prompted_by = author.as_ref().map(|a| a.user_id);
        // P1d-2 — the turn's number is on disk before its stub goes out.
        let n = self.count;
        self.sup.hosted_update(self.session, self.fence, |h| {
            h.turns = n;
            h.running = Some(RunningTurn {
                turn: n,
                prompted_by: prompted_by.map(|u| u.to_hex()),
            });
        });
        self.store.append(
            &self.sid,
            self.fence,
            TranscriptEvent::UserMessage {
                author: author.map(|a| a.name),
                text,
            },
        );
        self.current = Some(Current {
            prompted_by,
            steps: 0,
            started: Instant::now(),
        });
        self.turn_report(HiveTurnStatus::Running, None, None);
        self.settle_state();
    }

    /// Record one event; a `result` closes the turn and lets the next queued
    /// prompt in.
    async fn on_event(&mut self, mut ev: TranscriptEvent) {
        // P2e-4 — Claude Code says a turn it was told to stop was
        // interrupted "by user" (measured, 2.1.280): a drain cut it, and
        // the note before it says so.
        if self.cut()
            && matches!(&ev, TranscriptEvent::UserMessage { author: None, text }
                if text.starts_with(INTERRUPTED_MARKER))
        {
            return;
        }
        if matches!(ev, TranscriptEvent::ToolUse { .. })
            && let Some(c) = self.current.as_mut()
        {
            c.steps += 1;
        }
        // Claude Code's `total_cost_usd` is its PROCESS's running total, so
        // every `result` carries all the turns before it too (field,
        // 2026-10-07: turn 3 read $0.33 for a turn that cost $0.16). The
        // transcript and the stub both say what THIS turn cost.
        if let TranscriptEvent::Turn { cost_usd, .. } = &mut ev
            && let Some(total) = *cost_usd
        {
            debug!(session = %self.session, total, base = ?self.spent, "hive: the harness's running cost");
            *cost_usd = self
                .spent
                .map(|base| ((total - base) * 1e6).round() / 1e6)
                .map(|this_turn| this_turn.max(0.0));
            self.spent = Some(total);
        }
        let end = match &ev {
            TranscriptEvent::Turn {
                ok,
                duration_ms,
                cost_usd,
                ..
            } => Some((*ok, *duration_ms, *cost_usd)),
            _ => None,
        };
        self.store.append(&self.sid, self.fence, ev);
        if let Some((ok, duration_ms, cost_usd)) = end
            && self.current.is_some()
        {
            // P2e-4 — a turn a drain cut ends as one, whatever its result
            // says about the interrupt.
            let status = if self.cut() {
                HiveTurnStatus::Interrupted
            } else if ok {
                HiveTurnStatus::Ok
            } else {
                HiveTurnStatus::Error
            };
            let duration_ms = duration_ms.or_else(|| self.elapsed_ms());
            // P1d-2 — over before its stub says so: the server edits a stub
            // to whatever comes last, so a resume must never report a turn
            // that finished as cut.
            self.sup
                .hosted_update(self.session, self.fence, |h| h.running = None);
            self.turn_report(status, duration_ms, cost_usd);
            self.current = None;
            // P2b-3b — a replicated session's checkpoint: at the turn's end,
            // before the next prompt begins, so it holds the files as the
            // turn left them. The run loop takes it, where a stop is still
            // heard.
            if self.replicated.load(Ordering::SeqCst) {
                self.checkpoint_due = true;
            } else {
                self.next_prompt().await;
            }
        }
    }

    /// P2e-4 — a drain begins, or joins the one under way.
    fn begin_drain(&mut self, reply: tokio::sync::oneshot::Sender<Drained>) {
        if self.drain.is_none() {
            info!(
                session = %self.session, fence = self.fence,
                running = self.current.is_some(), "hive: draining for a move"
            );
        }
        take_up_drain(&mut self.drain, &self.pending, self.drain_timing, reply);
    }

    /// P2e-4 — the lease stayed: the prompts the drain held begin.
    async fn undrain(&mut self) {
        if !lift_drain(&mut self.drain) {
            return;
        }
        info!(session = %self.session, fence = self.fence, "hive: the drain is lifted");
        if self.current.is_none() && !self.checkpoint_due {
            self.next_prompt().await;
        }
    }

    /// P2e-4 — whether the drain may end: it has not answered, no turn runs
    /// and no checkpoint is due.
    fn drain_ready(&self) -> bool {
        self.drain.as_ref().is_some_and(|d| d.answer.is_none())
            && self.current.is_none()
            && !self.checkpoint_due
    }

    /// P2e-4 — the drain's answer, to everyone waiting for it. One that did
    /// not drain lifts it: the session goes on as before.
    fn answer_drain(&mut self, answer: Drained) {
        let Some(d) = self.drain.as_mut() else {
            return;
        };
        for reply in d.replies.drain(..) {
            let _ = reply.send(answer.clone());
        }
        match answer {
            Drained::Not(_) => self.drain = None,
            at @ Drained::At { .. } => d.answer = Some(at),
        }
    }

    /// P2e-4 — when the drain acts next on the running turn: the cut, then
    /// the end of its grace. `None` while no turn runs, or once it answered.
    fn drain_deadline(&self) -> Option<tokio::time::Instant> {
        let d = self.drain.as_ref()?;
        if d.answer.is_some() || self.current.is_none() {
            return None;
        }
        Some(d.gives_up_at.unwrap_or(d.cut_at))
    }

    /// P2e-4 — the drain's deadline came with the turn still running: cut
    /// it, with Claude Code's own interrupt; past the grace, the drain is
    /// refused and the turn runs on.
    async fn on_drain_deadline(&mut self) {
        let Some(gives_up_at) = self.drain.as_ref().map(|d| d.gives_up_at) else {
            return;
        };
        if self.current.is_none() {
            return;
        }
        if gives_up_at.is_some() {
            warn!(session = %self.session, turn = self.count, "hive: the cut turn did not stop — not drained");
            self.answer_drain(Drained::Not(
                "the running turn did not stop when it was told to".into(),
            ));
            return;
        }
        let grace = tokio::time::Instant::now() + self.drain_timing.grace;
        if let Some(d) = self.drain.as_mut() {
            d.gives_up_at = Some(grace);
        }
        info!(session = %self.session, turn = self.count, "hive: the running turn is cut for a move");
        self.store.append(
            &self.sid,
            self.fence,
            TranscriptEvent::Note {
                text: format!(
                    "Turn {} is cut: the session is moving to another device.",
                    self.count
                ),
            },
        );
        let line = interrupt_line(self.count);
        let Some(w) = self.stdin.as_mut() else {
            return;
        };
        if w.write_all(line.as_bytes()).await.is_err() || w.flush().await.is_err() {
            warn!(session = %self.session, "hive: the harness did not take the interrupt");
        }
    }

    /// P2e-4 — whether a drain cut the running turn.
    fn cut(&self) -> bool {
        self.drain.as_ref().is_some_and(|d| d.gives_up_at.is_some())
    }

    /// A turn the harness never finished — a stop, an exit, a crash.
    fn interrupt(&mut self) {
        if self.current.is_some() {
            let elapsed = self.elapsed_ms();
            self.turn_report(HiveTurnStatus::Interrupted, elapsed, None);
            self.current = None;
        }
    }

    fn elapsed_ms(&self) -> Option<u64> {
        self.current
            .as_ref()
            .map(|c| u64::try_from(c.started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    fn turn_report(&self, status: HiveTurnStatus, duration_ms: Option<u64>, cost_usd: Option<f64>) {
        let Some(c) = &self.current else { return };
        self.sup.report_turn(
            self.session,
            ClientMsg::HiveTurn {
                session_id: self.session,
                fence: self.fence,
                turn: self.count,
                status: Some(status),
                prompted_by: c.prompted_by,
                steps: c.steps,
                duration_ms,
                cost_usd,
            },
        );
    }
}

/// How an approval ended, as the server hears it: the word, and who
/// answered — never what was asked or what the driver said.
fn approval_outcome_of(ended: &toolbelt::Ended) -> (HiveApprovalStatus, Option<ObjectId>) {
    match ended {
        toolbelt::Ended::Answered(a) => match a.decision {
            toolbelt::Decision::Allow => (HiveApprovalStatus::Allowed, Some(a.by.user_id)),
            toolbelt::Decision::Deny { .. } => (HiveApprovalStatus::Denied, Some(a.by.user_id)),
        },
        toolbelt::Ended::Expired => (HiveApprovalStatus::Expired, None),
        toolbelt::Ended::Withdrawn => (HiveApprovalStatus::Withdrawn, None),
    }
}

/// How an approval ended, as the transcript records it.
fn resolved(id: String, ended: toolbelt::Ended) -> TranscriptEvent {
    let (outcome, by, message) = match ended {
        toolbelt::Ended::Answered(a) => match a.decision {
            toolbelt::Decision::Allow => (approval_outcome::ALLOWED, Some(a.by.name), None),
            toolbelt::Decision::Deny { message } => {
                (approval_outcome::DENIED, Some(a.by.name), message)
            }
        },
        toolbelt::Ended::Expired => (approval_outcome::EXPIRED, None, None),
        toolbelt::Ended::Withdrawn => (approval_outcome::WITHDRAWN, None, None),
    };
    TranscriptEvent::ApprovalResolved {
        id,
        outcome: outcome.to_string(),
        by,
        message,
    }
}

/// Own the session until its harness exits; return the `ended` detail —
/// or `None` when the harness went down with the daemon (P1d-2), and the
/// session is the next daemon's to resume.
async fn run(
    sup: &Supervisor,
    session: ObjectId,
    fence: u64,
    mut child: Child,
    inputs: Inputs,
    store: StoreHandle,
    resumed: Option<Resumed>,
) -> Option<String> {
    let Inputs {
        rx: mut input,
        waiting,
        mut approvals,
        toolbelt,
        checkpoints,
        replicated,
    } = inputs;
    let Some(stdout) = child.stdout.take() else {
        return Some("the harness has no stdout".into());
    };
    let stderr = child
        .stderr
        .take()
        .map(|err| tokio::spawn(read_stderr_tail(session, err)));
    let mut task = Task {
        sup,
        session,
        fence,
        sid: session.to_hex(),
        store,
        stdin: child.stdin.take(),
        state: HiveRunState::Idle,
        // P1d-2 — a resumed session counts on from its last turn: the
        // server ignores a stub for a turn older than its newest.
        count: resumed.as_ref().map_or(0, |r| r.turns),
        current: None,
        queued: Default::default(),
        waiting,
        // A process with no history counts from zero; one that resumed its
        // history, from wherever that history's last `cost-state` puts it.
        spent: match &resumed {
            Some(r) if r.history => None,
            _ => Some(0.0),
        },
        open_approvals: Vec::new(),
        checkpoints,
        replicated,
        checkpoint_due: false,
        drain: None,
        pending: toolbelt.pending(),
        drain_timing: sup.drain_timing,
    };
    let mut lines = LineReader::new(BufReader::new(stdout), MAX_LINE);
    let limits = Limits::default();
    let mut stopped: Option<String> = None;

    'session: loop {
        // P2e-4 — a drain with no turn left to wait for ends here: the last
        // checkpoint, then the store's tip.
        if task.drain_ready()
            && let Err(reason) = finish_drain(&mut task, &mut input).await
        {
            stopped = Some(reason);
            break;
        }
        tokio::select! {
            // Biased to stdout: whatever the harness already printed is
            // recorded before the next prompt goes in, so the transcript's
            // order is the order things happened — never a coin toss between
            // two ready arms.
            biased;
            read = lines.next_line() => match read {
                Ok(Some(line)) => {
                    let Ok(text) = std::str::from_utf8(&line) else { continue };
                    if text.trim().is_empty() {
                        continue;
                    }
                    match parse_line(text.trim_end(), &limits) {
                        Ok(parsed) => {
                            for ev in parsed.record {
                                task.on_event(ev).await;
                                if std::mem::take(&mut task.checkpoint_due) {
                                    match checkpoint_or_stop(&mut task, &mut input).await {
                                        Err(reason) => {
                                            stopped = Some(reason);
                                            break 'session;
                                        }
                                        // P2e-4 — the turn a drain waited
                                        // for: its checkpoint is the drain's.
                                        Ok(Checkpointed::Kept) => {
                                            if let Some(d) = task.drain.as_mut() {
                                                d.kept = true;
                                            }
                                        }
                                        Ok(_) => {}
                                    }
                                    task.next_prompt().await;
                                }
                            }
                            if !parsed.skipped.is_empty() {
                                debug!(session = %session, skipped = ?parsed.skipped, "hive: stream-json lines not recorded");
                            }
                        }
                        Err(e) => debug!(session = %session, %e, "hive: unparseable harness line"),
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(session = %session, %e, "hive: harness stdout failed");
                    break;
                }
            },
            // P1a — after stdout, so the `tool_use` the harness printed is
            // recorded before the approval it asked for. P1d-2 — not once the
            // daemon is stopping: the harness letting go then is the teardown,
            // and the next daemon records and reports the end of each
            // approval it cut, exactly once.
            Some(ev) = approvals.recv() => {
                if !sup.going_down() {
                    task.on_approval(ev);
                }
            }
            cmd = input.recv() => match cmd {
                Some(Input::Prompt { author, text }) => task.prompt(author, text).await,
                Some(Input::Stop { reason }) => {
                    stopped = Some(reason);
                    break;
                }
                Some(Input::Drain { reply }) => task.begin_drain(reply),
                Some(Input::Undrain) => task.undrain().await,
                Some(Input::Replicated) => {
                    if let Err(reason) = checkpoint_now(&mut task, &mut input).await {
                        stopped = Some(reason);
                        break;
                    }
                }
                // The supervisor let go of the session: end it.
                None => {
                    stopped = Some("supervisor".into());
                    break;
                }
            },
            // P2e-4 — last: a turn's `result` that is already there ends it
            // before its cut does.
            () = until(task.drain_deadline()) => task.on_drain_deadline().await,
        }
    }

    // P1d-2 — a harness that ended without being stopped may have gone down
    // with the daemon: systemd stops the whole unit, the daemon first and the
    // harness a moment later. Then the session is not over; it is the next
    // daemon's to resume, and this one says nothing — no `ended`, no cut
    // turn, no withdrawn approval — exactly as if it had been killed
    // outright. The next daemon reports all of it from what the device
    // hosts.
    if stopped.is_none() && sup.went_down_with_daemon().await {
        return None;
    }
    task.withdraw_open_approvals();
    task.interrupt();
    // EOF on stdin ends a stream-json harness; the signals cover one that
    // does not listen, and the tools it started.
    drop(task.stdin.take());
    if stopped.is_some() {
        terminate(&mut child).await;
    }
    let status = match tokio::time::timeout(STOP_GRACE, child.wait()).await {
        Ok(Ok(s)) => Some(s),
        _ => {
            let _ = child.start_kill();
            child.wait().await.ok()
        }
    };
    // The harness is gone; its toolbelt goes with it.
    drop(toolbelt);
    // The process is gone, so its stderr is at EOF: wait for the tail.
    let tail = match stderr {
        Some(task) => tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default(),
        None => String::new(),
    };
    // What a harness writes is the session's own output — it can echo a
    // prompt, a path, a tool's error — so its last words stay with the
    // transcript, on the device. The server hears only HOW it ended (FR-90
    // AC2; the canary test found this channel).
    let clean = status.is_some_and(|s| s.success());
    let said = stopped.is_none() && !clean && !tail.is_empty();
    if said {
        task.store.append(
            &task.sid,
            fence,
            TranscriptEvent::Note {
                text: format!("The harness's last words on stderr: {tail}"),
            },
        );
    }
    Some(describe_end(stopped.as_deref(), status, said))
}

/// P2b-3b — the checkpoint at the end of the turn that just ended, with the
/// session still listening: a prompt that arrives meanwhile waits behind it,
/// and a stop is a stop. A stop abandons the checkpoint — its child's whole
/// group is ended, and no checkpoint is recorded — and the next one takes
/// everything since the last one kept. `Err(reason)` when stopped.
///
/// ⚠️ A daemon going down says nothing (P1d-2): the child goes down with it
/// (systemd signals the whole cgroup at once), and the next daemon's next
/// checkpoint takes what this one would have. So none is started once the
/// daemon is stopping, and one that failed is said in the transcript only
/// when the daemon did not go down with it.
///
/// P2e-4 — a drain that comes meanwhile is taken up, and a lift heard: the
/// turn is over either way, and the caller sees the drain as it is now.
async fn checkpoint_or_stop(
    task: &mut Task<'_>,
    input: &mut mpsc::Receiver<Input>,
) -> Result<Checkpointed, String> {
    if task.sup.going_down() {
        return Ok(Checkpointed::NotStarted);
    }
    let taken = {
        let c = &mut task.checkpoints;
        let taking = c.after_turn(&task.store, &task.sid, task.fence, task.count);
        tokio::pin!(taking);
        loop {
            tokio::select! {
                // Biased to the checkpoint: one that is done is kept, even
                // with a stop waiting behind it.
                biased;
                taken = &mut taking => break taken,
                cmd = input.recv() => match cmd {
                    Some(Input::Prompt { author, text }) => task.queued.push_back((author, text)),
                    Some(Input::Stop { reason }) => return Err(reason),
                    Some(Input::Drain { reply }) => {
                        if task.drain.is_none() {
                            info!(session = %task.session, fence = task.fence, "hive: draining for a move, at a checkpoint");
                        }
                        take_up_drain(&mut task.drain, &task.pending, task.drain_timing, reply);
                    }
                    Some(Input::Undrain) => {
                        if lift_drain(&mut task.drain) {
                            info!(session = %task.session, fence = task.fence, "hive: the drain is lifted");
                        }
                    }
                    // P2f-1a — the checkpoint under way is the one it asks
                    // for, and its tip is told once it is kept.
                    Some(Input::Replicated) => {}
                    None => return Err("supervisor".into()),
                },
            }
        }
    };
    match taken {
        // P2c-3 — kept: the server hears where the copy ends now.
        Ok(()) => {
            task.sup.report_tip(task.session).await;
            Ok(Checkpointed::Kept)
        }
        Err(failed) => {
            if !task.sup.went_down_with_daemon().await {
                task.checkpoints
                    .say(&task.store, &task.sid, task.fence, failed);
            }
            Ok(Checkpointed::Failed)
        }
    }
}

/// FR-90 P2f-1a — a primary's join turned the running session replicated
/// ([`Input::Replicated`]). With no turn running, no checkpoint due and no
/// drain under way, its first checkpoint is taken now, and a member that
/// joins holds the session's files without waiting for its next turn to end;
/// otherwise that turn's end, or the drain, takes it. Where its copy ends is
/// told either way: a teleport waits for its target's copy to get there
/// before it drains the session. `Err(reason)` when stopped.
async fn checkpoint_now(
    task: &mut Task<'_>,
    input: &mut mpsc::Receiver<Input>,
) -> Result<(), String> {
    if task.current.is_some() || task.checkpoint_due || task.drain.is_some() {
        task.sup.report_tip(task.session).await;
        return Ok(());
    }
    match checkpoint_or_stop(task, input).await? {
        // Its tip was told as it was kept. A drain that began meanwhile
        // takes it for its own, as it takes a turn's end's.
        Checkpointed::Kept => {
            if let Some(d) = task.drain.as_mut() {
                d.kept = true;
            }
        }
        Checkpointed::Failed => task.sup.report_tip(task.session).await,
        Checkpointed::NotStarted => {}
    }
    task.next_prompt().await;
    Ok(())
}

/// P2e-4 — the drain ends, with no turn left to wait for: a replicated
/// session's last checkpoint (one its last turn's end kept since the drain
/// began will do), then the store's tip, which the server holds the member's
/// copy to. A checkpoint that is not taken is not drained: the member's copy
/// would not hold the files as the session left them. One that is lifted
/// meanwhile lets its held prompts begin. `Err(reason)` when stopped.
///
/// ⚠️ Nothing is written to the session's events after its tip is read, until
/// the drain is lifted or the run ends: the lease moves only once the
/// member's copy ends exactly there.
async fn finish_drain(
    task: &mut Task<'_>,
    input: &mut mpsc::Receiver<Input>,
) -> Result<(), String> {
    let kept = task.drain.as_ref().is_some_and(|d| d.kept);
    let taken = if task.replicated.load(Ordering::SeqCst) && !kept {
        checkpoint_or_stop(task, input).await?
    } else {
        Checkpointed::Kept
    };
    if task.drain.is_none() {
        task.next_prompt().await;
        return Ok(());
    }
    let answer = match taken {
        Checkpointed::Kept => match replica::tip_of(&task.store, task.session).await {
            Some(tip) => Drained::At {
                seq: tip.seq,
                hash: tip.hash,
            },
            None => Drained::Not("the session's copy could not be read".into()),
        },
        Checkpointed::Failed => Drained::Not("the last checkpoint was not taken".into()),
        Checkpointed::NotStarted => Drained::Not("this device is restarting".into()),
    };
    let drained = matches!(answer, Drained::At { .. });
    if drained {
        info!(session = %task.session, fence = task.fence, "hive: drained — the session waits for the move");
    }
    task.answer_drain(answer);
    if !drained {
        task.next_prompt().await;
    }
    Ok(())
}

/// Seconds since the epoch, for what the device hosts.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The last [`STDERR_TAIL`] characters a harness wrote to stderr, on one line.
async fn read_stderr_tail(session: ObjectId, err: impl AsyncRead + Unpin) -> String {
    let mut buf = Vec::new();
    let _ = err.take(1024 * 1024).read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf);
    let mut tail: Vec<char> = text.chars().rev().take(STDERR_TAIL).collect();
    tail.reverse();
    let tail: String = tail
        .into_iter()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let tail = tail.trim().to_string();
    if !tail.is_empty() {
        debug!(session = %session, stderr = %tail, "hive: harness stderr (tail)");
    }
    tail
}

/// P1h — the harness `h` records, if that very process is still running: the
/// same pid AND the same start time ([`super::procs::started`]), so whatever
/// has the pid since is never touched. A record from before P1h carries
/// neither, and nothing is done.
async fn reap_leftover(h: &HostedSession) {
    let (Some(pid), Some(was)) = (h.harness_pid, h.harness_started.as_deref()) else {
        return;
    };
    if super::procs::started(pid).as_deref() != Some(was) {
        return;
    }
    info!(session = %h.session, pid, "hive: the previous daemon left its harness running — taken down before the resume");
    super::procs::take_down(&[pid], STOP_GRACE).await;
}

/// SIGTERM to the harness's process group, then SIGKILL after the grace.
#[cfg(unix)]
async fn terminate(child: &mut Child) {
    if let Some(pid) = child.id() {
        // SAFETY: a plain syscall on a pid this task owns; the negative pid
        // addresses the group `process_group(0)` created for it.
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGTERM);
        }
    }
    if tokio::time::timeout(STOP_GRACE, child.wait())
        .await
        .is_err()
        && let Some(pid) = child.id()
    {
        // SAFETY: as above.
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
}

/// P1i-2 — on Windows no signal reaches a console-less harness. Its stdin is
/// closed already, which ends a stream-json harness; one still there after
/// the grace is ended with everything in its job.
#[cfg(windows)]
async fn terminate(child: &mut Child) {
    if tokio::time::timeout(STOP_GRACE, child.wait())
        .await
        .is_err()
    {
        let _ = child.start_kill();
    }
}

/// The `ended` detail, which the SERVER stores and posts in the session's
/// room: how the harness ended, never what it said — `said` only points at
/// the transcript, where its last words are.
fn describe_end(
    stopped: Option<&str>,
    status: Option<std::process::ExitStatus>,
    said: bool,
) -> String {
    #[cfg(unix)]
    let signal = |s: std::process::ExitStatus| {
        use std::os::unix::process::ExitStatusExt;
        s.signal()
    };
    // A Windows process always ends with a code, ended or not.
    #[cfg(windows)]
    let signal = |_: std::process::ExitStatus| None::<i32>;
    if let Some(reason) = stopped {
        return format!("stopped ({reason})");
    }
    let mut detail = match status.map(|s| (s.code(), signal(s))) {
        Some((Some(0), _)) => return "the harness exited".into(),
        Some((Some(c), _)) => format!("the harness exited with code {c}"),
        Some((None, Some(sig))) => format!("the harness was killed by signal {sig}"),
        _ => "the harness ended".into(),
    };
    if said {
        detail.push_str("; its last words are in the transcript");
    }
    detail.chars().take(hive_limits::MAX_DETAIL_LEN).collect()
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;

    /// P1h-3 — a link root made, in a directory only root writes to, is
    /// followed, where FR-85's check refuses it; a link anyone else could have
    /// made is refused, and named. The system link is macOS's own `/var`, or
    /// `/var/run` on Ubuntu: the first link this host's root owns.
    #[test]
    fn a_link_root_made_is_followed_and_any_other_refused() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let system = ["/var", "/var/run", "/lib", "/bin", "/sbin", "/tmp", "/etc"]
            .into_iter()
            .map(Path::new)
            .find(|p| {
                std::fs::symlink_metadata(p)
                    .is_ok_and(|m| m.file_type().is_symlink() && m.uid() == 0)
            });
        if let Some(link) = system {
            let under = link.join("roomler-p1h3-probe");
            assert_eq!(
                untrusted_link(&under),
                None,
                "{} is root's own",
                link.display()
            );
            assert_eq!(
                roomler_node_core::recording_dir::link_component(&under).as_deref(),
                Some(link),
                "FR-85's check, unchanged, still refuses every link"
            );
        }

        // A link in a directory anyone may write to: whoever runs this test,
        // root included, could not tell who made it.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(untrusted_link(&link.join("hive")), Some(link.clone()));
        let refused = private_dir(&link.join("hive")).unwrap_err();
        assert!(refused.contains("is a symbolic link"), "{refused}");
        assert!(!real.join("hive").exists(), "nothing made through the link");
        assert_eq!(untrusted_link(&real.join("hive")), None);
    }

    /// P1h-2 — `hive` is in the release builds, so every device starts a
    /// supervisor: one whose owner never turned agent sessions on keeps no
    /// store, while one that runs or adopts them does, and so does one that
    /// holds a store already (its transcripts are still served).
    #[test]
    fn a_device_that_never_turned_agent_sessions_on_keeps_no_store() {
        let closed = HiveConfig::closed();
        assert!(!store_wanted(&closed, false), "nothing to keep");
        assert!(store_wanted(&closed, true), "a store kept from before");
        let enabled = HiveConfig {
            enabled: true,
            ..HiveConfig::closed()
        };
        assert!(store_wanted(&enabled, false));
        let adopting = HiveConfig {
            adopt: true,
            ..HiveConfig::closed()
        };
        assert!(store_wanted(&adopting, false));
        // P2c — a replica runs nothing, but keeps the copies it holds: the
        // archive replica's container among them, whose `hive_enabled` stays
        // off.
        let replica = HiveConfig {
            replica: true,
            ..HiveConfig::closed()
        };
        assert!(store_wanted(&replica, false));
    }

    /// A stand-in for Claude Code that speaks just enough stream-json. Like
    /// the headless harness reading stream-json input, it says `init` once
    /// its first prompt arrives, then answers each prompt with a text block
    /// and a turn result. A prompt containing `crash` exits 3 with a word on
    /// stderr; `slow` takes a second; `tool` makes one tool call first;
    /// `hold` waits until the folder holds a `.release` file (and takes it),
    /// which is how a test keeps a turn running while it asks for an
    /// approval. Its `total_cost_usd`, like Claude Code's, is the PROCESS's
    /// running total: 0.25 more at every turn. Its argv is kept in the
    /// folder's `.argv`, one argument a line, every line it reads on stdin
    /// in `.stdin` — what reached the harness (P1c-2) — and its pid in
    /// `.pid`.
    ///
    /// P1e — before anything else, it copies the core memory it finds where
    /// Claude Code reads it (`$CLAUDE_CONFIG_DIR/CLAUDE.md`, the auto-memory
    /// `MEMORY.md`) to the folder's `.claude_md` and `.memory_md`: what this
    /// harness was given.
    ///
    /// P1d-2 — like Claude Code it keeps the session's history, from the
    /// first prompt on, at the path `LaunchSpec::history_path` names, and
    /// refuses the same two ways: `--session-id` for an id whose history
    /// exists, `--resume` for one without. `recall` answers with how many
    /// prompts its history holds, so a test sees what a resumed process
    /// remembers.
    ///
    /// P2e-4 — like Claude Code it takes a `control_request` on stdin and
    /// answers it with a `control_response`, never as a prompt. `CUTME` runs
    /// until its interrupt comes, then ends the turn as Claude Code 2.1.280
    /// does (measured): the response, the interrupted marker as a user
    /// message, a `result` that is an error. `DEAFME` reads its interrupt
    /// and holds on regardless, until the folder holds a `.release` file.
    ///
    /// P2f-3a — like Claude Code (2.1.296, probed) it takes `--resume <parent>
    /// --fork-session --session-id <id>`: the parent's history, under this
    /// session's pinned project name, becomes the start of `<id>`'s own at
    /// its first prompt, and the parent's is left as it was. No parent
    /// history there: "No conversation found".
    pub(crate) const FAKE_HARNESS: &str = r#"#!/bin/sh
[ -f "$CLAUDE_CONFIG_DIR/CLAUDE.md" ] && cp "$CLAUDE_CONFIG_DIR/CLAUDE.md" "$PWD/.claude_md"
[ -f "$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/memory/MEMORY.md" ] && cp "$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/memory/MEMORY.md" "$PWD/.memory_md"
printf '%s\n' "$@" > "$PWD/.argv"
echo $$ > "$PWD/.pid"
mode=""; sid=""; prev=""; parent=""; fork=""
for a in "$@"; do
  case "$prev" in --session-id|--resume) mode="$prev"; sid="$a" ;; esac
  case "$prev" in --resume) parent="$a" ;; esac
  case "$a" in --fork-session) fork=1 ;; esac
  prev="$a"
done
hist="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/$sid.jsonl"
from="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/$parent.jsonl"
if [ -n "$fork" ] && [ ! -e "$from" ]; then
  echo "No conversation found with session ID: $parent" >&2; exit 1
fi
if [ "$mode" = "--session-id" ] && [ -e "$hist" ]; then
  echo "Error: Session ID $sid is already in use." >&2; exit 1
fi
if [ "$mode" = "--resume" ] && [ ! -e "$hist" ]; then
  echo "No conversation found with session ID: $sid" >&2; exit 1
fi
first=1
spent=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$PWD/.stdin"
  case "$line" in
    *'"type":"control_request"'*)
      echo '{"type":"control_response","response":{"subtype":"success"}}'
      continue ;;
  esac
  if [ -n "$fork" ] && [ ! -e "$hist" ]; then
    mkdir -p "${hist%/*}" && cp "$from" "$hist"
  fi
  mkdir -p "${hist%/*}" && printf '%s\n' "$line" >> "$hist"
  case "$line" in
    *crash*) echo "boom" >&2; exit 3 ;;
  esac
  case "$line" in
    *recall*)
      n=$(wc -l < "$hist" | tr -d ' ')
      echo '{"type":"assistant","message":{"content":[{"type":"text","text":"history: '"$n"'"}]}}'
      ;;
  esac
  if [ "$first" = 1 ]; then
    echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
    first=0
  fi
  ok=1
  case "$line" in
    *slow*) sleep 1 ;;
    *hold*) while [ ! -e "$PWD/.release" ]; do sleep 0.05; done; rm -f "$PWD/.release" ;;
    *CUTME*)
      IFS= read -r ctl; printf '%s\n' "$ctl" >> "$PWD/.stdin"
      echo '{"type":"control_response","response":{"subtype":"success"}}'
      echo '{"type":"user","message":{"role":"user","content":[{"type":"text","text":"[Request interrupted by user]"}]}}'
      ok=0 ;;
    *DEAFME*)
      IFS= read -r ctl; printf '%s\n' "$ctl" >> "$PWD/.stdin"
      while [ ! -e "$PWD/.release" ]; do sleep 0.05; done; rm -f "$PWD/.release" ;;
  esac
  case "$line" in
    *tool*)
      echo '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}'
      echo '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"ok","is_error":false}]}}'
      ;;
  esac
  spent=$((spent + 25))
  cost=$(printf '%d.%02d' $((spent / 100)) $((spent % 100)))
  if [ "$ok" = 1 ]; then
    echo '{"type":"assistant","message":{"content":[{"type":"text","text":"hello from the fake"}]}}'
    echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":'"$cost"'}'
  else
    echo '{"type":"result","subtype":"error_during_execution","is_error":true,"num_turns":1,"duration_ms":5,"total_cost_usd":'"$cost"'}'
  fi
done
"#;

    pub(crate) struct Rig {
        pub(crate) sup: Arc<Supervisor>,
        pub(crate) store: StoreHandle,
        pub(crate) reports: mpsc::Receiver<ClientMsg>,
        pub(crate) root: tempfile::TempDir,
        pub(crate) user: ObjectId,
    }

    pub(crate) fn rig(enabled: bool, max: usize) -> Rig {
        rig_with(enabled, max, |_| {}, |s| s)
    }

    /// [`rig`], with the config and the supervisor adjusted before it runs
    /// (the sidecar's tests point it at a mock provider).
    pub(crate) fn rig_with(
        enabled: bool,
        max: usize,
        cfg_with: impl FnOnce(&mut HiveConfig),
        sup_with: impl FnOnce(Supervisor) -> Supervisor,
    ) -> Rig {
        // Under /tmp, not $TMPDIR: on macOS that is /var/folders/…/T/, about
        // 50 characters, and a session's socket (`run/<session>/toolbelt.sock`)
        // beneath it would come within a byte of `sun_path`'s 104 (P1h-1).
        let root = tempfile::Builder::new()
            .prefix("hive")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("home");
        let work = root.path().join("work");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let harness = root.path().join("claude");
        std::fs::write(&harness, FAKE_HARNESS).unwrap();
        std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
        let user = ObjectId::new();
        let mut cfg = HiveConfig {
            enabled,
            accounts: [(user.to_hex(), "dev".to_string())].into_iter().collect(),
            roots: vec![work],
            max_sessions: max,
            harness: Some(harness),
            api_key_helper: None,
            api_workspace_id: None,
            update_wait: super::gates::DEFAULT_UPDATE_WAIT,
            core_memory: false,
            adopt: false,
            allow_passwordless_sudo: false,
            replica: false,
            archive: false,
            store_quota_mib: None,
            net: false,
            ssh: false,
        };
        cfg_with(&mut cfg);
        let store = StoreHandle::spawn(None).unwrap();
        let sup = Arc::new(sup_with(Supervisor::new(
            cfg,
            root.path().join("run"),
            Launcher::AsDaemon { home },
            Ok(store.clone()),
            Hosted::load(root.path().join(HOSTED_FILE), TEST_AGENT),
        )));
        let (tx, reports) = mpsc::channel(64);
        sup.connected(tx);
        Rig {
            sup,
            store,
            reports,
            root,
            user,
        }
    }

    /// The enrollment every rig's hosted file belongs to.
    const TEST_AGENT: &str = "agent-test";

    /// P1d-2 — the rig's daemon goes down the way systemd stops it: told
    /// first, then every harness stopped by the same signal a moment later.
    async fn go_down(r: &Rig, sid: ObjectId) {
        go_down_in(r, sid, &r.root.path().join("work")).await;
    }

    /// [`go_down`], for a session whose folder is `folder`.
    async fn go_down_in(r: &Rig, sid: ObjectId, folder: &Path) {
        r.sup.begin_shutdown();
        // A turn can be `running` before the harness ran a line: the prompt
        // waits in its stdin, and an approval goes through the daemon's own
        // toolbelt.
        let pid_file = folder.join(".pid");
        let deadline = Instant::now() + Duration::from_secs(10);
        let pid: i32 = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "the harness never started");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        // SAFETY: a signal to the fake harness's own process group.
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while r.sup.holds_live(sid) {
            assert!(Instant::now() < deadline, "the session never let go");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// P1d-2 — the next daemon on the rig's device: the same hosted file,
    /// store, runtime and accounts, with `cfg_with` applied to the config.
    /// Not connected yet ([`connect`]).
    fn next_daemon(r: &mut Rig, cfg_with: impl FnOnce(&mut HiveConfig)) {
        let mut cfg = r.sup.cfg.clone();
        cfg_with(&mut cfg);
        r.sup = Arc::new(Supervisor::new(
            cfg,
            r.root.path().join("run"),
            r.sup.launcher.clone(),
            Ok(r.store.clone()),
            Hosted::load(r.root.path().join(HOSTED_FILE), TEST_AGENT),
        ));
    }

    /// A new connection of the rig's daemon; its reports replace the old.
    fn connect(r: &mut Rig) {
        let (tx, reports) = mpsc::channel(64);
        r.sup.connected(tx);
        r.reports = reports;
    }

    /// [`next_daemon`], then its first connection — which resumes what the
    /// last one hosted.
    fn restart(r: &mut Rig, cfg_with: impl FnOnce(&mut HiveConfig)) {
        next_daemon(r, cfg_with);
        connect(r);
    }

    /// Every report up to the connection's manifest, and the manifest.
    async fn until_manifest(r: &mut Rig) -> (Vec<ClientMsg>, Vec<(ObjectId, u64)>) {
        let mut seen = Vec::new();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("a manifest within 10 s")
                .expect("the connection is open");
            if let ClientMsg::HiveManifest { sessions } = &msg {
                let m = sessions.iter().map(|e| (e.session_id, e.fence)).collect();
                return (seen, m);
            }
            seen.push(msg);
        }
    }

    /// Nothing reported for `sid` in the next moment: what a daemon that
    /// went down says about a session.
    async fn silent_about(r: &mut Rig, sid: ObjectId) {
        while let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(400), r.reports.recv()).await
        {
            let about = match &msg {
                ClientMsg::HiveState { session_id, .. }
                | ClientMsg::HiveTurn { session_id, .. }
                | ClientMsg::HiveApproval { session_id, .. } => *session_id == sid,
                _ => false,
            };
            assert!(!about, "a daemon going down reports nothing: {msg:?}");
        }
    }

    /// P1d-2 — a hosted entry for `sid` on the rig's device, as a daemon
    /// that went down left it: the rig's starter, mapped to `dev`.
    fn host(r: &Rig, sid: ObjectId, f: impl FnOnce(&mut HostedSession)) {
        let o = order(r);
        let mut h = HostedSession {
            session: sid.to_hex(),
            fence: 1,
            harness: o.harness,
            harness_session: o.harness_session,
            folder: o.folder,
            account: "dev".into(),
            starter: r.user.to_hex(),
            starter_email: o.user_email,
            turns: 0,
            running: None,
            approvals: Vec::new(),
            resumed_at: None,
            quick_resumes: 0,
            harness_pid: None,
            harness_started: None,
            replicated: false,
            lease: false,
            fork_of: None,
        };
        f(&mut h);
        Hosted::load(r.root.path().join(HOSTED_FILE), TEST_AGENT).put(h);
    }

    /// Before a launch whose argv a test reads: the last one's goes. (Not a
    /// modification time: the kernel stamps files from its coarse clock,
    /// which can run behind the test's `SystemTime::now()`.)
    fn forget_argv(r: &Rig) {
        let _ = std::fs::remove_file(r.root.path().join("work").join(".argv"));
    }

    /// The fake harness's argv from the launch after [`forget_argv`].
    async fn next_argv(r: &Rig) -> Vec<String> {
        let file = r.root.path().join("work").join(".argv");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if std::fs::metadata(&file).is_ok_and(|m| m.len() > 0) {
                tokio::time::sleep(Duration::from_millis(50)).await;
                return std::fs::read_to_string(&file)
                    .unwrap()
                    .lines()
                    .map(str::to_string)
                    .collect();
            }
            assert!(Instant::now() < deadline, "the harness never started");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// What the rig's hosted file holds now, by session.
    fn hosted_on_disk(r: &Rig) -> Vec<HostedSession> {
        Hosted::load(r.root.path().join(HOSTED_FILE), TEST_AGENT)
            .sessions()
            .to_vec()
    }

    pub(crate) fn order(r: &Rig) -> StartOrder {
        StartOrder {
            session_id: ObjectId::new(),
            harness: HARNESS_CLAUDE_CODE.into(),
            harness_session: "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70".into(),
            fence: 1,
            folder: r.root.path().join("work").to_string_lossy().into(),
            user_id: r.user,
            user_email: "dev@example.com".into(),
            caller: "Dev".into(),
            resume: false,
            replicated: false,
            lease: false,
            fork_of: None,
            from_terminal: false,
        }
    }

    /// The next state reported for `session`.
    pub(crate) async fn next_state(
        r: &mut Rig,
        session: ObjectId,
    ) -> (HiveRunState, Option<String>) {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("a state report within 10 s")
                .expect("the reporter is open");
            if let ClientMsg::HiveState {
                session_id,
                state: Some(s),
                detail,
                ..
            } = msg
                && session_id == session
            {
                return (s, detail);
            }
        }
    }

    async fn until_ended(r: &mut Rig, session: ObjectId) -> Option<String> {
        loop {
            let (s, detail) = next_state(r, session).await;
            if s == HiveRunState::Ended {
                return detail;
            }
        }
    }

    /// One turn report, as the tests compare it.
    #[derive(Debug, PartialEq)]
    struct Turn {
        turn: u32,
        status: HiveTurnStatus,
        steps: u32,
        prompted_by: Option<ObjectId>,
    }

    /// Every report for `session` up to the state `until`: the turns, and
    /// the states in order.
    async fn reports_until(
        r: &mut Rig,
        session: ObjectId,
        until: HiveRunState,
    ) -> (Vec<Turn>, Vec<HiveRunState>, Vec<ClientMsg>) {
        let (mut turns, mut states, mut raw) = (Vec::new(), Vec::new(), Vec::new());
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("a report within 10 s")
                .expect("the reporter is open");
            match &msg {
                ClientMsg::HiveTurn {
                    session_id,
                    turn,
                    status: Some(status),
                    steps,
                    prompted_by,
                    ..
                } if *session_id == session => turns.push(Turn {
                    turn: *turn,
                    status: *status,
                    steps: *steps,
                    prompted_by: *prompted_by,
                }),
                ClientMsg::HiveState {
                    session_id,
                    state: Some(s),
                    ..
                } if *session_id == session => {
                    states.push(*s);
                    if *s == until {
                        raw.push(msg);
                        return (turns, states, raw);
                    }
                }
                _ => {}
            }
            raw.push(msg);
        }
    }

    pub(crate) fn dev(r: &Rig) -> Option<Author> {
        Some(Author {
            user_id: r.user,
            name: "Dev".into(),
        })
    }

    #[tokio::test]
    async fn every_closed_gate_refuses_with_its_own_word() {
        let off = rig(false, 4);
        assert_eq!(
            off.sup.start(order(&off), true).await.refused,
            Some(HiveRefusal::HiveDisabled)
        );

        let r = rig(true, 4);
        assert_eq!(
            r.sup.start(order(&r), false).await.refused,
            Some(HiveRefusal::HiveDisabled),
            "a secondary org's start"
        );

        let mut o = order(&r);
        o.user_id = ObjectId::new();
        o.user_email = "stranger@example.com".into();
        assert_eq!(
            r.sup.start(o, true).await.refused,
            Some(HiveRefusal::NoAccount)
        );

        let mut o = order(&r);
        o.folder = "/etc".into();
        assert_eq!(
            r.sup.start(o, true).await.refused,
            Some(HiveRefusal::FolderNotAllowed)
        );

        let mut o = order(&r);
        o.harness = "codex".into();
        assert_eq!(r.sup.start(o, true).await.refused, Some(HiveRefusal::Other));
        assert_eq!(r.sup.live_count(), 0, "no refusal launched anything");
    }

    /// The whole life of one session: accepted with its account, `idle`, a
    /// prompt makes it `running`, the turn's result `idle` again, a stop
    /// `ended` — and the transcript is in the store, in order.
    #[tokio::test]
    async fn a_session_runs_reports_and_records_then_stops() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert_eq!(r.sup.start(o.clone(), true).await, Answer::accepted("dev"));
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);

        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);

        // A re-sent start of the same session and fence launches nothing.
        assert_eq!(r.sup.start(o, true).await, Answer::accepted("dev"));
        assert_eq!(r.sup.live_count(), 1);

        r.sup.stop(sid, 1, "owner".into());
        assert_eq!(
            until_ended(&mut r, sid).await.as_deref(),
            Some("stopped (owner)")
        );
        assert_eq!(r.sup.live_count(), 0);
        assert!(
            hosted_on_disk(&r).is_empty(),
            "a stop leaves nothing to resume"
        );

        let events = r.store.events(&sid.to_hex());
        let kinds: Vec<&str> = events.iter().map(TranscriptEvent::kind).collect();
        assert_eq!(
            kinds,
            ["user_message", "session_init", "assistant_text", "turn"],
            "the transcript, in the order it happened"
        );
        assert!(
            matches!(&events[0], TranscriptEvent::UserMessage { author: Some(a), text } if a == "Dev" && text == "say hello")
        );
    }

    /// P2f-2c — a launch keeps where the session is worked on: the account
    /// it runs as, and the folder and state directory its checkpoints are
    /// taken in. It outlives the run, so a member is still packed for once
    /// the session ended here.
    #[tokio::test]
    async fn a_launch_keeps_where_the_session_is_worked_on() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert_eq!(r.sup.start(o, true).await, Answer::accepted("dev"));
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        let live = r.sup.workplace(sid).expect("it runs here");
        let want = roomler_hive_node::store::WorkplaceRecord {
            account: "dev".into(),
            folder: live.folder.display().to_string(),
            state_dir: live.state_dir.display().to_string(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let kept = r.store.workplace(&sid.to_hex()).await.unwrap();
            if kept.is_some() || Instant::now() > deadline {
                assert_eq!(kept.as_ref(), Some(&want), "kept at the launch");
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
        assert!(r.sup.workplace(sid).is_none(), "it no longer runs here");
        assert_eq!(
            r.store.workplace(&sid.to_hex()).await.unwrap(),
            Some(want),
            "and outlives the run"
        );
    }

    /// The `ended` detail goes to the SERVER, so it says how the harness
    /// ended and never what it wrote: its stderr can echo a prompt or a
    /// tool's output. The words stay in the transcript, on the device (AC2).
    #[tokio::test]
    async fn a_crash_ends_the_session_and_its_last_words_stay_on_the_device() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        r.sup.prompt(sid, None, "crash".into()).unwrap();
        let (turns, _, raw) = reports_until(&mut r, sid, HiveRunState::Ended).await;
        // The turn the crash cut short is reported as such, before the end.
        assert_eq!(
            turns.iter().map(|t| t.status).collect::<Vec<_>>(),
            [HiveTurnStatus::Running, HiveTurnStatus::Interrupted]
        );
        let detail = match raw.last() {
            Some(ClientMsg::HiveState {
                detail: Some(d), ..
            }) => d.clone(),
            other => panic!("expected the ended state, got {other:?}"),
        };
        assert!(detail.contains("code 3"), "{detail}");
        assert!(
            !detail.contains("boom"),
            "what the harness wrote never reaches the server: {detail}"
        );
        assert!(
            detail.contains("transcript"),
            "the detail says where the words are: {detail}"
        );
        let notes: Vec<String> = r
            .store
            .events(&sid.to_hex())
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::Note { text } => Some(text),
                _ => None,
            })
            .collect();
        assert!(
            notes.iter().any(|n| n.contains("boom")),
            "the stderr tail explains it, on the device: {notes:?}"
        );
        // P1d-2 — a harness that ends while the daemon runs ends its
        // session: there is nothing to resume.
        assert!(hosted_on_disk(&r).is_empty());
    }

    /// A turn is reported when its prompt goes in and when its result comes
    /// back — numbered, attributed, with its tool steps and what it cost.
    #[tokio::test]
    async fn a_turn_is_reported_when_it_starts_and_when_it_ends() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, dev(&r), "use a tool".into()).unwrap();
        let (turns, states, raw) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        let by = Some(r.user);
        assert_eq!(
            turns,
            [
                Turn {
                    turn: 1,
                    status: HiveTurnStatus::Running,
                    steps: 0,
                    prompted_by: by
                },
                Turn {
                    turn: 1,
                    status: HiveTurnStatus::Ok,
                    steps: 1,
                    prompted_by: by
                },
            ]
        );
        assert_eq!(states, [HiveRunState::Running, HiveRunState::Idle]);
        let ended = raw
            .iter()
            .find_map(|m| match m {
                ClientMsg::HiveTurn {
                    status: Some(HiveTurnStatus::Ok),
                    duration_ms,
                    cost_usd,
                    ..
                } => Some((*duration_ms, *cost_usd)),
                _ => None,
            })
            .unwrap();
        assert_eq!(ended, (Some(5), Some(0.25)), "the harness's own figures");
        r.sup.stop(sid, 1, "owner".into());
    }

    /// P2b-3b — a replicated session checkpoints each turn's end: the event
    /// lands after the turn's own, numbered on and built on the one before —
    /// the history from where that one left it, the folder's commit on its
    /// commit — with every blob it names kept first. A session that is not
    /// replicated records none.
    #[tokio::test]
    async fn a_replicated_session_checkpoints_each_turns_end_and_no_other_does() {
        use super::super::checkpointer::Runner;
        use roomler_hive_node::checkpoint::{Checkpoint, Growth, RepoKind};
        let mut r = rig_with(
            true,
            4,
            |_| {},
            |mut s| {
                // The rig's root is under /tmp: git's discovery stops there.
                s.checkpoint_runner = Some(Runner::InProcess {
                    ceiling: PathBuf::from("/tmp"),
                });
                s
            },
        );
        let mut o = order(&r);
        o.replicated = true;
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        std::fs::write(r.root.path().join("work").join("notes.md"), "first\n").unwrap();
        for _ in 0..2 {
            r.sup.prompt(sid, None, "hi".into()).unwrap();
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        }
        let events = r.store.events(&sid.to_hex());
        let cps: Vec<&Checkpoint> = events
            .iter()
            .filter_map(|e| match e {
                TranscriptEvent::Checkpoint(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cps.len(), 2, "one per turn");
        assert_eq!((cps[0].n, cps[0].turn), (1, 1));
        assert_eq!((cps[1].n, cps[1].turn), (2, 2));
        let kinds: Vec<&str> = events.iter().map(TranscriptEvent::kind).collect();
        let turn_end = kinds.iter().position(|k| *k == "turn").unwrap();
        let first = kinds.iter().position(|k| *k == "checkpoint").unwrap();
        assert!(first > turn_end, "after the turn's own end: {kinds:?}");
        let (w1, w2) = (
            cps[0].workspace.as_ref().expect("git on the test host"),
            cps[1].workspace.as_ref().unwrap(),
        );
        assert_eq!(
            w1.repo,
            RepoKind::Shadow,
            "the rig's folder is in no repository"
        );
        assert!(!w1.pack.is_empty());
        assert_eq!(w1.base, None, "the first commit starts the chain");
        // The fake keeps every prompt in the folder (`.stdin`), so the second
        // turn changed a file there; the commit it wrote is on the first's.
        assert_ne!(w2.commit, w1.commit);
        assert_eq!(w2.base.as_deref(), Some(w1.commit.as_str()));
        assert!(!w2.pack.is_empty());
        let history = |c: &Checkpoint| {
            c.files
                .iter()
                .find(|f| f.growth == Growth::Append && f.path.ends_with(".jsonl"))
                .cloned()
                .expect("the history is checkpointed")
        };
        let (h1, h2) = (history(cps[0]), history(cps[1]));
        assert_eq!(h1.chunks[0].offset, 0);
        assert_eq!(
            h2.chunks.iter().map(|c| c.offset).collect::<Vec<_>>(),
            [h1.len],
            "only the line the second turn appended"
        );
        for chunk in cps
            .iter()
            .flat_map(|c| c.files.iter().flat_map(|f| &f.chunks))
            .chain(&w1.pack)
            .chain(&w2.pack)
        {
            assert!(
                r.store.has_blob(&sid.to_hex(), chunk.hash.0).await.unwrap(),
                "blob {} kept",
                chunk.hash
            );
        }
        r.sup.stop(sid, 1, "owner".into());

        let o = order(&r);
        let plain = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, plain).await.0, HiveRunState::Idle);
        r.sup.prompt(plain, None, "hi".into()).unwrap();
        assert_eq!(next_state(&mut r, plain).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, plain).await.0, HiveRunState::Idle);
        assert!(
            !r.store
                .events(&plain.to_hex())
                .iter()
                .any(|e| matches!(e, TranscriptEvent::Checkpoint(_))),
            "not replicated: no checkpoint"
        );
        r.sup.stop(plain, 1, "owner".into());
    }

    /// Every report up to `sid`'s next `idle`: what one turn says.
    async fn until_idle(r: &mut Rig, sid: ObjectId) -> Vec<ClientMsg> {
        let mut seen = Vec::new();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("idle within 10 s")
                .expect("the reporter is open");
            if let ClientMsg::HiveState {
                session_id,
                state: Some(HiveRunState::Idle),
                ..
            } = &msg
                && *session_id == sid
            {
                return seen;
            }
            seen.push(msg);
        }
    }

    /// Whether `sid` runs here replicated now.
    fn runs_replicated(r: &Rig, sid: ObjectId) -> bool {
        r.sup
            .live
            .lock()
            .unwrap()
            .get(&sid)
            .is_some_and(|l| l.replicated.load(Ordering::SeqCst))
    }

    /// The checkpoints the rig's store holds for `sid`: (number, turn).
    fn checkpoints_of(r: &Rig, sid: ObjectId) -> Vec<(u64, u32)> {
        r.store
            .events(&sid.to_hex())
            .iter()
            .filter_map(|e| match e {
                TranscriptEvent::Checkpoint(c) => Some((c.n, c.turn)),
                _ => None,
            })
            .collect()
    }

    /// FR-90 P2f-1a — the next `rc:hive.replica.tip` for `sid` within 10 s,
    /// as the newest checkpoint it names (`Some(None)`: a tip naming none);
    /// `None` when no tip came, for the test's own assertion to say so.
    async fn tip_told(
        r: &mut Rig,
        sid: ObjectId,
    ) -> Option<Option<roomler_ai_remote_control::hive::HiveCheckpointMark>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let msg = tokio::time::timeout_at(deadline, r.reports.recv())
                .await
                .ok()??;
            if let ClientMsg::HiveReplicaTip {
                session_id,
                checkpoint,
                ..
            } = msg
                && session_id == sid
            {
                return Some(checkpoint);
            }
        }
    }

    /// P2c-4 — a session that started alone takes no checkpoint until its
    /// primary's join. P2f-1a — the join takes the first one at once, the
    /// session idle, and says where its copy ends with it; a join again takes
    /// none, and says where its copy ends; from then on each turn's end takes
    /// one. Its record keeps it for a restart, and the copies the device
    /// reports include it. At another fence, for a session the device does
    /// not run, or on a secondary org's connection, the join is refused and
    /// turns nothing on.
    #[tokio::test]
    async fn a_primarys_join_turns_checkpoints_on_for_a_session_already_running() {
        use super::super::checkpointer::Runner;
        use roomler_ai_remote_control::hive::{HiveJoinRefusal, HiveReplicaRole};
        let mut r = rig_with(
            true,
            4,
            |_| {},
            |mut s| {
                s.checkpoint_runner = Some(Runner::InProcess {
                    ceiling: PathBuf::from("/tmp"),
                });
                s
            },
        );
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        let checkpoints = |r: &Rig| checkpoints_of(r, sid);
        r.sup.prompt(sid, None, "alone".into()).unwrap();
        until_idle(&mut r, sid).await;
        assert!(checkpoints(&r).is_empty(), "alone: no checkpoint");
        assert!(!r.sup.reports_copies());

        let primary = Some(HiveReplicaRole::Primary);
        assert_eq!(
            r.sup.answer_join(false, sid, 1, primary, &[]).await.0,
            Some(HiveJoinRefusal::SecondaryOrg)
        );
        assert_eq!(
            r.sup
                .answer_join(true, ObjectId::new(), 1, primary, &[])
                .await
                .0,
            Some(HiveJoinRefusal::Other),
            "a session this device does not run"
        );
        assert_eq!(
            r.sup.answer_join(true, sid, 2, primary, &[]).await.0,
            Some(HiveJoinRefusal::Other),
            "a fence past the one it runs"
        );
        assert_eq!(
            r.sup.answer_join(true, sid, 0, primary, &[]).await.0,
            Some(HiveJoinRefusal::StaleFence),
            "a fence before the one it runs"
        );
        assert!(!runs_replicated(&r, sid), "a refused join turns nothing on");
        assert!(!hosted_on_disk(&r)[0].replicated);

        assert_eq!(
            r.sup.answer_join(true, sid, 1, primary, &[]).await,
            (None, None)
        );
        let told = tip_told(&mut r, sid).await;
        assert_eq!(
            checkpoints(&r),
            [(1, 1)],
            "at once, no turn running: after the turn that ran alone"
        );
        assert!(
            matches!(told, Some(Some(_))),
            "and where its copy ends, that checkpoint with it: {told:?}"
        );
        assert_eq!(
            r.sup.answer_join(true, sid, 1, primary, &[]).await,
            (None, None),
            "idempotent"
        );
        assert_eq!(
            tip_told(&mut r, sid).await,
            told,
            "a join again says where the copy ends"
        );
        assert_eq!(checkpoints(&r), [(1, 1)], "and takes no checkpoint");
        assert!(runs_replicated(&r, sid));
        assert!(r.sup.reports_copies());
        assert!(hosted_on_disk(&r)[0].replicated, "kept for a restart");
        assert!(
            store_memberships(&r).await.is_empty(),
            "the primary holds its run, never a membership"
        );

        r.sup.prompt(sid, None, "replicated".into()).unwrap();
        let seen = until_idle(&mut r, sid).await;
        assert_eq!(
            checkpoints(&r),
            [(1, 1), (2, 2)],
            "and each turn's end from then on"
        );
        assert!(
            seen.iter().any(|m| matches!(m,
                ClientMsg::HiveReplicaTip { session_id, seq, checkpoint: Some(_), .. }
                    if *session_id == sid && *seq > 0)),
            "and where its copy ends: {seen:?}"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// The memberships the rig's store keeps.
    async fn store_memberships(r: &Rig) -> Vec<String> {
        r.store
            .memberships()
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.session)
            .collect()
    }

    /// P2e-5c — a promotion's target hears its join as the primary before
    /// its start, for a session it does not run yet. It holds the session's
    /// copy, so its floor rises to the join's fence and the join is taken
    /// up; nothing runs, and nothing else is marked. One below the floor it
    /// holds, or for a session it holds nothing of, is refused.
    #[tokio::test]
    async fn a_primarys_join_ahead_of_its_start_raises_the_floor_of_its_copy() {
        use roomler_ai_remote_control::hive::{HiveJoinRefusal, HiveReplicaRole};
        use roomler_hive_node::EventEnvelope;
        let r = rig(true, 4);
        let sid = ObjectId::new();
        let s = sid.to_hex();
        let primary = Some(HiveReplicaRole::Primary);
        assert_eq!(
            r.sup.answer_join(true, sid, 2, primary, &[]).await.0,
            Some(HiveJoinRefusal::Other),
            "nothing of it held here"
        );
        assert_eq!(r.store.floor(&s).await.unwrap(), None, "nothing raised");

        // The member's copy, as it stood at the move.
        r.store.join(&s, "owner", 1).await.unwrap();
        let held = EventEnvelope::next(
            &s,
            None,
            1,
            0,
            &TranscriptEvent::Note {
                text: "held".into(),
            },
        );
        r.store.apply(held).await.unwrap();
        assert_eq!(
            r.sup.answer_join(true, sid, 2, primary, &[]).await,
            (None, None),
            "the copy is held: taken up ahead of the start"
        );
        assert_eq!(
            r.store.floor(&s).await.unwrap(),
            Some(2),
            "its floor is the new fence before it writes"
        );
        assert!(!runs_replicated(&r, sid), "nothing runs until the start");
        assert!(hosted_on_disk(&r).is_empty(), "and nothing is hosted");
        assert_eq!(
            r.sup.answer_join(true, sid, 2, primary, &[]).await,
            (None, None),
            "idempotent"
        );
        assert_eq!(
            r.sup.answer_join(true, sid, 1, primary, &[]).await.0,
            Some(HiveJoinRefusal::StaleFence),
            "below the floor it holds"
        );
    }

    /// FR-90 P2f-1a — a primary's join while a turn runs takes no checkpoint
    /// in the middle of it: it says at once where the copy ends, and the
    /// turn's end takes the first checkpoint.
    #[tokio::test]
    async fn a_primarys_join_while_a_turn_runs_says_where_the_copy_ends_and_its_end_checkpoints() {
        use roomler_ai_remote_control::hive::HiveReplicaRole;
        let mut r = moving_rig(ObjectId::new(), 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, None, "hold on".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(
            r.sup
                .answer_join(true, sid, 1, Some(HiveReplicaRole::Primary), &[])
                .await,
            (None, None)
        );
        assert_eq!(
            tip_told(&mut r, sid).await,
            Some(None),
            "where the copy ends, at once, and no checkpoint in it yet"
        );
        assert!(checkpoints_of(&r, sid).is_empty(), "none mid-turn");
        std::fs::write(r.root.path().join("work").join(".release"), "").unwrap();
        let seen = until_idle(&mut r, sid).await;
        assert_eq!(
            checkpoints_of(&r, sid),
            [(1, 1)],
            "the turn's end takes the first"
        );
        assert!(
            seen.iter().any(|m| matches!(m,
                ClientMsg::HiveReplicaTip { session_id, checkpoint: Some(_), .. }
                    if *session_id == sid)),
            "and says where the copy ends with it: {seen:?}"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2c-4 — a primary's join holds across the restart after it: the next
    /// daemon resumes the session replicated, from its record.
    #[tokio::test]
    async fn a_primarys_join_holds_across_a_restart() {
        use roomler_ai_remote_control::hive::HiveReplicaRole;
        // P2f-1a — the join checkpoints the idle session at once: in this
        // process, as the rig's own sessions do.
        let mut r = moving_rig(ObjectId::new(), 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        let primary = Some(HiveReplicaRole::Primary);
        assert_eq!(
            r.sup.answer_join(true, sid, 1, primary, &[]).await,
            (None, None)
        );
        go_down(&r, sid).await;
        restart(&mut r, |_| {});
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)], "resumed");
        assert!(runs_replicated(&r, sid), "replicated, as its record says");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2c-4 — a primary's join that reaches the next daemon before its first
    /// connection resumed the session (the server sends it at that very
    /// connection) is kept in the record the resume launches from.
    #[tokio::test]
    async fn a_primarys_join_reaches_a_session_still_to_resume() {
        use roomler_ai_remote_control::hive::HiveReplicaRole;
        let mut r = rig(true, 4);
        let sid = ObjectId::new();
        host(&r, sid, |_| {});
        next_daemon(&mut r, |_| {});
        let primary = Some(HiveReplicaRole::Primary);
        assert_eq!(
            r.sup.answer_join(true, sid, 1, primary, &[]).await,
            (None, None)
        );
        assert!(hosted_on_disk(&r)[0].replicated);
        connect(&mut r);
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)], "resumed");
        assert!(runs_replicated(&r, sid), "launched replicated");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2c-4 — a primary's join that lands while a resume launches, after
    /// the resume read the record and before the session is live, is not
    /// lost: the launch reads the record again once the session is live.
    /// (The start below is the resume, read from the record before the join
    /// changed it, as `a_start_the_server_re_sends_for_a_hosted_session_resumes_it`
    /// launches one.)
    #[tokio::test]
    async fn a_primarys_join_that_lands_while_a_resume_launches_is_kept() {
        use roomler_ai_remote_control::hive::HiveReplicaRole;
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        host(&r, sid, |_| {});
        next_daemon(&mut r, |_| {});
        assert!(!o.replicated, "the order as the resume read it");
        let primary = Some(HiveReplicaRole::Primary);
        assert_eq!(
            r.sup.answer_join(true, sid, 1, primary, &[]).await,
            (None, None)
        );
        assert!(!r.sup.holds_live(sid), "not live yet");
        assert_eq!(r.sup.start(o, true).await, Answer::accepted("dev"));
        assert!(runs_replicated(&r, sid), "the join is kept");
        connect(&mut r);
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)]);
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// A replicated session on `run`, started and idle.
    async fn replicated_on(run: super::super::checkpointer::Runner) -> (Rig, ObjectId) {
        let mut r = rig_with(
            true,
            4,
            |_| {},
            |mut s| {
                s.checkpoint_runner = Some(run);
                s
            },
        );
        let mut o = order(&r);
        o.replicated = true;
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        (r, sid)
    }

    /// P2b-3b — a checkpoint that fails is said in the transcript once per
    /// reason, not at every turn's end, and the session goes on: each prompt
    /// is answered.
    #[tokio::test]
    async fn a_failed_checkpoint_is_said_once_and_the_session_goes_on() {
        use super::super::checkpointer::Runner;
        let (mut r, sid) = replicated_on(Runner::Failing("the disk is full")).await;
        for _ in 0..2 {
            r.sup.prompt(sid, None, "hi".into()).unwrap();
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        }
        let events = r.store.events(&sid.to_hex());
        let notes: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                TranscriptEvent::Note { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(notes, ["Checkpoint 1 was not taken: the disk is full"]);
        let turns = events
            .iter()
            .filter(|e| matches!(e, TranscriptEvent::Turn { .. }))
            .count();
        assert_eq!(turns, 2, "both prompts answered");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TranscriptEvent::Checkpoint(_)))
        );
        r.sup.stop(sid, 1, "owner".into());
    }

    /// P2b-3b — a checkpoint that never finishes holds the next prompt back,
    /// never the session: a prompt sent meanwhile is not written to the
    /// harness, and a stop still stops it.
    #[tokio::test]
    async fn a_stop_is_heard_while_a_checkpoint_runs_and_a_prompt_waits_behind_it() {
        use super::super::checkpointer::Runner;
        let (mut r, sid) = replicated_on(Runner::Hangs).await;
        r.sup.prompt(sid, None, "first".into()).unwrap();
        // The turn ends; its checkpoint never does.
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("the turn ends within 10 s")
                .expect("the reporter is open");
            if let ClientMsg::HiveTurn {
                session_id,
                status: Some(HiveTurnStatus::Ok),
                ..
            } = msg
                && session_id == sid
            {
                break;
            }
        }
        r.sup.prompt(sid, None, "second".into()).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let stdin = std::fs::read_to_string(r.root.path().join("work").join(".stdin")).unwrap();
        assert!(stdin.contains("first"));
        assert!(!stdin.contains("second"), "waits behind the checkpoint");
        assert_eq!(r.sup.run_state(sid), Some(HiveRunState::Running));
        r.sup.stop(sid, 1, "owner".into());
        assert_eq!(
            until_ended(&mut r, sid).await.as_deref(),
            Some("stopped (owner)")
        );
    }

    /// Claude Code's `total_cost_usd` is its PROCESS's running total; a turn
    /// costs the difference. Field, 2026-10-07: turn 3 read $0.33 for a turn
    /// that cost $0.16.
    #[tokio::test]
    async fn each_turn_records_what_it_cost_not_the_running_total() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        for _ in 0..3 {
            r.sup.prompt(sid, None, "hi".into()).unwrap();
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        }
        let costs: Vec<f64> = r
            .store
            .events(&sid.to_hex())
            .iter()
            .filter_map(|e| match e {
                TranscriptEvent::Turn { cost_usd, .. } => *cost_usd,
                _ => None,
            })
            .collect();
        assert_eq!(
            costs,
            [0.25, 0.25, 0.25],
            "the harness said 0.25, 0.50, 0.75"
        );
        r.sup.stop(sid, 1, "owner".into());
    }

    /// A prompt that arrives while a turn runs waits for that turn's result:
    /// the harness would queue it too, and its result would then close the
    /// wrong turn. The session stays `running` across both.
    #[tokio::test]
    async fn a_prompt_during_a_turn_waits_for_it() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, dev(&r), "slow one".into()).unwrap();
        r.sup.prompt(sid, None, "second".into()).unwrap();
        let (turns, states, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert_eq!(
            turns
                .iter()
                .map(|t| (t.turn, t.status, t.prompted_by))
                .collect::<Vec<_>>(),
            [
                (1, HiveTurnStatus::Running, Some(r.user)),
                (1, HiveTurnStatus::Ok, Some(r.user)),
                (2, HiveTurnStatus::Running, None),
                (2, HiveTurnStatus::Ok, None),
            ]
        );
        assert_eq!(
            states,
            [HiveRunState::Running, HiveRunState::Idle],
            "running across both turns, idle only after the second"
        );
        let events = r.store.events(&sid.to_hex());
        let kinds: Vec<&str> = events.iter().map(TranscriptEvent::kind).collect();
        assert_eq!(
            kinds,
            [
                "user_message",
                "session_init",
                "assistant_text",
                "turn",
                "user_message",
                "assistant_text",
                "turn",
            ],
            "the second prompt went in after the first turn's result"
        );
        r.sup.stop(sid, 1, "owner".into());
    }

    /// What waits behind a running turn is bounded, and the caller is TOLD:
    /// past `MAX_WAITING` a prompt is refused, never queued without end nor
    /// dropped after an `Ok`. Every admitted prompt still runs, in order, and
    /// the places come back as they begin.
    #[tokio::test]
    async fn prompts_waiting_behind_a_turn_are_bounded_and_refused_out_loud() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, None, "slow one".into()).unwrap();
        // Turn 1 has begun (its place is back) before the rest are sent.
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("a report within 10 s")
                .expect("the reporter is open");
            if matches!(
                msg,
                ClientMsg::HiveTurn {
                    turn: 1,
                    status: Some(HiveTurnStatus::Running),
                    ..
                }
            ) {
                break;
            }
        }
        for i in 0..MAX_WAITING {
            r.sup
                .prompt(sid, None, format!("waiting {i}"))
                .unwrap_or_else(|e| panic!("prompt {i} of {MAX_WAITING} refused: {e}"));
        }
        let refused = r
            .sup
            .prompt(sid, None, "one too many".into())
            .expect_err("a prompt past the bound is refused");
        assert!(refused.contains("already waiting"), "{refused}");

        let (turns, _, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        let finished: Vec<u32> = turns
            .iter()
            .filter(|t| t.status == HiveTurnStatus::Ok)
            .map(|t| t.turn)
            .collect();
        let expected: Vec<u32> = (1..=1 + MAX_WAITING as u32).collect();
        assert_eq!(finished, expected, "every admitted prompt ran, in order");
        let texts: Vec<String> = r
            .store
            .events(&sid.to_hex())
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::UserMessage { text, .. } => Some(text),
                _ => None,
            })
            .collect();
        assert!(
            !texts.iter().any(|t| t == "one too many"),
            "the refused prompt reached the harness: {texts:?}"
        );
        // Idle again: every place is back.
        r.sup
            .prompt(sid, None, "after".into())
            .expect("an idle session takes a prompt again");
        r.sup.stop(sid, 1, "owner".into());
    }

    #[tokio::test]
    async fn capacity_is_a_refusal_and_a_stop_for_nothing_still_ends() {
        let mut r = rig(true, 1);
        let first = order(&r);
        assert!(r.sup.start(first.clone(), true).await.refused.is_none());
        assert_eq!(
            r.sup.start(order(&r), true).await.refused,
            Some(HiveRefusal::AtCapacity)
        );
        r.sup.stop(first.session_id, 1, "owner".into());
        until_ended(&mut r, first.session_id).await;

        // A stop for a session this device never ran is answered `ended`, so
        // the server's stop completes.
        let unknown = ObjectId::new();
        r.sup.stop(unknown, 1, "owner".into());
        assert_eq!(
            until_ended(&mut r, unknown).await.as_deref(),
            Some("not running on this device")
        );
    }

    /// The settings file is the daemon's: readable by the session, nobody
    /// else's to write, and naming no secret.
    #[tokio::test]
    async fn the_settings_file_is_daemon_owned_and_names_no_secret() {
        let mut r = rig(true, 4);
        let o = order(&r);
        assert!(r.sup.start(o.clone(), true).await.refused.is_none());
        let path = r
            .root
            .path()
            .join("run")
            .join(o.session_id.to_hex())
            .join("settings.json");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(doc.get("apiKeyHelper").is_none(), "none configured: {doc}");
        assert!(doc["permissions"]["deny"].to_string().contains("/proc"));
        r.sup.stop(o.session_id, 1, "owner".into());
        until_ended(&mut r, o.session_id).await;
    }

    /// FR-90 P3-4b — a session's settings allow the vault tools exactly
    /// where its toolbelt offers them, and allow nothing anywhere else.
    #[test]
    fn the_settings_allow_the_vault_tools_only_where_they_are_offered() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("run");
        let read = |sid: &str| -> serde_json::Value {
            let path = runtime.join(sid).join("settings.json");
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
        };
        write_settings(&runtime, "offered", true, false, false).unwrap();
        let offered = read("offered");
        #[cfg_attr(not(feature = "vault"), allow(unused_mut))]
        let mut allowed: Vec<&str> = toolbelt::VAULT_TOOLS.to_vec();
        // P3-4c-3 — asking a lease ahead is allowed with the reads.
        #[cfg(feature = "vault")]
        allowed.extend(toolbelt::VAULT_AHEAD_TOOLS);
        assert_eq!(offered["permissions"]["allow"], serde_json::json!(allowed));
        // P3-4c-2 — and where the vault tools are offered, the Read tool is
        // denied the session's secrets directory.
        #[cfg(feature = "vault")]
        {
            let secrets = runtime.join("offered").join("secrets");
            let rule = format!("Read(/{}/**)", secrets.display());
            assert!(
                offered["permissions"]["deny"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d == rule.as_str()),
                "{offered}"
            );
            // P3-4c — and each of the vault's uses is ASKED for: an ask
            // prompts whatever a repository's own settings allow.
            assert_eq!(
                offered["permissions"]["ask"],
                serde_json::json!(toolbelt::VAULT_USE_TOOLS),
                "{offered}"
            );
        }
        write_settings(&runtime, "not-offered", false, false, false).unwrap();
        let doc = read("not-offered");
        assert!(
            doc["permissions"].get("allow").is_none(),
            "nothing allowed: every tool call asks: {doc}"
        );
        assert!(
            doc["permissions"].get("ask").is_none(),
            "no vault use offered, none to ask for: {doc}"
        );
        assert!(
            !doc["permissions"]["deny"].to_string().contains("secrets"),
            "no secrets directory to deny: {doc}"
        );
    }

    /// FR-90 P3-7-3c — a session's own egress is ASKED for on every call,
    /// where it is offered, beside the vault's uses; never allowed outright,
    /// and absent where it is not offered.
    #[cfg(feature = "vault")]
    #[test]
    fn the_settings_ask_for_the_net_tools_where_they_are_offered() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("run");
        let read = |sid: &str| -> serde_json::Value {
            let path = runtime.join(sid).join("settings.json");
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
        };
        write_settings(&runtime, "net", true, true, false).unwrap();
        let doc = read("net");
        let mut asked: Vec<&str> = toolbelt::VAULT_USE_TOOLS.to_vec();
        asked.extend(toolbelt::NET_TOOLS);
        assert_eq!(doc["permissions"]["ask"], serde_json::json!(asked), "{doc}");
        for tool in toolbelt::NET_TOOLS {
            assert!(
                !doc["permissions"]["allow"].to_string().contains(tool),
                "{tool} is never allowed without a person: {doc}"
            );
        }
        write_settings(&runtime, "no-net", true, false, false).unwrap();
        let doc = read("no-net");
        assert!(
            !doc["permissions"]["ask"].to_string().contains("net_"),
            "not offered, not named: {doc}"
        );
    }

    /// FR-90 P3-8-2b-2 — so is `ssh_run`: asked for on every call where it is
    /// offered, after the egress tools when both are, never allowed outright,
    /// and absent where it is not offered or the vault is not.
    #[cfg(feature = "vault")]
    #[test]
    fn the_settings_ask_for_ssh_run_where_it_is_offered() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("run");
        let read = |sid: &str| -> serde_json::Value {
            let path = runtime.join(sid).join("settings.json");
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
        };
        write_settings(&runtime, "ssh", true, false, true).unwrap();
        let doc = read("ssh");
        let mut asked: Vec<&str> = toolbelt::VAULT_USE_TOOLS.to_vec();
        asked.extend(toolbelt::SSH_TOOLS);
        assert_eq!(doc["permissions"]["ask"], serde_json::json!(asked), "{doc}");
        assert!(
            !doc["permissions"]["allow"].to_string().contains("ssh_run"),
            "ssh_run is never allowed without a person: {doc}"
        );
        write_settings(&runtime, "both", true, true, true).unwrap();
        let mut asked: Vec<&str> = toolbelt::VAULT_USE_TOOLS.to_vec();
        asked.extend(toolbelt::NET_TOOLS);
        asked.extend(toolbelt::SSH_TOOLS);
        assert_eq!(read("both")["permissions"]["ask"], serde_json::json!(asked));
        for (sid, vault, ssh) in [("no-ssh", true, false), ("no-vault", false, true)] {
            write_settings(&runtime, sid, vault, false, ssh).unwrap();
            let doc = read(sid);
            assert!(
                !doc["permissions"].to_string().contains("ssh_run"),
                "not offered, not named: {doc}"
            );
        }
    }

    /// FR-90 P3-7-3c — a session's own egress opens on the daemon's primary
    /// hub, and only where the device's owner turned `hive_net` on and the
    /// vault is offered.
    #[cfg(feature = "vault")]
    #[tokio::test]
    async fn the_net_hub_is_the_owners_and_the_vaults_to_offer() {
        crate::tunnel::client_mgr::TunnelClientHub::new("test".into()).set_primary();
        let off = rig(true, 1);
        assert!(off.sup.net_hub(true).is_none(), "hive_net off");
        let on = rig_with(true, 1, |c| c.net = true, |s| s);
        assert!(
            on.sup.net_hub(true).is_some(),
            "hive_net on, the vault offered"
        );
        assert!(on.sup.net_hub(false).is_none(), "the vault not offered");
    }

    /// FR-90 P3-8-2b-2 — `ssh_run` reaches another device through the
    /// daemon's own runner, only where the device's owner turned `hive_ssh`
    /// on and the vault is offered; and a supervisor built without a runner
    /// offers it nowhere.
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    #[tokio::test]
    async fn the_ssh_runner_is_the_owners_and_the_vaults_to_offer() {
        struct Never;
        #[async_trait::async_trait]
        impl super::super::ssh_tools::SshRunner for Never {
            async fn run(
                &self,
                _: ObjectId,
                _: &crate::vault::SshTicket,
                _: &str,
                _: Duration,
            ) -> Result<super::super::ssh_tools::Ran, String> {
                Err("never run".into())
            }
        }
        let runner = |mut s: Supervisor| {
            s.ssh_runner = Some(Arc::new(Never));
            s
        };
        let off = rig_with(true, 1, |_| {}, runner);
        assert!(off.sup.ssh_runner(true).is_none(), "hive_ssh off");
        let on = rig_with(true, 1, |c| c.ssh = true, runner);
        assert!(
            on.sup.ssh_runner(true).is_some(),
            "hive_ssh on, the vault offered"
        );
        assert!(on.sup.ssh_runner(false).is_none(), "the vault not offered");
        let bare = rig_with(true, 1, |c| c.ssh = true, |s| s);
        assert!(bare.sup.ssh_runner(true).is_none(), "no runner, no tool");
        let net = rig_with(true, 1, |c| c.net = true, runner);
        assert!(
            net.sup.ssh_runner(true).is_none(),
            "hive_net is not hive_ssh"
        );
    }

    /// P3-4c-2 — the daemon's start removes every secrets directory an
    /// earlier process left, and nothing else.
    #[cfg(feature = "vault")]
    #[test]
    fn the_start_removes_the_secrets_an_earlier_process_left() {
        let root = tempfile::tempdir().unwrap();
        for sid in ["a1", "b2"] {
            let secrets = root.path().join(sid).join("secrets");
            std::fs::create_dir_all(&secrets).unwrap();
            std::fs::write(secrets.join("kubeconfig"), b"x").unwrap();
            std::fs::write(root.path().join(sid).join("settings.json"), b"{}").unwrap();
        }
        assert_eq!(super::super::vault_render::sweep(root.path()), 2);
        for sid in ["a1", "b2"] {
            assert!(!root.path().join(sid).join("secrets").exists());
            assert!(root.path().join(sid).join("settings.json").exists());
        }
        // P3-5b-2 — and every endpoint directory, the rest kept.
        let endpoint = root.path().join("a1").join("proxies").join("0123abcd");
        std::fs::create_dir_all(&endpoint).unwrap();
        std::fs::write(endpoint.join(".s.PGSQL.5432"), b"").unwrap();
        assert_eq!(super::super::vault_connect::sweep(root.path()), 1);
        assert!(!root.path().join("a1").join("proxies").exists());
        assert!(root.path().join("a1").join("settings.json").exists());
    }

    /// A reconnect replays the latest state of every session — what a dying
    /// socket swallowed.
    #[tokio::test]
    async fn a_new_connection_gets_the_latest_states_again() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        let (tx, mut again) = mpsc::channel(64);
        r.sup.connected(tx);
        match again.recv().await {
            Some(ClientMsg::HiveState {
                session_id,
                state: Some(s),
                ..
            }) => assert_eq!((session_id, s), (sid, HiveRunState::Idle)),
            other => panic!("expected a replayed state, got {other:?}"),
        }
        r.sup.stop(sid, 1, "owner".into());
    }

    /// The `rc:hive.manifest` a connection is sent, as (session, fence).
    async fn manifest_on(rx: &mut mpsc::Receiver<ClientMsg>) -> Vec<(ObjectId, u64)> {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("a manifest within 10 s")
                .expect("the connection is open");
            if let ClientMsg::HiveManifest { sessions } = msg {
                return sessions.iter().map(|e| (e.session_id, e.fence)).collect();
            }
        }
    }

    /// P1b — every connection hears which sessions run here, and only
    /// those: a session that ended is not in the list, so the server can end
    /// what a restart ended (finding 7).
    #[tokio::test]
    async fn a_new_connection_hears_which_sessions_run_here() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);

        let (tx, mut second) = mpsc::channel(64);
        r.sup.connected(tx);
        assert_eq!(manifest_on(&mut second).await, [(sid, 1)]);

        r.sup.stop(sid, 1, "owner".into());
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), second.recv())
                .await
                .expect("the stop's end within 10 s")
                .expect("open");
            if matches!(msg, ClientMsg::HiveState { session_id, state: Some(HiveRunState::Ended), .. } if session_id == sid)
            {
                break;
            }
        }
        let (tx, mut third) = mpsc::channel(64);
        r.sup.connected(tx);
        assert!(
            manifest_on(&mut third).await.is_empty(),
            "an ended session is not run here"
        );
    }

    // ─── P1a — approvals ────────────────────────────────────────────────

    use super::super::toolbelt::tests::{Client, call};
    use serde_json::json;

    pub(crate) fn toolbelt_socket(r: &Rig, sid: ObjectId) -> PathBuf {
        r.root
            .path()
            .join("run")
            .join(sid.to_hex())
            .join("toolbelt.sock")
    }

    /// Let a `hold` turn go on.
    pub(crate) fn release(r: &Rig) {
        std::fs::write(r.root.path().join("work").join(".release"), b"").unwrap();
    }

    /// Claude Code asking for one approval, as it does at a tool call: the
    /// toolbelt's handshake, then the permission prompt.
    pub(crate) async fn harness_asks(r: &Rig, sid: ObjectId, id: u64, command: &str) -> Client {
        let mut c = Client::at(&toolbelt_socket(r, sid)).await;
        c.send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"}}))
            .await;
        assert_eq!(c.recv().await["id"], 0);
        c.send(call(id, "Bash", json!({"command": command}))).await;
        c
    }

    /// The one approval open in `sid`, once the session reports it waits.
    pub(crate) async fn until_awaiting(r: &mut Rig, sid: ObjectId) -> String {
        loop {
            if next_state(r, sid).await.0 == HiveRunState::AwaitingApproval {
                break;
            }
        }
        let open = r.sup.pending_approvals(sid);
        assert_eq!(open.len(), 1, "{open:?}");
        open[0].clone()
    }

    fn approval_events(r: &Rig, sid: ObjectId) -> Vec<TranscriptEvent> {
        r.store
            .events(&sid.to_hex())
            .into_iter()
            .filter(|e| e.kind().starts_with("approval_"))
            .collect()
    }

    /// A turn that needs approval waits for a driver, `awaiting_approval`;
    /// the answer goes back to the harness; the transcript says what was
    /// asked and who answered; and the session is back at its turn.
    #[tokio::test]
    async fn an_approval_waits_for_a_driver_and_the_transcript_says_who_answered() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);

        let mut seen = r.sup.subscribe_approvals();
        let mut c = harness_asks(&r, sid, 2, "whoami").await;
        let approval = until_awaiting(&mut r, sid).await;
        assert_eq!(seen.recv().await.unwrap(), (sid, vec![approval.clone()]));

        let by = Author {
            user_id: r.user,
            name: "Dev".into(),
        };
        r.sup
            .answer_approval(sid, &approval, toolbelt::Decision::Allow, by.clone())
            .unwrap();
        assert_eq!(
            c.verdict(2).await,
            json!({"behavior": "allow", "updatedInput": {"command": "whoami"}})
        );
        assert_eq!(
            next_state(&mut r, sid).await.0,
            HiveRunState::Running,
            "back to the turn, which still runs"
        );
        assert_eq!(seen.recv().await.unwrap(), (sid, vec![]));
        assert!(
            r.sup
                .answer_approval(sid, &approval, toolbelt::Decision::Allow, by)
                .is_err(),
            "an approval is answered once"
        );

        release(&r);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert_eq!(
            approval_events(&r, sid),
            [
                TranscriptEvent::ApprovalRequested {
                    id: approval.clone(),
                    tool_name: "Bash".into(),
                    tool_use_id: Some("toolu_01FAKE".into()),
                    input: json!({"command": "whoami"}),
                },
                TranscriptEvent::ApprovalResolved {
                    id: approval,
                    outcome: approval_outcome::ALLOWED.into(),
                    by: Some("Dev".into()),
                    message: None,
                },
            ]
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// The relay check reads permissions as the kernel will for the session's
    /// account: a 0750 directory on the way stops anyone outside its group,
    /// whatever the binary's own bits say (field, 2026-10-08).
    #[test]
    fn a_relay_the_account_cannot_reach_is_not_executable_by_it() {
        use std::os::unix::fs::MetadataExt;
        // Under /tmp, opened up: the walk reads EVERY directory to the root,
        // and macOS's $TMPDIR is a 0700 per-user directory, which no other
        // account passes whatever the bits below it say (P1h-1, measured on
        // the macOS runner).
        let root = tempfile::Builder::new()
            .prefix("hive")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let bin = home.join("roomlerd");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = std::fs::metadata(&bin).unwrap();
        let (uid, gid) = (me.uid(), me.gid());
        let other = uid.wrapping_add(1);

        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(executable_by(&bin, uid, &[]), "the owner");
        assert!(
            executable_by(&bin, other, &[gid]),
            "the group, through 0750"
        );
        assert!(
            !executable_by(&bin, other, &[]),
            "anyone else is stopped at the 0750 home"
        );

        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(executable_by(&bin, other, &[]), "a 0755 path is everyone's");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(
            !executable_by(&bin, other, &[]),
            "the binary's own bits still count"
        );
        assert!(!executable_by(&home.join("absent"), uid, &[]));
    }

    /// The next `rc:hive.approval` reported for `sid`.
    async fn next_approval_frame(r: &mut Rig, sid: ObjectId) -> ClientMsg {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("a report within 10 s")
                .expect("the reporter is open");
            if matches!(&msg, ClientMsg::HiveApproval { session_id, .. } if *session_id == sid) {
                return msg;
            }
        }
    }

    /// P1a-2 — the server hears THAT an approval waits, how it ended and who
    /// answered — never the tool or what it would run — and a reconnect
    /// hears it again, so a lost end cannot leave the room's stub open.
    #[tokio::test]
    async fn the_server_hears_that_an_approval_waits_and_how_it_ended_never_what() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        let mut c = harness_asks(&r, sid, 2, "cat /etc/canary-secret").await;
        let opened = next_approval_frame(&mut r, sid).await;
        let ClientMsg::HiveApproval {
            ref approval_id,
            turn,
            status,
            answered_by,
            ..
        } = opened
        else {
            unreachable!()
        };
        assert_eq!(
            (turn, status, answered_by),
            (Some(1), Some(HiveApprovalStatus::Open), None)
        );
        let id = approval_id.clone();
        let by = Author {
            user_id: r.user,
            name: "Dev".into(),
        };
        r.sup
            .answer_approval(sid, &id, toolbelt::Decision::Allow, by)
            .unwrap();
        c.verdict(2).await;
        let ended = next_approval_frame(&mut r, sid).await;
        let wire = serde_json::to_string(&ended).unwrap();
        for word in ["canary-secret", "Bash", "command"] {
            assert!(!wire.contains(word), "the frame names {word:?}: {wire}");
        }
        assert!(matches!(
            &ended,
            ClientMsg::HiveApproval { approval_id, status: Some(HiveApprovalStatus::Allowed), answered_by: Some(u), .. }
                if *approval_id == id && *u == r.user
        ));

        let (tx, mut again) = mpsc::channel(64);
        r.sup.connected(tx);
        let mut replayed = None;
        while let Ok(Some(m)) = tokio::time::timeout(Duration::from_secs(2), again.recv()).await {
            if let ClientMsg::HiveApproval { status, .. } = m {
                replayed = status;
            }
        }
        assert_eq!(
            replayed,
            Some(HiveApprovalStatus::Allowed),
            "its newest word, again"
        );
        release(&r);
        r.sup.stop(sid, 1, "owner".into());
    }

    /// Nobody answering: the model is told so, the transcript says
    /// `expired`, and the session is back at its turn.
    #[tokio::test]
    async fn an_unanswered_approval_expires_into_a_denial() {
        let mut r = rig_with(
            true,
            4,
            |_| {},
            |s| {
                s.with_approval_timing(toolbelt::Timing {
                    timeout: Duration::from_millis(300),
                    progress_every: Duration::from_secs(30),
                })
            },
        );
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        let mut c = harness_asks(&r, sid, 3, "make deploy").await;
        let approval = until_awaiting(&mut r, sid).await;
        let v = c.verdict(3).await;
        assert_eq!(v["behavior"], "deny");
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .starts_with("Nobody answered"),
            "{v}"
        );
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        release(&r);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert!(matches!(
            approval_events(&r, sid).last(),
            Some(TranscriptEvent::ApprovalResolved { id, outcome, by: None, .. })
                if *id == approval && outcome == approval_outcome::EXPIRED
        ));
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// An approval still open when the session stops is withdrawn — in the
    /// transcript too — and the toolbelt goes with the session.
    #[tokio::test]
    async fn an_approval_open_at_a_stop_is_withdrawn_and_the_toolbelt_goes() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        let _harness = harness_asks(&r, sid, 2, "make").await;
        let approval = until_awaiting(&mut r, sid).await;
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
        assert!(
            matches!(
                approval_events(&r, sid).last(),
                Some(TranscriptEvent::ApprovalResolved { id, outcome, by: None, .. })
                    if *id == approval && outcome == approval_outcome::WITHDRAWN
            ),
            "{:?}",
            approval_events(&r, sid)
        );
        assert!(!toolbelt_socket(&r, sid).exists(), "the socket went too");
        assert!(r.sup.pending_approvals(sid).is_empty());
    }

    /// The harness is told who decides: the permission mode pinned, the
    /// toolbelt its only MCP config, its permission tool the toolbelt's
    /// `approve`; and the MCP config names the daemon's relay and the
    /// session's socket, which only the session's account may open.
    #[tokio::test]
    async fn the_launch_makes_the_toolbelt_the_one_that_decides() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        let argv_file = r.root.path().join("work").join(".argv");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !argv_file.exists() {
            assert!(Instant::now() < deadline, "the harness never started");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let argv: Vec<String> = std::fs::read_to_string(&argv_file)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let pair = |a: &str, b: &str| argv.windows(2).any(|w| w[0] == a && w[1] == b);
        assert!(pair("--permission-mode", "default"), "{argv:?}");
        assert!(
            pair("--permission-prompt-tool", "mcp__roomler__approve"),
            "{argv:?}"
        );
        assert!(
            argv.contains(&"--strict-mcp-config".to_string()),
            "{argv:?}"
        );
        assert!(pair("--disallowedTools", "AskUserQuestion"), "{argv:?}");

        let mcp_path = r
            .root
            .path()
            .join("run")
            .join(sid.to_hex())
            .join("mcp.json");
        assert!(pair("--mcp-config", mcp_path.to_str().unwrap()), "{argv:?}");
        let mcp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mcp_path).unwrap()).unwrap();
        let server = &mcp["mcpServers"]["roomler"];
        assert_eq!(
            server["args"],
            json!(["hive-mcp", toolbelt_socket(&r, sid).to_str().unwrap()])
        );
        assert!(Path::new(server["command"].as_str().unwrap()).is_file());
        let mode = std::fs::metadata(&mcp_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "the session reads it; only the daemon writes it"
        );
        let mode = std::fs::metadata(toolbelt_socket(&r, sid))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P1c-2 — the model is told who asked: the harness reads `[Name] …`,
    /// while the transcript keeps the prompt as typed, its author beside it.
    /// A slash command reaches the harness as typed.
    #[tokio::test]
    async fn a_prompt_reaches_the_harness_labelled_with_its_driver() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        for text in ["say hello", "/compact"] {
            r.sup.prompt(sid, dev(&r), text.into()).unwrap();
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
            assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        }
        let read: Vec<String> = std::fs::read_to_string(r.root.path().join("work").join(".stdin"))
            .unwrap()
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["message"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(read, ["[Dev] say hello", "/compact"]);
        let typed: Vec<(Option<String>, String)> = r
            .store
            .events(&sid.to_hex())
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::UserMessage { author, text } => Some((author, text)),
                _ => None,
            })
            .collect();
        assert_eq!(
            typed,
            [
                (Some("Dev".to_string()), "say hello".to_string()),
                (Some("Dev".to_string()), "/compact".to_string()),
            ],
            "the transcript keeps what was typed"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P1d-1 (AC7) — what an update waits for: a session mid-turn is in
    /// `turns_running`, an idle one is not. Once the update goes ahead, a new
    /// prompt and a new start are refused, while the turn already admitted
    /// runs to its end; an update that did not happen takes prompts again.
    #[tokio::test]
    async fn an_update_waits_for_turns_and_holds_new_ones() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert!(r.sup.turns_running().is_empty(), "idle is not a turn");

        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(r.sup.turns_running(), [sid]);

        r.sup.begin_update();
        let refused = r.sup.prompt(sid, dev(&r), "another".into()).unwrap_err();
        assert!(
            refused.contains("about to restart for an update"),
            "{refused}"
        );
        let start = r.sup.start(order(&r), true).await;
        assert_eq!(start.refused, Some(HiveRefusal::Other));
        assert!(
            start
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("update"),
            "{start:?}"
        );

        // The admitted turn still finishes, and is waited for no more.
        release(&r);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert!(r.sup.turns_running().is_empty());

        // The update did not happen: prompts are taken again.
        r.sup.end_update();
        r.sup.prompt(sid, dev(&r), "after".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P1c-2 — the device's own gate on a driver: the session's starter, or
    /// someone THIS device's `hive_accounts` maps to the account the session
    /// runs as; by id or by a proven address, never by an unproven one.
    #[tokio::test]
    async fn a_driver_acts_here_only_as_an_account_this_device_maps_them_to() {
        let same = ObjectId::new();
        let elsewhere = ObjectId::new();
        let mut r = rig_with(
            true,
            4,
            |c| {
                c.accounts.insert(same.to_hex(), "dev".into());
                c.accounts.insert("carol@example.com".into(), "dev".into());
                c.accounts
                    .insert("mallory@unverified.invalid".into(), "dev".into());
                c.accounts.insert(elsewhere.to_hex(), "ops".into());
            },
            |s| s,
        );
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);

        // The starter, by id from the start — even with no address at all,
        // as from a server before P1c-2.
        assert!(r.sup.drives_here(sid, r.user, None).is_ok());
        assert!(r.sup.drives_here(sid, same, None).is_ok(), "mapped by id");
        assert!(
            r.sup
                .drives_here(sid, ObjectId::new(), Some("Carol@Example.com"))
                .is_ok(),
            "mapped by a proven address"
        );
        assert!(
            r.sup
                .drives_here(sid, ObjectId::new(), Some("mallory@unverified.invalid"))
                .is_err(),
            "an unproven address maps nobody"
        );
        let other = r.sup.drives_here(sid, elsewhere, None).unwrap_err();
        assert!(other.contains("another account than dev"), "{other}");
        let nobody = r
            .sup
            .drives_here(sid, ObjectId::new(), Some("dave@example.com"))
            .unwrap_err();
        assert!(nobody.contains("no account"), "{nobody}");
        assert!(
            r.sup.drives_here(ObjectId::new(), r.user, None).is_err(),
            "a session this device does not run"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    // ─── P1d-2 — a restart resumes what the device hosted ───────────────

    /// The whole arc: a session runs a turn; the daemon goes down the way
    /// systemd stops it and reports nothing; the next daemon's first
    /// connection relaunches it with `--resume`, before a manifest that
    /// names it; the history is the harness's own; the turns count on; the
    /// first turn of the resumed process costs what nobody here can know,
    /// the next one what it cost; a stop forgets it.
    #[tokio::test]
    async fn a_restarted_daemon_resumes_what_it_hosted_and_counts_on() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let (sid, uuid) = (o.session_id, o.harness_session.clone());
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        let (turns, _, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert!(turns.iter().all(|t| t.turn == 1), "{turns:?}");
        let on_disk = hosted_on_disk(&r);
        assert_eq!(on_disk.len(), 1);
        assert_eq!((on_disk[0].turns, on_disk[0].running.as_ref()), (1, None));

        go_down(&r, sid).await;
        silent_about(&mut r, sid).await;
        assert_eq!(hosted_on_disk(&r).len(), 1, "kept for the next daemon");

        forget_argv(&r);
        restart(&mut r, |_| {});
        let (seen, manifest) = until_manifest(&mut r).await;
        assert!(
            seen.iter().any(|m| matches!(m,
                ClientMsg::HiveState { session_id, state: Some(HiveRunState::Idle), .. }
                    if *session_id == sid)),
            "resumed before the manifest: {seen:?}"
        );
        assert_eq!(manifest, [(sid, 1)], "the manifest names it");
        let argv = next_argv(&r).await;
        assert!(
            argv.windows(2).any(|w| w[0] == "--resume" && w[1] == uuid),
            "{argv:?}"
        );
        assert!(
            argv.contains(&"--mcp-config".to_string()) && argv.contains(&"--settings".to_string()),
            "rebuilt in full: {argv:?}"
        );

        r.sup.prompt(sid, dev(&r), "recall".into()).unwrap();
        let (turns, _, raw) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert!(
            !turns.is_empty() && turns.iter().all(|t| t.turn == 2),
            "counts on: {turns:?}"
        );
        let cost_of = |raw: &[ClientMsg]| {
            raw.iter().find_map(|m| match m {
                ClientMsg::HiveTurn {
                    status: Some(HiveTurnStatus::Ok),
                    cost_usd,
                    ..
                } => Some(*cost_usd),
                _ => None,
            })
        };
        assert_eq!(
            cost_of(&raw),
            Some(None),
            "a resumed process's first turn: no cost rather than a wrong one"
        );
        let events = r.store.events(&sid.to_hex());
        assert!(
            events.iter().any(
                |e| matches!(e, TranscriptEvent::AssistantText { text, .. } if text == "history: 2")
            ),
            "the resumed harness has both prompts in its history: {events:?}"
        );
        assert!(
            events.iter().any(|e| matches!(e, TranscriptEvent::Note { text } if text.starts_with("The device restarted, and this session resumed"))),
            "{events:?}"
        );

        r.sup.prompt(sid, dev(&r), "again".into()).unwrap();
        let (_, _, raw) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert_eq!(cost_of(&raw), Some(Some(0.25)), "then what each turn cost");

        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
        assert!(hosted_on_disk(&r).is_empty(), "over, so nothing to resume");
    }

    /// The fake harness's pid, which leads its process group, once it ran.
    async fn fake_pid(r: &Rig) -> u32 {
        let pid_file = r.root.path().join("work").join(".pid");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                return pid;
            }
            assert!(Instant::now() < deadline, "the harness never started");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Whether `pid`'s group is gone within a few seconds: its leader may be a
    /// zombie for a moment, until whoever spawned it reaps it.
    async fn group_gone(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while super::super::procs::group_alive(pid) {
            if Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }

    /// P1h-1 — a daemon leaving with no service manager to end its harnesses
    /// (launchd does not; nothing does for an unsupervised daemon): `wind_down`
    /// ends each harness's process group itself, and the session is kept for
    /// the next daemon, reported nowhere — the same as a stop under systemd.
    #[tokio::test]
    async fn wind_down_takes_the_harness_down_and_keeps_the_session() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        let pid = fake_pid(&r).await;
        assert!(super::super::procs::group_alive(pid));
        let on_disk = hosted_on_disk(&r);
        assert_eq!(on_disk[0].harness_pid, Some(pid), "the launch records it");
        assert_eq!(
            on_disk[0].harness_started,
            super::super::procs::started(pid),
            "with its start time"
        );

        r.sup.wind_down().await;
        assert!(group_gone(pid).await, "the harness and its group are gone");
        let deadline = Instant::now() + Duration::from_secs(10);
        while r.sup.holds_live(sid) {
            assert!(Instant::now() < deadline, "the session never let go");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        silent_about(&mut r, sid).await;
        assert_eq!(hosted_on_disk(&r).len(), 1, "kept for the next daemon");
    }

    /// P1h-1 — a crash leaves its harness running, and nothing takes it down:
    /// the next daemon does, before it resumes the session on the same
    /// history, which two harnesses would both write.
    #[tokio::test]
    async fn a_harness_a_crash_left_running_is_taken_down_before_the_resume() {
        use std::os::unix::process::CommandExt;
        let mut r = rig(true, 4);
        // The leftover: a group leader with a tool beneath it, as a harness is.
        let leftover = std::process::Command::new("sh")
            .args(["-c", "sleep 60 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = leftover.id();
        // Reaped the moment it dies, as an orphan is by init: until then a
        // zombie still counts as its group, and the take-down would wait out
        // its grace for nothing.
        let (died_tx, died) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut leftover = leftover;
            let _ = died_tx.send(leftover.wait());
        });
        let sid = ObjectId::new();
        host(&r, sid, |h| {
            h.harness_pid = Some(pid);
            h.harness_started = super::super::procs::started(pid);
        });
        assert!(hosted_on_disk(&r)[0].harness_started.is_some());

        restart(&mut r, |_| {});
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)], "resumed");
        let status = died
            .recv_timeout(Duration::from_secs(5))
            .expect("the leftover was taken down")
            .unwrap();
        assert!(!status.success(), "{status:?}");
        assert!(group_gone(pid).await, "and the tool beneath it");
        let relaunched = fake_pid(&r).await;
        assert_ne!(relaunched, pid);
        assert!(
            super::super::procs::group_alive(relaunched),
            "the resume runs"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P1h-1 — a recorded pid is only the harness while its start time still
    /// matches: whatever holds that pid since is left alone, and a record
    /// from before P1h (no pid) does nothing.
    #[tokio::test]
    async fn a_reused_pid_is_never_taken_down() {
        use std::os::unix::process::CommandExt;
        let r = rig(true, 4);
        let mut bystander = std::process::Command::new("sh")
            .args(["-c", "sleep 60 & wait"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = bystander.id();
        let o = order(&r);
        let mut h = HostedSession {
            session: ObjectId::new().to_hex(),
            fence: 1,
            harness: o.harness,
            harness_session: o.harness_session,
            folder: o.folder,
            account: "dev".into(),
            starter: r.user.to_hex(),
            starter_email: o.user_email,
            turns: 0,
            running: None,
            approvals: Vec::new(),
            resumed_at: None,
            quick_resumes: 0,
            harness_pid: Some(pid),
            harness_started: Some("an earlier process".into()),
            replicated: false,
            lease: false,
            fork_of: None,
        };
        reap_leftover(&h).await;
        h.harness_started = None;
        reap_leftover(&h).await;
        h.harness_pid = None;
        h.harness_started = super::super::procs::started(pid);
        reap_leftover(&h).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            bystander.try_wait().unwrap().is_none(),
            "a pid whose start time is not the recorded one is someone else's"
        );
        assert!(super::super::procs::group_alive(pid));
        super::super::procs::take_down(&[pid], Duration::from_millis(500)).await;
        bystander.wait().unwrap();
    }

    /// A restart in the middle of a turn that waits at an approval: the
    /// daemon going down says nothing; the next one reports the turn
    /// interrupted, naming who asked, and the approval withdrawn — in the
    /// transcript too — and the next prompt is the next turn.
    #[tokio::test]
    async fn a_turn_the_restart_cut_is_reported_and_its_approval_withdrawn() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        let harness = harness_asks(&r, sid, 2, "make").await;
        let approval = until_awaiting(&mut r, sid).await;
        let on_disk = hosted_on_disk(&r);
        assert_eq!(
            on_disk[0].running,
            Some(RunningTurn {
                turn: 1,
                prompted_by: Some(r.user.to_hex())
            }),
            "on disk before the server heard"
        );
        assert_eq!(on_disk[0].approvals, std::slice::from_ref(&approval));

        // The teardown as the field saw it: the daemon is stopping, and the
        // harness's MCP connection goes first, so the toolbelt withdraws the
        // approval while the session task still runs.
        r.sup.begin_shutdown();
        drop(harness);
        tokio::time::sleep(Duration::from_millis(300)).await;
        go_down(&r, sid).await;
        silent_about(&mut r, sid).await;
        assert_eq!(
            hosted_on_disk(&r)[0].approvals,
            std::slice::from_ref(&approval),
            "frozen from the shutdown on: the next daemon withdraws it"
        );

        restart(&mut r, |_| {});
        let (seen, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)]);
        assert!(
            seen.iter().any(|m| matches!(m,
                ClientMsg::HiveTurn { session_id, turn: 1, status: Some(HiveTurnStatus::Interrupted), prompted_by, .. }
                    if *session_id == sid && *prompted_by == Some(r.user))),
            "{seen:?}"
        );
        assert!(
            seen.iter().any(|m| matches!(m,
                ClientMsg::HiveApproval { approval_id, status: Some(HiveApprovalStatus::Withdrawn), turn: Some(1), .. }
                    if *approval_id == approval)),
            "{seen:?}"
        );
        let resolutions: Vec<TranscriptEvent> = approval_events(&r, sid)
            .into_iter()
            .filter(|e| matches!(e, TranscriptEvent::ApprovalResolved { .. }))
            .collect();
        assert!(
            matches!(
                resolutions.as_slice(),
                [TranscriptEvent::ApprovalResolved { id, outcome, .. }]
                    if *id == approval && outcome == approval_outcome::WITHDRAWN
            ),
            "withdrawn exactly once, by the next daemon: {resolutions:?}"
        );
        let events = r.store.events(&sid.to_hex());
        assert!(
            events.iter().any(|e| matches!(e, TranscriptEvent::Note { text } if text.contains("turn 1 was cut by the restart"))),
            "{events:?}"
        );
        let on_disk = hosted_on_disk(&r);
        assert!(on_disk[0].running.is_none() && on_disk[0].approvals.is_empty());

        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        let (turns, _, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert!(
            !turns.is_empty() && turns.iter().all(|t| t.turn == 2),
            "{turns:?}"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// A daemon that is stopping takes no new turn and no new session: the
    /// turn would be cut with a number the next daemon never learns, and the
    /// session would not outlive its launch.
    #[tokio::test]
    async fn a_stopping_daemon_takes_no_new_prompt_or_start() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.begin_shutdown();
        let err = r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap_err();
        assert!(err.contains("restarting"), "{err}");
        let refused = r.sup.start(order(&r), true).await;
        assert_eq!(refused.refused, Some(HiveRefusal::Other));
        assert!(refused.detail.unwrap_or_default().contains("restarting"));
        assert_eq!(r.sup.live_count(), 1);
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// The next daemon's gates are the ones configured NOW. Each refusal
    /// ends the session with its reason, forgets it, and launches nothing;
    /// so does a session that keeps taking the daemon down with it.
    #[tokio::test]
    async fn a_resume_passes_every_gate_again_as_the_device_is_configured_now() {
        async fn resumed_with(
            hosted: impl FnOnce(&mut HostedSession),
            cfg_with: impl FnOnce(&mut HiveConfig, ObjectId),
        ) -> String {
            let mut r = rig(true, 4);
            let sid = ObjectId::new();
            host(&r, sid, hosted);
            let user = r.user;
            restart(&mut r, |c| cfg_with(c, user));
            let (seen, manifest) = until_manifest(&mut r).await;
            assert!(manifest.is_empty(), "{manifest:?}");
            assert!(hosted_on_disk(&r).is_empty(), "forgotten");
            assert_eq!(r.sup.live_count(), 0);
            assert!(
                !r.root.path().join("work").join(".argv").exists(),
                "nothing launched"
            );
            seen.into_iter()
                .find_map(|m| match m {
                    ClientMsg::HiveState {
                        session_id,
                        state: Some(HiveRunState::Ended),
                        detail,
                        ..
                    } if session_id == sid => detail,
                    _ => None,
                })
                .expect("reported ended")
        }
        let why = resumed_with(|_| {}, |c, _| c.enabled = false).await;
        assert!(
            why.starts_with("not resumed after the device restarted: ")
                && why.contains("hive_enabled"),
            "{why}"
        );
        let why = resumed_with(
            |_| {},
            |c, user| {
                c.accounts.insert(user.to_hex(), "ops".into());
            },
        )
        .await;
        assert!(why.contains("whose home holds its history"), "{why}");
        let why = resumed_with(|_| {}, |c, _| c.roots = vec![PathBuf::from("/nowhere")]).await;
        assert!(why.contains("hive_roots"), "{why}");
        let why = resumed_with(
            |h| {
                h.resumed_at = Some(unix_now());
                h.quick_resumes = MAX_QUICK_RESUMES - 1;
            },
            |_, _| {},
        )
        .await;
        assert!(why.contains("restarted 3 times within 120 s"), "{why}");
    }

    /// Capacity holds across a restart: what the device now allows resumes,
    /// in the order it was hosted, and the rest end saying why.
    #[tokio::test]
    async fn a_resume_counts_against_capacity_as_configured_now() {
        let mut r = rig(true, 4);
        let (first, second) = (ObjectId::new(), ObjectId::new());
        host(&r, first, |_| {});
        host(&r, second, |_| {});
        restart(&mut r, |c| c.max_sessions = 1);
        let (seen, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(first, 1)]);
        assert!(
            seen.iter().any(|m| matches!(m,
                ClientMsg::HiveState { session_id, state: Some(HiveRunState::Ended), detail: Some(d), .. }
                    if *session_id == second && d.contains("hive_max_sessions"))),
            "{seen:?}"
        );
        let on_disk = hosted_on_disk(&r);
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].session, first.to_hex());
        r.sup.stop(first, 1, "owner".into());
        until_ended(&mut r, first).await;
    }

    /// A stop that reaches the next daemon before its first connection
    /// resumed the session ends it there, with no launch at all.
    #[tokio::test]
    async fn a_stop_before_the_resume_ends_the_session_without_a_launch() {
        let mut r = rig(true, 4);
        let sid = ObjectId::new();
        host(&r, sid, |_| {});
        next_daemon(&mut r, |_| {});
        r.sup.stop(sid, 1, "owner".into());
        connect(&mut r);
        let (seen, manifest) = until_manifest(&mut r).await;
        assert!(manifest.is_empty());
        assert!(
            seen.iter().any(|m| matches!(m,
                ClientMsg::HiveState { session_id, state: Some(HiveRunState::Ended), detail: Some(d), .. }
                    if *session_id == sid && d == "stopped (owner) before it resumed")),
            "{seen:?}"
        );
        assert!(hosted_on_disk(&r).is_empty());
        assert!(
            !r.root.path().join("work").join(".argv").exists(),
            "nothing launched"
        );
    }

    /// The server re-sends a start whose answer the last daemon never
    /// delivered, and it reaches the next daemon before the resume does: it
    /// IS the resume — `--resume` because the history exists, where a
    /// `--session-id` would be refused "already in use" — and the resume
    /// that follows leaves it alone.
    #[tokio::test]
    async fn a_start_the_server_re_sends_for_a_hosted_session_resumes_it() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        host(&r, sid, |h| h.turns = 2);
        let history = r
            .root
            .path()
            .join("home/.roomler/hive")
            .join(sid.to_hex())
            .join("claude/projects")
            .join(format!("hive-{}", o.harness_session))
            .join(format!("{}.jsonl", o.harness_session));
        std::fs::create_dir_all(history.parent().unwrap()).unwrap();
        std::fs::write(&history, "{}\n{}\n").unwrap();

        next_daemon(&mut r, |_| {});
        forget_argv(&r);
        assert_eq!(r.sup.start(o.clone(), true).await, Answer::accepted("dev"));
        let argv = next_argv(&r).await;
        assert!(argv.contains(&"--resume".to_string()), "{argv:?}");
        connect(&mut r);
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)]);
        assert_eq!(r.sup.live_count(), 1, "one harness, not two");

        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        let (turns, _, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert!(
            !turns.is_empty() && turns.iter().all(|t| t.turn == 3),
            "{turns:?}"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    // ─── P1e — core memory ──────────────────────────────────────────────

    fn memory_for(o: &StartOrder, claude: Option<&str>, auto: Option<&str>) -> CoreMemory {
        CoreMemory {
            session_id: o.session_id,
            fence: o.fence,
            brain_rev: 7,
            claude_md: claude.map(str::to_string),
            memory_md: auto.map(str::to_string),
        }
    }

    /// What the fake harness found where Claude Code reads `name`'s memory,
    /// once the launch after [`forget_argv`] has run (it copies before it
    /// writes its argv).
    async fn given(r: &Rig, name: &str) -> Option<String> {
        next_argv(r).await;
        std::fs::read_to_string(r.root.path().join("work").join(name)).ok()
    }

    fn notes(r: &Rig, sid: ObjectId) -> Vec<String> {
        r.store
            .events(&sid.to_hex())
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::Note { text } => Some(text),
                _ => None,
            })
            .collect()
    }

    fn config_claude_md(r: &Rig, sid: ObjectId) -> PathBuf {
        r.root
            .path()
            .join("home/.roomler/hive")
            .join(sid.to_hex())
            .join("claude/CLAUDE.md")
    }

    /// The device's own gate decides: allowed, both files are where Claude
    /// Code reads them, the account's own copies; off, neither is, and the
    /// transcript says why; no memory, nothing is placed or said.
    #[tokio::test]
    async fn core_memory_reaches_a_session_only_where_the_device_allows_it() {
        let mut r = rig_with(true, 4, |c| c.core_memory = true, |s| s);
        let o = order(&r);
        let sid = o.session_id;
        r.sup.receive_memory(memory_for(
            &o,
            Some("# Organization memory\n\n- (warning) ORG-FACT\n"),
            Some("# Device memory: d\n\n- (path) DEVICE-FACT\n"),
        ));
        forget_argv(&r);
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert!(
            given(&r, ".claude_md").await.unwrap().contains("ORG-FACT"),
            "CLAUDE.md, where Claude Code reads the user's instructions"
        );
        assert!(
            std::fs::read_to_string(r.root.path().join("work/.memory_md"))
                .unwrap()
                .contains("DEVICE-FACT"),
            "the auto-memory index"
        );
        let mode = std::fs::metadata(config_claude_md(&r, sid))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "copied in by the account, under its umask");
        // The daemon's own copy, which the account reads to copy in, is the
        // account's alone too: it carries the starter's own facts.
        for name in ["CLAUDE.md", "MEMORY.md"] {
            let own = r
                .root
                .path()
                .join("run")
                .join(sid.to_hex())
                .join("memory")
                .join(name);
            let mode = std::fs::metadata(&own).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", own.display());
        }
        assert!(
            notes(&r, sid)
                .iter()
                .any(|n| n.contains("revision 7") && n.contains("CLAUDE.md")),
            "{:?}",
            notes(&r, sid)
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;

        // Off — the default.
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        r.sup
            .receive_memory(memory_for(&o, Some("ORG-FACT"), Some("DEVICE-FACT")));
        forget_argv(&r);
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(given(&r, ".claude_md").await, None);
        assert!(!r.root.path().join("work/.memory_md").exists());
        assert!(!config_claude_md(&r, sid).exists());
        assert!(
            notes(&r, sid)
                .iter()
                .any(|n| n.contains("hive_core_memory is off")),
            "{:?}",
            notes(&r, sid)
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;

        // None came.
        let mut r = rig_with(true, 4, |c| c.core_memory = true, |s| s);
        let o = order(&r);
        let sid = o.session_id;
        forget_argv(&r);
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(given(&r, ".claude_md").await, None);
        assert!(
            !notes(&r, sid)
                .iter()
                .any(|n| n.to_lowercase().contains("core memory")),
            "{:?}",
            notes(&r, sid)
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// A resume (P1d-2) keeps the session's own copy, its own edits
    /// included: no memory comes with it, and the wrapper copies only into
    /// an empty place.
    #[tokio::test]
    async fn a_resume_keeps_the_sessions_own_core_memory() {
        let mut r = rig_with(true, 4, |c| c.core_memory = true, |s| s);
        let o = order(&r);
        let sid = o.session_id;
        r.sup
            .receive_memory(memory_for(&o, Some("ORG-FACT v1\n"), None));
        forget_argv(&r);
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(
            given(&r, ".claude_md").await.as_deref(),
            Some("ORG-FACT v1\n")
        );
        // A turn, so there is a history to resume; and the session's own note.
        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        reports_until(&mut r, sid, HiveRunState::Idle).await;
        let own = "ORG-FACT v1\n- a note the session kept\n";
        std::fs::write(config_claude_md(&r, sid), own).unwrap();

        go_down(&r, sid).await;
        std::fs::remove_file(r.root.path().join("work/.claude_md")).unwrap();
        forget_argv(&r);
        restart(&mut r, |_| {});
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)]);
        assert_eq!(
            given(&r, ".claude_md").await.as_deref(),
            Some(own),
            "the resumed harness has the session's own copy"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// A snapshot larger than the server ever renders is dropped; one for
    /// another start (another fence) is not this start's.
    #[tokio::test]
    async fn core_memory_too_large_or_for_another_start_is_not_used() {
        use roomler_ai_remote_control::hive::hive_limits::MAX_CORE_MEMORY_BYTES;
        let mut r = rig_with(true, 4, |c| c.core_memory = true, |s| s);
        let o = order(&r);
        let sid = o.session_id;
        let big = "x".repeat(MAX_CORE_MEMORY_BYTES + 1);
        r.sup.receive_memory(memory_for(&o, Some(&big), None));
        let mut other = memory_for(&o, Some("ANOTHER-FENCE"), None);
        other.fence = 2;
        r.sup.receive_memory(other);
        forget_argv(&r);
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(given(&r, ".claude_md").await, None);
        assert!(!config_claude_md(&r, sid).exists());
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    // ─── P2e-1 — the fence on the device ────────────────────────────────

    /// The next state reported for `session`, with its fence.
    async fn next_state_at(r: &mut Rig, session: ObjectId) -> (u64, HiveRunState, Option<String>) {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), r.reports.recv())
                .await
                .expect("a state report within 10 s")
                .expect("the reporter is open");
            if let ClientMsg::HiveState {
                session_id,
                fence,
                state: Some(s),
                detail,
            } = msg
                && session_id == session
            {
                return (fence, s, detail);
            }
        }
    }

    /// `o`, at `fence`.
    fn at_fence(o: &StartOrder, fence: u64) -> StartOrder {
        StartOrder { fence, ..o.clone() }
    }

    /// Reports of the rig's daemon, without a connection's resume: for a
    /// test that drives the resume itself.
    fn listen_only(r: &mut Rig) {
        let (tx, reports) = mpsc::channel(64);
        *r.sup.reporter.lock().unwrap() = Some(tx);
        r.reports = reports;
    }

    /// P2e-1 — a start at a newer fence on a device that runs an older one
    /// stops that run FIRST: its harness is gone before the start is
    /// answered, its `ended` comes before the new run's `idle`, and the new
    /// run takes up the history the old one left. Only the new run is live,
    /// and what the device hosts is the new run's.
    #[tokio::test]
    async fn a_start_at_a_newer_fence_stops_the_older_run_first() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert_eq!(r.sup.start(o.clone(), true).await, Answer::accepted("dev"));
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (1, HiveRunState::Idle, None)
        );
        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        let first = fake_pid(&r).await;
        let _ = std::fs::remove_file(r.root.path().join("work").join(".pid"));
        forget_argv(&r);

        assert_eq!(
            r.sup.start(at_fence(&o, 2), true).await,
            Answer::accepted("dev")
        );
        assert!(
            !super::super::procs::group_alive(first),
            "the fence-1 harness is gone before the fence-2 start is answered"
        );
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (
                1,
                HiveRunState::Ended,
                Some("stopped (superseded: the session is at fence 2)".into())
            ),
            "the old run's end comes first"
        );
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (2, HiveRunState::Idle, None)
        );
        assert!(
            next_argv(&r).await.iter().any(|a| a == "--resume"),
            "the new run takes up the history the old one left"
        );
        assert_ne!(fake_pid(&r).await, first);
        assert!(r.sup.runs_at(sid, 2) && !r.sup.runs_at(sid, 1));
        assert_eq!(r.sup.live_count(), 1);
        let on_disk = hosted_on_disk(&r);
        assert_eq!(on_disk.len(), 1);
        assert_eq!(
            on_disk[0].fence, 2,
            "what the device hosts is the new run's"
        );

        r.sup.stop(sid, 2, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-1 — a start older than the run here is a stale frame: refused,
    /// and the run here goes on untouched.
    #[tokio::test]
    async fn a_start_older_than_the_run_here_is_refused_and_moves_nothing() {
        let mut r = rig(true, 4);
        let o = at_fence(&order(&r), 2);
        let sid = o.session_id;
        assert!(r.sup.start(o.clone(), true).await.refused.is_none());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (2, HiveRunState::Idle, None)
        );
        let pid = fake_pid(&r).await;

        let stale = r.sup.start(at_fence(&o, 1), true).await;
        assert_eq!(stale.refused, Some(HiveRefusal::Other), "{stale:?}");
        assert!(
            stale
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("a newer fence (2)")),
            "{stale:?}"
        );
        assert!(
            super::super::procs::group_alive(pid),
            "the run here goes on"
        );
        assert!(r.sup.runs_at(sid, 2));
        assert_eq!(hosted_on_disk(&r)[0].fence, 2);

        r.sup.stop(sid, 2, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-1 — what a run removes when it ends, it removes at its own fence:
    /// an old run's end, or its going down with the daemon, takes nothing of
    /// a newer run's (not its live entry, so not its model access, and not
    /// what the device hosts of it), and an old run's write to what the
    /// device hosts lands nowhere.
    #[tokio::test]
    async fn an_old_runs_end_takes_nothing_of_a_newer_runs() {
        let mut r = rig(true, 4);
        let o = at_fence(&order(&r), 2);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (2, HiveRunState::Idle, None)
        );

        r.sup.finish(sid, 1, None, "an old run ended".into());
        assert!(r.sup.runs_at(sid, 2), "the new run is still live");
        assert_eq!(hosted_on_disk(&r).len(), 1, "and still hosted");
        r.sup.let_go(sid, 1, None);
        assert!(
            r.sup.runs_at(sid, 2),
            "an old run going down with the daemon lets go of nothing newer"
        );
        r.sup.hosted_update(sid, 1, |h| h.turns = 99);
        assert_eq!(
            hosted_on_disk(&r)[0].turns,
            0,
            "an old run writes nothing of the new run's"
        );
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (1, HiveRunState::Ended, Some("an old run ended".into()))
        );
        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (2, HiveRunState::Running, None),
            "and the new run takes its prompt"
        );

        r.sup.stop(sid, 2, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-1 — `rc:hive.demote`: the run at an older fence is fenced out
    /// the moment the demote is handled, before its harness has gone (its
    /// model calls, through the sidecar's gate, its prompts and its approval
    /// answers are refused), then it ends. The store's floor is the lease's
    /// fence, so a late write of the run's is refused there, and what the
    /// device hosts forgets it, so the next daemon resumes nothing.
    #[tokio::test]
    async fn a_demote_fences_the_run_out_at_once_and_nothing_resumes_it() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (1, HiveRunState::Idle, None)
        );
        assert!(r.sup.runs_at(sid, 1));

        r.sup.demote(sid, 2, "not_location").await;
        // Nothing has yielded to the session's task since (one thread): the
        // run is still here, fenced.
        assert!(r.sup.holds_live(sid), "the run has not let go yet");
        assert!(
            !r.sup.runs_at(sid, 1),
            "its model calls are refused at once"
        );
        assert_eq!(
            r.sup.prompt(sid, dev(&r), "more".into()),
            Err("the session has moved on from this device".into())
        );
        assert_eq!(
            r.sup
                .answer_approval(sid, "a1", toolbelt::Decision::Allow, dev(&r).unwrap()),
            Err("the session has moved on from this device".into())
        );
        assert!(hosted_on_disk(&r).is_empty(), "the device forgets it");
        assert_eq!(r.store.floor(&sid.to_hex()).await.unwrap(), Some(2));

        assert_eq!(
            next_state_at(&mut r, sid).await,
            (
                1,
                HiveRunState::Ended,
                Some("stopped (demoted: the session is at fence 2)".into())
            )
        );
        let before = r.store.events(&sid.to_hex()).len();
        r.store.append(
            &sid.to_hex(),
            1,
            TranscriptEvent::Note {
                text: "late".into(),
            },
        );
        assert_eq!(
            r.store.events(&sid.to_hex()).len(),
            before,
            "a late write at fence 1 is refused"
        );

        restart(&mut r, |_| {});
        let (_, manifest) = until_manifest(&mut r).await;
        assert!(manifest.is_empty(), "nothing resumed: {manifest:?}");
        assert!(!r.sup.holds_live(sid));
    }

    /// P2e-1 — a demote names the fence the lease is at now: a run here at
    /// that fence or a newer one is the session come back, not the
    /// demote's.
    #[tokio::test]
    async fn a_demote_for_a_fence_this_device_moved_past_changes_nothing() {
        let mut r = rig(true, 4);
        let o = at_fence(&order(&r), 3);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (3, HiveRunState::Idle, None)
        );
        for fence in [2, 3] {
            r.sup.demote(sid, fence, "not_location").await;
            assert!(r.sup.runs_at(sid, 3), "a demote at fence {fence}");
            assert_eq!(hosted_on_disk(&r)[0].fence, 3);
        }
        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (3, HiveRunState::Running, None)
        );
        r.sup.stop(sid, 3, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-1 — a session waiting to resume when a demote comes is not
    /// resumed, including by a resume that had already taken it from the
    /// queue and was waiting for the start lock.
    #[tokio::test]
    async fn a_demote_reaches_a_session_still_to_resume() {
        let mut r = rig(true, 4);
        let sid = ObjectId::new();
        host(&r, sid, |_| {});
        next_daemon(&mut r, |_| {});
        r.sup.demote(sid, 2, "not_location").await;
        assert!(hosted_on_disk(&r).is_empty());
        connect(&mut r);
        let (_, manifest) = until_manifest(&mut r).await;
        assert!(
            manifest.is_empty(),
            "a demoted session waiting to resume is not resumed: {manifest:?}"
        );
        assert!(!r.sup.holds_live(sid));

        // The race: the resume holds the record it took from the queue.
        let other = ObjectId::new();
        host(&r, other, |_| {});
        next_daemon(&mut r, |_| {});
        let taken = r
            .sup
            .to_resume
            .lock()
            .unwrap()
            .pop()
            .expect("waiting to resume");
        r.sup.demote(other, 2, "not_location").await;
        r.sup.resume(taken).await;
        assert!(!r.sup.holds_live(other), "a demoted session never resumes");
    }

    /// P2e-1 — a stop for a newer fence than the run here: that run is past
    /// and ends, and the device says at once that it does not run the fence
    /// the stop names. A start at it may be waiting for this very run to let
    /// go; its launch is answered with a stop when it reports in.
    #[tokio::test]
    async fn a_stop_for_a_newer_fence_ends_the_older_run_and_says_so() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (1, HiveRunState::Idle, None)
        );
        r.sup.stop(sid, 2, "owner".into());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (
                2,
                HiveRunState::Ended,
                Some("not running on this device".into())
            )
        );
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (1, HiveRunState::Ended, Some("stopped (owner)".into()))
        );
        assert!(!r.sup.holds_live(sid));
        assert!(hosted_on_disk(&r).is_empty());
    }

    /// P2e-1 — a stop that reaches a session a resume has taken from the
    /// queue, but not launched yet, wins: the resume finds it forgotten.
    #[tokio::test]
    async fn a_stop_that_comes_first_wins_over_a_resume_in_flight() {
        let mut r = rig(true, 4);
        let sid = ObjectId::new();
        host(&r, sid, |_| {});
        next_daemon(&mut r, |_| {});
        listen_only(&mut r);
        let taken = r
            .sup
            .to_resume
            .lock()
            .unwrap()
            .pop()
            .expect("waiting to resume");
        r.sup.stop(sid, 1, "owner".into());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (
                1,
                HiveRunState::Ended,
                Some("not running on this device".into())
            )
        );
        r.sup.resume(taken).await;
        assert!(!r.sup.holds_live(sid), "the stop came first");
        assert!(hosted_on_disk(&r).is_empty());
    }

    // ─── P2e-2 — the server's word ──────────────────────────────────────

    /// The rig's connection that is the latest now.
    pub(crate) fn latest(r: &Rig) -> mpsc::Sender<ClientMsg> {
        r.sup
            .reporter
            .lock()
            .unwrap()
            .clone()
            .expect("a connection")
    }

    /// Until the session is live here, at most 10 s.
    async fn until_live(r: &Rig, sid: ObjectId) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !r.sup.holds_live(sid) {
            assert!(Instant::now() < deadline, "the session never launched");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// P2e-2 — a leased session the previous daemon hosted launches only on
    /// the server's word, on the connection up now: held back meanwhile, and
    /// listed in the manifest so the server answers it. A word on an older
    /// connection launches nothing.
    #[tokio::test]
    async fn a_leased_session_resumes_after_a_restart_only_on_the_servers_word() {
        let mut r = rig(true, 4);
        let sid = ObjectId::new();
        host(&r, sid, |h| h.lease = true);
        restart(&mut r, |_| {});
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)], "held back, and listed");
        assert!(!r.sup.holds_live(sid), "not launched before the word");

        let (older, _gone) = mpsc::channel(1);
        r.sup.take_lease(sid, 1, &older);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !r.sup.holds_live(sid),
            "a word on another connection launches nothing"
        );

        let now = latest(&r);
        r.sup.take_lease(sid, 1, &now);
        until_live(&r, sid).await;
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (1, HiveRunState::Idle, None)
        );
        assert!(r.sup.leased(sid, 1), "and it stays leased");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-2 — the word can come before the resume has held the session
    /// back: the resume then finds it and launches at once.
    #[tokio::test]
    async fn a_word_that_comes_before_the_resume_launches_the_session_at_once() {
        let mut r = rig(true, 4);
        let sid = ObjectId::new();
        host(&r, sid, |h| h.lease = true);
        next_daemon(&mut r, |_| {});
        let (tx, reports) = mpsc::channel(64);
        r.reports = reports;
        r.sup.connected(tx.clone());
        // Before anything yields (one thread): the connection's resume has
        // not run yet, and the session still waits in its queue.
        r.sup.take_lease(sid, 1, &tx);
        assert!(r.sup.has_word(sid, 1), "kept: the session is the device's");
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(sid, 1)]);
        assert!(r.sup.holds_live(sid), "launched on the word it already had");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-2 — a session that is not leased resumes as in P1, without a word.
    #[tokio::test]
    async fn a_session_that_is_not_leased_resumes_without_a_word() {
        let mut r = rig(true, 4);
        let sid = ObjectId::new();
        host(&r, sid, |_| {});
        restart(&mut r, |_| {});
        until_manifest(&mut r).await;
        assert!(r.sup.holds_live(sid));
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-2 — a session held back for the word is ended by a stop, and a
    /// demote forgets it: a word that comes after launches neither.
    #[tokio::test]
    async fn a_stop_or_a_demote_ends_a_session_held_back_for_the_word() {
        let mut r = rig(true, 4);
        let (stopped, demoted) = (ObjectId::new(), ObjectId::new());
        host(&r, stopped, |h| h.lease = true);
        host(&r, demoted, |h| h.lease = true);
        restart(&mut r, |_| {});
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest.len(), 2, "{manifest:?}");

        r.sup.stop(stopped, 1, "owner".into());
        assert_eq!(
            next_state_at(&mut r, stopped).await,
            (
                1,
                HiveRunState::Ended,
                Some("stopped (owner) before it resumed".into())
            )
        );
        r.sup.demote(demoted, 2, "not_location").await;
        assert!(
            !r.sup.manifest().iter().any(|e| e.session_id == demoted),
            "a demoted session is held back no more"
        );
        assert!(hosted_on_disk(&r).is_empty(), "both forgotten");

        let now = latest(&r);
        r.sup.take_lease(stopped, 1, &now);
        r.sup.take_lease(demoted, 1, &now);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!r.sup.holds_live(stopped) && !r.sup.holds_live(demoted));
        assert!(r.sup.manifest().is_empty(), "neither is held back any more");
    }

    /// P2e-2 — a start at the fence of a session held back for the word is
    /// that word: it launches the session, whose record it resumes.
    #[tokio::test]
    async fn a_start_at_its_fence_launches_a_session_held_back_for_the_word() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        host(&r, sid, |h| h.lease = true);
        restart(&mut r, |_| {});
        until_manifest(&mut r).await;
        assert!(!r.sup.holds_live(sid));

        assert!(r.sup.start(o, true).await.refused.is_none());
        assert!(r.sup.holds_live(sid));
        let listed: Vec<(ObjectId, u64)> = r
            .sup
            .manifest()
            .iter()
            .map(|e| (e.session_id, e.fence))
            .collect();
        assert_eq!(listed, [(sid, 1)], "live, and no longer held back");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-2 — the first word for a running session makes it leased, here
    /// and in what the device hosts; a word for a session this device
    /// neither runs nor hosts is not kept.
    #[tokio::test]
    async fn the_first_word_leases_a_running_session_and_no_other_is_kept() {
        let mut r = rig(true, 4);
        let o = order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(
            next_state_at(&mut r, sid).await,
            (1, HiveRunState::Idle, None)
        );
        assert!(!r.sup.leased(sid, 1));
        let now = latest(&r);
        r.sup.take_lease(sid, 1, &now);
        assert!(r.sup.leased(sid, 1));
        assert!(r.sup.has_word(sid, 1));
        assert!(hosted_on_disk(&r)[0].lease, "a restart keeps it leased");
        // A late word on an older connection takes nothing from the latest
        // one's.
        let (older, _gone) = mpsc::channel(1);
        r.sup.take_lease(sid, 1, &older);
        assert!(
            r.sup.has_word(sid, 1),
            "a late word on an older connection displaced the latest one's"
        );

        let stranger = ObjectId::new();
        r.sup.take_lease(stranger, 1, &now);
        assert!(!r.sup.has_word(stranger, 1), "not ours: not kept");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — what a prompt hears while its session drains.
    const MOVING: &str = "the session is moving to another device — ask again in a minute";

    /// P2e-4 — `rc:hive.drain` for `sid` at `fence`, from the primary
    /// enrollment, as the dispatch hands it over: taken up at once, and
    /// answered on a connection of its own.
    fn drain(r: &Rig, sid: ObjectId, fence: u64) -> mpsc::Receiver<ClientMsg> {
        drain_as(r, sid, fence, true)
    }

    fn drain_as(r: &Rig, sid: ObjectId, fence: u64, is_primary: bool) -> mpsc::Receiver<ClientMsg> {
        let (tx, rx) = mpsc::channel(1);
        drain_with(Some(Arc::clone(&r.sup)), sid, fence, is_primary, tx);
        rx
    }

    /// P2e-4 — a drain's answer: where the copy ends, or the refusal and its
    /// words.
    async fn answered(
        mut rx: mpsc::Receiver<ClientMsg>,
    ) -> Result<(u64, String), (HiveDrainRefusal, String)> {
        let msg = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("a drain answered within 20 s")
            .expect("one answer");
        match msg {
            ClientMsg::HiveDrained {
                seq: Some(seq),
                hash: Some(hash),
                refused: None,
                detail: None,
                ..
            } => Ok((seq, hash)),
            ClientMsg::HiveDrained {
                seq: None,
                hash: None,
                refused: Some(word),
                detail,
                ..
            } => Err((word, detail.unwrap_or_default())),
            other => panic!("not a drain's answer: {other:?}"),
        }
    }

    /// P2e-4 — not answered yet.
    fn unanswered(rx: &mut mpsc::Receiver<ClientMsg>) -> bool {
        matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty))
    }

    /// P2e-4 — the store's tip for `sid`, as `rc:hive.drained` says it.
    async fn store_tip(r: &Rig, sid: ObjectId) -> (u64, String) {
        let t = r
            .store
            .chain_tip(&sid.to_hex())
            .await
            .unwrap()
            .expect("the session has events");
        (t.seq, hex::encode(t.hash))
    }

    /// P2e-4 — every line the fake harness read on stdin.
    fn harness_stdin(r: &Rig) -> String {
        std::fs::read_to_string(r.root.path().join("work").join(".stdin")).unwrap_or_default()
    }

    /// P2e-4 — the turn reports up to `sid`'s next `idle`, as (turn, status).
    async fn turns_until_idle(r: &mut Rig, sid: ObjectId) -> Vec<(u32, HiveTurnStatus)> {
        let (turns, _, _) = reports_until(r, sid, HiveRunState::Idle).await;
        turns.iter().map(|t| (t.turn, t.status)).collect()
    }

    /// P2e-4 — a rig whose drains cut a turn after `cut`, give it `grace`, and
    /// wait `checkpoint` beyond both.
    fn drain_rig(cut: u64, grace: u64, checkpoint: u64) -> Rig {
        rig_with(
            true,
            4,
            |_| {},
            |s| {
                s.with_drain_timing(DrainTiming {
                    cut: Duration::from_millis(cut),
                    grace: Duration::from_millis(grace),
                    checkpoint: Duration::from_millis(checkpoint),
                })
            },
        )
    }

    /// P2e-4 — a session started on `r`, idle.
    async fn started(r: &mut Rig) -> ObjectId {
        let o = order(r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(r, sid).await.0, HiveRunState::Idle);
        sid
    }

    /// P2e-4 — an idle session drains at once, at its store's own tip. From
    /// then on it takes no prompt and writes nothing more to its events, so
    /// the member's copy can end exactly there; the server's word at its
    /// fence says the lease stayed, and prompts are taken again.
    #[tokio::test]
    async fn an_idle_session_drains_at_its_tip_and_takes_no_prompt_until_the_word() {
        let mut r = rig(true, 4);
        let sid = started(&mut r).await;
        r.sup.prompt(sid, dev(&r), "say hello".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);

        let tip = answered(drain(&r, sid, 1)).await.expect("drained");
        assert_eq!(tip, store_tip(&r, sid).await, "the store's own tip");
        assert_eq!(
            r.sup.prompt(sid, dev(&r), "more".into()),
            Err(MOVING.into())
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(store_tip(&r, sid).await, tip, "nothing written after it");

        r.sup.take_lease(sid, 1, &latest(&r));
        r.sup.prompt(sid, dev(&r), "again".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert!(harness_stdin(&r).contains("again"), "the word let it in");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — a drain waits for the running turn to end on its own, and holds
    /// back the prompt that waited behind it: the answer is the tip as the
    /// turn left it. The server's word then lets the held prompt in.
    #[tokio::test]
    async fn a_drain_waits_for_the_running_turn_and_holds_the_prompt_behind_it() {
        let mut r = rig(true, 4);
        let sid = started(&mut r).await;
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        r.sup.prompt(sid, dev(&r), "second".into()).unwrap();

        let mut answer = drain(&r, sid, 1);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(unanswered(&mut answer), "the turn still runs");
        release(&r);
        let tip = answered(answer).await.expect("drained");
        assert_eq!(tip, store_tip(&r, sid).await);
        assert_eq!(
            turns_until_idle(&mut r, sid).await,
            [(1, HiveTurnStatus::Ok)],
            "it ended on its own, and nothing began after it"
        );
        assert!(!harness_stdin(&r).contains("second"), "held by the drain");

        r.sup.take_lease(sid, 1, &latest(&r));
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert!(harness_stdin(&r).contains("second"), "the word let it in");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — a turn still running at the cut is interrupted as Claude
    /// Code's own SDK interrupts one, over its stream-json input: the
    /// transcript says why first, the turn is reported interrupted, and the
    /// drain answers once it ended. The move's demote then ends the run.
    #[tokio::test]
    async fn a_turn_still_running_at_the_cut_is_interrupted_and_reported_so() {
        let mut r = drain_rig(300, 5_000, 5_000);
        let sid = started(&mut r).await;
        r.sup.prompt(sid, dev(&r), "CUTME".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);

        let tip = answered(drain(&r, sid, 1)).await.expect("drained");
        assert_eq!(tip, store_tip(&r, sid).await);
        let sent: Vec<serde_json::Value> = harness_stdin(&r)
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let interrupt = sent
            .iter()
            .find(|v| v["type"] == "control_request")
            .expect("the interrupt reached the harness");
        assert_eq!(
            *interrupt,
            json!({"type": "control_request", "request_id": "hive-drain-1",
                "request": {"subtype": "interrupt"}})
        );
        assert_eq!(
            turns_until_idle(&mut r, sid).await,
            [(1, HiveTurnStatus::Interrupted)]
        );
        let events = r.store.events(&sid.to_hex());
        let note = events.iter().position(|e| {
            matches!(e, TranscriptEvent::Note { text }
                if text == "Turn 1 is cut: the session is moving to another device.")
        });
        let end = events
            .iter()
            .position(|e| matches!(e, TranscriptEvent::Turn { ok: false, .. }));
        assert!(
            note.is_some() && note < end,
            "the cut is said before the turn's end: {:?}",
            events.iter().map(TranscriptEvent::kind).collect::<Vec<_>>()
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TranscriptEvent::UserMessage { text, .. }
                if text.starts_with(INTERRUPTED_MARKER))),
            "no one interrupted it but the drain, which the note says"
        );

        r.sup.demote(sid, 2, "not_location").await;
        assert_eq!(
            until_ended(&mut r, sid).await.as_deref(),
            Some("stopped (demoted: the session is at fence 2)")
        );
    }

    /// P2e-4 — a cut turn that does not stop within its grace is not drained:
    /// the drain is refused and lifted, the turn runs on and ends as it would
    /// have, and a prompt is taken again at once.
    #[tokio::test]
    async fn a_cut_turn_that_does_not_stop_is_not_drained_and_runs_on() {
        let mut r = drain_rig(200, 300, 5_000);
        let sid = started(&mut r).await;
        r.sup.prompt(sid, dev(&r), "DEAFME".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);

        assert_eq!(
            answered(drain(&r, sid, 1)).await,
            Err((
                HiveDrainRefusal::Other,
                "the running turn did not stop when it was told to".into()
            ))
        );
        assert!(harness_stdin(&r).contains("control_request"), "it was told");
        r.sup.prompt(sid, dev(&r), "after".into()).unwrap();
        release(&r);
        assert_eq!(
            turns_until_idle(&mut r, sid).await,
            [
                (1, HiveTurnStatus::Ok),
                (2, HiveTurnStatus::Running),
                (2, HiveTurnStatus::Ok)
            ],
            "not reported cut: it was not drained"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — the drain withdraws the session's open approvals at once, and
    /// one that opens while it waits: a turn waiting on a person could not
    /// end. The harness hears each withdrawn; the transcript says so.
    #[tokio::test]
    async fn a_drain_withdraws_the_open_approvals_so_the_turn_can_end() {
        let mut r = rig(true, 4);
        let sid = started(&mut r).await;
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        let mut first = harness_asks(&r, sid, 2, "make").await;
        let asked = until_awaiting(&mut r, sid).await;

        let answer = drain(&r, sid, 1);
        let withdrawn = json!({"behavior": "deny",
            "message": "This approval was withdrawn before anyone answered."});
        let soon = Duration::from_secs(5);
        let verdict = tokio::time::timeout(soon, first.verdict(2))
            .await
            .expect("the drain withdrew the approval open when it began");
        assert_eq!(verdict, withdrawn);
        let mut second = harness_asks(&r, sid, 3, "make install").await;
        let verdict = tokio::time::timeout(soon, second.verdict(3))
            .await
            .expect("the drain withdrew the approval asked while it drained");
        assert_eq!(verdict, withdrawn);
        release(&r);
        answered(answer).await.expect("drained");

        let ended: Vec<(String, String)> = approval_events(&r, sid)
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::ApprovalResolved { id, outcome, .. } => Some((id, outcome)),
                _ => None,
            })
            .collect();
        assert_eq!(ended.len(), 2, "{ended:?}");
        assert_eq!(ended[0].0, asked);
        assert!(
            ended.iter().all(|(_, o)| o == approval_outcome::WITHDRAWN),
            "{ended:?}"
        );
        assert!(r.sup.pending_approvals(sid).is_empty());
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — a drain for a run this device does not have at that fence is
    /// refused `not_running` and drains nothing; so is one for a run a newer
    /// fence took; and a secondary org's is refused like every Hive frame of
    /// its.
    #[tokio::test]
    async fn a_drain_for_a_run_not_here_or_from_a_secondary_org_is_refused() {
        let mut r = rig(true, 4);
        let sid = started(&mut r).await;
        assert_eq!(
            answered(drain(&r, ObjectId::new(), 1)).await,
            Err((
                HiveDrainRefusal::NotRunning,
                "this device does not run the session".into()
            ))
        );
        assert_eq!(
            answered(drain(&r, sid, 2)).await,
            Err((
                HiveDrainRefusal::NotRunning,
                "this device runs the session at fence 1".into()
            ))
        );
        assert_eq!(
            answered(drain_as(&r, sid, 1, false)).await,
            Err((
                HiveDrainRefusal::Other,
                "agent sessions run only for this device's primary organization".into()
            ))
        );
        r.sup.prompt(sid, dev(&r), "still here".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);

        r.sup.demote(sid, 2, "not_location").await;
        // Before anything yields: the run is still here, fenced.
        assert_eq!(
            answered(drain(&r, sid, 1)).await,
            Err((
                HiveDrainRefusal::NotRunning,
                "the session has moved on from this device".into()
            ))
        );
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — a replicated session's drain ends at a checkpoint, so the
    /// member's copy holds the files as the session left them: one taken for
    /// the drain when it found the session idle; the last turn's own when it
    /// waited for that turn, and never one more. The tip is that
    /// checkpoint's event.
    #[tokio::test]
    async fn a_replicated_session_drains_at_its_last_checkpoint() {
        use super::super::checkpointer::Runner;
        let (mut r, sid) = replicated_on(Runner::InProcess {
            ceiling: PathBuf::from("/tmp"),
        })
        .await;
        let checkpoints = |r: &Rig| -> Vec<u64> {
            r.store
                .events(&sid.to_hex())
                .iter()
                .filter_map(|e| match e {
                    TranscriptEvent::Checkpoint(c) => Some(c.n),
                    _ => None,
                })
                .collect()
        };
        r.sup.prompt(sid, None, "hi".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert_eq!(checkpoints(&r), [1]);

        let tip = answered(drain(&r, sid, 1)).await.expect("drained");
        assert_eq!(checkpoints(&r), [1, 2], "the drain's own");
        assert_eq!(tip, store_tip(&r, sid).await);
        assert!(
            matches!(r.store.events(&sid.to_hex()).last(),
                Some(TranscriptEvent::Checkpoint(c)) if c.n == 2),
            "the tip is the checkpoint"
        );

        r.sup.take_lease(sid, 1, &latest(&r));
        r.sup.prompt(sid, None, "hold".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        let answer = drain(&r, sid, 1);
        release(&r);
        let tip = answered(answer).await.expect("drained");
        assert_eq!(checkpoints(&r), [1, 2, 3], "the turn's own, and no other");
        assert_eq!(tip, store_tip(&r, sid).await);
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — a drain whose last checkpoint is not taken is not drained:
    /// the member's copy would not hold the files as the session left them.
    /// Why stays in the transcript, on the device; the session goes on.
    #[tokio::test]
    async fn a_drain_whose_last_checkpoint_fails_is_not_drained() {
        use super::super::checkpointer::Runner;
        let (mut r, sid) = replicated_on(Runner::Failing("the disk is full")).await;
        assert_eq!(
            answered(drain(&r, sid, 1)).await,
            Err((
                HiveDrainRefusal::Other,
                "the last checkpoint was not taken".into()
            ))
        );
        assert!(
            notes(&r, sid).contains(&"Checkpoint 1 was not taken: the disk is full".to_string()),
            "{:?}",
            notes(&r, sid)
        );
        r.sup.prompt(sid, None, "hi".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — a drain asked again, while the first waits or once it was
    /// answered, is answered with the same tip.
    #[tokio::test]
    async fn a_drain_asked_again_is_answered_with_the_same_tip() {
        let mut r = rig(true, 4);
        let sid = started(&mut r).await;
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        let (a, b) = (drain(&r, sid, 1), drain(&r, sid, 1));
        release(&r);
        let a = answered(a).await.expect("drained");
        assert_eq!(answered(b).await, Ok(a.clone()), "the one under way");
        assert_eq!(
            answered(drain(&r, sid, 1)).await,
            Ok(a),
            "the one it already gave"
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — the server's word at the run's fence right behind the drain
    /// lifts it, even before the session's task took the drain up: the
    /// dispatch takes a drain up as its frame comes, so the word reaches the
    /// session after it. The drain is refused, the turn runs on, and a prompt
    /// is taken again.
    #[tokio::test]
    async fn the_word_right_behind_a_drain_lifts_it() {
        let mut r = rig(true, 4);
        let sid = started(&mut r).await;
        r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        let answer = drain(&r, sid, 1);
        // Before anything yields (one thread): the session's task has not
        // read the drain yet.
        r.sup.take_lease(sid, 1, &latest(&r));
        r.sup.prompt(sid, dev(&r), "after".into()).unwrap();
        // The turn ends before the answer is read: a drain still on would
        // answer with the tip once it did.
        release(&r);
        assert_eq!(
            answered(answer).await,
            Err((
                HiveDrainRefusal::Other,
                "the lease stayed on this device".into()
            ))
        );
        assert_eq!(
            turns_until_idle(&mut r, sid).await,
            [
                (1, HiveTurnStatus::Ok),
                (2, HiveTurnStatus::Running),
                (2, HiveTurnStatus::Ok)
            ]
        );
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-4 — a drain that does not finish within its bound is refused and
    /// lifted: a checkpoint that never ends holds the session's next prompt
    /// back, never the session.
    #[tokio::test]
    async fn a_drain_that_does_not_finish_in_time_is_refused_and_lifted() {
        use super::super::checkpointer::Runner;
        let mut r = rig_with(
            true,
            4,
            |_| {},
            |mut s| {
                s.checkpoint_runner = Some(Runner::Hangs);
                s.with_drain_timing(DrainTiming {
                    cut: Duration::from_millis(100),
                    grace: Duration::from_millis(100),
                    checkpoint: Duration::from_millis(300),
                })
            },
        );
        let mut o = order(&r);
        o.replicated = true;
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);

        assert_eq!(
            answered(drain(&r, sid, 1)).await,
            Err((
                HiveDrainRefusal::Other,
                "the drain did not finish in time".into()
            ))
        );
        assert!(
            r.sup.prompt(sid, dev(&r), "later".into()).is_ok(),
            "lifted: prompts are taken again"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !harness_stdin(&r).contains("later"),
            "behind the checkpoint"
        );
        r.sup.stop(sid, 1, "owner".into());
        assert_eq!(
            until_ended(&mut r, sid).await.as_deref(),
            Some("stopped (owner)")
        );
    }

    /// P2e-4 — the interrupt is Claude Code's own control request, on one
    /// line of its stream-json input.
    #[test]
    fn the_interrupt_is_claude_codes_own_control_request() {
        let line = interrupt_line(3);
        assert!(line.ends_with('\n'));
        assert!(!line.trim_end().contains('\n'), "one line");
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(
            v,
            json!({"type": "control_request", "request_id": "hive-drain-3",
                "request": {"subtype": "interrupt"}})
        );
    }

    /// P2e-5 — a rig whose daemon knows its own id (`me`), and takes its
    /// checkpoints, and puts copies in place, in process.
    pub(crate) fn moving_rig(me: ObjectId, max: usize) -> Rig {
        use super::super::checkpointer::Runner;
        rig_with(
            true,
            max,
            |_| {},
            |mut s| {
                // The rig's root is under /tmp: git's discovery stops there.
                s.checkpoint_runner = Some(Runner::InProcess {
                    ceiling: PathBuf::from("/tmp"),
                });
                s.agent_id = Some(me);
                s
            },
        )
    }

    /// P2e-5 — a replicated session that ran two turns here at fence 1, and
    /// stopped: its copy, checkpoints and blobs, is in the store, and its
    /// folder holds `notes.md`.
    async fn ran_twice(r: &mut Rig) -> StartOrder {
        let mut o = order(r);
        o.replicated = true;
        let sid = o.session_id;
        assert!(r.sup.start(o.clone(), true).await.refused.is_none());
        assert_eq!(next_state(r, sid).await.0, HiveRunState::Idle);
        std::fs::write(
            r.root.path().join("work").join("notes.md"),
            "the session's work\n",
        )
        .unwrap();
        for text in ["hi", "again"] {
            r.sup.prompt(sid, None, text.into()).unwrap();
            assert_eq!(next_state(r, sid).await.0, HiveRunState::Running);
            assert_eq!(next_state(r, sid).await.0, HiveRunState::Idle);
        }
        r.sup.stop(sid, 1, "owner".into());
        until_ended(r, sid).await;
        o
    }

    /// P2e-5 — this device as another one sees it: nothing of the session but
    /// its copy in the store — no state directory, an empty folder.
    fn as_another_device(r: &Rig, sid: ObjectId) {
        let state = r
            .root
            .path()
            .join("home")
            .join(".roomler")
            .join("hive")
            .join(sid.to_hex());
        std::fs::remove_dir_all(&state).unwrap();
        for e in std::fs::read_dir(r.root.path().join("work")).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                std::fs::remove_dir_all(&p).unwrap();
            } else {
                std::fs::remove_file(&p).unwrap();
            }
        }
    }

    /// P2e-5 — `o` moved to fence 2, as the server's moved start says it.
    fn moved_start(o: &StartOrder) -> StartOrder {
        StartOrder {
            resume: true,
            ..at_fence(o, 2)
        }
    }

    /// P2e-5 — the fake harness's argv now: read once a turn of the launch in
    /// question ran, so it is that launch's.
    fn launched_with(r: &Rig) -> Vec<String> {
        std::fs::read_to_string(r.root.path().join("work").join(".argv"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// P2e-5 — the assistant's texts in `sid`'s transcript.
    fn said(r: &Rig, sid: ObjectId) -> Vec<String> {
        r.store
            .events(&sid.to_hex())
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::AssistantText { text } => Some(text),
                _ => None,
            })
            .collect()
    }

    /// FR-90 P2g-1 — `r.sup`'s purge of `sid`, under the start lock as the
    /// frame's handler takes it: its store and account parts and the detail.
    async fn purged(
        r: &Rig,
        sid: ObjectId,
    ) -> (
        roomler_ai_remote_control::hive::HivePurgePart,
        roomler_ai_remote_control::hive::HivePurgePart,
        Option<String>,
    ) {
        purged_as(r, sid, false).await
    }

    /// [`purged`], as the frame says: P2k-3 — `leaving`, a member's copy
    /// alone.
    async fn purged_as(
        r: &Rig,
        sid: ObjectId,
        leaving: bool,
    ) -> (
        roomler_ai_remote_control::hive::HivePurgePart,
        roomler_ai_remote_control::hive::HivePurgePart,
        Option<String>,
    ) {
        let purge = ObjectId::new();
        let ack = {
            let _serial = r.sup.start_lock.lock().await;
            r.sup.purge(purge, sid, leaving).await
        };
        match ack {
            ClientMsg::HivePurgeAck {
                purge_id,
                session_id,
                store,
                account,
                detail,
            } => {
                assert_eq!((purge_id, session_id), (purge, sid));
                (store, account, detail)
            }
            other => panic!("not a purge's answer: {other:?}"),
        }
    }

    /// FR-90 P2g-1 — a session that runs here, purged: its run stops first;
    /// then the daemon's copy, its runtime directory and what the device
    /// hosts of it go, and, as its account, its state directory. Done, done.
    /// Its id stays: a purge again finds it done and nothing of the
    /// account's, and a start of it is refused.
    #[tokio::test]
    async fn a_session_running_here_is_purged_whole_and_never_comes_back() {
        use roomler_ai_remote_control::hive::HivePurgePart::{Done, NotThere};
        let me = ObjectId::new();
        let mut r = moving_rig(me, 4);
        let mut o = order(&r);
        o.replicated = true;
        let sid = o.session_id;
        assert!(r.sup.start(o.clone(), true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, None, "hi".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        let hex = sid.to_hex();
        let state_dir = r
            .root
            .path()
            .join("home")
            .join(".roomler")
            .join("hive")
            .join(&hex);
        let run_dir = r.root.path().join("run").join(&hex);
        assert!(state_dir.is_dir() && run_dir.is_dir());
        assert!(r.store.holds(&hex).await.unwrap());
        assert!(r.sup.holds_live(sid));

        // What went first, each by itself; the answer last.
        let answer = purged(&r, sid).await;
        assert!(!r.sup.holds_live(sid), "its run stopped first");
        assert!(!r.store.holds(&hex).await.unwrap(), "nothing of it is held");
        assert!(r.store.is_purged(&hex).await.unwrap(), "its id is kept");
        assert!(!run_dir.exists(), "its runtime directory went");
        assert!(!state_dir.exists(), "its account's state directory went");
        assert_eq!(r.store.purge_debt(&hex).await.unwrap(), None, "settled");
        assert_eq!(answer, (Done, Done, None));

        assert_eq!(
            purged(&r, sid).await,
            (Done, NotThere, None),
            "again: done, and nothing of the account's"
        );
        let answer = r.sup.start(o, true).await;
        assert!(
            answer.refused == Some(HiveRefusal::Other)
                && answer
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.contains("purged")),
            "a purged session is never started: {answer:?}"
        );
    }

    /// FR-90 P2k-3 — a member's copy purged as it leaves goes whole, but not
    /// the session's id: a later join of it (placement choosing the device
    /// again, a teleport) is taken, where a removal that is final refuses it
    /// for ever. A whole session's purge after it is final, as before.
    #[tokio::test]
    async fn a_copy_purged_as_its_member_leaves_may_be_taken_again() {
        use roomler_ai_remote_control::hive::HivePurgePart::{Done, NotThere};
        let r = rig(true, 4);
        let sid = ObjectId::new();
        let hex = sid.to_hex();
        r.store.join(&hex, "owner", 1).await.unwrap();
        assert!(r.store.holds(&hex).await.unwrap());

        assert_eq!(purged_as(&r, sid, true).await, (Done, NotThere, None));
        assert!(!r.store.holds(&hex).await.unwrap(), "its copy went whole");
        assert!(
            !r.store.is_purged(&hex).await.unwrap(),
            "its removal is not final here"
        );
        r.store
            .join(&hex, "owner", 2)
            .await
            .expect("a later join of it is taken");
        assert!(r.store.holds(&hex).await.unwrap());

        assert_eq!(purged_as(&r, sid, false).await.0, Done);
        assert!(
            r.store.is_purged(&hex).await.unwrap(),
            "a whole session's purge is final"
        );
        assert!(
            r.store.join(&hex, "owner", 3).await.is_err(),
            "and refuses a join from then on"
        );
    }

    /// FR-90 P2g-1 — a session this device never held: not there, twice.
    #[tokio::test]
    async fn a_session_never_here_is_purged_as_not_there() {
        use roomler_ai_remote_control::hive::HivePurgePart::NotThere;
        let r = rig(true, 4);
        assert_eq!(
            purged(&r, ObjectId::new()).await,
            (NotThere, NotThere, None)
        );
    }

    /// FR-90 P2g-1 — the account's part failed (its state directory is a
    /// link, which is left as it is): the store's part is done, the account's
    /// says why and its debt is kept. Delivered again once the link is gone,
    /// only the account's part is done again, and settled.
    #[tokio::test]
    async fn an_account_part_that_failed_is_done_at_the_next_delivery() {
        use roomler_ai_remote_control::hive::HivePurgePart::{Done, Failed};
        let me = ObjectId::new();
        let mut r = moving_rig(me, 4);
        let o = ran_twice(&mut r).await;
        let (sid, hex) = (o.session_id, o.session_id.to_hex());
        let state_dir = r
            .root
            .path()
            .join("home")
            .join(".roomler")
            .join("hive")
            .join(&hex);
        let elsewhere = r.root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("keep"), "x").unwrap();
        std::fs::remove_dir_all(&state_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &state_dir).unwrap();

        let (store, account, detail) = purged(&r, sid).await;
        assert_eq!((store, account), (Done, Failed), "{detail:?}");
        assert!(
            detail.as_deref().is_some_and(|d| d.contains("link")),
            "{detail:?}"
        );
        assert!(
            r.store.purge_debt(&hex).await.unwrap().is_some(),
            "kept for the next delivery"
        );
        assert!(elsewhere.join("keep").exists(), "nothing through the link");

        std::fs::remove_file(&state_dir).unwrap();
        std::fs::create_dir_all(state_dir.join("claude")).unwrap();
        assert_eq!(purged(&r, sid).await, (Done, Done, None));
        assert!(!state_dir.exists());
        assert_eq!(r.store.purge_debt(&hex).await.unwrap(), None, "settled");
    }

    /// P2e-5 — a start the record moved here from another device takes the
    /// session over from its copy, as the account: the conversation's history
    /// and the folder are put in place before the harness resumes it, and it
    /// counts on from the session's turns.
    #[tokio::test]
    async fn a_moved_session_is_taken_over_from_its_copy_and_counts_on() {
        let me = ObjectId::new();
        let mut r = moving_rig(me, 4);
        let o = ran_twice(&mut r).await;
        let sid = o.session_id;
        as_another_device(&r, sid);

        // P2f-5 — it ran on venus before mars: the move names both places.
        let place = |device: &str, folder: &str| HivePlace {
            device_name: device.into(),
            folder: folder.into(),
        };
        r.sup.receive_move(Moved {
            session_id: sid,
            fence: 2,
            turns: 2,
            from_device_id: ObjectId::new(),
            from_device_name: "mars".into(),
            from_folder: "/srv/work".into(),
            moved_by_name: "Alice".into(),
            moved_at_ms: 1_791_813_720_000,
            earlier: vec![place("venus", "/home/a/work"), place("mars", "/srv/work")],
        });
        assert_eq!(
            r.sup.start(moved_start(&o), true).await,
            Answer::accepted("dev")
        );
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert_eq!(
            std::fs::read_to_string(r.root.path().join("work").join("notes.md"))
                .unwrap_or_default(),
            "the session's work\n",
            "the folder is put back"
        );
        assert!(
            !notes(&r, sid).iter().any(|n| n.contains("restarted")),
            "a move is no restart: {:?}",
            notes(&r, sid)
        );
        // P2e-7 — told it moved, once: the note left for the `SessionStart`
        // hook, which the session's settings carry.
        let run = r.root.path().join("run").join(sid.to_hex());
        let note = std::fs::read_to_string(run.join(resume_note::NOTE_FILE)).unwrap_or_default();
        assert!(
            note.starts_with(
                "This session was moved to this device by Alice at 2026-10-12 14:02 UTC.\n\
                 It ran on mars, in /srv/work."
            ),
            "the resume note is left for the hook: {note:?}"
        );
        assert!(
            note.contains(
                "Paths in earlier turns under /home/a/work and /srv/work now live under "
            ),
            "every folder its earlier turns worked in: {note:?}"
        );
        let settings: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(run.join("settings.json")).unwrap())
                .unwrap();
        let hook = &settings["hooks"]["SessionStart"][0];
        assert_eq!(
            hook["matcher"], "resume",
            "the settings carry the hook, on a resume: {settings}"
        );
        assert!(
            hook["hooks"][0]["command"]
                .as_str()
                .is_some_and(|c| c.contains(resume_note::RESUME_NOTE_SUBCOMMAND)),
            "the hook prints it: {settings}"
        );
        r.sup.prompt(sid, None, "recall".into()).unwrap();
        let (turns, _, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert_eq!(
            turns.iter().map(|t| (t.turn, t.status)).collect::<Vec<_>>(),
            [(3, HiveTurnStatus::Running), (3, HiveTurnStatus::Ok)],
            "counted on from the session's two turns"
        );
        assert!(
            notes(&r, sid).contains(&note),
            "the transcript says what the harness was told: {:?}",
            notes(&r, sid)
        );
        // Read once a turn ran: the folder put back holds fence 1's `.argv`,
        // which the new harness replaced as it started.
        assert!(
            launched_with(&r).iter().any(|a| a == "--resume"),
            "it resumes the conversation it was given: {:?}",
            launched_with(&r)
        );
        assert!(
            said(&r, sid).contains(&"history: 3".to_string()),
            "the history holds the two turns before the move: {:?}",
            said(&r, sid)
        );
        assert_eq!(hosted_on_disk(&r)[0].turns, 3);
        r.sup.stop(sid, 2, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-7 — the last tool call the store holds no result for, as the
    /// resume note names it; another call's result answers nothing.
    #[tokio::test]
    async fn the_note_names_the_last_tool_call_left_without_a_result() {
        let r = rig(true, 4);
        let sid = ObjectId::new().to_hex();
        assert_eq!(last_open_call(&r.store, &sid).await, None, "no tool call");
        let call = |id: &str, cmd: &str| TranscriptEvent::ToolUse {
            id: id.into(),
            name: "Bash".into(),
            input: serde_json::json!({ "command": cmd }),
        };
        let result = |id: &str| TranscriptEvent::ToolResult {
            tool_use_id: id.into(),
            ok: true,
            output: "ok".into(),
            truncated: false,
        };
        r.store.append(&sid, 1, call("t1", "ls"));
        r.store.append(&sid, 1, result("t1"));
        assert_eq!(
            last_open_call(&r.store, &sid).await,
            None,
            "a call its result follows is no open call"
        );
        r.store.append(&sid, 1, call("t2", "cargo test"));
        assert_eq!(
            last_open_call(&r.store, &sid).await.as_deref(),
            Some("cargo test"),
            "left open"
        );
        r.store.append(&sid, 1, result("t1"));
        assert_eq!(
            last_open_call(&r.store, &sid).await.as_deref(),
            Some("cargo test"),
            "another call's result answers nothing"
        );
    }

    /// P2e-5 — a move back is the session coming back where its state is:
    /// nothing is put in place over it. (Had the copy been, the folder this
    /// one changed since would have been refused as the person's own work.)
    #[tokio::test]
    async fn a_move_back_puts_nothing_in_place_and_resumes_the_state_here() {
        let me = ObjectId::new();
        let mut r = moving_rig(me, 4);
        let o = ran_twice(&mut r).await;
        let sid = o.session_id;
        std::fs::remove_file(r.root.path().join("work").join("notes.md")).unwrap();

        r.sup.receive_move(Moved {
            session_id: sid,
            fence: 2,
            turns: 2,
            from_device_id: me,
            from_device_name: "mars".into(),
            from_folder: "/srv/work".into(),
            moved_by_name: "Alice".into(),
            moved_at_ms: 1_791_813_720_000,
            earlier: Vec::new(),
        });
        // P2e-7 — a note an earlier move left here.
        let left = r
            .root
            .path()
            .join("run")
            .join(sid.to_hex())
            .join(resume_note::NOTE_FILE);
        std::fs::write(&left, "an earlier move's note\n").unwrap();
        assert_eq!(
            r.sup.start(moved_start(&o), true).await,
            Answer::accepted("dev")
        );
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        assert!(
            !r.root.path().join("work").join("notes.md").exists(),
            "nothing put in place"
        );
        let now = std::fs::read_to_string(&left).unwrap_or_default();
        assert!(
            !now.contains("moved to this device"),
            "a move back is told nothing: {now:?}"
        );
        assert!(!left.exists(), "and the note an earlier move left is gone");
        r.sup.prompt(sid, None, "recall".into()).unwrap();
        let (turns, _, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert_eq!(turns.last().map(|t| t.turn), Some(3));
        assert!(said(&r, sid).contains(&"history: 3".to_string()));
        assert!(
            !notes(&r, sid)
                .iter()
                .any(|n| n.contains("moved to this device")),
            "nor does its transcript say it moved: {:?}",
            notes(&r, sid)
        );
        r.sup.stop(sid, 2, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2e-5 — a moved start that cannot take the session over is refused,
    /// in words that name none of the account's files, and launches nothing:
    /// a copy with no checkpoint to start from; a session that has had turns
    /// with no history of them here.
    #[tokio::test]
    async fn a_moved_start_that_cannot_take_the_session_over_is_refused() {
        let me = ObjectId::new();
        let mut r = moving_rig(me, 4);
        const WORDS: &str = "this device could not take the session over from its copy \
                             (its log says why)";

        // Never replicated: no checkpoint in the copy.
        let plain = order(&r);
        let sid = plain.session_id;
        assert!(r.sup.start(plain.clone(), true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.prompt(sid, None, "hi".into()).unwrap();
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
        r.sup.receive_move(Moved {
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
        assert_eq!(
            r.sup.start(moved_start(&plain), true).await,
            Answer::refused(HiveRefusal::LaunchFailed, WORDS),
            "never replicated: no checkpoint to start from"
        );
        assert!(!r.sup.holds_live(sid));

        // Moved back with its history gone.
        let o = ran_twice(&mut r).await;
        let sid = o.session_id;
        as_another_device(&r, sid);
        r.sup.receive_move(Moved {
            session_id: sid,
            fence: 2,
            turns: 2,
            from_device_id: me,
            from_device_name: "mars".into(),
            from_folder: "/srv/work".into(),
            moved_by_name: "Alice".into(),
            moved_at_ms: 1_791_813_720_000,
            earlier: Vec::new(),
        });
        assert_eq!(
            r.sup.start(moved_start(&o), true).await,
            Answer::refused(HiveRefusal::LaunchFailed, WORDS),
            "moved back with its history gone"
        );
        assert!(!r.sup.holds_live(sid));
    }

    /// P2e-5 — a session moved before its first prompt has no history: it
    /// starts its conversation on the new device, with `--session-id`.
    #[tokio::test]
    async fn a_session_moved_before_its_first_prompt_begins_its_conversation_there() {
        let me = ObjectId::new();
        let mut r = moving_rig(me, 4);
        let mut o = order(&r);
        o.replicated = true;
        let sid = o.session_id;
        assert!(r.sup.start(o.clone(), true).await.refused.is_none());
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        // The drain's own checkpoint (P2e-4): the copy's only one.
        answered(drain(&r, sid, 1)).await.expect("drained");
        r.sup.stop(sid, 1, "owner".into());
        until_ended(&mut r, sid).await;
        as_another_device(&r, sid);

        r.sup.receive_move(Moved {
            session_id: sid,
            fence: 2,
            turns: 0,
            from_device_id: ObjectId::new(),
            from_device_name: "mars".into(),
            from_folder: "/srv/work".into(),
            moved_by_name: "Alice".into(),
            moved_at_ms: 1_791_813_720_000,
            earlier: Vec::new(),
        });
        assert_eq!(
            r.sup.start(moved_start(&o), true).await,
            Answer::accepted("dev")
        );
        assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Idle);
        // The new harness has rewritten `.argv` (the folder put back holds
        // fence 1's) as it started, its first act.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let argv = launched_with(&r);
        assert!(
            argv.iter().any(|a| a == "--session-id") && !argv.iter().any(|a| a == "--resume"),
            "nothing to resume yet: {argv:?}"
        );
        r.sup.prompt(sid, None, "hello".into()).unwrap();
        let (turns, _, _) = reports_until(&mut r, sid, HiveRunState::Idle).await;
        assert_eq!(
            turns.last().map(|t| (t.turn, t.status)),
            Some((1, HiveTurnStatus::Ok))
        );
        r.sup.stop(sid, 2, "owner".into());
        until_ended(&mut r, sid).await;
    }

    /// P2f-3a — the harness id of the rig's forks.
    const FORK_HID: &str = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b";

    /// P2f-3a — [`moving_rig`], with a second folder under `hive_roots`,
    /// `work2`, for a fork to run in beside its parent's `work`.
    fn forking_rig(me: ObjectId) -> Rig {
        use super::super::checkpointer::Runner;
        rig_with(
            true,
            4,
            |cfg| {
                let work2 = cfg.roots[0].with_file_name("work2");
                std::fs::create_dir_all(&work2).unwrap();
                cfg.roots.push(work2);
            },
            |mut s| {
                // The rig's root is under /tmp: git's discovery stops there.
                s.checkpoint_runner = Some(Runner::InProcess {
                    ceiling: PathBuf::from("/tmp"),
                });
                s.agent_id = Some(me);
                s
            },
        )
    }

    /// P2f-3a — a fork of `parent` into `work2`, as the server starts it.
    fn forked_from(r: &Rig, parent: &StartOrder) -> StartOrder {
        StartOrder {
            harness_session: FORK_HID.into(),
            folder: r.root.path().join("work2").to_string_lossy().into(),
            replicated: true,
            fork_of: Some(HiveForkOf {
                session_id: parent.session_id,
                harness_session: parent.harness_session.clone(),
            }),
            ..order(r)
        }
    }

    /// P2f-3a — `sid`'s checkpoints, as the store holds them.
    fn chain_in(r: &Rig, sid: ObjectId) -> Vec<Checkpoint> {
        r.store
            .events(&sid.to_hex())
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::Checkpoint(c) => Some(c),
                _ => None,
            })
            .collect()
    }

    /// P2f-3a — the fake harness's argv in `folder` now.
    fn argv_in(folder: &Path) -> Vec<String> {
        std::fs::read_to_string(folder.join(".argv"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// P2f-3a — a fork's first start: the parent's last checkpoint, from this
    /// device's copy, put in place under the fork's own ids, then a launch
    /// that resumes the parent's conversation as a new one with the fork's
    /// id. The fork remembers the parent's turns, counts its own from one,
    /// is told it is a fork, and its own checkpoints keep the parent's
    /// history beside its own; nothing of the parent changes. Once it has a
    /// history of its own, it launches as any session does, and is told
    /// nothing.
    #[tokio::test]
    async fn a_fork_starts_from_its_parents_copy_under_its_own_ids() {
        let mut r = forking_rig(ObjectId::new());
        let mut parent = order(&r);
        parent.replicated = true;
        let (psid, phid) = (parent.session_id, parent.harness_session.clone());
        assert!(r.sup.start(parent.clone(), true).await.refused.is_none());
        assert_eq!(next_state(&mut r, psid).await.0, HiveRunState::Idle);
        let home = r.root.path().join("home");
        let pconfig = config_dir_in(&session_state_dir(&home, &psid.to_hex()));
        let saved = pconfig.join(format!("projects/hive-{phid}/{phid}/tool-results/t1.txt"));
        std::fs::create_dir_all(saved.parent().unwrap()).unwrap();
        std::fs::write(&saved, "a long output\n").unwrap();
        std::fs::write(
            r.root.path().join("work").join("notes.md"),
            "the parent's work\n",
        )
        .unwrap();
        for text in ["hi", "again"] {
            r.sup.prompt(psid, None, text.into()).unwrap();
            assert_eq!(next_state(&mut r, psid).await.0, HiveRunState::Running);
            assert_eq!(next_state(&mut r, psid).await.0, HiveRunState::Idle);
        }
        r.sup.stop(psid, 1, "owner".into());
        until_ended(&mut r, psid).await;
        let phistory = history_path_in(&pconfig, &phid);
        let (parent_history, parent_chain) =
            (std::fs::read(&phistory).unwrap(), chain_in(&r, psid));

        let fork = forked_from(&r, &parent);
        let fsid = fork.session_id;
        assert_eq!(
            r.sup.start(fork.clone(), true).await,
            Answer::accepted("dev")
        );
        assert_eq!(next_state(&mut r, fsid).await.0, HiveRunState::Idle);
        let fconfig = config_dir_in(&session_state_dir(&home, &fsid.to_hex()));
        let fproject = fconfig.join(format!("projects/hive-{FORK_HID}"));
        assert_eq!(
            std::fs::read(fproject.join(format!("{phid}.jsonl"))).unwrap(),
            parent_history,
            "the parent's history, under the fork's project name"
        );
        assert_eq!(
            std::fs::read_to_string(fproject.join(format!("{phid}/tool-results/t1.txt"))).unwrap(),
            "a long output\n"
        );
        let work2 = r.root.path().join("work2");
        assert_eq!(
            std::fs::read_to_string(work2.join("notes.md")).unwrap_or_default(),
            "the parent's work\n",
            "the parent's folder, in the fork's"
        );
        // Told it is a fork, through the hook its settings carry on a fork's
        // launch as on a resume.
        let run = r.root.path().join("run").join(fsid.to_hex());
        let note = std::fs::read_to_string(run.join(resume_note::NOTE_FILE)).unwrap_or_default();
        assert!(
            note.starts_with("This session is a fork:"),
            "told it is a fork: {note:?}"
        );
        // The parent's folder as the device resolved it: on macOS `/tmp` is
        // a link to `/private/tmp` (CI's macOS lane, the first run).
        let work = std::fs::canonicalize(r.root.path().join("work")).unwrap();
        assert!(
            note.contains(&format!("Those turns worked in {}", work.display())),
            "{note:?}"
        );
        assert!(
            note.contains(&format!(
                "named hive-{phid} are under {} now",
                fproject.display()
            )),
            "{note:?}"
        );
        let settings: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(run.join("settings.json")).unwrap())
                .unwrap();
        let matchers: Vec<&str> = settings["hooks"]["SessionStart"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|h| h["matcher"].as_str())
            .collect();
        assert_eq!(matchers, ["resume", "fork"], "{settings}");

        r.sup.prompt(fsid, None, "recall".into()).unwrap();
        let (turns, _, _) = reports_until(&mut r, fsid, HiveRunState::Idle).await;
        assert_eq!(
            turns.iter().map(|t| (t.turn, t.status)).collect::<Vec<_>>(),
            [(1, HiveTurnStatus::Running), (1, HiveTurnStatus::Ok)],
            "the fork counts its own turns"
        );
        let argv = argv_in(&work2);
        assert!(
            argv.windows(5).any(|w| w
                == [
                    "--resume",
                    phid.as_str(),
                    "--fork-session",
                    "--session-id",
                    FORK_HID
                ]),
            "{argv:?}"
        );
        assert!(
            said(&r, fsid).contains(&"history: 3".to_string()),
            "the parent's two prompts, then its own: {:?}",
            said(&r, fsid)
        );
        let costs: Vec<Option<f64>> = r
            .store
            .events(&fsid.to_hex())
            .into_iter()
            .filter_map(|e| match e {
                TranscriptEvent::Turn { cost_usd, .. } => Some(cost_usd),
                _ => None,
            })
            .collect();
        assert_eq!(
            costs,
            [None],
            "its first turn claims no cost, as a resumed process's: the running total may \
             have begun at its parent's"
        );
        assert!(notes(&r, fsid).contains(&note), "{:?}", notes(&r, fsid));
        let fchain = chain_in(&r, fsid);
        let last = fchain.last().expect("a checkpoint at the turn's end");
        let paths: Vec<&str> = last.files.iter().map(|f| f.path.as_str()).collect();
        for kept in [
            format!("projects/hive-{FORK_HID}/{phid}.jsonl"),
            format!("projects/hive-{FORK_HID}/{phid}/tool-results/t1.txt"),
            format!("projects/hive-{FORK_HID}/{FORK_HID}.jsonl"),
        ] {
            assert!(paths.contains(&kept.as_str()), "{kept} in {paths:?}");
        }
        assert_eq!(
            hosted_on_disk(&r)
                .into_iter()
                .find(|h| h.session == fsid.to_hex())
                .and_then(|h| h.fork_of),
            fork.fork_of,
            "hosted as a fork"
        );
        assert_eq!(std::fs::read(&phistory).unwrap(), parent_history);
        assert_eq!(
            chain_in(&r, psid),
            parent_chain,
            "the parent's copy is as it was"
        );
        r.sup.stop(fsid, 1, "owner".into());
        until_ended(&mut r, fsid).await;

        // With a history of its own: a plain resume, and nothing to be told.
        assert_eq!(
            r.sup.start(at_fence(&fork, 2), true).await,
            Answer::accepted("dev")
        );
        assert_eq!(next_state(&mut r, fsid).await.0, HiveRunState::Idle);
        assert!(
            !run.join(resume_note::NOTE_FILE).exists(),
            "nothing to tell"
        );
        r.sup.prompt(fsid, None, "recall".into()).unwrap();
        reports_until(&mut r, fsid, HiveRunState::Idle).await;
        let argv = argv_in(&work2);
        assert!(
            argv.windows(2).any(|w| w == ["--resume", FORK_HID])
                && !argv.iter().any(|a| a == "--fork-session" || *a == phid),
            "{argv:?}"
        );
        assert!(
            said(&r, fsid).contains(&"history: 4".to_string()),
            "{:?}",
            said(&r, fsid)
        );
        r.sup.stop(fsid, 2, "owner".into());
        until_ended(&mut r, fsid).await;
    }

    /// P2f-3a — a fork's first start with nothing to make it from is
    /// refused, in words, and launches nothing: no copy of the parent here;
    /// a parent with no conversation yet; a fork of itself, by either id;
    /// and a folder that holds work of its own, which keeps it.
    #[tokio::test]
    async fn a_fork_with_nothing_to_start_from_is_refused_and_launches_nothing() {
        let mut r = forking_rig(ObjectId::new());
        let work2 = r.root.path().join("work2");
        let stranger = forked_from(&r, &order(&r));
        assert_eq!(
            r.sup.start(stranger.clone(), true).await,
            Answer::refused(
                HiveRefusal::Other,
                "this device holds no copy of the session the fork is made from"
            )
        );
        assert!(!r.sup.holds_live(stranger.session_id));
        assert!(argv_in(&work2).is_empty(), "nothing launched");

        // A copy whose checkpoint holds no conversation yet.
        let mut quiet = order(&r);
        quiet.replicated = true;
        let qsid = quiet.session_id;
        assert!(r.sup.start(quiet.clone(), true).await.refused.is_none());
        assert_eq!(next_state(&mut r, qsid).await.0, HiveRunState::Idle);
        answered(drain(&r, qsid, 1)).await.expect("drained");
        r.sup.stop(qsid, 1, "owner".into());
        until_ended(&mut r, qsid).await;
        let early = forked_from(&r, &quiet);
        assert_eq!(
            r.sup.start(early.clone(), true).await,
            Answer::refused(
                HiveRefusal::Other,
                "the session the fork is made from has no conversation to fork yet"
            )
        );
        assert!(!r.sup.holds_live(early.session_id));

        const ITSELF: &str = "a fork must be made from another session, named by its ids";
        let mut itself = forked_from(&r, &quiet);
        itself.fork_of = Some(HiveForkOf {
            session_id: itself.session_id,
            harness_session: quiet.harness_session.clone(),
        });
        assert_eq!(
            r.sup.start(itself, true).await,
            Answer::refused(HiveRefusal::Other, ITSELF)
        );
        let mut same_harness = forked_from(&r, &quiet);
        same_harness.harness_session = quiet.harness_session.clone();
        assert_eq!(
            r.sup.start(same_harness, true).await,
            Answer::refused(HiveRefusal::Other, ITSELF)
        );

        // A folder holding the person's own work.
        let parent = ran_twice(&mut r).await;
        std::fs::write(work2.join("mine.txt"), "the person's own\n").unwrap();
        let dirty = forked_from(&r, &parent);
        let answer = r.sup.start(dirty.clone(), true).await;
        assert_eq!(answer.refused, Some(HiveRefusal::FolderDirty), "{answer:?}");
        assert!(!r.sup.holds_live(dirty.session_id));
        assert_eq!(
            std::fs::read_to_string(work2.join("mine.txt")).unwrap(),
            "the person's own\n"
        );
        assert!(argv_in(&work2).is_empty(), "nothing launched");
    }

    /// FR-90 P2f-3d — a fork into the folder its parent runs in here is
    /// refused `folder_dirty`, a sibling named, even where the folder's own
    /// question would let it in: a clean repository holding all the parent's
    /// work. Two harnesses would work one folder, and the server, which
    /// compares the folder only as typed, cannot see another spelling of it.
    #[tokio::test]
    async fn a_fork_into_the_folder_its_parent_runs_in_here_is_refused() {
        let git = |dir: &Path, args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .args([
                    "-c",
                    "user.name=Person",
                    "-c",
                    "user.email=person@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output();
            matches!(out, Ok(o) if o.status.success())
        };
        let mut r = forking_rig(ObjectId::new());
        let work = r.root.path().join("work");
        if !git(&work, &["--version"]) {
            return eprintln!("no git here");
        }
        // The parent's folder: a repository at its HEAD, the fake harness's
        // own files ignored.
        let app = work.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("a.txt"), "one\n").unwrap();
        std::fs::write(
            app.join(".gitignore"),
            ".argv\n.pid\n.stdin\n.claude_md\n.memory_md\n",
        )
        .unwrap();
        for args in [
            &["init", "-q"][..],
            &["add", "-A"],
            &["commit", "-q", "-m", "first"],
        ] {
            assert!(git(&app, args), "{args:?}");
        }
        let mut parent = order(&r);
        parent.replicated = true;
        parent.folder = app.display().to_string();
        let psid = parent.session_id;
        assert!(r.sup.start(parent.clone(), true).await.refused.is_none());
        assert_eq!(next_state(&mut r, psid).await.0, HiveRunState::Idle);
        r.sup.prompt(psid, None, "hi".into()).unwrap();
        assert_eq!(next_state(&mut r, psid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, psid).await.0, HiveRunState::Idle);

        // Its folder, typed another way.
        let fork = StartOrder {
            folder: app.join(".").display().to_string(),
            ..forked_from(&r, &parent)
        };
        let answer = r.sup.start(fork.clone(), true).await;
        assert_eq!(answer.refused, Some(HiveRefusal::FolderDirty), "{answer:?}");
        let detail = answer.detail.unwrap_or_default();
        assert!(
            detail.contains("the session it forks runs in this folder")
                && detail.contains("git worktree add")
                && detail.contains("and fork there"),
            "why, and a sibling named: {detail}"
        );
        assert!(!r.sup.holds_live(fork.session_id), "nothing launched");
        assert!(r.sup.holds_live(psid), "the parent runs on");
    }

    /// P2f-3a — the argv in `folder` of a harness that names `id`, once it
    /// has started. A fork's folder holds its parent's tree, and with it the
    /// parent's harness's `.argv` and `.pid`.
    async fn argv_naming(folder: &Path, id: &str) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let argv = argv_in(folder);
            if argv.iter().any(|a| a == id) {
                return argv;
            }
            assert!(Instant::now() < deadline, "the harness never started");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// P2f-3a — [`go_down`], the harness named by what the device hosts of
    /// `sid`, not by its folder's `.pid`: a fork's folder holds its parent's.
    async fn go_down_hosted(r: &Rig, sid: ObjectId) {
        r.sup.begin_shutdown();
        let pid = hosted_on_disk(r)
            .into_iter()
            .find(|h| h.session == sid.to_hex())
            .and_then(|h| h.harness_pid)
            .expect("the harness's pid, as hosted");
        // SAFETY: a signal to the fake harness's own process group.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while r.sup.holds_live(sid) {
            assert!(Instant::now() < deadline, "the session never let go");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// P2f-3a — a fork the device went down with before its first prompt
    /// resumes as it was put in place: from its parent's history again, told
    /// again, and nothing made again from the parent's copy, so it stays
    /// where it was made. With its parent's history gone, it is not resumed:
    /// never started empty.
    #[tokio::test]
    async fn a_fork_restarted_before_its_first_prompt_starts_from_its_parent_again() {
        let mut r = forking_rig(ObjectId::new());
        let parent = ran_twice(&mut r).await;
        let fork = forked_from(&r, &parent);
        let fsid = fork.session_id;
        let work2 = r.root.path().join("work2");
        assert_eq!(
            r.sup.start(fork.clone(), true).await,
            Answer::accepted("dev")
        );
        assert_eq!(next_state(&mut r, fsid).await.0, HiveRunState::Idle);
        argv_naming(&work2, FORK_HID).await;
        // What a copy made again would put back.
        std::fs::remove_file(work2.join("notes.md")).unwrap();
        let note = r
            .root
            .path()
            .join("run")
            .join(fsid.to_hex())
            .join(resume_note::NOTE_FILE);

        go_down_hosted(&r, fsid).await;
        std::fs::remove_file(work2.join(".argv")).unwrap();
        std::fs::remove_file(&note).unwrap();
        restart(&mut r, |_| {});
        let (_, manifest) = until_manifest(&mut r).await;
        assert_eq!(manifest, [(fsid, 1)], "resumed as hosted");
        let argv = argv_naming(&work2, FORK_HID).await;
        assert!(
            argv.windows(5).any(|w| w
                == [
                    "--resume",
                    parent.harness_session.as_str(),
                    "--fork-session",
                    "--session-id",
                    FORK_HID
                ]),
            "{argv:?}"
        );
        assert!(
            std::fs::read_to_string(&note)
                .unwrap_or_default()
                .starts_with("This session is a fork:"),
            "told again"
        );
        assert!(
            !work2.join("notes.md").exists(),
            "nothing made again from the parent's copy"
        );

        go_down_hosted(&r, fsid).await;
        std::fs::remove_file(work2.join(".argv")).unwrap();
        let home = r.root.path().join("home");
        let fconfig = config_dir_in(&session_state_dir(&home, &fsid.to_hex()));
        std::fs::remove_file(parent_history_in(
            &fconfig,
            FORK_HID,
            &parent.harness_session,
        ))
        .unwrap();
        restart(&mut r, |_| {});
        let (seen, manifest) = until_manifest(&mut r).await;
        assert!(manifest.is_empty(), "not resumed: {manifest:?}");
        let why = seen
            .into_iter()
            .find_map(|m| match m {
                ClientMsg::HiveState {
                    session_id,
                    state: Some(HiveRunState::Ended),
                    detail,
                    ..
                } if session_id == fsid => detail,
                _ => None,
            })
            .expect("reported ended");
        assert!(
            why.contains("the conversation this fork starts from is not on this device"),
            "{why}"
        );
        assert!(argv_in(&work2).is_empty(), "nothing launched");
        assert!(hosted_on_disk(&r).is_empty(), "forgotten");
    }

    /// P2e-6a — a ready prepare names where this device's copy of the session
    /// ends, its store's tip; a refused one names none.
    #[tokio::test]
    async fn the_prepare_names_where_its_copy_ends_when_ready() {
        let me = ObjectId::new();
        let mut r = moving_rig(me, 1);
        let o = ran_twice(&mut r).await;
        let held = r
            .store
            .chain_tip(&o.session_id.to_hex())
            .await
            .unwrap()
            .unwrap();
        let (answer, tip) = r.sup.prepare_with_tip(&at_fence(&o, 2), true).await;
        assert_eq!(answer, Answer::accepted("dev"));
        assert_eq!(
            tip,
            Some(roomler_ai_remote_control::hive::HiveCopyTip {
                fence: held.fence,
                seq: held.seq,
                hash: hex::encode(held.hash),
            }),
            "ready: where its copy ends, the store's tip"
        );
        let mut no_copy = at_fence(&o, 2);
        no_copy.session_id = ObjectId::new();
        let (answer, tip) = r.sup.prepare_with_tip(&no_copy, true).await;
        assert!(answer.refused.is_some());
        assert_eq!(tip, None, "refused: no tip");
    }

    /// P2e-5 — the prepare answers with every gate a start passes, as the
    /// device is configured now, and the copy, and changes nothing: a run of
    /// the session here goes on, at its own fence.
    #[tokio::test]
    async fn the_prepare_answers_with_a_starts_gates_and_moves_nothing() {
        let me = ObjectId::new();
        let mut r = moving_rig(me, 1);
        let o = ran_twice(&mut r).await;
        let at2 = at_fence(&o, 2);
        assert_eq!(r.sup.prepare(&at2, true).await, Answer::accepted("dev"));
        assert_eq!(
            r.sup.prepare(&at2, false).await.refused,
            Some(HiveRefusal::HiveDisabled),
            "a secondary org's"
        );
        let mut stranger = at2.clone();
        stranger.user_id = ObjectId::new();
        stranger.user_email = "stranger@example.com".into();
        assert_eq!(
            r.sup.prepare(&stranger, true).await.refused,
            Some(HiveRefusal::NoAccount)
        );
        let mut elsewhere = at2.clone();
        elsewhere.folder = "/etc".into();
        assert_eq!(
            r.sup.prepare(&elsewhere, true).await.refused,
            Some(HiveRefusal::FolderNotAllowed)
        );
        let mut no_copy = at2.clone();
        no_copy.session_id = ObjectId::new();
        assert_eq!(
            r.sup.prepare(&no_copy, true).await,
            Answer::refused(
                HiveRefusal::Other,
                "this device holds no copy of the session to take it over from"
            )
        );

        // Another session runs here, at fence 1: the device is full for any
        // other, and the prepare of its own move stops nothing.
        let mut busy = order(&r);
        busy.replicated = true;
        let bid = busy.session_id;
        assert!(r.sup.start(busy.clone(), true).await.refused.is_none());
        assert_eq!(next_state(&mut r, bid).await.0, HiveRunState::Idle);
        r.sup.prompt(bid, None, "hi".into()).unwrap();
        assert_eq!(next_state(&mut r, bid).await.0, HiveRunState::Running);
        assert_eq!(next_state(&mut r, bid).await.0, HiveRunState::Idle);
        assert_eq!(
            r.sup.prepare(&at2, true).await.refused,
            Some(HiveRefusal::AtCapacity),
            "the only place is taken"
        );
        assert_eq!(
            r.sup.prepare(&at_fence(&busy, 2), true).await,
            Answer::accepted("dev"),
            "its own run gives its place up to the move"
        );
        assert_eq!(
            r.sup.prepare(&busy, true).await,
            Answer::accepted("dev"),
            "at the fence it runs at"
        );
        assert_eq!(
            r.sup.prepare(&at_fence(&busy, 0), true).await,
            Answer::refused(
                HiveRefusal::Other,
                "this device runs the session at fence 1"
            ),
            "an older fence than the run here"
        );
        assert!(r.sup.runs_at(bid, 1), "the prepare stopped nothing");
        r.sup.stop(bid, 1, "owner".into());
        until_ended(&mut r, bid).await;
    }

    /// FR-90 P2f-1a — a teleport's prepare asks every gate a promotion's asks
    /// but the copy, which the device takes after it. One that passes admits
    /// that session's join in the teleport's role, whatever the owner's
    /// `hive_replica` (off in the rig): at the record's fence, the one before
    /// the start's the prepare named, and for that session only, until the
    /// session launches here or the admission runs out. A refused prepare
    /// admits nothing, and neither does a promotion's. A device prepared for a
    /// teleport tells the server about the copy it takes.
    #[tokio::test]
    async fn a_teleports_prepare_asks_every_gate_but_the_copy_and_admits_its_join() {
        use roomler_ai_remote_control::hive::{HiveJoinRefusal, HiveReplicaRole};
        let r = moving_rig(ObjectId::new(), 1);
        let teleport = Some(HiveReplicaRole::Teleport);
        let o = at_fence(&order(&r), 2);
        let sid = o.session_id;
        let join = |session: ObjectId, fence: u64, role: Option<HiveReplicaRole>, is_primary| {
            let sup = Arc::clone(&r.sup);
            async move {
                sup.answer_join(is_primary, session, fence, role, &[])
                    .await
                    .0
            }
        };
        assert_eq!(
            r.sup.prepare(&o, true).await,
            Answer::refused(
                HiveRefusal::Other,
                "this device holds no copy of the session to take it over from"
            ),
            "a promotion's prepare needs the copy"
        );
        assert_eq!(
            join(sid, 1, teleport, true).await,
            Some(HiveJoinRefusal::NotPrepared),
            "and admits nothing"
        );

        assert_eq!(
            r.sup.prepare_teleport(&o, false, false).await.refused,
            Some(HiveRefusal::HiveDisabled),
            "a secondary org's"
        );
        let mut stranger = o.clone();
        stranger.user_id = ObjectId::new();
        stranger.user_email = "stranger@example.com".into();
        assert_eq!(
            r.sup.prepare_teleport(&stranger, true, false).await.refused,
            Some(HiveRefusal::NoAccount)
        );
        let mut elsewhere = o.clone();
        elsewhere.folder = "/etc".into();
        assert_eq!(
            r.sup
                .prepare_teleport(&elsewhere, true, false)
                .await
                .refused,
            Some(HiveRefusal::FolderNotAllowed)
        );
        assert_eq!(
            join(sid, 1, teleport, true).await,
            Some(HiveJoinRefusal::NotPrepared),
            "a refused prepare admits nothing"
        );
        assert!(!r.sup.reports_copies());

        assert_eq!(
            r.sup.prepare_teleport(&o, true, false).await,
            Answer::accepted("dev"),
            "no copy needed"
        );
        assert_eq!(
            join(sid, 2, teleport, true).await,
            Some(HiveJoinRefusal::NotPrepared),
            "the join comes at the record's fence, not the start's"
        );
        assert_eq!(
            join(ObjectId::new(), 1, teleport, true).await,
            Some(HiveJoinRefusal::NotPrepared),
            "another session"
        );
        assert_eq!(
            join(sid, 1, Some(HiveReplicaRole::Owner), true).await,
            Some(HiveJoinRefusal::ReplicaDisabled),
            "the prepare admits the teleport's role only"
        );
        assert_eq!(
            join(sid, 1, teleport, false).await,
            Some(HiveJoinRefusal::SecondaryOrg)
        );
        assert_eq!(
            join(sid, 1, teleport, true).await,
            None,
            "admitted: it takes the copy it will run"
        );
        assert_eq!(
            join(sid, 1, teleport, true).await,
            None,
            "a join re-sent at a connection is admitted too"
        );
        assert!(
            r.sup.reports_copies(),
            "it tells the server about the copy it takes"
        );
        assert_eq!(store_memberships(&r).await, [sid.to_hex()]);
        assert_eq!(r.store.floor(&sid.to_hex()).await.unwrap(), Some(1));

        // The session launched here at the prepare's fence: done with.
        r.sup.forget_teleport(sid, 1);
        assert_eq!(join(sid, 1, teleport, true).await, None, "an older launch");
        r.sup.forget_teleport(sid, 2);
        assert_eq!(
            join(sid, 1, teleport, true).await,
            Some(HiveJoinRefusal::NotPrepared),
            "launched at the prepare's fence"
        );
        // And an admission past its time admits nothing.
        if let Some(long_ago) =
            Instant::now().checked_sub(TELEPORT_ADMISSION + Duration::from_secs(1))
        {
            r.sup.teleports.lock().unwrap().insert(
                sid,
                Prepared {
                    order: o.clone(),
                    at: long_ago,
                    have_want: None,
                },
            );
            assert_eq!(
                join(sid, 1, teleport, true).await,
                Some(HiveJoinRefusal::NotPrepared),
                "run out"
            );
            assert!(!r.sup.reports_copies(), "and nothing to tell");
        }
    }

    /// FR-90 P2f-2d — a teleport's prepare asks its folder, as the account,
    /// whether the copy may go there, before anything moves. A clean clone
    /// may. One that holds work of its own is refused `folder_dirty`, the
    /// detail naming a sibling folder under `hive_roots` it could go to
    /// instead (none, for a folder whose sibling is outside them), and the
    /// refused prepare admits nothing.
    #[tokio::test]
    async fn a_teleports_prepare_refuses_a_folder_holding_work_of_its_own() {
        let git = |dir: &Path, args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .args([
                    "-c",
                    "user.name=Person",
                    "-c",
                    "user.email=person@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output();
            matches!(out, Ok(o) if o.status.success())
        };
        let r = moving_rig(ObjectId::new(), 1);
        let work = r.root.path().join("work");
        if !git(&work, &["--version"]) {
            return eprintln!("no git here");
        }
        let app = work.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("a.txt"), "one\n").unwrap();
        for args in [
            &["init", "-q"][..],
            &["add", "-A"],
            &["commit", "-q", "-m", "first"],
        ] {
            assert!(git(&app, args), "{args:?}");
        }
        let mut o = at_fence(&order(&r), 2);
        o.folder = app.display().to_string();
        assert_eq!(
            r.sup.prepare_teleport(&o, true, false).await,
            Answer::accepted("dev"),
            "a clean clone"
        );
        std::fs::write(app.join("theirs.txt"), "the person's own\n").unwrap();
        let mut dirty = o.clone();
        dirty.session_id = ObjectId::new();
        let answer = r.sup.prepare_teleport(&dirty, true, false).await;
        assert_eq!(answer.refused, Some(HiveRefusal::FolderDirty), "{answer:?}");
        // Beside it, named for the session's id's last eight digits.
        let hex = dirty.session_id.to_hex();
        let sibling = work.join(format!("app-hive-{}", &hex[16..]));
        assert!(
            answer
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("neither what its HEAD holds")
                    && d.contains(&sibling.display().to_string())),
            "the sibling named: {answer:?}"
        );
        assert!(
            !r.sup.teleport_admitted(dirty.session_id, 1),
            "a refused prepare admits nothing"
        );
        // The root itself: its sibling is outside `hive_roots`, so none is
        // named.
        std::fs::write(work.join("theirs.txt"), "the person's own\n").unwrap();
        let mut rooted = o.clone();
        rooted.session_id = ObjectId::new();
        rooted.folder = work.display().to_string();
        let answer = r.sup.prepare_teleport(&rooted, true, false).await;
        assert_eq!(answer.refused, Some(HiveRefusal::FolderDirty), "{answer:?}");
        assert!(
            answer
                .detail
                .as_deref()
                .is_some_and(|d| !d.contains("-hive-")),
            "no sibling outside hive_roots: {answer:?}"
        );
        // A folder that cannot be asked about is refused too, in words: the
        // moved start would ask the same git.
        std::fs::write(work.join("a-file"), "not a folder\n").unwrap();
        let mut unreadable = o.clone();
        unreadable.session_id = ObjectId::new();
        unreadable.folder = work.join("a-file").display().to_string();
        let answer = r.sup.prepare_teleport(&unreadable, true, false).await;
        assert_eq!(
            answer.refused,
            Some(HiveRefusal::Other),
            "a folder that cannot be read is refused: {answer:?}"
        );
        assert!(
            answer
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("could not be read as the account")),
            "{answer:?}"
        );
    }

    /// FR-90 P2f-2b — a teleport's prepare keeps where the session will run
    /// here, and as whom, only when the server let the copy's workspace come
    /// against what that folder's repository holds (`have_want`): the account
    /// its gates mapped the owner to and the folder they resolved, for that
    /// session, until the admission runs out. A refused prepare keeps
    /// nothing.
    #[tokio::test]
    async fn a_teleports_prepare_keeps_its_place_only_with_have_and_want() {
        let r = moving_rig(ObjectId::new(), 1);
        let o = at_fence(&order(&r), 2);
        let sid = o.session_id;
        assert_eq!(
            r.sup.prepare_teleport(&o, true, false).await,
            Answer::accepted("dev")
        );
        assert!(
            r.sup.have_want_place(sid).is_none(),
            "without it, the whole pack: no folder to ask about"
        );
        assert_eq!(
            r.sup.prepare_teleport(&o, true, true).await,
            Answer::accepted("dev")
        );
        let (kept, account, folder) = r.sup.have_want_place(sid).expect("kept, with it");
        assert_eq!(
            (kept.session_id, kept.fence, account.as_str()),
            (sid, 2, "dev")
        );
        assert_eq!(
            Some(folder),
            gates::folder_for(&r.sup.cfg, &o.folder).ok(),
            "the folder its gates resolved"
        );
        assert!(
            r.sup.have_want_place(ObjectId::new()).is_none(),
            "for that session only"
        );
        let mut elsewhere = o.clone();
        elsewhere.session_id = ObjectId::new();
        elsewhere.folder = "/etc".into();
        assert_eq!(
            r.sup.prepare_teleport(&elsewhere, true, true).await.refused,
            Some(HiveRefusal::FolderNotAllowed)
        );
        assert!(
            r.sup.have_want_place(elsewhere.session_id).is_none(),
            "a refused prepare keeps nothing"
        );
        if let Some(long_ago) =
            Instant::now().checked_sub(TELEPORT_ADMISSION + Duration::from_secs(1))
        {
            if let Some(p) = r.sup.teleports.lock().unwrap().get_mut(&sid) {
                p.at = long_ago;
            }
            assert!(r.sup.have_want_place(sid).is_none(), "run out");
        }
    }
}

/// P1i-4 — a session's directories on Windows, as the session's own account
/// meets them: a restricted Medium copy of this process's token, its
/// Administrators group deny-only, on a thread of its own.
#[cfg(all(test, windows))]
mod win_tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };

    /// Examine `p` as libuv's `lstat` does (Claude Code is a Bun build, whose
    /// file system on Windows is libuv's): `FILE_READ_ATTRIBUTES`, with backup
    /// semantics so a directory opens, and the reparse point itself.
    fn examine(p: &Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(p)
    }

    /// Field-found on Windows 11: Claude Code examines each component of its
    /// `--settings` path, and refused the session's file because its account
    /// could examine neither the store's directory nor the runtime root.
    #[test]
    fn a_sessions_account_examines_the_directories_on_its_way_and_lists_none() {
        let base = tempfile::tempdir().unwrap();
        let runtime = base.path().join("hive").join("run");
        let hive = runtime.parent().unwrap().to_path_buf();
        let me = crate::win_token::own_user_sid().unwrap();
        let mine = runtime.join("s1");
        session_dir(&runtime, &mine, &me).unwrap();
        let settings = mine.join("settings.json");
        std::fs::write(&settings, "{}").unwrap();
        // Another session's, run as another account (LocalService).
        let theirs = runtime.join("s2");
        session_dir(&runtime, &theirs, "S-1-5-19").unwrap();

        let (examined, listed, other) = std::thread::scope(|s| {
            s.spawn(|| {
                let token = crate::win_token::restricted_medium_copy().unwrap();
                // SAFETY: a live token opened for impersonation; the thread is
                // this test's alone, and reverts before it ends.
                assert_ne!(unsafe { ImpersonateLoggedOnUser(token.raw()) }, 0);
                // The test's own folder first: proof the thread really is that
                // account, since an impersonation Windows refused fails every
                // open, not just the ones under test.
                let own = base.path().to_path_buf();
                let examined: Vec<(String, Result<(), String>)> =
                    [&own, &hive, &runtime, &mine, &settings]
                        .into_iter()
                        .map(|p| {
                            let r = examine(p).map(drop).map_err(|e| e.to_string());
                            (p.display().to_string(), r)
                        })
                        .collect();
                let listed = [&hive, &runtime].map(|p| std::fs::read_dir(p).is_ok());
                let other = examine(&theirs).is_ok();
                // SAFETY: ends this thread's impersonation.
                assert_ne!(unsafe { RevertToSelf() }, 0);
                (examined, listed, other)
            })
            .join()
            .unwrap()
        });
        for (p, r) in &examined {
            assert!(r.is_ok(), "the session's account cannot examine {p}: {r:?}");
        }
        assert_eq!(
            listed,
            [false, false],
            "it lists neither the store nor the runtime root"
        );
        assert!(!other, "nor examines another session's directory");
    }
}

/// #2294 — platform-neutral, unlike the rigs above: a goodbye exit on every
/// system that runs sessions finishes its removal purge first.
#[cfg(test)]
mod removal_purge_tests {
    use super::RemovalPurges;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn nothing_in_flight_is_no_wait() {
        let r = RemovalPurges::new();
        let t0 = Instant::now();
        assert_eq!(r.finish(Duration::from_secs(30)).await, (0, true));
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_goodbye_exit_waits_for_the_removal_purge() {
        let r = RemovalPurges::new();
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        r.track(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            d.store(true, Ordering::SeqCst);
            2
        }));
        assert_eq!(r.finish(Duration::from_secs(30)).await, (1, true));
        assert!(
            done.load(Ordering::SeqCst),
            "the purge ran to its end before the exit"
        );
        assert_eq!(
            r.finish(Duration::from_secs(30)).await,
            (0, true),
            "each purge is waited for once"
        );
    }

    #[tokio::test]
    async fn the_wait_is_bounded() {
        let r = RemovalPurges::new();
        r.track(tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            0
        }));
        let t0 = Instant::now();
        assert_eq!(r.finish(Duration::from_millis(100)).await, (1, false));
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "a hung purge does not keep a removed daemon up"
        );
    }
}
