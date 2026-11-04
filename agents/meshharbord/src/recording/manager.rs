// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P2a — the daemon's side of a LOCAL recording: it launches
//! `roomlerd record` for the LocalAPI verbs, follows its events, and answers
//! "what is recording, and how did the last one end".
//!
//! The recorder stays a process of its own (a driver fault costs it, never the
//! daemon); this is only its supervisor. One recording at a time. A daemon
//! that goes away closes the child's stdin, which the child reads as
//! `parent_gone` and finalizes — a recording never outlives its launcher.
//!
//! FR-85 P1e — the recorder runs as the person signed in at the device, at
//! normal integrity ([`super::launch`]): an elevated worker hands it a
//! restricted medium copy of its token, a SYSTEM one the console user's. The
//! daemon's own work in the recordings folder (listing, deleting, serving a
//! download) runs as that same identity ([`RecordingManager::as_user`]), and
//! the folder is decided by the recorder, as the recorder (`record --where`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, watch};
use tunnel_core::localapi::{
    RecordStartOpts, RecordingEnded, RecordingItem, RecordingState, RecordingsListing, Response,
};

use super::child::parse_event_line;
use super::folder;
use super::launch::{self, Identity, Refusal};
use super::sidecar::{Initiator, SIDECAR_SUFFIX, Sidecar};

/// How long `start` waits for the child to report `started` or `refused`
/// (the first frame, the encoder open, a folder probe). The child's own
/// first-frame timeout is 10 s, so a healthy refusal always arrives first.
const START_TIMEOUT: Duration = Duration::from_secs(20);
/// How long `stop` waits for the file to be final — the remux of a long
/// recording copies every byte once.
const STOP_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a folder the recorder resolved (`record --where`) is reused. The
/// list is refreshed every few seconds while meshharbor-desktop's view is open,
/// and a process launch per refresh would be waste; a recording's own
/// `started` refreshes it early.
const WHERE_TTL: Duration = Duration::from_secs(60);
/// How long `record --where` may take: a folder probe on a slow or scanned
/// disk, never a capture.
const WHERE_TIMEOUT: Duration = Duration::from_secs(15);

/// Recorders of this process that reported `started` and have not ended —
/// for the updater's defer gate. A count, not a flag: each recorder's reader
/// task adds itself once and removes itself once, so no path can clear the
/// mark of a recording it does not own.
static RECORDING: AtomicUsize = AtomicUsize::new(0);

/// Is a recording running in this process right now?
pub fn is_recording() -> bool {
    RECORDING.load(Ordering::Relaxed) > 0
}

struct Active {
    stdin: Option<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>,
    child: launch::Child,
    /// Flips to `true` when the child reported `stopped`/`refused`/`error`, or
    /// its stdout closed.
    ended: watch::Receiver<bool>,
}

/// A folder the recorder decided, for the identity and `record_dir` it was
/// decided under.
struct WhereCache {
    identity: Identity,
    configured: Option<PathBuf>,
    choice: folder::FolderChoice,
    at: Instant,
}

/// FR-85 P3 — who a REMOTE recording is for: the session that asked (the
/// device side's handle on it) and the controller (what the sidecar keeps,
/// because a download is owned by the USER — the reconnect ladder mints new
/// session ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteInitiator {
    pub session_id: bson::oid::ObjectId,
    pub controller_user_id: bson::oid::ObjectId,
    pub controller_name: String,
}

/// FR-85 P3 — why a start did not happen, for a caller that must say so in
/// a closed set rather than a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// No recorder can be launched here now (P1e's [`Refusal`]): SYSTEM or
    /// root with nobody to record as, a login screen, the kill switch. The
    /// refusal itself, so a caller can name it (decision 6: `login_screen`).
    Unavailable(Refusal),
    /// A recording is already running (one at a time).
    Busy,
    /// The recorder refused, failed, or missed its start deadline.
    Failed(String),
}

impl StartError {
    pub fn message(&self) -> String {
        match self {
            Self::Unavailable(r) => r.message().into(),
            Self::Failed(m) => m.clone(),
            Self::Busy => "a recording is already running".into(),
        }
    }
}

/// The recorder's supervisor. Cheap to share (`Arc`).
pub struct RecordingManager {
    /// The binary to launch — this daemon's own executable in production.
    exe: PathBuf,
    /// Read at every start for `record_dir` (the key is live, no restart).
    config_path: PathBuf,
    state: Arc<StdMutex<RecordingState>>,
    active: Mutex<Option<Active>>,
    /// Set by a test; `None` = decide from this process ([`launch::decide`]).
    identity_override: StdMutex<Option<Result<Identity, Refusal>>>,
    /// `ROOMLERD_RECORDING=0`, read once at start like every `ROOMLERD_*`
    /// kill switch: the whole recording surface answers "switched off".
    switched_off: bool,
    /// The folder the recorder last decided (`record --where`).
    where_cache: StdMutex<Option<WhereCache>>,
    /// Extra environment for the child, on top of the config fallbacks.
    child_env: Vec<(String, String)>,
    /// [`START_TIMEOUT`], unless a test shortens it.
    start_timeout: Duration,
    /// FR-85 P3 — the initiator of the most recent start when it was REMOTE
    /// (`None` for a local one). Meaningful only while the state is active.
    remote: StdMutex<Option<RemoteInitiator>>,
    /// FR-85 P1f — the unattended folder; `None` = the daemon's own
    /// ([`folder::unattended_default`]). A test points it at a scratch dir.
    unattended_dir: Option<PathBuf>,
    /// FR-85 P3b-3 — how long a remote recording outlives the session that
    /// started it, waiting for its controller to come back
    /// ([`REATTACH_GRACE`], unless a test shortens it).
    reattach_grace: Duration,
    /// FR-85 P3b-3 — how often the grace looks at a detached recording, in
    /// ms ([`GRACE_POLL`]). A test lengthens it to put a second recording
    /// between two looks, which the grace must never stop.
    grace_poll_ms: AtomicU64,
}

/// FR-85 P3b-3 — how often the grace looks at a detached recording.
pub const GRACE_POLL: Duration = Duration::from_secs(1);

/// FR-85 P3b-3 — the re-attach grace. The reconnect ladder mints a new
/// session id on every drop, and a relay flap or a reloaded viewer should not
/// cost the recording; a minute is long enough for either and short enough
/// that a recording nobody comes back for does not run on unwatched.
pub const REATTACH_GRACE: Duration = Duration::from_secs(60);

impl RecordingManager {
    pub fn new(exe: PathBuf, config_path: PathBuf) -> Self {
        Self {
            exe,
            config_path,
            state: Arc::new(StdMutex::new(RecordingState::default())),
            active: Mutex::new(None),
            identity_override: StdMutex::new(None),
            switched_off: launch::switched_off(tunnel_core::env::node_env("RECORDING").as_deref()),
            where_cache: StdMutex::new(None),
            child_env: Vec::new(),
            start_timeout: START_TIMEOUT,
            remote: StdMutex::new(None),
            unattended_dir: None,
            reattach_grace: REATTACH_GRACE,
            grace_poll_ms: AtomicU64::new(GRACE_POLL.as_millis() as u64),
        }
    }

    /// FR-85 P3b-3 — how often the grace looks at a detached recording.
    pub fn grace_poll(&self) -> Duration {
        Duration::from_millis(self.grace_poll_ms.load(Ordering::Acquire))
    }

    /// FR-85 P3b-3 — change how often the grace looks (tests; a grace
    /// already watching keeps its own pace).
    pub fn set_grace_poll(&self, every: Duration) {
        self.grace_poll_ms
            .store(every.as_millis() as u64, Ordering::Release);
    }

    /// FR-85 P3b-3 — shorten the re-attach grace (tests).
    pub fn with_reattach_grace(mut self, grace: Duration) -> Self {
        self.reattach_grace = grace;
        self
    }

    /// FR-85 P3b-3 — how long a remote recording waits for its controller
    /// after its session drops.
    pub fn reattach_grace(&self) -> Duration {
        self.reattach_grace
    }

    /// FR-85 P3b-3 — move the remote recording in progress from session
    /// `from` to session `to` (its controller's next one). `false` when it is
    /// not `from`'s any more: idle, local, or already moved.
    pub fn retarget_remote(&self, from: bson::oid::ObjectId, to: bson::oid::ObjectId) -> bool {
        if !self.snapshot().active {
            return false;
        }
        match self.remote.lock() {
            Ok(mut r) => match r.as_mut() {
                Some(init) if init.session_id == from => {
                    init.session_id = to;
                    true
                }
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// FR-85 P1f — the identity a REMOTE recording starts under: as
    /// [`Self::identity`], except that a service with nobody signed in
    /// records as itself ([`Identity::Unattended`]) instead of refusing.
    /// Never for a local recording: that needs someone at the device to ask
    /// for it. The kill switch still answers first.
    ///
    /// ⚠️ Only [`Refusal::NoConsoleUser`] is "nobody". A login screen
    /// ([`Refusal::LoginScreen`], decision 6) stays refused: someone may be
    /// standing at it, and an unattended recording shows them nothing.
    pub fn identity_remote(&self) -> Result<Identity, Refusal> {
        match self.identity() {
            Err(Refusal::NoConsoleUser) => Ok(Identity::Unattended),
            other => other,
        }
    }

    /// FR-85 P1f — can a REMOTE controller record here (what the device
    /// advertises, and the remote precheck)?
    ///
    /// ⚠️ A login screen (decision 6) still CAN: it is who is at the screen
    /// right now, not what the device is. `available` is a capability, and a
    /// viewer hides the Record control without it (P3c-2), so a device at its
    /// sign-in screen would show no control and no reason at all. A start
    /// there is refused by name instead ("… once someone signs in").
    pub fn available_remote(&self) -> bool {
        matches!(self.identity_remote(), Ok(_) | Err(Refusal::LoginScreen))
    }

    /// FR-85 P1f — point the unattended folder somewhere else (a test's
    /// scratch dir, never a person's folder).
    pub fn with_unattended_dir(mut self, dir: PathBuf) -> Self {
        self.unattended_dir = Some(dir);
        self
    }

    /// The unattended folder, created and locked to the service side.
    fn unattended_folder(&self) -> Result<PathBuf, String> {
        let dir = self
            .unattended_dir
            .clone()
            .or_else(folder::unattended_default)
            .ok_or_else(|| "this platform has no folder for an unattended recording".to_string())?;
        folder::prepare_unattended(&dir).map_err(|e| format!("{e:#}"))?;
        Ok(dir)
    }

    /// FR-85 P1f — where a REMOTE controller's recordings can be, and as whom
    /// each is read: the person's folder, as the person (P1e), when someone
    /// is signed in; and the unattended folder, as the daemon (only the
    /// service side can write there), wherever one exists. So a recording
    /// made while nobody was signed in stays reachable after someone does —
    /// or while the device sits at its login screen, where nothing new can
    /// be recorded (decision 6) but what was made stays its controller's.
    pub async fn remote_places(&self) -> Vec<(PathBuf, Identity)> {
        let mut out = Vec::new();
        if let Ok(identity) = self.identity()
            && let Ok(choice) = self.folder_choice().await
        {
            out.push((choice.dir, identity));
        }
        if self.available_remote() {
            let dir = self
                .unattended_dir
                .clone()
                .or_else(folder::unattended_default);
            if let Some(dir) = dir
                && std::fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_dir())
                && !out.iter().any(|(d, _)| d == &dir)
            {
                out.push((dir, Identity::Unattended));
            }
        }
        out
    }

    /// Run blocking `f` as `identity` on a blocking thread (see
    /// [`Self::as_user`], which is this for the current identity).
    pub async fn as_identity<R: Send + 'static>(
        &self,
        identity: Identity,
        f: impl FnOnce() -> R + Send + 'static,
    ) -> Option<R> {
        match tokio::task::spawn_blocking(move || launch::as_identity(identity, f)).await {
            Ok(Ok(r)) => Some(r),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "recording: could not act as the recorder's identity");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "recording: the blocking task failed");
                None
            }
        }
    }

    /// Who a recorder launched now would run as, or why none can be (P1e).
    /// Read afresh each time: a person signs in and out. The kill switch
    /// comes first, so it answers every path — a local start, a remote one,
    /// what the device advertises, and the listing.
    pub fn identity(&self) -> Result<Identity, Refusal> {
        self.identity_with(false)
    }

    /// `fresh`: who is signed in, asked of the system now ([`launch::decide_fresh`]).
    fn identity_with(&self, fresh: bool) -> Result<Identity, Refusal> {
        if self.switched_off {
            return Err(Refusal::SwitchedOff);
        }
        let overridden = *self
            .identity_override
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        overridden.unwrap_or_else(if fresh {
            launch::decide_fresh
        } else {
            launch::decide
        })
    }

    /// FR-85 P1f — [`Self::identity_remote`], asking the system afresh who is
    /// signed in: what an unattended start is decided on, what the launch
    /// re-checks, and what the watch over a running one reads. A cached
    /// "nobody" read twice is one observation, not two.
    pub fn identity_remote_fresh(&self) -> Result<Identity, Refusal> {
        match self.identity_with(true) {
            Err(Refusal::NoConsoleUser) => Ok(Identity::Unattended),
            other => other,
        }
    }

    /// Set the kill switch the way `ROOMLERD_RECORDING=0` would — for the
    /// test that proves it closes every path.
    pub fn with_switched_off(mut self, switched_off: bool) -> Self {
        self.switched_off = switched_off;
        self
    }

    /// Can this daemon record at all (FR-85 P3 advertises remote recording
    /// only where it can)? `false` for SYSTEM with nobody signed in, and for
    /// root.
    pub fn available(&self) -> bool {
        self.identity().is_ok()
    }

    /// FR-85 P3 — the session a REMOTE recording in progress belongs to.
    /// `None` when idle, or when the active recording is local.
    pub fn active_remote(&self) -> Option<RemoteInitiator> {
        if !self.snapshot().active {
            return None;
        }
        self.remote.lock().ok().and_then(|r| r.clone())
    }

    /// Shorten the start deadline — for the test that proves a recorder
    /// missing it is stopped rather than left to start later, unseen.
    pub fn with_start_timeout(mut self, start_timeout: Duration) -> Self {
        self.start_timeout = start_timeout;
        self
    }

    /// Override the identity probe — for tests, which may run as root in a
    /// container and still need to drive the whole path. `true` = this
    /// platform's service refusal; `false` = record as this process.
    pub fn with_service_identity(self, service_identity: bool) -> Self {
        // What each platform's service really answers with nobody to record
        // as: SYSTEM is at the console's sign-in screen (decision 6: a
        // Windows service never has an empty seat); Linux root on a host
        // with no screen at all; root on macOS, where the drop is not built.
        let refusal = if cfg!(windows) {
            Refusal::LoginScreen
        } else if cfg!(target_os = "linux") {
            Refusal::NoConsoleUser
        } else {
            Refusal::RootDaemon
        };
        self.with_identity(if service_identity {
            Err(refusal)
        } else {
            Ok(Identity::Inherit)
        })
    }

    /// Override the identity decision outright (a test that must exercise a
    /// particular launch).
    pub fn with_identity(mut self, identity: Result<Identity, Refusal>) -> Self {
        *self
            .identity_override
            .get_mut()
            .unwrap_or_else(|p| p.into_inner()) = Some(identity);
        self
    }

    /// Switch the identity decision of a manager already in use (`None` =
    /// decide from this process again) — for a test binary whose one
    /// process-wide manager serves an attended cell and an unattended one.
    pub fn set_identity(&self, identity: Option<Result<Identity, Refusal>>) {
        *self
            .identity_override
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = identity;
    }

    /// Extra environment for every recorder this manager launches — how a
    /// test selects the synthetic frame source without `set_var` on its own
    /// (multi-threaded) process.
    pub fn with_child_env<K: Into<String>, V: Into<String>>(
        mut self,
        env: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        self.child_env
            .extend(env.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    fn snapshot(&self) -> RecordingState {
        let mut s = self.state.lock().map(|s| s.clone()).unwrap_or_default();
        let identity = self.identity();
        s.available = identity.is_ok();
        s.unavailable_reason = identity.err().map(|r| r.message().to_string());
        // #1760 — the same capability the remote gates read, told ahead of
        // any start, so the companion greys its "Computer audio" box out
        // (and the owner's remote toggle) with the words instead of offering
        // a start the recorder can only refuse.
        s.system_audio_unavailable_reason =
            super::system_audio_unsupported_reason().map(String::from);
        s
    }

    /// The environment every recorder gets on top of its own. The
    /// config-backed knobs (the encoder denylist, pinned devices) are
    /// process-local here, so they are handed over as real env, exactly as
    /// the capability probe does, or the gate would be a courtesy.
    fn child_env(&self) -> Vec<(String, String)> {
        let mut env = tunnel_core::env::config_fallbacks_for_child();
        env.extend(self.child_env.iter().cloned());
        env
    }

    /// The configured folder, if any (read fresh — `record_dir` is live).
    fn configured_dir(&self) -> Option<PathBuf> {
        meshharbor_node_core::config::load(&self.config_path)
            .ok()
            .and_then(|c| c.record_dir)
            .map(PathBuf::from)
    }

    /// Start a recording. Answers once the child has either begun encoding or
    /// refused, so the caller learns the folder, the encoder, or why not.
    pub async fn start(&self, opts: RecordStartOpts) -> Response {
        match self.start_inner(opts, None).await {
            Ok(state) => Response::Recording(state),
            Err(e) => Response::Error {
                message: e.message(),
            },
        }
    }

    /// FR-85 P3 — start a recording for a REMOTE controller: the sidecar
    /// names them (what a download is later checked against), and the state
    /// says who the host is being recorded for.
    ///
    /// ⚠️ Never the microphone. It is not a parameter here, so no caller can
    /// pass it through: a remote controller switching on a host's microphone
    /// is not a thing this path can express.
    ///
    /// FR-85 P1f — `identity` is the one the caller decided its gates under
    /// ([`Self::identity_remote`]): an unattended start skipped the on-screen
    /// indicator because nobody was signed in. If that is no longer true when
    /// the recorder launches (someone signed in meanwhile), the start is
    /// refused rather than recording a person with no banner.
    pub async fn start_remote(
        &self,
        initiator: RemoteInitiator,
        system_audio: bool,
        identity: Identity,
    ) -> Result<RecordingState, StartError> {
        let opts = RecordStartOpts {
            system_audio,
            microphone: false,
            ..Default::default()
        };
        self.start_inner(opts, Some((initiator, identity))).await
    }

    async fn start_inner(
        &self,
        opts: RecordStartOpts,
        remote: Option<(RemoteInitiator, Identity)>,
    ) -> Result<RecordingState, StartError> {
        let (remote, identity) = match remote {
            Some((initiator, decided)) => {
                let now = self
                    .identity_remote_fresh()
                    .map_err(StartError::Unavailable)?;
                if now != decided {
                    return Err(StartError::Failed(
                        "who is signed in at the device changed while the recording started; \
                         ask again"
                            .into(),
                    ));
                }
                (Some(initiator), now)
            }
            None => (None, self.identity().map_err(StartError::Unavailable)?),
        };
        let mut guard = self.active.lock().await;
        if let Some(a) = guard.as_ref()
            && !*a.ended.borrow()
        {
            return Err(StartError::Busy);
        }
        // A previous child that ended: reap it before starting the next — but
        // never wait on it unboundedly: one that already reported `stopped`
        // may still be finishing a big reconcile, and dropping the handle is
        // safe (tokio reaps an orphaned child in the background).
        if let Some(mut old) = guard.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), old.child.wait()).await;
        }

        let mut args: Vec<OsString> = vec![
            "record".into(),
            "--fps".into(),
            opts.fps.unwrap_or(30).clamp(1, 60).to_string().into(),
            "--encoder".into(),
            opts.encoder.as_deref().unwrap_or("auto").into(),
            "--max-minutes".into(),
            opts.max_minutes.unwrap_or(240).max(1).to_string().into(),
            "--config".into(),
            self.config_path.clone().into(),
        ];
        let configured = self.configured_dir();
        if identity == Identity::Unattended {
            // P1f — the daemon's own folder, locked to the service side, and
            // never `record_dir`: that is a person's setting, and a service
            // writing into a folder a user can rearrange is what the identity
            // rule forbids.
            let dir = self.unattended_folder().map_err(|e| {
                StartError::Failed(format!("the unattended recordings folder: {e}"))
            })?;
            args.extend(["--out".into(), dir.into()]);
        } else if let Some(dir) = &configured {
            args.extend(["--out".into(), dir.into()]);
        }
        // FR-85 P1c — both default OFF. The child refuses, by name, a source
        // it cannot open (or a build without audio) rather than recording
        // without the audio the person asked for.
        if opts.system_audio {
            args.push("--system-audio".into());
        }
        if opts.microphone {
            args.push("--microphone".into());
        }
        // FR-85 P3 — the `=` form, so a display name that starts with `-`
        // is a value, never a flag.
        if let Some(r) = &remote {
            args.push(format!("--remote-user-id={}", r.controller_user_id.to_hex()).into());
            args.push(format!("--remote-user-name={}", r.controller_name).into());
        }
        let launched = match launch::spawn(identity, &self.exe, &args, &self.child_env()) {
            Ok(l) => l,
            Err(e) => {
                return Err(StartError::Failed(format!(
                    "could not launch the recorder: {e}"
                )));
            }
        };
        let launch::Launched {
            stdin,
            stdout,
            child,
        } = launched;

        // A fresh state for this recording; the last one's ending stays.
        if let Ok(mut s) = self.state.lock() {
            let last = s.last.take();
            *s = RecordingState {
                last,
                remote_controller: remote.as_ref().map(|r| r.controller_name.clone()),
                ..Default::default()
            };
        }
        if let Ok(mut r) = self.remote.lock() {
            *r = remote;
        }
        let (ended_tx, ended_rx) = watch::channel(false);
        let (started_tx, mut started_rx) = watch::channel(false);
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            let mut reported_end = false;
            // This recorder's own mark in RECORDING: added once, removed once.
            let mut counted = false;
            while let Ok(Some(line)) = lines.next_line().await {
                let Some(ev) = parse_event_line(&line) else {
                    continue;
                };
                let mut finished = false;
                if let Ok(mut s) = state.lock() {
                    finished = apply_event(&mut s, &ev);
                }
                if ev["ev"] == "started" && !counted {
                    counted = true;
                    RECORDING.fetch_add(1, Ordering::Relaxed);
                    let _ = started_tx.send(true);
                }
                if finished {
                    reported_end = true;
                    if std::mem::take(&mut counted) {
                        RECORDING.fetch_sub(1, Ordering::Relaxed);
                    }
                    let _ = ended_tx.send(true);
                }
            }
            // stdout closed: whatever it said last, the child is done. One
            // that never said how it ended (a crash, bad arguments, a binary
            // without the recorder, a kill) must not leave the state claiming
            // a recording, nor a start answered with no reason at all.
            if counted {
                RECORDING.fetch_sub(1, Ordering::Relaxed);
            }
            if !reported_end && let Ok(mut s) = state.lock() {
                let detail = if s.active {
                    "the recorder exited without reporting a stop — the file may be \
                     finalized at the next recording (interrupted)"
                } else {
                    "the recorder exited before it started — see the daemon's log"
                };
                s.active = false;
                s.remote_controller = None;
                s.last = Some(RecordingEnded {
                    reason: "recorder_exited".into(),
                    path: s.path.clone(),
                    bytes: s.bytes,
                    duration_ms: s.duration_ms,
                    detail: Some(detail.into()),
                });
            }
            let _ = ended_tx.send(true);
        });

        *guard = Some(Active {
            stdin,
            child,
            ended: ended_rx.clone(),
        });
        drop(guard);

        let mut ended_rx = ended_rx;
        let outcome = tokio::time::timeout(self.start_timeout, async {
            tokio::select! {
                _ = started_rx.wait_for(|s| *s) => {}
                _ = ended_rx.wait_for(|e| *e) => {}
            }
        })
        .await;
        let snap = self.snapshot();
        match outcome {
            Ok(()) if snap.active => {
                // The recorder just decided its folder, as itself: the
                // freshest answer a listing could have. Not an unattended
                // one's: that folder is the daemon's, not a person's choice.
                if identity != Identity::Unattended
                    && let Some(dir) = snap.path.as_deref().and_then(|p| Path::new(p).parent())
                {
                    self.remember_folder(
                        identity,
                        configured,
                        folder::FolderChoice {
                            dir: dir.to_path_buf(),
                            reason: snap.folder_reason.clone(),
                        },
                    );
                }
                Ok(snap)
            }
            Ok(()) => Err(StartError::Failed(
                snap.last
                    .as_ref()
                    .map(|l| {
                        format!(
                            "the recording did not start ({}): {}",
                            l.reason,
                            l.detail.as_deref().unwrap_or("")
                        )
                    })
                    .unwrap_or_else(|| "the recording did not start".into()),
            )),
            Err(_) => {
                // ⚠️ Never leave running a recorder whose caller was told it
                // did not start: stuck in an encoder open or a first frame,
                // it could begin recording a minute later, unseen. A stop
                // command would not reach it (the recorder reads its stop
                // only once it is recording), so it is killed; a partial it
                // left is finalized `interrupted` by the next recorder.
                let mut guard = self.active.lock().await;
                if let Some(a) = guard.as_mut() {
                    a.stdin.take();
                    a.child.start_kill();
                    let mut ended = a.ended.clone();
                    let _ =
                        tokio::time::timeout(Duration::from_secs(5), ended.wait_for(|e| *e)).await;
                }
                // (Its RECORDING mark, if it got that far, went with its
                // reader task when the kill closed its stdout.)
                *guard = None;
                if let Ok(mut s) = self.state.lock() {
                    s.active = false;
                    s.remote_controller = None;
                    s.last = Some(RecordingEnded {
                        reason: "start_timeout".into(),
                        path: None,
                        bytes: 0,
                        duration_ms: 0,
                        detail: Some(format!(
                            "the recorder did not start within {} s and was stopped",
                            self.start_timeout.as_secs_f32()
                        )),
                    });
                }
                Err(StartError::Failed(format!(
                    "the recorder did not start within {} s — it was stopped",
                    self.start_timeout.as_secs_f32()
                )))
            }
        }
    }

    /// Stop the active recording and answer once its file is final — the
    /// person AT the device asking (the LocalAPI, the tray, the banner). A
    /// REMOTE recording stopped this way ends `host_stopped`, so the
    /// controller is told the host ended it rather than that they did.
    pub async fn stop(&self) -> Response {
        let reason = self.active_remote().map(|_| "host_stopped");
        self.stop_with(reason).await
    }

    /// Stop with a reason from the closed set the recorder knows
    /// (`requested`, `host_stopped`, `session_ended`, `gate_revoked`); `None`
    /// is a plain `requested`.
    pub async fn stop_with(&self, reason: Option<&str>) -> Response {
        let mut guard = self.active.lock().await;
        let Some(active) = guard.as_mut() else {
            return Response::Recording(self.snapshot());
        };
        if !*active.ended.borrow()
            && let Some(stdin) = active.stdin.as_mut()
        {
            let line = match reason {
                Some(r) => serde_json::json!({ "cmd": "stop", "reason": r }).to_string(),
                None => r#"{"cmd":"stop"}"#.to_string(),
            };
            let _ = stdin.write_all(format!("{line}\n").as_bytes()).await;
            let _ = stdin.flush().await;
        }
        let mut ended = active.ended.clone();
        let finished = tokio::time::timeout(STOP_TIMEOUT, ended.wait_for(|e| *e))
            .await
            .is_ok();
        if finished {
            // Close stdin and reap: the child exits after its last event.
            active.stdin.take();
            let _ = tokio::time::timeout(Duration::from_secs(10), active.child.wait()).await;
            *guard = None;
        }
        Response::Recording(self.snapshot())
    }

    pub fn status(&self) -> Response {
        Response::Recording(self.snapshot())
    }

    /// The same as [`Self::status`], unwrapped.
    pub fn state(&self) -> RecordingState {
        self.snapshot()
    }

    /// FR-85 P3b-2 — the folder recordings go to, for serving a download.
    /// `None` when it cannot be resolved: never a fallback directory, which
    /// would be a folder of files this device did not decide to serve.
    pub async fn folder(&self) -> Option<PathBuf> {
        self.folder_choice().await.ok().map(|c| c.dir)
    }

    /// The folder the NEXT recording would go to, decided the way the
    /// recorder decides it — by the recorder, as the recorder (P1e): a SYSTEM
    /// daemon's own answer would be SYSTEM's Videos folder, and its write
    /// probe would pass where the person's would not.
    async fn folder_choice(&self) -> Result<folder::FolderChoice, String> {
        let identity = self.identity().map_err(|r| r.message().to_string())?;
        let configured = self.configured_dir();
        if identity == Identity::Inherit {
            return tokio::task::spawn_blocking(move || folder::resolve(configured.as_deref()))
                .await
                .map_err(|e| format!("folder resolution: {e}"));
        }
        if let Ok(cache) = self.where_cache.lock()
            && let Some(c) = cache.as_ref()
            && c.identity == identity
            && c.configured == configured
            && c.at.elapsed() < WHERE_TTL
        {
            return Ok(c.choice.clone());
        }
        let choice = self
            .where_via_recorder(identity, configured.as_deref())
            .await?;
        self.remember_folder(identity, configured, choice.clone());
        Ok(choice)
    }

    fn remember_folder(
        &self,
        identity: Identity,
        configured: Option<PathBuf>,
        choice: folder::FolderChoice,
    ) {
        if let Ok(mut cache) = self.where_cache.lock() {
            *cache = Some(WhereCache {
                identity,
                configured,
                choice,
                at: Instant::now(),
            });
        }
    }

    /// `roomlerd record --where`, launched as `identity`: the folder and why
    /// it is that one.
    async fn where_via_recorder(
        &self,
        identity: Identity,
        configured: Option<&Path>,
    ) -> Result<folder::FolderChoice, String> {
        let mut args: Vec<OsString> = vec![
            "record".into(),
            "--where".into(),
            "--config".into(),
            self.config_path.clone().into(),
        ];
        if let Some(dir) = configured {
            args.extend(["--out".into(), dir.into()]);
        }
        let launched = launch::spawn(identity, &self.exe, &args, &self.child_env())
            .map_err(|e| format!("could not ask the recorder for its folder: {e}"))?;
        let launch::Launched {
            stdin,
            stdout,
            mut child,
        } = launched;
        // Nothing to say to it; closing stdin is also its "the parent is gone".
        drop(stdin);
        let answer = tokio::time::timeout(WHERE_TIMEOUT, async {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Some(ev) = parse_event_line(&line) else {
                    continue;
                };
                match ev["ev"].as_str() {
                    Some("where") => {
                        return ev["dir"].as_str().map(|d| folder::FolderChoice {
                            dir: PathBuf::from(d),
                            reason: ev["reason"].as_str().map(str::to_string),
                        });
                    }
                    Some("refused") | Some("error") => return None,
                    _ => {}
                }
            }
            None
        })
        .await;
        match answer {
            Ok(Some(choice)) => {
                let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                Ok(choice)
            }
            other => {
                child.start_kill();
                Err(if other.is_err() {
                    "the recorder did not say where its folder is in time".into()
                } else {
                    "the recorder could not resolve a folder".into()
                })
            }
        }
    }

    /// Run blocking work in the recordings folder AS the recorder's identity
    /// (P1e). The folder is the person's to rearrange: a junction or a hard
    /// link in it is followed with THEIR rights, never this daemon's — an
    /// elevated or SYSTEM reader, lister or deleter in a user-writable folder
    /// is the primitive the identity rule exists to avoid. `None` when no
    /// recorder can run here, or the identity could not be taken on.
    pub async fn as_user<R: Send + 'static>(
        &self,
        f: impl FnOnce() -> R + Send + 'static,
    ) -> Option<R> {
        let identity = self.identity().ok()?;
        self.as_identity(identity, f).await
    }

    /// The folder recordings go to, and the finished recordings in it.
    pub async fn list(&self) -> Response {
        let choice = match self.folder_choice().await {
            Ok(c) => c,
            Err(reason) => {
                return Response::Recordings(RecordingsListing {
                    dir: String::new(),
                    folder_reason: Some(reason),
                    items: Vec::new(),
                });
            }
        };
        let dir = choice.dir.clone();
        let items = self
            .as_user(move || list_recordings(&dir))
            .await
            .unwrap_or_default();
        Response::Recordings(RecordingsListing {
            dir: choice.dir.to_string_lossy().into_owned(),
            folder_reason: choice.reason,
            items,
        })
    }

    /// Delete one recording (and its sidecar) by file name.
    pub async fn delete(&self, name: &str) -> Response {
        if let Err(message) = check_recording_name(name) {
            return Response::RecordingDeleted {
                ok: false,
                message: Some(message),
            };
        }
        let dir = match self.folder_choice().await {
            Ok(c) => c.dir,
            Err(reason) => {
                return Response::RecordingDeleted {
                    ok: false,
                    message: Some(reason),
                };
            }
        };
        let path = dir.join(name);
        if self.snapshot().active
            && self.snapshot().path.as_deref() == Some(&*path.to_string_lossy())
        {
            return Response::RecordingDeleted {
                ok: false,
                message: Some("that recording is still being written".into()),
            };
        }
        let result = self
            .as_user(move || delete_recording(&path))
            .await
            .unwrap_or_else(|| Err("could not act as the recorder's identity".into()));
        match result {
            Ok(()) => Response::RecordingDeleted {
                ok: true,
                message: None,
            },
            Err(message) => Response::RecordingDeleted {
                ok: false,
                message: Some(message),
            },
        }
    }
}

/// Fold one child event into the state. Returns `true` when the recording is
/// over (it stopped, or never started).
fn apply_event(s: &mut RecordingState, ev: &serde_json::Value) -> bool {
    let str_of = |k: &str| ev[k].as_str().map(str::to_string);
    let u64_of = |k: &str| ev[k].as_u64().unwrap_or(0);
    match ev["ev"].as_str() {
        Some("folder") => {
            s.folder_reason = str_of("reason");
            false
        }
        Some("started") => {
            s.active = true;
            s.path = str_of("path");
            s.encoder = str_of("encoder");
            s.width = u64_of("width") as u32;
            s.height = u64_of("height") as u32;
            s.fps = u64_of("fps") as u32;
            s.system_audio = ev["system_audio"].as_bool().unwrap_or(false);
            s.microphone = ev["microphone"].as_bool().unwrap_or(false);
            s.started_at_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
            false
        }
        Some("progress") => {
            s.duration_ms = u64_of("duration_ms");
            s.bytes = u64_of("bytes");
            s.frames = u64_of("frames");
            false
        }
        Some("stopped") => {
            s.active = false;
            s.remote_controller = None;
            s.duration_ms = u64_of("duration_ms");
            s.bytes = u64_of("bytes");
            s.frames = u64_of("frames");
            s.last = Some(RecordingEnded {
                reason: str_of("reason").unwrap_or_else(|| "requested".into()),
                path: str_of("path"),
                bytes: u64_of("bytes"),
                duration_ms: u64_of("duration_ms"),
                detail: ev["fragmented"]
                    .as_bool()
                    .filter(|f| *f)
                    .map(|_| "kept as fragmented MP4 (the remux failed)".into()),
            });
            true
        }
        Some("refused") | Some("error") => {
            s.active = false;
            s.remote_controller = None;
            s.last = Some(RecordingEnded {
                reason: str_of("code").unwrap_or_else(|| "error".into()),
                path: None,
                bytes: 0,
                duration_ms: 0,
                detail: str_of("detail"),
            });
            true
        }
        _ => false,
    }
}

/// A recording's file name, from a client: a bare `*.mp4` name, nothing that
/// could leave the folder.
pub(crate) fn check_recording_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.contains(['/', '\\', ':'])
        || name.contains("..")
        || !name.to_ascii_lowercase().ends_with(".mp4")
    {
        return Err(format!("{name:?} is not a recording's file name"));
    }
    Ok(())
}

fn delete_recording(path: &Path) -> Result<(), String> {
    // Never follow a link out of the folder: a name that is a symlink is not
    // a recording this device made.
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let _ = std::fs::remove_file(Sidecar::path_for(path));
    // FR-85 P5c — and its edit list: nothing else would ever remove it.
    let _ = std::fs::remove_file(super::edit::EditList::path_for(path));
    Ok(())
}

/// The finished recordings in `dir` (newest first), described by their
/// sidecars where there is one.
pub fn list_recordings(dir: &Path) -> Vec<RecordingItem> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut items: Vec<(std::time::SystemTime, RecordingItem)> = entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_str()?.to_string();
            if !name.to_ascii_lowercase().ends_with(".mp4") || name.ends_with(SIDECAR_SUFFIX) {
                return None;
            }
            let meta = std::fs::symlink_metadata(&path).ok()?;
            if !meta.file_type().is_file() {
                return None;
            }
            let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            let sc: Option<Sidecar> = std::fs::read_to_string(Sidecar::path_for(&path))
                .ok()
                .and_then(|j| serde_json::from_str(&j).ok());
            let (origin, controller) = match sc.as_ref().map(|s| &s.initiator) {
                Some(Initiator::Remote {
                    controller_user_id,
                    controller_name,
                }) => (
                    "remote".to_string(),
                    Some(
                        controller_name
                            .clone()
                            .unwrap_or_else(|| controller_user_id.clone()),
                    ),
                ),
                _ => ("local".to_string(), None),
            };
            Some((
                modified,
                RecordingItem {
                    name,
                    bytes: meta.len(),
                    duration_ms: sc.as_ref().map(|s| s.duration_ms).unwrap_or(0),
                    started_at: sc
                        .as_ref()
                        .map(|s| s.started_at.clone())
                        .unwrap_or_default(),
                    origin,
                    controller,
                    stop_reason: sc
                        .as_ref()
                        .and_then(|s| s.stop_reason)
                        .map(|r| r.as_str().to_string()),
                    width: sc.as_ref().map(|s| s.width).unwrap_or(0),
                    height: sc.as_ref().map(|s| s.height).unwrap_or(0),
                },
            ))
        })
        .collect();
    items.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    items.into_iter().map(|(_, i)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn events_fold_into_the_state_and_mark_the_end() {
        let mut s = RecordingState::default();
        assert!(!apply_event(
            &mut s,
            &json!({"ev":"folder","path":"x","reason":"OneDrive"})
        ));
        assert_eq!(s.folder_reason.as_deref(), Some("OneDrive"));
        assert!(!apply_event(
            &mut s,
            &json!({"ev":"started","path":"C:\\r.mp4","encoder":"h264_nvenc","width":1920,"height":1080,"fps":30})
        ));
        assert!(s.active && s.encoder.as_deref() == Some("h264_nvenc") && s.width == 1920);
        assert!(!apply_event(
            &mut s,
            &json!({"ev":"progress","duration_ms":1000,"bytes":5,"frames":30})
        ));
        assert_eq!((s.duration_ms, s.bytes, s.frames), (1000, 5, 30));
        assert!(apply_event(
            &mut s,
            &json!({"ev":"stopped","reason":"disk_low","path":"C:\\r.mp4","bytes":9,"duration_ms":2000,"frames":60,"fragmented":false})
        ));
        assert!(!s.active);
        let last = s.last.clone().unwrap();
        assert_eq!((last.reason.as_str(), last.bytes), ("disk_low", 9));
        assert!(last.detail.is_none());
    }

    #[test]
    fn a_refusal_is_an_ending_with_its_code() {
        let mut s = RecordingState::default();
        assert!(apply_event(
            &mut s,
            &json!({"ev":"refused","code":"encoder_unavailable","detail":"no GPU"})
        ));
        let last = s.last.unwrap();
        assert_eq!(last.reason, "encoder_unavailable");
        assert_eq!(last.detail.as_deref(), Some("no GPU"));
    }

    #[test]
    fn only_a_bare_mp4_name_can_be_deleted() {
        assert!(check_recording_name("Roomler Recording 2026-09-25 14-30-12.mp4").is_ok());
        for bad in [
            "",
            "../x.mp4",
            "a/b.mp4",
            r"a\b.mp4",
            "C:x.mp4",
            "notes.txt",
            "x.mp4.roomler.json",
        ] {
            assert!(check_recording_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_listing_reads_sidecars_newest_first_and_skips_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.mp4");
        std::fs::write(&a, vec![0u8; 10]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let b = dir.path().join("b.mp4");
        std::fs::write(&b, vec![0u8; 20]).unwrap();
        let sc = Sidecar {
            version: 1,
            file: "b.mp4".into(),
            initiator: Initiator::Remote {
                controller_user_id: "66f0".into(),
                controller_name: Some("GJ".into()),
            },
            started_at: "2026-09-25T12:00:00Z".into(),
            ended_at: None,
            duration_ms: 5000,
            width: 1920,
            height: 1080,
            fps: 30,
            codec: "h264".into(),
            encoder: "openh264".into(),
            color: super::super::mp4::ColorInfo::BT601_LIMITED,
            audio: Default::default(),
            frames: 150,
            late_ticks: 0,
            events: Vec::new(),
            stop_reason: Some(super::super::sidecar::StopReason::Requested),
            bytes: 20,
            pointer: None,
        };
        std::fs::write(Sidecar::path_for(&b), sc.to_json()).unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        std::fs::create_dir(dir.path().join(".roomler-partial")).unwrap();
        let items = list_recordings(dir.path());
        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["b.mp4", "a.mp4"]);
        assert_eq!(items[0].origin, "remote");
        assert_eq!(items[0].controller.as_deref(), Some("GJ"));
        assert_eq!(items[0].duration_ms, 5000);
        assert_eq!(items[0].stop_reason.as_deref(), Some("requested"));
        assert_eq!(items[1].origin, "local", "no sidecar reads as local");
    }

    #[test]
    fn delete_refuses_a_link_and_removes_the_sidecar_with_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("r.mp4");
        std::fs::write(&f, b"x").unwrap();
        std::fs::write(Sidecar::path_for(&f), b"{}").unwrap();
        let edits = crate::recording::edit::EditList::path_for(&f);
        std::fs::write(&edits, b"{}").unwrap();
        // An export beside it is a recording of its own: it stays.
        let export = dir.path().join("r (edited).mp4");
        std::fs::write(&export, b"y").unwrap();
        delete_recording(&f).unwrap();
        assert!(!f.exists() && !Sidecar::path_for(&f).exists());
        assert!(!edits.exists(), "the edit list goes with its recording");
        assert!(export.exists(), "an export is not the recording's to take");
        assert!(delete_recording(&dir.path().join("missing.mp4")).is_err());
        std::fs::create_dir(dir.path().join("d.mp4")).unwrap();
        assert!(
            delete_recording(&dir.path().join("d.mp4")).is_err(),
            "a directory is not a recording"
        );
    }
}
