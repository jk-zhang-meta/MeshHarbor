// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P3b — the device's half of REMOTE recording.
//!
//! A controller already in a session asks, over the session's own `record`
//! DataChannel, to record this screen. The recording is made HERE, by the same
//! recorder a local one uses, and stays here; the server only ever sees the
//! grant (P3a) and what this side reports about it. The channel exists only on
//! a session whose grant holds `Permissions::RECORD`, which the hub strips
//! unless the controller may record AND this device advertises `record`.
//!
//! A start passes, in order (each refusal is named on the channel and
//! reported to the server):
//!
//! | # | gate | refusal |
//! |---|---|---|
//! | 1 | the owner's `record_remote_enabled`, read NOW | `disabled_on_device` |
//! | 2 | a recorder can run in this process | `unavailable` |
//! | 3 | computer audio asked for: this build can record it at all ([`super::system_audio_supported`]: the `audio` feature on Windows or Linux — a fact about the device that no setting fixes, so it is named BEFORE the owner's gate; #1760) | `audio_unsupported` |
//! | 4 | computer audio asked for: `record_remote_audio` | `audio_not_allowed` |
//! | 5 | one recording at a time | `busy` |
//! | 6 | one start at a time per session | `already_starting` |
//! | 7 | a session consented ON THE HOST asks the host again (a fresh prompt id, never the session's); a deny is final for [`DENY_COOLDOWN`] | `consent_denied`, `consent_timeout`, `no_prompt_surface`, `rate_limited` |
//! | 8 | something ON SCREEN says "recording" before the first frame: the daemon's badge (Windows) or the companion's banner | `no_indicator_surface` |
//!
//! Gates 3 and 4 are ONE predicate, [`audio_unavailable`], which also decides
//! whether `remote-audio` is advertised and is stamped on every
//! `rc:record.state` (`audio_unavailable`), so the viewer greys its
//! "Include what the computer plays" box out with the reason instead of
//! offering a start that can only fail.
//!
//! P1f — **the unattended exception to gate 8.** A service with nobody signed
//! in (SYSTEM or root, no console user) records a remote session with no
//! banner, because there is nobody to show one to: the owner's gate 1 is
//! what allows it, the controller is told (`unattended: true` on the state),
//! and the recorder is the daemon itself writing into the daemon's own folder,
//! locked to the service side, never a person's. Someone who signs in is
//! never recorded without a banner:
//! - the identity is decided ONCE, before the indicator is skipped, and the
//!   manager refuses the launch if it no longer holds;
//! - an unattended recording already running is stopped `session_changed` the
//!   moment someone signs in ([`Handler::follow`], every tick).
//!
//! All three read who is signed in FRESH: a cached "nobody" read twice within
//! milliseconds is one observation, and review found the launch re-check a
//! no-op on the cache before this was so. A LOCAL recording still needs
//! someone at the device.
//!
//! The microphone is not a remote option: [`RecordingManager::start_remote`]
//! has no parameter for it.
//!
//! P3b-3 — **a recording outlives its session for the re-attach grace.** The
//! reconnect ladder mints a new session id on every drop, and a relay flap or
//! a reloaded viewer must not cost a recording. When the session that owns a
//! recording goes, the recording is DETACHED, not stopped:
//! - its banner stays up, marked reconnecting (the indicator keeps a
//!   recording session's entry when the session ends): a recording is never
//!   unseen;
//! - the SAME controller (user id, not session id) on a new session holding
//!   RECORD picks it up when its `record` channel asks for the status, and
//!   the new session's banner takes over;
//! - nobody else can: another controller is told nothing is recording;
//! - after [`RecordingManager::reattach_grace`] with nobody back, it stops
//!   `session_ended`. Meanwhile the owner's OFF still stops it
//!   (`gate_revoked`), and an unattended one still stops `session_changed`
//!   the moment someone signs in.
//!
//! ⚠️ "Goes" is the signalling loop's word first ([`session_ended`]): it
//! knows every end, including a peer whose close overran its budget and
//! whose channel therefore stays open. The channel's STATE is watched as
//! well, not only its `on_close`: a channel closed from this side often
//! never fires it, and that is every network drop (the device's own session
//! watchdog closes the peer). See [`channel_gone`].
//!
//! ⚠️ **The host's Disconnect is not a drop** ([`host_ended`]): the
//! recording stops then and there, `host_stopped`, and waits for nobody.
//!
//! Exactly one party speaks for a recording's ending, and every hand-off
//! names the recording (its file): the follower that last claimed it
//! ([`Speakers`]), or the grace while it waits ([`Slot`]). The grace acts on
//! its own recording only, and claims it before stopping it.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use meshharbor_remote_control::models::{RecordCap, RecordingActivityKind};
use meshharbor_remote_control::signaling::ClientMsg;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;

use super::launch::{Identity, Refusal};
use super::manager::{RecordingManager, RemoteInitiator, StartError};

/// After a host says no, the same session may not ask again for this long:
/// a controller must not be able to wear the person down with prompts.
pub const DENY_COOLDOWN: Duration = Duration::from_secs(60);

/// How often a recording in progress reports its size and length.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);

/// How often a session's `record` channel is looked at for its end (see
/// [`channel_gone`]).
const WATCH_EVERY: Duration = Duration::from_millis(500);

/// Is this session's channel over, whichever end closed it?
///
/// ⚠️ Not `== Closed`, and not `on_close` alone. A close from the FAR end
/// always reaches `Closed` and fires `on_close`. A channel closed from THIS
/// side (the peer's own `close()`: the session watchdog after a network drop,
/// a terminate) is set `Closing` and its read loop told to stop, and whether
/// it then reaches `Closed` and fires `on_close` depends on which branch that
/// loop's `select!` takes: in the tests, most drops (8 of 13) stayed
/// `Closing` for good. A dropped network never hears from the far end, and
/// it is the case the re-attach grace exists for: a recording that waited
/// for `Closed` ran on, never detached.
///
/// Not `!= Open` either: webrtc-rs hands a channel the far end opened to
/// `on_data_channel` before it is open.
fn channel_gone(dc: &RTCDataChannel) -> bool {
    matches!(
        dc.ready_state(),
        RTCDataChannelState::Closing | RTCDataChannelState::Closed
    )
}

// ── P3b-3: a recording whose session dropped ───────────────────────────────

/// A remote recording whose session is gone, waiting for its controller to
/// come back on a new one. One at a time, like recordings.
struct Detached {
    /// The session it belonged to (its banner entry, its reports).
    session_id: ObjectId,
    /// Who may pick it up: the USER, since every reconnect is a new session.
    controller_user_id: ObjectId,
    /// The controller's handle for it: every state it is sent carries it.
    id: String,
    unattended: bool,
    /// WHICH recording (its file name). ⚠️ The grace acts on this recording
    /// only: by the time it looks again, this one may have ended by itself
    /// and another begun, and "whatever is recording" would be that other one.
    file: Option<String>,
    /// The grace is stopping it. From here nobody picks it up or detaches it
    /// again, or its ending would be reported twice.
    stopping: bool,
    /// The dropped session's surfaces: its banner comes down, and the ending
    /// is reported on its queue, if nobody picks it up.
    indicator: crate::indicator::ViewerIndicator,
    outbound: mpsc::Sender<ClientMsg>,
}

/// What [`Slot::detach`] did.
enum Detach {
    /// The recording is in the grace now.
    Done,
    /// It is, and ANOTHER session's recording was still there: that one is
    /// over (recordings are one at a time, and the running one is the new
    /// one), and the caller finishes it, or its banner would never come down.
    Evicted(Detached),
    /// That session's recording was already there.
    Already,
}

/// The one detached recording, and every way it changes hands. Each change
/// is one call under one lock, so two parties can never both win it.
#[derive(Default)]
struct Slot(Option<Detached>);

impl Slot {
    /// Put `d` into the grace.
    fn detach(&mut self, d: Detached) -> Detach {
        match &self.0 {
            Some(cur) if cur.session_id == d.session_id => Detach::Already,
            _ => match self.0.replace(d) {
                Some(old) => Detach::Evicted(old),
                None => Detach::Done,
            },
        }
    }

    /// The controller's next session picks it up: the same USER, and never a
    /// recording the grace is already stopping.
    fn pick_up(&mut self, user: ObjectId) -> Option<Detached> {
        if self
            .0
            .as_ref()
            .is_some_and(|d| d.controller_user_id == user && !d.stopping)
        {
            self.0.take()
        } else {
            None
        }
    }

    /// The grace claims `session`'s recording for a stop. `false` = it is not
    /// there to claim (picked up, or claimed already).
    fn claim_stop(&mut self, session: ObjectId) -> bool {
        match self.0.as_mut() {
            Some(d) if d.session_id == session && !d.stopping => {
                d.stopping = true;
                true
            }
            _ => false,
        }
    }

    /// Take `session`'s recording out: the grace is done with it.
    fn take(&mut self, session: ObjectId) -> Option<Detached> {
        if self.holds(session) {
            self.0.take()
        } else {
            None
        }
    }

    /// `session`'s recording, while it waits (not being stopped): whether it
    /// runs unattended.
    fn waiting(&self, session: ObjectId) -> Option<bool> {
        self.0
            .as_ref()
            .filter(|d| d.session_id == session && !d.stopping)
            .map(|d| d.unattended)
    }

    fn holds(&self, session: ObjectId) -> bool {
        self.0.as_ref().is_some_and(|d| d.session_id == session)
    }
}

static DETACHED: StdMutex<Slot> = StdMutex::new(Slot(None));

/// Run `f` on the slot, under its lock.
fn slot<T>(f: impl FnOnce(&mut Slot) -> T) -> Option<T> {
    DETACHED.lock().ok().map(|mut s| f(&mut s))
}

/// P3b-3 — the handler whose session holds the remote recording in progress.
/// The controller's next session may ask for the status before that
/// session's end has been seen (its channel is looked at twice a second);
/// with this it can see the drop itself and detach the recording first,
/// instead of answering "idle" to the one controller it belongs to.
static HOLDER: StdMutex<Option<std::sync::Weak<Handler>>> = StdMutex::new(None);

fn hold(h: &Arc<Handler>) {
    if let Ok(mut slot) = HOLDER.lock() {
        *slot = Some(Arc::downgrade(h));
    }
}

/// Who speaks for a recording's ending: the follower that last claimed THAT
/// recording, by its file. ⚠️ Keyed by the recording, not one counter for
/// all of them: a counter let a NEW recording's follower silence the
/// follower of the one before, whose ending then went unreported, its
/// banner up and its session's Stop stuck. A pick-up's claim, for the same
/// recording, does silence the dropped session's follower, so an ending is
/// reported once, by the session that holds it last.
#[derive(Default)]
struct Speakers {
    current: Option<(String, u64)>,
    next: u64,
}

impl Speakers {
    /// `file`'s follower from now on: its number.
    fn claim(&mut self, file: &str) -> u64 {
        self.next += 1;
        self.current = Some((file.to_string(), self.next));
        self.next
    }

    /// Has another follower claimed `file` since follower `id` did?
    fn superseded(&self, file: &str, id: u64) -> bool {
        self.current
            .as_ref()
            .is_some_and(|(f, n)| f == file && *n != id)
    }
}

static SPEAKERS: StdMutex<Speakers> = StdMutex::new(Speakers {
    current: None,
    next: 0,
});

fn claim_speaker(file: &str) -> u64 {
    SPEAKERS.lock().map(|mut s| s.claim(file)).unwrap_or(0)
}

fn superseded(file: &str, id: u64) -> bool {
    SPEAKERS.lock().is_ok_and(|s| s.superseded(file, id))
}

/// Report how a detached recording ended, on its own session, and take its
/// banner down. `last` describes it only if it is its file.
fn finish_detached(m: &RecordingManager, d: Detached) {
    let last = m.state().last.unwrap_or_default();
    let this = d.file.is_some() && file_name(last.path.as_deref()) == d.file;
    let msg = ClientMsg::RecordingActivity {
        session_id: d.session_id,
        kind: RecordingActivityKind::Stopped,
        name: d.file.clone(),
        bytes: this.then_some(last.bytes),
        duration_ms: this.then_some(last.duration_ms),
        reason: this.then(|| {
            if last.reason.is_empty() {
                "session_ended".into()
            } else {
                last.reason.clone()
            }
        }),
    };
    if d.outbound.try_send(msg).is_err() {
        tracing::debug!(session = %d.session_id, "recording activity dropped (queue full or closed)");
    }
    d.indicator.end_recording(d.session_id);
    info!(session = %d.session_id, reason = %last.reason, "detached remote recording ended");
}

/// P3b-3 — watch a detached recording until it is picked up or ends: every
/// look, the owner's OFF (`gate_revoked`), someone signing in at an
/// unattended one (`session_changed`), the recording ending on its own (the
/// host's Stop, a full disk), or the grace running out (`session_ended`).
/// Whichever wins the slot owns its ending: this task, or the controller's
/// next session.
async fn grace_watch(session_id: ObjectId) {
    let Some(m) = manager() else { return };
    let deadline = Instant::now() + m.reattach_grace();
    // The first look is immediate: with no grace at all, it stops at once.
    let mut tick = tokio::time::interval(m.grace_poll());
    loop {
        tick.tick().await;
        let Some(unattended) = slot(|s| s.waiting(session_id)).flatten() else {
            // Picked up by the controller's next session.
            return;
        };
        // ⚠️ ITS recording, by session: never "whatever is recording". It may
        // have ended by itself and another begun since the last look.
        let ours = m
            .active_remote()
            .is_some_and(|r| r.session_id == session_id);
        let reason = if !ours {
            // It ended by itself; its own reason stands.
            None
        } else if !gates().enabled {
            Some("gate_revoked")
        } else if unattended && fresh_remote_identity(m).await != Ok(Identity::Unattended) {
            Some("session_changed")
        } else if Instant::now() >= deadline {
            Some("session_ended")
        } else {
            continue;
        };
        if let Some(r) = reason {
            // Claimed BEFORE the stop: while the file finalizes, the
            // controller's next session must neither pick it up nor detach
            // it again (both would report its ending a second time).
            if slot(|s| s.claim_stop(session_id)) != Some(true) {
                return;
            }
            info!(session = %session_id, reason = r, "stopping a detached remote recording");
            m.stop_with(Some(r)).await;
        }
        if let Some(d) = slot(|s| s.take(session_id)).flatten() {
            finish_detached(m, d);
        }
        return;
    }
}

/// Every live `record` channel's handler, by session, for the signalling
/// loop to tell. ⚠️ A session's end is not only its channel's: the loop
/// closes a peer within a budget, and a close that overruns it is dropped
/// before it ever reaches the channel, which then stays `Open` for good.
/// The loop knows every end (the server's terminate, the control connection
/// lost, the host's Disconnect) and says so here. An entry goes when its
/// session ends.
static HANDLERS: StdMutex<Vec<(ObjectId, std::sync::Weak<Handler>)>> = StdMutex::new(Vec::new());

fn register(session_id: ObjectId, h: &Arc<Handler>) {
    if let Ok(mut all) = HANDLERS.lock() {
        all.retain(|(_, w)| w.strong_count() > 0);
        all.push((session_id, Arc::downgrade(h)));
    }
}

fn unregister(h: &Handler) {
    if let Ok(mut all) = HANDLERS.lock() {
        all.retain(|(_, w)| w.strong_count() > 0 && !std::ptr::eq(w.as_ptr(), h));
    }
}

fn handlers_of(session_id: ObjectId) -> Vec<Arc<Handler>> {
    HANDLERS
        .lock()
        .map(|all| {
            all.iter()
                .filter(|(s, _)| *s == session_id)
                .filter_map(|(_, w)| w.upgrade())
                .collect()
        })
        .unwrap_or_default()
}

/// P3b-3 — the signalling loop ended `session_id` (the server's terminate,
/// or the control connection lost): a recording it holds waits for its
/// controller (the grace), a question standing for it comes down. Whether
/// or not its channel ever closes.
pub fn session_ended(session_id: ObjectId) {
    for h in handlers_of(session_id) {
        h.end_session();
    }
}

/// P3b-3 — the person AT the device ended `session_id` (the banner's or the
/// badge's Disconnect). ⚠️ A recording it holds STOPS now, `host_stopped`:
/// it does not wait for the controller to come back. Detaching it would
/// keep recording someone who just sent the controller away, and a
/// controller whose device auto-grants would reconnect straight into it.
pub fn host_ended(session_id: ObjectId) {
    for h in handlers_of(session_id) {
        h.host_ended();
    }
}

// ── The device owner's gates ────────────────────────────────────────────────

/// The owner's two remote-recording gates, as they are NOW.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gates {
    /// `record_remote_enabled`.
    pub enabled: bool,
    /// `record_remote_audio`.
    pub audio: bool,
}

fn gates_tx() -> &'static watch::Sender<Gates> {
    static TX: OnceLock<watch::Sender<Gates>> = OnceLock::new();
    TX.get_or_init(|| watch::channel(Gates::default()).0)
}

/// Seed (at start-up) or re-seed (after a LOCAL `ConfigSet`) the live gates.
/// The server can never reach this: both keys are structurally absent from
/// `DesiredConfig`. A gate going OFF stops a remote recording in progress
/// (see [`Handler::follow`]).
pub fn adopt(cfg: &meshharbor_node_core::config::AgentConfig) {
    let next = Gates {
        enabled: cfg.record_remote_enabled,
        audio: cfg.record_remote_audio,
    };
    gates_tx().send_if_modified(|g| {
        let changed = *g != next;
        *g = next;
        changed
    });
}

/// The gates as they are now.
pub fn gates() -> Gates {
    *gates_tx().borrow()
}

/// FR-85 P1e-mac — be told when the gates change. A supervised Mac's GUI worker
/// re-sends its caps to the daemon on each change, because the DEVICE's row
/// advertises the worker's `record` caps and an OFF must reach the hub within
/// a heartbeat, not at the next attach.
pub fn subscribe_gates() -> watch::Receiver<Gates> {
    gates_tx().subscribe()
}

// ── The recorder this process runs ─────────────────────────────────────────

static MANAGER: OnceLock<Arc<RecordingManager>> = OnceLock::new();

/// Hand the daemon's recorder supervisor to the remote path — the SAME one
/// the LocalAPI verbs use, so a local and a remote recording can never run at
/// once. Called once, where the daemon builds it.
pub fn install(manager: Arc<RecordingManager>) {
    let _ = MANAGER.set(manager);
}

fn manager() -> Option<&'static Arc<RecordingManager>> {
    MANAGER.get()
}

/// P1f — [`RecordingManager::identity_remote_fresh`] off the async runtime:
/// asking afresh who is signed in runs `loginctl` on Linux. An answer that
/// cannot be had reads as "nobody to record as" at a start (refused) and as
/// "someone" in the watch (stopped): closed both ways.
async fn fresh_remote_identity(m: &'static Arc<RecordingManager>) -> Result<Identity, Refusal> {
    tokio::task::spawn_blocking(move || m.identity_remote_fresh())
        .await
        .unwrap_or(Err(Refusal::NoConsoleUser))
}

/// The wire code and words for a remote start the identity rule refuses. A
/// login screen has its own code (decision 6): the controller's fix is to
/// wait for someone to sign in, which "unavailable" would never say.
fn identity_refusal(r: Refusal) -> (&'static str, Option<String>) {
    let code = match r {
        Refusal::LoginScreen => "login_screen",
        Refusal::NoConsoleUser | Refusal::RootDaemon | Refusal::SwitchedOff => "unavailable",
    };
    (code, Some(r.message().into()))
}

/// What this device advertises in `AgentCaps.record` right now.
pub fn advertised() -> Vec<String> {
    advertise(
        gates(),
        manager().is_some_and(|m| m.available_remote()),
        super::system_audio_supported(),
    )
}

/// Pure half of [`advertised`]. Nothing at all unless a recorder can serve a
/// remote session here: silence is how the hub learns "no recorder", and a
/// viewer then shows no Record control. Then `available` (P3c-2: the device
/// HAS the feature — capability, never permission); `remote` only while the
/// owner's gate is on; `remote-audio` only on top of that, where computer
/// audio can be recorded at all (`system_audio`, the caller's
/// [`super::system_audio_supported`]) AND the audio gate is on — the same
/// predicate as the start's ([`audio_unavailable`]).
pub fn advertise(g: Gates, can_record: bool, system_audio: bool) -> Vec<String> {
    let mut out = Vec::new();
    if !can_record {
        return out;
    }
    out.push(RecordCap::Available.wire().to_string());
    if g.enabled {
        out.push(RecordCap::Remote.wire().to_string());
        if audio_unavailable(g, system_audio).is_none() {
            out.push(RecordCap::RemoteAudio.wire().to_string());
        }
    }
    out
}

/// Why a remote recording here could not include what the computer plays,
/// or `None` where it could (#1760). `system_audio` is
/// [`super::system_audio_supported`], passed in so both answers are testable
/// on any OS. The platform comes first: a device that cannot record computer
/// audio is `audio_unsupported` whatever the owner set, because no setting
/// fixes it; only then is the owner's gate `audio_not_allowed`.
///
/// ONE predicate for three entry points — what is advertised
/// ([`advertise`]), what a start is refused ([`precheck`]) and what every
/// state tells the viewer ([`StateMsg::audio_unavailable`]) — so they cannot
/// drift apart again. Before it, a Mac advertised `remote-audio` and let an
/// audio start through to the recorder, which refused it as `start_failed`.
pub fn audio_unavailable(g: Gates, system_audio: bool) -> Option<&'static str> {
    if !system_audio {
        Some("audio_unsupported")
    } else if !g.audio {
        Some("audio_not_allowed")
    } else {
        None
    }
}

// ── The wire, on the `record` DataChannel ──────────────────────────────────

/// Controller → device.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "t")]
pub enum Incoming {
    /// Start recording. `id` is the controller's handle for this attempt
    /// (echoed on every state); `audio` asks for what the computer plays.
    #[serde(rename = "rc:record.start")]
    Start {
        #[serde(default)]
        id: String,
        #[serde(default)]
        audio: bool,
    },
    /// Stop the recording this session started.
    #[serde(rename = "rc:record.stop")]
    Stop {
        #[serde(default)]
        id: String,
    },
    /// Say where things stand (a viewer that reconnected its channel).
    #[serde(rename = "rc:record.status")]
    Status,
    /// P3b-2 — this controller's finished recordings on this device.
    #[serde(rename = "rc:record.list")]
    List {
        #[serde(default)]
        id: String,
    },
    /// P3b-2 — send one of them from byte `offset` (a resumed transfer asks
    /// for where the last one broke off).
    #[serde(rename = "rc:record.get")]
    Get {
        #[serde(default)]
        id: String,
        name: String,
        #[serde(default)]
        offset: u64,
    },
    /// P3b-2 — abandon the transfer in progress.
    #[serde(rename = "rc:record.cancel")]
    Cancel {
        #[serde(default)]
        id: String,
    },
}

/// Device → controller: one `rc:record.state`.
#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct StateMsg {
    pub t: &'static str,
    pub id: String,
    /// `pending_consent` | `recording` | `stopped` | `refused` | `failed` | `idle`.
    pub state: &'static str,
    /// The refusal code or stop reason (closed sets, `docs/recording.md` §10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// A sentence for a human, when there is more to say than the code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The recording's file name (never a path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub bytes: u64,
    pub duration_ms: u64,
    pub audio: bool,
    /// FR-85 P1f — recording with nobody signed in at the device, so nothing
    /// on its screen says so. Absent (false) otherwise; a viewer that does
    /// not know the field reads nothing different.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unattended: bool,
    /// #1760 — why a remote recording here could not include what the
    /// computer plays: `audio_unsupported` (this device cannot record it at
    /// all) or `audio_not_allowed` (the owner has not allowed it). Absent
    /// where it could. Stamped on EVERY state ([`send`]), so the answer to
    /// `rc:record.status` reaches the viewer before it offers the box, and
    /// it greys the box out with the reason instead of offering a start
    /// that can only fail. A device older than this sends no field, and a
    /// viewer reads that as today's behaviour: the box offered, the device
    /// refusing by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_unavailable: Option<&'static str>,
}

impl StateMsg {
    fn new(id: &str, state: &'static str) -> Self {
        Self {
            t: "rc:record.state",
            id: id.to_string(),
            state,
            ..Default::default()
        }
    }
}

/// The refusals decided before anything is asked or launched, in order
/// (the module's gate table). `system_audio` is the caller's
/// [`super::system_audio_supported`]; an audio start where it is false is
/// `audio_unsupported` ahead of the owner's gate ([`audio_unavailable`]).
pub fn precheck(
    g: Gates,
    can_record: bool,
    audio: bool,
    system_audio: bool,
    busy: bool,
) -> Result<(), &'static str> {
    if !g.enabled {
        return Err("disabled_on_device");
    }
    if !can_record {
        return Err("unavailable");
    }
    if audio && let Some(code) = audio_unavailable(g, system_audio) {
        return Err(code);
    }
    if busy {
        return Err("busy");
    }
    Ok(())
}

/// A file name for the controller: never the path it lives at.
fn file_name(path: Option<&str>) -> Option<String> {
    path.and_then(|p| {
        std::path::Path::new(p)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
    })
}

// ── One session's handler ──────────────────────────────────────────────────

/// Whether the desktop companion can show this session's prompt and banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Companion {
    /// Ask the system: start the companion if it is installed and not
    /// running (`companion::ensure_running`, bounded).
    System,
    /// A fixed answer — for tests, which must never launch the real app.
    Fixed(bool),
}

impl Companion {
    async fn up(self) -> bool {
        match self {
            Self::System => tokio::time::timeout(
                crate::signaling::COMPANION_START_BUDGET,
                crate::companion::ensure_running(),
            )
            .await
            .unwrap_or(false),
            Self::Fixed(up) => up,
        }
    }
}

/// What a session's `record` channel needs from the signalling loop that
/// built the peer. Set once per session, before the offer is answered.
#[derive(Clone)]
pub struct SessionCtx {
    pub session_id: ObjectId,
    pub controller_user_id: ObjectId,
    pub controller_name: String,
    /// The asking organisation on a multi-org device; empty otherwise.
    pub org: String,
    /// `Some(window)` when this session was consented ON THE HOST, so a
    /// recording asks the host again with the same window; `None` when it
    /// was auto-granted (the owner opted into remote recording at gate 1).
    pub prompt_window: Option<Duration>,
    pub consent: crate::consent::ConsentBroker,
    pub indicator: crate::indicator::ViewerIndicator,
    /// This session's outbound queue — where activity reports go.
    pub outbound: mpsc::Sender<ClientMsg>,
    /// [`Companion::System`] in production.
    pub companion: Companion,
}

struct Handler {
    ctx: SessionCtx,
    dc: Arc<RTCDataChannel>,
    /// A start is between its first check and its answer.
    starting: AtomicBool,
    /// When the host last said no (for [`DENY_COOLDOWN`]).
    last_deny: StdMutex<Option<Instant>>,
    /// The prompt standing on the host's screen for this session, if any.
    prompt: StdMutex<Option<String>>,
    /// The controller's id for the recording in progress.
    current: StdMutex<Option<String>>,
    /// P1f — the recording in progress runs unattended (a service with
    /// nobody signed in), for the re-attach grace to keep watching for a
    /// sign-in once this session is gone.
    unattended: AtomicBool,
    /// P3b-3 — THIS session asked the recording to end (the controller's
    /// Stop, or the follower's own gate / sign-in stop). A drop while it
    /// finalizes then neither detaches it nor silences its report: this
    /// session's follower still reports the ending, once.
    ending: AtomicBool,
    /// The session's end has been handled ([`Handler::end_session`] runs
    /// once: from the signalling loop, `on_close`, or the channel watch that
    /// sees an end `on_close` never reports).
    gone: AtomicBool,
    /// P3b-2 — the transfer in progress (`id`, its cancel flag): one at a
    /// time per session.
    transfer: StdMutex<Option<(String, Arc<AtomicBool>)>>,
}

/// Serve `rc:record.*` on `dc` for the session in `ctx`. Installed only when
/// the session's grant holds `Permissions::RECORD`.
pub fn attach(dc: Arc<RTCDataChannel>, ctx: SessionCtx) {
    info!(session = %ctx.session_id, "record DC attached");
    let h = Arc::new(Handler {
        ctx,
        dc: dc.clone(),
        starting: AtomicBool::new(false),
        last_deny: StdMutex::new(None),
        prompt: StdMutex::new(None),
        current: StdMutex::new(None),
        unattended: AtomicBool::new(false),
        ending: AtomicBool::new(false),
        gone: AtomicBool::new(false),
        transfer: StdMutex::new(None),
    });
    // The session's end, three ways: the signalling loop says so
    // (`session_ended`, `host_ended`); `on_close` when the far end closed the
    // channel; and a look at the channel's state for when this side did,
    // which `on_close` often never reports (see `channel_gone`).
    register(h.ctx.session_id, &h);
    let on_close = h.clone();
    dc.on_close(Box::new(move || {
        let h = on_close.clone();
        Box::pin(async move {
            h.end_session();
        })
    }));
    let watched = Arc::downgrade(&h);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(WATCH_EVERY).await;
            let Some(h) = watched.upgrade() else { return };
            if h.gone.load(Ordering::Acquire) {
                return;
            }
            if channel_gone(&h.dc) {
                h.end_session();
                return;
            }
        }
    });
    dc.on_message(Box::new(move |msg| {
        let h = h.clone();
        Box::pin(async move {
            if !msg.is_string {
                return;
            }
            let Ok(text) = std::str::from_utf8(&msg.data) else {
                return;
            };
            match serde_json::from_str::<Incoming>(text) {
                // A prompt can stand for minutes: never hold the channel's
                // message loop for it, or a Stop could not get through.
                Ok(Incoming::Start { id, audio }) => {
                    tokio::spawn(h.start(id, audio));
                }
                Ok(Incoming::Stop { id }) => h.stop(id).await,
                Ok(Incoming::Status) => h.status().await,
                Ok(Incoming::List { id }) => h.list(id).await,
                // A transfer runs for as long as the file takes: off the
                // message loop, so a Cancel can get through.
                Ok(Incoming::Get { id, name, offset }) => {
                    tokio::spawn(h.get(id, name, offset));
                }
                Ok(Incoming::Cancel { id }) => h.cancel(&id),
                Err(e) => warn!(session = %h.ctx.session_id, %e, "record DC: unparseable message"),
            }
        })
    }));
}

/// A channel that answers every request with `reason` instead of silence, so
/// a viewer that opened it anyway is told why rather than left waiting:
/// `not_granted` on a session WITHOUT `Permissions::RECORD`, `unavailable`
/// where the session was not given a recording context.
pub fn attach_refusing(dc: Arc<RTCDataChannel>, session_id: ObjectId, reason: &'static str) {
    info!(session = %session_id, reason, "record DC attached in REFUSE mode");
    let dc_for_handler = dc.clone();
    dc.on_message(Box::new(move |msg| {
        let dc = dc_for_handler.clone();
        Box::pin(async move {
            if !msg.is_string {
                return;
            }
            let id = std::str::from_utf8(&msg.data)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string))
                .unwrap_or_default();
            let mut s = StateMsg::new(&id, "refused");
            s.reason = Some(reason.into());
            send(&dc, &s).await;
        })
    }));
}

/// Send a state, stamped with whether a remote recording here could include
/// what the computer plays (#1760, [`StateMsg::audio_unavailable`]). On
/// every state, from the one place every state goes through: a viewer that
/// asks for the status learns it before it offers the box, and one that
/// reads it off a refusal, a `recording` or a `stopped` is told the same.
async fn send(dc: &RTCDataChannel, s: &StateMsg) {
    let mut s = s.clone();
    s.audio_unavailable = audio_unavailable(gates(), super::system_audio_supported());
    send_json(dc, &s).await
}

async fn send_json<T: Serialize>(dc: &RTCDataChannel, v: &T) {
    if let Ok(text) = serde_json::to_string(v)
        && let Err(e) = dc.send_text(text).await
    {
        tracing::debug!(%e, "record DC: send failed (channel closing)");
    }
}

// ── P3b-2: downloading a remote recording ──────────────────────────────────

/// A transfer's chunk: the files channel's size, so the two pumps behave
/// alike under the same SCTP limits.
const CHUNK: usize = 64 * 1024;
/// Stop queuing chunks past this much buffered on the channel (the files
/// channel's number): a multi-GB file must not become a multi-GB queue.
const BACKPRESSURE_HIGH: usize = 4 * 1024 * 1024;

/// One of this controller's recordings, as the list says it.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct ListedRecording {
    pub name: String,
    pub bytes: u64,
    pub duration_ms: u64,
    /// RFC 3339.
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    pub width: u32,
    pub height: u32,
}

/// Does `name`'s sidecar say `controller` started it remotely? The only
/// thing that makes a recording theirs to list or fetch — a recording the
/// person at the device made, or another controller's, is not.
///
/// ⚠️ By USER, never by session: the reconnect ladder mints new session ids,
/// and a controller whose connection flapped must still reach their file.
pub fn owned_by(dir: &Path, name: &str, controller: &ObjectId) -> bool {
    let path = dir.join(name);
    let Ok(json) = std::fs::read_to_string(super::sidecar::Sidecar::path_for(&path)) else {
        return false;
    };
    let Ok(sc) = serde_json::from_str::<super::sidecar::Sidecar>(&json) else {
        return false;
    };
    matches!(
        sc.initiator,
        super::sidecar::Initiator::Remote { ref controller_user_id, .. }
            if *controller_user_id == controller.to_hex()
    )
}

/// `controller`'s finished recordings in `dir`, newest first.
pub fn owned_recordings(dir: &Path, controller: &ObjectId) -> Vec<ListedRecording> {
    super::manager::list_recordings(dir)
        .into_iter()
        .filter(|it| owned_by(dir, &it.name, controller))
        .map(|it| ListedRecording {
            name: it.name,
            bytes: it.bytes,
            duration_ms: it.duration_ms,
            started_at: it.started_at,
            stop_reason: it.stop_reason,
            width: it.width,
            height: it.height,
        })
        .collect()
}

/// Open a recording to send it: never through a link. The name has already
/// passed `check_recording_name` (a bare `*.mp4`, no separator, no `..`);
/// this refuses a symlink or junction at that name, and anything that is not
/// a regular file once open.
///
/// ⚠️ Two layers, and each refuses a link on its own, so the unit test stays
/// green with either one deleted. Keep both: the pre-check also keeps a FIFO
/// from blocking `open`, and the no-follow open closes the swap between the
/// check and the open.
pub fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the link itself, never its target.
        opts.custom_flags(0x0020_0000);
    }
    let file = opts.open(path)?;
    // Swapped between the check and the open? The handle says what was opened.
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

impl Handler {
    fn report(
        &self,
        kind: RecordingActivityKind,
        name: Option<String>,
        bytes: Option<u64>,
        duration_ms: Option<u64>,
        reason: Option<String>,
    ) {
        let msg = ClientMsg::RecordingActivity {
            session_id: self.ctx.session_id,
            kind,
            name,
            bytes,
            duration_ms,
            reason,
        };
        // Never blocks a session: a full queue means the connection is
        // already struggling, and losing a log line beats stalling.
        if self.ctx.outbound.try_send(msg).is_err() {
            tracing::debug!(session = %self.ctx.session_id, "recording activity dropped (queue full or closed)");
        }
    }

    async fn refuse(&self, id: &str, reason: &str, detail: Option<String>) {
        info!(session = %self.ctx.session_id, %reason, ?detail, "remote recording refused");
        let mut s = StateMsg::new(id, "refused");
        s.reason = Some(reason.to_string());
        s.detail = detail;
        send(&self.dc, &s).await;
        self.report(
            RecordingActivityKind::Refused,
            None,
            None,
            None,
            Some(reason.to_string()),
        );
    }

    /// Is the recording in progress this session's?
    fn owns_active(&self) -> bool {
        manager()
            .and_then(|m| m.active_remote())
            .is_some_and(|r| r.session_id == self.ctx.session_id)
    }

    async fn start(self: Arc<Self>, id: String, audio: bool) {
        let Some(m) = manager() else {
            self.refuse(&id, "unavailable", None).await;
            return;
        };
        if let Err(code) = precheck(
            gates(),
            m.available_remote(),
            audio,
            super::system_audio_supported(),
            m.state().active,
        ) {
            // The platform's refusal carries the words (a Mac, a build
            // without audio): the viewer shows them under the code's
            // sentence, where before it saw only `start_failed`.
            let detail = match code {
                "audio_unsupported" => super::system_audio_unsupported_reason().map(String::from),
                _ => None,
            };
            self.refuse(&id, code, detail).await;
            return;
        }
        if self.starting.swap(true, Ordering::AcqRel) {
            self.refuse(&id, "already_starting", None).await;
            return;
        }
        let outcome = self.clone().start_inner(&id, audio).await;
        self.starting.store(false, Ordering::Release);
        if let Some((code, detail)) = outcome {
            self.refuse(&id, code, detail).await;
        }
    }

    /// The prompt, the indicator and the launch. `Some((code, detail))` is a
    /// refusal for the caller to send; `None` = recording (or the session
    /// went away mid-prompt, which owes nobody an answer).
    async fn start_inner(
        self: Arc<Self>,
        id: &str,
        audio: bool,
    ) -> Option<(&'static str, Option<String>)> {
        let m = manager()?;
        let sid = self.ctx.session_id;

        // FR-85 decision 6 — a device at its login screen is refused before
        // anyone is asked: whoever stands at a sign-in screen must not be
        // asked to approve what could never run there. The answer after the
        // question is decided afresh below, whatever this one said.
        if self.ctx.prompt_window.is_some()
            && let Err(r @ Refusal::LoginScreen) = fresh_remote_identity(m).await
        {
            return Some(identity_refusal(r));
        }

        if let Some(window) = self.ctx.prompt_window {
            if self
                .last_deny
                .lock()
                .ok()
                .and_then(|d| *d)
                .is_some_and(|at| at.elapsed() < DENY_COOLDOWN)
            {
                return Some(("rate_limited", None));
            }
            send(&self.dc, &StateMsg::new(id, "pending_consent")).await;
            let (decision, have_surface) = self.ask_host(window, audio).await;
            use crate::consent::Decision;
            match decision {
                Decision::Granted => {
                    self.report(RecordingActivityKind::PromptGranted, None, None, None, None);
                }
                Decision::Denied => {
                    if let Ok(mut d) = self.last_deny.lock() {
                        *d = Some(Instant::now());
                    }
                    self.report(RecordingActivityKind::PromptDenied, None, None, None, None);
                    return Some(("consent_denied", None));
                }
                Decision::Timeout => {
                    self.report(
                        RecordingActivityKind::PromptTimedOut,
                        None,
                        None,
                        None,
                        Some(
                            if have_surface {
                                "consent_timeout"
                            } else {
                                "no_prompt_surface"
                            }
                            .into(),
                        ),
                    );
                    return Some(if have_surface {
                        ("consent_timeout", None)
                    } else {
                        ("no_prompt_surface", None)
                    });
                }
                // The session ended while the host was being asked.
                Decision::Cancelled => return None,
            }
            // The owner may have switched it off while the prompt stood.
            if !gates().enabled {
                return Some(("disabled_on_device", None));
            }
        }

        // P1f — decided ONCE, here, and asked FRESH (never a cached "nobody"):
        // the manager re-checks it, fresh again, before the recorder launches,
        // and `follow` stops an unattended recording the moment someone signs
        // in.
        let identity = match fresh_remote_identity(m).await {
            Ok(i) => i,
            Err(r) => return Some(identity_refusal(r)),
        };
        let unattended = identity == Identity::Unattended;

        // ⚠️ Something on screen says "recording" BEFORE the first frame —
        // wherever there is someone to see it. An unattended host (a service
        // with nobody signed in) has no one: the owner's gate is what allowed
        // it, and the controller is told it records unattended.
        if !unattended {
            let shown = self.ctx.indicator.set_recording(sid, true);
            let companion = shown.listed && self.ctx.companion.up().await;
            if !(shown.native || companion) {
                self.ctx.indicator.end_recording(sid);
                return Some((
                    "no_indicator_surface",
                    Some(
                        "nothing on this device can show that it is being recorded (no banner, \
                         and the Roomler desktop app is not running)"
                            .into(),
                    ),
                ));
            }
        }

        // The session may have gone while the host was asked, or the banner
        // raised: nobody is left to record for, or to answer.
        if channel_gone(&self.dc) {
            if !unattended {
                self.ctx.indicator.end_recording(sid);
            }
            return None;
        }

        let initiator = RemoteInitiator {
            session_id: sid,
            controller_user_id: self.ctx.controller_user_id,
            controller_name: self.ctx.controller_name.clone(),
        };
        match m.start_remote(initiator, audio, identity).await {
            Ok(state) => {
                let name = file_name(state.path.as_deref());
                // This session speaks for this recording's ending, claimed
                // before anything awaits.
                let speaker = claim_speaker(name.as_deref().unwrap_or_default());
                info!(session = %sid, ?name, audio, "remote recording started");
                if let Ok(mut c) = self.current.lock() {
                    *c = Some(id.to_string());
                }
                self.unattended.store(unattended, Ordering::Release);
                let mut s = StateMsg::new(id, "recording");
                s.name = name.clone();
                s.audio = state.system_audio;
                s.unattended = unattended;
                send(&self.dc, &s).await;
                self.report(
                    RecordingActivityKind::Started,
                    name.clone(),
                    None,
                    None,
                    None,
                );
                hold(&self);
                tokio::spawn(
                    self.clone()
                        .follow(id.to_string(), unattended, name, speaker),
                );
                None
            }
            Err(e) => {
                self.ctx.indicator.end_recording(sid);
                Some(match e {
                    StartError::Busy => ("busy", None),
                    // The launch re-check found a refusal (a login screen
                    // that came up since the decision): its own name.
                    StartError::Unavailable(r) => identity_refusal(r),
                    StartError::Failed(d) => ("start_failed", Some(d)),
                })
            }
        }
    }

    /// The just-in-time question, through the same surfaces as every other
    /// prompt: the daemon's own panel first, the companion second, the CLI
    /// always. Returns the decision and whether anyone could have been asked.
    async fn ask_host(&self, window: Duration, audio: bool) -> (crate::consent::Decision, bool) {
        // ⚠️ A FRESH id, never the session's, nor derived from it: the session
        // already has an answered prompt, and a decision recorded against its
        // id must not be able to answer this one (the ssh / ssh-consent lesson).
        let prompt_id = ObjectId::new().to_hex();
        let what = if audio {
            "record this screen and what the computer plays"
        } else {
            "record this screen"
        };
        let name = &self.ctx.controller_name;
        let view = crate::indicator::PromptView {
            session_hex: prompt_id.clone(),
            title: "Screen recording request".into(),
            lead: format!("{name} wants to {what}."),
            detail: "The recording is saved on this device, and a banner shows while it runs."
                .into(),
            permissions: String::new(),
            org: self.ctx.org.clone(),
            expires_at: Instant::now() + window,
        };
        let native = self.ctx.indicator.show_prompt(view.clone());
        let mut prompt = crate::consent::PendingPrompt {
            kind: crate::consent::PromptKind::Record,
            asked_by: name,
            permissions: "RECORD".into(),
            // The whole question, for a companion that predates `record`.
            detail: format!("Wants to {what}. The recording stays on this device."),
            org: self.ctx.org.clone(),
            timeout: window,
            surface: if native {
                crate::consent::PromptSurface::Native
            } else {
                crate::consent::PromptSurface::Companion
            },
        };
        // The marker is written either way (`roomlerd consent --list` shows a
        // natively-prompted question too); without it the companion has
        // nothing to render, so it is part of "could anyone be asked".
        let marker = match self.ctx.consent.write_prompt(&prompt_id, &prompt) {
            Ok(_) => true,
            Err(e) => {
                warn!(%e, native, "record: could not write the .pending consent marker");
                false
            }
        };
        let mut have_surface = native || (marker && self.ctx.companion.up().await);
        // FR-93 P6f — the last on-screen surface: a desktop notification where
        // neither the panel nor the companion can show the question.
        let mut notified = false;
        if !have_surface {
            notified = self.ctx.indicator.show_notification_prompt(view).await;
            have_surface = notified;
            if notified && marker {
                prompt.surface = crate::consent::PromptSurface::Notification;
                if let Err(e) = self.ctx.consent.write_prompt(&prompt_id, &prompt) {
                    warn!(%e, "record: could not mark the consent prompt as shown by a notification");
                }
            }
        }
        info!(session = %self.ctx.session_id, native, notified, have_surface, "consent prompt surface (record)");
        if let Ok(mut p) = self.prompt.lock() {
            *p = Some(prompt_id.clone());
        }
        let decision = self
            .ctx
            .consent
            .request_with_mode(&prompt_id, crate::consent::Mode::Prompt { timeout: window })
            .await;
        self.ctx.indicator.hide_prompt(&prompt_id);
        if let Ok(mut p) = self.prompt.lock() {
            *p = None;
        }
        (decision, have_surface)
    }

    async fn stop(&self, id: String) {
        if !self.owns_active() {
            let mut s = StateMsg::new(&id, "idle");
            s.reason = Some("not_recording".into());
            send(&self.dc, &s).await;
            return;
        }
        // The follower reports the ending once the file is final — even if
        // the session drops meanwhile (P3b-3: an ending asked for is not
        // detached).
        self.ending.store(true, Ordering::Release);
        tokio::spawn(async move {
            if let Some(m) = manager() {
                m.stop_with(Some("requested")).await;
            }
        });
    }

    async fn status(self: Arc<Self>) {
        // P3b-3 — a recording this controller's previous session left
        // running (a relay flap, a reloaded viewer) continues on this one.
        // Only the same USER: the channel exists only on a session holding
        // RECORD, and a recording is its controller's alone.
        let me = self.ctx.controller_user_id;
        // The session holding it may already be gone without its channel
        // watch having looked yet: if it is this controller's and its channel
        // is over, detach it now rather than answer "idle".
        let holder = HOLDER
            .lock()
            .ok()
            .and_then(|h| h.as_ref().and_then(std::sync::Weak::upgrade));
        if let Some(h) = holder
            && h.ctx.controller_user_id == me
            && channel_gone(&h.dc)
        {
            h.detach_recording();
        }
        if let Some(d) = slot(|s| s.pick_up(me)).flatten()
            && self.clone().reattach(d).await
        {
            return;
        }
        let id = self
            .current
            .lock()
            .ok()
            .and_then(|c| c.clone())
            .unwrap_or_default();
        let s = match manager().map(|m| m.state()) {
            Some(st) if st.active && self.owns_active() => {
                let mut s = StateMsg::new(&id, "recording");
                s.name = file_name(st.path.as_deref());
                s.bytes = st.bytes;
                s.duration_ms = st.duration_ms;
                s.audio = st.system_audio;
                s
            }
            _ => StateMsg::new(&id, "idle"),
        };
        send(&self.dc, &s).await;
    }

    /// P3b-3 — pick up `d`, which this controller's previous session left
    /// running: the recording moves to this session, this session's banner
    /// says so and the old one comes down, and this session's follower speaks
    /// for it from now on. `false` = it ended before it could be picked up:
    /// its ending is reported on its own session, and the caller answers the
    /// plain status.
    async fn reattach(self: Arc<Self>, d: Detached) -> bool {
        let Some(m) = manager() else { return false };
        let sid = self.ctx.session_id;
        // A re-offer on the SAME session (the old peer replaced, the session
        // not ended): the recording is this session's already, and its
        // banner entry is this one. Moving it, or taking "the old banner"
        // down, would take THIS banner down while it records.
        let same = d.session_id == sid;
        let moved = if same {
            m.active_remote().is_some_and(|r| r.session_id == sid)
        } else {
            m.retarget_remote(d.session_id, sid)
        };
        if !moved {
            // It ended between the drop and now: nobody else will report it.
            finish_detached(m, d);
            return false;
        }
        // The speaker from here, claimed before anything awaits: the dropped
        // session's follower, if it still runs, falls silent.
        let speaker = claim_speaker(d.file.as_deref().unwrap_or_default());
        // The new banner first, then the old one down: never a moment with
        // neither (an unattended recording has neither, and needs none).
        if !d.unattended {
            self.ctx.indicator.set_recording(sid, true);
        }
        if !same {
            d.indicator.end_recording(d.session_id);
        }
        if let Ok(mut c) = self.current.lock() {
            *c = Some(d.id.clone());
        }
        self.unattended.store(d.unattended, Ordering::Release);
        let st = m.state();
        let name = file_name(st.path.as_deref());
        info!(
            session = %sid,
            from = %d.session_id,
            ?name,
            "remote recording picked up by its controller's new session"
        );
        let mut s = StateMsg::new(&d.id, "recording");
        s.name = name.clone();
        s.bytes = st.bytes;
        s.duration_ms = st.duration_ms;
        s.audio = st.system_audio;
        s.unattended = d.unattended;
        send(&self.dc, &s).await;
        self.report(RecordingActivityKind::Reattached, name, None, None, None);
        hold(&self);
        tokio::spawn(self.clone().follow(d.id, d.unattended, d.file, speaker));
        true
    }

    /// P3b-2 — this controller's finished recordings.
    async fn list(&self, id: String) {
        let mut items = Vec::new();
        if let Some(m) = manager() {
            // P1e — each place read as its own identity: the person's folder
            // as the person (so whatever it has been made to point at is read
            // with their rights), the unattended folder (P1f) as the daemon.
            // The first place wins a name, as `get` does.
            for (dir, identity) in m.remote_places().await {
                let who = self.ctx.controller_user_id;
                let found = m
                    .as_identity(identity, move || owned_recordings(&dir, &who))
                    .await
                    .unwrap_or_default();
                for item in found {
                    if !items.iter().any(|i: &ListedRecording| i.name == item.name) {
                        items.push(item);
                    }
                }
            }
        }
        send_json(
            &self.dc,
            &serde_json::json!({ "t": "rc:record.list", "id": id, "items": items }),
        )
        .await;
    }

    async fn transfer_error(&self, id: &str, reason: &str, detail: Option<String>) {
        info!(session = %self.ctx.session_id, %reason, ?detail, "record: transfer refused");
        send_json(
            &self.dc,
            &serde_json::json!({ "t": "rc:record.error", "id": id, "reason": reason, "detail": detail }),
        )
        .await;
    }

    /// P3b-2 — send one of this controller's recordings from `offset`.
    ///
    /// `rc:record.file {id, name, offset, size}`, then the bytes as binary
    /// messages, then `rc:record.done {id, name, bytes, sha256}`: `sha256`
    /// is of the WHOLE file, so a transfer resumed from an offset (the prefix
    /// read from disk, not sent) is checked end to end like any other.
    async fn get(self: Arc<Self>, id: String, name: String, offset: u64) {
        if let Err(detail) = super::manager::check_recording_name(&name) {
            self.transfer_error(&id, "bad_name", Some(detail)).await;
            return;
        }
        let Some(m) = manager() else {
            self.transfer_error(&id, "unavailable", None).await;
            return;
        };
        let places = m.remote_places().await;
        if places.is_empty() {
            self.transfer_error(&id, "unavailable", None).await;
            return;
        }
        let who = self.ctx.controller_user_id;
        // P1e — the ownership check and the open run as each place's
        // identity, so a link or a junction in the person's folder reaches
        // only what the person could read themselves. The first place that
        // holds this controller's recording by that name answers (P1f: the
        // person's folder, then the unattended one), as the list does.
        let mut opened = None;
        for (dir, identity) in places {
            let name_c = name.clone();
            opened = m
                .as_identity(identity, move || {
                    if !owned_by(&dir, &name_c, &who) {
                        return None;
                    }
                    Some(open_no_follow(&dir.join(&name_c)))
                })
                .await
                .flatten();
            if opened.is_some() {
                break;
            }
        }
        // ⚠️ Someone else's recording and no recording look alike: a
        // controller learns nothing about files that are not theirs.
        let file = match opened {
            Some(Ok(f)) => f,
            Some(Err(e)) => {
                self.transfer_error(&id, "not_found", Some(e.to_string()))
                    .await;
                return;
            }
            None => {
                self.transfer_error(&id, "not_found", None).await;
                return;
            }
        };
        let cancel = Arc::new(AtomicBool::new(false));
        // The slot is claimed in ONE expression, so the (non-`Send`) guard is
        // gone before anything awaits.
        let claimed = match self.transfer.lock() {
            Ok(mut t) if t.is_none() => {
                *t = Some((id.clone(), cancel.clone()));
                true
            }
            Ok(_) => false,
            Err(_) => return,
        };
        if !claimed {
            self.transfer_error(&id, "transfer_in_progress", None).await;
            return;
        }
        let outcome = self.pump(&id, file, &name, offset, &cancel).await;
        if let Ok(mut t) = self.transfer.lock() {
            *t = None;
        }
        match outcome {
            Ok(sent) => {
                info!(session = %self.ctx.session_id, %name, offset, sent, "record: download sent");
                self.report(
                    RecordingActivityKind::Downloaded,
                    Some(name),
                    Some(sent),
                    None,
                    None,
                );
            }
            Err((reason, detail)) => self.transfer_error(&id, reason, detail).await,
        }
    }

    /// `std_file` was opened as the recorder's identity (P1e); reading an
    /// open handle needs no identity at all.
    async fn pump(
        &self,
        id: &str,
        std_file: std::fs::File,
        name: &str,
        offset: u64,
        cancel: &AtomicBool,
    ) -> Result<u64, (&'static str, Option<String>)> {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let read_failed = |e: std::io::Error| ("read_failed", Some(e.to_string()));
        let size = std_file.metadata().map_err(read_failed)?.len();
        if offset > size {
            return Err((
                "bad_offset",
                Some(format!("{offset} is past the end ({size})")),
            ));
        }
        let mut file = tokio::fs::File::from_std(std_file);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        // The part the controller already has: hashed, not sent.
        let mut left = offset;
        while left > 0 {
            let want = buf.len().min(left as usize);
            let n = file.read(&mut buf[..want]).await.map_err(read_failed)?;
            if n == 0 {
                return Err(("read_failed", Some("the file shrank".into())));
            }
            hasher.update(&buf[..n]);
            left -= n as u64;
        }
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(read_failed)?;
        send_json(
            &self.dc,
            &serde_json::json!({ "t": "rc:record.file", "id": id, "name": name, "offset": offset, "size": size }),
        )
        .await;
        let mut sent: u64 = 0;
        loop {
            if cancel.load(Ordering::Acquire) {
                return Err(("cancelled", None));
            }
            if channel_gone(&self.dc) {
                return Err(("session_ended", None));
            }
            // ⚠️ `channel_gone`, not `== Closed`: a channel this side closed
            // may never reach `Closed`, and that check could not end this wait.
            while self.dc.buffered_amount().await > BACKPRESSURE_HIGH {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if cancel.load(Ordering::Acquire) {
                    return Err(("cancelled", None));
                }
                if channel_gone(&self.dc) {
                    return Err(("session_ended", None));
                }
            }
            let n = file.read(&mut buf).await.map_err(read_failed)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            self.dc
                .send(&bytes::Bytes::copy_from_slice(&buf[..n]))
                .await
                .map_err(|e| ("send_failed", Some(e.to_string())))?;
            sent += n as u64;
        }
        send_json(
            &self.dc,
            &serde_json::json!({
                "t": "rc:record.done", "id": id, "name": name, "bytes": sent,
                "size": size, "sha256": hex::encode(hasher.finalize()),
            }),
        )
        .await;
        Ok(sent)
    }

    fn cancel(&self, id: &str) {
        if let Ok(t) = self.transfer.lock()
            && let Some((tid, flag)) = t.as_ref()
            && (id.is_empty() || tid == id)
        {
            flag.store(true, Ordering::Release);
        }
    }

    /// The session is over: its channel closed (`on_close`, the channel
    /// watch) or the signalling loop said so ([`session_ended`]). A prompt
    /// standing for it is withdrawn. A recording it holds is DETACHED
    /// (P3b-3): it waits for its controller's next session for the re-attach
    /// grace, its banner still up, and ends `session_ended` if nobody comes
    /// back ([`grace_watch`]). Once, whichever gets here first.
    fn end_session(&self) {
        if self.gone.swap(true, Ordering::AcqRel) {
            return;
        }
        unregister(self);
        let prompt = self.prompt.lock().ok().and_then(|p| p.clone());
        if let Some(p) = prompt {
            self.ctx.consent.cancel(&p);
        }
        // A transfer has nowhere left to go (the controller resumes it from
        // its offset on the next session).
        self.cancel("");
        self.detach_recording();
        // The channel's callbacks hold this handler, and it holds the
        // channel: without letting go here neither is ever freed, nor the
        // session's queue the handler keeps. A follower still reporting keeps
        // its own reference until it has.
        self.dc.on_message(Box::new(|_| Box::pin(async {})));
        self.dc.on_close(Box::new(|| Box::pin(async {})));
    }

    /// The person at the device ended this session ([`host_ended`]): its
    /// recording stops now, `host_stopped`, reported by its follower, and is
    /// never detached (`ending` is set first).
    fn host_ended(&self) {
        if self.gone.load(Ordering::Acquire) {
            return;
        }
        if self.owns_active() && !self.ending.swap(true, Ordering::AcqRel) {
            info!(session = %self.ctx.session_id, "the host ended the session — stopping its remote recording");
            tokio::spawn(async move {
                if let Some(m) = manager() {
                    m.stop_with(Some("host_stopped")).await;
                }
            });
        }
        self.end_session();
    }

    /// P3b-3 — put this session's recording into the re-attach grace. Once:
    /// the session's end (`end_session`) and the follower finding it gone
    /// both land here, and whichever comes first detaches it. The follower's
    /// look is what stops it following; the detach is the same either way.
    ///
    /// A recording this session already asked to end is left to finish: its
    /// follower reports the ending. One that moved to another session (picked
    /// up) is not this session's any more.
    fn detach_recording(&self) {
        if !self.owns_active() || self.ending.load(Ordering::Acquire) {
            return;
        }
        let Some(m) = manager() else { return };
        let sid = self.ctx.session_id;
        let d = Detached {
            session_id: sid,
            controller_user_id: self.ctx.controller_user_id,
            id: self
                .current
                .lock()
                .ok()
                .and_then(|c| c.clone())
                .unwrap_or_default(),
            unattended: self.unattended.load(Ordering::Acquire),
            file: file_name(m.state().path.as_deref()),
            stopping: false,
            indicator: self.ctx.indicator.clone(),
            outbound: self.ctx.outbound.clone(),
        };
        match slot(|s| s.detach(d)) {
            Some(Detach::Done) => {}
            // Another session's recording, over, whose grace had not looked
            // since: finished here, or its banner stays up for good.
            Some(Detach::Evicted(old)) => finish_detached(m, old),
            Some(Detach::Already) | None => return,
        }
        info!(
            session = %sid,
            grace_s = m.reattach_grace().as_secs(),
            "session ended while recording — waiting for its controller to come back"
        );
        tokio::spawn(grace_watch(sid));
    }

    /// Follow a recording this session started (or picked up, P3b-3) until
    /// its file is final: progress once a second, a stop when the owner
    /// switches remote recording off or someone signs in at an unattended
    /// one, then how it ended. A session that drops hands the recording to
    /// the re-attach grace and stops following it.
    ///
    /// `file` is WHICH recording (its file name) and `speaker` this
    /// follower's claim to report its ending ([`Speakers`]).
    async fn follow(
        self: Arc<Self>,
        id: String,
        unattended: bool,
        file: Option<String>,
        speaker: u64,
    ) {
        let Some(m) = manager() else { return };
        let file = file.unwrap_or_default();
        let sid = self.ctx.session_id;
        let mut gates_rx = gates_tx().subscribe();
        let mut tick = tokio::time::interval(PROGRESS_EVERY);
        let mut stopping = false;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                changed = gates_rx.changed() => {
                    if changed.is_err() {
                        // Unreachable (the sender is a static); keep ticking.
                    }
                }
            }
            // P3b-3 — another session's follower speaks for THIS recording
            // now (a pick-up).
            if superseded(&file, speaker) {
                return;
            }
            let st = m.state();
            let running =
                st.active && file_name(st.path.as_deref()).as_deref() == Some(file.as_str());
            if running && !self.owns_active() {
                // Moved to another session whose follower has not claimed it
                // yet: its claim comes before its first look.
                continue;
            }
            if running {
                // P3b-3 — the session is gone and this session had not asked
                // it to end: the recording is detached (here if nothing else
                // has done it), and whoever picks it up, or the grace, reports
                // how it ends. A stop this session asked for is still
                // reported here.
                if !self.ending.load(Ordering::Acquire)
                    && (self.gone.load(Ordering::Acquire)
                        || slot(|s| s.holds(sid)) == Some(true)
                        || channel_gone(&self.dc))
                {
                    self.detach_recording();
                    return;
                }
                let off = !gates().enabled;
                // P1f — an UNATTENDED recording ends the moment someone signs
                // in: they never saw it start, and nothing on their screen
                // says it runs. Asked fresh every tick, never from a cache;
                // an answer that cannot be had counts as "someone" (closed).
                let signed_in = unattended
                    && !stopping
                    && fresh_remote_identity(m).await != Ok(Identity::Unattended);
                if !stopping && (off || signed_in) {
                    stopping = true;
                    self.ending.store(true, Ordering::Release);
                    let reason = if off {
                        "gate_revoked"
                    } else {
                        "session_changed"
                    };
                    info!(session = %sid, reason, "stopping a remote recording");
                    tokio::spawn(async move {
                        if let Some(m) = manager() {
                            m.stop_with(Some(reason)).await;
                        }
                    });
                }
                let mut s = StateMsg::new(&id, "recording");
                s.name = file_name(st.path.as_deref());
                s.bytes = st.bytes;
                s.duration_ms = st.duration_ms;
                s.audio = st.system_audio;
                s.unattended = unattended;
                send(&self.dc, &s).await;
                continue;
            }
            // Over: how it ended is the state's `last`, if `last` is this
            // recording (another may have begun and ended since the last
            // look, and its numbers are not this one's). A `last` with no
            // file is a failure, which names no recording to tell by.
            let last = st.last.clone().filter(|l| {
                file.is_empty()
                    || l.path.is_none()
                    || file_name(l.path.as_deref()).as_deref() == Some(file.as_str())
            });
            let failed = last.as_ref().is_some_and(|l| l.path.is_none());
            let last = last.unwrap_or_default();
            let name = if failed {
                None
            } else {
                file_name(last.path.as_deref()).or_else(|| (!file.is_empty()).then(|| file.clone()))
            };
            let mut s = StateMsg::new(&id, if failed { "failed" } else { "stopped" });
            s.reason = Some(if last.reason.is_empty() {
                "requested".into()
            } else {
                last.reason.clone()
            });
            s.detail = last.detail.clone();
            s.name = name.clone();
            s.bytes = last.bytes;
            s.duration_ms = last.duration_ms;
            send(&self.dc, &s).await;
            self.report(
                RecordingActivityKind::Stopped,
                name,
                Some(last.bytes),
                Some(last.duration_ms),
                s.reason.clone(),
            );
            self.ctx.indicator.end_recording(sid);
            if let Ok(mut c) = self.current.lock() {
                *c = None;
            }
            self.ending.store(false, Ordering::Release);
            info!(session = %sid, reason = ?s.reason, bytes = last.bytes, "remote recording ended");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> Gates {
        Gates {
            enabled: true,
            audio: false,
        }
    }

    fn detached(session: ObjectId, user: ObjectId) -> Detached {
        Detached {
            session_id: session,
            controller_user_id: user,
            id: "r1".into(),
            unattended: false,
            file: Some("a.mp4".into()),
            stopping: false,
            indicator: crate::indicator::ViewerIndicator::disabled(),
            outbound: mpsc::channel::<ClientMsg>(1).0,
        }
    }

    /// FR-85 decision 6 — a login screen has its own wire code, with the
    /// device's words; every other identity refusal is `unavailable`, with
    /// its words. Red when the code is folded into `unavailable`: the viewer
    /// would say "can't record right now" where "once someone signs in" is
    /// the answer.
    #[test]
    fn a_login_screen_is_its_own_refusal_on_the_wire() {
        assert_eq!(
            identity_refusal(Refusal::LoginScreen),
            (
                "login_screen",
                Some(Refusal::LoginScreen.message().to_string())
            )
        );
        for r in [
            Refusal::NoConsoleUser,
            Refusal::RootDaemon,
            Refusal::SwitchedOff,
        ] {
            assert_eq!(
                identity_refusal(r),
                ("unavailable", Some(r.message().to_string())),
                "{r:?}"
            );
        }
    }

    /// P3b-3 — the slot hands a detached recording to ONE party. A recording
    /// the grace is stopping is never picked up (its ending would be
    /// reported twice, on two sessions); the same session never detaches
    /// twice; a detach over ANOTHER session's recording hands that one back
    /// to be finished, or its banner would stay up for good.
    #[test]
    fn the_slot_hands_a_detached_recording_to_one_party() {
        let (a, b, user, other) = (
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
        );
        let mut s = Slot::default();
        assert!(matches!(s.detach(detached(a, user)), Detach::Done));
        assert!(matches!(s.detach(detached(a, user)), Detach::Already));
        assert!(
            s.pick_up(other).is_none(),
            "another controller picked it up"
        );
        assert_eq!(s.waiting(a), Some(false));

        // The grace claims it for a stop: from here nobody picks it up.
        assert!(s.claim_stop(a));
        assert!(!s.claim_stop(a), "claimed twice");
        assert!(
            s.pick_up(user).is_none(),
            "picked up while the grace stops it"
        );
        assert_eq!(s.waiting(a), None, "a stopping recording still waits");
        assert!(s.holds(a));
        assert!(s.take(a).is_some());
        assert!(s.take(a).is_none());

        // Its own controller picks up one that waits.
        assert!(matches!(s.detach(detached(a, user)), Detach::Done));
        assert!(s.pick_up(user).is_some_and(|d| d.session_id == a));
        assert!(!s.holds(a));

        // A detach over another session's recording hands that one back.
        assert!(matches!(s.detach(detached(a, user)), Detach::Done));
        match s.detach(detached(b, user)) {
            Detach::Evicted(old) => assert_eq!(old.session_id, a),
            _ => panic!("the other session's recording was not handed back"),
        }
        assert!(s.holds(b) && !s.holds(a));
    }

    /// P3b-3 — a recording's ending has one speaker. A pick-up's claim for
    /// the SAME recording silences the dropped session's follower; a NEW
    /// recording's claim does not silence the follower of the one before,
    /// which has yet to report its ending.
    #[test]
    fn a_new_recording_does_not_silence_the_last_ones_follower() {
        let mut sp = Speakers::default();
        let first = sp.claim("a.mp4");
        assert!(!sp.superseded("a.mp4", first));
        let picked_up = sp.claim("a.mp4");
        assert!(
            sp.superseded("a.mp4", first),
            "the dropped session's follower still speaks"
        );
        assert!(!sp.superseded("a.mp4", picked_up));
        let _next = sp.claim("b.mp4");
        assert!(
            !sp.superseded("a.mp4", picked_up),
            "a new recording silenced the last one's follower"
        );
    }

    #[test]
    fn nothing_is_served_unless_the_owner_opted_in_and_a_recorder_can_run() {
        // P3c-2: a recorder that could serve says only that it exists.
        assert_eq!(advertise(Gates::default(), true, true), vec!["available"]);
        assert!(
            advertise(on(), false, true).is_empty(),
            "a host that cannot record a remote session must claim nothing, not even `available`"
        );
        assert!(advertise(Gates::default(), false, true).is_empty());
        assert_eq!(advertise(on(), true, true), vec!["available", "remote"]);
        let both = Gates {
            enabled: true,
            audio: true,
        };
        assert_eq!(
            advertise(both, true, true),
            vec!["available", "remote", "remote-audio"]
        );
        assert_eq!(
            advertise(both, true, false),
            vec!["available", "remote"],
            "where computer audio cannot be recorded (a Mac, a build without audio), \
             no audio claim — whatever the owner set (#1760)"
        );
        // The audio gate alone opts nothing in.
        let audio_only = Gates {
            enabled: false,
            audio: true,
        };
        assert_eq!(advertise(audio_only, true, true), vec!["available"]);
    }

    #[test]
    fn the_prechecks_refuse_in_order_and_by_name() {
        let off = Gates::default();
        assert_eq!(
            precheck(off, false, true, false, true),
            Err("disabled_on_device")
        );
        assert_eq!(
            precheck(on(), false, false, true, false),
            Err("unavailable")
        );
        assert_eq!(
            precheck(on(), true, true, true, false),
            Err("audio_not_allowed")
        );
        let both = Gates {
            enabled: true,
            audio: true,
        };
        // #1760 — a device that cannot record computer audio at all names
        // that, ahead of the owner's gate: a fact no setting fixes, where
        // `audio_not_allowed` would send the controller to ask the owner.
        assert_eq!(
            precheck(both, true, true, false, false),
            Err("audio_unsupported"),
            "the owner allowed it, but this device cannot record it"
        );
        assert_eq!(
            precheck(on(), true, true, false, false),
            Err("audio_unsupported"),
            "with both against it, the platform is the one named"
        );
        assert_eq!(precheck(both, true, true, true, true), Err("busy"));
        assert_eq!(precheck(both, true, true, true, false), Ok(()));
        assert_eq!(precheck(on(), true, false, false, false), Ok(()));
        assert_eq!(
            precheck(both, true, false, false, false),
            Ok(()),
            "a video-only start on such a device is not the audio gate's business"
        );
    }

    /// #1760 — computer audio is ONE answer at every entry point, on both
    /// kinds of device. `supported` stands in for `system_audio_supported()`
    /// (the `audio` feature on Windows or Linux), so a Mac's answer is
    /// checked on a Windows or Linux box and the reverse. What is advertised,
    /// what a start is refused, and what every state tells the viewer must
    /// agree: before this, a Mac's gates read only the audio FEATURE, so it
    /// advertised `remote-audio`, let the start through, and the recorder
    /// refused it as a bare `start_failed`. Red with the `supported` check
    /// dropped from `audio_unavailable`.
    #[test]
    fn computer_audio_is_one_answer_at_every_entry_point() {
        let both = Gates {
            enabled: true,
            audio: true,
        };
        // A device that cannot record it: named as such whatever the owner
        // set, never offered, never started.
        assert_eq!(audio_unavailable(both, false), Some("audio_unsupported"));
        assert_eq!(
            audio_unavailable(on(), false),
            Some("audio_unsupported"),
            "the platform comes before the owner's gate"
        );
        assert!(
            !advertise(both, true, false)
                .iter()
                .any(|c| c == "remote-audio")
        );
        assert_eq!(
            precheck(both, true, true, false, false),
            Err("audio_unsupported")
        );
        // A device that can: the owner's gate decides, and says so.
        assert_eq!(audio_unavailable(both, true), None);
        assert_eq!(audio_unavailable(on(), true), Some("audio_not_allowed"));
        assert!(
            advertise(both, true, true)
                .iter()
                .any(|c| c == "remote-audio")
        );
        assert_eq!(precheck(both, true, true, true, false), Ok(()));
        // The three entry points agree on every combination.
        for enabled in [false, true] {
            for audio in [false, true] {
                for supported in [false, true] {
                    let g = Gates { enabled, audio };
                    let offered = enabled && audio_unavailable(g, supported).is_none();
                    assert_eq!(
                        advertise(g, true, supported)
                            .iter()
                            .any(|c| c == "remote-audio"),
                        offered,
                        "advertise {g:?} supported={supported}"
                    );
                    assert_eq!(
                        precheck(g, true, true, supported, false).is_ok(),
                        offered,
                        "precheck {g:?} supported={supported}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_wire_parses_and_speaks_the_documented_shapes() {
        assert_eq!(
            serde_json::from_str::<Incoming>(r#"{"t":"rc:record.start","id":"a1","audio":true}"#)
                .unwrap(),
            Incoming::Start {
                id: "a1".into(),
                audio: true
            }
        );
        assert_eq!(
            serde_json::from_str::<Incoming>(r#"{"t":"rc:record.start"}"#).unwrap(),
            Incoming::Start {
                id: String::new(),
                audio: false
            },
            "audio is OFF unless asked for"
        );
        assert_eq!(
            serde_json::from_str::<Incoming>(r#"{"t":"rc:record.stop","id":"a1"}"#).unwrap(),
            Incoming::Stop { id: "a1".into() }
        );
        // ⚠️ There is no microphone on this wire: a field that asks for one is
        // ignored, never honoured.
        assert_eq!(
            serde_json::from_str::<Incoming>(
                r#"{"t":"rc:record.start","id":"m","microphone":true}"#
            )
            .unwrap(),
            Incoming::Start {
                id: "m".into(),
                audio: false
            }
        );

        let mut s = StateMsg::new("a1", "refused");
        s.reason = Some("no_indicator_surface".into());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["t"], "rc:record.state");
        assert_eq!(v["state"], "refused");
        assert_eq!(v["reason"], "no_indicator_surface");
        assert!(v.get("name").is_none() && v.get("detail").is_none());
        // #1760 — `audio_unavailable` is absent where computer audio is
        // available (so an old device and an able one read alike), and the
        // code where it is not.
        assert!(
            v.get("audio_unavailable").is_none(),
            "absent where computer audio is available: {v}"
        );
        let mut s = StateMsg::new("", "idle");
        s.audio_unavailable = audio_unavailable(on(), false);
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["audio_unavailable"], "audio_unsupported");
        s.audio_unavailable = audio_unavailable(on(), true);
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["audio_unavailable"], "audio_not_allowed");
        s.audio_unavailable = audio_unavailable(
            Gates {
                enabled: true,
                audio: true,
            },
            true,
        );
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("audio_unavailable").is_none(), "{v}");
    }

    #[test]
    fn the_controller_is_told_a_file_name_never_a_path() {
        let p = if cfg!(windows) {
            r"C:\Users\someone\Videos\Roomler\Roomler Recording 2026-09-25 14-30-12.mp4"
        } else {
            "/home/someone/Videos/Roomler/Roomler Recording 2026-09-25 14-30-12.mp4"
        };
        assert_eq!(
            file_name(Some(p)).as_deref(),
            Some("Roomler Recording 2026-09-25 14-30-12.mp4")
        );
        assert_eq!(file_name(None), None);
    }

    /// A recording and its sidecar, in `dir`.
    fn made(dir: &Path, name: &str, initiator: Option<super::super::sidecar::Initiator>) {
        use super::super::mp4::ColorInfo;
        use super::super::sidecar::{AudioInfo, SIDECAR_VERSION, Sidecar};
        let path = dir.join(name);
        std::fs::write(&path, b"not really an mp4").unwrap();
        if let Some(initiator) = initiator {
            let sc = Sidecar {
                version: SIDECAR_VERSION,
                file: name.into(),
                initiator,
                started_at: "2026-09-25T12:30:12Z".into(),
                ended_at: None,
                duration_ms: 1000,
                width: 320,
                height: 240,
                fps: 30,
                codec: "h264".into(),
                encoder: "openh264".into(),
                color: ColorInfo::BT601_LIMITED,
                audio: AudioInfo::default(),
                frames: 30,
                late_ticks: 0,
                events: Vec::new(),
                stop_reason: None,
                bytes: 17,
                pointer: None,
            };
            std::fs::write(Sidecar::path_for(&path), sc.to_json()).unwrap();
        }
    }

    /// P3b-2 — a recording is a controller's to list or fetch only when its
    /// sidecar says THAT user started it remotely: not the person at the
    /// device's own, not another controller's, not one with no sidecar or a
    /// broken one.
    #[test]
    fn only_the_controller_who_started_it_owns_a_recording() {
        use super::super::sidecar::Initiator;
        let dir = tempfile::tempdir().unwrap();
        let me = ObjectId::new();
        let other = ObjectId::new();
        let remote = |who: &ObjectId| Initiator::Remote {
            controller_user_id: who.to_hex(),
            controller_name: Some("x".into()),
        };
        made(dir.path(), "mine.mp4", Some(remote(&me)));
        made(dir.path(), "theirs.mp4", Some(remote(&other)));
        made(
            dir.path(),
            "local.mp4",
            Some(Initiator::Local { user: None }),
        );
        made(dir.path(), "bare.mp4", None);
        made(dir.path(), "broken.mp4", None);
        std::fs::write(dir.path().join("broken.mp4.roomler.json"), b"{nope").unwrap();

        assert!(owned_by(dir.path(), "mine.mp4", &me));
        for name in [
            "theirs.mp4",
            "local.mp4",
            "bare.mp4",
            "broken.mp4",
            "absent.mp4",
        ] {
            assert!(!owned_by(dir.path(), name, &me), "{name}");
        }
        let listed: Vec<String> = owned_recordings(dir.path(), &me)
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(listed, vec!["mine.mp4"]);
        assert!(owned_recordings(dir.path(), &ObjectId::new()).is_empty());
    }

    /// P3b-2 — a download never follows a link out of the folder.
    #[test]
    fn a_link_at_a_recordings_name_is_never_opened() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        let real = dir.path().join("real.mp4");
        std::fs::write(&real, b"a recording").unwrap();
        assert!(open_no_follow(&real).is_ok(), "the positive control");
        assert!(
            open_no_follow(dir.path()).is_err(),
            "a directory is not a recording"
        );

        let link = dir.path().join("link.mp4");
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&outside, &link).is_ok();
        // Creating a symlink on Windows needs a privilege (or developer
        // mode): where it is refused, the case cannot be staged here.
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&outside, &link).is_ok();
        if made {
            assert!(
                open_no_follow(&link).is_err(),
                "followed a link out of the folder"
            );
        }
    }

    #[test]
    fn adopt_follows_the_config_and_only_signals_a_change() {
        let mut cfg = meshharbor_node_core::config::test_fixture();
        cfg.record_remote_enabled = true;
        adopt(&cfg);
        let rx = gates_tx().subscribe();
        adopt(&cfg);
        assert!(!rx.has_changed().unwrap(), "the same gates are not news");
        cfg.record_remote_enabled = false;
        adopt(&cfg);
        assert!(
            rx.has_changed().unwrap(),
            "an OFF must reach a recording in progress"
        );
        assert_eq!(gates(), Gates::default());
    }
}
