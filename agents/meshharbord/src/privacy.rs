// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-99 P1b — the device's half of privacy mode.
//!
//! A controller whose session grant holds `Permissions::PRIVACY` asks, over
//! the session's own `privacy` DataChannel, to cover this screen: a curtain
//! the person in front of it sees, and every capture path looks through
//! (`WDA_EXCLUDEFROMCAPTURE`, verified after it is set rather than trusted;
//! `indicator/win.rs`). The hub grants the bit only to a device that
//! advertises `privacy-mode` (P1a), and this side decides again, on its own
//! word, at every "on":
//!
//! | # | gate | refusal |
//! |---|---|---|
//! | 1 | the session's grant holds `PRIVACY` (checked when the channel opens) | `not_granted` |
//! | 2 | the owner's `privacy_mode_allowed`, read NOW | `disabled_on_device` |
//! | 3 | a curtain is possible here: Windows 10 2004 or later, in a build whose overlay came up | `unavailable` |
//! | 4 | the overlay put the curtain up, out of capture | `no_curtain` |
//!
//! Gate 2 is the one that survives a compromised server: the owner's switch is
//! device-owned and absent from `DesiredConfig`, so no server push reaches it.
//!
//! Turning it off is never refused. The curtain comes down when the controller
//! says so, when the session ends (the channel closes, or the overlay drops the
//! session), and when the owner switches the gate off, which the viewer is told
//! (`disabled_on_device`). Nothing survives the session: the windows die with
//! the process that drew them.
//!
//! ⚠️ The curtain HIDES the screen; it does not stop a person at the keyboard.
//! It is click-through by necessity (the controller's injected clicks must
//! reach the application beneath it), so the person's own mouse passes through
//! too, and the system UI the shell draws above every topmost window (the Start
//! menu, notifications, Alt+Tab's thumbnails) still shows over it. Blocking
//! local input is P2's `BlockInput`.
//!
//! **The device's account (P1d).** Every curtain up, every take-down with its
//! reason (`controller`, `session_end`, `disabled_on_device`) and every refused
//! "on" goes to the server as `rc:privacy.activity`, which keeps it in
//! `privacy_activity` beside the grant. A process killed with a curtain up
//! cannot report its end: the OS takes the windows down with it, so the curtain
//! is gone, but nothing told the server. So each curtain is noted in a
//! [`Ledger`] on disk while it is up, and the next process to start reports
//! each one it finds as `off {worker_exit}` ([`collect_leftovers`],
//! [`drain_leftovers`]).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bson::oid::ObjectId;
use meshharbor_remote_control::models::{PrivacyActivityKind, RpcCap};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::signaling::ClientMsg;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;

/// The first Windows build whose `SetWindowDisplayAffinity` knows
/// `WDA_EXCLUDEFROMCAPTURE` (10 2004). Earlier builds treat it as
/// `WDA_MONITOR`, which blacks the window out of the capture instead of
/// leaving it out: the controller would see the curtain too.
pub const MIN_WINDOWS_BUILD: u32 = 19041;

/// How often an attached channel looks at its own state. A channel this side
/// closed often never reports `on_close` (webrtc-rs leaves it `Closing`).
const WATCH_EVERY: Duration = Duration::from_millis(500);

// ── The owner's gate ────────────────────────────────────────────────────────

fn allowed_tx() -> &'static watch::Sender<bool> {
    static TX: OnceLock<watch::Sender<bool>> = OnceLock::new();
    TX.get_or_init(|| watch::channel(false).0)
}

/// Seed (at start-up) or re-seed (after a LOCAL `ConfigSet`) the owner's
/// `privacy_mode_allowed`. The server never reaches this: the key is
/// structurally absent from `DesiredConfig`. Going OFF takes every curtain
/// that is up down (see [`attach`]).
pub fn set_device_allowed(allowed: bool) {
    allowed_tx().send_if_modified(|v| {
        let changed = *v != allowed;
        *v = allowed;
        changed
    });
}

/// The owner's gate, as it is now.
pub fn device_allowed() -> bool {
    *allowed_tx().borrow()
}

// ── Whether a curtain is possible here ──────────────────────────────────────

static OVERLAY_UP: AtomicBool = AtomicBool::new(false);

/// Called once the native overlay that draws the curtain is running in this
/// process (`ViewerIndicator::new` succeeded). Without it there is nothing to
/// draw with — a service in session 0, a headless host — and the device must
/// not advertise what it cannot do.
pub fn set_overlay_up(up: bool) {
    OVERLAY_UP.store(up, Ordering::Release);
}

/// Can this process put a curtain up at all? Windows 10 2004 or later, a build
/// with the overlay (`viewer-indicator`), and the overlay running.
pub fn curtain_possible() -> bool {
    #[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
    {
        OVERLAY_UP.load(Ordering::Acquire)
            && crate::encode::hwid::windows_build().is_some_and(|b| b >= MIN_WINDOWS_BUILD)
    }
    #[cfg(not(all(target_os = "windows", feature = "viewer-indicator")))]
    {
        false
    }
}

/// The `rpc` words for privacy mode: `privacy-available` where a curtain is
/// possible, and `privacy-mode` only while the owner allows it as well. The
/// hub grants `PRIVACY` on `privacy-mode` alone; `privacy-available` lets it
/// tell the viewer "the owner has not allowed it" instead of nothing.
pub fn words(possible: bool, allowed: bool) -> Vec<RpcCap> {
    match (possible, allowed) {
        (false, _) => Vec::new(),
        (true, false) => vec![RpcCap::PrivacyAvailable],
        (true, true) => vec![RpcCap::PrivacyAvailable, RpcCap::PrivacyMode],
    }
}

/// [`words`] for this process, now.
pub fn current_words() -> Vec<RpcCap> {
    words(curtain_possible(), device_allowed())
}

/// The consent prompt's line for a grant that may cover the screen. `None`
/// unless the grant holds `PRIVACY` AND this device could act on it: a line
/// the device would refuse anyway (gate 2 or 3) tells the person something
/// that cannot happen.
///
/// One short line: the native panel draws `detail` on a single line and cuts
/// what does not fit. How to end the session is on the curtain itself.
pub fn consent_line(
    permissions: Permissions,
    allowed: bool,
    possible: bool,
) -> Option<&'static str> {
    (permissions.contains(Permissions::PRIVACY) && allowed && possible)
        .then_some("They may also cover this screen while they work.")
}

/// `roomlerd curtain-smoke` — put a curtain up through the PRODUCTION overlay
/// for `seconds`, print whether it went up out of capture, and take it down.
/// A field check that needs no server and no viewer: a screenshot of the host
/// shows the curtain while a session's stream shows the desktop under it.
/// `Ok(false)` when no curtain went up (not possible here, or refused).
pub fn curtain_smoke(seconds: u64) -> anyhow::Result<bool> {
    let (kill_tx, _kill_rx) = tokio::sync::mpsc::channel(1);
    let (consent_tx, _consent_rx) = tokio::sync::mpsc::channel(1);
    let indicator = crate::indicator::ViewerIndicator::new(
        kill_tx,
        crate::rc_sessions::RcSessionRegistry::new(),
        consent_tx,
    )?;
    set_overlay_up(true);
    let session = ObjectId::new();
    indicator.show_session_full(
        session,
        "curtain-smoke".into(),
        "VIEW | PRIVACY".into(),
        String::new(),
    );
    let possible = curtain_possible();
    let up = possible && indicator.set_privacy(session, true, "curtain-smoke");
    println!("curtain-smoke: possible={possible} up={up}");
    if up {
        std::thread::sleep(Duration::from_secs(seconds));
        indicator.set_privacy(session, false, "curtain-smoke");
        println!("curtain-smoke: down after {seconds}s");
    }
    indicator.hide_session(session.to_hex());
    Ok(up)
}

// ── The wire, on the `privacy` DataChannel ─────────────────────────────────

/// Controller → device.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "t")]
pub enum Incoming {
    /// Cover the screen (`on: true`) or uncover it. `id` is the controller's
    /// handle for this request, echoed on the answer.
    #[serde(rename = "rc:privacy.set")]
    Set {
        #[serde(default)]
        id: String,
        on: bool,
    },
    /// Say where things stand (a viewer that reconnected its channel).
    #[serde(rename = "rc:privacy.status")]
    Status {
        #[serde(default)]
        id: String,
    },
}

/// Device → controller: one `rc:privacy.state`.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct StateMsg {
    pub t: &'static str,
    pub id: String,
    /// Is the curtain up for this session?
    pub on: bool,
    /// Why a request was refused, or why the curtain came down when the
    /// controller did not ask: `not_granted`, `disabled_on_device`,
    /// `unavailable`, `no_curtain`. Absent when it did what was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// P4 — while the curtain is up: are the host's speakers muted? `false`
    /// when muting failed. Absent when the curtain is down, or the device has
    /// no endpoint to mute. A viewer that predates P4 ignores it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_muted: Option<bool>,
}

impl StateMsg {
    fn new(id: &str, on: bool, reason: Option<&'static str>) -> Self {
        Self {
            t: "rc:privacy.state",
            id: id.to_string(),
            on,
            reason,
            host_muted: None,
        }
    }

    fn muted(mut self, host_muted: Option<bool>) -> Self {
        self.host_muted = host_muted;
        self
    }
}

// ── The curtain's host, and one session's privacy ───────────────────────────

/// Whatever draws the curtain: the native overlay in production
/// (`ViewerIndicator`), a recorder in tests.
pub trait CurtainHost: Send + Sync + 'static {
    /// Put `session`'s curtain up (`on`) or take it down. `true` only when it
    /// is UP and out of capture; a take-down answers `false`. May block for
    /// as long as the overlay takes to answer, so callers off a runtime
    /// thread only.
    fn set_curtain(&self, session: ObjectId, on: bool, controller: &str) -> bool;
}

impl CurtainHost for crate::indicator::ViewerIndicator {
    fn set_curtain(&self, session: ObjectId, on: bool, controller: &str) -> bool {
        self.set_privacy(session, on, controller)
    }
}

// ── The device's account (P1d) ──────────────────────────────────────────────

/// One curtain a process holds, as the [`Ledger`] keeps it: the session, and
/// the org whose connection reports on it (a session belongs to the org that
/// asked, and the server looks it up within that org).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub session_id: String,
    pub tenant_id: String,
}

/// The curtains this process holds, kept on disk while they are up, so that
/// the next process can report the ones this one died holding.
pub struct Ledger {
    path: Option<PathBuf>,
    /// One read-modify-write at a time: two sessions can change it at once.
    lock: Mutex<()>,
}

impl Ledger {
    pub fn at(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            lock: Mutex::new(()),
        }
    }

    /// `privacy-curtains.json` in this process's own local data dir: SYSTEM's
    /// profile for a service's worker, the person's for a per-user install, so
    /// the next process of the same install finds it and nobody else writes
    /// it.
    fn default_location() -> Self {
        Self {
            path: meshharbor_node_core::appdirs::project_dirs()
                .map(|p| p.data_local_dir().join("privacy-curtains.json")),
            lock: Mutex::new(()),
        }
    }

    fn read(&self) -> Vec<Held> {
        let Some(path) = &self.path else {
            return Vec::new();
        };
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn write(&self, held: &[Held]) {
        let Some(path) = &self.path else {
            return;
        };
        let res = if held.is_empty() {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
        } else {
            // Written aside and renamed over, so a process killed mid-write
            // leaves the old ledger or the new one, never half of one.
            let tmp = path.with_extension("json.tmp");
            path.parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::write(&tmp, serde_json::to_vec(held).unwrap_or_default()))
                .and_then(|()| std::fs::rename(&tmp, path))
        };
        if let Err(e) = res {
            warn!(%e, path = %path.display(), "privacy: the curtain ledger could not be written");
        }
    }

    fn add(&self, held: Held) {
        let _l = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut all = self.read();
        if !all.contains(&held) {
            all.push(held);
            self.write(&all);
        }
    }

    fn remove(&self, session_id: &str) {
        let _l = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut all = self.read();
        let before = all.len();
        all.retain(|h| h.session_id != session_id);
        if all.len() != before {
            self.write(&all);
        }
    }

    /// What a previous process left: read, then cleared. Called once, at
    /// start-up, before any session of this process can put a curtain up.
    pub fn take_leftovers(&self) -> Vec<Held> {
        let _l = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let all = self.read();
        if !all.is_empty() {
            self.write(&[]);
        }
        all
    }
}

/// The process's ledger.
pub fn ledger() -> Arc<Ledger> {
    static LEDGER: OnceLock<Arc<Ledger>> = OnceLock::new();
    LEDGER
        .get_or_init(|| Arc::new(Ledger::default_location()))
        .clone()
}

/// The curtains a previous process died holding, waiting for their org's
/// connection.
fn leftovers() -> &'static Mutex<Vec<Held>> {
    static LEFTOVERS: OnceLock<Mutex<Vec<Held>>> = OnceLock::new();
    LEFTOVERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// At start-up, before the first connection: take what a previous process left
/// in the ledger. Each is reported as `off {worker_exit}` once its org's
/// connection is up ([`drain_leftovers`]).
pub fn collect_leftovers() {
    // P4 — and a mute of the host's speakers that a previous process died
    // holding is undone before any curtain of this one.
    crate::host_mute::host_mute().restore_leftover();
    let found = ledger().take_leftovers();
    if !found.is_empty() {
        info!(
            count = found.len(),
            "privacy: the previous process ended with curtains up; reporting them as worker_exit"
        );
        leftovers()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend(found);
    }
}

/// A connection of the org `tenant_id` is up: report that org's leftovers on
/// it. One the queue refuses waits for the next connection.
pub fn drain_leftovers(tenant_id: &str, outbound: &mpsc::Sender<ClientMsg>) {
    let mut all = leftovers().lock().unwrap_or_else(|p| p.into_inner());
    drain_into(&mut all, tenant_id, outbound);
}

fn drain_into(all: &mut Vec<Held>, tenant_id: &str, outbound: &mpsc::Sender<ClientMsg>) {
    all.retain(|h| {
        if h.tenant_id != tenant_id {
            return true;
        }
        let Ok(session_id) = ObjectId::parse_str(&h.session_id) else {
            return false;
        };
        let msg = ClientMsg::PrivacyActivity {
            session_id,
            kind: PrivacyActivityKind::Off,
            reason: Some("worker_exit".into()),
        };
        outbound.try_send(msg).is_err()
    });
}

/// Where a session's privacy activity goes: the server, on the connection of
/// the org the session belongs to, and the ledger while a curtain is up.
#[derive(Clone)]
pub struct Reporter {
    pub outbound: mpsc::Sender<ClientMsg>,
    pub tenant_id: String,
    pub ledger: Arc<Ledger>,
}

impl Reporter {
    fn send(&self, session_id: ObjectId, kind: PrivacyActivityKind, reason: Option<&'static str>) {
        let msg = ClientMsg::PrivacyActivity {
            session_id,
            kind,
            reason: reason.map(str::to_string),
        };
        // Never blocks a session: a full queue means the connection is already
        // struggling, and losing an audit line beats stalling the curtain.
        if self.outbound.try_send(msg).is_err() {
            debug!(session = %session_id, "privacy activity dropped (queue full or closed)");
        }
    }
}

/// What the `privacy` channel of one session needs. Set by the signalling loop
/// before the answer, so a channel can never open without it.
#[derive(Clone)]
pub struct PrivacyCtx {
    pub session_id: ObjectId,
    pub controller_name: String,
    pub host: Arc<dyn CurtainHost>,
    /// Gate 3, asked at every "on": [`curtain_possible`] in production. A
    /// field so the channel's own test can run the whole path on a runner
    /// where no curtain is possible.
    pub possible: fn() -> bool,
    /// P1d — the session's account to the server, and the ledger.
    pub report: Reporter,
    /// P4 — the process's guard over the host's speakers
    /// ([`crate::host_mute::host_mute`] in production, a fake in tests).
    pub mute: Arc<crate::host_mute::HostMute>,
}

/// One session's privacy mode: its gates and whether its curtain is up. The
/// decisions are here and the channel glue is in [`attach`], so the gates are
/// tested without a peer.
pub struct Session {
    ctx: PrivacyCtx,
    /// Whether the curtain is up. Read without the lock, so a `status` on the
    /// channel's message loop never waits behind an overlay that is slow to
    /// answer.
    on: AtomicBool,
    /// Serialises the transitions (each may block on the overlay).
    transition: Mutex<()>,
    /// P4 — what [`crate::host_mute::HostMute::hold`] answered for this
    /// session's curtain; `None` while it is down. Set under `transition`.
    host_muted: Mutex<Option<Option<bool>>>,
}

impl Session {
    pub fn new(ctx: PrivacyCtx) -> Self {
        Self {
            ctx,
            on: AtomicBool::new(false),
            transition: Mutex::new(()),
            host_muted: Mutex::new(None),
        }
    }

    /// P4 — the host's speakers, as the last hold left them: `None` while the
    /// curtain is down or there is no endpoint.
    pub fn host_muted(&self) -> Option<bool> {
        self.host_muted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .flatten()
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Acquire)
    }

    /// Take the curtain down, and say why: `controller`, `session_end` or
    /// `disabled_on_device`, the reason codes the server keeps.
    fn take_down(&self, reason: &'static str) {
        self.ctx
            .host
            .set_curtain(self.ctx.session_id, false, &self.ctx.controller_name);
        self.on.store(false, Ordering::Release);
        // P4 — this session's hold on the host's speakers ends with its curtain.
        if self
            .host_muted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .is_some()
        {
            self.ctx.mute.release();
        }
        self.ctx.report.ledger.remove(&self.ctx.session_id.to_hex());
        self.ctx
            .report
            .send(self.ctx.session_id, PrivacyActivityKind::Off, Some(reason));
        info!(session = %self.ctx.session_id, reason, "privacy: curtain down");
    }

    /// Refuse an "on" in the device's words, and report it.
    fn refuse(&self, id: &str, reason: &'static str) -> StateMsg {
        self.ctx.report.send(
            self.ctx.session_id,
            PrivacyActivityKind::Refused,
            Some(reason),
        );
        StateMsg::new(id, self.is_on(), Some(reason))
    }

    /// A controller's `rc:privacy.set`, against the gates as they are now.
    pub fn set(&self, id: &str, want: bool, allowed: bool, possible: bool) -> StateMsg {
        let _t = self.transition.lock().unwrap_or_else(|p| p.into_inner());
        if !want {
            if self.is_on() {
                self.take_down("controller");
            }
            return StateMsg::new(id, false, None);
        }
        if !allowed {
            return self.refuse(id, "disabled_on_device");
        }
        if !possible {
            return self.refuse(id, "unavailable");
        }
        if self.is_on() {
            return StateMsg::new(id, true, None).muted(self.host_muted());
        }
        // Noted BEFORE it goes up: a process that dies between the two then
        // leaves an entry for a curtain that may never have shown, never a
        // curtain with no entry.
        let held = Held {
            session_id: self.ctx.session_id.to_hex(),
            tenant_id: self.ctx.report.tenant_id.clone(),
        };
        self.ctx.report.ledger.add(held);
        if !self
            .ctx
            .host
            .set_curtain(self.ctx.session_id, true, &self.ctx.controller_name)
        {
            self.ctx.report.ledger.remove(&self.ctx.session_id.to_hex());
            warn!(session = %self.ctx.session_id, "privacy: the overlay could not put a curtain up");
            return self.refuse(id, "no_curtain");
        }
        self.on.store(true, Ordering::Release);
        // P4 — the person at the device neither sees nor hears the session:
        // the host's speakers are muted while the curtain is up, and the
        // controller keeps the audio (the loopback survives the mute).
        let muted = self.ctx.mute.hold();
        *self.host_muted.lock().unwrap_or_else(|p| p.into_inner()) = Some(muted);
        self.ctx
            .report
            .send(self.ctx.session_id, PrivacyActivityKind::On, None);
        info!(session = %self.ctx.session_id, host_muted = ?muted, "privacy: curtain up");
        StateMsg::new(id, true, None).muted(muted)
    }

    /// The owner switched the gate off: a curtain that is up comes down, and
    /// the viewer is told why. `None` when there was nothing up.
    pub fn owner_switched_off(&self) -> Option<StateMsg> {
        let _t = self.transition.lock().unwrap_or_else(|p| p.into_inner());
        if !self.is_on() {
            return None;
        }
        self.take_down("disabled_on_device");
        Some(StateMsg::new("", false, Some("disabled_on_device")))
    }

    /// The session ended: whatever is up comes down. Idempotent.
    pub fn end(&self) {
        let _t = self.transition.lock().unwrap_or_else(|p| p.into_inner());
        if self.is_on() {
            self.take_down("session_end");
        }
    }
}

// ── The channel ─────────────────────────────────────────────────────────────

fn channel_gone(dc: &RTCDataChannel) -> bool {
    matches!(
        dc.ready_state(),
        RTCDataChannelState::Closing | RTCDataChannelState::Closed
    )
}

async fn send(dc: &RTCDataChannel, s: &StateMsg) {
    if let Ok(text) = serde_json::to_string(s)
        && let Err(e) = dc.send_text(text).await
    {
        tracing::debug!(%e, "privacy DC: send failed (channel closing)");
    }
}

/// Run a blocking [`Session`] call off the runtime: the overlay may take a
/// moment to answer, and the channel's message loop must not wait on it.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

/// Serve `rc:privacy.*` on `dc` for the session in `ctx`. Installed only when
/// the session's grant holds `Permissions::PRIVACY`.
pub fn attach(dc: Arc<RTCDataChannel>, ctx: PrivacyCtx) {
    info!(session = %ctx.session_id, "privacy DC attached");
    let possible = ctx.possible;
    let session = Arc::new(Session::new(ctx));
    let gone = Arc::new(AtomicBool::new(false));

    // The session's end, two ways: `on_close` when the far end closed the
    // channel, and a look at the channel's state for when this side did. The
    // overlay also drops a session's curtain when the session leaves it.
    let end = {
        let session = session.clone();
        let gone = gone.clone();
        move || {
            if !gone.swap(true, Ordering::AcqRel) {
                let session = session.clone();
                tokio::task::spawn_blocking(move || session.end());
            }
        }
    };
    let on_close = end.clone();
    dc.on_close(Box::new(move || {
        on_close();
        Box::pin(async {})
    }));

    // Watch the channel, and the owner's gate: OFF takes the curtain down.
    {
        let dc = dc.clone();
        let session = session.clone();
        let gone = gone.clone();
        let end = end.clone();
        let mut allowed = allowed_tx().subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = allowed.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        let now = *allowed.borrow_and_update();
                        if !now {
                            let s = session.clone();
                            if let Some(Some(msg)) = blocking(move || s.owner_switched_off()).await {
                                send(&dc, &msg).await;
                            }
                        }
                    }
                    _ = tokio::time::sleep(WATCH_EVERY) => {}
                }
                if gone.load(Ordering::Acquire) {
                    return;
                }
                if channel_gone(&dc) {
                    end();
                    return;
                }
            }
        });
    }

    let dc_for_handler = dc.clone();
    dc.on_message(Box::new(move |msg| {
        let dc = dc_for_handler.clone();
        let session = session.clone();
        Box::pin(async move {
            if !msg.is_string {
                return;
            }
            let Ok(text) = std::str::from_utf8(&msg.data) else {
                return;
            };
            match serde_json::from_str::<Incoming>(text) {
                Ok(Incoming::Set { id, on }) => {
                    // Off the message loop: the overlay may take a moment.
                    tokio::spawn(async move {
                        let (allowed, possible) = (device_allowed(), possible());
                        let s = session.clone();
                        if let Some(msg) = blocking(move || s.set(&id, on, allowed, possible)).await
                        {
                            send(&dc, &msg).await;
                        }
                    });
                }
                Ok(Incoming::Status { id }) => {
                    let msg = StateMsg::new(&id, session.is_on(), None).muted(session.host_muted());
                    send(&dc, &msg).await;
                }
                Err(e) => warn!(%e, "privacy DC: unparseable message"),
            }
        })
    }));
}

/// A channel that answers every request with `reason` instead of silence, so
/// a viewer that opened it anyway is told why: `not_granted` on a session
/// WITHOUT `Permissions::PRIVACY`, `unavailable` where the session was given
/// no privacy context.
pub fn attach_refusing(dc: Arc<RTCDataChannel>, session_id: ObjectId, reason: &'static str) {
    info!(session = %session_id, reason, "privacy DC attached in REFUSE mode");
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
            send(&dc, &StateMsg::new(&id, false, Some(reason))).await;
        })
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-99 AC6 — FR-92's no-hooks rule covers privacy mode: no hook, raw-input
    /// sink or keyboard-state read anywhere in the curtain's code, this module
    /// and the overlay that draws it. Each is what a keylogger looks like to
    /// EDR, and a GPO-locked desktop running EDR is in the acceptance bar; P2's
    /// block is `BlockInput` for the same reason. Comments may name them; code,
    /// string constants included, may not. The banned names are assembled at
    /// run time, so this file cannot trip its own scan.
    #[test]
    fn no_keylogger_shaped_api_in_privacy_mode() {
        let sources: [(&str, &str); 3] = [
            ("privacy.rs", include_str!("privacy.rs")),
            ("indicator/win.rs", include_str!("indicator/win.rs")),
            // P4 — the host mute is privacy mode's too.
            ("host_mute.rs", include_str!("host_mute.rs")),
        ];
        let banned: Vec<String> = [
            ["SetWindows", "HookEx"],
            ["RegisterRaw", "InputDevices"],
            ["GetRaw", "InputData"],
            ["GetKeyboard", "State"],
            ["GetAsync", "KeyState"],
        ]
        .iter()
        .map(|p| p.concat())
        .collect();
        for (name, src) in sources {
            for (i, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for b in &banned {
                    assert!(!code.contains(b.as_str()), "{name}:{}: uses {b}", i + 1);
                }
            }
        }
    }

    /// Records every call, and answers an "up" with `up_ok`.
    struct Recorder {
        calls: Mutex<Vec<bool>>,
        up_ok: bool,
    }

    impl CurtainHost for Recorder {
        fn set_curtain(&self, _session: ObjectId, on: bool, _controller: &str) -> bool {
            self.calls.lock().unwrap().push(on);
            on && self.up_ok
        }
    }

    /// P4 — an endpoint whose mute is a flag (`None` = no endpoint), so no
    /// test ever touches the real speakers of the machine it runs on.
    struct FakeSpeakers(Mutex<Option<bool>>);

    impl crate::host_mute::Speakers for FakeSpeakers {
        fn muted(&self) -> Option<bool> {
            *self.0.lock().unwrap()
        }
        fn set_muted(&self, mute: bool) -> bool {
            let mut m = self.0.lock().unwrap();
            if m.is_some() {
                *m = Some(mute);
            }
            true
        }
    }

    fn fake_mute(start: Option<bool>) -> (Arc<crate::host_mute::HostMute>, Arc<FakeSpeakers>) {
        let speakers = Arc::new(FakeSpeakers(Mutex::new(start)));
        let guard = crate::host_mute::HostMute::new(speakers.clone(), None);
        (Arc::new(guard), speakers)
    }

    /// A session whose reports go nowhere: no ledger file, and a queue
    /// nobody reads (a report that cannot be queued is dropped, as on a dying
    /// connection).
    fn session(up_ok: bool) -> (Session, Arc<Recorder>) {
        let (s, host, _) = session_with_speakers(up_ok, None);
        (s, host)
    }

    /// [`session`] over a fake endpoint that starts as `speakers` (P4).
    fn session_with_speakers(
        up_ok: bool,
        speakers: Option<bool>,
    ) -> (Session, Arc<Recorder>, Arc<FakeSpeakers>) {
        let host = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            up_ok,
        });
        let (mute, fake) = fake_mute(speakers);
        let s = Session::new(PrivacyCtx {
            session_id: ObjectId::new(),
            controller_name: "Alex".into(),
            host: host.clone(),
            possible: || true,
            report: Reporter {
                outbound: mpsc::channel(1).0,
                tenant_id: ObjectId::new().to_hex(),
                ledger: Arc::new(Ledger {
                    path: None,
                    lock: Mutex::new(()),
                }),
            },
            mute,
        });
        (s, host, fake)
    }

    /// P4 — the curtain mutes the host's speakers and says so; its end
    /// restores them. A status while it is up says so too.
    #[test]
    fn a_curtain_mutes_the_host_and_its_end_unmutes_it() {
        let (s, _host, speakers) = session_with_speakers(true, Some(false));
        let up = s.set("a", true, true, true);
        assert_eq!((up.on, up.host_muted), (true, Some(true)));
        assert_eq!(*speakers.0.lock().unwrap(), Some(true), "muted while up");
        assert_eq!(s.host_muted(), Some(true));
        let again = s.set("b", true, true, true);
        assert_eq!(again.host_muted, Some(true), "a repeated on says the same");
        s.end();
        assert_eq!(
            *speakers.0.lock().unwrap(),
            Some(false),
            "restored at the end"
        );
        assert_eq!(s.host_muted(), None, "nothing to say once down");
        let json =
            serde_json::to_value(StateMsg::new("c", false, None).muted(s.host_muted())).unwrap();
        assert!(
            json.get("host_muted").is_none(),
            "absent while down: {json}"
        );
    }

    /// P4 — no endpoint: the curtain still goes up, and the answer carries no
    /// `host_muted` at all; a curtain that could not go up never mutes.
    #[test]
    fn no_endpoint_or_no_curtain_means_no_mute() {
        let (s, _host, _sp) = session_with_speakers(true, None);
        let up = s.set("a", true, true, true);
        assert_eq!((up.on, up.host_muted), (true, None));
        let json = serde_json::to_value(&up).unwrap();
        assert!(json.get("host_muted").is_none(), "{json}");
        s.end();

        let (s, _host, speakers) = session_with_speakers(false, Some(false));
        let refused = s.set("a", true, true, true);
        assert_eq!((refused.on, refused.reason), (false, Some("no_curtain")));
        assert_eq!(*speakers.0.lock().unwrap(), Some(false), "never muted");
    }

    /// P1d — a session whose reports and ledger can be read back.
    struct Reporting {
        s: Session,
        reports: mpsc::Receiver<ClientMsg>,
        ledger: Arc<Ledger>,
        _dir: tempfile::TempDir,
    }

    fn reporting(up_ok: bool) -> Reporting {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Ledger::at(dir.path().join("privacy-curtains.json")));
        let (outbound, reports) = mpsc::channel(32);
        let s = Session::new(PrivacyCtx {
            session_id: ObjectId::new(),
            controller_name: "Alex".into(),
            host: Arc::new(Recorder {
                calls: Mutex::new(Vec::new()),
                up_ok,
            }),
            possible: || true,
            report: Reporter {
                outbound,
                tenant_id: "aaaaaaaaaaaaaaaaaaaaaaaa".into(),
                ledger: ledger.clone(),
            },
            mute: fake_mute(None).0,
        });
        Reporting {
            s,
            reports,
            ledger,
            _dir: dir,
        }
    }

    /// Every report queued so far, as (kind, reason).
    fn drained(rx: &mut mpsc::Receiver<ClientMsg>) -> Vec<(PrivacyActivityKind, Option<String>)> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            match m {
                ClientMsg::PrivacyActivity { kind, reason, .. } => out.push((kind, reason)),
                other => panic!("not a privacy report: {other:?}"),
            }
        }
        out
    }

    /// P1d — the device reports every curtain it put up, every take-down with
    /// its reason, and every "on" it refused. A second "on" while up, and an
    /// "off" with nothing up, change nothing and say nothing.
    #[test]
    fn the_device_reports_what_it_did_with_the_curtain() {
        use PrivacyActivityKind::*;
        let mut r = reporting(true);
        let s = &r.s;
        s.set("1", false, true, true);
        assert!(s.set("2", true, true, true).on);
        assert!(s.set("3", true, true, true).on);
        s.set("4", false, true, true);
        s.set("5", true, false, true);
        s.set("6", true, true, false);
        assert!(s.set("7", true, true, true).on);
        s.owner_switched_off();
        assert!(s.set("8", true, true, true).on);
        s.end();
        s.end();
        let code = |c: &str| Some(c.to_string());
        assert_eq!(
            drained(&mut r.reports),
            vec![
                (On, None),
                (Off, code("controller")),
                (Refused, code("disabled_on_device")),
                (Refused, code("unavailable")),
                (On, None),
                (Off, code("disabled_on_device")),
                (On, None),
                (Off, code("session_end")),
            ]
        );
    }

    /// A refusal from the overlay is reported in its own words.
    #[test]
    fn a_failing_overlay_is_reported_as_no_curtain() {
        let mut r = reporting(false);
        assert!(!r.s.set("1", true, true, true).on);
        assert_eq!(
            drained(&mut r.reports),
            vec![(PrivacyActivityKind::Refused, Some("no_curtain".into()))]
        );
        assert!(
            r.ledger.read().is_empty(),
            "a curtain that never went up is not held"
        );
    }

    /// A curtain is in the ledger exactly while it is up, under its session
    /// and its org.
    #[test]
    fn a_curtain_is_in_the_ledger_only_while_it_is_up() {
        let r = reporting(true);
        assert!(r.ledger.read().is_empty());
        assert!(r.s.set("1", true, true, true).on);
        assert_eq!(
            r.ledger.read(),
            vec![Held {
                session_id: r.s.ctx.session_id.to_hex(),
                tenant_id: "aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            }]
        );
        r.s.set("2", false, true, true);
        assert!(r.ledger.read().is_empty());
        assert!(r.s.set("3", true, true, true).on);
        r.s.end();
        assert!(
            r.ledger.read().is_empty(),
            "the session's end clears it too"
        );
    }

    /// The next process reports each curtain it finds as `off {worker_exit}`,
    /// on the connection of the org the session belonged to, and clears the
    /// file. One the queue refuses waits for the next connection.
    #[test]
    fn the_next_process_reports_each_curtain_left_as_worker_exit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("privacy-curtains.json");
        let (org_a, org_b) = ("aaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbb");
        let (s1, s2) = (ObjectId::new(), ObjectId::new());
        {
            // The process that died.
            let before = Ledger::at(path.clone());
            before.add(Held {
                session_id: s1.to_hex(),
                tenant_id: org_a.into(),
            });
            before.add(Held {
                session_id: s2.to_hex(),
                tenant_id: org_b.into(),
            });
        }
        let after = Ledger::at(path.clone());
        let mut left = after.take_leftovers();
        assert_eq!(left.len(), 2);
        assert!(!path.exists(), "taken once: the file is gone");
        assert!(after.take_leftovers().is_empty());

        let (tx, mut rx) = mpsc::channel(8);
        drain_into(&mut left, org_a, &tx);
        match rx.try_recv().unwrap() {
            ClientMsg::PrivacyActivity {
                session_id,
                kind,
                reason,
            } => {
                assert_eq!(session_id, s1);
                assert_eq!(kind, PrivacyActivityKind::Off);
                assert_eq!(reason.as_deref(), Some("worker_exit"));
            }
            other => panic!("{other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "org B's session is not org A's to report"
        );
        assert_eq!(left.len(), 1);

        // A full queue keeps it for the next connection.
        let (full, _keep) = mpsc::channel(1);
        full.try_send(ClientMsg::Ping { id: 0 }).unwrap();
        drain_into(&mut left, org_b, &full);
        assert_eq!(left.len(), 1, "refused by the queue, so still waiting");
        drain_into(&mut left, org_b, &tx);
        assert!(left.is_empty());
        assert!(matches!(
            rx.try_recv(),
            Ok(ClientMsg::PrivacyActivity { session_id, .. }) if session_id == s2
        ));
    }

    /// Each gate refuses in its own words, and none of them touches the
    /// overlay: a refused "on" must not flash a curtain.
    #[test]
    fn every_gate_refuses_before_the_overlay_is_asked() {
        let (s, host) = session(true);
        assert_eq!(
            s.set("a", true, false, true).reason,
            Some("disabled_on_device")
        );
        assert_eq!(s.set("b", true, true, false).reason, Some("unavailable"));
        // The owner's gate is named first: it is the one the owner can change.
        assert_eq!(
            s.set("c", true, false, false).reason,
            Some("disabled_on_device")
        );
        assert!(host.calls.lock().unwrap().is_empty());
        assert!(!s.is_on());
    }

    #[test]
    fn on_then_off_puts_the_curtain_up_and_takes_it_down() {
        let (s, host) = session(true);
        let up = s.set("1", true, true, true);
        assert_eq!(up, StateMsg::new("1", true, None));
        assert!(s.is_on());
        // A second "on" is answered, not drawn twice.
        assert!(s.set("2", true, true, true).on);
        let down = s.set("3", false, true, true);
        assert_eq!(down, StateMsg::new("3", false, None));
        assert!(!s.is_on());
        assert_eq!(*host.calls.lock().unwrap(), vec![true, false]);
    }

    /// The overlay could not put it up (or could not keep it out of the
    /// capture): refused, and nothing claims a curtain that is not there.
    #[test]
    fn an_overlay_that_fails_is_a_refusal_not_a_curtain() {
        let (s, _) = session(false);
        let r = s.set("x", true, true, true);
        assert_eq!(r, StateMsg::new("x", false, Some("no_curtain")));
        assert!(!s.is_on());
    }

    /// Off is never refused — not even when the gates have closed since.
    #[test]
    fn off_is_never_refused() {
        let (s, host) = session(true);
        assert!(s.set("1", true, true, true).on);
        let r = s.set("2", false, false, false);
        assert_eq!(r, StateMsg::new("2", false, None));
        assert_eq!(*host.calls.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn the_owner_switching_off_takes_it_down_and_says_why() {
        let (s, host) = session(true);
        assert_eq!(s.owner_switched_off(), None, "nothing up, nothing to say");
        assert!(s.set("1", true, true, true).on);
        let msg = s.owner_switched_off().expect("a curtain was up");
        assert_eq!(msg.reason, Some("disabled_on_device"));
        assert!(!msg.on && !s.is_on());
        assert_eq!(*host.calls.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn the_session_ending_takes_it_down_once() {
        let (s, host) = session(true);
        assert!(s.set("1", true, true, true).on);
        s.end();
        s.end();
        assert_eq!(*host.calls.lock().unwrap(), vec![true, false]);
    }

    /// `privacy-mode` only with `privacy-available`, and only while the owner
    /// allows it; nothing at all where no curtain is possible.
    #[test]
    fn the_words_follow_the_platform_and_the_owner() {
        assert!(words(false, true).is_empty());
        assert!(words(false, false).is_empty());
        assert_eq!(words(true, false), vec![RpcCap::PrivacyAvailable]);
        assert_eq!(
            words(true, true),
            vec![RpcCap::PrivacyAvailable, RpcCap::PrivacyMode]
        );
    }

    /// The prompt says the screen may be covered only when it could be.
    #[test]
    fn the_consent_line_appears_only_when_the_device_could_act_on_it() {
        let p = Permissions::VIEW | Permissions::INPUT | Permissions::PRIVACY;
        assert!(consent_line(p, true, true).is_some());
        assert!(consent_line(p, false, true).is_none());
        assert!(consent_line(p, true, false).is_none());
        assert!(consent_line(Permissions::VIEW | Permissions::INPUT, true, true).is_none());
    }

    #[test]
    fn the_wire_reads_and_writes_as_documented() {
        assert_eq!(
            serde_json::from_str::<Incoming>(r#"{"t":"rc:privacy.set","id":"a","on":true}"#)
                .unwrap(),
            Incoming::Set {
                id: "a".into(),
                on: true
            }
        );
        assert_eq!(
            serde_json::from_str::<Incoming>(r#"{"t":"rc:privacy.status"}"#).unwrap(),
            Incoming::Status { id: String::new() }
        );
        // `on` is required: a set that does not say which way is an error,
        // never a default that might cover the screen.
        assert!(serde_json::from_str::<Incoming>(r#"{"t":"rc:privacy.set","id":"a"}"#).is_err());
        let v = serde_json::to_value(StateMsg::new("a", false, Some("no_curtain"))).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"t":"rc:privacy.state","id":"a","on":false,"reason":"no_curtain"})
        );
        let v = serde_json::to_value(StateMsg::new("b", true, None)).unwrap();
        assert!(v.get("reason").is_none(), "{v}");
    }

    #[test]
    fn the_owner_gate_is_live() {
        set_device_allowed(true);
        assert!(device_allowed());
        set_device_allowed(false);
        assert!(!device_allowed());
    }

    /// Off Windows, or without the overlay, a curtain is never possible — and
    /// so no word is ever advertised there.
    #[cfg(not(all(target_os = "windows", feature = "viewer-indicator")))]
    #[test]
    fn no_curtain_is_possible_without_the_windows_overlay() {
        set_overlay_up(true);
        assert!(!curtain_possible());
        // Whatever the owner's gate says: there is nothing to offer.
        assert!(current_words().is_empty());
    }
}
