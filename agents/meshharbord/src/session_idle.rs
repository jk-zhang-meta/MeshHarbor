// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-101 P4b-2 — the idle limit, kept by the device.
//!
//! A session sent `Request.idle_secs` ends after that long with no input from
//! its controller and no significant change on the screen. The hub cannot keep
//! this limit: input rides the peer-to-peer data channels and the pixels never
//! leave the device, so only the device sees both halves of "idle".
//!
//! - **Controller activity** is anything the controller sent: input (counted
//!   even when the lock screen suppresses it), the clipboard either way, and
//!   file transfer, where a download's progress counts so that a long one is
//!   never ended under the person waiting for it. Read from
//!   [`crate::session_telemetry`], which the channel handlers bump.
//! - **Screen activity** is change a watcher would be watching, not any change
//!   at all: a clock, a blinking caret or a tray icon repaints forever, and
//!   counting those would keep every forgotten session open. [`ScreenActivity`]
//!   samples a coarse grid of each captured frame, at most once a second per
//!   screen, and calls the screen active when the cells that changed within a
//!   window cover enough of it. A clock keeps repainting the same two cells; a
//!   scrolling log, a video or a paragraph being typed spreads across many.
//! - **The verdict** is [`IdleClock::tick`]: carry on, warn the viewer (`rc:idle`
//!   on the control channel, with `ends_in_ms`), clear the warning, or end the
//!   session. The end goes out as `ClientMsg::Terminate` with `IdleTimeout` and
//!   `limit: "idle"`, through the same path as the host's own Disconnect: say it
//!   first, then close.
//!
//! The screen is one for the whole process, not one per session: two sessions
//! on one host watch the same desktop, and on two monitors one session's
//! activity keeps the other alive. That errs the safe way, toward keeping a
//! session someone may be using; the org's maximum length (P4b-1) bounds it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use webrtc::data_channel::RTCDataChannel;

use crate::capture::{Frame, PixelFormat};
use crate::session_telemetry::ControllerActivity;

/// A session's control-channel stash, as `AgentPeer` keeps it: `None` until
/// the viewer opens the channel.
pub type ControlStash = Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>;

// ── the screen ───────────────────────────────────────────────────────────

/// The grid a frame is sampled on: 32 × 18 cells (60 px square at 1080p).
const GRID_W: usize = 32;
const GRID_H: usize = 18;
const CELLS: usize = GRID_W * GRID_H;
/// Samples per cell side: 4 × 4 points, each at the centre of a sub-cell.
/// A small change rarely lands on one, which is the point: what matters is
/// change big enough to be seen, and that reliably hits many.
const LATTICE: usize = 4;
/// The most often one screen is sampled. The limit is counted in minutes, so
/// a second of resolution is plenty, and it keeps the cost off the pump: ~9k
/// pixel reads a second per screen.
pub const ANALYZE_EVERY: Duration = Duration::from_secs(1);
/// The window the changed cells are gathered over.
pub const WINDOW: Duration = Duration::from_secs(30);
/// How many distinct cells must change within one [`WINDOW`] for the screen
/// to count as active: about 1 % of the grid. A clock or a caret repaints
/// one or two cells for as long as it runs; a line of typing, a scroll or a
/// video crosses this within seconds.
pub const ACTIVE_CELLS: usize = 6;
/// How many surfaces (monitor × size × format) are remembered. Two sessions
/// on one monitor at different sizes are two surfaces; a frame is compared
/// only with the last frame of its own.
const SURFACES_KEPT: usize = 8;

/// What a frame is compared against: the last frame of the same monitor,
/// size and format. Comparing across them would read every frame as a change.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SurfaceKey {
    monitor: u8,
    width: u32,
    height: u32,
    format: u8,
}

impl SurfaceKey {
    pub fn of(frame: &Frame) -> Self {
        Self {
            monitor: frame.monitor,
            width: frame.width,
            height: frame.height,
            format: match frame.pixel_format {
                PixelFormat::Bgra => 0,
                PixelFormat::Nv12 => 1,
                PixelFormat::I420 => 2,
            },
        }
    }
}

struct Surface {
    sigs: Vec<u64>,
    changed: Vec<bool>,
    changed_count: usize,
    window_start: Instant,
    last_analyzed: Instant,
}

/// Whether the screen has changed in a way someone could be watching, and
/// when it last did.
#[derive(Default)]
pub struct ScreenActivity {
    surfaces: HashMap<SurfaceKey, Surface>,
    last_active: Option<Instant>,
}

impl ScreenActivity {
    /// Take the next sample of `key` now? `false` within [`ANALYZE_EVERY`] of
    /// the last; `true` claims the slot, so a second pump on the same screen
    /// does not sample it again.
    pub fn claim(&mut self, key: SurfaceKey, now: Instant) -> bool {
        match self.surfaces.get_mut(&key) {
            Some(s) if now.saturating_duration_since(s.last_analyzed) < ANALYZE_EVERY => false,
            Some(s) => {
                s.last_analyzed = now;
                true
            }
            None => true,
        }
    }

    /// One sample of `key`, as cell signatures ([`signatures`]). The first
    /// sample of a surface is its baseline and changes nothing. Returns
    /// whether the screen counts as active after it.
    pub fn observe(&mut self, key: SurfaceKey, sigs: Vec<u64>, now: Instant) -> bool {
        let Some(s) = self.surfaces.get_mut(&key) else {
            if self.surfaces.len() >= SURFACES_KEPT
                && let Some(oldest) = self
                    .surfaces
                    .iter()
                    .min_by_key(|(_, s)| s.last_analyzed)
                    .map(|(k, _)| *k)
            {
                self.surfaces.remove(&oldest);
            }
            self.surfaces.insert(
                key,
                Surface {
                    sigs,
                    changed: vec![false; CELLS],
                    changed_count: 0,
                    window_start: now,
                    last_analyzed: now,
                },
            );
            return false;
        };
        if now.saturating_duration_since(s.window_start) >= WINDOW {
            s.changed.fill(false);
            s.changed_count = 0;
            s.window_start = now;
        }
        for (i, (old, new)) in s.sigs.iter().zip(&sigs).enumerate() {
            if old != new && !s.changed[i] {
                s.changed[i] = true;
                s.changed_count += 1;
            }
        }
        s.sigs = sigs;
        s.last_analyzed = now;
        let active = s.changed_count >= ACTIVE_CELLS;
        if active {
            self.last_active = Some(now);
        }
        active
    }

    /// When the screen last counted as active, if it has since the process
    /// started watching.
    pub fn last_active(&self) -> Option<Instant> {
        self.last_active
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// A frame's cell signatures: for each cell of the grid, a hash of its
/// lattice samples. Luma for NV12 and I420 (their first plane), the colour
/// bytes for BGRA (alpha is not looked at). `None` for a frame too small to
/// sample or shorter than its own dimensions say, which is skipped rather
/// than read out of bounds.
pub fn signatures(frame: &Frame) -> Option<Vec<u64>> {
    let (w, h) = (frame.width as usize, frame.height as usize);
    if w < GRID_W * LATTICE || h < GRID_H * LATTICE {
        return None;
    }
    let (bpp, hashed) = match frame.pixel_format {
        PixelFormat::Bgra => (4, 3),
        PixelFormat::Nv12 | PixelFormat::I420 => (1, 1),
    };
    let stride = frame.stride as usize;
    if stride < w * bpp {
        return None;
    }
    let mut sigs = vec![0u64; CELLS];
    for cy in 0..GRID_H {
        let (y0, y1) = (cy * h / GRID_H, (cy + 1) * h / GRID_H);
        for cx in 0..GRID_W {
            let (x0, x1) = (cx * w / GRID_W, (cx + 1) * w / GRID_W);
            let mut sig = FNV_OFFSET;
            for ly in 0..LATTICE {
                let y = y0 + (2 * ly + 1) * (y1 - y0) / (2 * LATTICE);
                for lx in 0..LATTICE {
                    let x = x0 + (2 * lx + 1) * (x1 - x0) / (2 * LATTICE);
                    let at = y * stride + x * bpp;
                    for b in frame.data.get(at..at + hashed)? {
                        sig ^= u64::from(*b);
                        sig = sig.wrapping_mul(FNV_PRIME);
                    }
                }
            }
            sigs[cy * GRID_W + cx] = sig;
        }
    }
    Some(sigs)
}

/// How many sessions have an idle limit running. While none does, a frame
/// costs one atomic load.
static ARMED: AtomicUsize = AtomicUsize::new(0);

fn screen() -> &'static Mutex<ScreenActivity> {
    static SCREEN: OnceLock<Mutex<ScreenActivity>> = OnceLock::new();
    SCREEN.get_or_init(|| Mutex::new(ScreenActivity::default()))
}

/// A captured frame, from a media pump. Call it for REAL captures only, never
/// for a keepalive re-encode of the last frame. Costs nothing unless a live
/// session has an idle limit, and then samples at most one frame a second per
/// screen. It never waits on another pump: if one is already in here, this
/// frame is skipped.
pub fn note_frame(frame: &Frame) {
    if ARMED.load(Ordering::Relaxed) == 0 {
        return;
    }
    let key = SurfaceKey::of(frame);
    let now = Instant::now();
    match screen().try_lock() {
        Ok(mut s) => {
            if !s.claim(key, now) {
                return;
            }
        }
        Err(std::sync::TryLockError::WouldBlock) => return,
        Err(std::sync::TryLockError::Poisoned(p)) => {
            if !p.into_inner().claim(key, now) {
                return;
            }
        }
    }
    // Sampled outside the lock: ~9k reads, but no pump waits on them.
    let Some(sigs) = signatures(frame) else {
        return;
    };
    let became_active = screen()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .observe(key, sigs, now);
    if became_active {
        debug!(monitor = frame.monitor, "idle limit: the screen is active");
    }
}

/// When the screen last counted as active.
pub fn last_screen_activity() -> Option<Instant> {
    screen()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .last_active()
}

// ── one session's clock ──────────────────────────────────────────────────

/// What a tick of a session's clock decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing to say.
    Carry,
    /// Warn the viewer: the session ends in this long unless someone acts.
    Warn(Duration),
    /// The warning is void: there was activity after it.
    Clear,
    /// The limit is reached: end the session.
    End,
}

/// One session's idle clock. Pure: it is told the time and what it should
/// know, so a test can drive it without waiting.
#[derive(Debug)]
pub struct IdleClock {
    limit: Duration,
    warn_lead: Duration,
    last_activity: Instant,
    last_seen: Option<ControllerActivity>,
    warned: bool,
}

impl IdleClock {
    pub fn new(limit: Duration, now: Instant) -> Self {
        Self {
            limit,
            warn_lead: Self::warn_lead(limit),
            last_activity: now,
            last_seen: None,
            warned: false,
        }
    }

    /// How long before the end the viewer is warned: a fifth of the limit,
    /// and never more than a minute.
    pub fn warn_lead(limit: Duration) -> Duration {
        (limit / 5).min(Duration::from_secs(60))
    }

    /// How often the clock is ticked: an eighth of the limit, between a
    /// quarter of a second and five seconds.
    pub fn tick_every(limit: Duration) -> Duration {
        (limit / 8).clamp(Duration::from_millis(250), Duration::from_secs(5))
    }

    /// One look at the session. `controller` is what the controller has done
    /// so far (`None` once its counters are gone); any change since the last
    /// look is activity now. The first look is the baseline. `screen` is when
    /// the screen last counted as active.
    pub fn tick(
        &mut self,
        now: Instant,
        controller: Option<ControllerActivity>,
        screen: Option<Instant>,
    ) -> Verdict {
        if let Some(c) = controller {
            if self.last_seen.is_some_and(|prev| prev != c) {
                self.last_activity = now;
            }
            self.last_seen = Some(c);
        }
        if let Some(t) = screen
            && t > self.last_activity
        {
            self.last_activity = t;
        }
        let idle = now.saturating_duration_since(self.last_activity);
        if idle >= self.limit {
            return Verdict::End;
        }
        if idle >= self.limit - self.warn_lead {
            if self.warned {
                return Verdict::Carry;
            }
            self.warned = true;
            return Verdict::Warn(self.limit - idle);
        }
        if self.warned {
            self.warned = false;
            return Verdict::Clear;
        }
        Verdict::Carry
    }
}

/// The warning the viewer is sent on the control channel: `ends_in_ms` until
/// the session ends, or `null` when the warning is void. A duration, not a
/// time, so the viewer turns it into a deadline on its own clock (the way it
/// reads `rc:media-waiting`). An older viewer ignores the message.
pub fn notice_json(ends_in: Option<Duration>) -> String {
    serde_json::json!({
        "t": "rc:idle",
        "ends_in_ms": ends_in.map(|d| d.as_millis() as u64),
    })
    .to_string()
}

/// Decrements [`ARMED`] however the watcher ends: the session ending, the
/// limit, or its task being dropped.
struct Armed;

impl Armed {
    fn new() -> Self {
        ARMED.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        ARMED.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Start keeping a live session's idle limit. Call once the session is live
/// (its answer sent). The watcher stops when `session_end` fires; at the
/// limit it sends the session id on `ended`, where the signalling loop ends
/// the session the way the host's Disconnect does.
pub fn arm(
    session_id: ObjectId,
    limit: Duration,
    session_end: CancellationToken,
    control: ControlStash,
    ended: mpsc::Sender<ObjectId>,
) {
    let armed = Armed::new();
    // The controller's baseline, taken NOW, as the session goes live. This
    // also creates the session's counters if nothing has touched them yet
    // (the peer's drop forgets them). Without it the clock's first look would
    // find none, and the first input after going live would become the
    // baseline instead of activity: one click, then nothing, would end the
    // session a limit after it went live rather than after the click.
    let baseline = crate::session_telemetry::counters(session_id).activity();
    tokio::spawn(async move {
        let _armed = armed;
        let every = IdleClock::tick_every(limit);
        let started = Instant::now();
        let mut clock = IdleClock::new(limit, started);
        let _ = clock.tick(started, Some(baseline), None);
        info!(
            %session_id,
            limit_secs = limit.as_secs(),
            "idle limit: armed — the session ends after this long with no input and no change on screen"
        );
        loop {
            tokio::select! {
                _ = session_end.cancelled() => return,
                _ = tokio::time::sleep(every) => {}
            }
            let controller = crate::session_telemetry::peek(session_id).map(|c| c.activity());
            match clock.tick(Instant::now(), controller, last_screen_activity()) {
                Verdict::Carry => {}
                Verdict::Warn(left) => {
                    info!(%session_id, ends_in_secs = left.as_secs(), "idle limit: warning the viewer");
                    send_notice(&control, Some(left)).await;
                }
                Verdict::Clear => {
                    debug!(%session_id, "idle limit: activity again — warning withdrawn");
                    send_notice(&control, None).await;
                }
                Verdict::End => {
                    info!(%session_id, limit_secs = limit.as_secs(), "idle limit: reached — ending the session");
                    let _ = ended.send(session_id).await;
                    return;
                }
            }
        }
    });
}

/// Send the warning (or its withdrawal) if the control channel is open. Best
/// effort and bounded: a channel that is gone or stuck costs the warning,
/// never the clock.
async fn send_notice(control: &ControlStash, ends_in: Option<Duration>) {
    let dc = control.lock().await.clone();
    if let Some(dc) = dc {
        let _ =
            tokio::time::timeout(Duration::from_secs(2), dc.send_text(notice_json(ends_in))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u32 = 1920;
    const H: u32 = 1080;

    fn bgra(w: u32, h: u32) -> Frame {
        Frame {
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: PixelFormat::Bgra,
            data: vec![40u8; (w * h * 4) as usize],
            monotonic_us: 0,
            monitor: 0,
            damage: crate::capture::Damage::Unknown,
            source: None,
        }
    }

    /// Paint a solid rectangle into a BGRA frame.
    fn paint(f: &mut Frame, x: u32, y: u32, w: u32, h: u32, v: u8) {
        for row in y..(y + h).min(f.height) {
            for col in x..(x + w).min(f.width) {
                let at = (row * f.stride + col * 4) as usize;
                f.data[at..at + 3].copy_from_slice(&[v, v, v]);
            }
        }
    }

    /// Feed `frames` at one-second steps; return whether the screen ever
    /// counted as active.
    fn active_over(frames: impl IntoIterator<Item = Frame>) -> bool {
        let mut s = ScreenActivity::default();
        let t0 = Instant::now();
        let mut any = false;
        for (i, f) in frames.into_iter().enumerate() {
            let now = t0 + Duration::from_secs(i as u64);
            let key = SurfaceKey::of(&f);
            assert!(s.claim(key, now));
            any |= s.observe(key, signatures(&f).expect("sampled"), now);
        }
        any
    }

    /// A still screen is no activity, however long it stays still.
    #[test]
    fn a_still_screen_is_idle() {
        assert!(!active_over((0..60).map(|_| bgra(W, H))));
    }

    /// A clock that changes every second, in the same corner, never counts:
    /// it repaints the same cells for as long as the screen is on.
    #[test]
    fn a_ticking_clock_is_not_activity() {
        let frames = (0..120u32).map(|i| {
            let mut f = bgra(W, H);
            // A seconds clock in the corner, every digit a different shade.
            paint(&mut f, W - 140, H - 40, 120, 30, 100 + (i % 60) as u8);
            f
        });
        assert!(!active_over(frames));
    }

    /// A caret blinking in a text field never counts either.
    #[test]
    fn a_blinking_caret_is_not_activity() {
        let frames = (0..120u32).map(|i| {
            let mut f = bgra(W, H);
            if i % 2 == 0 {
                paint(&mut f, 400, 300, 2, 20, 255);
            }
            f
        });
        assert!(!active_over(frames));
    }

    /// Text typed across the screen spreads over many cells: within a window
    /// it counts.
    #[test]
    fn typing_counts() {
        let mut f = bgra(W, H);
        let frames = (0..30u32).map(|i| {
            // One more word on the line each second, wrapping to the next.
            let (line, word) = (i / 10, i % 10);
            paint(&mut f, 100 + word * 160, 200 + line * 120, 140, 24, 230);
            f.clone()
        });
        assert!(active_over(frames));
    }

    /// A window scrolling, or a video playing, counts at once.
    #[test]
    fn a_scrolling_window_counts() {
        let frames = (0..3u32).map(|i| {
            let mut f = bgra(W, H);
            for row in 0..20 {
                paint(
                    &mut f,
                    200,
                    100 + row * 40,
                    1200,
                    20,
                    ((row + i) * 37 % 200) as u8 + 30,
                );
            }
            f
        });
        assert!(active_over(frames));
    }

    /// Two monitors (or two sizes of one) are two surfaces: alternating
    /// between them is not a change of every cell.
    #[test]
    fn surfaces_are_compared_only_with_themselves() {
        let mut s = ScreenActivity::default();
        let t0 = Instant::now();
        for i in 0..20u64 {
            let mut f = if i % 2 == 0 {
                bgra(W, H)
            } else {
                bgra(1280, 720)
            };
            paint(&mut f, 0, 0, 640, 360, if i % 2 == 0 { 10 } else { 250 });
            let now = t0 + Duration::from_secs(i);
            let key = SurfaceKey::of(&f);
            assert!(s.claim(key, now));
            assert!(!s.observe(key, signatures(&f).unwrap(), now), "frame {i}");
        }
    }

    /// A screen is sampled at most once a second, whichever pump asks.
    #[test]
    fn a_surface_is_sampled_once_a_second() {
        let mut s = ScreenActivity::default();
        let f = bgra(W, H);
        let key = SurfaceKey::of(&f);
        let t0 = Instant::now();
        assert!(s.claim(key, t0));
        s.observe(key, signatures(&f).unwrap(), t0);
        assert!(!s.claim(key, t0 + Duration::from_millis(500)));
        assert!(s.claim(key, t0 + ANALYZE_EVERY));
    }

    /// A frame shorter than its dimensions claim, or too small for the grid,
    /// is skipped, never read past its end.
    #[test]
    fn a_malformed_frame_is_skipped() {
        let mut short = bgra(W, H);
        short.data.truncate(1000);
        assert_eq!(signatures(&short), None);
        assert_eq!(signatures(&bgra(64, 32)), None);
        let mut nv12 = bgra(W, H);
        nv12.pixel_format = PixelFormat::Nv12;
        nv12.stride = W;
        assert!(signatures(&nv12).is_some());
    }

    fn act(n: u64) -> Option<ControllerActivity> {
        Some(ControllerActivity {
            input: n,
            ..Default::default()
        })
    }

    /// The clock: a session with nothing happening is warned a fifth of the
    /// limit before its end (capped at a minute), then ended.
    #[test]
    fn an_idle_session_is_warned_then_ended() {
        let limit = Duration::from_secs(600);
        let t0 = Instant::now();
        let mut c = IdleClock::new(limit, t0);
        assert_eq!(c.tick(t0, act(5), None), Verdict::Carry, "the baseline");
        assert_eq!(
            c.tick(t0 + Duration::from_secs(539), act(5), None),
            Verdict::Carry
        );
        assert_eq!(
            c.tick(t0 + Duration::from_secs(540), act(5), None),
            Verdict::Warn(Duration::from_secs(60))
        );
        assert_eq!(
            c.tick(t0 + Duration::from_secs(560), act(5), None),
            Verdict::Carry,
            "warned once"
        );
        assert_eq!(
            c.tick(t0 + Duration::from_secs(600), act(5), None),
            Verdict::End
        );
    }

    /// Input after the warning withdraws it and starts the clock again.
    #[test]
    fn input_withdraws_the_warning() {
        let limit = Duration::from_secs(300);
        let t0 = Instant::now();
        let mut c = IdleClock::new(limit, t0);
        c.tick(t0, act(1), None);
        assert!(matches!(
            c.tick(t0 + Duration::from_secs(250), act(1), None),
            Verdict::Warn(_)
        ));
        let t1 = t0 + Duration::from_secs(260);
        assert_eq!(c.tick(t1, act(2), None), Verdict::Clear);
        assert_eq!(
            c.tick(t1 + Duration::from_secs(239), act(2), None),
            Verdict::Carry
        );
        assert!(matches!(
            c.tick(t1 + Duration::from_secs(240), act(2), None),
            Verdict::Warn(_)
        ));
        assert_eq!(
            c.tick(t1 + Duration::from_secs(300), act(2), None),
            Verdict::End
        );
    }

    /// Activity on the screen keeps a session with no input alive: a view-only
    /// watcher, or someone reading a build log scroll by.
    #[test]
    fn screen_activity_keeps_a_session() {
        let limit = Duration::from_secs(120);
        let t0 = Instant::now();
        let mut c = IdleClock::new(limit, t0);
        c.tick(t0, act(0), None);
        let mut screen = None;
        for s in (10..=600).step_by(10) {
            let now = t0 + Duration::from_secs(s);
            screen = Some(now - Duration::from_secs(3));
            assert_eq!(c.tick(now, act(0), screen), Verdict::Carry, "at {s}s");
        }
        // The screen goes still: ended a limit after its last activity.
        let last = screen.unwrap();
        assert_eq!(c.tick(last + limit, act(0), screen), Verdict::End);
    }

    /// The first look is a baseline, however much the controller had done
    /// before it, and the counters going away (the peer dropped) is no
    /// activity.
    #[test]
    fn the_baseline_is_not_activity() {
        let limit = Duration::from_secs(60);
        let t0 = Instant::now();
        let mut c = IdleClock::new(limit, t0);
        assert_eq!(
            c.tick(t0 + Duration::from_secs(30), act(900), None),
            Verdict::Carry
        );
        assert_eq!(
            c.tick(t0 + Duration::from_secs(48), None, None),
            Verdict::Warn(Duration::from_secs(12))
        );
        assert_eq!(
            c.tick(t0 + Duration::from_secs(60), None, None),
            Verdict::End
        );
    }

    #[test]
    fn the_warning_and_the_tick_scale_with_the_limit() {
        assert_eq!(
            IdleClock::warn_lead(Duration::from_secs(60)),
            Duration::from_secs(12)
        );
        assert_eq!(
            IdleClock::warn_lead(Duration::from_secs(3600)),
            Duration::from_secs(60)
        );
        assert_eq!(
            IdleClock::tick_every(Duration::from_secs(2)),
            Duration::from_millis(250)
        );
        assert_eq!(
            IdleClock::tick_every(Duration::from_secs(16)),
            Duration::from_secs(2)
        );
        assert_eq!(
            IdleClock::tick_every(Duration::from_secs(3600)),
            Duration::from_secs(5)
        );
    }

    /// The viewer's message, both shapes. A compatibility surface: the viewer
    /// keys its banner on these names. Compared parsed, so the key order (a
    /// serde_json feature away from changing) does not matter.
    #[test]
    fn the_notice_spelling_is_locked() {
        let parse = |s: String| serde_json::from_str::<serde_json::Value>(&s).unwrap();
        assert_eq!(
            parse(notice_json(Some(Duration::from_millis(60_000)))),
            serde_json::json!({"t": "rc:idle", "ends_in_ms": 60000})
        );
        assert_eq!(
            parse(notice_json(None)),
            serde_json::json!({"t": "rc:idle", "ends_in_ms": null})
        );
    }
}
